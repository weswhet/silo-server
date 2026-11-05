//! Turns routes, fixtures and scenarios into an ordered list of cases. The order is
//! a pure function of the sources, and both servers receive it one case at a time,
//! so they stay in step: reads see the seed, then rejected writes that should change
//! nothing, then real writes in stages, creates before updates before deletes.

use crate::model::*;
use crate::params::has_params;
use crate::schema;
use crate::sources::Sources;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[derive(Clone, Debug, Serialize)]
pub struct Skip {
    pub what: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub cases: Vec<Case>,
    pub skipped: Vec<Skip>,
}

const DEFAULT_TIMEOUT: u64 = 20;
const STREAM_TIMEOUT: u64 = 5;
const MALFORMED_JSON: &[u8] = b"{\"conformance\":";
const WRONG_SHAPE_JSON: &[u8] = b"[]";
const MULTIPART_BOUNDARY: &str = "conformanceboundary";

type AuthVariant = (
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static [(&'static str, &'static str)],
);

/// Spellings of one credential a Jellyfin client may send, as (name, headers, query).
/// `${token}` is filled per side. The Go server matches these case-insensitively, so
/// a port that only accepts what the harness's identities send must show up here.
const JF_AUTH_VARIANTS: &[AuthVariant] = &[
    (
        "authorization_mediabrowser",
        &[(
            "Authorization",
            "MediaBrowser Client=\"c\", Device=\"d\", DeviceId=\"conformance-1\", Version=\"1.0\", Token=\"${token}\"",
        )],
        &[],
    ),
    (
        "lowercase_scheme_and_key",
        &[(
            "X-Emby-Authorization",
            "mediabrowser client=\"c\", device=\"d\", deviceid=\"conformance-1\", version=\"1.0\", token=\"${token}\"",
        )],
        &[],
    ),
    (
        "uppercase_unquoted_token",
        &[("X-Emby-Authorization", "MEDIABROWSER TOKEN=${token}")],
        &[],
    ),
    (
        "lowercase_bearer",
        &[("Authorization", "bearer ${token}")],
        &[],
    ),
    (
        "uppercase_bearer",
        &[("X-Emby-Authorization", "BEARER ${token}")],
        &[],
    ),
    ("x_emby_token", &[("X-Emby-Token", "${token}")], &[]),
    (
        "x_mediabrowser_token",
        &[("X-MediaBrowser-Token", "${token}")],
        &[],
    ),
    ("query_api_key", &[], &[("api_key", "${token}")]),
    ("query_apikey", &[], &[("ApiKey", "${token}")]),
    ("query_uppercase_api_key", &[], &[("API_KEY", "${token}")]),
    (
        "bad_token",
        &[("X-Emby-Token", "conformance-not-a-token")],
        &[],
    ),
    (
        "bad_authorization_good_token_header",
        &[
            ("Authorization", "Bearer conformance-not-a-token"),
            ("X-Emby-Token", "${token}"),
        ],
        &[],
    ),
];

/// The route every Jellyfin auth spelling is tried on. The rest get one each in turn.
const JF_AUTH_ROUTE: &str = "/Users/Me";

/// Routes whose privileged success would disrupt the run itself rather than say
/// anything about the API. They still get unauthenticated and forbidden cases.
const DENY_PRIVILEGED: &[(&str, &str)] = &[
    (r"/admin/server/restart/?$", "restarts the server process"),
    (
        r"/admin/storage-transitions/?$",
        "starts a storage migration",
    ),
];

/// Routes that answer while the work they started is still running, so the same
/// request can truthfully return different bodies. Status and headers still count.
const BODY_RACES: &[(&str, &str)] = &[(
    "/admin/jellyfin-compat/web/remove",
    "the removal runs in the background and may finish before the response",
)];

const ACTIVITY_FLUSH_WAIT_MS: u64 = 3000;

fn body_race(path: &str) -> Option<&'static str> {
    BODY_RACES
        .iter()
        .find(|(suffix, _)| path.trim_end_matches('/').ends_with(suffix))
        .map(|(_, why)| *why)
}

fn deny_reason(path: &str) -> Option<&'static str> {
    static RES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RES.get_or_init(|| {
        DENY_PRIVILEGED
            .iter()
            .map(|(p, why)| (Regex::new(p).unwrap(), *why))
            .collect()
    })
    .iter()
    .find(|(re, _)| re.is_match(path))
    .map(|(_, why)| *why)
}

/// Facts the runner supplies for scenario placeholders. A scenario naming anything
/// else depends on fixture rows the conformance seed does not have, and is skipped.
pub const SCENARIO_FACTS: &[&str] = &[
    "admin_api_key_id",
    "admin_password",
    "admin_user_id",
    "admin_username",
    "member_api_key_id",
    "member_email",
    "member_password",
    "member_user_id",
    "member_username",
    "profile_admin_primary",
    "profile_child",
    "profile_missing",
    "profile_primary",
    "profile_secondary",
    "server_name",
];

/// Some routes refuse API keys on purpose, so they need a login session to do anything.
fn needs_login_session(path: &str) -> bool {
    path.contains("/api-keys") || path.contains("/diagnostics/") || path.contains("/auth/sessions")
}

fn privileged(route: &Route) -> Identity {
    if needs_login_session(&route.path) && !route.path.contains("/admin/") {
        return Identity::UserJwt;
    }
    match route.auth {
        Auth::Admin | Auth::Permission => Identity::Admin,
        Auth::Node => Identity::Anon,
        _ => Identity::User,
    }
}

fn identities_for_read(route: &Route) -> Vec<Identity> {
    if route.handle_all {
        return vec![Identity::Anon];
    }
    match route.auth {
        Auth::Public | Auth::Delegated => vec![Identity::Anon, Identity::User],
        Auth::Node => vec![Identity::Anon],
        _ => vec![Identity::Anon, Identity::User, Identity::Admin],
    }
}

fn accepts_body(route: &Route) -> bool {
    if route.method == "DELETE" || !route.mutating() {
        return false;
    }
    if let Some(op) = &route.op {
        if op.body_schema.is_some() {
            return true;
        }
    }
    match route.request_kind.as_deref() {
        Some("json") => true,
        Some("unknown") | None => matches!(route.surface, Surface::Jellycompat | Surface::Abs),
        _ => false,
    }
}

pub(crate) struct Builder<'a> {
    pub(crate) src: &'a Sources,
    pub(crate) index: BTreeMap<(Surface, String, String), usize>,
    cases: Vec<Case>,
    skipped: Vec<Skip>,
    seen_ids: BTreeSet<String>,
}

impl Builder<'_> {
    pub(crate) fn push(&mut self, mut c: Case) {
        let route = &self.src.routes[c.route];
        let mut id = format!("{}#{}", route.key(), c.name);
        let mut n = 2;
        while self.seen_ids.contains(&id) {
            id = format!("{}#{}.{n}", route.key(), c.name);
            n += 1;
        }
        self.seen_ids.insert(id.clone());
        c.id = id;
        self.cases.push(c);
    }

    pub(crate) fn skip(&mut self, what: String, reason: impl Into<String>) {
        self.skipped.push(Skip {
            what,
            reason: reason.into(),
        });
    }

    pub(crate) fn blank(
        &self,
        route_idx: usize,
        name: &str,
        phase: Phase,
        identity: Identity,
    ) -> Case {
        let route = &self.src.routes[route_idx];
        Case {
            id: String::new(),
            route: route_idx,
            name: name.to_string(),
            phase,
            identity,
            // `ALL` names a mount that takes any method, so one has to be picked.
            method: if route.method == "ALL" {
                "GET".to_string()
            } else {
                route.method.clone()
            },
            path: route.path.clone(),
            query: required_query(self.src, route),
            raw_query: None,
            headers: required_headers(self.src, route),
            body: None,
            content_type: None,
            path_override: None,
            capture_as: None,
            may_mutate: false,
            // A refusal happens before the race, so its body is still comparable.
            skip_body: match route.surface {
                Surface::Debug => Some("profiler output differs on every request"),
                Surface::Metrics => Some("metric samples differ on every request"),
                _ if matches!(name, "cors_preflight" | "anon" | "user") => None,
                _ => body_race(&route.path),
            },
            timeout_secs: if route.streams {
                STREAM_TIMEOUT
            } else {
                DEFAULT_TIMEOUT
            },
            sort_key: route.path.clone(),
            source: None,
            host: None,
            settle_on: None,
            wait_ms: 0,
            capture_facts: Vec::new(),
            needs_empty_users: false,
        }
    }

    fn with_generated_body(&self, route: &Route, case: &mut Case) {
        let Some(op) = &route.op else { return };
        let Some(sch) = &op.body_schema else { return };
        let tag = op.id.clone();
        let generated = schema::generate(&self.src.openapi, sch, &tag);
        let media = op
            .body_media
            .clone()
            .unwrap_or_else(|| "application/json".to_string());
        if media.contains("multipart") {
            case.body = Some(schema::multipart(&generated, MULTIPART_BOUNDARY));
            case.content_type = Some(format!(
                "multipart/form-data; boundary={MULTIPART_BOUNDARY}"
            ));
        } else if media == "application/json" || media.ends_with("+json") {
            case.body = Some(generated.to_string().into_bytes());
            case.content_type = Some(media);
        } else {
            case.body = Some(b"conformance".to_vec());
            case.content_type = Some(media);
        }
    }
}

fn required_query(src: &Sources, route: &Route) -> Vec<(String, String)> {
    let Some(op) = &route.op else {
        return Vec::new();
    };
    op.params
        .iter()
        .filter(|p| p.location == "query" && p.required)
        .map(|p| (p.name.clone(), param_literal(src, &p.name, &p.schema)))
        .collect()
}

fn required_headers(src: &Sources, route: &Route) -> Vec<(String, String)> {
    let Some(op) = &route.op else {
        return Vec::new();
    };
    op.params
        .iter()
        .filter(|p| {
            p.location == "header"
                && p.required
                && !p.name.eq_ignore_ascii_case("x-profile-id")
                && !p.name.eq_ignore_ascii_case("authorization")
        })
        .map(|p| (p.name.clone(), param_literal(src, &p.name, &p.schema)))
        .collect()
}

fn param_literal(src: &Sources, name: &str, sch: &Value) -> String {
    let wrapped = serde_json::json!({
        "type": "object",
        "required": [name],
        "properties": { name: sch },
    });
    match &schema::generate(&src.openapi, &wrapped, "Param")[name] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn invalid_query(src: &Sources, route: &Route) -> Option<Vec<(String, String)>> {
    let op = route.op.as_ref()?;
    op.params.iter().find_map(|p| {
        if p.location != "query" {
            return None;
        }
        let s = schema::deref(&src.openapi, &p.schema);
        let typed = s.get("enum").is_some()
            || matches!(
                s.get("type").and_then(Value::as_str),
                Some("integer" | "number" | "boolean")
            );
        typed.then(|| {
            let mut q = required_query(src, route);
            q.retain(|(k, _)| k != &p.name);
            q.push((p.name.clone(), "conformance-invalid".to_string()));
            q
        })
    })
}

fn creator_prefix(routes: &[Route], route: &Route) -> Option<String> {
    if route.method != "POST" || route.path.contains('{') {
        return None;
    }
    let prefix = route.path.trim_end_matches('/').to_string();
    if prefix.contains("/auth/") || prefix.ends_with("/libraries") || deny_reason(&prefix).is_some()
    {
        return None;
    }
    let child = format!("{prefix}/{{");
    routes
        .iter()
        .any(|r| r.surface == route.surface && r.path.starts_with(&child))
        .then_some(prefix)
}

fn mutate_phase(route: &Route) -> Phase {
    match route.surface {
        Surface::ApiV2 | Surface::ApiV2Walked | Surface::ApiDelegate => Phase::MutateV2,
        Surface::ApiV1 | Surface::Root => Phase::MutateV1,
        _ => Phase::MutateCompat,
    }
}

/// Writes that change or remove seeded catalog objects in the background, so anything
/// reading them next races the work. They run after the `after_writes` reads.
fn rewrites_catalog(method: &str, path: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(concat!(
            r"/libraries/\{[^}]+\}(/(confirm-empty-root-cleanup|refresh-metadata|poster|providers))?/?$",
            r"|/libraries/stale-ids/\{[^}]+\}/rematch$",
            r"|/admin/items/\{[^}]+\}(/(match/apply|metadata|refresh-metadata|refresh-markers))?/?$",
        ))
        .unwrap()
    });
    method != "DELETE" && re.is_match(path)
}

/// Creates run before updates, deletes last and children before parents.
fn mutation_sort_key(method: &str, path: &str, name: &str) -> String {
    if rewrites_catalog(method, path) {
        return format!("3zz/00/{path}/{name}");
    }
    let rank = match method {
        "POST" => 1,
        "PUT" => 2,
        "PATCH" => 3,
        _ => 4,
    };
    let depth = if rank == 4 {
        99 - path.matches('/').count()
    } else {
        0
    };
    format!("{rank}/{depth:02}/{path}/{name}")
}

pub fn build(src: &Sources) -> Plan {
    let mut index = BTreeMap::new();
    for (i, r) in src.routes.iter().enumerate() {
        index.insert((r.surface, r.method.clone(), r.path.clone()), i);
    }
    let mut b = Builder {
        src,
        index,
        cases: Vec::new(),
        skipped: Vec::new(),
        seen_ids: BTreeSet::new(),
    };
    let best_fixture = best_fixtures(src);
    for (i, route) in src.routes.iter().enumerate() {
        add_route_cases(&mut b, i, route, &best_fixture);
    }
    add_fixture_cases(&mut b);
    add_scenario_cases(&mut b);
    add_compat_logins(&mut b);
    add_auth_variants(&mut b);
    add_native_chain_refusals(&mut b);
    add_slash_variants(&mut b);
    add_doc_examples(&mut b);
    add_peer_cases(&mut b);
    crate::settings_flows::add(&mut b);
    crate::notification_flows::add(&mut b);
    crate::personal_flows::add(&mut b);
    crate::series_pref_flows::add(&mut b);
    crate::download_flows::add(&mut b);
    crate::collection_flows::add(&mut b);
    crate::request_flows::add(&mut b);
    crate::auth_flows::add(&mut b);
    let mut plan = Plan {
        cases: std::mem::take(&mut b.cases),
        skipped: std::mem::take(&mut b.skipped),
    };
    plan.cases
        .sort_by(|a, b| (a.phase, &a.sort_key).cmp(&(b.phase, &b.sort_key)));
    plan
}

/// The fixture to borrow a working request body from, per operation.
fn best_fixtures(src: &Sources) -> BTreeMap<String, Value> {
    let mut best: BTreeMap<String, Value> = BTreeMap::new();
    for f in &src.fixtures {
        let (Some(op), Some(_), Some(status)) = (
            f["operation_id"].as_str(),
            f["request"]["body"].as_str(),
            f["expected_status"].as_u64(),
        ) else {
            continue;
        };
        if (200..300).contains(&status) && !best.contains_key(op) {
            best.insert(op.to_string(), f.clone());
        }
    }
    best
}

fn add_route_cases(b: &mut Builder, i: usize, route: &Route, fixtures: &BTreeMap<String, Value>) {
    let denied = deny_reason(&route.path);
    if let Some(why) = denied {
        b.skip(route.key(), format!("no privileged success case: {why}"));
    }
    if route.method != "OPTIONS" {
        let mut c = b.blank(i, "cors_preflight", Phase::Reads, Identity::Anon);
        c.method = "OPTIONS".to_string();
        c.query.clear();
        c.headers = vec![
            ("Origin".to_string(), CONFORMANCE_ORIGIN.to_string()),
            (
                "Access-Control-Request-Method".to_string(),
                route.method.clone(),
            ),
        ];
        b.push(c);
    }
    if !route.mutating() || route.handle_all {
        add_read_cases(b, i, route, denied.is_some());
        return;
    }
    // Writes that must be refused before they change anything.
    let mut anon = b.blank(i, "anon", Phase::Rejections, Identity::Anon);
    anon.headers
        .push(("Origin".to_string(), CONFORMANCE_ORIGIN.to_string()));
    b.push(anon);
    if matches!(route.auth, Auth::Admin | Auth::Permission) {
        b.push(b.blank(i, "user", Phase::Rejections, Identity::User));
    }
    if denied.is_some() {
        return;
    }
    let who = privileged(route);
    if has_params(&route.path) {
        let mut c = b.blank(i, "invalid_path", Phase::Rejections, who);
        c.path_override = Some(INVALID_ID.to_string());
        c.may_mutate = true;
        b.push(c);
    }
    if accepts_body(route) {
        for (name, body) in [
            ("invalid_json", MALFORMED_JSON),
            ("invalid_shape", WRONG_SHAPE_JSON),
        ] {
            let mut c = b.blank(i, name, Phase::Rejections, who);
            c.body = Some(body.to_vec());
            c.content_type = Some("application/json".to_string());
            c.may_mutate = true;
            b.push(c);
        }
    }
    // Writes that should succeed. A fixture's body is known to pass validation.
    let phase = mutate_phase(route);
    let mut valid = b.blank(i, "valid", phase, who);
    valid.may_mutate = true;
    valid.sort_key = mutation_sort_key(&route.method, &route.path, "valid");
    let fixture = route.op.as_ref().and_then(|op| fixtures.get(&op.id));
    match fixture {
        Some(f) => {
            valid.body = f["request"]["body"].as_str().map(|s| {
                // A body borrowed from v2 for its v1 twin would collide on unique names.
                let text = if route.surface == Surface::ApiV1 {
                    s.replace("sample", "samplev1")
                } else {
                    s.to_string()
                };
                fixup_playback_start(&route.path, text).into_bytes()
            });
            valid.content_type = Some(
                f["request"]["headers"]["Content-Type"]
                    .as_str()
                    .unwrap_or("application/json")
                    .to_string(),
            );
        }
        None => b.with_generated_body(route, &mut valid),
    }
    let creator = creator_prefix(&b.src.routes, route);
    valid.capture_as = creator.clone();
    if creator.is_some() {
        let mut seed = valid.clone();
        seed.name = "seed".to_string();
        seed.phase = Phase::Seed;
        seed.sort_key = route.path.clone();
        b.push(seed);
    }
    b.push(valid);
}

/// The playback fixture names synthetic objects. The seed's installation id is fixed
/// (`diagnostics.server_instance_id`), so a real start is possible.
fn fixup_playback_start(path: &str, body: String) -> String {
    if !path.ends_with("/playback/start") {
        return body;
    }
    body.replace(
        "11111111-1111-4111-8111-111111111111",
        "c0f00000-0000-4000-8000-00000000f002",
    )
    .replace("file:42:audio:0", "file:1:audio:0")
    .replace("\"file_id\":\"42\"", "\"file_id\":\"1\"")
    .replace(
        "\"profile_id\":\"p-owner\"",
        "\"profile_id\":\"${user_profile_id}\"",
    )
}

fn add_read_cases(b: &mut Builder, i: usize, route: &Route, denied: bool) {
    let phase = if route.mutating() {
        Phase::Rejections
    } else {
        Phase::Reads
    };
    for who in identities_for_read(route) {
        let name = match who {
            Identity::Anon => "anon",
            Identity::User => "user",
            _ => "admin",
        };
        let mut c = b.blank(i, name, phase, who);
        if who == Identity::Anon {
            c.headers
                .push(("Origin".to_string(), CONFORMANCE_ORIGIN.to_string()));
        }
        b.push(c);
    }
    if denied || route.handle_all {
        return;
    }
    let who = privileged(route);
    if !route.mutating() && !route.websocket && !route.streams {
        // The same read once the writes have landed: objects now exist behind ids
        // that were 404 on the seed, and a write that stored the wrong thing shows up.
        let stage = mutate_phase(route);
        let mut again = b.blank(i, "after_writes", stage, who);
        again.sort_key = format!("3z/00/{}", route.path);
        b.push(again);
    }
    if has_params(&route.path) {
        let mut c = b.blank(i, "invalid_path", phase, who);
        c.path_override = Some(INVALID_ID.to_string());
        b.push(c);
    }
    if let Some(q) = invalid_query(b.src, route) {
        let mut c = b.blank(i, "invalid_query", phase, who);
        c.query = q;
        b.push(c);
    }
}

fn add_fixture_cases(b: &mut Builder) {
    let mut by_op = BTreeMap::new();
    for (i, r) in b.src.routes.iter().enumerate() {
        if let (Surface::ApiV2, Some(op)) = (r.surface, &r.op) {
            by_op.insert(op.id.clone(), i);
        }
    }
    let fixtures: Vec<Value> = b.src.fixtures.clone();
    for f in &fixtures {
        let name = f["name"].as_str().unwrap_or("unnamed");
        let what = format!("fixture {name}");
        let Some(op) = f["operation_id"].as_str() else {
            b.skip(what, "fixture has no contract operation");
            continue;
        };
        let Some(&route_idx) = by_op.get(op) else {
            b.skip(
                what,
                format!("operation {op} is not in the OpenAPI document"),
            );
            continue;
        };
        let req = &f["request"];
        let headers = req["headers"].as_object();
        let auth = headers
            .and_then(|h| h.get("Authorization"))
            .and_then(Value::as_str);
        let has_profile = headers.is_some_and(|h| h.contains_key("X-Profile-Id"));
        let identity = match (auth, has_profile) {
            (None, _) => Identity::Anon,
            (Some("Bearer tok-admin"), true) => Identity::Admin,
            (Some("Bearer tok-admin"), false) => Identity::AdminNoProfile,
            (Some("Bearer tok-member" | "Bearer sa_member"), true) => Identity::User,
            (Some("Bearer tok-member" | "Bearer sa_member"), false) => Identity::UserNoProfile,
            (Some(other), _) => {
                b.skip(
                    what,
                    format!("fixture principal {other} is not in the conformance seed"),
                );
                continue;
            }
        };
        if headers.is_some_and(|h| h.contains_key("Cookie")) {
            b.skip(what, "fixture depends on a cookie from its own session");
            continue;
        }
        let route = &b.src.routes[route_idx];
        let mutating = route.mutating();
        let phase = if mutating {
            mutate_phase(route)
        } else {
            Phase::Reads
        };
        let raw_path = req["path"].as_str().unwrap_or_default();
        let (path_only, query_text) = raw_path.split_once('?').unwrap_or((raw_path, ""));
        let mut c = b.blank(route_idx, &format!("fixture:{name}"), phase, identity);
        c.may_mutate = mutating;
        // Reads the activity log, which `activitylog.Consumer` writes every 2 seconds, for the address
        // the run's own requests come from when a run gives both servers one. Each side's counts and
        // order depend on which of its batches landed, so let them all land.
        if name == "admin_ip_users" {
            c.wait_ms = ACTIVITY_FLUSH_WAIT_MS;
        }
        // A not-found fixture's synthetic id is the point; everything else uses seed ids.
        if f["expected_status"].as_u64() == Some(404) {
            c.path = path_only.to_string();
        }
        c.query = query_text
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (k.to_string(), v.to_string())
            })
            .collect();
        c.headers = headers
            .into_iter()
            .flatten()
            .filter(|(k, _)| {
                !k.eq_ignore_ascii_case("authorization")
                    && !k.eq_ignore_ascii_case("x-profile-id")
                    && !k.eq_ignore_ascii_case("content-type")
            })
            .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
            .collect();
        if let Some(body) = req["body"].as_str() {
            c.body = Some(body.as_bytes().to_vec());
            c.content_type = Some(
                headers
                    .and_then(|h| h.get("Content-Type"))
                    .and_then(Value::as_str)
                    .unwrap_or("application/json")
                    .to_string(),
            );
        }
        if mutating {
            c.sort_key = mutation_sort_key(&route.method, &route.path, &format!("fixture:{name}"));
        }
        b.push(c);
    }
}

/// The same path with its trailing slash toggled: whether a router redirects, serves
/// or refuses it is behaviour clients hit, and no source lists it as a route.
fn add_slash_variants(b: &mut Builder) {
    for (i, route) in b.src.routes.iter().enumerate() {
        let path = route.path.as_str();
        if path == "/" || path.ends_with('*') || route.streams || route.websocket {
            continue;
        }
        let toggled = match path.strip_suffix('/') {
            Some(without) => without.to_string(),
            None => format!("{path}/"),
        };
        let mutating = route.mutating();
        // Anonymous for a write: it stops where the route's own anon case stops.
        let who = if mutating || route.handle_all {
            Identity::Anon
        } else {
            privileged(route)
        };
        let phase = if mutating {
            Phase::Rejections
        } else {
            Phase::Reads
        };
        let mut c = b.blank(i, "slash_variant", phase, who);
        c.path = toggled;
        b.push(c);
    }
}

/// A doc's concrete example of a templated route stays a request, on the route it illustrates: it is
/// not a row, but it is often the only value the handler answers with a success.
fn add_doc_examples(b: &mut Builder) {
    for ill in crate::sources::DOC_ILLUSTRATIONS {
        let Some(parent) = ill.parent else {
            b.skip(
                format!("jellycompat {} {}", ill.method, ill.path),
                ill.reason,
            );
            continue;
        };
        b.skip(
            format!("jellycompat {} {}", ill.method, ill.path),
            format!("{}; sent as a case of {parent}", ill.reason),
        );
        let key = (
            Surface::Jellycompat,
            ill.method.to_string(),
            parent.to_string(),
        );
        let Some(&i) = b.index.get(&key) else {
            continue;
        };
        let mut c = b.blank(
            i,
            &format!("doc_example:{}", ill.path),
            Phase::Reads,
            Identity::User,
        );
        c.path = ill.path.to_string();
        b.push(c);
    }
}

/// One credential spelled the ways real clients spell it. Sent with no identity, so
/// the spelling is the only thing authenticating the request.
/// Rows behind the native chain, each with its credential and profile refusals. A row in no such list
/// still gets the generated anonymous cases.
/// The contract's public operations in the native rows: they get the v2 guards' cases too.
const PUBLIC_V2_ROWS: &[&str] = &["/api/v2/openapi.json", "/api/v2/auth/device/capability"];

const CHAIN_ROWS: &[(Surface, &str, bool)] = &[
    (Surface::ApiV1, "/api/v1/notifications/", true),
    (Surface::ApiV1, "/api/v1/notifications/sync", true),
    (Surface::ApiV1, "/api/v1/notifications/unread-count", true),
    (Surface::ApiV1, "/api/v1/notifications/capability", true),
    (Surface::ApiV1, "/api/v1/notifications/preferences", true),
    (
        Surface::ApiV1,
        "/api/v1/notifications/email-preferences",
        true,
    ),
    (
        Surface::ApiV1,
        "/api/v1/notifications/discord-preferences",
        true,
    ),
    (Surface::ApiV1, "/api/v1/admin/stats", true),
    (Surface::ApiV1, "/api/v1/admin/stats/downloads", true),
    (
        Surface::ApiV1,
        "/api/v1/admin/stats/playback-activity",
        true,
    ),
    (Surface::ApiV1, "/api/v1/admin/stats/timeseries", true),
    (Surface::ApiV1, "/api/v1/admin/stats/top-activity", true),
    (Surface::ApiV2, "/api/v2/notifications", true),
    (Surface::ApiV2, "/api/v2/notifications/sync", true),
    (Surface::ApiV2, "/api/v2/notifications/unread-count", true),
    (Surface::ApiV2, "/api/v2/notifications/capabilities", true),
    (Surface::ApiV2, "/api/v2/notifications/preferences", true),
    (
        Surface::ApiV2,
        "/api/v2/notifications/email-preferences",
        true,
    ),
    (
        Surface::ApiV2,
        "/api/v2/notifications/discord-preferences",
        true,
    ),
    (Surface::ApiV2, "/api/v2/admin/stats", true),
    (Surface::ApiV2, "/api/v2/admin/stats/api-clients", true),
    (Surface::ApiV2, "/api/v2/admin/stats/downloads", true),
    (
        Surface::ApiV2,
        "/api/v2/admin/stats/playback-activity",
        true,
    ),
    (Surface::ApiV2, "/api/v2/admin/stats/timeseries", true),
    (Surface::ApiV2, "/api/v2/admin/stats/top-activity", true),
    (Surface::ApiV2, "/api/v2/admin/catalog/capabilities", true),
    (Surface::ApiV2, "/api/v2/catalog/search/capabilities", true),
    (Surface::ApiV2, "/api/v2/capabilities/trailers", true),
    (Surface::ApiV1, "/api/v1/notifications/webhooks/", true),
    (
        Surface::ApiV1,
        "/api/v1/notifications/web-push/subscriptions",
        true,
    ),
    (
        Surface::ApiV1,
        "/api/v1/admin/notifications/server-channels/",
        true,
    ),
    (Surface::ApiV2, "/api/v2/notifications/webhooks", true),
    (
        Surface::ApiV2,
        "/api/v2/notifications/web-push/subscriptions",
        true,
    ),
    (
        Surface::ApiV2,
        "/api/v2/admin/notifications/server-channels",
        true,
    ),
    (
        Surface::ApiV2,
        "/api/v2/notifications/push/devices/capabilities",
        true,
    ),
    (
        Surface::ApiV2,
        "/api/v2/devices/push/apple/capabilities",
        true,
    ),
    (Surface::ApiV1, "/api/v1/requests/mine", true),
    (Surface::ApiV1, "/api/v1/admin/requests", true),
    (Surface::ApiV1, "/api/v1/admin/request-integrations", true),
    (Surface::ApiV2, "/api/v2/requests/mine", true),
    (Surface::ApiV2, "/api/v2/requests/status", true),
    (Surface::ApiV2, "/api/v2/admin/requests", true),
    (Surface::ApiV2, "/api/v2/admin/requests/counts", true),
    (Surface::ApiV2, "/api/v2/admin/request-routes", true),
    (Surface::ApiV2, "/api/v2/admin/request-integrations", true),
    (
        Surface::ApiV2,
        "/api/v2/admin/libraries/{library_id}/collection-groups",
        true,
    ),
    (
        Surface::ApiV2,
        "/api/v2/admin/libraries/{library_id}/collection-groups/order",
        true,
    ),
    (Surface::ApiV1, "/api/v1/collections/capabilities", true),
    (Surface::ApiV1, "/api/v1/collections/templates", true),
    (Surface::ApiV1, "/api/v1/admin/collections/templates", true),
    (
        Surface::ApiV1,
        "/api/v1/admin/collections/template-bundles",
        true,
    ),
    (Surface::ApiV2, "/api/v2/collections/capabilities", true),
    (Surface::ApiV2, "/api/v2/collections/templates", true),
    (Surface::ApiV2, "/api/v2/collections/groups/order", true),
    (Surface::ApiV2, "/api/v2/collections/order", true),
    (Surface::ApiV2, "/api/v2/admin/collections/templates", true),
    (
        Surface::ApiV2,
        "/api/v2/admin/collections/template-bundles",
        true,
    ),
    (Surface::ApiV1, "/api/v1/auth/me", false),
    (Surface::ApiV1, "/api/v1/auth/account/capability", true),
    (Surface::ApiV1, "/api/v1/images/capability", true),
    (Surface::ApiV2, "/api/v2/account/me", false),
    (Surface::ApiV2, "/api/v2/account/password/capability", true),
    (Surface::ApiV2, "/api/v2/images/capabilities", true),
    (Surface::ApiV2, "/api/v2/user/libraries/capabilities", true),
    (Surface::ApiV1, "/api/v1/auth/sessions", false),
    (Surface::ApiV2, "/api/v2/auth/sessions", false),
    (Surface::ApiV2, "/api/v2/auth/sessions/capabilities", false),
    (Surface::ApiV1, "/api/v1/api-keys/", false),
    (Surface::ApiV1, "/api/v1/api-keys/scopes", false),
    (Surface::ApiV2, "/api/v2/api-keys", false),
    (Surface::ApiV2, "/api/v2/api-keys/scopes", false),
    (Surface::ApiV1, "/api/v1/admin/api-keys", true),
    (Surface::ApiV2, "/api/v2/admin/api-keys", true),
    (Surface::ApiV2, "/api/v2/admin/api-keys/capabilities", true),
    (Surface::ApiV1, "/api/v1/settings/", true),
    (Surface::ApiV1, "/api/v1/settings/overlay-config", true),
    (Surface::ApiV1, "/api/v1/settings/contract", true),
    (Surface::ApiV2, "/api/v2/settings/contract", true),
    (Surface::ApiV2, "/api/v2/settings/overlay-config", true),
    (Surface::ApiV1, "/api/v1/profiles/", true),
    (Surface::ApiV2, "/api/v2/profiles", true),
    (Surface::ApiV1, "/api/v1/admin/settings", true),
    (Surface::ApiV2, "/api/v2/admin/settings", true),
    (Surface::ApiV1, "/api/v1/libraries/", true),
    (
        Surface::ApiV1,
        "/api/v1/libraries/metadata-match-queue",
        true,
    ),
    (Surface::ApiV1, "/api/v1/libraries/provider-defaults", true),
    (Surface::ApiV1, "/api/v1/libraries/roots", true),
    (Surface::ApiV1, "/api/v1/libraries/skipped-roots", true),
    (Surface::ApiV1, "/api/v1/libraries/stale-ids", true),
    (Surface::ApiV1, "/api/v1/libraries/unmatched-items", true),
    (
        Surface::ApiV1,
        "/api/v1/libraries/{id}/metadata-match-queue",
        true,
    ),
    (Surface::ApiV1, "/api/v1/libraries/{id}/providers", true),
    (Surface::ApiV1, "/api/v1/library-playback-prefs/", true),
    (Surface::ApiV1, "/api/v1/library/{id}/layout", true),
    (Surface::ApiV1, "/api/v1/user/libraries", true),
    (Surface::ApiV2, "/api/v2/libraries", true),
    (Surface::ApiV2, "/api/v2/libraries/capabilities", true),
    (
        Surface::ApiV2,
        "/api/v2/libraries/metadata-match-queue",
        true,
    ),
    (Surface::ApiV2, "/api/v2/libraries/provider-defaults", true),
    (
        Surface::ApiV2,
        "/api/v2/libraries/realtime-monitoring",
        true,
    ),
    (Surface::ApiV2, "/api/v2/libraries/roots", true),
    (Surface::ApiV2, "/api/v2/libraries/skipped-roots", true),
    (Surface::ApiV2, "/api/v2/libraries/stale-ids", true),
    (Surface::ApiV2, "/api/v2/libraries/unmatched-items", true),
    (
        Surface::ApiV2,
        "/api/v2/libraries/{id}/metadata-match-queue",
        true,
    ),
    (Surface::ApiV2, "/api/v2/libraries/{id}/providers", true),
    (Surface::ApiV2, "/api/v2/library-jobs/{job_id}", true),
    (Surface::ApiV2, "/api/v2/library-playback-prefs", true),
    (Surface::ApiV2, "/api/v2/library/{id}/layout", true),
    (Surface::ApiV2, "/api/v2/user/libraries", true),
    (Surface::ApiV1, "/api/v1/ratings/", true),
    (Surface::ApiV1, "/api/v1/progress/", true),
    (Surface::ApiV1, "/api/v1/devices/", true),
    (Surface::ApiV2, "/api/v2/ratings", true),
    (Surface::ApiV2, "/api/v2/audio-prefs/{series_id}", true),
    (Surface::ApiV2, "/api/v2/subtitle-prefs/{series_id}", true),
    (Surface::ApiV2, "/api/v2/downloads/subscriptions", true),
    (Surface::ApiV2, "/api/v2/downloads/subscriptions/{id}", true),
    (Surface::ApiV2, "/api/v2/progress", true),
    (Surface::ApiV2, "/api/v2/devices", true),
    (Surface::ApiV2, "/api/v2/capabilities/personal-lists", true),
    (Surface::ApiV2, "/api/v2/capabilities/not-interested", true),
    (Surface::ApiV2, "/api/v2/progress/capabilities", true),
    (Surface::ApiV2, "/api/v2/home/capabilities", true),
];

/// `queryGuard`, Huma's unknown-parameter refusal, and the v2 representation guards.
fn add_v2_guards(b: &mut Builder, i: usize, identity: Identity) {
    let query = |name: &str, spelled: &str, b: &mut Builder| {
        let mut c = b.blank(i, &format!("chain:query_{name}"), Phase::Reads, identity);
        c.raw_query = Some(spelled.to_string());
        b.push(c);
    };
    query("unknown", "nope=1", b);
    query("empty_key", "=1", b);
    query("empty_pairs", "&&", b);
    query("bad_percent", "nope=%zz", b);
    query("bad_percent_key", "%zz=1", b);
    query("semicolon", "a=1;b=2", b);
    query("plus_key", "a+b=1", b);
    query("token", "token=not.a.token", b);
    let headers: [(&str, &str, &str); 5] = [
        ("accept_unacceptable", "Accept", "text/plain"),
        ("accept_q0", "Accept", "application/json;q=0"),
        ("identity_forbidden", "Accept-Encoding", "identity;q=0"),
        ("star_forbidden", "Accept-Encoding", "*;q=0"),
        ("request_encoded", "Content-Encoding", "gzip"),
    ];
    for (name, header, value) in headers {
        let mut c = b.blank(i, &format!("chain:{name}"), Phase::Reads, identity);
        c.headers.push((header.to_string(), value.to_string()));
        b.push(c);
    }
}

/// Library jobs the seed holds (`normalize.sql`), one of each state a poll reports. A plan run's own jobs
/// race the workers that finish them, so only terminal ones can be compared.
fn add_seeded_library_jobs(b: &mut Builder) {
    const PATH: &str = "/api/v2/library-jobs/{job_id}";
    let Some(&i) = b
        .index
        .get(&(Surface::ApiV2, "GET".to_string(), PATH.to_string()))
    else {
        return;
    };
    for job in [
        "01CONF0RMANCEJ0B000000REFR",
        "01CONF0RMANCEJ0B000000FAIL",
        "01CONF0RMANCEJ0B000000DELE",
    ] {
        let mut c = b.blank(i, &format!("seeded:{job}"), Phase::Reads, Identity::Admin);
        c.path = format!("/api/v2/library-jobs/{job}");
        b.push(c);
    }
}

fn add_native_chain_refusals(b: &mut Builder) {
    add_seeded_library_jobs(b);
    const NO_SUCH_PROFILE: &str = "c0f00000-0000-4000-8000-0000000000ff";
    for path in PUBLIC_V2_ROWS {
        match b
            .index
            .get(&(Surface::ApiV2, "GET".to_string(), path.to_string()))
        {
            Some(&i) => add_v2_guards(b, i, Identity::Anon),
            None => b.skip(
                format!("api_v2 GET {path}"),
                "chain row is not in the sources",
            ),
        }
    }
    for &(surface, path, viewer) in CHAIN_ROWS {
        let Some(&i) = b.index.get(&(surface, "GET".to_string(), path.to_string())) else {
            b.skip(
                format!("{} GET {path}", surface.name()),
                "chain row is not in the sources",
            );
            continue;
        };
        if surface == Surface::ApiV2 {
            add_v2_guards(b, i, Identity::User);
        }
        let credentials = [
            ("anonymous", Identity::Anon, None),
            ("malformed_scheme", Identity::Anon, Some("Basic abc")),
            ("empty_bearer", Identity::Anon, Some("Bearer ")),
            ("wrong_token", Identity::Anon, Some("Bearer not.a.token")),
            (
                "wrong_api_key",
                Identity::Anon,
                Some("Bearer sa_0000000000"),
            ),
            ("api_key", Identity::Anon, Some("Bearer ${user_api_key}")),
        ];
        for (name, identity, authorization) in credentials {
            let mut c = b.blank(i, &format!("chain:{name}"), Phase::Reads, identity);
            if let Some(value) = authorization {
                c.headers
                    .push(("Authorization".to_string(), value.to_string()));
            }
            b.push(c);
        }
        let mut c = b.blank(i, "chain:query_token_refused", Phase::Reads, Identity::Anon);
        c.query
            .push(("token".to_string(), "not.a.token".to_string()));
        b.push(c);
        let profiles = [
            ("wrong_profile", Identity::UserJwt, NO_SUCH_PROFILE),
            (
                "wrong_profile_api_key",
                Identity::UserNoProfile,
                NO_SUCH_PROFILE,
            ),
            (
                "other_account_profile",
                Identity::UserJwt,
                "${admin_profile_id}",
            ),
            ("not_a_uuid_profile", Identity::UserJwt, "nope"),
        ];
        for (name, identity, profile) in profiles {
            let mut c = b.blank(i, &format!("chain:{name}"), Phase::Reads, identity);
            c.headers
                .push(("X-Profile-Id".to_string(), profile.to_string()));
            b.push(c);
        }
        // Without viewer access on the row, a named profile is not judged; these still run above.
        let _ = viewer;
        let c = b.blank(i, "chain:admin", Phase::Reads, Identity::AdminJwt);
        b.push(c);
        let c = b.blank(i, "chain:kid_profile", Phase::Reads, Identity::Kid);
        b.push(c);
        let mut c = b.blank(
            i,
            "chain:device_header_repeated",
            Phase::Reads,
            Identity::User,
        );
        c.headers
            .push(("X-Silo-Device-Id".to_string(), "a,b".to_string()));
        b.push(c);
    }
}

fn add_auth_variants(b: &mut Builder) {
    let mut turn = 0usize;
    for (i, route) in b.src.routes.iter().enumerate() {
        let eligible = route.surface == Surface::Jellycompat
            && route.method == "GET"
            && !route.streams
            && !route.websocket
            && !route.handle_all;
        if !eligible {
            continue;
        }
        let variants: Vec<_> = if route.path == JF_AUTH_ROUTE {
            JF_AUTH_VARIANTS.iter().collect()
        } else {
            turn += 1;
            vec![&JF_AUTH_VARIANTS[turn % JF_AUTH_VARIANTS.len()]]
        };
        for (name, headers, query) in variants {
            let mut c = b.blank(
                i,
                &format!("auth_variant:{name}"),
                Phase::Reads,
                Identity::Anon,
            );
            let fill = |v: &str| v.replace("${token}", "${jf_token_user}");
            c.headers
                .extend(headers.iter().map(|(k, v)| (k.to_string(), fill(v))));
            c.query
                .extend(query.iter().map(|(k, v)| (k.to_string(), fill(v))));
            b.push(c);
        }
    }
    let native_key = "${user_api_key}";
    let native = [
        ("lowercase_bearer", format!("bearer {native_key}")),
        ("uppercase_bearer", format!("BEARER {native_key}")),
    ];
    let targets = [
        (Surface::ApiV2, "/api/v2/account/me"),
        (Surface::ApiV1, "/api/v1/auth/me"),
    ];
    for (surface, path) in targets {
        let Some(&i) = b.index.get(&(surface, "GET".to_string(), path.to_string())) else {
            b.skip(
                format!("{} GET {path}", surface.name()),
                "route for auth spellings is not in the sources",
            );
            continue;
        };
        for (name, value) in &native {
            let mut c = b.blank(
                i,
                &format!("auth_variant:{name}"),
                Phase::Reads,
                Identity::Anon,
            );
            c.headers.push(("Authorization".to_string(), value.clone()));
            c.headers
                .push(("X-Profile-Id".to_string(), "${user_profile_id}".to_string()));
            b.push(c);
        }
    }
    for path in ["/api/me", "/abs/api/me"] {
        let key = (Surface::Abs, "GET".to_string(), path.to_string());
        let Some(&i) = b.index.get(&key) else {
            continue;
        };
        for (name, value) in [
            ("lowercase_bearer", "bearer ${abs_token_user}"),
            ("uppercase_bearer", "BEARER ${abs_token_user}"),
        ] {
            let mut c = b.blank(
                i,
                &format!("auth_variant:{name}"),
                Phase::Reads,
                Identity::Anon,
            );
            c.headers
                .push(("Authorization".to_string(), value.to_string()));
            b.push(c);
        }
    }
}

/// Generated bodies do not get past a compatibility login, and clients do everything
/// after one, so these are spelled out.
fn add_compat_logins(b: &mut Builder) {
    let jf = "{\"Username\":\"${member_username}#Conf User\",\"Pw\":\"${member_password}\"}";
    let native = "{\"username\":\"${member_username}\",\"password\":\"${member_password}\"}";
    #[allow(clippy::type_complexity)]
    let logins: [(Surface, &str, &str, Vec<(String, String)>); 3] = [
        (
            Surface::Jellycompat,
            "/Users/AuthenticateByName",
            jf,
            vec![(
                "X-Emby-Authorization".to_string(),
                "MediaBrowser Client=\"conformance\", Device=\"harness\", DeviceId=\"conformance-1\", Version=\"1.0\"".to_string(),
            )],
        ),
        (Surface::Abs, "/login", native, vec![]),
        (Surface::Abs, "/abs/login", native, vec![]),
    ];
    for (surface, path, body, headers) in logins {
        let key = (surface, "POST".to_string(), path.to_string());
        let Some(&idx) = b.index.get(&key) else {
            b.skip(
                format!("{} POST {path}", surface.name()),
                "login route is not in the sources",
            );
            continue;
        };
        let mut c = b.blank(idx, "login", Phase::MutateCompat, Identity::Anon);
        c.headers = headers;
        c.body = Some(body.as_bytes().to_vec());
        c.content_type = Some("application/json".to_string());
        c.may_mutate = true;
        c.sort_key = format!("0/{path}");
        b.push(c);
    }
}

/// The peer lab's clients: `scripts/peer-lab.sh` gives each its own address on both sides.
const UNTRUSTED_A: &str = "untrusted_a";
const UNTRUSTED_B: &str = "untrusted_b";
const TRUSTED_A: &str = "trusted_a";
const TRUSTED_B: &str = "trusted_b";

fn header_list(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

struct PeerCase<'a> {
    surface: Surface,
    method: &'a str,
    path: &'a str,
    name: String,
    source: &'a str,
    identity: Identity,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    body: Option<&'a str>,
    host: Option<&'a str>,
    settle_on: Option<&'a str>,
    path_override: Option<&'a str>,
}

impl PeerCase<'_> {
    fn new<'a>(surface: Surface, method: &'a str, path: &'a str) -> PeerCase<'a> {
        PeerCase {
            surface,
            method,
            path,
            name: String::new(),
            source: "",
            identity: Identity::Anon,
            headers: Vec::new(),
            query: Vec::new(),
            body: None,
            host: None,
            settle_on: None,
            path_override: None,
        }
    }
}

fn push_peer(b: &mut Builder, peer: PeerCase) {
    let key = (peer.surface, peer.method.to_string(), peer.path.to_string());
    let Some(&idx) = b.index.get(&key) else {
        b.skip(
            format!("{} {} {}", peer.surface.name(), peer.method, peer.path),
            "peer case's route is not in the sources",
        );
        return;
    };
    let seq = b.cases.iter().filter(|c| c.phase == Phase::Peers).count();
    let name = format!("peer:{}:{}", peer.source, peer.name);
    let mut c = b.blank(idx, &name, Phase::Peers, peer.identity);
    c.headers.extend(peer.headers);
    // A value the case names replaces the example a required parameter was filled with.
    c.query
        .retain(|(k, _)| !peer.query.iter().any(|(q, _)| q == k));
    c.query.extend(peer.query);
    c.path_override = peer.path_override.map(str::to_string);
    if let Some(body) = peer.body {
        c.body = Some(body.as_bytes().to_vec());
        c.content_type = Some("application/json".to_string());
    }
    c.source = Some(peer.source.to_string());
    c.host = peer.host.map(str::to_string);
    c.settle_on = peer.settle_on.map(str::to_string);
    c.sort_key = format!("{seq:06}");
    b.push(c);
}

/// What only a real source address can show. The rest of the plan goes through one peer, so it cannot
/// see a relay turning every client into a trusted peer: whether forwarding headers count, who the
/// client is, and which buckets and grants are kept per client.
fn add_peer_cases(b: &mut Builder) {
    add_peer_origin_cases(b);
    add_peer_client_cases(b);
    add_peer_activity_cases(b);
    add_peer_rate_limit_cases(b);
    add_peer_stream_grant_cases(b);
    add_peer_base_url_cases(b);
    add_peer_native_cases(b);
}

/// `request_origin` takes forwarded scheme and host only from a trusted peer.
fn add_peer_origin_cases(b: &mut Builder) {
    let variants: [(&str, &[(&str, &str)]); 7] = [
        ("plain", &[]),
        ("host", &[("X-Forwarded-Host", "spoof.conformance.test")]),
        ("proto", &[("X-Forwarded-Proto", "https")]),
        (
            "host_and_proto",
            &[
                ("X-Forwarded-Host", "spoof.conformance.test"),
                ("X-Forwarded-Proto", "https"),
            ],
        ),
        (
            "host_list",
            &[("X-Forwarded-Host", "a.conformance.test, b.conformance.test")],
        ),
        (
            "proto_two_lines",
            &[
                ("X-Forwarded-Proto", "http"),
                ("X-Forwarded-Proto", "https"),
            ],
        ),
        ("proto_unknown", &[("X-Forwarded-Proto", "ftp")]),
    ];
    for source in [UNTRUSTED_A, TRUSTED_A] {
        for (name, headers) in variants {
            let mut c = PeerCase::new(Surface::ApiV2, "GET", "/api/v2/system/info");
            c.name = format!("origin:{name}");
            c.source = source;
            c.headers = header_list(headers);
            push_peer(b, c);
        }
    }
}

/// A Jellyfin login answers with the client address Go resolved (`SessionInfo.RemoteEndPoint`), so
/// each branch of `resolver.resolve` is compared directly, from both kinds of peer.
fn add_peer_client_cases(b: &mut Builder) {
    let variants: [(&str, &[(&str, &str)]); 14] = [
        ("plain", &[]),
        ("xff", &[("X-Forwarded-For", "198.51.100.7")]),
        (
            "xff_chain",
            &[("X-Forwarded-For", "198.51.100.7, 198.51.100.8")],
        ),
        (
            "xff_client_then_private",
            &[("X-Forwarded-For", "198.51.100.7, 10.1.2.3")],
        ),
        (
            "xff_all_private",
            &[("X-Forwarded-For", "10.1.2.3, 10.1.2.4")],
        ),
        ("xff_junk", &[("X-Forwarded-For", "junk")]),
        (
            "xff_junk_then_client",
            &[("X-Forwarded-For", "junk, 198.51.100.7")],
        ),
        (
            "xff_two_lines",
            &[
                ("X-Forwarded-For", "198.51.100.7"),
                ("X-Forwarded-For", "198.51.100.8"),
            ],
        ),
        ("xff_blank", &[("X-Forwarded-For", " , ")]),
        ("xff_v6_port", &[("X-Forwarded-For", "[2001:db8::1]:1234")]),
        ("real_ip", &[("X-Real-IP", "198.51.100.9")]),
        (
            "real_ip_two_lines",
            &[
                ("X-Real-IP", "198.51.100.9"),
                ("X-Real-IP", "198.51.100.10"),
            ],
        ),
        ("forwarded", &[("Forwarded", "for=198.51.100.11")]),
        (
            "xff_and_real_ip",
            &[
                ("X-Forwarded-For", "198.51.100.7"),
                ("X-Real-IP", "198.51.100.9"),
            ],
        ),
    ];
    let auth = (
        "X-Emby-Authorization",
        "MediaBrowser Client=\"conformance\", Device=\"harness\", DeviceId=\"conformance-peer\", Version=\"1.0\"",
    );
    for source in [UNTRUSTED_A, TRUSTED_A] {
        for (name, headers) in variants {
            let mut c = PeerCase::new(Surface::Jellycompat, "POST", "/Users/AuthenticateByName");
            c.name = format!("client:{name}");
            c.source = source;
            c.headers = header_list(&[auth]);
            c.headers.extend(header_list(headers));
            c.body = Some(
                "{\"Username\":\"${member_username}#Conf User\",\"Pw\":\"${member_password}\"}",
            );
            push_peer(b, c);
        }
    }
}

/// The address the activity log files a request under, read back the way an administrator does.
fn add_peer_activity_cases(b: &mut Builder) {
    let spoofs = [(UNTRUSTED_A, "198.51.100.31"), (TRUSTED_A, "198.51.100.32")];
    for (source, xff) in spoofs {
        let mut c = PeerCase::new(Surface::ApiV2, "GET", "/api/v2/account/me");
        c.name = "activity:spoof".to_string();
        c.source = source;
        c.identity = Identity::User;
        c.headers = header_list(&[("X-Forwarded-For", xff)]);
        push_peer(b, c);
    }
    for source in [UNTRUSTED_B, TRUSTED_B] {
        let mut c = PeerCase::new(Surface::ApiV2, "GET", "/api/v2/account/me");
        c.name = "activity:plain".to_string();
        c.source = source;
        c.identity = Identity::User;
        push_peer(b, c);
    }
    // The last request above was sent last, so once it shows the batch holding the others was written.
    let settle = "/api/v2/admin/ips?ip=${ip_trusted_b}";
    for (name, ip) in [
        ("untrusted_spoof", "198.51.100.31"),
        ("trusted_spoof", "198.51.100.32"),
        ("untrusted_b", "${ip_untrusted_b}"),
        ("trusted_b", "${ip_trusted_b}"),
    ] {
        let mut c = PeerCase::new(Surface::ApiV2, "GET", "/api/v2/admin/ips");
        c.name = format!("activity:read:{name}");
        c.source = TRUSTED_A;
        c.identity = Identity::Admin;
        c.query = vec![("ip".to_string(), ip.to_string())];
        c.settle_on = Some(settle);
        push_peer(b, c);
    }
}

/// Buckets are per client, and every client behind one trusted peer also shares that peer's looser
/// budget. Through a relay that gives each client its own peer, one client must not spend another's.
/// A password reset request has the budget to use here: the seed leaves it at the default, 3 per client
/// and 30 per peer, and refills a peer's token only every 1.2 seconds, so a run this short does not race
/// the refill. The seed has no mail configured, so nothing is sent.
fn add_peer_rate_limit_cases(b: &mut Builder) {
    let request = |b: &mut Builder, source: &str, name: String, xff: Option<String>| {
        let mut c = PeerCase::new(Surface::ApiV2, "POST", "/api/v2/password-resets");
        c.name = format!("auth_limit:{name}");
        c.source = source;
        c.body = Some("{\"login\":\"no-such-user\"}");
        if let Some(xff) = xff {
            c.headers = vec![("X-Forwarded-For".to_string(), xff)];
        }
        push_peer(b, c);
    };
    // An untrusted client cannot buy new budgets by naming new clients.
    for i in 0..6 {
        request(
            b,
            UNTRUSTED_A,
            format!("rotating:{i:03}"),
            Some(format!("198.51.101.{}", i + 1)),
        );
    }
    request(b, UNTRUSTED_B, "other_source".to_string(), None);
    // One client behind a trusted peer spends its own budget, whichever peer it comes through.
    for i in 0..6 {
        request(
            b,
            TRUSTED_A,
            format!("one_client:{i:03}"),
            Some("198.51.102.1".to_string()),
        );
    }
    request(
        b,
        TRUSTED_B,
        "one_client_other_peer".to_string(),
        Some("198.51.102.1".to_string()),
    );
    // Many clients behind one trusted peer run out of that peer's budget, and only that peer's.
    for i in 0..34 {
        request(
            b,
            TRUSTED_A,
            format!("peer_budget:{i:03}"),
            Some(format!("198.51.103.{}", i + 1)),
        );
    }
    for i in 0..3 {
        request(
            b,
            TRUSTED_B,
            format!("other_peer_budget:{i:03}"),
            Some(format!("198.51.104.{}", i + 1)),
        );
    }

    // The Audiobookshelf limiter keys on the transport peer alone. Each attempt names a new account,
    // because a second limiter counts failures per name.
    let abs = |b: &mut Builder, source: &str, name: String, xff: Option<String>| {
        let mut c = PeerCase::new(Surface::Abs, "POST", "/login");
        let account = format!("no-such-user-{source}-{name}").replace(':', "-");
        let body = format!("{{\"username\":\"{account}\",\"password\":\"wrong\"}}");
        c.name = format!("abs_limit:{name}");
        c.source = source;
        if let Some(xff) = xff {
            c.headers = vec![("X-Forwarded-For".to_string(), xff)];
        }
        c.body = Some(&body);
        push_peer(b, c);
    };
    for source in [UNTRUSTED_A, TRUSTED_A] {
        for i in 0..12 {
            abs(
                b,
                source,
                format!("rotating:{i:03}"),
                Some(format!("198.51.105.{}", i + 1)),
            );
        }
    }
    abs(b, UNTRUSTED_B, "other_source".to_string(), None);
    abs(b, TRUSTED_B, "other_source".to_string(), None);
}

/// A Jellyfin negotiation grants credential-less static streams to the address and path it came from.
fn add_peer_stream_grant_cases(b: &mut Builder) {
    let auth = |b: &mut Builder, source: &str, name: &str, xff: Option<&str>| {
        let mut c = PeerCase::new(Surface::Jellycompat, "POST", "/Items/{id}/PlaybackInfo");
        c.name = format!("grant:{name}");
        c.source = source;
        c.identity = Identity::User;
        c.headers = xff.map_or_else(Vec::new, |x| header_list(&[("X-Forwarded-For", x)]));
        c.body = Some("{}");
        push_peer(b, c);
    };
    let stream = |b: &mut Builder, source: &str, name: &str, xff: Option<&str>| {
        let mut c = PeerCase::new(Surface::Jellycompat, "GET", "/Videos/{id}/stream");
        c.name = format!("grant:{name}");
        c.source = source;
        c.query = vec![
            ("Static".to_string(), "true".to_string()),
            (
                "MediaSourceId".to_string(),
                "${jf_media_source_id}".to_string(),
            ),
        ];
        c.headers = xff.map_or_else(Vec::new, |x| header_list(&[("X-Forwarded-For", x)]));
        push_peer(b, c);
    };
    // Negotiated by a client connecting directly: only that address may stream.
    auth(b, UNTRUSTED_A, "negotiate_direct", None);
    stream(b, UNTRUSTED_A, "same_client", None);
    stream(
        b,
        UNTRUSTED_A,
        "same_client_spoofing",
        Some("198.51.100.40"),
    );
    stream(b, UNTRUSTED_B, "other_client", None);
    stream(
        b,
        UNTRUSTED_B,
        "other_client_claiming",
        Some("${ip_untrusted_a}"),
    );
    stream(
        b,
        TRUSTED_A,
        "proxy_claiming_direct_client",
        Some("${ip_untrusted_a}"),
    );
    // Negotiated through a proxy: another proxy may carry the same client, nobody else may.
    auth(b, TRUSTED_A, "negotiate_proxied", Some("198.51.100.41"));
    stream(
        b,
        TRUSTED_A,
        "same_proxy_same_client",
        Some("198.51.100.41"),
    );
    stream(
        b,
        TRUSTED_B,
        "other_proxy_same_client",
        Some("198.51.100.41"),
    );
    stream(
        b,
        TRUSTED_A,
        "same_proxy_other_client",
        Some("198.51.100.42"),
    );
    stream(b, TRUSTED_A, "the_proxy_itself", None);
    stream(
        b,
        UNTRUSTED_B,
        "untrusted_claiming_proxied_client",
        Some("198.51.100.41"),
    );
}

/// The speed test URL reads forwarding headers directly and asks whether Host is an address. Every
/// request through a relay carries a forwarding header, which must not change the answer.
fn add_peer_base_url_cases(b: &mut Builder) {
    type Variant<'a> = (&'a str, Option<&'a str>, &'a [(&'a str, &'a str)]);
    let variants: [Variant; 7] = [
        ("name", None, &[]),
        ("ip_host", Some("192.0.2.50:8080"), &[]),
        ("ip_host_no_port", Some("192.0.2.50"), &[]),
        ("v6_host", Some("[2001:db8::50]:8080"), &[]),
        (
            "ip_host_xff",
            Some("192.0.2.50:8080"),
            &[("X-Forwarded-For", "198.51.100.50")],
        ),
        (
            "ip_host_blank_xff",
            Some("192.0.2.50:8080"),
            &[("X-Forwarded-For", " , ")],
        ),
        (
            "ip_host_forwarded_host",
            Some("192.0.2.50:8080"),
            &[("X-Forwarded-Host", "spoof.conformance.test")],
        ),
    ];
    for source in [UNTRUSTED_A, TRUSTED_A] {
        for (name, host, headers) in variants {
            let mut c = PeerCase::new(Surface::ApiV2, "GET", "/api/v2/playback/capabilities");
            c.name = format!("base_url:{name}");
            c.source = source;
            c.identity = Identity::User;
            c.host = host;
            c.headers = header_list(headers);
            push_peer(b, c);
        }
        let mut c = PeerCase::new(Surface::ApiV2, "GET", "/api/v2/playback/capabilities");
        c.name = "base_url:proto".to_string();
        c.source = source;
        c.identity = Identity::User;
        c.headers = header_list(&[("X-Forwarded-Proto", "https")]);
        push_peer(b, c);
    }
}

/// Rows the front answers itself must not care who is asking or what they claim.
fn add_peer_native_cases(b: &mut Builder) {
    let headers: &[(&str, &str)] = &[
        ("X-Forwarded-For", "198.51.100.60"),
        ("X-Forwarded-Host", "spoof.conformance.test"),
        ("X-Forwarded-Proto", "https"),
        ("X-Real-IP", "198.51.100.61"),
    ];
    for source in [UNTRUSTED_A, TRUSTED_A] {
        for (surface, path) in [
            (Surface::ApiV1, "/api/v1/health"),
            (Surface::ApiV2, "/api/v2/openapi.json"),
            (Surface::ApiV2, "/api/v2/docs"),
            (Surface::Root, "/"),
        ] {
            let mut c = PeerCase::new(surface, "GET", path);
            c.name = "native:spoof".to_string();
            c.source = source;
            c.headers = header_list(headers);
            push_peer(b, c);
        }
    }
}

fn placeholders(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$\{([a-zA-Z_]+)(?::int)?\}").unwrap())
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect()
}

fn scenario_identity(principal: &Value) -> Result<Identity, String> {
    if principal.get("user").is_some() || principal.get("profile").is_some() {
        return Err("names a fixture account or profile the seed lacks".to_string());
    }
    if principal.get("verified").is_some() || principal.get("scopes").is_some() {
        return Err("needs a PIN-verified profile or a scoped key".to_string());
    }
    Ok(match principal["class"].as_str().unwrap_or_default() {
        "public" => Identity::Anon,
        "authenticated" => Identity::UserJwt,
        "profile" | "primary_profile" | "api_key" => Identity::User,
        "child_profile" => Identity::Kid,
        "admin" => Identity::AdminJwt,
        "acting_admin" => Identity::Admin,
        other => return Err(format!("principal class {other} is not in the seed")),
    })
}

/// One exchange of a scenario: `principal` + `request`, as the primary step or a `then`.
#[allow(clippy::too_many_arguments)]
fn scenario_step(
    b: &mut Builder,
    route_idx: usize,
    name: &str,
    method: &str,
    principal: &Value,
    req: &Value,
    phase: Phase,
    sort_key: &str,
) -> Result<Case, String> {
    let mut identity = scenario_identity(principal)?;
    for key in ["body_ref", "multipart", "repeat"] {
        if req.get(key).is_some() {
            return Err(format!("uses {key}"));
        }
    }
    let path = req["path"].as_str().ok_or("no request path")?;
    let mut c = b.blank(route_idx, name, phase, identity);
    c.method = method.to_string();
    c.path = path.to_string();
    c.query = req["query"]
        .as_object()
        .map(|q| {
            q.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    c.headers = Vec::new();
    for (k, v) in req["headers"].as_object().into_iter().flatten() {
        match v.as_str() {
            Some(val) => c.headers.push((k.clone(), val.to_string())),
            None if k.eq_ignore_ascii_case("x-profile-id") => {
                identity = match identity {
                    Identity::User | Identity::UserJwt => Identity::UserNoProfile,
                    Identity::Admin | Identity::AdminJwt => Identity::AdminNoProfile,
                    other => other,
                };
                c.identity = identity;
            }
            None => return Err(format!("removes header {k}")),
        }
    }
    if let Some(body) = req.get("body") {
        c.body = Some(body.to_string().into_bytes());
        c.content_type = Some("application/json".to_string());
    }
    if let Some(raw) = req["raw_body"].as_str() {
        c.body = Some(raw.as_bytes().to_vec());
    }
    if let Some(ct) = req["content_type"].as_str() {
        c.content_type = Some(ct.to_string());
    }
    c.may_mutate = is_mutating(method);
    c.sort_key = sort_key.to_string();
    let mut all = String::from(path);
    all.push_str(&req.to_string());
    for p in placeholders(&all) {
        if !SCENARIO_FACTS.contains(&p.as_str()) {
            return Err(format!("needs fixture value {p}"));
        }
    }
    Ok(c)
}

fn path_matches_template(template: &str, path: &str) -> bool {
    let (a, b): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    a.len() == b.len() && a.iter().zip(&b).all(|(t, p)| t.starts_with('{') || t == p)
}

fn add_scenario_cases(b: &mut Builder) {
    let catalogs: Vec<Value> = b.src.scenarios.clone();
    let mut seq = 0usize;
    for catalog in &catalogs {
        for row in catalog["rows"].as_array().into_iter().flatten() {
            let (Some(method), Some(path)) = (row["method"].as_str(), row["path"].as_str()) else {
                continue;
            };
            let key = (Surface::ApiV1, method.to_string(), path.to_string());
            let Some(&route_idx) = b.index.get(&key) else {
                b.skip(
                    format!("scenario row {method} {path}"),
                    "not an /api/v1 inventory route",
                );
                continue;
            };
            for sc in row["scenarios"].as_array().into_iter().flatten() {
                seq += 1;
                add_scenario(b, route_idx, method, sc, seq);
            }
        }
    }
}

fn add_scenario(b: &mut Builder, route_idx: usize, method: &str, sc: &Value, seq: usize) {
    let id = sc["id"].as_str().unwrap_or("unnamed");
    let what = format!("scenario {id}");
    let requires: Vec<&str> = sc["requires"]
        .as_array()
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if requires.iter().any(|r| *r != "database") {
        b.skip(what, format!("requires {requires:?}"));
        return;
    }
    if sc.get("settings").is_some() {
        b.skip(what, "needs temporary server settings");
        return;
    }
    let stateful = sc["fresh_state"].as_bool() == Some(true) || sc.get("then").is_some();
    let phase = if stateful || is_mutating(method) {
        Phase::MutateScenarios
    } else {
        Phase::Reads
    };
    let key = |step: usize| format!("{seq:05}/{step:02}");
    let primary = match scenario_step(
        b,
        route_idx,
        &format!("scenario:{id}"),
        method,
        &sc["principal"],
        &sc["request"],
        phase,
        &key(0),
    ) {
        Ok(c) => c,
        Err(reason) => {
            b.skip(what, reason);
            return;
        }
    };
    let mut steps = vec![primary];
    for (n, then) in sc["then"].as_array().into_iter().flatten().enumerate() {
        let then_method = then["method"].as_str().unwrap_or("GET");
        let then_path = then["request"]["path"].as_str().unwrap_or_default();
        // A follow-up belongs to the route it actually calls.
        let target = b
            .src
            .routes
            .iter()
            .position(|r| {
                r.surface == Surface::ApiV1
                    && r.method == then_method
                    && path_matches_template(&r.path, then_path)
            })
            .unwrap_or(route_idx);
        match scenario_step(
            b,
            target,
            &format!("scenario:{id}.then{n}"),
            then_method,
            &then["principal"],
            &then["request"],
            phase,
            &key(n + 1),
        ) {
            Ok(c) => steps.push(c),
            Err(reason) => {
                b.skip(what, format!("follow-up {n}: {reason}"));
                return;
            }
        }
    }
    for c in steps {
        b.push(c);
    }
}
