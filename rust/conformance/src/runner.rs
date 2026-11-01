//! Executes a plan against both servers: one case at a time, the two requests sent
//! concurrently. Between stages both databases can be reset. After a write that
//! succeeded, credentials are probed so one destructive route cannot silently turn
//! the rest of the run into a comparison of 401s.

use crate::diff::{self, Aliases, Diff, DiffKind};
use crate::http::{self, Exchange, Request};
use crate::model::*;
use crate::normalize::Rules;
use crate::origin::{self, OriginLog};
use crate::params::{fill, resolve_path, SideState};
use anyhow::{bail, Result};
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::process::Command;
use std::thread;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Reference,
    Candidate,
}

pub struct Config {
    /// Per surface, the (reference, candidate) base URLs. A surface absent here is
    /// not exercised and all its routes count as not matched.
    pub urls: BTreeMap<Surface, (String, String)>,
    pub fixture: BTreeMap<String, String>,
    pub rules: Rules,
    pub proxy_header: String,
    /// The candidate's origin log. With it, a case that was not answered natively counts as proxied.
    pub origin_log: Option<std::path::PathBuf>,
    pub reset_reference: Option<String>,
    pub reset_candidate: Option<String>,
    pub only: Option<Regex>,
    pub progress: bool,
    /// Name each recorded case on its candidate request, for `conformance-mutproxy`.
    pub tag_cases: bool,
    /// The peer lab's clients. Without them the `Peers` phase does not run.
    pub sources: BTreeMap<String, PeerSource>,
    /// Wait this long before each case. Some Go state depends on how fast requests arrive, so a
    /// slower candidate can show a difference that only a Go vs Go run at the same pace can explain.
    pub pace: std::time::Duration,
}

/// One peer-lab client: an address, and the reference and candidate as reached from it.
#[derive(Clone, Debug, Default)]
pub struct PeerSource {
    pub ip: String,
    pub urls: BTreeMap<Surface, (String, String)>,
}

/// Reads the file `scripts/peer-lab.sh` writes.
pub fn parse_sources(text: &str) -> Result<BTreeMap<String, PeerSource>> {
    #[derive(Deserialize)]
    struct Entry {
        ip: String,
        main: (String, String),
        jellycompat: (String, String),
        abs: (String, String),
        metrics: (String, String),
    }
    let raw: BTreeMap<String, Entry> = serde_json::from_str(text)?;
    Ok(raw
        .into_iter()
        .map(|(name, e)| {
            let mut urls = BTreeMap::new();
            for s in NATIVE_SURFACES {
                urls.insert(s, e.main.clone());
            }
            urls.insert(Surface::Jellycompat, e.jellycompat);
            urls.insert(Surface::Abs, e.abs);
            urls.insert(Surface::Metrics, e.metrics);
            (name, PeerSource { ip: e.ip, urls })
        })
        .collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaseResult {
    pub id: String,
    pub route_key: String,
    pub name: String,
    pub phase: Phase,
    pub identity: Identity,
    pub method: String,
    pub path: String,
    pub reference_status: u16,
    pub candidate_status: u16,
    pub diffs: Vec<Diff>,
    pub proxied: bool,
    pub body_compared: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_skip_reason: Option<String>,
    /// A feed rule names this route, so its contents do not count as compared.
    #[serde(default)]
    pub feed_relaxed: bool,
    /// False when both sides failed at the transport level: no evidence either way.
    pub exercised: bool,
    /// The start of an error answer from the reference, to explain a shallow route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub kind: String,
    pub detail: String,
}

#[derive(Default, Debug)]
pub struct RunOutput {
    pub results: Vec<CaseResult>,
    pub rule_hits: BTreeMap<String, u64>,
    pub events: Vec<Event>,
    pub not_run: BTreeMap<String, String>,
}

pub struct Runner<'a> {
    cfg: &'a Config,
    routes: &'a [Route],
    client: Client,
    reference: SideState,
    candidate: SideState,
    aliases: Aliases,
    run_start: i64,
    out: RunOutput,
    origin_log: Option<OriginLog>,
}

const SETTLE_POLLS: u32 = 100;
const SETTLE_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

const NATIVE_SURFACES: [Surface; 4] = [
    Surface::ApiV2,
    Surface::ApiV1,
    Surface::ApiDelegate,
    Surface::Root,
];

fn native(surface: Surface) -> bool {
    NATIVE_SURFACES.contains(&surface)
}

fn jf_auth(token: Option<&str>) -> String {
    let base = "MediaBrowser Client=\"conformance\", Device=\"harness\", DeviceId=\"conformance-1\", Version=\"1.0\"";
    match token {
        Some(t) => format!("{base}, Token=\"{t}\""),
        None => base.to_string(),
    }
}

/// The request headers that make `identity` real on `surface`.
fn identity_headers(surface: Surface, identity: Identity, s: &SideState) -> Vec<(String, String)> {
    let fact = |k: &str| s.fact(k).unwrap_or("").to_string();
    let bearer = |t: String| ("Authorization".to_string(), format!("Bearer {t}"));
    let profile = |k: &str| ("X-Profile-Id".to_string(), fact(k));
    if native(surface) {
        return match identity {
            Identity::Anon => vec![],
            Identity::User => vec![bearer(fact("user_api_key")), profile("user_profile_id")],
            Identity::Admin => vec![bearer(fact("admin_api_key")), profile("admin_profile_id")],
            Identity::Kid => vec![bearer(fact("user_api_key")), profile("kid_profile_id")],
            Identity::UserJwt => vec![bearer(fact("jwt_user"))],
            Identity::AdminJwt => vec![bearer(fact("jwt_admin"))],
            Identity::UserNoProfile => vec![bearer(fact("user_api_key"))],
            Identity::AdminNoProfile => vec![bearer(fact("admin_api_key"))],
        };
    }
    let who = match identity {
        Identity::Anon => return vec![],
        Identity::Admin | Identity::AdminJwt | Identity::AdminNoProfile => "admin",
        _ => "user",
    };
    match surface {
        Surface::Jellycompat => vec![(
            "X-Emby-Authorization".to_string(),
            jf_auth(s.fact(&format!("jf_token_{who}"))),
        )],
        Surface::Abs => vec![bearer(fact(&format!("abs_token_{who}")))],
        _ => vec![],
    }
}

fn encode_query(q: &[(String, String)]) -> String {
    let enc = |s: &str| {
        let mut out = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~:,".contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    };
    q.iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn parse_fixture_env(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v
                .strip_prefix("${")
                .and_then(|x| x.strip_suffix('}'))
                .and_then(|x| x.split_once(":-").map(|(_, d)| d))
                .unwrap_or(v);
            out.insert(k.to_string(), v.to_string());
        }
    }
    out
}

/// Everything known before talking to a server. Ids here are the ones the seed
/// fixes (see baseline/seed); server-generated ones are discovered in `bootstrap`.
fn static_facts(env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let e = |k: &str| env.get(k).cloned().unwrap_or_default();
    let pairs = [
        ("movie_id", "movie-tmdb-9000001".to_string()),
        ("series_id", "series-tvdb-9000003".to_string()),
        ("episode_id", "episode-tvdb-9000003-1-1".to_string()),
        ("file_id", "1".to_string()),
        ("library_id", "1".to_string()),
        ("admin_user_id", "1".to_string()),
        ("member_user_id", "2".to_string()),
        ("admin_api_key_id", "1".to_string()),
        ("member_api_key_id", "2".to_string()),
        ("admin_profile_id", e("CONF_ADMIN_PROFILE_ID")),
        ("user_profile_id", e("CONF_USER_PROFILE_ID")),
        ("kid_profile_id", e("CONF_USER_SECOND_PROFILE_ID")),
        ("admin_api_key", e("CONF_ADMIN_API_KEY")),
        ("user_api_key", e("CONF_USER_API_KEY")),
        ("admin_username", e("CONF_ADMIN_USERNAME")),
        ("admin_password", e("CONF_ADMIN_PASSWORD")),
        ("member_username", e("CONF_USER_USERNAME")),
        ("member_password", e("CONF_USER_PASSWORD")),
        ("member_email", "conf-user@silo.example.test".to_string()),
        ("profile_primary", e("CONF_USER_PROFILE_ID")),
        ("profile_secondary", e("CONF_USER_SECOND_PROFILE_ID")),
        ("profile_child", e("CONF_USER_SECOND_PROFILE_ID")),
        ("profile_admin_primary", e("CONF_ADMIN_PROFILE_ID")),
        (
            "profile_missing",
            "c0f00000-0000-4000-8000-00000000dead".to_string(),
        ),
        ("server_name", "Silo Conformance".to_string()),
    ];
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

impl<'a> Runner<'a> {
    pub fn new(cfg: &'a Config, routes: &'a [Route], run_start: i64) -> Self {
        Runner {
            origin_log: cfg.origin_log.as_deref().map(OriginLog::new),
            cfg,
            routes,
            client: http::client(),
            reference: SideState::default(),
            candidate: SideState::default(),
            aliases: Aliases::default(),
            run_start,
            out: RunOutput::default(),
        }
    }

    fn event(&mut self, kind: &str, detail: impl Into<String>) {
        let detail = detail.into();
        if self.cfg.progress {
            eprintln!("[conformance] {kind}: {detail}");
        }
        self.out.events.push(Event {
            kind: kind.to_string(),
            detail,
        });
    }

    /// Both databases back to the seed. Failure ends the run: everything after it
    /// would compare servers in unknown states.
    fn reset(&mut self, why: &str) -> Result<()> {
        let (Some(r), Some(c)) = (&self.cfg.reset_reference, &self.cfg.reset_candidate) else {
            self.event(
                "reset_skipped",
                format!("{why}: no reset command configured"),
            );
            return Ok(());
        };
        self.event("reset", why.to_string());
        let shell = |cmd: &str| -> Result<String, String> {
            let out = Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()
                .map_err(|e| e.to_string())?;
            if out.status.success() {
                Ok(String::new())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).into_owned())
            }
        };
        let (a, b) = thread::scope(|s| {
            let ha = s.spawn(|| shell(r));
            let hb = s.spawn(|| shell(c));
            (
                ha.join().expect("reset thread"),
                hb.join().expect("reset thread"),
            )
        });
        if let Err(e) = a {
            bail!("reference reset failed: {e}");
        }
        if let Err(e) = b {
            bail!("candidate reset failed: {e}");
        }
        self.reference.created.clear();
        self.candidate.created.clear();
        Ok(())
    }

    fn bootstrap(&mut self) {
        let facts = static_facts(&self.cfg.fixture);
        let cfg = self.cfg;
        let client = &self.client;
        let (r, c) = thread::scope(|s| {
            let a = s.spawn(|| bootstrap_side(client, cfg, Side::Reference, facts.clone()));
            let b = s.spawn(|| bootstrap_side(client, cfg, Side::Candidate, facts.clone()));
            (a.join().expect("bootstrap"), b.join().expect("bootstrap"))
        });
        for (name, problems) in [("reference", &r.1), ("candidate", &c.1)] {
            for p in problems {
                self.event("bootstrap_problem", format!("{name}: {p}"));
            }
        }
        self.reference.facts = r.0;
        self.candidate.facts = c.0;
    }

    pub fn run(mut self, cases: &[Case]) -> Result<RunOutput> {
        let seed: Vec<&Case> = cases.iter().filter(|c| c.phase == Phase::Seed).collect();
        let stages: [(&str, &[Phase]); 5] = [
            ("reads and rejections", &[Phase::Reads, Phase::Rejections]),
            ("v2 writes", &[Phase::MutateV2]),
            ("v1 writes", &[Phase::MutateV1]),
            ("v1 scenarios", &[Phase::MutateScenarios]),
            ("compatibility writes", &[Phase::MutateCompat]),
        ];
        for (n, (name, phases)) in stages.iter().enumerate() {
            self.reset(&format!("before stage: {name}"))?;
            self.bootstrap();
            for c in &seed {
                // The first pass is compared; later passes only rebuild state.
                self.run_case(c, n == 0)?;
            }
            for phase in *phases {
                let selected: Vec<&Case> = cases.iter().filter(|c| c.phase == *phase).collect();
                self.event(
                    "stage",
                    format!("{name}: {phase:?}, {} cases", selected.len()),
                );
                for c in selected {
                    self.run_case(c, true)?;
                }
            }
        }
        let peers: Vec<&Case> = cases.iter().filter(|c| c.phase == Phase::Peers).collect();
        if self.cfg.sources.is_empty() {
            for c in peers {
                self.out
                    .not_run
                    .insert(c.id.clone(), "no peer lab: pass --sources".to_string());
            }
            return Ok(self.out);
        }
        self.reset("before stage: peer addresses")?;
        self.bootstrap();
        self.bootstrap_peers();
        self.event("stage", format!("peer addresses: {} cases", peers.len()));
        for c in peers {
            self.run_case(c, true)?;
        }
        Ok(self.out)
    }

    /// What the peer cases need beyond the usual facts.
    fn bootstrap_peers(&mut self) {
        let ips: Vec<(String, String)> = self
            .cfg
            .sources
            .iter()
            .map(|(name, s)| (format!("ip_{name}"), s.ip.clone()))
            .collect();
        let Some((base_r, base_c)) = self.cfg.urls.get(&Surface::Jellycompat).cloned() else {
            return;
        };
        for (base, side) in [(base_r, Side::Reference), (base_c, Side::Candidate)] {
            let state = self.state(side);
            let auth = identity_headers(Surface::Jellycompat, Identity::Admin, state);
            let path = format!(
                "/Items/{}/PlaybackInfo",
                state.fact("jf_movie_id").unwrap_or("")
            );
            let source = http::send(
                &self.client,
                &Request {
                    base: &base,
                    method: "GET",
                    path_and_query: &path,
                    headers: &auth,
                    body: None,
                    timeout_secs: 20,
                    host: None,
                },
            );
            let id = serde_json::from_slice::<Value>(&source.body)
                .ok()
                .and_then(|v| v["MediaSources"][0]["Id"].as_str().map(str::to_string));
            let state = match side {
                Side::Reference => &mut self.reference,
                Side::Candidate => &mut self.candidate,
            };
            state.facts.extend(ips.iter().cloned());
            match id {
                Some(id) => {
                    state.facts.insert("jf_media_source_id".to_string(), id);
                }
                None => self.event(
                    "bootstrap_problem",
                    "no Jellyfin media source for the peer cases",
                ),
            }
        }
    }

    /// Waits for a batched write to show on both sides. Giving up is not an error: the case that
    /// follows compares whatever is there.
    fn settle(&self, path: &str, base_r: &str, base_c: &str) {
        for (base, state) in [(base_r, &self.reference), (base_c, &self.candidate)] {
            let path = fill(path, &state.facts);
            let headers = identity_headers(Surface::ApiV2, Identity::Admin, state);
            for _ in 0..SETTLE_POLLS {
                let e = http::send(
                    &self.client,
                    &Request {
                        base,
                        method: "GET",
                        path_and_query: &path,
                        headers: &headers,
                        body: None,
                        timeout_secs: 10,
                        host: None,
                    },
                );
                let seen = serde_json::from_slice::<Value>(&e.body)
                    .ok()
                    .and_then(|v| v["items"].as_array().map(|items| !items.is_empty()))
                    .unwrap_or(false);
                if seen {
                    break;
                }
                thread::sleep(SETTLE_WAIT);
            }
        }
    }

    fn state(&self, side: Side) -> &SideState {
        match side {
            Side::Reference => &self.reference,
            Side::Candidate => &self.candidate,
        }
    }

    fn build_request(
        &self,
        case: &Case,
        side: Side,
    ) -> (String, Vec<(String, String)>, Option<Vec<u8>>) {
        let route = &self.routes[case.route];
        let state = self.state(side);
        let mut filled = case.clone();
        filled.path = fill(&case.path, &state.facts);
        let mut path = resolve_path(&filled, route, state);
        if !case.query.is_empty() {
            let q: Vec<(String, String)> = case
                .query
                .iter()
                .map(|(k, v)| (k.clone(), fill(v, &state.facts)))
                .collect();
            path.push('?');
            path.push_str(&encode_query(&q));
        }
        let mut headers = identity_headers(route.surface, case.identity, state);
        for (k, v) in &case.headers {
            headers.push((k.clone(), fill(v, &state.facts)));
        }
        if let Some(ct) = &case.content_type {
            headers.push(("Content-Type".to_string(), ct.clone()));
        }
        let body = case.body.as_ref().map(|b| match std::str::from_utf8(b) {
            Ok(text) => fill(text, &state.facts).into_bytes(),
            Err(_) => b.clone(),
        });
        (path, headers, body)
    }

    fn send_pair(
        &self,
        case: &Case,
        base_r: &str,
        base_c: &str,
        extra: &[(Side, (String, String))],
    ) -> (Exchange, Exchange, String, String) {
        let (path_r, mut headers_r, body_r) = self.build_request(case, Side::Reference);
        let (path_c, mut headers_c, body_c) = self.build_request(case, Side::Candidate);
        for (side, h) in extra {
            match side {
                Side::Reference => headers_r.push(h.clone()),
                Side::Candidate => headers_c.push(h.clone()),
            }
        }
        let client = &self.client;
        let (r, c) = thread::scope(|s| {
            let a = s.spawn(|| {
                http::send(
                    client,
                    &Request {
                        base: base_r,
                        method: &case.method,
                        path_and_query: &path_r,
                        headers: &headers_r,
                        body: body_r.as_deref(),
                        timeout_secs: case.timeout_secs,
                        host: case.host.as_deref(),
                    },
                )
            });
            let b = s.spawn(|| {
                http::send(
                    client,
                    &Request {
                        base: base_c,
                        method: &case.method,
                        path_and_query: &path_c,
                        headers: &headers_c,
                        body: body_c.as_deref(),
                        timeout_secs: case.timeout_secs,
                        host: case.host.as_deref(),
                    },
                )
            });
            (a.join().expect("request"), b.join().expect("request"))
        });
        (r, c, path_r, path_c)
    }

    fn run_case(&mut self, case: &Case, record: bool) -> Result<()> {
        let route = &self.routes[case.route];
        if let Some(only) = &self.cfg.only {
            if !only.is_match(&case.id) {
                return Ok(());
            }
        }
        let urls = match &case.source {
            Some(name) => self.cfg.sources.get(name).map(|s| &s.urls),
            None => Some(&self.cfg.urls),
        };
        let Some((base_r, base_c)) = urls.and_then(|u| u.get(&route.surface)).cloned() else {
            self.out.not_run.insert(
                case.id.clone(),
                format!("no base URL for surface {}", route.surface.name()),
            );
            return Ok(());
        };
        if let Some(path) = &case.settle_on {
            self.settle(path, &base_r, &base_c);
        }
        thread::sleep(self.cfg.pace);
        let tag: Vec<(Side, (String, String))> = if self.cfg.tag_cases && record {
            vec![(
                Side::Candidate,
                (crate::mutate::CASE_TAG_HEADER.to_string(), case.id.clone()),
            )]
        } else {
            Vec::new()
        };
        // Logins and liveness probes since the last case also wrote lines. They are not this case's.
        if let Some(log) = &mut self.origin_log {
            log.drain()?;
        }
        let (r, c, path, candidate_path) = self.send_pair(case, &base_r, &base_c, &tag);

        if let Some(prefix) = &case.capture_as {
            self.capture_created(prefix, &r, &c);
        }

        let method_path = format!("{} {}", route.method, route.path);
        let ctx = diff::Ctx {
            rules: &self.cfg.rules,
            surface: route.surface.name(),
            method_path: &method_path,
            run_start: self.run_start,
            proxy_header: &self.cfg.proxy_header,
            reference_path: &path,
            candidate_path: &candidate_path,
        };
        let mut outcome = diff::compare(&ctx, &mut self.aliases, &r, &c, case.skip_body);
        for (id, n) in std::mem::take(&mut outcome.rule_hits) {
            *self.out.rule_hits.entry(id).or_default() += n;
        }
        let marked_proxied = c.header(&self.cfg.proxy_header).is_some();
        if case.method == "GET" && r.status == 200 && c.status == 200 {
            if let (Some(tag_r), Some(tag_c)) = (r.header("etag"), c.header("etag")) {
                let mut extra = vec![
                    (Side::Reference, ("If-None-Match".to_string(), tag_r)),
                    (Side::Candidate, ("If-None-Match".to_string(), tag_c)),
                ];
                extra.extend(tag.iter().cloned());
                let (r2, c2, _, _) = self.send_pair(case, &base_r, &base_c, &extra);
                if r2.status != c2.status {
                    outcome.diffs.push(Diff {
                        kind: DiffKind::EtagBehaviour,
                        at: "revalidation status".to_string(),
                        reference: r2.status.to_string(),
                        candidate: c2.status.to_string(),
                    });
                }
            }
        }
        let proxied = marked_proxied
            || match &mut self.origin_log {
                Some(log) => origin::proxied(&log.drain()?),
                None => false,
            };
        if record {
            self.out.results.push(CaseResult {
                id: case.id.clone(),
                route_key: route.key(),
                name: case.name.clone(),
                phase: case.phase,
                identity: case.identity,
                method: case.method.clone(),
                path,
                reference_status: r.status,
                candidate_status: c.status,
                diffs: outcome.diffs,
                proxied,
                body_compared: outcome.body_compared,
                body_skip_reason: outcome.body_skip_reason,
                feed_relaxed: outcome.feed_relaxed,
                exercised: !(r.error.is_some() && c.error.is_some()),
                reference_error: (r.status >= 400).then(|| {
                    let text = String::from_utf8_lossy(&r.body);
                    text.chars().take(200).collect()
                }),
            });
        }
        let write_landed =
            case.may_mutate && ((200..300).contains(&r.status) || (200..300).contains(&c.status));
        let transport_failed = r.error.is_some() || c.error.is_some();
        if write_landed || transport_failed {
            self.check_liveness(&case.id)?;
        }
        Ok(())
    }

    fn capture_created(&mut self, prefix: &str, r: &Exchange, c: &Exchange) {
        let singular = prefix
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_end_matches('s')
            .replace('-', "_");
        let id_key = format!("{singular}_id");
        let keys = ["id", id_key.as_str(), "token", "key", "code"];
        let (Some(a), Some(b)) = (created_id(r, &keys), created_id(c, &keys)) else {
            return;
        };
        // Each side keeps the id it generated either way. Only one that could have
        // come from the same generator is excused from the comparison of this answer.
        if diff::same_id_shape(&a, &b) {
            self.aliases.add(&a, &b);
        }
        self.reference.created.insert(prefix.to_string(), a);
        self.candidate.created.insert(prefix.to_string(), b);
    }

    /// Accounts must still work on both servers. A lost login session is restored
    /// by logging in again; a lost API key or dead server needs a reset.
    fn check_liveness(&mut self, after: &str) -> Result<()> {
        let Some((base_r, base_c)) = self.cfg.urls.get(&Surface::ApiV2).cloned() else {
            return Ok(());
        };
        let probe = |base: &str, state: &SideState, identity: Identity| -> u16 {
            let headers = identity_headers(Surface::ApiV2, identity, state);
            http::send(
                &self.client,
                &Request {
                    base,
                    method: "GET",
                    path_and_query: "/api/v2/account/me",
                    headers: &headers,
                    body: None,
                    timeout_secs: 10,
                    host: None,
                },
            )
            .status
        };
        let mut need_reset = false;
        let mut need_login = false;
        for (base, state) in [(&base_r, &self.reference), (&base_c, &self.candidate)] {
            for id in [Identity::Admin, Identity::User] {
                if probe(base, state, id) != 200 {
                    need_reset = true;
                }
            }
            for id in [Identity::AdminJwt, Identity::UserJwt] {
                if probe(base, state, id) != 200 {
                    need_login = true;
                }
            }
        }
        if need_reset {
            self.reset(&format!("credentials or server lost after {after}"))?;
            self.bootstrap();
        } else if need_login {
            self.event("relogin", format!("session lost after {after}"));
            self.bootstrap();
        }
        Ok(())
    }
}

fn created_id(e: &Exchange, keys: &[&str]) -> Option<String> {
    if !(200..300).contains(&e.status) {
        return None;
    }
    let v: Value = serde_json::from_slice(&e.body).ok()?;
    let scalar = |v: &Value| match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    for k in keys {
        if let Some(found) = v.get(*k).and_then(scalar) {
            return Some(found);
        }
    }
    let obj = v.as_object()?;
    for nested in obj.values().filter(|n| n.is_object()) {
        for k in keys {
            if let Some(found) = nested.get(*k).and_then(scalar) {
                return Some(found);
            }
        }
    }
    None
}

/// Logs in and discovers server-generated ids on one server. A failure here is an
/// event, not fatal: the cases that depend on it will show the difference.
fn bootstrap_side(
    client: &Client,
    cfg: &Config,
    side: Side,
    mut facts: BTreeMap<String, String>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut problems = Vec::new();
    let pick = |surface: Surface| {
        cfg.urls.get(&surface).map(|(r, c)| match side {
            Side::Reference => r.clone(),
            Side::Candidate => c.clone(),
        })
    };
    let call = |base: &str,
                method: &str,
                path: &str,
                headers: Vec<(String, String)>,
                body: Option<Value>|
     -> Option<Value> {
        let mut headers = headers;
        let bytes = body.map(|b| {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
            b.to_string().into_bytes()
        });
        let e = http::send(
            client,
            &Request {
                base,
                method,
                path_and_query: path,
                headers: &headers,
                body: bytes.as_deref(),
                timeout_secs: 20,
                host: None,
            },
        );
        if !(200..300).contains(&e.status) {
            return None;
        }
        serde_json::from_slice(&e.body).ok()
    };
    let creds = [
        (
            "admin",
            facts["admin_username"].clone(),
            facts["admin_password"].clone(),
            "Conf Admin",
        ),
        (
            "user",
            facts["member_username"].clone(),
            facts["member_password"].clone(),
            "Conf User",
        ),
    ];
    if let Some(base) = pick(Surface::ApiV1) {
        for (who, user, pass, _) in &creds {
            match call(
                &base,
                "POST",
                "/api/v1/auth/login",
                vec![],
                Some(json!({"username": user, "password": pass})),
            ) {
                Some(v) => {
                    facts.insert(
                        format!("jwt_{who}"),
                        v["access_token"].as_str().unwrap_or("").to_string(),
                    );
                }
                None => problems.push(format!("native login failed for {who}")),
            }
        }
        let auth = vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", facts["admin_api_key"]),
            ),
            (
                "X-Profile-Id".to_string(),
                facts["admin_profile_id"].clone(),
            ),
        ];
        let path = format!("/api/v2/catalog/items/{}", facts["movie_id"]);
        if let Some(item) = call(&base, "GET", &path, auth, None) {
            if let Some(v) = item["versions"][0]["file_id"].as_str() {
                facts.insert("file_id".to_string(), v.to_string());
            }
            if let Some(v) = item["cast"][0]["person_id"].as_str() {
                facts.insert("person_id".to_string(), v.to_string());
            }
        } else {
            problems.push("could not read the seeded movie".to_string());
        }
    }
    if let Some(base) = pick(Surface::Jellycompat) {
        let client_header = ("X-Emby-Authorization".to_string(), jf_auth(None));
        for (who, user, pass, profile) in &creds {
            let body = json!({"Username": format!("{user}#{profile}"), "Pw": pass});
            match call(
                &base,
                "POST",
                "/Users/AuthenticateByName",
                vec![client_header.clone()],
                Some(body),
            ) {
                Some(v) => {
                    facts.insert(
                        format!("jf_token_{who}"),
                        v["AccessToken"].as_str().unwrap_or("").to_string(),
                    );
                    facts.insert(
                        format!("jf_{who}_user_id"),
                        v["User"]["Id"].as_str().unwrap_or("").to_string(),
                    );
                }
                None => problems.push(format!("Jellyfin login failed for {who}")),
            }
        }
        if let (Some(token), Some(uid)) = (
            facts.get("jf_token_user").cloned(),
            facts.get("jf_user_user_id").cloned(),
        ) {
            let auth = vec![("X-Emby-Authorization".to_string(), jf_auth(Some(&token)))];
            let path =
                format!("/Users/{uid}/Items?Recursive=true&IncludeItemTypes=Movie,Series,Episode");
            if let Some(items) = call(&base, "GET", &path, auth.clone(), None) {
                for item in items["Items"].as_array().into_iter().flatten() {
                    let key = match item["Type"].as_str() {
                        Some("Movie") => "jf_movie_id",
                        Some("Series") => "jf_series_id",
                        Some("Episode") => "jf_episode_id",
                        _ => continue,
                    };
                    if !facts.contains_key(key) {
                        facts.insert(
                            key.to_string(),
                            item["Id"].as_str().unwrap_or("").to_string(),
                        );
                    }
                }
            } else {
                problems.push("could not list Jellyfin items".to_string());
            }
            if let Some(series) = facts.get("jf_series_id").cloned() {
                if let Some(s) = call(
                    &base,
                    "GET",
                    &format!("/Shows/{series}/Seasons"),
                    auth.clone(),
                    None,
                ) {
                    if let Some(v) = s["Items"][0]["Id"].as_str() {
                        facts.insert("jf_season_id".to_string(), v.to_string());
                    }
                }
            }
            if let Some(views) = call(&base, "GET", &format!("/Users/{uid}/Views"), auth, None) {
                if let Some(v) = views["Items"][0]["Id"].as_str() {
                    facts.insert("jf_library_id".to_string(), v.to_string());
                }
            }
        }
    }
    if let Some(base) = pick(Surface::Abs) {
        for (who, user, pass, _) in &creds {
            match call(
                &base,
                "POST",
                "/login",
                vec![],
                Some(json!({"username": user, "password": pass})),
            ) {
                Some(v) => {
                    let token = v["accessToken"]
                        .as_str()
                        .or(v["user"]["token"].as_str())
                        .unwrap_or("");
                    facts.insert(format!("abs_token_{who}"), token.to_string());
                }
                None => problems.push(format!("Audiobookshelf login failed for {who}")),
            }
        }
    }
    (facts, problems)
}
