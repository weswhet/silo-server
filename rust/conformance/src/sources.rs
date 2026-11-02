//! Loads the route universe from the contract artifacts and route manifests. The
//! totals here are the denominators of the parity report: a source route that no
//! case reaches still counts, as not matched.

use crate::model::{is_mutating, Auth, Op, Param, Route, Surface};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub const OPENAPI: &str = "contracts/api/v2/openapi.json";
pub const INVENTORY: &str = "contracts/api/v2/route-inventory.json";
pub const MIGRATION: &str = "contracts/api/v2/migration.json";
pub const FIXTURES: &str = "contracts/api/v2/fixtures/index.json";
pub const SCENARIOS: &str = "contracts/api/v2/scenarios/api";
pub const API_ROUTES: &str = "internal/api/testdata/media_routes.txt";
pub const JELLY_ROUTES: &str = "internal/jellycompat/testdata/media_routes.txt";
pub const JELLY_DOC: &str = "docs/jellycompat-api.md";
pub const ABS_ROUTES: &str = "internal/audiobooks/abs/testdata/media_routes.txt";

pub struct Sources {
    pub routes: Vec<Route>,
    pub openapi: Value,
    pub fixtures: Vec<Value>,
    pub scenarios: Vec<Value>,
}

fn read_json(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn load(repo: &Path) -> Result<Sources> {
    let openapi = read_json(&repo.join(OPENAPI))?;
    let inventory = read_json(&repo.join(INVENTORY))?;
    let migration = read_json(&repo.join(MIGRATION))?;
    let mut routes = Vec::new();
    let ops = openapi_routes(&openapi, &mut routes);
    inventory_routes(&inventory, &migration, &ops, &mut routes);
    let api_manifest = fs::read_to_string(repo.join(API_ROUTES))?;
    walked_routes(&api_manifest, &mut routes);
    let jelly_manifest = fs::read_to_string(repo.join(JELLY_ROUTES))?;
    let jelly_doc = fs::read_to_string(repo.join(JELLY_DOC))?;
    compat_routes(
        Surface::Jellycompat,
        &jelly_manifest,
        Some(&jelly_doc),
        WIRED_JELLY,
        &mut routes,
    );
    let abs_manifest = fs::read_to_string(repo.join(ABS_ROUTES))?;
    compat_routes(Surface::Abs, &abs_manifest, None, WIRED_ABS, &mut routes);

    let fixtures = read_json(&repo.join(FIXTURES))?["fixtures"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut scenarios = Vec::new();
    let mut files: Vec<_> = fs::read_dir(repo.join(SCENARIOS))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for f in files {
        scenarios.push(read_json(&f)?);
    }
    Ok(Sources {
        routes,
        openapi,
        fixtures,
        scenarios,
    })
}

const OPENAPI_METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];

fn parse_op(id: &str, op: &Value, shared: &[Value], root: &Value) -> Op {
    let mut params = Vec::new();
    for p in shared
        .iter()
        .chain(op["parameters"].as_array().into_iter().flatten())
    {
        let p = crate::schema::deref(root, p);
        params.push(Param {
            name: p["name"].as_str().unwrap_or_default().to_string(),
            location: p["in"].as_str().unwrap_or_default().to_string(),
            required: p["required"].as_bool().unwrap_or(false),
            schema: p["schema"].clone(),
        });
    }
    let body = crate::schema::deref(root, &op["requestBody"]);
    let mut body_media = None;
    let mut body_schema = None;
    if let Some(content) = body["content"].as_object() {
        // Prefer JSON; a route that also accepts other media types is still JSON here.
        let chosen = content
            .get_key_value("application/json")
            .or_else(|| content.iter().next());
        if let Some((media, spec)) = chosen {
            body_media = Some(media.clone());
            body_schema = Some(spec["schema"].clone());
        }
    }
    Op {
        id: id.to_string(),
        params,
        body_media,
        body_schema,
        body_required: body["required"].as_bool().unwrap_or(false),
    }
}

fn openapi_routes(openapi: &Value, routes: &mut Vec<Route>) -> BTreeMap<String, Arc<Op>> {
    let mut by_id = BTreeMap::new();
    let empty = serde_json::Map::new();
    for (path, item) in openapi["paths"].as_object().unwrap_or(&empty) {
        let shared = item["parameters"].as_array().cloned().unwrap_or_default();
        for method in OPENAPI_METHODS {
            let Some(op) = item.get(method) else { continue };
            let id = op["operationId"].as_str().unwrap_or_default();
            let parsed = Arc::new(parse_op(id, op, &shared, openapi));
            by_id.insert(id.to_string(), parsed.clone());
            let raw = op["x-silo-raw-protocol"].as_str().unwrap_or_default();
            routes.push(Route {
                surface: Surface::ApiV2,
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                auth: Auth::parse(op["x-silo-class"].as_str().unwrap_or_default()),
                op: Some(parsed),
                streams: matches!(
                    raw,
                    "media-bytes"
                        | "hls"
                        | "download-bytes"
                        | "managed-download-file"
                        | "theme-audio"
                ),
                websocket: raw == "websocket",
                handle_all: false,
                request_kind: None,
                source: "openapi",
            });
        }
    }
    by_id
}

fn inventory_routes(
    inventory: &Value,
    migration: &Value,
    ops: &BTreeMap<String, Arc<Op>>,
    routes: &mut Vec<Route>,
) {
    let mut v1_to_v2 = BTreeMap::new();
    for e in migration["entries"].as_array().into_iter().flatten() {
        if let (Some(method), Some(path), Some(op)) = (
            e["method"].as_str(),
            e["path"].as_str(),
            e["v2"]["operation_id"].as_str(),
        ) {
            v1_to_v2.insert((method.to_string(), path.to_string()), op.to_string());
        }
    }
    for r in inventory["routes"].as_array().into_iter().flatten() {
        let listener = r["listener"].as_str().unwrap_or_default();
        let namespace = r["namespace"].as_str().unwrap_or_default();
        let surface = match (listener, namespace) {
            ("api", "api_v1") => Surface::ApiV1,
            ("api", _) => Surface::ApiDelegate,
            ("root", _) => Surface::Root,
            ("operational_metrics", _) => Surface::Metrics,
            ("operational_debug", _) => Surface::Debug,
            ("proxy", _) => Surface::ProxyNode,
            ("transcode_node", _) => Surface::TranscodeNode,
            _ => continue,
        };
        let method = r["method"].as_str().unwrap_or_default().to_string();
        let path = r["path"].as_str().unwrap_or_default().to_string();
        let op = v1_to_v2
            .get(&(method.clone(), path.clone()))
            .and_then(|id| ops.get(id))
            .cloned();
        routes.push(Route {
            surface,
            auth: Auth::parse(r["auth_class"].as_str().unwrap_or_default()),
            op,
            streams: r["streams"].as_bool().unwrap_or(false),
            websocket: r["upgrades_websocket"].as_bool().unwrap_or(false),
            handle_all: r["method_origin"].as_str() == Some("handle_all"),
            request_kind: r["request_kind"].as_str().map(str::to_string),
            source: "route-inventory",
            method,
            path,
        });
    }
}

/// `/api/v2` rows the route walk finds and neither `openapi.json` nor the inventory lists. Raw plugin
/// and artwork routes: no typed contract, so only the generated cases reach them.
fn walked_routes(manifest: &str, routes: &mut Vec<Route>) {
    let listed: BTreeSet<(String, String)> = routes
        .iter()
        .filter(|r| r.surface.on_main_listener())
        .map(|r| (r.method.clone(), r.path.clone()))
        .collect();
    let mut seen = BTreeSet::new();
    for line in manifest.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let head = line.split('\t').next().unwrap_or_default();
        let Some((method, path)) = head.split_once(' ') else {
            continue;
        };
        let pair = (method.to_string(), path.to_string());
        if listed.contains(&pair) || !seen.insert(pair) {
            continue;
        }
        routes.push(Route {
            surface: Surface::ApiV2Walked,
            method: method.to_string(),
            path: path.to_string(),
            auth: Auth::Unknown,
            op: None,
            streams: false,
            websocket: false,
            handle_all: matches!(method, "CONNECT" | "TRACE"),
            request_kind: None,
            source: "route-walk",
        });
    }
}

/// A `METHOD /path` the prose of `docs/jellycompat-api.md` mentions that is no route of its own.
pub struct DocIllustration {
    pub method: &'static str,
    pub path: &'static str,
    /// The route this path is a value of. `None` when it matches no route.
    pub parent: Option<&'static str>,
    pub reason: &'static str,
}

const IMAGE_TYPE: &str = "doc example: an {imageType} value of the image route";

/// Not rows: the router has no line for them, so they are out of the denominator.
pub const DOC_ILLUSTRATIONS: &[DocIllustration] = &[
    DocIllustration {
        method: "GET",
        path: "/Items/{boxSetId}/Images/Primary",
        parent: Some("/Items/{id}/Images/{imageType}"),
        reason: IMAGE_TYPE,
    },
    DocIllustration {
        method: "GET",
        path: "/Items/{personId}/Images/Primary",
        parent: Some("/Items/{id}/Images/{imageType}"),
        reason: IMAGE_TYPE,
    },
    DocIllustration {
        method: "GET",
        path: "/Items/{id}/Images/Art",
        parent: Some("/Items/{id}/Images/{imageType}"),
        reason: IMAGE_TYPE,
    },
    DocIllustration {
        method: "GET",
        path: "/Items/{id}/Images/Banner",
        parent: Some("/Items/{id}/Images/{imageType}"),
        reason: IMAGE_TYPE,
    },
    DocIllustration {
        method: "GET",
        path: "/Items/{id}/Images/Disc",
        parent: Some("/Items/{id}/Images/{imageType}"),
        reason: IMAGE_TYPE,
    },
    DocIllustration {
        method: "GET",
        path: "/Items/{id}/Images/Thumb",
        parent: Some("/Items/{id}/Images/{imageType}"),
        reason: IMAGE_TYPE,
    },
    DocIllustration {
        method: "GET",
        path: "/Items/{id}/Images/Backdrop/{index}",
        parent: Some("/Items/{id}/Images/{imageType}/{index}"),
        reason: IMAGE_TYPE,
    },
    DocIllustration {
        method: "GET",
        path: "/System/Configuration/encoding",
        parent: Some("/System/Configuration/{key}"),
        reason: "doc example: the one {key} value the named-configuration route serves",
    },
    DocIllustration {
        method: "GET",
        path: "/ThemeVideos",
        parent: None,
        reason:
            "doc shorthand for /Items/{id}/ThemeVideos in a table cell; no router line, 404 on Go",
    },
];

/// Rows the manifests cannot show, because the walk runs with these dependencies nil. Read from
/// router source; `silo_front::reconcile::WIRING_CONDITIONAL_ROWS` says why for each, and
/// `tests/contracts.rs` holds the two lists together.
const WIRED_JELLY: &[(&str, &str)] = &[("POST", "/Library/Media/Updated")];
const WIRED_ABS: &[(&str, &str)] = &[
    ("GET", "/api/v2/artwork/*"),
    ("HEAD", "/api/v2/artwork/*"),
    ("ALL", "/socket.io"),
    ("ALL", "/abs/socket.io"),
];

/// Route identity ignoring parameter names and letter case: the compatibility
/// routers match case-insensitively, and docs name parameters loosely.
fn loose_key(method: &str, path: &str) -> String {
    let mut out = format!("{method} ");
    let mut in_param = false;
    for c in path.chars() {
        match c {
            '{' => {
                in_param = true;
                out.push('{');
            }
            '}' => {
                in_param = false;
                out.push('}');
            }
            _ if in_param => {}
            _ => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

fn compat_routes(
    surface: Surface,
    manifest: &str,
    doc: Option<&str>,
    wired: &[(&str, &str)],
    routes: &mut Vec<Route>,
) {
    let mut seen = BTreeSet::new();
    let mut add =
        |method: &str, path: &str, source: &'static str, streams: bool, routes: &mut Vec<Route>| {
            if !seen.insert(loose_key(method, path)) {
                return;
            }
            routes.push(Route {
                surface,
                method: method.to_string(),
                path: path.to_string(),
                auth: Auth::Unknown,
                op: None,
                streams,
                websocket: path.to_ascii_lowercase().contains("socket"),
                handle_all: matches!(method, "CONNECT" | "TRACE" | "QUERY" | "ALL"),
                request_kind: None,
                source,
            });
        };
    for line in manifest.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let head = cols.next().unwrap_or_default();
        let Some((method, path)) = head.split_once(' ') else {
            continue;
        };
        let media = cols.next() == Some("media");
        add(method, path, "manifest", media, routes);
    }
    if let Some(doc) = doc {
        for (method, path) in doc_routes(doc) {
            let illustration = DOC_ILLUSTRATIONS
                .iter()
                .any(|d| d.method == method && d.path == path);
            if !illustration {
                add(&method, &path, "docs", false, routes);
            }
        }
    }
    for (method, path) in wired {
        add(method, path, "router", false, routes);
    }
}

const HTTP_METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// Pulls `METHOD /path` mentions out of Markdown. The docs write these several ways:
/// `POST /x`, `GET`, `POST /x`, and "`POST /x` and `/y`" for a second path. An optional
/// `[/{index}]` suffix expands to both routes.
pub fn doc_routes(doc: &str) -> Vec<(String, String)> {
    let mut out = BTreeSet::new();
    for line in doc.lines() {
        let mut pending: Vec<String> = Vec::new();
        let mut current: Vec<String> = Vec::new();
        for (i, span) in line.split('`').enumerate() {
            if i % 2 == 0 {
                // Prose between spans ends a method list unless it just joins spans.
                let t = span.trim().trim_matches(',').trim();
                if !(t.is_empty() || t == "and" || t == "or" || t == "/" || t == "|") {
                    pending.clear();
                    current.clear();
                }
                continue;
            }
            let span = span.trim();
            if HTTP_METHODS.contains(&span) {
                pending.push(span.to_string());
                continue;
            }
            if let Some((m, rest)) = span.split_once(' ') {
                if HTTP_METHODS.contains(&m) && rest.starts_with('/') {
                    pending.push(m.to_string());
                    current = std::mem::take(&mut pending);
                    add_doc_path(&mut out, &current, rest);
                    continue;
                }
            }
            if span.starts_with('/') && !current.is_empty() {
                add_doc_path(&mut out, &current, span);
            } else {
                pending.clear();
                current.clear();
            }
        }
    }
    out.into_iter().collect()
}

fn add_doc_path(out: &mut BTreeSet<(String, String)>, methods: &[String], raw: &str) {
    let raw = raw.split(['?', ' ']).next().unwrap_or(raw);
    let mut variants = Vec::new();
    if let (Some(a), Some(b)) = (raw.find('['), raw.rfind(']')) {
        if a < b {
            variants.push(format!("{}{}", &raw[..a], &raw[b + 1..]));
            variants.push(format!("{}{}{}", &raw[..a], &raw[a + 1..b], &raw[b + 1..]));
        }
    } else {
        variants.push(raw.to_string());
    }
    for v in variants {
        let valid = v.len() > 1
            && !v.starts_with("/api/")
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || "/{}_.-".contains(c));
        if valid {
            for m in methods {
                out.insert((m.clone(), v.clone()));
            }
        }
    }
}

pub fn surface_totals(routes: &[Route]) -> BTreeMap<Surface, usize> {
    let mut totals = BTreeMap::new();
    for r in routes {
        *totals.entry(r.surface).or_default() += 1;
    }
    totals
}

pub fn mutating_count(routes: &[Route]) -> usize {
    routes.iter().filter(|r| is_mutating(&r.method)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_routes_handles_the_ways_the_docs_list_methods() {
        let doc = "| `GET`, `POST /UserItems/{itemId}/UserData` | Read |\n\
                   | `POST`, `DELETE /UserPlayedItems/{itemId}` and `/Users/{userId}/PlayedItems/{itemId}` | x |\n\
                   | `HEAD /Items/{id}/Images/{type}[/{index}]` | y |\n\
                   Authenticated `GET /System/Configuration/encoding` returns `{\"a\":1}`.\n\
                   Use `GET` carefully, then see `/not/a/route`.\n\
                   The native `GET /api/v1/health` is separate.\n";
        let got: Vec<String> = doc_routes(doc)
            .into_iter()
            .map(|(m, p)| format!("{m} {p}"))
            .collect();
        assert_eq!(
            got,
            vec![
                "DELETE /UserPlayedItems/{itemId}",
                "DELETE /Users/{userId}/PlayedItems/{itemId}",
                "GET /System/Configuration/encoding",
                "GET /UserItems/{itemId}/UserData",
                "HEAD /Items/{id}/Images/{type}",
                "HEAD /Items/{id}/Images/{type}/{index}",
                "POST /UserItems/{itemId}/UserData",
                "POST /UserPlayedItems/{itemId}",
                "POST /Users/{userId}/PlayedItems/{itemId}",
            ]
        );
    }
}
