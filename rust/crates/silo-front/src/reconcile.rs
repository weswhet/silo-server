// Reconciles the row table with the contract artifacts. `build.rs` includes this file so a mismatch
// fails the build, and the crate compiles it too so the check itself is tested.

use std::collections::{BTreeMap, BTreeSet};

/// A denominator row: surface variant name, method, path.
pub type Key = (String, String, String);

/// Why a row outside the artifacts exists. These are read from router source because the walked
/// manifests run with those dependencies nil.
pub const WIRING_CONDITIONAL_ROWS: &[(&str, &str, &str, &str)] = &[
    (
        "Jellycompat",
        "GET",
        "/Persons/{name}",
        "internal/jellycompat/router.go: needs personsHandler",
    ),
    (
        "Jellycompat",
        "POST",
        "/Library/Media/Updated",
        "internal/jellycompat/router.go: needs autoscanHandler",
    ),
    (
        "Abs",
        "GET",
        "/api/v2/artwork/*",
        "cmd/silo/abs_listener.go: needs the artwork handler",
    ),
    (
        "Abs",
        "HEAD",
        "/api/v2/artwork/*",
        "cmd/silo/abs_listener.go: needs the artwork handler",
    ),
    (
        "Abs",
        "ALL",
        "/socket.io",
        "internal/audiobooks/abs/handler.go: chi Mount of the Socket.IO server",
    ),
    (
        "Abs",
        "ALL",
        "/abs/socket.io",
        "internal/audiobooks/abs/handler.go: chi Mount of the Socket.IO server",
    ),
];

const OPENAPI_METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];

fn inventory_surface(listener: &str, namespace: &str) -> Option<&'static str> {
    Some(match (listener, namespace) {
        ("api", "api_v1") => "ApiV1",
        ("api", _) => "ApiDelegate",
        ("root", _) => "Root",
        ("operational_metrics", _) => "Metrics",
        ("operational_debug", _) => "Debug",
        ("proxy", _) => "ProxyNode",
        ("transcode_node", _) => "TranscodeNode",
        _ => return None,
    })
}

fn key(surface: &str, method: &str, path: &str) -> Key {
    (surface.to_string(), method.to_string(), path.to_string())
}

fn manifest_rows(manifest: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for line in manifest.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let head = line.split('\t').next().unwrap_or_default();
        if let Some((method, path)) = head.split_once(' ') {
            out.insert((method.to_string(), path.to_string()));
        }
    }
    out
}

/// The artifact contents `denominators` reads.
pub struct Sources<'a> {
    pub inventory: &'a str,
    pub openapi: &'a str,
    pub api_manifest: &'a str,
    pub jelly_manifest: &'a str,
    pub abs_manifest: &'a str,
}

/// Every denominator row the artifacts name, with the source that names it. The 12 inventory rows
/// registered twice under different middleware count once: a table line routes both.
pub fn denominators(s: &Sources) -> Result<BTreeMap<Key, &'static str>, String> {
    let mut rows = BTreeMap::new();
    let inventory: serde_json::Value =
        serde_json::from_str(s.inventory).map_err(|e| format!("route-inventory.json: {e}"))?;
    let list = inventory["routes"]
        .as_array()
        .ok_or("route-inventory.json: no routes")?;
    for r in list {
        let str_of = |k: &str| r[k].as_str().unwrap_or_default();
        let surface = inventory_surface(str_of("listener"), str_of("namespace"))
            .ok_or_else(|| format!("route-inventory.json: new listener {}", str_of("listener")))?;
        rows.insert(
            key(surface, str_of("method"), str_of("path")),
            "route-inventory.json",
        );
    }
    let openapi: serde_json::Value =
        serde_json::from_str(s.openapi).map_err(|e| format!("openapi.json: {e}"))?;
    let paths = openapi["paths"]
        .as_object()
        .ok_or("openapi.json: no paths")?;
    let mut in_openapi = BTreeSet::new();
    for (path, item) in paths {
        for method in OPENAPI_METHODS {
            if item.get(method).is_some() {
                let method = method.to_ascii_uppercase();
                rows.insert(key("ApiV2", &method, path), "openapi.json");
                in_openapi.insert((method, path.clone()));
            }
        }
    }
    let api_listener: BTreeSet<(String, String)> = list
        .iter()
        .filter(|r| r["listener"].as_str() == Some("api"))
        .map(|r| {
            (
                r["method"].as_str().unwrap_or_default().to_string(),
                r["path"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    for (method, path) in manifest_rows(s.api_manifest) {
        let pair = (method, path);
        if !in_openapi.contains(&pair) && !api_listener.contains(&pair) {
            rows.insert(
                key("ApiV2Walked", &pair.0, &pair.1),
                "internal/api/testdata/media_routes.txt",
            );
        }
    }
    for (method, path) in manifest_rows(s.jelly_manifest) {
        rows.insert(
            key("Jellycompat", &method, &path),
            "internal/jellycompat/testdata/media_routes.txt",
        );
    }
    for (method, path) in manifest_rows(s.abs_manifest) {
        rows.insert(
            key("Abs", &method, &path),
            "internal/audiobooks/abs/testdata/media_routes.txt",
        );
    }
    for (surface, method, path, _why) in WIRING_CONDITIONAL_ROWS {
        rows.insert(key(surface, method, path), "wiring-conditional");
    }
    Ok(rows)
}

/// Compares the table with the denominators. `Err` names every line to add and every line to delete.
pub fn reconcile(
    declared: &[Key],
    denominators: &BTreeMap<Key, &'static str>,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    let mut duplicate = Vec::new();
    for k in declared {
        if !seen.insert(k.clone()) {
            duplicate.push(k.clone());
        }
    }
    let missing: Vec<_> = denominators
        .iter()
        .filter(|(k, _)| !seen.contains(*k))
        .collect();
    let extra: Vec<_> = seen
        .iter()
        .filter(|k| !denominators.contains_key(*k))
        .collect();
    if missing.is_empty() && extra.is_empty() && duplicate.is_empty() {
        return Ok(());
    }
    let mut msg = String::from("the row table does not match the contract artifacts\n");
    for (k, source) in &missing {
        msg.push_str(&format!(
            "  add to src/rows_table.rs ({source}): go({}, {:?}, {:?}),\n",
            k.0, k.1, k.2
        ));
    }
    for k in &extra {
        msg.push_str(&format!(
            "  delete from src/rows_table.rs (no artifact names it): {} {} {}\n",
            k.0, k.1, k.2
        ));
    }
    for k in &duplicate {
        msg.push_str(&format!(
            "  declared twice in src/rows_table.rs: {} {} {}\n",
            k.0, k.1, k.2
        ));
    }
    Err(msg)
}
