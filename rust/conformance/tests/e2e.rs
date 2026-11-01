//! Drives the real runner over HTTP against two small servers that differ the way a
//! real port could. The servers hold state, so these tests would fail if requests
//! were sent out of step, to the wrong side, or with another side's generated id.

use serde_json::{json, Value};
use silo_conformance::baseline::{self, CandidateKind};
use silo_conformance::model::{Auth, Case, Identity, Phase, Route, Surface, PROXY_MARKER_HEADER};
use silo_conformance::normalize::Rules;
use silo_conformance::report::{route_reports, FlakeSet, RouteState};
use silo_conformance::runner::{Config, RunOutput, Runner};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Copy, Default)]
struct Quirks {
    field_as_string: bool,
    proxy_marker: bool,
    ignores_if_none_match: bool,
    id_seed: u32,
    drops_cache_control: bool,
    error_shape_differs: bool,
}

#[derive(Default)]
struct Store {
    next_id: u32,
    things: BTreeMap<String, Value>,
    log: Vec<String>,
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

fn json_reply(status: u16, v: Value) -> Reply {
    Reply {
        status,
        headers: vec![("Content-Type", "application/json".to_string())],
        body: v.to_string(),
    }
}

fn handle(
    q: Quirks,
    store: &Mutex<Store>,
    method: &str,
    path: &str,
    headers: &str,
    body: &str,
) -> Reply {
    let mut s = store.lock().unwrap();
    s.log.push(format!("{method} {path}"));
    if path == "/api/v2/account/me" {
        return if headers.contains("authorization: bearer") {
            json_reply(200, json!({"ok": true}))
        } else {
            json_reply(401, json!({"error": "unauthorized"}))
        };
    }
    if path == "/api/v2/stable" {
        let etag = "\"v1\"".to_string();
        if headers.contains("if-none-match") && !q.ignores_if_none_match {
            return Reply {
                status: 304,
                headers: vec![("ETag", etag)],
                body: String::new(),
            };
        }
        let mut r = json_reply(
            200,
            json!({"count": if q.field_as_string { json!("3") } else { json!(3) }}),
        );
        r.headers.push(("ETag", etag));
        if !q.drops_cache_control {
            r.headers.push(("Cache-Control", "no-store".to_string()));
        }
        return r;
    }
    if path == "/api/v2/things" && method == "POST" {
        if serde_json::from_str::<Value>(body).is_err() {
            let shape = if q.error_shape_differs {
                json!({"message": "bad"})
            } else {
                json!({"error": "bad"})
            };
            return json_reply(400, shape);
        }
        s.next_id += 1;
        // Ids differ between the servers, as random ids do.
        let id = format!("{:08x}-0000-4000-8000-000000000000", q.id_seed + s.next_id);
        let thing = json!({"id": id, "self": format!("/api/v2/things/{id}")});
        s.things.insert(id.clone(), thing.clone());
        return json_reply(201, thing);
    }
    if let Some(id) = path.strip_prefix("/api/v2/things/") {
        return match (method, s.things.get(id).cloned()) {
            ("GET", Some(t)) => json_reply(200, t),
            ("DELETE", Some(_)) => {
                s.things.remove(id);
                Reply {
                    status: 204,
                    headers: vec![],
                    body: String::new(),
                }
            }
            _ => json_reply(404, json!({"error": "not_found"})),
        };
    }
    json_reply(404, json!({"error": "no route"}))
}

fn serve(q: Quirks) -> (String, Arc<Mutex<Store>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let store = Arc::new(Mutex::new(Store::default()));
    let shared = store.clone();
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let store = shared.clone();
            thread::spawn(move || connection(conn, q, &store));
        }
    });
    (base, store)
}

fn connection(mut conn: TcpStream, q: Quirks, store: &Mutex<Store>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            match conn.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    continue;
                }
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
        let first = String::from_utf8_lossy(&buf[..head_end])
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        let mut parts = first.split(' ');
        let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + 4 + len {
            match conn.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body = String::from_utf8_lossy(&buf[head_end + 4..head_end + 4 + len]).into_owned();
        let reply = handle(q, store, method, path, &head, &body);
        let mut out = format!(
            "HTTP/1.1 {} X\r\nContent-Length: {}\r\n",
            reply.status,
            reply.body.len()
        );
        for (k, v) in reply.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        if q.proxy_marker {
            out.push_str(&format!("{PROXY_MARKER_HEADER}: go\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(&reply.body);
        if conn.write_all(out.as_bytes()).is_err() {
            return;
        }
        buf.drain(..head_end + 4 + len);
    }
}

fn route(method: &str, path: &str) -> Route {
    Route {
        surface: Surface::ApiV2,
        method: method.to_string(),
        path: path.to_string(),
        auth: Auth::Profile,
        op: None,
        streams: false,
        websocket: false,
        handle_all: false,
        request_kind: None,
        source: "test",
    }
}

struct World {
    routes: Vec<Route>,
    cases: Vec<Case>,
}

fn world() -> World {
    let routes = vec![
        route("GET", "/api/v2/stable"),
        route("POST", "/api/v2/things"),
        route("GET", "/api/v2/things/{id}"),
        route("DELETE", "/api/v2/things/{id}"),
        route("GET", "/api/v2/never"),
    ];
    let case = |route_idx: usize, name: &str, phase: Phase| {
        let r: &Route = &routes[route_idx];
        Case {
            id: format!("{}#{name}", r.key()),
            route: route_idx,
            name: name.to_string(),
            phase,
            identity: Identity::User,
            method: r.method.clone(),
            path: r.path.clone(),
            query: vec![],
            headers: vec![],
            body: None,
            content_type: None,
            path_override: None,
            capture_as: None,
            may_mutate: false,
            skip_body: None,
            timeout_secs: 5,
            sort_key: String::new(),
        }
    };
    let mut create = case(1, "valid", Phase::Seed);
    create.body = Some(b"{}".to_vec());
    create.content_type = Some("application/json".to_string());
    create.capture_as = Some("/api/v2/things".to_string());
    create.may_mutate = true;
    let mut malformed = case(1, "invalid_json", Phase::Rejections);
    malformed.body = Some(b"{".to_vec());
    malformed.content_type = Some("application/json".to_string());
    let mut delete = case(3, "valid", Phase::MutateV2);
    delete.may_mutate = true;
    let cases = vec![
        create,
        case(0, "user", Phase::Reads),
        case(2, "user", Phase::Reads),
        malformed,
        delete,
    ];
    World { routes, cases }
}

fn compare(
    reference: Quirks,
    candidate: Quirks,
) -> (World, RunOutput, Arc<Mutex<Store>>, Arc<Mutex<Store>>) {
    let w = world();
    let (ra, store_a) = serve(reference);
    let (rb, store_b) = serve(candidate);
    let mut urls = BTreeMap::new();
    urls.insert(Surface::ApiV2, (ra, rb));
    let mut fixture = BTreeMap::new();
    fixture.insert("CONF_USER_API_KEY".to_string(), "k".to_string());
    fixture.insert("CONF_ADMIN_API_KEY".to_string(), "k".to_string());
    let cfg = Config {
        urls,
        fixture,
        rules: Rules::default(),
        proxy_header: PROXY_MARKER_HEADER.to_string(),
        reset_reference: None,
        reset_candidate: None,
        only: None,
        progress: false,
        tag_cases: false,
    };
    let out = Runner::new(&cfg, &w.routes, 0).run(&w.cases).unwrap();
    (w, out, store_a, store_b)
}

fn seeded() -> (Quirks, Quirks) {
    (
        Quirks {
            id_seed: 0x1000,
            ..Quirks::default()
        },
        Quirks {
            id_seed: 0x2000,
            ..Quirks::default()
        },
    )
}

fn state(w: &World, out: &RunOutput, key: &str) -> RouteState {
    route_reports(&w.routes, out, &FlakeSet::new())
        .into_iter()
        .find(|r| r.key == key)
        .unwrap_or_else(|| panic!("no route {key}"))
        .state
}

#[test]
fn identical_servers_match_even_with_their_own_generated_ids() {
    let (a, b) = seeded();
    let (w, out, store_a, store_b) = compare(a, b);
    assert_eq!(
        state(&w, &out, "api_v2 GET /api/v2/stable"),
        RouteState::Matched
    );
    assert_eq!(
        state(&w, &out, "api_v2 POST /api/v2/things"),
        RouteState::Matched
    );
    // The second side was asked for its own id, not the first side's.
    assert_eq!(
        state(&w, &out, "api_v2 GET /api/v2/things/{id}"),
        RouteState::Matched
    );
    assert_eq!(
        state(&w, &out, "api_v2 DELETE /api/v2/things/{id}"),
        RouteState::Matched
    );
    // Declared in the universe but never requested.
    assert_eq!(
        state(&w, &out, "api_v2 GET /api/v2/never"),
        RouteState::NotExercised
    );
    let (la, lb) = (store_a.lock().unwrap(), store_b.lock().unwrap());
    assert_eq!(
        la.next_id, lb.next_id,
        "both servers must apply the same writes"
    );
    assert!(la.log.iter().any(|l| l.contains("00001001")));
    assert!(lb.log.iter().any(|l| l.contains("00002001")));
    assert!(
        !lb.log.iter().any(|l| l.contains("00001001")),
        "candidate was sent a reference id"
    );
}

#[test]
fn a_changed_json_type_is_a_difference_at_its_path() {
    let (a, mut b) = seeded();
    b.field_as_string = true;
    let (w, out, _, _) = compare(a, b);
    assert_eq!(
        state(&w, &out, "api_v2 GET /api/v2/stable"),
        RouteState::Differs
    );
    let result = out
        .results
        .iter()
        .find(|r| r.id == "api_v2 GET /api/v2/stable#user")
        .unwrap();
    assert!(result.diffs.iter().any(|d| d.at == "$.count"));
}

#[test]
fn error_bodies_are_compared() {
    let (a, mut b) = seeded();
    b.error_shape_differs = true;
    let (w, out, _, _) = compare(a, b);
    assert_eq!(
        state(&w, &out, "api_v2 POST /api/v2/things"),
        RouteState::Differs
    );
}

#[test]
fn a_dropped_compared_header_is_a_difference() {
    let (a, mut b) = seeded();
    b.drops_cache_control = true;
    let (w, out, _, _) = compare(a, b);
    assert_eq!(
        state(&w, &out, "api_v2 GET /api/v2/stable"),
        RouteState::Differs
    );
}

#[test]
fn a_candidate_that_ignores_if_none_match_is_caught_by_the_replay() {
    let (a, mut b) = seeded();
    b.ignores_if_none_match = true;
    let (_, out, store_a, _) = compare(a, b);
    let result = out
        .results
        .iter()
        .find(|r| r.id == "api_v2 GET /api/v2/stable#user")
        .unwrap();
    assert!(
        result.diffs.iter().any(|d| d.at == "revalidation status"),
        "{:?}",
        result.diffs
    );
    let count = store_a
        .lock()
        .unwrap()
        .log
        .iter()
        .filter(|l| l.ends_with("/api/v2/stable"))
        .count();
    assert_eq!(count, 2, "one request and one revalidation");
}

#[test]
fn a_proxied_answer_is_not_ported_and_a_regression_only_if_the_baseline_says_ported() {
    let (a, b) = seeded();
    let (w, good, _, _) = compare(a, b);
    let (a2, mut b2) = seeded();
    b2.proxy_marker = true;
    let (_, proxied, _, _) = compare(a2, b2);
    let key = "api_v2 GET /api/v2/stable";
    assert_eq!(state(&w, &proxied, key), RouteState::NotPorted);

    let good_reports = route_reports(&w.routes, &good, &FlakeSet::new());
    let proxied_reports = route_reports(&w.routes, &proxied, &FlakeSet::new());
    let kinds = |kind| {
        let base = baseline::record(
            kind,
            std::slice::from_ref(&good),
            &good_reports,
            BTreeMap::new(),
            "t",
            &baseline::ManualFlakes::default(),
        );
        baseline::compare(&base, &proxied_reports)
            .regressions
            .into_iter()
            .map(|r| r.kind)
            .collect::<Vec<_>>()
    };
    assert!(kinds(CandidateKind::SelfCompare).is_empty());
    let ratchet = kinds(CandidateKind::Strangler);
    assert!(ratchet.iter().all(|k| k == "ported_route_now_proxied"));
    assert!(!ratchet.is_empty());
}
