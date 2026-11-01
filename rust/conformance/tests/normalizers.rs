//! Every rule in baseline/normalizers.json, driven through the real differ: the pair
//! it exists to excuse must pass, and values outside what it should excuse must not.
//! A new rule must get a row here, so its limits are stated when it is written.

use serde_json::{json, Value};
use silo_conformance::diff::{compare, Aliases, Ctx};
use silo_conformance::http::Exchange;
use silo_conformance::normalize::{b64url_encode, Format, PathSeg, Rule, Rules};
use std::path::Path;

const RUN_START: i64 = 1_000_000_000;

fn load_rules() -> Rules {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("baseline/normalizers.json");
    Rules::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct Row {
    surface: &'static str,
    route: &'static str,
    a: Value,
    b: Value,
    bad: Vec<Value>,
}

fn row(surface: &'static str, route: &'static str, a: Value, b: Value, bad: Vec<Value>) -> Row {
    Row {
        surface,
        route,
        a,
        b,
        bad,
    }
}

fn jwt(alg: &str, claims: Value) -> String {
    let h = b64url_encode(json!({"alg": alg, "typ": "JWT"}).to_string().as_bytes());
    let p = b64url_encode(claims.to_string().as_bytes());
    format!("{h}.{p}.c2ln")
}

const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

fn uuid_row(surface: &'static str, route: &'static str) -> Row {
    row(
        surface,
        route,
        json!(UUID_A),
        json!(UUID_B),
        vec![
            json!("not-a-uuid"),
            json!(UUID_B.to_ascii_uppercase().replace('2', "A")),
            json!("22222222-2222-7222-8222-222222222222"),
            json!(1),
            Value::Null,
        ],
    )
}

fn gauge_row(route: &'static str) -> Row {
    row(
        "api_v2",
        route,
        json!(1),
        json!(2.5),
        vec![json!(-1), json!("1"), Value::Null],
    )
}

fn row_for(id: &str) -> Option<Row> {
    const AUTH: &str = "POST /api/v2/auth/device/start";
    const LOGS: &str = "GET /api/v2/admin/logs/app";
    Some(match id {
        "problem-instance" => row(
            "api_v2",
            "GET /api/v2/x",
            json!("urn:silo:request:aaaaaaaaaaaaaaaaaaaaaaaa"),
            json!("urn:silo:request:bbbbbbbbbbbbbbbbbbbbbbbb"),
            vec![
                json!("urn:silo:request:abc"),
                json!("urn:other:request:bbbbbbbbbbbbbbbbbbbbbbbb"),
                json!("!! bad !!"),
            ],
        ),
        "jwt-tokens" => {
            let c = |sub: u32, exp: i64| json!({"sub": sub, "iat": 1000, "exp": exp});
            row(
                "api_v2",
                "POST /api/v1/auth/login",
                json!(jwt("HS256", c(1, 4600))),
                json!(jwt("HS256", c(2, 4630))),
                vec![
                    json!(jwt("none", c(1, 4600))),
                    json!(jwt("HS256", json!({"sub": 1, "iat": 1000}))),
                    json!(jwt("HS256", c(1, 90000))),
                    json!("not.a.jwt"),
                    json!("eyJa.b.c"),
                ],
            )
        }
        "run-time-timestamps" => row(
            "api_v2",
            "GET /api/v2/x",
            json!("2026-11-01T00:00:00.5Z"),
            json!("2026-11-01T00:00:10.25Z"),
            vec![
                json!("2026-11-01T00:00:10.25+00:00"),
                json!("2026-11-01T00:00:10Z"),
                json!("2026-11-01 00:00:10.25Z"),
                json!("2026-11-02T00:00:00.5Z"),
                json!("2000-01-01T00:00:00.5Z"),
                json!("not a timestamp"),
            ],
        ),
        "telemetry-parity-mismatch-times" => row(
            "api_v2",
            "GET /api/v2/admin/stream-telemetry/parity",
            json!("2026-11-01T00:00:00.5Z"),
            json!("2026-11-01T00:00:10.25Z"),
            vec![
                json!("2026-11-01T00:00:10.25+00:00"),
                json!("2026-11-02T00:00:00.5Z"),
                json!("2000-01-01T00:00:00.5Z"),
                json!("direct"),
            ],
        ),
        "stats-window-bounds" => row(
            "api_v2",
            "GET /api/v2/admin/stats/api-clients",
            json!("2000-01-01T00:00:00.5Z"),
            json!("2000-01-01T00:00:30.5Z"),
            vec![
                json!("2000-01-02T00:00:00.5Z"),
                json!("2000-01-01T00:00:30.5+00:00"),
                json!("2000-01-01T00:00:30Z"),
                json!("nope"),
            ],
        ),
        "client-address" => row(
            "api_v2",
            "GET /api/v2/x",
            json!("172.25.0.3"),
            json!("172.25.10.123"),
            vec![
                json!("999.1.1.1"),
                json!("172.25.0.3/32"),
                json!("localhost"),
            ],
        ),
        "feed-cursors" => row(
            "api_v2",
            LOGS,
            json!("MTc5"),
            json!("MTc5MzUy"),
            vec![json!("cursor:page=2"), json!("!! bad !!")],
        ),
        "keyset-cursors" => row(
            "api_v2",
            "GET /api/v2/catalog",
            json!("eyJhIjox.sig-a"),
            json!("eyJhIjoyMDB9.sig-b"),
            vec![json!("cursor:page=2"), json!("MTc5")],
        ),
        "policy-decision-detail" | "marker-history-request-id" => row(
            "api_v2",
            if id == "policy-decision-detail" {
                "GET /api/v2/admin/policy/decisions/{id}"
            } else {
                "GET /api/v2/admin/markers/history"
            },
            json!("aaaaaaaaaaaaaaaaaaaaaaaa"),
            json!("bbbbbbbbbbbbbbbbbbbbbbbb"),
            vec![
                json!("aaaa"),
                json!("AAAAAAAAAAAAAAAAAAAAAAAA"),
                json!("!! bad !!"),
            ],
        ),
        "policy-decision-input-digest" => row(
            "api_v2",
            "GET /api/v2/admin/policy/decisions/{id}",
            json!("a".repeat(64)),
            json!("b".repeat(64)),
            vec![json!("b".repeat(32)), json!("B".repeat(64)), json!("nope")],
        ),
        "policy-decision-eval-time" => gauge_row("GET /api/v2/admin/policy/decisions/{id}"),
        "policy-simulate-time" => gauge_row("POST /api/v2/admin/policy/simulate"),
        "discord-test-duration" => gauge_row("POST /api/v2/admin/notifications/discord/test"),
        "storage-usage-gauge" => gauge_row("GET /api/v2/admin/downloads/storage"),
        "warning-count-gauge" => gauge_row("GET /api/v2/admin/server/status"),
        "server-gauges" => gauge_row("GET /api/v2/admin/system/resources"),
        "request-count-gauge" => gauge_row("GET /api/v2/admin/users/{id}/ips"),
        "telemetry-build-time" => gauge_row("GET /api/v2/admin/stream-telemetry/parity"),
        "telemetry-parity-mismatch-sessions" => {
            uuid_row("api_v2", "GET /api/v2/admin/stream-telemetry/parity")
        }
        "sync-generation" => uuid_row("api_v2", "GET /api/v2/sync/progress/capabilities"),
        "login-session-ids" => uuid_row("api_v2", "GET /api/v2/auth/sessions"),
        "generated-uuid-ids" => uuid_row("api_v2", "POST /api/v2/collections"),
        "server-instance-id" => uuid_row("api_v2", "GET /api/v2/admin/system/resources"),
        "jf-play-session-id" => uuid_row("jellycompat", "GET /Items/{id}/PlaybackInfo"),
        "abs-account-times" => row(
            "abs",
            "GET /api/me",
            json!(1793526251564i64),
            json!(1793526252000i64),
            vec![
                json!(1793526251i64),
                json!(1793626251564i64),
                json!(0),
                json!("1793526251564"),
            ],
        ),
        "invite-claim-url" => row(
            "api_v2",
            "POST /api/v2/admin/invitations",
            json!("https://silo.conformance.test/invite/aaaaaaaa"),
            json!("https://silo.conformance.test/invite/bbbbbbbb"),
            vec![
                json!("https://silo.conformance.test/invite/aaa"),
                json!("https://other.test/invite/bbbbbbbb"),
                json!("!! bad !!"),
            ],
        ),
        "password-reset-url" => row(
            "api_v2",
            "POST /api/v2/admin/users/{id}/password-reset",
            json!("https://silo.conformance.test/reset-password/aaaaaaaa"),
            json!("https://silo.conformance.test/reset-password/bbbbbbbb"),
            vec![
                json!("https://silo.conformance.test/reset-password/aaa"),
                json!("https://silo.conformance.test/reset/bbbbbbbb"),
            ],
        ),
        "chatgpt-login-status" | "chatgpt-login-attempt" | "ws-ticket" => row(
            "api_v2",
            match id {
                "chatgpt-login-status" => "GET /api/v2/admin/ai/chatgpt",
                "chatgpt-login-attempt" => "POST /api/v2/admin/ai/chatgpt/login",
                _ => "POST /api/v2/events/ws-ticket",
            },
            json!("aaaaaaaaaaaaaaaaaaaaaaaa"),
            json!("bbbbbbbbbbbbbbbbbbbbbbbb"),
            vec![json!("aaaa"), json!("aaaa aaaa aaaa aaaa aaaa"), json!("")],
        ),
        "chatgpt-authorize-url" => {
            let url = |challenge: &str, scope: &str| {
                json!(format!(
                    "https://auth.openai.com/api/accounts/authorize?agent_name_hint=Silo&client_id=dynamic_agent_client&code_challenge={challenge}&code_challenge_method=S256&ext_agent_host_id=h&nonce=n&redirect_uri=http%3A%2F%2Flocalhost&resource=r&response_type=code&scope={scope}&state=s"
                ))
            };
            row(
                "api_v2",
                "POST /api/v2/admin/ai/chatgpt/login",
                url("aaaa", "read"),
                url("bbbb", "read"),
                vec![
                    url("aaaa", "write"),
                    url("a", "read"),
                    json!("https://auth.openai.com/api/accounts/authorize?x=1"),
                ],
            )
        }
        "web-operation-process" => row(
            "api_v2",
            "GET /api/v2/admin/jellyfin-compat/status",
            json!("56626538"),
            json!("566265381"),
            vec![json!("process-1"), json!("")],
        ),
        "web-operation-id-in-status" => row(
            "api_v2",
            "GET /api/v2/admin/jellyfin-compat/status",
            json!("remove-1793526555969336901"),
            json!("remove-1793526575930435345"),
            vec![json!("remove-1"), json!("add-1793526575930435345")],
        ),
        "catalog-snapshot-id" => row(
            "api_v1",
            "GET /api/v1/catalog",
            json!("2026-11-01T00:00:00.5Z"),
            json!("2026-11-01T00:00:10.5Z"),
            vec![
                json!("2026-11-01T00:00:10.5+00:00"),
                json!("2000-01-01T00:00:00.5Z"),
            ],
        ),
        "api-key-material" => row(
            "api_v2",
            "POST /api/v2/admin/api-keys",
            json!("sa_aaaaaaaa"),
            json!("sa_bbbbbbbb"),
            vec![
                json!(format!("sa_{}", "b".repeat(64))),
                json!("xx_bbbbbbbb"),
                json!("sa_BBBBBBBB"),
            ],
        ),
        "generated-snowflake-ids" => row(
            "api_v2",
            "POST /api/v2/admin/sections",
            json!("150087577985136888"),
            json!("150087577985136999"),
            vec![
                json!("15008757798513699"),
                json!("123"),
                json!("aaaaaaaaaaaaaaaaaa"),
            ],
        ),
        "generated-ulid-ids" => row(
            "api_v2",
            "POST /api/v2/notifications/push/devices",
            json!("01M6B811CZNK585VBXCS5YY38C"),
            json!("01M6B811CZNK585VBXCTM52ZX2"),
            vec![json!("01M6B811"), json!("01m6b811cznk585vbxctm52zx2")],
        ),
        "short-codes" => row(
            "api_v2",
            "POST /api/v2/admin/invite-codes",
            json!("ZPQFTY8E"),
            json!("AYR2KUZX"),
            vec![json!("AYR2KUZ"), json!("ayr2kuzx"), json!("conformance")],
        ),
        "room-invite-link" => row(
            "api_v2",
            "POST /api/v2/watch-together/rooms",
            json!("/rooms/join?token=AAAAAAAA"),
            json!("/rooms/join?token=BBBBBBBB"),
            vec![
                json!("/rooms/join?token=AAA"),
                json!("/join?token=BBBBBBBB"),
            ],
        ),
        "device-pairing-codes" => row(
            "api_v2",
            AUTH,
            json!("9sdET6gtrK-Um8GyFwEkEjxg9fNraGW9pZMoaz7fn6U"),
            json!("WsC_2ghl4pyMP2B-q27I7dxjIRADu9jQGtbRcCqfwIM"),
            vec![json!("short"), json!("anything at all")],
        ),
        "device-pairing-user-code" => row(
            "api_v2",
            AUTH,
            json!("3896-2968"),
            json!("7894-7737"),
            vec![json!("38962968"), json!("ABCD-EFGH"), json!("389-2968")],
        ),
        "device-pairing-match-code" => row(
            "api_v2",
            AUTH,
            json!("gold duck"),
            json!("blue wool"),
            vec![json!("gold"), json!("Gold Duck"), json!("3896-2968")],
        ),
        "device-pairing-link" => row(
            "api_v2",
            AUTH,
            json!("https://silo.conformance.test/activate?code=08725610"),
            json!("https://silo.conformance.test/activate?code=54904375"),
            vec![
                json!("https://silo.conformance.test/activate?code=5490"),
                json!("https://silo.conformance.test/activate?token=54904375"),
                json!("!! bad !!"),
            ],
        ),
        "upload-id" => row(
            "api_v2",
            "POST /api/v2/admin/plugins/uploads/chunked",
            json!("a16efdfc42f72c81e1e71355d9f9fb16"),
            json!("13a9ee96cf3aa19cdb2dd54453bc1891"),
            vec![
                json!("a16efdfc42f72c81e1e71355d9f9fb16a16e"),
                json!("A16EFDFC42F72C81E1E71355D9F9FB16"),
                json!("abc"),
            ],
        ),
        "sync-revision" => row(
            "api_v2",
            "GET /api/v2/sync/progress/capabilities",
            json!("a".repeat(64)),
            json!("b".repeat(64)),
            vec![json!("b".repeat(128)), json!("B".repeat(64)), json!("abc")],
        ),
        "random-section-order" => row(
            "api_v2",
            "GET /api/v2/home/sections",
            json!(["x", "y", "z"]),
            json!(["z", "x", "y"]),
            vec![json!(["x", "y"]), json!(["x", "y", "q"]), Value::Null],
        ),
        "telemetry-parity-session-ids" => row(
            "api_v2",
            "GET /api/v2/admin/stream-telemetry/parity",
            json!(format!("{UUID_A}=fresh")),
            json!(format!("{UUID_B}=fresh")),
            vec![
                json!(format!("{UUID_B}=stale")),
                json!(UUID_B),
                json!("not an id"),
            ],
        ),
        "signed-url-signature" => {
            let u = |p: &str, q: &str| json!(format!("/api/v2/artwork/local/{p}/w300.webp?{q}"));
            row(
                "api_v2",
                "GET /api/v2/x",
                u("movies/a", "exp=100&sig=aaaa"),
                u("movies/a", "exp=200&sig=bbbb"),
                vec![
                    u("movies/b", "exp=200&sig=bbbb"),
                    u("movies/a", "sig=bbbb&exp=200"),
                    u("movies/a", "exp=200"),
                    u("movies/a", "exp=200&sig=b"),
                ],
            )
        }
        "jf-playback-urls" => {
            let u = |path: &str, sess: &str| {
                json!(format!(
                    "/Videos/02c00107-c2a8-a504-0000-000000000000/{path}?static=true&PlaySessionId={sess}&MediaSourceId=1"
                ))
            };
            row(
                "jellycompat",
                "GET /Items/{id}/PlaybackInfo",
                u("stream", UUID_A),
                u("stream", UUID_B),
                vec![
                    u("master.m3u8", UUID_B),
                    u("stream", "short"),
                    json!("/Videos/x/stream"),
                ],
            )
        }
        "jf-quick-connect" => row(
            "jellycompat",
            "GET /QuickConnect/Initiate",
            json!("370633"),
            json!("496160"),
            vec![json!("370"), json!("abc123")],
        ),
        "jf-client-log-name" => row(
            "jellycompat",
            "POST /ClientLog/Document",
            json!(format!("{UUID_A}.log")),
            json!(format!("{UUID_B}.log")),
            vec![json!(format!("{UUID_B}.txt")), json!("x.log")],
        ),
        "jf-login-session" => row(
            "jellycompat",
            "POST /Users/AuthenticateByName",
            json!(UUID_A),
            json!(UUID_B),
            vec![json!("short"), json!("11111111111111111111111111111111")],
        ),
        "collection-collage-url" => {
            let u = |id: &str, q: &str| {
                json!(format!(
                    "/api/v2/artwork/user-collection-images/{id}/collage/w300.abcdef.webp?{q}"
                ))
            };
            row(
                "api_v2",
                "GET /api/v2/collections",
                u(UUID_A, "exp=100&sig=aaaa"),
                u(UUID_B, "exp=200&sig=bbbb"),
                vec![u(UUID_B, "exp=200"), json!("/api/v2/artwork/other")],
            )
        }
        _ => return None,
    })
}

fn doc_at(rule: &Rule, path_index: usize, leaf: Value) -> Value {
    let path = silo_conformance::normalize::parse_path(&rule.spec.json_paths[path_index]).unwrap();
    let sibling = match &rule.spec.format {
        Format::UnorderedArray { when_sibling } => Some(when_sibling.clone()),
        _ => None,
    };
    let mut v = leaf;
    let innermost = path.segs.len().saturating_sub(1);
    for (i, seg) in path.segs.iter().enumerate().rev() {
        v = match seg {
            PathSeg::Key(k) if i == innermost && sibling.is_some() => {
                let s = sibling.as_ref().unwrap();
                json!({ k: v, s.key.clone(): s.equals.clone() })
            }
            PathSeg::Key(k) => json!({ k: v }),
            PathSeg::AnyKey => json!({ "somekey": v }),
            PathSeg::AnyIndex => json!([v]),
        };
    }
    v
}

fn exchange(body: Value) -> Exchange {
    Exchange {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.to_string().into_bytes(),
        ..Exchange::default()
    }
}

fn diff_count(rules: &Rules, surface: &str, route: &str, a: Value, b: Value) -> usize {
    let ctx = Ctx {
        rules,
        surface,
        method_path: route,
        run_start: RUN_START,
        proxy_header: "x-marker",
        reference_path: "/",
        candidate_path: "/",
    };
    compare(
        &ctx,
        &mut Aliases::default(),
        &exchange(a),
        &exchange(b),
        None,
    )
    .diffs
    .len()
}

/// A feed's limits come from its required keys, so its row is generated.
fn check_feed(rules: &Rules, rule: &Rule, required: &[String], keys_vary: bool) {
    let route = feed_route(&rule.spec.id);
    let entry = |value: Value| -> Value {
        let mut m = serde_json::Map::new();
        for k in required {
            m.insert(k.clone(), value.clone());
        }
        m.insert("optional_detail".to_string(), value);
        Value::Object(m)
    };
    for i in 0..rule.spec.json_paths.len() {
        let doc = |leaf: Value| doc_at(rule, i, leaf);
        let id = &rule.spec.id;
        // Different length and contents, same shape: what the rule exists to allow.
        assert_eq!(
            diff_count(
                rules,
                "api_v2",
                route,
                doc(json!([entry(json!("a"))])),
                doc(json!([entry(json!("b")), entry(json!("c"))])),
            ),
            0,
            "{id}: the pair it excuses"
        );
        let base = doc(json!([entry(json!("a"))]));
        let mut missing_required = entry(json!("b"));
        missing_required
            .as_object_mut()
            .unwrap()
            .remove(&required[0]);
        let mut wrong_type = entry(json!("b"));
        wrong_type[&required[0]] = json!(7);
        let mut lost_optional = entry(json!("b"));
        lost_optional
            .as_object_mut()
            .unwrap()
            .remove("optional_detail");
        for (what, bad) in [
            ("emptied", json!([])),
            ("not objects", json!(["x"])),
            ("missing a required key", json!([missing_required])),
            ("a required key changed type", json!([wrong_type])),
            ("a key every entry had is gone", json!([lost_optional])),
        ] {
            if keys_vary && what == "a key every entry had is gone" {
                assert_eq!(
                    diff_count(rules, "api_v2", route, base.clone(), doc(bad)),
                    0
                );
                continue;
            }
            assert!(
                diff_count(rules, "api_v2", route, base.clone(), doc(bad)) > 0,
                "{id}: {what}"
            );
        }
    }
}

fn feed_route(id: &str) -> &'static str {
    match id {
        "own-activity-feeds" => "GET /api/v2/admin/logs/app",
        "own-audit-feed" => "GET /api/v2/admin/logs/audit",
        "own-policy-decision-feed" => "GET /api/v2/admin/policy/decisions",
        "own-export-listing" => "GET /api/v2/admin/catalog/import-sources",
        "own-job-feed" => "GET /api/v2/admin/jobs",
        "own-job-feed-v1" => "GET /api/v1/admin/jobs/",
        "own-session-feed" => "GET /api/v2/admin/sessions",
        other => panic!("feed {other} needs a route in feed_route"),
    }
}

#[test]
fn the_peer_lab_compares_client_addresses_exactly() {
    let lab = load_rules().for_peer_lab();
    assert!(lab.rules.iter().all(|r| r.spec.id != "client-address"));
    assert_eq!(lab.rules.len() + 1, load_rules().rules.len());
}

#[test]
fn every_rule_excuses_its_pair_and_nothing_outside_it() {
    let rules = load_rules();
    let mut missing = Vec::new();
    for rule in &rules.rules {
        let id = rule.spec.id.as_str();
        if let Format::ArrayOfObjects {
            required_keys,
            keys_vary,
        } = &rule.spec.format
        {
            check_feed(&rules, rule, required_keys, *keys_vary);
            continue;
        }
        if rule.spec.body {
            continue; // bandwidth_probe_filler_compares_length_only, below.
        }
        let Some(r) = row_for(id) else {
            missing.push(id.to_string());
            continue;
        };
        for i in 0..rule.spec.json_paths.len() {
            let path = &rule.spec.json_paths[i];
            let doc = |leaf: Value| doc_at(rule, i, leaf);
            assert_eq!(
                diff_count(
                    &rules,
                    r.surface,
                    r.route,
                    doc(r.a.clone()),
                    doc(r.b.clone())
                ),
                0,
                "{id} {path}: must excuse {} vs {}",
                r.a,
                r.b
            );
            for bad in &r.bad {
                assert!(
                    diff_count(
                        &rules,
                        r.surface,
                        r.route,
                        doc(r.a.clone()),
                        doc(bad.clone())
                    ) > 0,
                    "{id} {path}: must not excuse {} vs {bad}",
                    r.a
                );
            }
            // A route the rule does not name gets no excuse.
            if !rule.spec.route.starts_with(".*") && !rule.spec.route.starts_with("[A-Z]+ /.*") {
                assert!(
                    diff_count(
                        &rules,
                        r.surface,
                        "GET /conformance/other",
                        doc(r.a.clone()),
                        doc(r.b.clone())
                    ) > 0,
                    "{id} {path}: applied outside its route"
                );
            }
        }
    }
    assert!(missing.is_empty(), "rules with no row: {missing:?}");
}

#[test]
fn only_a_random_section_may_change_item_order() {
    let rules = load_rules();
    let doc = |section_type: &str, items: Value| json!({"sections": [{"section_type": section_type, "items": items}]});
    let route = "GET /api/v2/home/sections";
    let order = |t: &str| {
        diff_count(
            &rules,
            "api_v2",
            route,
            doc(t, json!(["x", "y"])),
            doc(t, json!(["y", "x"])),
        )
    };
    assert_eq!(order("random"), 0);
    assert!(order("recently_added") > 0);
}

#[test]
fn bandwidth_probe_filler_compares_length_only() {
    let rules = load_rules();
    let bytes = |b: &[u8]| Exchange {
        status: 200,
        headers: vec![("content-type".into(), "application/octet-stream".into())],
        body: b.to_vec(),
        ..Exchange::default()
    };
    let ctx = Ctx {
        rules: &rules,
        surface: "api_v2",
        method_path: "GET /api/v2/playback/bandwidth-probe",
        run_start: RUN_START,
        proxy_header: "x-marker",
        reference_path: "/",
        candidate_path: "/",
    };
    let diffs = |a: &[u8], b: &[u8]| {
        compare(&ctx, &mut Aliases::default(), &bytes(a), &bytes(b), None)
            .diffs
            .len()
    };
    assert_eq!(diffs(&[1, 2, 3], &[9, 9, 9]), 0);
    assert_eq!(diffs(&[1, 2, 3], &[9, 9]), 1);
}

#[test]
fn an_alias_rule_rejects_a_reused_id_and_an_answer_about_another_object() {
    let rules = load_rules();
    let route = "PATCH /api/v2/collections/{id}";
    let ids = |r: &str, c: &str| (exchange(json!({"id": r})), exchange(json!({"id": c})));
    let third = "33333333-3333-4333-8333-333333333333";
    let path_a = format!("/api/v2/collections/{UUID_A}");
    let path_b = format!("/api/v2/collections/{UUID_B}");
    let ctx = |reference_path, candidate_path| Ctx {
        rules: &rules,
        surface: "api_v2",
        method_path: route,
        run_start: RUN_START,
        proxy_header: "x-marker",
        reference_path,
        candidate_path,
    };
    // The object each side's request named: fine, and now remembered.
    let mut aliases = Aliases::default();
    let (a, b) = ids(UUID_A, UUID_B);
    assert!(compare(&ctx(&path_a, &path_b), &mut aliases, &a, &b, None)
        .diffs
        .is_empty());
    // The same reference object now comes back under another candidate id.
    let (a, b) = ids(UUID_A, third);
    assert_eq!(
        compare(&ctx("/", "/"), &mut aliases, &a, &b, None)
            .diffs
            .len(),
        1
    );
    // The candidate reuses an id for a different reference object.
    let (a, b) = ids(third, UUID_B);
    assert_eq!(
        compare(&ctx("/", "/"), &mut aliases, &a, &b, None)
            .diffs
            .len(),
        1
    );
    // A well-formed id, but not the one this side's request named.
    let (a, b) = ids(UUID_A, third);
    assert_eq!(
        compare(
            &ctx(&path_a, &path_b),
            &mut Aliases::default(),
            &a,
            &b,
            None
        )
        .diffs
        .len(),
        1
    );
}
