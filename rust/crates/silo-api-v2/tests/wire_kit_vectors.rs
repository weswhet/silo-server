//! Replays the real-Go vectors under `rust/conformance/vectors/apiv2wire/` (written by
//! `rust/conformance/vectors/generators/apiv2wire`, which calls the real `internal/apiv2`
//! package, directly for its exported functions and through a build-overlay export shim for
//! `fromHumaError` and its mapping helpers) against this crate's port. Every value compared here
//! came out of that generator; nothing in this file is a hand-written expected value.

use serde_json::Value;
use silo_api_v2::cursor::{CursorScope, Cursors};
use silo_api_v2::precondition as pre;
use silo_api_v2::problem::{self, ErrorDetail, HumaErr, Problem};
use silo_api_v2::wire;
use silo_core::apiv2::EntityTag;

// This loads the generator's own already-produced fixture file into a generic `Value` tree for
// the test to pick fields out of; it does not stand in for any Go encoding/decoding behavior, so
// the plain decoder is fine.
#[allow(clippy::disallowed_methods)]
fn vectors(name: &str) -> Value {
    let path = format!(
        "{}/../../conformance/vectors/apiv2wire/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

/// Renders a `Problem` (or its absence) in the same shape the generator's `problemOut` used.
fn problem_json(p: Option<&Problem>) -> Value {
    let Some(p) = p else { return Value::Null };
    let mut obj = serde_json::Map::new();
    obj.insert("type".into(), Value::String(p.r#type.clone()));
    obj.insert("title".into(), Value::String(p.title.clone()));
    obj.insert("status".into(), Value::Number(p.status.into()));
    obj.insert("detail".into(), Value::String(p.detail.clone()));
    obj.insert("instance".into(), Value::String(p.instance.clone()));
    if !p.errors.is_empty() {
        obj.insert("errors".into(), serde_json::to_value(&p.errors).unwrap());
    }
    if !p.headers().is_empty() {
        let mut h = serde_json::Map::new();
        for (k, v) in p.headers() {
            h.entry(k.clone())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .unwrap()
                .push(Value::String(v.clone()));
        }
        obj.insert("headers".into(), Value::Object(h));
    }
    Value::Object(obj)
}

fn want_problem(case: &Value) -> Value {
    case.get("problem").cloned().unwrap_or(Value::Null)
}

fn rendered(opaque: &str) -> EntityTag {
    EntityTag {
        opaque: opaque.to_owned(),
        weak: false,
    }
}

#[test]
fn evaluate_if_match_matches_go() {
    for case in vectors("evaluate_if_match").as_array().unwrap() {
        let if_match = case["if_match"].as_str().unwrap();
        let current = rendered(case["current"]["Opaque"].as_str().unwrap());
        let got = pre::evaluate_if_match(if_match, &current);
        assert_eq!(
            problem_json(got.as_ref()),
            want_problem(case),
            "if_match={if_match:?}"
        );
    }
}

#[test]
fn evaluate_if_none_match_matches_go() {
    for case in vectors("evaluate_if_none_match").as_array().unwrap() {
        let inm = case["if_none_match"].as_str().unwrap();
        let current = rendered(case["current"]["Opaque"].as_str().unwrap());
        let (matched, p) = pre::evaluate_if_none_match(inm, &current);
        assert_eq!(
            matched,
            case["matched"].as_bool().unwrap(),
            "if_none_match={inm:?}"
        );
        assert_eq!(
            problem_json(p.as_ref()),
            want_problem(case),
            "if_none_match={inm:?}"
        );
    }
}

#[test]
fn evaluate_create_only_matches_go() {
    for case in vectors("evaluate_create_only").as_array().unwrap() {
        let inm = case["if_none_match"].as_str().unwrap();
        let existing = case
            .get("existing")
            .and_then(|e| e.get("Opaque"))
            .and_then(Value::as_str)
            .map(rendered);
        let got = pre::evaluate_create_only(inm, existing.as_ref());
        assert_eq!(
            problem_json(got.as_ref()),
            want_problem(case),
            "if_none_match={inm:?} existing={existing:?}"
        );
    }
}

#[test]
fn evaluate_guarded_preconditions_matches_go() {
    for case in vectors("evaluate_guarded_preconditions")
        .as_array()
        .unwrap()
    {
        let im = case["IfMatch"].as_str().unwrap();
        let inm = case["IfNoneMatch"].as_str().unwrap();
        let current = rendered("cur1");
        let got = pre::evaluate_guarded_preconditions(im, inm, &current);
        assert_eq!(
            problem_json(got.as_ref()),
            want_problem(case),
            "if_match={im:?} if_none_match={inm:?}"
        );
    }
}

#[test]
fn evaluate_read_preconditions_matches_go() {
    for case in vectors("evaluate_read_preconditions").as_array().unwrap() {
        let im = case["IfMatch"].as_str().unwrap();
        let inm = case["IfNoneMatch"].as_str().unwrap();
        let current = rendered("cur1");
        let (not_modified, p) = pre::evaluate_read_preconditions(im, inm, &current);
        assert_eq!(
            not_modified,
            case["NotModified"].as_bool().unwrap(),
            "if_match={im:?} if_none_match={inm:?}"
        );
        assert_eq!(
            problem_json(p.as_ref()),
            want_problem(case),
            "if_match={im:?} if_none_match={inm:?}"
        );
    }
}

#[test]
fn evaluate_create_only_preconditions_matches_go() {
    for case in vectors("evaluate_create_only_preconditions")
        .as_array()
        .unwrap()
    {
        let im = case["IfMatch"].as_str().unwrap();
        let inm = case["IfNoneMatch"].as_str().unwrap();
        let existing = case
            .get("existing")
            .and_then(|e| e.get("Opaque"))
            .and_then(Value::as_str)
            .map(rendered);
        let got = pre::evaluate_create_only_preconditions(im, inm, existing.as_ref());
        assert_eq!(
            problem_json(got.as_ref()),
            want_problem(case),
            "if_match={im:?} if_none_match={inm:?} existing={existing:?}"
        );
    }
}

#[test]
fn is_overwrite_matches_go() {
    for case in vectors("is_overwrite").as_array().unwrap() {
        let im = case["IfMatch"].as_str().unwrap();
        assert_eq!(
            pre::is_overwrite(im),
            case["Is"].as_bool().unwrap(),
            "if_match={im:?}"
        );
    }
}

#[test]
fn stale_version_problem_matches_go() {
    let cases = vectors("stale_version_problem");
    let cases = cases.as_array().unwrap();
    let non_zero = pre::stale_version_problem(Some(&pre::Tag {
        opaque: b"cur1".to_vec(),
        weak: false,
    }));
    assert_eq!(problem_json(Some(&non_zero)), cases[0]["problem"]);
    let zero = pre::stale_version_problem(None);
    assert_eq!(problem_json(Some(&zero)), cases[1]["problem"]);
}

#[test]
fn cursor_round_trip_matches_go() {
    let secret = b"vector-secret-do-not-use-in-prod";
    let c = Cursors::new(secret.to_vec());
    let scope = CursorScope {
        operation_id: "list-items".to_owned(),
        security: "acct:1/profile:2".to_owned(),
        filter: "library=1".to_owned(),
        sort: "name".to_owned(),
        tiebreaker: "item_id".to_owned(),
    };

    let encoded = vectors("cursor_encode");
    let case = &encoded.as_array().unwrap()[0];
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Position {
        name: String,
        id: i64,
    }
    let position = Position {
        name: case["position"]["name"].as_str().unwrap().to_owned(),
        id: case["position"]["id"].as_i64().unwrap(),
    };
    let got = c.encode(&scope, &position).expect("encode");
    assert_eq!(got, case["cursor"].as_str().unwrap());

    for case in vectors("cursor_decode").as_array().unwrap() {
        let scope = CursorScope {
            operation_id: case["scope"]["OperationID"].as_str().unwrap().to_owned(),
            security: case["scope"]["Security"].as_str().unwrap().to_owned(),
            filter: case["scope"]["Filter"].as_str().unwrap().to_owned(),
            sort: case["scope"]["Sort"].as_str().unwrap().to_owned(),
            tiebreaker: case["scope"]["Tiebreaker"].as_str().unwrap().to_owned(),
        };
        let cursor = case["cursor"].as_str().unwrap();
        let ok = case["ok"].as_bool().unwrap();
        let got: Result<Position, Problem> = c.decode(&scope, cursor);
        assert_eq!(got.is_ok(), ok, "cursor={cursor:?}");
        match got {
            Ok(pos) => {
                let want = &case["position"];
                assert_eq!(pos.name, want["name"].as_str().unwrap());
                assert_eq!(pos.id, want["id"].as_i64().unwrap());
            }
            Err(p) => assert_eq!(problem_json(Some(&p)), case["problem"], "cursor={cursor:?}"),
        }
    }
}

#[test]
fn cursor_without_secret_matches_go() {
    let want = vectors("cursor_no_secret");
    let c = Cursors::new(Vec::new());
    let scope = CursorScope::default();
    let err = c.encode(&scope, &serde_json::json!({})).unwrap_err();
    assert_eq!(problem_json(Some(&err)), want["encode_err"]);
    let decoded: Result<serde_json::Value, Problem> = c.decode(&scope, "whatever.cursor");
    assert_eq!(
        problem_json(Some(&decoded.unwrap_err())),
        want["decode_err"]
    );
}

// These three tests assert that this crate's wire types marshal/unmarshal exactly as Go's
// encoding/json does on the recorded vectors, so they go through `silo_gocompat::json` rather
// than plain `serde_json`, matching every other Go-wire-format site in this workspace.

#[test]
fn instant_matches_go() {
    for case in vectors("instant").as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let got: Result<wire::Instant, _> = silo_gocompat::json::unmarshal(input.as_bytes());
        assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap(), "input={input}");
        if let Ok(i) = got {
            let out = silo_gocompat::json::marshal_to_string(&i).unwrap();
            assert_eq!(out, case["out"].as_str().unwrap(), "input={input}");
        }
    }
}

#[test]
fn nullable_instant_matches_go() {
    for case in vectors("nullable_instant").as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let got: Result<wire::NullableInstant, _> =
            silo_gocompat::json::unmarshal(input.as_bytes());
        assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap(), "input={input}");
        if let Ok(n) = got {
            let out = silo_gocompat::json::marshal_to_string(&n).unwrap();
            assert_eq!(out, case["out"].as_str().unwrap(), "input={input}");
        }
    }
}

#[test]
fn patch_matches_go() {
    #[derive(serde::Serialize, serde::Deserialize, Default)]
    struct WithPatch {
        #[serde(default, skip_serializing_if = "wire::Patch::is_absent")]
        field: wire::Patch<String>,
    }
    for case in vectors("patch").as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let w: WithPatch = silo_gocompat::json::unmarshal(input.as_bytes()).unwrap();
        assert_eq!(
            w.field.present,
            case["present"].as_bool().unwrap(),
            "input={input}"
        );
        assert_eq!(
            w.field.null,
            case["null"].as_bool().unwrap(),
            "input={input}"
        );
        if w.field.present && !w.field.null {
            assert_eq!(w.field.value, case["value"].as_str().unwrap());
        }
        assert_eq!(w.field.is_absent(), !case["present"].as_bool().unwrap());
        let out = silo_gocompat::json::marshal_to_string(&w).unwrap();
        assert_eq!(out, case["out"].as_str().unwrap(), "input={input}");
    }
}

#[test]
fn parse_sort_matches_go() {
    for case in vectors("parse_sort").as_array().unwrap() {
        let raw = case["raw"].as_str().unwrap();
        let allowed: Vec<&str> = case["allowed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let got = wire::parse_sort(raw, &allowed);
        match case.get("problem") {
            Some(p) if !p.is_null() => {
                let err = got.unwrap_err();
                assert_eq!(problem_json(Some(&err)), *p, "raw={raw:?}");
            }
            _ => {
                let fields = got.unwrap_or_else(|p| panic!("raw={raw:?}: {p:?}"));
                let want = case
                    .get("fields")
                    .cloned()
                    .unwrap_or(Value::Array(Vec::new()));
                let want: Vec<(String, bool)> = want
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| {
                        (
                            f["Field"].as_str().unwrap().to_owned(),
                            f["Desc"].as_bool().unwrap(),
                        )
                    })
                    .collect();
                let got: Vec<(String, bool)> =
                    fields.into_iter().map(|f| (f.field, f.desc)).collect();
                assert_eq!(got, want, "raw={raw:?}");
            }
        }
    }
}

#[test]
fn validation_code_matches_go() {
    for case in vectors("validation_code").as_array().unwrap() {
        let msg = case["msg"].as_str().unwrap();
        assert_eq!(
            problem::validation_code(msg),
            case["code"].as_str().unwrap(),
            "msg={msg:?}"
        );
    }
}

#[test]
fn validation_detail_matches_go() {
    for case in vectors("validation_detail").as_array().unwrap() {
        let msg = case["msg"].as_str().unwrap();
        assert_eq!(
            problem::validation_detail(msg),
            case["out"].as_str().unwrap(),
            "msg={msg:?}"
        );
    }
}

#[test]
fn validation_location_matches_go() {
    for case in vectors("validation_location").as_array().unwrap() {
        let detail = ErrorDetail {
            location: case["Location"].as_str().unwrap().to_owned(),
            message: case["Message"].as_str().unwrap().to_owned(),
        };
        assert_eq!(
            problem::validation_location(&detail),
            case["Out"].as_str().unwrap()
        );
    }
}

#[test]
fn huma_status_type_matches_go() {
    for case in vectors("huma_status_type").as_array().unwrap() {
        let status = case["status"].as_u64().unwrap() as u16;
        let msg = case["msg"].as_str().unwrap();
        assert_eq!(
            problem::huma_status_type(status, msg).id,
            case["id"].as_str().unwrap(),
            "status={status}"
        );
    }
}

#[test]
fn huma_detail_matches_go() {
    let by_id = |id: &str| {
        problem::CATALOG
            .iter()
            .find(|t| t.id == id)
            .copied()
            .unwrap()
    };
    for case in vectors("huma_detail").as_array().unwrap() {
        let t = by_id(case["type_id"].as_str().unwrap());
        let msg = case["msg"].as_str().unwrap();
        let body_limit = case["body_limit"].as_i64().unwrap();
        assert_eq!(
            problem::huma_detail(t, msg, body_limit),
            case["out"].as_str().unwrap()
        );
    }
}

#[test]
fn from_huma_error_matches_go() {
    for case in vectors("from_huma_error").as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let request_id = case["request_id"].as_str().unwrap();
        let status = case["status"].as_u64().unwrap() as u16;
        let msg = case["msg"].as_str().unwrap();
        let body_limit = case["body_limit"].as_i64().unwrap();
        let errs: Vec<HumaErr> = match name {
            "form_size_exceeded" => vec![HumaErr::Detail(ErrorDetail {
                location: "body".into(),
                message: format!(
                    "cannot read multipart form: {}",
                    problem::HTTP_MAX_BYTES_MESSAGE
                ),
            })],
            "form_parse_failure" => vec![HumaErr::Detail(ErrorDetail {
                location: "body".into(),
                message: "cannot read multipart form: multipart: NextPart: EOF".into(),
            })],
            "body_parse_failure" => {
                vec![HumaErr::Detail(ErrorDetail {
                    location: "body".into(),
                    message: "unexpected EOF".into(),
                })]
            }
            "validation_failure" => vec![
                HumaErr::Detail(ErrorDetail {
                    location: "body".into(),
                    message: "expected required property name to be present".into(),
                }),
                HumaErr::Detail(ErrorDetail {
                    location: "body.kind".into(),
                    message: "expected value to be one of \"a\", \"b\"".into(),
                }),
            ],
            "app_error_detail" => vec![HumaErr::Other("library not found".into())],
            _ => Vec::new(),
        };
        let got = problem::from_huma_error(
            request_id,
            status,
            msg,
            &errs,
            body_limit,
            problem::HTTP_MAX_BYTES_MESSAGE,
        );
        assert_eq!(problem_json(Some(&got)), case["problem"], "case={name}");
    }
}
