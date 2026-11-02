//! `internal/access/rating.go` against `rust/conformance/vectors/access/access.json`.

use serde_json::Value;
use silo_store::rating::{age_for_ceiling, normalize, stricter_ceiling};

fn vectors() -> Value {
    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/access/access.json"
    ))
    .expect("the vectors");
    silo_gocompat::json::unmarshal(&raw).expect("JSON")
}

#[test]
fn ceilings_match_go() {
    let data = vectors();
    for case in data["ceilings"].as_array().expect("ceilings") {
        let raw = case["raw"].as_str().expect("raw");
        let got = normalize(raw);
        assert_eq!(got.is_some(), case["ok"].as_bool().expect("ok"), "{raw:?}");
        assert_eq!(
            got.map_or("", |g| g.0),
            case["system"].as_str().expect("system"),
            "{raw:?}"
        );
        assert_eq!(
            got.and_then(|g| g.1).map(i64::from),
            case["age"].as_i64(),
            "{raw:?}"
        );
        assert_eq!(
            age_for_ceiling(raw).map(i64::from),
            case["ceiling_age"].as_i64(),
            "{raw:?}"
        );
    }
}

#[test]
fn stricter_ceiling_matches_go() {
    let data = vectors();
    for case in data["stricter"].as_array().expect("stricter") {
        let (a, b) = (
            case["A"].as_str().expect("a"),
            case["B"].as_str().expect("b"),
        );
        assert_eq!(
            stricter_ceiling(a, b),
            case["Out"].as_str().expect("out"),
            "{a:?} {b:?}"
        );
    }
}
