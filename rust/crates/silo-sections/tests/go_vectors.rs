//! Checks against rust/conformance/vectors/sections/defaults.json, written by the Go generator
//! rust/conformance/vectors/generators/sectiondefaults.

use serde_json::{Value, json};
use silo_sections::continue_type::{
    ContinueType, continue_type_config, continue_type_from_config, is_audiobook_library_type,
    parse_continue_type,
};
use silo_sections::*;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/sections/defaults.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn encode(s: &[PageSection]) -> Value {
    Value::Array(s.iter().map(PageSection::to_json).collect())
}

#[test]
fn home_defaults() {
    let v = vectors();
    for case in v["home"].as_array().unwrap() {
        let mut libs: Vec<Option<MediaFolder>> = case["libraries"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|l| {
                        Some(MediaFolder {
                            id: l["id"].as_i64().unwrap(),
                            name: l["name"].as_str().unwrap().into(),
                            r#type: l["type"].as_str().unwrap().into(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        libs.push(None);
        assert_eq!(
            encode(&default_home_sections(&libs)),
            case["sections"],
            "libraries {}",
            case["libraries"]
        );
    }
}

#[test]
fn library_defaults() {
    let v = vectors();
    for case in v["library"].as_array().unwrap() {
        let got = default_library_sections_for_type(
            case["library_id"].as_i64(),
            case["type"].as_str().unwrap(),
        );
        assert_eq!(
            encode(&got),
            case["sections"],
            "type {} id {}",
            case["type"],
            case["library_id"]
        );
    }
    assert_eq!(
        encode(&default_library_sections(Some(7))),
        v["library_fallback"]
    );
}

#[test]
fn helpers() {
    let v = vectors();
    for c in v["clamp"].as_array().unwrap() {
        assert_eq!(
            clamp_item_limit(c[0].as_i64().unwrap()),
            c[1].as_i64().unwrap()
        );
    }
    for c in v["continue_parse"].as_array().unwrap() {
        let cfg = c["config"].as_str().unwrap().as_bytes();
        let r = parse_continue_type(cfg);
        let typ = match &r {
            Ok(t) => t.as_str().to_string(),
            Err(_) => "watching".into(),
        };
        assert_eq!(
            json!({"config": c["config"], "type": typ, "error": r.is_err(), "from_config": continue_type_from_config(cfg).as_str()}),
            *c,
            "{}",
            c["config"]
        );
    }
    for c in v["continue_types"].as_array().unwrap() {
        let t = ContinueType::new(c["type"].as_str().unwrap());
        let m: Vec<&str> = ["movie", "episode", "series", "audiobook", "ebook", "manga"]
            .into_iter()
            .filter(|i| t.matches_item(i))
            .collect();
        let m = if m.is_empty() { Value::Null } else { json!(m) };
        assert_eq!(
            json!({"type": t.as_str(), "config": continue_type_config(&t), "valid": t.is_valid(), "matches": m, "next_up": t.allows_next_up()}),
            *c
        );
    }
    for c in v["library_kinds"].as_array().unwrap() {
        let t = c["type"].as_str().unwrap();
        assert_eq!(
            is_video_library_type(t),
            c["video"].as_bool().unwrap(),
            "{t}"
        );
        assert_eq!(
            is_audiobook_library_type(t),
            c["audiobook"].as_bool().unwrap(),
            "{t}"
        );
    }
}
