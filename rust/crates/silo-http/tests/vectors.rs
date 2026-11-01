//! Pure functions against vectors from real Go, under `rust/conformance/vectors/silohttp`.
//! Regenerate with the command at the top of the generator's `vectors.go`.

use silo_http::url::{parse_request_uri, parse_url};
use silo_http::{canonical_header_key, detect_content_type, status_text};

fn load() -> serde_json::Value {
    let raw = include_str!("../../../conformance/vectors/silohttp/pure.json");
    serde_json::from_str(raw).expect("vector file parses")
}

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    (0..b.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(std::str::from_utf8(&b[i..i + 2]).unwrap(), 16).unwrap())
        .collect()
}

fn hex_field(v: &serde_json::Value, key: &str) -> Vec<u8> {
    unhex(v[key].as_str().unwrap_or(""))
}

#[test]
fn detect_content_type_matches_go() {
    let doc = load();
    let list = doc["sniff"].as_array().unwrap();
    assert!(list.len() > 500);
    for v in list {
        let data = hex_field(v, "hex");
        assert_eq!(
            detect_content_type(&data),
            v["ct"].as_str().unwrap(),
            "input {}",
            v["hex"]
        );
    }
}

#[test]
fn canonical_header_key_matches_go() {
    let doc = load();
    for v in doc["keys"].as_array().unwrap() {
        assert_eq!(
            canonical_header_key(v["in"].as_str().unwrap()),
            v["out"].as_str().unwrap()
        );
    }
}

#[test]
fn status_text_matches_go() {
    let doc = load();
    let known: std::collections::BTreeMap<u16, String> = doc["status"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["code"].as_u64().unwrap() as u16,
                v["text"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(known.len() > 50);
    for code in 0..1000u16 {
        assert_eq!(
            status_text(code),
            known.get(&code).map_or("", String::as_str),
            "code {code}"
        );
    }
}

#[test]
fn url_parsing_matches_go() {
    let doc = load();
    let list = doc["urls"].as_array().unwrap();
    assert!(list.len() > 150);
    for v in list {
        let raw = hex_field(v, "raw");
        let request = v["request"].as_bool().unwrap();
        let got = if request {
            parse_request_uri(&raw)
        } else {
            parse_url(&raw)
        };
        let label = format!("{:?} request={request}", String::from_utf8_lossy(&raw));
        assert_eq!(got.is_ok(), v["ok"].as_bool().unwrap(), "{label}: {got:?}");
        let Ok(u) = got else { continue };
        assert_eq!(u.scheme, v["scheme"].as_str().unwrap_or(""), "{label}");
        assert_eq!(u.host, hex_field(v, "host"), "{label}");
        assert_eq!(u.path, hex_field(v, "path_hex"), "{label}");
        assert_eq!(u.raw_path, hex_field(v, "raw_path_hex"), "{label}");
        assert_eq!(u.raw_query, hex_field(v, "raw_query_hex"), "{label}");
        assert_eq!(u.opaque, hex_field(v, "opaque_hex"), "{label}");
        assert_eq!(
            u.escaped_path(),
            v["escaped"].as_str().unwrap_or("").as_bytes(),
            "{label}"
        );
        assert_eq!(u.string(), hex_field(v, "string_hex"), "{label}");
    }
}
