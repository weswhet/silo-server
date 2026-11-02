//! Replays `rust/conformance/vectors/clientip/middleware.json`, recorded from the real
//! `clientip.Middleware` by `rust/conformance/vectors/generators/clientip`, against
//! [`silo_gate::clientip`]. Every context value must match; there are no tolerated differences.

use std::collections::BTreeMap;

use serde::Deserialize;
use silo_gate::clientip::{
    RequestFields, Resolver, has_forwarding_headers, normalize_cidr_list, parse_cidrs,
};

#[derive(Deserialize)]
struct Record {
    name: String,
    trusted: String,
    remote_addr: String,
    host: String,
    tls: bool,
    #[serde(default)]
    headers: BTreeMap<String, Vec<String>>,
    client_ip: String,
    remote_after: String,
    unknown: bool,
    scheme: String,
    request_host: String,
    peer: String,
    peer_ip: String,
    origin: String,
    has_forwarding: bool,
}

#[derive(Deserialize)]
struct CidrRecord {
    raw: String,
    err: bool,
    normalized: String,
    norm_err: bool,
}

#[derive(Deserialize)]
struct Output {
    middleware: Vec<Record>,
    cidrs: Vec<CidrRecord>,
}

fn vectors() -> Output {
    let path = silo_gocompat::filepath::join(&[
        env!("CARGO_MANIFEST_DIR"),
        "../../conformance/vectors/clientip/middleware.json",
    ]);
    let data = std::fs::read(&path).expect("reading clientip vectors");
    silo_gocompat::json::unmarshal(&data).expect("parsing clientip vectors")
}

#[test]
fn middleware_matches_go() {
    let vectors = vectors();
    assert!(vectors.middleware.len() >= 6000);
    let mut differences = Vec::new();
    for case in &vectors.middleware {
        let resolver = Resolver::new(parse_cidrs(&case.trusted).expect("trusted list"));
        let owned: BTreeMap<&str, Vec<&str>> = case
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.iter().map(String::as_str).collect()))
            .collect();
        let values = |name: &str| owned.get(name).map(Vec::as_slice).unwrap_or(&[]);
        let got = resolver.middleware(&RequestFields {
            remote_addr: &case.remote_addr,
            host: &case.host,
            tls: case.tls,
            x_forwarded_for: values("X-Forwarded-For"),
            x_real_ip: values("X-Real-Ip"),
            forwarded: values("Forwarded"),
            x_forwarded_proto: values("X-Forwarded-Proto"),
            x_forwarded_host: values("X-Forwarded-Host"),
            upgrade: values("Upgrade"),
            connection: values("Connection"),
        });
        // Go's exported RequestScheme returns the stored value, which is what `scheme` holds.
        let actual = (
            got.client_ip.as_str(),
            got.forwarded_client_unknown,
            got.scheme.as_str(),
            got.request_host(),
            got.peer.as_str(),
            got.peer_ip(),
            got.request_origin(case.tls),
            has_forwarding_headers(
                values("X-Forwarded-For"),
                values("X-Real-Ip"),
                values("Forwarded"),
            ),
        );
        let expected = (
            case.client_ip.as_str(),
            case.unknown,
            case.scheme.as_str(),
            case.request_host.as_str(),
            case.peer.as_str(),
            case.peer_ip.clone(),
            case.origin.clone(),
            case.has_forwarding,
        );
        assert_eq!(case.client_ip, case.remote_after);
        if actual != expected {
            differences.push(format!(
                "{}: trusted={:?} remote={:?} host={:?} headers={:?}\n  go   {expected:?}\n  rust {actual:?}",
                case.name, case.trusted, case.remote_addr, case.host, case.headers
            ));
        }
    }
    eprintln!(
        "clientip: {} cases, {} differences",
        vectors.middleware.len(),
        differences.len()
    );
    let shown: Vec<&String> = differences.iter().take(20).collect();
    assert!(differences.is_empty(), "{shown:#?}");
}

#[test]
fn cidr_lists_match_go() {
    for case in vectors().cidrs {
        assert_eq!(parse_cidrs(&case.raw).is_err(), case.err, "{:?}", case.raw);
        match normalize_cidr_list(&case.raw) {
            Ok(normalized) => {
                assert!(!case.norm_err, "{:?}", case.raw);
                assert_eq!(normalized, case.normalized, "{:?}", case.raw);
            }
            Err(_) => assert!(case.norm_err, "{:?}", case.raw),
        }
    }
}
