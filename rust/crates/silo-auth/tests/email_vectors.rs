//! Replays `rust/conformance/vectors/auth/looks_like_email.json`, recorded from the real
//! `auth.LookupLogin` by `rust/conformance/vectors/generators/authemail`.

use serde::Deserialize;
use silo_auth::provider::looks_like_email;

#[derive(Deserialize)]
struct Record {
    identifier: String,
    email: bool,
    valid: bool,
}

/// `auth.ValidateEmail`, recorded beside it.
#[test]
fn matches_validate_email() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/auth/looks_like_email.json"
    );
    let records: Vec<Record> =
        silo_gocompat::json::unmarshal(&std::fs::read(path).unwrap()).unwrap();
    let differences: Vec<(&str, bool)> = records
        .iter()
        .filter(|r| silo_auth::provider::validate_email(&r.identifier).is_ok() != r.valid)
        .map(|r| (r.identifier.as_str(), r.valid))
        .collect();
    assert!(differences.is_empty(), "{differences:#?}");
}

#[test]
fn matches_lookup_login() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/auth/looks_like_email.json"
    );
    let records: Vec<Record> =
        silo_gocompat::json::unmarshal(&std::fs::read(path).unwrap()).unwrap();
    assert!(records.len() >= 8000);
    let differences: Vec<(&str, bool)> = records
        .iter()
        .filter(|r| looks_like_email(&r.identifier) != r.email)
        .map(|r| (r.identifier.as_str(), r.email))
        .collect();
    assert!(differences.is_empty(), "{differences:#?}");
}
