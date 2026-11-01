//! The token half of this task's exit-gate line "tokens and sessions created by Go are accepted
//! by Rust and the reverse" — see `session_go_interop.rs` for the session half. Drives the real
//! Go `internal/auth.JWTService` through the `jwtcheck` harness
//! (`rust/conformance/harness/jwtcheck`, pinned to `GOTOOLCHAIN=go1.26.10`) and [`silo_auth::claims`]
//! against the same shared secret, with no database involved (a JWT's validity depends only on
//! the HMAC secret both sides already share, never on which process minted it).
//!
//! Needs no Postgres; still gated behind `--ignored` because it shells out to a Go binary that
//! must be built first, matching this crate's other interop test.

use std::process::Command;

use silo_auth::claims::JwtService;

const SECRET: &str = "a-shared-test-secret-both-sides-know";

fn jwtcheck(args: &[&str]) -> (bool, serde_json::Value) {
    let bin = std::env::var("JWTCHECK_BIN").expect("JWTCHECK_BIN must be set");
    let output = Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {bin}: {e}"));
    let value: serde_json::Value = silo_gocompat::json::unmarshal(&output.stdout)
        .unwrap_or_else(|e| panic!("parsing jwtcheck output: {e}"));
    (output.status.success(), value)
}

#[test]
#[ignore = "needs the jwtcheck binary built; see module doc"]
fn go_minted_access_token_is_accepted_by_rust() {
    let (ok, minted) = jwtcheck(&[
        "mint", "-secret", SECRET, "-user", "42", "-role", "admin", "-session", "sess-abc",
    ]);
    assert!(ok);
    let access = minted["access"].as_str().unwrap();

    let svc = JwtService::new(
        SECRET.as_bytes().to_vec(),
        900 * 1_000_000_000,
        2_592_000 * 1_000_000_000,
    );
    let claims = svc
        .validate_token(access)
        .expect("rust must accept a Go-minted token");
    assert_eq!(claims.user_id, 42);
    assert_eq!(claims.role, "admin");
    assert_eq!(claims.session_id, "sess-abc");
    assert_eq!(claims.token_type, silo_auth::claims::token_type::ACCESS);
}

#[test]
#[ignore = "needs the jwtcheck binary built; see module doc"]
fn rust_minted_access_token_is_accepted_by_go() {
    let svc = JwtService::new(
        SECRET.as_bytes().to_vec(),
        900 * 1_000_000_000,
        2_592_000 * 1_000_000_000,
    );
    let token = svc.generate_access_token(7, "user", "sess-xyz").unwrap();

    let (ok, decoded) = jwtcheck(&["validate", "-secret", SECRET, "-token", &token]);
    assert!(ok, "Go refused a Rust-minted token: {decoded}");
    assert_eq!(decoded["user_id"], serde_json::json!(7));
    assert_eq!(decoded["role"], serde_json::json!("user"));
    assert_eq!(decoded["session_id"], serde_json::json!("sess-xyz"));
    assert_eq!(decoded["token_type"], serde_json::json!("access"));
}

#[test]
#[ignore = "needs the jwtcheck binary built; see module doc"]
fn go_refuses_a_token_signed_with_a_different_secret_and_so_does_rust() {
    let svc = JwtService::new(
        b"wrong-secret".to_vec(),
        900 * 1_000_000_000,
        2_592_000 * 1_000_000_000,
    );
    let token = svc.generate_access_token(1, "user", "s").unwrap();

    let (ok, _) = jwtcheck(&["validate", "-secret", SECRET, "-token", &token]);
    assert!(
        !ok,
        "Go should have refused a token signed with the wrong secret"
    );

    let rust_svc = JwtService::new(
        SECRET.as_bytes().to_vec(),
        900 * 1_000_000_000,
        2_592_000 * 1_000_000_000,
    );
    assert!(rust_svc.validate_token(&token).is_err());
}
