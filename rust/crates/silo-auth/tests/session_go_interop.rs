//! Bidirectional session conformance against a real Postgres database and the real Go
//! `internal/auth.SessionRepository`, run through the `sessioncheck` harness
//! (`rust/conformance/harness/sessioncheck`, pinned to `GOTOOLCHAIN=go1.26.10`):
//!
//! - **Go creates, Rust reads**: the harness inserts a session with Go's own
//!   `SessionRepository.Create`; this test reads it back with
//!   [`silo_auth::session::SessionRepository`] and asserts every field matches, and that
//!   `active_session`/`is_valid` agree with Go's own `ActiveSession`/`IsValid` on the same row.
//! - **Rust creates, Go reads**: this test inserts a session with the Rust port; the harness
//!   reads it back with Go's `GetByID`/`ActiveSession` and this test asserts the printed JSON
//!   matches what Rust itself believes it wrote.
//!
//! This is this task's exit-gate line "tokens and sessions created by Go are accepted by Rust and
//! the reverse, on one database", scoped to `auth_sessions` (the session half; the JWT/token half
//! is covered by `claims` module's own round-trip tests and is architecturally independent of the
//! database — a JWT's validity never depends on which process minted it, only on the shared HMAC
//! secret, which this test does not model since neither side needs the other's secret to read a
//! session row).
//!
//! Ignored by default (needs a running Postgres with Silo's full schema migrated, and the
//! `sessioncheck` binary built) — same pattern as `silo-core`'s `conformance_pg` test. Run with:
//! ```text
//! DATABASE_URL=postgres://silo:silo@localhost:25999/silo?sslmode=disable \
//! SESSIONCHECK_BIN=/path/to/sessioncheck \
//! SESSIONCHECK_TEST_USER_ID=1 \
//! cargo test -p silo-auth --test session_go_interop -- --ignored
//! ```

use std::process::Command;
use std::sync::Arc;

use serde::Deserialize;
use silo_auth::session::{AuthSession, SessionRepository};
use silo_pg::{Pool, PoolConfig};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn pool() -> Arc<Pool> {
    let url = env("DATABASE_URL").expect("DATABASE_URL must be set");
    let config = PoolConfig::parse(&url).expect("parsing DATABASE_URL");
    Arc::new(Pool::new(config).expect("building pool"))
}

fn sessioncheck(args: &[&str]) -> serde_json::Value {
    let bin = env("SESSIONCHECK_BIN").expect("SESSIONCHECK_BIN must be set");
    let db = env("DATABASE_URL").expect("DATABASE_URL must be set");
    let mut full_args = vec![args[0]];
    full_args.push("-db");
    full_args.push(db.as_str());
    full_args.extend_from_slice(&args[1..]);
    let output = Command::new(&bin)
        .args(&full_args)
        .output()
        .unwrap_or_else(|e| panic!("running {bin}: {e}"));
    assert!(
        output.status.success(),
        "sessioncheck {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    silo_gocompat::json::unmarshal(&output.stdout).expect("parsing sessioncheck JSON")
}

#[derive(Deserialize)]
struct GoSessionJson {
    id: String,
    user_id: i64,
    device_id: String,
    device_platform: String,
    ip_address: String,
    purpose: String,
    bound_profile_id: String,
}

#[tokio::test]
#[ignore = "needs a live Postgres with Silo's schema migrated and the sessioncheck binary built; see module doc"]
async fn go_created_session_is_read_identically_by_rust() {
    let user_id: i64 = env("SESSIONCHECK_TEST_USER_ID")
        .expect("SESSIONCHECK_TEST_USER_ID must be set")
        .parse()
        .unwrap();
    let session_id = format!("go-created-{}", uuid::Uuid::new_v4());

    let created: GoSessionJson = serde_json::from_value(sessioncheck(&[
        "create",
        "-session",
        &session_id,
        "-user",
        &user_id.to_string(),
        "-device-id",
        "go-device",
        "-device-platform",
        "android",
        "-purpose",
        "account",
        "-ip",
        "203.0.113.9",
    ]))
    .expect("decoding sessioncheck create output");
    assert_eq!(created.id, session_id);

    let repo = SessionRepository::new(pool().await);
    let rust_view: AuthSession = repo
        .get_by_id(&session_id)
        .await
        .expect("rust reading Go-created session");
    assert_eq!(rust_view.id, session_id);
    assert_eq!(rust_view.user_id, user_id);
    assert_eq!(rust_view.device_id, "go-device");
    assert_eq!(rust_view.device_platform, "android");
    assert_eq!(rust_view.ip_address, "203.0.113.9");
    assert_eq!(rust_view.purpose, "account");
    assert!(rust_view.revoked_at.is_none());

    // Business-logic agreement, not just column agreement: ActiveSession/IsValid on the same row.
    let go_active = sessioncheck(&[
        "active",
        "-session",
        &session_id,
        "-user",
        &user_id.to_string(),
    ]);
    let rust_authority = repo
        .active_session(&session_id, user_id)
        .await
        .expect("rust active_session query");
    assert_eq!(go_active["active"], serde_json::json!(true));
    let authority = rust_authority.expect("rust must also see this session as active");
    assert_eq!(go_active["role"], serde_json::json!(authority.role));
    assert_eq!(go_active["purpose"], serde_json::json!(authority.purpose));

    let go_valid = sessioncheck(&["valid", "-session", &session_id]);
    let rust_valid = repo
        .is_valid(&session_id)
        .await
        .expect("rust is_valid query");
    assert_eq!(go_valid["valid"], serde_json::json!(rust_valid));
    assert!(rust_valid);
}

#[tokio::test]
#[ignore = "needs a live Postgres with Silo's schema migrated and the sessioncheck binary built; see module doc"]
async fn rust_created_session_is_read_identically_by_go() {
    let user_id: i64 = env("SESSIONCHECK_TEST_USER_ID")
        .expect("SESSIONCHECK_TEST_USER_ID must be set")
        .parse()
        .unwrap();
    let session_id = format!("rust-created-{}", uuid::Uuid::new_v4());

    let repo = SessionRepository::new(pool().await);
    let expires_at = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    repo.create(AuthSession {
        id: session_id.clone(),
        user_id,
        device_name: String::new(),
        device_id: "rust-device".to_owned(),
        device_platform: "web".to_owned(),
        ip_address: "198.51.100.7".to_owned(),
        created_at: std::time::SystemTime::now(),
        expires_at,
        revoked_at: None,
        impersonator_user_id: None,
        impersonation_started_at: None,
        identity_id: None,
        provider_since: None,
        last_seen_at: None,
        purpose: "account".to_owned(),
        bound_profile_id: String::new(),
        absolute_expires_at: None,
    })
    .await
    .expect("rust creating session");

    let go_view: GoSessionJson =
        serde_json::from_value(sessioncheck(&["get", "-session", &session_id]))
            .expect("decoding sessioncheck get output");
    assert_eq!(go_view.id, session_id);
    assert_eq!(go_view.user_id, user_id);
    assert_eq!(go_view.device_id, "rust-device");
    assert_eq!(go_view.device_platform, "web");
    assert_eq!(go_view.ip_address, "198.51.100.7");
    assert_eq!(go_view.purpose, "account");
    assert_eq!(go_view.bound_profile_id, "");

    let go_active = sessioncheck(&[
        "active",
        "-session",
        &session_id,
        "-user",
        &user_id.to_string(),
    ]);
    assert_eq!(go_active["active"], serde_json::json!(true));
}

/// H2: a user ID outside `int4` must be an error on every method on both sides, must never reach the
/// row of the account named by its low 32 bits, and must leave that account's session usable.
#[tokio::test]
#[ignore = "needs a live Postgres with Silo's schema migrated and the sessioncheck binary built; see module doc"]
async fn oversized_user_ids_are_refused_like_go() {
    let user_id: i64 = env("SESSIONCHECK_TEST_USER_ID")
        .expect("SESSIONCHECK_TEST_USER_ID must be set")
        .parse()
        .unwrap();
    let session_id = format!("oversized-{}", uuid::Uuid::new_v4());
    sessioncheck(&[
        "create",
        "-session",
        &session_id,
        "-user",
        &user_id.to_string(),
    ]);
    let repo = SessionRepository::new(pool().await);
    let blank = |id: &str, user: i64, impersonator: Option<i64>| AuthSession {
        id: id.to_owned(),
        user_id: user,
        device_name: String::new(),
        device_id: String::new(),
        device_platform: String::new(),
        ip_address: String::new(),
        created_at: std::time::SystemTime::now(),
        expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        revoked_at: None,
        impersonator_user_id: impersonator,
        impersonation_started_at: None,
        identity_id: None,
        provider_since: None,
        last_seen_at: None,
        purpose: String::new(),
        bound_profile_id: String::new(),
        absolute_expires_at: None,
    };

    // Same low 32 bits as the real account, plus values at and past each int4 bound.
    let oversized = [
        (1i64 << 32) + user_id,
        i64::from(i32::MAX) + 1,
        i64::from(i32::MIN) - 1,
        i64::MAX,
        i64::MIN,
    ];
    let mut total = 0;
    for value in oversized {
        let text = value.to_string();
        let go = sessioncheck(&[
            "oversized",
            "-session",
            &session_id,
            &format!("-user={text}"),
        ]);
        let rust = [
            (
                "active_session",
                repo.active_session(&session_id, value).await.map(|_| ()),
            ),
            ("list_by_user", repo.list_by_user(value).await.map(|_| ())),
            (
                "list_by_user_page",
                repo.list_by_user_page(value, None, 10).await.map(|_| ()),
            ),
            ("revoke_all_by_user", repo.revoke_all_by_user(value).await),
            (
                "revoke_all_by_impersonator",
                repo.revoke_all_by_impersonator(value).await,
            ),
            (
                "create",
                repo.create(blank(&format!("{session_id}-r"), value, None))
                    .await,
            ),
            (
                "create_impersonator",
                repo.create(blank(&format!("{session_id}-ri"), user_id, Some(value)))
                    .await,
            ),
        ];
        for (name, result) in rust {
            total += 1;
            assert_eq!(go[name], serde_json::json!(true), "Go {name} with {value}");
            assert!(
                matches!(
                    result,
                    Err(silo_auth::session::Error::Int4OutOfRange { .. })
                ),
                "Rust {name} with {value}: {result:?}"
            );
        }
    }
    assert_eq!(total, 35);
    assert!(
        repo.get_by_id(&session_id)
            .await
            .unwrap()
            .revoked_at
            .is_none(),
        "an oversized ID must not revoke the low-32-bit account's session"
    );
    assert!(
        repo.active_session(&session_id, user_id)
            .await
            .unwrap()
            .is_some()
    );
}

/// The NULL `device_name` the column allows is an error in Go's plain-string scan, and must not
/// panic here.
#[tokio::test]
#[ignore = "needs a live Postgres with Silo's schema migrated and the sessioncheck binary built; see module doc"]
async fn null_device_name_is_an_error_not_a_panic() {
    let user_id: i64 = env("SESSIONCHECK_TEST_USER_ID").unwrap().parse().unwrap();
    let session_id = format!("null-device-{}", uuid::Uuid::new_v4());
    sessioncheck(&[
        "create",
        "-session",
        &session_id,
        "-user",
        &user_id.to_string(),
    ]);
    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();
    conn.execute(
        "UPDATE auth_sessions SET device_name = NULL WHERE id = $1",
        &[&session_id],
    )
    .await
    .unwrap();
    let output = Command::new(env("SESSIONCHECK_BIN").unwrap())
        .args([
            "get",
            "-db",
            &env("DATABASE_URL").unwrap(),
            "-session",
            &session_id,
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "Go must refuse a NULL device_name"
    );
    let repo = SessionRepository::new(pool);
    assert!(matches!(
        repo.get_by_id(&session_id).await,
        Err(silo_auth::session::Error::Scan { .. })
    ));
}
