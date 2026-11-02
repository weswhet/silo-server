//! Drives a real Go program (go1.26.10, `github.com/jackc/pgx/v5` v5.9.2, `github.com/redis/go-redis/v9`
//! v9.18.0 — the exact versions `go.mod` pins) against the same Postgres and Redis this crate's own
//! client connects to, and checks that each side observes the other's locks and events. This is the
//! exit gate's "tested against a real Go program" proof; `tests/postgres.rs` and `tests/redis.rs`
//! cover the same code against each other and are not a substitute for this file.
//!
//! The Go binary is `rust/conformance/harness/runtimeinterop`, built with
//! `GOTOOLCHAIN=go1.26.10 go build -o <bin> ./rust/conformance/harness/runtimeinterop`.
//! Set `SILO_RUNTIME_GO_INTEROP_BIN` to its path, plus `SILO_RUNTIME_TEST_DATABASE_URL` and
//! `SILO_RUNTIME_TEST_REDIS_URL`, to run these. Run with `-- --test-threads=1`: the lock tests share
//! fixed key numbers and must not interleave with each other or with `tests/postgres.rs`.

use silo_config::config::RedisConfig;
use silo_core::redis::Event;
use silo_pg::{Pool, PoolConfig};
use silo_runtime::cache;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

fn go_bin() -> Option<String> {
    std::env::var("SILO_RUNTIME_GO_INTEROP_BIN")
        .ok()
        .filter(|v| !v.is_empty())
}
fn db_url() -> Option<String> {
    std::env::var("SILO_RUNTIME_TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
}
fn redis_addr() -> Option<String> {
    std::env::var("SILO_RUNTIME_TEST_REDIS_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|url| url.trim_start_matches("redis://").to_owned())
}

macro_rules! skip_unless_all_set {
    () => {{
        let (Some(bin), Some(db), Some(redis)) = (go_bin(), db_url(), redis_addr()) else {
            eprintln!(
                "SILO_RUNTIME_GO_INTEROP_BIN / SILO_RUNTIME_TEST_DATABASE_URL / \
                 SILO_RUNTIME_TEST_REDIS_URL not all set; skipping"
            );
            return;
        };
        (bin, db, redis)
    }};
}

/// Spawns the Go holder (`lock-shared` or `lock-exclusive`), returning once it has printed
/// "locked" so the caller knows Postgres granted it before testing contention against it.
async fn spawn_go_holder(bin: &str, mode: &str, db_url: &str, key: i64) -> GoHolder {
    let mut child = Command::new(bin)
        .args([mode, db_url, &key.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawning the Go interop binary");
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(
        line.trim(),
        "locked",
        "Go holder did not report taking the lock"
    );
    GoHolder { child, reader }
}

struct GoHolder {
    child: Child,
    // Kept open (and drained in `release`), not just dropped: closing a child's stdout pipe while
    // it still has something to print makes a plain Go program die from SIGPIPE on that write
    // instead of exiting cleanly, since Go installs no handler to turn that into an `error` return.
    reader: BufReader<tokio::process::ChildStdout>,
}

impl GoHolder {
    /// Tells the Go process to release and waits for it to exit.
    async fn release(mut self) {
        let mut stdin = self.child.stdin.take().unwrap();
        stdin.write_all(b"release\n").await.unwrap();
        drop(stdin);
        let mut line = String::new();
        self.reader.read_line(&mut line).await.unwrap();
        assert_eq!(
            line.trim(),
            "released",
            "Go holder did not confirm releasing the lock"
        );
        let status = self.child.wait().await.unwrap();
        assert!(status.success(), "Go holder exited with {status}");
    }
}

async fn go_try(bin: &str, mode: &str, db_url: &str, key: i64) -> bool {
    let output = Command::new(bin)
        .args([mode, db_url, &key.to_string()])
        .output()
        .await
        .expect("running the Go interop binary");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim() == "true"
}

// Distinct key space from `tests/postgres.rs`'s `TEST_LOCK_KEY` family and from the real
// `silo_core::advisory_locks` constants, except where a test deliberately uses the real
// `STORAGE_NODE_ADMISSION` constant to prove the exact value Go and Rust will share in production.
const GO_RUST_TEST_KEY: i64 = 0x0047_4f5f_5255_5354; // "GO_RUST"

#[tokio::test]
async fn go_shared_holder_blocks_rust_exclusive_and_freeing_it_unblocks() {
    let (bin, db, _redis) = skip_unless_all_set!();
    let pool = Pool::connect(PoolConfig::parse(&db).unwrap())
        .await
        .unwrap();
    let key = GO_RUST_TEST_KEY;

    let holder = spawn_go_holder(&bin, "lock-shared", &db, key).await;

    // Rust's own shared-lock session must coexist with Go's shared holder (both are "readers").
    let rust_admission = silo_runtime::admission::admit_node(&pool, key)
        .await
        .unwrap();
    assert!(
        !rust_admission.try_exclusive().await.unwrap(),
        "Rust must not be able to go exclusive while Go holds the shared lock"
    );

    holder.release().await;

    assert!(
        rust_admission.try_exclusive().await.unwrap(),
        "Rust must be able to go exclusive once Go's shared holder released"
    );
    rust_admission.release_exclusive().await.unwrap();
    rust_admission.close().await;
}

#[tokio::test]
async fn rust_exclusive_blocks_go_shared_and_releasing_it_unblocks() {
    let (bin, db, _redis) = skip_unless_all_set!();
    let pool = Pool::connect(PoolConfig::parse(&db).unwrap())
        .await
        .unwrap();
    let key = GO_RUST_TEST_KEY + 1;

    let rust_admission = silo_runtime::admission::admit_node(&pool, key)
        .await
        .unwrap();
    assert!(rust_admission.try_exclusive().await.unwrap());

    assert!(
        !go_try(&bin, "lock-try-shared", &db, key).await,
        "Go must not be able to take the shared lock while Rust holds exclusive"
    );

    rust_admission.release_exclusive().await.unwrap();

    assert!(
        go_try(&bin, "lock-try-shared", &db, key).await,
        "Go must be able to take the shared lock once Rust released exclusive"
    );
    rust_admission.close().await;
}

/// Uses the real `STORAGE_NODE_ADMISSION` constant both sides will actually share in production,
/// confirming Go and Rust agree on its value, not just on advisory-lock mechanics in general.
#[tokio::test]
async fn go_and_rust_agree_on_the_storage_node_admission_lock_id() {
    let (bin, db, _redis) = skip_unless_all_set!();
    let pool = Pool::connect(PoolConfig::parse(&db).unwrap())
        .await
        .unwrap();
    let key = silo_core::advisory_locks::STORAGE_NODE_ADMISSION;

    let go_exclusive = spawn_go_holder(&bin, "lock-exclusive", &db, key).await;
    // A fresh Rust admission must be unable to even take the *shared* mode while Go holds
    // exclusive on the one true constant, proving the integer (not just the mechanism) matches.
    // `pg_advisory_lock_shared` blocks server-side with no timeout, so this must race it against a
    // client-side deadline rather than await it directly, or a mismatch would hang the test forever
    // instead of failing it.
    let admit_future = silo_runtime::admission::admit_node(&pool, key);
    let blocked = tokio::time::timeout(Duration::from_millis(500), admit_future).await;
    assert!(
        blocked.is_err(),
        "admit_node must not complete while Go holds the exclusive lock on the same constant"
    );
    go_exclusive.release().await;

    // Now Rust can admit normally.
    let rust_admission = silo_runtime::admission::admit_node(&pool, key)
        .await
        .unwrap();
    rust_admission.close().await;
}

#[tokio::test]
async fn go_publishes_and_rust_receives_byte_identical_json() {
    let (_bin, _db, redis) = skip_unless_all_set!();
    let bin = go_bin().unwrap();
    let cfg = RedisConfig {
        url: format!("redis://{redis}"),
        db: String::new(),
    };
    let bus = cache::event_bus::new_event_bus(&cfg);

    let received: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received);
    bus.subscribe(
        silo_core::redis::CHANNEL_CATALOG,
        Arc::new(move |event| received_clone.lock().unwrap().push(event)),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let output = Command::new(&bin)
        .args([
            "redis-publish",
            &redis,
            silo_core::redis::CHANNEL_CATALOG,
            "scan_complete",
            "lib-9",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let wire_json = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert_eq!(
        wire_json, r#"{"type":"scan_complete","payload":"lib-9"}"#,
        "Go's encoding/json output for cache.Event must be exactly this shape"
    );

    for _ in 0..50 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        received.lock().unwrap().clone(),
        vec![Event {
            event_type: "scan_complete".to_owned(),
            payload: "lib-9".to_owned()
        }]
    );
    bus.close().await.unwrap();
}

#[tokio::test]
async fn rust_publishes_and_go_receives_it() {
    let (bin, _db, redis) = skip_unless_all_set!();
    let cfg = RedisConfig {
        url: format!("redis://{redis}"),
        db: String::new(),
    };
    let bus = cache::event_bus::new_event_bus(&cfg);

    let mut subscriber = Command::new(&bin)
        .args([
            "redis-subscribe",
            &redis,
            silo_core::redis::CHANNEL_ADMIN,
            "5",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = subscriber.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut confirm = String::new();
    reader.read_line(&mut confirm).await.unwrap();
    assert_eq!(confirm.trim(), "subscribed");
    tokio::time::sleep(Duration::from_millis(100)).await;

    bus.publish(
        silo_core::redis::CHANNEL_ADMIN,
        Event {
            event_type: "settings_changed".to_owned(),
            payload: "auth.jwt_secret".to_owned(),
        },
    )
    .await
    .unwrap();

    let mut received = String::new();
    reader.read_line(&mut received).await.unwrap();
    assert_eq!(received.trim(), "settings_changed auth.jwt_secret");
    let status = subscriber.wait().await.unwrap();
    assert!(status.success());
    bus.close().await.unwrap();
}

/// Confirms every Lua script text in `silo_core::redis_lua` hashes, under the exact SHA1 `EVALSHA`
/// keys a script by, to what a real Go process computes over the same bytes — proving the two
/// languages' copies are not just visually similar but byte-identical where it matters: a mismatch
/// here means a Go-cached script and a Rust `EVALSHA` call for "the same" script would collide with
/// the wrong Lua or miss entirely.
#[tokio::test]
async fn lua_script_sha1_matches_a_real_go_program() {
    let Some(bin) = go_bin() else {
        eprintln!("SILO_RUNTIME_GO_INTEROP_BIN is not set; skipping");
        return;
    };
    use sha1::{Digest, Sha1};
    let scripts: &[(&str, &str)] = &[
        (
            "AUTOSCAN_CLAIM_STATE",
            silo_core::redis_lua::AUTOSCAN_CLAIM_STATE,
        ),
        (
            "AUTOSCAN_RELEASE_STATE",
            silo_core::redis_lua::AUTOSCAN_RELEASE_STATE,
        ),
        ("RATELIMIT_ATTEMPT", silo_core::redis_lua::RATELIMIT_ATTEMPT),
        ("RATELIMIT_QUOTA", silo_core::redis_lua::RATELIMIT_QUOTA),
        ("RATELIMIT_WINDOW", silo_core::redis_lua::RATELIMIT_WINDOW),
        ("NODERECIPE_PUT", silo_core::redis_lua::NODERECIPE_PUT),
        (
            "NODERECIPE_VALIDATE_LEGACY",
            silo_core::redis_lua::NODERECIPE_VALIDATE_LEGACY,
        ),
        (
            "NODERECIPE_REVOKE_NODE",
            silo_core::redis_lua::NODERECIPE_REVOKE_NODE,
        ),
        (
            "DOWNLOADS_SHARED_BANDWIDTH",
            silo_core::redis_lua::DOWNLOADS_SHARED_BANDWIDTH,
        ),
        (
            "CATALOG_SEARCH_SESSION_PUT",
            silo_core::redis_lua::CATALOG_SEARCH_SESSION_PUT,
        ),
    ];
    for (name, text) in scripts {
        let rust_sha1 = hex::encode(Sha1::digest(text.as_bytes()));
        let output = Command::new(&bin)
            .args(["lua-sha1", text])
            .output()
            .await
            .unwrap_or_else(|e| panic!("running lua-sha1 for {name}: {e}"));
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let go_sha1 = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        assert_eq!(
            rust_sha1, go_sha1,
            "{name}'s SHA1 must match between Rust and a real Go program"
        );
    }
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for byte in bytes.as_ref() {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}
