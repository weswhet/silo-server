//! Exercises the advisory-lock, storage-admission, database-bootstrap, and idgen-lease code against
//! a real Postgres. Set `SILO_RUNTIME_TEST_DATABASE_URL` to run these; each test clears the lock and
//! lease tables it touches first so repeated runs on the same throwaway database stay independent.
//!
//! Run with `-- --test-threads=1`: several tests inspect `pg_stat_activity` or rely on a lock key
//! being uncontended by anything else, which a second test running at the same time would break.

use silo_pg::{Pool, PoolConfig};
use silo_runtime::{admission, database, idgen_lease, locks};
use std::time::Duration;

fn test_url() -> Option<String> {
    std::env::var("SILO_RUNTIME_TEST_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

macro_rules! pool_or_skip {
    () => {{
        let Some(url) = test_url() else {
            eprintln!("SILO_RUNTIME_TEST_DATABASE_URL is not set; skipping");
            return;
        };
        Pool::connect(PoolConfig::parse(&url).unwrap())
            .await
            .unwrap()
    }};
}

// A fixed, test-only lock id far outside every real Go constant in `silo_core::advisory_locks`, so
// this test suite never contends with a real Go or Rust process using one of those.
const TEST_LOCK_KEY: i64 = 0x0052_4553_544B_4559; // "RESTKEY" won't collide with any real namespace.

#[tokio::test]
async fn try_acquire_blocks_a_second_session_and_release_frees_it() {
    let pool = pool_or_skip!();

    let first = locks::try_acquire(&pool, TEST_LOCK_KEY).await.unwrap();
    assert!(first.is_some(), "the first session should take the lock");

    let second = locks::try_acquire(&pool, TEST_LOCK_KEY).await.unwrap();
    assert!(
        second.is_none(),
        "a second session must not be able to take a lock the first still holds"
    );

    first.unwrap().release().await.unwrap();

    let third = locks::try_acquire(&pool, TEST_LOCK_KEY).await.unwrap();
    assert!(
        third.is_some(),
        "the lock must be free again once the holder released it"
    );
    third.unwrap().release().await.unwrap();
}

#[tokio::test]
async fn acquire_waits_out_the_wait_then_gives_up() {
    let pool = pool_or_skip!();
    let holder = locks::try_acquire(&pool, TEST_LOCK_KEY + 1)
        .await
        .unwrap()
        .unwrap();

    let started = std::time::Instant::now();
    let waiter = locks::acquire(&pool, TEST_LOCK_KEY + 1, Duration::from_millis(300))
        .await
        .unwrap();
    assert!(
        waiter.is_none(),
        "the wait should run out while the lock is held"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "acquire must actually wait, not fail immediately"
    );

    holder.release().await.unwrap();
    let waiter2 = locks::acquire(&pool, TEST_LOCK_KEY + 1, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(
        waiter2.is_some(),
        "the lock is free now, so acquire should succeed"
    );
    waiter2.unwrap().release().await.unwrap();
}

#[tokio::test]
async fn acquire_also_and_release_also_share_one_session() {
    let pool = pool_or_skip!();
    let mut lock = locks::try_acquire(&pool, TEST_LOCK_KEY + 2)
        .await
        .unwrap()
        .unwrap();

    let also_acquired = lock
        .acquire_also(TEST_LOCK_KEY + 3, Duration::ZERO)
        .await
        .unwrap();
    assert!(also_acquired);

    // Another session cannot take either key while this one holds both.
    assert!(
        locks::try_acquire(&pool, TEST_LOCK_KEY + 2)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        locks::try_acquire(&pool, TEST_LOCK_KEY + 3)
            .await
            .unwrap()
            .is_none()
    );

    lock.release_also(TEST_LOCK_KEY + 3).await.unwrap();
    assert!(
        lock.held(),
        "releasing the 'also' key must not drop the main lock"
    );
    let freed = locks::try_acquire(&pool, TEST_LOCK_KEY + 3).await.unwrap();
    assert!(freed.is_some(), "key 3 must be free after release_also");
    freed.unwrap().release().await.unwrap();

    lock.check().await.unwrap();
    lock.release().await.unwrap();
}

/// Admission's own lock key, from the real Go constant, so this proves the exact integer this
/// process will share with Go in production, not a test-only stand-in.
fn admission_key() -> i64 {
    silo_core::advisory_locks::STORAGE_NODE_ADMISSION
}

#[tokio::test]
async fn two_shared_admissions_coexist_and_exclusive_excludes_them() {
    let pool = pool_or_skip!();
    let key = admission_key();

    let node_a = admission::admit_node(&pool, key).await.unwrap();
    let node_b = admission::admit_node(&pool, key).await.unwrap();

    // Neither can upgrade while the other holds the shared lock.
    assert!(!node_a.try_exclusive().await.unwrap());
    assert!(!node_b.try_exclusive().await.unwrap());

    node_a.close().await;
    node_b.close().await;

    // With both shared holders gone, a fresh admission can go exclusive.
    let node_c = admission::admit_node(&pool, key).await.unwrap();
    assert!(node_c.try_exclusive().await.unwrap());
    node_c.verify_exclusive().await.unwrap();
    node_c.release_exclusive().await.unwrap();
    assert!(!node_c.is_exclusive().await);
    node_c.close().await;
}

#[tokio::test]
async fn probe_rejoins_after_the_session_is_dropped_out_from_under_it() {
    let pool = pool_or_skip!();
    let key = admission_key() + 1; // a distinct key so this test cannot interact with the one above
    let node = admission::admit_node(&pool, key).await.unwrap();

    // Simulate the pinned backend dying: terminate its own backend PID from a second connection.
    let pid: i32 = pool
        .query(
            "SELECT pid FROM pg_stat_activity WHERE query LIKE '%pg_advisory_lock_shared%' ORDER BY pid DESC LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .first()
        .map(|r| r.get(0))
        .unwrap_or(0);
    if pid != 0 {
        let _ = pool
            .execute("SELECT pg_terminate_backend($1)", &[&pid])
            .await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The next probe must notice the dead session and rejoin on a fresh one rather than staying
    // lost, since this node never held the exclusive lock.
    node.probe().await.unwrap();
    assert!(!node.is_lost().await);
    node.close().await;
}

#[tokio::test]
async fn idgen_lease_claims_and_renews_a_machine_id() {
    let pool = pool_or_skip!();
    // Keep this test independent of whatever the full `database::bootstrap` test below has claimed.
    pool.execute(
        "DELETE FROM idgen_machine_leases WHERE holder = $1",
        &[&"silo-runtime-test-lease"],
    )
    .await
    .ok(); // the table may not exist yet if migrations have not run in this database

    let Ok(_probe) = pool
        .query("SELECT 1 FROM idgen_machine_leases LIMIT 1", &[])
        .await
    else {
        eprintln!("idgen_machine_leases does not exist; run the database::bootstrap test first");
        return;
    };

    let lease = idgen_lease::Lease::start(pool.clone(), "silo-runtime-test-lease")
        .await
        .unwrap();
    let generator = lease.generator().current().await;
    let id1 = generator.next_id().unwrap();
    let id2 = generator.next_id().unwrap();
    assert!(id2.parse::<i64>().unwrap() > id1.parse::<i64>().unwrap());
    lease.stop().await;
}

#[tokio::test]
async fn database_bootstrap_connects_migrates_and_leases() {
    let Some(url) = test_url() else {
        eprintln!("SILO_RUNTIME_TEST_DATABASE_URL is not set; skipping");
        return;
    };
    let mut db = database::bootstrap(&url, "silo-runtime-bootstrap-test")
        .await
        .expect("bootstrap should connect, migrate, and lease a machine id");
    let generator = db
        .idgen()
        .expect("idgen lease should be set after bootstrap")
        .current()
        .await;
    assert!(!generator.next_id().unwrap().is_empty());
    db.shutdown().await;
}
