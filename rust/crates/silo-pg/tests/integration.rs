//! Driver behavior that only a server can show. Set `SILO_PG_TEST_URL` to run these. The migrator's
//! gate does, with a throwaway database.

use std::time::Duration;

use silo_pg::goose::{GoFunc, GoFuture, Migration, Provider, ProviderConfig};
use silo_pg::{AnyInt, ExecMode, HalfVector, PgText, Pool, PoolConfig, Session, TextValue, Vector};

fn test_url() -> Option<String> {
    std::env::var("SILO_PG_TEST_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

macro_rules! pool_or_skip {
    ($suffix:expr) => {{
        let Some(url) = test_url() else {
            eprintln!("SILO_PG_TEST_URL is not set; skipping");
            return;
        };
        let separator = if url.contains('?') { '&' } else { '?' };
        let url = format!("{url}{separator}{}", $suffix);
        Pool::connect(PoolConfig::parse(&url).unwrap())
            .await
            .unwrap()
    }};
}

async fn scalar_text(session: &mut Session, sql: &str) -> String {
    let row = session.query_one(sql, &[]).await.unwrap();
    row.get::<_, TextValue>(0).0
}

// A named statement moves to a generic plan after five executions when that costs no more. The unnamed
// statement in CacheDescribe mode is planned fresh each time, which is what search and recommendations
// opt into. pg_stat_statements counts plans, so it shows the difference directly.
#[tokio::test]
async fn cache_describe_keeps_custom_plans_and_cache_statement_goes_generic() {
    let pool = pool_or_skip!("application_name=plans");
    let mut s = pool.acquire().await.unwrap();
    s.batch_execute(
        "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
         SET pg_stat_statements.track_planning = on;
         DROP TABLE IF EXISTS plan_probe;
         CREATE TABLE plan_probe (k int);
         INSERT INTO plan_probe SELECT n FROM generate_series(1, 1000) n;
         ANALYZE plan_probe;",
    )
    .await
    .unwrap();

    s.batch_execute("SELECT pg_stat_statements_reset()")
        .await
        .unwrap();
    // pg_stat_statements ignores aliases, so the two statements need different shapes.
    let statement_sql = "SELECT count(*) FROM plan_probe WHERE k = $1";
    let describe_sql = "SELECT min(k) FROM plan_probe WHERE k = $1";
    for i in 0..10i32 {
        s.query_mode(ExecMode::CacheStatement, statement_sql, &[&i])
            .await
            .unwrap();
        s.query_mode(ExecMode::CacheDescribe, describe_sql, &[&i])
            .await
            .unwrap();
    }

    let row = s
        .query_one(
            "SELECT generic_plans, custom_plans FROM pg_prepared_statements WHERE statement = $1",
            &[&statement_sql],
        )
        .await
        .unwrap();
    let (generic, custom): (Option<i64>, Option<i64>) = (row.get(0), row.get(1));
    assert!(
        generic.unwrap_or(0) > 0,
        "a cached statement should reach a generic plan: generic {generic:?}, custom {custom:?}"
    );
    let describe_statements: i64 = s
        .query_one(
            "SELECT count(*) FROM pg_prepared_statements WHERE statement = $1",
            &[&describe_sql],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        describe_statements, 0,
        "CacheDescribe must not leave a named statement"
    );

    let row = s
        .query_one(
            "SELECT calls, plans FROM pg_stat_statements WHERE query = 'SELECT min(k) FROM plan_probe WHERE k = $1'",
            &[],
        )
        .await
        .unwrap();
    let (calls, plans): (i64, i64) = (row.get(0), row.get(1));
    assert_eq!(calls, 10);
    assert!(
        plans >= calls,
        "CacheDescribe reused a plan: {plans} plans for {calls} calls"
    );

    let row = s
        .query_one(
            "SELECT calls, plans FROM pg_stat_statements WHERE query = 'SELECT count(*) FROM plan_probe WHERE k = $1'",
            &[],
        )
        .await
        .unwrap();
    let (calls, plans): (i64, i64) = (row.get(0), row.get(1));
    assert_eq!(calls, 10);
    assert!(
        plans < calls,
        "a cached statement kept planning: {plans} plans for {calls} calls"
    );
    s.batch_execute("DROP TABLE plan_probe").await.unwrap();
}

#[tokio::test]
async fn default_mode_comes_from_the_url() {
    let pool = pool_or_skip!("default_query_exec_mode=cache_describe");
    let mut s = pool.acquire().await.unwrap();
    let sql = "SELECT $1::int + 1";
    let got: i32 = s.query_one(sql, &[&1i32]).await.unwrap().get(0);
    assert_eq!(got, 2);
    let count: i64 = s
        .query_one(
            "SELECT count(*) FROM pg_prepared_statements WHERE statement = $1",
            &[&sql],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

// pgx drops a statement from its caches when a query using it fails, so the next try re-prepares.
#[tokio::test]
async fn a_failed_cached_statement_is_invalidated() {
    let pool = pool_or_skip!("application_name=invalidate");
    let mut s = pool.acquire().await.unwrap();
    s.batch_execute("DROP TABLE IF EXISTS shape_probe; CREATE TABLE shape_probe (a int); INSERT INTO shape_probe VALUES (1)")
        .await
        .unwrap();
    let sql = "SELECT * FROM shape_probe WHERE a = $1";
    assert_eq!(s.query(sql, &[&1i32]).await.unwrap()[0].len(), 1);
    s.batch_execute("ALTER TABLE shape_probe ADD COLUMN b int")
        .await
        .unwrap();
    let err = s.query(sql, &[&1i32]).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("cached plan must not change result type"),
        "{err}"
    );
    assert_eq!(s.query(sql, &[&1i32]).await.unwrap()[0].len(), 2);
    s.batch_execute("DROP TABLE shape_probe").await.unwrap();
}

#[tokio::test]
async fn execute_without_parameters_uses_the_simple_protocol_and_reports_the_last_command() {
    let pool = pool_or_skip!("application_name=simple");
    let mut s = pool.acquire().await.unwrap();
    let n = s
        .execute(
            "CREATE TEMP TABLE simple_probe (a int); INSERT INTO simple_probe VALUES (1), (2), (3)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(n, 3);
}

#[tokio::test]
async fn jit_is_off_unless_the_connection_chose_it() {
    let pool = pool_or_skip!("application_name=jit");
    let mut s = pool.acquire().await.unwrap();
    assert_eq!(
        scalar_text(&mut s, "SELECT current_setting('jit')").await,
        "off"
    );
    drop(s);

    let pool = pool_or_skip!("jit=on");
    let mut s = pool.acquire().await.unwrap();
    assert_eq!(
        scalar_text(&mut s, "SELECT current_setting('jit')").await,
        "on"
    );
    assert_eq!(
        scalar_text(&mut s, "SELECT source FROM pg_settings WHERE name = 'jit'").await,
        "client"
    );
}

#[tokio::test]
async fn vector_codecs_round_trip_in_binary_and_null_is_an_error() {
    let pool = pool_or_skip!("application_name=vectors");
    let mut s = pool.acquire().await.unwrap();
    s.batch_execute("CREATE EXTENSION IF NOT EXISTS vector")
        .await
        .unwrap();
    // The connection predates the extension, so reconnect, as RunMigrations does.
    drop(s);
    pool.reset();
    let mut s = pool.acquire().await.unwrap();
    assert!(s.vector_oid().is_some() && s.halfvec_oid().is_some());

    let values = vec![0.0f32, 1.5, -2.25, 0.1, 3e10];
    let text: String = s
        .query_one("SELECT ($1::vector)::text", &[&Vector(values.clone())])
        .await
        .unwrap()
        .get(0);
    let server: String = s
        .query_one("SELECT ('[0,1.5,-2.25,0.1,3e10]'::vector)::text", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(text, server);
    let back: Vector = s
        .query_one("SELECT $1::vector", &[&Vector(values.clone())])
        .await
        .unwrap()
        .get(0);
    assert_eq!(back.0, values);

    // The client's f16 rounding has to match the server's own cast.
    let half = vec![0.0f32, 1.5, -2.25, 0.1, 0.3333];
    let client: String = s
        .query_one("SELECT ($1::halfvec)::text", &[&HalfVector(half.clone())])
        .await
        .unwrap()
        .get(0);
    let server: String = s
        .query_one("SELECT ('[0,1.5,-2.25,0.1,0.3333]'::halfvec)::text", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(client, server);
    let back: HalfVector = s
        .query_one("SELECT '[0.5,-1]'::halfvec", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(back.0, vec![0.5, -1.0]);

    // Go wraps its codec because a NULL scan panics upstream. Here it's an error, and Option works.
    let row = s.query_one("SELECT NULL::vector", &[]).await.unwrap();
    assert!(row.try_get::<_, Vector>(0).is_err());
    assert_eq!(row.get::<_, Option<Vector>>(0), None);
    // A wrong-typed parameter fails instead of sending a vector as something else.
    assert!(
        s.query_one("SELECT $1::halfvec", &[&Vector(vec![1.0])])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn loose_parameter_types_match_pgx() {
    let pool = pool_or_skip!("application_name=loose");
    let mut s = pool.acquire().await.unwrap();
    let row = s
        .query_one(
            "SELECT $1::int2, $2::int4, $3::int8, $4::jsonb, $5::text, $6::json",
            &[
                &AnyInt(1),
                &AnyInt(2),
                &AnyInt(3),
                &PgText("{\"a\": 1}"),
                &PgText("text"),
                &PgText("[1]"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, AnyInt>(0).0, 1);
    assert_eq!(row.get::<_, AnyInt>(1).0, 2);
    assert_eq!(row.get::<_, AnyInt>(2).0, 3);
    assert_eq!(row.get::<_, TextValue>(3).0, "{\"a\": 1}");
    assert_eq!(row.get::<_, TextValue>(4).0, "text");
    assert_eq!(row.get::<_, TextValue>(5).0, "[1]");
    // Out of range is an error, as in pgx, not a wrapped value.
    assert!(
        s.query_one("SELECT $1::int2", &[&AnyInt(70_000)])
            .await
            .is_err()
    );
}

async fn backend_pid(session: &mut Session) -> i32 {
    session
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn sessions_pin_a_connection_and_the_pool_discards_unsafe_ones() {
    let mut config = {
        let Some(url) = test_url() else {
            eprintln!("SILO_PG_TEST_URL is not set; skipping");
            return;
        };
        PoolConfig::parse(&url).unwrap()
    };
    config.max_conns = 2;
    let pool = Pool::connect(config).await.unwrap();

    // A session keeps one backend, so session-level state stays on it.
    let mut pinned = pool.acquire().await.unwrap();
    let pid = backend_pid(&mut pinned).await;
    let locked: bool = pinned
        .query_one("SELECT pg_try_advisory_lock(424242)", &[])
        .await
        .unwrap()
        .get(0);
    assert!(locked);
    assert_eq!(backend_pid(&mut pinned).await, pid);
    let mut other = pool.acquire().await.unwrap();
    let locked: bool = other
        .query_one("SELECT pg_try_advisory_lock(424242)", &[])
        .await
        .unwrap()
        .get(0);
    assert!(!locked, "the lock must be held by the pinned session");
    drop(other);

    // A hijacked session leaves the pool. Dropping it ends the backend and releases the lock.
    let hijacked = pinned.hijack();
    assert_eq!(pool.status().size, 1);
    drop(hijacked);
    let mut next = pool.acquire().await.unwrap();
    let mut released = false;
    for _ in 0..50 {
        let got: bool = next
            .query_one("SELECT pg_try_advisory_lock(424242)", &[])
            .await
            .unwrap()
            .get(0);
        if got {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(released);
    next.batch_execute("SELECT pg_advisory_unlock_all()")
        .await
        .unwrap();

    // Commit keeps the connection reusable.
    let pid = backend_pid(&mut next).await;
    let tx = next.begin().await.unwrap();
    tx.commit().await.unwrap();
    drop(next);
    let mut same = pool.acquire().await.unwrap();
    assert_eq!(backend_pid(&mut same).await, pid);

    // An abandoned transaction must not reach the next user of the connection.
    {
        let mut tx = same.begin().await.unwrap();
        tx.execute("CREATE TEMP TABLE abandoned (a int)", &[])
            .await
            .unwrap();
    }
    drop(same);
    let mut fresh = pool.acquire().await.unwrap();
    assert_ne!(
        backend_pid(&mut fresh).await,
        pid,
        "the connection left in a transaction was reused"
    );
    let in_tx: i64 = fresh
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE pid = pg_backend_pid() AND state = 'idle in transaction'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(in_tx, 0);
    let pid = backend_pid(&mut fresh).await;
    drop(fresh);

    // Reset reconnects, so per-connection setup runs again.
    pool.reset();
    let mut after = pool.acquire().await.unwrap();
    assert_ne!(backend_pid(&mut after).await, pid);
}

// --- goose provider ---

fn ok_tx<'a>(session: &'a mut Session) -> GoFuture<'a> {
    Box::pin(async move {
        session
            .execute("INSERT INTO goose_probe_data (v) VALUES ('tx')", &[])
            .await?;
        Ok(())
    })
}

fn failing_tx<'a>(session: &'a mut Session) -> GoFuture<'a> {
    Box::pin(async move {
        session
            .execute(
                "INSERT INTO goose_probe_data (v) VALUES ('rolled back')",
                &[],
            )
            .await?;
        Err("go migration failed".into())
    })
}

fn ok_db(pool: &Pool) -> GoFuture<'_> {
    Box::pin(async move {
        pool.execute("INSERT INTO goose_probe_data (v) VALUES ('db')", &[])
            .await?;
        Ok(())
    })
}

fn noop_db(_: &Pool) -> GoFuture<'_> {
    Box::pin(async { Ok(()) })
}

fn noop_tx<'a>(_: &'a mut Session) -> GoFuture<'a> {
    Box::pin(async { Ok(()) })
}

const LOCK_ID: i64 = 777_000_111;

fn provider(pool: &Pool, migrations: Vec<Migration>) -> Provider {
    Provider::new(
        pool.clone(),
        ProviderConfig {
            table: "public.goose_probe_versions".to_string(),
            lock_id: LOCK_ID,
            allow_missing: true,
            after_lock: None,
        },
        migrations,
    )
    .unwrap()
}

async fn recorded(pool: &Pool) -> Vec<i64> {
    pool.query(
        "SELECT version_id FROM public.goose_probe_versions ORDER BY id",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|row| row.get::<_, i64>(0))
    .collect()
}

async fn probe_rows(pool: &Pool) -> Vec<String> {
    pool.query("SELECT v FROM goose_probe_data ORDER BY id", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect()
}

#[tokio::test]
async fn provider_transaction_rules_match_goose() {
    let pool = pool_or_skip!("application_name=goose");
    pool.execute(
        "DROP TABLE IF EXISTS public.goose_probe_versions; DROP TABLE IF EXISTS goose_probe_data; DROP TABLE IF EXISTS goose_probe_conc;",
        &[],
    )
    .await
    .unwrap();

    let migrations = vec![
        Migration::sql(
            1,
            "1_create.sql",
            "-- +goose Up\nCREATE TABLE goose_probe_data (id serial PRIMARY KEY, v text);\nINSERT INTO goose_probe_data (v) VALUES ('one');\n-- +goose Down\nDROP TABLE goose_probe_data;\n",
        ),
        // Several CONCURRENTLY statements only work if each is sent alone, outside a transaction.
        Migration::sql(
            2,
            "2_concurrent.sql",
            "-- +goose NO TRANSACTION\n-- +goose Up\nCREATE TABLE goose_probe_conc (a int, b int);\nCREATE INDEX CONCURRENTLY goose_probe_a ON goose_probe_conc (a);\nCREATE INDEX CONCURRENTLY goose_probe_b ON goose_probe_conc (b);\n-- +goose Down\nDROP TABLE goose_probe_conc;\n",
        ),
        Migration::go(3, "3_tx.go", GoFunc::Tx(ok_tx), GoFunc::Tx(noop_tx)),
        Migration::go(4, "4_db.go", GoFunc::Db(ok_db), GoFunc::Db(noop_db)),
    ];
    let p = provider(&pool, migrations);
    assert!(p.has_pending().await.unwrap());
    let done = p.up_to(4).await.unwrap();
    assert_eq!(done.len(), 4);
    assert_eq!(recorded(&pool).await, vec![0, 1, 2, 3, 4]);
    assert_eq!(probe_rows(&pool).await, vec!["one", "tx", "db"]);
    assert!(!p.has_pending().await.unwrap());
    assert!(matches!(
        p.apply_version(3, true).await,
        Err(silo_pg::goose::ProviderError::AlreadyApplied(3))
    ));
    // The lock is free again after every operation.
    let mut s = pool.acquire().await.unwrap();
    let free: bool = s
        .query_one("SELECT pg_try_advisory_lock($1)", &[&LOCK_ID])
        .await
        .unwrap()
        .get(0);
    assert!(free);
    s.batch_execute(&format!("SELECT pg_advisory_unlock({LOCK_ID})"))
        .await
        .unwrap();
    drop(s);

    // A failing transactional migration rolls back its work and records nothing.
    let p = provider(
        &pool,
        vec![
            Migration::go(5, "5_fails.go", GoFunc::Tx(failing_tx), GoFunc::Tx(noop_tx)),
            Migration::sql(
                6,
                "6_fails.sql",
                "-- +goose Up\nINSERT INTO goose_probe_data (v) VALUES ('rolled back too');\nSELECT 1/0;\n-- +goose Down\nSELECT 1;\n",
            ),
            Migration::sql(
                7,
                "7_partial.sql",
                "-- +goose NO TRANSACTION\n-- +goose Up\nINSERT INTO goose_probe_data (v) VALUES ('kept');\nSELECT 1/0;\n",
            ),
        ],
    );
    let err = p.apply_version(5, true).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "partial migration error (type:go,version:5): go migration failed"
    );
    let err = p.apply_version(6, true).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("division by zero (SQLSTATE 22012)"),
        "{err}"
    );
    let err = p.apply_version(7, true).await.unwrap_err();
    assert!(err.to_string().contains("division by zero"), "{err}");
    assert_eq!(recorded(&pool).await, vec![0, 1, 2, 3, 4]);
    assert_eq!(probe_rows(&pool).await, vec!["one", "tx", "db", "kept"]);
}

#[tokio::test]
async fn provider_waits_for_the_session_lock() {
    let pool = pool_or_skip!("application_name=lockwait");
    let mut holder = pool.acquire().await.unwrap();
    holder
        .query_one("SELECT pg_advisory_lock($1)", &[&(LOCK_ID + 1)])
        .await
        .map(|_| ())
        .unwrap();

    let contender = pool.clone();
    let task = tokio::spawn(async move {
        let p = Provider::new(
            contender,
            ProviderConfig {
                table: "public.goose_lock_probe".to_string(),
                lock_id: LOCK_ID + 1,
                allow_missing: true,
                after_lock: None,
            },
            vec![Migration::go(
                1,
                "1.go",
                GoFunc::Db(noop_db),
                GoFunc::Db(noop_db),
            )],
        )
        .unwrap();
        p.status().await.map(|s| s.len())
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !task.is_finished(),
        "the provider must wait while the lock is held"
    );
    holder
        .query_one("SELECT pg_advisory_unlock($1)", &[&(LOCK_ID + 1)])
        .await
        .map(|_| ())
        .unwrap();
    // goose polls every five seconds.
    let done = tokio::time::timeout(Duration::from_secs(8), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.unwrap(), 1);
}
