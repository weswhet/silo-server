//! The viewer scope and the permission gates against a seeded database: what a pure test cannot reach.
//! Set `SILO_GATE_TEST_DATABASE_URL` to the conformance stack's database, and run with
//! `--test-threads=1`. The tests skip without it, and write and remove their own settings.

use std::sync::Arc;

use silo_auth::claims::{Claims, token_type};
use silo_auth::user::UserRepository;
use silo_config::config::AdminDefaults;
use silo_gate::mw::policy_gates::PolicyGates;
use silo_gate::mw::viewer::{GroupStore, ProfileTokens, ViewerResolver, require_viewer_access};
use silo_gate::pdp::Pdp;
use silo_gate::settings_cache::{admin_defaults, unrated_content};
use silo_http::Request;
use silo_pg::{Pool, PoolConfig};
use silo_store::access::ResolveInput;
use silo_store::settings::ServerSettingsRepo;

const USER_ID: i64 = 2;
const PROFILE_ID: &str = "c0f00000-0000-4000-8000-000000000002";

async fn pool(url: &str) -> Arc<Pool> {
    Arc::new(
        Pool::connect(PoolConfig::parse(url).expect("a database URL"))
            .await
            .expect("the database"),
    )
}

fn resolver(
    pool: &Arc<Pool>,
    defaults: AdminDefaults,
    settings: ServerSettingsRepo,
) -> ViewerResolver {
    ViewerResolver::new(
        UserRepository::new(pool.clone()),
        pool.clone(),
        ProfileTokens::new(b"unused".to_vec()),
        Arc::new(Pdp::vendor().expect("the vendor policy")),
        Some(Arc::new(defaults)),
        Some(Arc::new(unrated_content(settings))),
    )
}

fn claims() -> Claims {
    Claims {
        user_id: USER_ID,
        role: "user".to_owned(),
        token_type: token_type::API_KEY.to_owned(),
        ..Claims::default()
    }
}

#[tokio::test]
async fn scope_reads_server_settings_and_admin_defaults() {
    let Ok(url) = std::env::var("SILO_GATE_TEST_DATABASE_URL") else {
        return;
    };
    let pool = pool(&url).await;
    let settings = ServerSettingsRepo::new(pool.clone());
    let set = async |key: &str, value: &str| {
        pool.execute(
            "INSERT INTO server_settings(key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &[&key, &value],
        )
        .await
        .expect("a setting");
    };
    set("access.unrated_content", " ALLOW ").await;
    set("defaults.ui.next_up_mode", "\"separate\"").await;
    set("defaults.ui.next_up_new_releases_first", "true").await;
    let resolver = resolver(&pool, admin_defaults(settings.clone()), settings);
    let scope = resolver
        .resolve(
            &ResolveInput {
                user_id: USER_ID as i32,
                profile_id: PROFILE_ID.to_owned(),
                skip_pin_verification: true,
                ..ResolveInput::default()
            },
            "req",
        )
        .await;
    pool.execute(
        "DELETE FROM server_settings WHERE key IN ('access.unrated_content', 'defaults.ui.next_up_mode', 'defaults.ui.next_up_new_releases_first')",
        &[],
    )
    .await
    .expect("cleaning up");
    let scope = scope.expect("the scope");
    assert!(scope.maturity_limits.allow_unrated_content);
    assert_eq!(scope.next_up_mode, "separate");
    assert!(scope.next_up_new_releases_first);
}

/// R2: bytes that are not UTF-8 are not an absent header. Go's store read fails on them.
#[tokio::test]
async fn a_profile_id_that_is_not_utf8_is_refused() {
    let Ok(url) = std::env::var("SILO_GATE_TEST_DATABASE_URL") else {
        return;
    };
    let pool = pool(&url).await;
    let settings = ServerSettingsRepo::new(pool.clone());
    let resolver = resolver(&pool, admin_defaults(settings.clone()), settings);
    let mut r = Request::new_for_test("GET", "/");
    r.extensions.insert(Arc::new(claims()));
    r.header.set("X-Profile-Id", b"\xff".as_slice());
    let denial = require_viewer_access(&resolver, &mut r)
        .await
        .expect_err("refused");
    assert_eq!(denial.status, 500);
}

/// R4: the group is read once, so a failed read cannot pass as no mask.
#[tokio::test]
async fn a_failed_group_read_refuses_the_permission() {
    let Ok(url) = std::env::var("SILO_GATE_TEST_DATABASE_URL") else {
        return;
    };
    let good = pool(&url).await;
    // The `postgres` database on the same server has no `users` table to join.
    let elsewhere = url.replacen("/silo?", "/postgres?", 1);
    let bad = pool(&elsewhere).await;
    let settings = ServerSettingsRepo::new(good.clone());
    let viewer = Arc::new(resolver(&good, admin_defaults(settings.clone()), settings));
    let gates = PolicyGates {
        viewer,
        users: UserRepository::new(good.clone()),
        groups: GroupStore::new(bad),
        pool: good,
        pdp: Arc::new(Pdp::vendor().expect("the vendor policy")),
    };
    let mut r = Request::new_for_test("GET", "/");
    r.extensions.insert(Arc::new(claims()));
    r.header.set("X-Profile-Id", PROFILE_ID);
    let denial = gates
        .require_marker_edit(&r, "127.0.0.1")
        .await
        .expect_err("refused");
    assert_eq!(denial.status, 403);
}
