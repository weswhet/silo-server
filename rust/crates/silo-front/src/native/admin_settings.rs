//! The administrator settings reads (`admin.go`, `admin_setting_read.go`, `admin_settings_inspection.go`, and
//! v2 `admin_settings_inspection.go`, `admin_settings_discovery.go`) and the admin projection of the canonical
//! settings API (`settings_values_admin.go`, `admin_account_settings_service.go`).
//!
//! `PUT /admin/settings` stays on Go: it validates through the catalog, diagnostics, AI, and storage domains and
//! runs `OnServerSettingUpdated` in the Go process.

use std::collections::BTreeMap;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::problem::{Problem, type_for_status};
use silo_auth::claims::Claims;
use silo_auth::user::UserError;
use silo_config::config::{
    RedisConfig, effective_admin_settings, restart_required, restart_required_keys,
    restart_required_prefixes,
};
use silo_config::resolve::SettingIdentity;
use silo_config::settings::{ClientFamily, Scope, keys};
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::json::unmarshal;
use silo_gocompat::strings::trim_space;
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_store::access::Scope as AccessScope;
use silo_store::settings::is_sensitive;
use silo_store::userstore::prefs::Reader;

use super::auth::{ApiError, service_problem, write_v1_error};
use super::chain::{
    Stack, Step, V2Class, problem_type, write_problem, write_v1_json, write_v2_json,
};
use super::huma::RawBody;
use super::settings::{
    api, clear_setting_value, contract, field_error, q1, query_of, set_value_at_v1, value_view,
    write_api, write_setting_value, write_value_v2,
};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/settings"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/settings/effective"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/settings/restart-keys"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/settings/sensitive-status"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/settings/{key}"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/users/{id}/profiles"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/users/{id}/settings/values"),
    NativeRow::new(
        ApiV1,
        "PUT",
        "/api/v1/admin/users/{id}/settings/values/{key}",
    ),
    NativeRow::new(
        ApiV1,
        "DELETE",
        "/api/v1/admin/users/{id}/settings/values/{key}",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/settings"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/settings/effective"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/settings/restart-keys"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/settings/sensitive-status"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/settings/{key}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/users/{id}/profiles"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/users/{id}/settings/values"),
    NativeRow::new(
        ApiV2,
        "PUT",
        "/api/v2/admin/users/{id}/settings/values/{key}",
    ),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/admin/users/{id}/settings/values/{key}",
    ),
];

const V1_ACTING_ADMIN: &[Step] = &[Step::ActingAdmin];
const V2_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
];
const INTERNAL: &str = "internal_error";
const SHORTCUT_REPAIR: &str =
    "Use whole-document PUT on this admin resource to clear or replace navigation shortcuts";

/// `machineManagedSettingKeys`.
fn machine_managed(key: &str) -> bool {
    matches!(
        key,
        "auth.jwt_secret"
            | "audiobooks.abs.jwt_secret"
            | "ai.chatgpt.credentials"
            | "ai.providers"
            | "s3.public_storage_reconcile_checkpoint"
            | "artwork.storage_sweep_checkpoint"
            | "media_images.sweep_checkpoint"
            | "chapter_thumbnails.originals_cleanup_checkpoint"
            | "artwork.storage_identity"
            | "storage.operational_identity"
            | "storage.transition.target"
    )
}

/// `BootstrapSensitiveValues`: what the process environment supplies.
fn bootstrap_values() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    // A front whose route to Redis differs from Go's names Go's, because it is part of the settings tag.
    if let Ok(url) =
        std::env::var("SILO_FRONT_GO_REDIS_URL").or_else(|_| std::env::var("REDIS_URL"))
        && !url.is_empty()
    {
        let db = RedisConfig {
            url: url.clone(),
            db: String::new(),
        }
        .database()
        .unwrap_or(0);
        out.insert("redis.url".to_owned(), url);
        out.insert("redis.db".to_owned(), db.to_string());
    }
    if let Ok(raw) = std::env::var("SILO_TRUSTED_PROXIES")
        && !trim_space(&raw).is_empty()
        && let Ok(normalized) = silo_gate::clientip::normalize_cidr_list(&raw)
    {
        out.insert("clientip.trusted_proxies".to_owned(), normalized);
    }
    // `catalog.SearchSettingsFromEnv`. Go normalizes these as an admin save would, and the ones the
    // baseline does not set take this path only when they are plain values already.
    for (env, key) in [
        ("SILO_SEARCH_PROVIDER", "catalog.search.provider"),
        ("SILO_MEILISEARCH_URL", "catalog.search.meilisearch.url"),
        (
            "SILO_MEILISEARCH_API_KEY",
            "catalog.search.meilisearch.api_key",
        ),
    ] {
        if let Ok(raw) = std::env::var(env)
            && !trim_space(&raw).is_empty()
        {
            out.insert(key.to_owned(), trim_space(&raw).to_owned());
        }
    }
    out
}

fn effective_of(stored: &silo_config::config::SettingsMap) -> silo_config::config::SettingsMap {
    let mut active = stored.clone();
    for (key, value) in bootstrap_values() {
        active.insert(key, value);
    }
    let mut effective = effective_admin_settings(&active);
    if effective.get("redis.db").is_none_or(String::is_empty)
        && let Some(url) = effective.get("redis.url").filter(|u| !u.is_empty())
        && let Some(db) = (RedisConfig {
            url: url.clone(),
            db: String::new(),
        })
        .database()
    {
        effective.insert("redis.db".to_owned(), db.to_string());
    }
    effective
}

fn visible(values: &silo_config::config::SettingsMap) -> BTreeMap<String, String> {
    values
        .iter()
        .filter(|(k, _)| !is_sensitive(k) && !machine_managed(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// `adminSettingsSnapshotTag`.
fn snapshot_tag(
    s: &Stack,
    r: &Request,
    claims: &Claims,
    stored: &silo_config::config::SettingsMap,
) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Validator {
        stored: BTreeMap<String, String>,
        effective: BTreeMap<String, String>,
    }
    let strip = |m: &silo_config::config::SettingsMap| {
        m.iter()
            .filter(|(k, _)| !machine_managed(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let raw = silo_gocompat::json::marshal(&Validator {
        stored: strip(stored),
        effective: strip(&effective_of(stored)),
    })
    .unwrap_or_default();
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(s.artwork_secret.as_bytes()).expect("HMAC takes any key");
    mac.update(&raw);
    let id: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let scope = r
        .extensions
        .get::<Arc<AccessScope>>()
        .map(|scope| silo_core::apiv2::ViewerScope {
            policy_revision: scope.policy_revision,
            libraries_restricted: scope.libraries_restricted,
            allowed_library_ids: scope
                .libraries_restricted
                .then(|| scope.allowed_library_ids.clone()),
            disabled_library_ids: (!scope.disabled_library_ids.is_empty())
                .then(|| scope.disabled_library_ids.clone()),
            max_content_rating: scope.maturity_limits.max_content_rating.clone(),
            allow_unrated_content: scope.maturity_limits.allow_unrated_content,
            max_advisory_age: i64::from(scope.maturity_limits.max_advisory_age),
            require_advisory_age: scope.maturity_limits.require_advisory_age,
        });
    let digest = silo_core::apiv2::viewer_scope_digest(scope.as_ref());
    let label = format!(
        "admin-settings:{}:{}:{digest}",
        claims.user_id,
        get_profile_id(r)
    );
    silo_core::apiv2::render_etag(label.as_bytes(), id.as_bytes(), 1).to_wire()
}

/// `adminSensitiveSettingsStatus`.
fn sensitive_status(stored: &silo_config::config::SettingsMap) -> (Vec<String>, Vec<String>) {
    let bootstrap = bootstrap_values();
    let mut configured: Vec<String> = silo_store::settings::SENSITIVE_SETTING_KEYS
        .iter()
        .filter(|k| !machine_managed(k))
        .filter(|k| stored.get(**k).is_some_and(|v| !v.is_empty()) || bootstrap.contains_key(**k))
        .map(|k| (*k).to_owned())
        .collect();
    configured.sort();
    (configured, bootstrap.keys().cloned().collect())
}

/// `AdminSettingValue`.
#[derive(Serialize)]
struct SettingV1 {
    key: String,
    value: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    restart_required: bool,
}

/// `ReadAdminSetting`.
async fn read_setting(s: &Stack, key: &str) -> Result<(String, bool), ApiError> {
    if key.is_empty() {
        return Err(api(400, "bad_request", "Setting key is required"));
    }
    if is_sensitive(key) || machine_managed(key) {
        return Err(api(404, "not_found", "Setting not found"));
    }
    if let Some(value) = bootstrap_values().get(key) {
        return Ok((value.clone(), restart_required(key)));
    }
    let value = s
        .encrypted
        .get(key)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to load setting"))?;
    if value.is_empty() {
        return Err(api(404, "not_found", "Setting not found"));
    }
    Ok((value, restart_required(key)))
}

macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

macro_rules! claims {
    ($r:ident) => {
        match get_claims($r) {
            Some(claims) => claims,
            None => return,
        }
    };
}

fn parse_user_id(r: &Request) -> Option<i64> {
    r.url_param("id").parse::<i64>().ok().filter(|n| *n > 0)
}

/// `adminIdentityFromRequest`.
async fn v1_identity(s: &Stack, r: &Request) -> Result<SettingIdentity, ApiError> {
    let query = query_of(r);
    let (key, scope) = super::settings::keyed_scope(r.url_param("key"), &q1(&query, "scope"))?;
    let mut identity = SettingIdentity {
        key,
        scope: scope.clone(),
        ..SettingIdentity::default()
    };
    if scope != Scope::ACCOUNT {
        identity.profile_id = trim_space(&q1(&query, "profile_id")).to_owned();
        if identity.profile_id.is_empty() {
            return Err(api(
                400,
                "bad_request",
                "profile_id is required for this scope",
            ));
        }
    }
    if scope == Scope::PROFILE_CLIENT {
        identity.client_family = ClientFamily::new(trim_space(&q1(&query, "client_family")));
        if !identity.client_family.valid() {
            return Err(api(
                400,
                "bad_request",
                "client_family must be one of tv, mobile, tablet, desktop or web",
            ));
        }
    }
    if scope == Scope::PROFILE_DEVICE {
        identity.device_id = trim_space(&q1(&query, "device_id")).to_owned();
        if identity.device_id.is_empty() {
            return Err(api(
                400,
                "bad_request",
                "device_id is required for a device override",
            ));
        }
    }
    super::settings::complete_identity(
        s,
        &q1(&query, "library_id"),
        &q1(&query, "series_id"),
        identity,
    )
    .await
}

/// `adminSettingIdentity`.
async fn v2_identity(s: &Stack, r: &Request, user_id: i64) -> Result<SettingIdentity, ApiError> {
    let query = query_of(r);
    let (key, scope) = super::settings::keyed_scope(r.url_param("key"), &q1(&query, "scope"))?;
    let mut identity = SettingIdentity {
        key,
        scope: scope.clone(),
        ..SettingIdentity::default()
    };
    if scope != Scope::ACCOUNT {
        identity.profile_id = trim_space(&q1(&query, "profile_id")).to_owned();
        if identity.profile_id.is_empty() {
            return Err(field_error("profile_id", "A target profile is required"));
        }
        match s.viewer.get_profile(user_id, &identity.profile_id).await {
            Err(_) => return Err(api(500, INTERNAL, "Failed to load target profile")),
            Ok(None) => return Err(api(404, "not_found", "Target profile not found")),
            Ok(Some(_)) => {}
        }
    }
    if scope == Scope::PROFILE_CLIENT {
        identity.client_family = ClientFamily::new(q1(&query, "client_family"));
    }
    if scope == Scope::PROFILE_DEVICE {
        identity.device_id = trim_space(&q1(&query, "device_id")).to_owned();
    }
    super::settings::complete_identity(
        s,
        &q1(&query, "library_id"),
        &q1(&query, "series_id"),
        identity,
    )
    .await
}

/// Registers the v1 rows on the admin router, whose group gates they share.
pub fn mount_v1(stack: &Arc<Stack>, admin: &Mux) {
    let at = "/api/v1/admin/settings";
    admin.get(
        "/settings",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, _r| {
                match s.encrypted.get_all().await {
                    Ok(all) => write_v1_json(w, 200, &visible(&all)).await,
                    Err(_) => write_v1_error(w, 500, INTERNAL, "Failed to load settings").await,
                }
            }),
        ),
    );
    let at = "/api/v1/admin/settings/effective";
    admin.get(
        "/settings/effective",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, _r| {
                match s.encrypted.get_all().await {
                    Ok(all) => write_v1_json(w, 200, &visible(&effective_of(&all))).await,
                    Err(_) => write_v1_error(w, 500, INTERNAL, "Failed to load settings").await,
                }
            }),
        ),
    );
    let at = "/api/v1/admin/settings/restart-keys";
    admin.get(
        "/settings/restart-keys",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            handler_fn(|w, _r| {
                Box::pin(async move {
                    #[derive(Serialize)]
                    struct Out {
                        keys: Vec<String>,
                        prefixes: Vec<String>,
                    }
                    write_v1_json(
                        w,
                        200,
                        &Out {
                            keys: restart_required_keys(),
                            prefixes: restart_required_prefixes(),
                        },
                    )
                    .await;
                })
            }),
        ),
    );
    let at = "/api/v1/admin/settings/sensitive-status";
    admin.get(
        "/settings/sensitive-status",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, _r| {
                match s.encrypted.get_all().await {
                    Ok(all) => {
                        let (configured, managed_by_env) = sensitive_status(&all);
                        #[derive(Serialize)]
                        struct Out {
                            configured: Vec<String>,
                            #[serde(skip_serializing_if = "Vec::is_empty")]
                            managed_by_env: Vec<String>,
                        }
                        write_v1_json(
                            w,
                            200,
                            &Out {
                                configured,
                                managed_by_env,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_v1_error(w, 500, "settings_error", &e.to_string()).await,
                }
            }),
        ),
    );
    let at = "/api/v1/admin/settings/{key}";
    admin.get(
        "/settings/{key}",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let key = r.url_param("key").to_owned();
                match read_setting(&s, &key).await {
                    Ok((value, restart_required)) => {
                        write_v1_json(
                            w,
                            200,
                            &SettingV1 {
                                key,
                                value,
                                restart_required,
                            },
                        )
                        .await
                    }
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    let at = "/api/v1/admin/users/{id}/profiles";
    admin.get(
        "/users/{id}/profiles",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let Ok(user_id) = r.url_param("id").parse::<i64>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid user ID").await;
                };
                let Ok(profiles) = s.viewer.list_profiles(user_id).await else {
                    return write_v1_error(w, 500, INTERNAL, "Failed to list profiles").await;
                };
                #[derive(Serialize)]
                struct Row {
                    id: String,
                    name: String,
                }
                let rows: Vec<Row> = profiles
                    .into_iter()
                    .map(|p| Row {
                        id: p.id,
                        name: p.name,
                    })
                    .collect();
                write_v1_json(w, 200, &rows).await;
            }),
        ),
    );
    let at = "/api/v1/admin/users/{id}/settings/values";
    admin.get(
        "/users/{id}/settings/values",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let Some(user_id) = parse_user_id(r) else {
                    return write_v1_error(w, 400, "bad_request", "Invalid user id").await;
                };
                let store =
                    silo_store::userstore::pgstore::PostgresUserStore::new(s.pool.clone(), user_id);
                let Ok(values) = store.list_all_setting_values().await else {
                    return write_v1_error(w, 500, INTERNAL, "Failed to list settings").await;
                };
                #[derive(Serialize)]
                struct Out {
                    revision: i64,
                    values: Vec<super::settings::ValueView>,
                }
                write_v1_json(
                    w,
                    200,
                    &Out {
                        revision: contract().revision,
                        values: values.iter().map(value_view).collect(),
                    },
                )
                .await;
            }),
        ),
    );
    let at = "/api/v1/admin/users/{id}/settings/values/{key}";
    admin.put(
        "/users/{id}/settings/values/{key}",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let Some(user_id) = parse_user_id(r) else {
                    return write_v1_error(w, 400, "bad_request", "Invalid user id").await;
                };
                let identity = match v1_identity(&s, r).await {
                    Ok(identity) => identity,
                    Err(e) => return write_api(w, &e).await,
                };
                if !identity.profile_id.is_empty() {
                    match s.viewer.get_profile(user_id, &identity.profile_id).await {
                        Err(_) => {
                            return write_v1_error(w, 500, INTERNAL, "Failed to load profile")
                                .await;
                        }
                        Ok(None) => {
                            return write_v1_error(w, 404, "not_found", "Profile not found").await;
                        }
                        Ok(Some(_)) => {}
                    }
                }
                let (bytes, _) = r.read_all().await;
                set_value_at_v1(&s, w, r, &claims, user_id, &identity, &bytes).await;
            }),
        ),
    );
    admin.delete(
        "/users/{id}/settings/values/{key}",
        stack.v1(
            at,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let Some(user_id) = parse_user_id(r) else {
                    return write_v1_error(w, 400, "bad_request", "Invalid user id").await;
                };
                let identity = match v1_identity(&s, r).await {
                    Ok(identity) => identity,
                    Err(e) => return write_api(w, &e).await,
                };
                if identity.key == keys::NAV_SHORTCUTS {
                    return write_v1_error(w, 400, "atomic_update_required", SHORTCUT_REPAIR).await;
                }
                match clear_setting_value(&s, r, &claims, user_id, &identity).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
}

/// `adminAccountSettingTarget`.
async fn target_v2(s: &Stack, r: &Request) -> Result<i64, Problem> {
    let raw = r.url_param("id");
    let Some(id) = super::settings::int_of_id(raw) else {
        return Err(Problem::new(
            problem_type("validation_failed"),
            "Expected a positive account identifier.",
        ));
    };
    match s.users.get_by_id(id).await {
        Ok(_) => Ok(id),
        Err(UserError::NotFound) => Err(Problem::new(
            problem_type("not_found"),
            "Account not found.",
        )),
        Err(_) => Err(Problem::new(
            silo_api_v2::problem::internal_error(),
            "An unexpected error occurred.",
        )),
    }
}

/// `apiv2.PageInfo`.
#[derive(Serialize)]
struct PageInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    has_more: bool,
}

/// The page key, spelled as Go marshals `userstore.SettingIdentity`.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
struct PageKey {
    key: String,
    scope: String,
    #[serde(rename = "ProfileID")]
    profile_id: String,
    client_family: String,
    #[serde(rename = "DeviceID")]
    device_id: String,
    #[serde(rename = "LibraryID")]
    library_id: i64,
    #[serde(rename = "SeriesID")]
    series_id: String,
}

/// Registers the v2 rows.
pub fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    #[derive(Clone, Copy)]
    enum Which {
        Stored,
        Effective,
    }
    for (path, which) in [
        ("/api/v2/admin/settings", Which::Stored),
        ("/api/v2/admin/settings/effective", Which::Effective),
    ] {
        v2.get(
            path,
            stack.v2(
                path,
                V2Class::ActingAdmin,
                route!(stack, |s, w, r| {
                    let claims = claims!(r);
                    let all = match s.encrypted.get_all().await {
                        Ok(all) => all,
                        Err(_) => {
                            return write_problem(
                                w,
                                r,
                                Problem::new(
                                    silo_api_v2::problem::internal_error(),
                                    "An unexpected error occurred.",
                                ),
                            )
                            .await;
                        }
                    };
                    w.header().set("ETag", snapshot_tag(&s, r, &claims, &all));
                    let values = match which {
                        Which::Stored => visible(&all),
                        Which::Effective => visible(&effective_of(&all)),
                    };
                    write_v2_json(w, &values).await;
                }),
            ),
        );
    }
    let path = "/api/v2/admin/settings/restart-keys";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(|w, _r| {
                Box::pin(async move {
                    #[derive(Serialize)]
                    struct Out {
                        keys: Vec<String>,
                        prefixes: Vec<String>,
                    }
                    write_v2_json(
                        w,
                        &Out {
                            keys: restart_required_keys(),
                            prefixes: restart_required_prefixes(),
                        },
                    )
                    .await;
                })
            }),
        ),
    );
    let path = "/api/v2/admin/settings/sensitive-status";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                match s.encrypted.get_all().await {
                    Ok(all) => {
                        let (configured, managed_by_env) = sensitive_status(&all);
                        #[derive(Serialize)]
                        struct Out {
                            configured: Vec<String>,
                            managed_by_env: Vec<String>,
                        }
                        write_v2_json(
                            w,
                            &Out {
                                configured,
                                managed_by_env,
                            },
                        )
                        .await;
                    }
                    Err(_) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(
                                silo_api_v2::problem::internal_error(),
                                "An unexpected error occurred.",
                            ),
                        )
                        .await
                    }
                }
            }),
        ),
    );
    let path = "/api/v2/admin/settings/{key}";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let key = r.url_param("key").to_owned();
                match read_setting(&s, &key).await {
                    Ok((value, restart_required)) => {
                        #[derive(Serialize)]
                        struct Out {
                            key: String,
                            value: String,
                            restart_required: bool,
                        }
                        write_v2_json(
                            w,
                            &Out {
                                key,
                                value,
                                restart_required,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/admin/users/{id}/profiles";
    v2.get(path, stack.v2(path, V2Class::ActingAdmin, route!(stack, |s, w, r| {
        let id = match target_v2(&s, r).await {
            Ok(id) => id,
            Err(p) => return write_problem(w, r, p).await,
        };
        let Ok(profiles) = silo_store::userstore::profiles::list_profiles(&s.pool, id).await else {
            return write_problem(w, r, Problem::new(silo_api_v2::problem::internal_error(), "An unexpected error occurred.")).await;
        };
        // Last use is a hint: a failed read leaves it unknown.
        let id32 = silo_pg::AnyInt(id);
        let seen = s.pool.query(
            "SELECT profile_id, max(last_seen_at) FROM user_devices WHERE user_id = $1 GROUP BY profile_id",
            &[&id32],
        ).await.unwrap_or_default();
        #[derive(Serialize)]
        struct Item {
            id: String,
            name: String,
            avatar: String,
            #[serde(skip_serializing_if = "String::is_empty")]
            avatar_url: String,
            avatar_source: &'static str,
            last_seen_at: Option<String>,
        }
        let mut items = Vec::with_capacity(profiles.len());
        for p in profiles {
            let (source, url) = super::profiles::resolve_avatar(&s, &p.avatar);
            let last_seen = seen.iter().find(|row| row.get::<_, String>(0) == p.id).map(|row| {
                let at: std::time::SystemTime = row.get(1);
                silo_gocompat::time::GoTime::from_system_time(at).to_utc().format("2006-01-02T15:04:05.000Z")
            });
            items.push(Item {
                id: p.id,
                name: trim_space(&p.name).to_owned(),
                avatar: p.avatar,
                avatar_url: url,
                avatar_source: source,
                last_seen_at: last_seen,
            });
        }
        #[derive(Serialize)]
        struct Out { items: Vec<Item>, page: PageInfo }
        write_v2_json(w, &Out { items, page: PageInfo { next_cursor: None, has_more: false } }).await;
    })));

    let path = "/api/v2/admin/users/{id}/settings/values";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let id = match target_v2(&s, r).await {
                    Ok(id) => id,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let query = query_of(r);
                let limit: i64 = q1(&query, "limit").parse().unwrap_or(50);
                let scope = CursorScope {
                    operation_id: "listAdminUserSettingValues".to_owned(),
                    security: format!("{}/{}", claims.user_id, get_profile_id(r)),
                    filter: format!("{id}/{limit}"),
                    sort: "key,scope,profile,client,device,library,series".to_owned(),
                    tiebreaker: "identity".to_owned(),
                };
                let cursor = q1(&query, "cursor");
                let mut after = PageKey::default();
                if !cursor.is_empty() {
                    after = match s.cursors.decode(&scope, &cursor) {
                        Ok(after) => after,
                        Err(p) => return write_problem(w, r, p).await,
                    };
                }
                let reader = Reader {
                    pool: &s.pool,
                    user_id: silo_pg::AnyInt(id),
                };
                let after_identity = SettingIdentity {
                    key: after.key,
                    scope: Scope::new(after.scope),
                    profile_id: after.profile_id,
                    client_family: ClientFamily::new(after.client_family),
                    device_id: after.device_id,
                    library_id: after.library_id,
                    series_id: after.series_id,
                };
                let (rows, more) = match reader.list_admin_page(&after_identity, limit).await {
                    Ok(page) => page,
                    Err(_) => {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                silo_api_v2::problem::internal_error(),
                                "An unexpected error occurred.",
                            ),
                        )
                        .await;
                    }
                };
                let mut items = Vec::with_capacity(rows.len());
                for row in &rows {
                    match super::settings::v2_value(value_view(row)) {
                        Ok(item) => items.push(item),
                        Err(p) => return write_problem(w, r, p).await,
                    }
                }
                let mut next = None;
                if more && let Some(last) = rows.last() {
                    let key = PageKey {
                        key: last.identity.key.clone(),
                        scope: last.identity.scope.as_str().to_owned(),
                        profile_id: last.identity.profile_id.clone(),
                        client_family: last.identity.client_family.as_str().to_owned(),
                        device_id: last.identity.device_id.clone(),
                        library_id: last.identity.library_id,
                        series_id: last.identity.series_id.clone(),
                    };
                    next = match s.cursors.encode(&scope, &key) {
                        Ok(token) => Some(token),
                        Err(p) => return write_problem(w, r, p).await,
                    };
                }
                #[derive(Serialize)]
                struct Out {
                    items: Vec<super::settings::V2Value>,
                    page: PageInfo,
                    revision: i64,
                }
                let page = PageInfo {
                    has_more: next.is_some(),
                    next_cursor: next,
                };
                write_v2_json(
                    w,
                    &Out {
                        items,
                        page,
                        revision: contract().revision,
                    },
                )
                .await;
            }),
        ),
    );

    let path = "/api/v2/admin/users/{id}/settings/values/{key}";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let id = match target_v2(&s, r).await {
                    Ok(id) => id,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let identity = match v2_identity(&s, r, id).await {
                    Ok(identity) => identity,
                    Err(e) => return write_problem(w, r, service_problem(&e)).await,
                };
                #[derive(Default, Deserialize)]
                #[serde(default)]
                struct Body {
                    value: silo_gocompat::json::RawMessage,
                }
                let raw = r
                    .extensions
                    .get::<RawBody>()
                    .map(|b| b.0.clone())
                    .unwrap_or_default();
                let body: Body = unmarshal(&raw).unwrap_or_default();
                let value = body.value.as_bytes().unwrap_or_default().to_vec();
                match write_setting_value(
                    &s,
                    r,
                    &claims,
                    id,
                    &identity,
                    &value,
                    "",
                    &super::settings::Device::default(),
                )
                .await
                {
                    Ok(result) => {
                        if let Some(view) = result.into_view() {
                            write_value_v2(w, r, view).await;
                        }
                    }
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let id = match target_v2(&s, r).await {
                    Ok(id) => id,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let identity = match v2_identity(&s, r, id).await {
                    Ok(identity) => identity,
                    Err(e) => return write_problem(w, r, service_problem(&e)).await,
                };
                if identity.key == keys::NAV_SHORTCUTS {
                    return write_problem(
                        w,
                        r,
                        service_problem(&field_error("key", SHORTCUT_REPAIR)),
                    )
                    .await;
                }
                match clear_setting_value(&s, r, &claims, id, &identity).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
    let _ = type_for_status;
}
