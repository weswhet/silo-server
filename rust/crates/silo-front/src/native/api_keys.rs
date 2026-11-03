//! `handlers/api_keys.go`, `apiv2/personal_api_keys.go`, and `apiv2/admin_api_keys.go`.

use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::precondition::{evaluate_guarded_preconditions, evaluate_read_preconditions};
use silo_api_v2::problem::{Problem, ProblemError};
use silo_api_v2::wire::{Instant, paginated};
use silo_auth::api_key::{
    api_key_scope_catalog, normalize_api_key_scopes, normalize_v1_api_key_scopes,
    v1_api_key_scope_catalog,
};
use silo_auth::api_key_store::{ApiKeyMetadata, CreatedApiKey, KeyError, Precondition};
use silo_auth::claims::{Claims, token_type};
use silo_auth::service::check_owner_target_by_id;
use silo_core::apiv2::{EntityTag, render_etag};
use silo_gate::mw::auth::{declared_profile_id, get_claims, get_profile_id};
use silo_gocompat::time::GoTime;
use silo_http::chi::Mux;
use silo_http::{Request, ResponseWriter, handler_fn};
use silo_store::access::Scope;
use silo_store::userstore::profiles::Profile;

use super::auth::{service_problem, write_v1_error};
use super::chain::{
    Stack, Step, V2Class, capability_json, problem_type, write_capability, write_problem,
    write_v1_json, write_v2_json, write_v2_json_status,
};
use super::huma::{RawBody, reject_nulls};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "POST", "/api/v1/api-keys/"),
    NativeRow::new(ApiV1, "GET", "/api/v1/api-keys/"),
    NativeRow::new(ApiV1, "GET", "/api/v1/api-keys/scopes"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/api-keys/{id}"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/users/{userId}/api-keys"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/api-keys"),
    NativeRow::new(ApiV1, "POST", "/api/v1/admin/api-keys"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/admin/api-keys/{id}"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/admin/api-keys/{id}/tier"),
    NativeRow::new(ApiV2, "GET", "/api/v2/api-keys/scopes"),
    NativeRow::new(ApiV2, "GET", "/api/v2/api-keys"),
    NativeRow::new(ApiV2, "POST", "/api/v2/api-keys"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/api-keys/{id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/api-keys/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/api-keys"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/api-keys/{id}"),
    NativeRow::new(ApiV2, "POST", "/api/v2/admin/api-keys"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/admin/api-keys/{id}/tier"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/admin/api-keys/{id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/users/{id}/api-keys"),
];

const V1_KEYS: &[Step] = &[Step::Auth, Step::Demo];
const V1_VIEWER_GROUP: &[Step] = &[Step::Auth, Step::Demo, Step::RateLimit, Step::Viewer];
const V1_ACTING_ADMIN: &[Step] = &[Step::ActingAdmin];
const V2_READ: &[Step] = &[Step::Auth, Step::RateLimit];
const V2_WRITE: &[Step] = &[Step::Auth, Step::DemoRestricted, Step::RateLimit];
const V2_CREATE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
];
const V2_ADMIN_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
];

fn go_time(t: SystemTime) -> String {
    GoTime::from_system_time(t).format(silo_gocompat::time::RFC3339_NANO)
}

fn instant(t: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(t))
}

#[derive(Serialize)]
struct V1Created {
    id: i64,
    user_id: i64,
    label: String,
    key: String,
    rate_tier: String,
    scopes: Vec<String>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<String>,
}

fn v1_created(k: CreatedApiKey) -> V1Created {
    V1Created {
        id: k.id,
        user_id: k.user_id,
        label: k.label,
        key: k.key,
        rate_tier: k.rate_tier,
        scopes: k.scopes,
        created_at: go_time(k.created_at),
        last_used_at: k.last_used_at.map(go_time),
    }
}

#[derive(Serialize)]
struct V1ListItem {
    id: i64,
    user_id: i64,
    label: String,
    key_prefix: String,
    rate_tier: String,
    scopes: Vec<String>,
    created_at: String,
    revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<String>,
}

#[derive(Serialize)]
struct V1AdminListItem {
    #[serde(flatten)]
    item: V1ListItem,
    username: String,
}

fn v1_item(k: ApiKeyMetadata) -> V1ListItem {
    V1ListItem {
        id: k.id,
        user_id: k.user_id,
        label: k.label,
        key_prefix: k.key_prefix,
        rate_tier: k.rate_tier,
        scopes: k.scopes,
        created_at: go_time(k.created_at),
        revision: k.revision,
        last_used_at: k.last_used_at.map(go_time),
    }
}

#[derive(Serialize)]
struct Scopes<S> {
    scopes: S,
}

#[derive(Serialize)]
struct ScopeView {
    name: &'static str,
    description: &'static str,
}

fn scope_views(list: Vec<silo_auth::api_key::ApiKeyScope>) -> Vec<ScopeView> {
    list.into_iter()
        .map(|s| ScopeView {
            name: s.name,
            description: s.description,
        })
        .collect()
}

/// `requireJWTAuth`.
async fn require_jwt(w: &mut dyn ResponseWriter, r: &Request) -> Option<Arc<Claims>> {
    let Some(claims) = get_claims(r) else {
        write_v1_error(w, 401, "unauthorized", "Authentication required").await;
        return None;
    };
    if claims.token_type == token_type::API_KEY {
        write_v1_error(
            w,
            403,
            "forbidden",
            "API key management is not accessible via API key authentication",
        )
        .await;
        return None;
    }
    Some(claims)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CreateBody {
    label: String,
    scopes: Option<Vec<String>>,
    user_id: Option<serde_json::Value>,
}

/// `householdManagerAs`, as key creation reads it: a child profile on the admin's account may not mint a
/// key that would skip every profile's PIN.
async fn may_create(
    s: &Stack,
    claims: &Claims,
    active: &str,
    verify: impl FnOnce(&Profile) -> bool,
) -> Result<Result<bool, Unverified>, String> {
    if claims.is_remote_playback() {
        return Ok(Ok(false));
    }
    if active.is_empty() {
        if claims.role != "admin" {
            return Ok(Ok(false));
        }
        if claims.token_type == token_type::API_KEY {
            return Ok(Ok(true));
        }
        let profiles = s.viewer.list_profiles(claims.user_id).await?;
        return Ok(Ok(!silo_gate::mw::viewer::household_requires_profile(
            &profiles,
        )));
    }
    let Some(profile) = s.viewer.get_profile(claims.user_id, active).await? else {
        return Ok(Ok(false));
    };
    if !profile.is_primary {
        return Ok(Ok(false));
    }
    if profile.pin_hash.is_empty() || verify(&profile) {
        return Ok(Ok(true));
    }
    Ok(Err(Unverified))
}

/// `access.ErrProfileUnverified`.
struct Unverified;

/// `verifyProfileTokenFor`, the v1 verifier.
fn v1_verify(s: &Stack, r: &Request, claims: &Claims, profile: &Profile) -> bool {
    if claims.session_id.is_empty() || claims.user_id == 0 {
        return false;
    }
    let token = String::from_utf8_lossy(r.header.get("X-Profile-Token")).into_owned();
    s.profile_tokens.validate(&token).is_ok_and(|t| {
        i64::from(t.user_id) == claims.user_id
            && t.session_id == claims.session_id
            && t.profile_id == profile.id
            && t.pin_revision == profile.pin_revision
    })
}

/// `Scope.CheckProfileVerification`, the v2 verifier.
fn v2_verify(r: &Request, profile: &Profile) -> bool {
    r.extensions.get::<Arc<Scope>>().is_some_and(|s| {
        s.profile_id == profile.id
            && s.profile_verified
            && !s.pin_verification_skipped
            && s.profile_pin_revision == profile.pin_revision
    })
}

/// `checkOwnerKey`, its outcome as `ownerError` words it.
async fn check_owner_key(s: &Stack, actor: i64, id: i64) -> Result<(), OwnerCheck> {
    let key = match s.api_keys.metadata_by_id(id).await {
        Ok(key) => key,
        Err(KeyError::NotFound) => return Ok(()),
        Err(_) => return Err(OwnerCheck::Store),
    };
    match check_owner_target_by_id(&s.pool, actor, key.user_id).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(refusal)) => Err(OwnerCheck::Refused(refusal.message())),
        Err(_) => Err(OwnerCheck::Store),
    }
}

enum OwnerCheck {
    Refused(&'static str),
    Store,
}

fn actor_of(r: &Request) -> i64 {
    get_claims(r).map_or(0, |c| c.user_id)
}

fn v1_id(r: &Request, name: &str) -> Option<i64> {
    r.url_param(name).parse().ok()
}

/// `adminAPIKeyTag`.
fn tag(r: &Request, id: i64, revision: i64) -> EntityTag {
    let scope = format!("admin-api-keys/{}/{}", actor_of(r), get_profile_id(r));
    render_etag(scope.as_bytes(), id.to_string().as_bytes(), revision)
}

#[derive(Serialize)]
struct V2Key {
    id: String,
    user_id: String,
    label: String,
    key_prefix: String,
    rate_tier: String,
    scopes: Vec<String>,
    created_at: Instant,
}

fn v2_key(k: &ApiKeyMetadata) -> V2Key {
    V2Key {
        id: k.id.to_string(),
        user_id: k.user_id.to_string(),
        label: k.label.clone(),
        key_prefix: k.key_prefix.clone(),
        rate_tier: k.rate_tier.clone(),
        scopes: k.scopes.clone(),
        created_at: instant(k.created_at),
    }
}

#[derive(Serialize)]
struct V2AdminItem {
    #[serde(flatten)]
    key: V2Key,
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<Instant>,
}

#[derive(Serialize)]
struct V2PersonalItem {
    #[serde(flatten)]
    key: V2Key,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<Instant>,
}

#[derive(Serialize)]
struct V2Created {
    id: String,
    user_id: String,
    label: String,
    key: String,
    rate_tier: String,
    scopes: Vec<String>,
    created_at: Instant,
}

fn v2_created(k: CreatedApiKey) -> V2Created {
    V2Created {
        id: k.id.to_string(),
        user_id: k.user_id.to_string(),
        label: k.label,
        key: k.key,
        rate_tier: k.rate_tier,
        scopes: k.scopes,
        created_at: instant(k.created_at),
    }
}

/// `apiv2.APIKeyPageKey` as Go's JSON writes it.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct PageKey {
    #[serde(rename = "CreatedAt")]
    created_at: String,
    #[serde(rename = "ID")]
    id: i64,
}

#[allow(clippy::result_large_err)]
fn after_of(
    s: &Stack,
    scope: &CursorScope,
    cursor: &str,
) -> Result<Option<(SystemTime, i64)>, Problem> {
    if cursor.is_empty() {
        return Ok(None);
    }
    let invalid = || Problem::new(problem_type("invalid_cursor"), "Invalid API key cursor.");
    let key: PageKey = s.cursors.decode(scope, cursor)?;
    let at = silo_gocompat::time::parse(silo_gocompat::time::RFC3339_NANO, &key.created_at)
        .map_err(|_| invalid())?;
    if key.id <= 0 || at.is_zero() {
        return Err(invalid());
    }
    Ok(Some((at.to_system_time(), key.id)))
}

fn query_param(r: &Request, name: &str) -> String {
    let (values, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    values
        .get(name)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
}

fn limit_of(r: &Request) -> i64 {
    query_param(r, "limit").parse().unwrap_or(50)
}

/// `adminAPIKeyProblem`.
fn key_problem(r: &Request, e: KeyError) -> Problem {
    match e {
        KeyError::Conflict(current) => Problem::new(
            problem_type("precondition_failed"),
            "The API key changed; reload before saving.",
        )
        .with_header("ETag", tag(r, current.id, current.revision).to_wire()),
        KeyError::NotFound => Problem::new(problem_type("not_found"), "API key not found."),
        KeyError::InvalidTier => Problem::new(
            problem_type("validation_failed"),
            "Invalid API key configuration.",
        ),
        KeyError::Owner(refusal) => service_problem(&super::auth::ApiError {
            status: 403,
            code: "owner_protected",
            message: refusal.message().to_owned(),
            retry_after: 0,
            field: "",
        }),
        _ => Problem::new(problem_type("internal_error"), "Unable to manage API key."),
    }
}

/// `CreateAdminAPIKey`.
#[allow(clippy::result_large_err)]
fn v2_scopes(label: &str, user_id: i64, scopes: &[String]) -> Result<Vec<String>, Problem> {
    if user_id <= 0 || label.is_empty() {
        return Err(Problem::new(
            problem_type("validation_failed"),
            "Invalid API key configuration.",
        ));
    }
    normalize_api_key_scopes(scopes).map_err(|e| {
        Problem::new(
            problem_type("validation_failed"),
            "Invalid API key configuration.",
        )
        .with_errors([ProblemError {
            location: "body.scopes".to_owned(),
            code: "invalid".to_owned(),
            detail: format!("unknown api key scope {}", go_quote(&e.0)),
        }])
    })
}

fn go_quote(s: &str) -> String {
    silo_gocompat::strconv::quote(s)
}

fn raw_of(r: &Request) -> Vec<u8> {
    r.extensions
        .get::<RawBody>()
        .map(|b| b.0.clone())
        .unwrap_or_default()
}

/// `adminAPIKeyID`.
#[allow(clippy::result_large_err)]
fn v2_id(r: &Request) -> Result<i64, Problem> {
    let raw = r.url_param("id");
    let id: i64 = raw
        .parse()
        .map_err(|_| Problem::new(problem_type("validation_failed"), "Invalid API key ID."))?;
    if id <= 0 || id.to_string() != raw {
        return Err(Problem::new(
            problem_type("validation_failed"),
            "Invalid API key ID.",
        ));
    }
    Ok(id)
}

/// The header as Huma's `header:` field reads it: the first value.
fn header_text(r: &Request, name: &str) -> String {
    String::from_utf8_lossy(r.header.get(name)).into_owned()
}

/// `adminAPIKeyGuard`.
#[allow(clippy::result_large_err)]
fn guard_of(r: &Request, row: &ApiKeyMetadata) -> Result<Precondition, Problem> {
    let (if_match, if_none) = (header_text(r, "If-Match"), header_text(r, "If-None-Match"));
    if let Some(problem) =
        evaluate_guarded_preconditions(&if_match, &if_none, &tag(r, row.id, row.revision))
    {
        return Err(problem);
    }
    if silo_gocompat::strings::trim_space(&if_match) == "*" {
        return Ok(Precondition {
            revision: 0,
            any: true,
        });
    }
    Ok(Precondition {
        revision: row.revision,
        any: false,
    })
}

#[derive(Serialize)]
struct AdminCapabilities<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    available: bool,
    guarded_configuration: bool,
    scopes: &'a [ScopeView],
    rate_tiers: [&'a str; 2],
}

#[derive(Serialize)]
struct PersonalScopes {
    available: bool,
    scopes: Vec<ScopeView>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TierV1 {
    tier: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TierV2 {
    rate_tier: String,
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

/// `json.NewDecoder(r.Body).Decode`, a v1 refusal on failure.
async fn decode_v1<T: serde::de::DeserializeOwned>(
    w: &mut dyn ResponseWriter,
    bytes: &[u8],
) -> Option<T> {
    let mut stream = silo_gocompat::json::Decoder::new().stream(bytes);
    match stream.decode::<T>() {
        Ok(value) => Some(value),
        Err(_) => {
            write_v1_error(w, 400, "bad_request", "Invalid request body").await;
            None
        }
    }
}

/// Registers this domain's v1 handlers.
fn mount_v1(stack: &Arc<Stack>, api: &Mux) {
    // `r.Route("/api-keys")` in a group with its own `Use`, and `r.Route("/admin")` in the viewer group:
    // the gates run before the subrouter's own 404 and 405.
    let personal = "/api/v1/api-keys/";
    let keys = Mux::new();
    keys.use_middleware([stack.v1_group(V1_KEYS)]);
    let create = stack.v1(
        personal,
        &[],
        route!(stack, |s, w, r| {
            let Some(claims) = require_jwt(w, r).await else {
                return;
            };
            if claims.role != "admin" {
                write_v1_error(
                    w,
                    403,
                    "forbidden",
                    "Only server admins can create API keys",
                )
                .await;
                return;
            }
            let (bytes, error) = r.read_all().await;
            if error.is_some() || bytes.len() > 1 << 20 {
                write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                return;
            }
            let active = declared_profile_id(r);
            let verified = |profile: &Profile| v1_verify(&s, r, &claims, profile);
            match may_create(&s, &claims, &active, verified).await {
                Err(_) => {
                    write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to check profile permissions",
                    )
                    .await;
                    return;
                }
                Ok(Err(Unverified)) => {
                    write_v1_error(
                        w,
                        403,
                        "forbidden",
                        "Profile management requires verifying the primary profile PIN",
                    )
                    .await;
                    return;
                }
                Ok(Ok(false)) => {
                    write_v1_error(
                        w,
                        403,
                        "forbidden",
                        "Creating API keys requires the account's primary profile",
                    )
                    .await;
                    return;
                }
                Ok(Ok(true)) => {}
            }
            let Some(body) = decode_v1::<CreateBody>(w, &bytes).await else {
                return;
            };
            if body.label.is_empty() {
                write_v1_error(w, 400, "bad_request", "Label is required").await;
                return;
            }
            let scopes = match normalize_v1_api_key_scopes(&body.scopes.unwrap_or_default()) {
                Ok(scopes) => scopes,
                Err(e) => {
                    write_v1_error(w, 400, "bad_request", &e.to_string()).await;
                    return;
                }
            };
            let audit = s.audit_request(r, false);
            match s
                .api_keys
                .create(claims.user_id, &body.label, &scopes, &audit)
                .await
            {
                Ok(key) => write_v1_json(w, 201, &v1_created(key)).await,
                Err(_) => {
                    write_v1_error(w, 500, "internal_error", "Failed to create API key").await
                }
            }
        }),
    );
    keys.post("/", create);

    let list = stack.v1(
        personal,
        &[],
        route!(stack, |s, w, r| {
            let Some(claims) = require_jwt(w, r).await else {
                return;
            };
            match s.api_keys.list_by_user(claims.user_id).await {
                Ok(keys) => {
                    let items: Vec<V1ListItem> = keys.into_iter().map(v1_item).collect();
                    write_v1_json(w, 200, &items).await;
                }
                Err(_) => write_v1_error(w, 500, "internal_error", "Failed to list API keys").await,
            }
        }),
    );
    keys.get("/", list);

    let scopes = "/api/v1/api-keys/scopes";
    keys.get(
        "/scopes",
        stack.v1(
            scopes,
            &[],
            handler_fn(|w, _r| {
                Box::pin(async move {
                    write_v1_json(
                        w,
                        200,
                        &Scopes {
                            scopes: scope_views(v1_api_key_scope_catalog()),
                        },
                    )
                    .await;
                })
            }),
        ),
    );

    let one = "/api/v1/api-keys/{id}";
    keys.delete(
        "/{id}",
        stack.v1(
            one,
            &[],
            route!(stack, |s, w, r| {
                let Some(claims) = require_jwt(w, r).await else {
                    return;
                };
                let Some(id) = v1_id(r, "id") else {
                    write_v1_error(w, 400, "bad_request", "Invalid API key ID").await;
                    return;
                };
                let audit = s.audit_request(r, false);
                match s.api_keys.delete(id, claims.user_id, &audit).await {
                    Ok(()) => w.write_header(204).await,
                    Err(KeyError::NotFound) => {
                        write_v1_error(w, 404, "not_found", "API key not found").await
                    }
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to delete API key").await
                    }
                }
            }),
        ),
    );

    api.mount("/api/v1/api-keys", keys);

    let admin_mux = Mux::new();
    admin_mux.use_middleware([stack.v1_group(V1_VIEWER_GROUP)]);
    let of_user = "/api/v1/admin/users/{userId}/api-keys";
    admin_mux.get(
        "/users/{userId}/api-keys",
        stack.v1(
            of_user,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let Some(id) = r.url_param("userId").parse::<i64>().ok() else {
                    write_v1_error(w, 400, "bad_request", "Invalid user ID").await;
                    return;
                };
                match s.api_keys.list_by_user(id).await {
                    Ok(keys) => {
                        let items: Vec<V1ListItem> = keys.into_iter().map(v1_item).collect();
                        write_v1_json(w, 200, &items).await;
                    }
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to list API keys").await
                    }
                }
            }),
        ),
    );

    let admin = "/api/v1/admin/api-keys";
    admin_mux.get(
        "/api-keys",
        stack.v1(
            admin,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, _r| {
                match s.api_keys.list_all().await {
                    Ok(keys) => {
                        let items: Vec<V1AdminListItem> = keys
                            .into_iter()
                            .map(|k| {
                                let username = k.username.clone();
                                V1AdminListItem {
                                    item: v1_item(k),
                                    username,
                                }
                            })
                            .collect();
                        write_v1_json(w, 200, &items).await;
                    }
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to list API keys").await
                    }
                }
            }),
        ),
    );

    admin_mux.post(
        "/api-keys",
        stack.v1(
            admin,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let Some(claims) = get_claims(r) else {
                    write_v1_error(w, 401, "unauthorized", "Authentication required").await;
                    return;
                };
                let (bytes, _) = r.read_all().await;
                let Some(body) = decode_v1::<V1AdminCreate>(w, &bytes).await else {
                    return;
                };
                if body.label.is_empty() {
                    write_v1_error(w, 400, "bad_request", "Label is required").await;
                    return;
                }
                let scopes = match normalize_v1_api_key_scopes(&body.scopes.unwrap_or_default()) {
                    Ok(scopes) => scopes,
                    Err(e) => {
                        write_v1_error(w, 400, "bad_request", &e.to_string()).await;
                        return;
                    }
                };
                let target = body.user_id.unwrap_or(claims.user_id);
                let audit = s.audit_request(r, false);
                match s
                    .api_keys
                    .create_as_actor(claims.user_id, target, &body.label, &scopes, &audit)
                    .await
                {
                    Ok(key) => write_v1_json(w, 201, &v1_created(key)).await,
                    Err(KeyError::Owner(refusal)) => {
                        write_v1_error(w, 403, "owner_protected", refusal.message()).await;
                    }
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to create API key").await
                    }
                }
            }),
        ),
    );

    let admin_one = "/api/v1/admin/api-keys/{id}";
    admin_mux.delete(
        "/api-keys/{id}",
        stack.v1(
            admin_one,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let Some(id) = v1_id(r, "id") else {
                    write_v1_error(w, 400, "bad_request", "Invalid API key ID").await;
                    return;
                };
                match check_owner_key(&s, actor_of(r), id).await {
                    Ok(()) => {}
                    Err(OwnerCheck::Refused(message)) => {
                        write_v1_error(w, 403, "owner_protected", message).await;
                        return;
                    }
                    Err(OwnerCheck::Store) => {
                        write_v1_error(w, 500, "internal_error", "An unexpected error occurred")
                            .await;
                        return;
                    }
                }
                match s.api_keys.delete_by_admin(id).await {
                    Ok(()) => w.write_header(204).await,
                    Err(KeyError::NotFound) => {
                        write_v1_error(w, 404, "not_found", "API key not found").await
                    }
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to delete API key").await
                    }
                }
            }),
        ),
    );

    let admin_tier = "/api/v1/admin/api-keys/{id}/tier";
    admin_mux.put(
        "/api-keys/{id}/tier",
        stack.v1(
            admin_tier,
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                let Some(id) = v1_id(r, "id") else {
                    write_v1_error(w, 400, "bad_request", "Invalid API key ID").await;
                    return;
                };
                let (bytes, _) = r.read_all().await;
                let Some(body) = decode_v1::<TierV1>(w, &bytes).await else {
                    return;
                };
                if body.tier != "standard" && body.tier != "elevated" {
                    write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Tier must be 'standard' or 'elevated'",
                    )
                    .await;
                    return;
                }
                match check_owner_key(&s, actor_of(r), id).await {
                    Ok(()) => {}
                    Err(OwnerCheck::Refused(message)) => {
                        write_v1_error(w, 403, "owner_protected", message).await;
                        return;
                    }
                    Err(OwnerCheck::Store) => {
                        write_v1_error(w, 500, "internal_error", "An unexpected error occurred")
                            .await;
                        return;
                    }
                }
                match s.api_keys.update_tier(id, &body.tier).await {
                    Ok(()) => write_v1_json(w, 200, &StatusOk { status: "ok" }).await,
                    Err(KeyError::NotFound) => {
                        write_v1_error(w, 404, "not_found", "API key not found").await
                    }
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to update tier").await
                    }
                }
            }),
        ),
    );
    super::admin_settings::mount_v1(stack, &admin_mux);
    super::admin_stats::mount_v1(stack, &admin_mux);
    super::catalog::mount_v1(stack, &admin_mux);
    super::collections::mount_v1_admin(stack, &admin_mux);
    super::requests::mount_v1_admin(stack, &admin_mux);
    api.mount("/api/v1/admin", admin_mux);
}

#[derive(Serialize)]
struct StatusOk {
    status: &'static str,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct V1AdminCreate {
    label: String,
    user_id: Option<i64>,
    scopes: Option<Vec<String>>,
}

async fn personal_account(r: &Request) -> Result<i64, Problem> {
    let claims = get_claims(r).filter(|c| c.user_id > 0);
    let Some(claims) = claims else {
        return Err(Problem::new(
            problem_type("authentication_required"),
            "Authentication required.",
        ));
    };
    if claims.token_type == token_type::API_KEY {
        return Err(Problem::new(
            problem_type("permission_denied"),
            "API key management requires a login session.",
        ));
    }
    Ok(claims.user_id)
}

/// Registers this domain's v2 handlers.
fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/api-keys/scopes";
    v2.get(
        path,
        stack.v2_steps(
            path,
            V2_READ,
            handler_fn(|w, _r| {
                Box::pin(async move {
                    write_v2_json(
                        w,
                        &PersonalScopes {
                            available: true,
                            scopes: scope_views(api_key_scope_catalog()),
                        },
                    )
                    .await;
                })
            }),
        ),
    );

    let path = "/api/v2/api-keys";
    v2.get(
        path,
        stack.v2_steps(
            path,
            V2_READ,
            route!(stack, |s, w, r| {
                let user_id = match personal_account(r).await {
                    Ok(id) => id,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let limit = limit_of(r);
                let scope = CursorScope {
                    operation_id: "listPersonalAPIKeys".to_owned(),
                    security: user_id.to_string(),
                    filter: format!("limit={limit}"),
                    sort: "created_at:desc".to_owned(),
                    tiebreaker: "id:desc".to_owned(),
                };
                let after = match after_of(&s, &scope, &query_param(r, "cursor")) {
                    Ok(after) => after,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let (rows, more) = match s.api_keys.list_by_user_page(user_id, after, limit).await {
                    Ok(page) => page,
                    Err(e) => return write_problem(w, r, key_problem(r, e)).await,
                };
                let mut next = String::new();
                if more && let Some(last) = rows.last() {
                    let key = PageKey {
                        created_at: go_time(last.created_at),
                        id: last.id,
                    };
                    next = match s.cursors.encode(&scope, &key) {
                        Ok(next) => next,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                }
                let items: Vec<V2PersonalItem> = rows
                    .iter()
                    .map(|k| V2PersonalItem {
                        key: v2_key(k),
                        last_used_at: k.last_used_at.map(instant),
                    })
                    .collect();
                write_v2_json(w, &paginated(items, next)).await;
            }),
        ),
    );

    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_CREATE,
            route!(stack, |s, w, r| {
                let user_id = match personal_account(r).await {
                    Ok(id) => id,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let Some(claims) = get_claims(r) else {
                    return;
                };
                if claims.role != "admin" {
                    return write_problem(
                        w,
                        r,
                        Problem::new(
                            problem_type("permission_denied"),
                            "Only server admins can create API keys.",
                        ),
                    )
                    .await;
                }
                let raw = raw_of(r);
                if let Some(problem) = reject_nulls(&raw) {
                    return write_problem(w, r, problem).await;
                }
                let verified = |profile: &Profile| v2_verify(r, profile);
                match may_create(&s, &claims, &get_profile_id(r), verified).await {
                    Err(_) => {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                problem_type("internal_error"),
                                "An unexpected error occurred.",
                            ),
                        )
                        .await;
                    }
                    Ok(Err(Unverified)) => {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                problem_type("profile_verification_required"),
                                "Creating API keys requires verifying the primary profile PIN.",
                            ),
                        )
                        .await;
                    }
                    Ok(Ok(false)) => {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                problem_type("permission_denied"),
                                "Creating API keys requires the account's primary profile.",
                            ),
                        )
                        .await;
                    }
                    Ok(Ok(true)) => {}
                }
                let body: CreateBody = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                let scopes = match v2_scopes(&body.label, user_id, &body.scopes.unwrap_or_default())
                {
                    Ok(scopes) => scopes,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let audit = s.audit_request(r, true);
                match s
                    .api_keys
                    .create_as_actor(user_id, user_id, &body.label, &scopes, &audit)
                    .await
                {
                    Ok(key) => write_v2_json_status(w, 201, &v2_created(key)).await,
                    Err(e) => write_problem(w, r, key_problem(r, e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/api-keys/{id}";
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let user_id = match personal_account(r).await {
                    Ok(id) => id,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let id = match v2_id(r) {
                    Ok(id) => id,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let audit = s.audit_request(r, true);
                match s.api_keys.delete(id, user_id, &audit).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, key_problem(r, e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/admin/api-keys/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    let scopes = scope_views(api_key_scope_catalog());
                    write_capability(w, r, "getAdminAPIKeyCapabilities", |revision| {
                        capability_json(&AdminCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                            guarded_configuration: true,
                            scopes: &scopes,
                            rate_tiers: ["standard", "elevated"],
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    let path = "/api/v2/admin/api-keys";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let limit = limit_of(r);
                let scope = CursorScope {
                    operation_id: "listAdminAPIKeys".to_owned(),
                    security: format!("{}/{}", actor_of(r), get_profile_id(r)),
                    filter: format!("v1/limit={limit}"),
                    sort: "created_at:desc".to_owned(),
                    tiebreaker: "id:desc".to_owned(),
                };
                let after = match after_of(&s, &scope, &query_param(r, "cursor")) {
                    Ok(after) => after,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let (rows, more) = match s.api_keys.list_all_page(after, limit).await {
                    Ok(page) => page,
                    Err(e) => return write_problem(w, r, key_problem(r, e)).await,
                };
                write_admin_page(&s, w, r, &scope, rows, more).await;
            }),
        ),
    );

    let path = "/api/v2/admin/users/{id}/api-keys";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let raw = r.url_param("id").to_owned();
                let user_id: i64 = raw.parse().unwrap_or(0);
                if user_id <= 0 || user_id.to_string() != raw {
                    return write_problem(
                        w,
                        r,
                        Problem::new(
                            problem_type("validation_failed"),
                            "Expected a positive account identifier.",
                        ),
                    )
                    .await;
                }
                // `GetAdminAccount` reads an ID no row can hold as a missing account.
                if i32::try_from(user_id).is_err() {
                    return write_problem(
                        w,
                        r,
                        Problem::new(problem_type("not_found"), "Account not found."),
                    )
                    .await;
                }
                let limit = limit_of(r);
                let scope = CursorScope {
                    operation_id: "listAdminUserAPIKeys".to_owned(),
                    security: format!("{}/{}", actor_of(r), get_profile_id(r)),
                    filter: format!("{user_id}/{limit}"),
                    sort: "-created_at,-id".to_owned(),
                    tiebreaker: "id".to_owned(),
                };
                let after = match after_of(&s, &scope, &query_param(r, "cursor")) {
                    Ok(after) => after,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let (rows, more) = match s.api_keys.list_by_user_page(user_id, after, limit).await {
                    Ok(page) => page,
                    Err(e) => return write_problem(w, r, key_problem(r, e)).await,
                };
                write_admin_page(&s, w, r, &scope, rows, more).await;
            }),
        ),
    );

    let path = "/api/v2/admin/api-keys";
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let raw = raw_of(r);
                if let Some(problem) = reject_nulls(&raw) {
                    return write_problem(w, r, problem).await;
                }
                let body: CreateBody = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                let mut user_id = actor_of(r);
                if let Some(value) = body.user_id.as_ref().and_then(|v| v.as_str()) {
                    let parsed: i64 = value.parse().unwrap_or(0);
                    if parsed <= 0 || parsed.to_string() != value {
                        return write_problem(
                            w,
                            r,
                            Problem::new(problem_type("validation_failed"), "Invalid account ID."),
                        )
                        .await;
                    }
                    user_id = parsed;
                }
                let scopes = match v2_scopes(&body.label, user_id, &body.scopes.unwrap_or_default())
                {
                    Ok(scopes) => scopes,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let audit = s.audit_request(r, false);
                match s
                    .api_keys
                    .create_as_actor(actor_of(r), user_id, &body.label, &scopes, &audit)
                    .await
                {
                    Ok(key) => {
                        w.header()
                            .set("Location", format!("/api/v2/admin/api-keys/{}", key.id));
                        write_v2_json_status(w, 201, &v2_created(key)).await;
                    }
                    Err(e) => write_problem(w, r, key_problem(r, e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/admin/api-keys/{id}";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let id = match v2_id(r) {
                    Ok(id) => id,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let row = match s.api_keys.metadata_by_id(id).await {
                    Ok(row) => row,
                    Err(e) => return write_problem(w, r, key_problem(r, e)).await,
                };
                let current = tag(r, row.id, row.revision);
                let (matched, problem) = evaluate_read_preconditions(
                    &header_text(r, "If-Match"),
                    &header_text(r, "If-None-Match"),
                    &current,
                );
                if let Some(problem) = problem {
                    return write_problem(w, r, problem).await;
                }
                let h = w.header();
                h.set("Content-Encoding", "identity");
                h.set("ETag", current.to_wire());
                if matched {
                    w.write_header(304).await;
                    return;
                }
                write_v2_json(w, &v2_key(&row)).await;
            }),
        ),
    );

    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let id = match v2_id(r) {
                    Ok(id) => id,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let row = match s.api_keys.metadata_by_id(id).await {
                    Ok(row) => row,
                    Err(e) => return write_problem(w, r, key_problem(r, e)).await,
                };
                let guard = match guard_of(r, &row) {
                    Ok(guard) => guard,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Err(problem) = v2_owner(&s, r, row.user_id).await {
                    return write_problem(w, r, problem).await;
                }
                let audit = s.audit_request(r, false);
                match s
                    .api_keys
                    .delete_by_admin_conditional(id, guard, &audit)
                    .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, key_problem(r, e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/admin/api-keys/{id}/tier";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let id = match v2_id(r) {
                    Ok(id) => id,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let row = match s.api_keys.metadata_by_id(id).await {
                    Ok(row) => row,
                    Err(e) => return write_problem(w, r, key_problem(r, e)).await,
                };
                let guard = match guard_of(r, &row) {
                    Ok(guard) => guard,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Err(problem) = v2_owner(&s, r, row.user_id).await {
                    return write_problem(w, r, problem).await;
                }
                let body: TierV2 = silo_gocompat::json::unmarshal(&raw_of(r)).unwrap_or_default();
                let audit = s.audit_request(r, false);
                match s
                    .api_keys
                    .update_tier_conditional(id, &body.rate_tier, guard, &audit)
                    .await
                {
                    Ok(row) => {
                        let current = tag(r, row.id, row.revision);
                        let h = w.header();
                        h.set("Content-Encoding", "identity");
                        h.set("ETag", current.to_wire());
                        write_v2_json(w, &v2_key(&row)).await;
                    }
                    Err(e) => write_problem(w, r, key_problem(r, e)).await,
                }
            }),
        ),
    );
}

/// `checkOwnerKey`, once the key is in hand.
async fn v2_owner(s: &Stack, r: &Request, user_id: i64) -> Result<(), Problem> {
    match check_owner_target_by_id(&s.pool, actor_of(r), user_id).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(refusal)) => Err(key_problem(r, KeyError::Owner(refusal))),
        Err(_) => Err(Problem::new(
            problem_type("internal_error"),
            "Unable to manage API key.",
        )),
    }
}

async fn write_admin_page(
    s: &Stack,
    w: &mut dyn ResponseWriter,
    r: &Request,
    scope: &CursorScope,
    rows: Vec<ApiKeyMetadata>,
    more: bool,
) {
    let mut next = String::new();
    if more && let Some(last) = rows.last() {
        let key = PageKey {
            created_at: go_time(last.created_at),
            id: last.id,
        };
        next = match s.cursors.encode(scope, &key) {
            Ok(next) => next,
            Err(_) => {
                return write_problem(
                    w,
                    r,
                    Problem::new(problem_type("internal_error"), "Unable to encode cursor."),
                )
                .await;
            }
        };
    }
    let items: Vec<V2AdminItem> = rows
        .iter()
        .map(|k| V2AdminItem {
            key: v2_key(k),
            username: k.username.clone(),
            last_used_at: k.last_used_at.map(instant),
        })
        .collect();
    write_v2_json(w, &paginated(items, next)).await;
}

/// Registers this domain's handlers.
pub fn mount(stack: &Arc<Stack>, api: &Mux, v2: &Mux) {
    mount_v1(stack, api);
    mount_v2(stack, v2);
}
