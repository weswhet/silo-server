//! The settings domain: `settings.go`, `settings_values*.go`, `user_settings_events.go`,
//! `device_sightings.go`, `household.go`, and v2 `settings.go`.

#![allow(clippy::too_many_arguments, clippy::large_enum_variant)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use silo_api_v2::problem::{Problem, ProblemError, validation_failed};
use silo_auth::claims::{Claims, token_type};
use silo_config::resolve::{
    self, Constraints, Context as ResolveContext, Effective, SettingIdentity,
    SettingResolutionQuery, SettingValue,
};
use silo_config::settings::{
    ClientFamily, Definition, Manifest, Scope, canonical, keys, load, mirror,
};
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gate::mw::viewer::household_requires_profile;
use silo_gocompat::json::{RawMessage, unmarshal};
use silo_gocompat::strings::trim_space;
use silo_gocompat::time::GoTime;
use silo_http::chi::Mux;
use silo_http::{Request, ResponseWriter, handler_fn};
use silo_store::access::Scope as AccessScope;
use silo_store::userstore::SettingMutationRecord;
use silo_store::userstore::pgstore::{Error as StoreError, PostgresUserStore};
use silo_store::userstore::prefs::{DeviceSettingEntry, Reader, Writer};
use silo_store::userstore::profiles::Profile;

use super::auth::{ApiError, service_problem, write_v1_error};
use super::chain::{Stack, Step, V2Class, write_problem, write_v1_json, write_v2_json};
use super::huma::RawBody;
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/overlay-config"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/effective"),
    NativeRow::new(
        ApiV1,
        "GET",
        "/api/v1/settings/subtitle_appearance/effective",
    ),
    NativeRow::new(ApiV1, "PUT", "/api/v1/settings/device/subtitle_appearance"),
    NativeRow::new(
        ApiV1,
        "DELETE",
        "/api/v1/settings/device/subtitle_appearance",
    ),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/device/{key}"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/settings/device/{key}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/settings/device/{key}"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/contract"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/contract/capabilities"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/manifest"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/capability"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/values"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/values/effective"),
    NativeRow::new(ApiV1, "POST", "/api/v1/settings/values/effective"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/settings/values/nav.shortcuts/item"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/values/{key}"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/settings/values/{key}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/settings/values/{key}"),
    NativeRow::new(ApiV1, "GET", "/api/v1/settings/{key}"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/settings/{key}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/settings/{key}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/settings/contract"),
    NativeRow::new(ApiV2, "GET", "/api/v2/settings/contract/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/settings/overlay-config"),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/settings/subtitle-appearance/effective",
    ),
    NativeRow::new(ApiV2, "PUT", "/api/v2/settings/device/subtitle-appearance"),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/settings/device/subtitle-appearance",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/settings/values"),
    NativeRow::new(ApiV2, "GET", "/api/v2/settings/values/effective"),
    NativeRow::new(ApiV2, "POST", "/api/v2/settings/values/effective"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/settings/values/nav.shortcuts/item"),
    NativeRow::new(ApiV2, "GET", "/api/v2/settings/values/{key}"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/settings/values/{key}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/settings/values/{key}"),
];

const V1_GROUP: &[Step] = &[Step::Auth, Step::Demo, Step::RateLimit, Step::Viewer];
const PROFILE: &[Step] = &[Step::Profile];
const V2_PROFILE_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::Profile,
];

const FIELD_KEY: &str = "key";
const FIELD_KEYS: &str = "keys";
const FIELD_SCOPE: &str = "scope";
const FIELD_PROFILE_ID: &str = "profile_id";
const FIELD_PROFILE_HEADER: &str = "profile_header";
const FIELD_DEVICE_ID: &str = "device_id";
const FIELD_DEVICE_HEADER: &str = "device_header";
const FIELD_CLIENT_FAMILY: &str = "client_family";
const FIELD_LIBRARY_ID: &str = "library_id";
const FIELD_SERIES_ID: &str = "series_id";
const FIELD_VALUE: &str = "value";
const FIELD_ITEM: &str = "item";
const FIELD_PRESENT: &str = "present";
const FIELD_CONTEXTS: &str = "contexts";

const MAX_EFFECTIVE_CONTENT_IDS: usize = 200;
const MAX_RESPONSE_VALUE_BYTES: i64 = 16 << 20;
const MAX_SHORTCUT_RETRIES: usize = 32;
const NAV_ATOMIC_MESSAGE: &str =
    "Use PUT /settings/values/nav.shortcuts/item to change navigation shortcuts";
const SUBTITLE_APPEARANCE: &str = "subtitle_appearance";
const LEGACY_NEXT_UP: &str = "player.next_up_prompt_seconds";
const CANONICAL_NEXT_UP: &str = "playback.next_up_prompt_seconds";
const POLICY_INPUT_MAX_QUALITY: &str = "max_playback_quality";
const INTERNAL: &str = "internal_error";

pub(super) fn api(status: u16, code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError {
        status,
        code,
        message: message.into(),
        retry_after: 0,
        field: "",
    }
}

pub(super) fn field_error(field: &'static str, message: impl Into<String>) -> ApiError {
    ApiError {
        field,
        ..api(400, "bad_request", message)
    }
}

fn coded_field(status: u16, code: &'static str, field: &'static str, message: String) -> ApiError {
    ApiError {
        field,
        ..api(status, code, message)
    }
}

/// `writeAPIError`.
pub(super) async fn write_api(w: &mut dyn ResponseWriter, e: &ApiError) {
    if e.retry_after > 0 {
        w.header().set("Retry-After", e.retry_after.to_string());
    }
    write_v1_error(w, e.status, e.code, &e.message).await;
}

pub(super) fn contract() -> &'static Manifest {
    load::must_load()
}

/// `DeviceMetadata` with `NewDeviceMetadata`'s clamps.
#[derive(Clone, Debug, Default)]
pub(super) struct Device {
    pub id: String,
    pub name: String,
    pub platform: String,
}

fn clamp(value: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(value);
    let trimmed = trim_space(&text);
    if trimmed.chars().count() <= max {
        return trimmed.to_owned();
    }
    trimmed.chars().take(max).collect()
}

/// `DeviceMetadataFromHeaders`. `MaxDeviceNameRunes` is 120.
pub(super) fn device_of(r: &Request) -> Device {
    Device {
        id: clamp(r.header.get("X-Silo-Device-Id"), 128),
        name: clamp(r.header.get("X-Silo-Device-Name"), 120),
        platform: clamp(r.header.get("X-Silo-Device-Platform"), 40),
    }
}

/// `DeviceSightings`: one per process, as in Go.
pub(super) async fn record_sighting(s: &Stack, claims: &Claims, profile_id: &str, device: &Device) {
    static SEEN: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    const THROTTLE: Duration = Duration::from_secs(300);
    let profile_id = trim_space(profile_id).to_owned();
    if profile_id.is_empty()
        || trim_space(&device.id).is_empty()
        || claims.impersonator_user_id.is_some()
    {
        return;
    }
    let key = format!("{profile_id}\0{}", device.id);
    {
        let mut seen = SEEN
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if seen.len() > 10_000 {
            seen.retain(|_, at| now.duration_since(*at) < THROTTLE);
        }
        if seen
            .get(&key)
            .is_some_and(|at| now.duration_since(*at) < THROTTLE)
        {
            return;
        }
        seen.insert(key.clone(), now);
    }
    let reader = Reader {
        pool: &s.pool,
        user_id: claims.user_id as i32,
    };
    if let Err(e) = reader
        .register_device(&profile_id, &device.id, &device.name, &device.platform)
        .await
    {
        if let Some(seen) = SEEN.get() {
            seen.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&key);
        }
        tracing::warn!(component = "api", profile_id, device_id = device.id, error = %e, "failed to register request device");
    }
}

#[derive(Serialize)]
struct UserSettingsPayload<'a> {
    key: &'a str,
    scope: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    profile_id: &'a str,
}

#[derive(Serialize)]
struct Envelope<'a> {
    channel: &'a str,
    event: &'a str,
    event_id: String,
    timestamp: String,
    source_id: String,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    data: RawMessage,
    #[serde(skip_serializing_if = "is_zero")]
    user_id: i64,
    #[serde(skip_serializing_if = "str::is_empty")]
    profile_id: &'a str,
    #[serde(skip_serializing_if = "is_false")]
    admin_only: bool,
    #[serde(skip_serializing_if = "is_false")]
    all_viewers: bool,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}

/// A ULID: 48 bits of milliseconds and 80 of randomness, in Crockford base 32.
fn ulid() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let random = u128::from_be_bytes(*uuid::Uuid::new_v4().as_bytes()) >> 48;
    let mut value = (millis << 80) | random;
    let mut out = [0u8; 26];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `Hub.Publish` for an envelope with no local subscriber here: Go's hubs take it from `silo:events`.
pub(super) async fn publish_envelope(
    s: &Stack,
    channel: &str,
    event: &str,
    data: Vec<u8>,
    user_id: i64,
    profile_id: &str,
    admin_only: bool,
    all_viewers: bool,
) {
    let Some(bus) = &s.bus else {
        return;
    };
    let envelope = Envelope {
        channel,
        event,
        event_id: ulid(),
        timestamp: GoTime::now_utc().rfc3339_nano(),
        source_id: super::chain::hub_source(&s.node_id),
        data: data.into(),
        user_id,
        profile_id,
        admin_only,
        all_viewers,
    };
    let payload = match silo_gocompat::json::marshal_to_string(&envelope) {
        Ok(payload) => payload,
        Err(_) => return,
    };
    let event = silo_core::redis::Event {
        event_type: "events_notification".to_owned(),
        payload,
    };
    if let Err(e) = bus.publish("silo:events", event).await {
        tracing::warn!(component = "api", error = %e, "publishing event failed");
    }
}

/// `publishUserSettingsEvent`.
pub(super) async fn publish_user_settings(
    s: &Stack,
    user_id: i64,
    profile_id: &str,
    key: &str,
    scope: &str,
) {
    if user_id == 0 || key.is_empty() || scope.is_empty() {
        return;
    }
    let data = silo_gocompat::json::marshal(&UserSettingsPayload {
        key,
        scope,
        profile_id,
    })
    .unwrap_or_default();
    publish_envelope(
        s,
        "user_settings",
        "user_settings.changed",
        data,
        user_id,
        profile_id,
        false,
        false,
    )
    .await;
}

/// `Worker.NotifySignalsChanged`, the part any server does: the stale sweep picks the mark up. Go's
/// refresh queue is per process, and the sweep is what covers a refresh queued on another server.
pub(super) async fn mark_profile_stale(s: &Stack, user_id: i64, profile_id: &str) {
    if user_id <= 0 || profile_id.is_empty() {
        return;
    }
    let user_id = user_id as i32;
    if let Err(e) = s
        .pool
        .execute(
            "INSERT INTO user_taste_profiles (user_id, profile_id, embedding, updated_at, stale_at)
             VALUES ($1, $2, NULL, to_timestamp(0), NOW())
             ON CONFLICT (user_id, profile_id) DO UPDATE SET stale_at = NOW()",
            &[&user_id, &profile_id],
        )
        .await
    {
        tracing::warn!(component = "recommendations", user_id, profile_id, error = %e, "marking taste profile stale failed");
    }
}

/// `notifyScopeSettingChanged`.
async fn notify_scope_setting(s: &Stack, user_id: i64, profile_id: &str, key: &str) {
    if key == keys::UI_DISABLED_LIBRARY_IDS && !profile_id.is_empty() {
        mark_profile_stale(s, user_id, profile_id).await;
    }
}

/// `access.ErrProfileUnverified`, as a decision from a [`Verifier`].
#[derive(Debug)]
pub(super) enum HouseholdError {
    Unverified,
    Other,
}

/// The check a PIN-locked primary profile must pass: `verifyProfileTokenFor` on v1, and
/// `Scope.CheckProfileVerification` on v2.
#[derive(Clone)]
pub(super) enum Verifier {
    Token {
        user_id: i64,
        session_id: String,
        claims: Option<silo_store::access::ProfileTokenClaims>,
    },
    Scope(Option<Arc<AccessScope>>),
}

impl Verifier {
    pub fn v1(s: &Stack, r: &Request, claims: &Claims) -> Self {
        let token = String::from_utf8_lossy(r.header.get("X-Profile-Token")).into_owned();
        Verifier::Token {
            user_id: claims.user_id,
            session_id: claims.session_id.clone(),
            claims: s.profile_tokens.validate(&token).ok(),
        }
    }

    pub fn v2(r: &Request) -> Self {
        Verifier::Scope(r.extensions.get::<Arc<AccessScope>>().cloned())
    }

    fn check(&self, profile: &Profile) -> bool {
        match self {
            Verifier::Token {
                user_id,
                session_id,
                claims,
            } => {
                if session_id.is_empty() || *user_id == 0 {
                    return false;
                }
                claims.as_ref().is_some_and(|t| {
                    i64::from(t.user_id) == *user_id
                        && t.session_id == *session_id
                        && t.profile_id == profile.id
                        && t.pin_revision == profile.pin_revision
                })
            }
            Verifier::Scope(scope) => scope.as_ref().is_some_and(|s| {
                s.profile_id == profile.id
                    && s.profile_verified
                    && !s.pin_verification_skipped
                    && s.profile_pin_revision == profile.pin_revision
            }),
        }
    }
}

/// `householdManagerAs`: whether the caller manages the household, and the authorized acting row.
pub(super) async fn household_manager(
    s: &Stack,
    claims: &Claims,
    user_id: i64,
    active: &str,
    verify: &Verifier,
) -> Result<(bool, Option<Profile>), HouseholdError> {
    if claims.is_remote_playback() {
        return Ok((false, None));
    }
    if active.is_empty() {
        if claims.role != "admin" {
            return Ok((false, None));
        }
        if claims.token_type == token_type::API_KEY {
            return Ok((true, None));
        }
        let profiles = s
            .viewer
            .list_profiles(user_id)
            .await
            .map_err(|_| HouseholdError::Other)?;
        return Ok((!household_requires_profile(&profiles), None));
    }
    let Some(profile) = s
        .viewer
        .get_profile(user_id, active)
        .await
        .map_err(|_| HouseholdError::Other)?
    else {
        return Ok((false, None));
    };
    if !profile.is_primary {
        return Ok((false, None));
    }
    if profile.pin_hash.is_empty() || verify.check(&profile) {
        return Ok((true, Some(profile)));
    }
    Err(HouseholdError::Unverified)
}

fn definition(key: &str) -> Result<&'static Definition, ApiError> {
    let Some(def) = contract().lookup(key) else {
        return Err(coded_field(
            404,
            "unknown_setting",
            FIELD_KEY,
            format!("No setting named {key} exists in this server's contract"),
        ));
    };
    if !def.is_remote() {
        return Err(coded_field(
            400,
            "client_local_setting",
            FIELD_KEY,
            format!("{key} is a device-local setting and is never stored by the server"),
        ));
    }
    Ok(def)
}

pub(super) fn keyed_scope(
    requested_key: &str,
    requested_scope: &str,
) -> Result<(String, Scope), ApiError> {
    let key = trim_space(requested_key);
    if key.is_empty() {
        return Err(field_error(FIELD_KEY, "A setting key is required"));
    }
    definition(key)?;
    let scope = trim_space(requested_scope);
    if scope.is_empty() {
        return Err(field_error(
            FIELD_SCOPE,
            "A scope is required: account, profile, profile_client, profile_device, profile_library or profile_series",
        ));
    }
    Ok((key.to_owned(), Scope::new(scope)))
}

/// `SettingIdentityRequest`.
struct IdentityRequest {
    key: String,
    scope: String,
    active_profile: String,
    profile_id: String,
    device_id: String,
    device: Device,
    client_family: String,
    library_id: String,
    series_id: String,
    verify: Verifier,
}

pub(super) fn query_of(r: &Request) -> std::collections::BTreeMap<String, Vec<String>> {
    silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query)).0
}

pub(super) fn q1(query: &std::collections::BTreeMap<String, Vec<String>>, name: &str) -> String {
    query
        .get(name)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
}

fn identity_request(r: &Request, key: &str, verify: Verifier) -> IdentityRequest {
    let query = query_of(r);
    IdentityRequest {
        key: key.to_owned(),
        scope: q1(&query, "scope"),
        active_profile: get_profile_id(r),
        profile_id: q1(&query, "profile_id"),
        device_id: q1(&query, "device_id"),
        device: device_of(r),
        client_family: String::from_utf8_lossy(r.header.get("X-Silo-Client-Family")).into_owned(),
        library_id: q1(&query, "library_id"),
        series_id: q1(&query, "series_id"),
        verify,
    }
}

async fn may_act_for(
    s: &Stack,
    claims: &Claims,
    user_id: i64,
    active: &str,
    verify: &Verifier,
    profile_id: &str,
) -> Result<(), ApiError> {
    match household_manager(s, claims, user_id, active, verify).await {
        Err(HouseholdError::Unverified) => {
            return Err(api(
                403,
                "forbidden",
                "Profile management requires verifying the primary profile PIN",
            ));
        }
        Err(HouseholdError::Other) => {
            return Err(api(500, INTERNAL, "Failed to check profile permissions"));
        }
        Ok((false, _)) => {
            return Err(api(
                403,
                "forbidden",
                "Managing another profile's settings requires the primary profile or admin access",
            ));
        }
        Ok((true, _)) => {}
    }
    match s.viewer.get_profile(user_id, profile_id).await {
        Err(_) => Err(api(500, INTERNAL, "Failed to load profile")),
        Ok(None) => Err(coded_field(
            404,
            "not_found",
            FIELD_PROFILE_ID,
            "Profile not found".to_owned(),
        )),
        Ok(Some(_)) => Ok(()),
    }
}

async fn device_belongs(
    s: &Stack,
    user_id: i64,
    profile: &str,
    device: &str,
) -> Result<(), ApiError> {
    let reader = Reader {
        pool: &s.pool,
        user_id: user_id as i32,
    };
    match reader.device_exists(profile, device).await {
        Err(_) => Err(api(500, INTERNAL, "Failed to look up device")),
        Ok(false) => Err(coded_field(
            404,
            "not_found",
            FIELD_DEVICE_ID,
            "Device not found".to_owned(),
        )),
        Ok(true) => Ok(()),
    }
}

/// `strconv.Atoi` of a Go `int`.
fn atoi(value: &str) -> Option<i64> {
    let (sign, digits) = match value.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, value.strip_prefix('+').unwrap_or(value)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i64>().ok().map(|n| n * sign)
}

async fn library_exists(s: &Stack, id: i64) -> Result<(), ApiError> {
    match s
        .pool
        .query("SELECT 1 FROM media_folders WHERE id = $1::bigint", &[&id])
        .await
    {
        Err(_) => Err(api(500, INTERNAL, "Failed to look up library")),
        Ok(rows) if rows.is_empty() => Err(coded_field(
            404,
            "not_found",
            FIELD_LIBRARY_ID,
            "Library not found".to_owned(),
        )),
        Ok(_) => Ok(()),
    }
}

/// `completeIdentityFor`.
pub(super) async fn complete_identity(
    s: &Stack,
    library_id: &str,
    series_id: &str,
    mut identity: SettingIdentity,
) -> Result<SettingIdentity, ApiError> {
    if identity.scope == Scope::PROFILE_LIBRARY {
        let id = atoi(trim_space(library_id))
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                field_error(
                    FIELD_LIBRARY_ID,
                    "library_id is required for a library override",
                )
            })?;
        identity.library_id = id;
        library_exists(s, id).await?;
    }
    if identity.scope == Scope::PROFILE_SERIES {
        identity.series_id = trim_space(series_id).to_owned();
        if identity.series_id.is_empty() {
            return Err(field_error(
                FIELD_SERIES_ID,
                "series_id is required for a series override",
            ));
        }
    }
    if let Err(e) = silo_store::userstore::validate_identity(&identity) {
        return Err(field_error(FIELD_SCOPE, e.to_string()));
    }
    let def = contract().lookup(&identity.key);
    if !def.is_some_and(|d| d.allows_scope(&identity.scope)) {
        return Err(coded_field(
            400,
            "scope_not_allowed",
            FIELD_SCOPE,
            format!("{} cannot be set at {}", identity.key, identity.scope),
        ));
    }
    Ok(identity)
}

/// `sessionIdentity`.
async fn session_identity(
    s: &Stack,
    claims: &Claims,
    req: &IdentityRequest,
) -> Result<SettingIdentity, ApiError> {
    let (key, scope) = keyed_scope(&req.key, &req.scope)?;
    let mut identity = SettingIdentity {
        key,
        scope: scope.clone(),
        ..SettingIdentity::default()
    };
    if scope != Scope::ACCOUNT {
        identity.profile_id = trim_space(&req.active_profile).to_owned();
        if identity.profile_id.is_empty() {
            return Err(field_error(
                FIELD_PROFILE_HEADER,
                "X-Profile-Id header is required for this scope",
            ));
        }
        let named = trim_space(&req.profile_id);
        if !named.is_empty() && named != identity.profile_id {
            may_act_for(
                s,
                claims,
                claims.user_id,
                &identity.profile_id,
                &req.verify,
                named,
            )
            .await?;
            identity.profile_id = named.to_owned();
        }
    }
    if scope == Scope::PROFILE_CLIENT {
        let family = ClientFamily::new(trim_space(&req.client_family));
        if !family.valid() {
            return Err(field_error(
                FIELD_CLIENT_FAMILY,
                "X-Silo-Client-Family header must be one of tv, mobile, tablet, desktop or web",
            ));
        }
        identity.client_family = family;
    }
    if scope == Scope::PROFILE_DEVICE {
        let named = trim_space(&req.device_id).to_owned();
        identity.device_id = named.clone();
        if identity.device_id.is_empty() {
            identity.device_id = req.device.id.clone();
        }
        if identity.device_id.is_empty() {
            return Err(field_error(
                FIELD_DEVICE_HEADER,
                "X-Silo-Device-Id header is required for a device override",
            ));
        }
        if !named.is_empty() {
            device_belongs(s, claims.user_id, &identity.profile_id, &named).await?;
        }
    }
    complete_identity(s, &req.library_id, &req.series_id, identity).await
}

/// `settingValueResponse`.
#[derive(Clone, Debug, Serialize)]
pub(super) struct ValueView {
    key: String,
    scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "is_zero")]
    library_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_id: String,
    value: RawMessage,
    revision: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    updated_at: String,
}

pub(super) fn value_view(v: &SettingValue) -> ValueView {
    ValueView {
        key: v.identity.key.clone(),
        scope: v.identity.scope.as_str().to_owned(),
        profile_id: v.identity.profile_id.clone(),
        client_family: v.identity.client_family.as_str().to_owned(),
        device_id: v.identity.device_id.clone(),
        library_id: v.identity.library_id,
        series_id: v.identity.series_id.clone(),
        value: v.value.clone().into(),
        revision: v.revision,
        updated_at: v.updated_at.clone(),
    }
}

/// `explicitSettingValueResponse`.
#[derive(Serialize)]
struct ExplicitView {
    key: String,
    scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "is_zero")]
    library_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_id: String,
    is_set: bool,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    value: RawMessage,
    #[serde(skip_serializing_if = "is_zero")]
    revision: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    updated_at: String,
}

/// `effectiveSourceContextResponse`.
#[derive(Clone, Serialize)]
struct SourceContext {
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "is_zero")]
    library_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_id: String,
}

/// `effectiveSettingValueResponse`.
#[derive(Clone, Serialize)]
struct EffectiveView {
    key: String,
    value: RawMessage,
    source: String,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    stored_value: RawMessage,
    #[serde(skip_serializing_if = "is_false")]
    constrained: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    constraint_kind: String,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    requested_value: RawMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    constrained_by: Option<silo_config::settings::Constraint>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    permitted_values: Vec<RawMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    suggested_values: Vec<String>,
    definition_revision: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_context: Option<SourceContext>,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "is_zero")]
    library_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_id: String,
}

fn effective_view(eff: &Effective) -> EffectiveView {
    let mut out = EffectiveView {
        key: eff.key.clone(),
        value: eff.value.clone(),
        source: eff.source.as_str().to_owned(),
        stored_value: eff.stored_value.clone(),
        constrained: eff.constrained,
        constraint_kind: eff.constraint_kind.as_str().to_owned(),
        requested_value: eff.requested_value.clone(),
        constrained_by: eff.constrained_by.clone(),
        permitted_values: eff.permitted_values.clone(),
        suggested_values: Vec::new(),
        definition_revision: eff.definition_revision,
        updated_at: eff.updated_at.clone(),
        source_context: None,
        scope: String::new(),
        profile_id: String::new(),
        client_family: String::new(),
        device_id: String::new(),
        library_id: 0,
        series_id: String::new(),
    };
    if let Some(identity) = &eff.identity {
        out.scope = identity.scope.as_str().to_owned();
        out.profile_id = identity.profile_id.clone();
        out.client_family = identity.client_family.as_str().to_owned();
        out.device_id = identity.device_id.clone();
        out.library_id = identity.library_id;
        out.series_id = identity.series_id.clone();
        out.source_context = Some(SourceContext {
            profile_id: identity.profile_id.clone(),
            client_family: identity.client_family.as_str().to_owned(),
            device_id: identity.device_id.clone(),
            library_id: identity.library_id,
            series_id: identity.series_id.clone(),
        });
    }
    out
}

/// `mergeLanguageSuggestions`.
fn merge_suggestions(floor: &[String], observed: &[String], current: &[u8]) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut add = |value: &str, replace: bool, values: &mut Vec<String>| {
        let Some(normalized) = silo_config::settings::normalize_language_tag(value) else {
            return;
        };
        let identity =
            silo_config::lang::language_parse(&normalized).unwrap_or_else(|| normalized.clone());
        if let Some(&at) = index.get(&identity) {
            if replace {
                values[at] = normalized;
            }
            return;
        }
        index.insert(identity, values.len());
        values.push(normalized);
    };
    for value in floor {
        add(value, false, &mut values);
    }
    for value in observed {
        add(value, false, &mut values);
    }
    if let Ok(text) = unmarshal::<String>(current) {
        add(&text, true, &mut values);
    }
    values
}

/// `ListOriginalLanguages`, with the three filters `observedLanguageSuggestions` sets.
async fn observed_languages(s: &Stack, scope: Option<&AccessScope>) -> Result<Vec<String>, String> {
    let mut conditions: Vec<String> = Vec::new();
    let mut args: Vec<Box<dyn silo_pg::ToSql + Sync + Send>> = Vec::new();
    let mut disabled: Vec<i64> = Vec::new();
    let mut positive = false;
    if let Some(scope) = scope {
        // `AllowedLibraryIDs` is nil when unrestricted, and an empty list then lists nothing.
        if scope.libraries_restricted {
            if scope.allowed_library_ids.is_empty() {
                return Ok(Vec::new());
            }
            args.push(Box::new(scope.allowed_library_ids.clone()));
            conditions.push(format!(
                "EXISTS (SELECT 1 FROM media_item_libraries mil_scope_in WHERE mil_scope_in.content_id = mi.content_id AND mil_scope_in.media_folder_id = ANY(${}::bigint[]))",
                args.len()
            ));
            positive = true;
        }
        disabled = scope.disabled_library_ids.clone();
    }
    if !positive {
        conditions.push(
            "EXISTS (SELECT 1 FROM media_item_libraries mil_scope_any WHERE mil_scope_any.content_id = mi.content_id)"
                .to_owned(),
        );
    }
    if !disabled.is_empty() {
        args.push(Box::new(disabled));
        conditions.push(format!(
            "NOT EXISTS (SELECT 1 FROM media_item_libraries mil_scope_out WHERE mil_scope_out.content_id = mi.content_id AND mil_scope_out.media_folder_id = ANY(${}::bigint[]))",
            args.len()
        ));
    }
    if let Some(scope) = scope {
        let limits = &scope.maturity_limits;
        if silo_store::rating::has_ceiling(&limits.max_content_rating) {
            let Some(age) = silo_store::rating::age_for_ceiling(&limits.max_content_rating) else {
                conditions.push("1 = 0".to_owned());
                return run_observed(s, conditions, args).await;
            };
            args.push(Box::new(age));
            let at = args.len();
            conditions.push(if limits.allow_unrated_content {
                format!("(mi.content_rating_age IS NULL OR mi.content_rating_age <= ${at}::int)")
            } else {
                format!(
                    "(mi.content_rating_age IS NOT NULL AND mi.content_rating_age <= ${at}::int)"
                )
            });
        }
        if limits.max_advisory_age > 0 {
            args.push(Box::new(limits.max_advisory_age));
            let at = args.len();
            conditions.push(if limits.require_advisory_age {
                format!("(mi.advisory_age IS NOT NULL AND mi.advisory_age <= ${at}::int)")
            } else {
                format!("(mi.advisory_age IS NULL OR mi.advisory_age <= ${at}::int)")
            });
        }
    }
    run_observed(s, conditions, args).await
}

async fn run_observed(
    s: &Stack,
    conditions: Vec<String>,
    args: Vec<Box<dyn silo_pg::ToSql + Sync + Send>>,
) -> Result<Vec<String>, String> {
    let sql = format!(
        "SELECT DISTINCT mi.original_language FROM media_items mi WHERE {} AND mi.original_language <> '' ORDER BY mi.original_language ASC LIMIT 1000",
        conditions.join(" AND ")
    );
    let params: Vec<&(dyn silo_pg::ToSql + Sync)> = args
        .iter()
        .map(|b| b.as_ref() as &(dyn silo_pg::ToSql + Sync))
        .collect();
    let rows = s
        .pool
        .query(&sql, &params)
        .await
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in &rows {
        let value: String = row.try_get(0).map_err(|e| e.to_string())?;
        let value = trim_space(&value).to_owned();
        if !value.is_empty() {
            out.push(value);
        }
    }
    Ok(out)
}

async fn observed_for(s: &Stack, r: &Request, resolved: &[Effective]) -> Vec<String> {
    if !resolved
        .iter()
        .any(|e| e.key == keys::CATALOG_METADATA_LANGUAGE)
    {
        return Vec::new();
    }
    let scope = r.extensions.get::<Arc<AccessScope>>().cloned();
    match observed_languages(s, scope.as_deref()).await {
        Ok(values) => values,
        Err(e) => {
            tracing::warn!(component = "settings", error = %e, "settings: listing metadata language suggestions");
            Vec::new()
        }
    }
}

fn responses_with(resolved: &[Effective], observed: &[String]) -> Vec<EffectiveView> {
    let manifest = contract();
    resolved
        .iter()
        .map(|eff| {
            let mut view = effective_view(eff);
            if let Some(def) = manifest.lookup(&eff.key)
                && !def.suggested_options.is_empty()
            {
                let floor: Vec<String> = manifest
                    .option_sets
                    .get(&def.suggested_options)
                    .map(|set| {
                        set.options_at_revision(manifest.revision)
                            .into_iter()
                            .map(|o| o.value)
                            .collect()
                    })
                    .unwrap_or_default();
                let observed: &[String] = if eff.key == keys::CATALOG_METADATA_LANGUAGE {
                    observed
                } else {
                    &[]
                };
                view.suggested_values =
                    merge_suggestions(&floor, observed, eff.value.as_bytes().unwrap_or_default());
            }
            view
        })
        .collect()
}

fn constraints_for(r: &Request) -> Constraints {
    let mut out = Constraints::new();
    if let Some(scope) = r.extensions.get::<Arc<AccessScope>>() {
        let quality = trim_space(&scope.max_playback_quality);
        if !quality.is_empty()
            && let Ok(limit) = silo_gocompat::json::marshal(quality)
        {
            out.insert(POLICY_INPUT_MAX_QUALITY.to_owned(), limit);
        }
    }
    out
}

pub(super) fn resolver_for(s: &Stack) -> resolve::Resolver {
    let resolver = resolve::Resolver::new(contract());
    match &s.admin_defaults {
        Some(defaults) => resolver.with_admin_defaults(defaults.clone()),
        None => resolver,
    }
}

fn store_for(s: &Stack, user_id: i64) -> PostgresUserStore {
    PostgresUserStore::new(s.pool.clone(), user_id as i32)
}

/// `hashMutationRequest`.
fn hash_mutation(identity: &SettingIdentity, value: &[u8]) -> String {
    let mut sum = Sha256::new();
    sum.update(identity.key.as_bytes());
    sum.update([0]);
    sum.update(identity.scope.as_str().as_bytes());
    sum.update([0]);
    sum.update(identity.profile_id.as_bytes());
    sum.update([0]);
    sum.update(identity.device_id.as_bytes());
    sum.update([0]);
    sum.update(identity.library_id.to_string().as_bytes());
    sum.update([0]);
    sum.update(identity.series_id.as_bytes());
    sum.update([0]);
    sum.update(value);
    if !identity.client_family.as_str().is_empty() {
        sum.update([0]);
        sum.update(identity.client_family.as_str().as_bytes());
    }
    sum.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// `settingMutationResult`.
pub(super) struct MutationResult {
    view: Option<ValueView>,
    raw: Option<Vec<u8>>,
    replay: bool,
}

impl MutationResult {
    pub(super) fn into_view(self) -> Option<ValueView> {
        self.view
    }
}

enum Outcome {
    Replay(Vec<u8>),
    Done(SettingValue, Option<Vec<u8>>),
}

fn store_failed(key: &str, scope: &str, e: &StoreError) -> ApiError {
    match e {
        StoreError::Invalid(inner) => field_error(FIELD_VALUE, inner.to_string()),
        other => {
            tracing::error!(component = "api", key, scope, error = %other, "failed to store a canonical setting");
            api(500, INTERNAL, "Failed to store the setting")
        }
    }
}

const MUTATION_CONFLICT: &str = "This mutation id was used for a different write";

/// `legacyIntroSkipColumnWrite`.
fn intro_skip_column_write(
    key: &str,
    normalized: &[u8],
    mirror: Option<&mirror::MirroredWrite>,
) -> Option<Vec<u8>> {
    let mirror = mirror?;
    match key {
        keys::PLAYBACK_AUTO_SKIP_INTRO => Some(normalized.to_vec()),
        keys::PLAYBACK_INTRO_SKIP_MODE => Some(mirror.value.clone()),
        _ => None,
    }
}

/// `legacyIntroSkipColumnCleared`.
fn intro_skip_column_cleared(key: &str) -> Option<Vec<u8>> {
    if key != keys::PLAYBACK_AUTO_SKIP_INTRO && key != keys::PLAYBACK_INTRO_SKIP_MODE {
        return None;
    }
    let def = contract().lookup(keys::PLAYBACK_AUTO_SKIP_INTRO)?;
    if def.default_value.is_empty() {
        return None;
    }
    Some(def.default_value.clone())
}

/// `writeLegacyIntroSkipColumn`.
async fn write_intro_skip_column(
    writer: &mut Writer<'_>,
    identity: &SettingIdentity,
    value: Option<&[u8]>,
) -> Result<(), StoreError> {
    let Some(value) = value else {
        return Ok(());
    };
    if identity.scope != Scope::PROFILE {
        return Ok(());
    }
    let enabled: bool = unmarshal(value).map_err(|e| {
        StoreError::Invalid(silo_store::userstore::Error::InvalidValue(format!(
            "{} produced a non-boolean auto_skip_intro: {e}",
            identity.key
        )))
    })?;
    let input = silo_store::userstore::prefs::UpdateProfileInput {
        auto_skip_intro: Some(enabled),
        ..Default::default()
    };
    let updated = writer.update_profile(&identity.profile_id, &input).await?;
    if !updated {
        return Err(StoreError::Pg {
            op: "updating auto_skip_intro: profile not found",
            source: silo_pg::Error::NoRows,
        });
    }
    Ok(())
}

/// `writeSettingValue`.
pub(super) async fn write_setting_value(
    s: &Stack,
    r: &Request,
    claims: &Claims,
    event_user: i64,
    identity: &SettingIdentity,
    raw: &[u8],
    mutation_id: &str,
    device: &Device,
) -> Result<MutationResult, ApiError> {
    let def = definition(&identity.key)?;
    if raw.is_empty() {
        return Err(field_error(FIELD_VALUE, "value is required"));
    }
    let schemas =
        load::object_schemas().ok_or_else(|| api(500, INTERNAL, "Failed to store the setting"))?;
    let normalized = def
        .value_schema
        .normalize_value(raw, schemas)
        .map_err(|e| coded_field(400, "invalid_value", FIELD_VALUE, e))?;
    let mirror_write = mirror::mirror_write(&identity.key, &normalized).map_err(|e| {
        tracing::error!(component = "api", key = identity.key, error = %e, "settings mirror could not convert a normalized value");
        api(500, INTERNAL, "Failed to store the setting")
    })?;
    let column = intro_skip_column_write(&identity.key, &normalized, mirror_write.as_ref());
    let hash = hash_mutation(identity, &normalized);

    let outcome = run_mutation(
        s,
        event_user,
        mutation_id,
        &hash,
        Mutate::Upsert {
            identity,
            normalized: &normalized,
            mirror: mirror_write.as_ref(),
            column: column.as_deref(),
        },
    )
    .await;
    let (stored, raw_result) = match outcome {
        Err(MutationError::IdConflict) => {
            return Err(api(409, "mutation_id_conflict", MUTATION_CONFLICT));
        }
        Err(MutationError::Store(e)) => {
            return Err(store_failed(&identity.key, identity.scope.as_str(), &e));
        }
        Ok(Outcome::Replay(raw)) => {
            return Ok(MutationResult {
                view: None,
                raw: Some(raw),
                replay: true,
            });
        }
        Ok(Outcome::Done(stored, raw)) => (stored, raw),
    };
    let acting = get_profile_id(r);
    if identity.scope == Scope::PROFILE_DEVICE
        && identity.device_id == device.id
        && identity.profile_id == acting
    {
        record_sighting(s, claims, &identity.profile_id, device).await;
    }
    publish_user_settings(
        s,
        event_user,
        &identity.profile_id,
        &identity.key,
        identity.scope.as_str(),
    )
    .await;
    notify_scope_setting(s, event_user, &identity.profile_id, &identity.key).await;
    audit_for_other(claims, &acting, event_user, identity, "set");
    Ok(MutationResult {
        view: Some(value_view(&stored)),
        raw: raw_result,
        replay: false,
    })
}

/// `auditSettingsForOther`.
fn audit_for_other(
    claims: &Claims,
    acting: &str,
    target_user: i64,
    id: &SettingIdentity,
    action: &str,
) {
    let same_profile = id.profile_id.is_empty() || id.profile_id == acting;
    let same_user = target_user == 0 || target_user == claims.user_id;
    if same_profile && same_user {
        return;
    }
    tracing::info!(
        component = "api",
        action,
        actor_user_id = claims.user_id,
        actor_profile_id = acting,
        target_user_id = target_user,
        target_profile_id = id.profile_id,
        acting_as_admin = claims.role == "admin",
        setting_key = id.key,
        scope = id.scope.as_str(),
        "settings changed for another profile"
    );
}

enum MutationError {
    IdConflict,
    Store(StoreError),
}

impl From<StoreError> for MutationError {
    fn from(e: StoreError) -> Self {
        MutationError::Store(e)
    }
}

/// What `runSettingMutation`'s `mutate` does.
enum Mutate<'a> {
    Upsert {
        identity: &'a SettingIdentity,
        normalized: &'a [u8],
        mirror: Option<&'a mirror::MirroredWrite>,
        column: Option<&'a [u8]>,
    },
    Shortcut {
        def: &'static Definition,
        identity: &'a SettingIdentity,
        item: &'a ShortcutItem,
        present: bool,
        changed: &'a mut bool,
    },
}

impl Mutate<'_> {
    async fn apply(self, writer: &mut Writer<'_>) -> Result<SettingValue, StoreError> {
        match self {
            Mutate::Upsert {
                identity,
                normalized,
                mirror,
                column,
            } => {
                let stored = match mirror {
                    None => writer.upsert_setting_value(identity, normalized).await?,
                    Some(mirror) => {
                        let mut other = identity.clone();
                        other.key = mirror.key.to_owned();
                        // Key order, so requests naming opposite halves cannot deadlock.
                        if other.key < identity.key {
                            writer.upsert_setting_value(&other, &mirror.value).await?;
                            writer.upsert_setting_value(identity, normalized).await?
                        } else {
                            let stored = writer.upsert_setting_value(identity, normalized).await?;
                            writer.upsert_setting_value(&other, &mirror.value).await?;
                            stored
                        }
                    }
                };
                write_intro_skip_column(writer, identity, column).await?;
                Ok(stored)
            }
            Mutate::Shortcut {
                def,
                identity,
                item,
                present,
                changed,
            } => {
                let (value, did) = mutate_in_tx(writer, def, identity, item, present).await?;
                *changed = did;
                Ok(value)
            }
        }
    }
}

/// `runSettingMutation`.
async fn run_mutation(
    s: &Stack,
    user_id: i64,
    mutation_id: &str,
    hash: &str,
    mutate: Mutate<'_>,
) -> Result<Outcome, MutationError> {
    let pg = |op: &'static str| move |source| StoreError::Pg { op, source };
    let mut conn = s
        .pool
        .acquire()
        .await
        .map_err(pg("beginning setting mutation transaction"))?;
    let mut tx = conn
        .begin()
        .await
        .map_err(pg("beginning setting mutation transaction"))?;
    let mut writer = Writer {
        tx: &mut tx,
        user_id: user_id as i32,
    };
    writer.lock_preferences().await?;
    if !mutation_id.is_empty() {
        writer.lock_mutation(mutation_id).await?;
        if let Some(prior) = writer.get_mutation(mutation_id).await? {
            if prior.request_hash != hash {
                return Err(MutationError::IdConflict);
            }
            return Ok(Outcome::Replay(prior.result));
        }
    }
    let stored = mutate.apply(&mut writer).await?;
    if mutation_id.is_empty() {
        tx.commit()
            .await
            .map_err(pg("committing setting mutation transaction"))?;
        return Ok(Outcome::Done(stored, None));
    }
    let result = silo_gocompat::json::marshal(&value_view(&stored)).unwrap_or_default();
    let expires = GoTime::from_system_time(
        std::time::SystemTime::now() + Duration::from_secs(30 * 24 * 3600),
    )
    .to_utc()
    .rfc3339_nano();
    let (record, inserted) = writer
        .put_mutation(&SettingMutationRecord {
            mutation_id: mutation_id.to_owned(),
            request_hash: hash.to_owned(),
            result,
            created_at: String::new(),
            expires_at: expires,
        })
        .await?;
    if !inserted {
        if record.request_hash != hash {
            return Err(MutationError::IdConflict);
        }
        return Ok(Outcome::Replay(record.result));
    }
    tx.commit()
        .await
        .map_err(pg("committing setting mutation transaction"))?;
    Ok(Outcome::Done(stored, Some(record.result)))
}

/// `clearSettingValue`.
pub(super) async fn clear_setting_value(
    s: &Stack,
    r: &Request,
    claims: &Claims,
    event_user: i64,
    identity: &SettingIdentity,
) -> Result<(), ApiError> {
    let failed = |e: &dyn std::fmt::Display| {
        tracing::error!(component = "api", key = identity.key, scope = identity.scope.as_str(), error = %e, "failed to clear a canonical setting");
        api(500, INTERNAL, "Failed to clear the setting")
    };
    let mirror_key = mirror::mirror_key(&identity.key);
    let cleared = intro_skip_column_cleared(&identity.key);
    let mut conn = s.pool.acquire().await.map_err(|e| failed(&e))?;
    let mut tx = conn.begin().await.map_err(|e| failed(&e))?;
    let (removed, mirror_removed) = {
        let mut writer = Writer {
            tx: &mut tx,
            user_id: event_user as i32,
        };
        writer.lock_preferences().await.map_err(|e| failed(&e))?;
        let removed = writer
            .delete_setting_value(identity)
            .await
            .map_err(|e| failed(&e))?;
        let mut mirror_removed = false;
        if let Some(mirror) = mirror_key {
            let mut other = identity.clone();
            other.key = mirror.to_owned();
            mirror_removed = writer
                .delete_setting_value(&other)
                .await
                .map_err(|e| failed(&e))?;
        }
        if removed || mirror_removed {
            write_intro_skip_column(&mut writer, identity, cleared.as_deref())
                .await
                .map_err(|e| failed(&e))?;
        }
        (removed, mirror_removed)
    };
    tx.commit().await.map_err(|e| failed(&e))?;
    if !removed {
        if let Some(mirror) = mirror_key.filter(|_| mirror_removed) {
            tracing::warn!(
                component = "api",
                key = identity.key,
                mirror_key = mirror,
                scope = identity.scope.as_str(),
                "cleared a mirrored setting whose addressed half was already gone"
            );
            publish_user_settings(
                s,
                event_user,
                &identity.profile_id,
                mirror,
                identity.scope.as_str(),
            )
            .await;
        }
        return Err(api(404, "not_found", "No value is set at this scope"));
    }
    audit_for_other(claims, &get_profile_id(r), event_user, identity, "clear");
    publish_user_settings(
        s,
        event_user,
        &identity.profile_id,
        &identity.key,
        identity.scope.as_str(),
    )
    .await;
    notify_scope_setting(s, event_user, &identity.profile_id, &identity.key).await;
    Ok(())
}

/// `navigationShortcutItem`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
struct ShortcutItem {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    library_id: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    section_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    collection_id: String,
    label: String,
}

impl ShortcutItem {
    fn same_destination(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.library_id == other.library_id
            && self.section_id == other.section_id
            && self.collection_id == other.collection_id
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct ShortcutDocument {
    items: Vec<ShortcutItem>,
}

/// `normalizeNavigationShortcutItem`.
fn normalize_shortcut(def: &Definition, item: &[u8]) -> Result<ShortcutItem, String> {
    if item.is_empty() {
        return Err("item is required".to_owned());
    }
    let mut raw = b"{\"items\":[".to_vec();
    raw.extend_from_slice(item);
    raw.extend_from_slice(b"]}");
    let schemas = load::object_schemas().ok_or("the settings contract did not load")?;
    let normalized = def.value_schema.normalize_value(&raw, schemas)?;
    let document: ShortcutDocument =
        unmarshal(&normalized).map_err(|_| "shortcut did not normalize to one item")?;
    if document.items.len() != 1 {
        return Err("shortcut did not normalize to one item".to_owned());
    }
    Ok(document.items.into_iter().next().unwrap_or_default())
}

/// `setNavigationShortcut`.
async fn set_navigation_shortcut(
    s: &Stack,
    r: &Request,
    claims: &Claims,
    user_id: i64,
    profile_id: &str,
    raw_item: &[u8],
    present: Option<bool>,
    mutation_id: &str,
) -> Result<MutationResult, ApiError> {
    let identity = SettingIdentity {
        key: keys::NAV_SHORTCUTS.to_owned(),
        scope: Scope::PROFILE,
        profile_id: trim_space(profile_id).to_owned(),
        ..SettingIdentity::default()
    };
    if silo_store::userstore::validate_identity(&identity).is_err() {
        return Err(field_error(
            FIELD_PROFILE_HEADER,
            "X-Profile-Id header is required",
        ));
    }
    let def = definition(&identity.key)?;
    let Some(present) = present else {
        return Err(field_error(FIELD_PRESENT, "present is required"));
    };
    let item = normalize_shortcut(def, raw_item)
        .map_err(|e| coded_field(400, "invalid_value", FIELD_ITEM, e))?;
    // `hashNavigationShortcutMutation`: removal ignores the label.
    #[derive(Serialize)]
    struct Canonical<'a> {
        operation: &'a str,
        item: ShortcutItem,
        present: bool,
    }
    let mut hashed = item.clone();
    if !present {
        hashed.label = String::new();
    }
    let canonical = silo_gocompat::json::marshal(&Canonical {
        operation: "set_navigation_shortcut_presence",
        item: hashed,
        present,
    })
    .unwrap_or_default();
    let hash = hash_mutation(&identity, &canonical);

    let pg = |op: &'static str| move |source| StoreError::Pg { op, source };
    let mut last_conflict = true;
    let mut stored = None;
    let mut changed = false;
    let mut raw_result = None;
    if !mutation_id.is_empty() {
        let mut did = false;
        let outcome = run_mutation(
            s,
            user_id,
            mutation_id,
            &hash,
            Mutate::Shortcut {
                def,
                identity: &identity,
                item: &item,
                present,
                changed: &mut did,
            },
        )
        .await;
        match outcome {
            Err(MutationError::IdConflict) => {
                return Err(api(409, "mutation_id_conflict", MUTATION_CONFLICT));
            }
            Err(MutationError::Store(StoreError::RevisionConflict)) => {
                return Err(api(
                    409,
                    "setting_update_conflict",
                    "Navigation shortcuts changed too quickly; retry this mutation",
                ));
            }
            Err(MutationError::Store(StoreError::Invalid(e))) => {
                return Err(field_error(FIELD_ITEM, e.to_string()));
            }
            Err(MutationError::Store(_)) => {
                return Err(api(500, INTERNAL, "Failed to store navigation shortcuts"));
            }
            Ok(Outcome::Replay(raw)) => {
                return Ok(MutationResult {
                    view: None,
                    raw: Some(raw),
                    replay: true,
                });
            }
            Ok(Outcome::Done(value, raw)) => {
                stored = Some(value);
                raw_result = raw;
                changed = did;
                last_conflict = false;
            }
        }
    } else {
        // Each attempt reads and writes outside one transaction, as `mutateNavigationShortcut` does on
        // the store itself: the compare-and-set is the guard.
        for _ in 0..MAX_SHORTCUT_RETRIES {
            let attempt: Result<(SettingValue, bool), StoreError> = async {
                let mut conn = s
                    .pool
                    .acquire()
                    .await
                    .map_err(pg("reading navigation shortcuts"))?;
                let mut writer = Writer {
                    tx: &mut conn,
                    user_id: user_id as i32,
                };
                mutate_in_tx(&mut writer, def, &identity, &item, present).await
            }
            .await;
            match attempt {
                Err(StoreError::RevisionConflict) => continue,
                Err(StoreError::Invalid(e)) => return Err(field_error(FIELD_ITEM, e.to_string())),
                Err(StoreError::NoStorageIdentity(detail)) => {
                    return Err(coded_field(400, "invalid_value", FIELD_ITEM, detail));
                }
                Err(_) => return Err(api(500, INTERNAL, "Failed to store navigation shortcuts")),
                Ok((value, did)) => {
                    stored = Some(value);
                    changed = did;
                    last_conflict = false;
                    break;
                }
            }
        }
    }
    if last_conflict {
        return Err(api(
            409,
            "setting_update_conflict",
            "Navigation shortcuts changed too quickly; retry this mutation",
        ));
    }
    let stored = stored.unwrap_or_default();
    if changed {
        publish_user_settings(
            s,
            user_id,
            &identity.profile_id,
            &identity.key,
            identity.scope.as_str(),
        )
        .await;
        audit_for_other(claims, &get_profile_id(r), user_id, &identity, "set");
    }
    Ok(MutationResult {
        view: Some(value_view(&stored)),
        raw: raw_result,
        replay: false,
    })
}

/// One attempt of `mutateNavigationShortcut`, with `applyNavigationShortcutMutation`. An unchanged
/// document on an empty row answers the empty document without a row.
async fn mutate_in_tx(
    writer: &mut Writer<'_>,
    def: &Definition,
    identity: &SettingIdentity,
    item: &ShortcutItem,
    present: bool,
) -> Result<(SettingValue, bool), StoreError> {
    let current = writer.get_setting_value(identity).await?;
    let mut document = ShortcutDocument::default();
    if let Some(current) = &current {
        document = unmarshal(&current.value).map_err(|e| {
            StoreError::NoStorageIdentity(format!("decoding stored navigation shortcuts: {e}"))
        })?;
    }
    let at = document.items.iter().position(|c| c.same_destination(item));
    let unchanged = || -> SettingValue {
        current.clone().unwrap_or_else(|| SettingValue {
            identity: identity.clone(),
            value: b"{\"items\":[]}".to_vec(),
            ..SettingValue::default()
        })
    };
    if present {
        match at {
            Some(i) if document.items[i].label == item.label => return Ok((unchanged(), false)),
            Some(i) => document.items[i] = item.clone(),
            None => document.items.push(item.clone()),
        }
    } else {
        match at {
            None => return Ok((unchanged(), false)),
            Some(i) => {
                document.items.remove(i);
            }
        }
    }
    let raw = silo_gocompat::json::marshal(&document).unwrap_or_default();
    let schemas = load::object_schemas().ok_or(StoreError::NoStorageIdentity(
        "the settings contract did not load".to_owned(),
    ))?;
    let next = def
        .value_schema
        .normalize_value(&raw, schemas)
        .map_err(StoreError::NoStorageIdentity)?;
    let expected = current.as_ref().map_or(0, |c| c.revision);
    let stored = writer.compare_and_set(identity, &next, expected).await?;
    Ok((stored, true))
}

/// `clientFamilyFor`.
fn client_family_for(header: &str, keys: &[String]) -> Result<(ClientFamily, bool), ApiError> {
    let eligible = keys.iter().any(|key| {
        contract()
            .lookup(key)
            .is_some_and(|d| d.allows_scope(&Scope::PROFILE_CLIENT))
    });
    let value = trim_space(header);
    if value.is_empty() {
        return Ok((ClientFamily::default(), false));
    }
    let family = ClientFamily::new(value);
    if !family.valid() {
        return Err(field_error(
            FIELD_CLIENT_FAMILY,
            "X-Silo-Client-Family header must be one of tv, mobile, tablet, desktop or web",
        ));
    }
    Ok((family, eligible))
}

/// `EffectiveSettingsQuery`.
struct EffectiveQuery {
    keys: Vec<String>,
    active_profile: String,
    profile_id: String,
    device_id: String,
    device: Device,
    client_family: String,
    library_ids: Vec<i64>,
    series_ids: Vec<String>,
    verify: Verifier,
}

/// `resolveEffective`.
async fn resolve_effective(
    s: &Stack,
    r: &Request,
    claims: &Claims,
    q: EffectiveQuery,
) -> Result<Vec<EffectiveView>, ApiError> {
    let manifest = contract();
    let mut keys = q.keys;
    if keys.is_empty() {
        keys = manifest
            .definitions
            .iter()
            .filter(|d| d.is_remote())
            .map(|d| d.key.clone())
            .collect();
    } else {
        for key in &keys {
            if manifest.lookup(key).is_none() {
                return Err(coded_field(
                    404,
                    "unknown_setting",
                    FIELD_KEYS,
                    format!("No setting named {key} exists in this server's contract"),
                ));
            }
        }
    }
    let active = trim_space(&q.active_profile).to_owned();
    let mut rc = ResolveContext {
        profile_id: active.clone(),
        device_id: q.device.id.clone(),
        library_ids: q.library_ids,
        series_ids: q.series_ids,
        ..ResolveContext::default()
    };
    let (family, needed) = client_family_for(&q.client_family, &keys)?;
    if needed {
        rc.client_family = family;
    }
    let named = trim_space(&q.profile_id);
    if !named.is_empty() && named != rc.profile_id {
        may_act_for(
            s,
            claims,
            claims.user_id,
            &q.active_profile,
            &q.verify,
            named,
        )
        .await?;
        rc.profile_id = named.to_owned();
    }
    let named_device = trim_space(&q.device_id);
    if !named_device.is_empty() {
        device_belongs(s, claims.user_id, &rc.profile_id, named_device).await?;
        rc.device_id = named_device.to_owned();
    }
    if rc.library_ids.len() + rc.series_ids.len() > MAX_EFFECTIVE_CONTENT_IDS {
        return Err(field_error(
            FIELD_LIBRARY_ID,
            "Too many library_ids/series_ids in one request; resolve in smaller batches",
        ));
    }
    if rc.device_id.is_empty() {
        for key in &keys {
            if manifest
                .lookup(key)
                .is_some_and(|d| d.allows_scope(&Scope::PROFILE_DEVICE))
            {
                return Err(field_error(
                    FIELD_DEVICE_HEADER,
                    format!("X-Silo-Device-Id header is required to resolve {key}"),
                ));
            }
        }
    }
    let store = store_for(s, claims.user_id);
    let resolved = resolver_for(s)
        .resolve(&store, &rc, &keys, &constraints_for(r))
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to resolve settings"))?;
    if rc.profile_id == active && rc.device_id == q.device.id {
        record_sighting(s, claims, &rc.profile_id, &q.device).await;
    }
    let observed = observed_for(s, r, &resolved).await;
    Ok(responses_with(&resolved, &observed))
}

/// `effectiveContextRequest`.
struct ContextRequest {
    context_id: String,
    library_id: Vec<u8>,
    series_id: String,
}

/// `parseOptionalPositiveJSONInt`.
fn optional_positive(raw: &[u8]) -> Result<i64, ()> {
    if raw.is_empty() || silo_config::settings::strictjson::trim_space_bytes(raw) == b"null" {
        return Ok(0);
    }
    if let Ok(number) = unmarshal::<silo_gocompat::json::Number>(raw)
        && let Some(n) = atoi(&number.0).filter(|n| *n > 0)
    {
        return Ok(n);
    }
    if let Ok(text) = unmarshal::<String>(raw)
        && let Some(n) = atoi(trim_space(&text)).filter(|n| *n > 0)
    {
        return Ok(n);
    }
    Err(())
}

/// `effectiveContextResponse`.
#[derive(Serialize)]
struct ContextView {
    context_id: String,
    settings: Vec<EffectiveView>,
}

/// `resolveEffectiveContexts`.
async fn resolve_contexts(
    s: &Stack,
    r: &Request,
    claims: &Claims,
    keys: Vec<String>,
    active: &str,
    device: Device,
    client_family: &str,
    requested: &[ContextRequest],
) -> Result<Vec<ContextView>, ApiError> {
    if keys.is_empty() {
        return Err(field_error(
            FIELD_KEYS,
            "keys must contain at least one setting",
        ));
    }
    for key in &keys {
        definition(key).map_err(|mut e| {
            e.field = FIELD_KEYS;
            e
        })?;
    }
    if requested.is_empty() {
        return Err(field_error(
            FIELD_CONTEXTS,
            "contexts must contain at least one content context",
        ));
    }
    if requested.len() > MAX_EFFECTIVE_CONTENT_IDS {
        return Err(field_error(
            FIELD_CONTEXTS,
            "Too many contexts in one request; resolve in smaller batches",
        ));
    }
    let profile_id = trim_space(active).to_owned();
    let (family, needed) = client_family_for(client_family, &keys)?;
    if device.id.is_empty() {
        for key in &keys {
            if contract()
                .lookup(key)
                .is_some_and(|d| d.allows_scope(&Scope::PROFILE_DEVICE))
            {
                return Err(field_error(
                    FIELD_DEVICE_HEADER,
                    format!("X-Silo-Device-Id header is required to resolve {key}"),
                ));
            }
        }
    }
    let mut seen = HashSet::new();
    let mut contexts = Vec::with_capacity(requested.len());
    let mut content_ids = 0;
    for request in requested {
        if trim_space(&request.context_id).is_empty() {
            return Err(field_error(
                FIELD_CONTEXTS,
                "Every context requires a non-empty context_id",
            ));
        }
        if !seen.insert(request.context_id.clone()) {
            return Err(field_error(
                FIELD_CONTEXTS,
                "context_id values must be unique",
            ));
        }
        let library = optional_positive(&request.library_id).map_err(|()| {
            field_error(
                FIELD_CONTEXTS,
                "library_id must be a positive integer or numeric string",
            )
        })?;
        let series = trim_space(&request.series_id).to_owned();
        if library == 0 && series.is_empty() {
            return Err(field_error(
                FIELD_CONTEXTS,
                "Every context requires library_id or series_id",
            ));
        }
        let mut rc = ResolveContext {
            profile_id: profile_id.clone(),
            device_id: device.id.clone(),
            ..ResolveContext::default()
        };
        if needed {
            rc.client_family = family.clone();
        }
        if library > 0 {
            rc.library_ids = vec![library];
            content_ids += 1;
        }
        if !series.is_empty() {
            rc.series_ids = vec![series];
            content_ids += 1;
        }
        if content_ids > MAX_EFFECTIVE_CONTENT_IDS {
            return Err(field_error(
                FIELD_CONTEXTS,
                "Too many content ids in one request; resolve in smaller batches",
            ));
        }
        contexts.push(rc);
    }
    let store = store_for(s, claims.user_id);
    let resolved = resolver_for(s)
        .resolve_contexts(&store, &contexts, &keys, &constraints_for(r))
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to resolve settings"))?;
    record_sighting(s, claims, &profile_id, &device).await;
    let all: Vec<Effective> = resolved.iter().flatten().cloned().collect();
    let observed = observed_for(s, r, &all).await;
    let mut out = Vec::with_capacity(resolved.len());
    for (i, values) in resolved.iter().enumerate() {
        let views = responses_with(values, &observed);
        let mut by_key: HashMap<String, EffectiveView> = HashMap::new();
        for view in views {
            by_key.insert(view.key.clone(), view);
        }
        let settings = keys
            .iter()
            .filter_map(|key| by_key.get(key).cloned())
            .collect();
        out.push(ContextView {
            context_id: requested[i].context_id.clone(),
            settings,
        });
    }
    Ok(out)
}

/// `listExplicitValues`.
async fn list_explicit(
    s: &Stack,
    claims: &Claims,
    identity: &SettingIdentity,
    keys: &[String],
) -> Result<Vec<ExplicitView>, ApiError> {
    for key in &keys[1..] {
        let def = definition(key).map_err(|mut e| {
            e.field = FIELD_KEYS;
            e
        })?;
        if !def.allows_scope(&identity.scope) {
            return Err(coded_field(
                400,
                "scope_not_allowed",
                FIELD_SCOPE,
                format!("{key} cannot be set at {}", identity.scope),
            ));
        }
    }
    let mut query = SettingResolutionQuery {
        keys: keys.to_vec(),
        ..SettingResolutionQuery::default()
    };
    match identity.scope.as_str() {
        "profile" => query.profile_ids = vec![identity.profile_id.clone()],
        "profile_client" => {
            query.profile_ids = vec![identity.profile_id.clone()];
            query.client_family = identity.client_family.clone();
        }
        "profile_device" => {
            query.profile_ids = vec![identity.profile_id.clone()];
            query.device_id = identity.device_id.clone();
        }
        "profile_library" => {
            query.profile_ids = vec![identity.profile_id.clone()];
            query.library_ids = vec![identity.library_id];
        }
        "profile_series" => {
            query.profile_ids = vec![identity.profile_id.clone()];
            query.series_ids = vec![identity.series_id.clone()];
        }
        _ => {}
    }
    let stored = store_for(s, claims.user_id)
        .list_setting_values_for_resolution(&query)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to read settings"))?;
    let same = |a: &SettingIdentity| {
        a.scope == identity.scope
            && a.profile_id == identity.profile_id
            && a.client_family == identity.client_family
            && a.device_id == identity.device_id
            && a.library_id == identity.library_id
            && a.series_id == identity.series_id
    };
    let mut by_key: HashMap<&str, &SettingValue> = HashMap::new();
    for value in &stored {
        if same(&value.identity) {
            by_key.insert(&value.identity.key, value);
        }
    }
    Ok(keys
        .iter()
        .map(|key| {
            let mut entry = ExplicitView {
                key: key.clone(),
                scope: identity.scope.as_str().to_owned(),
                profile_id: identity.profile_id.clone(),
                client_family: identity.client_family.as_str().to_owned(),
                device_id: identity.device_id.clone(),
                library_id: identity.library_id,
                series_id: identity.series_id.clone(),
                is_set: false,
                value: RawMessage::nil(),
                revision: 0,
                updated_at: String::new(),
            };
            if let Some(value) = by_key.get(key.as_str()) {
                entry.is_set = true;
                entry.value = value.value.clone().into();
                entry.revision = value.revision;
                entry.updated_at = value.updated_at.clone();
            }
            entry
        })
        .collect())
}

/// `readSettingValue`.
async fn read_value(
    s: &Stack,
    claims: &Claims,
    identity: &SettingIdentity,
) -> Result<ValueView, ApiError> {
    match store_for(s, claims.user_id)
        .get_setting_value(identity)
        .await
    {
        Err(_) => Err(api(500, INTERNAL, "Failed to read the setting")),
        Ok(None) => Err(api(404, "not_found", "No value is set at this scope")),
        Ok(Some(value)) => Ok(value_view(&value)),
    }
}

/// `splitCSV`.
fn split_csv(raw: &str) -> Vec<String> {
    if trim_space(raw).is_empty() {
        return Vec::new();
    }
    raw.split(',')
        .map(|p| trim_space(p).to_owned())
        .filter(|p| !p.is_empty())
        .collect()
}

/// `parseSettingKeys`.
fn parse_setting_keys(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.split(',')
        .map(|p| trim_space(p).to_owned())
        .filter(|p| !p.is_empty() && seen.insert(p.clone()))
        .collect()
}

/// `uniqueTrimmed`.
fn unique_trimmed(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .map(|p| trim_space(&p).to_owned())
        .filter(|p| !p.is_empty() && seen.insert(p.clone()))
        .collect()
}

/// `json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))`, then the one-document check.
fn decode_limited<T: serde::de::DeserializeOwned>(bytes: &[u8], strict: bool) -> Result<T, Tail> {
    let limit = 1 << 20;
    let slice = &bytes[..bytes.len().min(limit)];
    let mut decoder = silo_gocompat::json::Decoder::new();
    if strict {
        decoder = decoder.disallow_unknown_fields();
    }
    let mut stream = decoder.stream(slice);
    let value: T = stream.decode().map_err(|_| Tail::Decode)?;
    let rest = &slice[stream.input_offset() as usize..];
    if bytes.len() > limit || !silo_config::settings::strictjson::trim_space_bytes(rest).is_empty()
    {
        return Err(Tail::Trailing);
    }
    Ok(value)
}

enum Tail {
    Decode,
    Trailing,
}

const SINGLE_DOCUMENT: &str = "Body must be a single JSON document";

#[derive(Deserialize, Default)]
#[serde(default)]
struct ValueBody {
    value: RawMessage,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ShortcutBody {
    item: RawMessage,
    present: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ContextBody {
    context_id: String,
    library_id: RawMessage,
    series_id: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct EffectiveBody {
    keys: Vec<String>,
    contexts: Vec<ContextBody>,
}

/// `settingRegistry` in `settings.go`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacyScope {
    User,
    Device,
}

impl LegacyScope {
    fn name(self) -> &'static str {
        match self {
            LegacyScope::User => "user",
            LegacyScope::Device => "device",
        }
    }
}

#[derive(Clone, Copy)]
enum Check {
    Enum(&'static [&'static str]),
    Bool,
    Int(i64, i64),
    Float(f64, f64),
    Language,
    Json,
}

struct Spec {
    key: &'static str,
    scope: LegacyScope,
    default: &'static str,
    check: Check,
}

const REGISTRY: &[Spec] = &[
    Spec {
        key: "playback.preferred_quality",
        scope: LegacyScope::Device,
        default: "auto",
        check: Check::Enum(&[
            "auto",
            "original",
            "2160p",
            "1080p-high",
            "1080p-medium",
            "1080p",
            "1080p-8",
            "720p-high",
            "720p-medium",
            "720p",
            "480p",
            "420p",
            "328p",
        ]),
    },
    Spec {
        key: "playback.audio_language",
        scope: LegacyScope::Device,
        default: "",
        check: Check::Language,
    },
    Spec {
        key: "playback.auto_skip_intro",
        scope: LegacyScope::Device,
        default: "false",
        check: Check::Bool,
    },
    Spec {
        key: "playback.auto_skip_credits",
        scope: LegacyScope::Device,
        default: "false",
        check: Check::Bool,
    },
    Spec {
        key: "playback.auto_skip_recap",
        scope: LegacyScope::Device,
        default: "false",
        check: Check::Bool,
    },
    Spec {
        key: "playback.auto_play_next_preview",
        scope: LegacyScope::Device,
        default: "false",
        check: Check::Bool,
    },
    Spec {
        key: "playback.auto_play_next",
        scope: LegacyScope::Device,
        default: "true",
        check: Check::Bool,
    },
    Spec {
        key: CANONICAL_NEXT_UP,
        scope: LegacyScope::Device,
        default: "30",
        check: Check::Int(0, 120),
    },
    Spec {
        key: SUBTITLE_APPEARANCE,
        scope: LegacyScope::Device,
        default: "",
        check: Check::Json,
    },
    Spec {
        key: "ui.library_page_state",
        scope: LegacyScope::Device,
        default: "",
        check: Check::Json,
    },
    Spec {
        key: "ui.remember_library_page_state",
        scope: LegacyScope::Device,
        default: "true",
        check: Check::Bool,
    },
    Spec {
        key: "search.media_scope",
        scope: LegacyScope::User,
        default: "video",
        check: Check::Enum(&["all", "video", "audiobook"]),
    },
    Spec {
        key: "ui.date_format",
        scope: LegacyScope::User,
        default: "auto",
        check: Check::Enum(&["auto", "DD/MM/YYYY", "MM/DD/YYYY", "YYYY-MM-DD"]),
    },
    Spec {
        key: "ui.time_format",
        scope: LegacyScope::User,
        default: "auto",
        check: Check::Enum(&["auto", "12h", "24h"]),
    },
    Spec {
        key: "player.hdr_enabled",
        scope: LegacyScope::Device,
        default: "true",
        check: Check::Bool,
    },
    Spec {
        key: "player.dolby_vision_enabled",
        scope: LegacyScope::Device,
        default: "true",
        check: Check::Bool,
    },
    Spec {
        key: "player.dv_profile7_hdr10_fallback",
        scope: LegacyScope::Device,
        default: "false",
        check: Check::Bool,
    },
    Spec {
        key: "player.seek_cache_enabled",
        scope: LegacyScope::Device,
        default: "true",
        check: Check::Bool,
    },
    Spec {
        key: "player.playback_speed",
        scope: LegacyScope::Device,
        default: "1",
        check: Check::Float(0.25, 3.0),
    },
    Spec {
        key: "player.audio_sync_ms",
        scope: LegacyScope::Device,
        default: "0",
        check: Check::Int(-5000, 5000),
    },
    Spec {
        key: "player.subtitle_sync_ms",
        scope: LegacyScope::Device,
        default: "0",
        check: Check::Int(-10000, 10000),
    },
    Spec {
        key: "player.video_gravity",
        scope: LegacyScope::Device,
        default: "fit",
        check: Check::Enum(&["fit", "fill", "stretch"]),
    },
    Spec {
        key: "player.orientation_mode",
        scope: LegacyScope::Device,
        default: "landscapeLocked",
        check: Check::Enum(&["landscapeLocked", "rotateFreely"]),
    },
];

fn canonical_device_key(key: &str) -> &str {
    if key == LEGACY_NEXT_UP {
        CANONICAL_NEXT_UP
    } else {
        key
    }
}

fn spec_of(key: &str) -> Option<&'static Spec> {
    let key = canonical_device_key(key);
    REGISTRY.iter().find(|s| s.key == key)
}

/// `keyUsesUserScope`.
pub(super) fn legacy_user_key(key: &str) -> bool {
    uses_user_scope(key)
}

fn uses_user_scope(key: &str) -> bool {
    spec_of(key).is_some_and(|s| s.scope == LegacyScope::User)
}

fn uses_device_scope(key: &str) -> bool {
    spec_of(key).is_some_and(|s| s.scope == LegacyScope::Device)
}

fn is_migrated_playback(key: &str) -> bool {
    matches!(
        canonical_device_key(key),
        "playback.preferred_quality"
            | "playback.audio_language"
            | "playback.auto_skip_intro"
            | "playback.auto_skip_credits"
            | "playback.auto_play_next"
            | CANONICAL_NEXT_UP
    )
}

/// `%g` for the float bounds this table has.
fn fmt_g(v: f64) -> String {
    v.to_string()
}

/// `validateRegisteredSetting`.
fn validate_registered(key: &str, value: &str, expected: LegacyScope) -> Result<(), String> {
    let key = canonical_device_key(key);
    let Some(spec) = spec_of(key) else {
        return Ok(());
    };
    if spec.scope != expected {
        return Err(format!("{key} is not a {} setting", expected.name()));
    }
    match spec.check {
        Check::Enum(allowed) => {
            if allowed.contains(&value) {
                Ok(())
            } else {
                Err(format!("{key} must be one of {}", allowed.join(", ")))
            }
        }
        Check::Bool => {
            if value == "true" || value == "false" {
                Ok(())
            } else {
                Err(format!("{key} must be true or false"))
            }
        }
        Check::Int(min, max) => {
            let parsed = atoi(value).ok_or_else(|| format!("{key} must be an integer"))?;
            if parsed < min || parsed > max {
                return Err(format!("{key} must be between {min} and {max}"));
            }
            Ok(())
        }
        Check::Float(min, max) => {
            let parsed = silo_contracts::settingsmigrate::go_parse_float(value)
                .ok_or_else(|| format!("{key} must be a number"))?;
            if parsed.is_nan() || parsed < min || parsed > max {
                return Err(format!(
                    "{key} must be between {} and {}",
                    fmt_g(min),
                    fmt_g(max)
                ));
            }
            Ok(())
        }
        Check::Language => {
            let trimmed = trim_space(value);
            if trimmed.is_empty()
                || silo_config::settings::normalize_language_tag(trimmed).is_some()
            {
                Ok(())
            } else {
                Err(format!(
                    "{key} must be a BCP 47 language tag such as en or en-US"
                ))
            }
        }
        Check::Json => {
            if unmarshal::<serde_json::Value>(value.as_bytes()).is_ok() {
                Ok(())
            } else {
                Err(format!("{key} must be valid JSON"))
            }
        }
    }
}

/// `planLegacyRuntimeSettings`.
pub(super) fn plan_legacy_runtime(
    key: &str,
    value: Option<&str>,
) -> Result<Vec<(String, Option<String>)>, String> {
    let planner = silo_contracts::settingsmigrate::Planner::new(
        silo_contracts::settingscontract::load_contract(),
    );
    match value {
        None => {
            let keys = planner.runtime_keys(key);
            if keys.is_empty() {
                return Err(format!("{key} has no canonical runtime target"));
            }
            Ok(keys.into_iter().map(|k| (k, None)).collect())
        }
        Some(value) => planner.plan_runtime_value(key, value),
    }
}

/// `writeCanonicalSettingsSync`.
pub(super) async fn write_canonical_sync(
    writer: &mut Writer<'_>,
    base: &SettingIdentity,
    writes: &[(String, Option<String>)],
) -> Result<Vec<String>, StoreError> {
    let mut changed = Vec::with_capacity(writes.len());
    for (key, value) in writes {
        let mut identity = base.clone();
        identity.key = key.clone();
        match value {
            None => {
                if !writer.delete_setting_value(&identity).await? {
                    continue;
                }
            }
            Some(value) => {
                writer
                    .upsert_setting_value(&identity, value.as_bytes())
                    .await?;
            }
        }
        changed.push(key.clone());
    }
    Ok(changed)
}

const NEXT_UP_MOVE: &[&str] = &[CANONICAL_NEXT_UP];

fn legacy_device_key(key: &str) -> Option<&'static str> {
    (canonical_device_key(key) == NEXT_UP_MOVE[0]).then_some(LEGACY_NEXT_UP)
}

/// `syncLegacyUserSetting`.
async fn sync_legacy_user(
    s: &Stack,
    user_id: i64,
    key: &str,
    value: Option<&str>,
) -> Result<(), String> {
    let writes = plan_legacy_runtime(key, value).unwrap_or_else(|e| {
        tracing::warn!(component = "api", key, error = %e, "legacy user setting has no canonical representation; preserving legacy write");
        Vec::new()
    });
    let mut conn = s.pool.acquire().await.map_err(|e| e.to_string())?;
    let mut tx = conn.begin().await.map_err(|e| e.to_string())?;
    let mut changed: Vec<(String, Vec<String>)> = Vec::new();
    {
        let mut writer = Writer {
            tx: &mut tx,
            user_id: user_id as i32,
        };
        writer.lock_preferences().await.map_err(|e| e.to_string())?;
        match value {
            None => writer.delete_setting(key).await,
            Some(value) => writer.set_setting(key, value).await,
        }
        .map_err(|e| e.to_string())?;
        for profile_id in writer.list_profile_ids().await.map_err(|e| e.to_string())? {
            let base = SettingIdentity {
                scope: Scope::PROFILE,
                profile_id: profile_id.clone(),
                ..SettingIdentity::default()
            };
            let keys = write_canonical_sync(&mut writer, &base, &writes)
                .await
                .map_err(|e| e.to_string())?;
            changed.push((profile_id, keys));
        }
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    for (profile_id, keys) in changed {
        for key in keys {
            publish_user_settings(s, user_id, &profile_id, &key, "profile").await;
            notify_scope_setting(s, user_id, &profile_id, &key).await;
        }
    }
    Ok(())
}

/// `syncLegacyDeviceSetting`.
async fn sync_legacy_device(
    s: &Stack,
    user_id: i64,
    mut entry: DeviceSettingEntry,
    value: Option<&str>,
) -> Result<(), String> {
    let writes = plan_legacy_runtime(&entry.key, value).unwrap_or_else(|e| {
        tracing::warn!(component = "api", key = entry.key, error = %e, "legacy device setting has no canonical representation; preserving legacy write");
        Vec::new()
    });
    let base = SettingIdentity {
        scope: Scope::PROFILE_DEVICE,
        profile_id: entry.profile_id.clone(),
        device_id: entry.device_id.clone(),
        ..SettingIdentity::default()
    };
    let mut conn = s.pool.acquire().await.map_err(|e| e.to_string())?;
    let mut tx = conn.begin().await.map_err(|e| e.to_string())?;
    let changed = {
        let mut writer = Writer {
            tx: &mut tx,
            user_id: user_id as i32,
        };
        writer.lock_preferences().await.map_err(|e| e.to_string())?;
        let legacy = legacy_device_key(&entry.key);
        match value {
            None => {
                if let Some(legacy) = legacy {
                    writer
                        .delete_device_setting(&entry.profile_id, &entry.device_id, legacy)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                writer
                    .delete_device_setting(&entry.profile_id, &entry.device_id, &entry.key)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Some(value) => {
                entry.value = value.to_owned();
                writer
                    .set_device_setting(&entry)
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(legacy) = legacy {
                    writer
                        .delete_device_setting(&entry.profile_id, &entry.device_id, legacy)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        write_canonical_sync(&mut writer, &base, &writes)
            .await
            .map_err(|e| e.to_string())?
    };
    tx.commit().await.map_err(|e| e.to_string())?;
    for key in changed {
        publish_user_settings(s, user_id, &base.profile_id, &key, "profile_device").await;
    }
    Ok(())
}

/// `effectiveSettingResponse`.
#[derive(Default, Serialize)]
struct LegacyEffective {
    key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    user_value: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_value: String,
    effective_value: String,
    source: String,
    has_device_override: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_platform: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    updated_at: String,
}

/// `getDeviceSettingWithLegacyFallback`.
async fn device_setting_fallback(
    reader: &Reader<'_>,
    profile: &str,
    device: &str,
    key: &str,
) -> Result<Option<DeviceSettingEntry>, StoreError> {
    if let Some(found) = reader.get_device_setting(profile, device, key).await? {
        return Ok(Some(found));
    }
    match legacy_device_key(key) {
        Some(legacy) => reader.get_device_setting(profile, device, legacy).await,
        None => Ok(None),
    }
}

/// `resolveEffectiveSetting`.
async fn resolve_legacy_effective(
    reader: &Reader<'_>,
    profile: &str,
    device: &Device,
    key: &str,
) -> Result<LegacyEffective, StoreError> {
    let requested = key;
    let key = canonical_device_key(key);
    let spec = spec_of(key);
    let mut out = LegacyEffective {
        key: requested.to_owned(),
        profile_id: profile.to_owned(),
        device_id: device.id.clone(),
        device_name: device.name.clone(),
        device_platform: device.platform.clone(),
        ..LegacyEffective::default()
    };
    if let Some(spec) = spec.filter(|s| s.scope == LegacyScope::Device) {
        out.source = "default".to_owned();
        if spec.default.is_empty() {
            out.source = "unset".to_owned();
        } else {
            out.effective_value = spec.default.to_owned();
        }
        if !device.id.is_empty() {
            if let Some(found) = device_setting_fallback(reader, profile, &device.id, key).await? {
                out.device_value = found.value.clone();
                out.effective_value = found.value;
                out.source = "device".to_owned();
                out.has_device_override = true;
                out.device_name = found.device_name;
                out.device_platform = found.device_platform;
                out.updated_at = found.updated_at;
                return Ok(out);
            }
            if is_migrated_playback(key) {
                let legacy = reader.get_setting(key).await?;
                if !legacy.is_empty() {
                    reader
                        .set_device_setting(&DeviceSettingEntry {
                            profile_id: profile.to_owned(),
                            device_id: device.id.clone(),
                            device_name: device.name.clone(),
                            device_platform: device.platform.clone(),
                            key: key.to_owned(),
                            value: legacy.clone(),
                            updated_at: String::new(),
                        })
                        .await?;
                    out.device_value = legacy.clone();
                    out.effective_value = legacy;
                    out.source = "device".to_owned();
                    out.has_device_override = true;
                    return Ok(out);
                }
            }
        }
        if key == SUBTITLE_APPEARANCE {
            let legacy = reader.get_setting(key).await?;
            if !legacy.is_empty() {
                out.user_value = legacy.clone();
                out.effective_value = legacy;
                out.source = "user".to_owned();
            }
        }
        return Ok(out);
    }
    let value = reader.get_setting(key).await?;
    out.user_value = value.clone();
    out.effective_value = value;
    out.source = "user".to_owned();
    if !out.effective_value.is_empty() {
        return Ok(out);
    }
    if let Some(spec) = spec.filter(|s| !s.default.is_empty()) {
        out.effective_value = spec.default.to_owned();
        out.source = "default".to_owned();
        return Ok(out);
    }
    out.source = "unset".to_owned();
    Ok(out)
}

/// `EffectiveSubtitleAppearanceView`.
#[derive(Serialize)]
struct SubtitleView {
    key: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    global_value: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_value: String,
    effective_value: String,
    has_device_override: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_platform: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    updated_at: String,
}

/// `EffectiveSubtitleAppearance`.
async fn effective_subtitle(
    s: &Stack,
    claims: &Claims,
    profile: &str,
    device: &Device,
) -> Result<SubtitleView, ApiError> {
    record_sighting(s, claims, profile, device).await;
    let reader = Reader {
        pool: &s.pool,
        user_id: claims.user_id as i32,
    };
    let resolved = resolve_legacy_effective(&reader, profile, device, SUBTITLE_APPEARANCE)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to get setting"))?;
    Ok(SubtitleView {
        key: SUBTITLE_APPEARANCE,
        profile_id: resolved.profile_id,
        global_value: resolved.user_value,
        device_value: resolved.device_value,
        effective_value: resolved.effective_value,
        has_device_override: resolved.has_device_override,
        device_id: resolved.device_id,
        device_name: resolved.device_name,
        device_platform: resolved.device_platform,
        updated_at: resolved.updated_at,
    })
}

/// `validateDeviceSettingTarget`.
fn device_target(key: &str, device: &Device) -> Result<String, ApiError> {
    if key.is_empty() {
        return Err(field_error(FIELD_KEY, "Setting key is required"));
    }
    let key = canonical_device_key(key);
    if !uses_device_scope(key) {
        return Err(field_error(
            FIELD_KEY,
            format!("{key} is not a device setting"),
        ));
    }
    if device.id.is_empty() {
        return Err(field_error(FIELD_DEVICE_ID, "Device id is required"));
    }
    Ok(key.to_owned())
}

/// `SetDeviceSetting`.
async fn set_device(
    s: &Stack,
    claims: &Claims,
    profile: &str,
    device: &Device,
    key: &str,
    value: &str,
) -> Result<(), ApiError> {
    let key = device_target(key, device)?;
    validate_registered(&key, value, LegacyScope::Device)
        .map_err(|e| field_error(FIELD_VALUE, e))?;
    let entry = DeviceSettingEntry {
        profile_id: profile.to_owned(),
        device_id: device.id.clone(),
        device_name: device.name.clone(),
        device_platform: device.platform.clone(),
        key,
        value: value.to_owned(),
        updated_at: String::new(),
    };
    sync_legacy_device(s, claims.user_id, entry, Some(value))
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to set device setting"))
}

/// `DeleteDeviceSetting`.
async fn delete_device(
    s: &Stack,
    claims: &Claims,
    profile: &str,
    device: &Device,
    key: &str,
) -> Result<(), ApiError> {
    let key = device_target(key, device)?;
    record_sighting(s, claims, profile, device).await;
    let entry = DeviceSettingEntry {
        profile_id: profile.to_owned(),
        device_id: device.id.clone(),
        key,
        ..DeviceSettingEntry::default()
    };
    sync_legacy_device(s, claims.user_id, entry, None)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to delete device setting"))
}

/// `SettingsCapabilitiesView`, in v1's key order.
#[derive(Serialize)]
struct CapabilitiesV1 {
    api_version: i64,
    client_families: [&'static str; 5],
    contract_etag: String,
    definition_count: usize,
    revision: i64,
    scopes: [&'static str; 6],
    supports_atomic_shortcuts: bool,
    supports_batched_effective: bool,
    supports_idempotent_writes: bool,
}

const SCOPES: [&str; 6] = [
    "account",
    "profile",
    "profile_client",
    "profile_device",
    "profile_library",
    "profile_series",
];
const FAMILIES: [&str; 5] = ["tv", "mobile", "tablet", "desktop", "web"];

/// `OverlayConfigView`.
#[derive(Serialize)]
struct OverlayView {
    enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    defaults: String,
    quick_actions_enabled: bool,
    quick_actions_default: String,
}

/// `OverlayConfig`.
async fn overlay_config(s: &Stack) -> OverlayView {
    let get = |key: &'static str| async move { s.settings.get(key).await.unwrap_or_default() };
    let mut view = OverlayView {
        enabled: true,
        defaults: String::new(),
        quick_actions_enabled: false,
        quick_actions_default: "both".to_owned(),
    };
    if get("overlays.enabled").await == "false" {
        view.enabled = false;
    }
    view.defaults = get("defaults.card_overlays").await;
    if get("defaults.card_quick_actions_enabled").await == "true" {
        view.quick_actions_enabled = true;
    }
    let mode = get("defaults.card_quick_actions").await;
    let known = contract()
        .lookup(keys::UI_CARD_QUICK_ACTIONS)
        .is_some_and(|d| {
            d.value_schema
                .values
                .iter()
                .any(|m| matches!(&m.value, silo_config::gojson::Value::String(t) if *t == mode))
        });
    if known {
        view.quick_actions_default = mode;
    }
    view
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

/// `ETagMatches`.
fn etag_matches(header: &str, etag: &str) -> bool {
    let header = trim_space(header);
    if header == "*" {
        return true;
    }
    header.split(',').any(|c| trim_space(c) == etag)
}

/// `HandleGetContract`.
async fn serve_contract_v1(w: &mut dyn ResponseWriter, r: &Request) {
    let failed = "Failed to read the settings contract";
    let Ok(etag) = canonical::public_etag() else {
        write_v1_error(w, 500, INTERNAL, failed).await;
        return;
    };
    w.header().set("ETag", etag.clone());
    w.header().set("Cache-Control", "no-cache");
    let header = String::from_utf8_lossy(r.header.get("If-None-Match")).into_owned();
    if !header.is_empty() && etag_matches(&header, &etag) {
        w.write_header(304).await;
        return;
    }
    let Ok(body) = canonical::public_bytes() else {
        write_v1_error(w, 500, INTERNAL, failed).await;
        return;
    };
    w.header().set("Content-Type", "application/json");
    w.write_header(200).await;
    let _ = w.write(&body).await;
}

async fn serve_capabilities_v1(w: &mut dyn ResponseWriter) {
    let Ok(etag) = canonical::public_etag() else {
        write_v1_error(w, 500, INTERNAL, "Failed to read the settings contract").await;
        return;
    };
    let m = contract();
    write_v1_json(
        w,
        200,
        &CapabilitiesV1 {
            api_version: m.api_version,
            client_families: FAMILIES,
            contract_etag: etag,
            definition_count: m.definitions.len(),
            revision: m.revision,
            scopes: SCOPES,
            supports_atomic_shortcuts: true,
            supports_batched_effective: true,
            supports_idempotent_writes: true,
        },
    )
    .await;
}

fn mutation_id(r: &Request) -> String {
    trim_space(&String::from_utf8_lossy(r.header.get("X-Silo-Mutation-Id"))).to_owned()
}

/// Renders a v1 mutation's result, as `setValueAt` and `HandleSetNavigationShortcut` do.
async fn write_mutation_v1(w: &mut dyn ResponseWriter, result: MutationResult) {
    if result.replay {
        w.header().set("X-Silo-Idempotent-Replay", "true");
    }
    if let Some(raw) = result.raw {
        w.header().set("Content-Type", "application/json");
        w.write_header(200).await;
        let _ = w.write(&raw).await;
    } else if let Some(view) = result.view {
        write_v1_json(w, 200, &view).await;
    }
}

/// `setValueAt`, for the session and admin routes.
pub(super) async fn set_value_at_v1(
    s: &Stack,
    w: &mut dyn ResponseWriter,
    r: &mut Request,
    claims: &Claims,
    event_user: i64,
    identity: &SettingIdentity,
    bytes: &[u8],
) {
    if let Err(e) = definition(&identity.key) {
        return write_api(w, &e).await;
    }
    let body: ValueBody = match decode_limited(bytes, false) {
        Ok(body) => body,
        Err(Tail::Decode) => {
            return write_v1_error(w, 400, "bad_request", "Body must be {\"value\": …}").await;
        }
        Err(Tail::Trailing) => return write_v1_error(w, 400, "bad_request", SINGLE_DOCUMENT).await,
    };
    let raw = body.value.as_bytes().unwrap_or_default().to_vec();
    match write_setting_value(
        s,
        r,
        claims,
        event_user,
        identity,
        &raw,
        &mutation_id(r),
        &device_of(r),
    )
    .await
    {
        Ok(result) => write_mutation_v1(w, result).await,
        Err(e) => write_api(w, &e).await,
    }
}

/// `io.ReadAll(http.MaxBytesReader(...))` for a request that must be readable.
async fn read_household_body(w: &mut dyn ResponseWriter, r: &mut Request) -> Option<Vec<u8>> {
    let (bytes, error) = r.read_all().await;
    if error.is_some() || bytes.len() > 1 << 20 {
        write_v1_error(w, 400, "bad_request", "Invalid request body").await;
        return None;
    }
    Some(bytes)
}

/// `activeProfileIDFromRequest`.
async fn active_profile_v1(w: &mut dyn ResponseWriter, r: &Request) -> Option<String> {
    let id = trim_space(&get_profile_id(r)).to_owned();
    if id.is_empty() {
        write_v1_error(w, 400, "bad_request", "X-Profile-Id header is required").await;
        return None;
    }
    Some(id)
}

fn mount_v1(stack: &Arc<Stack>, api_mux: &Mux) {
    let mux = Mux::new();
    mux.use_middleware([stack.v1_group(V1_GROUP)]);
    let at = |p: &str| format!("/api/v1/settings{p}");

    mux.get(
        "/",
        stack.v1(
            &at("/"),
            &[],
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let reader = Reader {
                    pool: &s.pool,
                    user_id: claims.user_id as i32,
                };
                let Ok(entries) = reader.list_settings().await else {
                    return write_v1_error(w, 500, INTERNAL, "Failed to list settings").await;
                };
                #[derive(Serialize)]
                struct Item {
                    key: String,
                    value: String,
                }
                #[derive(Serialize)]
                struct List {
                    settings: Vec<Item>,
                }
                let settings = entries
                    .into_iter()
                    .filter(|e| uses_user_scope(&e.key))
                    .map(|e| Item {
                        key: e.key,
                        value: e.value,
                    })
                    .collect();
                write_v1_json(w, 200, &List { settings }).await;
            }),
        ),
    );

    mux.get(
        "/overlay-config",
        stack.v1(
            &at("/overlay-config"),
            &[],
            route!(stack, |s, w, _r| {
                w.header().set("Cache-Control", "private, no-cache");
                let view = overlay_config(&s).await;
                write_v1_json(w, 200, &view).await;
            }),
        ),
    );

    mux.get(
        "/effective",
        stack.v1(
            &at("/effective"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let Some(profile) = active_profile_v1(w, r).await else {
                    return;
                };
                let query = query_of(r);
                let keys_param = trim_space(&q1(&query, "keys")).to_owned();
                if keys_param.is_empty() {
                    return write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Query parameter keys is required",
                    )
                    .await;
                }
                let device = device_of(r);
                record_sighting(&s, &claims, &profile, &device).await;
                let reader = Reader {
                    pool: &s.pool,
                    user_id: claims.user_id as i32,
                };
                let mut settings = Vec::new();
                for key in parse_setting_keys(&keys_param) {
                    match resolve_legacy_effective(&reader, &profile, &device, &key).await {
                        Ok(item) => settings.push(item),
                        Err(_) => {
                            return write_v1_error(
                                w,
                                500,
                                INTERNAL,
                                "Failed to resolve effective settings",
                            )
                            .await;
                        }
                    }
                }
                #[derive(Serialize)]
                struct List {
                    settings: Vec<LegacyEffective>,
                }
                write_v1_json(w, 200, &List { settings }).await;
            }),
        ),
    );

    mux.get(
        "/subtitle_appearance/effective",
        stack.v1(
            &at("/subtitle_appearance/effective"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let Some(profile) = active_profile_v1(w, r).await else {
                    return;
                };
                match effective_subtitle(&s, &claims, &profile, &device_of(r)).await {
                    Ok(view) => write_v1_json(w, 200, &view).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    async fn v1_set_device(
        s: Arc<Stack>,
        w: &mut dyn ResponseWriter,
        r: &mut Request,
        key: String,
    ) {
        let Some(claims) = get_claims(r) else { return };
        let Some(profile) = active_profile_v1(w, r).await else {
            return;
        };
        let device = device_of(r);
        if let Err(e) = device_target(&key, &device) {
            return write_api(w, &e).await;
        }
        let (bytes, _) = r.read_all().await;
        let mut stream = silo_gocompat::json::Decoder::new().stream(&bytes[..]);
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Body {
            value: String,
        }
        let Ok(body) = stream.decode::<Body>() else {
            return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
        };
        match set_device(&s, &claims, &profile, &device, &key, &body.value).await {
            Ok(()) => w.write_header(204).await,
            Err(e) => write_api(w, &e).await,
        }
    }
    async fn v1_delete_device(
        s: Arc<Stack>,
        w: &mut dyn ResponseWriter,
        r: &mut Request,
        key: String,
    ) {
        let Some(claims) = get_claims(r) else { return };
        let Some(profile) = active_profile_v1(w, r).await else {
            return;
        };
        match delete_device(&s, &claims, &profile, &device_of(r), &key).await {
            Ok(()) => w.write_header(204).await,
            Err(e) => write_api(w, &e).await,
        }
    }

    mux.put(
        "/device/subtitle_appearance",
        stack.v1(
            &at("/device/subtitle_appearance"),
            PROFILE,
            route!(stack, |s, w, r| {
                v1_set_device(s, w, r, SUBTITLE_APPEARANCE.to_owned()).await;
            }),
        ),
    );
    mux.delete(
        "/device/subtitle_appearance",
        stack.v1(
            &at("/device/subtitle_appearance"),
            PROFILE,
            route!(stack, |s, w, r| {
                v1_delete_device(s, w, r, SUBTITLE_APPEARANCE.to_owned()).await;
            }),
        ),
    );
    mux.get(
        "/device/{key}",
        stack.v1(
            &at("/device/{key}"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let Some(profile) = active_profile_v1(w, r).await else {
                    return;
                };
                let requested = r.url_param("key").to_owned();
                let device = device_of(r);
                if requested.is_empty() {
                    return write_v1_error(w, 400, "bad_request", "Setting key is required").await;
                }
                let key = canonical_device_key(&requested).to_owned();
                if !uses_device_scope(&key) {
                    return write_v1_error(
                        w,
                        400,
                        "bad_request",
                        &format!("{key} is not a device setting"),
                    )
                    .await;
                }
                if device.id.is_empty() {
                    return write_v1_error(w, 400, "bad_request", "Device id is required").await;
                }
                record_sighting(&s, &claims, &profile, &device).await;
                let reader = Reader {
                    pool: &s.pool,
                    user_id: claims.user_id as i32,
                };
                match device_setting_fallback(&reader, &profile, &device.id, &key).await {
                    Err(_) => {
                        write_v1_error(w, 500, INTERNAL, "Failed to get device setting").await
                    }
                    Ok(None) => write_v1_error(w, 404, "not_found", "Setting not found").await,
                    Ok(Some(found)) => {
                        #[derive(Serialize)]
                        struct Item {
                            key: String,
                            value: String,
                        }
                        write_v1_json(
                            w,
                            200,
                            &Item {
                                key: requested,
                                value: found.value,
                            },
                        )
                        .await;
                    }
                }
            }),
        ),
    );
    mux.put(
        "/device/{key}",
        stack.v1(
            &at("/device/{key}"),
            PROFILE,
            route!(stack, |s, w, r| {
                let key = r.url_param("key").to_owned();
                v1_set_device(s, w, r, key).await;
            }),
        ),
    );
    mux.delete(
        "/device/{key}",
        stack.v1(
            &at("/device/{key}"),
            PROFILE,
            route!(stack, |s, w, r| {
                let key = r.url_param("key").to_owned();
                v1_delete_device(s, w, r, key).await;
            }),
        ),
    );

    mux.get(
        "/contract",
        stack.v1(
            &at("/contract"),
            &[],
            handler_fn(|w, r| Box::pin(serve_contract_v1(w, r))),
        ),
    );
    mux.get(
        "/manifest",
        stack.v1(
            &at("/manifest"),
            &[],
            handler_fn(|w, r| Box::pin(serve_contract_v1(w, r))),
        ),
    );
    mux.get(
        "/contract/capabilities",
        stack.v1(
            &at("/contract/capabilities"),
            &[],
            handler_fn(|w, _r| Box::pin(serve_capabilities_v1(w))),
        ),
    );
    mux.get(
        "/capability",
        stack.v1(
            &at("/capability"),
            &[],
            handler_fn(|w, _r| Box::pin(serve_capabilities_v1(w))),
        ),
    );

    mux.get(
        "/values",
        stack.v1(
            &at("/values"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let keys = parse_setting_keys(&q1(&query_of(r), "keys"));
                if keys.is_empty() {
                    return write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Query parameter keys is required",
                    )
                    .await;
                }
                let verify = Verifier::v1(&s, r, &claims);
                let identity =
                    match session_identity(&s, &claims, &identity_request(r, &keys[0], verify))
                        .await
                    {
                        Ok(identity) => identity,
                        Err(e) => return write_api(w, &e).await,
                    };
                match list_explicit(&s, &claims, &identity, &keys).await {
                    Ok(values) => {
                        #[derive(Serialize)]
                        struct List {
                            revision: i64,
                            values: Vec<ExplicitView>,
                        }
                        write_v1_json(
                            w,
                            200,
                            &List {
                                revision: contract().revision,
                                values,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    mux.get(
        "/values/effective",
        stack.v1(
            &at("/values/effective"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let query = query_of(r);
                let q = EffectiveQuery {
                    keys: split_csv(&q1(&query, "keys")),
                    active_profile: get_profile_id(r),
                    profile_id: q1(&query, "profile_id"),
                    device_id: q1(&query, "device_id"),
                    device: device_of(r),
                    client_family: String::from_utf8_lossy(r.header.get("X-Silo-Client-Family"))
                        .into_owned(),
                    library_ids: split_csv(&q1(&query, "library_ids"))
                        .iter()
                        .filter_map(|p| atoi(p))
                        .filter(|n| *n > 0)
                        .collect(),
                    series_ids: split_csv(&q1(&query, "series_ids")),
                    verify: Verifier::v1(&s, r, &claims),
                };
                match resolve_effective(&s, r, &claims, q).await {
                    Ok(settings) => {
                        #[derive(Serialize)]
                        struct List {
                            revision: i64,
                            settings: Vec<EffectiveView>,
                        }
                        write_v1_json(
                            w,
                            200,
                            &List {
                                revision: contract().revision,
                                settings,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    mux.post(
        "/values/effective",
        stack.v1(
            &at("/values/effective"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let (bytes, _) = r.read_all().await;
                let body: EffectiveBody = match decode_limited(&bytes, false) {
                    Ok(body) => body,
                    Err(Tail::Decode) => {
                        return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                    }
                    Err(Tail::Trailing) => {
                        return write_v1_error(w, 400, "bad_request", SINGLE_DOCUMENT).await;
                    }
                };
                let keys = unique_trimmed(body.keys);
                let contexts: Vec<ContextRequest> = body
                    .contexts
                    .into_iter()
                    .map(|c| ContextRequest {
                        context_id: trim_space(&c.context_id).to_owned(),
                        library_id: c.library_id.as_bytes().unwrap_or_default().to_vec(),
                        series_id: c.series_id,
                    })
                    .collect();
                let family =
                    String::from_utf8_lossy(r.header.get("X-Silo-Client-Family")).into_owned();
                match resolve_contexts(
                    &s,
                    r,
                    &claims,
                    keys,
                    &get_profile_id(r),
                    device_of(r),
                    &family,
                    &contexts,
                )
                .await
                {
                    Ok(contexts) => {
                        #[derive(Serialize)]
                        struct List {
                            contexts: Vec<ContextView>,
                            revision: i64,
                        }
                        write_v1_json(
                            w,
                            200,
                            &List {
                                contexts,
                                revision: contract().revision,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    mux.put(
        "/values/nav.shortcuts/item",
        stack.v1(
            &at("/values/nav.shortcuts/item"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let (bytes, _) = r.read_all().await;
                let body: ShortcutBody = match decode_limited(&bytes, true) {
                    Ok(body) => body,
                    Err(Tail::Decode) => {
                        return write_v1_error(
                            w,
                            400,
                            "bad_request",
                            "Body must be {\"item\": {…}, \"present\": true|false}",
                        )
                        .await;
                    }
                    Err(Tail::Trailing) => {
                        return write_v1_error(w, 400, "bad_request", SINGLE_DOCUMENT).await;
                    }
                };
                let raw = body.item.as_bytes().unwrap_or_default().to_vec();
                match set_navigation_shortcut(
                    &s,
                    r,
                    &claims,
                    claims.user_id,
                    &get_profile_id(r),
                    &raw,
                    body.present,
                    &mutation_id(r),
                )
                .await
                {
                    Ok(result) => write_mutation_v1(w, result).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    mux.get(
        "/values/{key}",
        stack.v1(
            &at("/values/{key}"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let verify = Verifier::v1(&s, r, &claims);
                let key = r.url_param("key").to_owned();
                let identity =
                    match session_identity(&s, &claims, &identity_request(r, &key, verify)).await {
                        Ok(identity) => identity,
                        Err(e) => return write_api(w, &e).await,
                    };
                match read_value(&s, &claims, &identity).await {
                    Ok(view) => write_v1_json(w, 200, &view).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    mux.put(
        "/values/{key}",
        stack.v1(
            &at("/values/{key}"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let Some(bytes) = read_household_body(w, r).await else {
                    return;
                };
                let verify = Verifier::v1(&s, r, &claims);
                let key = r.url_param("key").to_owned();
                let identity =
                    match session_identity(&s, &claims, &identity_request(r, &key, verify)).await {
                        Ok(identity) => identity,
                        Err(e) => return write_api(w, &e).await,
                    };
                if identity.key == keys::NAV_SHORTCUTS {
                    return write_v1_error(w, 400, "atomic_update_required", NAV_ATOMIC_MESSAGE)
                        .await;
                }
                set_value_at_v1(&s, w, r, &claims, claims.user_id, &identity, &bytes).await;
            }),
        ),
    );

    mux.delete(
        "/values/{key}",
        stack.v1(
            &at("/values/{key}"),
            PROFILE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let verify = Verifier::v1(&s, r, &claims);
                let key = r.url_param("key").to_owned();
                let identity =
                    match session_identity(&s, &claims, &identity_request(r, &key, verify)).await {
                        Ok(identity) => identity,
                        Err(e) => return write_api(w, &e).await,
                    };
                if identity.key == keys::NAV_SHORTCUTS {
                    return write_v1_error(w, 400, "atomic_update_required", NAV_ATOMIC_MESSAGE)
                        .await;
                }
                match clear_setting_value(&s, r, &claims, claims.user_id, &identity).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    mux.get(
        "/{key}",
        stack.v1(
            &at("/{key}"),
            &[],
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let key = r.url_param("key").to_owned();
                if key.is_empty() {
                    return write_v1_error(w, 400, "bad_request", "Setting key is required").await;
                }
                if !uses_user_scope(&key) {
                    return write_v1_error(
                        w,
                        400,
                        "bad_request",
                        &format!("{key} is not a user setting"),
                    )
                    .await;
                }
                let reader = Reader {
                    pool: &s.pool,
                    user_id: claims.user_id as i32,
                };
                match reader.get_setting(&key).await {
                    Err(_) => write_v1_error(w, 500, INTERNAL, "Failed to get setting").await,
                    Ok(value) if value.is_empty() => {
                        write_v1_error(w, 404, "not_found", "Setting not found").await
                    }
                    Ok(value) => {
                        #[derive(Serialize)]
                        struct Item {
                            key: String,
                            value: String,
                        }
                        write_v1_json(w, 200, &Item { key, value }).await;
                    }
                }
            }),
        ),
    );

    mux.put(
        "/{key}",
        stack.v1(
            &at("/{key}"),
            &[],
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let key = r.url_param("key").to_owned();
                if key.is_empty() {
                    return write_v1_error(w, 400, "bad_request", "Setting key is required").await;
                }
                if !uses_user_scope(&key) {
                    return write_v1_error(
                        w,
                        400,
                        "bad_request",
                        &format!("{key} is not a user setting"),
                    )
                    .await;
                }
                let (bytes, _) = r.read_all().await;
                let mut stream = silo_gocompat::json::Decoder::new().stream(&bytes[..]);
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct Body {
                    value: String,
                }
                let Ok(body) = stream.decode::<Body>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                if let Err(e) = validate_registered(&key, &body.value, LegacyScope::User) {
                    return write_v1_error(w, 400, "bad_request", &e).await;
                }
                match sync_legacy_user(&s, claims.user_id, &key, Some(&body.value)).await {
                    Ok(()) => w.write_header(204).await,
                    Err(_) => write_v1_error(w, 500, INTERNAL, "Failed to set setting").await,
                }
            }),
        ),
    );

    mux.delete(
        "/{key}",
        stack.v1(
            &at("/{key}"),
            &[],
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let key = r.url_param("key").to_owned();
                if key.is_empty() {
                    return write_v1_error(w, 400, "bad_request", "Setting key is required").await;
                }
                if !uses_user_scope(&key) {
                    return write_v1_error(
                        w,
                        400,
                        "bad_request",
                        &format!("{key} is not a user setting"),
                    )
                    .await;
                }
                match sync_legacy_user(&s, claims.user_id, &key, None).await {
                    Ok(()) => w.write_header(204).await,
                    Err(_) => write_v1_error(w, 500, INTERNAL, "Failed to delete setting").await,
                }
            }),
        ),
    );

    api_mux.mount("/api/v1/settings", mux);
}

/// `settingValueProblem`.
fn setting_problem(r_fields: &[(&str, &str)], e: &ApiError) -> Problem {
    if e.field.is_empty() || e.status >= 500 {
        return service_problem(e);
    }
    let unknown_key = e.status == 404 && (e.field == FIELD_KEY || e.field == FIELD_KEYS);
    if e.status != 400 && !unknown_key {
        return service_problem(e);
    }
    let location = r_fields
        .iter()
        .find(|(field, _)| *field == e.field)
        .map(|(_, at)| (*at).to_owned())
        .or_else(|| field_location(e.field).map(str::to_owned))
        .unwrap_or_else(|| "body".to_owned());
    Problem::new(
        validation_failed(),
        "The request did not pass validation; see errors.",
    )
    .with_errors([ProblemError {
        location,
        code: "invalid".to_owned(),
        detail: e.message.clone(),
    }])
}

fn field_location(field: &str) -> Option<&'static str> {
    Some(match field {
        FIELD_KEY => "path.key",
        FIELD_KEYS => "query.keys",
        FIELD_SCOPE => "query.scope",
        FIELD_PROFILE_ID => "query.profile_id",
        FIELD_PROFILE_HEADER => "header.X-Profile-Id",
        FIELD_DEVICE_ID => "query.device_id",
        FIELD_DEVICE_HEADER => "header.X-Silo-Device-Id",
        FIELD_CLIENT_FAMILY => "header.X-Silo-Client-Family",
        FIELD_LIBRARY_ID => "query.library_id",
        FIELD_SERIES_ID => "query.series_id",
        FIELD_VALUE => "body.value",
        FIELD_ITEM => "body.item",
        FIELD_PRESENT => "body.present",
        FIELD_CONTEXTS => "body.contexts",
        _ => return None,
    })
}

/// `storedInstant`: `Ok(None)` only for an empty value.
pub(super) fn stored_instant(raw: &str) -> Result<Option<String>, Problem> {
    if raw.is_empty() {
        return Ok(None);
    }
    for layout in [
        silo_gocompat::time::RFC3339_NANO,
        "2006-01-02 15:04:05.999999999-07",
        "2006-01-02 15:04:05.999999999-07:00",
        "2006-01-02 15:04:05.999999999",
    ] {
        if let Ok(t) = silo_gocompat::time::parse(layout, raw) {
            return Ok(Some(t.to_utc().format("2006-01-02T15:04:05.000Z")));
        }
    }
    Err(Problem::new(
        silo_api_v2::problem::internal_error(),
        "An unexpected error occurred.",
    ))
}

/// `intOfID`.
pub(super) fn int_of_id(id: &str) -> Option<i64> {
    atoi(id).filter(|n| *n > 0 && n.to_string() == id)
}

/// `apiv2.SettingValue`.
#[derive(Serialize)]
pub(super) struct V2Value {
    key: String,
    scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    library_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_id: String,
    value: RawMessage,
    revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

fn id_or_empty(n: i64) -> String {
    if n == 0 { String::new() } else { n.to_string() }
}

/// `settingValueOf`.
pub(super) fn v2_value(v: ValueView) -> Result<V2Value, Problem> {
    Ok(V2Value {
        updated_at: stored_instant(&v.updated_at)?,
        key: v.key,
        scope: v.scope,
        profile_id: v.profile_id,
        client_family: v.client_family,
        device_id: v.device_id,
        library_id: id_or_empty(v.library_id),
        series_id: v.series_id,
        value: if v.value.is_empty() {
            RawMessage::nil()
        } else {
            v.value
        },
        revision: v.revision,
    })
}

pub(super) async fn write_value_v2(w: &mut dyn ResponseWriter, r: &Request, v: ValueView) {
    match v2_value(v) {
        Ok(value) => write_v2_json(w, &value).await,
        Err(p) => write_problem(w, r, p).await,
    }
}

/// `apiv2.ExplicitSettingValue`.
#[derive(Serialize)]
struct V2Explicit {
    key: String,
    scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    library_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_id: String,
    is_set: bool,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    value: RawMessage,
    #[serde(skip_serializing_if = "is_zero")]
    revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

/// `apiv2.SettingSourceContext`.
#[derive(Serialize)]
struct V2SourceContext {
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    library_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_id: String,
}

/// `apiv2.SettingConstraint`.
#[derive(Serialize)]
struct V2Constraint {
    policy_input: String,
    constraint: String,
}

/// `apiv2.EffectiveSettingValue`.
#[derive(Serialize)]
struct V2Effective {
    key: String,
    value: RawMessage,
    source: String,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    stored_value: RawMessage,
    #[serde(skip_serializing_if = "is_false")]
    constrained: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    constraint_kind: String,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    requested_value: RawMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    constrained_by: Option<V2Constraint>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    permitted_values: Vec<RawMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    suggested_values: Vec<String>,
    definition_revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_context: Option<V2SourceContext>,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_family: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    library_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_id: String,
}

fn v2_effective(views: Vec<EffectiveView>) -> Result<Vec<V2Effective>, Problem> {
    views
        .into_iter()
        .map(|v| {
            Ok(V2Effective {
                updated_at: stored_instant(&v.updated_at)?,
                key: v.key,
                value: v.value,
                source: v.source,
                stored_value: v.stored_value,
                constrained: v.constrained,
                constraint_kind: v.constraint_kind,
                requested_value: v.requested_value,
                constrained_by: v.constrained_by.map(|c| V2Constraint {
                    policy_input: c.policy_input,
                    constraint: c.constraint.as_str().to_owned(),
                }),
                permitted_values: v.permitted_values,
                suggested_values: v.suggested_values,
                definition_revision: v.definition_revision,
                source_context: v.source_context.map(|c| V2SourceContext {
                    profile_id: c.profile_id,
                    client_family: c.client_family,
                    device_id: c.device_id,
                    library_id: id_or_empty(c.library_id),
                    series_id: c.series_id,
                }),
                scope: v.scope,
                profile_id: v.profile_id,
                client_family: v.client_family,
                device_id: v.device_id,
                library_id: id_or_empty(v.library_id),
                series_id: v.series_id,
            })
        })
        .collect()
}

/// `apiv2.EffectiveSubtitleAppearance`.
#[derive(Serialize)]
struct V2Subtitle {
    key: &'static str,
    profile_id: String,
    global_value: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_value: String,
    effective_value: String,
    has_device_override: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

async fn write_subtitle_v2(w: &mut dyn ResponseWriter, r: &Request, v: SubtitleView) {
    let updated_at = match stored_instant(&v.updated_at) {
        Ok(t) => t,
        Err(p) => return write_problem(w, r, p).await,
    };
    write_v2_json(
        w,
        &V2Subtitle {
            key: v.key,
            profile_id: v.profile_id,
            global_value: v.global_value,
            device_value: v.device_value,
            effective_value: v.effective_value,
            has_device_override: v.has_device_override,
            device_id: v.device_id,
            device_name: v.device_name,
            device_platform: v.device_platform,
            updated_at,
        },
    )
    .await;
}

/// `deviceSettingProblem`.
fn device_problem(e: &ApiError) -> Problem {
    if e.field.is_empty() {
        return service_problem(e);
    }
    let location = if e.field == FIELD_DEVICE_ID {
        "header.X-Silo-Device-Id".to_owned()
    } else {
        format!("body.{}", e.field)
    };
    Problem::new(
        validation_failed(),
        "The request did not pass validation; see errors.",
    )
    .with_errors([ProblemError {
        location,
        code: "invalid".to_owned(),
        detail: e.message.clone(),
    }])
}

fn raw_body(r: &Request) -> Vec<u8> {
    r.extensions
        .get::<RawBody>()
        .map(|b| b.0.clone())
        .unwrap_or_default()
}

fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/settings/contract";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            handler_fn(|w, r| {
                Box::pin(async move {
                    let (Ok(body), Ok(etag)) =
                        (canonical::public_bytes(), canonical::public_etag())
                    else {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                silo_api_v2::problem::internal_error(),
                                "An unexpected error occurred.",
                            ),
                        )
                        .await;
                    };
                    let h = w.header();
                    h.set("Cache-Control", "private, no-cache");
                    h.set("Content-Type", "application/json");
                    h.set("ETag", etag);
                    w.write_header(200).await;
                    let _ = w.write(&body).await;
                })
            }),
        ),
    );

    let path = "/api/v2/settings/contract/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            handler_fn(|w, r| {
                Box::pin(async move {
                    let Ok(etag) = canonical::public_etag() else {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                silo_api_v2::problem::internal_error(),
                                "An unexpected error occurred.",
                            ),
                        )
                        .await;
                    };
                    #[derive(Serialize)]
                    struct Capabilities<'a> {
                        revision: &'a str,
                        state: &'a str,
                        allowed: bool,
                        api_version: i64,
                        manifest_revision: i64,
                        contract_etag: &'a str,
                        definition_count: usize,
                        scopes: [&'a str; 6],
                        client_families: [&'a str; 5],
                        supports_batched_effective: bool,
                        supports_idempotent_writes: bool,
                        supports_atomic_shortcuts: bool,
                        supports_device_rename: bool,
                    }
                    let m = contract();
                    let render = |revision: &str| {
                        super::chain::capability_json(&Capabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            api_version: m.api_version,
                            manifest_revision: m.revision,
                            contract_etag: &etag,
                            definition_count: m.definitions.len(),
                            scopes: SCOPES,
                            client_families: FAMILIES,
                            supports_batched_effective: true,
                            supports_idempotent_writes: true,
                            supports_atomic_shortcuts: true,
                            supports_device_rename: true,
                        })
                    };
                    super::chain::write_capability(w, r, "getSettingsContractCapabilities", render)
                        .await;
                })
            }),
        ),
    );

    let path = "/api/v2/settings/overlay-config";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            route!(stack, |s, w, _r| {
                let view = overlay_config(&s).await;
                w.header().set("Cache-Control", "private, no-cache");
                write_v2_json(w, &view).await;
            }),
        ),
    );

    let path = "/api/v2/settings/subtitle-appearance/effective";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                match effective_subtitle(&s, &claims, &get_profile_id(r), &device_of(r)).await {
                    Ok(view) => write_subtitle_v2(w, r, view).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/settings/device/subtitle-appearance";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_PROFILE_WRITE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct Body {
                    value: String,
                }
                let body: Body = unmarshal(&raw_body(r)).unwrap_or_default();
                let profile = get_profile_id(r);
                let device = device_of(r);
                if let Err(e) = set_device(
                    &s,
                    &claims,
                    &profile,
                    &device,
                    SUBTITLE_APPEARANCE,
                    &body.value,
                )
                .await
                {
                    return write_problem(w, r, device_problem(&e)).await;
                }
                match effective_subtitle(&s, &claims, &profile, &device).await {
                    Ok(view) => write_subtitle_v2(w, r, view).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_PROFILE_WRITE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                match delete_device(
                    &s,
                    &claims,
                    &get_profile_id(r),
                    &device_of(r),
                    SUBTITLE_APPEARANCE,
                )
                .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, device_problem(&e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/settings/values";
    v2.get(path, stack.v2(path, V2Class::ProfileScoped, route!(stack, |s, w, r| {
        let claims = claims!(r);
        let query = query_of(r);
        let mut keys: Vec<String> = query.get("keys").cloned().unwrap_or_default();
        keys = keys.into_iter().map(|k| trim_space(&k).to_owned()).filter(|k| !k.is_empty()).collect();
        let overrides: &[(&str, &str)] = &[(FIELD_KEY, "query.keys")];
        if keys.is_empty() {
            return write_problem(w, r, setting_problem(overrides, &field_error(FIELD_KEYS, "Query parameter keys is required"))).await;
        }
        let verify = Verifier::v2(r);
        let identity = match session_identity(&s, &claims, &identity_request(r, &keys[0], verify)).await {
            Ok(identity) => identity,
            Err(mut e) => {
                if e.field == FIELD_KEY {
                    e.field = FIELD_KEYS;
                }
                return write_problem(w, r, setting_problem(overrides, &e)).await;
            }
        };
        let views = match list_explicit(&s, &claims, &identity, &keys).await {
            Ok(views) => views,
            Err(e) => return write_problem(w, r, setting_problem(overrides, &e)).await,
        };
        let mut budget = MAX_RESPONSE_VALUE_BYTES;
        for view in &views {
            budget -= view.value.as_bytes().map_or(0, |b| b.len() as i64);
            if budget < 0 {
                let e = field_error(FIELD_KEYS, "The requested values are too large for one response; request fewer keys");
                return write_problem(w, r, setting_problem(overrides, &e)).await;
            }
        }
        let mut items = Vec::with_capacity(views.len());
        for v in views {
            let updated_at = match stored_instant(&v.updated_at) {
                Ok(t) => t,
                Err(p) => return write_problem(w, r, p).await,
            };
            items.push(V2Explicit {
                key: v.key,
                scope: v.scope,
                profile_id: v.profile_id,
                client_family: v.client_family,
                device_id: v.device_id,
                library_id: id_or_empty(v.library_id),
                series_id: v.series_id,
                is_set: v.is_set,
                value: v.value,
                revision: v.revision,
                updated_at,
            });
        }
        #[derive(Serialize)]
        struct List { items: Vec<V2Explicit>, revision: i64 }
        write_v2_json(w, &List { items, revision: contract().revision }).await;
    })));

    let path = "/api/v2/settings/values/effective";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let query = query_of(r);
                let mut library_ids = Vec::new();
                for id in query.get("library_ids").into_iter().flatten() {
                    match int_of_id(id) {
                        Some(n) => library_ids.push(n),
                        None => {
                            let problem = Problem::new(
                                validation_failed(),
                                "The request did not pass validation; see errors.",
                            )
                            .with_errors([ProblemError {
                                location: "query.library_ids".to_owned(),
                                code: "invalid".to_owned(),
                                detail: "library_ids must name libraries by id".to_owned(),
                            }]);
                            return write_problem(w, r, problem).await;
                        }
                    }
                }
                let q = EffectiveQuery {
                    keys: query.get("keys").cloned().unwrap_or_default(),
                    active_profile: get_profile_id(r),
                    profile_id: q1(&query, "profile_id"),
                    device_id: q1(&query, "device_id"),
                    device: device_of(r),
                    client_family: String::from_utf8_lossy(r.header.get("X-Silo-Client-Family"))
                        .into_owned(),
                    library_ids,
                    series_ids: query.get("series_ids").cloned().unwrap_or_default(),
                    verify: Verifier::v2(r),
                };
                let overrides: &[(&str, &str)] = &[
                    (FIELD_LIBRARY_ID, "query.library_ids"),
                    (FIELD_SERIES_ID, "query.series_ids"),
                ];
                let views = match resolve_effective(&s, r, &claims, q).await {
                    Ok(views) => views,
                    Err(e) => return write_problem(w, r, setting_problem(overrides, &e)).await,
                };
                let items = match v2_effective(views) {
                    Ok(items) => items,
                    Err(p) => return write_problem(w, r, p).await,
                };
                #[derive(Serialize)]
                struct List {
                    items: Vec<V2Effective>,
                    revision: i64,
                }
                write_v2_json(
                    w,
                    &List {
                        items,
                        revision: contract().revision,
                    },
                )
                .await;
            }),
        ),
    );
    v2.post(path, stack.v2(path, V2Class::ProfileScoped, route!(stack, |s, w, r| {
        let claims = claims!(r);
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Ctx { context_id: String, library_id: String, series_id: String }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Body { keys: Vec<String>, contexts: Vec<Ctx> }
        let body: Body = unmarshal(&raw_body(r)).unwrap_or_default();
        let contexts: Vec<ContextRequest> = body.contexts.into_iter().map(|c| ContextRequest {
            context_id: c.context_id,
            library_id: if c.library_id.is_empty() { Vec::new() } else { silo_gocompat::json::marshal(&c.library_id).unwrap_or_default() },
            series_id: c.series_id,
        }).collect();
        let family = String::from_utf8_lossy(r.header.get("X-Silo-Client-Family")).into_owned();
        let overrides: &[(&str, &str)] = &[(FIELD_KEYS, "body.keys")];
        let views = match resolve_contexts(&s, r, &claims, body.keys, &get_profile_id(r), device_of(r), &family, &contexts).await {
            Ok(views) => views,
            Err(e) => return write_problem(w, r, setting_problem(overrides, &e)).await,
        };
        let mut budget = MAX_RESPONSE_VALUE_BYTES;
        for view in &views {
            for setting in &view.settings {
                budget -= [&setting.value, &setting.stored_value, &setting.requested_value]
                    .iter()
                    .map(|m| m.as_bytes().map_or(0, |b| b.len() as i64))
                    .sum::<i64>();
                if budget < 0 {
                    let e = field_error(FIELD_KEYS, "The requested values are too large for one response; request fewer keys or contexts");
                    return write_problem(w, r, setting_problem(overrides, &e)).await;
                }
            }
        }
        #[derive(Serialize)]
        struct Item { context_id: String, settings: Vec<V2Effective> }
        let mut items = Vec::with_capacity(views.len());
        for view in views {
            let settings = match v2_effective(view.settings) {
                Ok(settings) => settings,
                Err(p) => return write_problem(w, r, p).await,
            };
            items.push(Item { context_id: view.context_id, settings });
        }
        #[derive(Serialize)]
        struct List { items: Vec<Item>, revision: i64 }
        write_v2_json(w, &List { items, revision: contract().revision }).await;
    })));

    let path = "/api/v2/settings/values/nav.shortcuts/item";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_PROFILE_WRITE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let body: ShortcutBody = unmarshal(&raw_body(r)).unwrap_or_default();
                let raw = body.item.as_bytes().unwrap_or_default().to_vec();
                match set_navigation_shortcut(
                    &s,
                    r,
                    &claims,
                    claims.user_id,
                    &get_profile_id(r),
                    &raw,
                    Some(body.present.unwrap_or(false)),
                    "",
                )
                .await
                {
                    Ok(result) => {
                        if let Some(view) = result.view {
                            write_value_v2(w, r, view).await;
                        }
                    }
                    Err(e) => write_problem(w, r, setting_problem(&[], &e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/settings/values/{key}";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let key = r.url_param("key").to_owned();
                let identity = match session_identity(
                    &s,
                    &claims,
                    &identity_request(r, &key, Verifier::v2(r)),
                )
                .await
                {
                    Ok(identity) => identity,
                    Err(e) => return write_problem(w, r, setting_problem(&[], &e)).await,
                };
                match read_value(&s, &claims, &identity).await {
                    Ok(view) => write_value_v2(w, r, view).await,
                    Err(e) => write_problem(w, r, setting_problem(&[], &e)).await,
                }
            }),
        ),
    );
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_PROFILE_WRITE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let key = r.url_param("key").to_owned();
                let identity = match session_identity(
                    &s,
                    &claims,
                    &identity_request(r, &key, Verifier::v2(r)),
                )
                .await
                {
                    Ok(identity) => identity,
                    Err(e) => return write_problem(w, r, setting_problem(&[], &e)).await,
                };
                if identity.key == keys::NAV_SHORTCUTS {
                    let e = coded_field(
                        400,
                        "atomic_update_required",
                        FIELD_KEY,
                        NAV_ATOMIC_MESSAGE.to_owned(),
                    );
                    return write_problem(w, r, setting_problem(&[], &e)).await;
                }
                let body: ValueBody = unmarshal(&raw_body(r)).unwrap_or_default();
                let raw = body.value.as_bytes().unwrap_or_default().to_vec();
                match write_setting_value(
                    &s,
                    r,
                    &claims,
                    claims.user_id,
                    &identity,
                    &raw,
                    "",
                    &device_of(r),
                )
                .await
                {
                    Ok(result) => {
                        if let Some(view) = result.view {
                            write_value_v2(w, r, view).await;
                        }
                    }
                    Err(e) => write_problem(w, r, setting_problem(&[], &e)).await,
                }
            }),
        ),
    );
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_PROFILE_WRITE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let key = r.url_param("key").to_owned();
                let identity = match session_identity(
                    &s,
                    &claims,
                    &identity_request(r, &key, Verifier::v2(r)),
                )
                .await
                {
                    Ok(identity) => identity,
                    Err(e) => return write_problem(w, r, setting_problem(&[], &e)).await,
                };
                if identity.key == keys::NAV_SHORTCUTS {
                    let e = coded_field(
                        400,
                        "atomic_update_required",
                        FIELD_KEY,
                        NAV_ATOMIC_MESSAGE.to_owned(),
                    );
                    return write_problem(w, r, setting_problem(&[], &e)).await;
                }
                match clear_setting_value(&s, r, &claims, claims.user_id, &identity).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, setting_problem(&[], &e)).await,
                }
            }),
        ),
    );
}

/// Registers this domain's handlers.
pub fn mount(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    mount_v1(stack, api_mux);
    mount_v2(stack, v2);
}
