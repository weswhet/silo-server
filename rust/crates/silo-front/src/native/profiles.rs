//! The profiles domain: `profiles.go`, `profiles_settings_sync.go`, `profiles_audit.go`, the read side of
//! `profile_avatars.go`, and v2 `profiles.go`.
//!
//! Deleting a profile, uploading or clearing an avatar, and the household session list stay on Go: they
//! reach the request, watchlist, blob, and playback domains.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use silo_api_v2::problem::{Problem, ProblemError, type_for_status, validation_failed};
use silo_auth::audit::{self, AuditRequest};
use silo_auth::claims::Claims;
use silo_config::resolve::{Constraints, SettingIdentity};
use silo_config::settings::{Scope, keys, load, mirror};
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::json::unmarshal;
use silo_gocompat::strings::{equal_fold, trim_space};
use silo_gocompat::time::GoTime;
use silo_http::chi::Mux;
use silo_http::{Request, ResponseWriter, handler_fn};
use silo_store::userstore::pgstore::{Error as StoreError, PostgresUserStore};
use silo_store::userstore::prefs::{NewProfile, UpdateProfileInput, Writer};
use silo_store::userstore::profiles::{self, Profile};

use super::auth::{ApiError, service_problem, write_v1_error};
use super::chain::{
    Stack, Step, V2Class, write_problem, write_v1_json, write_v2_json, write_v2_json_status,
};
use super::huma::{RawBody, reject_nulls_except};
use super::settings::{
    HouseholdError, Verifier, api, contract, field_error, household_manager, int_of_id,
    mark_profile_stale, plan_legacy_runtime, publish_user_settings, stored_instant, write_api,
    write_canonical_sync,
};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/profiles/"),
    NativeRow::new(ApiV1, "POST", "/api/v1/profiles/"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/profiles/{id}"),
    NativeRow::new(ApiV1, "POST", "/api/v1/profiles/{id}/verify-pin"),
    NativeRow::new(ApiV2, "GET", "/api/v2/profiles"),
    NativeRow::new(ApiV2, "POST", "/api/v2/profiles"),
    NativeRow::new(ApiV2, "PATCH", "/api/v2/profiles/{id}"),
    NativeRow::new(ApiV2, "POST", "/api/v2/profiles/{id}/verify-pin"),
];

const V1_GROUP: &[Step] = &[Step::Auth, Step::Demo, Step::RateLimit, Step::Viewer];
const V2_MUTATE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
];
const CODE_MANAGEMENT: &str = "profile_management";
const INTERNAL: &str = "internal_error";
const LEGACY_AVATARS: [&str; 8] = [
    "avatar-1", "avatar-2", "avatar-3", "avatar-4", "avatar-5", "avatar-6", "avatar-7", "avatar-8",
];
const DICEBEAR_STYLES: [&str; 5] = [
    "identicon",
    "initials",
    "bottts-neutral",
    "fun-emoji",
    "pixel-art-neutral",
];
const AVATAR_TTL: Duration = Duration::from_secs(15 * 60);

/// `parseDiceBearPresetID`.
fn dicebear(id: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = id.split(':').collect();
    if parts.len() != 3 || parts[0] != "dicebear" {
        return None;
    }
    let style = trim_space(parts[1]);
    let seed = trim_space(parts[2]);
    if !DICEBEAR_STYLES.contains(&style) {
        return None;
    }
    let safe = !seed.is_empty()
        && seed.len() <= 64
        && seed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    safe.then(|| (style.to_owned(), seed.to_owned()))
}

fn known_preset(id: &str) -> bool {
    LEGACY_AVATARS.contains(&id) || dicebear(id).is_some()
}

/// `normalizePresetAvatarReference`.
fn normalize_preset(raw: &str) -> Result<String, String> {
    let value = trim_space(raw);
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.starts_with("upload:") {
        return Err(
            "custom upload avatar references are not allowed in JSON profile updates".to_owned(),
        );
    }
    let id = value.strip_prefix("preset:").unwrap_or(value);
    if !known_preset(id) {
        return Err("unknown avatar preset".to_owned());
    }
    Ok(format!("preset:{id}"))
}

/// `bundledProfileAvatarURL`.
fn bundled_url(id: &str) -> String {
    if let Some((style, seed)) = dicebear(id) {
        // `url.Values.Encode` sorts by key.
        return format!(
            "https://api.dicebear.com/9.x/{style}/svg?backgroundType=gradientLinear&radius=24&seed={}&size=128",
            silo_gocompat::url::query_escape(seed)
        );
    }
    format!("/profile-avatars/{id}.svg")
}

/// `Signer.SignFor` for a mutable key, over the local store's server resolver. `ttl` is clamped as `clampTTL` does.
pub(super) fn sign_artwork(secret: &str, key: &str, ttl: Duration) -> String {
    type H = Hmac<Sha256>;
    let derive = |key_bytes: &[u8], data: &[u8]| -> Vec<u8> {
        let mut h = H::new_from_slice(key_bytes).expect("HMAC takes any key");
        h.update(data);
        h.finalize().into_bytes().to_vec()
    };
    let signing = derive(secret.as_bytes(), b"silo-artwork-url-v1");
    let ttl = ttl.as_secs().clamp(60, 86_400) as i64;
    let bucket = ttl.min(AVATAR_TTL.as_secs() as i64);
    let now = GoTime::now_utc().to_system_time();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // `Time.Truncate` counts from Go's zero time, 62135596800 seconds before the Unix epoch.
    let since_zero = secs + 62_135_596_800;
    let exp = secs - since_zero.rem_euclid(bucket) + bucket + ttl;
    let signature = derive(&signing, format!("artwork-v1\n{key}\n{exp}").as_bytes());
    let sig = base64_url(&signature[..16]);
    let path: String = key
        .trim_start_matches('/')
        .split('/')
        .map(silo_gocompat::url::path_escape)
        .collect::<Vec<_>>()
        .join("/");
    format!("/api/v2/artwork/{path}?exp={exp}&sig={sig}")
}

fn base64_url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        }
    }
    out
}

/// `resolveProfileAvatar`.
pub(super) fn resolve_avatar(s: &Stack, reference: &str) -> (&'static str, String) {
    let trimmed = trim_space(reference);
    if trimmed.is_empty() {
        return ("none", String::new());
    }
    if let Some(id) = trimmed.strip_prefix("preset:") {
        if !known_preset(id) {
            return ("none", String::new());
        }
        return ("preset", bundled_url(id));
    }
    if let Some(original) = trimmed.strip_prefix("upload:") {
        let display = match original.strip_suffix("/original.webp") {
            Some(base) => format!("{base}/w256.webp"),
            None => format!("{}/w256.webp", original.trim_end_matches('/')),
        };
        return (
            "upload",
            sign_artwork(&s.artwork_secret, &display, AVATAR_TTL),
        );
    }
    if known_preset(trimmed) {
        return ("preset", bundled_url(trimmed));
    }
    ("none", String::new())
}

/// `profilePreferences`.
#[derive(Clone, Default)]
struct Preferences {
    audio_language: String,
    metadata_language: String,
    subtitle_language: String,
    subtitle_mode: String,
    show_forced_subtitles: bool,
}

const PREFERENCE_KEYS: [&str; 5] = [
    keys::PLAYBACK_AUDIO_LANGUAGE,
    keys::CATALOG_METADATA_LANGUAGE,
    keys::PLAYBACK_SUBTITLE_LANGUAGE,
    keys::PLAYBACK_SUBTITLE_MODE,
    keys::PLAYBACK_SHOW_FORCED_SUBTITLES,
];

fn apply_preference(prefs: &mut Preferences, key: &str, value: &[u8]) {
    let set_string = |target: &mut String| {
        if let Ok(decoded) = unmarshal::<Option<String>>(value) {
            *target = trim_space(&decoded.unwrap_or_default()).to_owned();
        }
    };
    match key {
        keys::PLAYBACK_AUDIO_LANGUAGE => set_string(&mut prefs.audio_language),
        keys::CATALOG_METADATA_LANGUAGE => set_string(&mut prefs.metadata_language),
        keys::PLAYBACK_SUBTITLE_LANGUAGE => set_string(&mut prefs.subtitle_language),
        keys::PLAYBACK_SUBTITLE_MODE => set_string(&mut prefs.subtitle_mode),
        keys::PLAYBACK_SHOW_FORCED_SUBTITLES => {
            if let Ok(forced) = unmarshal::<bool>(value) {
                prefs.show_forced_subtitles = forced;
            }
        }
        _ => {}
    }
}

fn default_preferences() -> Preferences {
    let mut prefs = Preferences::default();
    for key in PREFERENCE_KEYS {
        if let Some(def) = contract().lookup(key) {
            apply_preference(&mut prefs, key, &def.default_value);
        }
    }
    prefs
}

/// `resolveProfilePreferences`.
async fn resolve_preferences(
    s: &Stack,
    user_id: i64,
    ids: &[String],
) -> HashMap<String, Preferences> {
    let defaults = default_preferences();
    let mut out: HashMap<String, Preferences> = ids
        .iter()
        .map(|id| (id.clone(), defaults.clone()))
        .collect();
    if ids.is_empty() {
        return out;
    }
    let store = PostgresUserStore::new(s.pool.clone(), user_id);
    let keys: Vec<String> = PREFERENCE_KEYS.iter().map(|k| (*k).to_owned()).collect();
    match silo_config::resolve::Resolver::new(contract())
        .resolve_profiles(&store, ids, &keys, &Constraints::new())
        .await
    {
        Err(e) => {
            tracing::warn!(component = "api", profiles = ids.len(), error = %e, "profile preferences degraded to contract defaults: reading setting values failed");
        }
        Ok(resolved) => {
            for (id, effective) in resolved {
                let mut prefs = defaults.clone();
                for eff in effective {
                    apply_preference(
                        &mut prefs,
                        &eff.key,
                        eff.value.as_bytes().unwrap_or_default(),
                    );
                }
                out.insert(id, prefs);
            }
        }
    }
    out
}

/// `handlers.ProfileView`, as v1 serializes it.
#[derive(Clone, Serialize)]
struct V1Profile {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    avatar: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    avatar_url: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    avatar_source: &'static str,
    has_pin: bool,
    is_child: bool,
    is_primary: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    max_content_rating: String,
    #[serde(skip)]
    max_advisory_age: i32,
    #[serde(skip)]
    require_advisory_age: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    quality_preference: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    language: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    preferred_metadata_language: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    subtitle_language: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    subtitle_mode: String,
    auto_skip_intro: bool,
    auto_skip_credits: bool,
    auto_skip_recap: bool,
    auto_play_next_preview: bool,
    show_forced_subtitles: bool,
    library_restrictions_enabled: bool,
    allowed_library_ids: Option<Vec<i32>>,
    max_playback_quality: String,
    created_at: String,
    updated_at: String,
}

fn view_of(s: &Stack, p: &Profile, prefs: &Preferences) -> V1Profile {
    let (source, url) = resolve_avatar(s, &p.avatar);
    V1Profile {
        id: p.id.clone(),
        name: p.name.clone(),
        avatar: p.avatar.clone(),
        avatar_url: url,
        avatar_source: source,
        has_pin: !p.pin_hash.is_empty(),
        is_child: p.is_child,
        is_primary: p.is_primary,
        max_content_rating: p.max_content_rating.clone(),
        max_advisory_age: p.max_advisory_age,
        require_advisory_age: p.require_advisory_age,
        quality_preference: p.quality_preference.clone(),
        language: prefs.audio_language.clone(),
        preferred_metadata_language: prefs.metadata_language.clone(),
        subtitle_language: prefs.subtitle_language.clone(),
        subtitle_mode: prefs.subtitle_mode.clone(),
        auto_skip_intro: p.auto_skip_intro,
        auto_skip_credits: p.auto_skip_credits,
        auto_skip_recap: p.auto_skip_recap,
        auto_play_next_preview: p.auto_play_next_preview,
        show_forced_subtitles: prefs.show_forced_subtitles,
        library_restrictions_enabled: p.library_restrictions_enabled,
        // `append([]int(nil), ...)`: nil stays null.
        allowed_library_ids: (!p.allowed_library_ids.is_empty())
            .then(|| p.allowed_library_ids.clone()),
        max_playback_quality: silo_gate::mw::viewer::normalize_playback_quality(
            &p.max_playback_quality,
        ),
        created_at: p.created_at.clone(),
        updated_at: p.updated_at.clone(),
    }
}

async fn one_view(s: &Stack, user_id: i64, p: &Profile) -> V1Profile {
    let prefs = resolve_preferences(s, user_id, std::slice::from_ref(&p.id)).await;
    view_of(s, p, &prefs[&p.id])
}

/// `apiv2.Profile`.
#[derive(Serialize)]
struct V2Profile {
    id: String,
    name: String,
    avatar: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    avatar_url: String,
    avatar_source: &'static str,
    has_pin: bool,
    is_child: bool,
    is_primary: bool,
    max_content_rating: String,
    max_advisory_age: Option<i32>,
    require_advisory_age: bool,
    quality_preference: String,
    language: String,
    preferred_metadata_language: String,
    subtitle_language: String,
    subtitle_mode: String,
    auto_skip_intro: bool,
    auto_skip_credits: bool,
    auto_skip_recap: bool,
    auto_play_next_preview: bool,
    show_forced_subtitles: bool,
    library_restrictions_enabled: bool,
    allowed_library_ids: Vec<String>,
    max_playback_quality: String,
    created_at: String,
    updated_at: String,
}

fn v2_profile(v: V1Profile) -> Result<V2Profile, Problem> {
    let instant = |raw: &str| -> Result<String, Problem> {
        match silo_gocompat::time::parse(silo_gocompat::time::RFC3339_NANO, raw) {
            Ok(t) => Ok(t.to_utc().format("2006-01-02T15:04:05.000Z")),
            Err(_) => Err(Problem::new(
                silo_api_v2::problem::internal_error(),
                "An unexpected error occurred.",
            )),
        }
    };
    let _ = stored_instant;
    Ok(V2Profile {
        created_at: instant(&v.created_at)?,
        updated_at: instant(&v.updated_at)?,
        id: v.id,
        name: v.name,
        avatar: v.avatar,
        avatar_url: v.avatar_url,
        avatar_source: v.avatar_source,
        has_pin: v.has_pin,
        is_child: v.is_child,
        is_primary: v.is_primary,
        max_content_rating: v.max_content_rating,
        max_advisory_age: (v.max_advisory_age > 0).then_some(v.max_advisory_age),
        require_advisory_age: v.require_advisory_age,
        quality_preference: v.quality_preference,
        language: v.language,
        preferred_metadata_language: v.preferred_metadata_language,
        subtitle_language: v.subtitle_language,
        subtitle_mode: v.subtitle_mode,
        auto_skip_intro: v.auto_skip_intro,
        auto_skip_credits: v.auto_skip_credits,
        auto_skip_recap: v.auto_skip_recap,
        auto_play_next_preview: v.auto_play_next_preview,
        show_forced_subtitles: v.show_forced_subtitles,
        library_restrictions_enabled: v.library_restrictions_enabled,
        allowed_library_ids: v
            .allowed_library_ids
            .unwrap_or_default()
            .iter()
            .map(i32::to_string)
            .collect(),
        max_playback_quality: v.max_playback_quality,
    })
}

/// `ProfileCreateRequest`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct CreateRequest {
    name: String,
    avatar: String,
    pin: String,
    is_child: bool,
    max_content_rating: String,
    #[serde(skip)]
    max_advisory_age: i32,
    #[serde(skip)]
    require_advisory_age: bool,
    quality_preference: String,
    language: String,
    preferred_metadata_language: String,
    subtitle_language: String,
    subtitle_mode: String,
    auto_skip_intro: bool,
    auto_skip_credits: bool,
    auto_skip_recap: bool,
    auto_play_next_preview: bool,
    show_forced_subtitles: Option<bool>,
    library_restrictions_enabled: bool,
    allowed_library_ids: Vec<i64>,
    max_playback_quality: String,
}

/// `ProfileUpdateRequest`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct UpdateRequest {
    name: Option<String>,
    avatar: Option<String>,
    pin: Option<String>,
    is_child: Option<bool>,
    max_content_rating: Option<String>,
    #[serde(skip)]
    max_advisory_age: Option<i32>,
    #[serde(skip)]
    require_advisory_age: Option<bool>,
    quality_preference: Option<String>,
    language: Option<String>,
    preferred_metadata_language: Option<String>,
    subtitle_language: Option<String>,
    subtitle_mode: Option<String>,
    auto_skip_intro: Option<bool>,
    auto_skip_credits: Option<bool>,
    auto_skip_recap: Option<bool>,
    auto_play_next_preview: Option<bool>,
    show_forced_subtitles: Option<bool>,
    library_restrictions_enabled: Option<bool>,
    allowed_library_ids: Option<Vec<i64>>,
    max_playback_quality: Option<String>,
}

pub(super) type Sync = (String, Option<String>);

pub(super) fn string_sync(out: &mut Vec<Sync>, key: &str, raw: Option<&str>) -> Result<(), String> {
    let Some(raw) = raw else {
        return Ok(());
    };
    let trimmed = trim_space(raw);
    if trimmed.is_empty() {
        out.push((key.to_owned(), None));
        return Ok(());
    }
    let encoded = silo_gocompat::json::marshal(trimmed).map_err(|e| format!("{key}: {e}"))?;
    let def = contract()
        .lookup(key)
        .ok_or_else(|| format!("{key} has no contract definition"))?;
    let schemas = load::object_schemas().ok_or("loading the settings contract: not loaded")?;
    let normalized = def
        .value_schema
        .normalize_value(&encoded, schemas)
        .map_err(|e| format!("{key}: {e}"))?;
    out.push((
        key.to_owned(),
        Some(String::from_utf8_lossy(&normalized).into_owned()),
    ));
    Ok(())
}

/// `planProfileSettingsSync`.
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_sync(
    audio: Option<&str>,
    subtitle: Option<&str>,
    metadata: Option<&str>,
    mode: Option<&str>,
    forced: Option<bool>,
    intro: Option<bool>,
    credits: Option<bool>,
    recap: Option<bool>,
    preview: Option<bool>,
) -> Result<Vec<Sync>, String> {
    let mut out = Vec::new();
    string_sync(&mut out, keys::PLAYBACK_AUDIO_LANGUAGE, audio)?;
    string_sync(&mut out, keys::PLAYBACK_SUBTITLE_LANGUAGE, subtitle)?;
    string_sync(&mut out, keys::CATALOG_METADATA_LANGUAGE, metadata)?;
    string_sync(&mut out, keys::PLAYBACK_SUBTITLE_MODE, mode)?;
    for (key, value) in [
        (keys::PLAYBACK_SHOW_FORCED_SUBTITLES, forced),
        (keys::PLAYBACK_AUTO_SKIP_INTRO, intro),
        (keys::PLAYBACK_AUTO_SKIP_CREDITS, credits),
        (keys::PLAYBACK_AUTO_SKIP_RECAP, recap),
        (keys::PLAYBACK_AUTO_PLAY_NEXT_PREVIEW, preview),
    ] {
        let Some(value) = value else {
            continue;
        };
        let text = if value { "true" } else { "false" };
        out.push((key.to_owned(), Some(text.to_owned())));
        if let Some(companion) =
            mirror::mirror_write(key, text.as_bytes()).map_err(|e| format!("{key}: {e}"))?
        {
            out.push((
                companion.key.to_owned(),
                Some(String::from_utf8_lossy(&companion.value).into_owned()),
            ));
        }
    }
    Ok(out)
}

/// `profileAuditValues`.
fn audit_values(p: &Profile) -> BTreeMap<&'static str, String> {
    let json = |v: &dyn erased::Encode| v.encode();
    let mut out = BTreeMap::new();
    out.insert("name", json(&trim_space(&p.name).to_owned()));
    out.insert("is_child", json(&p.is_child));
    out.insert("is_primary", json(&p.is_primary));
    out.insert("max_content_rating", json(&p.max_content_rating));
    out.insert("max_advisory_age", json(&p.max_advisory_age));
    out.insert("require_advisory_age", json(&p.require_advisory_age));
    out.insert(
        "library_restrictions_enabled",
        json(&p.library_restrictions_enabled),
    );
    out.insert("allowed_library_ids", json(&p.allowed_library_ids));
    out.insert("max_playback_quality", json(&p.max_playback_quality));
    out.insert("pin", json(&!p.pin_hash.is_empty()));
    out
}

mod erased {
    pub trait Encode {
        fn encode(&self) -> String;
    }
    impl<T: serde::Serialize> Encode for T {
        fn encode(&self) -> String {
            silo_gocompat::json::marshal_to_string(self).unwrap_or_default()
        }
    }
}

/// `profileManagementError`.
fn management_error(e: &HouseholdError) -> ApiError {
    match e {
        HouseholdError::Unverified => api(
            403,
            CODE_MANAGEMENT,
            "Profile management requires verifying the primary profile PIN",
        ),
        HouseholdError::Other => api(500, CODE_MANAGEMENT, "Failed to check profile permissions"),
    }
}

/// `writeProfileManagementPermissionError` around `writeAPIError`.
async fn write_v1(w: &mut dyn ResponseWriter, e: &ApiError) {
    if e.code == CODE_MANAGEMENT {
        let code = if e.status == 403 {
            "forbidden"
        } else {
            INTERNAL
        };
        return write_v1_error(w, e.status, code, &e.message).await;
    }
    write_api(w, e).await;
}

/// `profileProblem`.
fn v2_problem(e: &ApiError) -> Problem {
    let invalid = |location: String, detail: &str| {
        Problem::new(
            validation_failed(),
            "The request did not pass validation; see errors.",
        )
        .with_errors([ProblemError {
            location,
            code: "invalid".to_owned(),
            detail: detail.to_owned(),
        }])
    };
    if !e.field.is_empty() {
        return invalid(format!("body.{}", e.field), &e.message);
    }
    if e.status == 400 {
        return invalid("body".to_owned(), &e.message);
    }
    if e.status == 403 && e.code == CODE_MANAGEMENT {
        return Problem::new(
            super::chain::problem_type("profile_verification_required"),
            e.message.clone(),
        );
    }
    service_problem(e)
}

fn parse_quality(value: &str) -> Option<String> {
    match silo_gocompat::strings::to_upper(trim_space(value)).as_str() {
        "" | "ANY" => Some(String::new()),
        "STANDARD" | "480P" | "720P" | "1080P" => Some("1080p".to_owned()),
        "4K" | "UHD" | "2160P" | "4320P" => Some("2160p".to_owned()),
        _ => None,
    }
}

fn name_conflicts(profiles: &[Profile], name: &str, exclude: &str) -> bool {
    let trimmed = trim_space(name);
    profiles
        .iter()
        .any(|p| p.id != exclude && equal_fold(trim_space(&p.name), trimmed))
}

fn valid_advisory_age(age: i32) -> bool {
    (1..=21).contains(&age)
}

fn invalid_advisory_age() -> ApiError {
    field_error(
        "max_advisory_age",
        "max_advisory_age must be between 1 and 21",
    )
}

fn limit_reached(limit: i32) -> ApiError {
    api(
        409,
        "profile_limit_reached",
        format!("This account has reached its profile limit ({limit})"),
    )
}

enum CreateFailure {
    Limit,
    Unverified,
    Other(String),
}

impl From<StoreError> for CreateFailure {
    fn from(e: StoreError) -> Self {
        CreateFailure::Other(e.to_string())
    }
}

impl From<silo_pg::Error> for CreateFailure {
    fn from(e: silo_pg::Error) -> Self {
        CreateFailure::Other(e.to_string())
    }
}

impl From<String> for CreateFailure {
    fn from(e: String) -> Self {
        CreateFailure::Other(e)
    }
}

/// `CreateProfile`.
async fn create_profile(
    s: &Stack,
    claims: &Claims,
    active: &str,
    verify: &Verifier,
    audit_request: &AuditRequest,
    req: CreateRequest,
) -> Result<V1Profile, ApiError> {
    let user_id = claims.user_id;
    if trim_space(&req.name).is_empty() {
        return Err(field_error("name", "Profile name is required"));
    }
    if req.pin.len() > 72 {
        return Err(field_error("pin", "PIN must be at most 72 bytes"));
    }
    let avatar = normalize_preset(&req.avatar).map_err(|e| field_error("avatar", e))?;
    let quality = parse_quality(&req.max_playback_quality)
        .ok_or_else(|| field_error("max_playback_quality", "Invalid max_playback_quality"))?;
    if req.max_advisory_age != 0 && !valid_advisory_age(req.max_advisory_age) {
        return Err(invalid_advisory_age());
    }
    let sync = plan_sync(
        Some(&req.language),
        Some(&req.subtitle_language),
        Some(&req.preferred_metadata_language),
        Some(&req.subtitle_mode),
        req.show_forced_subtitles,
        Some(req.auto_skip_intro),
        Some(req.auto_skip_credits),
        Some(req.auto_skip_recap),
        Some(req.auto_play_next_preview),
    )
    .map_err(|e| api(400, "bad_request", e))?;
    let existing = profiles::list_profiles(&s.pool, user_id)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to list profiles"))?;
    let bootstrap = existing.is_empty();
    let mut acting = None;
    if !bootstrap {
        let (allowed, row) = household_manager(s, claims, user_id, active, verify)
            .await
            .map_err(|e| management_error(&e))?;
        acting = row;
        if !allowed {
            return Err(api(
                403,
                "forbidden",
                "Profile management requires the primary profile or admin access",
            ));
        }
    }
    if bootstrap
        && claims.role != "admin"
        && (req.is_child
            || !req.max_content_rating.is_empty()
            || req.max_advisory_age != 0
            || req.require_advisory_age
            || req.library_restrictions_enabled
            || !req.allowed_library_ids.is_empty()
            || !req.max_playback_quality.is_empty())
    {
        return Err(api(
            403,
            "forbidden",
            "Profile access settings require the primary profile or admin access",
        ));
    }
    let user = s
        .users
        .get_by_id(user_id)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to load user"))?;
    let effective = s
        .groups
        .effective_policy(&user)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to load the account's profile limit"))?;
    let limit = if effective.max_profiles >= 1 {
        effective.max_profiles
    } else {
        0
    };
    if limit >= 1 && existing.len() as i32 >= limit {
        return Err(limit_reached(limit));
    }
    if name_conflicts(&existing, &req.name, "") {
        return Err(api(
            409,
            "name_conflict",
            "A profile with this name already exists",
        ));
    }
    let mut pin_hash = String::new();
    if !req.pin.is_empty() {
        pin_hash = silo_auth::passwordhash::generate(req.pin.clone().into_bytes())
            .await
            .map_err(|e| match e {
                silo_auth::passwordhash::GenerateError::Busy(_) => super::auth::busy_error(),
                _ => api(500, INTERNAL, "Failed to set profile PIN"),
            })?;
    }
    let id = uuid::Uuid::new_v4().to_string();
    let new = NewProfile {
        id: id.clone(),
        name: trim_space(&req.name).to_owned(),
        pin_hash,
        avatar,
        is_child: req.is_child,
        max_content_rating: req.max_content_rating.clone(),
        max_advisory_age: req.max_advisory_age,
        require_advisory_age: req.require_advisory_age,
        quality_preference: req.quality_preference.clone(),
        language: req.language.clone(),
        preferred_metadata_language: req.preferred_metadata_language.clone(),
        subtitle_language: req.subtitle_language.clone(),
        subtitle_mode: req.subtitle_mode.clone(),
        auto_skip_intro: req.auto_skip_intro,
        auto_skip_credits: req.auto_skip_credits,
        auto_skip_recap: req.auto_skip_recap,
        auto_play_next_preview: req.auto_play_next_preview,
        library_restrictions_enabled: req.library_restrictions_enabled,
        allowed_library_ids: int4_ids(&req.allowed_library_ids)?,
        max_playback_quality: quality,
    };
    let result = create_tx(
        s,
        user_id,
        &new,
        limit,
        &sync,
        acting.as_ref(),
        audit_request,
    )
    .await;
    let changed = match result {
        Ok(changed) => changed,
        Err(CreateFailure::Limit) => return Err(limit_reached(limit)),
        Err(CreateFailure::Unverified) => {
            return Err(management_error(&HouseholdError::Unverified));
        }
        Err(CreateFailure::Other(e)) => {
            tracing::error!(component = "api", user_id, profile_id = id, error = %e, "profile create failed to sync canonical settings");
            return Err(api(500, INTERNAL, "Failed to store profile preferences"));
        }
    };
    for key in changed {
        publish_user_settings(s, user_id, &id, &key, "profile").await;
    }
    let mut created = get_full(s, user_id, &id)
        .await
        .ok_or_else(|| api(500, INTERNAL, "Failed to retrieve created profile"))?;
    if req.show_forced_subtitles == Some(false) {
        let input = UpdateProfileInput {
            show_forced_subtitles: Some(false),
            ..UpdateProfileInput::default()
        };
        let failed = || api(500, INTERNAL, "Failed to set forced subtitle preference");
        let mut conn = s.pool.acquire().await.map_err(|_| failed())?;
        let mut writer = Writer {
            tx: &mut conn,
            user_id: silo_pg::AnyInt(user_id),
        };
        writer
            .update_profile(&id, &input)
            .await
            .map_err(|_| failed())?;
        created = get_full(s, user_id, &id).await.ok_or_else(|| {
            api(
                500,
                INTERNAL,
                "Failed to retrieve profile after forced subtitle update",
            )
        })?;
    }
    Ok(one_view(s, user_id, &created).await)
}

async fn get_full(s: &Stack, user_id: i64, id: &str) -> Option<Profile> {
    profiles::get_profile(&s.pool, user_id, id)
        .await
        .ok()
        .flatten()
}

/// `createProfileWithSettingsSync`.
async fn create_tx(
    s: &Stack,
    user_id: i64,
    new: &NewProfile,
    limit: i32,
    writes: &[Sync],
    acting: Option<&Profile>,
    audit_request: &AuditRequest,
) -> Result<Vec<String>, CreateFailure> {
    let mut conn = s.pool.acquire().await?;
    let mut tx = conn.begin().await?;
    let recording = audit_request.recording();
    let entry;
    let changed = {
        let mut writer = Writer {
            tx: &mut tx,
            user_id: silo_pg::AnyInt(user_id),
        };
        writer.lock_preferences().await?;
        if recording {
            audit_request.lock_actors(writer.tx).await?;
        }
        if let Some(active) = acting
            && !writer
                .check_pin_revision(&active.id, active.pin_revision)
                .await?
        {
            return Err(CreateFailure::Unverified);
        }
        if limit >= 1 && writer.list_profile_ids().await?.len() as i32 >= limit {
            return Err(CreateFailure::Limit);
        }
        writer.create_profile(new).await?;
        let mut all = writes.to_vec();
        for entry in writer.list_settings().await? {
            if !super::settings::legacy_user_key(&entry.key) {
                continue;
            }
            match plan_legacy_runtime(&entry.key, Some(&entry.value)) {
                Ok(planned) => all.extend(planned),
                Err(e) => {
                    tracing::warn!(component = "api", key = entry.key, error = %e, "legacy user setting cannot seed a new canonical profile");
                }
            }
        }
        let base = SettingIdentity {
            scope: Scope::PROFILE,
            profile_id: new.id.clone(),
            ..SettingIdentity::default()
        };
        let changed = write_canonical_sync(&mut writer, &base, &all).await?;
        entry = if recording {
            match profiles::get_profile_tx(writer.tx, user_id, &new.id).await? {
                Some(created) => audit_request
                    .record(
                        writer.tx,
                        audit::ACTION_PROFILE_CREATED,
                        audit::TARGET_PROFILE,
                        &created.id,
                        201,
                        audit::changes(None, Some(&audit_values(&created))),
                    )
                    .await
                    .map_err(|e| CreateFailure::Other(e.to_string()))?,
                None => None,
            }
        } else {
            None
        };
        changed
    };
    tx.commit().await?;
    audit::commit(entry);
    Ok(changed)
}

/// `UpdateProfile`.
async fn update_profile(
    s: &Stack,
    claims: &Claims,
    profile_id: &str,
    active: &str,
    verify: &Verifier,
    audit_request: &AuditRequest,
    mut req: UpdateRequest,
) -> Result<V1Profile, ApiError> {
    let user_id = claims.user_id;
    let mut avatar = None;
    if let Some(raw) = &req.avatar {
        avatar = Some(normalize_preset(raw).map_err(|e| field_error("avatar", e))?);
    }
    let mut quality = None;
    if let Some(raw) = &req.max_playback_quality {
        quality =
            Some(parse_quality(raw).ok_or_else(|| {
                field_error("max_playback_quality", "Invalid max_playback_quality")
            })?);
    }
    if let Some(age) = req.max_advisory_age
        && age != 0
        && !valid_advisory_age(age)
    {
        return Err(invalid_advisory_age());
    }
    let Some(current) = get_full(s, user_id, profile_id).await else {
        return Err(api(404, "not_found", "Profile not found"));
    };
    let (can_manage, acting) = household_manager(s, claims, user_id, active, verify)
        .await
        .map_err(|e| management_error(&e))?;
    if !can_manage {
        if active.is_empty() || active != profile_id {
            return Err(api(
                403,
                "forbidden",
                "You can only update the active profile's playback preferences",
            ));
        }
        if req.is_child.is_some()
            || req.max_content_rating.is_some()
            || req.max_advisory_age.is_some()
            || req.require_advisory_age.is_some()
            || req.library_restrictions_enabled.is_some()
            || req.allowed_library_ids.is_some()
            || req.max_playback_quality.is_some()
        {
            return Err(api(
                403,
                "forbidden",
                "Profile access settings require the primary profile or admin access",
            ));
        }
    }
    if let Some(name) = &req.name {
        let trimmed = trim_space(name).to_owned();
        if trimmed.is_empty() {
            return Err(field_error("name", "Profile name is required"));
        }
        let existing = profiles::list_profiles(&s.pool, user_id)
            .await
            .map_err(|_| api(500, INTERNAL, "Failed to list profiles"))?;
        if name_conflicts(&existing, &trimmed, profile_id) {
            return Err(api(
                409,
                "name_conflict",
                "A profile with this name already exists",
            ));
        }
        req.name = Some(trimmed);
    }
    let sync = plan_sync(
        req.language.as_deref(),
        req.subtitle_language.as_deref(),
        req.preferred_metadata_language.as_deref(),
        req.subtitle_mode.as_deref(),
        req.show_forced_subtitles,
        req.auto_skip_intro,
        req.auto_skip_credits,
        req.auto_skip_recap,
        req.auto_play_next_preview,
    )
    .map_err(|e| api(400, "bad_request", e))?;
    let pin_hash = match &req.pin {
        None => None,
        Some(pin) if pin.is_empty() => Some(String::new()),
        Some(pin) => Some(
            silo_auth::passwordhash::generate(pin.clone().into_bytes())
                .await
                .map_err(|e| match e {
                    silo_auth::passwordhash::GenerateError::Busy(_) => super::auth::busy_error(),
                    _ => api(500, INTERNAL, "Failed to set profile PIN"),
                })?,
        ),
    };
    let scope_set = req.max_content_rating.is_some()
        || req.max_advisory_age.is_some()
        || req.require_advisory_age.is_some()
        || req.library_restrictions_enabled.is_some()
        || req.allowed_library_ids.is_some();
    let input = UpdateProfileInput {
        name: req.name.clone(),
        avatar,
        pin_hash,
        is_child: req.is_child,
        max_content_rating: req.max_content_rating.clone(),
        max_advisory_age: req.max_advisory_age,
        require_advisory_age: req.require_advisory_age,
        quality_preference: req.quality_preference.clone(),
        language: req.language.clone(),
        preferred_metadata_language: req.preferred_metadata_language.clone(),
        subtitle_language: req.subtitle_language.clone(),
        subtitle_mode: req.subtitle_mode.clone(),
        auto_skip_intro: req.auto_skip_intro,
        auto_skip_credits: req.auto_skip_credits,
        auto_skip_recap: req.auto_skip_recap,
        auto_play_next_preview: req.auto_play_next_preview,
        show_forced_subtitles: req.show_forced_subtitles,
        library_restrictions_enabled: req.library_restrictions_enabled,
        allowed_library_ids: req
            .allowed_library_ids
            .as_deref()
            .map(int4_ids)
            .transpose()?,
        max_playback_quality: quality,
    };
    let changed = update_tx(
        s,
        user_id,
        profile_id,
        &input,
        &sync,
        acting.as_ref(),
        audit_request,
    )
    .await;
    let changed = match changed {
        Ok(changed) => changed,
        Err(CreateFailure::Unverified) => {
            return Err(management_error(&HouseholdError::Unverified));
        }
        Err(CreateFailure::Limit) | Err(CreateFailure::Other(_)) => {
            if let Err(CreateFailure::Other(e)) = Err::<(), _>(CreateFailure::Other(String::new()))
            {
                let _ = e;
            }
            tracing::error!(
                component = "api",
                user_id,
                profile_id,
                "profile update failed to sync canonical settings"
            );
            return Err(api(500, INTERNAL, "Failed to store profile preferences"));
        }
    };
    for key in changed {
        publish_user_settings(s, user_id, profile_id, &key, "profile").await;
    }
    if req.pin.is_some() {
        s.pin_attempts.reset(&pin_key(user_id, profile_id)).await;
    }
    if scope_set {
        mark_profile_stale(s, user_id, profile_id).await;
    }
    // Replacing an uploaded avatar: the objects are Go's to clean, since only Go holds the store.
    let _ = current;
    let profile = get_full(s, user_id, profile_id)
        .await
        .ok_or_else(|| api(500, INTERNAL, "Failed to retrieve updated profile"))?;
    Ok(one_view(s, user_id, &profile).await)
}

/// `applyProfileUpdateSettingsSync`.
async fn update_tx(
    s: &Stack,
    user_id: i64,
    profile_id: &str,
    input: &UpdateProfileInput,
    writes: &[Sync],
    acting: Option<&Profile>,
    audit_request: &AuditRequest,
) -> Result<Vec<String>, CreateFailure> {
    let mut conn = s.pool.acquire().await?;
    let mut tx = conn.begin().await?;
    let recording = audit_request.recording();
    let entry;
    let changed = {
        let mut writer = Writer {
            tx: &mut tx,
            user_id: silo_pg::AnyInt(user_id),
        };
        writer.lock_preferences().await?;
        if recording {
            audit_request.lock_actors(writer.tx).await?;
        }
        if let Some(active) = acting
            && !writer
                .check_pin_revision(&active.id, active.pin_revision)
                .await?
        {
            return Err(CreateFailure::Unverified);
        }
        let before = if recording {
            profiles::get_profile_tx(writer.tx, user_id, profile_id).await?
        } else {
            None
        };
        if !writer.update_profile(profile_id, input).await? {
            return Err(CreateFailure::Other(format!(
                "profile {profile_id} not found"
            )));
        }
        entry = match before {
            None => None,
            Some(before) => match profiles::get_profile_tx(writer.tx, user_id, profile_id).await? {
                None => None,
                Some(after) => {
                    let mut changes =
                        audit::changes(Some(&audit_values(&before)), Some(&audit_values(&after)));
                    if !before.pin_hash.is_empty()
                        && !after.pin_hash.is_empty()
                        && before.pin_revision != after.pin_revision
                    {
                        changes.push(audit::Change {
                            field: "pin".to_owned(),
                            before: Some("true".to_owned()),
                            after: Some("true".to_owned()),
                        });
                    }
                    audit_request
                        .record(
                            writer.tx,
                            audit::ACTION_PROFILE_UPDATED,
                            audit::TARGET_PROFILE,
                            &before.id,
                            200,
                            changes,
                        )
                        .await
                        .map_err(|e| CreateFailure::Other(e.to_string()))?
                }
            },
        };
        let base = SettingIdentity {
            scope: Scope::PROFILE,
            profile_id: profile_id.to_owned(),
            ..SettingIdentity::default()
        };
        write_canonical_sync(&mut writer, &base, writes).await?
    };
    tx.commit().await?;
    audit::commit(entry);
    Ok(changed)
}

fn pin_key(user_id: i64, profile_id: &str) -> String {
    format!("profile_pin:{user_id}:{profile_id}")
}

/// `VerifyPIN`: whether it matched and the token. These tokens do not expire.
async fn verify_pin(
    s: &Stack,
    claims: &Claims,
    profile_id: &str,
    pin: &str,
) -> Result<(bool, String), ApiError> {
    let user_id = claims.user_id;
    let profile = profiles::get_profile(&s.pool, user_id, profile_id)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to load profile"))?;
    let profile = match profile {
        Some(p) if !p.pin_hash.is_empty() => p,
        _ => return Err(api(404, "not_found", "Profile not found or has no PIN")),
    };
    let user = s
        .users
        .get_by_id(user_id)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to load user policy"))?;
    let key = pin_key(user_id, profile_id);
    if let Err(retry) = s.pin_attempts.reserve(&key).await {
        let mut e = api(
            429,
            "rate_limited",
            "Too many incorrect PINs. Try again later.",
        );
        e.retry_after = silo_auth::attempts::retry_after_seconds(retry);
        return Err(e);
    }
    let valid = silo_auth::passwordhash::compare(
        profile.pin_hash.clone().into_bytes(),
        pin.as_bytes().to_vec(),
    )
    .await
    .map_err(|_| super::auth::busy_error())?;
    if valid {
        s.pin_attempts.reset(&key).await;
    }
    if !valid {
        return Ok((false, String::new()));
    }
    let token = s
        .profile_tokens
        .mint(
            user_id,
            &claims.session_id,
            profile_id,
            profile.pin_revision,
            user.access_policy_revision,
        )
        .map_err(|_| api(500, INTERNAL, "Failed to issue profile token"))?;
    Ok((true, token))
}

fn active_of(r: &Request) -> String {
    silo_gate::mw::auth::declared_profile_id(r)
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

fn mount_v1(stack: &Arc<Stack>, api_mux: &Mux) {
    let mux = Mux::new();
    mux.use_middleware([stack.v1_group(V1_GROUP)]);
    let path = "/api/v1/profiles/";
    mux.get(
        "/",
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let Ok(list) = profiles::list_profiles_full(&s.pool, claims.user_id).await else {
                    return write_v1_error(w, 500, INTERNAL, "Failed to list profiles").await;
                };
                let ids: Vec<String> = list.iter().map(|p| p.id.clone()).collect();
                let prefs = resolve_preferences(&s, claims.user_id, &ids).await;
                let views: Vec<V1Profile> =
                    list.iter().map(|p| view_of(&s, p, &prefs[&p.id])).collect();
                #[derive(Serialize)]
                struct Out {
                    profiles: Vec<V1Profile>,
                    avatar_upload_enabled: bool,
                }
                write_v1_json(
                    w,
                    200,
                    &Out {
                        profiles: views,
                        avatar_upload_enabled: s.local_operational_store,
                    },
                )
                .await;
            }),
        ),
    );
    mux.post(
        "/",
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let (bytes, _) = r.read_all().await;
                let mut stream = silo_gocompat::json::Decoder::new().stream(&bytes[..]);
                let Ok(req) = stream.decode::<CreateRequest>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                let verify = Verifier::v1(&s, r, &claims);
                let audit_request = s.audit_request(r, false);
                match create_profile(&s, &claims, &active_of(r), &verify, &audit_request, req).await
                {
                    Ok(view) => write_v1_json(w, 201, &view).await,
                    Err(e) => write_v1(w, &e).await,
                }
            }),
        ),
    );
    let one = "/api/v1/profiles/{id}";
    mux.put(
        "/{id}",
        stack.v1(
            one,
            &[],
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let id = r.url_param("id").to_owned();
                let (bytes, _) = r.read_all().await;
                let mut stream = silo_gocompat::json::Decoder::new().stream(&bytes[..]);
                let Ok(req) = stream.decode::<UpdateRequest>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                let verify = Verifier::v1(&s, r, &claims);
                let audit_request = s.audit_request(r, false);
                match update_profile(
                    &s,
                    &claims,
                    &id,
                    &active_of(r),
                    &verify,
                    &audit_request,
                    req,
                )
                .await
                {
                    Ok(view) => write_v1_json(w, 200, &view).await,
                    Err(e) => write_v1(w, &e).await,
                }
            }),
        ),
    );
    let pin = "/api/v1/profiles/{id}/verify-pin";
    mux.post(
        "/{id}/verify-pin",
        stack.v1(
            pin,
            &[],
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let id = r.url_param("id").to_owned();
                #[derive(Default, Deserialize)]
                #[serde(default)]
                struct Body {
                    pin: String,
                }
                let (bytes, _) = r.read_all().await;
                let mut stream = silo_gocompat::json::Decoder::new().stream(&bytes[..]);
                let Ok(body) = stream.decode::<Body>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                if body.pin.is_empty() {
                    return write_v1_error(w, 400, "bad_request", "PIN is required").await;
                }
                match verify_pin(&s, &claims, &id, &body.pin).await {
                    Ok((valid, token)) => {
                        #[derive(Serialize)]
                        struct Out {
                            valid: bool,
                            #[serde(skip_serializing_if = "String::is_empty")]
                            profile_token: String,
                        }
                        write_v1_json(
                            w,
                            200,
                            &Out {
                                valid,
                                profile_token: token,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    // Go's handlers for the rest of `/profiles` are not mounted here, but a mount must still claim the
    // whole prefix, so the Gate sends those methods and paths to Go before they reach this router.
    api_mux.mount("/api/v1/profiles", mux);
}

/// `Patch[T]`: `None` is omitted, `Some(None)` is null.
fn patch<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(d)?))
}

/// `apiv2.ProfileUpdate`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct V2Update {
    name: Option<String>,
    #[serde(deserialize_with = "patch")]
    avatar: Option<Option<String>>,
    #[serde(deserialize_with = "patch")]
    pin: Option<Option<String>>,
    is_child: Option<bool>,
    #[serde(deserialize_with = "patch")]
    max_content_rating: Option<Option<String>>,
    #[serde(deserialize_with = "patch")]
    max_advisory_age: Option<Option<i32>>,
    require_advisory_age: Option<bool>,
    quality_preference: Option<String>,
    #[serde(deserialize_with = "patch")]
    language: Option<Option<String>>,
    #[serde(deserialize_with = "patch")]
    preferred_metadata_language: Option<Option<String>>,
    #[serde(deserialize_with = "patch")]
    subtitle_language: Option<Option<String>>,
    subtitle_mode: Option<String>,
    auto_skip_intro: Option<bool>,
    auto_skip_credits: Option<bool>,
    auto_skip_recap: Option<bool>,
    auto_play_next_preview: Option<bool>,
    show_forced_subtitles: Option<bool>,
    library_restrictions_enabled: Option<bool>,
    allowed_library_ids: Option<Vec<String>>,
    #[serde(deserialize_with = "patch")]
    max_playback_quality: Option<Option<String>>,
}

/// `apiv2.ProfileCreate`.
#[derive(Default, Deserialize)]
#[serde(default)]
struct V2Create {
    name: String,
    avatar: Option<String>,
    pin: Option<String>,
    is_child: Option<bool>,
    max_content_rating: Option<String>,
    max_advisory_age: Option<i32>,
    require_advisory_age: Option<bool>,
    quality_preference: Option<String>,
    language: Option<String>,
    preferred_metadata_language: Option<String>,
    subtitle_language: Option<String>,
    subtitle_mode: Option<String>,
    auto_skip_intro: Option<bool>,
    auto_skip_credits: Option<bool>,
    auto_skip_recap: Option<bool>,
    auto_play_next_preview: Option<bool>,
    show_forced_subtitles: Option<bool>,
    library_restrictions_enabled: Option<bool>,
    allowed_library_ids: Option<Vec<String>>,
    max_playback_quality: Option<String>,
}

/// A v1 body keeps Go's `int`, and the row insert is what refuses a value `int4` cannot hold.
fn int4_ids(ids: &[i64]) -> Result<Vec<i32>, ApiError> {
    ids.iter()
        .map(|id| i32::try_from(*id))
        .collect::<Result<_, _>>()
        .map_err(|_| api(500, INTERNAL, "Failed to store profile preferences"))
}

fn invalid_at(location: &str, code: &str, detail: &str) -> Problem {
    Problem::new(
        validation_failed(),
        "The request did not pass validation; see errors.",
    )
    .with_errors([ProblemError {
        location: location.to_owned(),
        code: code.to_owned(),
        detail: detail.to_owned(),
    }])
}

/// `libraryIDsOf`.
fn library_ids_of(raw: &[String]) -> Result<Vec<i32>, Problem> {
    const AT: &str = "body.allowed_library_ids";
    let mut out = Vec::with_capacity(raw.len());
    for id in raw {
        let Some(n) = int_of_id(id) else {
            return Err(invalid_at(AT, "invalid", "expected library identifiers"));
        };
        // Go keeps an `int` here, and no library has this ID. Truncating would name another library.
        let Ok(n) = i32::try_from(n) else {
            return Err(invalid_at(
                AT,
                "invalid",
                &format!("unknown library identifier: {n}"),
            ));
        };
        if out.contains(&n) {
            return Err(invalid_at(AT, "invalid", "duplicate library identifier"));
        }
        out.push(n);
    }
    Ok(out)
}

/// `validatePIN`.
fn validate_pin(pin: Option<&str>) -> Result<(), Problem> {
    let detail = match pin {
        Some("") => "PIN must not be empty",
        Some(p) if p.len() > 72 => "PIN must be at most 72 bytes",
        _ => return Ok(()),
    };
    Err(invalid_at("body.pin", "out_of_range", detail))
}

/// `rejectUnknownLibraries`.
async fn reject_unknown_libraries(s: &Stack, ids: &[i32]) -> Result<(), Problem> {
    if ids.is_empty() {
        return Ok(());
    }
    let wide: Vec<i64> = ids.iter().map(|i| i64::from(*i)).collect();
    let rows = s
        .pool
        .query(
            "SELECT id FROM media_folders WHERE id = ANY($1::bigint[])",
            &[&wide],
        )
        .await
        .map_err(|_| {
            Problem::new(
                silo_api_v2::problem::internal_error(),
                "An unexpected error occurred.",
            )
        })?;
    let known: Vec<i64> = rows.iter().map(|r| r.get(0)).collect();
    for id in ids {
        if !known.contains(&i64::from(*id)) {
            return Err(invalid_at(
                "body.allowed_library_ids",
                "invalid",
                &format!("unknown library identifier: {id}"),
            ));
        }
    }
    Ok(())
}

const UPDATE_NULLABLE: &[&str] = &[
    "avatar",
    "pin",
    "max_content_rating",
    "language",
    "preferred_metadata_language",
    "subtitle_language",
    "max_playback_quality",
    "max_advisory_age",
];

fn raw_body(r: &Request) -> Vec<u8> {
    r.extensions
        .get::<RawBody>()
        .map(|b| b.0.clone())
        .unwrap_or_default()
}

fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/profiles";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let Ok(list) = profiles::list_profiles_full(&s.pool, claims.user_id).await else {
                    let e = api(500, INTERNAL, "Failed to list profiles");
                    return write_problem(w, r, service_problem(&e)).await;
                };
                let ids: Vec<String> = list.iter().map(|p| p.id.clone()).collect();
                let prefs = resolve_preferences(&s, claims.user_id, &ids).await;
                let mut items = Vec::new();
                for p in &list {
                    if claims.is_remote_playback() && p.id != claims.profile_id {
                        continue;
                    }
                    match v2_profile(view_of(&s, p, &prefs[&p.id])) {
                        Ok(item) => items.push(item),
                        Err(problem) => return write_problem(w, r, problem).await,
                    }
                }
                #[derive(Serialize)]
                struct Out {
                    items: Vec<V2Profile>,
                    avatar_upload_enabled: bool,
                    max_advisory_age_supported: bool,
                    require_advisory_age_supported: bool,
                }
                write_v2_json(
                    w,
                    &Out {
                        items,
                        avatar_upload_enabled: s.local_operational_store,
                        max_advisory_age_supported: true,
                        require_advisory_age_supported: true,
                    },
                )
                .await;
            }),
        ),
    );

    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_MUTATE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let raw = raw_body(r);
                if let Some(problem) = reject_nulls_except(&raw, &[]) {
                    return write_problem(w, r, problem).await;
                }
                let body: V2Create = unmarshal(&raw).unwrap_or_default();
                if let Err(problem) = validate_pin(body.pin.as_deref()) {
                    return write_problem(w, r, problem).await;
                }
                let libraries = match body
                    .allowed_library_ids
                    .as_deref()
                    .map(library_ids_of)
                    .transpose()
                {
                    Ok(ids) => ids.unwrap_or_default(),
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Err(problem) = reject_unknown_libraries(&s, &libraries).await {
                    return write_problem(w, r, problem).await;
                }
                let req = CreateRequest {
                    name: body.name,
                    avatar: body.avatar.unwrap_or_default(),
                    pin: body.pin.unwrap_or_default(),
                    is_child: body.is_child.unwrap_or(false),
                    max_content_rating: body.max_content_rating.unwrap_or_default(),
                    max_advisory_age: body.max_advisory_age.unwrap_or(0),
                    require_advisory_age: body.require_advisory_age.unwrap_or(false),
                    quality_preference: body.quality_preference.unwrap_or_default(),
                    language: body.language.unwrap_or_default(),
                    preferred_metadata_language: body
                        .preferred_metadata_language
                        .unwrap_or_default(),
                    subtitle_language: body.subtitle_language.unwrap_or_default(),
                    subtitle_mode: body.subtitle_mode.unwrap_or_default(),
                    auto_skip_intro: body.auto_skip_intro.unwrap_or(false),
                    auto_skip_credits: body.auto_skip_credits.unwrap_or(false),
                    auto_skip_recap: body.auto_skip_recap.unwrap_or(false),
                    auto_play_next_preview: body.auto_play_next_preview.unwrap_or(false),
                    show_forced_subtitles: body.show_forced_subtitles,
                    library_restrictions_enabled: body
                        .library_restrictions_enabled
                        .unwrap_or(false),
                    allowed_library_ids: libraries.iter().copied().map(i64::from).collect(),
                    max_playback_quality: body.max_playback_quality.unwrap_or_default(),
                };
                let verify = Verifier::v2(r);
                let audit_request = s.audit_request(r, true);
                match create_profile(
                    &s,
                    &claims,
                    &get_profile_id(r),
                    &verify,
                    &audit_request,
                    req,
                )
                .await
                {
                    Ok(view) => match v2_profile(view) {
                        Ok(profile) => {
                            w.header()
                                .set("Location", format!("/api/v2/profiles/{}", profile.id));
                            write_v2_json_status(w, 201, &profile).await;
                        }
                        Err(problem) => write_problem(w, r, problem).await,
                    },
                    Err(e) => write_problem(w, r, v2_problem(&e)).await,
                }
            }),
        ),
    );

    let one = "/api/v2/profiles/{id}";
    v2.patch(
        one,
        stack.v2_steps(
            one,
            V2_MUTATE,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                let raw = raw_body(r);
                if let Some(problem) = reject_nulls_except(&raw, UPDATE_NULLABLE) {
                    return write_problem(w, r, problem).await;
                }
                let body: V2Update = unmarshal(&raw).unwrap_or_default();
                if let Err(problem) = validate_pin(body.pin.as_ref().and_then(Option::as_deref)) {
                    return write_problem(w, r, problem).await;
                }
                let libraries = match body
                    .allowed_library_ids
                    .as_deref()
                    .map(library_ids_of)
                    .transpose()
                {
                    Ok(ids) => ids,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Some(ids) = &libraries
                    && let Err(problem) = reject_unknown_libraries(&s, ids).await
                {
                    return write_problem(w, r, problem).await;
                }
                let clear = |p: Option<Option<String>>| p.map(Option::unwrap_or_default);
                let req = UpdateRequest {
                    name: body.name,
                    avatar: clear(body.avatar),
                    pin: clear(body.pin),
                    is_child: body.is_child,
                    max_content_rating: clear(body.max_content_rating),
                    max_advisory_age: body.max_advisory_age.map(|p| p.unwrap_or(0)),
                    require_advisory_age: body.require_advisory_age,
                    quality_preference: body.quality_preference,
                    language: clear(body.language),
                    preferred_metadata_language: clear(body.preferred_metadata_language),
                    subtitle_language: clear(body.subtitle_language),
                    subtitle_mode: body.subtitle_mode,
                    auto_skip_intro: body.auto_skip_intro,
                    auto_skip_credits: body.auto_skip_credits,
                    auto_skip_recap: body.auto_skip_recap,
                    auto_play_next_preview: body.auto_play_next_preview,
                    show_forced_subtitles: body.show_forced_subtitles,
                    library_restrictions_enabled: body.library_restrictions_enabled,
                    allowed_library_ids: libraries
                        .as_ref()
                        .map(|ids| ids.iter().copied().map(i64::from).collect()),
                    max_playback_quality: clear(body.max_playback_quality),
                };
                let id = r.url_param("id").to_owned();
                let verify = Verifier::v2(r);
                let audit_request = s.audit_request(r, true);
                match update_profile(
                    &s,
                    &claims,
                    &id,
                    &get_profile_id(r),
                    &verify,
                    &audit_request,
                    req,
                )
                .await
                {
                    Ok(view) => match v2_profile(view) {
                        Ok(profile) => write_v2_json(w, &profile).await,
                        Err(problem) => write_problem(w, r, problem).await,
                    },
                    Err(e) => write_problem(w, r, v2_problem(&e)).await,
                }
            }),
        ),
    );

    let pin = "/api/v2/profiles/{id}/verify-pin";
    v2.post(
        pin,
        stack.v2(
            pin,
            V2Class::ProfileOptional,
            route!(stack, |s, w, r| {
                let claims = claims!(r);
                #[derive(Default, Deserialize)]
                #[serde(default)]
                struct Body {
                    pin: String,
                }
                let body: Body = unmarshal(&raw_body(r)).unwrap_or_default();
                if body.pin.len() > 72 {
                    return write_problem(
                        w,
                        r,
                        invalid_at("body.pin", "out_of_range", "PIN must be at most 72 bytes"),
                    )
                    .await;
                }
                let id = r.url_param("id").to_owned();
                match verify_pin(&s, &claims, &id, &body.pin).await {
                    Ok((valid, token)) => {
                        #[derive(Serialize)]
                        struct Out {
                            valid: bool,
                            #[serde(skip_serializing_if = "String::is_empty")]
                            profile_token: String,
                            expires_at: Option<String>,
                        }
                        write_v2_json(
                            w,
                            &Out {
                                valid,
                                profile_token: token,
                                expires_at: None,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, v2_problem(&e)).await,
                }
            }),
        ),
    );
}

/// Registers this domain's handlers.
pub fn mount(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    let _ = type_for_status;
    mount_v1(stack, api_mux);
    mount_v2(stack, v2);
}
