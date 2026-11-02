//! `viewer_access.go`, `household_profile_gate.go`, and what they call: `access/resolver.go`,
//! `access/profile_token.go`, `access/household.go`, `access/groups.go`, `access/quality.go`,
//! `access/viewer_preferences.go`, and `policy/viewer_resolver.go`.

use std::sync::{Arc, Mutex};

use silo_auth::claims::{Claims, token_type};
use silo_auth::user::{User, UserError, UserRepository};
use silo_config::resolve::{self, Context as ResolveContext};
use silo_http::Request;
use silo_jwt::{Parser, RegisteredClaims};
use silo_pg::Pool;
use silo_store::access::{MaturityLimits, ProfileTokenClaims, ResolveInput, Scope};
use silo_store::userstore::pgstore::PostgresUserStore;
use silo_store::userstore::profiles::{self, Profile};

use super::auth::{ProfileId, get_claims};
use super::denial::{self, Denial, reason};
use crate::policy::{Domain, Engine, EvalError, ScopeDecision, ScopeInput};

/// A viewer resolution failure.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// `access.ErrProfileUnverified`.
    #[error("profile verification required: {0}")]
    ProfileUnverified(String),
    /// `access.ErrProfileNotFound`.
    #[error("profile not found")]
    ProfileNotFound,
    /// `policy.ErrPolicyEvalTimeout`.
    #[error("policy evaluation timed out")]
    PolicyTimeout,
    #[error("{0}")]
    Other(String),
}

/// `access.GroupPolicy`, the fields the viewer scope reads.
#[derive(Debug, Clone, Default)]
pub struct GroupPolicy {
    pub library_ids: Option<Vec<i32>>,
    pub max_playback_quality: String,
    pub download_allowed: bool,
    pub max_remote_stream_bitrate_kbps: i32,
    pub max_local_stream_bitrate_kbps: i32,
}

/// `access.EffectiveUserPolicy`, the same fields.
#[derive(Debug, Clone, Default)]
pub struct EffectivePolicy {
    pub library_ids: Option<Vec<i32>>,
    pub max_playback_quality: String,
    pub download_allowed: bool,
    pub max_remote_stream_bitrate_kbps: i32,
    pub max_local_stream_bitrate_kbps: i32,
}

/// `access.ParsePlaybackQualityPreset` and `NormalizePlaybackQuality`.
pub fn normalize_playback_quality(value: &str) -> String {
    match silo_gocompat::strings::to_upper(silo_gocompat::strings::trim_space(value)).as_str() {
        "STANDARD" | "480P" | "720P" | "1080P" => "1080p".to_owned(),
        "4K" | "UHD" | "2160P" | "4320P" => "2160p".to_owned(),
        _ => String::new(),
    }
}

fn sorted_unique(values: &[i32]) -> Vec<i32> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

/// `access.ApplyGroupPolicy`.
pub fn apply_group_policy(user: &User, group: Option<&GroupPolicy>) -> EffectivePolicy {
    let no_group = GroupPolicy {
        download_allowed: true,
        ..GroupPolicy::default()
    };
    let group = if user.role == "admin" { None } else { group };
    let base = group.unwrap_or(&no_group);
    let non_negative = |v: Option<i32>, inherited: i32| v.map_or(inherited, |v| v.max(0));
    EffectivePolicy {
        library_ids: user
            .library_ids
            .as_deref()
            .or(base.library_ids.as_deref())
            .map(sorted_unique),
        max_playback_quality: normalize_playback_quality(
            user.max_playback_quality
                .as_deref()
                .unwrap_or(&base.max_playback_quality),
        ),
        download_allowed: user.download_allowed.unwrap_or(base.download_allowed),
        max_remote_stream_bitrate_kbps: non_negative(
            user.max_remote_stream_bitrate_kbps,
            base.max_remote_stream_bitrate_kbps,
        ),
        max_local_stream_bitrate_kbps: non_negative(
            user.max_local_stream_bitrate_kbps,
            base.max_local_stream_bitrate_kbps,
        ),
    }
}

/// `access.GroupStore`, the `GetPolicyForUser` read.
#[derive(Clone)]
pub struct GroupStore {
    pool: Arc<Pool>,
}

impl GroupStore {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self { pool }
    }

    pub async fn policy_for_user(&self, user_id: i64) -> Result<Option<GroupPolicy>, String> {
        let rows = self
            .pool
            .query(
                "SELECT g.library_ids, g.max_playback_quality, g.download_allowed,
                    g.max_remote_stream_bitrate_kbps, g.max_local_stream_bitrate_kbps
                 FROM users u JOIN access_groups g ON g.id = u.access_group_id WHERE u.id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| format!("loading access group policy for user {user_id}: {e}"))?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let scan = || -> Result<GroupPolicy, silo_pg::DriverError> {
            Ok(GroupPolicy {
                library_ids: row.try_get(0)?,
                max_playback_quality: row.try_get(1)?,
                download_allowed: row.try_get(2)?,
                max_remote_stream_bitrate_kbps: row.try_get(3)?,
                max_local_stream_bitrate_kbps: row.try_get(4)?,
            })
        };
        scan()
            .map(Some)
            .map_err(|e| format!("loading access group policy for user {user_id}: {e}"))
    }

    /// `access.EffectivePolicyForUser`.
    pub async fn effective_policy(&self, user: &User) -> Result<EffectivePolicy, String> {
        if user.access_group_id.is_none() || user.role == "admin" {
            return Ok(apply_group_policy(user, None));
        }
        let group = self.policy_for_user(user.id).await?;
        Ok(apply_group_policy(user, group.as_ref()))
    }
}

silo_jwt::impl_claims!(
    ProfileJwtClaims,
    [
        silo_jwt::gojson::value("user_id"),
        silo_jwt::gojson::value("session_id"),
        silo_jwt::gojson::value("profile_id"),
        silo_jwt::gojson::pointer("pin_revision"),
        silo_jwt::gojson::value("policy_revision"),
    ]
);

/// `access.profileJWTClaims`.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
struct ProfileJwtClaims {
    user_id: i64,
    session_id: String,
    profile_id: String,
    pin_revision: Option<i64>,
    policy_revision: i64,
    #[serde(flatten)]
    registered: RegisteredClaims,
}

/// `access.ProfileTokenService.Validate`.
#[derive(Clone)]
pub struct ProfileTokens {
    secret: Vec<u8>,
}

impl ProfileTokens {
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    pub fn validate(&self, token: &str) -> Result<ProfileTokenClaims, ResolveError> {
        let unverified = |why: String| ResolveError::ProfileUnverified(why);
        if token.is_empty() {
            return Err(unverified(String::new()));
        }
        let claims = Parser::new()
            .parse_hmac::<ProfileJwtClaims>(token, &self.secret)
            .map_err(|e| unverified(e.to_string()))?
            .claims;
        let pin_revision = claims
            .pin_revision
            .ok_or_else(|| unverified("token predates pin_revision".to_owned()))?;
        Ok(ProfileTokenClaims {
            user_id: claims.user_id as i32,
            session_id: claims.session_id,
            profile_id: claims.profile_id,
            pin_revision,
            policy_revision: claims.policy_revision,
        })
    }
}

/// `access.VerifyProfileForRequest` and `CheckProfileToken`.
fn verify_profile(
    profile: &Profile,
    input: &ResolveInput,
    user_id: i64,
    tokens: &ProfileTokens,
) -> Result<bool, ResolveError> {
    if profile.pin_hash.is_empty() || input.skip_pin_verification {
        return Ok(true);
    }
    let claims = tokens.validate(&input.profile_token)?;
    if i64::from(claims.user_id) != user_id
        || claims.session_id != input.session_id
        || claims.profile_id != profile.id
        || claims.pin_revision != profile.pin_revision
    {
        return Err(ResolveError::ProfileUnverified(String::new()));
    }
    Ok(true)
}

/// `access.ProfileIsLimited`.
pub fn profile_is_limited(profile: &Profile) -> bool {
    let maturity = MaturityLimits {
        max_content_rating: profile.max_content_rating.clone(),
        max_advisory_age: profile.max_advisory_age,
        ..MaturityLimits::default()
    };
    !profile.pin_hash.is_empty() || maturity.active() || profile.library_restrictions_enabled
}

/// `access.HouseholdRequiresProfile`.
pub fn household_requires_profile(profiles: &[Profile]) -> bool {
    profiles.iter().any(profile_is_limited)
}

fn int_list(raw: &[u8]) -> Vec<i64> {
    let ids: Vec<i64> = silo_gocompat::json::unmarshal(raw).unwrap_or_default();
    ids.into_iter().filter(|id| *id > 0).collect()
}

#[derive(Default)]
struct Preferences {
    disabled_library_ids: Vec<i64>,
    preferred_metadata_language: String,
    next_up_mode: String,
    next_up_new_releases_first: bool,
    degraded: bool,
}

/// `policy.ViewerResolver`.
pub struct ViewerResolver {
    users: UserRepository,
    pool: Arc<Pool>,
    groups: GroupStore,
    tokens: ProfileTokens,
    engine: Arc<Mutex<Engine>>,
    defaults: Option<Arc<dyn resolve::ServerSettings>>,
}

impl ViewerResolver {
    pub fn new(
        users: UserRepository,
        pool: Arc<Pool>,
        tokens: ProfileTokens,
        engine: Engine,
        defaults: Option<Arc<dyn resolve::ServerSettings>>,
    ) -> Self {
        Self {
            users,
            groups: GroupStore::new(pool.clone()),
            pool,
            tokens,
            engine: Arc::new(Mutex::new(engine)),
            defaults,
        }
    }

    /// Replaces the engine, the reload half of `policy.System`.
    pub fn set_engine(&self, engine: Engine) {
        *self.engine.lock().unwrap_or_else(|e| e.into_inner()) = engine;
    }

    /// `ListProfiles`.
    pub async fn list_profiles(&self, user_id: i64) -> Result<Vec<Profile>, String> {
        profiles::list_profiles(&self.pool, user_id).await
    }

    /// `GetProfile`.
    pub async fn get_profile(&self, user_id: i64, id: &str) -> Result<Option<Profile>, String> {
        profiles::get_profile(&self.pool, user_id, id).await
    }

    async fn preferences(&self, user_id: i64, profile_id: &str) -> Preferences {
        let profile_id = silo_gocompat::strings::trim_space(profile_id);
        if profile_id.is_empty() {
            return Preferences::default();
        }
        let store = PostgresUserStore::new(self.pool.clone(), user_id as i32);
        let contract = silo_config::settings::load::must_load();
        let mut resolver = resolve::Resolver::new(contract);
        if let Some(defaults) = &self.defaults {
            resolver = resolver.with_admin_defaults(defaults.clone());
        }
        let keys = [
            "ui.disabled_library_ids",
            "catalog.metadata_language",
            "catalog.metadata_language_overrides",
            "ui.next_up_mode",
            "ui.next_up_new_releases_first",
        ]
        .map(str::to_owned);
        let context = ResolveContext {
            profile_id: profile_id.to_owned(),
            ..ResolveContext::default()
        };
        let values = match resolver
            .resolve(&store, &context, &keys, &resolve::Constraints::default())
            .await
        {
            Ok(values) => values,
            Err(e) => {
                tracing::warn!(component = "access", profile_id, error = %e, "viewer preference resolution degraded");
                return Preferences {
                    degraded: true,
                    ..Preferences::default()
                };
            }
        };
        let mut out = Preferences::default();
        for value in values {
            let raw = value.value.as_bytes().unwrap_or_default();
            match value.key.as_str() {
                "ui.disabled_library_ids" => out.disabled_library_ids = int_list(raw),
                "catalog.metadata_language" => {
                    if let Ok(language) = silo_gocompat::json::unmarshal::<String>(raw) {
                        out.preferred_metadata_language =
                            silo_gocompat::strings::trim_space(&language).to_owned();
                    }
                }
                "ui.next_up_mode" => {
                    if let Ok(mode) = silo_gocompat::json::unmarshal::<String>(raw) {
                        out.next_up_mode = silo_gocompat::strings::trim_space(&mode).to_owned();
                    }
                }
                "ui.next_up_new_releases_first" => {
                    if let Ok(first) = silo_gocompat::json::unmarshal::<bool>(raw) {
                        out.next_up_new_releases_first = first;
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// `ViewerResolver.Resolve`.
    pub async fn resolve(&self, input: &ResolveInput) -> Result<Scope, ResolveError> {
        let user_id = i64::from(input.user_id);
        let user = self.users.get_by_id(user_id).await.map_err(|e| match e {
            UserError::NotFound => ResolveError::Other(format!("loading user {user_id}: {e}")),
            UserError::Store(_) => ResolveError::Other(format!("loading user {user_id}: {e}")),
        })?;
        let effective = self
            .groups
            .effective_policy(&user)
            .await
            .map_err(ResolveError::Other)?;
        let profile = if input.profile_id.is_empty() {
            None
        } else {
            let profile = self
                .get_profile(user_id, &input.profile_id)
                .await
                .map_err(ResolveError::Other)?;
            Some(profile.ok_or(ResolveError::ProfileNotFound)?)
        };
        let preferences = self.preferences(user_id, &input.profile_id).await;

        let mut profile_verified = input.profile_id.is_empty();
        if let Some(profile) = &profile {
            profile_verified = verify_profile(profile, input, user.id, &self.tokens)?;
        }
        let disabled = if input.content_access_only {
            Vec::new()
        } else {
            preferences.disabled_library_ids.clone()
        };
        let to_i64 = |ids: &[i32]| ids.iter().map(|id| i64::from(*id)).collect::<Vec<i64>>();
        let mut policy_input = ScopeInput {
            schema_version: 1,
            user_id: user.id,
            session_id: input.session_id.clone(),
            profile_id: input.profile_id.clone(),
            account_library_ids: effective
                .library_ids
                .as_deref()
                .map(to_i64)
                .unwrap_or_default(),
            account_restricted: effective.library_ids.is_some(),
            account_max_quality: effective.max_playback_quality.clone(),
            access_policy_revision: user.access_policy_revision,
            disabled_library_ids: disabled,
            profile_verified,
            request_time: now_rfc3339(),
            ..ScopeInput::default()
        };
        if let Some(profile) = &profile {
            policy_input.profile_present = true;
            policy_input.profile_max_rating = profile.max_content_rating.clone();
            policy_input.profile_max_advisory_age = profile.max_advisory_age;
            policy_input.profile_max_quality = profile.max_playback_quality.clone();
            policy_input.profile_library_limited = profile.library_restrictions_enabled;
            policy_input.profile_library_ids = to_i64(&profile.allowed_library_ids);
            policy_input.profile_has_pin = !profile.pin_hash.is_empty();
            policy_input.profile_metadata_lang = preferences.preferred_metadata_language.clone();
        }
        let decision = self.decide(policy_input).await?;
        if profile_verified && !decision.profile_verified {
            return Err(ResolveError::ProfileUnverified(
                "revoked by policy".to_owned(),
            ));
        }
        Ok(Scope {
            user_id: user.id as i32,
            profile_id: input.profile_id.clone(),
            profile_pin_revision: profile.as_ref().map_or(0, |p| p.pin_revision),
            allowed_library_ids: if decision.unrestricted {
                Vec::new()
            } else {
                decision.allowed_library_ids.clone()
            },
            disabled_library_ids: decision.disabled_library_ids.clone(),
            libraries_restricted: decision.libraries_restricted,
            hidden_library_ids: (!decision.hidden_library_ids.is_empty())
                .then(|| decision.hidden_library_ids.clone()),
            maturity_limits: MaturityLimits {
                max_content_rating: decision.max_content_rating.clone(),
                allow_unrated_content: false,
                max_advisory_age: decision.max_advisory_age,
                require_advisory_age: profile.as_ref().is_some_and(|p| p.require_advisory_age)
                    && decision.max_advisory_age > 0,
            },
            max_playback_quality: decision.max_playback_quality.clone(),
            max_remote_stream_bitrate_kbps: i64::from(effective.max_remote_stream_bitrate_kbps),
            max_local_stream_bitrate_kbps: i64::from(effective.max_local_stream_bitrate_kbps),
            preferred_metadata_language: decision.preferred_metadata_language.clone(),
            policy_revision: user.access_policy_revision,
            profile_verified: profile_verified && decision.profile_verified,
            pin_verification_skipped: profile_verified
                && profile.as_ref().is_some_and(|p| !p.pin_hash.is_empty())
                && input.skip_pin_verification,
            next_up_mode: preferences.next_up_mode,
            next_up_new_releases_first: preferences.next_up_new_releases_first,
            preferences_degraded: preferences.degraded,
            ..Scope::default()
        })
    }

    /// `PDP.ResolveViewerScope`. Regorus is CPU work, so it runs off the async workers.
    async fn decide(&self, input: ScopeInput) -> Result<ScopeDecision, ResolveError> {
        let engine = self.engine.clone();
        let value = serde_json::to_value(&input).map_err(|e| ResolveError::Other(e.to_string()))?;
        let result = tokio::task::spawn_blocking(move || {
            engine
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .evaluate::<ScopeDecision>(Domain::Scope, &value)
        })
        .await
        .map_err(|e| ResolveError::Other(e.to_string()))?;
        result.map_err(|e| match e {
            EvalError::Eval { ref source, .. } if is_time_limit(source) => {
                ResolveError::PolicyTimeout
            }
            other => ResolveError::Other(format!("resolve viewer scope policy: {other}")),
        })
    }
}

fn is_time_limit(error: &anyhow::Error) -> bool {
    error.to_string().contains("time limit")
}

pub(crate) fn now_rfc3339() -> String {
    silo_gocompat::time::GoTime::now_utc().format(silo_gocompat::time::RFC3339)
}

fn skips_pin(claims: &Claims) -> bool {
    claims.token_type == token_type::API_KEY
        || claims.token_type == token_type::APPLE_PUSH_DISPLAY
        || claims.token_type == token_type::DIRECT_DOWNLOAD_LINK
}

/// `RequireViewerAccess`.
pub async fn require_viewer_access(
    resolver: &ViewerResolver,
    r: &mut Request,
) -> Result<(), Denial> {
    let claims = get_claims(r).ok_or_else(|| {
        Denial::unauthorized("Authentication required", reason::AUTHENTICATION_REQUIRED)
    })?;
    let profile_id = r.header.get_str("X-Profile-Id").to_owned();
    let input = ResolveInput {
        user_id: claims.user_id as i32,
        session_id: claims.session_id.clone(),
        profile_id: profile_id.clone(),
        profile_token: r.header.get_str("X-Profile-Token").to_owned(),
        skip_pin_verification: skips_pin(&claims),
        content_access_only: false,
    };
    match resolver.resolve(&input).await {
        Ok(scope) => {
            r.extensions.insert(Arc::new(scope));
            if !profile_id.is_empty() {
                r.extensions.insert(ProfileId(profile_id));
            }
            Ok(())
        }
        Err(ResolveError::ProfileUnverified(_)) => Err(Denial::new(
            403,
            "profile_unverified",
            "Profile verification required",
        )),
        Err(ResolveError::ProfileNotFound) => {
            Err(Denial::new(404, "not_found", "Profile not found"))
        }
        Err(ResolveError::PolicyTimeout) => Err(Denial {
            reason: reason::VIEWER_ACCESS_UNAVAILABLE,
            retry_after: Some(denial::VIEWER_ACCESS_RETRY_AFTER_SECONDS),
            ..Denial::new(
                503,
                denial::CODE_SERVICE_UNAVAILABLE,
                "Viewer access could not be resolved right now; try again shortly",
            )
        }),
        Err(ResolveError::Other(e)) => {
            tracing::warn!(component = "api", error = %e, "resolving viewer access failed");
            Err(Denial::internal("Failed to resolve viewer access"))
        }
    }
}

/// `optionalProfileViewerAccess`.
pub async fn optional_profile_viewer_access(
    resolver: &ViewerResolver,
    r: &mut Request,
) -> Result<(), Denial> {
    if silo_gocompat::strings::trim_space(r.header.get_str("X-Profile-Id")).is_empty() {
        return Ok(());
    }
    require_viewer_access(resolver, r).await
}

/// `HouseholdProfileGate.Require`.
pub async fn household_profile_gate(resolver: &ViewerResolver, r: &Request) -> Result<(), Denial> {
    if !r.header.get("X-Profile-Id").is_empty() {
        return Ok(());
    }
    let claims = get_claims(r).ok_or_else(|| {
        Denial::unauthorized("Authentication required", reason::AUTHENTICATION_REQUIRED)
    })?;
    if claims.token_type == token_type::API_KEY {
        return Ok(());
    }
    let profiles = resolver.list_profiles(claims.user_id).await.map_err(|e| {
        tracing::error!(component = "api", user_id = claims.user_id, error = %e, "household profile gate: listing profiles");
        Denial::internal("Failed to resolve viewer access")
    })?;
    if household_requires_profile(&profiles) {
        return Err(Denial::profile_header_required());
    }
    Ok(())
}

impl GroupStore {
    /// `GroupPolicy.AllowedPermissions`: `None` means every assignable one.
    pub async fn allowed_permissions(&self, user_id: i64) -> Result<Option<Vec<String>>, String> {
        let rows = self
            .pool
            .query(
                "SELECT g.allowed_permissions FROM users u JOIN access_groups g ON g.id = u.access_group_id WHERE u.id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        match rows.first() {
            Some(row) => row.try_get(0).map_err(|e| e.to_string()),
            None => Ok(None),
        }
    }
}
