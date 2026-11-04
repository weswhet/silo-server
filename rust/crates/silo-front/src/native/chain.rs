//! The request chain: `useBaseMiddleware`, the v1 route groups' gates, and the v2 `classGate`,
//! `writeProblem`, and `prepareCapabilityOperation` rendering around them.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, resume_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use futures_util::FutureExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use silo_api_v2::problem::{self as p, Problem, ProblemError};
use silo_auth::api_key_store::ApiKeyRepository;
use silo_auth::attempts::{
    AttemptLimiter, MemoryAttempts, PROFILE_PIN_POLICY, QUICK_CONNECT_CODE_POLICY,
    SIGN_IN_NAME_POLICY,
};
use silo_auth::claims::{Claims, JwtService};
use silo_auth::device::DeviceLoginService;
use silo_auth::service::AuthService;
use silo_auth::session::SessionRepository;
use silo_auth::user::UserRepository;
use silo_core::redis::{CHANNEL_ADMIN, Event};
use silo_gate::clientip::{self, RequestContext, RequestFields, Resolver};
use silo_gate::limiter::{Limiter, RateLimit, RateRequest, RedisLimiter, config_from_settings};
use silo_gate::mw::activity::{self, ActivityWriter, LogEntry};
use silo_gate::mw::auth::{self, LogContext, get_claims};
use silo_gate::mw::denial::reason;
use silo_gate::mw::logging::{Metrics, request_logger_skips};
use silo_gate::mw::policy_gates::PolicyGates;
use silo_gate::mw::viewer::{self, GroupStore, ProfileTokens, ViewerResolver};
use silo_gate::mw::{AuthGate, Denial, RequestId, new_request_id};
use silo_gate::pdp::{DecisionLogger, Pdp};
use silo_gate::policy::Engine;
use silo_gate::ratelimit::MemoryLimiter;
use silo_gate::settings_cache::{admin_defaults, unrated_content};
use silo_http::chi::{Middleware, middleware_fn};
use silo_http::{
    AbortHandler, BoxFuture, BoxHandler, Header, Hijacked, Request, ResponseWriter, WriteError,
    handler_fn,
};
use silo_pg::Pool;
use silo_runtime::cache::event_bus::EventBus;
use silo_runtime::logstream::Hub;
use silo_store::settings::{EncryptedSettingsRepo, ServerSettingsRepo};

/// `cache.EventSettingsChanged` and `EventPolicyChanged`.
pub const EVENT_SETTINGS_CHANGED: &str = "settings_changed";
pub const EVENT_POLICY_CHANGED: &str = "policy_changed";
/// `cache.EventAuthProvidersChanged` and `EventPluginsChanged`, which rebuild Go's provider list.
pub const EVENT_AUTH_PROVIDERS_CHANGED: &str = "auth_providers_changed";
pub const EVENT_PLUGINS_CHANGED: &str = "plugins_changed";
/// `cache.EventUserSessionsRevoked`.
pub const EVENT_USER_SESSIONS_REVOKED: &str = "user_sessions_revoked";

/// `nodeconfig`'s and `policy.System`'s poll fallback, for an event this process missed.
pub const POLL_WITH_BUS: Duration = Duration::from_secs(60);
/// Without Redis, Go has no way to tell this process anything, and it applies a change at once.
pub const POLL_WITHOUT_BUS: Duration = Duration::from_secs(2);

/// A reload signal from `silo:admin`, and how often to re-read anyway. With no bus, or when the
/// subscription fails, the short poll is all there is.
pub async fn admin_reload_signal(
    bus: Option<&Arc<dyn EventBus>>,
    kinds: &'static [&'static str],
) -> (Arc<tokio::sync::Notify>, Duration) {
    let notify = Arc::new(tokio::sync::Notify::new());
    let Some(bus) = bus else {
        return (notify, POLL_WITHOUT_BUS);
    };
    let signal = notify.clone();
    let handler = Arc::new(move |event: Event| {
        if kinds.contains(&event.event_type.as_str()) {
            signal.notify_one();
        }
    });
    match bus.subscribe(CHANNEL_ADMIN, handler).await {
        Ok(()) => (notify, POLL_WITH_BUS),
        Err(e) => {
            tracing::warn!(component = "front", error = %e, "subscribing to the admin channel failed; polling");
            (notify, POLL_WITHOUT_BUS)
        }
    }
}

/// One gate. Lists run in order, as a chi group's `Use` calls do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `RequireAuth`.
    Auth,
    /// `AttachSession`.
    AttachSession,
    /// `RequireDirectDownloadAuth`.
    DirectDownload,
    /// `DemoGuard.Guard` (v1, by path).
    Demo,
    /// `demoGate` (v2, an operation declared demo restricted).
    DemoRestricted,
    /// `RateLimitMW.Handler`.
    RateLimit,
    /// `RateLimitMW.AuthEndpointHandler(name)`.
    RateLimitEndpoint(&'static str),
    /// `RequireViewerAccess`.
    Viewer,
    /// `optionalProfileViewerAccess`.
    OptionalViewer,
    /// `HouseholdProfileGate.Require`.
    Household,
    /// `RequireProfile`.
    Profile,
    /// `RequireActingAdminWith`.
    ActingAdmin,
    /// `RequireAdmin`.
    Admin,
    /// `PolicyPermissionMiddleware.RequireMarkerEdit`.
    MarkerEdit,
    /// `RequireMetadataCurationForItem`, on the route's `{id}`.
    MetadataCuration,
}

/// `apiv2.Class`, as `gateChain` composes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2Class {
    Public,
    Authenticated,
    /// `ClassProfileScoped`, with a profile required.
    ProfileScoped,
    /// `ClassProfileScoped`, `ProfileOptional`.
    ProfileOptional,
    ActingAdmin,
}

impl V2Class {
    /// `gateChain`.
    pub fn steps(self) -> &'static [Step] {
        match self {
            V2Class::Public => &[],
            V2Class::Authenticated => &[Step::Auth, Step::RateLimit],
            V2Class::ProfileScoped => &[Step::Auth, Step::RateLimit, Step::Viewer, Step::Profile],
            V2Class::ProfileOptional => &[Step::Auth, Step::RateLimit, Step::Viewer],
            V2Class::ActingAdmin => &[Step::Auth, Step::RateLimit, Step::Viewer, Step::ActingAdmin],
        }
    }
}

/// Everything a gate reads.
pub struct Stack {
    pub pool: Arc<Pool>,
    pub auth: AuthGate,
    pub users: UserRepository,
    pub groups: GroupStore,
    pub viewer: Arc<ViewerResolver>,
    pub gates: PolicyGates,
    pub rate: RateLimit,
    pub settings: ServerSettingsRepo,
    pub activity: ActivityWriter,
    pub resolver: Arc<Resolver>,
    pub metrics: Metrics,
    pub node_id: String,
    /// An active custom policy could not be loaded, so this process cannot answer for it.
    policy_refused: AtomicBool,
    pub jwt: Arc<JwtService>,
    pub sign_in: AuthService,
    pub devices: DeviceLoginService,
    pub api_keys: ApiKeyRepository,
    pub profile_tokens: ProfileTokens,
    pub cursors: silo_api_v2::cursor::Cursors,
    pub hub: Arc<Hub>,
    /// `cfg.Recommendations.Enabled`, read at startup as Go reads it.
    pub recommendations_enabled: bool,
    pub bus: Option<Arc<dyn EventBus>>,
    /// `config.NewAdminDefaults`.
    pub admin_defaults: Option<Arc<dyn silo_config::resolve::ServerSettings>>,
    /// `SettingsRepo`, decrypting.
    pub encrypted: Arc<EncryptedSettingsRepo>,
    /// `deps.ProfilePINAttempts`.
    pub pin_attempts: Arc<dyn AttemptLimiter>,
    /// The artwork signer's secret, and whether avatars live in the local store.
    pub artwork_secret: String,
    pub local_operational_store: bool,
    /// `cfg.S3.MetadataPresignExpiry`, read at startup as Go's signer takes it.
    pub artwork_url_ttl: Duration,
    /// `cfg.Matcher.TVSeriesRootQueueEnabled()`, read at startup as `NewRouter` reads it.
    pub tv_series_root_queue: bool,
    /// An auth plugin binding or a linked identity exists, so sign-in needs the plugin host, on Go.
    external_sign_in: AtomicBool,
    /// A watch provider connection or a watchlist title entry exists.
    personal_needs_go: AtomicBool,
    /// A plugin installation exists, so its watch provider could be registered in Go's process.
    plugins_installed: AtomicBool,
    /// `catalog.search.provider` names Meilisearch.
    search_meilisearch: AtomicBool,
    /// An enabled request server exists, whose plugin `/requests/status` would ask.
    request_server_enabled: AtomicBool,
    /// Decrypts stored request server keys.
    pub cipher: silo_core::secret::Cipher,
    /// The machine lease for route IDs, taken on the first create.
    pub route_ids: tokio::sync::OnceCell<silo_runtime::idgen_lease::Lease>,
}

/// `config.parseDuration`: a whole number of days, or Go's own form.
fn parse_config_duration(raw: &str) -> Option<i64> {
    let raw = silo_gocompat::strings::trim_space(raw);
    if let Some(days) = raw.strip_suffix('d')
        && let Ok(days) = days.parse::<i64>()
    {
        return days.checked_mul(86_400_000_000_000);
    }
    silo_gocompat::time::parse_duration(raw).ok().map(|d| d.0)
}

/// Whether `blobstore.Open` puts avatars in the local store: no private bucket and a local backend.
/// S3 presigning is not ported, so a deployment with a bucket keeps the profile rows on Go.
async fn local_operational_store(settings: &ServerSettingsRepo) -> bool {
    let mut keys = vec![
        "s3.private_bucket",
        "s3.public_bucket",
        "s3.operational_bucket",
    ];
    keys.push("artwork.storage_backend");
    let Ok(values) = settings.get_many(&keys).await else {
        return false;
    };
    let set = |key: &str| values.get(key).is_some_and(|v| !v.trim().is_empty());
    let backend = values
        .get("artwork.storage_backend")
        .map_or("", |v| v.trim());
    !set("s3.private_bucket")
        && !set("s3.public_bucket")
        && !set("s3.operational_bucket")
        && !silo_gocompat::strings::equal_fold(backend, "s3")
}

/// `auth.access_token_expiry` and `auth.refresh_token_expiry`, with `EffectiveAdminSettings`' defaults.
fn token_expiries(all: &HashMap<String, String>) -> (i64, i64) {
    const HOUR: i64 = 3_600_000_000_000;
    let read = |key: &str, default: i64| {
        all.get(key)
            .and_then(|v| parse_config_duration(v))
            .filter(|v| *v > 0)
            .unwrap_or(default)
    };
    (
        read("auth.access_token_expiry", 8 * HOUR),
        read("auth.refresh_token_expiry", 30 * 24 * HOUR),
    )
}

/// Whether a personal list write would owe a watch provider a dispatch, or a read a title promotion.
async fn personal_needs_go(pool: &Pool) -> Result<bool, String> {
    let rows = pool
        .query(
            "SELECT EXISTS(SELECT 1 FROM watch_provider_connections) OR EXISTS(SELECT 1 FROM user_watchlist_titles)",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.first().is_none_or(|r| r.get::<_, bool>(0)))
}

async fn search_meilisearch(pool: &Pool) -> Result<bool, String> {
    let rows = pool
        .query(
            "SELECT EXISTS(SELECT 1 FROM server_settings WHERE key = 'catalog.search.provider' AND value <> 'postgres' AND value <> '')",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.first().is_none_or(|r| r.get::<_, bool>(0)))
}

async fn request_server_enabled(pool: &Pool) -> Result<bool, String> {
    let rows = pool
        .query(
            "SELECT EXISTS(SELECT 1 FROM request_integrations WHERE enabled)",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.first().is_none_or(|r| r.get::<_, bool>(0)))
}

async fn plugins_installed(pool: &Pool) -> Result<bool, String> {
    let rows = pool
        .query(
            "SELECT EXISTS(SELECT 1 FROM plugin_installations WHERE kind <> 'builtin')",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.first().is_none_or(|r| r.get::<_, bool>(0)))
}

/// Whether sign-in depends on a plugin provider: any binding, or an identity a re-check would consult.
async fn external_sign_in_configured(pool: &Pool) -> Result<bool, String> {
    let rows = pool
        .query(
            "SELECT EXISTS(SELECT 1 FROM plugin_auth_bindings) OR EXISTS(SELECT 1 FROM plugin_auth_identities)",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    match rows.first() {
        Some(row) => row
            .try_get(0)
            .map_err(|e: silo_pg::DriverError| e.to_string()),
        None => Ok(true),
    }
}

/// `cfg.UserDB.Backend`, `cfg.RateLimit.Backend`, `REDIS_URL`, and what the front does with them: Rust reads profiles
/// from Postgres only, and native rows need the rate limit counters Go has. Each reason a stack cannot
/// answer for Go keeps every row behind a credential on Go.
fn why_not_native(
    all: &HashMap<String, String>,
    redis: bool,
    split_budgets: bool,
) -> Option<String> {
    let setting = |key: &str, default: &'static str| -> String {
        all.get(key)
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| default.to_owned())
    };
    let userdb = setting("userdb.backend", "postgres");
    if userdb != "postgres" {
        return Some(format!(
            "userdb.backend is {userdb}, and native rows read profiles from Postgres only"
        ));
    }
    if split_budgets {
        return None;
    }
    if !config_from_settings(all).enabled {
        // The request limiter is off, but Go's sign-in name, Quick Connect, and PIN budgets are not, and
        // those are shared only through Redis.
        return (!redis).then(|| {
            "REDIS_URL is not set, so native rows would add a second sign-in, Quick Connect, and PIN budget"
                .to_owned()
        });
    }
    let backend = setting("ratelimit.backend", "memory");
    if backend != "redis" {
        return Some(format!(
            "ratelimit.backend is {backend}, so Go's counters are in its process and native rows would add a second budget"
        ));
    }
    if !redis {
        return Some(
            "ratelimit.backend is redis but REDIS_URL is not set, so native rows would add a second budget"
                .to_owned(),
        );
    }
    None
}

/// `DefaultConfig().Recommendations.Enabled`.
const RECOMMENDATIONS_DEFAULT: bool = false;

/// What [`build`] takes from the process's environment.
pub struct BuildOptions<'a> {
    pub secret_key: &'a str,
    pub redis_url: Option<&'a str>,
    pub bus: Option<Arc<dyn EventBus>>,
    /// `SILO_FRONT_SPLIT_RATE_BUDGETS`: keep rows native on the memory backend, with separate counters.
    /// For a comparison that compares one row at a time.
    pub split_rate_budgets: bool,
}

/// `clientip.DefaultTrustedProxies` when the setting is empty, as `registerClientIPConfigReload` does.
fn trusted_cidrs(raw: Option<&String>) -> Result<Vec<clientip::IpNet>, String> {
    let raw = raw.map_or("", String::as_str);
    let list = if raw.is_empty() {
        clientip::DEFAULT_TRUSTED_PROXIES
    } else {
        raw
    };
    clientip::parse_cidrs(list).map_err(|e| e.0)
}

/// `cfg.Policy`'s decision log settings.
fn apply_decision_log_settings(logger: &DecisionLogger, all: &HashMap<String, String>) {
    logger.set_verbosity(
        all.get("policy.decision_log_verbosity")
            .map_or("", String::as_str),
    );
    if let Some(Ok(rate)) = all
        .get("policy.decision_log_scope_sample_rate")
        .filter(|v| !v.is_empty())
        .map(|v| silo_gocompat::strings::trim_space(v).parse())
    {
        logger.set_scope_sample_rate(rate);
    }
}

/// `resolveNodeIdentity`.
fn node_identity() -> String {
    for name in ["SILO_NODE_NAME", "NODE_NAME"] {
        if let Some(value) = std::env::var_os(name).filter(|v| !v.is_empty()) {
            return value.to_string_lossy().into_owned();
        }
    }
    let mut buf = [0u8; 256];
    // SAFETY: the pointer and length describe `buf`, which outlives the call.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Another process only shows a row whose source is not its own, so this cannot be Go's node name.
pub(super) fn hub_source(node_id: &str) -> String {
    format!("{node_id}-front-{}", std::process::id())
}

/// Builds the chain from the reference's database. `Ok(None)` means this deployment's rows behind a
/// credential stay on Go.
pub async fn build(
    pool: Arc<Pool>,
    options: BuildOptions<'_>,
) -> Result<Option<Arc<Stack>>, String> {
    let cipher =
        silo_core::secret::Cipher::new(options.secret_key.as_bytes()).map_err(|e| e.to_string())?;
    let settings = ServerSettingsRepo::new(pool.clone());
    let all = settings.get_all().await.map_err(|e| e.to_string())?;
    let artwork_url_ttl = all
        .get("s3.metadata_presign_expiry")
        .and_then(|v| parse_config_duration(v))
        .filter(|ns| *ns > 0)
        .map_or(Duration::from_secs(4 * 3600), |ns| {
            Duration::from_nanos(ns as u64)
        });
    let setting_true = |key: &str, default: bool| {
        all.get(key).filter(|v| !v.is_empty()).map_or(default, |v| {
            matches!(v.as_str(), "1" | "t" | "T" | "TRUE" | "true" | "True")
        })
    };
    let tv_series_root_queue = setting_true("matcher.enable_tv_series_root_queue", true)
        || setting_true("matcher.enable_tv_series_group_queue", false);
    if let Some(why) = why_not_native(
        &all,
        options.redis_url.is_some(),
        options.split_rate_budgets,
    ) {
        tracing::warn!(component = "front", reason = %why, "rows behind a credential stay on Go");
        return Ok(None);
    }
    let encrypted = EncryptedSettingsRepo::new(settings.clone(), cipher);
    let jwt_secret = encrypted
        .get("auth.jwt_secret")
        .await
        .map_err(|e| format!("reading auth.jwt_secret: {e}"))?;
    if jwt_secret.is_empty() {
        return Err("auth.jwt_secret is empty".to_owned());
    }
    let (access_expiry, refresh_expiry) = token_expiries(&all);
    let jwt = Arc::new(JwtService::new(
        jwt_secret.clone().into_bytes(),
        access_expiry,
        refresh_expiry,
    ));
    let users = UserRepository::new(pool.clone());
    let api_keys = ApiKeyRepository::new(pool.clone());
    let sessions = SessionRepository::new(pool.clone());
    let auth = AuthGate::new(
        jwt.clone(),
        sessions.clone(),
        api_keys.clone(),
        users.clone(),
    );
    let node_id = node_identity();

    let logger = DecisionLogger::start(pool.clone(), node_id.clone());
    apply_decision_log_settings(&logger, &all);
    // `System.initialEngine`: a store that cannot be read or a bundle that does not load must not stop
    // the process, so it starts on the vendor policy, and the rows it governs go to Go until it can read
    // the stored policy.
    let loaded = load_policy(&pool).await;
    let (scope, permission, generation, refused) = match loaded {
        Ok((engines, generation)) => (engines.0, engines.1, generation, false),
        Err(e) => {
            tracing::error!(component = "policy", error = %e, "custom policy not loaded; rows behind a credential stay on Go until it loads");
            let vendor = |e: silo_gate::policy::EvalError| e.to_string();
            (
                Engine::new().map_err(vendor)?,
                Engine::new().map_err(vendor)?,
                0,
                true,
            )
        }
    };
    let pdp = Arc::new(Pdp::new(
        scope,
        permission,
        generation,
        Some(logger.clone()),
    ));
    let defaults = admin_defaults(settings.clone());
    let refresher = defaults.clone();
    tokio::spawn(async move { refresher.run().await });
    let viewer = Arc::new(ViewerResolver::new(
        users.clone(),
        pool.clone(),
        ProfileTokens::new(jwt_secret.clone().into_bytes()),
        pdp.clone(),
        Some(Arc::new(defaults.clone())),
        Some(Arc::new(unrated_content(settings.clone()))),
    ));
    let groups = GroupStore::new(pool.clone());
    let gates = PolicyGates {
        viewer: viewer.clone(),
        users: users.clone(),
        groups: groups.clone(),
        pool: pool.clone(),
        pdp: pdp.clone(),
    };

    // `cfg.RateLimit.Backend`: the configured backend, memory by default, as Go chooses at startup.
    let backend = all
        .get("ratelimit.backend")
        .map_or("memory", String::as_str);
    let limiter = match options.redis_url.filter(|_| backend == "redis") {
        Some(url) => {
            let config = silo_config::config::RedisConfig {
                url: url.to_owned(),
                db: String::new(),
            };
            let conn = silo_runtime::cache::connect(&config, "tasks")
                .await
                .map_err(|e| format!("connecting to Redis: {e}"))?;
            Limiter::Redis(Arc::new(RedisLimiter::new(conn)))
        }
        None => Limiter::Memory(MemoryLimiter::new()),
    };
    let rate = RateLimit::new(limiter, config_from_settings(&all));
    let resolver = Arc::new(Resolver::new(trusted_cidrs(
        all.get(clientip::SETTING_TRUSTED_PROXIES),
    )?));

    // `NewSignInNameAttemptLimiter` and `NewQuickConnectCodeAttemptLimiter`: shared through Redis whenever
    // the deployment has it, whatever the request limiter's backend.
    let attempts = |policy| -> Arc<dyn AttemptLimiter> { Arc::new(MemoryAttempts::new(policy)) };
    let (sign_in_attempts, quick_connect_attempts, pin_attempts) = match options.redis_url {
        Some(url) => {
            let config = silo_config::config::RedisConfig {
                url: url.to_owned(),
                db: String::new(),
            };
            let conn = silo_runtime::cache::connect(&config, "api")
                .await
                .map_err(|e| format!("connecting to Redis: {e}"))?;
            let shared = |policy| -> Arc<dyn AttemptLimiter> {
                Arc::new(silo_gate::limiter::RedisAttempts::new(conn.clone(), policy))
            };
            (
                shared(SIGN_IN_NAME_POLICY),
                shared(QUICK_CONNECT_CODE_POLICY),
                shared(PROFILE_PIN_POLICY),
            )
        }
        None => (
            attempts(SIGN_IN_NAME_POLICY),
            attempts(QUICK_CONNECT_CODE_POLICY),
            attempts(PROFILE_PIN_POLICY),
        ),
    };
    let profile_tokens = ProfileTokens::new(jwt_secret.clone().into_bytes());
    let sign_in = AuthService::new(
        pool.clone(),
        jwt.clone(),
        sessions,
        users.clone(),
        Some(sign_in_attempts),
    );
    let devices = DeviceLoginService::new(
        pool.clone(),
        users.clone(),
        jwt.clone(),
        Arc::new(profile_tokens.clone()),
        Some(quick_connect_attempts),
    );
    let external_sign_in = external_sign_in_configured(&pool)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(component = "front", error = %e, "reading auth bindings failed; sign-in stays on Go");
            true
        });

    let hub = Arc::new(Hub::new(hub_source(&node_id), options.bus.clone()));
    silo_runtime::opslog::start(
        pool.clone(),
        hub.clone(),
        node_id.clone(),
        all.get("opslog.capture_level")
            .map_or("info", String::as_str),
    );
    let recommendations_enabled = setting_true("recommendations.enabled", RECOMMENDATIONS_DEFAULT);
    let stack = Arc::new(Stack {
        recommendations_enabled,
        activity: ActivityWriter::start(pool.clone(), hub.clone()),
        jwt,
        sign_in,
        devices,
        api_keys,
        profile_tokens,
        cursors: silo_api_v2::cursor::Cursors::new(jwt_secret.clone().into_bytes()),
        hub,
        bus: options.bus.clone(),
        admin_defaults: Some(Arc::new(defaults.clone())),
        encrypted: Arc::new(encrypted),
        pin_attempts,
        artwork_secret: jwt_secret.clone(),
        local_operational_store: local_operational_store(&settings).await,
        artwork_url_ttl,
        tv_series_root_queue,
        external_sign_in: external_sign_in.into(),
        personal_needs_go: personal_needs_go(&pool).await.unwrap_or(true).into(),
        plugins_installed: plugins_installed(&pool).await.unwrap_or(true).into(),
        search_meilisearch: search_meilisearch(&pool).await.unwrap_or(true).into(),
        request_server_enabled: request_server_enabled(&pool).await.unwrap_or(true).into(),
        cipher: silo_core::secret::Cipher::new(options.secret_key.as_bytes())
            .map_err(|e| e.to_string())?,
        route_ids: tokio::sync::OnceCell::new(),
        pool: pool.clone(),
        auth,
        users,
        groups,
        viewer: viewer.clone(),
        gates,
        rate,
        settings: settings.clone(),
        resolver: resolver.clone(),
        metrics: Metrics::default(),
        node_id,
        policy_refused: refused.into(),
    });

    // Its own subscription, as in Go, so a slow settings read holds up nothing else.
    if let Some(bus) = &options.bus {
        let defaults = defaults.clone();
        let handler = Arc::new(move |event: Event| {
            if event.event_type == EVENT_SETTINGS_CHANGED {
                let defaults = defaults.clone();
                tokio::spawn(async move { defaults.changed(&event.payload).await });
            }
        });
        if let Err(e) = bus.subscribe(CHANNEL_ADMIN, handler).await {
            tracing::warn!(component = "front", error = %e, "subscribing to the admin channel failed");
        }
    }
    const KINDS: &[&str] = &[
        EVENT_SETTINGS_CHANGED,
        EVENT_POLICY_CHANGED,
        EVENT_AUTH_PROVIDERS_CHANGED,
        EVENT_PLUGINS_CHANGED,
    ];
    let (signal, poll) = admin_reload_signal(options.bus.as_ref(), KINDS).await;
    let poller = stack.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(poll);
        let mut sources = None;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                () = signal.notified() => {}
            }
            poller.reload(&logger, &pdp, &mut sources).await;
        }
    });
    Ok(Some(stack))
}

impl Stack {
    /// Whether rows behind a credential must go to Go, because this process cannot load a policy Go may
    /// be enforcing. [`silo_gate::policy::compile_check`] refuses sources OPA accepts, so a refusal says
    /// nothing about what Go does with the source; Go always answers correctly for its own policy.
    pub fn policy_refused(&self) -> bool {
        self.policy_refused.load(Ordering::Relaxed)
    }

    /// Whether sign-in needs a plugin provider. Those rows go to Go.
    pub fn external_sign_in(&self) -> bool {
        self.external_sign_in.load(Ordering::Relaxed)
    }

    /// Whether personal rows go to Go. See `personal.rs`.
    pub fn search_meilisearch(&self) -> bool {
        self.search_meilisearch.load(Ordering::Relaxed)
    }

    pub fn plugins_installed(&self) -> bool {
        self.plugins_installed.load(Ordering::Relaxed)
    }

    pub fn request_server_enabled(&self) -> bool {
        self.request_server_enabled.load(Ordering::Relaxed)
    }

    /// `personal_needs_go`, read now. A failed read routes to Go.
    pub async fn refresh_personal_needs_go(&self) -> bool {
        let needs_go = personal_needs_go(&self.pool).await.unwrap_or(true);
        self.personal_needs_go.store(needs_go, Ordering::Relaxed);
        needs_go
    }

    /// `request_server_enabled`, read now. A failed read routes to Go.
    pub async fn refresh_request_server(&self) -> bool {
        let enabled = request_server_enabled(&self.pool).await.unwrap_or(true);
        self.request_server_enabled
            .store(enabled, Ordering::Relaxed);
        enabled
    }

    pub fn personal_needs_go(&self) -> bool {
        self.personal_needs_go.load(Ordering::Relaxed)
    }

    /// `OnUserSessionsRevoked`: every Go replica discards its cached Jellyfin-compatible sessions.
    /// Without a bus no event can reach Go, and persistent lookups still check the deleted rows.
    pub async fn publish_sessions_revoked(&self, user_id: i64) {
        let Some(bus) = &self.bus else {
            return;
        };
        let event = Event {
            event_type: EVENT_USER_SESSIONS_REVOKED.to_owned(),
            payload: user_id.to_string(),
        };
        if let Err(e) = bus.publish(CHANNEL_ADMIN, event).await {
            tracing::warn!(user_id, error = %e, "publish session revocation failed");
        }
    }

    /// The request's `auditmutation.LogContext`.
    pub fn audit_request(
        self: &Arc<Self>,
        r: &Request,
        opted_in: bool,
    ) -> silo_auth::audit::AuditRequest {
        let fields = r
            .extensions
            .get::<LogContext>()
            .map(|log| log.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_default();
        let hub = self.hub.clone();
        silo_auth::audit::AuditRequest {
            opted_in,
            client_ip: client_ip_of(r),
            user_id: fields.user_id,
            impersonator_user_id: fields.impersonator_user_id,
            session_id: fields.session_id,
            request_id: request_id_of(r),
            node_id: self.node_id.clone(),
            method: r.method.clone(),
            path: String::from_utf8_lossy(&r.url.path).into_owned(),
            pattern: pattern_of(r),
            user_agent: String::from_utf8_lossy(r.header.get("User-Agent")).into_owned(),
            started: Instant::now(),
            publish: Some(Arc::new(move |json| {
                if let Err(e) = hub.publish_append(silo_runtime::logstream::Stream::Audit, json) {
                    tracing::warn!(component = "activitylog", error = %e, "publishing an audit row failed");
                }
            })),
            committed: r.extensions.get::<LogContext>().map(|log| {
                let log = log.clone();
                Arc::new(move |status| {
                    log.0
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .committed_statuses
                        .push(status);
                }) as Arc<dyn Fn(i32) + Send + Sync>
            }),
        }
    }

    /// One reload: what the settings event and the policy event each change in Go.
    async fn reload(&self, logger: &DecisionLogger, pdp: &Pdp, sources: &mut Option<Sources>) {
        let needs_go = personal_needs_go(&self.pool).await.unwrap_or(true);
        self.personal_needs_go.store(needs_go, Ordering::Relaxed);
        let installed = plugins_installed(&self.pool).await.unwrap_or(true);
        self.plugins_installed.store(installed, Ordering::Relaxed);
        let enabled = request_server_enabled(&self.pool).await.unwrap_or(true);
        self.request_server_enabled
            .store(enabled, Ordering::Relaxed);
        let meili = search_meilisearch(&self.pool).await.unwrap_or(true);
        self.search_meilisearch.store(meili, Ordering::Relaxed);
        match external_sign_in_configured(&self.pool).await {
            Ok(configured) => self.external_sign_in.store(configured, Ordering::Relaxed),
            Err(e) => {
                tracing::warn!(component = "front", error = %e, "reading auth bindings failed")
            }
        }
        match self.settings.get_all().await {
            Ok(all) => {
                let (access, refresh) = token_expiries(&all);
                self.jwt.set_expiries(access, refresh);
                self.rate.reload(config_from_settings(&all));
                apply_decision_log_settings(logger, &all);
                match trusted_cidrs(all.get(clientip::SETTING_TRUSTED_PROXIES)) {
                    Ok(cidrs) => self.resolver.update_trusted_cidrs(cidrs),
                    Err(e) => {
                        tracing::warn!(component = "app", error = %e, "clientip config reload failed");
                    }
                }
            }
            Err(e) => tracing::warn!(component = "app", error = %e, "reading settings failed"),
        }
        match active_sources(&self.pool).await {
            Ok(current) if sources.as_ref() != Some(&current) => {
                let generation = policy_generation(&self.pool)
                    .await
                    .unwrap_or(pdp.generation());
                match engines_for(&current) {
                    Ok((scope, permission)) => {
                        pdp.swap(scope, permission, generation);
                        self.policy_refused.store(false, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::error!(component = "policy", error = %e, "custom policy not loaded; rows behind a credential go to Go until it loads");
                        self.policy_refused.store(true, Ordering::Relaxed);
                    }
                }
                *sources = Some(current);
            }
            Ok(_) => {
                if let Ok(generation) = policy_generation(&self.pool).await {
                    pdp.set_generation(generation);
                }
            }
            Err(e) => tracing::warn!(component = "policy", error = %e, "reading policies failed"),
        }
    }
}

type Sources = Vec<(String, String)>;

/// `policy.Store.ActiveSources`.
async fn active_sources(pool: &Pool) -> Result<Sources, String> {
    let rows = pool
        .query(
            "SELECT d.domain, v.rego_source FROM policy_documents d
             JOIN policy_document_versions v ON v.id = d.active_version_id
             WHERE d.enabled
             ORDER BY d.domain ASC, d.id ASC",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get(0)
                    .map_err(|e: silo_pg::DriverError| e.to_string())?,
                r.try_get(1)
                    .map_err(|e: silo_pg::DriverError| e.to_string())?,
            ))
        })
        .collect()
}

fn engine_for(sources: &Sources) -> Result<Engine, String> {
    let mut custom = std::collections::BTreeMap::new();
    for (domain, source) in sources {
        if let Some(domain) = silo_gate::policy::Domain::parse(domain) {
            custom.insert(domain, source.clone());
        }
    }
    Engine::with_custom(&custom).map_err(|e| e.to_string())
}

/// One engine per decision; see [`Pdp`].
fn engines_for(sources: &Sources) -> Result<(Engine, Engine), String> {
    Ok((engine_for(sources)?, engine_for(sources)?))
}

/// `PolicyStore.Generation`.
async fn policy_generation(pool: &Pool) -> Result<i64, String> {
    let rows = pool
        .query(
            "SELECT generation FROM policy_generation WHERE id = true",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    match rows.first() {
        Some(row) => row
            .try_get(0)
            .map_err(|e: silo_pg::DriverError| e.to_string()),
        None => Err("no policy generation row".to_owned()),
    }
}

async fn load_policy(pool: &Pool) -> Result<((Engine, Engine), i64), String> {
    let sources = active_sources(pool).await?;
    let generation = policy_generation(pool).await?;
    Ok((engines_for(&sources)?, generation))
}

/// `chimw.GetReqID`.
pub fn request_id_of(r: &Request) -> String {
    r.extensions
        .get::<RequestId>()
        .map(|id| id.0.clone())
        .unwrap_or_default()
}

/// `clientip.FromContext`, the address.
pub fn client_ip_of(r: &Request) -> String {
    client_context(r)
        .map(|c| c.client_ip.clone())
        .unwrap_or_default()
}

/// `clientip.FromContext`.
fn client_context(r: &Request) -> Option<&RequestContext> {
    r.extensions.get::<RequestContext>()
}

/// The route pattern a logger reports, set by the handler wrappers.
#[derive(Clone)]
struct RowPattern(String);

/// A writer that remembers the status, as `requestStatusWriter` and `statusWriter` do.
struct StatusWriter<'a> {
    inner: &'a mut dyn ResponseWriter,
    status: u16,
    wrote: bool,
    bytes: u64,
}

impl ResponseWriter for StatusWriter<'_> {
    fn header(&mut self) -> &mut Header {
        self.inner.header()
    }
    fn write_header(&mut self, code: u16) -> BoxFuture<'_, ()> {
        if !self.wrote {
            self.status = code;
            self.wrote = true;
        }
        self.inner.write_header(code)
    }
    fn write<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, Result<usize, WriteError>> {
        self.wrote = true;
        self.bytes += data.len() as u64;
        self.inner.write(data)
    }
    fn write_string<'a>(&'a mut self, data: &'a str) -> BoxFuture<'a, Result<usize, WriteError>> {
        self.wrote = true;
        self.bytes += data.len() as u64;
        self.inner.write_string(data)
    }
    fn flush(&mut self) -> BoxFuture<'_, Result<(), WriteError>> {
        self.inner.flush()
    }
    fn hijack(&mut self) -> BoxFuture<'_, Result<Hijacked, WriteError>> {
        self.inner.hijack()
    }
}

/// A Go string holds any bytes, and a value that is not text must stay a value that matches nothing,
/// not vanish.
fn header_values(h: &Header, key: &str) -> Vec<String> {
    h.values(key)
        .iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect()
}

fn as_strs(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

/// `clientip.Middleware`.
fn resolve_client(resolver: &Resolver, r: &Request) -> RequestContext {
    let (xff, real, forwarded, proto, host, upgrade, connection) = (
        header_values(&r.header, "X-Forwarded-For"),
        header_values(&r.header, "X-Real-Ip"),
        header_values(&r.header, "Forwarded"),
        header_values(&r.header, "X-Forwarded-Proto"),
        header_values(&r.header, "X-Forwarded-Host"),
        header_values(&r.header, "Upgrade"),
        header_values(&r.header, "Connection"),
    );
    let (xff, real, forwarded, proto, host, upgrade, connection) = (
        as_strs(&xff),
        as_strs(&real),
        as_strs(&forwarded),
        as_strs(&proto),
        as_strs(&host),
        as_strs(&upgrade),
        as_strs(&connection),
    );
    resolver.middleware(&RequestFields {
        remote_addr: &r.remote_addr,
        host: std::str::from_utf8(&r.host).unwrap_or_default(),
        tls: false,
        x_forwarded_for: &xff,
        x_real_ip: &real,
        forwarded: &forwarded,
        x_forwarded_proto: &proto,
        x_forwarded_host: &host,
        upgrade: &upgrade,
        connection: &connection,
    })
}

/// `clampLabel`.
fn clamp_label(value: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(value);
    let mut out: String = silo_gocompat::strings::trim_space(&text)
        .chars()
        .filter(|c| *c >= '\u{20}' && *c != '\u{7f}')
        .collect();
    if out.len() > limit {
        let mut end = limit;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// `report`'s log line: a v2 request is logged once, by operation, and never by its raw path.
#[allow(clippy::too_many_arguments)]
fn v2_request_line(
    r: &Request,
    id: &str,
    method: &str,
    status: u16,
    duration_ms: u64,
    body_bytes: u64,
    client_ip: &str,
    fields: &silo_gate::mw::auth::LogFields,
) {
    let or = |value: &'_ str, other: &'static str| -> String {
        if value.is_empty() {
            other.to_owned()
        } else {
            value.to_owned()
        }
    };
    let method_label = if METHOD_LABELS.contains(&method) {
        method
    } else {
        "other"
    };
    let class = match status {
        0 => "abandoned".to_owned(),
        _ => format!("{}xx", status / 100),
    };
    let name = clamp_label(r.header.get("X-Silo-Client"), 64);
    let version = clamp_label(r.header.get("X-Silo-Client-Version"), 32);
    tracing::info!(
        component = "apiv2",
        request_id = %id,
        api_major = 2,
        operation_id = %or(&fields.v2_operation_id, "none"),
        method = %method_label,
        path_pattern = %fields.v2_path_pattern,
        status,
        status_class = %class,
        error_code = %or(&fields.v2_error_code, "none"),
        auth_class = %or(&fields.v2_auth_class, "anonymous"),
        duration_ms,
        body_bytes,
        client_ip = %client_ip,
        client_name = (!name.is_empty()).then_some(name.as_str()),
        client_version = (!version.is_empty()).then_some(version.as_str()),
        user_id = fields.user_id,
        "apiv2 request"
    );
}

/// `methodLabel`'s standard set.
const METHOD_LABELS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// `observeOperation` for a raw public operation, which has no `v2_wrap`.
pub fn note_public_operation(r: &Request, pattern: &str) {
    let Some(log) = r.extensions.get::<LogContext>() else {
        return;
    };
    let mut log = log.0.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(meta) = operations().get(pattern).and_then(|m| m.get(&r.method)) {
        log.v2_operation_id.clone_from(&meta.operation_id);
    }
    pattern.clone_into(&mut log.v2_path_pattern);
    "public".clone_into(&mut log.v2_auth_class);
}

/// `noteProblem`.
pub fn note_problem(r: &Request, slug: &str) {
    if let Some(log) = r.extensions.get::<LogContext>() {
        log.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .v2_error_code = slug.to_owned();
    }
}

impl Stack {
    /// The first half of `useBaseMiddleware`: request ID, client IP, request logger. [`recoverer`] and
    /// [`Self::observe_middleware`] follow it, so the logger sees a recovered panic's 500 and the other
    /// two do not run for it, as in Go.
    pub fn base_middleware(self: &Arc<Self>) -> Middleware {
        let stack = self.clone();
        middleware_fn(move |next: BoxHandler| {
            let stack = stack.clone();
            handler_fn(move |w, r| {
                let stack = stack.clone();
                let next = next.clone();
                Box::pin(async move {
                    let id = new_request_id();
                    r.extensions.insert(RequestId(id.clone()));
                    let client = resolve_client(&stack.resolver, r);
                    let client_ip = client.client_ip.clone();
                    r.extensions.insert(client);
                    let log = LogContext::default();
                    r.extensions.insert(log.clone());
                    let path = String::from_utf8_lossy(&r.url.path).into_owned();
                    let method = r.method.clone();
                    let user_agent =
                        String::from_utf8_lossy(r.header.get("User-Agent")).into_owned();
                    let started = Instant::now();

                    let mut wrapped = StatusWriter {
                        inner: w,
                        status: 200,
                        wrote: false,
                        bytes: 0,
                    };
                    next.serve_http(&mut wrapped, r).await;
                    let status = wrapped.status;
                    let body_bytes = wrapped.bytes;

                    let pattern = pattern_of(r);
                    let fields = log.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let is_v2 = path.starts_with(silo_gate::mw::API_V2_PREFIX);
                    let session_id =
                        (!fields.session_id.is_empty()).then_some(fields.session_id.as_str());
                    if is_v2 {
                        v2_request_line(
                            r,
                            &id,
                            &method,
                            status,
                            started.elapsed().as_millis() as u64,
                            body_bytes,
                            &client_ip,
                            &fields,
                        );
                    } else if !request_logger_skips(&path) {
                        tracing::info!(
                            component = "api",
                            request_id = %id,
                            method = %method,
                            path = %path,
                            path_pattern = %pattern,
                            status,
                            duration_ms = started.elapsed().as_millis() as u64,
                            client_ip = %client_ip,
                            user_agent = %user_agent,
                            node_id = %stack.node_id,
                            user_id = fields.user_id,
                            session_id,
                            "api request"
                        );
                    }
                })
            })
        })
    }

    /// The rest of `useBaseMiddleware`: metrics and the activity log.
    pub fn observe_middleware(self: &Arc<Self>) -> Middleware {
        let stack = self.clone();
        middleware_fn(move |next: BoxHandler| {
            let stack = stack.clone();
            handler_fn(move |w, r| {
                let stack = stack.clone();
                let next = next.clone();
                Box::pin(async move {
                    let path = String::from_utf8_lossy(&r.url.path).into_owned();
                    let method = r.method.clone();
                    let user_agent =
                        String::from_utf8_lossy(r.header.get("User-Agent")).into_owned();
                    let started = Instant::now();
                    let timestamp = SystemTime::now();
                    let mut wrapped = StatusWriter {
                        inner: w,
                        status: 200,
                        wrote: false,
                        bytes: 0,
                    };
                    next.serve_http(&mut wrapped, r).await;
                    let status = wrapped.status;
                    let elapsed = started.elapsed();
                    let pattern = pattern_of(r);
                    if !path.starts_with(silo_gate::mw::API_V2_PREFIX) {
                        stack.metrics.observe(&method, &pattern, status, elapsed);
                    }
                    if activity::recorded(&path) {
                        let fields = r
                            .extensions
                            .get::<LogContext>()
                            .map(|log| log.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
                            .unwrap_or_default();
                        stack.activity.write(LogEntry {
                            timestamp,
                            client_ip: client_context(r)
                                .map(|c| c.client_ip.clone())
                                .unwrap_or_default(),
                            user_id: fields.user_id,
                            impersonator_user_id: fields.impersonator_user_id,
                            session_id: fields.session_id,
                            request_id: request_id_of(r),
                            node_id: stack.node_id.clone(),
                            method,
                            path: path.clone(),
                            path_pattern: if pattern.is_empty() { path } else { pattern },
                            status_code: i32::from(status),
                            user_agent,
                            duration_ms: elapsed.as_millis() as i32,
                            persisted: fields.committed_statuses.contains(&i32::from(status)),
                        });
                    }
                })
            })
        })
    }

    async fn demo_enabled(&self) -> String {
        self.settings.get("demo.enabled").await.unwrap_or_default()
    }

    /// Runs a gate list. Headers a gate sets go to `sink`.
    pub async fn run_steps(
        &self,
        steps: &[Step],
        sink: &mut Header,
        r: &mut Request,
    ) -> Result<(), Denial> {
        for step in steps {
            let client = client_context(r);
            let client_ip = client.map(|c| c.client_ip.clone()).unwrap_or_default();
            let peer_ip = client.map(RequestContext::peer_ip).unwrap_or_default();
            match step {
                Step::Auth => self.auth.require_auth(r).await?,
                Step::AttachSession => self.auth.attach_session(r).await,
                Step::DirectDownload => self.auth.direct_download(r).await?,
                Step::Demo => auth::demo_guard(r, || self.demo_enabled()).await?,
                Step::DemoRestricted => auth::demo_gate(r, || self.demo_enabled()).await?,
                Step::RateLimit | Step::RateLimitEndpoint(_) => {
                    let claims: Option<Arc<Claims>> = get_claims(r);
                    let path = String::from_utf8_lossy(&r.url.path).into_owned();
                    let req = RateRequest {
                        client_ip: &client_ip,
                        peer_ip: &peer_ip,
                        path: &path,
                        claims: claims.as_deref(),
                    };
                    match step {
                        Step::RateLimitEndpoint(name) => {
                            self.rate.check_endpoint(sink, &req, name).await?
                        }
                        _ => self.rate.check(sink, &req).await?,
                    }
                }
                Step::Viewer => viewer::require_viewer_access(&self.viewer, r).await?,
                Step::OptionalViewer => {
                    viewer::optional_profile_viewer_access(&self.viewer, r).await?
                }
                Step::Household => viewer::household_profile_gate(&self.viewer, r).await?,
                Step::Profile => auth::require_profile(r)?,
                Step::Admin => auth::require_admin(r)?,
                Step::ActingAdmin => self.gates.require_acting_admin(r, &client_ip).await?,
                Step::MarkerEdit => self.gates.require_marker_edit(r, &client_ip).await?,
                Step::MetadataCuration => {
                    self.gates
                        .require_metadata_curation(r, r.url_param("id"), &client_ip)
                        .await?
                }
            }
        }
        Ok(())
    }

    /// A v1 route: the gates, the v1 refusal body, then the handler.
    pub fn v1(
        self: &Arc<Self>,
        pattern: &str,
        steps: &'static [Step],
        handler: BoxHandler,
    ) -> BoxHandler {
        let stack = self.clone();
        let pattern = pattern.to_owned();
        handler_fn(move |w, r| {
            let stack = stack.clone();
            let handler = handler.clone();
            let pattern = pattern.clone();
            Box::pin(async move {
                r.extensions.insert(RowPattern(pattern));
                if let Err(denial) = stack.run_steps(steps, w.header(), r).await {
                    write_v1_denial(w, &denial).await;
                    return;
                }
                handler.serve_http(w, r).await;
            })
        })
    }

    /// A v1 route group's `Use` list, for a mounted subrouter: it runs before the subrouter's own 404 and
    /// 405, so an unauthenticated caller gets the 401 at any path below the mount.
    pub fn v1_group(self: &Arc<Self>, steps: &'static [Step]) -> Middleware {
        let stack = self.clone();
        middleware_fn(move |next: BoxHandler| {
            let stack = stack.clone();
            handler_fn(move |w, r| {
                let stack = stack.clone();
                let next = next.clone();
                Box::pin(async move {
                    if let Err(denial) = stack.run_steps(steps, w.header(), r).await {
                        write_v1_denial(w, &denial).await;
                        return;
                    }
                    next.serve_http(w, r).await;
                })
            })
        })
    }

    /// A v2 operation whose gates differ from its class's: a named budget, or a demo restriction.
    pub fn v2_steps(
        self: &Arc<Self>,
        pattern: &str,
        steps: &'static [Step],
        handler: BoxHandler,
    ) -> BoxHandler {
        v2_wrap(Some(self.clone()), pattern, steps, handler)
    }

    /// A v2 operation: `classGate` with the `denialWriter` translation, `defaultHeaders`, and the guards.
    pub fn v2(self: &Arc<Self>, pattern: &str, class: V2Class, handler: BoxHandler) -> BoxHandler {
        v2_wrap(Some(self.clone()), pattern, class.steps(), handler)
    }
}

/// `middleware.Recoverer`. An abort still ends the connection, and an upgrade gets no status.
pub fn recoverer() -> Middleware {
    middleware_fn(|next: BoxHandler| {
        handler_fn(move |w, r| {
            let next = next.clone();
            Box::pin(async move {
                let served = AssertUnwindSafe(next.serve_http(w, r)).catch_unwind().await;
                if let Err(payload) = served {
                    if payload.is::<AbortHandler>() {
                        resume_unwind(payload);
                    }
                    tracing::error!(component = "api", panic = %panic_text(payload.as_ref()), "panic serving a request");
                    if r.header.get("Connection") != b"Upgrade" {
                        w.write_header(500).await;
                    }
                }
            })
        })
    })
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic".to_owned())
}

/// `bufferedWriter`: a v2 operation's response stays here until it ends, so a panic can replace it.
struct BufferedWriter<'a> {
    inner: &'a mut dyn ResponseWriter,
    status: u16,
    body: Vec<u8>,
}

impl ResponseWriter for BufferedWriter<'_> {
    fn header(&mut self) -> &mut Header {
        self.inner.header()
    }
    fn write_header(&mut self, code: u16) -> BoxFuture<'_, ()> {
        if self.status == 0 {
            self.status = code;
        }
        Box::pin(async {})
    }
    fn write<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, Result<usize, WriteError>> {
        if self.status == 0 {
            self.status = 200;
        }
        self.body.extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
    fn write_string<'a>(&'a mut self, data: &'a str) -> BoxFuture<'a, Result<usize, WriteError>> {
        self.write(data.as_bytes())
    }
    fn flush(&mut self) -> BoxFuture<'_, Result<(), WriteError>> {
        Box::pin(async { Ok(()) })
    }
    fn hijack(&mut self) -> BoxFuture<'_, Result<Hijacked, WriteError>> {
        self.inner.hijack()
    }
}

impl BufferedWriter<'_> {
    /// `discard`: the operation's status, body and headers go, except the request ID.
    fn discard(&mut self) {
        self.status = 0;
        self.body.clear();
        let h = self.inner.header();
        let id = h.get_raw_values("X-Request-ID").to_vec();
        *h = Header::new();
        if !id.is_empty() {
            h.set_raw("X-Request-ID", id);
        }
    }

    /// `flush`.
    async fn finish(self) {
        let status = if self.status == 0 { 200 } else { self.status };
        let mut body = self.body;
        let h = self.inner.header();
        // `IdentityEncoded`: declares identity, and no-transform, to preserve the strong ETag.
        if !h.get("ETag").is_empty() {
            h.set("Content-Encoding", "identity");
            let values = h.values("Cache-Control");
            let policy = values
                .iter()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect::<Vec<_>>()
                .join(", ");
            let transformed = policy.split(',').any(|d| {
                silo_gocompat::strings::equal_fold(
                    silo_gocompat::strings::trim_space(d),
                    "no-transform",
                )
            });
            if !transformed {
                let joined = if policy.is_empty() {
                    "no-transform".to_owned()
                } else {
                    format!("{policy}, no-transform")
                };
                h.set("Cache-Control", joined);
            }
        }
        if status == 304 || status == 204 {
            h.del("Content-Type");
            body.clear();
        } else if h.get("Content-Length").is_empty() {
            h.set("Content-Length", body.len().to_string());
        }
        self.inner.write_header(status).await;
        let _ = self.inner.write(&body).await;
    }
}

/// `writeUnauthorized` and its siblings.
pub async fn write_v1_denial(w: &mut dyn ResponseWriter, denial: &Denial) {
    auth::apply_denial_headers(w.header(), denial);
    w.write_header(denial.status).await;
    let _ = w.write(&denial.v1_body()).await;
}

/// `denialWriter.problem`.
pub fn denial_problem(denial: &Denial) -> Problem {
    use silo_gate::mw::denial::{
        CODE_PASSWORD_CHANGE_REQUIRED, CODE_SERVICE_UNAVAILABLE,
        CREDENTIAL_CHECK_RETRY_AFTER_SECONDS,
    };
    let detail_or = |fallback: &str| {
        if silo_gocompat::strings::trim_space(&denial.message).is_empty() {
            fallback.to_owned()
        } else {
            denial.message.clone()
        }
    };
    match denial.code {
        "unauthorized" => match denial.reason {
            reason::SESSION_INVALID => Problem::new(
                find("session_expired"),
                "The session is no longer valid; sign in again.",
            ),
            reason::TOKEN_REFRESH_REQUIRED => Problem::new(
                find("token_refresh_required"),
                "The account's role changed; refresh the session and retry the request.",
            ),
            reason::INVALID_CREDENTIAL | reason::ACCOUNT_DISABLED => Problem::new(
                find("invalid_token"),
                "The credential is invalid or expired.",
            ),
            _ => Problem::new(
                find("authentication_required"),
                "Authentication is required.",
            ),
        },
        "profile_unverified" => Problem::new(
            find("profile_verification_required"),
            "The declared profile is locked; verify it and retry with X-Profile-Token.",
        ),
        CODE_PASSWORD_CHANGE_REQUIRED => Problem::new(
            find("password_change_required"),
            "The account holds a temporary password; change it, then refresh the session.",
        ),
        "forbidden" | "demo_restricted" => Problem::new(
            find("permission_denied"),
            detail_or("The caller is not permitted to perform this operation."),
        ),
        "not_found" => Problem::new(
            find("not_found"),
            detail_or("The requested resource does not exist."),
        ),
        "rate_limit_exceeded" => Problem::new(
            find("rate_limited"),
            "Too many requests; retry after the Retry-After delay.",
        )
        .with_header("Retry-After", denial.retry_after.unwrap_or(1).to_string()),
        CODE_SERVICE_UNAVAILABLE => {
            let detail = if denial.reason == reason::VIEWER_ACCESS_UNAVAILABLE {
                "The viewer's access could not be resolved right now; retry after the Retry-After delay."
            } else {
                "The sign-in could not be checked right now; retry after the Retry-After delay."
            };
            Problem::new(find("dependency_unavailable"), detail).with_header(
                "Retry-After",
                denial
                    .retry_after
                    .unwrap_or(CREDENTIAL_CHECK_RETRY_AFTER_SECONDS)
                    .to_string(),
            )
        }
        "bad_request" => match denial.reason {
            reason::PROFILE_HEADER_REQUIRED => Problem::new(
                find("validation_failed"),
                "The request did not pass validation; see errors.",
            )
            .with_errors([ProblemError {
                location: "header.x-profile-id".to_owned(),
                code: "required".to_owned(),
                detail: "The X-Profile-Id header is required.".to_owned(),
            }]),
            reason::ITEM_ID_REQUIRED => Problem::new(
                find("validation_failed"),
                "The request did not pass validation; see errors.",
            )
            .with_errors([ProblemError {
                location: "path.id".to_owned(),
                code: "required".to_owned(),
                detail: "The item id path parameter is required.".to_owned(),
            }]),
            _ => Problem::new(
                find("malformed_request"),
                "The request could not be parsed.",
            ),
        },
        _ => Problem::new(find("internal_error"), "An unexpected error occurred."),
    }
}

/// A catalog entry by id.
pub fn problem_type(id: &str) -> p::ProblemType {
    find(id)
}

fn find(id: &str) -> p::ProblemType {
    p::CATALOG
        .iter()
        .copied()
        .find(|t| t.id == id)
        .expect("a problem type in the catalog")
}

/// `writeProblem`. The encoder does not escape HTML.
pub async fn write_problem(w: &mut dyn ResponseWriter, r: &Request, mut problem: Problem) {
    problem.instance = p::request_instance(&request_id_of(r));
    if let Some(slug) = problem.r#type.strip_prefix(p::PROBLEM_TYPE_ORIGIN) {
        note_problem(r, slug);
    }
    let mut body = Vec::new();
    {
        let mut enc = silo_gocompat::json::Encoder::new(&mut body);
        enc.set_escape_html(false);
        enc.encode(&problem.to_body()).expect("a problem marshals");
    }
    let h = w.header();
    for (name, value) in problem.headers() {
        h.add(name, value.as_bytes());
    }
    h.set("Content-Type", p::PROBLEM_CONTENT_TYPE);
    h.set("Cache-Control", p::DEFAULT_CACHE_CONTROL);
    w.write_header(problem.status).await;
    let _ = w.write(&body).await;
}

/// `acceptsRepresentation`.
fn accepts_json(accept: &str) -> bool {
    let (mut best, mut best_q) = (0, 0.0);
    for part in accept.split(',') {
        let mut fields = part.split(';');
        let media = silo_gocompat::strings::to_lower(silo_gocompat::strings::trim_space(
            fields.next().unwrap_or_default(),
        ));
        let mut q = 1.0;
        for param in fields {
            if let Some(v) = silo_gocompat::strings::trim_space(param).strip_prefix("q=")
                && let Ok(v) = v.parse::<f64>()
            {
                q = v;
            }
        }
        let specificity = match media.as_str() {
            "application/json" => 3,
            "application/*" => 2,
            "*/*" => 1,
            _ => continue,
        };
        if specificity > best {
            (best, best_q) = (specificity, q);
        }
    }
    best > 0 && best_q > 0.0
}

/// What the contract declares about one v2 operation.
#[derive(Clone, Debug, Default)]
pub struct OperationMeta {
    operation_id: String,
    /// `metaIdentityOnly`: its output declares an ETag, or it is a guarded write answering a receipt.
    identity_only: bool,
    /// `queryParams`, name to whether it is an array and whether it is a boolean.
    query: HashMap<String, QueryParam>,
    /// The path and query parameters Huma parses and validates, in the contract's order.
    params: Vec<(String, String, serde_json::Value, bool)>,
    /// The JSON body schema.
    body: Option<serde_json::Value>,
    body_required: bool,
}

/// `queryParam`.
#[derive(Clone, Copy, Debug, Default)]
struct QueryParam {
    array: bool,
    boolean: bool,
}

/// Path, then method, read from the contract the operations were generated from.
fn operations() -> &'static HashMap<String, HashMap<String, OperationMeta>> {
    static OPERATIONS: OnceLock<HashMap<String, HashMap<String, OperationMeta>>> = OnceLock::new();
    OPERATIONS.get_or_init(|| {
        let document: serde_json::Value =
            silo_gocompat::json::unmarshal(silo_contracts::embedded::openapi_v2())
                .expect("the embedded contract is JSON");
        let mut out: HashMap<String, HashMap<String, OperationMeta>> = HashMap::new();
        for (path, item) in document["paths"].as_object().expect("paths") {
            for (method, op) in item.as_object().expect("a path item") {
                out.entry(path.clone()).or_default().insert(
                    silo_gocompat::strings::to_upper(method),
                    operation_meta(method, op),
                );
            }
        }
        out
    })
}

fn operation_meta(method: &str, op: &serde_json::Value) -> OperationMeta {
    let declares_etag = op["responses"].as_object().is_some_and(|responses| {
        responses.values().any(|r| {
            r["headers"]
                .as_object()
                .is_some_and(|h| h.contains_key("ETag"))
        })
    });
    // `GuardedReceipt` is a guarded PUT or PATCH: the one guarded write that does not declare the ETag.
    let guarded = op["x-silo-guarded"].as_bool().unwrap_or(false);
    let receipt = guarded && matches!(method, "put" | "patch");
    let mut query = HashMap::new();
    let mut params = Vec::new();
    for parameter in op["parameters"].as_array().into_iter().flatten() {
        let location = parameter["in"].as_str().unwrap_or_default();
        if matches!(location, "path" | "query" | "header") && parameter["schema"].is_object() {
            params.push((
                location.to_owned(),
                parameter["name"].as_str().unwrap_or_default().to_owned(),
                parameter["schema"].clone(),
                parameter["required"].as_bool().unwrap_or(false),
            ));
        }
        if parameter["in"] == "query" && parameter["schema"].is_object() {
            let kind = &parameter["schema"]["type"];
            query.insert(
                parameter["name"].as_str().unwrap_or_default().to_owned(),
                QueryParam {
                    array: kind == "array",
                    boolean: kind == "boolean",
                },
            );
        }
    }
    let body = op["requestBody"]["content"]["application/json"]["schema"].clone();
    OperationMeta {
        operation_id: op["operationId"].as_str().unwrap_or_default().to_owned(),
        identity_only: declares_etag || receipt,
        query,
        params,
        body: body.is_object().then_some(body),
        body_required: op["requestBody"]["required"].as_bool().unwrap_or(false),
    }
}

fn validation_problem(errors: Vec<ProblemError>) -> Problem {
    Problem::new(
        find("validation_failed"),
        "The request did not pass validation; see errors.",
    )
    .with_errors(errors)
}

/// `queryGuard`, then Huma's `RejectUnknownQueryParameters`. A problem in the query is the only thing
/// either answers.
fn query_problem(raw: &[u8], meta: &OperationMeta) -> Option<Problem> {
    if raw.is_empty() {
        return None;
    }
    let (values, error) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(raw));
    if error.is_some() {
        return Some(Problem::new(
            find("malformed_request"),
            "The query string is not valid percent-encoded form data.",
        ));
    }
    let mut invalid = Vec::new();
    let mut unknown = Vec::new();
    for (name, list) in &values {
        let Some(param) = meta.query.get(name) else {
            unknown.push(ProblemError {
                location: format!("query.{name}"),
                code: "unknown_parameter".to_owned(),
                detail: "unknown query parameter".to_owned(),
            });
            continue;
        };
        if list.len() > 1 && !param.array {
            return Some(Problem::new(
                find("malformed_request"),
                "A scalar query parameter was repeated.",
            ));
        }
        if param.boolean {
            for value in list {
                if value != "true" && value != "false" {
                    invalid.push(ProblemError {
                        location: format!("query.{name}"),
                        code: "invalid_type".to_owned(),
                        detail: "expected the lowercase literal true or false".to_owned(),
                    });
                }
            }
        }
    }
    if !invalid.is_empty() {
        return Some(validation_problem(invalid));
    }
    (!unknown.is_empty()).then(|| validation_problem(unknown))
}

/// `identityForbidden`.
fn identity_forbidden(field: &str) -> bool {
    let (mut identity, mut star) = (-1.0, -1.0);
    for part in field.split(',') {
        let mut fields = part.split(';');
        let coding = silo_gocompat::strings::to_lower(silo_gocompat::strings::trim_space(
            fields.next().unwrap_or_default(),
        ));
        if coding != "identity" && coding != "*" {
            continue;
        }
        let mut q: f64 = 1.0;
        for param in fields {
            if let Some(v) = silo_gocompat::strings::trim_space(param).strip_prefix("q=")
                && let Ok(v) = v.parse::<f64>()
            {
                q = v;
            }
        }
        if coding == "identity" {
            identity = q;
        } else {
            star = q;
        }
    }
    if identity >= 0.0 {
        return identity == 0.0;
    }
    star == 0.0
}

/// `contentEncodingOK`.
fn content_encoding_ok(field: &str) -> bool {
    silo_gocompat::strings::trim_space(field).is_empty()
        || field.split(',').all(|part| {
            silo_gocompat::strings::to_lower(silo_gocompat::strings::trim_space(part)) == "identity"
        })
}

fn v2_wrap(
    stack: Option<Arc<Stack>>,
    pattern: &str,
    steps: &'static [Step],
    handler: BoxHandler,
) -> BoxHandler {
    let pattern = pattern.to_owned();
    let methods = operations()
        .get(&pattern)
        .unwrap_or_else(|| panic!("{pattern} is not in the contract"));
    handler_fn(move |w, r| {
        let stack = stack.clone();
        let handler = handler.clone();
        let pattern = pattern.clone();
        Box::pin(async move {
            let meta_early = methods.get(&r.method);
            if let (Some(meta), Some(log)) = (meta_early, r.extensions.get::<LogContext>()) {
                let mut log = log.0.lock().unwrap_or_else(|e| e.into_inner());
                log.v2_operation_id.clone_from(&meta.operation_id);
                log.v2_path_pattern.clone_from(&pattern);
                // `observeOperation`.
                if steps.is_empty() {
                    "public".clone_into(&mut log.v2_auth_class);
                }
            }
            r.extensions.insert(RowPattern(pattern));
            // `bufferResponse`.
            let mut buffered = BufferedWriter {
                inner: w,
                status: 0,
                body: Vec::new(),
            };
            let meta = methods.get(&r.method);
            let served =
                AssertUnwindSafe(v2_operation(stack, steps, meta, &handler, &mut buffered, r))
                    .catch_unwind()
                    .await;
            if let Err(payload) = served {
                if payload.is::<AbortHandler>() {
                    resume_unwind(payload);
                }
                tracing::error!(component = "apiv2", request_id = %request_id_of(r), panic = %panic_text(payload.as_ref()), "apiv2 handler panic");
                buffered.discard();
                write_problem(
                    &mut buffered,
                    r,
                    Problem::new(find("internal_error"), "An unexpected error occurred."),
                )
                .await;
            }
            buffered.finish().await;
        })
    })
}

/// The operation behind `bufferResponse`: `defaultHeaders`, `classGate`, and the guards, in Go's order.
async fn v2_operation(
    stack: Option<Arc<Stack>>,
    steps: &'static [Step],
    meta: Option<&OperationMeta>,
    handler: &BoxHandler,
    w: &mut dyn ResponseWriter,
    r: &mut Request,
) {
    w.header().set("Cache-Control", p::DEFAULT_CACHE_CONTROL);
    if let Some(stack) = &stack {
        // `denialWriter`: what a gate sets stays off the response unless translated.
        let mut sink = Header::new();
        if let Err(denial) = stack.run_steps(steps, &mut sink, r).await {
            write_problem(w, r, denial_problem(&denial)).await;
            return;
        }
        // `observeIdentity`.
        if let (Some(claims), Some(log)) = (
            silo_gate::mw::auth::get_claims(r),
            r.extensions.get::<LogContext>(),
        ) {
            let class = match claims.token_type.as_str() {
                silo_auth::claims::token_type::API_KEY => "api_key",
                silo_auth::claims::token_type::PLUGIN_ACCESS => "plugin",
                silo_auth::claims::token_type::ACCESS => "session",
                _ => "other",
            };
            let mut log = log.0.lock().unwrap_or_else(|e| e.into_inner());
            class.clone_into(&mut log.v2_auth_class);
            log.user_id = Some(claims.user_id);
        }
    }
    let accept = String::from_utf8_lossy(r.header.get("Accept")).into_owned();
    if !accept.is_empty() && !accepts_json(&accept) {
        write_problem(
            w,
            r,
            Problem::new(
                find("not_acceptable"),
                "No acceptable representation is available for this operation.",
            ),
        )
        .await;
        return;
    }
    r.header.set("Accept", "application/json");
    // `encodingGuard`, for the operations that declare a validator.
    let excluded = r.header.values("Accept-Encoding");
    if !excluded.is_empty() && meta.is_some_and(|m| m.identity_only) {
        let field: Vec<String> = excluded
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        if identity_forbidden(&field.join(",")) {
            write_problem(
                w,
                r,
                Problem::new(
                    find("not_acceptable"),
                    "This response carries a validator and is served identity-encoded; Accept-Encoding must not exclude identity.",
                ),
            )
            .await;
            return;
        }
    }
    // `mediaTypeGuard`.
    if !content_encoding_ok(&String::from_utf8_lossy(r.header.get("Content-Encoding"))) {
        write_problem(
            w,
            r,
            Problem::new(
                find("unsupported_media_type"),
                "Compressed request bodies are not supported; send an unencoded application/json body.",
            ),
        )
        .await;
        return;
    }
    let empty = OperationMeta::default();
    let meta = meta.unwrap_or(&empty);
    if meta.body.is_some() {
        let content_type = String::from_utf8_lossy(r.header.get("Content-Type")).into_owned();
        if !structured_media_type_ok(&content_type) {
            write_problem(
                w,
                r,
                Problem::new(
                    find("unsupported_media_type"),
                    "The request media type is not supported; send application/json.",
                ),
            )
            .await;
            return;
        }
        r.header.set("Content-Type", "application/json");
    }
    if let Some(problem) = query_problem(&r.url.raw_query, meta) {
        write_problem(w, r, problem).await;
        return;
    }
    if let Err(problem) =
        super::huma::read_input(r, &meta.params, meta.body.as_ref(), meta.body_required).await
    {
        write_problem(w, r, problem).await;
        return;
    }
    handler.serve_http(w, r).await;
}

/// `structuredMediaTypeOK`: exactly `application/json`, with `charset=utf-8` the only parameter.
fn structured_media_type_ok(content_type: &str) -> bool {
    use silo_gocompat::strings::{to_lower, trim_space};
    let mut parts = content_type.split(';');
    if to_lower(trim_space(parts.next().unwrap_or_default())) != "application/json" {
        return false;
    }
    parts.all(|param| {
        let mut kv = trim_space(param).splitn(2, '=');
        let (name, value) = (kv.next().unwrap_or_default(), kv.next());
        value.is_some_and(|value| {
            to_lower(trim_space(name)) == "charset" && to_lower(value.trim_matches('"')) == "utf-8"
        })
    })
}

/// The v1 `r.Route` mounts that hold native rows, read from `internal/api/router.go`. A v1 row's gates that
/// sit on or above its mount run before the subrouter matches, and so do its own 404 and 405.
const V1_MOUNTS: &[&str] = &[
    "/api/v1/admin/collections",
    "/api/v1/admin/notifications/server-channels",
    "/api/v1/admin",
    "/api/v1/api-keys",
    "/api/v1/auth",
    "/api/v1/collections",
    "/api/v1/devices",
    "/api/v1/favorites",
    "/api/v1/home/dismissals",
    "/api/v1/libraries",
    "/api/v1/library-playback-prefs",
    "/api/v1/notifications",
    "/api/v1/profiles",
    "/api/v1/progress",
    "/api/v1/ratings",
    "/api/v1/requests",
    "/api/v1/settings",
    "/api/v1/sync",
    "/api/v1/watchlist",
];

/// chi's `RoutePattern` for a v1 request that never reached a row: the deepest mount it matched.
fn v1_mount_pattern(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/api/v1")?;
    if !rest.starts_with('/') {
        return None;
    }
    for mount in V1_MOUNTS {
        if let Some(below) = path.strip_prefix(mount) {
            if below.is_empty() || below == "/" {
                return Some((*mount).to_owned());
            }
            if below.starts_with('/') {
                return Some(format!("{mount}/*"));
            }
        }
    }
    Some("/api/v1/*".to_owned())
}

/// chi's `RoutePattern`, as the loggers and metrics read it after the handler ran. A row with a mounted
/// `/` reads without the slash. Outside v1 a request that reached no row has no pattern.
pub fn pattern_of(r: &Request) -> String {
    match r.extensions.get::<RowPattern>() {
        Some(p) => {
            let pattern = p.0.as_str();
            pattern.strip_suffix('/').unwrap_or(pattern).to_owned()
        }
        // A row on a mounted subrouter that names no pattern, or the mount itself when a gate on it refused.
        None if r.pattern.starts_with("/api/v1/") => r.pattern.clone(),
        None => v1_mount_pattern(&String::from_utf8_lossy(&r.url.path)).unwrap_or_default(),
    }
}

/// A public v2 operation needs no stack.
pub fn v2_public(pattern: &str, handler: BoxHandler) -> BoxHandler {
    v2_wrap(None, pattern, &[], handler)
}

/// `requestID`: reuses the outer ID, or mints one standalone.
pub fn request_id_v2() -> Middleware {
    middleware_fn(|next: BoxHandler| {
        handler_fn(move |w, r| {
            let next = next.clone();
            Box::pin(async move {
                let mut id = request_id_of(r);
                if id.is_empty() {
                    id = new_request_id();
                    r.extensions.insert(RequestId(id.clone()));
                }
                w.header().set_raw("X-Request-ID", vec![id.into_bytes()]);
                next.serve_http(w, r).await;
            })
        })
    })
}

/// `rejectMalformedDeviceHeader`.
pub fn reject_malformed_device_header() -> Middleware {
    middleware_fn(|next: BoxHandler| {
        handler_fn(move |w, r| {
            let next = next.clone();
            Box::pin(async move {
                let values = r.header.values("X-Silo-Device-Id").to_vec();
                let refusal = if values.len() > 1 {
                    Some(format!(
                        "X-Silo-Device-Id must be sent once; the request carried it {} times",
                        values.len()
                    ))
                } else if let Some(value) = values.first() {
                    let trimmed = silo_http::header::trim_string(value).to_vec();
                    let valid = trimmed.iter().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')
                    });
                    if !trimmed.is_empty() && !valid {
                        Some("X-Silo-Device-Id must be a single device identifier: letters, digits, '.', '_', ':' or '-', with no comma or interior whitespace".to_owned())
                    } else {
                        r.header.set("X-Silo-Device-Id", trimmed);
                        None
                    }
                } else {
                    None
                };
                if let Some(detail) = refusal {
                    let problem = Problem::new(
                        find("validation_failed"),
                        "The request did not pass validation; see errors.",
                    )
                    .with_errors([ProblemError {
                        location: "header.x-silo-device-id".to_owned(),
                        code: "invalid".to_owned(),
                        detail,
                    }]);
                    write_problem(w, r, problem).await;
                    return;
                }
                next.serve_http(w, r).await;
            })
        })
    })
}

/// A JSON response the v1 way: `writeJSON`, HTML-escaped with a trailing newline.
pub async fn write_v1_json<T: Serialize>(w: &mut dyn ResponseWriter, status: u16, value: &T) {
    let mut body = silo_gocompat::json::marshal(value).expect("a response marshals");
    body.push(b'\n');
    w.header().set("Content-Type", "application/json");
    w.write_header(status).await;
    let _ = w.write(&body).await;
}

/// A JSON response the Huma way: `Content-Type` and no HTML escaping.
pub async fn write_v2_json<T: Serialize>(w: &mut dyn ResponseWriter, value: &T) {
    write_v2_json_status(w, 200, value).await;
}

/// [`write_v2_json`] with the operation's `DefaultStatus`.
pub async fn write_v2_json_status<T: Serialize>(
    w: &mut dyn ResponseWriter,
    status: u16,
    value: &T,
) {
    let mut body = Vec::new();
    {
        let mut enc = silo_gocompat::json::Encoder::new(&mut body);
        enc.set_escape_html(false);
        enc.encode(value).expect("a response marshals");
    }
    w.header().set("Content-Type", "application/json");
    w.write_header(status).await;
    let _ = w.write(&body).await;
}

/// `prepareCapabilityOperation`: hashes the document with its revision cleared, sets the revision, tags
/// the result, and answers preconditions. `render` marshals the document for a given revision.
pub async fn write_capability(
    w: &mut dyn ResponseWriter,
    r: &Request,
    operation: &str,
    render: impl Fn(&str) -> Vec<u8>,
) {
    let digest = |data: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(operation.as_bytes());
        hash.update([0u8]);
        hash.update(data);
        hex(&hash.finalize())
    };
    let revision = digest(&render(""));
    let body = render(&revision);
    let opaque = digest(&body);
    let tag = silo_core::apiv2::EntityTag {
        opaque,
        weak: false,
    };
    let wire = tag.to_wire();

    let joined = |name: &str| -> String {
        let values = r.header.values(name);
        if values.is_empty() {
            return String::new();
        }
        let list: Vec<String> = values
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        let list = list.join(", ");
        if silo_gocompat::strings::trim_space(&list).is_empty() {
            ",".to_owned()
        } else {
            list
        }
    };
    let (unchanged, problem) = silo_api_v2::precondition::evaluate_read_preconditions(
        &joined("If-Match"),
        &joined("If-None-Match"),
        &tag,
    );
    if let Some(problem) = problem {
        write_problem(w, r, problem).await;
        return;
    }
    let h = w.header();
    h.set("Cache-Control", "private, no-cache, no-transform");
    h.set("Content-Encoding", "identity");
    h.set("ETag", wire);
    if unchanged {
        w.write_header(304).await;
        return;
    }
    let h = w.header();
    h.set("Content-Type", "application/json");
    w.write_header(200).await;
    // The hash covers `json.Marshal`'s output, and the answer is `json.Encoder`'s, which ends in a newline.
    let mut body = body;
    body.push(b'\n');
    let _ = w.write(&body).await;
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Marshals a capability the way `json.Marshal` does for the hash.
pub fn capability_json<T: Serialize>(value: &T) -> Vec<u8> {
    silo_gocompat::json::marshal(value).expect("a capability document marshals")
}

/// The Go map shape: sorted keys.
pub type GoMap<V> = std::collections::BTreeMap<&'static str, V>;

#[cfg(test)]
mod tests {
    #[test]
    fn a_v1_request_that_reached_no_row_reads_as_its_deepest_mount() {
        for (path, want) in [
            ("/api/v1/libraries", Some("/api/v1/libraries")),
            ("/api/v1/libraries/", Some("/api/v1/libraries")),
            ("/api/v1/libraries/1/providers", Some("/api/v1/libraries/*")),
            ("/api/v1/auth/me/", Some("/api/v1/auth/*")),
            ("/api/v1/library/1/layout/", Some("/api/v1/*")),
            ("/api/v1/libraries-x", Some("/api/v1/*")),
            ("/api/v2/libraries", None),
        ] {
            assert_eq!(v1_mount_pattern(path).as_deref(), want, "{path}");
        }
    }

    use super::*;

    #[derive(Default)]
    struct Recorded {
        header: Header,
        status: Option<u16>,
        body: Vec<u8>,
    }

    impl ResponseWriter for Recorded {
        fn header(&mut self) -> &mut Header {
            &mut self.header
        }
        fn write_header(&mut self, code: u16) -> BoxFuture<'_, ()> {
            self.status.get_or_insert(code);
            Box::pin(async {})
        }
        fn write<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, Result<usize, WriteError>> {
            self.status.get_or_insert(200);
            self.body.extend_from_slice(data);
            Box::pin(async move { Ok(data.len()) })
        }
        fn write_string<'a>(
            &'a mut self,
            data: &'a str,
        ) -> BoxFuture<'a, Result<usize, WriteError>> {
            self.write(data.as_bytes())
        }
        fn flush(&mut self) -> BoxFuture<'_, Result<(), WriteError>> {
            Box::pin(async { Ok(()) })
        }
        fn hijack(&mut self) -> BoxFuture<'_, Result<Hijacked, WriteError>> {
            Box::pin(async { Err(WriteError::Hijacked) })
        }
    }

    fn panics() -> BoxHandler {
        handler_fn(|_w, _r| Box::pin(async { panic!("boom") }))
    }

    /// chi's `Recoverer`, recorded in `vectors/access/access.json`.
    #[tokio::test]
    async fn recoverer_answers_like_chi() {
        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/access/access.json"
        ))
        .unwrap();
        let data: serde_json::Value = silo_gocompat::json::unmarshal(&raw).unwrap();
        for case in data["recoverer"].as_array().unwrap() {
            let handler = recoverer()(panics());
            let mut w = Recorded::default();
            let mut r = Request::new_for_test("GET", "/");
            let connection = case["connection"].as_str().unwrap();
            if !connection.is_empty() {
                r.header.set("Connection", connection);
            }
            handler.serve_http(&mut w, &mut r).await;
            let wrote = case["written"].as_bool().unwrap();
            assert_eq!(w.status.is_some(), wrote, "{connection:?}");
            if wrote {
                assert_eq!(
                    i64::from(w.status.unwrap()),
                    case["status"].as_i64().unwrap()
                );
            }
            assert!(w.body.is_empty());
        }
    }

    #[tokio::test]
    #[should_panic]
    async fn recoverer_passes_an_abort_on() {
        let handler = recoverer()(handler_fn(|_w, _r| {
            Box::pin(async { silo_http::abort_handler() })
        }));
        let mut r = Request::new_for_test("GET", "/");
        handler.serve_http(&mut Recorded::default(), &mut r).await;
    }

    /// `bufferResponse`: what the operation wrote and set goes, and the problem takes its place.
    #[tokio::test]
    async fn a_v2_panic_is_the_internal_error_problem() {
        let handler = v2_public(
            "/api/v2/auth/device/capability",
            handler_fn(|w, _r| {
                Box::pin(async move {
                    w.header().set("ETag", "\"x\"");
                    let _ = w.write(b"partial").await;
                    panic!("boom")
                })
            }),
        );
        let mut w = Recorded::default();
        w.header.set_raw("X-Request-ID", vec![b"abc".to_vec()]);
        let mut r = Request::new_for_test("GET", "/");
        r.extensions.insert(RequestId("abc".to_owned()));
        handler.serve_http(&mut w, &mut r).await;
        assert_eq!(w.status, Some(500));
        assert!(w.header.get("ETag").is_empty());
        assert_eq!(w.header.get_raw_values("X-Request-ID"), [b"abc".to_vec()]);
        let body: serde_json::Value = silo_gocompat::json::unmarshal(&w.body).unwrap();
        assert_eq!(body["detail"], "An unexpected error occurred.");
        assert_eq!(body["instance"], "urn:silo:request:abc");
    }

    fn meta() -> OperationMeta {
        OperationMeta {
            operation_id: String::new(),
            identity_only: false,
            params: Vec::new(),
            body: None,
            body_required: false,
            query: HashMap::from([
                (
                    "ids".to_owned(),
                    QueryParam {
                        array: true,
                        boolean: false,
                    },
                ),
                (
                    "flag".to_owned(),
                    QueryParam {
                        array: false,
                        boolean: true,
                    },
                ),
                ("q".to_owned(), QueryParam::default()),
            ]),
        }
    }

    /// The rows that take a query are not ported yet, so this covers what the harness cannot reach.
    #[test]
    fn query_guard_grammar() {
        for (raw, want) in [
            ("", None),
            ("&&", None),
            ("q=1", None),
            ("ids=1&ids=2", None),
            ("flag=true", None),
            (
                "q=1&q=2",
                Some((400, "A scalar query parameter was repeated.")),
            ),
            (
                "flag=TRUE",
                Some((422, "The request did not pass validation; see errors.")),
            ),
            (
                "flag=1",
                Some((422, "The request did not pass validation; see errors.")),
            ),
            (
                "nope=1",
                Some((422, "The request did not pass validation; see errors.")),
            ),
            (
                "q=%zz",
                Some((
                    400,
                    "The query string is not valid percent-encoded form data.",
                )),
            ),
            (
                "q=1;r=2",
                Some((
                    400,
                    "The query string is not valid percent-encoded form data.",
                )),
            ),
        ] {
            let got = query_problem(raw.as_bytes(), &meta());
            assert_eq!(
                got.as_ref().map(|p| (p.status, p.detail.as_str())),
                want,
                "{raw}"
            );
        }
    }

    /// Go's rule, a declared ETag, not a path spelling.
    #[test]
    fn identity_only_follows_the_contract() {
        let get = |path: &str| operations()[path]["GET"].identity_only;
        assert!(get("/api/v2/openapi.json"));
        assert!(get("/api/v2/images/capabilities"));
        assert!(!get("/api/v2/account/me"));
    }

    /// R5 and R8: what would hand a client a second budget or the wrong profiles stays on Go.
    #[test]
    fn why_rows_stay_on_go() {
        let set = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        assert!(why_not_native(&set(&[]), true, false).is_some());
        assert!(why_not_native(&set(&[]), true, true).is_none());
        let off = set(&[("ratelimit.enabled", "false")]);
        assert!(why_not_native(&off, false, false).is_some());
        assert!(why_not_native(&off, true, false).is_none());
        let redis = set(&[("ratelimit.backend", "redis")]);
        assert!(why_not_native(&redis, true, false).is_none());
        assert!(why_not_native(&redis, false, false).is_some());
        let sqlite = set(&[("userdb.backend", "sqlite"), ("ratelimit.backend", "redis")]);
        assert!(why_not_native(&sqlite, true, false).is_some());
        assert!(why_not_native(&sqlite, true, true).is_some());
    }
}
