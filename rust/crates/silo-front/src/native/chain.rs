//! The request chain: `useBaseMiddleware`, the v1 route groups' gates, and the v2 `classGate`,
//! `writeProblem`, and `prepareCapabilityOperation` rendering around them.

use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use serde::Serialize;
use sha2::{Digest, Sha256};
use silo_api_v2::problem::{self as p, Problem, ProblemError};
use silo_auth::api_key_store::ApiKeyRepository;
use silo_auth::claims::{Claims, JwtService};
use silo_auth::session::SessionRepository;
use silo_auth::user::UserRepository;
use silo_gate::clientip::{self, RequestContext, RequestFields, Resolver};
use silo_gate::limiter::{Limiter, RateLimit, RateRequest, RedisLimiter, config_from_settings};
use silo_gate::mw::activity::{self, ActivityWriter, LogEntry};
use silo_gate::mw::auth::{self, LogContext, get_claims};
use silo_gate::mw::denial::reason;
use silo_gate::mw::logging::{Metrics, request_logger_skips};
use silo_gate::mw::policy_gates::PolicyGates;
use silo_gate::mw::viewer::{self, GroupStore, ProfileTokens, ViewerResolver};
use silo_gate::mw::{AuthGate, Denial, RequestId, new_request_id};
use silo_gate::policy::Engine;
use silo_gate::ratelimit::MemoryLimiter;
use silo_http::chi::{Middleware, middleware_fn};
use silo_http::{
    BoxFuture, BoxHandler, Header, Hijacked, Request, ResponseWriter, WriteError, handler_fn,
};
use silo_pg::Pool;
use silo_store::settings::{EncryptedSettingsRepo, ServerSettingsRepo};

/// How often settings the chain reads are re-read. Go reloads on a settings event; this polls.
const SETTINGS_POLL: std::time::Duration = std::time::Duration::from_secs(2);

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
}

/// Builds the chain from the reference's database.
pub async fn build(
    pool: Arc<Pool>,
    secret_key: &str,
    redis_url: Option<&str>,
    trusted_fallback: String,
) -> Result<Arc<Stack>, String> {
    let cipher =
        silo_core::secret::Cipher::new(secret_key.as_bytes()).map_err(|e| e.to_string())?;
    let settings = ServerSettingsRepo::new(pool.clone());
    let encrypted = EncryptedSettingsRepo::new(settings.clone(), cipher);
    let jwt_secret = encrypted
        .get("auth.jwt_secret")
        .await
        .map_err(|e| format!("reading auth.jwt_secret: {e}"))?;
    if jwt_secret.is_empty() {
        return Err("auth.jwt_secret is empty".to_owned());
    }
    let jwt = Arc::new(JwtService::new(jwt_secret.clone().into_bytes(), 0, 0));
    let users = UserRepository::new(pool.clone());
    let api_keys = ApiKeyRepository::new(pool.clone());
    let sessions = SessionRepository::new(pool.clone());
    let auth = AuthGate::new(jwt, sessions, api_keys, users.clone());

    let engine = load_engine(&pool).await?;
    let gate_engine = Arc::new(Mutex::new(load_engine(&pool).await?));
    let viewer = Arc::new(ViewerResolver::new(
        users.clone(),
        pool.clone(),
        ProfileTokens::new(jwt_secret.into_bytes()),
        engine,
        None,
    ));
    let groups = GroupStore::new(pool.clone());
    let gates = PolicyGates {
        viewer: viewer.clone(),
        users: users.clone(),
        groups: groups.clone(),
        pool: pool.clone(),
        engine: gate_engine.clone(),
    };

    let all = settings.get_all().await.map_err(|e| e.to_string())?;
    // `cfg.RateLimit.Backend`: the configured backend, memory by default, as Go chooses at startup.
    let backend = all
        .get("ratelimit.backend")
        .map_or("memory", String::as_str);
    let limiter = match redis_url.filter(|_| backend == "redis") {
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

    let raw = all
        .get(clientip::SETTING_TRUSTED_PROXIES)
        .cloned()
        .filter(|v| !v.is_empty())
        .unwrap_or(trusted_fallback);
    let list = if raw.is_empty() {
        clientip::DEFAULT_TRUSTED_PROXIES
    } else {
        &raw
    };
    let resolver = Arc::new(Resolver::new(clientip::parse_cidrs(list).map_err(|e| e.0)?));

    let stack = Arc::new(Stack {
        activity: ActivityWriter::start(pool.clone()),
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
        node_id: all.get("node.id").cloned().unwrap_or_default(),
    });

    let poller = stack.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SETTINGS_POLL);
        let mut sources = None;
        loop {
            tick.tick().await;
            if let Ok(all) = poller.settings.get_all().await {
                poller.rate.reload(config_from_settings(&all));
                if let Some(raw) = all
                    .get(clientip::SETTING_TRUSTED_PROXIES)
                    .filter(|v| !v.is_empty())
                    && let Ok(cidrs) = clientip::parse_cidrs(raw)
                {
                    poller.resolver.update_trusted_cidrs(cidrs);
                }
            }
            match active_sources(&poller.pool).await {
                Ok(current) if sources.as_ref() != Some(&current) => match engine_for(&current) {
                    Ok(engine) => {
                        poller.viewer.set_engine(engine);
                        if let Ok(engine) = engine_for(&current) {
                            *gate_engine.lock().unwrap_or_else(|e| e.into_inner()) = engine;
                        }
                        sources = Some(current);
                    }
                    Err(e) => {
                        tracing::warn!(component = "policy", error = %e, "custom policy refused; keeping the last engine");
                        sources = Some(current);
                    }
                },
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(component = "policy", error = %e, "reading policies failed")
                }
            }
        }
    });
    Ok(stack)
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

async fn load_engine(pool: &Pool) -> Result<Engine, String> {
    engine_for(&active_sources(pool).await?)
}

/// `chimw.GetReqID`.
pub fn request_id_of(r: &Request) -> String {
    r.extensions
        .get::<RequestId>()
        .map(|id| id.0.clone())
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
        self.inner.write(data)
    }
    fn write_string<'a>(&'a mut self, data: &'a str) -> BoxFuture<'a, Result<usize, WriteError>> {
        self.wrote = true;
        self.inner.write_string(data)
    }
    fn flush(&mut self) -> BoxFuture<'_, Result<(), WriteError>> {
        self.inner.flush()
    }
    fn hijack(&mut self) -> BoxFuture<'_, Result<Hijacked, WriteError>> {
        self.inner.hijack()
    }
}

fn header_values<'a>(h: &'a Header, key: &str) -> Vec<&'a str> {
    h.values(key)
        .iter()
        .filter_map(|v| std::str::from_utf8(v).ok())
        .collect()
}

/// `clientip.Middleware`.
fn resolve_client(resolver: &Resolver, r: &Request) -> RequestContext {
    let xff = header_values(&r.header, "X-Forwarded-For");
    let real = header_values(&r.header, "X-Real-Ip");
    let forwarded = header_values(&r.header, "Forwarded");
    let proto = header_values(&r.header, "X-Forwarded-Proto");
    let host = header_values(&r.header, "X-Forwarded-Host");
    let upgrade = header_values(&r.header, "Upgrade");
    let connection = header_values(&r.header, "Connection");
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

impl Stack {
    /// `useBaseMiddleware`: request ID, client IP, request logger, metrics, activity log. Compression
    /// runs inside it, on the mux, as in Go; nothing it does changes what these read.
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
                    let user_agent = r.header.get_str("User-Agent").to_owned();
                    let started = Instant::now();
                    let timestamp = SystemTime::now();

                    let mut wrapped = StatusWriter {
                        inner: w,
                        status: 200,
                        wrote: false,
                    };
                    next.serve_http(&mut wrapped, r).await;
                    let status = wrapped.status;

                    let pattern = r
                        .extensions
                        .get::<RowPattern>()
                        .map(|p| p.0.clone())
                        .unwrap_or_default();
                    let elapsed = started.elapsed();
                    let fields = log.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let is_v2 = path.starts_with(silo_gate::mw::API_V2_PREFIX);
                    if !is_v2 {
                        stack.metrics.observe(&method, &pattern, status, elapsed);
                    }
                    if !request_logger_skips(&path) || is_v2 {
                        tracing::info!(
                            component = "api",
                            request_id = %id,
                            method = %method,
                            path = %path,
                            path_pattern = %pattern,
                            status,
                            duration_ms = elapsed.as_millis() as u64,
                            client_ip = %client_ip,
                            user_agent = %user_agent,
                            node_id = %stack.node_id,
                            user_id = ?fields.user_id,
                            session_id = %fields.session_id,
                            "api request"
                        );
                    }
                    if activity::recorded(&path) {
                        stack.activity.write(LogEntry {
                            timestamp,
                            client_ip,
                            user_id: fields.user_id,
                            impersonator_user_id: fields.impersonator_user_id,
                            session_id: fields.session_id,
                            request_id: id,
                            node_id: stack.node_id.clone(),
                            method,
                            path: path.clone(),
                            path_pattern: if pattern.is_empty() { path } else { pattern },
                            status_code: i32::from(status),
                            user_agent,
                            duration_ms: elapsed.as_millis() as i32,
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

    /// A v2 operation: `classGate` with the `denialWriter` translation, `defaultHeaders`, and the guards.
    pub fn v2(self: &Arc<Self>, pattern: &str, class: V2Class, handler: BoxHandler) -> BoxHandler {
        v2_wrap(Some(self.clone()), pattern, class.steps(), handler)
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
    handler_fn(move |w, r| {
        let stack = stack.clone();
        let handler = handler.clone();
        let pattern = pattern.clone();
        Box::pin(async move {
            r.extensions.insert(RowPattern(pattern));
            w.header().set("Cache-Control", p::DEFAULT_CACHE_CONTROL);
            if let Some(stack) = &stack {
                // `denialWriter`: what a gate sets stays off the response unless translated.
                let mut sink = Header::new();
                if let Err(denial) = stack.run_steps(steps, &mut sink, r).await {
                    write_problem(w, r, denial_problem(&denial)).await;
                    return;
                }
            }
            let accept = r.header.get_str("Accept").to_owned();
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
            if !content_encoding_ok(r.header.get_str("Content-Encoding")) {
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
            // `encodingGuard`, for the operations that carry a validator.
            let excluded = r.header.values("Accept-Encoding");
            if !excluded.is_empty() && identity_only(&pattern_of(r)) {
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
            handler.serve_http(w, r).await;
        })
    })
}

fn pattern_of(r: &Request) -> String {
    r.extensions
        .get::<RowPattern>()
        .map(|p| p.0.clone())
        .unwrap_or_default()
}

/// `metaIdentityOnly`: this port sets it on capability documents and the contract document.
fn identity_only(pattern: &str) -> bool {
    pattern.ends_with("/capability") || pattern.ends_with("/capabilities")
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
    let mut body = Vec::new();
    {
        let mut enc = silo_gocompat::json::Encoder::new(&mut body);
        enc.set_escape_html(false);
        enc.encode(value).expect("a response marshals");
    }
    w.header().set("Content-Type", "application/json");
    w.write_header(200).await;
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
