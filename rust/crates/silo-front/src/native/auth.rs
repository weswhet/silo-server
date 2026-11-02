//! `handlers/auth*.go` and `apiv2/auth*.go`, `device_login.go`, `plugin_launch.go`: password sign-in,
//! refresh, the login session list, setup, signup, device pairing, and the password change.
//!
//! OAuth, network sign-in, and provider logout need the plugin host, so their rows stay on Go. Password
//! sign-in, refresh, and provider discovery go to Go while any auth plugin is configured
//! ([`PROVIDER_PATHS`]).

use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::problem::{self as p, Problem, ProblemError};
use silo_api_v2::wire::{Instant, NullableInstant, new_collection, paginated};
use silo_auth::audit::AuditRequest;
use silo_auth::claims::{Claims, token_type};
use silo_auth::device::{self, DeviceError, LookupInput, StartInput};
use silo_auth::service::{AuthFailure, ClientDevice, NewAccount, SignInContext, TokenPair};
use silo_auth::session::AuthSession;
use silo_auth::user::User;
use silo_gate::mw::auth::{declared_profile_id, get_claims, get_profile_id};
use silo_gocompat::strings::trim_space;
use silo_gocompat::time::GoTime;
use silo_http::chi::Mux;
use silo_http::{BoxHandler, Request, ResponseWriter, handler_fn};
use silo_pg::Row;
use silo_store::access::Scope;

use super::account::{V1User, V2Account, password_change_allowed, v1_user, v2_account};
use super::chain::{
    Stack, Step, V2Class, capability_json, client_ip_of, problem_type, write_capability,
    write_problem, write_v1_json, write_v2_json, write_v2_json_status,
};
use super::huma::{RawBody, reject_nulls};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/login"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/setup"),
    NativeRow::new(ApiV1, "GET", "/api/v1/auth/setup"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/signup"),
    NativeRow::new(ApiV1, "GET", "/api/v1/auth/signup"),
    NativeRow::new(ApiV1, "GET", "/api/v1/auth/providers"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/refresh"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/plugin-launch"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/device/start"),
    NativeRow::new(ApiV1, "GET", "/api/v1/auth/device"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/device/poll"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/logout"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/impersonation/end"),
    NativeRow::new(ApiV1, "GET", "/api/v1/auth/sessions"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/auth/sessions/{id}"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/account/password"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/device/approve"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/device/deny"),
    NativeRow::new(ApiV1, "POST", "/api/v1/auth/device/approve-handoff"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/login"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/logout"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/impersonation/end"),
    NativeRow::new(ApiV2, "GET", "/api/v2/auth/providers"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/refresh"),
    NativeRow::new(ApiV2, "GET", "/api/v2/auth/sessions"),
    NativeRow::new(ApiV2, "GET", "/api/v2/auth/sessions/capabilities"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/auth/sessions/{id}"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/setup"),
    NativeRow::new(ApiV2, "GET", "/api/v2/auth/signup"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/signup"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/plugin-launch"),
    NativeRow::new(ApiV2, "GET", "/api/v2/auth/device"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/device/start"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/device/poll"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/device/cancel"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/device/approve"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/device/approve-handoff"),
    NativeRow::new(ApiV2, "POST", "/api/v2/auth/device/deny"),
    NativeRow::new(ApiV2, "POST", "/api/v2/account/password"),
];

/// Paths whose answer depends on the configured providers.
pub const PROVIDER_PATHS: &[&str] = &[
    "/api/v1/auth/login",
    "/api/v2/auth/login",
    "/api/v1/auth/providers",
    "/api/v2/auth/providers",
    "/api/v1/auth/refresh",
    "/api/v2/auth/refresh",
];

const AUTH_LIMIT: i64 = 1 << 20;
const INTERNAL: &str = "An unexpected error occurred";
const VALIDATION: &str = "The request did not pass validation; see errors.";
/// `CredentialCheckRetryAfterSeconds`.
const CREDENTIAL_CHECK_RETRY_AFTER: i64 = 5;
/// `PluginLaunchTTL`.
const PLUGIN_LAUNCH_TTL_SECS: i64 = 300;
/// `plugins.ContentPrefix`.
const PLUGIN_CONTENT_PREFIX: &str = "/api/v2/plugin-content";

/// `handlers.APIError`.
#[derive(Debug, Clone)]
pub(super) struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub retry_after: i64,
    pub field: &'static str,
}

fn api_error(status: u16, code: &'static str, message: &str) -> ApiError {
    ApiError {
        status,
        code,
        message: message.to_owned(),
        retry_after: 0,
        field: "",
    }
}

fn field_error(status: u16, code: &'static str, message: &str, field: &'static str) -> ApiError {
    ApiError {
        field,
        ..api_error(status, code, message)
    }
}

fn internal() -> ApiError {
    api_error(500, "internal_error", INTERNAL)
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: &'a str,
}

/// `writeError`.
pub(super) async fn write_v1_error(
    w: &mut dyn ResponseWriter,
    status: u16,
    code: &str,
    message: &str,
) {
    write_v1_json(
        w,
        status,
        &ErrorBody {
            error: code,
            message,
        },
    )
    .await;
}

/// `writeAPIError`.
pub(super) async fn write_v1_api_error(w: &mut dyn ResponseWriter, e: &ApiError) {
    if e.retry_after > 0 {
        w.header().set("Retry-After", e.retry_after.to_string());
    }
    write_v1_error(w, e.status, e.code, &e.message).await;
}

/// `externalSignInProblemTypes`, the codes this domain reports.
fn external_problem(code: &str) -> Option<p::ProblemType> {
    p::CATALOG
        .iter()
        .copied()
        .find(|t| matches!(code, "not_permitted" | "local_login_disabled") && t.id == code)
}

/// `serviceProblem`.
pub(super) fn service_problem(e: &ApiError) -> Problem {
    if e.status >= 500 && e.status != 503 {
        return Problem::new(
            problem_type("internal_error"),
            "An unexpected error occurred.",
        );
    }
    let kind = external_problem(e.code)
        .filter(|t| t.status == e.status)
        .unwrap_or_else(|| p::type_for_status(e.status));
    let problem = Problem::new(kind, e.message.clone());
    if e.retry_after > 0 {
        problem.with_retry_after(e.retry_after)
    } else {
        problem
    }
}

/// `busyError`.
pub(super) fn busy_error() -> ApiError {
    busy()
}

fn busy() -> ApiError {
    ApiError {
        retry_after: silo_auth::passwordhash::RETRY_AFTER_SECONDS,
        ..api_error(
            503,
            "service_unavailable",
            "The server is busy; try again in a moment",
        )
    }
}

/// `externalSignInError`.
fn external_sign_in_error(e: &AuthFailure) -> Option<ApiError> {
    match e {
        AuthFailure::LocalLoginDisabled => Some(api_error(
            403,
            "local_login_disabled",
            "Password sign-in is turned off on this server; sign in with the server's sign-in provider",
        )),
        AuthFailure::NotPermitted => Some(api_error(
            403,
            "not_permitted",
            "This account is not permitted to sign in to this server",
        )),
        _ => None,
    }
}

/// `AuthHandler.Login`'s failure mapping.
fn login_error(e: &AuthFailure) -> ApiError {
    match e {
        AuthFailure::Throttled(seconds) => ApiError {
            retry_after: *seconds,
            ..api_error(
                429,
                "rate_limited",
                "Too many failed sign-ins for this name. Try again later.",
            )
        },
        AuthFailure::InvalidCredentials => {
            api_error(401, "invalid_credentials", "Invalid username or password")
        }
        AuthFailure::UserDisabled => api_error(403, "user_disabled", "User account is disabled"),
        AuthFailure::Busy => busy(),
        other => external_sign_in_error(other).unwrap_or_else(internal),
    }
}

fn loginless_v2(e: ApiError) -> Problem {
    if e.status == 401 {
        return Problem::new(problem_type("invalid_token"), format!("{}.", e.message));
    }
    service_problem(&e)
}

/// The JSON bodies `decodeLimitedJSONBody` and `json.NewDecoder(r.Body).Decode` read. The limit is
/// applied on the bytes the decoder would have seen, so a value that ends in time still decodes.
async fn decode_v1<T: serde::de::DeserializeOwned + Default>(
    w: &mut dyn ResponseWriter,
    r: &mut Request,
    limit: Option<i64>,
    allow_empty: bool,
) -> Option<T> {
    let (bytes, error) = r.read_all().await;
    let over = limit.is_some_and(|l| bytes.len() as i64 > l);
    let data = match limit {
        Some(l) if over => &bytes[..l as usize],
        _ => &bytes[..],
    };
    let mut stream = silo_gocompat::json::Decoder::new().stream(data);
    match stream.decode::<T>() {
        Ok(value) => Some(value),
        Err(e) if allow_empty && e.is_eof() && error.is_none() && !over => Some(T::default()),
        Err(_) => {
            if over {
                write_v1_error(w, 413, "too_large", "Request body is too large").await;
            } else {
                write_v1_error(w, 400, "bad_request", "Invalid request body").await;
            }
            None
        }
    }
}

/// What Huma validated, or the problem `rejectNonNullableNulls` has for it.
fn decode_v2<T: serde::de::DeserializeOwned + Default>(r: &Request) -> Result<T, Problem> {
    let raw = r
        .extensions
        .get::<RawBody>()
        .map(|b| b.0.clone())
        .unwrap_or_default();
    if let Some(problem) = reject_nulls(&raw) {
        return Err(problem);
    }
    if raw.is_empty() {
        return Ok(T::default());
    }
    silo_gocompat::json::unmarshal(&raw)
        .map_err(|_| Problem::new(problem_type("validation_failed"), VALIDATION))
}

/// `extractClaims`: what `HandleLogout` and its siblings re-read from the header. An API key is no JWT,
/// so v1's logout answers it 401.
fn jwt_claims(stack: &Stack, r: &Request) -> Option<Claims> {
    let header = r.header.get("Authorization");
    let text = std::str::from_utf8(header).ok()?;
    let (scheme, token) = text.split_once(' ')?;
    if !silo_gocompat::strings::equal_fold(scheme, "bearer") {
        return None;
    }
    stack.jwt.validate_token(token).ok()
}

fn sign_in_context(r: &Request) -> SignInContext {
    SignInContext {
        device_name: String::from_utf8_lossy(r.header.get("User-Agent")).into_owned(),
        ip: client_ip_of(r),
        device: ClientDevice::new(
            r.header.get("X-Silo-Device-Id"),
            r.header.get("X-Silo-Device-Name"),
            r.header.get("X-Silo-Device-Platform"),
        ),
    }
}

fn device_of(r: &Request) -> ClientDevice {
    sign_in_context(r).device
}

/// `isSecureRequest`.
fn is_secure(r: &Request) -> bool {
    silo_gocompat::strings::equal_fold(
        &String::from_utf8_lossy(r.header.get("X-Forwarded-Proto")),
        "https",
    )
}

/// `requestBaseURL`.
fn request_base_url(r: &Request) -> String {
    let forwarded = String::from_utf8_lossy(r.header.get("X-Forwarded-Proto"));
    let forwarded = trim_space(&forwarded);
    let scheme = if forwarded.is_empty() {
        "http"
    } else {
        forwarded
    };
    let raw_host = String::from_utf8_lossy(r.header.get("X-Forwarded-Host"));
    let first = trim_space(&raw_host);
    let first = trim_space(first.split(',').next().unwrap_or_default());
    let host = if first.is_empty() {
        String::from_utf8_lossy(&r.host).into_owned()
    } else {
        first.to_owned()
    };
    format!("{scheme}://{host}")
}

/// `publicBaseURL`.
async fn public_base_url(stack: &Stack) -> String {
    let raw = stack
        .settings
        .get("server.public_url")
        .await
        .unwrap_or_default();
    let raw = trim_space(&raw);
    if raw.is_empty() {
        return String::new();
    }
    let Ok(u) = silo_gocompat::url::parse(raw) else {
        return String::new();
    };
    let scheme = silo_gocompat::strings::to_lower(&u.scheme);
    if u.host.is_empty()
        || u.user.is_some()
        || u.host.contains('%')
        || (scheme != "http" && scheme != "https")
    {
        return String::new();
    }
    format!(
        "{scheme}://{}{}",
        silo_gocompat::strings::to_lower(&u.host),
        u.escaped_path().trim_end_matches('/')
    )
}

fn go_time(t: SystemTime) -> String {
    GoTime::from_system_time(t).format(silo_gocompat::time::RFC3339_NANO)
}

fn go_rfc3339(t: SystemTime) -> String {
    GoTime::from_system_time(t).format(silo_gocompat::time::RFC3339)
}

fn instant(t: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(t))
}

#[derive(Serialize)]
struct V1TokenPair {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    user: V1User,
}

#[derive(Serialize)]
pub(super) struct V2TokenPair {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    user: V2Account,
}

async fn v1_pair(s: &Stack, pair: TokenPair, user: &User) -> V1TokenPair {
    V1TokenPair {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
        user: v1_user(s, user).await,
    }
}

async fn v2_pair(s: &Stack, pair: TokenPair, user: &User) -> V2TokenPair {
    V2TokenPair {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
        user: v2_account(s, user).await,
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LoginBody {
    username: String,
    password: String,
    provider: String,
}

/// `AuthHandler.Login`.
async fn do_login(s: &Stack, r: &Request, body: &LoginBody) -> Result<(TokenPair, User), ApiError> {
    if body.username.is_empty() || body.password.is_empty() {
        return Err(api_error(
            400,
            "bad_request",
            "Username and password are required",
        ));
    }
    s.sign_in
        .login_with_provider(
            &body.provider,
            &body.username,
            &body.password,
            &sign_in_context(r),
        )
        .await
        .map_err(|e| {
            if matches!(e, AuthFailure::Other(_)) {
                tracing::error!(component = "auth", error = %e, "login failed");
            }
            login_error(&e)
        })
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RegistrationBody {
    username: String,
    email: String,
    password: String,
    invite_code: String,
    create_default_profile: bool,
    default_profile_name: String,
}

fn validate_registration_password(password: &str) -> Result<(), ApiError> {
    match silo_auth::service::check_new_password(password) {
        Err(AuthFailure::PasswordTooShort) => Err(field_error(
            400,
            "weak_password",
            "Password must be at least 8 characters",
            "password",
        )),
        Err(AuthFailure::PasswordTooLong) => Err(field_error(
            400,
            "password_too_long",
            "Password must be at most 72 bytes",
            "password",
        )),
        _ => Ok(()),
    }
}

/// `AuthHandler.SetupInitialUser`.
async fn do_setup(
    s: &Stack,
    r: &Request,
    body: &RegistrationBody,
) -> Result<(TokenPair, User), ApiError> {
    let (username, email) = (trim_space(&body.username), trim_space(&body.email));
    if username.is_empty() || email.is_empty() || body.password.is_empty() {
        return Err(api_error(
            400,
            "bad_request",
            "Username, email, and password are required",
        ));
    }
    validate_registration_password(&body.password)?;
    let account = NewAccount {
        username,
        email,
        password: &body.password,
        create_default_profile: body.create_default_profile,
        default_profile_name: &body.default_profile_name,
    };
    s.sign_in
        .setup_initial_user(&account, &sign_in_context(r))
        .await
        .map_err(|e| match e {
            AuthFailure::SetupAlreadyComplete => api_error(
                401,
                "setup_complete",
                "Initial setup has already been completed",
            ),
            AuthFailure::Busy => busy(),
            other => {
                tracing::error!(component = "auth", error = %other, "setup failed");
                internal()
            }
        })
}

/// `AuthHandler.Signup`.
async fn do_signup(
    s: &Stack,
    r: &Request,
    body: &RegistrationBody,
) -> Result<(TokenPair, User), ApiError> {
    let (username, email) = (trim_space(&body.username), trim_space(&body.email));
    if username.is_empty()
        || email.is_empty()
        || body.password.is_empty()
        || body.invite_code.is_empty()
    {
        return Err(api_error(
            400,
            "bad_request",
            "Username, email, password, and invite code are required",
        ));
    }
    validate_registration_password(&body.password)?;
    let account = NewAccount {
        username,
        email,
        password: &body.password,
        create_default_profile: body.create_default_profile,
        default_profile_name: &body.default_profile_name,
    };
    s.sign_in
        .signup(&account, &body.invite_code, &sign_in_context(r))
        .await
        .map_err(|e| match &e {
            AuthFailure::SignupDisabled => api_error(
                403,
                "signup_disabled",
                "Public signups are not currently enabled",
            ),
            AuthFailure::InviteCodeNotFound => {
                field_error(400, "invalid_code", "Invalid invite code", "invite_code")
            }
            AuthFailure::InviteCodeExhausted => field_error(
                400,
                "code_exhausted",
                "This invite code has reached its maximum uses",
                "invite_code",
            ),
            AuthFailure::InviteCodeDisabled => field_error(
                400,
                "code_disabled",
                "This invite code is no longer active",
                "invite_code",
            ),
            AuthFailure::Duplicate => {
                api_error(400, "duplicate", "Username or email already taken")
            }
            AuthFailure::Busy => busy(),
            AuthFailure::SignupSessionStart(inner) => {
                external_sign_in_error(inner).unwrap_or_else(internal)
            }
            other => external_sign_in_error(other).unwrap_or_else(internal),
        })
}

/// `invalidEmailProblem`.
fn invalid_email_problem(email: &str) -> Option<Problem> {
    if silo_auth::provider::validate_email(email).is_ok() {
        return None;
    }
    Some(
        Problem::new(problem_type("validation_failed"), VALIDATION).with_errors([ProblemError {
            location: "body.email".to_owned(),
            code: "invalid".to_owned(),
            detail: "Enter a valid email address, like name@example.com.".to_owned(),
        }]),
    )
}

/// `registrationProblem`.
fn registration_problem(e: ApiError) -> Problem {
    if !e.field.is_empty() {
        return Problem::new(problem_type("validation_failed"), VALIDATION).with_errors([
            ProblemError {
                location: format!("body.{}", e.field),
                code: "invalid".to_owned(),
                detail: e.message,
            },
        ]);
    }
    service_problem(&e)
}

/// `AuthHandler.Refresh`.
async fn do_refresh(s: &Stack, token: &str) -> Result<TokenPair, ApiError> {
    if token.is_empty() {
        return Err(field_error(
            400,
            "bad_request",
            "Refresh token is required",
            "refresh_token",
        ));
    }
    s.sign_in.refresh(token).await.map_err(|e| match e {
        AuthFailure::SessionRevoked => {
            api_error(401, "session_revoked", "Session has been revoked")
        }
        AuthFailure::SessionCheckUnavailable(why) => {
            tracing::warn!(component = "auth", error = %why, "refresh could not check the login session; answering 503");
            ApiError {
                retry_after: CREDENTIAL_CHECK_RETRY_AFTER,
                ..api_error(
                    503,
                    silo_gate::mw::denial::CODE_SERVICE_UNAVAILABLE,
                    "The session could not be checked right now; try again shortly",
                )
            }
        }
        _ => api_error(401, "invalid_token", "Invalid or expired refresh token"),
    })
}

#[derive(Serialize)]
struct RefreshedTokens {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RefreshBody {
    refresh_token: String,
}

#[derive(Serialize)]
struct V1Session {
    id: String,
    device_name: String,
    ip_address: String,
    created_at: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
}

#[derive(Serialize)]
struct V2Session {
    id: String,
    device_name: String,
    ip_address: String,
    created_at: Instant,
    expires_at: Instant,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_platform: String,
    last_seen_at: NullableInstant,
    current: bool,
}

fn v2_session(s: &AuthSession, current: &str) -> V2Session {
    V2Session {
        id: s.id.clone(),
        device_name: s.device_name.clone(),
        ip_address: s.ip_address.clone(),
        created_at: instant(s.created_at),
        expires_at: instant(s.expires_at),
        device_id: s.device_id.clone(),
        device_platform: s.device_platform.clone(),
        last_seen_at: NullableInstant {
            valid: s.last_seen_at.is_some(),
            time: s.last_seen_at.map(instant),
        },
        current: s.id == current,
    }
}

fn authentication_required() -> Problem {
    Problem::new(
        problem_type("authentication_required"),
        "Authentication is required.",
    )
}

/// `AuthHandler.RevokeSession`.
async fn do_revoke(
    s: &Stack,
    id: &str,
    user_id: i64,
    audit: &AuditRequest,
) -> Result<(), ApiError> {
    if id.is_empty() {
        return Err(api_error(400, "bad_request", "Session ID is required"));
    }
    s.sign_in
        .revoke_session(id, user_id, audit)
        .await
        .map_err(|e| match e {
            AuthFailure::SessionNotFound => api_error(404, "not_found", "Session not found"),
            _ => internal(),
        })
}

/// `AuthHandler.EndImpersonation`.
async fn do_end_impersonation(
    s: &Stack,
    claims: &Claims,
    audit: &AuditRequest,
) -> Result<(), ApiError> {
    let not_impersonating =
        || api_error(400, "not_impersonating", "No active impersonation session");
    let Some(impersonator) = claims.impersonator_user_id else {
        return Err(not_impersonating());
    };
    s.sign_in
        .end_impersonation(&claims.session_id, impersonator, audit)
        .await
        .map_err(|e| match e {
            AuthFailure::NotImpersonating => not_impersonating(),
            AuthFailure::ImpersonationNotAllowed => api_error(
                403,
                "impersonation_not_allowed",
                "Impersonation is not allowed",
            ),
            _ => internal(),
        })
}

/// `AuthHandler.ChangePassword`, then the `OnSessionsRevoked` hook.
async fn do_change_password(
    s: &Stack,
    claims: &Claims,
    current: &str,
    new: &str,
    sign_out_others: bool,
    audit: &AuditRequest,
) -> Result<(), ApiError> {
    if current.is_empty() || new.is_empty() {
        return Err(api_error(
            400,
            "bad_request",
            "Current password and new password are required",
        ));
    }
    let revoked = s
        .sign_in
        .change_password(
            claims.user_id,
            &claims.session_id,
            current,
            new,
            sign_out_others,
            audit,
        )
        .await
        .map_err(|e| match e {
            AuthFailure::CurrentPasswordInvalid => field_error(
                400,
                "invalid_current_password",
                "Current password is incorrect",
                "current_password",
            ),
            AuthFailure::PasswordTooShort => field_error(
                400,
                "weak_password",
                "Password must be at least 8 characters",
                "new_password",
            ),
            AuthFailure::PasswordTooLong => field_error(
                400,
                "password_too_long",
                "Password must be at most 72 bytes",
                "new_password",
            ),
            AuthFailure::PasswordUnchanged => field_error(
                400,
                "weak_password",
                "Choose a password different from the temporary one",
                "new_password",
            ),
            AuthFailure::PasswordLoginDisabled => api_error(
                409,
                "password_login_disabled",
                "This account does not use local password sign-in",
            ),
            AuthFailure::Busy => busy(),
            _ => api_error(500, "internal_error", "Failed to change password"),
        })?;
    if revoked {
        s.publish_sessions_revoked(claims.user_id).await;
    }
    Ok(())
}

/// `AuthorizePasswordChange`.
async fn authorize_password_change(
    s: &Stack,
    claims: Option<&Claims>,
    profile_id: &str,
) -> Result<(), ApiError> {
    let allowed = match claims {
        Some(claims) => password_change_allowed(s, claims, profile_id)
            .await
            .map_err(|()| {
                api_error(500, "internal_error", "Failed to verify the active profile")
            })?,
        None => false,
    };
    if !allowed {
        return Err(api_error(
            403,
            "password_change_forbidden",
            "Changing the account password requires the account's primary profile",
        ));
    }
    Ok(())
}

/// `passwordProblem`.
fn password_problem(e: ApiError) -> Problem {
    if !e.field.is_empty() {
        return Problem::new(problem_type("validation_failed"), VALIDATION).with_errors([
            ProblemError {
                location: format!("body.{}", e.field),
                code: "invalid".to_owned(),
                detail: format!("{}.", e.message),
            },
        ]);
    }
    if e.status == 503 && e.code == "service_unavailable" {
        return Problem::new(
            problem_type("dependency_unavailable"),
            "The server is busy; try again in a moment.",
        )
        .with_retry_after(silo_auth::passwordhash::RETRY_AFTER_SECONDS);
    }
    service_problem(&e)
}

fn plugin_cookie(token: &str, path: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{}={token}; Path={path}; Max-Age={PLUGIN_LAUNCH_TTL_SECS}; HttpOnly{secure}; SameSite=Lax",
        silo_auth::claims::PLUGIN_ACCESS_COOKIE_NAME
    )
}

/// `AuthHandler.PluginLaunchToken`.
fn plugin_token(
    s: &Stack,
    r: &Request,
    claims: &Claims,
    profile: &str,
) -> Result<String, ApiError> {
    let profile = trim_space(profile);
    let revision = r
        .extensions
        .get::<Arc<Scope>>()
        .filter(|scope| {
            !profile.is_empty() && scope.profile_id == profile && scope.profile_verified
        })
        .map(|scope| scope.profile_pin_revision);
    s.jwt
        .generate_plugin_access_token(
            claims.user_id,
            &claims.role,
            &claims.session_id,
            profile,
            revision,
            PLUGIN_LAUNCH_TTL_SECS * 1_000_000_000,
        )
        .map_err(|_| api_error(500, "internal_error", "Failed to prepare plugin access"))
}

#[derive(Serialize)]
struct PluginLaunch {
    expires_in: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DeviceStartBody {
    device_name: String,
    device_platform: String,
    client_purpose: String,
    temporary: bool,
}

#[derive(Serialize)]
struct V1DeviceStart {
    device_code: String,
    user_code: String,
    match_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_at: String,
    expires_in: i64,
    interval: i64,
    device_name: String,
    device_platform: String,
    client_purpose: String,
    temporary: bool,
}

#[derive(Serialize)]
struct V2DeviceStart {
    device_code: String,
    user_code: String,
    match_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_at: Instant,
    expires_in: i64,
    interval: i64,
    device_name: String,
    device_platform: String,
    client_purpose: String,
    temporary: bool,
}

/// `StartDeviceLogin`.
async fn do_device_start(s: &Stack, input: StartInput) -> Result<device::StartResult, ApiError> {
    s.devices.start(input).await.map_err(|e| match e {
        DeviceError::BadPurpose => field_error(
            400,
            "bad_request",
            "Invalid device login purpose",
            "client_purpose",
        ),
        other => {
            tracing::error!(component = "auth", error = %other, "starting a device login failed");
            api_error(500, "internal_error", "Failed to start device login")
        }
    })
}

/// `deviceProblem`.
fn device_problem(e: ApiError) -> Problem {
    if !e.field.is_empty() {
        return Problem::new(problem_type("validation_failed"), VALIDATION).with_errors([
            ProblemError {
                location: format!("body.{}", e.field),
                code: "invalid".to_owned(),
                detail: e.message,
            },
        ]);
    }
    if e.status == 410 {
        return Problem::new(
            problem_type("device_login_expired"),
            format!("{}.", e.message),
        );
    }
    service_problem(&e)
}

fn quick_connect_attempts(retry_after: i64) -> ApiError {
    ApiError {
        retry_after,
        ..api_error(
            429,
            "rate_limited",
            "Too many Quick Connect codes tried. Try again later.",
        )
    }
}

/// `LookupDeviceLogin`.
async fn do_device_lookup(s: &Stack, input: &LookupInput) -> Result<device::Info, ApiError> {
    s.devices.lookup(input).await.map_err(|e| match e {
        DeviceError::NotFound => api_error(404, "not_found", "Device login request not found"),
        DeviceError::QuickConnectAttempts(left) => quick_connect_attempts(left),
        _ => api_error(500, "internal_error", "Failed to load device login"),
    })
}

/// `PollDeviceLogin`.
async fn do_device_poll(
    s: &Stack,
    code: &str,
    device: &ClientDevice,
) -> Result<device::PollResult, ApiError> {
    s.devices.poll(code, device).await.map_err(|e| match e {
        DeviceError::NotFound => api_error(404, "not_found", "Device login request not found"),
        other => {
            tracing::error!(component = "auth", error = %other, "polling a device login failed");
            api_error(500, "internal_error", "Failed to poll device login")
        }
    })
}

/// `deviceDecisionError`.
fn decision_error(e: DeviceError) -> ApiError {
    match e {
        DeviceError::QuickConnectAttempts(left) => quick_connect_attempts(left),
        DeviceError::NotFound => api_error(404, "not_found", "Device login request not found"),
        DeviceError::Expired => api_error(410, "expired", "Device login request has expired"),
        DeviceError::Consumed => api_error(
            409,
            "consumed",
            "Device login request has already been used",
        ),
        DeviceError::Denied => api_error(
            409,
            "denied",
            "Device login request has already been denied",
        ),
        DeviceError::Canceled => api_error(
            409,
            "denied",
            "Device login request was canceled on the device",
        ),
        DeviceError::UserDisabled => api_error(403, "user_disabled", "User account is disabled"),
        DeviceError::SessionRevoked => {
            api_error(401, "unauthorized", "Login session is no longer valid")
        }
        DeviceError::Purpose => api_error(
            409,
            "purpose_mismatch",
            "Device login purpose does not match this approval route",
        ),
        DeviceError::Conflict => api_error(
            409,
            "approval_conflict",
            "Device login request was approved by another identity",
        ),
        DeviceError::NoProfile => api_error(404, "profile_not_found", "Profile not found"),
        other => {
            tracing::error!(component = "auth", error = %other, "a device login decision failed");
            api_error(500, "internal_error", "Device login request failed")
        }
    }
}

/// `deviceDecisionSessionError`.
fn decision_session_error(claims: Option<&Claims>) -> Option<ApiError> {
    claims.filter(|c| !c.is_own_login_session()).map(|_| {
        api_error(
            403,
            "forbidden",
            "Approving or denying a device needs a signed-in session; API keys and impersonation sessions cannot",
        )
    })
}

#[derive(Serialize)]
struct Decision {
    status: &'static str,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DecisionBody {
    token: String,
    code: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PollBody {
    device_code: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PasswordBody {
    current_password: String,
    new_password: String,
    sign_out_other_sessions: bool,
}

fn v1_status(status: &str) -> &str {
    if status == device::STATUS_CANCELED {
        device::STATUS_DENIED
    } else {
        status
    }
}

/// `deviceDecisionClaims`.
fn v2_decision_claims(r: &Request) -> Result<Arc<Claims>, Problem> {
    let Some(claims) = get_claims(r) else {
        return Err(authentication_required());
    };
    if !claims.is_own_login_session() {
        return Err(Problem::new(
            problem_type("permission_denied"),
            "Approving or denying a device needs a signed-in session; API keys and impersonation sessions cannot.",
        ));
    }
    Ok(claims)
}

/// `decisionCodes`.
fn v2_decision_codes(body: &DecisionBody) -> Result<(), Problem> {
    if body.token.is_empty() && body.code.is_empty() {
        return Err(
            Problem::new(problem_type("validation_failed"), VALIDATION).with_errors([
                ProblemError {
                    location: "body.code".to_owned(),
                    code: "required".to_owned(),
                    detail: "Either token or code is required.".to_owned(),
                },
            ]),
        );
    }
    Ok(())
}

fn path_param(r: &Request, name: &str) -> String {
    r.url_param(name).to_owned()
}

fn query_param(r: &Request, name: &str) -> String {
    let (values, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    values
        .get(name)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
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

/// `optionalProfileViewerAccess`, in a v1 group's order.
const OPTIONAL_VIEWER: &[Step] = &[Step::Auth, Step::OptionalViewer];
const V1_PASSWORD: &[Step] = &[
    Step::Auth,
    Step::OptionalViewer,
    Step::RateLimitEndpoint("password_change"),
];
const V1_DECISION: &[Step] = &[Step::Auth, Step::RateLimitEndpoint("device_lookup")];
const V1_HANDOFF: &[Step] = &[
    Step::Auth,
    Step::Viewer,
    Step::RateLimitEndpoint("device_lookup"),
];
const AUTH: &[Step] = &[Step::Auth];

/// Registers this domain's v1 handlers.
fn mount_v1(stack: &Arc<Stack>, api: &Mux) {
    let v1 = |path: &str, steps: &'static [Step], h: BoxHandler| stack.v1(path, steps, h);

    api.post(
        "/api/v1/auth/login",
        v1(
            "/api/v1/auth/login",
            &[Step::RateLimitEndpoint("login")],
            route!(stack, |s, w, r| {
                let Some(body) = decode_v1::<LoginBody>(w, r, Some(AUTH_LIMIT), false).await else {
                    return;
                };
                match do_login(&s, r, &body).await {
                    Ok((pair, user)) => {
                        let view = v1_pair(&s, pair, &user).await;
                        write_v1_json(w, 200, &view).await;
                    }
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.get(
        "/api/v1/auth/providers",
        v1(
            "/api/v1/auth/providers",
            &[],
            handler_fn(|w, _r| {
                Box::pin(async move {
                    write_v1_json(
                        w,
                        200,
                        &[V1Provider {
                            id: "local",
                            display_name: "Local",
                            mode: "credentials",
                            default: true,
                        }],
                    )
                    .await;
                })
            }),
        ),
    );

    api.get(
        "/api/v1/auth/setup",
        v1(
            "/api/v1/auth/setup",
            &[],
            route!(stack, |s, w, _r| {
                match s.sign_in.needs_setup().await {
                    Ok(needs_setup) => write_v1_json(w, 200, &SetupStatus { needs_setup }).await,
                    Err(_) => write_v1_error(w, 500, "internal_error", INTERNAL).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/setup",
        v1(
            "/api/v1/auth/setup",
            &[Step::RateLimitEndpoint("setup")],
            route!(stack, |s, w, r| {
                // A browser cannot send JSON cross-origin without a CORS preflight, so a safelisted form or
                // text body is not decoded as setup credentials.
                let content_type =
                    String::from_utf8_lossy(r.header.get("Content-Type")).into_owned();
                if !media_type_is_json(&content_type) {
                    write_v1_error(
                        w,
                        415,
                        "unsupported_media_type",
                        "Initial setup requires application/json",
                    )
                    .await;
                    return;
                }
                let Some(body) = decode_v1::<RegistrationBody>(w, r, Some(AUTH_LIMIT), false).await
                else {
                    return;
                };
                match do_setup(&s, r, &body).await {
                    Ok((pair, user)) => {
                        let view = v1_pair(&s, pair, &user).await;
                        write_v1_json(w, 201, &view).await;
                    }
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.get(
        "/api/v1/auth/signup",
        v1(
            "/api/v1/auth/signup",
            &[],
            route!(stack, |s, w, _r| {
                match s.sign_in.is_signup_enabled().await {
                    Ok(enabled) => write_v1_json(w, 200, &SignupStatus { enabled }).await,
                    Err(_) => write_v1_error(w, 500, "internal_error", INTERNAL).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/signup",
        v1(
            "/api/v1/auth/signup",
            &[Step::RateLimitEndpoint("signup")],
            route!(stack, |s, w, r| {
                let Some(body) = decode_v1::<RegistrationBody>(w, r, Some(AUTH_LIMIT), false).await
                else {
                    return;
                };
                match do_signup(&s, r, &body).await {
                    Ok((pair, user)) => {
                        let view = v1_pair(&s, pair, &user).await;
                        write_v1_json(w, 201, &view).await;
                    }
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/refresh",
        v1(
            "/api/v1/auth/refresh",
            &[],
            route!(stack, |s, w, r| {
                let Some(body) = decode_v1::<RefreshBody>(w, r, Some(AUTH_LIMIT), false).await
                else {
                    return;
                };
                match do_refresh(&s, &body.refresh_token).await {
                    Ok(pair) => {
                        write_v1_json(
                            w,
                            200,
                            &RefreshedTokens {
                                access_token: pair.access_token,
                                refresh_token: pair.refresh_token,
                                expires_in: pair.expires_in,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/plugin-launch",
        v1(
            "/api/v1/auth/plugin-launch",
            OPTIONAL_VIEWER,
            route!(stack, |s, w, r| {
                let Some(claims) = jwt_claims(&s, r).filter(|c| !c.session_id.is_empty()) else {
                    write_v1_error(
                        w,
                        401,
                        "unauthorized",
                        "Invalid or missing authentication token",
                    )
                    .await;
                    return;
                };
                match plugin_token(&s, r, &claims, &get_profile_id(r)) {
                    Ok(token) => {
                        let cookie = plugin_cookie(&token, "/api/v1", is_secure(r));
                        w.header().add("Set-Cookie", cookie.as_bytes());
                        write_v1_json(
                            w,
                            200,
                            &PluginLaunch {
                                expires_in: PLUGIN_LAUNCH_TTL_SECS,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/device/start",
        v1(
            "/api/v1/auth/device/start",
            &[Step::RateLimitEndpoint("device_start")],
            route!(stack, |s, w, r| {
                let Some(body) = decode_v1::<DeviceStartBody>(w, r, Some(AUTH_LIMIT), true).await
                else {
                    return;
                };
                let input = StartInput {
                    device_name: body.device_name,
                    device_platform: body.device_platform,
                    ip_address: client_ip_of(r),
                    user_agent: String::from_utf8_lossy(r.header.get("User-Agent")).into_owned(),
                    base_url: request_base_url(r),
                    client_purpose: body.client_purpose,
                    temporary: body.temporary,
                    legacy: true,
                };
                match do_device_start(&s, input).await {
                    Ok(result) => {
                        write_v1_json(
                            w,
                            201,
                            &V1DeviceStart {
                                device_code: result.device_code,
                                user_code: result.user_code,
                                match_code: result.match_code,
                                verification_uri: result.verification_uri,
                                verification_uri_complete: result.verification_uri_complete,
                                expires_at: go_rfc3339(result.expires_at),
                                expires_in: result.expires_in,
                                interval: result.interval,
                                device_name: result.device_name,
                                device_platform: result.device_platform,
                                client_purpose: result.client_purpose,
                                temporary: result.temporary,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.get(
        "/api/v1/auth/device",
        v1(
            "/api/v1/auth/device",
            &[Step::RateLimitEndpoint("device_lookup")],
            route!(stack, |s, w, r| {
                let input = LookupInput {
                    browser_code: query_param(r, "token"),
                    user_code: query_param(r, "code"),
                    ..Default::default()
                };
                match do_device_lookup(&s, &input).await {
                    Ok(info) => {
                        write_v1_json(
                            w,
                            200,
                            &V1DeviceLookup {
                                status: v1_status(&info.status).to_owned(),
                                user_code: info.user_code,
                                match_code: info.match_code,
                                device_name: info.device_name,
                                device_platform: info.device_platform,
                                ip_address_hint: info.ip_address_hint,
                                expires_at: go_rfc3339(info.expires_at),
                                client_purpose: info.client_purpose,
                                temporary: info.temporary,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/device/poll",
        v1(
            "/api/v1/auth/device/poll",
            &[Step::RateLimitEndpoint("device_poll")],
            route!(stack, |s, w, r| {
                let Some(body) = decode_v1::<PollBody>(w, r, Some(AUTH_LIMIT), false).await else {
                    return;
                };
                if body.device_code.is_empty() {
                    write_v1_error(w, 400, "bad_request", "device_code is required").await;
                    return;
                }
                match do_device_poll(&s, &body.device_code, &device_of(r)).await {
                    Ok(result) => {
                        let mut resp = V1DevicePoll {
                            status: v1_status(&result.status).to_owned(),
                            poll_after: result.poll_after,
                            access_token: String::new(),
                            refresh_token: String::new(),
                            expires_in: 0,
                            user: None,
                            profile_id: String::new(),
                            profile_token: String::new(),
                            temporary: false,
                            session_expires_at: String::new(),
                        };
                        if let Some((pair, user)) = &result.tokens {
                            resp.access_token.clone_from(&pair.access_token);
                            resp.refresh_token.clone_from(&pair.refresh_token);
                            resp.expires_in = pair.expires_in;
                            resp.user = Some(v1_user(&s, user).await);
                            if result.temporary {
                                resp.profile_id.clone_from(&result.profile_id);
                                resp.profile_token.clone_from(&result.profile_token);
                                resp.temporary = true;
                                if let Some(t) = result.session_expires_at {
                                    resp.session_expires_at = go_rfc3339(t);
                                }
                            }
                        }
                        write_v1_json(w, 200, &resp).await;
                    }
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/logout",
        v1(
            "/api/v1/auth/logout",
            AUTH,
            route!(stack, |s, w, r| {
                let Some(claims) = jwt_claims(&s, r) else {
                    write_v1_error(
                        w,
                        401,
                        "unauthorized",
                        "Invalid or missing authentication token",
                    )
                    .await;
                    return;
                };
                match s.sign_in.logout(&claims.session_id).await {
                    Ok(()) => w.write_header(204).await,
                    Err(_) => write_v1_error(w, 500, "internal_error", INTERNAL).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/impersonation/end",
        v1(
            "/api/v1/auth/impersonation/end",
            AUTH,
            route!(stack, |s, w, r| {
                let Some(claims) = jwt_claims(&s, r) else {
                    write_v1_error(
                        w,
                        401,
                        "unauthorized",
                        "Invalid or missing authentication token",
                    )
                    .await;
                    return;
                };
                let audit = s.audit_request(r, false);
                match do_end_impersonation(&s, &claims, &audit).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.get(
        "/api/v1/auth/sessions",
        v1(
            "/api/v1/auth/sessions",
            AUTH,
            route!(stack, |s, w, r| {
                let Some(claims) = jwt_claims(&s, r) else {
                    write_v1_error(
                        w,
                        401,
                        "unauthorized",
                        "Invalid or missing authentication token",
                    )
                    .await;
                    return;
                };
                match s.sign_in.sessions_of(claims.user_id).await {
                    Ok(sessions) => {
                        let sessions = sessions
                            .iter()
                            .map(|x| V1Session {
                                id: x.id.clone(),
                                device_name: x.device_name.clone(),
                                ip_address: x.ip_address.clone(),
                                created_at: go_time(x.created_at),
                                expires_at: go_time(x.expires_at),
                                revoked_at: x.revoked_at.map(go_time),
                            })
                            .collect();
                        write_v1_json(w, 200, &V1Sessions { sessions }).await;
                    }
                    Err(_) => write_v1_error(w, 500, "internal_error", INTERNAL).await,
                }
            }),
        ),
    );

    api.delete(
        "/api/v1/auth/sessions/{id}",
        v1(
            "/api/v1/auth/sessions/{id}",
            AUTH,
            route!(stack, |s, w, r| {
                let Some(claims) = jwt_claims(&s, r) else {
                    write_v1_error(
                        w,
                        401,
                        "unauthorized",
                        "Invalid or missing authentication token",
                    )
                    .await;
                    return;
                };
                let audit = s.audit_request(r, false);
                match do_revoke(&s, &path_param(r, "id"), claims.user_id, &audit).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/account/password",
        v1(
            "/api/v1/auth/account/password",
            V1_PASSWORD,
            route!(stack, |s, w, r| {
                let claims = get_claims(r);
                let profile = declared_profile_id(r);
                if let Err(e) = authorize_password_change(&s, claims.as_deref(), &profile).await {
                    write_v1_api_error(w, &e).await;
                    return;
                }
                let Some(claims) = claims else {
                    return;
                };
                let Some(body) = decode_v1::<PasswordBody>(w, r, None, false).await else {
                    return;
                };
                let audit = s.audit_request(r, false);
                match do_change_password(
                    &s,
                    &claims,
                    &body.current_password,
                    &body.new_password,
                    false,
                    &audit,
                )
                .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_v1_api_error(w, &e).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/device/approve",
        v1(
            "/api/v1/auth/device/approve",
            V1_DECISION,
            route!(stack, |s, w, r| {
                let claims = get_claims(r);
                let user_id = claims.as_ref().map_or(0, |c| c.user_id);
                if user_id == 0 {
                    write_v1_error(w, 401, "unauthorized", "Authentication required").await;
                    return;
                }
                let Some(body) = decode_v1::<DecisionBody>(w, r, None, false).await else {
                    return;
                };
                if let Some(e) = decision_session_error(claims.as_deref()) {
                    write_v1_api_error(w, &e).await;
                    return;
                }
                let input = LookupInput {
                    browser_code: body.token,
                    user_code: body.code,
                    ..Default::default()
                };
                match s.devices.approve(&input, user_id, claims.as_deref()).await {
                    Ok(()) => write_v1_json(w, 200, &Decision { status: "approved" }).await,
                    Err(e) => write_v1_api_error(w, &decision_error(e)).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/device/approve-handoff",
        v1(
            "/api/v1/auth/device/approve-handoff",
            V1_HANDOFF,
            route!(stack, |s, w, r| {
                let scope = r.extensions.get::<Arc<Scope>>().cloned();
                let Some(scope) = scope.filter(|x| x.user_id != 0 && !x.profile_id.is_empty())
                else {
                    write_v1_error(
                        w,
                        403,
                        "profile_required",
                        "An active verified profile is required",
                    )
                    .await;
                    return;
                };
                let Some(body) = decode_v1::<DecisionBody>(w, r, None, false).await else {
                    return;
                };
                let claims = get_claims(r);
                if let Some(e) = decision_session_error(claims.as_deref()) {
                    write_v1_api_error(w, &e).await;
                    return;
                }
                let input = LookupInput {
                    browser_code: body.token,
                    user_code: body.code,
                    ..Default::default()
                };
                match s
                    .devices
                    .approve_for_profile(
                        &input,
                        i64::from(scope.user_id),
                        &scope.profile_id,
                        claims.as_deref(),
                    )
                    .await
                {
                    Ok(()) => write_v1_json(w, 200, &Decision { status: "approved" }).await,
                    Err(e) => write_v1_api_error(w, &decision_error(e)).await,
                }
            }),
        ),
    );

    api.post(
        "/api/v1/auth/device/deny",
        v1(
            "/api/v1/auth/device/deny",
            V1_DECISION,
            route!(stack, |s, w, r| {
                let claims = get_claims(r);
                let user_id = claims.as_ref().map_or(0, |c| c.user_id);
                if user_id == 0 {
                    write_v1_error(w, 401, "unauthorized", "Authentication required").await;
                    return;
                }
                let Some(body) = decode_v1::<DecisionBody>(w, r, None, false).await else {
                    return;
                };
                if let Some(e) = decision_session_error(claims.as_deref()) {
                    write_v1_api_error(w, &e).await;
                    return;
                }
                let input = LookupInput {
                    browser_code: body.token,
                    user_code: body.code,
                    ..Default::default()
                };
                match s.devices.deny(&input, user_id).await {
                    Ok(()) => write_v1_json(w, 200, &Decision { status: "denied" }).await,
                    Err(e) => write_v1_api_error(w, &decision_error(e)).await,
                }
            }),
        ),
    );
}

#[derive(Serialize)]
struct V1Provider<'a> {
    id: &'a str,
    display_name: &'a str,
    mode: &'a str,
    default: bool,
}

#[derive(Serialize)]
struct SetupStatus {
    needs_setup: bool,
}

#[derive(Serialize)]
struct SignupStatus {
    enabled: bool,
}

#[derive(Serialize)]
struct V1Sessions {
    sessions: Vec<V1Session>,
}

#[derive(Serialize)]
struct V1DeviceLookup {
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    user_code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    match_code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_platform: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ip_address_hint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    expires_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_purpose: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    temporary: bool,
}

#[derive(Serialize)]
struct V1DevicePoll {
    status: String,
    poll_after: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    access_token: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    refresh_token: String,
    #[serde(skip_serializing_if = "is_zero")]
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<V1User>,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_token: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    temporary: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_expires_at: String,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// `mime.ParseMediaType` being exactly `application/json`, parameters aside.
fn media_type_is_json(content_type: &str) -> bool {
    let media = content_type.split(';').next().unwrap_or_default();
    let media = silo_gocompat::strings::to_lower(trim_space(media));
    media == "application/json"
}

#[derive(Serialize)]
struct V2Provider {
    id: &'static str,
    display_name: &'static str,
    mode: &'static str,
    default: bool,
}

#[derive(Serialize)]
struct V2Providers {
    items: Vec<V2Provider>,
    password_login: bool,
}

#[derive(Serialize)]
struct SessionPage {
    #[serde(flatten)]
    page: silo_api_v2::wire::Collection<V2Session>,
    current_session: Option<V2Session>,
}

#[derive(Serialize, Deserialize)]
struct SessionPosition {
    c: String,
    i: String,
}

#[derive(Serialize)]
struct V2DeviceLogin {
    status: String,
    user_code: String,
    match_code: String,
    device_name: String,
    device_platform: String,
    ip_address_hint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<Instant>,
    requested_at: Instant,
    client_purpose: String,
    temporary: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    server_id: String,
    server_name: String,
}

#[derive(Serialize)]
struct V2DevicePoll {
    status: String,
    poll_after: i64,
    opened: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tokens: Option<V2TokenPair>,
    profile_id: String,
    profile_token: String,
    temporary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_expires_at: Option<Instant>,
}

#[derive(Serialize)]
struct LoginSessionCapabilities<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    available: bool,
    last_seen: bool,
    admin_management: bool,
}

const LOGIN_SESSION_CURSOR_SORT: &str = "-created_at,-id";

/// `ListByUserPage`, the query the session repository offers with the keyset Go passes.
async fn sessions_page(
    s: &Stack,
    user_id: i64,
    after: Option<(SystemTime, String)>,
    limit: i64,
) -> Result<Vec<AuthSession>, ApiError> {
    s.sign_in
        .sessions_page(user_id, after, limit)
        .await
        .map_err(|_| internal())
}

fn limit_of(r: &Request) -> i64 {
    query_param(r, "limit").parse().unwrap_or(50)
}

/// Registers this domain's v2 handlers.
fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    v2.post(
        "/api/v2/auth/login",
        stack.v2_steps(
            "/api/v2/auth/login",
            &[Step::RateLimitEndpoint("login")],
            route!(stack, |s, w, r| {
                let body: LoginBody = match decode_v2(r) {
                    Ok(b) => b,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                match do_login(&s, r, &body).await {
                    Ok((pair, user)) => {
                        let view = v2_pair(&s, pair, &user).await;
                        write_v2_json(w, &view).await;
                    }
                    Err(e) => write_problem(w, r, loginless_v2(e)).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/logout",
        stack.v2(
            "/api/v2/auth/logout",
            V2Class::Authenticated,
            route!(stack, |s, w, r| {
                let Some(claims) = get_claims(r) else {
                    return write_problem(w, r, authentication_required()).await;
                };
                if claims.token_type == token_type::API_KEY || claims.session_id.is_empty() {
                    return write_problem(
                        w,
                        r,
                        Problem::new(
                            problem_type("permission_denied"),
                            "API keys cannot end a login session.",
                        ),
                    )
                    .await;
                }
                match s.sign_in.logout(&claims.session_id).await {
                    Ok(()) => w.write_header(204).await,
                    Err(_) => write_problem(w, r, service_problem(&internal())).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/impersonation/end",
        stack.v2(
            "/api/v2/auth/impersonation/end",
            V2Class::Authenticated,
            route!(stack, |s, w, r| {
                let Some(claims) = get_claims(r) else {
                    return write_problem(w, r, authentication_required()).await;
                };
                let audit = s.audit_request(r, true);
                match do_end_impersonation(&s, &claims, &audit).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) if e.status == 400 => {
                        write_problem(
                            w,
                            r,
                            Problem::new(problem_type("conflict"), format!("{}.", e.message)),
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );

    v2.get(
        "/api/v2/auth/providers",
        stack.v2_steps(
            "/api/v2/auth/providers",
            &[],
            route!(stack, |s, w, r| {
                let allowed = s.sign_in.local_password_login_allowed().await;
                let Ok(allowed) = allowed else {
                    return write_problem(w, r, service_problem(&internal())).await;
                };
                let items = if allowed {
                    vec![V2Provider {
                        id: "local",
                        display_name: "Local",
                        mode: "credentials",
                        default: true,
                    }]
                } else {
                    Vec::new()
                };
                write_v2_json(
                    w,
                    &V2Providers {
                        password_login: !items.is_empty(),
                        items,
                    },
                )
                .await;
            }),
        ),
    );

    v2.post("/api/v2/auth/refresh", stack.v2_steps(
        "/api/v2/auth/refresh",
        &[],
        route!(stack, |s, w, r| {
            let body: RefreshBody = match decode_v2(r) {
                Ok(b) => b,
                Err(problem) => return write_problem(w, r, problem).await,
            };
            match do_refresh(&s, &body.refresh_token).await {
                Ok(pair) => {
                    write_v2_json(
                        w,
                        &RefreshedTokens {
                            access_token: pair.access_token,
                            refresh_token: pair.refresh_token,
                            expires_in: pair.expires_in,
                        },
                    )
                    .await;
                }
                Err(e) if e.status == 503 => {
                    let problem = Problem::new(
                        problem_type("dependency_unavailable"),
                        "The session could not be checked right now. Retry after the Retry-After delay; the session stays valid.",
                    )
                    .with_retry_after(CREDENTIAL_CHECK_RETRY_AFTER);
                    write_problem(w, r, problem).await;
                }
                Err(e) if e.status == 401 && e.code == "session_revoked" => {
                    write_problem(
                        w,
                        r,
                        Problem::new(problem_type("session_expired"), format!("{}.", e.message)),
                    )
                    .await;
                }
                Err(e) if e.status == 401 => {
                    write_problem(
                        w,
                        r,
                        Problem::new(problem_type("invalid_token"), format!("{}.", e.message)),
                    )
                    .await;
                }
                Err(e) => write_problem(w, r, service_problem(&e)).await,
            }
        }),
    ));

    v2.get("/api/v2/auth/sessions", stack.v2(
        "/api/v2/auth/sessions",
        V2Class::Authenticated,
        route!(stack, |s, w, r| {
            let Some(claims) = get_claims(r) else {
                return write_problem(w, r, authentication_required()).await;
            };
            let scope = CursorScope {
                operation_id: "listSessions".to_owned(),
                security: claims.user_id.to_string(),
                filter: String::new(),
                sort: LOGIN_SESSION_CURSOR_SORT.to_owned(),
                tiebreaker: "id".to_owned(),
            };
            let cursor = query_param(r, "cursor");
            let mut after = None;
            if !cursor.is_empty() {
                let position: SessionPosition = match s.cursors.decode(&scope, &cursor) {
                    Ok(position) => position,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let Ok(at) = silo_gocompat::time::parse(silo_gocompat::time::RFC3339_NANO, &position.c).map(|t| t.to_system_time()) else {
                    return write_problem(
                        w,
                        r,
                        Problem::new(
                            problem_type("invalid_cursor"),
                            "The cursor is malformed, tampered with, or belongs to a different query.",
                        ),
                    )
                    .await;
                };
                after = Some((at, position.i));
            }
            let limit = limit_of(r);
            let mut sessions = match sessions_page(&s, claims.user_id, after, limit + 1).await {
                Ok(sessions) => sessions,
                Err(e) => return write_problem(w, r, service_problem(&e)).await,
            };
            let more = sessions.len() as i64 > limit;
            sessions.truncate(limit as usize);
            let mut next = String::new();
            if more && let Some(last) = sessions.last() {
                let position = SessionPosition {
                    c: go_time(last.created_at),
                    i: last.id.clone(),
                };
                next = match s.cursors.encode(&scope, &position) {
                    Ok(next) => next,
                    Err(_) => {
                        return write_problem(
                            w,
                            r,
                            Problem::new(problem_type("internal_error"), "An unexpected error occurred."),
                        )
                        .await;
                    }
                };
            }
            let items: Vec<V2Session> = sessions
                .iter()
                .map(|x| v2_session(x, &claims.session_id))
                .collect();
            let mut current_session = None;
            if !claims.session_id.is_empty() {
                match s
                    .sign_in
                    .current_login_session(claims.user_id, &claims.session_id)
                    .await
                {
                    Ok(current) => {
                        current_session =
                            current.map(|x| v2_session(&x, &claims.session_id));
                    }
                    Err(_) => {
                        return write_problem(w, r, service_problem(&internal())).await;
                    }
                }
            }
            write_v2_json(
                w,
                &SessionPage {
                    page: paginated(items, next),
                    current_session,
                },
            )
            .await;
        }),
    ));

    v2.get(
        "/api/v2/auth/sessions/capabilities",
        stack.v2(
            "/api/v2/auth/sessions/capabilities",
            V2Class::Authenticated,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getLoginSessionCapabilities", |revision| {
                        capability_json(&LoginSessionCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                            last_seen: true,
                            admin_management: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    v2.delete(
        "/api/v2/auth/sessions/{id}",
        stack.v2(
            "/api/v2/auth/sessions/{id}",
            V2Class::Authenticated,
            route!(stack, |s, w, r| {
                let Some(claims) = get_claims(r) else {
                    return write_problem(w, r, authentication_required()).await;
                };
                let audit = s.audit_request(r, true);
                match do_revoke(&s, &path_param(r, "id"), claims.user_id, &audit).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/setup",
        stack.v2_steps(
            "/api/v2/auth/setup",
            &[Step::RateLimitEndpoint("setup")],
            route!(stack, |s, w, r| {
                let body: RegistrationBody = match decode_v2(r) {
                    Ok(b) => b,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Some(problem) = invalid_email_problem(&body.email) {
                    return write_problem(w, r, problem).await;
                }
                match do_setup(&s, r, &body).await {
                    Ok((pair, user)) => {
                        let view = v2_pair(&s, pair, &user).await;
                        write_v2_json_status(w, 201, &view).await;
                    }
                    Err(e) if e.code == "setup_complete" => {
                        write_problem(
                            w,
                            r,
                            Problem::new(problem_type("conflict"), format!("{}.", e.message)),
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, registration_problem(e)).await,
                }
            }),
        ),
    );

    v2.get(
        "/api/v2/auth/signup",
        stack.v2_steps(
            "/api/v2/auth/signup",
            &[],
            route!(stack, |s, w, r| {
                match s.sign_in.is_signup_enabled().await {
                    Ok(enabled) => write_v2_json(w, &SignupStatus { enabled }).await,
                    Err(_) => write_problem(w, r, service_problem(&internal())).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/signup",
        stack.v2_steps(
            "/api/v2/auth/signup",
            &[Step::RateLimitEndpoint("signup")],
            route!(stack, |s, w, r| {
                let body: RegistrationBody = match decode_v2(r) {
                    Ok(b) => b,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Some(problem) = invalid_email_problem(&body.email) {
                    return write_problem(w, r, problem).await;
                }
                match do_signup(&s, r, &body).await {
                    Ok((pair, user)) => {
                        let view = v2_pair(&s, pair, &user).await;
                        write_v2_json_status(w, 201, &view).await;
                    }
                    Err(e) if e.code == "duplicate" => {
                        write_problem(
                            w,
                            r,
                            Problem::new(problem_type("conflict"), format!("{}.", e.message)),
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, registration_problem(e)).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/plugin-launch",
        stack.v2(
            "/api/v2/auth/plugin-launch",
            V2Class::ProfileOptional,
            route!(stack, |s, w, r| {
                let claims = get_claims(r)
                    .filter(|c| !c.session_id.is_empty() && c.token_type == token_type::ACCESS);
                let Some(claims) = claims else {
                    return write_problem(
                        w,
                        r,
                        Problem::new(
                            problem_type("permission_denied"),
                            "A current login session is required to launch a plugin.",
                        ),
                    )
                    .await;
                };
                match plugin_token(&s, r, &claims, &get_profile_id(r)) {
                    Ok(token) => {
                        let cookie = plugin_cookie(&token, PLUGIN_CONTENT_PREFIX, is_secure(r));
                        w.header().add("Set-Cookie", cookie.as_bytes());
                        write_v2_json(
                            w,
                            &PluginLaunch {
                                expires_in: PLUGIN_LAUNCH_TTL_SECS,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );

    v2.get("/api/v2/auth/device", stack.v2_steps(
        "/api/v2/auth/device",
        &[Step::AttachSession, Step::RateLimitEndpoint("device_lookup")],
        route!(stack, |s, w, r| {
            let (token, code) = (query_param(r, "token"), query_param(r, "code"));
            if token.is_empty() && code.is_empty() {
                let problem = Problem::new(problem_type("validation_failed"), VALIDATION).with_errors([
                    ProblemError {
                        location: "query.code".to_owned(),
                        code: "required".to_owned(),
                        detail: "Either token or code is required.".to_owned(),
                    },
                ]);
                return write_problem(w, r, problem).await;
            }
            let claims = get_claims(r);
            let account_id = claims
                .as_ref()
                .filter(|c| c.is_own_login_session())
                .map_or(0, |c| c.user_id);
            if token.is_empty() && device::is_quick_connect_code(&code) && account_id == 0 {
                let problem = if claims.is_some() {
                    Problem::new(
                        problem_type("permission_denied"),
                        "Only the account's own signed-in session can look up a Quick Connect code.",
                    )
                } else {
                    Problem::new(
                        problem_type("authentication_required"),
                        "Sign in to look up a Quick Connect code.",
                    )
                };
                return write_problem(w, r, problem).await;
            }
            let input = LookupInput {
                browser_code: token,
                user_code: code,
                mark_opened: true,
                account_id,
            };
            match do_device_lookup(&s, &input).await {
                Ok(info) => {
                    let names = s
                        .settings
                        .get_many(&["branding.server_name", "server.identity_id"])
                        .await
                        .unwrap_or_default();
                    let server_name = names
                        .get("branding.server_name")
                        .filter(|v| !v.is_empty())
                        .cloned()
                        .unwrap_or_else(|| "Silo".to_owned());
                    write_v2_json(
                        w,
                        &V2DeviceLogin {
                            status: info.status,
                            user_code: info.user_code,
                            match_code: info.match_code,
                            device_name: info.device_name,
                            device_platform: info.device_platform,
                            ip_address_hint: info.ip_address_hint,
                            expires_at: Some(instant(info.expires_at)),
                            requested_at: instant(info.requested_at),
                            client_purpose: info.client_purpose,
                            temporary: info.temporary,
                            server_id: names.get("server.identity_id").cloned().unwrap_or_default(),
                            server_name,
                        },
                    )
                    .await;
                }
                Err(e) => write_problem(w, r, device_problem(e)).await,
            }
        }),
    ));

    v2.post(
        "/api/v2/auth/device/start",
        stack.v2_steps(
            "/api/v2/auth/device/start",
            &[Step::RateLimitEndpoint("device_start")],
            route!(stack, |s, w, r| {
                let body: DeviceStartBody = match decode_v2(r) {
                    Ok(b) => b,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let mut base_url = public_base_url(&s).await;
                if base_url.is_empty() {
                    base_url = request_base_url(r);
                }
                let input = StartInput {
                    device_name: body.device_name,
                    device_platform: body.device_platform,
                    ip_address: client_ip_of(r),
                    user_agent: String::from_utf8_lossy(r.header.get("User-Agent")).into_owned(),
                    base_url,
                    client_purpose: body.client_purpose,
                    temporary: body.temporary,
                    legacy: false,
                };
                match do_device_start(&s, input).await {
                    Ok(result) => {
                        write_v2_json_status(
                            w,
                            201,
                            &V2DeviceStart {
                                device_code: result.device_code,
                                user_code: result.user_code,
                                match_code: result.match_code,
                                verification_uri: result.verification_uri,
                                verification_uri_complete: result.verification_uri_complete,
                                expires_at: instant(result.expires_at),
                                expires_in: result.expires_in,
                                interval: result.interval,
                                device_name: result.device_name,
                                device_platform: result.device_platform,
                                client_purpose: result.client_purpose,
                                temporary: result.temporary,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, device_problem(e)).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/device/poll",
        stack.v2_steps(
            "/api/v2/auth/device/poll",
            &[Step::RateLimitEndpoint("device_poll")],
            route!(stack, |s, w, r| {
                let raw = r
                    .extensions
                    .get::<RawBody>()
                    .map(|b| b.0.clone())
                    .unwrap_or_default();
                let body: PollBody = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                match do_device_poll(&s, &body.device_code, &device_of(r)).await {
                    Ok(result) => {
                        let mut out = V2DevicePoll {
                            status: result.status.clone(),
                            poll_after: result.poll_after,
                            opened: result.opened,
                            expires_at: None,
                            tokens: None,
                            profile_id: String::new(),
                            profile_token: String::new(),
                            temporary: false,
                            session_expires_at: None,
                        };
                        if result.status == device::STATUS_PENDING {
                            out.expires_at = result.expires_at.map(instant);
                        }
                        if let Some((pair, user)) = &result.tokens {
                            out.tokens = Some(v2_pair(&s, pair.clone(), user).await);
                            if result.temporary {
                                out.profile_id.clone_from(&result.profile_id);
                                out.profile_token.clone_from(&result.profile_token);
                                out.temporary = true;
                                out.session_expires_at = result.session_expires_at.map(instant);
                            }
                        }
                        write_v2_json(w, &out).await;
                    }
                    Err(e) => write_problem(w, r, device_problem(e)).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/device/cancel",
        stack.v2_steps(
            "/api/v2/auth/device/cancel",
            &[Step::RateLimitEndpoint("device_poll")],
            route!(stack, |s, w, r| {
                let raw = r
                    .extensions
                    .get::<RawBody>()
                    .map(|b| b.0.clone())
                    .unwrap_or_default();
                let body: PollBody = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                match s.devices.cancel(&body.device_code).await {
                    Ok(status) => write_v2_json(w, &DeviceCancel { status }).await,
                    Err(DeviceError::NotFound) => {
                        let e = api_error(404, "not_found", "Device login request not found");
                        write_problem(w, r, device_problem(e)).await;
                    }
                    Err(_) => {
                        let e = api_error(500, "internal_error", "Failed to cancel device login");
                        write_problem(w, r, device_problem(e)).await;
                    }
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/device/approve",
        stack.v2_steps(
            "/api/v2/auth/device/approve",
            &[Step::Auth, Step::RateLimitEndpoint("device_lookup")],
            route!(stack, |s, w, r| {
                let claims = match v2_decision_claims(r) {
                    Ok(claims) => claims,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let body: DecisionBody = match decode_v2(r) {
                    Ok(b) => b,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Err(problem) = v2_decision_codes(&body) {
                    return write_problem(w, r, problem).await;
                }
                let input = LookupInput {
                    browser_code: body.token,
                    user_code: body.code,
                    mark_opened: false,
                    account_id: claims.user_id,
                };
                match s
                    .devices
                    .approve(&input, claims.user_id, Some(&claims))
                    .await
                {
                    Ok(()) => write_v2_json(w, &Decision { status: "approved" }).await,
                    Err(e) => write_problem(w, r, device_problem(decision_error(e))).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/device/approve-handoff",
        stack.v2_steps(
            "/api/v2/auth/device/approve-handoff",
            &[
                Step::Auth,
                Step::RateLimitEndpoint("device_lookup"),
                Step::Viewer,
                Step::Profile,
            ],
            route!(stack, |s, w, r| {
                let claims = match v2_decision_claims(r) {
                    Ok(claims) => claims,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let scope = r.extensions.get::<Arc<Scope>>().cloned();
                let Some(scope) = scope.filter(|x| x.user_id != 0 && !x.profile_id.is_empty())
                else {
                    return write_problem(
                        w,
                        r,
                        Problem::new(
                            problem_type("permission_denied"),
                            "An active verified profile is required.",
                        ),
                    )
                    .await;
                };
                let body: DecisionBody = match decode_v2(r) {
                    Ok(b) => b,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Err(problem) = v2_decision_codes(&body) {
                    return write_problem(w, r, problem).await;
                }
                let user_id = i64::from(scope.user_id);
                let input = LookupInput {
                    browser_code: body.token,
                    user_code: body.code,
                    mark_opened: false,
                    account_id: user_id,
                };
                match s
                    .devices
                    .approve_for_profile(&input, user_id, &scope.profile_id, Some(&claims))
                    .await
                {
                    Ok(()) => write_v2_json(w, &Decision { status: "approved" }).await,
                    Err(e) => write_problem(w, r, device_problem(decision_error(e))).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/auth/device/deny",
        stack.v2_steps(
            "/api/v2/auth/device/deny",
            &[Step::Auth, Step::RateLimitEndpoint("device_lookup")],
            route!(stack, |s, w, r| {
                let claims = match v2_decision_claims(r) {
                    Ok(claims) => claims,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let body: DecisionBody = match decode_v2(r) {
                    Ok(b) => b,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if let Err(problem) = v2_decision_codes(&body) {
                    return write_problem(w, r, problem).await;
                }
                let input = LookupInput {
                    browser_code: body.token,
                    user_code: body.code,
                    mark_opened: false,
                    account_id: claims.user_id,
                };
                match s.devices.deny(&input, claims.user_id).await {
                    Ok(()) => write_v2_json(w, &Decision { status: "denied" }).await,
                    Err(e) => write_problem(w, r, device_problem(decision_error(e))).await,
                }
            }),
        ),
    );

    v2.post(
        "/api/v2/account/password",
        stack.v2_steps(
            "/api/v2/account/password",
            &[
                Step::Auth,
                Step::RateLimitEndpoint("password_change"),
                Step::Viewer,
            ],
            route!(stack, |s, w, r| {
                let body: PasswordBody = match decode_v2(r) {
                    Ok(b) => b,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let Some(claims) = get_claims(r) else {
                    return write_problem(w, r, authentication_required()).await;
                };
                if let Err(e) =
                    authorize_password_change(&s, Some(&claims), &get_profile_id(r)).await
                {
                    return write_problem(w, r, password_problem(e)).await;
                }
                let audit = s.audit_request(r, true);
                match do_change_password(
                    &s,
                    &claims,
                    &body.current_password,
                    &body.new_password,
                    body.sign_out_other_sessions,
                    &audit,
                )
                .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, password_problem(e)).await,
                }
            }),
        ),
    );
    let _ = new_collection::<u8>;
    let _ = |_: &Row| ();
}

#[derive(Serialize)]
struct DeviceCancel {
    status: String,
}

/// Registers this domain's handlers.
pub fn mount(stack: &Arc<Stack>, api: &Mux, v2: &Mux) {
    mount_v1(stack, api);
    mount_v2(stack, v2);
}
