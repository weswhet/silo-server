//! `auth.go`, `apple_push_display.go`, `direct_download_link.go`, `current_authority.go`, and the
//! session half of `remote_playback.go`.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex};

use silo_auth::api_key_store::{
    ApiKeyError, ApiKeyLastUsedTracker, ApiKeyRepository, SessionLastSeenTracker,
};
use silo_auth::claims::{Claims, JwtService, SESSION_PURPOSE_REMOTE_PLAYBACK, token_type};
use silo_auth::session::{SessionAuthority, SessionRepository};
use silo_auth::user::{UserError, UserRepository};
use silo_http::{Header, Request};

use super::denial::{Denial, reason};
use super::scopes;

/// `DirectDownloadLinkParam`.
pub const DIRECT_DOWNLOAD_LINK_PARAM: &str = "dl";

/// `SetProfileID`: the profile the request context carries.
#[derive(Clone, Debug)]
pub struct ProfileId(pub String);

/// `activitylog.LogContext`: filled by authentication, read by the loggers after the handler ran.
#[derive(Clone, Debug, Default)]
pub struct LogFields {
    pub user_id: Option<i64>,
    pub impersonator_user_id: Option<i64>,
    pub session_id: String,
    /// The status of each audited mutation this request committed (`LogContext.Committed`).
    pub committed_statuses: Vec<i32>,
}

/// The shared cell the outermost logging middleware reads back.
#[derive(Clone, Default)]
pub struct LogContext(pub Arc<Mutex<LogFields>>);

/// `passwordChangeRoutes`.
static PASSWORD_CHANGE_ROUTES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "GET /api/v1/auth/me",
        "GET /api/v1/auth/account/capability",
        "POST /api/v1/auth/account/password",
        "POST /api/v1/auth/logout",
        "GET /api/v2/account/me",
        "GET /api/v2/account/password/capability",
        "POST /api/v2/account/password",
        "POST /api/v2/auth/logout",
    ])
});

/// `parseBearerHeader`.
pub fn parse_bearer_header(header: &[u8]) -> Option<&[u8]> {
    let space = header.iter().position(|&b| b == b' ')?;
    let (scheme, rest) = (&header[..space], &header[space + 1..]);
    if !scheme.eq_ignore_ascii_case(b"bearer") {
        return None;
    }
    let token = silo_http::header::trim_string(rest);
    (!token.is_empty()).then_some(token)
}

/// The first value of a query parameter: `r.URL.Query().Get(name)`.
pub fn query_get(r: &Request, name: &str) -> Option<String> {
    query_values(r)
        .remove(name)
        .and_then(|mut v| (!v.is_empty()).then(|| v.remove(0)))
}

/// `r.URL.Query()`: bad pairs are skipped.
fn query_values(r: &Request) -> std::collections::HashMap<String, Vec<String>> {
    let mut out: std::collections::HashMap<String, Vec<String>> = Default::default();
    for pair in r.url.raw_query.split(|&b| b == b'&') {
        if pair.is_empty() || pair.contains(&b';') {
            continue;
        }
        let eq = pair.iter().position(|&b| b == b'=');
        let (k, v) = match eq {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &pair[pair.len()..]),
        };
        if let (Ok(k), Ok(v)) = (
            silo_gocompat::url::query_unescape(k),
            silo_gocompat::url::query_unescape(v),
        ) {
            out.entry(String::from_utf8_lossy(&k).into_owned())
                .or_default()
                .push(String::from_utf8_lossy(&v).into_owned());
        }
    }
    out
}

/// `extractBearerToken`.
fn extract_bearer_token(r: &Request) -> Option<Vec<u8>> {
    if let Some(token) = parse_bearer_header(r.header.get("Authorization")) {
        return Some(token.to_vec());
    }
    query_get(r, "token")
        .filter(|t| !t.is_empty())
        .map(String::into_bytes)
}

/// `SessionAuthority.Narrow`.
fn narrow(authority: &SessionAuthority, claims: &mut Claims) {
    if authority.is_remote_playback() {
        claims.role = "user".to_owned();
        claims.session_purpose = SESSION_PURPOSE_REMOTE_PLAYBACK.to_owned();
        claims.profile_id = authority.bound_profile_id.clone();
    }
}

/// `narrowRemotePlayback`.
fn narrow_remote_playback(
    r: &mut Request,
    claims: &mut Claims,
    authority: &SessionAuthority,
) -> bool {
    let allowed = scopes::unambiguous_request_path(r)
        .is_some_and(|path| scopes::remote_playback_allows_route(&r.method, path));
    if !allowed {
        return false;
    }
    let declared = r.header.get("X-Profile-Id").to_vec();
    if declared.is_empty() {
        r.header
            .set("X-Profile-Id", authority.bound_profile_id.as_bytes());
    } else if declared != authority.bound_profile_id.as_bytes() {
        return false;
    }
    narrow(authority, claims);
    true
}

fn attribute(r: &Request, claims: &Claims) {
    if let Some(lc) = r.extensions.get::<LogContext>() {
        let mut fields = lc.0.lock().unwrap_or_else(|e| e.into_inner());
        fields.user_id = Some(claims.user_id);
        fields.impersonator_user_id = claims.impersonator_user_id;
        fields.session_id = claims.session_id.clone();
    }
}

fn set_claims(r: &mut Request, claims: Claims) {
    r.extensions.insert(Arc::new(claims));
}

/// `GetClaims`.
pub fn get_claims(r: &Request) -> Option<Arc<Claims>> {
    r.extensions.get::<Arc<Claims>>().cloned()
}

/// `GetProfileID`.
pub fn get_profile_id(r: &Request) -> String {
    r.extensions
        .get::<ProfileId>()
        .map(|p| p.0.clone())
        .unwrap_or_default()
}

/// `declaredProfileID`.
pub fn declared_profile_id(r: &Request) -> String {
    let id = get_profile_id(r);
    if !id.is_empty() {
        return id;
    }
    String::from_utf8_lossy(r.header.get("X-Profile-Id")).into_owned()
}

/// `ErrCurrentCredentialInvalid` and friends.
#[derive(Debug, thiserror::Error)]
pub enum RevalidateError {
    #[error("current credential is invalid")]
    Invalid,
    #[error("current credential does not permit this operation")]
    Forbidden,
    #[error("{0}")]
    Store(String),
}

/// `AuthMiddleware`.
pub struct AuthGate {
    jwt: Arc<JwtService>,
    sessions: SessionRepository,
    api_keys: ApiKeyRepository,
    users: UserRepository,
    api_key_last_used: ApiKeyLastUsedTracker,
    session_last_seen: SessionLastSeenTracker,
}

impl AuthGate {
    pub fn new(
        jwt: Arc<JwtService>,
        sessions: SessionRepository,
        api_keys: ApiKeyRepository,
        users: UserRepository,
    ) -> Self {
        Self {
            jwt,
            api_key_last_used: ApiKeyLastUsedTracker::new(api_keys.clone()),
            session_last_seen: SessionLastSeenTracker::new(sessions.clone()),
            sessions,
            api_keys,
            users,
        }
    }

    /// `RequireAuth`.
    pub async fn require_auth(&self, r: &mut Request) -> Result<(), Denial> {
        let Some(token) = extract_bearer_token(r) else {
            return Err(Denial::unauthorized(
                "Missing or malformed authorization header",
                reason::AUTHENTICATION_REQUIRED,
            ));
        };
        let claims = if token.starts_with(b"sa_") {
            self.api_key_claims(r, &token).await?
        } else {
            self.access_claims(r, &token).await?
        };
        attribute(r, &claims);
        if claims.password_change_required {
            let route = format!("{} {}", r.method, String::from_utf8_lossy(&r.url.path));
            if !PASSWORD_CHANGE_ROUTES.contains(route.as_str()) {
                return Err(Denial::password_change_required());
            }
        }
        set_claims(r, claims);
        Ok(())
    }

    async fn api_key_claims(&self, r: &Request, token: &[u8]) -> Result<Claims, Denial> {
        let invalid = || Denial::unauthorized("Invalid API key", reason::INVALID_CREDENTIAL);
        let key = match self.api_keys.get_by_key(token).await {
            Ok(key) => key,
            Err(ApiKeyError::NotFound) => return Err(invalid()),
            Err(e) => {
                tracing::warn!(component = "auth", error = %e, "credential check failed; answering 503");
                return Err(Denial::credential_check_unavailable());
            }
        };
        if key.user_id <= 0 {
            return Err(invalid());
        }
        let user = match self.users.get_by_id(key.user_id).await {
            Ok(user) => user,
            Err(UserError::NotFound) => return Err(invalid()),
            Err(e) => {
                tracing::warn!(component = "auth", error = %e, "credential check failed; answering 503");
                return Err(Denial::credential_check_unavailable());
            }
        };
        if user.id <= 0 {
            return Err(invalid());
        }
        if !user.enabled {
            return Err(Denial::unauthorized(
                "User account is disabled",
                reason::ACCOUNT_DISABLED,
            ));
        }
        if !scopes::api_key_scopes_allow(&key.scopes, r) {
            return Err(Denial::forbidden("API key scopes do not permit this route"));
        }
        self.api_key_last_used.touch(key.id);
        Ok(Claims {
            user_id: user.id,
            role: user.role,
            token_type: token_type::API_KEY.to_owned(),
            api_key_id: key.id,
            rate_tier: key.rate_tier,
            api_key_scopes: key.scopes,
            ..Claims::default()
        })
    }

    fn validate(&self, token: &[u8]) -> Option<Claims> {
        self.jwt
            .validate_token(std::str::from_utf8(token).ok()?)
            .ok()
    }

    async fn access_claims(&self, r: &mut Request, token: &[u8]) -> Result<Claims, Denial> {
        let invalid =
            || Denial::unauthorized("Invalid or expired token", reason::INVALID_CREDENTIAL);
        let mut claims = self.validate(token).ok_or_else(invalid)?;
        if claims.user_id <= 0 || claims.token_type != token_type::ACCESS {
            return Err(invalid());
        }
        let authority = self.active_session(&claims).await?;
        if authority.is_remote_playback() {
            if !narrow_remote_playback(r, &mut claims, &authority) {
                return Err(Denial::forbidden(
                    "A remote-playback session can only play on its approved profile",
                ));
            }
        } else if authority.role != claims.role {
            return Err(Denial::unauthorized(
                "The account's role changed; refresh the access token",
                reason::TOKEN_REFRESH_REQUIRED,
            ));
        }
        self.session_last_seen.touch(&claims.session_id);
        Ok(claims)
    }

    /// `ActiveSession`, with both of Go's refusals.
    async fn active_session(&self, claims: &Claims) -> Result<SessionAuthority, Denial> {
        match self
            .sessions
            .active_session(&claims.session_id, claims.user_id)
            .await
        {
            Ok(Some(authority)) => Ok(authority),
            Ok(None) => Err(Denial::unauthorized(
                "Session is no longer valid",
                reason::SESSION_INVALID,
            )),
            Err(e) => {
                tracing::warn!(component = "auth", error = %e, "credential check failed; answering 503");
                Err(Denial::credential_check_unavailable())
            }
        }
    }

    /// `AuthHandler.extractClaims`: the Authorization header's token only, untrimmed, with no session
    /// check. `HandleMe` reads the account through this even behind `RequireAuth`, so an API key or a
    /// `?token=` credential that passed the gate is still refused there.
    pub fn extract_claims(&self, r: &Request) -> Option<Claims> {
        let header = r.header.get("Authorization");
        let space = header.iter().position(|&b| b == b' ')?;
        if !header[..space].eq_ignore_ascii_case(b"bearer") {
            return None;
        }
        self.validate(&header[space + 1..])
    }

    /// `AttachSession`: never refuses.
    pub async fn attach_session(&self, r: &mut Request) {
        let Some(token) = extract_bearer_token(r).filter(|t| !t.starts_with(b"sa_")) else {
            return;
        };
        let Some(mut claims) = self.validate(&token) else {
            return;
        };
        if claims.user_id <= 0
            || claims.token_type != token_type::ACCESS
            || claims.password_change_required
        {
            return;
        }
        let Ok(Some(authority)) = self
            .sessions
            .active_session(&claims.session_id, claims.user_id)
            .await
        else {
            return;
        };
        if authority.is_remote_playback() {
            narrow(&authority, &mut claims);
        } else if authority.role != claims.role {
            return;
        }
        self.session_last_seen.touch(&claims.session_id);
        attribute(r, &claims);
        set_claims(r, claims);
    }

    /// `RequireApplePushDisplayAuth`. `Ok(true)` took the display-token path; `Ok(false)` means the
    /// caller runs its standard chain, as Go's `fallback` does.
    pub async fn apple_push_display(&self, r: &mut Request) -> Result<bool, Denial> {
        let Some(token) = parse_bearer_header(r.header.get("Authorization"))
            .filter(|t| !t.starts_with(b"sa_"))
            .map(<[u8]>::to_vec)
        else {
            return Ok(false);
        };
        let Some(mut claims) = self
            .validate(&token)
            .filter(|c| c.token_type == token_type::APPLE_PUSH_DISPLAY)
        else {
            return Ok(false);
        };
        if claims.profile_id.is_empty() {
            return Err(Denial::unauthorized(
                "Invalid or expired token",
                reason::INVALID_CREDENTIAL,
            ));
        }
        let authority = self.active_session(&claims).await?;
        if authority.is_remote_playback() {
            return Err(Denial::forbidden(
                "A remote-playback session cannot read notifications",
            ));
        }
        claims.role = authority.role;
        attribute(r, &claims);
        let profile = claims.profile_id.clone();
        set_claims(r, claims);
        r.header.set("X-Profile-Id", profile.as_bytes());
        r.extensions.insert(ProfileId(profile));
        r.header.del("X-Profile-Token");
        Ok(true)
    }

    /// `RequireDirectDownloadAuth`.
    pub async fn direct_download(&self, r: &mut Request) -> Result<(), Denial> {
        let query = query_values(r);
        let Some(link) = query.get(DIRECT_DOWNLOAD_LINK_PARAM) else {
            return self.require_auth(r).await;
        };
        let invalid = || {
            Denial::unauthorized(
                "Invalid or expired download link",
                reason::INVALID_CREDENTIAL,
            )
        };
        let link = link.first().cloned().unwrap_or_default();
        let mut claims = self.validate(link.as_bytes()).ok_or_else(invalid)?;
        if claims.token_type != token_type::DIRECT_DOWNLOAD_LINK
            || claims.user_id <= 0
            || claims.profile_id.is_empty()
            || claims.file_id <= 0
        {
            return Err(invalid());
        }
        let file_id = query
            .get("file_id")
            .and_then(|v| v.first().cloned())
            .unwrap_or_default();
        if claims.file_id.to_string() != file_id {
            return Err(Denial::forbidden(
                "The download link does not authorize this file",
            ));
        }
        let authority = self.active_session(&claims).await?;
        if authority.is_remote_playback() {
            return Err(Denial::forbidden(
                "A remote-playback session cannot download files",
            ));
        }
        claims.role = authority.role;
        attribute(r, &claims);
        let profile = claims.profile_id.clone();
        set_claims(r, claims);
        r.header.set("X-Profile-Id", profile.as_bytes());
        r.header.del("X-Profile-Token");
        Ok(())
    }

    /// `RevalidateCurrent`.
    pub async fn revalidate_current(
        &self,
        bearer: &[u8],
        expected: &Claims,
        method: &str,
        path: &str,
    ) -> Result<(), RevalidateError> {
        let token = parse_bearer_header(bearer).ok_or(RevalidateError::Invalid)?;
        if expected.token_type == token_type::API_KEY {
            let key = match self.api_keys.get_by_key(token).await {
                Ok(key) => key,
                Err(ApiKeyError::NotFound) => return Err(RevalidateError::Invalid),
                Err(e) => return Err(RevalidateError::Store(e.to_string())),
            };
            if key.id != expected.api_key_id || key.user_id != expected.user_id {
                return Err(RevalidateError::Invalid);
            }
            if !key.scopes.is_empty() {
                let clean = !path.is_empty() && silo_gocompat::path::clean(path) == path;
                if !clean || !scopes::scopes_allow_path(&key.scopes, method, path) {
                    return Err(RevalidateError::Forbidden);
                }
            }
        } else {
            let current = self.validate(token).ok_or(RevalidateError::Invalid)?;
            if current.token_type != token_type::ACCESS
                || current.user_id != expected.user_id
                || current.session_id != expected.session_id
            {
                return Err(RevalidateError::Invalid);
            }
            let authority = self
                .sessions
                .active_session(&current.session_id, current.user_id)
                .await
                .map_err(|e| RevalidateError::Store(e.to_string()))?
                .ok_or(RevalidateError::Invalid)?;
            if authority.is_remote_playback()
                && (expected.profile_id != authority.bound_profile_id
                    || !scopes::remote_playback_allows_route(method, path))
            {
                return Err(RevalidateError::Forbidden);
            }
        }
        match self.users.get_by_id(expected.user_id).await {
            Ok(user) if user.enabled => Ok(()),
            Ok(_) | Err(UserError::NotFound) => Err(RevalidateError::Invalid),
            Err(e) => Err(RevalidateError::Store(e.to_string())),
        }
    }
}

/// `RequireProfile`.
pub fn require_profile(r: &mut Request) -> Result<(), Denial> {
    let id = String::from_utf8_lossy(r.header.get("X-Profile-Id")).into_owned();
    if id.is_empty() {
        return Err(Denial::profile_header_required());
    }
    r.extensions.insert(ProfileId(id));
    Ok(())
}

/// `RequireAdmin`.
pub fn require_admin(r: &Request) -> Result<(), Denial> {
    let claims = get_claims(r).ok_or_else(|| {
        Denial::unauthorized("Authentication required", reason::AUTHENTICATION_REQUIRED)
    })?;
    if claims.role != "admin" {
        return Err(Denial::forbidden("Admin access required"));
    }
    Ok(())
}

const DEMO_BLOCKED_ROUTES: &[(&[&str], &str)] = &[
    (&["POST", "DELETE"], "/api/v1/api-keys"),
    (&["POST", "DELETE"], "/api/v1/downloads"),
    (&["POST"], "/api/v1/history-imports"),
    (&["POST"], "/api/v1/subtitles/download"),
    (&["POST"], "/api/v1/subtitles/upload"),
    (&["DELETE"], "/api/v1/subtitles/"),
    (&["POST", "PUT", "DELETE"], "/api/v1/diagnostics/reports"),
];

/// Whether a method always passes demo mode.
fn read_only(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

/// `DemoGuard.Guard`. `enabled` reads `demo.enabled` only when the method needs it.
pub async fn demo_guard<F, Fut>(r: &Request, enabled: F) -> Result<(), Denial>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = String>,
{
    if read_only(&r.method) || enabled().await != "true" {
        return Ok(());
    }
    if get_claims(r).is_some_and(|c| c.role == "admin") {
        return Ok(());
    }
    let path = String::from_utf8_lossy(&r.url.path);
    for (methods, prefix) in DEMO_BLOCKED_ROUTES {
        if path.starts_with(prefix) && methods.contains(&r.method.as_str()) {
            return Err(Denial::demo_blocked());
        }
    }
    Ok(())
}

/// `demoGate`: the v2 rule for an operation declared demo restricted.
pub async fn demo_gate<F, Fut>(r: &Request, enabled: F) -> Result<(), Denial>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = String>,
{
    if read_only(&r.method) || enabled().await != "true" {
        return Ok(());
    }
    if get_claims(r).is_some_and(|c| c.role == "admin") {
        return Ok(());
    }
    Err(Denial::demo_blocked())
}

/// Writes a gate's headers, as Go's denial writers see them.
pub fn apply_denial_headers(sink: &mut Header, denial: &Denial) {
    if let Some(retry) = denial.retry_after {
        sink.set("Retry-After", retry.to_string().as_bytes());
    }
    sink.set("Content-Type", "application/json");
}
