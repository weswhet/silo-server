//! `internal/auth/service.go`, `repository.go`, `local_login_policy.go`, `signin_attempts.go`,
//! `client_device.go`, and `account_provisioner.go`: password sign-in, refresh, sign-out, the password
//! change, first-run setup, and invited signup, for a server with no external sign-in provider.
//!
//! The front keeps these rows on Go while any auth plugin binding or linked identity exists, because the
//! plugin host has no Rust port. So a provider named here finds nothing, and the provider re-check does
//! not run; a session opened through a provider identity fails the check rather than going unchecked.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use silo_pg::{Pool, Row, Session};

use crate::attempts::{AttemptLimiter, retry_after_seconds};
use crate::audit::{self, AuditRequest};
use crate::claims::{Claims, JwtService, token_type};
use crate::passwordhash;
use crate::permissions::{default_user_permissions, normalize_permissions};
use crate::session::{self, AuthSession, SessionRepository};
use crate::user::{USER_COLUMNS, User, UserError, UserRepository, scan_user};

/// `MinimumPasswordLength` and `MaximumPasswordBytes`.
pub const MINIMUM_PASSWORD_LENGTH: usize = 8;
pub const MAXIMUM_PASSWORD_BYTES: usize = 72;

/// `config.ServerSettingsMutationLock`.
const SERVER_SETTINGS_MUTATION_LOCK: &str = "silo:server_settings:mutation";
/// `InitialSetupAdvisoryLock`: "SILOSETU".
const INITIAL_SETUP_ADVISORY_LOCK: i64 = 0x5349_4C4F_5345_5455;
/// `AuthLocalPasswordLoginSettingKey`.
const LOCAL_PASSWORD_LOGIN_KEY: &str = "auth.local_password_login";
/// `LocalProviderID`.
pub const LOCAL_PROVIDER_ID: &str = "local";
/// `CheckStatusNotFound`, `CheckStatusDisabled`, `CheckStatusNotPermitted`.
const REFUSAL_STATUSES: [&str; 3] = ["not_found", "disabled", "not_permitted"];

/// What a service call can refuse with, in Go's sentinel errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthFailure {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user account is disabled")]
    UserDisabled,
    #[error("local password sign-in is turned off on this server")]
    LocalLoginDisabled,
    #[error("not permitted")]
    NotPermitted,
    #[error("password hashing is at capacity")]
    Busy,
    #[error("too many failed sign-ins for this name")]
    Throttled(i64),
    #[error("session has been revoked")]
    SessionRevoked,
    #[error("login session could not be checked: {0}")]
    SessionCheckUnavailable(String),
    #[error("invalid refresh token")]
    InvalidToken,
    #[error("session not found")]
    SessionNotFound,
    #[error("not impersonating")]
    NotImpersonating,
    #[error("impersonation not allowed")]
    ImpersonationNotAllowed,
    #[error("current password is invalid")]
    CurrentPasswordInvalid,
    #[error("password is too short")]
    PasswordTooShort,
    #[error("password is too long")]
    PasswordTooLong,
    #[error("new password matches the temporary password")]
    PasswordUnchanged,
    #[error("local password login is disabled")]
    PasswordLoginDisabled,
    #[error("initial setup already complete")]
    SetupAlreadyComplete,
    #[error("public signups are not enabled")]
    SignupDisabled,
    #[error("invite code not found")]
    InviteCodeNotFound,
    #[error("invite code exhausted")]
    InviteCodeExhausted,
    #[error("invite code disabled")]
    InviteCodeDisabled,
    #[error("duplicate user")]
    Duplicate,
    /// `ErrSignupSessionStart`: the account exists, so repeating the signup cannot succeed.
    #[error("account created but login failed: {0}")]
    SignupSessionStart(Box<AuthFailure>),
    #[error("{0}")]
    Other(String),
}

impl From<silo_pg::Error> for AuthFailure {
    fn from(e: silo_pg::Error) -> Self {
        AuthFailure::Other(e.to_string())
    }
}

impl From<silo_pg::DriverError> for AuthFailure {
    fn from(e: silo_pg::DriverError) -> Self {
        AuthFailure::Other(e.to_string())
    }
}

impl From<passwordhash::GenerateError> for AuthFailure {
    fn from(e: passwordhash::GenerateError) -> Self {
        match e {
            passwordhash::GenerateError::Busy(_) => AuthFailure::Busy,
            other => AuthFailure::Other(other.to_string()),
        }
    }
}

impl From<passwordhash::Busy> for AuthFailure {
    fn from(_: passwordhash::Busy) -> Self {
        AuthFailure::Busy
    }
}

impl From<UserError> for AuthFailure {
    fn from(e: UserError) -> Self {
        AuthFailure::Other(e.to_string())
    }
}

impl From<session::Error> for AuthFailure {
    fn from(e: session::Error) -> Self {
        match e {
            session::Error::NotFound => AuthFailure::SessionNotFound,
            other => AuthFailure::Other(other.to_string()),
        }
    }
}

impl From<silo_jwt::Error> for AuthFailure {
    fn from(e: silo_jwt::Error) -> Self {
        AuthFailure::Other(format!("generating token: {e}"))
    }
}

/// `TokenPair`.
#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub session_id: String,
}

/// `ClientDevice`: audit and display data a request reports about itself. It authorizes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientDevice {
    pub id: String,
    pub name: String,
    pub platform: String,
}

const MAX_CLIENT_DEVICE_ID_LEN: usize = 128;
const MAX_CLIENT_DEVICE_NAME_LEN: usize = 120;
pub(crate) const MAX_CLIENT_DEVICE_PLATFORM_LEN: usize = 40;

impl ClientDevice {
    /// `NewClientDevice`, over what the header held.
    pub fn new(id: &[u8], name: &[u8], platform: &[u8]) -> Self {
        let id = String::from_utf8_lossy(id);
        let id = silo_gocompat::strings::trim_space(&id);
        let shaped = id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
        Self {
            id: if id.len() > MAX_CLIENT_DEVICE_ID_LEN || id.is_empty() || !shaped {
                String::new()
            } else {
                id.to_owned()
            },
            name: clamp_device_value(name, MAX_CLIENT_DEVICE_NAME_LEN),
            platform: clamp_device_value(platform, MAX_CLIENT_DEVICE_PLATFORM_LEN),
        }
    }

    /// `applyClientDevice`: what the device itself reported wins.
    pub(crate) fn apply(&self, session: &mut AuthSession) {
        if !self.id.is_empty() {
            session.device_id = self.id.clone();
        }
        if !self.name.is_empty() {
            session.device_name = self.name.clone();
        }
        if !self.platform.is_empty() {
            session.device_platform = self.platform.clone();
        }
    }
}

/// `clampClientDeviceValue`. A value that is not text is dropped: Postgres would refuse it.
pub(crate) fn clamp_device_value(value: &[u8], max: usize) -> String {
    let Ok(value) = std::str::from_utf8(value) else {
        return String::new();
    };
    let value = silo_gocompat::strings::trim_space(value);
    if value.chars().count() <= max {
        return value.to_owned();
    }
    let clamped: String = value.chars().take(max).collect();
    silo_gocompat::strings::trim_space(&clamped).to_owned()
}

/// What a session opening needs to know about the request.
#[derive(Debug, Clone, Default)]
pub struct SignInContext {
    pub device_name: String,
    pub ip: String,
    pub device: ClientDevice,
}

fn validate_new_password(password: &str) -> Result<(), AuthFailure> {
    if password.chars().count() < MINIMUM_PASSWORD_LENGTH {
        return Err(AuthFailure::PasswordTooShort);
    }
    if password.len() > MAXIMUM_PASSWORD_BYTES {
        return Err(AuthFailure::PasswordTooLong);
    }
    Ok(())
}

/// `ValidateNewPassword`.
pub fn check_new_password(password: &str) -> Result<(), AuthFailure> {
    validate_new_password(password)
}

fn is_duplicate(e: &silo_pg::Error) -> bool {
    e.code().is_some_and(|c| c.code() == "23505")
}

fn is_int4(value: i64) -> Result<i32, AuthFailure> {
    i32::try_from(value).map_err(|_| AuthFailure::Other(format!("{value} does not fit in int4")))
}

/// `settingBool`.
fn setting_bool(value: &str, fallback: bool) -> bool {
    match silo_gocompat::strings::trim_space(value) {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => true,
        "0" | "f" | "F" | "FALSE" | "false" | "False" => false,
        _ => fallback,
    }
}

/// `readBoolSetting` for the local password switch.
async fn local_password_login_allowed(db: &mut Session) -> Result<bool, AuthFailure> {
    let rows = db
        .query(
            "SELECT value FROM server_settings WHERE key = $1",
            &[&LOCAL_PASSWORD_LOGIN_KEY],
        )
        .await?;
    Ok(match rows.first() {
        Some(row) => setting_bool(&row.try_get::<_, String>(0)?, true),
        None => true,
    })
}

async fn lock_server_settings(tx: &mut Session) -> Result<(), AuthFailure> {
    tx.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        &[&SERVER_SETTINGS_MUTATION_LOCK],
    )
    .await?;
    Ok(())
}

/// `networkRefused`.
async fn network_refused(db: &mut Session, user_id: i64) -> Result<bool, AuthFailure> {
    let id = is_int4(user_id)?;
    let refusals: Vec<&str> = REFUSAL_STATUSES.to_vec();
    let rows = db
        .query(
            "SELECT EXISTS (SELECT 1 FROM plugin_auth_identities i
                JOIN plugin_installations p ON p.id = i.plugin_installation_id AND p.enabled
                JOIN plugin_auth_bindings b ON b.plugin_installation_id = p.id AND b.enabled
                WHERE i.user_id = $1
                  AND COALESCE((SELECT c.metadata->'auth_modes' ? 'network' FROM plugin_capabilities c
                        WHERE c.plugin_installation_id = b.plugin_installation_id AND c.capability_type = 'auth_provider.v1'
                          AND c.capability_id = b.capability_id), false)
                  AND (i.last_check_status = ANY($2) OR i.pending_refusal = ANY($2)))",
            &[&id, &refusals],
        )
        .await?;
    Ok(rows
        .first()
        .map(|r| r.try_get(0))
        .transpose()?
        .unwrap_or(false))
}

/// `lockUser`.
pub(crate) async fn lock_user(db: &mut Session, id: i64) -> Result<User, UserError> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1 FOR UPDATE");
    let rows = db
        .query(&sql, &[&id])
        .await
        .map_err(|e| UserError::Store(e.to_string()))?;
    let row = rows.first().ok_or(UserError::NotFound)?;
    scan_user(row).map_err(|e| UserError::Store(e.to_string()))
}

/// `createWithQuerier`.
pub(crate) async fn insert_session(
    db: &mut Session,
    mut session: AuthSession,
    device: &ClientDevice,
) -> Result<(), AuthFailure> {
    device.apply(&mut session);
    if session.purpose.is_empty() {
        session.purpose = session::SESSION_PURPOSE_ACCOUNT.to_owned();
    }
    if session.identity_id.is_some() && session.provider_since.is_none() {
        session.provider_since = Some(SystemTime::now());
    }
    let user_id = is_int4(session.user_id)?;
    let impersonator = session.impersonator_user_id.map(is_int4).transpose()?;
    db.execute(
        "INSERT INTO auth_sessions
            (id, user_id, device_name, ip_address, expires_at, impersonator_user_id, impersonation_started_at, identity_id, provider_since, device_id, device_platform, purpose, bound_profile_id, absolute_expires_at)
            VALUES ($1, $2, $3, NULLIF($4::text, '')::inet, $5, $6, $7, $8, $9, NULLIF($10, ''), NULLIF($11, ''), $12, NULLIF($13, ''), $14)",
        &[
            &session.id,
            &user_id,
            &session.device_name,
            &session.ip_address,
            &session.expires_at,
            &impersonator,
            &session.impersonation_started_at,
            &session.identity_id,
            &session.provider_since,
            &session.device_id,
            &session.device_platform,
            &session.purpose,
            &session.bound_profile_id,
            &session.absolute_expires_at,
        ],
    )
    .await?;
    Ok(())
}

pub(crate) fn blank_session(
    user_id: i64,
    device_name: &str,
    ip: &str,
    expires_at: SystemTime,
) -> AuthSession {
    AuthSession {
        id: uuid::Uuid::new_v4().to_string(),
        user_id,
        device_name: device_name.to_owned(),
        device_id: String::new(),
        device_platform: String::new(),
        ip_address: ip.to_owned(),
        created_at: SystemTime::now(),
        expires_at,
        revoked_at: None,
        impersonator_user_id: None,
        impersonation_started_at: None,
        identity_id: None,
        provider_since: None,
        last_seen_at: None,
        purpose: String::new(),
        bound_profile_id: String::new(),
        absolute_expires_at: None,
    }
}

fn from_ns(ns: i64) -> Duration {
    Duration::from_nanos(ns.max(0) as u64)
}

/// `Service`.
#[derive(Clone)]
pub struct AuthService {
    pool: Arc<Pool>,
    jwt: Arc<JwtService>,
    sessions: SessionRepository,
    users: UserRepository,
    sign_in_attempts: Option<Arc<dyn AttemptLimiter>>,
}

impl AuthService {
    pub fn new(
        pool: Arc<Pool>,
        jwt: Arc<JwtService>,
        sessions: SessionRepository,
        users: UserRepository,
        sign_in_attempts: Option<Arc<dyn AttemptLimiter>>,
    ) -> Self {
        // Hash the placeholder now so the first sign-in that needs it does not also pay for creating it.
        tokio::task::spawn_blocking(passwordhash::placeholder_hash);
        Self {
            pool,
            jwt,
            sessions,
            users,
            sign_in_attempts,
        }
    }

    pub fn jwt(&self) -> &JwtService {
        &self.jwt
    }

    fn generate_token_pair(&self, claims: Claims) -> Result<TokenPair, AuthFailure> {
        let access_token = self.jwt.access_token_for(claims.clone())?;
        let refresh_token = self.jwt.refresh_token_for(claims.clone())?;
        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.jwt.access_expires_in(&claims),
            session_id: claims.session_id,
        })
    }

    fn refresh_expiry(&self) -> Duration {
        from_ns(self.jwt.refresh_expiry_ns())
    }

    async fn reserve_sign_in(&self, name: &str) -> Result<(), AuthFailure> {
        if let Some(limiter) = &self.sign_in_attempts
            && let Err(left) = limiter
                .reserve(&silo_core::apikey::sign_in_attempt_key(name))
                .await
        {
            return Err(AuthFailure::Throttled(retry_after_seconds(left)));
        }
        Ok(())
    }

    /// `finishSignIn`: only a matched password clears the count.
    async fn finish_sign_in(&self, name: &str, failed: bool) {
        if !failed && let Some(limiter) = &self.sign_in_attempts {
            limiter
                .reset(&silo_core::apikey::sign_in_attempt_key(name))
                .await;
        }
    }

    /// `checkLocalPassword`: every rejection costs one comparison, so timing names no account.
    async fn check_local_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<User, AuthFailure> {
        let found = match self.users.lookup_login(username).await {
            Ok(user) => Some(user),
            Err(UserError::NotFound) => None,
            Err(e) => return Err(AuthFailure::Other(format!("looking up user: {e}"))),
        };
        let Some(user) = found.filter(|u| u.local_password_login_enabled) else {
            passwordhash::compare(
                passwordhash::placeholder_hash().as_bytes().to_vec(),
                password.as_bytes().to_vec(),
            )
            .await?;
            return Err(AuthFailure::InvalidCredentials);
        };
        let matches = passwordhash::compare(
            user.password_hash.clone().into_bytes(),
            password.as_bytes().to_vec(),
        )
        .await?;
        if !matches {
            return Err(AuthFailure::InvalidCredentials);
        }
        Ok(user)
    }

    /// `LocalProvider.Authenticate`.
    async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthFailure> {
        let user = self.check_local_password(username, password).await?;
        if !user.enabled {
            return Err(AuthFailure::UserDisabled);
        }
        if !user.break_glass {
            let mut conn = self.pool.acquire().await?;
            if !local_password_login_allowed(&mut conn).await? {
                return Err(AuthFailure::LocalLoginDisabled);
            }
            if network_refused(&mut conn, user.id).await? {
                return Err(AuthFailure::NotPermitted);
            }
        }
        Ok(user)
    }

    /// `loginWithProvider` for the local provider.
    async fn login_local(
        &self,
        username: &str,
        password: &str,
        ctx: &SignInContext,
    ) -> Result<(TokenPair, User), AuthFailure> {
        let authenticated = self.authenticate(username, password).await?;
        let expires = SystemTime::now() + self.refresh_expiry();
        let session = blank_session(authenticated.id, &ctx.device_name, &ctx.ip, expires);
        let session_id = session.id.clone();

        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        // Linking and account changes hold this row lock while retiring local credentials, so an
        // in-flight login cannot outlive their revocation.
        let current = match lock_user(&mut tx, authenticated.id).await {
            Ok(user) => user,
            Err(UserError::NotFound) => return Err(AuthFailure::InvalidCredentials),
            Err(e) => return Err(AuthFailure::Other(e.to_string())),
        };
        if !current.local_password_login_enabled
            || current.password_hash != authenticated.password_hash
        {
            return Err(AuthFailure::InvalidCredentials);
        }
        if !current.enabled {
            return Err(AuthFailure::UserDisabled);
        }
        if !current.break_glass {
            lock_server_settings(&mut tx).await?;
            if !local_password_login_allowed(&mut tx).await? {
                return Err(AuthFailure::LocalLoginDisabled);
            }
            if network_refused(&mut tx, current.id).await? {
                return Err(AuthFailure::NotPermitted);
            }
        }
        insert_session(&mut tx, session, &ctx.device).await?;
        tx.commit().await?;
        let pair = self.generate_token_pair(Claims {
            user_id: current.id,
            role: current.role.clone(),
            session_id,
            password_change_required: current.password_change_required,
            ..Default::default()
        })?;
        Ok((pair, current))
    }

    /// `LoginWithProvider`. A provider other than the local one is not reachable here: with one
    /// configured, these rows are on Go, and naming an unknown one is invalid credentials as in Go.
    pub async fn login_with_provider(
        &self,
        provider: &str,
        username: &str,
        password: &str,
        ctx: &SignInContext,
    ) -> Result<(TokenPair, User), AuthFailure> {
        self.reserve_sign_in(username).await?;
        let outcome = if provider.is_empty() || provider == LOCAL_PROVIDER_ID {
            self.login_local(username, password, ctx).await
        } else {
            Err(AuthFailure::InvalidCredentials)
        };
        self.finish_sign_in(username, outcome.is_err()).await;
        outcome
    }

    /// `NeedsSetup`.
    pub async fn needs_setup(&self) -> Result<bool, AuthFailure> {
        Ok(self.users.count().await? == 0)
    }

    /// `LocalPasswordLoginAllowed`.
    pub async fn local_password_login_allowed(&self) -> Result<bool, AuthFailure> {
        let mut conn = self.pool.acquire().await?;
        local_password_login_allowed(&mut conn).await
    }

    /// `ListByUserPage`.
    pub async fn sessions_page(
        &self,
        user_id: i64,
        after: Option<(SystemTime, String)>,
        limit: i64,
    ) -> Result<Vec<AuthSession>, AuthFailure> {
        Ok(self
            .sessions
            .list_by_user_page(
                user_id,
                after.as_ref().map(|(at, id)| (*at, id.as_str())),
                limit,
            )
            .await?)
    }

    /// `SetupWizardCompleted` is the system rows' job. `IsSignupEnabled`.
    pub async fn is_signup_enabled(&self) -> Result<bool, AuthFailure> {
        let mut conn = self.pool.acquire().await?;
        let rows = conn
            .query(
                "SELECT value FROM server_settings WHERE key = 'signup.enabled'",
                &[],
            )
            .await?;
        let enabled = rows
            .first()
            .map(|r| r.try_get::<_, String>(0))
            .transpose()?
            .unwrap_or_default();
        if enabled != "true" {
            return Ok(false);
        }
        local_password_login_allowed(&mut conn).await
    }

    /// `SetupInitialUser`.
    pub async fn setup_initial_user(
        &self,
        input: &NewAccount<'_>,
        ctx: &SignInContext,
    ) -> Result<(TokenPair, User), AuthFailure> {
        validate_new_password(input.password)?;
        let hash = passwordhash::generate(input.password.as_bytes().to_vec()).await?;
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        tx.query(
            "SELECT pg_advisory_xact_lock($1)",
            &[&INITIAL_SETUP_ADVISORY_LOCK],
        )
        .await?;
        let rows = tx.query("SELECT COUNT(*) FROM users", &[]).await?;
        let count: i64 = rows
            .first()
            .map(|r| r.try_get(0))
            .transpose()?
            .unwrap_or_default();
        if count > 0 {
            return Err(AuthFailure::SetupAlreadyComplete);
        }
        let mut user = create_user(&mut tx, input, &hash, "admin").await?;
        tx.execute(
            "UPDATE users SET is_owner = true, break_glass = true WHERE id = $1",
            &[&user.id],
        )
        .await?;
        user.is_owner = true;
        user.break_glass = true;
        create_default_profile(&mut tx, user.id, input).await?;
        let expires = SystemTime::now() + self.refresh_expiry();
        let session = blank_session(user.id, &ctx.device_name, &ctx.ip, expires);
        let session_id = session.id.clone();
        insert_session(&mut tx, session, &ctx.device).await?;
        let pair = self.generate_token_pair(Claims {
            user_id: user.id,
            role: user.role.clone(),
            session_id,
            ..Default::default()
        })?;
        tx.commit().await?;
        Ok((pair, user))
    }

    /// `Signup`.
    pub async fn signup(
        &self,
        input: &NewAccount<'_>,
        code: &str,
        ctx: &SignInContext,
    ) -> Result<(TokenPair, User), AuthFailure> {
        validate_new_password(input.password)?;
        {
            let mut conn = self.pool.acquire().await?;
            let rows = conn
                .query(
                    "SELECT value FROM server_settings WHERE key = 'signup.enabled'",
                    &[],
                )
                .await
                .map_err(|e| AuthFailure::Other(format!("checking signup setting: {e}")))?;
            let enabled = rows
                .first()
                .map(|r| r.try_get::<_, String>(0))
                .transpose()?
                .unwrap_or_default();
            if enabled != "true" {
                return Err(AuthFailure::SignupDisabled);
            }
            if !local_password_login_allowed(&mut conn).await? {
                return Err(AuthFailure::LocalLoginDisabled);
            }
        }
        let hash = passwordhash::generate(input.password.as_bytes().to_vec()).await?;
        {
            let mut conn = self.pool.acquire().await?;
            let mut tx = conn.begin().await?;
            lock_server_settings(&mut tx).await?;
            if !local_password_login_allowed(&mut tx).await? {
                return Err(AuthFailure::LocalLoginDisabled);
            }
            redeem_code(&mut tx, code).await?;
            let user = create_user(&mut tx, input, &hash, "user").await?;
            create_default_profile(&mut tx, user.id, input).await?;
            tx.commit().await?;
        }
        // `Login`: this path spends no attempt of the name's budget.
        self.login_local(input.username, input.password, ctx)
            .await
            .map_err(|e| AuthFailure::SignupSessionStart(Box::new(e)))
    }

    /// `Logout`.
    pub async fn logout(&self, session_id: &str) -> Result<(), AuthFailure> {
        Ok(self.sessions.revoke(session_id).await?)
    }

    /// `revokeChecked`.
    async fn revoke_checked(
        &self,
        id: &str,
        check: impl FnOnce(&AuthSession) -> Result<(), AuthFailure>,
        audit: &AuditRequest,
        action: &str,
        field: &str,
    ) -> Result<(), AuthFailure> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        audit.lock_actors(&mut tx).await?;
        let sql = format!(
            "SELECT {} FROM auth_sessions WHERE id = $1 FOR UPDATE",
            session::SESSION_COLUMNS
        );
        let rows = tx.query(&sql, &[&id]).await?;
        let row = rows.first().ok_or(AuthFailure::SessionNotFound)?;
        let current = session::scan_session("getting session", row)?;
        check(&current)?;
        let rows = tx
            .query(
                "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1
                 RETURNING expires_at > NOW()",
                &[&id],
            )
            .await?;
        let unexpired: bool = rows
            .first()
            .map(|r| r.try_get(0))
            .transpose()?
            .unwrap_or(false);
        let mut entry = None;
        if current.revoked_at.is_none() && unexpired {
            entry = audit
                .record(
                    &mut tx,
                    action,
                    audit::TARGET_USER,
                    &current.user_id.to_string(),
                    204,
                    audit::removed(field, &current.id),
                )
                .await?;
        }
        tx.commit().await?;
        audit::commit(entry);
        Ok(())
    }

    /// `EndImpersonation`.
    pub async fn end_impersonation(
        &self,
        session_id: &str,
        impersonator: i64,
        audit: &AuditRequest,
    ) -> Result<(), AuthFailure> {
        self.revoke_checked(
            session_id,
            |s| match s.impersonator_user_id {
                None => Err(AuthFailure::NotImpersonating),
                Some(id) if id != impersonator => Err(AuthFailure::ImpersonationNotAllowed),
                Some(_) => Ok(()),
            },
            audit,
            audit::ACTION_IMPERSONATION_ENDED,
            audit::FIELD_IMPERSONATION_SESSION,
        )
        .await
    }

    /// `RevokeSession`.
    pub async fn revoke_session(
        &self,
        session_id: &str,
        user_id: i64,
        audit: &AuditRequest,
    ) -> Result<(), AuthFailure> {
        self.revoke_checked(
            session_id,
            |s| {
                if s.user_id == user_id {
                    Ok(())
                } else {
                    Err(AuthFailure::SessionNotFound)
                }
            },
            audit,
            audit::ACTION_LOGIN_SESSION_REVOKED,
            audit::FIELD_LOGIN_SESSION,
        )
        .await
    }

    /// `validateImpersonator`.
    async fn validate_impersonator(&self, id: Option<i64>) -> Result<(), AuthFailure> {
        let Some(id) = id else {
            return Ok(());
        };
        match self.users.get_by_id(id).await {
            Ok(user) if user.enabled && user.role == "admin" => Ok(()),
            Ok(_) | Err(UserError::NotFound) => Err(AuthFailure::SessionRevoked),
            Err(e) => Err(AuthFailure::SessionCheckUnavailable(format!(
                "checking impersonator: {e}"
            ))),
        }
    }

    /// `Refresh`, with `checkSessionStanding` inline. A store failure ends nothing.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenPair, AuthFailure> {
        let claims = self
            .jwt
            .validate_token(refresh_token)
            .map_err(|_| AuthFailure::InvalidToken)?;
        if claims.token_type != token_type::REFRESH {
            return Err(AuthFailure::InvalidToken);
        }
        let session = match self.sessions.get_by_id(&claims.session_id).await {
            Ok(session) => session,
            Err(session::Error::NotFound) => return Err(AuthFailure::SessionRevoked),
            Err(e) => {
                return Err(AuthFailure::SessionCheckUnavailable(format!(
                    "getting session: {e}"
                )));
            }
        };
        let now = SystemTime::now();
        if session.revoked_at.is_some() || session.expires_at <= now {
            return Err(AuthFailure::SessionRevoked);
        }
        if session.is_remote_playback()
            && (session.bound_profile_id.is_empty() || session.absolute_expires_at.is_none())
        {
            return Err(AuthFailure::SessionRevoked);
        }
        let user = match self.users.get_by_id(session.user_id).await {
            Ok(user) => user,
            Err(UserError::NotFound) => return Err(AuthFailure::SessionRevoked),
            Err(e) => {
                return Err(AuthFailure::SessionCheckUnavailable(format!(
                    "getting user: {e}"
                )));
            }
        };
        if !user.enabled {
            return Err(AuthFailure::SessionRevoked);
        }
        self.validate_impersonator(session.impersonator_user_id)
            .await?;

        let mut expiry = now + self.refresh_expiry();
        // A session whose provider identity is gone can no longer be re-checked: it ends an absolute age
        // after the provider last vouched for it, and refresh no longer slides it.
        if session.identity_id.is_some() && session.impersonator_user_id.is_none() {
            // The provider re-check lives with the plugin host, on Go. Not judged, so the token stands.
            return Err(AuthFailure::SessionCheckUnavailable(
                "re-checking provider identity: no plugin host in this process".to_owned(),
            ));
        }
        if session.identity_id.is_none()
            && session.provider_since.is_some()
            && session.impersonator_user_id.is_none()
        {
            let anchor = match session.provider_since {
                Some(since) if since < session.created_at => since,
                _ => session.created_at,
            };
            let limit = anchor + self.refresh_expiry();
            if limit <= now {
                return Err(AuthFailure::SessionRevoked);
            }
            expiry = limit.min(session.expires_at);
        }
        if let Some(end) = session.absolute_expires_at
            && end < expiry
        {
            expiry = end;
        }
        // A failure to slide is not fatal unless the store failed; the session keeps its prior expiry.
        match self.sessions.extend_expires_at(&session.id, expiry).await {
            Ok(()) | Err(session::Error::NotFound) => {}
            Err(e) => {
                return Err(AuthFailure::SessionCheckUnavailable(format!(
                    "extending session: {e}"
                )));
            }
        }
        let mut refreshed = Claims {
            user_id: user.id,
            role: user.role.clone(),
            session_id: session.id.clone(),
            impersonator_user_id: session.impersonator_user_id,
            password_change_required: user.password_change_required
                && session.impersonator_user_id.is_none(),
            ..Default::default()
        };
        if session.is_remote_playback() {
            remote_playback_claims(&mut refreshed, &session);
        }
        self.generate_token_pair(refreshed)
    }

    /// `ChangePassword`. `true` when the account was signed out of its other sessions, so the caller runs
    /// the `OnSessionsRevoked` hook.
    pub async fn change_password(
        &self,
        user_id: i64,
        session_id: &str,
        current_password: &str,
        new_password: &str,
        sign_out_others: bool,
        audit: &AuditRequest,
    ) -> Result<bool, AuthFailure> {
        let user = self.users.get_by_id(user_id).await?;
        if !user.local_password_login_enabled || user.password_hash.is_empty() {
            return Err(AuthFailure::PasswordLoginDisabled);
        }
        let matches = passwordhash::compare(
            user.password_hash.clone().into_bytes(),
            current_password.as_bytes().to_vec(),
        )
        .await?;
        if !matches {
            return Err(AuthFailure::CurrentPasswordInvalid);
        }
        validate_new_password(new_password)?;
        if user.password_change_required && new_password == current_password {
            return Err(AuthFailure::PasswordUnchanged);
        }
        let hash = passwordhash::generate(new_password.as_bytes().to_vec()).await?;

        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        audit.lock_actors(&mut tx).await?;
        let changed = tx
            .execute(
                "UPDATE users SET password_hash = $1, password_change_required = false, updated_at = NOW()
                 WHERE id = $2 AND password_hash = $3",
                &[&hash, &user_id, &user.password_hash],
            )
            .await?;
        if changed != 1 {
            tx.rollback().await?;
            drop(conn);
            self.users.get_by_id(user_id).await?;
            return Err(AuthFailure::CurrentPasswordInvalid);
        }
        if sign_out_others {
            revoke_other_sign_ins(&mut tx, user_id, session_id).await?;
        } else if user.password_change_required {
            let id = is_int4(user_id)?;
            tx.execute(
                "UPDATE auth_sessions SET revoked_at = NOW()
                 WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
                &[&id, &session_id],
            )
            .await?;
        }
        let entry = audit
            .record(
                &mut tx,
                audit::ACTION_PASSWORD_CHANGED,
                audit::TARGET_USER,
                &user_id.to_string(),
                204,
                audit::secret_changed(audit::FIELD_PASSWORD),
            )
            .await?;
        tx.commit().await?;
        audit::commit(entry);
        Ok(sign_out_others)
    }

    /// `ListByUser`: every retained session, for v1.
    pub async fn sessions_of(&self, user_id: i64) -> Result<Vec<AuthSession>, AuthFailure> {
        Ok(self.sessions.list_by_user(user_id).await?)
    }

    /// `CurrentLoginSession`.
    pub async fn current_login_session(
        &self,
        user_id: i64,
        session_id: &str,
    ) -> Result<Option<AuthSession>, AuthFailure> {
        match self.sessions.get_by_id(session_id).await {
            Ok(s)
                if s.user_id == user_id
                    && s.revoked_at.is_none()
                    && s.expires_at > SystemTime::now() =>
            {
                Ok(Some(s))
            }
            Ok(_) | Err(session::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// `remotePlaybackClaims`.
pub(crate) fn remote_playback_claims(claims: &mut Claims, session: &AuthSession) {
    claims.role = "user".to_owned();
    claims.session_purpose = session::SESSION_PURPOSE_REMOTE_PLAYBACK.to_owned();
    claims.profile_id = session.bound_profile_id.clone();
    if let Some(end) = session.absolute_expires_at {
        claims.session_ends_at = end
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() as i64);
    }
}

/// `RevokeOtherSignInsInTransaction`.
async fn revoke_other_sign_ins(
    tx: &mut Session,
    user_id: i64,
    keep: &str,
) -> Result<(), AuthFailure> {
    let ids = vec![is_int4(user_id)?];
    tx.execute(
        "UPDATE auth_sessions SET revoked_at = NOW()
         WHERE (user_id = ANY($1::int[]) OR impersonator_user_id = ANY($1::int[])) AND revoked_at IS NULL
           AND id IS DISTINCT FROM $2::text",
        &[&ids, &keep],
    )
    .await?;
    tx.execute(
        "UPDATE abs_sessions SET revoked_at = NOW()
         WHERE user_id = ANY($1::int[]) AND revoked_at IS NULL",
        &[&ids],
    )
    .await?;
    delete_jellyfin_sessions(tx, &ids).await?;
    crate::device::withdraw_approvals(tx, &ids).await?;
    Ok(())
}

/// `deleteJellyfinSessionsInTransaction`.
async fn delete_jellyfin_sessions(tx: &mut Session, ids: &[i32]) -> Result<(), AuthFailure> {
    tx.execute(
        "DELETE FROM jellycompat_sessions WHERE streamapp_user_id = ANY($1::int[])",
        &[&ids],
    )
    .await?;
    Ok(())
}

/// What `CreateAccountInput` holds for a setup or signup.
pub struct NewAccount<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub password: &'a str,
    pub create_default_profile: bool,
    pub default_profile_name: &'a str,
}

/// `createUser`.
async fn create_user(
    tx: &mut Session,
    input: &NewAccount<'_>,
    hash: &str,
    role: &str,
) -> Result<User, AuthFailure> {
    let permissions = if role == "admin" {
        Vec::new()
    } else {
        default_user_permissions()
    };
    let permissions = normalize_permissions(&permissions).map_err(AuthFailure::Other)?;
    let email = silo_gocompat::strings::trim_space(input.email);
    let username = silo_gocompat::strings::trim_space(input.username);
    // Admins stay ungrouped: scope and action decisions are role-blind.
    let group = if role == "admin" {
        "NULL"
    } else {
        "(SELECT id FROM access_groups WHERE is_default)"
    };
    let sql = format!(
        "INSERT INTO users (email, username, password_hash, local_password_login_enabled, password_change_required, role, permissions, access_group_id)
         VALUES ($1::text::citext, $2::text::citext, $3, true, false, $4, $5, {group}) RETURNING {USER_COLUMNS}"
    );
    let rows = tx
        .query(&sql, &[&email, &username, &hash, &role, &permissions])
        .await
        .map_err(|e| {
            if is_duplicate(&e) {
                AuthFailure::Duplicate
            } else {
                AuthFailure::Other(format!("creating user: {e}"))
            }
        })?;
    let row: &Row = rows
        .first()
        .ok_or_else(|| AuthFailure::Other("creating user: no row".to_owned()))?;
    Ok(scan_user(row)?)
}

/// `createProfileInTransactionOrBridge`, `defaultAccountProfile`, and the store's `createProfile`.
async fn create_default_profile(
    tx: &mut Session,
    user_id: i64,
    input: &NewAccount<'_>,
) -> Result<(), AuthFailure> {
    if !input.create_default_profile {
        return Ok(());
    }
    let mut name = silo_gocompat::strings::trim_space(input.default_profile_name);
    if name.is_empty() {
        name = silo_gocompat::strings::trim_space(input.username);
    }
    if name.is_empty() {
        return Err(AuthFailure::Other(
            "default profile name is required".to_owned(),
        ));
    }
    let id = is_int4(user_id)?;
    let rows = tx
        .query(
            "SELECT EXISTS(SELECT 1 FROM user_profiles WHERE user_id = $1)",
            &[&id],
        )
        .await?;
    let existing: bool = rows
        .first()
        .map(|r| r.try_get(0))
        .transpose()?
        .unwrap_or(false);
    let profile_id = uuid::Uuid::new_v4().to_string();
    let primary = !existing;
    let now = SystemTime::now();
    tx.execute(
        "INSERT INTO user_profiles (
            id, user_id, name, avatar, pin_hash, is_child, is_primary, max_content_rating, max_advisory_age,
            require_advisory_age, quality_preference, language, preferred_metadata_language, subtitle_language, subtitle_mode,
            auto_skip_intro, auto_skip_credits, auto_skip_recap, auto_play_next_preview, library_restrictions_enabled,
            show_forced_subtitles, max_playback_quality, created_at, updated_at
         ) VALUES ($1, $2, $3, '', '', false, $4, '', NULL, false, '', '', '', '', '', false, false, false, false, false, true, '', $5, $5)",
        &[&profile_id, &id, &name, &primary, &now],
    )
    .await
    .map_err(|e| AuthFailure::Other(format!("store profile: {e}")))?;
    Ok(())
}

/// `redeemCode`.
async fn redeem_code(tx: &mut Session, code: &str) -> Result<(), AuthFailure> {
    let updated = tx
        .execute(
            "UPDATE invite_codes SET use_count = use_count + 1, updated_at = NOW()
             WHERE code = $1 AND enabled = true AND use_count < max_uses",
            &[&code],
        )
        .await?;
    if updated != 0 {
        return Ok(());
    }
    let rows = tx
        .query(
            "SELECT enabled, use_count, max_uses FROM invite_codes WHERE code = $1",
            &[&code],
        )
        .await
        .map_err(|_| AuthFailure::InviteCodeNotFound)?;
    let Some(row) = rows.first() else {
        return Err(AuthFailure::InviteCodeNotFound);
    };
    let (enabled, used, max): (bool, i32, i32) =
        (row.try_get(0)?, row.try_get(1)?, row.try_get(2)?);
    if !enabled {
        return Err(AuthFailure::InviteCodeDisabled);
    }
    if used >= max {
        return Err(AuthFailure::InviteCodeExhausted);
    }
    Err(AuthFailure::InviteCodeNotFound)
}

/// `CheckOwnerTargetByID`'s outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerRefusal {
    /// `ErrOwnerProtected`.
    Owner,
    /// `ErrAdminProtected`.
    Admin,
}

impl OwnerRefusal {
    /// `ownerError`'s message.
    pub fn message(self) -> &'static str {
        match self {
            OwnerRefusal::Owner => "Only the server owner can change the owner account",
            OwnerRefusal::Admin => {
                "Only the server owner can grant the admin role or change another admin account"
            }
        }
    }
}

/// `CheckOwnerTarget`.
pub fn check_owner_target(
    actor_id: i64,
    actor_is_owner: bool,
    target_id: i64,
    target_role: &str,
    target_is_owner: bool,
) -> Result<(), OwnerRefusal> {
    if target_id == actor_id {
        return Ok(());
    }
    if target_is_owner {
        return Err(OwnerRefusal::Owner);
    }
    if target_role == "admin" && !actor_is_owner {
        return Err(OwnerRefusal::Admin);
    }
    Ok(())
}

/// `UserRepository.CheckOwnerTargetByID`. An unknown account passes, so the operation reports it.
pub async fn check_owner_target_by_id(
    pool: &Pool,
    actor_id: i64,
    user_id: i64,
) -> Result<Result<(), OwnerRefusal>, silo_pg::Error> {
    let rows = pool
        .query(
            "SELECT role, is_owner, COALESCE((SELECT is_owner FROM users WHERE id = $1), false)
             FROM users WHERE id = $2",
            &[&actor_id, &user_id],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(Ok(()));
    };
    let role: String = row.try_get(0).unwrap_or_default();
    let is_owner: bool = row.try_get(1).unwrap_or(false);
    let actor_owner: bool = row.try_get(2).unwrap_or(false);
    Ok(check_owner_target(
        actor_id,
        actor_owner,
        user_id,
        &role,
        is_owner,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_policy_counts_characters_and_bytes() {
        assert!(matches!(
            check_new_password("short"),
            Err(AuthFailure::PasswordTooShort)
        ));
        assert!(check_new_password("eightchr").is_ok());
        // Eight characters, more bytes.
        assert!(check_new_password("éééééééé").is_ok());
        assert!(matches!(
            check_new_password(&"a".repeat(73)),
            Err(AuthFailure::PasswordTooLong)
        ));
    }

    #[test]
    fn a_device_id_with_the_wrong_shape_is_dropped_not_truncated() {
        let d = ClientDevice::new(b"a,b", b"  TV  ", b"tvos");
        assert_eq!(d.id, "");
        assert_eq!(d.name, "TV");
        assert_eq!(ClientDevice::new(&[b'a'; 129], b"", b"").id, "");
        assert_eq!(ClientDevice::new(b"x:1", b"", b"").id, "x:1");
        assert_eq!(ClientDevice::new(b"", &[0xff], b"").name, "");
    }

    #[test]
    fn owner_rule() {
        assert!(check_owner_target(1, false, 1, "admin", true).is_ok());
        assert_eq!(
            check_owner_target(1, true, 2, "admin", true),
            Err(OwnerRefusal::Owner)
        );
        assert_eq!(
            check_owner_target(1, false, 2, "admin", false),
            Err(OwnerRefusal::Admin)
        );
        assert!(check_owner_target(1, true, 2, "admin", false).is_ok());
        assert!(check_owner_target(1, false, 2, "user", false).is_ok());
    }

    #[test]
    fn settings_read_as_strconv_parse_bool() {
        assert!(setting_bool(" true ", false));
        assert!(!setting_bool("0", true));
        assert!(setting_bool("nope", true));
    }
}
