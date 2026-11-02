//! `internal/auth/device_login.go`: the pairing state machine, except what only the Jellyfin listener
//! calls (`StartQuickConnect`, `QuickConnectState`, `CollectQuickConnect`).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use silo_core::apikey::{format_user_code, hash_device_login_secret, normalize_user_code};
use silo_gocompat::strings::trim_space;
use silo_pg::{Pool, Row, Session};

use crate::attempts::{AttemptLimiter, retry_after_seconds};
use crate::claims::{Claims, JwtService};
use crate::service::{
    AuthFailure, ClientDevice, MAX_CLIENT_DEVICE_PLATFORM_LEN, TokenPair, blank_session,
    clamp_device_value, insert_session, lock_user, remote_playback_claims,
};
use crate::session::{SESSION_PURPOSE_ACCOUNT, SESSION_PURPOSE_REMOTE_PLAYBACK};
use crate::user::{User, UserError, UserRepository};

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_APPROVED: &str = "approved";
pub const STATUS_DENIED: &str = "denied";
pub const STATUS_CONSUMED: &str = "consumed";
pub const STATUS_CANCELED: &str = "canceled";
pub const STATUS_EXPIRED: &str = "expired";
pub const PURPOSE_LOGIN: &str = "device_login";
pub const PURPOSE_REMOTE: &str = "remote_playback";
pub const PURPOSE_QUICK_CONNECT: &str = "jellyfin_quick_connect";

const TTL: Duration = Duration::from_secs(15 * 60);
const LEGACY_TTL: Duration = Duration::from_secs(10 * 60);
const POLL_INTERVAL_SECS: i64 = 3;
const REMOTE_PLAYBACK_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const USER_CODE_ATTEMPTS: u32 = 5;
const QUICK_CONNECT_CODE_LENGTH: usize = 6;
const MAX_DEVICE_NAME_LEN: usize = 120;
const MAX_DEVICE_PLATFORM_LEN: usize = 80;
const MAX_USER_AGENT_LEN: usize = 256;
const OPENED_HOLD_SECS: f64 = 300.0;
const MAX_LIFETIME_SECS: f64 = 1800.0;

/// `ErrDeviceLogin*`.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("device login request not found")]
    NotFound,
    #[error("device login request expired")]
    Expired,
    #[error("device login request denied")]
    Denied,
    #[error("device login request already consumed")]
    Consumed,
    #[error("device login request not approved")]
    Unapproved,
    #[error("invalid device login purpose")]
    BadPurpose,
    #[error("device login purpose mismatch")]
    Purpose,
    #[error("device login already approved by another identity")]
    Conflict,
    #[error("device login profile not found")]
    NoProfile,
    #[error("device login request canceled by the device")]
    Canceled,
    #[error("user account is disabled")]
    UserDisabled,
    #[error("session has been revoked")]
    SessionRevoked,
    /// `QuickConnectAttemptsError`, its retry-after in seconds.
    #[error("too many Quick Connect code attempts")]
    QuickConnectAttempts(i64),
    #[error("{0}")]
    Other(String),
}

impl From<silo_pg::Error> for DeviceError {
    fn from(e: silo_pg::Error) -> Self {
        DeviceError::Other(e.to_string())
    }
}

impl From<silo_pg::DriverError> for DeviceError {
    fn from(e: silo_pg::DriverError) -> Self {
        DeviceError::Other(e.to_string())
    }
}

impl From<UserError> for DeviceError {
    fn from(e: UserError) -> Self {
        DeviceError::Other(e.to_string())
    }
}

impl From<AuthFailure> for DeviceError {
    fn from(e: AuthFailure) -> Self {
        DeviceError::Other(e.to_string())
    }
}

/// `DeviceLoginStartInput`.
#[derive(Debug, Clone, Default)]
pub struct StartInput {
    pub device_name: String,
    pub device_platform: String,
    pub ip_address: String,
    pub user_agent: String,
    pub base_url: String,
    pub client_purpose: String,
    pub temporary: bool,
    pub legacy: bool,
}

/// `DeviceLoginStartResult`.
#[derive(Debug, Clone)]
pub struct StartResult {
    pub device_code: String,
    pub user_code: String,
    pub match_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_at: SystemTime,
    pub expires_in: i64,
    pub interval: i64,
    pub device_name: String,
    pub device_platform: String,
    pub client_purpose: String,
    pub temporary: bool,
}

/// `DeviceLoginLookupInput`.
#[derive(Debug, Clone, Default)]
pub struct LookupInput {
    pub browser_code: String,
    pub user_code: String,
    pub mark_opened: bool,
    pub account_id: i64,
}

/// `DeviceLoginInfo`.
#[derive(Debug, Clone)]
pub struct Info {
    pub status: String,
    pub user_code: String,
    pub match_code: String,
    pub device_name: String,
    pub device_platform: String,
    pub ip_address_hint: String,
    pub expires_at: SystemTime,
    pub requested_at: SystemTime,
    pub client_purpose: String,
    pub temporary: bool,
}

/// `DeviceLoginPollResult`.
#[derive(Debug, Clone)]
pub struct PollResult {
    pub status: String,
    pub poll_after: i64,
    pub opened: bool,
    pub expires_at: Option<SystemTime>,
    pub tokens: Option<(TokenPair, User)>,
    pub profile_id: String,
    pub profile_token: String,
    pub temporary: bool,
    pub session_expires_at: Option<SystemTime>,
}

impl PollResult {
    fn state(status: &str) -> Self {
        Self {
            status: status.to_owned(),
            poll_after: POLL_INTERVAL_SECS,
            opened: false,
            expires_at: None,
            tokens: None,
            profile_id: String::new(),
            profile_token: String::new(),
            temporary: false,
            session_expires_at: None,
        }
    }
}

const SELECT: &str = "SELECT id::text, match_code, device_name, device_platform,
    COALESCE(host(ip_address), ''), status, approved_by_user_id, approved_profile_id,
    client_purpose, temporary, expires_at, opened_at, created_at, approved_identity_id, approved_provider_since
    FROM device_login_requests ";

#[derive(Debug, Clone)]
struct Record {
    id: String,
    match_code: String,
    device_name: String,
    device_platform: String,
    ip_address: String,
    status: String,
    approved_by: Option<i32>,
    approved_profile: Option<String>,
    purpose: String,
    temporary: bool,
    expires_at: SystemTime,
    opened_at: Option<SystemTime>,
    created_at: SystemTime,
    approved_identity: Option<i64>,
    approved_provider_since: Option<SystemTime>,
}

fn scan(row: &Row) -> Result<Record, silo_pg::DriverError> {
    Ok(Record {
        id: row.try_get(0)?,
        match_code: row.try_get(1)?,
        device_name: row.try_get(2)?,
        device_platform: row.try_get(3)?,
        ip_address: row.try_get(4)?,
        status: row.try_get(5)?,
        approved_by: row.try_get(6)?,
        approved_profile: row.try_get(7)?,
        purpose: row.try_get(8)?,
        temporary: row.try_get(9)?,
        expires_at: row.try_get(10)?,
        opened_at: row.try_get(11)?,
        created_at: row.try_get(12)?,
        approved_identity: row.try_get(13)?,
        approved_provider_since: row.try_get(14)?,
    })
}

impl Record {
    fn expired(&self) -> bool {
        self.expires_at <= SystemTime::now()
    }
}

/// `withdrawDeviceSignInApprovalsInTransaction`.
pub(crate) async fn withdraw_approvals(
    tx: &mut Session,
    user_ids: &[i32],
) -> Result<u64, silo_pg::Error> {
    tx.execute(
        "UPDATE device_login_requests SET status = $2, updated_at = NOW()
         WHERE approved_by_user_id = ANY($1::int[]) AND status = $3",
        &[&user_ids, &STATUS_DENIED, &STATUS_APPROVED],
    )
    .await
}

fn random_token(size: usize) -> Result<String, DeviceError> {
    let mut buf = vec![0u8; size];
    getrandom::fill(&mut buf).map_err(|e| DeviceError::Other(e.to_string()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

fn fallback_device_name(device_name: &str, user_agent: &str) -> String {
    let value = trim_device_field(device_name, MAX_DEVICE_NAME_LEN);
    if !value.is_empty() {
        return value;
    }
    let value = trim_device_field(user_agent, MAX_DEVICE_NAME_LEN);
    if !value.is_empty() {
        return value;
    }
    "This device".to_owned()
}

/// `trimDeviceField`: cuts at a byte, as Go does. Text this cuts mid-character is what Postgres would
/// refuse; the same request fails on Go.
fn trim_device_field(value: &str, limit: usize) -> String {
    let joined = silo_gocompat::strings::fields(value).join(" ");
    if joined.len() <= limit {
        return joined;
    }
    let mut end = limit;
    while !joined.is_char_boundary(end) {
        end -= 1;
    }
    joined[..end].to_owned()
}

/// `maskDeviceIPAddress`.
fn mask_ip(ip: &str) -> String {
    let ip = trim_space(ip);
    if ip.is_empty() {
        return String::new();
    }
    if ip.matches('.').count() == 3 {
        let parts: Vec<&str> = ip.split('.').collect();
        return format!("{}.{}.*.*", parts[0], parts[1]);
    }
    if ip.contains(':') {
        let parts: Vec<&str> = ip.split(':').collect();
        if parts.len() >= 2 {
            return format!("{}:{}:*", parts[0], parts[1]);
        }
    }
    String::new()
}

/// `normalizeDeviceLoginPurpose`.
fn normalize_purpose(value: &str, temporary: bool) -> Result<(String, bool), DeviceError> {
    let purpose = trim_space(value);
    let purpose = if purpose.is_empty() {
        PURPOSE_LOGIN
    } else {
        purpose
    };
    match (purpose, temporary) {
        (PURPOSE_LOGIN, false) => Ok((purpose.to_owned(), false)),
        (PURPOSE_REMOTE, true) => Ok((purpose.to_owned(), true)),
        _ => Err(DeviceError::BadPurpose),
    }
}

/// `IsQuickConnectCode`.
pub fn is_quick_connect_code(code: &str) -> bool {
    normalize_user_code(code).len() == QUICK_CONNECT_CODE_LENGTH
}

fn validate_decision(record: &Record) -> Result<(), DeviceError> {
    if record.expired() {
        return Err(DeviceError::Expired);
    }
    match record.status.as_str() {
        STATUS_CONSUMED => Err(DeviceError::Consumed),
        STATUS_DENIED => Err(DeviceError::Denied),
        STATUS_CANCELED => Err(DeviceError::Canceled),
        STATUS_PENDING | STATUS_APPROVED => Ok(()),
        _ => Err(DeviceError::Conflict),
    }
}

fn same_approved_identity(record: &Record, user_id: i64, profile_id: &str) -> bool {
    if record.approved_by.map(i64::from) != Some(user_id) {
        return false;
    }
    let approved = record.approved_profile.as_deref().map(trim_space);
    if profile_id.is_empty() {
        return approved.is_none_or(str::is_empty);
    }
    approved == Some(profile_id)
}

/// What the device poll needs from outside this crate.
pub trait ProfileTokenMinter: Send + Sync {
    /// `ProfileTokenService.Mint`.
    fn mint(
        &self,
        user_id: i64,
        session_id: &str,
        profile_id: &str,
        pin_revision: i64,
        policy_revision: i64,
    ) -> Result<String, String>;
}

/// `DeviceLoginService`.
#[derive(Clone)]
pub struct DeviceLoginService {
    pool: Arc<Pool>,
    users: UserRepository,
    jwt: Arc<JwtService>,
    profiles: Arc<dyn ProfileTokenMinter>,
    quick_connect_attempts: Option<Arc<dyn AttemptLimiter>>,
}

impl DeviceLoginService {
    pub fn new(
        pool: Arc<Pool>,
        users: UserRepository,
        jwt: Arc<JwtService>,
        profiles: Arc<dyn ProfileTokenMinter>,
        quick_connect_attempts: Option<Arc<dyn AttemptLimiter>>,
    ) -> Self {
        Self {
            pool,
            users,
            jwt,
            profiles,
            quick_connect_attempts,
        }
    }

    /// `Start`.
    pub async fn start(&self, input: StartInput) -> Result<StartResult, DeviceError> {
        let (purpose, temporary) = normalize_purpose(&input.client_purpose, input.temporary)?;
        let ttl = if input.legacy { LEGACY_TTL } else { TTL };
        let device_name = fallback_device_name(&input.device_name, &input.user_agent);
        let device_platform = trim_device_field(&input.device_platform, MAX_DEVICE_PLATFORM_LEN);
        let ip = trim_device_field(&input.ip_address, 64);
        let user_agent = trim_device_field(&input.user_agent, MAX_USER_AGENT_LEN);
        let mut attempt = 1;
        loop {
            let device_code = random_token(32)?;
            let browser_code = random_token(32)?;
            let user_code = silo_core::apikey::mint_user_code()
                .ok_or_else(|| DeviceError::Other("generate user code".to_owned()))?;
            let match_code = crate::device_login::random_match_code()
                .map_err(|e| DeviceError::Other(e.to_string()))?;
            let now = SystemTime::now();
            let expires_at = now + ttl;
            let id = uuid::Uuid::new_v4().to_string();
            let inserted = self
                .pool
                .execute(
                    "INSERT INTO device_login_requests (
                        id, device_code_hash, browser_code_hash, user_code_hash, match_code,
                        device_name, device_platform, ip_address, requested_user_agent,
                        status, client_purpose, temporary, expires_at, created_at, updated_at
                     ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, NULLIF($8::text, '')::inet, $9, $10, $11, $12, $13, $14, $15)",
                    &[
                        &id,
                        &hash_device_login_secret(device_code.as_bytes()),
                        &hash_device_login_secret(browser_code.as_bytes()),
                        &hash_device_login_secret(normalize_user_code(&user_code).as_bytes()),
                        &match_code,
                        &device_name,
                        &device_platform,
                        &ip,
                        &user_agent,
                        &STATUS_PENDING,
                        &purpose,
                        &temporary,
                        &expires_at,
                        &now,
                        &now,
                    ],
                )
                .await;
            match inserted {
                Ok(_) => {
                    let base = format!(
                        "{}/activate",
                        trim_space(&input.base_url).trim_end_matches('/')
                    );
                    let complete = if input.legacy {
                        format!("{base}?token={browser_code}")
                    } else {
                        format!("{base}?code={}", normalize_user_code(&user_code))
                    };
                    return Ok(StartResult {
                        device_code,
                        user_code,
                        match_code,
                        verification_uri: base,
                        verification_uri_complete: complete,
                        expires_at,
                        expires_in: ttl.as_secs() as i64,
                        interval: POLL_INTERVAL_SECS,
                        device_name,
                        device_platform,
                        client_purpose: purpose,
                        temporary,
                    });
                }
                Err(e)
                    if e.code().is_some_and(|c| c.code() == "23505")
                        && attempt < USER_CODE_ATTEMPTS =>
                {
                    attempt += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn by_column(&self, column: &str, hash: &str) -> Result<Record, DeviceError> {
        let sql = format!("{SELECT} WHERE {column} = $1");
        let rows = self.pool.query(&sql, &[&hash]).await?;
        let row = rows.first().ok_or(DeviceError::NotFound)?;
        Ok(scan(row)?)
    }

    async fn by_id(&self, db: &mut Session, id: &str) -> Result<Record, DeviceError> {
        let sql = format!("{SELECT} WHERE id = $1::text::uuid");
        let rows = db.query(&sql, &[&id]).await?;
        let row = rows.first().ok_or(DeviceError::NotFound)?;
        Ok(scan(row)?)
    }

    /// `findByLookup`.
    async fn find(&self, input: &LookupInput) -> Result<(Record, String), DeviceError> {
        let token = trim_space(&input.browser_code);
        if !token.is_empty() {
            let record = self
                .by_column(
                    "browser_code_hash",
                    &hash_device_login_secret(token.as_bytes()),
                )
                .await?;
            return Ok((record, String::new()));
        }
        let code = normalize_user_code(&input.user_code);
        if code.is_empty() {
            return Err(DeviceError::NotFound);
        }
        if code.len() == QUICK_CONNECT_CODE_LENGTH {
            // Six digits are few enough to guess, so one is looked up only for a signed-in account.
            if input.account_id <= 0 {
                return Err(DeviceError::NotFound);
            }
            if let Some(limiter) = &self.quick_connect_attempts
                && let Err(left) = limiter
                    .reserve(&format!("quick_connect_code:{}", input.account_id))
                    .await
            {
                return Err(DeviceError::QuickConnectAttempts(retry_after_seconds(left)));
            }
        }
        let record = self
            .by_column("user_code_hash", &hash_device_login_secret(code.as_bytes()))
            .await?;
        let formatted = String::from_utf8_lossy(&format_user_code(&code)).into_owned();
        Ok((record, formatted))
    }

    /// `Lookup`.
    pub async fn lookup(&self, input: &LookupInput) -> Result<Info, DeviceError> {
        let (mut record, user_code) = self.find(input).await?;
        let expired = record.expired();
        if !expired && input.mark_opened && record.status == STATUS_PENDING {
            self.mark_opened(&mut record).await?;
        }
        Ok(Info {
            status: if expired {
                STATUS_EXPIRED.to_owned()
            } else {
                record.status.clone()
            },
            user_code,
            match_code: record.match_code,
            device_name: record.device_name,
            device_platform: record.device_platform,
            ip_address_hint: mask_ip(&record.ip_address),
            expires_at: record.expires_at,
            requested_at: record.created_at,
            client_purpose: record.purpose,
            temporary: record.temporary,
        })
    }

    /// `markOpened`.
    async fn mark_opened(&self, record: &mut Record) -> Result<(), DeviceError> {
        let rows = self
            .pool
            .query(
                "UPDATE device_login_requests
                 SET opened_at = COALESCE(opened_at, NOW()),
                     expires_at = GREATEST(expires_at, LEAST(NOW() + make_interval(secs => $2::float8), created_at + make_interval(secs => $3::float8))),
                     updated_at = NOW()
                 WHERE id = $1::text::uuid AND status = $4 AND expires_at > NOW()
                 RETURNING expires_at, opened_at",
                &[&record.id, &OPENED_HOLD_SECS, &MAX_LIFETIME_SECS, &STATUS_PENDING],
            )
            .await?;
        if let Some(row) = rows.first() {
            record.expires_at = row.try_get(0)?;
            record.opened_at = row.try_get(1)?;
        }
        Ok(())
    }

    /// `validateApprovingUser`.
    async fn validate_approving_user(&self, id: i64) -> Result<(), DeviceError> {
        let user = self
            .users
            .get_by_id(id)
            .await
            .map_err(|e| DeviceError::Other(format!("load approving user: {e}")))?;
        if !user.enabled {
            return Err(DeviceError::UserDisabled);
        }
        Ok(())
    }

    /// `approvingProviderChain`.
    async fn approving_chain(
        &self,
        tx: &mut Session,
        approver: i64,
        claims: Option<&Claims>,
    ) -> Result<(Option<i64>, Option<SystemTime>), DeviceError> {
        let user = lock_user(tx, approver).await?;
        if !user.enabled {
            return Err(DeviceError::UserDisabled);
        }
        let Some(claims) = claims else {
            return Ok((None, None));
        };
        if claims.user_id != approver || !claims.is_own_login_session() {
            return Err(DeviceError::SessionRevoked);
        }
        let id = i32::try_from(approver).map_err(|e| DeviceError::Other(e.to_string()))?;
        let rows = tx
            .query(
                "SELECT identity_id, provider_since FROM auth_sessions
                 WHERE id = $1 AND user_id = $2 AND impersonator_user_id IS NULL AND purpose = $3
                   AND revoked_at IS NULL AND expires_at > NOW() FOR UPDATE",
                &[&claims.session_id, &id, &SESSION_PURPOSE_ACCOUNT],
            )
            .await?;
        let row = rows.first().ok_or(DeviceError::SessionRevoked)?;
        Ok((row.try_get(0)?, row.try_get(1)?))
    }

    async fn reload_approval_state(
        &self,
        tx: &mut Session,
        id: &str,
        approver: i64,
        profile_id: &str,
    ) -> Result<(), DeviceError> {
        let record = self.by_id(tx, id).await?;
        if record.expired() {
            return Err(DeviceError::Expired);
        }
        match record.status.as_str() {
            STATUS_CONSUMED => Err(DeviceError::Consumed),
            STATUS_DENIED => Err(DeviceError::Denied),
            STATUS_CANCELED => Err(DeviceError::Canceled),
            STATUS_APPROVED if same_approved_identity(&record, approver, profile_id) => Ok(()),
            _ => Err(DeviceError::Conflict),
        }
    }

    /// `Approve`.
    pub async fn approve(
        &self,
        input: &LookupInput,
        approver: i64,
        claims: Option<&Claims>,
    ) -> Result<(), DeviceError> {
        let (record, _) = self.find(input).await?;
        if record.purpose != PURPOSE_LOGIN || record.temporary {
            return Err(DeviceError::Purpose);
        }
        validate_decision(&record)?;
        self.validate_approving_user(approver).await?;
        if record.status == STATUS_APPROVED {
            return if record.approved_by.map(i64::from) == Some(approver) {
                Ok(())
            } else {
                Err(DeviceError::Conflict)
            };
        }
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let (identity, since) = self.approving_chain(&mut tx, approver, claims).await?;
        let now = SystemTime::now();
        let by = approver as i32;
        let changed = tx
            .execute(
                "UPDATE device_login_requests
                 SET status = $2, approved_by_user_id = $3, approved_at = $4, approved_identity_id = $7,
                     approved_provider_since = $8, denied_at = NULL, updated_at = $4
                 WHERE id = $1::text::uuid AND status = $5 AND client_purpose = $6 AND temporary = FALSE AND expires_at > NOW()",
                &[&record.id, &STATUS_APPROVED, &by, &now, &STATUS_PENDING, &PURPOSE_LOGIN, &identity, &since],
            )
            .await?;
        if changed == 0 {
            self.reload_approval_state(&mut tx, &record.id, approver, "")
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// `ApproveForProfile`.
    pub async fn approve_for_profile(
        &self,
        input: &LookupInput,
        approver: i64,
        profile_id: &str,
        claims: Option<&Claims>,
    ) -> Result<(), DeviceError> {
        let profile_id = trim_space(profile_id);
        if profile_id.is_empty() {
            return Err(DeviceError::NoProfile);
        }
        let (record, _) = self.find(input).await?;
        let allowed = record.purpose == PURPOSE_REMOTE || record.purpose == PURPOSE_QUICK_CONNECT;
        if !allowed || record.temporary != (record.purpose == PURPOSE_REMOTE) {
            return Err(DeviceError::Purpose);
        }
        validate_decision(&record)?;
        self.validate_approving_user(approver).await?;
        self.load_owned_profile(approver, profile_id).await?;
        if record.status == STATUS_APPROVED {
            return if same_approved_identity(&record, approver, profile_id) {
                Ok(())
            } else {
                Err(DeviceError::Conflict)
            };
        }
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let (identity, since) = self.approving_chain(&mut tx, approver, claims).await?;
        let now = SystemTime::now();
        let by = approver as i32;
        let changed = tx
            .execute(
                "UPDATE device_login_requests
                 SET status = $2, approved_by_user_id = $3, approved_profile_id = $4, approved_at = $5,
                     approved_identity_id = $8, approved_provider_since = $9, denied_at = NULL, updated_at = $5
                 WHERE id = $1::text::uuid AND status = $6 AND client_purpose = $7 AND temporary = $10 AND expires_at > NOW()",
                &[&record.id, &STATUS_APPROVED, &by, &profile_id, &now, &STATUS_PENDING, &record.purpose, &identity, &since, &record.temporary],
            )
            .await?;
        if changed == 0 {
            self.reload_approval_state(&mut tx, &record.id, approver, profile_id)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// `loadOwnedProfile`.
    async fn load_owned_profile(
        &self,
        user_id: i64,
        profile_id: &str,
    ) -> Result<(String, i64), DeviceError> {
        let id = user_id as i32;
        let rows = self
            .pool
            .query(
                "SELECT name, pin_revision FROM user_profiles WHERE user_id = $1 AND id = $2",
                &[&id, &profile_id],
            )
            .await
            .map_err(|e| DeviceError::Other(format!("load approving profile: {e}")))?;
        let row = rows.first().ok_or(DeviceError::NoProfile)?;
        Ok((row.try_get(0)?, row.try_get(1)?))
    }

    /// `Cancel`.
    pub async fn cancel(&self, device_code: &str) -> Result<String, DeviceError> {
        let hash = hash_device_login_secret(trim_space(device_code).as_bytes());
        let rows = self
            .pool
            .query(
                "UPDATE device_login_requests SET status = $2, canceled_at = NOW(), updated_at = NOW()
                 WHERE device_code_hash = $1 AND status IN ($3, $4) AND expires_at > NOW()
                 RETURNING status",
                &[&hash, &STATUS_CANCELED, &STATUS_PENDING, &STATUS_APPROVED],
            )
            .await?;
        if let Some(row) = rows.first() {
            return Ok(row.try_get(0)?);
        }
        let record = self.by_column("device_code_hash", &hash).await?;
        if record.expired() {
            return Ok(STATUS_EXPIRED.to_owned());
        }
        Ok(record.status)
    }

    /// `Deny`.
    pub async fn deny(&self, input: &LookupInput, denier: i64) -> Result<(), DeviceError> {
        let (record, _) = self.find(input).await?;
        if record.expired() {
            return Err(DeviceError::Expired);
        }
        match record.status.as_str() {
            STATUS_CONSUMED => return Err(DeviceError::Consumed),
            STATUS_CANCELED => return Err(DeviceError::Canceled),
            STATUS_DENIED => return Ok(()),
            STATUS_APPROVED if record.approved_by.is_some_and(|by| i64::from(by) != denier) => {
                return Err(DeviceError::Conflict);
            }
            _ => {}
        }
        let now = SystemTime::now();
        let by = denier as i32;
        let changed = self
            .pool
            .execute(
                "UPDATE device_login_requests
                 SET status = $2, approved_by_user_id = NULL, approved_profile_id = NULL, approved_identity_id = NULL,
                     approved_provider_since = NULL, approved_at = NULL, denied_at = $3, updated_at = $3
                 WHERE id = $1::text::uuid
                   AND (status = $4 OR (status = $5 AND (approved_by_user_id IS NULL OR approved_by_user_id = $6)))
                   AND expires_at > NOW()",
                &[&record.id, &STATUS_DENIED, &now, &STATUS_PENDING, &STATUS_APPROVED, &by],
            )
            .await?;
        if changed > 0 {
            return Ok(());
        }
        let mut conn = self.pool.acquire().await?;
        let record = self.by_id(&mut conn, &record.id).await?;
        if record.expired() {
            return Err(DeviceError::Expired);
        }
        match record.status.as_str() {
            STATUS_CONSUMED => Err(DeviceError::Consumed),
            STATUS_DENIED => Ok(()),
            STATUS_CANCELED => Err(DeviceError::Canceled),
            _ => Err(DeviceError::Conflict),
        }
    }

    /// `deviceLoginPollState`: `None` for an approved, live request, which [`Self::poll`] collects.
    fn poll_state(record: &Record) -> Result<Option<PollResult>, DeviceError> {
        if record.expired() {
            return Ok(Some(PollResult::state(STATUS_EXPIRED)));
        }
        match record.status.as_str() {
            STATUS_APPROVED => Ok(None),
            STATUS_PENDING => {
                let mut result = PollResult::state(STATUS_PENDING);
                result.opened = record.opened_at.is_some();
                result.expires_at = Some(record.expires_at);
                Ok(Some(result))
            }
            STATUS_CANCELED | STATUS_DENIED | STATUS_CONSUMED => {
                Ok(Some(PollResult::state(&record.status)))
            }
            other => Err(DeviceError::Other(format!(
                "unexpected device login status {other:?}"
            ))),
        }
    }

    /// `Poll`: a Quick Connect request is collected only by its Jellyfin app, and reads as unknown here.
    pub async fn poll(
        &self,
        device_code: &str,
        device: &ClientDevice,
    ) -> Result<PollResult, DeviceError> {
        let hash = hash_device_login_secret(trim_space(device_code).as_bytes());
        let preview = self.by_column("device_code_hash", &hash).await?;
        if preview.purpose == PURPOSE_QUICK_CONNECT {
            return Err(DeviceError::NotFound);
        }
        if let Some(result) = Self::poll_state(&preview)? {
            return Ok(result);
        }
        let Some(approver) = preview.approved_by else {
            return Err(DeviceError::Unapproved);
        };

        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let user = lock_user(&mut tx, i64::from(approver))
            .await
            .map_err(|e| DeviceError::Other(format!("load approved user: {e}")))?;
        let sql = format!("{SELECT} WHERE device_code_hash = $1 FOR UPDATE");
        let rows = tx.query(&sql, &[&hash]).await?;
        let row = rows.first().ok_or(DeviceError::NotFound)?;
        let record = scan(row)?;
        if let Some(result) = Self::poll_state(&record)? {
            return Ok(result);
        }
        if record.approved_by.map(i64::from) != Some(user.id) {
            return Err(DeviceError::Unapproved);
        }
        if !user.enabled {
            return Err(DeviceError::UserDisabled);
        }

        let mut profile_id = String::new();
        let mut pin_revision = 0;
        if record.purpose == PURPOSE_REMOTE {
            let approved = record.approved_profile.as_deref().map_or("", trim_space);
            if !record.temporary || approved.is_empty() {
                return Err(DeviceError::NoProfile);
            }
            profile_id = approved.to_owned();
            pin_revision = self.load_owned_profile(user.id, &profile_id).await?.1;
        }

        let now = SystemTime::now();
        let mut session_expires = now + Duration::from_nanos(self.jwt.refresh_expiry_ns() as u64);
        if record.temporary {
            session_expires = session_expires.min(now + REMOTE_PLAYBACK_SESSION_TTL);
        }
        let mut session = blank_session(
            user.id,
            &record.device_name,
            &record.ip_address,
            session_expires,
        );
        session.device_platform = String::from_utf8_lossy(
            clamp_device_value(
                record.device_platform.as_bytes(),
                MAX_CLIENT_DEVICE_PLATFORM_LEN,
            )
            .as_bytes(),
        )
        .into_owned();
        session.identity_id = record.approved_identity;
        session.provider_since = record.approved_provider_since;
        let session_id = session.id.clone();
        let mut claims = Claims {
            user_id: user.id,
            role: user.role.clone(),
            session_id: session_id.clone(),
            password_change_required: user.password_change_required,
            ..Default::default()
        };
        if record.purpose == PURPOSE_REMOTE {
            session.purpose = SESSION_PURPOSE_REMOTE_PLAYBACK.to_owned();
            session.bound_profile_id = profile_id.clone();
            session.absolute_expires_at = Some(session_expires);
            remote_playback_claims(&mut claims, &session);
        }
        insert_session(&mut tx, session, device).await?;

        let access_token = self
            .jwt
            .access_token_for(claims.clone())
            .map_err(|e| DeviceError::Other(e.to_string()))?;
        let refresh_token = self
            .jwt
            .refresh_token_for(claims.clone())
            .map_err(|e| DeviceError::Other(e.to_string()))?;
        let pair = TokenPair {
            access_token,
            refresh_token,
            expires_in: self.jwt.access_expires_in(&claims),
            session_id: session_id.clone(),
        };
        let mut profile_token = String::new();
        if record.purpose == PURPOSE_REMOTE {
            profile_token = self
                .profiles
                .mint(
                    user.id,
                    &session_id,
                    &profile_id,
                    pin_revision,
                    user.access_policy_revision,
                )
                .map_err(|e| {
                    DeviceError::Other(format!("mint remote playback profile token: {e}"))
                })?;
        }
        tx.execute(
            "UPDATE device_login_requests
             SET status = $2, auth_session_id = $3, consumed_at = $4, updated_at = $4
             WHERE id = $1::text::uuid",
            &[&record.id, &STATUS_CONSUMED, &session_id, &now],
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| DeviceError::Other(format!("commit device login poll: {e}")))?;
        let temporary = record.temporary;
        Ok(PollResult {
            status: STATUS_APPROVED.to_owned(),
            poll_after: POLL_INTERVAL_SECS,
            opened: false,
            expires_at: None,
            tokens: Some((pair, user)),
            profile_id,
            profile_token,
            temporary,
            session_expires_at: Some(session_expires),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_rules() {
        assert_eq!(normalize_purpose("", false).unwrap().0, PURPOSE_LOGIN);
        assert!(normalize_purpose("", true).is_err());
        assert!(normalize_purpose(PURPOSE_REMOTE, true).is_ok());
        assert!(normalize_purpose(PURPOSE_REMOTE, false).is_err());
        assert!(normalize_purpose("nope", false).is_err());
    }

    #[test]
    fn masks_addresses() {
        assert_eq!(mask_ip("203.0.113.7"), "203.0.*.*");
        assert_eq!(mask_ip("2001:db8::1"), "2001:db8:*");
        assert_eq!(mask_ip(""), "");
    }

    #[test]
    fn device_names_fall_back_and_collapse_space() {
        assert_eq!(fallback_device_name("  a   b ", "ua"), "a b");
        assert_eq!(fallback_device_name("", "  ua "), "ua");
        assert_eq!(fallback_device_name("", ""), "This device");
    }
}
