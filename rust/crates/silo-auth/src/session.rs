//! `internal/auth/session.go`: CRUD over the `auth_sessions` table. Ported faithfully for every
//! read path and every single-row write; the admin-revocation path that also touches audit
//! records and other features' sessions is not ported (see [`SessionRepository::revoke_as_admin`]
//! stub note below).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use silo_pg::pg_types::{IsNull, Type};
use silo_pg::{Error as PgError, Params, Pool, Row, ToSql};

/// A parameter for an `inet` column, sent as Postgres's own `inet_send` binary wire format
/// (family byte, netmask-bits byte, `is_cidr` byte, address-length byte, then the address bytes) —
/// `tokio-postgres`/`postgres-types` have no built-in `ToSql` for a bare `std::net::IpAddr` into
/// `inet` without an extra `cidr` crate dependency, and this crate's `ip_address` is always a
/// plain, unmasked host address. If another crate in this workspace ever needs the same thing,
/// this is a good candidate to promote into `silo_pg::types` alongside `PgText`/`AnyInt` — it is
/// kept local here because this session's task is scoped to `silo-auth`/`silo-gate`.
#[derive(Debug)]
struct InetAddr(IpAddr);

impl ToSql for InetAddr {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> std::result::Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        use bytes::BufMut;
        let (family, octets): (u8, Vec<u8>) = match self.0 {
            IpAddr::V4(v4) => (2, v4.octets().to_vec()),
            IpAddr::V6(v6) => (3, v6.octets().to_vec()),
        };
        out.put_u8(family);
        out.put_u8((octets.len() * 8) as u8); // bits: full host address, no mask
        out.put_u8(0); // is_cidr
        out.put_u8(octets.len() as u8);
        out.put_slice(&octets);
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::INET)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> std::result::Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        if !Self::accepts(ty) {
            return Err(format!("InetAddr does not accept column type {ty}").into());
        }
        self.to_sql(ty, out)
    }
}

/// `models.SessionPurposeAccount`/`SessionPurposeRemotePlayback`.
pub const SESSION_PURPOSE_ACCOUNT: &str = "account";
pub const SESSION_PURPOSE_REMOTE_PLAYBACK: &str = "remote_playback";
/// `models.RoleUser`.
pub const ROLE_USER: &str = "user";

/// `models.AuthSession`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthSession {
    pub id: String,
    pub user_id: i64,
    /// `models.AuthSession.DeviceName`: a plain (non-nullable at the Go level) string, defaulting
    /// to `""`. The `device_name` column is nullable in the schema, but `Create` never writes
    /// NULL — Go's zero value for an unset field is `""`, and a non-pointer `string` field can
    /// never scan a NULL row even on a legacy or hand-edited row, so this type does not either.
    pub device_name: String,
    pub device_id: String,
    pub device_platform: String,
    pub ip_address: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub revoked_at: Option<SystemTime>,
    pub impersonator_user_id: Option<i64>,
    pub impersonation_started_at: Option<SystemTime>,
    pub identity_id: Option<i64>,
    pub provider_since: Option<SystemTime>,
    pub last_seen_at: Option<SystemTime>,
    pub purpose: String,
    pub bound_profile_id: String,
    pub absolute_expires_at: Option<SystemTime>,
}

impl AuthSession {
    /// `AuthSession.IsRemotePlayback`.
    pub fn is_remote_playback(&self) -> bool {
        self.purpose == SESSION_PURPOSE_REMOTE_PLAYBACK
    }
}

/// `auth.ErrSessionNotFound`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session not found")]
    NotFound,
    #[error("{op}: {source}")]
    Query {
        op: &'static str,
        #[source]
        source: PgError,
    },
    /// Go has no client-side check here: a malformed `ip_address` reaches Postgres's `inet` input
    /// parser and fails there (SQLSTATE 22P02) when `Create`'s `INSERT` runs. This port's
    /// `InetAddr` wire-format wrapper needs a parsed `std::net::IpAddr` to serialize at all, so an
    /// unparsable address is rejected client-side instead — same ultimate failure (the session is
    /// not created), different error shape. See the port report's `divergences`.
    #[error("creating session: not an IP address: {0:?}")]
    InvalidIpAddress(String),
}

/// `auth.IsSessionNotFound`.
pub fn is_session_not_found(err: &Error) -> bool {
    matches!(err, Error::NotFound)
}

type Result<T> = std::result::Result<T, Error>;

const SESSION_COLUMNS: &str = "id, user_id, device_name, COALESCE(device_id, '') AS device_id, \
    COALESCE(device_platform, '') AS device_platform, COALESCE(host(ip_address), '') AS ip_address, \
    created_at, expires_at, revoked_at, impersonator_user_id, impersonation_started_at, identity_id, \
    provider_since, last_seen_at, purpose, COALESCE(bound_profile_id, '') AS bound_profile_id, \
    absolute_expires_at";

fn scan_session(row: &Row) -> AuthSession {
    AuthSession {
        id: row.get(0),
        user_id: row.get::<_, i32>(1) as i64,
        device_name: row.get(2),
        device_id: row.get(3),
        device_platform: row.get(4),
        ip_address: row.get(5),
        created_at: row.get(6),
        expires_at: row.get(7),
        revoked_at: row.get(8),
        impersonator_user_id: row.get::<_, Option<i32>>(9).map(i64::from),
        impersonation_started_at: row.get(10),
        identity_id: row.get(11),
        provider_since: row.get(12),
        last_seen_at: row.get(13),
        purpose: row.get(14),
        bound_profile_id: row.get(15),
        absolute_expires_at: row.get(16),
    }
}

/// `auth.SessionAuthority`.
///
/// `auth.SessionAuthority.Narrow` is not ported: it mutates a [`crate::claims::Claims`] in place,
/// and composing the two crates isn't exercised by any test in this session. A caller does the
/// equivalent by hand: when `is_remote_playback()`, set the claims' role to [`ROLE_USER`], session
/// purpose to [`SESSION_PURPOSE_REMOTE_PLAYBACK`], and profile ID to `bound_profile_id`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SessionAuthority {
    pub role: String,
    pub purpose: String,
    pub bound_profile_id: String,
}

impl SessionAuthority {
    /// `SessionAuthority.IsRemotePlayback`.
    pub fn is_remote_playback(&self) -> bool {
        self.purpose == SESSION_PURPOSE_REMOTE_PLAYBACK
    }
}

/// `auth.SessionRepository`.
pub struct SessionRepository {
    pool: Arc<Pool>,
}

impl SessionRepository {
    /// `auth.NewSessionRepository`.
    pub fn new(pool: Arc<Pool>) -> Self {
        Self { pool }
    }

    async fn query_row_opt(
        &self,
        op: &'static str,
        sql: &str,
        params: Params<'_>,
    ) -> Result<Option<Row>> {
        let mut session = self
            .pool
            .acquire()
            .await
            .map_err(|source| Error::Query { op, source })?;
        let rows = session
            .query(sql, params)
            .await
            .map_err(|source| Error::Query { op, source })?;
        Ok(rows.into_iter().next())
    }

    /// `SessionRepository.Create`: `session.id` is generated (UUID v4) when empty, matching Go's
    /// `uuid.New()`. `session.purpose` defaults to [`SESSION_PURPOSE_ACCOUNT`] when empty.
    /// `applyClientDevice` (reading the device from a sign-in transport's context) is the caller's
    /// job here, since this crate has no HTTP request-context type.
    pub async fn create(&self, mut session: AuthSession) -> Result<()> {
        if session.id.is_empty() {
            session.id = uuid::Uuid::new_v4().to_string();
        }
        if session.purpose.is_empty() {
            session.purpose = SESSION_PURPOSE_ACCOUNT.to_owned();
        }
        if session.identity_id.is_some() && session.provider_since.is_none() {
            session.provider_since = Some(SystemTime::now());
        }

        let query = "INSERT INTO auth_sessions
            (id, user_id, device_name, ip_address, expires_at, impersonator_user_id, impersonation_started_at, identity_id, provider_since, device_id, device_platform, purpose, bound_profile_id, absolute_expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), NULLIF($11, ''), $12, NULLIF($13, ''), $14)";

        // `ip_address` is a Postgres `inet` column; an empty string fails the inet input parser
        // (SQLSTATE 22P02), so pass NULL when no client IP is known — e.g. ABS-compat logins that
        // validate credentials in-process without a real request to read from (matches Go's own
        // comment on this exact branch).
        let ip_arg: Option<InetAddr> = if session.ip_address.is_empty() {
            None
        } else {
            let parsed: IpAddr = session
                .ip_address
                .parse()
                .map_err(|_| Error::InvalidIpAddress(session.ip_address.clone()))?;
            Some(InetAddr(parsed))
        };
        let user_id = session.user_id as i32;
        let impersonator = session.impersonator_user_id.map(|v| v as i32);

        let mut conn = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "creating session",
            source,
        })?;
        conn.execute(
            query,
            &[
                &session.id,
                &user_id,
                &session.device_name,
                &ip_arg,
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
        .await
        .map_err(|source| Error::Query {
            op: "creating session",
            source,
        })?;
        Ok(())
    }

    /// `SessionRepository.GetByID`.
    pub async fn get_by_id(&self, id: &str) -> Result<AuthSession> {
        let sql = format!("SELECT {SESSION_COLUMNS} FROM auth_sessions WHERE id = $1");
        self.query_row_opt("getting session", &sql, &[&id])
            .await?
            .map(|row| scan_session(&row))
            .ok_or(Error::NotFound)
    }

    /// `SessionRepository.ListByUser`.
    pub async fn list_by_user(&self, user_id: i64) -> Result<Vec<AuthSession>> {
        let sql = format!(
            "SELECT {SESSION_COLUMNS} FROM auth_sessions WHERE user_id = $1 ORDER BY created_at DESC"
        );
        let mut session = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "listing sessions",
            source,
        })?;
        let user_id = user_id as i32;
        let rows = session
            .query(&sql, &[&user_id])
            .await
            .map_err(|source| Error::Query {
                op: "listing sessions",
                source,
            })?;
        Ok(rows.iter().map(scan_session).collect())
    }

    /// `auth.SessionKey`.
    pub fn session_key(created_at: SystemTime, id: impl Into<String>) -> (SystemTime, String) {
        (created_at, id.into())
    }

    /// `SessionRepository.ListByUserPage`.
    pub async fn list_by_user_page(
        &self,
        user_id: i64,
        after: Option<(SystemTime, &str)>,
        limit: i64,
    ) -> Result<Vec<AuthSession>> {
        let user_id_i32 = user_id as i32;
        let mut sql = format!(
            "SELECT {SESSION_COLUMNS} FROM auth_sessions WHERE user_id = $1 AND expires_at > NOW() AND revoked_at IS NULL"
        );
        let mut session = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "listing session page",
            source,
        })?;
        let rows = if let Some((created_at, id)) = after {
            sql.push_str(" AND (created_at, id) < ($2::timestamptz, $3) ORDER BY created_at DESC, id DESC LIMIT $4");
            session
                .query(&sql, &[&user_id_i32, &created_at, &id, &limit])
                .await
        } else {
            sql.push_str(" ORDER BY created_at DESC, id DESC LIMIT $2");
            session.query(&sql, &[&user_id_i32, &limit]).await
        }
        .map_err(|source| Error::Query {
            op: "listing session page",
            source,
        })?;
        Ok(rows.iter().map(scan_session).collect())
    }

    /// `SessionRepository.Revoke`.
    pub async fn revoke(&self, id: &str) -> Result<()> {
        let mut conn = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "revoking session",
            source,
        })?;
        let affected = conn
            .execute(
                "UPDATE auth_sessions SET revoked_at = NOW() WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(|source| Error::Query {
                op: "revoking session",
                source,
            })?;
        if affected == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// `SessionRepository.RevokeAllByUser`.
    pub async fn revoke_all_by_user(&self, user_id: i64) -> Result<()> {
        let user_id = user_id as i32;
        let mut conn = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "revoking sessions for user",
            source,
        })?;
        conn.execute(
            "UPDATE auth_sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
            &[&user_id],
        )
        .await
        .map_err(|source| Error::Query {
            op: "revoking sessions for user",
            source,
        })?;
        Ok(())
    }

    /// `SessionRepository.RevokeAllByImpersonator`.
    pub async fn revoke_all_by_impersonator(&self, user_id: i64) -> Result<()> {
        let user_id = user_id as i32;
        let mut conn = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "revoking impersonation sessions",
            source,
        })?;
        conn.execute(
            "UPDATE auth_sessions SET revoked_at = NOW() WHERE impersonator_user_id = $1 AND revoked_at IS NULL",
            &[&user_id],
        )
        .await
        .map_err(|source| Error::Query {
            op: "revoking impersonation sessions",
            source,
        })?;
        Ok(())
    }

    /// `SessionRepository.IsValid`.
    pub async fn is_valid(&self, id: &str) -> Result<bool> {
        let sql = "SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW())";
        let row = self
            .query_row_opt("checking session validity", sql, &[&id])
            .await?
            .expect("EXISTS always returns one row");
        Ok(row.get(0))
    }

    /// `SessionRepository.ActiveSession`.
    pub async fn active_session(&self, id: &str, user_id: i64) -> Result<Option<SessionAuthority>> {
        let sql = "SELECT u.role, s.purpose, COALESCE(s.bound_profile_id, '') FROM auth_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > NOW()";
        let user_id_i32 = user_id as i32;
        let Some(row) = self
            .query_row_opt("checking session validity", sql, &[&id, &user_id_i32])
            .await?
        else {
            return Ok(None);
        };
        let mut authority = SessionAuthority {
            role: row.get(0),
            purpose: row.get(1),
            bound_profile_id: row.get(2),
        };
        if authority.purpose == SESSION_PURPOSE_REMOTE_PLAYBACK {
            if authority.bound_profile_id.is_empty() {
                return Ok(None);
            }
            authority.role = ROLE_USER.to_owned();
        }
        Ok(Some(authority))
    }

    /// `SessionRepository.UpdateLastSeen`.
    pub async fn update_last_seen(&self, id: &str, observed_at: SystemTime) -> Result<()> {
        let mut conn = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "updating last seen",
            source,
        })?;
        conn.execute(
            "UPDATE auth_sessions SET last_seen_at = $2
             WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()
             AND (last_seen_at IS NULL OR last_seen_at <= $2::timestamptz - INTERVAL '1 minute')",
            &[&id, &observed_at],
        )
        .await
        .map_err(|source| Error::Query {
            op: "updating last seen",
            source,
        })?;
        Ok(())
    }

    /// `SessionRepository.ExtendExpiresAt`.
    pub async fn extend_expires_at(&self, id: &str, new_expires_at: SystemTime) -> Result<()> {
        let mut conn = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "extending session expiry",
            source,
        })?;
        let affected = conn
            .execute(
                "UPDATE auth_sessions SET expires_at = $2 WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()",
                &[&id, &new_expires_at],
            )
            .await
            .map_err(|source| Error::Query {
                op: "extending session expiry",
                source,
            })?;
        if affected == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// `SessionRepository.DeleteExpired`.
    pub async fn delete_expired(&self) -> Result<u64> {
        let mut conn = self.pool.acquire().await.map_err(|source| Error::Query {
            op: "deleting expired sessions",
            source,
        })?;
        conn.execute("DELETE FROM auth_sessions WHERE expires_at < NOW()", &[])
            .await
            .map_err(|source| Error::Query {
                op: "deleting expired sessions",
                source,
            })
    }

    // `SessionRepository.RevokeAsAdmin` is NOT ported: it locks `users` rows in the same order as
    // ownership transfers, calls `auditmutation` (not a crate yet), `CheckOwnerTarget`
    // (`internal/auth/owner.go`, not ported this session), and cross-feature revocation of
    // Audiobookshelf sessions, Jellyfin sessions, and uncollected device sign-in approvals (none
    // of those packages are ported yet either). Porting this one method faithfully needs all of
    // them wired together, which is its own bounded task; every other method on this type is a
    // complete, independent port of its Go counterpart.
}
