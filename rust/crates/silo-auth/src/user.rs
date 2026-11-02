//! `internal/auth/repository.go`'s `GetByID` and the `models.User` columns the request path reads.

use std::sync::Arc;

use silo_pg::{Pool, Row};

/// `models.User`.
#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub local_password_login_enabled: bool,
    pub password_change_required: bool,
    pub role: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub library_ids: Option<Vec<i32>>,
    pub max_playback_quality: Option<String>,
    pub access_policy_revision: i64,
    pub max_streams: Option<i32>,
    pub max_transcodes: Option<i32>,
    pub max_remote_stream_bitrate_kbps: Option<i32>,
    pub max_local_stream_bitrate_kbps: Option<i32>,
    pub transcode_allowed: Option<bool>,
    pub audio_transcode_allowed: Option<bool>,
    pub max_profiles: Option<i32>,
    pub download_allowed: Option<bool>,
    pub download_transcode_allowed: Option<bool>,
    pub requests_allowed: Option<bool>,
    pub access_group_id: Option<i64>,
    pub is_owner: bool,
    pub break_glass: bool,
}

/// The columns `allColumns` names that the request path reads, for a statement in this crate.
pub(crate) const USER_COLUMNS: &str = COLUMNS;

/// `scanUser`.
pub(crate) fn scan_user(row: &Row) -> Result<User, silo_pg::DriverError> {
    scan(row)
}

/// `email` is citext, which the driver reads only through a cast.
const COLUMNS: &str = "id, email::text, username, password_hash, local_password_login_enabled, password_change_required, role, permissions, enabled,
    library_ids, max_playback_quality, access_policy_revision,
    max_streams, max_transcodes, max_remote_stream_bitrate_kbps, max_local_stream_bitrate_kbps, transcode_allowed, audio_transcode_allowed, max_profiles, download_allowed,
    download_transcode_allowed, requests_allowed, access_group_id, is_owner, break_glass";

fn scan(row: &Row) -> Result<User, silo_pg::DriverError> {
    Ok(User {
        id: row.try_get(0)?,
        email: row.try_get::<_, Option<String>>(1)?.unwrap_or_default(),
        username: row.try_get(2)?,
        password_hash: row.try_get::<_, Option<String>>(3)?.unwrap_or_default(),
        local_password_login_enabled: row.try_get(4)?,
        password_change_required: row.try_get(5)?,
        role: row.try_get(6)?,
        permissions: row
            .try_get::<_, Option<Vec<String>>>(7)?
            .unwrap_or_default(),
        enabled: row.try_get(8)?,
        library_ids: row.try_get(9)?,
        max_playback_quality: row.try_get(10)?,
        access_policy_revision: row.try_get(11)?,
        max_streams: row.try_get(12)?,
        max_transcodes: row.try_get(13)?,
        max_remote_stream_bitrate_kbps: row.try_get(14)?,
        max_local_stream_bitrate_kbps: row.try_get(15)?,
        transcode_allowed: row.try_get(16)?,
        audio_transcode_allowed: row.try_get(17)?,
        max_profiles: row.try_get(18)?,
        download_allowed: row.try_get(19)?,
        download_transcode_allowed: row.try_get(20)?,
        requests_allowed: row.try_get(21)?,
        access_group_id: row.try_get(22)?,
        is_owner: row.try_get(23)?,
        break_glass: row.try_get(24)?,
    })
}

/// A failed user read: `NotFound` is `auth.IsNotFound`, anything else means it could not be checked.
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("user not found")]
    NotFound,
    #[error("querying user: {0}")]
    Store(String),
}

/// `auth.Repository`, the read half.
#[derive(Clone)]
pub struct UserRepository {
    pool: Arc<Pool>,
}

impl UserRepository {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self { pool }
    }

    /// `Repository.GetByUsername`.
    pub async fn get_by_username(&self, username: &str) -> Result<User, UserError> {
        let sql = format!("SELECT {COLUMNS} FROM users WHERE username = $1::text::citext");
        let name = silo_gocompat::strings::trim_space(username);
        let rows = self
            .pool
            .query(&sql, &[&name])
            .await
            .map_err(|e| UserError::Store(e.to_string()))?;
        let row = rows.first().ok_or(UserError::NotFound)?;
        scan(row).map_err(|e| UserError::Store(e.to_string()))
    }

    /// `Repository.GetByEmail`.
    pub async fn get_by_email(&self, email: &str) -> Result<User, UserError> {
        let sql = format!("SELECT {COLUMNS} FROM users WHERE email = $1::text::citext");
        let email = silo_gocompat::strings::trim_space(email);
        let rows = self
            .pool
            .query(&sql, &[&email])
            .await
            .map_err(|e| UserError::Store(e.to_string()))?;
        let row = rows.first().ok_or(UserError::NotFound)?;
        scan(row).map_err(|e| UserError::Store(e.to_string()))
    }

    /// `LookupLogin`: a username first, then, for what looks like an address, an email.
    pub async fn lookup_login(&self, identifier: &str) -> Result<User, UserError> {
        match self.get_by_username(identifier).await {
            Err(UserError::NotFound) if crate::provider::looks_like_email(identifier) => {
                self.get_by_email(identifier).await
            }
            other => other,
        }
    }

    /// `Repository.Count`.
    pub async fn count(&self) -> Result<i64, UserError> {
        let rows = self
            .pool
            .query("SELECT COUNT(*) FROM users", &[])
            .await
            .map_err(|e| UserError::Store(e.to_string()))?;
        rows.first()
            .ok_or(UserError::NotFound)?
            .try_get(0)
            .map_err(|e| UserError::Store(e.to_string()))
    }

    /// `Repository.GetByID`.
    pub async fn get_by_id(&self, id: i64) -> Result<User, UserError> {
        let sql = format!("SELECT {COLUMNS} FROM users WHERE id = $1");
        let rows = self
            .pool
            .query(&sql, &[&id])
            .await
            .map_err(|e| UserError::Store(e.to_string()))?;
        let row = rows.first().ok_or(UserError::NotFound)?;
        scan(row).map_err(|e| UserError::Store(e.to_string()))
    }
}

/// `auth.EffectivePermissions`.
pub fn effective_permissions(user: &User) -> Vec<String> {
    if !user.enabled {
        return Vec::new();
    }
    if user.role == "admin" {
        return vec!["marker_edit".to_owned(), "metadata_curation".to_owned()];
    }
    crate::permissions::normalize_permissions(&user.permissions).unwrap_or_default()
}
