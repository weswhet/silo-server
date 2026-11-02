//! `internal/auth/api_key_repository.go`, `api_key_metadata.go`, and the two activity trackers:
//! `api_key_last_used.go` and `session_last_seen.go`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use silo_pg::{Pool, Row, Session};

use crate::audit::{self, AuditRequest};
use crate::service::{OwnerRefusal, check_owner_target};
use crate::session::SessionRepository;

/// `models.APIKey`, without the secret.
#[derive(Debug, Clone, Default)]
pub struct ApiKey {
    pub id: i64,
    pub user_id: i64,
    pub label: String,
    pub rate_tier: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    /// `auth.ErrAPIKeyNotFound`.
    #[error("api key not found")]
    NotFound,
    #[error("scanning api key: {0}")]
    Store(String),
}

/// `auth.APIKeyRepository`.
#[derive(Clone)]
pub struct ApiKeyRepository {
    pool: Arc<Pool>,
}

impl ApiKeyRepository {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self { pool }
    }

    /// `GetByKey`. A key Postgres cannot take as text matches no key.
    pub async fn get_by_key(&self, key: &[u8]) -> Result<ApiKey, ApiKeyError> {
        if !silo_core::apikey::valid_text_key(key) {
            return Err(ApiKeyError::NotFound);
        }
        let hash = silo_core::apikey::hash_link_token(key);
        let rows = self
            .pool
            .query(
                "SELECT id, user_id, label, rate_tier, scopes FROM api_keys WHERE key_hash = $1",
                &[&hash],
            )
            .await
            .map_err(|e| ApiKeyError::Store(e.to_string()))?;
        let row = rows.first().ok_or(ApiKeyError::NotFound)?;
        let scan = || -> Result<ApiKey, silo_pg::DriverError> {
            Ok(ApiKey {
                id: row.try_get(0)?,
                user_id: i64::from(row.try_get::<_, i32>(1)?),
                label: row.try_get(2)?,
                rate_tier: row.try_get(3)?,
                scopes: row
                    .try_get::<_, Option<Vec<String>>>(4)?
                    .unwrap_or_default(),
            })
        };
        scan().map_err(|e| ApiKeyError::Store(e.to_string()))
    }

    /// `UpdateLastUsed`.
    pub async fn update_last_used(&self, id: i64) -> Result<(), ApiKeyError> {
        self.pool
            .execute(
                "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                &[&id],
            )
            .await
            .map(|_| ())
            .map_err(|e| ApiKeyError::Store(e.to_string()))
    }
}

/// `apiKeyMetadataColumns`: neither bearer nor verifier is part of a management projection.
const METADATA_COLUMNS: &str = "ak.id,ak.user_id::bigint,ak.label,ak.key_prefix,ak.rate_tier,COALESCE(ak.scopes,'{}'::text[]),ak.created_at,ak.revision";

/// `models.APIKeyMetadata`, with its list decorations.
#[derive(Debug, Clone)]
pub struct ApiKeyMetadata {
    pub id: i64,
    pub user_id: i64,
    pub label: String,
    pub key_prefix: String,
    pub rate_tier: String,
    pub scopes: Vec<String>,
    pub created_at: SystemTime,
    pub revision: i64,
    pub last_used_at: Option<SystemTime>,
    pub username: String,
}

fn scan_metadata(row: &Row) -> Result<ApiKeyMetadata, silo_pg::DriverError> {
    Ok(ApiKeyMetadata {
        id: row.try_get(0)?,
        user_id: row.try_get(1)?,
        label: row.try_get(2)?,
        key_prefix: row.try_get(3)?,
        rate_tier: row.try_get(4)?,
        scopes: row.try_get(5)?,
        created_at: row.try_get(6)?,
        revision: row.try_get(7)?,
        last_used_at: None,
        username: String::new(),
    })
}

fn scan_listed(row: &Row) -> Result<ApiKeyMetadata, silo_pg::DriverError> {
    let mut key = scan_metadata(row)?;
    key.last_used_at = row.try_get(8)?;
    key.username = row.try_get(9)?;
    Ok(key)
}

/// `models.APIKey` as `Create` answers it, the only value that carries the bearer.
#[derive(Debug, Clone)]
pub struct CreatedApiKey {
    pub id: i64,
    pub user_id: i64,
    pub label: String,
    pub key: String,
    pub rate_tier: String,
    pub scopes: Vec<String>,
    pub created_at: SystemTime,
    pub last_used_at: Option<SystemTime>,
}

/// `APIKeyPrecondition`: an explicit wildcard, or an exact revision.
#[derive(Debug, Clone, Copy)]
pub struct Precondition {
    pub revision: i64,
    pub any: bool,
}

impl Precondition {
    fn valid(self) -> bool {
        (self.any && self.revision == 0) || (!self.any && self.revision > 0)
    }
}

/// The API key store's failures.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// `ErrAPIKeyNotFound`.
    #[error("api key not found")]
    NotFound,
    /// `APIKeyRevisionConflict`.
    #[error("API key configuration changed")]
    Conflict(Box<ApiKeyMetadata>),
    /// `ErrInvalidAPIKeyTier`.
    #[error("invalid API key rate tier")]
    InvalidTier,
    /// `ErrAPIKeyPreconditionInvalid`.
    #[error("invalid API key revision precondition")]
    Precondition,
    /// `CheckOwnerTarget`'s refusal.
    #[error("{}", .0.message())]
    Owner(OwnerRefusal),
    #[error("{0}")]
    Store(String),
}

impl From<silo_pg::Error> for KeyError {
    fn from(e: silo_pg::Error) -> Self {
        KeyError::Store(e.to_string())
    }
}

impl From<silo_pg::DriverError> for KeyError {
    fn from(e: silo_pg::DriverError) -> Self {
        KeyError::Store(e.to_string())
    }
}

/// `apiKeyAuditValues`: the configuration, never the credential, its prefix or its usage.
fn audit_values(
    user_id: i64,
    label: &str,
    rate_tier: &str,
    scopes: &[String],
) -> BTreeMap<&'static str, String> {
    let json = |v: &dyn erased::Marshal| v.marshal();
    BTreeMap::from([
        ("user_id", json(&user_id)),
        ("label", json(&label.to_owned())),
        ("rate_tier", json(&rate_tier.to_owned())),
        ("scopes", json(&scopes.to_vec())),
    ])
}

mod erased {
    pub trait Marshal {
        fn marshal(&self) -> String;
    }
    impl<T: serde::Serialize> Marshal for T {
        fn marshal(&self) -> String {
            silo_gocompat::json::marshal_to_string(self).unwrap_or_default()
        }
    }
}

fn metadata_audit(key: &ApiKeyMetadata) -> BTreeMap<&'static str, String> {
    audit_values(key.user_id, &key.label, &key.rate_tier, &key.scopes)
}

const PAGE_MAX: i64 = 200;
const PAGE_DEFAULT: i64 = 50;

impl ApiKeyRepository {
    /// `insertAPIKey`, in `tx`, which it commits.
    async fn insert(
        tx: &mut Session,
        user_id: i64,
        label: &str,
        scopes: &[String],
        audit_request: &AuditRequest,
    ) -> Result<(CreatedApiKey, Option<audit::Committed>), KeyError> {
        let key = silo_core::apikey::mint_api_key()
            .ok_or_else(|| KeyError::Store("generating random bytes".to_owned()))?;
        let owner = i32::try_from(user_id).map_err(|e| KeyError::Store(e.to_string()))?;
        let hash = silo_core::apikey::hash_link_token(key.as_bytes());
        let prefix = key[..11].to_owned();
        let scopes = scopes.to_vec();
        let rows = tx
            .query(
                "INSERT INTO api_keys (user_id, label, key_hash, key_prefix, scopes)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING id, user_id::bigint, label, rate_tier, scopes, created_at, last_used_at",
                &[&owner, &label, &hash, &prefix, &scopes],
            )
            .await?;
        let row = rows
            .first()
            .ok_or_else(|| KeyError::Store("scanning api key".to_owned()))?;
        let created = CreatedApiKey {
            id: row.try_get(0)?,
            user_id: row.try_get(1)?,
            label: row.try_get(2)?,
            key,
            rate_tier: row.try_get(3)?,
            scopes: row
                .try_get::<_, Option<Vec<String>>>(4)?
                .unwrap_or_default(),
            created_at: row.try_get(5)?,
            last_used_at: row.try_get(6)?,
        };
        let after = audit_values(
            created.user_id,
            &created.label,
            &created.rate_tier,
            &created.scopes,
        );
        let entry = audit_request
            .record(
                tx,
                audit::ACTION_API_KEY_CREATED,
                audit::TARGET_API_KEY,
                &created.id.to_string(),
                201,
                audit::changes(None, Some(&after)),
            )
            .await?;
        Ok((created, entry))
    }

    /// `Create`.
    pub async fn create(
        &self,
        user_id: i64,
        label: &str,
        scopes: &[String],
        audit_request: &AuditRequest,
    ) -> Result<CreatedApiKey, KeyError> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let (created, entry) = Self::insert(&mut tx, user_id, label, scopes, audit_request).await?;
        tx.commit().await?;
        audit::commit(entry);
        Ok(created)
    }

    /// `CreateAsActor`: both accounts stay share-locked, in id order, until the key is inserted.
    pub async fn create_as_actor(
        &self,
        actor_id: i64,
        user_id: i64,
        label: &str,
        scopes: &[String],
        audit_request: &AuditRequest,
    ) -> Result<CreatedApiKey, KeyError> {
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let mut ids = vec![actor_id, user_id];
        ids.extend(audit_request.actor_ids());
        let rows = tx
            .query(
                "SELECT id, role, is_owner FROM users WHERE id = ANY($1) ORDER BY id FOR SHARE",
                &[&ids],
            )
            .await?;
        let mut actor_owner = false;
        let mut target = None;
        for row in &rows {
            let id: i64 = row.try_get(0)?;
            let role: String = row.try_get(1)?;
            let is_owner: bool = row.try_get(2)?;
            if id == actor_id {
                actor_owner = is_owner;
            }
            if id == user_id {
                target = Some((role, is_owner));
            }
        }
        if let Some((role, is_owner)) = target {
            check_owner_target(actor_id, actor_owner, user_id, &role, is_owner)
                .map_err(KeyError::Owner)?;
        }
        let (created, entry) = Self::insert(&mut tx, user_id, label, scopes, audit_request).await?;
        tx.commit().await?;
        audit::commit(entry);
        Ok(created)
    }

    /// `Delete`: ownership is checked in the deleting statement.
    pub async fn delete(
        &self,
        id: i64,
        user_id: i64,
        audit_request: &AuditRequest,
    ) -> Result<(), KeyError> {
        let owner = i32::try_from(user_id).map_err(|e| KeyError::Store(e.to_string()))?;
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        audit_request.lock_actors(&mut tx).await?;
        let sql = format!(
            "DELETE FROM api_keys ak WHERE ak.id = $1 AND ak.user_id = $2 RETURNING {METADATA_COLUMNS}"
        );
        let rows = tx.query(&sql, &[&id, &owner]).await?;
        let row = rows.first().ok_or(KeyError::NotFound)?;
        let deleted = scan_metadata(row)?;
        let before = metadata_audit(&deleted);
        let entry = audit_request
            .record(
                &mut tx,
                audit::ACTION_API_KEY_DELETED,
                audit::TARGET_API_KEY,
                &deleted.id.to_string(),
                204,
                audit::changes(Some(&before), None),
            )
            .await?;
        tx.commit().await?;
        audit::commit(entry);
        Ok(())
    }

    /// `DeleteByAdmin`.
    pub async fn delete_by_admin(&self, id: i64) -> Result<(), KeyError> {
        if self
            .pool
            .execute("DELETE FROM api_keys WHERE id = $1", &[&id])
            .await?
            == 0
        {
            return Err(KeyError::NotFound);
        }
        Ok(())
    }

    /// `UpdateTier`.
    pub async fn update_tier(&self, id: i64, tier: &str) -> Result<(), KeyError> {
        if self
            .pool
            .execute(
                "UPDATE api_keys SET rate_tier = $1 WHERE id = $2",
                &[&tier, &id],
            )
            .await?
            == 0
        {
            return Err(KeyError::NotFound);
        }
        Ok(())
    }

    /// `GetMetadataByID`.
    pub async fn metadata_by_id(&self, id: i64) -> Result<ApiKeyMetadata, KeyError> {
        let sql = format!("SELECT {METADATA_COLUMNS} FROM api_keys ak WHERE ak.id=$1");
        let rows = self.pool.query(&sql, &[&id]).await?;
        Ok(scan_metadata(rows.first().ok_or(KeyError::NotFound)?)?)
    }

    /// `ListByUser` and `ListByUserAdmin`.
    pub async fn list_by_user(&self, user_id: i64) -> Result<Vec<ApiKeyMetadata>, KeyError> {
        let owner = i32::try_from(user_id).map_err(|e| KeyError::Store(e.to_string()))?;
        let sql = format!(
            "SELECT {METADATA_COLUMNS},ak.last_used_at,'' FROM api_keys ak WHERE ak.user_id=$1 ORDER BY ak.created_at DESC,ak.id DESC"
        );
        let rows = self.pool.query(&sql, &[&owner]).await?;
        rows.iter().map(|r| Ok(scan_listed(r)?)).collect()
    }

    /// `ListAll`.
    pub async fn list_all(&self) -> Result<Vec<ApiKeyMetadata>, KeyError> {
        let sql = format!(
            "SELECT {METADATA_COLUMNS},ak.last_used_at,u.username::text FROM api_keys ak JOIN users u ON u.id=ak.user_id ORDER BY ak.created_at DESC,ak.id DESC"
        );
        let rows = self.pool.query(&sql, &[]).await?;
        rows.iter().map(|r| Ok(scan_listed(r)?)).collect()
    }

    /// `ListAllPage`.
    pub async fn list_all_page(
        &self,
        after: Option<(SystemTime, i64)>,
        limit: i64,
    ) -> Result<(Vec<ApiKeyMetadata>, bool), KeyError> {
        let limit = if limit < 1 {
            PAGE_DEFAULT
        } else {
            limit.min(PAGE_MAX)
        };
        let (stamp, id) = (after.map(|a| a.0), after.map_or(0, |a| a.1));
        let sql = format!(
            "SELECT {METADATA_COLUMNS},ak.last_used_at,u.username::text FROM api_keys ak JOIN users u ON u.id=ak.user_id
             WHERE ($1::timestamptz IS NULL OR (ak.created_at,ak.id)<($1,$2)) ORDER BY ak.created_at DESC,ak.id DESC LIMIT $3"
        );
        let rows = self.pool.query(&sql, &[&stamp, &id, &(limit + 1)]).await?;
        page(&rows, limit)
    }

    /// `ListByUserAdminPage`.
    pub async fn list_by_user_page(
        &self,
        user_id: i64,
        after: Option<(SystemTime, i64)>,
        limit: i64,
    ) -> Result<(Vec<ApiKeyMetadata>, bool), KeyError> {
        let limit = limit.clamp(1, PAGE_MAX);
        let owner = i32::try_from(user_id).map_err(|e| KeyError::Store(e.to_string()))?;
        let (stamp, id) = (after.map(|a| a.0), after.map_or(0, |a| a.1));
        let sql = format!(
            "SELECT {METADATA_COLUMNS},ak.last_used_at,u.username::text FROM api_keys ak JOIN users u ON u.id=ak.user_id
             WHERE ak.user_id=$1 AND ($2::timestamptz IS NULL OR (ak.created_at,ak.id)<($2,$3)) ORDER BY ak.created_at DESC,ak.id DESC LIMIT $4"
        );
        let rows = self
            .pool
            .query(&sql, &[&owner, &stamp, &id, &(limit + 1)])
            .await?;
        page(&rows, limit)
    }

    /// `lockAPIKeyMetadata`.
    async fn lock_metadata(
        tx: &mut Session,
        id: i64,
        guard: Precondition,
    ) -> Result<ApiKeyMetadata, KeyError> {
        let sql = format!("SELECT {METADATA_COLUMNS} FROM api_keys ak WHERE ak.id=$1 FOR UPDATE");
        let rows = tx.query(&sql, &[&id]).await?;
        let current = scan_metadata(rows.first().ok_or(KeyError::NotFound)?)?;
        if !guard.any && guard.revision != current.revision {
            return Err(KeyError::Conflict(Box::new(current)));
        }
        Ok(current)
    }

    /// `UpdateTierConditional`.
    pub async fn update_tier_conditional(
        &self,
        id: i64,
        tier: &str,
        guard: Precondition,
        audit_request: &AuditRequest,
    ) -> Result<ApiKeyMetadata, KeyError> {
        if tier != "standard" && tier != "elevated" {
            return Err(KeyError::InvalidTier);
        }
        if !guard.valid() {
            return Err(KeyError::Precondition);
        }
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        audit_request.lock_actors(&mut tx).await?;
        let before = Self::lock_metadata(&mut tx, id, guard).await?;
        let sql = format!(
            "UPDATE api_keys ak SET rate_tier=$2 WHERE ak.id=$1 RETURNING {METADATA_COLUMNS}"
        );
        let rows = tx.query(&sql, &[&id, &tier]).await?;
        let current = scan_metadata(rows.first().ok_or(KeyError::NotFound)?)?;
        let (a, b) = (metadata_audit(&before), metadata_audit(&current));
        let entry = audit_request
            .record(
                &mut tx,
                audit::ACTION_API_KEY_UPDATED,
                audit::TARGET_API_KEY,
                &before.id.to_string(),
                200,
                audit::changes(Some(&a), Some(&b)),
            )
            .await?;
        tx.commit().await?;
        audit::commit(entry);
        Ok(current)
    }

    /// `DeleteByAdminConditional`.
    pub async fn delete_by_admin_conditional(
        &self,
        id: i64,
        guard: Precondition,
        audit_request: &AuditRequest,
    ) -> Result<(), KeyError> {
        if !guard.valid() {
            return Err(KeyError::Precondition);
        }
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        audit_request.lock_actors(&mut tx).await?;
        let before = Self::lock_metadata(&mut tx, id, guard).await?;
        tx.execute("DELETE FROM api_keys WHERE id=$1", &[&id])
            .await?;
        let a = metadata_audit(&before);
        let entry = audit_request
            .record(
                &mut tx,
                audit::ACTION_API_KEY_DELETED,
                audit::TARGET_API_KEY,
                &before.id.to_string(),
                204,
                audit::changes(Some(&a), None),
            )
            .await?;
        tx.commit().await?;
        audit::commit(entry);
        Ok(())
    }
}

fn page(rows: &[Row], limit: i64) -> Result<(Vec<ApiKeyMetadata>, bool), KeyError> {
    let mut keys: Vec<ApiKeyMetadata> = rows.iter().map(scan_listed).collect::<Result<_, _>>()?;
    let more = keys.len() as i64 > limit;
    keys.truncate(limit as usize);
    Ok((keys, more))
}

const INTERVAL: Duration = Duration::from_secs(60);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The bounded map both trackers share: at most one write per key per minute, pruned inline.
struct Coalescer<K> {
    seen: Mutex<(HashMap<K, Instant>, Option<Instant>)>,
}

impl<K: std::hash::Hash + Eq + Clone> Coalescer<K> {
    fn new() -> Self {
        Self {
            seen: Mutex::new((HashMap::new(), None)),
        }
    }

    fn should_update(&self, key: &K, now: Instant) -> bool {
        let mut guard = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let (seen, next_prune) = &mut *guard;
        if next_prune.is_none_or(|at| now >= at) {
            seen.retain(|_, at| now.duration_since(*at) < INTERVAL);
            *next_prune = Some(now + INTERVAL);
        }
        if seen
            .get(key)
            .is_some_and(|at| now.duration_since(*at) < INTERVAL)
        {
            return false;
        }
        seen.insert(key.clone(), now);
        true
    }
}

/// `auth.APIKeyLastUsedTracker`.
pub struct ApiKeyLastUsedTracker {
    repo: ApiKeyRepository,
    seen: Coalescer<i64>,
}

impl ApiKeyLastUsedTracker {
    pub fn new(repo: ApiKeyRepository) -> Self {
        Self {
            repo,
            seen: Coalescer::new(),
        }
    }

    pub fn touch(&self, id: i64) {
        if !self.seen.should_update(&id, Instant::now()) {
            return;
        }
        let repo = self.repo.clone();
        tokio::spawn(async move {
            if let Ok(Err(e)) = tokio::time::timeout(WRITE_TIMEOUT, repo.update_last_used(id)).await
            {
                tracing::debug!(component = "auth", id, error = %e, "api key last-used update failed");
            }
        });
    }
}

/// `auth.SessionLastSeenTracker`.
pub struct SessionLastSeenTracker {
    repo: SessionRepository,
    seen: Coalescer<String>,
}

impl SessionLastSeenTracker {
    pub fn new(repo: SessionRepository) -> Self {
        Self {
            repo,
            seen: Coalescer::new(),
        }
    }

    pub fn touch(&self, id: &str) {
        if id.is_empty() || !self.seen.should_update(&id.to_owned(), Instant::now()) {
            return;
        }
        let repo = self.repo.clone();
        let id = id.to_owned();
        let observed = SystemTime::now();
        tokio::spawn(async move {
            if let Ok(Err(e)) =
                tokio::time::timeout(WRITE_TIMEOUT, repo.update_last_seen(&id, observed)).await
            {
                tracing::debug!(component = "auth", error = %e, "login session activity update failed");
            }
        });
    }
}
