//! `internal/auth/api_key_repository.go`'s request-path half, and the two activity trackers:
//! `api_key_last_used.go` and `session_last_seen.go`. Key creation and deletion stay with Go until the
//! API key rows are ported.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use silo_pg::Pool;

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
