//! The storage admission lock, ported from `internal/database/pglock/node_admission.go`.
//!
//! Critique finding 6: every write-capable API process must hold the shared
//! [`silo_core::advisory_locks::STORAGE_NODE_ADMISSION`] lock before it opens a blob store. A
//! storage transition takes the lock's exclusive mode on the same key to pause every other writer
//! while it moves data. A Rust writer that skipped this could corrupt a storage transition a Go
//! replica started, or vice versa, so the lock and its session-pinning discipline must match exactly.
//!
//! The `Mutex` guarding the pinned session is `tokio::sync::Mutex`, not `std::sync::Mutex`: every
//! operation here does a round trip on that session while holding the lock (to serialize concurrent
//! callers the way Go's single mutex-guarded struct does), and only an async-aware mutex can be held
//! across an `.await` in a future other code may send between threads.

use std::time::Duration;

use silo_pg::{Error, Pool, Session};
use tokio::sync::Mutex;

/// `pglock.ErrAdmissionLost`: admission is gone for good. A process in this state must stop writing
/// to blob storage and should exit; a storage transition that loses admission while it owns the
/// exclusive lock is unrecoverable in the same way.
#[derive(Debug, thiserror::Error)]
#[error("storage node admission lock was lost")]
pub struct AdmissionLost;

/// `pglock.ErrAdmissionRejoining`: the admission session failed and has not been replaced yet. Pause
/// storage writes until [`NodeAdmission::probe`] succeeds again.
#[derive(Debug, thiserror::Error)]
#[error("storage node admission is rejoining: {0}")]
pub struct AdmissionRejoining(String);

/// `pglock.ErrStorageMoved`: a storage transition committed while this node was out, so its open
/// stores no longer match the recorded location. The process must restart, not rejoin. Carried
/// inside [`AdmissionError::Lost`], as Go wraps `ErrStorageMoved` inside `ErrAdmissionLost`.
#[derive(Debug, thiserror::Error)]
#[error("storage moved while this node was out: {0}")]
pub struct StorageMoved(pub String);

/// What [`NodeAdmission`]'s operations can report.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error(transparent)]
    Lost(#[from] AdmissionLost),
    #[error(transparent)]
    Rejoining(#[from] AdmissionRejoining),
    #[error(transparent)]
    Pg(#[from] Error),
}

/// A rejoin's check that the stores this process opened still match the recorded storage location.
/// `Err` describes the mismatch; the caller decides whether it means [`StorageMoved`] (a committed
/// transition) or a transient failure (stay rejoining).
pub trait RejoinCheck: Send + Sync {
    fn check(&self) -> Result<(), String>;
}

struct Inner {
    session: Option<Session>,
    exclusive: bool,
    /// Set once admission is gone for good; distinct from `session.is_none()`, which is also true
    /// transiently while rejoining.
    failed: bool,
}

/// Owns one Postgres session for a process's storage lifetime. The session must stay pinned:
/// session advisory locks disappear if a pooled connection is returned or its backend exits.
///
/// A session that fails while this node holds only the shared lock is replaced by
/// [`NodeAdmission::probe`]. Rejoining succeeds only while no node holds the exclusive lock and the
/// recorded storage location still matches this process, so a node never resumes writing beside a
/// transition or after one. Losing the session while this node owns a transition, or failing either
/// rejoin condition, is final. `pglock.NodeAdmission`.
pub struct NodeAdmission {
    pool: Pool,
    key: i64,
    inner: Mutex<Inner>,
    check: Option<Box<dyn RejoinCheck>>,
}

/// Waits for any transitioning owner, then admits this process before it opens storage or starts
/// writers. A failed acquisition destroys the session because Postgres may have granted the lock
/// just before reporting an error. `pglock.AdmitNode`.
pub async fn admit_node(pool: &Pool, key: i64) -> Result<NodeAdmission, Error> {
    let mut session = pool.acquire().await?;
    if let Err(err) = session
        .execute("SELECT pg_advisory_lock_shared($1)", &[&key])
        .await
    {
        drop(session.hijack());
        return Err(err);
    }
    // Detach from the pool so the pool's own shutdown or recycling cannot release the lock while
    // old storage workers are still draining; this is kept until process exit.
    let session = session.hijack();
    Ok(NodeAdmission {
        pool: pool.clone(),
        key,
        inner: Mutex::new(Inner {
            session: Some(session),
            exclusive: false,
            failed: false,
        }),
        check: None,
    })
}

async fn query_bool(session: &mut Session, sql: &str, key: i64) -> Result<bool, Error> {
    session
        .query_one(sql, &[&key])
        .await?
        .try_get(0)
        .map_err(|_| Error::Pool(format!("{sql} returned no boolean")))
}

impl NodeAdmission {
    /// Installs the check a rejoin must pass. Without it a node that was out for a whole transition,
    /// including its commit and restart, would resume with the old stores. `SetRejoinCheck`.
    pub fn set_rejoin_check(&mut self, check: Box<dyn RejoinCheck>) {
        self.check = Some(check);
    }

    /// Upgrades this node's own shared lock without waiting for other API processes. Postgres keeps
    /// the shared lock if another node prevents the upgrade, so normal storage service continues
    /// after a rejected transition. `TryExclusive`.
    pub async fn try_exclusive(&self) -> Result<bool, AdmissionError> {
        let mut inner = self.inner.lock().await;
        if inner.failed {
            return Err(AdmissionLost.into());
        }
        if inner.exclusive {
            return Ok(false);
        }
        let Some(session) = inner.session.as_mut() else {
            return Err(AdmissionRejoining("no session is pinned".to_owned()).into());
        };
        match query_bool(session, "SELECT pg_try_advisory_lock($1)", self.key).await {
            Ok(acquired) => {
                inner.exclusive = acquired;
                Ok(acquired)
            }
            Err(err) => {
                // The upgrade may have been granted before the error, so the session cannot be
                // treated as shared-only and replaced; this is final, like Go's markLost.
                mark_lost(&mut inner);
                Err(err.into())
            }
        }
    }

    /// Confirms that this node still owns the exclusive lock: its pinned session is alive, so
    /// Postgres still holds the lock for it. A transition calls this inside its commit, so no node
    /// can have rejoined between a lost session and the settings change. `VerifyExclusive`.
    pub async fn verify_exclusive(&self) -> Result<(), AdmissionError> {
        let mut inner = self.inner.lock().await;
        if inner.failed || !inner.exclusive {
            return Err(AdmissionLost.into());
        }
        let Some(session) = inner.session.as_mut() else {
            return Err(AdmissionLost.into());
        };
        // `SELECT 1` stands in for pgx's Ping: a round trip that fails only if the backend session
        // is gone.
        if let Err(err) = session.execute("SELECT 1", &[]).await {
            mark_lost(&mut inner);
            tracing::warn!(error = %err, "storage node admission exclusive session failed");
            return Err(AdmissionLost.into());
        }
        Ok(())
    }

    /// Leaves the process's shared lock held after an uncommitted transition fails or is canceled. A
    /// committed transition retains exclusivity until the old process has drained and exits. Not
    /// exclusive is a no-op: an exclusive owner is never rejoining, so losing its session is always
    /// final. `ReleaseExclusive`.
    pub async fn release_exclusive(&self) -> Result<(), AdmissionError> {
        let mut inner = self.inner.lock().await;
        if inner.failed {
            return Err(AdmissionLost.into());
        }
        if !inner.exclusive {
            return Ok(());
        }
        let session = inner.session.as_mut().expect("exclusive implies a session");
        let released = tokio::time::timeout(
            Duration::from_secs(5),
            query_bool(session, "SELECT pg_advisory_unlock($1)", self.key),
        )
        .await;
        match released {
            Ok(Ok(true)) => {
                inner.exclusive = false;
                Ok(())
            }
            Ok(Ok(false)) => {
                mark_lost(&mut inner);
                Err(AdmissionLost.into())
            }
            Ok(Err(err)) => {
                mark_lost(&mut inner);
                Err(err.into())
            }
            Err(_elapsed) => {
                mark_lost(&mut inner);
                Err(AdmissionLost.into())
            }
        }
    }

    /// Checks the pinned session and replaces a failed shared-only session. Returns
    /// [`AdmissionError::Lost`] once admission is gone for good, and [`AdmissionError::Rejoining`]
    /// while still waiting to rejoin. `Probe`.
    pub async fn probe(&self) -> Result<(), AdmissionError> {
        {
            let mut inner = self.inner.lock().await;
            if inner.failed {
                return Err(AdmissionLost.into());
            }
            if let Some(session) = inner.session.as_mut() {
                match session.execute("SELECT 1", &[]).await {
                    Ok(_) => return Ok(()),
                    Err(err) if inner.exclusive => {
                        mark_lost(&mut inner);
                        tracing::error!(error = %err, "storage node admission failed while owning a transition");
                        return Err(AdmissionLost.into());
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "storage node admission session failed; rejoining");
                        if let Some(session) = inner.session.take() {
                            drop(session.hijack());
                        }
                    }
                }
            }
        }
        self.rejoin().await
    }

    /// Admits the node on a new session without waiting. Any exclusive holder at that moment makes
    /// the loss final: its transition may already be copying beside this node. A transition that
    /// committed and restarted while this node was out is caught by the rejoin check. A database
    /// that cannot be reached leaves the node rejoining. `rejoinLocked`.
    async fn rejoin(&self) -> Result<(), AdmissionError> {
        let mut session = match self.pool.acquire().await {
            Ok(session) => session,
            Err(err) => return Err(AdmissionRejoining(err.to_string()).into()),
        };
        let joined = query_bool(
            &mut session,
            "SELECT pg_try_advisory_lock_shared($1)",
            self.key,
        )
        .await;
        let joined = match joined {
            Ok(joined) => joined,
            Err(err) => {
                drop(session.hijack());
                return Err(AdmissionRejoining(err.to_string()).into());
            }
        };
        if !joined {
            drop(session.hijack());
            let mut inner = self.inner.lock().await;
            mark_lost(&mut inner);
            return Err(AdmissionLost.into());
        }
        let session = session.hijack();
        // The shared lock now keeps any transition from starting, but one may have committed and
        // restarted while this node was out.
        if let Some(check) = &self.check
            && let Err(message) = check.check()
        {
            drop(session.hijack());
            let mut inner = self.inner.lock().await;
            mark_lost(&mut inner);
            tracing::error!(reason = %message, "storage moved while this node was out");
            return Err(AdmissionLost.into());
        }
        let mut inner = self.inner.lock().await;
        inner.session = Some(session);
        tracing::info!("storage node admission rejoined");
        Ok(())
    }

    /// Destroys the pinned session after all handlers and workers have drained. Closing the backend
    /// releases both lock modes together. `Close`.
    pub async fn close(&self) {
        let mut inner = self.inner.lock().await;
        if let Some(session) = inner.session.take() {
            drop(session.hijack());
        }
    }

    /// Whether this node still holds the exclusive lock.
    pub async fn is_exclusive(&self) -> bool {
        self.inner.lock().await.exclusive
    }

    /// Whether admission is gone for good.
    pub async fn is_lost(&self) -> bool {
        self.inner.lock().await.failed
    }
}

fn mark_lost(inner: &mut Inner) {
    inner.failed = true;
    if let Some(session) = inner.session.take() {
        drop(session.hijack());
    }
}
