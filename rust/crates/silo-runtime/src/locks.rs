//! Session-level Postgres advisory locks, ported from `internal/database/pglock/pglock.go`.
//!
//! A session-level advisory lock lives on the connection that took it, so a connection returned to
//! the pool while still holding the lock poisons every later borrower: the lock is never observable
//! as free again. [`Lock::release`] therefore destroys the connection whenever the unlock cannot be
//! confirmed, exactly as Go's `Lock.Release` does by hijacking the `pgxpool.Conn`.
//!
//! The fixed lock integers themselves are not redefined here: [`silo_core::advisory_locks`] is the
//! single source, generated from the Go constants, and every caller must use those values so a Go
//! and a Rust replica contending for the same lock agree on its identity.

use std::time::{Duration, Instant};

use silo_pg::{Error, Pool, Session};
use tokio_postgres::error::SqlState;

/// Re-exports every fixed advisory lock integer Go defines. Identical to [`silo_core::advisory_locks`];
/// kept here too so callers that only depend on `silo-runtime` do not also need `silo-core` for the
/// constant they are about to take a lock with.
pub use silo_core::advisory_locks as ids;

/// The SQLSTATE Postgres reports when `lock_timeout` ends a wait for `pg_advisory_lock`.
const LOCK_NOT_AVAILABLE: SqlState = SqlState::LOCK_NOT_AVAILABLE;

/// The least time [`Lock::acquire`] gives itself to get a pooled connection, so a call with little or
/// no wait left still gets an idle one. `pglock.go`'s `minAcquireWait`.
const MIN_ACQUIRE_WAIT: Duration = Duration::from_millis(250);

/// How long [`Lock::release`] and [`Lock::release_also`] give an unlock round trip, so a caller whose
/// own deadline has already passed still gets a chance to release cleanly instead of always losing
/// the connection. `pglock.go`'s `releaseTimeout`.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

fn is_lock_not_available(err: &Error) -> bool {
    err.code() == Some(&LOCK_NOT_AVAILABLE)
}

/// A held session-level advisory lock and the connection holding it.
///
/// The caller owns it and should call [`Lock::release`] exactly once; a `Lock` dropped without that
/// call still ends up closing the connection (and so releasing the lock) once the pool eventually
/// recycles or drops it, but Go's deterministic unlock-then-return-to-pool behavior is only
/// reproduced by calling `release`.
pub struct Lock {
    session: Option<Session>,
    key: i64,
    /// Keys [`Lock::acquire_also`] took on the same session, oldest first.
    also: Vec<i64>,
}

/// Takes advisory lock `key` on a pooled connection without blocking. Returns `Ok(None)` (no error)
/// when another session already holds the lock. `pglock.TryAcquire`.
pub async fn try_acquire(pool: &Pool, key: i64) -> Result<Option<Lock>, Error> {
    let mut session = pool.acquire().await?;
    let locked: bool = session
        .query_one("SELECT pg_try_advisory_lock($1)", &[&key])
        .await?
        .try_get(0)
        .map_err(|_| Error::Pool("pg_try_advisory_lock returned no boolean".to_owned()))?;
    if !locked {
        return Ok(None);
    }
    Ok(Some(Lock {
        session: Some(session),
        key,
        also: Vec::new(),
    }))
}

/// Takes advisory lock `key`, waiting up to `wait` in all for a pooled connection (at least
/// [`MIN_ACQUIRE_WAIT`]) and for another session holding the lock to release it; with no wait left it
/// only tries the lock. Returns `Ok(None)` when the wait runs out. Postgres enforces the lock wait, so
/// a wait that runs out leaves no session queued on the lock. `pglock.Acquire`.
pub async fn acquire(pool: &Pool, key: i64, wait: Duration) -> Result<Option<Lock>, Error> {
    let deadline = Instant::now() + wait;
    // silo-pg's pool has no acquire-timeout parameter of its own; Go's pgxpool.Acquire(acquireCtx)
    // bounds the *wait for an idle connection* this way, so a slow pool under a short wait still
    // behaves like Go's deadline rather than hanging on `pool.acquire()` indefinitely.
    let acquire_wait = wait.max(MIN_ACQUIRE_WAIT);
    let session = match tokio::time::timeout(acquire_wait, pool.acquire()).await {
        Ok(result) => result?,
        Err(_) => return Ok(None),
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let mut session = session;
    match lock_within(&mut session, key, remaining).await {
        Ok(true) => Ok(Some(Lock {
            session: Some(session),
            key,
            also: Vec::new(),
        })),
        Ok(false) => {
            // session drops here and returns to the pool: lock_within rolled its own transaction
            // back, so nothing is held.
            Ok(None)
        }
        Err(err) => {
            // Postgres may have granted the lock just before the error, so the session cannot be
            // trusted back to the pool.
            drop(session.hijack());
            Err(err)
        }
    }
}

/// Takes advisory lock `key` on `conn`'s session, waiting up to `wait` (at least a millisecond).
/// Returns `Ok(false)` when the wait runs out. After any `Err` the session's lock state is unknown
/// and the connection must not be reused. `pglock.LockWithin`.
async fn lock_within(session: &mut Session, key: i64, wait: Duration) -> Result<bool, Error> {
    let mut tx = session.begin().await?;
    let millis = wait.as_millis().max(1).to_string();
    tx.execute("SELECT set_config('lock_timeout', $1, true)", &[&millis])
        .await?;
    match tx.execute("SELECT pg_advisory_lock($1)", &[&key]).await {
        Ok(_) => {
            tx.commit().await?;
            Ok(true)
        }
        Err(err) if is_lock_not_available(&err) => {
            tx.rollback().await?;
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

impl Lock {
    /// Takes advisory lock `key` on the session this lock already holds, waiting up to `wait` for
    /// another session holding `key` to release it, or not at all when `wait` is zero. Work guarded
    /// by two locks then holds one pooled connection instead of two. Returns `Ok(false)` when the
    /// wait runs out; this lock's own key is unaffected. [`Lock::release`] unlocks every key this
    /// session holds. `pglock.Lock.AcquireAlso`.
    pub async fn acquire_also(&mut self, key: i64, wait: Duration) -> Result<bool, Error> {
        let Some(session) = self.session.as_mut() else {
            return Err(Error::Pool(format!(
                "acquiring advisory lock {key}: no session holds a lock"
            )));
        };
        let result = if wait.is_zero() {
            session
                .query_one("SELECT pg_try_advisory_lock($1)", &[&key])
                .await
                .and_then(|row| {
                    row.try_get::<_, bool>(0)
                        .map_err(|_| Error::Pool("pg_try_advisory_lock returned no boolean".into()))
                })
        } else {
            lock_within(session, key, wait).await
        };
        match result {
            Ok(true) => {
                self.also.push(key);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(err) => {
                if let Some(session) = self.session.take() {
                    drop(session.hijack());
                }
                Err(err)
            }
        }
    }

    /// Reports whether this lock's session is still open. A failed [`Lock::acquire_also`] or
    /// [`Lock::release_also`] closes it, which drops every lock it held. `pglock.Lock.Held`.
    pub fn held(&self) -> bool {
        self.session.is_some()
    }

    /// Runs a trivial query on this lock's session and returns an error when the session has closed,
    /// which released every lock it held. `pglock.Lock.Check`.
    pub async fn check(&mut self) -> Result<(), Error> {
        let Some(session) = self.session.as_mut() else {
            return Err(Error::Pool(
                "checking advisory lock: no session holds a lock".to_owned(),
            ));
        };
        if let Err(err) = session.execute("SELECT 1", &[]).await {
            if let Some(session) = self.session.take() {
                drop(session.hijack());
            }
            return Err(err);
        }
        Ok(())
    }

    /// Unlocks `key`, which [`Lock::acquire_also`] took on this session, and keeps this lock's other
    /// keys. On an unlock failure, or a report that `key` was not held, the session is closed, as in
    /// [`Lock::release`]: that drops every other key too, and `release` becomes a no-op. A key this
    /// lock does not hold, or a session already closed, is a no-op. `pglock.Lock.ReleaseAlso`.
    pub async fn release_also(&mut self, key: i64) -> Result<(), Error> {
        let Some(index) = self.also.iter().position(|&k| k == key) else {
            return Ok(());
        };
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        self.also.remove(index);
        let result = tokio::time::timeout(RELEASE_TIMEOUT, unlock_one(session, key)).await;
        match result {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => {
                self.poison();
                Err(Error::Pool(format!(
                    "releasing advisory lock {key}: lock was not held"
                )))
            }
            Ok(Err(err)) => {
                self.poison();
                Err(err)
            }
            Err(_) => {
                self.poison();
                Err(Error::Pool(format!(
                    "releasing advisory lock {key}: unlock timed out"
                )))
            }
        }
    }

    /// Drops the session without returning it to the pool, matching a Go `Hijack().Close()` that
    /// happened inline with the lock held: the backend connection closing releases every lock it
    /// held.
    fn poison(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session.hijack());
        }
    }

    /// Unlocks every key this session holds (its own, and any [`Lock::acquire_also`] took, newest
    /// first) and returns the connection to the pool. If an unlock fails, or reports that the lock was
    /// not held, the connection is hijacked out of the pool and dropped so the stranded locks die
    /// with it. Idempotent; a second call is a no-op. `pglock.Lock.Release`.
    pub async fn release(mut self) -> Result<(), Error> {
        let Some(mut session) = self.session.take() else {
            return Ok(());
        };
        let mut keys = std::mem::take(&mut self.also);
        keys.reverse();
        keys.push(self.key);
        for key in keys {
            match tokio::time::timeout(RELEASE_TIMEOUT, unlock_one(&mut session, key)).await {
                Ok(Ok(true)) => continue,
                Ok(Ok(false)) => {
                    drop(session.hijack());
                    return Err(Error::Pool(format!(
                        "releasing advisory lock {key}: lock was not held"
                    )));
                }
                Ok(Err(err)) => {
                    drop(session.hijack());
                    return Err(err);
                }
                Err(_) => {
                    drop(session.hijack());
                    return Err(Error::Pool(format!(
                        "releasing advisory lock {key}: unlock timed out"
                    )));
                }
            }
        }
        // session drops here (Holder::Pooled) and returns to the pool, unlocked.
        Ok(())
    }
}

async fn unlock_one(session: &mut Session, key: i64) -> Result<bool, Error> {
    session
        .query_one("SELECT pg_advisory_unlock($1)", &[&key])
        .await?
        .try_get(0)
        .map_err(|_| Error::Pool("pg_advisory_unlock returned no boolean".to_owned()))
}
