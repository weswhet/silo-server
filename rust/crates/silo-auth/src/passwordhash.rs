//! `internal/auth/passwordhash`: every bcrypt hash and comparison in this process runs under one limit.
//!
//! The limit is this process's: Go keeps its own. At most half the cores hash, a few operations queue
//! briefly, and the rest are refused with [`Busy`], which callers answer as "try again".

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::oneshot;

/// `passwordhash.ErrBusy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("password hashing is at capacity")]
pub struct Busy;

/// `RetryAfterSeconds`.
pub const RETRY_AFTER_SECONDS: i64 = 1;

const WAITERS_PER_SLOT: usize = 4;
const MAX_WAIT: Duration = Duration::from_secs(2);

/// `bcrypt.DefaultCost`, what `passwordHashCost` is in production.
pub const COST: u32 = 10;

#[derive(Default)]
struct State {
    in_flight: usize,
    next_waiter: u64,
    queue: VecDeque<(u64, oneshot::Sender<()>)>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(Mutex::default)
}

fn slot_limit() -> usize {
    (std::thread::available_parallelism().map_or(1, usize::from) / 2).max(1)
}

/// `Permit`.
struct Permit;

impl Drop for Permit {
    fn drop(&mut self) {
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        s.in_flight -= 1;
        while s.in_flight < slot_limit() {
            let Some((_, turn)) = s.queue.pop_front() else {
                break;
            };
            if turn.send(()).is_ok() {
                s.in_flight += 1;
            }
        }
    }
}

/// Takes a waiter out when its request ends first. A turn that came anyway is passed on by the permit.
struct Waiting(u64);

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        s.queue.retain(|(id, _)| *id != self.0);
    }
}

/// `Admit`.
async fn admit() -> Result<Permit, Busy> {
    let (id, mut turn) = {
        let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
        let limit = slot_limit();
        if s.in_flight < limit && s.queue.is_empty() {
            s.in_flight += 1;
            return Ok(Permit);
        }
        if s.queue.len() >= limit * WAITERS_PER_SLOT {
            return Err(Busy);
        }
        let (tx, rx) = oneshot::channel();
        s.next_waiter += 1;
        let id = s.next_waiter;
        s.queue.push_back((id, tx));
        (id, rx)
    };
    let _waiting = Waiting(id);
    match tokio::time::timeout(MAX_WAIT, &mut turn).await {
        Ok(Ok(())) => Ok(Permit),
        Ok(Err(_)) => Err(Busy),
        Err(_) => {
            turn.close();
            // The turn came as the wait ended: it holds a slot that has to go back.
            if turn.try_recv().is_ok() {
                drop(Permit);
            }
            Err(Busy)
        }
    }
}

/// `Compare`: whether `password` matches `hash`. A hash bcrypt cannot read matches nothing.
pub async fn compare(hash: Vec<u8>, password: Vec<u8>) -> Result<bool, Busy> {
    let permit = admit().await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let hash = String::from_utf8_lossy(&hash);
        bcrypt::verify(&password, &hash).unwrap_or(false)
    })
    .await
    .map_err(|_| Busy)
}

/// A failed hash: at capacity, or a password bcrypt refuses.
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error(transparent)]
    Busy(#[from] Busy),
    #[error("hashing password: {0}")]
    Hash(String),
}

/// `Generate`: `$2a$` at [`COST`], the form `golang.org/x/crypto/bcrypt` writes.
pub async fn generate(password: Vec<u8>) -> Result<String, GenerateError> {
    let permit = admit().await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // Go refuses what bcrypt would silently truncate.
        if password.len() > 72 {
            return Err(GenerateError::Hash(
                "bcrypt: password length exceeds 72 bytes".to_owned(),
            ));
        }
        bcrypt::hash_with_result(&password, COST)
            .map(|parts| parts.format_for_version(bcrypt::Version::TwoA))
            .map_err(|e| GenerateError::Hash(e.to_string()))
    })
    .await
    .map_err(|e| GenerateError::Hash(e.to_string()))?
}

/// `placeholderPasswordHash`: what a sign-in compares against when it has no local password to check,
/// so that rejection takes as long as a wrong password. Outside the limit, once per process.
pub fn placeholder_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        let mut random = [0u8; 24];
        getrandom::fill(&mut random).expect("the OS CSPRNG source is unavailable");
        bcrypt::hash_with_result(random, COST)
            .expect("bcrypt hashes a short password")
            .format_for_version(bcrypt::Version::TwoA)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_what_go_reads() {
        let written = generate(b"correct horse".to_vec()).await.unwrap();
        assert!(written.starts_with("$2a$10$"), "{written}");
        assert!(
            compare(written.clone().into(), b"correct horse".to_vec())
                .await
                .unwrap()
        );
        assert!(!compare(written.into(), b"wrong".to_vec()).await.unwrap());
    }

    #[tokio::test]
    async fn refuses_a_password_go_refuses() {
        assert!(matches!(
            generate(vec![b'a'; 73]).await,
            Err(GenerateError::Hash(_))
        ));
    }

    #[tokio::test]
    async fn an_unreadable_hash_matches_nothing() {
        assert!(!compare(b"nope".to_vec(), b"x".to_vec()).await.unwrap());
    }
}
