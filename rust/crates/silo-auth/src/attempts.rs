//! `internal/ratelimit/attempts.go`, the memory backend and the interface a shared one implements.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `AttemptPolicy`.
#[derive(Debug, Clone, Copy)]
pub struct AttemptPolicy {
    pub max_attempts: i64,
    pub window: Duration,
}

/// `ProfilePINPolicy`: five attempts, then five minutes locked.
pub const PROFILE_PIN_POLICY: AttemptPolicy = AttemptPolicy {
    max_attempts: 5,
    window: Duration::from_secs(300),
};

/// `QuickConnectCodePolicy`.
pub const QUICK_CONNECT_CODE_POLICY: AttemptPolicy = AttemptPolicy {
    max_attempts: 20,
    window: Duration::from_secs(15 * 60),
};

/// `SignInNamePolicy`.
pub const SIGN_IN_NAME_POLICY: AttemptPolicy = AttemptPolicy {
    max_attempts: 10,
    window: Duration::from_secs(15 * 60),
};

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// `attemptBackend`, with the fail-open of `AttemptLimiter.Reserve` inside it.
pub trait AttemptLimiter: Send + Sync {
    /// `Reserve`: `Ok(())` when the attempt may go ahead, `Err(retry after)` while the key is locked.
    fn reserve<'a>(&'a self, key: &'a str) -> Boxed<'a, Result<(), Duration>>;
    /// `Reset`.
    fn reset<'a>(&'a self, key: &'a str) -> Boxed<'a, ()>;
}

/// Attempts and expiry by key, and when they were last swept.
type Counts = (HashMap<String, (i64, Instant)>, Option<Instant>);

/// `memoryAttempts`.
pub struct MemoryAttempts {
    policy: AttemptPolicy,
    inner: Mutex<Counts>,
}

impl MemoryAttempts {
    pub fn new(policy: AttemptPolicy) -> Self {
        Self {
            policy,
            inner: Mutex::new((HashMap::new(), None)),
        }
    }

    fn take(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (entries, swept) = &mut *guard;
        if swept.is_none_or(|at| now.duration_since(at) >= self.policy.window) {
            entries.retain(|_, (_, expires)| now < *expires);
            *swept = Some(now);
        }
        let entry = entries
            .get(key)
            .copied()
            .filter(|(_, expires)| now < *expires);
        let (count, expires) = entry.unwrap_or((0, now));
        if count >= self.policy.max_attempts {
            return Err(expires.duration_since(now));
        }
        let count = count + 1;
        // The first attempt opens the window, and the one that reaches the limit restarts it.
        let expires = if count == 1 || count >= self.policy.max_attempts {
            now + self.policy.window
        } else {
            expires
        };
        entries.insert(key.to_owned(), (count, expires));
        Ok(())
    }
}

impl AttemptLimiter for MemoryAttempts {
    fn reserve<'a>(&'a self, key: &'a str) -> Boxed<'a, Result<(), Duration>> {
        Box::pin(async move { self.take(key, Instant::now()) })
    }

    fn reset<'a>(&'a self, key: &'a str) -> Boxed<'a, ()> {
        Box::pin(async move {
            self.inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .0
                .remove(key);
        })
    }
}

/// `RetryAfterSeconds`: rounded up, never below one.
pub fn retry_after_seconds(d: Duration) -> i64 {
    let mut seconds = d.as_secs() as i64;
    if d.subsec_nanos() > 0 {
        seconds += 1;
    }
    seconds.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_for_a_window_at_the_limit_and_resets() {
        let m = MemoryAttempts::new(AttemptPolicy {
            max_attempts: 2,
            window: Duration::from_secs(60),
        });
        let now = Instant::now();
        assert!(m.take("k", now).is_ok());
        assert!(m.take("k", now + Duration::from_secs(30)).is_ok());
        let left = m.take("k", now + Duration::from_secs(40)).unwrap_err();
        assert_eq!(left, Duration::from_secs(50));
        assert!(m.take("k", now + Duration::from_secs(91)).is_ok());
    }

    #[test]
    fn rounds_retry_after_up() {
        assert_eq!(retry_after_seconds(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(1500)), 2);
        assert_eq!(retry_after_seconds(Duration::ZERO), 1);
    }
}
