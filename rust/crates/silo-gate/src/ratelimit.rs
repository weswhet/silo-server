//! `internal/ratelimit`: the rate-limit types (`ratelimit.go`), the in-memory limiter
//! (`memory.go`), ported as a faithful reproduction of `golang.org/x/time/rate.Limiter`'s token-
//! bucket math (`golang.org/x/time` v0.15.0, pinned in `go.mod`) since the limiter's behavior
//! under contention depends on its exact floating-point arithmetic.
//!
//! Not ported in this session: [`redis`] (the Lua-script-backed distributed limiter — needs
//! `silo_core::redis_lua`'s scripts wired through a live Redis connection, which is `silo-runtime`
//! territory, not this crate's), [`attempts`] (sign-in attempt tracking), [`session_quota`] (the
//! hourly per-session quota — same token-bucket math as here, but keyed and configured
//! differently; not attempted), [`outbound`], [`account`], and [`middleware`] (the HTTP middleware
//! chain itself: this crate has no HTTP stack dependency). See the port report for the full list.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

/// `rate.Limit`: events per second. `rate.Inf`'s "no burst needed" special case is represented as
/// `f64::INFINITY`, matching Go's `math.MaxFloat64` closely enough for every comparison this port
/// performs (`limit <= 0` and `limit == Inf` are the only branches on it).
pub type Limit = f64;

/// `rate.InfDuration`: the maximum representable duration, Go's sentinel for "never".
pub const INF_DURATION: Duration = Duration::from_nanos(i64::MAX as u64);

fn tokens_from_duration(limit: Limit, d: Duration) -> f64 {
    if limit <= 0.0 {
        return 0.0;
    }
    d.as_secs_f64() * limit
}

fn duration_from_tokens(limit: Limit, tokens: f64) -> Duration {
    if limit <= 0.0 {
        return INF_DURATION;
    }
    let duration = (tokens / limit) * 1_000_000_000.0;
    if duration > i64::MAX as f64 {
        return INF_DURATION;
    }
    if duration < 0.0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(duration as u64)
}

/// `rate.Limiter`: a token bucket of size `burst`, refilling at `limit` tokens/second. Time is a
/// monotonic nanosecond count the caller supplies (Go's `time.Time`); this port does not read the
/// clock itself, so every public method takes `now` explicitly, matching `memory.go`'s own
/// `allowAt(key, limit, time.Now())` split for testability.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    limit: Limit,
    burst: i32,
    tokens: f64,
    /// Nanoseconds since an arbitrary epoch; only deltas matter.
    last: i64,
}

impl TokenBucket {
    /// `rate.NewLimiter`.
    pub fn new(limit: Limit, burst: i32) -> Self {
        Self {
            limit,
            burst,
            tokens: f64::from(burst),
            last: 0,
        }
    }

    pub fn limit(&self) -> Limit {
        self.limit
    }

    pub fn burst(&self) -> i32 {
        self.burst
    }

    /// `(*Limiter).advance`: does not mutate `self`.
    fn advance(&self, now: i64) -> f64 {
        let last = now.min(self.last);
        let elapsed = Duration::from_nanos(now.saturating_sub(last).max(0) as u64);
        let delta = tokens_from_duration(self.limit, elapsed);
        let tokens = self.tokens + delta;
        let burst = f64::from(self.burst);
        if tokens > burst { burst } else { tokens }
    }

    /// `(*Limiter).TokensAt`.
    pub fn tokens_at(&self, now: i64) -> f64 {
        self.advance(now)
    }

    /// `(*Limiter).AllowN`: whether `n` events may happen at `now`; mutates the bucket when `true`.
    pub fn allow_n(&mut self, now: i64, n: i32) -> bool {
        if self.limit == Limit::INFINITY {
            return true;
        }
        let tokens = self.advance(now) - f64::from(n);
        let wait = if tokens < 0.0 {
            duration_from_tokens(self.limit, -tokens)
        } else {
            Duration::ZERO
        };
        // `AllowN` calls Go's `reserveN(t, n, 0)`: the max tolerated wait is zero, i.e. a token
        // must already be available, not merely reservable for a future time.
        let ok = n <= self.burst && wait <= Duration::ZERO;
        if ok {
            self.last = now;
            self.tokens = tokens;
        }
        ok
    }
}

/// `ratelimit.MaxBurst`/`MaxRequestsPerWindow`/`MaxGlobalRequestsPerSecond`.
pub const MAX_BURST: i64 = i32::MAX as i64;
pub const MAX_REQUESTS_PER_WINDOW: f64 = MAX_BURST as f64;
pub const MAX_GLOBAL_REQUESTS_PER_SECOND: f64 = (MAX_BURST / 60) as f64;

/// `ratelimit.Rate`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Rate {
    pub requests_per_second: f64,
    pub requests_per_minute: f64,
    pub burst: i32,
}

/// `ratelimit.AllowResult`. `reset_at` is nanoseconds on the same clock the caller passed to
/// [`MemoryLimiter::allow_at`]. It is an `i128` because a saturated delay added to a Unix-epoch `now`
/// does not fit in `i64`; Go's `time.Time` holds that sum without overflow.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AllowResult {
    pub allowed: bool,
    pub retry_after: Duration,
    pub limit: i64,
    pub remaining: i64,
    pub reset_at: i128,
}

/// `memory.tokenDelay`: how long `bucket` needs to hold a whole token at `now`, without taking
/// one. A bucket that can never hold one reports [`INF_DURATION`].
fn token_delay(bucket: &TokenBucket, now: i64) -> Duration {
    let missing = 1.0 - bucket.tokens_at(now);
    if missing <= 0.0 {
        return Duration::ZERO;
    }
    let per_second = bucket.limit();
    if per_second <= 0.0 || bucket.burst() < 1 {
        return INF_DURATION;
    }
    let delay = (missing / per_second * 1_000_000_000.0).ceil();
    if delay >= i64::MAX as f64 {
        return INF_DURATION;
    }
    Duration::from_nanos(delay as u64)
}

/// `memory.roundUpToSecond`. Rounding the time, not the delay, keeps a saturated delay from
/// overflowing.
fn round_up_to_second(now: i128) -> i128 {
    let whole = now.div_euclid(SECOND) * SECOND;
    if whole < now { whole + SECOND } else { whole }
}

const SECOND: i128 = 1_000_000_000;
/// `evictLoop`'s ticker.
const EVICT_INTERVAL: Duration = Duration::from_secs(60);
/// `evictLoop`'s idle cutoff.
const EVICT_IDLE: Duration = Duration::from_secs(600);

struct Buckets {
    per_second: TokenBucket,
    per_minute: TokenBucket,
}

/// `memoryEntry`: its mutex makes checking and taking tokens one step for one key.
struct Entry {
    buckets: Mutex<Buckets>,
    /// `lastUsed`: nanoseconds since the Unix epoch, always read from the wall clock as in Go,
    /// independent of the `now` a caller passes to `allow_at`.
    last_used: AtomicI64,
}

type Entries = RwLock<HashMap<String, Arc<Entry>>>;

fn wall_clock_nanos() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// A panic elsewhere must not disable rate limiting, so a poisoned lock is still used. Nothing here
/// leaves the guarded data in a state that a later caller could misread.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn evict_idle(entries: &Entries, cutoff: i64) {
    entries
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|_, entry| entry.last_used.load(Ordering::Relaxed) >= cutoff);
}

/// `ratelimit.MemoryLimiter`: a two-bucket (per-second and per-minute) in-memory limiter, keyed by
/// an arbitrary string, with per-entry locks and a background eviction thread like Go's `evictLoop`.
/// The thread stops when the limiter is dropped or [`Self::close`] runs.
pub struct MemoryLimiter {
    entries: Arc<Entries>,
    stop: Mutex<Option<mpsc::Sender<()>>>,
}

impl Default for MemoryLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryLimiter {
    /// `ratelimit.NewMemoryLimiter`.
    pub fn new() -> Self {
        let entries: Arc<Entries> = Arc::default();
        let (stop, stopped) = mpsc::channel::<()>();
        let weak = Arc::downgrade(&entries);
        std::thread::Builder::new()
            .name("ratelimit-evict".to_owned())
            .spawn(move || {
                while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(EVICT_INTERVAL) {
                    let Some(entries) = weak.upgrade() else {
                        return;
                    };
                    let idle = i64::try_from(EVICT_IDLE.as_nanos()).unwrap_or(i64::MAX);
                    evict_idle(&entries, wall_clock_nanos().saturating_sub(idle));
                }
            })
            .expect("spawning the rate limiter eviction thread");
        Self {
            entries,
            stop: Mutex::new(Some(stop)),
        }
    }

    fn get_or_create(&self, key: &str, limit: Rate) -> Arc<Entry> {
        if let Some(entry) = self
            .entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
        {
            return Arc::clone(entry);
        }
        let minute_burst = (limit.requests_per_minute.ceil() as i32).max(1);
        let entry = Arc::new(Entry {
            buckets: Mutex::new(Buckets {
                per_second: TokenBucket::new(limit.requests_per_second, limit.burst),
                per_minute: TokenBucket::new(limit.requests_per_minute / 60.0, minute_burst),
            }),
            last_used: AtomicI64::new(wall_clock_nanos()),
        });
        Arc::clone(
            self.entries
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(key.to_owned())
                .or_insert(entry),
        )
    }

    /// `MemoryLimiter.allowAt`. `now` is a nanosecond timestamp on the caller's chosen clock,
    /// consistent across calls for one key.
    pub fn allow_at(&self, key: &str, limit: Rate, now: i64) -> AllowResult {
        let entry = self.get_or_create(key, limit);
        entry.last_used.store(wall_clock_nanos(), Ordering::Relaxed);
        let mut buckets = lock(&entry.buckets);

        let delay =
            token_delay(&buckets.per_second, now).max(token_delay(&buckets.per_minute, now));
        if delay > Duration::ZERO {
            return AllowResult {
                allowed: false,
                retry_after: delay,
                limit: limit.requests_per_second as i64,
                remaining: 0,
                reset_at: round_up_to_second(i128::from(now) + delay.as_nanos() as i128),
            };
        }

        buckets.per_second.allow_n(now, 1);
        buckets.per_minute.allow_n(now, 1);

        let remaining = buckets.per_second.tokens_at(now).max(0.0).floor() as i64;
        AllowResult {
            allowed: true,
            retry_after: Duration::ZERO,
            limit: limit.requests_per_second as i64,
            remaining,
            reset_at: (i128::from(now) + SECOND).div_euclid(SECOND) * SECOND,
        }
    }

    /// `MemoryLimiter.Clear`.
    pub fn clear(&self) {
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// `MemoryLimiter.Close`: stops the eviction thread. Unlike Go's `close(ml.done)`, a second call
    /// is harmless.
    pub fn close(&self) {
        lock(&self.stop).take();
    }

    /// The number of live keys, for tests and metrics.
    pub fn len(&self) -> usize {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no key is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `ratelimit.TierConfig`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TierConfig {
    pub requests_per_second: f64,
    pub requests_per_minute: f64,
    pub burst: i32,
}

/// `ratelimit.AuthEndpointConfig`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AuthEndpointConfig {
    pub requests_per_minute: f64,
    pub burst: i32,
}

/// `ratelimit.SessionQuotaConfig`. `mode` is one of [`SESSION_QUOTA_OFF`]/[`SESSION_QUOTA_LOG`]/
/// [`SESSION_QUOTA_ENFORCE`].
#[derive(Debug, Clone, PartialEq)]
pub struct SessionQuotaConfig {
    pub mode: String,
    pub requests_per_hour: f64,
    pub burst: i32,
}

pub const SESSION_QUOTA_OFF: &str = "off";
pub const SESSION_QUOTA_LOG: &str = "log";
pub const SESSION_QUOTA_ENFORCE: &str = "enforce";

/// `ratelimit.Config`.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub enabled: bool,
    pub global_req_per_second: f64,
    pub tiers: std::collections::BTreeMap<String, TierConfig>,
    pub ip_req_per_second: f64,
    pub ip_req_per_minute: f64,
    pub ip_burst: i32,
    pub auth_endpoints: std::collections::BTreeMap<String, AuthEndpointConfig>,
    pub session: SessionQuotaConfig,
}

/// `ratelimit.DefaultConfig`.
pub fn default_config() -> Config {
    let mut tiers = std::collections::BTreeMap::new();
    tiers.insert(
        "standard".to_owned(),
        TierConfig {
            requests_per_second: 20.0,
            requests_per_minute: 1200.0,
            burst: 20,
        },
    );
    tiers.insert(
        "elevated".to_owned(),
        TierConfig {
            requests_per_second: 100.0,
            requests_per_minute: 6000.0,
            burst: 100,
        },
    );

    let mut auth_endpoints = std::collections::BTreeMap::new();
    for (name, per_minute, burst) in [
        ("login", 20.0, 10),
        ("signup", 10.0, 6),
        ("setup", 10.0, 6),
        ("password_change", 10.0, 5),
        ("device_start", 20.0, 10),
        ("device_lookup", 60.0, 20),
        ("device_poll", 120.0, 30),
        ("invitation", 20.0, 10),
        ("password_reset", 20.0, 10),
        ("password_reset_request", 5.0, 3),
        ("autoscan_webhook", 60.0, 30),
        ("apple_push_retire", 20.0, 10),
        ("android_push_retire", 20.0, 10),
    ] {
        auth_endpoints.insert(
            name.to_owned(),
            AuthEndpointConfig {
                requests_per_minute: per_minute,
                burst,
            },
        );
    }

    Config {
        enabled: true,
        global_req_per_second: 1000.0,
        tiers,
        ip_req_per_second: 120.0,
        ip_req_per_minute: 6000.0,
        ip_burst: 120,
        auth_endpoints,
        session: SessionQuotaConfig {
            mode: SESSION_QUOTA_LOG.to_owned(),
            requests_per_hour: 10000.0,
            burst: 30000,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_up_to_burst_then_refuses() {
        let mut b = TokenBucket::new(1.0, 3);
        assert!(b.allow_n(0, 1));
        assert!(b.allow_n(0, 1));
        assert!(b.allow_n(0, 1));
        assert!(!b.allow_n(0, 1));
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let mut b = TokenBucket::new(1.0, 1);
        assert!(b.allow_n(0, 1));
        assert!(!b.allow_n(100_000_000, 1)); // 0.1s later, not enough
        assert!(b.allow_n(1_000_000_000, 1)); // 1s later, refilled
    }

    #[test]
    fn zero_rate_refuses_without_breaking_the_limiter() {
        let ml = MemoryLimiter::new();
        // 2026-11-01 as Unix nanoseconds: the saturated delay would overflow an i64 sum.
        let now = 1_793_577_600_000_000_000;
        let refused = ml.allow_at("a", Rate::default(), now);
        assert!(!refused.allowed);
        assert_eq!(refused.retry_after, INF_DURATION);
        assert!(refused.reset_at > i128::from(i64::MAX));
        let other = Rate {
            requests_per_second: 1.0,
            requests_per_minute: 60.0,
            burst: 1,
        };
        assert!(ml.allow_at("b", other, now).allowed);
    }

    #[test]
    fn eviction_drops_only_idle_keys() {
        let ml = MemoryLimiter::new();
        let rate = Rate {
            requests_per_second: 1.0,
            requests_per_minute: 60.0,
            burst: 1,
        };
        ml.allow_at("old", rate, 0);
        ml.allow_at("new", rate, 0);
        let old = wall_clock_nanos() - 1_000_000_000_000;
        ml.entries.read().unwrap()["old"]
            .last_used
            .store(old, Ordering::Relaxed);
        evict_idle(&ml.entries, wall_clock_nanos() - 600_000_000_000);
        assert_eq!(ml.len(), 1);
        assert!(ml.entries.read().unwrap().contains_key("new"));
    }

    #[test]
    fn memory_limiter_tracks_keys_independently() {
        let ml = MemoryLimiter::new();
        let rate = Rate {
            requests_per_second: 1.0,
            requests_per_minute: 60.0,
            burst: 1,
        };
        assert!(ml.allow_at("a", rate, 0).allowed);
        assert!(!ml.allow_at("a", rate, 0).allowed);
        assert!(ml.allow_at("b", rate, 0).allowed);
    }
}
