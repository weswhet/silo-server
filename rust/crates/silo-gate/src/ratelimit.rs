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
//! chain itself: this crate has no HTTP stack dependency, same reasoning as `clientip`'s module
//! doc). See the port report for the full list.

use std::time::Duration;

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

/// `ratelimit.AllowResult`. `reset_at`/`retry_after` are nanosecond values on the same clock the
/// caller passed to [`MemoryLimiter::allow_at`], not wall-clock `SystemTime`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AllowResult {
    pub allowed: bool,
    pub retry_after: Duration,
    pub limit: i64,
    pub remaining: i64,
    pub reset_at: i64,
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

/// `memory.roundUpToSecond`.
fn round_up_to_second(now: i64) -> i64 {
    const SECOND: i64 = 1_000_000_000;
    let whole = (now / SECOND) * SECOND;
    if whole < now { whole + SECOND } else { whole }
}

struct Entry {
    per_second: TokenBucket,
    per_minute: TokenBucket,
}

/// `ratelimit.MemoryLimiter`: a two-bucket (per-second and per-minute) in-memory limiter, keyed by
/// an arbitrary string. The eviction goroutine (`evictLoop`) is not ported — callers that need
/// bounded memory under many distinct keys should expire entries themselves, e.g. on a timer
/// calling a method this type does not yet have. `Clear` and key eviction economics are otherwise
/// unaffected: the per-key math is unchanged by not evicting promptly.
#[derive(Default)]
pub struct MemoryLimiter {
    entries: std::sync::Mutex<std::collections::HashMap<String, Entry>>,
}

impl MemoryLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// `MemoryLimiter.allowAt`. `now` is a nanosecond timestamp on the caller's chosen clock,
    /// consistent across calls for one key.
    pub fn allow_at(&self, key: &str, limit: Rate, now: i64) -> AllowResult {
        let mut entries = self.entries.lock().expect("ratelimit entries lock");
        let entry = entries.entry(key.to_owned()).or_insert_with(|| {
            let minute_burst = (limit.requests_per_minute.ceil() as i32).max(1);
            Entry {
                per_second: TokenBucket::new(limit.requests_per_second, limit.burst),
                per_minute: TokenBucket::new(limit.requests_per_minute / 60.0, minute_burst),
            }
        });

        let delay = token_delay(&entry.per_second, now).max(token_delay(&entry.per_minute, now));
        if delay > Duration::ZERO {
            return AllowResult {
                allowed: false,
                retry_after: delay,
                limit: limit.requests_per_second as i64,
                remaining: 0,
                reset_at: round_up_to_second(now + delay.as_nanos() as i64),
            };
        }

        entry.per_second.allow_n(now, 1);
        entry.per_minute.allow_n(now, 1);

        let remaining = entry.per_second.tokens_at(now).max(0.0).floor() as i64;
        const SECOND: i64 = 1_000_000_000;
        AllowResult {
            allowed: true,
            retry_after: Duration::ZERO,
            limit: limit.requests_per_second as i64,
            remaining,
            reset_at: ((now + SECOND) / SECOND) * SECOND,
        }
    }

    /// `MemoryLimiter.Clear`.
    pub fn clear(&self) {
        self.entries.lock().expect("ratelimit entries lock").clear();
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
