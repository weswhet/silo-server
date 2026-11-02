//! `internal/ratelimit`: `redis.go`, `session_quota.go`, `config.go`'s reader, `middleware.go`'s budgets.
//! The token buckets and the rate types live in [`crate::ratelimit`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use redis::aio::MultiplexedConnection;
use silo_auth::claims::{Claims, token_type};
use silo_gocompat::regexp::GoRegex as Regexp;
use silo_http::Header;

use crate::mw::Denial;
use crate::ratelimit::{
    AllowResult, Config, MAX_BURST, MAX_GLOBAL_REQUESTS_PER_SECOND, MAX_REQUESTS_PER_WINDOW,
    MemoryLimiter, Rate, SESSION_QUOTA_ENFORCE, SESSION_QUOTA_LOG, SessionQuotaConfig,
    default_config,
};

const WINDOW_SCRIPT: &str = r#"
local sec_key = KEYS[1]
local min_key = KEYS[2]
local sec_limit = tonumber(ARGV[1])
local min_limit = tonumber(ARGV[2])

-- Check current counts before incrementing
local sec_count = tonumber(redis.call('GET', sec_key) or "0")
local min_count = tonumber(redis.call('GET', min_key) or "0")

-- Deny if either limit is exceeded
if sec_count >= sec_limit then
    local sec_ttl = redis.call('TTL', sec_key)
    if sec_ttl < 0 then sec_ttl = 1 end
    return {0, sec_count, sec_limit, min_count, min_limit, sec_ttl}
end
if min_count >= min_limit then
    local sec_ttl = redis.call('TTL', sec_key)
    if sec_ttl < 0 then sec_ttl = 1 end
    return {0, sec_count, sec_limit, min_count, min_limit, sec_ttl}
end

-- Allowed: increment both counters
sec_count = redis.call('INCR', sec_key)
if sec_count == 1 then
    redis.call('EXPIRE', sec_key, 2)
end

min_count = redis.call('INCR', min_key)
if min_count == 1 then
    redis.call('EXPIRE', min_key, 120)
end

local sec_ttl = redis.call('TTL', sec_key)
return {1, sec_count, sec_limit, min_count, min_limit, sec_ttl}
"#;

const QUOTA_SCRIPT: &str = r#"
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local stored = redis.call('HMGET', KEYS[1], 'tokens', 'updated')
local tokens = tonumber(stored[1])
local updated = tonumber(stored[2])
if tokens == nil or updated == nil then
    tokens = burst
    updated = now
end
if now > updated then
    tokens = math.min(burst, tokens + (now - updated) * rate)
    updated = now
end
local allowed = 0
if tokens >= 1 then
    tokens = tokens - 1
    allowed = 1
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'updated', tostring(updated))
local missing = math.min(1, math.max(0, 1 - tokens / burst))
redis.call('EXPIRE', KEYS[1], math.max(1, math.ceil(missing * tonumber(ARGV[3]))))
return {allowed, tostring(tokens)}
"#;

const REDIS_CALL_TIMEOUT: Duration = Duration::from_secs(1);
const REDIS_OUTAGE_PAUSE: Duration = Duration::from_secs(5);
/// `SessionQuotaIdleTTL`.
const SESSION_QUOTA_IDLE_TTL_SECS: i64 = 7 * 24 * 3600;

fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// `redisWindowLimits`.
pub fn redis_window_limits(limit: Rate) -> (i64, i64, i64) {
    let mut sec = limit.requests_per_second.ceil() as i64;
    let mut min = limit.requests_per_minute.ceil() as i64;
    if i64::from(limit.burst) > sec {
        sec = i64::from(limit.burst);
    }
    if sec <= 0 && min > 0 {
        sec = min;
    }
    if min <= 0 && sec > 0 {
        min = sec * 60;
    }
    (sec, min, sec)
}

#[derive(Default)]
struct LocalCount {
    second: i64,
    sec_count: i64,
    min_count: i64,
}

/// `localWindows`.
#[derive(Default)]
struct LocalWindows {
    state: Mutex<(i64, HashMap<String, LocalCount>)>,
}

impl LocalWindows {
    fn allow(&self, key: &str, sec_limit: i64, min_limit: i64, second: i64) -> (bool, i64, i64) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (minute, counts) = &mut *guard;
        if second / 60 > *minute {
            *minute = second / 60;
            counts.clear();
        }
        let c = counts.entry(key.to_owned()).or_default();
        if second > c.second {
            c.second = second;
            c.sec_count = 0;
        }
        if c.sec_count >= sec_limit || c.min_count >= min_limit {
            return (false, c.sec_count, c.min_count);
        }
        c.sec_count += 1;
        c.min_count += 1;
        (true, c.sec_count, c.min_count)
    }
}

/// `windowResult`.
#[allow(clippy::too_many_arguments)]
fn window_result(
    allowed: bool,
    sec_count: i64,
    min_count: i64,
    sec_limit: i64,
    min_limit: i64,
    effective: i64,
    sec_ttl: Duration,
    now: Duration,
) -> AllowResult {
    if !allowed {
        let retry_after = if min_count >= min_limit {
            Duration::from_secs(60 - now.as_secs() % 60)
        } else {
            sec_ttl
        };
        return AllowResult {
            allowed: false,
            retry_after,
            limit: effective,
            remaining: 0,
            reset_at: (now + retry_after).as_nanos() as i128,
        };
    }
    AllowResult {
        allowed: true,
        retry_after: Duration::ZERO,
        limit: effective,
        remaining: (min_limit - min_count).min(sec_limit - sec_count).max(0),
        reset_at: Duration::from_secs(now.as_secs() + 1).as_nanos() as i128,
    }
}

/// `RedisLimiter`. A check Redis cannot count is counted here, so limits hold per node while it is down.
pub struct RedisLimiter {
    conn: MultiplexedConnection,
    script: redis::Script,
    quota_script: redis::Script,
    started: Instant,
    /// Nanoseconds since `started` before which checks skip Redis. Zero while Redis answers.
    paused_until: Arc<AtomicI64>,
    local: LocalWindows,
    local_quota: Mutex<HashMap<String, (f64, Instant)>>,
}

impl RedisLimiter {
    pub fn new(conn: MultiplexedConnection) -> Self {
        Self {
            conn,
            script: redis::Script::new(WINDOW_SCRIPT),
            quota_script: redis::Script::new(QUOTA_SCRIPT),
            started: Instant::now(),
            paused_until: Arc::new(AtomicI64::new(0)),
            local: LocalWindows::default(),
            local_quota: Mutex::new(HashMap::new()),
        }
    }

    fn pause_time(&self, at: Instant) -> i64 {
        (at - self.started).as_nanos() as i64 + 1
    }

    fn start_pause(&self) -> bool {
        let until = self.pause_time(Instant::now() + REDIS_OUTAGE_PAUSE);
        self.paused_until
            .compare_exchange(0, until, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    async fn count(
        &self,
        key: &str,
        sec_limit: i64,
        min_limit: i64,
        now: Duration,
    ) -> Result<Vec<i64>, String> {
        let sec_key = format!("silo:ratelimit:{key}:s:{}", now.as_secs());
        let min_key = format!("silo:ratelimit:{key}:m:{}", now.as_secs() / 60);
        let mut conn = self.conn.clone();
        let mut invocation = self.script.key(sec_key);
        invocation.key(min_key).arg(sec_limit).arg(min_limit);
        let call = invocation.invoke_async::<Vec<i64>>(&mut conn);
        match tokio::time::timeout(REDIS_CALL_TIMEOUT, call).await {
            Ok(Ok(values)) if values.len() == 6 => Ok(values),
            Ok(Ok(values)) => Err(format!("unexpected reply of {} values", values.len())),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("timed out".to_owned()),
        }
    }

    fn local_result(
        &self,
        key: &str,
        sec: i64,
        min: i64,
        effective: i64,
        now: Duration,
    ) -> AllowResult {
        let (allowed, sec_count, min_count) = self.local.allow(key, sec, min, now.as_secs() as i64);
        let until_next = Duration::from_secs(now.as_secs() + 1) - now;
        window_result(
            allowed, sec_count, min_count, sec, min, effective, until_next, now,
        )
    }

    /// `paused`: the first check after a pause runs out starts the next pause and probes Redis.
    fn paused(self: &Arc<Self>, key: &str, sec: i64, min: i64, now: Duration) -> bool {
        let until = self.paused_until.load(Ordering::SeqCst);
        if until == 0 {
            return false;
        }
        if self.pause_time(Instant::now()) >= until {
            let next = self.pause_time(Instant::now() + REDIS_OUTAGE_PAUSE);
            if self
                .paused_until
                .compare_exchange(until, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let this = self.clone();
                let key = key.to_owned();
                tokio::spawn(async move {
                    match this.count(&key, sec, min, now).await {
                        Ok(_) => {
                            if this
                                .paused_until
                                .compare_exchange(next, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                            {
                                tracing::info!(
                                    component = "ratelimit",
                                    "rate limit Redis answering again"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(component = "ratelimit", error = %e, key, "rate limit Redis error, counting requests on this node until it answers");
                        }
                    }
                });
            }
        }
        true
    }

    /// `Allow`.
    pub async fn allow(self: &Arc<Self>, key: &str, limit: Rate) -> AllowResult {
        let now = unix_now();
        let (sec, min, effective) = redis_window_limits(limit);
        if self.paused(key, sec, min, now) {
            return self.local_result(key, sec, min, effective, now);
        }
        match self.count(key, sec, min, now).await {
            Ok(r) => window_result(
                r[0] == 1,
                r[1],
                r[3],
                sec,
                min,
                effective,
                Duration::from_secs(r[5].max(0) as u64),
                now,
            ),
            Err(e) => {
                if self.start_pause() {
                    tracing::warn!(component = "ratelimit", error = %e, key, "rate limit Redis error, counting requests on this node until it answers");
                }
                self.local_result(key, sec, min, effective, now)
            }
        }
    }

    /// `RedisQuotaLimiter.Take`. Returns whether it was allowed and the tokens left.
    async fn take(&self, key: &str, q: &SessionQuotaConfig) -> (bool, f64) {
        let per_second = q.requests_per_hour / 3600.0;
        if self.paused_until.load(Ordering::SeqCst) == 0 {
            let mut conn = self.conn.clone();
            let mut invocation = self.quota_script.key(format!("silo:ratelimit:quota:{key}"));
            invocation
                .arg(per_second)
                .arg(q.burst)
                .arg(SESSION_QUOTA_IDLE_TTL_SECS);
            let call = invocation.invoke_async::<(i64, String)>(&mut conn);
            match tokio::time::timeout(REDIS_CALL_TIMEOUT, call).await {
                Ok(Ok((allowed, tokens))) => {
                    return (allowed == 1, tokens.parse().unwrap_or(0.0));
                }
                Ok(Err(e)) => {
                    if self.start_pause() {
                        tracing::warn!(component = "ratelimit", error = %e, key, "session quota Redis error");
                    }
                }
                Err(_) => {
                    self.start_pause();
                }
            }
        }
        let mut buckets = self.local_quota.lock().unwrap_or_else(|e| e.into_inner());
        take_bucket(&mut buckets, key, q)
    }
}

/// `quotaBucket.take`.
fn take_bucket(
    buckets: &mut HashMap<String, (f64, Instant)>,
    key: &str,
    q: &SessionQuotaConfig,
) -> (bool, f64) {
    let now = Instant::now();
    let burst = f64::from(q.burst);
    let per_second = q.requests_per_hour / 3600.0;
    let (tokens, updated) = buckets.entry(key.to_owned()).or_insert((burst, now));
    *tokens = (*tokens + (now - *updated).as_secs_f64() * per_second).min(burst);
    *updated = now;
    let allowed = *tokens >= 1.0;
    if allowed {
        *tokens -= 1.0;
    }
    (allowed, *tokens)
}

/// `RateLimiter`: Redis when configured, this process otherwise.
pub enum Limiter {
    Redis(Arc<RedisLimiter>),
    Memory(MemoryLimiter),
}

fn monotonic_ns() -> i64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_nanos() as i64
}

impl Limiter {
    async fn allow(&self, key: &str, rate: Rate) -> AllowResult {
        match self {
            Limiter::Redis(limiter) => limiter.allow(key, rate).await,
            Limiter::Memory(limiter) => {
                let mono = monotonic_ns();
                let mut result = limiter.allow_at(key, rate, mono);
                result.reset_at += unix_now().as_nanos() as i128 - i128::from(mono);
                result
            }
        }
    }
}

/// `strconv.ParseBool`.
fn parse_go_bool(v: &str) -> Option<bool> {
    match v {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// `ConfigFromSettings`.
pub fn config_from_settings(all: &HashMap<String, String>) -> Config {
    let defaults = default_config();
    let rate = |key: &str, fallback: f64, max: f64| -> f64 {
        all.get(key)
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| *v > 0.0 && *v <= max)
            .unwrap_or(fallback)
    };
    let int = |key: &str, fallback: i32| -> i32 {
        all.get(key)
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v > 0 && *v <= MAX_BURST)
            .map_or(fallback, |v| v as i32)
    };
    let mut cfg = defaults.clone();
    cfg.enabled = all
        .get("ratelimit.enabled")
        .and_then(|v| parse_go_bool(v))
        .unwrap_or(defaults.enabled);
    cfg.global_req_per_second = rate(
        "ratelimit.global.requests_per_second",
        defaults.global_req_per_second,
        MAX_GLOBAL_REQUESTS_PER_SECOND,
    );
    for (name, tier) in cfg.tiers.iter_mut() {
        let prefix = format!("ratelimit.tier.{name}.");
        tier.requests_per_second = rate(
            &format!("{prefix}requests_per_second"),
            tier.requests_per_second,
            MAX_REQUESTS_PER_WINDOW,
        );
        tier.requests_per_minute = rate(
            &format!("{prefix}requests_per_minute"),
            tier.requests_per_minute,
            MAX_REQUESTS_PER_WINDOW,
        );
        tier.burst = int(&format!("{prefix}burst"), tier.burst);
    }
    cfg.ip_req_per_second = rate(
        "ratelimit.ip.requests_per_second",
        defaults.ip_req_per_second,
        MAX_REQUESTS_PER_WINDOW,
    );
    cfg.ip_req_per_minute = rate(
        "ratelimit.ip.requests_per_minute",
        defaults.ip_req_per_minute,
        MAX_REQUESTS_PER_WINDOW,
    );
    cfg.ip_burst = int("ratelimit.ip.burst", defaults.ip_burst);
    if let Some(mode) = all.get("ratelimit.session.mode")
        && matches!(
            mode.as_str(),
            "off" | SESSION_QUOTA_LOG | SESSION_QUOTA_ENFORCE
        )
    {
        cfg.session.mode = mode.clone();
    }
    cfg.session.requests_per_hour = rate(
        "ratelimit.session.requests_per_hour",
        defaults.session.requests_per_hour,
        MAX_REQUESTS_PER_WINDOW,
    );
    cfg.session.burst = int("ratelimit.session.burst", defaults.session.burst);
    for (name, ep) in cfg.auth_endpoints.iter_mut() {
        let prefix = format!("ratelimit.auth.{name}.");
        ep.requests_per_minute = rate(
            &format!("{prefix}requests_per_minute"),
            ep.requests_per_minute,
            MAX_REQUESTS_PER_WINDOW,
        );
        ep.burst = int(&format!("{prefix}burst"), ep.burst);
    }
    cfg
}

/// `SourceKey`.
pub fn source_key(ip: &str) -> String {
    let Ok(std::net::IpAddr::V6(addr)) = ip.parse::<std::net::IpAddr>() else {
        return ip.to_owned();
    };
    let seg = addr.segments();
    let mapped = addr.to_ipv4_mapped().is_some();
    let global_unicast = !(addr.is_unspecified()
        || addr.is_loopback()
        || seg[0] & 0xff00 == 0xff00
        || seg[0] & 0xffc0 == 0xfe80);
    let private = seg[0] & 0xfe00 == 0xfc00;
    let nat64 = (seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0])
        || (seg[0] == 0x64 && seg[1] == 0xff9b && seg[2] == 1);
    if mapped || !global_unicast || private || nat64 {
        return ip.to_owned();
    }
    let prefix = std::net::Ipv6Addr::new(seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0);
    format!("{prefix}/64")
}

/// `QuotaExemptPathPattern`.
static QUOTA_EXEMPT: LazyLock<Regexp> = LazyLock::new(|| {
    Regexp::must_compile(concat!(
        r"^/api/v[12]/(stream|playback)(/|$)",
        r"|^/api/v[12]/auth/(provider-)?logout$",
        r"|^/api/v[12]/direct-download(-proxy)?$",
        r"|^/api/v[12]/downloads/[^/]+/(file|file-proxy)$",
        r"|^/api/v[12]/downloads/[^/]+/subtitles/",
        r"|^/api/v2/catalog/items/[^/]+/themes/[^/]+/audio$",
        r"|^/api/v1/ebooks/[^/]+/files/[^/]+/read$",
    ))
});

/// `IsQuotaExemptPath`.
pub fn is_quota_exempt_path(path: &str) -> bool {
    path.starts_with("/api/v") && QUOTA_EXEMPT.match_string(path)
}

/// `authPeerRate`.
fn auth_peer_rate(rate: Rate) -> Rate {
    Rate {
        requests_per_second: (rate.requests_per_second * 10.0).min(MAX_REQUESTS_PER_WINDOW),
        requests_per_minute: (rate.requests_per_minute * 10.0).min(MAX_REQUESTS_PER_WINDOW),
        burst: (i64::from(rate.burst).min(MAX_BURST / 10) * 10) as i32,
    }
}

/// `accountRate`.
fn account_rate(cfg: &Config) -> Rate {
    Rate {
        requests_per_second: (cfg.ip_req_per_second * 4.0).min(MAX_REQUESTS_PER_WINDOW),
        requests_per_minute: (cfg.ip_req_per_minute * 4.0).min(MAX_REQUESTS_PER_WINDOW),
        burst: (i64::from(cfg.ip_burst).min(MAX_BURST / 4) * 4) as i32,
    }
}

/// `globalRateFor`.
fn global_rate(cfg: &Config) -> Rate {
    let mut rps = cfg.global_req_per_second;
    if !rps.is_finite() || rps <= 0.0 {
        rps = default_config().global_req_per_second;
    } else if rps > MAX_GLOBAL_REQUESTS_PER_SECOND {
        rps = MAX_GLOBAL_REQUESTS_PER_SECOND;
    }
    Rate {
        requests_per_second: rps,
        requests_per_minute: rps * 60.0,
        burst: 1.max(rps.ceil() as i32),
    }
}

/// `writeRateLimitResponse`, which sets the headers before the body. Go counts whole seconds plus one.
fn refuse(sink: &mut Header, result: &AllowResult) -> Denial {
    let retry = result.retry_after.as_secs() as i64 + 1;
    sink.set("X-RateLimit-Limit", result.limit.to_string().as_bytes());
    sink.set("X-RateLimit-Remaining", "0");
    sink.set(
        "X-RateLimit-Reset",
        (result.reset_at / 1_000_000_000).to_string().as_bytes(),
    );
    Denial::rate_limited(retry)
}

/// What a limiter gate reads about the request.
pub struct RateRequest<'a> {
    pub client_ip: &'a str,
    pub peer_ip: &'a str,
    pub path: &'a str,
    pub claims: Option<&'a Claims>,
}

/// `ratelimit.Middleware`.
pub struct RateLimit {
    cfg: RwLock<Config>,
    per_key: Limiter,
    quota_logged: Mutex<HashMap<String, Instant>>,
    memory_quota: Mutex<HashMap<String, (f64, Instant)>>,
}

impl RateLimit {
    /// `MemoryQuotaLimiter.Take`.
    fn take_memory(&self, key: &str, q: &SessionQuotaConfig) -> (bool, f64) {
        let mut buckets = self.memory_quota.lock().unwrap_or_else(|e| e.into_inner());
        take_bucket(&mut buckets, key, q)
    }

    pub fn new(per_key: Limiter, cfg: Config) -> Self {
        Self {
            cfg: RwLock::new(cfg),
            per_key,
            quota_logged: Mutex::new(HashMap::new()),
            memory_quota: Mutex::new(HashMap::new()),
        }
    }

    /// `Reload`.
    pub fn reload(&self, cfg: Config) {
        let mut current = self.cfg.write().unwrap_or_else(|e| e.into_inner());
        // Go reloads on a settings event; this is polled, so an unchanged read must not clear counts.
        if *current == cfg {
            return;
        }
        *current = cfg;
        drop(current);
        if let Limiter::Memory(limiter) = &self.per_key {
            limiter.clear();
        }
    }

    fn config(&self) -> Config {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// `Middleware.Handler`.
    pub async fn check(&self, sink: &mut Header, req: &RateRequest<'_>) -> Result<(), Denial> {
        let cfg = self.config();
        if !cfg.enabled {
            return Ok(());
        }
        if !req.client_ip.is_empty() {
            let rate = Rate {
                requests_per_second: cfg.ip_req_per_second,
                requests_per_minute: cfg.ip_req_per_minute,
                burst: cfg.ip_burst,
            };
            let result = self
                .per_key
                .allow(&format!("ip:{}", source_key(req.client_ip)), rate)
                .await;
            if !result.allowed {
                return Err(refuse(sink, &result));
            }
        }
        if let Some(claims) = req
            .claims
            .filter(|c| c.token_type == token_type::API_KEY && c.api_key_id != 0)
        {
            let tier = if claims.rate_tier.is_empty() {
                "standard"
            } else {
                &claims.rate_tier
            };
            let tier = cfg.tiers.get(tier).or_else(|| cfg.tiers.get("standard"));
            let rate = tier.map_or(
                Rate {
                    requests_per_second: 0.0,
                    requests_per_minute: 0.0,
                    burst: 0,
                },
                |t| Rate {
                    requests_per_second: t.requests_per_second,
                    requests_per_minute: t.requests_per_minute,
                    burst: t.burst,
                },
            );
            let result = self
                .per_key
                .allow(&format!("key:{}", claims.api_key_id), rate)
                .await;
            sink.set("X-RateLimit-Limit", result.limit.to_string().as_bytes());
            if result.remaining >= 0 {
                sink.set(
                    "X-RateLimit-Remaining",
                    result.remaining.to_string().as_bytes(),
                );
            }
            sink.set(
                "X-RateLimit-Reset",
                (result.reset_at / 1_000_000_000).to_string().as_bytes(),
            );
            if !result.allowed {
                return Err(refuse(sink, &result));
            }
        }
        self.allow_account(sink, req, &cfg).await?;
        self.allow_session(sink, req, &cfg.session).await?;
        self.allow_global(sink, &cfg).await
    }

    /// `AuthEndpointHandler`.
    pub async fn check_endpoint(
        &self,
        sink: &mut Header,
        req: &RateRequest<'_>,
        endpoint: &str,
    ) -> Result<(), Denial> {
        let cfg = self.config();
        if !cfg.enabled {
            return Ok(());
        }
        if !req.client_ip.is_empty() {
            let source = source_key(req.client_ip);
            let rate = Rate {
                requests_per_second: cfg.ip_req_per_second,
                requests_per_minute: cfg.ip_req_per_minute,
                burst: cfg.ip_burst,
            };
            let result = self.per_key.allow(&format!("ip:{source}"), rate).await;
            if !result.allowed {
                return Err(refuse(sink, &result));
            }
            if let Some(ep) = cfg.auth_endpoints.get(endpoint) {
                let rate = Rate {
                    requests_per_second: ep.requests_per_minute / 60.0,
                    requests_per_minute: ep.requests_per_minute,
                    burst: ep.burst,
                };
                let result = self
                    .per_key
                    .allow(&format!("authip:{source}:{endpoint}"), rate)
                    .await;
                if !result.allowed {
                    return Err(refuse(sink, &result));
                }
                if !req.peer_ip.is_empty() && req.peer_ip != req.client_ip {
                    let key = format!("authpeer:{}:{endpoint}", source_key(req.peer_ip));
                    let result = self.per_key.allow(&key, auth_peer_rate(rate)).await;
                    if !result.allowed {
                        return Err(refuse(sink, &result));
                    }
                }
            }
        }
        self.allow_account(sink, req, &cfg).await?;
        self.allow_global(sink, &cfg).await
    }

    async fn allow_account(
        &self,
        sink: &mut Header,
        req: &RateRequest<'_>,
        cfg: &Config,
    ) -> Result<(), Denial> {
        let Some(id) = req.claims.map(|c| c.user_id).filter(|id| *id > 0) else {
            return Ok(());
        };
        let result = self
            .per_key
            .allow(&format!("account:{id}"), account_rate(cfg))
            .await;
        if result.allowed {
            Ok(())
        } else {
            Err(refuse(sink, &result))
        }
    }

    async fn allow_global(&self, sink: &mut Header, cfg: &Config) -> Result<(), Denial> {
        let result = self.per_key.allow("global", global_rate(cfg)).await;
        if result.allowed {
            Ok(())
        } else {
            Err(refuse(sink, &result))
        }
    }

    /// `allowSession`.
    async fn allow_session(
        &self,
        sink: &mut Header,
        req: &RateRequest<'_>,
        q: &SessionQuotaConfig,
    ) -> Result<(), Denial> {
        if q.mode != SESSION_QUOTA_LOG && q.mode != SESSION_QUOTA_ENFORCE {
            return Ok(());
        }
        let Some(claims) = req.claims else {
            return Ok(());
        };
        if claims.session_id.is_empty()
            || claims.token_type != token_type::ACCESS
            || claims.role == "admin"
            || claims.impersonator_user_id.is_some()
            || is_quota_exempt_path(req.path)
        {
            return Ok(());
        }
        let key = format!("session:{}", claims.session_id);
        let (allowed, tokens) = match &self.per_key {
            Limiter::Redis(limiter) => limiter.take(&key, q).await,
            Limiter::Memory(_) => self.take_memory(&key, q),
        };
        if allowed {
            return Ok(());
        }
        self.log_over_quota(claims, q, req.path);
        if q.mode != SESSION_QUOTA_ENFORCE {
            return Ok(());
        }
        let retry = (1.0 - tokens) / (q.requests_per_hour / 3600.0);
        let retry = Duration::from_secs_f64(retry.max(0.0));
        let result = AllowResult {
            allowed: false,
            retry_after: retry,
            limit: q.requests_per_hour as i64,
            remaining: 0,
            reset_at: ((unix_now() + retry).as_secs() as i128 + 1) * 1_000_000_000,
        };
        Err(refuse(sink, &result))
    }

    fn log_over_quota(&self, claims: &Claims, q: &SessionQuotaConfig, path: &str) {
        const EVERY: Duration = Duration::from_secs(600);
        let now = Instant::now();
        let mut logged = self.quota_logged.lock().unwrap_or_else(|e| e.into_inner());
        if logged
            .get(&claims.session_id)
            .is_some_and(|at| now.duration_since(*at) < EVERY)
        {
            return;
        }
        logged.insert(claims.session_id.clone(), now);
        logged.retain(|_, at| now.duration_since(*at) < EVERY);
        tracing::warn!(component = "ratelimit", mode = %q.mode, user_id = claims.user_id, session_id = %claims.session_id, path, "sign-in session over its hourly request quota");
    }
}
