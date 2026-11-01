//! `redis.url`: go-redis's `ParseURL` and `ParseFailoverURL` and Silo's stricter rules on top.

use super::{REDIS_DB_SETTING_KEY, RedisConfig};
use crate::gonet::{Url, Values, join_host_port, parse_query, split_host_port};
use crate::goparse::atoi;
use serde::Serialize;
use silo_gocompat::strconv::quote;
use silo_gocompat::strings::trim_space;
use silo_gocompat::time::{Duration, parse_duration};

use super::types::ser_duration;

/// The TLS settings a `rediss://` URL implies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RedisTls {
    #[serde(rename = "ServerName")]
    pub server_name: String,
    #[serde(rename = "InsecureSkipVerify")]
    pub insecure_skip_verify: bool,
}

/// `redis.Options`, the fields a URL can set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RedisOptions {
    #[serde(rename = "Network")]
    pub network: String,
    #[serde(rename = "Addr")]
    pub addr: String,
    #[serde(rename = "ClientName")]
    pub client_name: String,
    #[serde(rename = "Protocol")]
    pub protocol: i64,
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "DB")]
    pub db: i64,
    #[serde(rename = "MaxRetries")]
    pub max_retries: i64,
    #[serde(rename = "MinRetryBackoff", serialize_with = "ser_duration")]
    pub min_retry_backoff: Duration,
    #[serde(rename = "MaxRetryBackoff", serialize_with = "ser_duration")]
    pub max_retry_backoff: Duration,
    #[serde(rename = "DialTimeout", serialize_with = "ser_duration")]
    pub dial_timeout: Duration,
    #[serde(rename = "ReadTimeout", serialize_with = "ser_duration")]
    pub read_timeout: Duration,
    #[serde(rename = "WriteTimeout", serialize_with = "ser_duration")]
    pub write_timeout: Duration,
    #[serde(rename = "PoolFIFO")]
    pub pool_fifo: bool,
    #[serde(rename = "PoolSize")]
    pub pool_size: i64,
    #[serde(rename = "MaxConcurrentDials")]
    pub max_concurrent_dials: i64,
    #[serde(rename = "PoolTimeout", serialize_with = "ser_duration")]
    pub pool_timeout: Duration,
    #[serde(rename = "MinIdleConns")]
    pub min_idle_conns: i64,
    #[serde(rename = "MaxIdleConns")]
    pub max_idle_conns: i64,
    #[serde(rename = "MaxActiveConns")]
    pub max_active_conns: i64,
    #[serde(rename = "ConnMaxIdleTime", serialize_with = "ser_duration")]
    pub conn_max_idle_time: Duration,
    #[serde(rename = "ConnMaxLifetime", serialize_with = "ser_duration")]
    pub conn_max_lifetime: Duration,
    #[serde(rename = "ConnMaxLifetimeJitter", serialize_with = "ser_duration")]
    pub conn_max_lifetime_jitter: Duration,
    #[serde(rename = "TLS")]
    pub tls: Option<RedisTls>,
}

/// `redis.FailoverOptions`, the fields a URL can set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RedisFailoverOptions {
    #[serde(rename = "MasterName")]
    pub master_name: String,
    #[serde(rename = "SentinelAddrs")]
    pub sentinel_addrs: Vec<String>,
    #[serde(rename = "ClientName")]
    pub client_name: String,
    #[serde(rename = "SentinelUsername")]
    pub sentinel_username: String,
    #[serde(rename = "SentinelPassword")]
    pub sentinel_password: String,
    #[serde(rename = "RouteByLatency")]
    pub route_by_latency: bool,
    #[serde(rename = "RouteRandomly")]
    pub route_randomly: bool,
    #[serde(rename = "ReplicaOnly")]
    pub replica_only: bool,
    #[serde(rename = "UseDisconnectedReplicas")]
    pub use_disconnected_replicas: bool,
    #[serde(rename = "Protocol")]
    pub protocol: i64,
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "DB")]
    pub db: i64,
    #[serde(rename = "MaxRetries")]
    pub max_retries: i64,
    #[serde(rename = "MinRetryBackoff", serialize_with = "ser_duration")]
    pub min_retry_backoff: Duration,
    #[serde(rename = "MaxRetryBackoff", serialize_with = "ser_duration")]
    pub max_retry_backoff: Duration,
    #[serde(rename = "DialTimeout", serialize_with = "ser_duration")]
    pub dial_timeout: Duration,
    #[serde(rename = "DialerRetries")]
    pub dialer_retries: i64,
    #[serde(rename = "DialerRetryTimeout", serialize_with = "ser_duration")]
    pub dialer_retry_timeout: Duration,
    #[serde(rename = "ReadTimeout", serialize_with = "ser_duration")]
    pub read_timeout: Duration,
    #[serde(rename = "WriteTimeout", serialize_with = "ser_duration")]
    pub write_timeout: Duration,
    #[serde(rename = "ContextTimeoutEnabled")]
    pub context_timeout_enabled: bool,
    #[serde(rename = "PoolFIFO")]
    pub pool_fifo: bool,
    #[serde(rename = "PoolSize")]
    pub pool_size: i64,
    #[serde(rename = "MaxConcurrentDials")]
    pub max_concurrent_dials: i64,
    #[serde(rename = "PoolTimeout", serialize_with = "ser_duration")]
    pub pool_timeout: Duration,
    #[serde(rename = "MinIdleConns")]
    pub min_idle_conns: i64,
    #[serde(rename = "MaxIdleConns")]
    pub max_idle_conns: i64,
    #[serde(rename = "MaxActiveConns")]
    pub max_active_conns: i64,
    #[serde(rename = "ConnMaxIdleTime", serialize_with = "ser_duration")]
    pub conn_max_idle_time: Duration,
    #[serde(rename = "ConnMaxLifetime", serialize_with = "ser_duration")]
    pub conn_max_lifetime: Duration,
    #[serde(rename = "ConnMaxLifetimeJitter", serialize_with = "ser_duration")]
    pub conn_max_lifetime_jitter: Duration,
    #[serde(rename = "DisableIdentity")]
    pub disable_identity: bool,
    #[serde(rename = "IdentitySuffix")]
    pub identity_suffix: String,
    #[serde(rename = "UnstableResp3")]
    pub unstable_resp3: bool,
    #[serde(rename = "TLS")]
    pub tls: Option<RedisTls>,
}

/// What a `redis.url` names: one server or a Sentinel deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisTarget {
    Single(Box<RedisOptions>),
    Sentinel(Box<RedisFailoverOptions>),
}

struct QueryOptions {
    q: Values,
    err: Option<String>,
}

impl QueryOptions {
    fn has(&self, name: &str) -> bool {
        self.q.get(name).is_some_and(|v| !v.is_empty())
    }

    fn string(&mut self, name: &str) -> String {
        match self.q.get(name).filter(|v| !v.is_empty()).cloned() {
            None => String::new(),
            Some(vs) => {
                self.q.remove(name);
                vs.last().cloned().unwrap_or_default()
            }
        }
    }

    fn strings(&mut self, name: &str) -> Vec<String> {
        self.q.remove(name).unwrap_or_default()
    }

    fn int(&mut self, name: &str) -> i64 {
        let s = self.string(name);
        if s.is_empty() {
            return 0;
        }
        match atoi(&s) {
            Ok(i) => i,
            Err(e) => {
                self.err
                    .get_or_insert(format!("redis: invalid {name} number: {e}"));
                0
            }
        }
    }

    fn duration(&mut self, name: &str) -> Duration {
        let s = self.string(name);
        if s.is_empty() {
            return Duration(0);
        }
        if let Ok(i) = atoi(&s) {
            if i <= 0 {
                return Duration(-1);
            }
            return Duration(i.wrapping_mul(Duration::SECOND.0));
        }
        match parse_duration(&s) {
            Ok(d) => d,
            Err(e) => {
                self.err
                    .get_or_insert(format!("redis: invalid {name} duration: {e}"));
                Duration(0)
            }
        }
    }

    fn bool_(&mut self, name: &str) -> bool {
        let s = self.string(name);
        match s.as_str() {
            "true" | "1" => true,
            "false" | "0" | "" => false,
            _ => {
                self.err.get_or_insert(format!(
                    "redis: invalid {name} boolean: expected true/false/1/0 or an empty string, got {}",
                    quote(&s)
                ));
                false
            }
        }
    }

    fn remaining(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.q.0.iter().map(|(k, _)| k.clone()).collect();
        keys.sort();
        keys
    }
}

fn get_user_password(u: &Url) -> (String, String) {
    match &u.user {
        Some(user) => (
            user.username.clone(),
            user.password.clone().unwrap_or_default(),
        ),
        None => (String::new(), String::new()),
    }
}

fn get_host_port_with_defaults(u: &Url) -> (String, String) {
    let (mut host, mut port) = match split_host_port(&u.host) {
        Ok(hp) => hp,
        Err(_) => (u.host.clone(), String::new()),
    };
    if host.is_empty() {
        host = "localhost".to_owned();
    }
    if port.is_empty() {
        port = "6379".to_owned();
    }
    (host, port)
}

fn path_db(u: &Url) -> Result<i64, String> {
    let f: Vec<&str> = u.path.split('/').filter(|s| !s.is_empty()).collect();
    match f.len() {
        0 => Ok(0),
        1 => atoi(f[0]).map_err(|_| format!("redis: invalid database number: {}", quote(f[0]))),
        _ => Err(format!("redis: invalid URL path: {}", u.path)),
    }
}

/// `redis.ParseURL`.
pub fn go_redis_parse_url(redis_url: &str) -> Result<RedisOptions, String> {
    let u = Url::parse(redis_url).map_err(|e| e.to_string())?;
    match u.scheme.as_str() {
        "redis" | "rediss" => setup_tcp_conn(&u),
        "unix" => setup_unix_conn(&u),
        other => Err(format!("redis: invalid URL scheme: {other}")),
    }
}

fn setup_tcp_conn(u: &Url) -> Result<RedisOptions, String> {
    let mut o = RedisOptions {
        network: "tcp".to_owned(),
        ..Default::default()
    };
    (o.username, o.password) = get_user_password(u);
    let (h, p) = get_host_port_with_defaults(u);
    o.addr = join_host_port(&h, &p);
    o.db = path_db(u)?;
    if u.scheme == "rediss" {
        o.tls = Some(RedisTls {
            server_name: h,
            insecure_skip_verify: false,
        });
    }
    setup_conn_params(u, o)
}

fn setup_unix_conn(u: &Url) -> Result<RedisOptions, String> {
    let mut o = RedisOptions {
        network: "unix".to_owned(),
        ..Default::default()
    };
    if trim_space(&u.path).is_empty() {
        return Err("redis: empty unix socket path".to_owned());
    }
    o.addr.clone_from(&u.path);
    (o.username, o.password) = get_user_password(u);
    setup_conn_params(u, o)
}

fn min_duration(a: Duration, b: Duration) -> Duration {
    if a.0 < b.0 { a } else { b }
}

fn setup_conn_params(u: &Url, mut o: RedisOptions) -> Result<RedisOptions, String> {
    let mut q = QueryOptions {
        q: u.query(),
        err: None,
    };
    let tmp = q.string("db");
    if !tmp.is_empty() {
        o.db = atoi(&tmp).map_err(|e| format!("redis: invalid database number: {e}"))?;
    }
    o.protocol = q.int("protocol");
    o.client_name = q.string("client_name");
    o.max_retries = q.int("max_retries");
    o.min_retry_backoff = q.duration("min_retry_backoff");
    o.max_retry_backoff = q.duration("max_retry_backoff");
    o.dial_timeout = q.duration("dial_timeout");
    o.read_timeout = q.duration("read_timeout");
    o.write_timeout = q.duration("write_timeout");
    o.pool_fifo = q.bool_("pool_fifo");
    o.pool_size = q.int("pool_size");
    o.pool_timeout = q.duration("pool_timeout");
    o.min_idle_conns = q.int("min_idle_conns");
    o.max_idle_conns = q.int("max_idle_conns");
    o.max_active_conns = q.int("max_active_conns");
    o.max_concurrent_dials = q.int("max_concurrent_dials");
    o.conn_max_idle_time = if q.has("conn_max_idle_time") {
        q.duration("conn_max_idle_time")
    } else {
        q.duration("idle_timeout")
    };
    o.conn_max_lifetime = if q.has("conn_max_lifetime") {
        q.duration("conn_max_lifetime")
    } else {
        q.duration("max_conn_age")
    };
    if q.has("conn_max_lifetime_jitter") {
        o.conn_max_lifetime_jitter =
            min_duration(q.duration("conn_max_lifetime_jitter"), o.conn_max_lifetime);
    }
    if let Some(e) = q.err.take() {
        return Err(e);
    }
    if o.tls.is_some() && q.has("skip_verify") {
        let v = q.bool_("skip_verify");
        if let Some(tls) = &mut o.tls {
            tls.insecure_skip_verify = v;
        }
    }
    let r = q.remaining();
    if !r.is_empty() {
        return Err(format!("redis: unexpected option: {}", r.join(", ")));
    }
    Ok(o)
}

/// `redis.ParseFailoverURL`.
pub fn go_redis_parse_failover_url(redis_url: &str) -> Result<RedisFailoverOptions, String> {
    let u = Url::parse(redis_url).map_err(|e| e.to_string())?;
    let mut o = RedisFailoverOptions::default();
    (o.sentinel_username, o.sentinel_password) = get_user_password(&u);
    let (h, p) = get_host_port_with_defaults(&u);
    o.sentinel_addrs.push(join_host_port(&h, &p));
    match u.scheme.as_str() {
        "rediss" => {
            o.tls = Some(RedisTls {
                server_name: h,
                insecure_skip_verify: false,
            })
        }
        "redis" => o.tls = None,
        other => return Err(format!("redis: invalid URL scheme: {other}")),
    }
    o.db = path_db(&u)?;

    let mut q = QueryOptions {
        q: u.query(),
        err: None,
    };
    o.master_name = q.string("master_name");
    o.client_name = q.string("client_name");
    o.route_by_latency = q.bool_("route_by_latency");
    o.route_randomly = q.bool_("route_randomly");
    o.replica_only = q.bool_("replica_only");
    o.use_disconnected_replicas = q.bool_("use_disconnected_replicas");
    o.protocol = q.int("protocol");
    o.username = q.string("username");
    o.password = q.string("password");
    o.max_retries = q.int("max_retries");
    o.min_retry_backoff = q.duration("min_retry_backoff");
    o.max_retry_backoff = q.duration("max_retry_backoff");
    o.dial_timeout = q.duration("dial_timeout");
    o.dialer_retries = q.int("dialer_retries");
    o.dialer_retry_timeout = q.duration("dialer_retry_timeout");
    o.read_timeout = q.duration("read_timeout");
    o.write_timeout = q.duration("write_timeout");
    o.context_timeout_enabled = q.bool_("context_timeout_enabled");
    o.pool_fifo = q.bool_("pool_fifo");
    o.pool_size = q.int("pool_size");
    o.max_concurrent_dials = q.int("max_concurrent_dials");
    o.min_idle_conns = q.int("min_idle_conns");
    o.max_idle_conns = q.int("max_idle_conns");
    o.max_active_conns = q.int("max_active_conns");
    o.conn_max_lifetime = q.duration("conn_max_lifetime");
    if q.has("conn_max_lifetime_jitter") {
        o.conn_max_lifetime_jitter =
            min_duration(q.duration("conn_max_lifetime_jitter"), o.conn_max_lifetime);
    }
    o.conn_max_idle_time = q.duration("conn_max_idle_time");
    o.pool_timeout = q.duration("pool_timeout");
    o.disable_identity = q.bool_("disableIdentity");
    o.identity_suffix = q.string("identitySuffix");
    o.unstable_resp3 = q.bool_("unstable_resp3");
    if let Some(e) = q.err.take() {
        return Err(e);
    }
    let tmp = q.string("db");
    if !tmp.is_empty() {
        o.db = atoi(&tmp).map_err(|e| format!("redis: invalid database number: {e}"))?;
    }
    for addr in q.strings("addr") {
        match split_host_port(&addr) {
            Ok((h, p)) if !h.is_empty() && !p.is_empty() => {
                o.sentinel_addrs.push(join_host_port(&h, &p))
            }
            _ => return Err(format!("redis: unable to parse addr param: {addr}")),
        }
    }
    if o.tls.is_some() && q.has("skip_verify") {
        let v = q.bool_("skip_verify");
        if let Some(tls) = &mut o.tls {
            tls.insecure_skip_verify = v;
        }
    }
    let r = q.remaining();
    if !r.is_empty() {
        return Err(format!("redis: unexpected option: {}", r.join(", ")));
    }
    Ok(o)
}

const REDIS_SENTINEL_MASTER_PARAM: &str = "master_name";
const REDIS_URL_ENCODING_HINT: &str =
    "; percent-encode reserved characters in user names and passwords";
const ERR_NEGATIVE_POOL_SIZE: &str =
    "redis: pool_size must be 0 or more; leave it out for the default";

fn percent_decoded(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(a), Some(c)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            )
        {
            out.push((a * 16 + c) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn redis_url_error(err: &str) -> String {
    let trimmed = err.strip_prefix("redis: ").unwrap_or(err);
    let problem = trimmed.split_once(": ").map_or(trimmed, |(p, _)| p);
    match problem {
        "unexpected option" | "invalid database number" | "invalid URL path" => {
            format!("redis: {problem}{REDIS_URL_ENCODING_HINT}")
        }
        _ => format!("redis: {problem}"),
    }
}

/// `ParseRedisURL`: exactly one set of options. The errors say what is wrong without quoting any part
/// of the URL, which can carry passwords.
pub fn parse_redis_url(raw: &str) -> Result<RedisTarget, String> {
    let raw = trim_space(raw);
    let u = Url::parse(raw)
        .map_err(|_| format!("redis: the URL is malformed{REDIS_URL_ENCODING_HINT}"))?;
    let (query, query_err) = parse_query(&u.raw_query);
    let sentinel = query.has(REDIS_SENTINEL_MASTER_PARAM);
    let mentioned = contains_bytes(
        &percent_decoded(&u.raw_query),
        REDIS_SENTINEL_MASTER_PARAM.as_bytes(),
    ) || u.fragment.contains(REDIS_SENTINEL_MASTER_PARAM);
    if mentioned && (query_err.is_some() || raw.contains('#')) {
        return Err(format!(
            "redis: a parameter of the URL cannot be read{REDIS_URL_ENCODING_HINT}"
        ));
    }
    if !sentinel {
        let options = go_redis_parse_url(raw).map_err(|e| redis_url_error(&e))?;
        if options.pool_size < 0 {
            return Err(ERR_NEGATIVE_POOL_SIZE.to_owned());
        }
        return Ok(RedisTarget::Single(Box::new(options)));
    }
    if u.raw_query.contains('+') {
        return Err(
            "redis: a + in a Sentinel URL parameter means a space; write %2B for a plus sign"
                .to_owned(),
        );
    }
    let mut failover = go_redis_parse_failover_url(raw).map_err(|e| redis_url_error(&e))?;
    if trim_space(&failover.master_name).is_empty() {
        return Err(format!(
            "redis: {REDIS_SENTINEL_MASTER_PARAM} must name the Sentinel master"
        ));
    }
    if failover.pool_size < 0 {
        return Err(ERR_NEGATIVE_POOL_SIZE.to_owned());
    }
    match split_host_port(&u.host) {
        Ok((h, p)) if !h.is_empty() && !p.is_empty() => {}
        _ => {
            return Err(
                "redis: the Sentinel address needs a host and a port, for example sentinel-1:26379; name further Sentinels with addr parameters"
                    .to_owned(),
            )
        }
    }
    if failover.route_by_latency
        || failover.route_randomly
        || failover.replica_only
        || failover.use_disconnected_replicas
    {
        return Err(
            "redis: route_by_latency, route_randomly, replica_only and use_disconnected_replicas are not supported; Silo reads and writes on the master"
                .to_owned(),
        );
    }
    if failover.dial_timeout.0 < 0 || failover.read_timeout.0 < 0 {
        return Err(
            "redis: dial_timeout and read_timeout must be more than 0 in a Sentinel URL; leave them out for the defaults"
                .to_owned(),
        );
    }
    if failover.dial_timeout.0 == 0 {
        failover.dial_timeout = Duration(5 * Duration::SECOND.0);
    }
    Ok(RedisTarget::Sentinel(Box::new(failover)))
}

/// `NormalizeRedisURL`.
pub fn normalize_redis_url(raw: &str) -> Result<String, String> {
    let value = trim_space(raw);
    if value.is_empty() {
        return Ok(String::new());
    }
    if let Err(e) = parse_redis_url(value) {
        return Err(format!(
            "redis.url must be a valid redis://, rediss://, or unix:// URL: {e}"
        ));
    }
    Ok(value.to_owned())
}

/// `NormalizeRedisDB`: empty leaves the database number to `redis.url`.
pub fn normalize_redis_db(raw: &str) -> Result<String, String> {
    Ok(match parse_redis_db(raw)? {
        Some(db) => db.to_string(),
        None => String::new(),
    })
}

fn parse_redis_db(raw: &str) -> Result<Option<i64>, String> {
    let value = trim_space(raw);
    if value.is_empty() {
        return Ok(None);
    }
    match atoi(value) {
        Ok(db) if db >= 0 => Ok(Some(db)),
        _ => Err(format!(
            "{REDIS_DB_SETTING_KEY} must be a whole number, 0 or more"
        )),
    }
}

impl RedisConfig {
    /// `RedisConfig.Options`: what the URL says, on database `db` when `db` is set.
    pub fn options(&self) -> Result<RedisTarget, String> {
        let mut target =
            parse_redis_url(&self.url).map_err(|e| format!("invalid redis URL: {e}"))?;
        if let Some(db) = parse_redis_db(&self.db)? {
            match &mut target {
                RedisTarget::Single(o) => o.db = db,
                RedisTarget::Sentinel(f) => f.db = db,
            }
        }
        Ok(target)
    }

    /// `RedisConfig.Database`: the database number, or `None` with no URL or an unreadable config.
    pub fn database(&self) -> Option<i64> {
        if trim_space(&self.url).is_empty() {
            return None;
        }
        let db = match self.options().ok()? {
            RedisTarget::Single(o) => o.db,
            RedisTarget::Sentinel(f) => f.db,
        };
        Some(db.max(0))
    }

    /// `RedisConfig.WithBootstrapURL`: the environment names the whole connection, database included.
    pub fn with_bootstrap_url(&self, bootstrap_url: &str) -> RedisConfig {
        if bootstrap_url.is_empty() {
            return self.clone();
        }
        RedisConfig {
            url: bootstrap_url.to_owned(),
            db: String::new(),
        }
    }
}
