//! Connection string handling, following `pgxpool.ParseConfig` and `pgconn.ParseConfig`.

use std::collections::BTreeMap;
use std::time::Duration;

use silo_gocompat::time::parse_duration;
use silo_gocompat::url::path_unescape;

use crate::error::Error;
use crate::session::ExecMode;

/// `sslmode`, as far as this crate acts on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SslMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

/// Settings for a [`crate::Pool`].
#[derive(Clone, Debug)]
pub struct PoolConfig {
    pub(crate) pg: tokio_postgres::Config,
    /// pgxpool's `MaxConns`.
    pub max_conns: usize,
    /// pgxpool's `MaxConnLifetime`.
    pub max_conn_lifetime: Duration,
    /// pgxpool's `MaxConnIdleTime`.
    pub max_conn_idle_time: Duration,
    /// pgx's `DefaultQueryExecMode`.
    pub default_exec_mode: ExecMode,
    /// pgx's `StatementCacheCapacity`.
    pub statement_cache_capacity: usize,
    /// pgx's `DescriptionCacheCapacity`.
    pub description_cache_capacity: usize,
    /// The parsed `sslmode`.
    pub ssl_mode: SslMode,
    /// `sslnegotiation=direct`. pgx compares against this one value and ignores any other.
    pub direct_tls: bool,
}

const NOT_RUNTIME_PARAMS: &[&str] = &[
    "host",
    "port",
    "database",
    "user",
    "password",
    "passfile",
    "connect_timeout",
    "sslmode",
    "sslkey",
    "sslcert",
    "sslrootcert",
    "sslnegotiation",
    "sslpassword",
    "sslsni",
    "krbspn",
    "krbsrvname",
    "target_session_attrs",
    "service",
    "servicefile",
    "min_read_buffer_size",
];

const ENV_SETTINGS: &[(&str, &str)] = &[
    ("PGHOST", "host"),
    ("PGPORT", "port"),
    ("PGDATABASE", "database"),
    ("PGUSER", "user"),
    ("PGPASSWORD", "password"),
    ("PGAPPNAME", "application_name"),
    ("PGCONNECT_TIMEOUT", "connect_timeout"),
    ("PGSSLMODE", "sslmode"),
    ("PGTARGETSESSIONATTRS", "target_session_attrs"),
    ("PGOPTIONS", "options"),
];

impl PoolConfig {
    /// Parses a URL or keyword/value connection string, merged over the `PG*` environment.
    pub fn parse(conn_string: &str) -> Result<Self, Error> {
        let env = ENV_SETTINGS
            .iter()
            .filter_map(|(env, key)| {
                std::env::var(env)
                    .ok()
                    .filter(|v| !v.is_empty())
                    .map(|v| (*key, v))
            })
            .collect::<Vec<_>>();
        Self::parse_with_env(conn_string, &env)
    }

    fn parse_with_env(conn_string: &str, env: &[(&str, String)]) -> Result<Self, Error> {
        let mut settings: BTreeMap<String, String> = BTreeMap::new();
        for (key, value) in env {
            settings.insert((*key).to_string(), value.clone());
        }
        let trimmed = conn_string;
        if trimmed.starts_with("postgres://") || trimmed.starts_with("postgresql://") {
            parse_url(trimmed, &mut settings)?;
        } else if !trimmed.is_empty() {
            parse_keyword_value(trimmed, &mut settings)?;
        }
        build(settings)
    }

    /// The connection's target, for messages. Never includes the password.
    pub fn describe(&self) -> String {
        format!(
            "{:?}/{}",
            self.pg.get_hosts(),
            self.pg.get_dbname().unwrap_or_default()
        )
    }
}

fn cfg_err(msg: impl Into<String>) -> Error {
    Error::Config(msg.into())
}

fn unescape(part: &str) -> Result<String, Error> {
    let bytes = path_unescape(part).map_err(|e| cfg_err(e.to_string()))?;
    String::from_utf8(bytes).map_err(|_| cfg_err("not valid UTF-8"))
}

// pgconn's parseURLSettings. Query values use the same percent decoding, plus "+" as a space.
fn parse_url(url: &str, settings: &mut BTreeMap<String, String>) -> Result<(), Error> {
    let (_, rest) = url.split_once("://").ok_or_else(|| cfg_err("no scheme"))?;
    let (rest, query) = match rest.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (rest, None),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (rest, None),
    };
    let hosts = match authority.rsplit_once('@') {
        Some((userinfo, hosts)) => {
            let (user, password) = match userinfo.split_once(':') {
                Some((user, password)) => (user, Some(password)),
                None => (userinfo, None),
            };
            settings.insert("user".into(), unescape(user)?);
            if let Some(password) = password {
                settings.insert("password".into(), unescape(password)?);
            }
            hosts
        }
        None => authority,
    };

    let mut host_list = Vec::new();
    let mut port_list = Vec::new();
    for part in hosts.split(',') {
        if part.is_empty() {
            continue;
        }
        let (host, port) = split_host_port(part);
        if !host.is_empty() {
            host_list.push(unescape(host)?);
        }
        if let Some(port) = port {
            port_list.push(port.to_string());
        }
    }
    if !host_list.is_empty() {
        settings.insert("host".into(), host_list.join(","));
    }
    if !port_list.is_empty() {
        settings.insert("port".into(), port_list.join(","));
    }
    if let Some(path) = path
        && !path.is_empty()
    {
        settings.insert("database".into(), unescape(path)?);
    }
    if let Some(query) = query {
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let mut key = query_unescape(key)?;
            if key == "dbname" {
                key = "database".into();
            }
            settings.insert(key, query_unescape(value)?);
        }
    }
    Ok(())
}

fn query_unescape(part: &str) -> Result<String, Error> {
    let bytes = silo_gocompat::url::query_unescape(part).map_err(|e| cfg_err(e.to_string()))?;
    String::from_utf8(bytes).map_err(|_| cfg_err("not valid UTF-8"))
}

fn split_host_port(part: &str) -> (&str, Option<&str>) {
    if let Some(rest) = part.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        return (host, tail.strip_prefix(':'));
    }
    match part.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (part, None),
    }
}

// pgconn's parseKeywordValueSettings: key=value pairs, values optionally single-quoted, backslash
// escaping the next byte.
fn parse_keyword_value(s: &str, settings: &mut BTreeMap<String, String>) -> Result<(), Error> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == bytes.len() {
            break;
        }
        let eq = s[i..]
            .find('=')
            .map(|p| p + i)
            .ok_or_else(|| cfg_err("invalid keyword/value"))?;
        let key = s[i..eq].trim();
        i = eq + 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = Vec::new();
        if bytes.get(i) == Some(&b'\'') {
            i += 1;
            loop {
                match bytes.get(i) {
                    None => {
                        return Err(cfg_err(
                            "unterminated quoted string in connection info string",
                        ));
                    }
                    Some(b'\'') => {
                        i += 1;
                        break;
                    }
                    Some(b'\\') => {
                        i += 1;
                        let next = bytes.get(i).ok_or_else(|| cfg_err("invalid backslash"))?;
                        value.push(*next);
                        i += 1;
                    }
                    Some(c) => {
                        value.push(*c);
                        i += 1;
                    }
                }
            }
        } else {
            while let Some(c) = bytes.get(i) {
                match c {
                    b' ' | b'\t' | b'\n' | b'\r' => break,
                    b'\\' => {
                        i += 1;
                        let next = bytes.get(i).ok_or_else(|| cfg_err("invalid backslash"))?;
                        value.push(*next);
                        i += 1;
                    }
                    _ => {
                        value.push(*c);
                        i += 1;
                    }
                }
            }
        }
        if key.is_empty() {
            return Err(cfg_err("invalid keyword/value"));
        }
        let key = if key == "dbname" { "database" } else { key };
        let value = String::from_utf8(value).map_err(|_| cfg_err("not valid UTF-8"))?;
        settings.insert(key.to_string(), value);
    }
    Ok(())
}

fn take_duration(
    settings: &mut BTreeMap<String, String>,
    key: &str,
    default: Duration,
) -> Result<Duration, Error> {
    let Some(raw) = settings.remove(key) else {
        return Ok(default);
    };
    let parsed = parse_duration(&raw).map_err(|_| cfg_err(format!("invalid {key}")))?;
    Ok(Duration::from_nanos(parsed.0.max(0).unsigned_abs()))
}

fn take_usize(
    settings: &mut BTreeMap<String, String>,
    key: &str,
    default: usize,
) -> Result<usize, Error> {
    let Some(raw) = settings.remove(key) else {
        return Ok(default);
    };
    raw.parse()
        .map_err(|_| cfg_err(format!("cannot parse {key}")))
}

fn build(mut settings: BTreeMap<String, String>) -> Result<PoolConfig, Error> {
    let default_conns = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .max(4);
    let max_conns = take_usize(&mut settings, "pool_max_conns", default_conns)?;
    if max_conns < 1 {
        return Err(cfg_err("pool_max_conns too small"));
    }
    // Accepted because they are valid in a pgx URL. deadpool has neither a minimum pool size nor a
    // periodic health check; idle and lifetime limits apply on acquire instead.
    settings.remove("pool_min_conns");
    settings.remove("pool_min_idle_conns");
    settings.remove("pool_health_check_period");
    settings.remove("pool_max_conn_lifetime_jitter");
    let max_conn_lifetime = take_duration(
        &mut settings,
        "pool_max_conn_lifetime",
        Duration::from_secs(3600),
    )?;
    let max_conn_idle_time = take_duration(
        &mut settings,
        "pool_max_conn_idle_time",
        Duration::from_secs(1800),
    )?;
    let statement_cache_capacity = take_usize(&mut settings, "statement_cache_capacity", 512)?;
    let description_cache_capacity = take_usize(&mut settings, "description_cache_capacity", 512)?;
    let default_exec_mode = match settings.remove("default_query_exec_mode").as_deref() {
        None | Some("cache_statement") => ExecMode::CacheStatement,
        Some("cache_describe") => ExecMode::CacheDescribe,
        Some(other) => {
            return Err(cfg_err(format!("invalid default_query_exec_mode: {other}")));
        }
    };

    let ssl_mode = match settings.get("sslmode").map(String::as_str) {
        None | Some("prefer") | Some("") => SslMode::Prefer,
        Some("disable") => SslMode::Disable,
        Some("allow") => SslMode::Allow,
        Some("require") => SslMode::Require,
        Some("verify-ca") => SslMode::VerifyCa,
        Some("verify-full") => SslMode::VerifyFull,
        Some(_) => return Err(cfg_err("sslmode is invalid")),
    };
    let direct_tls = settings.get("sslnegotiation").map(String::as_str) == Some("direct");
    // pgx loads `sslrootcert`/`sslcert`/`sslkey` into the TLS config it builds for every mode but
    // `disable` (which never looks at them). This crate does not load certificate files yet (see
    // `Pool::new`), so refuse to start rather than silently connect without the CA pin or client
    // certificate the caller configured.
    if ssl_mode != SslMode::Disable {
        for key in ["sslrootcert", "sslcert", "sslkey"] {
            if settings.get(key).is_some_and(|v| !v.is_empty()) {
                return Err(cfg_err(format!(
                    "{key} is not implemented yet; configure Postgres TLS without a custom cert \
                     file, or use sslmode=disable"
                )));
            }
        }
    }

    let mut pg = tokio_postgres::Config::new();
    // `Pool::new` builds the real per-attempt TLS connector for `ssl_mode` (pgx's semantics need
    // two attempts for `allow`, which a single `tokio_postgres::config::SslMode` can't express).
    // This default only matters for a `Pool` built directly from this `Config` without going
    // through that mapping, so keep it at the conservative end: never negotiate TLS silently.
    pg.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let host = settings
        .get("host")
        .cloned()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(default_host);
    let ports = settings.get("port").cloned().unwrap_or_default();
    let port_list: Vec<&str> = ports.split(',').filter(|p| !p.is_empty()).collect();
    for (index, one) in host.split(',').enumerate() {
        pg.host(one);
        let port = port_list
            .get(index)
            .or(port_list.last())
            .copied()
            .unwrap_or("5432");
        let port: u16 = port.parse().map_err(|_| cfg_err("invalid port"))?;
        pg.port(port);
    }
    if let Some(user) = settings.get("user") {
        pg.user(user);
    } else if let Ok(user) = std::env::var("USER") {
        pg.user(user);
    }
    if let Some(password) = settings.get("password") {
        pg.password(password);
    }
    if let Some(db) = settings.get("database") {
        pg.dbname(db);
    }
    if let Some(timeout) = settings.get("connect_timeout") {
        let seconds: u64 = timeout
            .parse()
            .map_err(|_| cfg_err("invalid connect_timeout"))?;
        if seconds > 0 {
            pg.connect_timeout(Duration::from_secs(seconds));
        }
    }
    match settings.get("target_session_attrs").map(String::as_str) {
        None | Some("any") | Some("") => {}
        Some("read-write") => {
            pg.target_session_attrs(tokio_postgres::config::TargetSessionAttrs::ReadWrite);
        }
        Some("read-only") => {
            pg.target_session_attrs(tokio_postgres::config::TargetSessionAttrs::ReadOnly);
        }
        Some(_) => return Err(cfg_err("unknown target_session_attrs value")),
    }

    // Everything else is a runtime parameter in pgconn. tokio-postgres sends only application_name
    // and options in the startup message, so the rest go through options as "-c key=value". Postgres
    // applies both at the same GUC source, which is what the JIT check looks at.
    let mut options = settings.get("options").cloned().unwrap_or_default();
    for (key, value) in &settings {
        if key == "options" || NOT_RUNTIME_PARAMS.contains(&key.as_str()) {
            continue;
        }
        if key == "application_name" {
            pg.application_name(value);
            continue;
        }
        if !options.is_empty() {
            options.push(' ');
        }
        options.push_str("-c ");
        options.push_str(key);
        options.push('=');
        for c in value.chars() {
            if c == ' ' || c == '\\' {
                options.push('\\');
            }
            options.push(c);
        }
    }
    if !options.is_empty() {
        pg.options(&options);
    }

    Ok(PoolConfig {
        pg,
        max_conns,
        max_conn_lifetime,
        max_conn_idle_time,
        default_exec_mode,
        statement_cache_capacity,
        description_cache_capacity,
        ssl_mode,
        direct_tls,
    })
}

// pgconn's defaultHost: the first Postgres socket directory that exists, else localhost.
fn default_host() -> String {
    for dir in ["/var/run/postgresql", "/private/tmp", "/tmp"] {
        if std::path::Path::new(dir).exists() {
            return dir.to_string();
        }
    }
    "localhost".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_settings_follow_pgconn() {
        let cfg = PoolConfig::parse_with_env(
            "postgres://u%40x:p%2Fw@db.example:6432/silo?sslmode=disable&pool_max_conns=7&search_path=a%20b&application_name=silo",
            &[("user", "envuser".to_string()), ("port", "1".to_string())],
        )
        .unwrap();
        assert_eq!(cfg.max_conns, 7);
        assert_eq!(cfg.ssl_mode, SslMode::Disable);
        assert_eq!(cfg.pg.get_user(), Some("u@x"));
        assert_eq!(cfg.pg.get_password(), Some(&b"p/w"[..]));
        assert_eq!(cfg.pg.get_dbname(), Some("silo"));
        assert_eq!(cfg.pg.get_ports(), &[6432]);
        assert_eq!(cfg.pg.get_application_name(), Some("silo"));
        // A runtime parameter survives as a -c option, with its space escaped.
        assert_eq!(cfg.pg.get_options(), Some(r"-c search_path=a\ b"));
    }

    #[test]
    fn query_exec_mode_is_read_from_the_url() {
        let cfg = PoolConfig::parse_with_env(
            "postgres://u@h/d?default_query_exec_mode=cache_describe",
            &[],
        )
        .unwrap();
        assert_eq!(cfg.default_exec_mode, ExecMode::CacheDescribe);
        assert!(
            PoolConfig::parse_with_env("postgres://u@h/d?default_query_exec_mode=nope", &[])
                .is_err()
        );
    }

    #[test]
    fn keyword_value_strings_parse() {
        let cfg = PoolConfig::parse_with_env(
            r"host=h port=5433 dbname='a b' user=u password=p\ q sslmode=disable",
            &[],
        )
        .unwrap();
        assert_eq!(cfg.pg.get_dbname(), Some("a b"));
        assert_eq!(cfg.pg.get_password(), Some(&b"p q"[..]));
        assert_eq!(cfg.pg.get_ports(), &[5433]);
    }
}
