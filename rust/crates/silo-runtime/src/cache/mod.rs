//! Port of `internal/cache`: a Redis client factory, the pub/sub event bus, the live-replica
//! census, and a small in-process TTL cache.
//!
//! Every externally observable format here — the channel names, the `@dbN` scoping suffix, and the
//! event JSON shape — is defined once in [`silo_core::redis`] and reused, not redefined, so a Go and
//! a Rust replica that both import this module agree with each other automatically. The Lua scripts
//! this crate's domain callers will run (ratelimit, noderecipe, downloads, autoscan, search
//! sessions) are [`silo_core::redis_lua`] constants; [`redis::Script`] already reproduces go-redis's
//! `Script.Run` EVALSHA-then-load-and-retry behavior, so no separate wrapper is needed here.

pub mod event_bus;
pub mod replicas;
pub mod ttlcache;

use redis::aio::MultiplexedConnection;
use redis::sentinel::{Sentinel, SentinelNodeConnectionInfo};
use silo_config::config::{RedisConfig, RedisOptions, RedisTarget, RedisTls};
use silo_gocompat::strings::trim_space;
use thiserror::Error;

/// What building a Redis connection can fail with.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),
    #[error(transparent)]
    Redis(#[from] redis::RedisError),
}

/// `isBareRedisAddress`: reports whether `value` is a `host:port` with a numeric port, or the path of
/// a Unix socket. A host name, an IPv6 zone, and path segments are letters, digits, dots, hyphens,
/// and underscores.
fn is_bare_redis_address(value: &str) -> bool {
    const HOST_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";
    if value.starts_with('/') {
        return value
            .trim_matches(|c: char| HOST_CHARS.contains(c) || c == '/')
            .is_empty();
    }
    let Ok((host, port)) = silo_config::gonet::split_host_port(value) else {
        return false;
    };
    let (address, zone) = host.split_once('%').unwrap_or((host.as_str(), ""));
    if !zone.chars().all(|c| HOST_CHARS.contains(c)) {
        return false;
    }
    let looks_like_ip = address.parse::<std::net::IpAddr>().is_ok();
    if !looks_like_ip && (!zone.is_empty() || !address.chars().all(|c| HOST_CHARS.contains(c))) {
        return false;
    }
    port.parse::<u16>().is_ok()
}

/// A resolved Redis target: either a single server or a Sentinel-monitored master, re-resolved on
/// every connection the way go-redis's `FailoverClient` asks Sentinel for the current master each
/// time it dials. `newRedisClient`.
#[derive(Clone)]
pub enum Connector {
    Single(Box<redis::ConnectionInfo>),
    Sentinel {
        sentinel_addrs: Vec<String>,
        master_name: String,
        node: SentinelNodeConnectionInfo,
    },
    /// The URL could not be parsed or is not a bare address either; every connection attempt fails
    /// with this message, matching Go's `unparsedRedisOptions` dialer-that-always-errors trick so a
    /// bad `REDIS_URL` surfaces as a connection error at the same call sites Go surfaces it at,
    /// rather than at client construction.
    AlwaysFails(String),
}

fn tls_connection_info(tls: &Option<RedisTls>) -> Result<(), Error> {
    if tls.is_some() {
        return Err(Error::Config(
            "rediss:// (TLS to Redis) is not implemented yet".to_owned(),
        ));
    }
    Ok(())
}

fn single_connection_info(o: &RedisOptions) -> Result<redis::ConnectionInfo, Error> {
    tls_connection_info(&o.tls)?;
    let addr = if o.network == "unix" {
        redis::ConnectionAddr::Unix(std::path::PathBuf::from(&o.addr))
    } else {
        let (host, port) = silo_config::gonet::split_host_port(&o.addr)
            .map_err(|e| Error::Config(format!("invalid redis address {:?}: {e}", o.addr)))?;
        let port: u16 = port
            .parse()
            .map_err(|_| Error::Config(format!("invalid redis port {:?}", o.addr)))?;
        redis::ConnectionAddr::Tcp(host, port)
    };
    Ok(redis::ConnectionInfo {
        addr,
        redis: redis::RedisConnectionInfo {
            db: o.db,
            username: (!o.username.is_empty()).then(|| o.username.clone()),
            password: (!o.password.is_empty()).then(|| o.password.clone()),
            protocol: redis::ProtocolVersion::RESP2,
        },
    })
}

/// Options that are not a URL at all: a bare `host:port` or socket path, matching Go's
/// `unparsedRedisOptions`. `db_override` is the validated `redis.db` setting, when set.
fn bare_address_connector(address: &str, db_override: Option<i64>) -> Connector {
    if !is_bare_redis_address(address) {
        return Connector::AlwaysFails(format!("redis: the URL is malformed: {address}"));
    }
    let addr = if address.starts_with('/') {
        redis::ConnectionAddr::Unix(std::path::PathBuf::from(address))
    } else {
        // is_bare_redis_address already proved this splits and parses.
        let (host, port) = silo_config::gonet::split_host_port(address).expect("checked above");
        redis::ConnectionAddr::Tcp(host, port.parse().expect("checked above"))
    };
    Connector::Single(Box::new(redis::ConnectionInfo {
        addr,
        redis: redis::RedisConnectionInfo {
            db: db_override.unwrap_or(0),
            username: None,
            password: None,
            protocol: redis::ProtocolVersion::RESP2,
        },
    }))
}

impl Connector {
    /// Builds a connector from `cfg`, Go's `redis.Options`/`FailoverOptions` already parsed. Falls
    /// back to a bare-address reading, and finally to an always-failing connector, exactly in Go's
    /// order. `NewRedisClient`/`newRedisClient`.
    pub fn from_config(cfg: &RedisConfig) -> Self {
        match cfg.options() {
            Ok(RedisTarget::Single(o)) => match single_connection_info(&o) {
                Ok(info) => Connector::Single(Box::new(info)),
                Err(err) => Connector::AlwaysFails(err.to_string()),
            },
            Ok(RedisTarget::Sentinel(f)) => {
                if f.tls.is_some() {
                    return Connector::AlwaysFails(
                        "rediss:// (TLS to Redis) is not implemented yet".to_owned(),
                    );
                }
                Connector::Sentinel {
                    sentinel_addrs: f.sentinel_addrs.clone(),
                    master_name: f.master_name.clone(),
                    node: SentinelNodeConnectionInfo {
                        tls_mode: None,
                        redis_connection_info: Some(redis::RedisConnectionInfo {
                            db: f.db,
                            username: (!f.username.is_empty()).then(|| f.username.clone()),
                            password: (!f.password.is_empty()).then(|| f.password.clone()),
                            protocol: redis::ProtocolVersion::RESP2,
                        }),
                    },
                }
            }
            Err(parse_err) => {
                if is_bare_redis_address(trim_space(&cfg.url)) {
                    let db_override = silo_config::config::normalize_redis_db(&cfg.db)
                        .ok()
                        .filter(|s| !s.is_empty())
                        .and_then(|s| s.parse().ok());
                    bare_address_connector(trim_space(&cfg.url), db_override)
                } else {
                    Connector::AlwaysFails(parse_err)
                }
            }
        }
    }

    /// Whether this connector follows a Sentinel-monitored master rather than one fixed address.
    pub fn is_sentinel(&self) -> bool {
        matches!(self, Connector::Sentinel { .. })
    }

    /// Resolves the current address (asking Sentinel, for a Sentinel connector) and returns a fresh
    /// [`redis::Client`] for it. Call this again after a Sentinel connection goes silent or breaks,
    /// the way go-redis's `FailoverClient` re-asks Sentinel on every new dial.
    pub async fn client(&self) -> Result<redis::Client, Error> {
        match self {
            Connector::Single(info) => Ok(redis::Client::open((**info).clone())?),
            Connector::Sentinel {
                sentinel_addrs,
                master_name,
                node,
            } => {
                let mut infos = Vec::with_capacity(sentinel_addrs.len());
                for addr in sentinel_addrs {
                    let (host, port) = silo_config::gonet::split_host_port(addr).map_err(|e| {
                        Error::Config(format!("invalid sentinel address {addr:?}: {e}"))
                    })?;
                    let port: u16 = port
                        .parse()
                        .map_err(|_| Error::Config(format!("invalid sentinel port {addr:?}")))?;
                    infos.push((host, port));
                }
                let mut sentinel = Sentinel::build(infos)?;
                Ok(sentinel.async_master_for(master_name, Some(node)).await?)
            }
            Connector::AlwaysFails(message) => Err(Error::Config(message.clone())),
        }
    }

    /// The database number this connector selects, for channel scoping (`silo_core::redis::channel`).
    pub fn database(&self) -> i64 {
        match self {
            Connector::Single(info) => info.redis.db,
            Connector::Sentinel { node, .. } => {
                node.redis_connection_info.as_ref().map_or(0, |i| i.db)
            }
            Connector::AlwaysFails(_) => 0,
        }
    }
}

/// `NewRedisClient`/`NewRedisClientForRole`: a multiplexed connection for ordinary command use.
/// `role` is accepted for parity with Go's call sites (`internal/telemetry` labels pool-pressure
/// metrics by it); this crate does not yet wire Prometheus, so it is otherwise unused here.
pub async fn connect(cfg: &RedisConfig, _role: &str) -> Result<MultiplexedConnection, Error> {
    let connector = Connector::from_config(cfg);
    let client = connector.client().await?;
    Ok(client.get_multiplexed_async_connection().await?)
}
