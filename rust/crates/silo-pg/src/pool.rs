use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use deadpool::managed::{self, Metrics, RecycleError, RecycleResult};
use lru::LruCache;
use tokio_postgres::types::Type;
use tokio_postgres::{Client, NoTls, Statement};

use crate::config::{PoolConfig, SslMode};
use crate::error::Error;
use crate::session::{ExecMode, Session};
use crate::setup::{VectorTypes, prepare_connection};
use crate::tls::insecure_connector;

/// One server connection and the state pgx keeps per connection.
pub(crate) struct Conn {
    pub client: Client,
    pub statements: LruCache<String, Statement>,
    pub descriptions: LruCache<String, Arc<Vec<Type>>>,
    pub vector_types: VectorTypes,
    pub default_mode: ExecMode,
    /// Set around each server round trip, so a future dropped mid-query marks the connection unsafe
    /// to reuse. pgx closes a connection whose context ends mid-query.
    pub busy: bool,
    /// Set while a [`crate::Tx`] is open. pgx destroys a connection released in a transaction.
    pub in_tx: bool,
    pub last_used: Instant,
    generation: u64,
}

pub(crate) struct Manager {
    config: PoolConfig,
    generation: Arc<AtomicU64>,
}

impl managed::Manager for Manager {
    type Type = Conn;
    type Error = tokio_postgres::Error;

    async fn create(&self) -> Result<Conn, Self::Error> {
        let client = connect(&self.config).await?;
        let vector_types = prepare_connection(&client).await?;
        Ok(Conn {
            client,
            statements: LruCache::new(capacity(self.config.statement_cache_capacity)),
            descriptions: LruCache::new(capacity(self.config.description_cache_capacity)),
            vector_types,
            default_mode: self.config.default_exec_mode,
            busy: false,
            in_tx: false,
            last_used: Instant::now(),
            generation: self.generation.load(Ordering::Acquire),
        })
    }

    async fn recycle(&self, conn: &mut Conn, metrics: &Metrics) -> RecycleResult<Self::Error> {
        if conn.client.is_closed() {
            return Err(RecycleError::message("connection is closed"));
        }
        if conn.busy {
            return Err(RecycleError::message("connection was left mid-query"));
        }
        if conn.in_tx {
            return Err(RecycleError::message(
                "connection was left in a transaction",
            ));
        }
        if conn.generation != self.generation.load(Ordering::Acquire) {
            return Err(RecycleError::message("pool was reset"));
        }
        if metrics.age() > self.config.max_conn_lifetime {
            return Err(RecycleError::message("connection reached its lifetime"));
        }
        let idle = conn.last_used.elapsed();
        if idle > self.config.max_conn_idle_time {
            return Err(RecycleError::message("connection idled too long"));
        }
        // pgxpool's default ShouldPing.
        if idle > std::time::Duration::from_secs(1) {
            conn.client.simple_query("").await?;
        }
        Ok(())
    }
}

fn capacity(n: usize) -> std::num::NonZeroUsize {
    std::num::NonZeroUsize::new(n.max(1)).expect("at least one")
}

/// pgconn's `connectPreferred` stops trying further configurations on these three server errors:
/// a wrong password, a missing database, or no connect privilege.
fn stops_fallback(err: &tokio_postgres::Error) -> bool {
    use tokio_postgres::error::SqlState;
    err.code().is_some_and(|code| {
        *code == SqlState::INVALID_PASSWORD
            || *code == SqlState::INVALID_CATALOG_NAME
            || *code == SqlState::INSUFFICIENT_PRIVILEGE
    })
}

/// Connects per `config.ssl_mode`, in pgx's `configTLS` order (`pgconn/config.go`):
/// - `disable`: plaintext only.
/// - `require`: TLS only.
/// - `prefer`: TLS, then plaintext if that attempt fails. `sslnegotiation=direct` upgrades this to
///   `require`, because a server cannot decline direct TLS. The startup message goes in the clear
///   only after a TLS attempt failed, as with pgx.
/// - `allow`: plaintext, then TLS if that attempt fails.
///
/// Fallbacks stop on [`stops_fallback`] errors. `verify-ca` and `verify-full` are rejected in
/// [`Pool::new`] before this is ever called.
async fn connect(config: &PoolConfig) -> Result<Client, tokio_postgres::Error> {
    match (config.ssl_mode, config.direct_tls) {
        (SslMode::Disable, _) => connect_plain(config).await,
        (SslMode::Require, _) | (SslMode::Prefer, true) => connect_tls(config).await,
        (SslMode::Prefer, false) => match connect_tls(config).await {
            Err(err) if !stops_fallback(&err) => connect_plain(config).await,
            result => result,
        },
        (SslMode::Allow, _) => match connect_plain(config).await {
            Err(err) if !stops_fallback(&err) => connect_tls(config).await,
            result => result,
        },
        (SslMode::VerifyCa | SslMode::VerifyFull, _) => {
            unreachable!("Pool::new rejects verify-ca and verify-full before connecting")
        }
    }
}

async fn connect_plain(config: &PoolConfig) -> Result<Client, tokio_postgres::Error> {
    let mut cfg = config.pg.clone();
    cfg.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let (client, connection) = cfg.connect(NoTls).await?;
    spawn_connection(connection);
    Ok(client)
}

async fn connect_tls(config: &PoolConfig) -> Result<Client, tokio_postgres::Error> {
    let mut cfg = config.pg.clone();
    cfg.ssl_mode(tokio_postgres::config::SslMode::Require);
    if config.direct_tls {
        cfg.ssl_negotiation(tokio_postgres::config::SslNegotiation::Direct);
    }
    let (client, connection) = cfg.connect(insecure_connector(config.direct_tls)).await?;
    spawn_connection(connection);
    Ok(client)
}

fn spawn_connection<S, T>(connection: tokio_postgres::Connection<S, T>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(error = %err, "postgres connection ended");
        }
    });
}

/// A connection pool.
#[derive(Clone)]
pub struct Pool {
    inner: managed::Pool<Manager>,
    generation: Arc<AtomicU64>,
    config: Arc<PoolConfig>,
}

/// Pool occupancy.
#[derive(Clone, Copy, Debug)]
pub struct PoolStatus {
    pub max_size: usize,
    pub size: usize,
    pub available: usize,
}

impl Pool {
    /// Builds a pool and proves it can connect, like `database.NewPool`.
    pub async fn connect(config: PoolConfig) -> Result<Self, Error> {
        let pool = Self::new(config)?;
        pool.acquire().await?;
        Ok(pool)
    }

    /// Builds a pool without connecting.
    pub fn new(config: PoolConfig) -> Result<Self, Error> {
        match config.ssl_mode {
            SslMode::Disable | SslMode::Allow | SslMode::Prefer | SslMode::Require => {}
            SslMode::VerifyCa | SslMode::VerifyFull => {
                return Err(Error::Config(
                    "verify-ca and verify-full are not implemented yet; sslmode must be disable, \
                     allow, prefer, or require"
                        .to_string(),
                ));
            }
        }
        let generation = Arc::new(AtomicU64::new(0));
        let manager = Manager {
            config: config.clone(),
            generation: Arc::clone(&generation),
        };
        let inner = managed::Pool::builder(manager)
            .max_size(config.max_conns)
            .runtime(deadpool::Runtime::Tokio1)
            .build()
            .map_err(|e| Error::Pool(e.to_string()))?;
        Ok(Self {
            inner,
            generation,
            config: Arc::new(config),
        })
    }

    /// Pins a connection until the session is dropped.
    pub async fn acquire(&self) -> Result<Session, Error> {
        let object = self.inner.get().await.map_err(|err| match err {
            managed::PoolError::Backend(pg) => Error::Pg(pg),
            other => Error::Pool(other.to_string()),
        })?;
        Ok(Session::pooled(object))
    }

    /// Runs one query on a connection from the pool, in the pool's default mode.
    pub async fn query(
        &self,
        sql: &str,
        params: crate::Params<'_>,
    ) -> Result<Vec<tokio_postgres::Row>, Error> {
        self.acquire().await?.query(sql, params).await
    }

    /// Runs one statement on a connection from the pool, in the pool's default mode.
    pub async fn execute(&self, sql: &str, params: crate::Params<'_>) -> Result<u64, Error> {
        self.acquire().await?.execute(sql, params).await
    }

    /// `pgxpool.Pool.Reset`: connections reconnect on their next use, so per-connection setup runs
    /// again. Migrations call this because they can create the vector types.
    pub fn reset(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.inner.retain(|_, _| false);
    }

    /// Closes the pool.
    pub fn close(&self) {
        self.inner.close();
    }

    /// Current occupancy.
    pub fn status(&self) -> PoolStatus {
        let status = self.inner.status();
        PoolStatus {
            max_size: status.max_size,
            size: status.size,
            available: status.available,
        }
    }

    /// The settings this pool was built with.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }
}
