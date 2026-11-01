//! Postgres access that behaves like the Go server's pgx setup.
//!
//! - [`Pool`] is a deadpool pool whose connections run the per-connection setup Go runs in
//!   `AfterConnect`: JIT off unless something configured it, and the pgvector type lookup.
//! - [`Session`] is a pinned connection. Session advisory locks live on it, and [`Session::hijack`]
//!   detaches it from the pool, like `pgxpool.Conn.Hijack`.
//! - [`ExecMode`] reproduces both pgx exec modes the server uses, because the mode decides whether
//!   Postgres may switch a statement to a generic plan.
//! - [`Vector`] and [`HalfVector`] are the pgvector binary codecs.
//! - [`goose`] is a compatible runner: the statement parser, `goose_db_version` handling, and the
//!   per-migration transaction rules.

mod config;
mod error;
pub mod goose;
mod pool;
mod session;
mod setup;
mod types;

pub use config::{PoolConfig, SslMode};
pub use error::Error;
pub use pool::{Pool, PoolStatus};
pub use session::{ExecMode, Session, Tx};
pub use setup::JIT_OFF;
pub use tokio_postgres::types as pg_types;
pub use tokio_postgres::types::ToSql;
pub use tokio_postgres::{Row, SimpleQueryMessage};
pub use types::{AnyInt, HalfVector, PgText, TextValue, Vector};

/// A parameter list, as the query methods take it.
pub type Params<'a> = &'a [&'a (dyn ToSql + Sync)];
