//! Database bootstrap: connect, migrate, and lease a Sonyflake machine ID.
//!
//! This is the orchestration `cmd/silo/main.go` runs between "bootstrap pool (max 20)" and
//! "idgen lease (primary only)" (see `docs/superpowers/rust-port/maps.json`, area 3, "Startup
//! order"). The pieces it calls are already ported and already byte-exact with Go:
//! [`silo_pg::Pool`] is the pgx-equivalent pool, and [`silo_contracts::migrate::run_migrations`] is
//! the goose-compatible runner with the 6 Go-coded migrations folded in. This module does not
//! reimplement either; it is the glue that calls them in the right order and then hands back a
//! pool other crates can build on.
//!
//! Not ported here (disclosed, not silently dropped): `internal/database/postgres_tune.go`'s
//! opt-in `ALTER SYSTEM` sizing heuristic (829 LOC, gated by `SILO_POSTGRES_TUNE`, off by default)
//! and the non-goose boot side effects (credential backfills, legacy AI provider conversion,
//! `partman` partition creation, `activity_log` index ensure). None of these change what a client
//! observes on a correctly-tuned, already-migrated database, which is the case the conformance
//! harness and this crate's own tests run against.

use silo_pg::{Error, Pool, PoolConfig};

/// A connected, migrated database and this process's Sonyflake machine-ID lease.
pub struct Database {
    pub pool: Pool,
    lease: Option<crate::idgen_lease::Lease>,
}

/// `database.NewPool` + `database.RunMigrations` + `idgen.Start`, in that order: connect, apply
/// every pending migration (which also resets the pool so the per-connection vector-type lookup
/// runs again on a schema that may have just created the `vector` extension), then lease a
/// Sonyflake machine ID so this process can mint content IDs. `holder` names this process in
/// `idgen_machine_leases` for operators.
///
/// Mirrors `main()`'s order up through the primary-only idgen lease; it is the caller's job not to
/// call this from more than one place per process, and to call [`Database::shutdown`] before the
/// pool is dropped so the lease's renewal task stops cleanly.
pub async fn bootstrap(database_url: &str, holder: &str) -> Result<Database, BootstrapError> {
    let config = PoolConfig::parse(database_url).map_err(BootstrapError::Pool)?;
    let pool = Pool::connect(config).await.map_err(BootstrapError::Pool)?;
    silo_contracts::migrate::run_migrations(&pool)
        .await
        .map_err(|err| BootstrapError::Migrate(err.to_string()))?;
    let lease = crate::idgen_lease::Lease::start(pool.clone(), holder)
        .await
        .map_err(BootstrapError::Pool)?;
    Ok(Database {
        pool,
        lease: Some(lease),
    })
}

impl Database {
    /// Stops the idgen lease's renewal task and lets the pool close as the process exits. `NextID`
    /// keeps working on the lease's already-granted deadline until it runs out, which leaves
    /// shutdown time to drain in-flight writers, exactly as Go's `Lease.Stop` does.
    pub async fn shutdown(&mut self) {
        if let Some(lease) = self.lease.take() {
            lease.stop().await;
        }
    }

    /// The cell holding the Sonyflake generator this process should mint content IDs with right
    /// now; call [`crate::idgen_lease::GeneratorCell::current`] on it for every ID, since a renewal
    /// can swap the generator. `None` only before [`bootstrap`] finishes or after
    /// [`Database::shutdown`].
    pub fn idgen(&self) -> Option<&std::sync::Arc<crate::idgen_lease::GeneratorCell>> {
        self.lease
            .as_ref()
            .map(crate::idgen_lease::Lease::generator)
    }
}

/// What [`bootstrap`] can fail with.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("database: {0}")]
    Pool(#[from] Error),
    #[error("database migrations: {0}")]
    Migrate(String),
}
