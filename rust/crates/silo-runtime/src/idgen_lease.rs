//! Leases a Sonyflake machine ID from `idgen_machine_leases`, ported from `internal/idgen/lease.go`.
//!
//! [`silo_core::idgen`] already holds the generator, the bit layout, and the lease SQL text, because
//! those have to match Go byte-for-byte and a database crate was the natural place to keep the
//! queries next to the struct they fill in. This module is the missing piece: the background
//! renewal loop and the claim-then-retry-as-expired fallback that Go's `idgen.Start`/`Lease.run`
//! run on a live pool.

use std::sync::Arc;

use silo_core::idgen::{
    CLAIM_EXPIRED_SQL, CLAIM_LOCK_KEY, CLAIM_UNUSED_SQL, Generator, Instant2, LEASE_TTL,
    RENEW_INTERVAL, RENEW_SQL, REUSE_AFTER,
};
use silo_pg::{Error, Pool};
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;

/// This process's hold on a Sonyflake machine ID. It renews in the background until [`Lease::stop`].
/// `idgen.Lease`.
pub struct Lease {
    generator: Arc<GeneratorCell>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

/// The generator `NextID` should use right now. A renewal that discovers another process took over
/// this machine ID (the lease lapsed before it renewed) claims a fresh one and swaps the pointer;
/// `idgen.active`'s `atomic.Pointer[generator]`, scoped to one lease instead of the whole process so
/// more than one `Lease` can run in one Rust process (a deliberate, disclosed divergence: Go's
/// `idgen.NextID` is a package-level function with one process-wide generator).
pub struct GeneratorCell(Mutex<Arc<Generator>>);

impl GeneratorCell {
    /// The currently active generator.
    pub async fn current(&self) -> Arc<Generator> {
        Arc::clone(&*self.0.lock().await)
    }

    async fn set(&self, generator: Arc<Generator>) {
        *self.0.lock().await = generator;
    }
}

async fn claim(pool: &Pool, token: Uuid, holder: &str) -> Result<Arc<Generator>, Error> {
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&CLAIM_LOCK_KEY])
        .await?;
    // Measured after the lock wait, which can be long when several processes start at once.
    let started = Instant2::now();
    let ttl_secs = LEASE_TTL.as_secs_f64();
    let machine_id: Result<i32, Error> = tx
        .query_one(CLAIM_UNUSED_SQL, &[&token, &holder, &ttl_secs])
        .await
        .and_then(|row| {
            row.try_get(0)
                .map_err(|_| Error::Pool("claiming machine ID: no machine_id column".into()))
        });
    let machine_id = match machine_id {
        Ok(id) => id,
        Err(Error::NoRows) => {
            let reuse_secs = REUSE_AFTER.as_secs_f64();
            tx.query_one(
                CLAIM_EXPIRED_SQL,
                &[&token, &holder, &ttl_secs, &reuse_secs],
            )
            .await
            .and_then(|row| {
                row.try_get(0)
                    .map_err(|_| Error::Pool("claiming machine ID: no machine_id column".into()))
            })
            .map_err(|err| match err {
                Error::NoRows => Error::Pool(
                    "idgen: every Sonyflake machine ID is leased or expired within the last hour"
                        .to_owned(),
                ),
                other => other,
            })?
        }
        Err(other) => return Err(other),
    };
    tx.commit().await?;

    let machine_id = u16::try_from(machine_id)
        .map_err(|_| Error::Pool(format!("idgen: machine ID {machine_id} out of range")))?;
    let generator = Generator::new(machine_id);
    generator.set_valid_until(Some(started.lease_deadline()));
    Ok(Arc::new(generator))
}

async fn renew(
    pool: &Pool,
    token: Uuid,
    holder: &str,
    generator: &Arc<Generator>,
) -> Option<Arc<Generator>> {
    let started = Instant2::now();
    let ttl_secs = LEASE_TTL.as_secs_f64();
    let machine_id = i32::from(generator.machine_id());
    let result = pool
        .execute(RENEW_SQL, &[&machine_id, &token, &ttl_secs])
        .await;
    match result {
        Ok(1) => {
            generator.set_valid_until(Some(started.lease_deadline()));
            None
        }
        Ok(_) => {
            // Another process claimed the machine ID after this lease lapsed. `generator` is
            // already refused past its deadline, so switch to a freshly claimed one.
            tracing::error!(
                machine_id = generator.machine_id(),
                "idgen: machine ID lease was taken over; claiming a new one"
            );
            match claim(pool, token, holder).await {
                Ok(next) => {
                    tracing::info!(
                        machine_id = next.machine_id(),
                        holder,
                        "idgen: leased Sonyflake machine ID"
                    );
                    Some(next)
                }
                Err(err) => {
                    tracing::error!(error = %err, "idgen: claiming a new machine ID failed");
                    None
                }
            }
        }
        Err(err) => {
            tracing::warn!(machine_id = generator.machine_id(), error = %err, "idgen: renewing machine ID lease failed");
            None
        }
    }
}

impl Lease {
    /// Leases a machine ID from `pool`. `holder` names this process in `idgen_machine_leases` for
    /// operators; uniqueness comes from the lease token, not the name. Call it once per pool, after
    /// migrations and before anything generates IDs. `idgen.Start`.
    pub async fn start(pool: Pool, holder: &str) -> Result<Self, Error> {
        let token = Uuid::new_v4();
        let holder = holder.to_owned();
        let generator = claim(&pool, token, &holder).await?;
        tracing::info!(
            machine_id = generator.machine_id(),
            holder,
            "idgen: leased Sonyflake machine ID"
        );
        let cell = Arc::new(GeneratorCell(Mutex::new(generator)));

        let (stop_tx, mut stop_rx) = oneshot::channel();
        let task_cell = Arc::clone(&cell);
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(RENEW_INTERVAL);
            ticker.tick().await; // the first tick fires immediately; skip it, as Go's ticker does not.
            loop {
                tokio::select! {
                    _ = &mut stop_rx => return,
                    _ = ticker.tick() => {
                        let current = task_cell.current().await;
                        if let Some(next) = renew(&pool, token, &holder, &current).await {
                            task_cell.set(next).await;
                        }
                    }
                }
            }
        });

        Ok(Self {
            generator: cell,
            stop_tx: Some(stop_tx),
            task: Some(task),
        })
    }

    /// The generator this process should mint IDs with right now.
    pub fn generator(&self) -> &Arc<GeneratorCell> {
        &self.generator
    }

    /// Ends renewal and waits for the background task to stop. `NextID` keeps working until the
    /// current lease runs out, which leaves shutdown time to drain in-flight writers. `Lease.Stop`.
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
