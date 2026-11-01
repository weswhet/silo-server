//! The Rust side of the migrator's exit gate, mirroring the Go harness in
//! `rust/conformance/vectors/generators/migrate`.
//!
//!     migrate up | up-to VERSION | apply VERSION | down-to VERSION | status
//!
//! `DATABASE_URL` names the database.

use silo_contracts::migrate::{
    format_migration_statuses, migrate_down_to, migration_statuses, new_provider, run_migrations,
};
use silo_pg::{Pool, PoolConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or_default();
    let version = || -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(args.get(2).ok_or("missing version")?.parse()?)
    };
    let mut config = PoolConfig::parse(&std::env::var("DATABASE_URL")?)?;
    config.max_conns = 20;
    let pool = Pool::connect(config).await?;
    match command {
        "up" => run_migrations(&pool).await?,
        "up-to" => {
            new_provider(pool.clone())?.up_to(version()?).await?;
        }
        "apply" => {
            new_provider(pool.clone())?
                .apply_version(version()?, true)
                .await?;
        }
        "down-to" => {
            migrate_down_to(&pool, version()?).await?;
        }
        "status" => print!(
            "{}",
            format_migration_statuses(&migration_statuses(&pool).await?)
        ),
        other => return Err(format!("unknown command {other:?}").into()),
    }
    Ok(())
}
