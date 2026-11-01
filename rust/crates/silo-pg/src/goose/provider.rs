//! Port of goose's `Provider` for Postgres, including `internal/gooseutil.UpVersions` and the
//! Postgres session locker.

use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use silo_gocompat::time::GoTime;
use tokio_postgres::types::{FromSql, Type};

use super::parser::{Direction, ParsedSql, parse_all};
use crate::{Error, Pool, Session};

type BoxError = Box<dyn StdError + Send + Sync>;

/// The future a Go-style migration function returns.
pub type GoFuture<'a> = Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + 'a>>;

/// What a Go-style migration runs against, which also decides its transaction handling.
#[derive(Clone, Copy)]
pub enum GoFunc {
    /// goose's `RunTx`: the session has an open transaction that also records the version.
    Tx(for<'a> fn(&'a mut Session) -> GoFuture<'a>),
    /// goose's `RunDB`: the function takes its own connections, and the version is recorded after
    /// it returns.
    Db(for<'a> fn(&'a Pool) -> GoFuture<'a>),
}

/// A migration's body.
pub enum MigrationKind {
    /// A goose SQL file. It is parsed when it first runs.
    Sql {
        contents: &'static str,
        parsed: OnceLock<ParsedSql>,
    },
    /// A migration written in code.
    Go { up: GoFunc, down: GoFunc },
}

/// One migration.
pub struct Migration {
    pub version: i64,
    /// The file name for SQL migrations, and goose's `Source` for Go ones.
    pub source: String,
    pub kind: MigrationKind,
}

impl Migration {
    /// An SQL migration from file contents.
    pub fn sql(version: i64, source: impl Into<String>, contents: &'static str) -> Self {
        Self {
            version,
            source: source.into(),
            kind: MigrationKind::Sql {
                contents,
                parsed: OnceLock::new(),
            },
        }
    }

    /// A migration written in code.
    pub fn go(version: i64, source: impl Into<String>, up: GoFunc, down: GoFunc) -> Self {
        Self {
            version,
            source: source.into(),
            kind: MigrationKind::Go { up, down },
        }
    }

    fn type_name(&self) -> &'static str {
        match self.kind {
            MigrationKind::Sql { .. } => "sql",
            MigrationKind::Go { .. } => "go",
        }
    }

    fn parsed(&self) -> Result<Option<&ParsedSql>, ProviderError> {
        match &self.kind {
            MigrationKind::Go { .. } => Ok(None),
            MigrationKind::Sql { contents, parsed } => {
                if let Some(done) = parsed.get() {
                    return Ok(Some(done));
                }
                let value = parse_all(&self.source, contents).map_err(|err| {
                    ProviderError::Other(format!(
                        "failed to prepare migration {}: {err}",
                        self.reference()
                    ))
                })?;
                Ok(Some(parsed.get_or_init(|| value)))
            }
        }
    }

    // Migration.ref()
    fn reference(&self) -> String {
        format!("type:{},version:{}", self.type_name(), self.version)
    }
}

/// A hook that runs on the locked session before each locked operation.
pub type SessionHook = Arc<dyn for<'a> Fn(&'a mut Session) -> GoFuture<'a> + Send + Sync>;

/// Provider settings.
pub struct ProviderConfig {
    /// The version table, such as `public.goose_db_version`.
    pub table: String,
    /// The session advisory lock ID.
    pub lock_id: i64,
    /// Out-of-order applies. The server turns this on.
    pub allow_missing: bool,
    /// Runs right after the lock is taken. If it fails, the lock is released.
    pub after_lock: Option<SessionHook>,
}

/// A migration's state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationState {
    Pending,
    Applied,
}

impl MigrationState {
    /// goose's state text.
    pub fn as_str(self) -> &'static str {
        match self {
            MigrationState::Pending => "pending",
            MigrationState::Applied => "applied",
        }
    }
}

/// One migration's status.
#[derive(Clone, Debug)]
pub struct MigrationStatus {
    pub version: i64,
    pub source: String,
    pub state: MigrationState,
    pub applied_at: Option<GoTime>,
}

/// One migration's outcome.
#[derive(Clone, Debug)]
pub struct MigrationResult {
    pub version: i64,
    pub source: String,
    pub direction: Direction,
    pub duration: Duration,
}

/// A provider failure. The messages follow goose's.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("version not found")]
    VersionNotFound,
    #[error("version {0}: migration already applied")]
    AlreadyApplied(i64),
    #[error("version {0}: migration not applied")]
    NotApplied(i64),
    #[error("version must be greater than 0")]
    InvalidVersion,
    #[error("missing zero version migration")]
    MissingZeroVersion,
    #[error("partial migration error (type:{type_name},version:{version}): {cause}")]
    Partial {
        applied: Vec<MigrationResult>,
        type_name: &'static str,
        version: i64,
        cause: BoxError,
    },
    #[error("failed to initialize: {0}")]
    Initialize(BoxError),
    #[error("{0}")]
    Db(#[from] Error),
    #[error("{0}")]
    Other(String),
}

/// A Postgres `timestamp` read without a time zone, which pgx reads as UTC.
struct Timestamp(GoTime);

impl<'a> FromSql<'a> for Timestamp {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        const POSTGRES_EPOCH_UNIX: i64 = 946_684_800;
        let micros = i64::from_be_bytes(raw.try_into()?);
        let secs = micros.div_euclid(1_000_000) + POSTGRES_EPOCH_UNIX;
        let nanos = u32::try_from(micros.rem_euclid(1_000_000) * 1000)?;
        Ok(Timestamp(GoTime::from_unix(secs, nanos)))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::TIMESTAMP
    }
}

/// A goose provider over a pool.
pub struct Provider {
    pool: Pool,
    config: ProviderConfig,
    migrations: Vec<Migration>,
    version_table_checked: AtomicBool,
    mu: tokio::sync::Mutex<()>,
}

// A pinned connection, and whether it holds the session lock. Dropping one that still holds the
// lock, which a cancelled future does, must not hand the lock back to the pool.
struct Held {
    session: Session,
    locked: bool,
}

impl Drop for Held {
    fn drop(&mut self) {
        if self.locked {
            self.session.mark_unreusable();
        }
    }
}

impl Provider {
    /// Builds a provider. Migrations are sorted by version, and a repeated version is an error.
    pub fn new(
        pool: Pool,
        config: ProviderConfig,
        mut migrations: Vec<Migration>,
    ) -> Result<Self, ProviderError> {
        if migrations.is_empty() {
            return Err(ProviderError::Other("no migrations found".to_string()));
        }
        migrations.sort_by_key(|m| m.version);
        for pair in migrations.windows(2) {
            if pair[0].version == pair[1].version {
                return Err(ProviderError::Other(format!(
                    "found duplicate migration version {}:\n\texisting:{}\n\tcurrent:{}",
                    pair[0].version, pair[0].source, pair[1].source
                )));
            }
        }
        Ok(Self {
            pool,
            config,
            migrations,
            version_table_checked: AtomicBool::new(false),
            mu: tokio::sync::Mutex::new(()),
        })
    }

    /// The migrations, by ascending version.
    pub fn migrations(&self) -> &[Migration] {
        &self.migrations
    }

    /// `Provider.Status`: every migration's state, by ascending version. Takes the lock.
    pub async fn status(&self) -> Result<Vec<MigrationStatus>, ProviderError> {
        let _serial = self.mu.lock().await;
        let mut held = self
            .initialize(true)
            .await
            .map_err(ProviderError::Initialize)?;
        let result = self.status_on(&mut held.session).await;
        finish(result, self.cleanup(held).await)
    }

    async fn status_on(
        &self,
        session: &mut Session,
    ) -> Result<Vec<MigrationStatus>, ProviderError> {
        let mut status = Vec::with_capacity(self.migrations.len());
        for m in &self.migrations {
            let applied_at = self.get_migration(session, m.version).await?;
            status.push(MigrationStatus {
                version: m.version,
                source: m.source.clone(),
                state: if applied_at.is_some() {
                    MigrationState::Applied
                } else {
                    MigrationState::Pending
                },
                applied_at,
            });
        }
        Ok(status)
    }

    /// `Provider.HasPending`: whether anything is left to apply. Does not take the lock.
    pub async fn has_pending(&self) -> Result<bool, ProviderError> {
        let _serial = self.mu.lock().await;
        let mut held = self
            .initialize(false)
            .await
            .map_err(ProviderError::Initialize)?;
        let result = async {
            let db_versions = self.list_versions(&mut held.session).await?;
            let apply = up_versions(
                &self.fs_versions(),
                &db_versions,
                i64::MAX,
                self.config.allow_missing,
            )?;
            Ok(!apply.is_empty())
        }
        .await;
        finish(result, self.cleanup(held).await)
    }

    /// `Provider.ApplyVersion`: applies or rolls back exactly one migration under the lock.
    pub async fn apply_version(
        &self,
        version: i64,
        up: bool,
    ) -> Result<MigrationResult, ProviderError> {
        if version < 1 {
            return Err(ProviderError::InvalidVersion);
        }
        let m = self.find(version)?;
        let _serial = self.mu.lock().await;
        let mut held = self
            .initialize(true)
            .await
            .map_err(ProviderError::Initialize)?;
        let result = async {
            let found = self.get_migration(&mut held.session, version).await?;
            if up && found.is_some() {
                return Err(ProviderError::AlreadyApplied(version));
            }
            if !up && found.is_none() {
                return Err(ProviderError::NotApplied(version));
            }
            let direction = if up { Direction::Up } else { Direction::Down };
            let mut results = self
                .run_migrations(&mut held.session, &[m], direction)
                .await?;
            results.pop().ok_or_else(|| {
                ProviderError::Other("no migration result from an apply".to_string())
            })
        }
        .await;
        finish(result, self.cleanup(held).await)
    }

    /// `Provider.UpTo`: applies pending migrations up to and including `version`.
    pub async fn up_to(&self, version: i64) -> Result<Vec<MigrationResult>, ProviderError> {
        if !self.has_pending().await? {
            return Ok(Vec::new());
        }
        if version < 1 {
            return Err(ProviderError::InvalidVersion);
        }
        let _serial = self.mu.lock().await;
        let mut held = self
            .initialize(true)
            .await
            .map_err(ProviderError::Initialize)?;
        let result = async {
            let db_versions = self.list_versions(&mut held.session).await?;
            if db_versions.is_empty() {
                return Err(ProviderError::MissingZeroVersion);
            }
            let versions = up_versions(
                &self.fs_versions(),
                &db_versions,
                version,
                self.config.allow_missing,
            )?;
            let mut apply = Vec::with_capacity(versions.len());
            for v in versions {
                apply.push(self.find(v)?);
            }
            self.run_migrations(&mut held.session, &apply, Direction::Up)
                .await
        }
        .await;
        finish(result, self.cleanup(held).await)
    }

    /// `Provider.DownTo`: rolls back in application order, newest first, stopping at the first
    /// recorded version at or below `version`.
    pub async fn down_to(&self, version: i64) -> Result<Vec<MigrationResult>, ProviderError> {
        if version < 0 {
            return Err(ProviderError::Other(format!(
                "invalid version: must be a valid number or zero: {version}"
            )));
        }
        let _serial = self.mu.lock().await;
        let mut held = self
            .initialize(true)
            .await
            .map_err(ProviderError::Initialize)?;
        let result = async {
            let db_versions = self.list_versions(&mut held.session).await?;
            let Some(first) = db_versions.first() else {
                return Err(ProviderError::MissingZeroVersion);
            };
            // goose never migrates the zero version down.
            if *first == 0 {
                return Ok(Vec::new());
            }
            let mut apply = Vec::new();
            for db_version in db_versions {
                if db_version <= version {
                    break;
                }
                apply.push(self.find(db_version)?);
            }
            self.run_migrations(&mut held.session, &apply, Direction::Down)
                .await
        }
        .await;
        finish(result, self.cleanup(held).await)
    }

    fn find(&self, version: i64) -> Result<&Migration, ProviderError> {
        self.migrations
            .iter()
            .find(|m| m.version == version)
            .ok_or(ProviderError::VersionNotFound)
    }

    fn fs_versions(&self) -> Vec<i64> {
        self.migrations.iter().map(|m| m.version).collect()
    }

    async fn initialize(&self, use_locker: bool) -> Result<Held, BoxError> {
        let session = self.pool.acquire().await?;
        let mut held = Held {
            session,
            locked: false,
        };
        if use_locker {
            self.session_lock(&mut held.session).await?;
            held.locked = true;
            if let Some(hook) = &self.config.after_lock
                && let Err(err) = hook(&mut held.session).await
            {
                let unlock = self.session_unlock(&mut held.session).await;
                if unlock.is_ok() {
                    held.locked = false;
                }
                return Err(err);
            }
        }
        if !self.version_table_checked.swap(true, Ordering::AcqRel)
            && let Err(err) = self.try_ensure_version_table(&mut held.session).await
        {
            let unlock = self.cleanup(held).await;
            return Err(match unlock {
                Ok(()) => err,
                Err(unlock) => format!("{err}; {unlock}").into(),
            });
        }
        Ok(held)
    }

    async fn cleanup(&self, mut held: Held) -> Result<(), ProviderError> {
        if held.locked {
            self.session_unlock(&mut held.session).await?;
            held.locked = false;
        }
        Ok(())
    }

    // lock.postgresSessionLocker.SessionLock: 60 retries, five seconds apart.
    async fn session_lock(&self, session: &mut Session) -> Result<(), BoxError> {
        let mut retries = 60;
        loop {
            let row = session
                .query_one("SELECT pg_try_advisory_lock($1)", &[&self.config.lock_id])
                .await
                .map_err(|e| format!("failed to execute pg_try_advisory_lock: {e}"))?;
            let locked: bool = row.try_get(0)?;
            if locked {
                return Ok(());
            }
            if retries == 0 {
                return Err("failed to acquire lock".into());
            }
            retries -= 1;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    // lock.postgresSessionLocker.SessionUnlock: 30 retries, two seconds apart.
    async fn session_unlock(&self, session: &mut Session) -> Result<(), ProviderError> {
        let mut retries = 30;
        loop {
            let row = session
                .query_one("SELECT pg_advisory_unlock($1)", &[&self.config.lock_id])
                .await
                .map_err(|e| {
                    ProviderError::Other(format!("failed to execute pg_advisory_unlock: {e}"))
                })?;
            let unlocked: bool = row
                .try_get(0)
                .map_err(|e| ProviderError::Db(Error::Pg(e)))?;
            if unlocked {
                return Ok(());
            }
            if retries == 0 {
                return Err(ProviderError::Other("failed to unlock session".to_string()));
            }
            retries -= 1;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    // tryEnsureVersionTable: three retries, a second apart, in case another instance is creating it.
    async fn try_ensure_version_table(&self, session: &mut Session) -> Result<(), BoxError> {
        let (schema, table) = match self.config.table.split_once('.') {
            Some((schema, table)) => (Some(schema), table),
            None => (None, self.config.table.as_str()),
        };
        let exists_sql = match schema {
            Some(schema) => format!(
                "SELECT EXISTS ( SELECT 1 FROM pg_tables WHERE schemaname = '{schema}' AND tablename = '{table}' )"
            ),
            None => format!(
                "SELECT EXISTS ( SELECT 1 FROM pg_tables WHERE (current_schema() IS NULL OR schemaname = current_schema()) AND tablename = '{table}' )"
            ),
        };
        let create_sql = format!(
            "CREATE TABLE {} (
		id integer PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
		version_id bigint NOT NULL,
		is_applied boolean NOT NULL,
		tstamp timestamp NOT NULL DEFAULT now()
	)",
            self.config.table
        );
        let mut retries = 3;
        loop {
            let row = session
                .query_one(&exists_sql, &[])
                .await
                .map_err(|e| format!("check if version table exists: {e}"))?;
            let exists: bool = row.try_get(0)?;
            if exists {
                return Ok(());
            }
            let attempt = async {
                let mut tx = session.begin().await?;
                tx.execute(&create_sql, &[]).await?;
                self.insert_version(&mut tx, 0).await?;
                tx.commit().await?;
                Ok::<(), ProviderError>(())
            }
            .await;
            match attempt {
                Ok(()) => return Ok(()),
                Err(err) if retries == 0 => {
                    return Err(format!("create version table: {err}").into());
                }
                Err(_) => {
                    retries -= 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn get_migration(
        &self,
        session: &mut Session,
        version: i64,
    ) -> Result<Option<GoTime>, ProviderError> {
        let sql = format!(
            "SELECT tstamp, is_applied FROM {} WHERE version_id=$1 ORDER BY tstamp DESC LIMIT 1",
            self.config.table
        );
        let rows = session
            .query(&sql, &[&version])
            .await
            .map_err(|e| ProviderError::Other(format!("failed to get migration {version}: {e}")))?;
        match rows.first() {
            None => Ok(None),
            Some(row) => {
                let at: Timestamp = row.try_get(0).map_err(|e| {
                    ProviderError::Other(format!("failed to get migration {version}: {e}"))
                })?;
                Ok(Some(at.0))
            }
        }
    }

    // goose's list keeps every row, newest first. It ignores is_applied.
    async fn list_versions(&self, session: &mut Session) -> Result<Vec<i64>, ProviderError> {
        let sql = format!(
            "SELECT version_id, is_applied from {} ORDER BY id DESC",
            self.config.table
        );
        let rows = session
            .query(&sql, &[])
            .await
            .map_err(|e| ProviderError::Other(format!("failed to list migrations: {e}")))?;
        rows.iter()
            .map(|row| {
                row.try_get(0).map_err(|e| {
                    ProviderError::Other(format!("failed to scan list migrations result: {e}"))
                })
            })
            .collect()
    }

    async fn insert_version(
        &self,
        session: &mut Session,
        version: i64,
    ) -> Result<(), ProviderError> {
        let sql = format!(
            "INSERT INTO {} (version_id, is_applied) VALUES ($1, $2)",
            self.config.table
        );
        session
            .execute(&sql, &[&version, &true])
            .await
            .map_err(|e| {
                ProviderError::Other(format!("failed to insert version {version}: {e}"))
            })?;
        Ok(())
    }

    async fn delete_version(
        &self,
        session: &mut Session,
        version: i64,
    ) -> Result<(), ProviderError> {
        let sql = format!("DELETE FROM {} WHERE version_id=$1", self.config.table);
        session.execute(&sql, &[&version]).await.map_err(|e| {
            ProviderError::Other(format!("failed to delete version {version}: {e}"))
        })?;
        Ok(())
    }

    async fn record(
        &self,
        session: &mut Session,
        version: i64,
        direction: Direction,
    ) -> Result<(), ProviderError> {
        match direction {
            Direction::Up => self.insert_version(session, version).await,
            Direction::Down => self.delete_version(session, version).await,
        }
    }

    async fn run_migrations(
        &self,
        session: &mut Session,
        apply: &[&Migration],
        direction: Direction,
    ) -> Result<Vec<MigrationResult>, ProviderError> {
        // Parsed first, so a broken file fails before anything has run.
        for m in apply {
            m.parsed()?;
        }
        let mut results = Vec::with_capacity(apply.len());
        for m in apply {
            let start = Instant::now();
            if let Err(cause) = self.run_individually(session, m, direction).await {
                return Err(ProviderError::Partial {
                    applied: results,
                    type_name: m.type_name(),
                    version: m.version,
                    cause,
                });
            }
            results.push(MigrationResult {
                version: m.version,
                source: m.source.clone(),
                direction,
                duration: start.elapsed(),
            });
        }
        Ok(results)
    }

    async fn run_individually(
        &self,
        session: &mut Session,
        m: &Migration,
        direction: Direction,
    ) -> Result<(), BoxError> {
        match &m.kind {
            MigrationKind::Sql { .. } => {
                let parsed = m.parsed()?.ok_or("sql migration has no parsed form")?;
                let statements = match direction {
                    Direction::Up => &parsed.up,
                    Direction::Down => &parsed.down,
                };
                if parsed.use_tx {
                    let mut tx = session.begin().await?;
                    let outcome = async {
                        for statement in statements {
                            tx.batch_execute(statement).await?;
                        }
                        self.record(&mut tx, m.version, direction).await?;
                        Ok::<(), BoxError>(())
                    }
                    .await;
                    return finish_tx(tx, outcome).await;
                }
                for statement in statements {
                    session.batch_execute(statement).await?;
                }
                self.record(session, m.version, direction).await?;
                Ok(())
            }
            MigrationKind::Go { up, down } => {
                let func = match direction {
                    Direction::Up => up,
                    Direction::Down => down,
                };
                match func {
                    GoFunc::Tx(run) => {
                        let mut tx = session.begin().await?;
                        let outcome = async {
                            run(&mut tx).await?;
                            self.record(&mut tx, m.version, direction).await?;
                            Ok::<(), BoxError>(())
                        }
                        .await;
                        finish_tx(tx, outcome).await
                    }
                    // RunDB gets the pool, not the locked connection, and the version is recorded
                    // through the pool too.
                    GoFunc::Db(run) => {
                        run(&self.pool).await?;
                        let mut other = self.pool.acquire().await?;
                        self.record(&mut other, m.version, direction).await?;
                        Ok(())
                    }
                }
            }
        }
    }
}

async fn finish_tx(tx: crate::Tx<'_>, outcome: Result<(), BoxError>) -> Result<(), BoxError> {
    match outcome {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(err) => match tx.rollback().await {
            Ok(()) => Err(err),
            Err(rollback) => Err(format!("{err}; {rollback}").into()),
        },
    }
}

// multierr.Append(result, cleanup)
fn finish<T>(
    result: Result<T, ProviderError>,
    cleanup: Result<(), ProviderError>,
) -> Result<T, ProviderError> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), Ok(())) | (Ok(_), Err(err)) => Err(err),
        (Err(err), Err(cleanup)) => Err(ProviderError::Other(format!("{err}; {cleanup}"))),
    }
}

/// `gooseutil.UpVersions`.
fn up_versions(
    fsys: &[i64],
    db: &[i64],
    target: i64,
    allow_missing: bool,
) -> Result<Vec<i64>, ProviderError> {
    let applied: std::collections::HashSet<i64> = db.iter().copied().collect();
    let db_max = db.iter().copied().max().unwrap_or(0).max(0);
    let mut sorted = fsys.to_vec();
    sorted.sort_unstable();
    let missing: Vec<i64> = sorted
        .iter()
        .copied()
        .filter(|v| !applied.contains(v) && *v < db_max && *v <= target)
        .collect();
    if !missing.is_empty() && !allow_missing {
        return Err(ProviderError::Other(missing_error(
            &missing, db_max, target,
        )));
    }
    let mut out = missing;
    out.extend(
        sorted
            .iter()
            .copied()
            .filter(|v| !applied.contains(v) && *v > db_max && *v <= target),
    );
    out.sort_unstable();
    Ok(out)
}

fn missing_error(missing: &[i64], db_max: i64, target: i64) -> String {
    let joined = missing
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let (noun, versions) = if missing.len() > 1 {
        ("migrations", format!("versions {joined}"))
    } else {
        ("migration", format!("version {joined}"))
    };
    let mut desired = format!("database version ({db_max})");
    if target != i64::MAX {
        desired.push_str(&format!(", with target version ({target})"));
    }
    format!(
        "detected {} missing (out-of-order) {noun} lower than {desired}: {versions}",
        missing.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Out-of-order applies run older unapplied versions first, in version order. Versions recorded in
    // the database with no source (the legacy gaps) are tolerated.
    #[test]
    fn up_versions_follows_gooseutil() {
        let fs = [1, 2, 3, 4, 5, 6];
        let got = up_versions(&fs, &[0, 1, 4, 99], i64::MAX, true).unwrap();
        assert_eq!(got, vec![2, 3, 5, 6]);
        let got = up_versions(&fs, &[0, 1, 4], 5, true).unwrap();
        assert_eq!(got, vec![2, 3, 5]);
        let err = up_versions(&fs, &[0, 1, 4], i64::MAX, false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "detected 2 missing (out-of-order) migrations lower than database version (4): versions 2,3"
        );
    }
}
