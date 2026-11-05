//! Database-only plugin catalog configuration and repositories from `internal/plugins`.
use std::time::SystemTime;

use silo_pg::{Error as PgError, Pool, Row};

const INCLUDE: &str = "plugins.include_approved_community_plugins";
const MIGRATED: &str = "plugins.approved_community_migrated_plugin_count";

#[derive(Debug)]
pub enum Error {
    Database(PgError),
    Changed(bool),
}
impl From<PgError> for Error {
    fn from(error: PgError) -> Self {
        Self::Database(error)
    }
}

impl From<silo_pg::DriverError> for Error {
    fn from(error: silo_pg::DriverError) -> Self {
        Self::Database(PgError::from(error))
    }
}

fn include_from_rows(rows: &[Row]) -> Result<bool, PgError> {
    let Some(row) = rows.first() else {
        return Ok(false);
    };
    let value: String = row.try_get(0)?;
    Ok(matches!(
        silo_gocompat::strings::trim_space(&value),
        "1" | "t" | "T" | "TRUE" | "true" | "True"
    ))
}

pub async fn get_settings(pool: &Pool) -> Result<bool, Error> {
    let include = include_from_rows(&pool.query(READ_SETTING, &[&INCLUDE]).await?)?;
    // Go reads these status fields even for the configuration-only response.
    let rows = pool
        .query(COUNT_INSTALLED, &[&"approved_community"])
        .await?;
    let _: i64 = rows[0].try_get(0)?;
    let rows = pool.query(READ_SETTING, &[&MIGRATED]).await?;
    if let Some(row) = rows.first() {
        let _: String = row.try_get(0)?;
    }
    Ok(include)
}

pub async fn set_include_conditional(
    pool: &Pool,
    include: bool,
    expected: Option<bool>,
) -> Result<bool, Error> {
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;
    tx.execute(SEED_SETTING, &[&INCLUDE]).await?;
    let current = include_from_rows(&tx.query(LOCK_SETTING, &[&INCLUDE]).await?)?;
    if expected.is_some_and(|expected| expected != current) {
        return Err(Error::Changed(current));
    }
    tx.execute(WRITE_SETTING, &[&INCLUDE, &include.to_string()])
        .await?;
    for (key, url, name, source) in [
        (
            "official",
            "https://raw.githubusercontent.com/Silo-Server/silo-plugins/main/manifest.json",
            "Silo maintained",
            "silo",
        ),
        (
            "approved-community",
            "https://raw.githubusercontent.com/Silo-Community/silo-plugins/main/manifest.json",
            "Approved community",
            "approved_community",
        ),
    ] {
        let rows = tx.query(REPOSITORY_EXISTS, &[&url]).await?;
        let _: bool = rows[0].try_get(0)?;
        let enabled = key == "official" || include;
        tx.execute(
            RECONCILE_REPOSITORY,
            &[&url, &name, &enabled, &key, &source],
        )
        .await?;
    }
    tx.commit().await?;
    get_settings(pool).await
}

pub struct Repository {
    pub id: i64,
    pub url: String,
    pub display_name: String,
    pub enabled: bool,
    pub managed_key: Option<String>,
    pub source_kind: String,
    pub last_fetched_at: Option<SystemTime>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

pub async fn list_repositories(pool: &Pool) -> Result<Vec<Repository>, Error> {
    pool.query(LIST_REPOSITORIES, &[])
        .await?
        .iter()
        .map(|row| {
            Ok(Repository {
                id: row.try_get(0)?,
                url: row.try_get(1)?,
                display_name: row.try_get(2)?,
                enabled: row.try_get(3)?,
                managed_key: row.try_get(4)?,
                source_kind: row.try_get(5)?,
                last_fetched_at: row.try_get(6)?,
                created_at: row.try_get(7)?,
                updated_at: row.try_get(8)?,
            })
        })
        .collect()
}

const COUNT_INSTALLED: &str = r#"
		SELECT COUNT(*)
		FROM plugin_installations AS installation
		JOIN plugin_repositories AS repository ON repository.id = installation.repository_id
		WHERE repository.source_kind = $1
	"#;

const SEED_SETTING: &str =
    r#"INSERT INTO server_settings (key,value) VALUES ($1,'false') ON CONFLICT (key) DO NOTHING"#;

const WRITE_SETTING: &str = r#"
		INSERT INTO server_settings (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	"#;

const READ_SETTING: &str = r#"SELECT value FROM server_settings WHERE key = $1"#;

const LOCK_SETTING: &str = r#"SELECT value FROM server_settings WHERE key = $1 FOR UPDATE"#;

const REPOSITORY_EXISTS: &str =
    r#"SELECT EXISTS (SELECT 1 FROM plugin_repositories WHERE url = $1)"#;

const RECONCILE_REPOSITORY: &str = r#"
			INSERT INTO plugin_repositories (url, display_name, enabled, managed_key, source_kind)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (url) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				enabled = EXCLUDED.enabled,
				managed_key = EXCLUDED.managed_key,
				source_kind = EXCLUDED.source_kind,
				updated_at = NOW()
		"#;

const LIST_REPOSITORIES: &str = "SELECT id, url, display_name, enabled, managed_key, source_kind, last_fetched_at, created_at, updated_at FROM plugin_repositories ORDER BY id ASC";
