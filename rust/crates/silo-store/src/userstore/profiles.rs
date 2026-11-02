//! `userstore/pgstore/profiles.go`: `GetProfile` and `ListProfiles`, the columns access decisions read.

use silo_pg::{Pool, Row, Session};

use super::pgstore::pg_time_to_string;

/// `userstore.Profile`.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub pin_hash: String,
    pub is_child: bool,
    pub is_primary: bool,
    pub max_content_rating: String,
    pub max_advisory_age: i32,
    pub require_advisory_age: bool,
    pub library_restrictions_enabled: bool,
    pub max_playback_quality: String,
    pub pin_revision: i64,
    pub allowed_library_ids: Vec<i32>,
    pub avatar: String,
    pub quality_preference: String,
    pub auto_skip_intro: bool,
    pub auto_skip_credits: bool,
    pub auto_skip_recap: bool,
    pub auto_play_next_preview: bool,
    pub created_at: String,
    pub updated_at: String,
}

pub(super) const COLUMNS: &str =
    "id, name, COALESCE(pin_hash, ''), is_child, is_primary, COALESCE(max_content_rating, ''),
    COALESCE(max_advisory_age, 0)::int4, require_advisory_age, library_restrictions_enabled,
    COALESCE(max_playback_quality, ''), pin_revision,
    avatar, quality_preference, auto_skip_intro, auto_skip_credits, auto_skip_recap,
    auto_play_next_preview, created_at, updated_at";

pub(super) fn scan(row: &Row) -> Result<Profile, silo_pg::DriverError> {
    Ok(Profile {
        id: row.try_get(0)?,
        name: row.try_get(1)?,
        pin_hash: row.try_get(2)?,
        is_child: row.try_get(3)?,
        is_primary: row.try_get(4)?,
        max_content_rating: row.try_get(5)?,
        max_advisory_age: row.try_get(6)?,
        require_advisory_age: row.try_get(7)?,
        library_restrictions_enabled: row.try_get(8)?,
        max_playback_quality: row.try_get(9)?,
        pin_revision: row.try_get(10)?,
        allowed_library_ids: Vec::new(),
        avatar: row.try_get(11)?,
        quality_preference: row.try_get(12)?,
        auto_skip_intro: row.try_get(13)?,
        auto_skip_credits: row.try_get(14)?,
        auto_skip_recap: row.try_get(15)?,
        auto_play_next_preview: row.try_get(16)?,
        created_at: pg_time_to_string(row.try_get(17)?),
        updated_at: pg_time_to_string(row.try_get(18)?),
    })
}

/// `GetProfile`: `None` when the account has no such profile.
pub async fn get_profile(pool: &Pool, user_id: i64, id: &str) -> Result<Option<Profile>, String> {
    let sql = format!("SELECT {COLUMNS} FROM user_profiles WHERE user_id = $1::bigint AND id = $2");
    let rows = pool
        .query(&sql, &[&user_id, &id])
        .await
        .map_err(|e| format!("querying profile {id}: {e}"))?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let mut profile = scan(row).map_err(|e| format!("querying profile {id}: {e}"))?;
    let rows = pool
        .query(
            "SELECT library_id::int4 FROM user_profile_allowed_libraries WHERE user_id = $1::bigint AND profile_id = $2 ORDER BY library_id",
            &[&user_id, &id],
        )
        .await
        .map_err(|e| format!("listing profile libraries: {e}"))?;
    for row in &rows {
        profile
            .allowed_library_ids
            .push(row.try_get(0).map_err(|e| e.to_string())?);
    }
    Ok(Some(profile))
}

/// `ListProfiles`, without the library lists the household check does not read.
pub async fn list_profiles(pool: &Pool, user_id: i64) -> Result<Vec<Profile>, String> {
    let sql = format!(
        "SELECT {COLUMNS} FROM user_profiles WHERE user_id = $1::bigint ORDER BY created_at ASC"
    );
    let rows = pool
        .query(&sql, &[&user_id])
        .await
        .map_err(|e| format!("listing profiles: {e}"))?;
    rows.iter()
        .map(|row| scan(row).map_err(|e| format!("listing profiles: {e}")))
        .collect()
}

/// `ListProfiles`, with `attachAllowedLibraries`.
pub async fn list_profiles_full(pool: &Pool, user_id: i64) -> Result<Vec<Profile>, String> {
    let mut profiles = list_profiles(pool, user_id).await?;
    if profiles.is_empty() {
        return Ok(profiles);
    }
    let ids: Vec<String> = profiles.iter().map(|p| p.id.clone()).collect();
    let rows = pool
        .query(
            "SELECT profile_id, library_id::int4 FROM user_profile_allowed_libraries
             WHERE user_id = $1::bigint AND profile_id = ANY($2) ORDER BY library_id ASC",
            &[&user_id, &ids],
        )
        .await
        .map_err(|e| format!("listing allowed libraries for user {user_id}: {e}"))?;
    for row in &rows {
        let profile_id: String = row.try_get(0).map_err(|e| e.to_string())?;
        let library: i32 = row.try_get(1).map_err(|e| e.to_string())?;
        if let Some(p) = profiles.iter_mut().find(|p| p.id == profile_id) {
            p.allowed_library_ids.push(library);
        }
    }
    Ok(profiles)
}

/// `getProfile` on an open transaction.
pub async fn get_profile_tx(
    tx: &mut Session,
    user_id: i64,
    id: &str,
) -> Result<Option<Profile>, String> {
    let sql = format!("SELECT {COLUMNS} FROM user_profiles WHERE user_id = $1::bigint AND id = $2");
    let rows = tx
        .query(&sql, &[&user_id, &id])
        .await
        .map_err(|e| format!("querying profile {id}: {e}"))?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let mut profile = scan(row).map_err(|e| format!("querying profile {id}: {e}"))?;
    let rows = tx
        .query(
            "SELECT library_id::int4 FROM user_profile_allowed_libraries WHERE user_id = $1::bigint AND profile_id = $2 ORDER BY library_id",
            &[&user_id, &id],
        )
        .await
        .map_err(|e| format!("listing profile libraries: {e}"))?;
    for row in &rows {
        profile
            .allowed_library_ids
            .push(row.try_get(0).map_err(|e| e.to_string())?);
    }
    Ok(Some(profile))
}
