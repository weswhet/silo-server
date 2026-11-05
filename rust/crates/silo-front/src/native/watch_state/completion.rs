//! `watchlist.Maintainer`: remove completed movies from the watchlist, best effort.

use std::time::Duration;

use silo_pg::{AnyInt, Pool};

use super::super::chain::Stack;
use super::super::interest;

/// `ItemRepository.GetByIDs`, with `itemColumns` expanded exactly as Go renders it.
const ITEMS: &str = r#"SELECT content_id, type, title, sort_title, default_metadata_language, original_title, year, genres, content_rating, runtime, overview, tagline, rating_imdb, rating_tmdb, rating_rt_critic, rating_rt_audience, imdb_id, tmdb_id, tvdb_id, COALESCE(poster_path, '') AS poster_path, COALESCE(poster_source_path, '') AS poster_source_path, COALESCE(poster_thumbhash, '') AS poster_thumbhash, COALESCE(backdrop_path, '') AS backdrop_path, COALESCE(backdrop_source_path, '') AS backdrop_source_path, COALESCE(backdrop_thumbhash, '') AS backdrop_thumbhash, COALESCE(logo_path, '') AS logo_path, COALESCE(logo_source_path, '') AS logo_source_path, banner_path, banner_source_path, banner_thumbhash, thumb_path, thumb_source_path, thumb_thumbhash, clearart_path, clearart_source_path, disc_path, disc_source_path, COALESCE(metadata_s3_path, '') AS metadata_s3_path, COALESCE(metadata_etag, '') AS metadata_etag, season_count, studios, networks, countries, keywords, original_language, release_date::text, first_air_date, last_air_date, air_time, air_timezone, show_status, matched_at, last_refreshed, refresh_failures, episode_metadata_incomplete, episode_metadata_last_checked_at, locked_fields, status, created_at, updated_at, advisory_age, COALESCE(advisory_source, '') AS advisory_source FROM media_items WHERE content_id = ANY($1) ORDER BY content_id ASC"#;

/// `HandleWatchedCompleted` runs independently of the request that recorded the play.
pub(super) async fn notify_completed(s: &Stack, user: i64, profile: &str, ids: &[String]) {
    if user == 0 || profile.is_empty() || ids.is_empty() {
        return;
    }
    let pool = s.pool.clone();
    let profile = profile.to_owned();
    let ids = ids.to_vec();
    tokio::spawn(async move {
        let result = tokio::time::timeout(
            Duration::from_secs(120),
            process(&pool, user, &profile, &ids),
        )
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(component = "watchlist", user_id = user, profile_id = profile, %error, "watchlist auto-remove failed")
            }
            Err(error) => {
                tracing::warn!(component = "watchlist", user_id = user, profile_id = profile, %error, "watchlist auto-remove failed")
            }
        }
    });
}

async fn process(
    pool: &Pool,
    user: i64,
    profile: &str,
    ids: &[String],
) -> Result<(), silo_pg::Error> {
    let settings = pool.query(
        "SELECT remove_watched_from_watchlist FROM user_profiles WHERE user_id = $1 AND id = $2",
        &[&AnyInt(user), &profile],
    ).await?;
    if let Some(row) = settings.first()
        && !row.try_get::<_, bool>(0)?
    {
        return Ok(());
    }
    let rows = pool.query(ITEMS, &[&ids]).await?;
    for row in rows {
        if row.try_get::<_, String>(1)? != "movie" {
            continue;
        }
        let item: String = row.try_get(0)?;
        let changed = pool.execute(
            "DELETE FROM user_watchlist WHERE user_id = $1 AND profile_id = $2 AND media_item_id = $3",
            &[&AnyInt(user), &profile, &item],
        ).await?;
        if changed > 0 {
            interest::queue_item(user, profile, &item);
        }
        // Connected watch providers route this operation to Go before reaching this handler.
    }
    Ok(())
}
