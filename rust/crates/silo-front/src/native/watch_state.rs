//! Watched-state commands: v2 `markWatched`, `unmarkWatched`, and `clearResumePosition` over
//! `handlers.ItemsHandler.ClearResumePosition` (`watch_state_service.go`), `lookupWatchedTarget`
//! (`items.go`), and `PostgresUserStore.ClearResumePosition` (`userstore/pgstore/progress.go`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

mod completion;
mod ebook;

use silo_gate::mw::auth::get_profile_id;
use silo_gocompat::strings::trim_space;
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_pg::{AnyInt, PgText};
use silo_store::catalog::access::{AccessFilter, ensure_accessible};

use super::auth::{ApiError, service_problem};
use super::chain::{Stack, V2Class, write_problem};
use super::interest;
use super::personal::{access_of, publish_state, user_of, validation};
use super::settings::{api, mark_profile_stale};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "DELETE", "/api/v2/progress/{media_item_id}/position"),
    NativeRow::new(ApiV2, "POST", "/api/v2/watched/{id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/watched/{id}"),
];

const INTERNAL: &str = "internal_error";

/// `watchedTarget`: the target's type and, for a season or episode, its series.
struct Target {
    kind: String,
    series: String,
}

enum Lookup {
    Found(Target),
    NotFound,
}

/// `lookupWatchedTarget`. Any other item type is not found.
async fn lookup_target(s: &Stack, content: &str, filter: &AccessFilter) -> Result<Lookup, String> {
    let rows = s
        .pool
        .query(
            "SELECT type FROM media_items WHERE content_id = $1",
            &[&content],
        )
        .await
        .map_err(|e| e.to_string())?;
    if let Some(row) = rows.first() {
        let kind: String = row.try_get(0).map_err(|e| e.to_string())?;
        if !ensure_accessible(&s.pool, content, filter).await? {
            return Ok(Lookup::NotFound);
        }
        return Ok(match kind.as_str() {
            "movie" | "audiobook" | "ebook" | "series" => Lookup::Found(Target {
                kind,
                series: String::new(),
            }),
            _ => Lookup::NotFound,
        });
    }
    for (table, kind) in [("seasons", "season"), ("episodes", "episode")] {
        let rows = s
            .pool
            .query(
                &format!("SELECT series_id FROM {table} WHERE content_id = $1"),
                &[&content],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = rows.first() else {
            continue;
        };
        let series: Option<String> = row.try_get(0).map_err(|e| e.to_string())?;
        let series = series.unwrap_or_default();
        if !ensure_accessible(&s.pool, &series, filter).await? {
            return Ok(Lookup::NotFound);
        }
        return Ok(Lookup::Found(Target {
            kind: kind.to_owned(),
            series,
        }));
    }
    Ok(Lookup::NotFound)
}

/// `PostgresUserStore.ClearResumePosition`.
const CLEAR_RESUME_POSITION: &str = "
		UPDATE user_watch_progress
		SET position_seconds = 0,
			updated_at = GREATEST($4::timestamptz, updated_at, event_at),
			event_at = GREATEST($4::timestamptz, event_at)
		WHERE user_id = $1 AND profile_id = $2 AND media_item_id = $3
		  AND position_seconds > 0
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = user_watch_progress.user_id
			  AND hhi.profile_id = user_watch_progress.profile_id
			  AND hhi.media_item_id = user_watch_progress.media_item_id
			  AND user_watch_progress.updated_at <= hhi.hidden_before
		  )";

/// `ItemsHandler.ClearResumePosition`.
async fn clear_resume_position(
    s: &Stack,
    r: &Request,
    user: i64,
    profile: &str,
    content: &str,
) -> Result<(), ApiError> {
    let not_found = || api(404, "not_found", "Item not found");
    if content.contains('\0') {
        return Err(not_found());
    }
    let target = match lookup_target(s, content, &access_of(r)).await {
        Ok(Lookup::Found(target)) => target,
        Ok(Lookup::NotFound) => return Err(not_found()),
        Err(e) => {
            tracing::error!(component = "api", content_id = content, error = %e, "clear resume position: lookup failed");
            return Err(api(500, INTERNAL, "Failed to clear resume position"));
        }
    };
    if target.kind == "audiobook" {
        return Err(not_found());
    }
    if target.kind != "movie" && target.kind != "episode" {
        return Err(api(
            400,
            "invalid_watch_target",
            "Only a movie or an episode has a resume position",
        ));
    }
    let cleared = s
        .pool
        .execute(
            CLEAR_RESUME_POSITION,
            &[&AnyInt(user), &profile, &content, &SystemTime::now()],
        )
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to clear resume position"))?;
    if cleared == 0 {
        return Ok(());
    }
    interest::queue_item(user, profile, content);
    mark_profile_stale(s, user, profile).await;
    publish_state(
        s,
        user,
        profile,
        content,
        &target.series,
        "progress",
        None,
        None,
        None,
    )
    .await;
    Ok(())
}

/// Registers the watched-state commands.
pub fn mount(stack: &Arc<Stack>, v2: &Mux) {
    for (method, played) in [("POST", true), ("DELETE", false)] {
        let path = "/api/v2/watched/{id}";
        let st = stack.clone();
        let handler = stack.v2(
            path,
            V2Class::ProfileScoped,
            handler_fn(move |w, r| {
                let s = st.clone();
                Box::pin(async move {
                    match set_watched(&s, r, played).await {
                        Ok(()) => w.write_header(204).await,
                        Err(e) => write_problem(w, r, service_problem(&e)).await,
                    }
                })
            }),
        );
        if method == "POST" {
            v2.post(path, handler);
        } else {
            v2.delete(path, handler);
        }
    }

    let path = "/api/v2/progress/{media_item_id}/position";
    let st = stack.clone();
    v2.delete(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            handler_fn(move |w, r| {
                let s = st.clone();
                Box::pin(async move {
                    let item = r.url_param("media_item_id").to_owned();
                    match clear_resume_position(&s, r, user_of(r), &get_profile_id(r), &item).await
                    {
                        Ok(()) => w.write_header(204).await,
                        // `watchTargetProblem`: a target without a resume position fails validation
                        // of the path parameter.
                        Err(e) if e.code == "invalid_watch_target" => {
                            write_problem(w, r, validation("path.media_item_id", &e.message)).await
                        }
                        Err(e) => write_problem(w, r, service_problem(&e)).await,
                    }
                })
            }),
        ),
    );
}

const MARK_BATCH: &str = r#"
		WITH target(media_item_id, duration_seconds, event_at) AS (
			SELECT * FROM unnest($3::text[], $4::double precision[], $6::timestamptz[])
		),
		visible AS (
			SELECT
				t.media_item_id,
				t.duration_seconds,
				t.event_at,
				CASE
					WHEN hhi.hidden_before IS NOT NULL AND $5::timestamptz <= hhi.hidden_before
					THEN hhi.hidden_before + interval '1 second'
					ELSE $5::timestamptz
				END AS updated_at
			FROM target t
			LEFT JOIN user_history_hidden_items hhi
			  ON hhi.user_id = $1
			 AND hhi.profile_id = $2
			 AND hhi.media_item_id = t.media_item_id
		)
		INSERT INTO user_watch_progress
			(user_id, profile_id, media_item_id, position_seconds, duration_seconds, completed, updated_at, event_at)
		SELECT $1, $2, media_item_id, 0, duration_seconds, TRUE, updated_at, COALESCE(event_at, updated_at)
		FROM visible
 ORDER BY media_item_id
		ON CONFLICT (user_id, profile_id, media_item_id) DO UPDATE SET
			position_seconds = 0,
			-- Keep a known duration when the caller has none: jellycompat's
			-- series mark-played passes 0 for every target, and its previous
			-- MarkProgressBatch path left duration_seconds untouched.
			duration_seconds = CASE
				WHEN EXCLUDED.duration_seconds > 0 THEN EXCLUDED.duration_seconds
				ELSE user_watch_progress.duration_seconds
			END,
			completed = TRUE,
			updated_at = EXCLUDED.updated_at,
			event_at = EXCLUDED.event_at
 WHERE NOT user_watch_progress.completed
  OR (user_watch_progress.position_seconds > 0 AND user_watch_progress.media_item_id = ANY($7::text[]))
  OR EXISTS (
  SELECT 1 FROM user_history_hidden_items hhi
  WHERE hhi.user_id = user_watch_progress.user_id AND hhi.profile_id = user_watch_progress.profile_id
  AND hhi.media_item_id = user_watch_progress.media_item_id AND user_watch_progress.updated_at <= hhi.hidden_before
 )
 RETURNING media_item_id"#;

const HISTORY_BATCH: &str = r#"
			WITH entry(id, media_item_id, watched_at, duration_seconds, completed, source, watch_identity, ord) AS (
				SELECT * FROM unnest(
					$3::text[], $4::text[], $5::timestamptz[], $6::double precision[],
					$7::boolean[], $8::text[], $9::jsonb[]
				) WITH ORDINALITY
			)
			INSERT INTO user_watch_history
				(id, user_id, profile_id, media_item_id, watched_at, duration_seconds, completed, source, watch_identity)
			SELECT
				e.id, $1, $2, e.media_item_id,
				CASE
					WHEN hhi.hidden_before IS NOT NULL AND e.watched_at <= hhi.hidden_before
					THEN hhi.hidden_before + interval '1 second'
					ELSE e.watched_at
				END,
				e.duration_seconds, e.completed, e.source, e.watch_identity
			FROM entry e
			LEFT JOIN user_history_hidden_items hhi
			  ON hhi.user_id = $1
			 AND hhi.profile_id = $2
			 AND hhi.media_item_id = e.media_item_id
			WHERE e.media_item_id = ANY($10::text[])
			ORDER BY e.ord
			RETURNING id, media_item_id, watched_at"#;

const RAISE_CUTOFF: &str = r#"
		WITH target(media_item_id) AS (
			SELECT unnest($3::text[])
		),
		watermark AS (
			SELECT
				t.media_item_id,
				GREATEST($4::timestamptz, COALESCE(MAX(h.watched_at), $4::timestamptz)) AS hidden_before
			FROM target t
			LEFT JOIN user_watch_history h
			  ON h.user_id = $1
			 AND h.profile_id = $2
			 AND h.media_item_id = t.media_item_id
			GROUP BY t.media_item_id
		)
		INSERT INTO user_history_hidden_items (user_id, profile_id, media_item_id, hidden_before, removed_before, updated_at)
		SELECT $1, $2, media_item_id, hidden_before,
			CASE WHEN $5::boolean THEN hidden_before ELSE '-infinity'::timestamptz END, $4
		FROM watermark
		ON CONFLICT (user_id, profile_id, media_item_id) DO UPDATE SET
			hidden_before = GREATEST(user_history_hidden_items.hidden_before, EXCLUDED.hidden_before),
			removed_before = GREATEST(
				COALESCE(user_history_hidden_items.removed_before, user_history_hidden_items.hidden_before),
				EXCLUDED.removed_before),
			updated_at = EXCLUDED.updated_at
	"#;

const DELETE_PROGRESS: &str = r#"
		DELETE FROM user_watch_progress
		WHERE user_id = $1
		  AND profile_id = $2
		  AND media_item_id = ANY($3::text[])
	"#;

const LOCK_CUTOFF: &str =
    r#"SELECT pg_advisory_xact_lock($1::integer, hashtext('imported-history:' || $2))"#;

const LIST_PROGRESS: &str = r#"
		SELECT profile_id, media_item_id, position_seconds, duration_seconds, completed, updated_at,
		       last_file_id, last_resolution, last_hdr, last_codec_video, last_edition_key
		FROM user_watch_progress
		WHERE user_id = $1 AND profile_id = $2 AND media_item_id = ANY($3::text[])
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = user_watch_progress.user_id
			  AND hhi.profile_id = user_watch_progress.profile_id
			  AND hhi.media_item_id = user_watch_progress.media_item_id
			  AND user_watch_progress.updated_at <= hhi.hidden_before
		  )"#;

const LATEST_HISTORY: &str = r#"
 SELECT DISTINCT ON (g.key) g.key, latest.id
 FROM jsonb_each($3::jsonb) g
 CROSS JOIN LATERAL jsonb_array_elements_text(g.value) member(media_item_id)
 CROSS JOIN LATERAL (
  SELECT h.id, date_trunc('second', h.watched_at AT TIME ZONE 'UTC') AS watched_second
  FROM user_watch_history h
  WHERE h.user_id = $1 AND h.profile_id = $2 AND h.media_item_id = member.media_item_id
   AND h.watched_at > COALESCE((
    SELECT COALESCE(hidden.removed_before, hidden.hidden_before) FROM user_history_hidden_items hidden
    WHERE hidden.user_id = h.user_id AND hidden.profile_id = h.profile_id
     AND hidden.media_item_id = h.media_item_id
   ), '-infinity'::timestamptz)
  ORDER BY date_trunc('second', h.watched_at AT TIME ZONE 'UTC') DESC, h.id DESC
  LIMIT 1
 ) latest
 ORDER BY g.key, latest.watched_second DESC, latest.id DESC"#;

const LIST_SERIES: &str = r#"SELECT content_id, series_id, season_id, season_number, episode_number,
	title, default_metadata_language, overview, air_date, runtime,
	rating_imdb, rating_tmdb,
	imdb_id, tmdb_id, tvdb_id,
	still_path, still_source_path, still_thumbhash,
	metadata_s3_path, metadata_etag, metadata_source,
	created_at, updated_at
		FROM episodes
		WHERE series_id = $1
		  AND EXISTS (
		SELECT 1
		FROM episode_libraries el
		WHERE el.episode_id = episodes.content_id
	)
		ORDER BY season_number ASC, episode_number ASC"#;

const LIST_SEASON: &str = r#"SELECT content_id, series_id, season_id, season_number, episode_number,
	title, default_metadata_language, overview, air_date, runtime,
	rating_imdb, rating_tmdb,
	imdb_id, tmdb_id, tvdb_id,
	still_path, still_source_path, still_thumbhash,
	metadata_s3_path, metadata_etag, metadata_source,
	created_at, updated_at
		FROM episodes
		WHERE season_id = $1
		  AND EXISTS (
		SELECT 1
		FROM episode_libraries el
		WHERE el.episode_id = episodes.content_id
	)
		ORDER BY episode_number ASC"#;

const PARTITION_SERIES: &str = r#"SELECT content_id, EXISTS (
		SELECT 1
		FROM episode_libraries el
		WHERE el.episode_id = episodes.content_id
	) FROM episodes
		WHERE series_id = $1
		ORDER BY season_number ASC, episode_number ASC"#;

const PARTITION_SEASON: &str = r#"SELECT content_id, EXISTS (
		SELECT 1
		FROM episode_libraries el
		WHERE el.episode_id = episodes.content_id
	) FROM episodes
		WHERE season_id = $1
		ORDER BY season_number ASC, episode_number ASC"#;

const GET_EPISODE: &str = r#"SELECT content_id, series_id, season_id, season_number, episode_number,
	title, default_metadata_language, overview, air_date, runtime,
	rating_imdb, rating_tmdb,
	imdb_id, tmdb_id, tvdb_id,
	still_path, still_source_path, still_thumbhash,
	metadata_s3_path, metadata_etag, metadata_source,
	created_at, updated_at
		FROM episodes
		WHERE content_id = $1"#;

const GET_EPISODES: &str = r#"SELECT content_id, series_id, season_id, season_number, episode_number,
	title, default_metadata_language, overview, air_date, runtime,
	rating_imdb, rating_tmdb,
	imdb_id, tmdb_id, tvdb_id,
	still_path, still_source_path, still_thumbhash,
	metadata_s3_path, metadata_etag, metadata_source,
	created_at, updated_at FROM episodes WHERE content_id = ANY($1)"#;

const GET_ITEM: &str = r#"SELECT content_id, type, title, sort_title, default_metadata_language, original_title, year, genres, content_rating, runtime, overview, tagline, rating_imdb, rating_tmdb, rating_rt_critic, rating_rt_audience, imdb_id, tmdb_id, tvdb_id, COALESCE(poster_path, '') AS poster_path, COALESCE(poster_source_path, '') AS poster_source_path, COALESCE(poster_thumbhash, '') AS poster_thumbhash, COALESCE(backdrop_path, '') AS backdrop_path, COALESCE(backdrop_source_path, '') AS backdrop_source_path, COALESCE(backdrop_thumbhash, '') AS backdrop_thumbhash, COALESCE(logo_path, '') AS logo_path, COALESCE(logo_source_path, '') AS logo_source_path, banner_path, banner_source_path, banner_thumbhash, thumb_path, thumb_source_path, thumb_thumbhash, clearart_path, clearart_source_path, disc_path, disc_source_path, COALESCE(metadata_s3_path, '') AS metadata_s3_path, COALESCE(metadata_etag, '') AS metadata_etag, season_count, studios, networks, countries, keywords, original_language, release_date::text, first_air_date, last_air_date, air_time, air_timezone, show_status, matched_at, last_refreshed, refresh_failures, episode_metadata_incomplete, episode_metadata_last_checked_at, locked_fields, status, created_at, updated_at, advisory_age, COALESCE(advisory_source, '') AS advisory_source FROM media_items WHERE content_id = $1"#;

const GET_FILES: &str = r#"SELECT id, content_id, episode_id, extra_id, season_number, episode_number,
	media_folder_id, canonical_root_path, observed_root_path, content_group_key, group_key_version,
	base_title, base_year, base_type, identity_confidence, identity_json,
	file_path, file_size, file_modified_at, file_hash,
	codec_video, codec_audio, resolution, audio_channels, hdr, container,
	duration, bitrate, video_tracks, audio_tracks, subtitle_tracks, external_subtitles, chapters, marker_thumbnails,
	chapter_thumbnail_retry_after, chapter_thumbnail_failure_count, chapter_thumbnail_last_error,
	intro_start, intro_end, credits_start, credits_end, recap_start, recap_end, preview_start, preview_end, marker_segments, markers_source, markers_confidence,
	intro_markers_source, intro_markers_provider, intro_markers_confidence, intro_markers_algorithm, intro_markers_detected_at,
	credits_markers_source, credits_markers_provider, credits_markers_confidence, credits_markers_algorithm, credits_markers_detected_at,
	recap_markers_source, recap_markers_provider, recap_markers_confidence, recap_markers_algorithm, recap_markers_detected_at,
	preview_markers_source, preview_markers_provider, preview_markers_confidence, preview_markers_algorithm, preview_markers_detected_at,
	edition_raw, edition_key, edition_confidence, edition_source,
	presentation_kind, presentation_group_key, presentation_part_index, presentation_part_total,
	multi_episode_start, multi_episode_end,
	multiple_pps, multiple_pps_scan_size, multiple_pps_scan_mtime,
	probe_source, probe_updated_at, probe_failed_at, match_attempted_at, missing_since,
	first_seen_scan_run_id, created_at, updated_at FROM media_files
		WHERE content_id = $1 AND missing_since IS NULL
		ORDER BY id ASC"#;

const EPISODE_FILES: &str = r#"SELECT served.episode_id, mf.id, mf.content_id, mf.episode_id, mf.extra_id, mf.season_number, mf.episode_number,
	mf.media_folder_id, mf.canonical_root_path, mf.observed_root_path, mf.content_group_key, mf.group_key_version,
	mf.base_title, mf.base_year, mf.base_type, mf.identity_confidence, mf.identity_json,
	mf.file_path, mf.file_size, mf.file_modified_at, mf.file_hash,
	mf.codec_video, mf.codec_audio, mf.resolution, mf.audio_channels, mf.hdr, mf.container,
	mf.duration, mf.bitrate, mf.video_tracks, mf.audio_tracks, mf.subtitle_tracks, mf.external_subtitles, mf.chapters, mf.marker_thumbnails,
	mf.chapter_thumbnail_retry_after, mf.chapter_thumbnail_failure_count, mf.chapter_thumbnail_last_error,
	mf.intro_start, mf.intro_end, mf.credits_start, mf.credits_end, mf.recap_start, mf.recap_end, mf.preview_start, mf.preview_end, mf.marker_segments, mf.markers_source, mf.markers_confidence,
	mf.intro_markers_source, mf.intro_markers_provider, mf.intro_markers_confidence, mf.intro_markers_algorithm, mf.intro_markers_detected_at,
	mf.credits_markers_source, mf.credits_markers_provider, mf.credits_markers_confidence, mf.credits_markers_algorithm, mf.credits_markers_detected_at,
	mf.recap_markers_source, mf.recap_markers_provider, mf.recap_markers_confidence, mf.recap_markers_algorithm, mf.recap_markers_detected_at,
	mf.preview_markers_source, mf.preview_markers_provider, mf.preview_markers_confidence, mf.preview_markers_algorithm, mf.preview_markers_detected_at,
	mf.edition_raw, mf.edition_key, mf.edition_confidence, mf.edition_source,
	mf.presentation_kind, mf.presentation_group_key, mf.presentation_part_index, mf.presentation_part_total,
	mf.multi_episode_start, mf.multi_episode_end,
	mf.multiple_pps, mf.multiple_pps_scan_size, mf.multiple_pps_scan_mtime,
	mf.probe_source, mf.probe_updated_at, mf.probe_failed_at, mf.match_attempted_at, mf.missing_since,
	mf.first_seen_scan_run_id, mf.created_at, mf.updated_at
		FROM (
	SELECT mf.episode_id, mf.id
	FROM media_files mf
	WHERE mf.episode_id = ANY($1::text[])
	  AND mf.missing_since IS NULL
	UNION
	SELECT covered.content_id, mf.id
	FROM episodes covered
	JOIN episodes first ON first.series_id = covered.series_id
	     AND first.season_number = covered.season_number
	     AND first.episode_number BETWEEN covered.episode_number - 10 AND covered.episode_number - 1
	JOIN media_files mf ON mf.episode_id = first.content_id
	     AND mf.missing_since IS NULL
	     AND mf.multi_episode_end > mf.multi_episode_start
	     AND covered.episode_number BETWEEN mf.multi_episode_start AND mf.multi_episode_end
	WHERE covered.content_id = ANY($1::text[])) served(episode_id, file_id)
		JOIN media_files mf ON mf.id = served.file_id
		ORDER BY served.episode_id ASC, mf.id ASC"#;

const PROVIDER_IDS: &str = r#"
		SELECT content_id, item_type, provider, provider_id, created_at, updated_at
		FROM media_item_provider_ids
		WHERE content_id = ANY($1)
		ORDER BY content_id,
			CASE LOWER(provider)
				WHEN 'tmdb' THEN 0
				WHEN 'tvdb' THEN 1
				WHEN 'imdb' THEN 2
				ELSE 3
			END,
			LOWER(provider) ASC,
			provider_id ASC
	"#;

#[derive(Clone)]
struct Leaf {
    id: String,
    duration: f64,
}

fn failed(e: impl std::fmt::Display) -> String {
    e.to_string()
}

async fn progress(
    s: &Stack,
    user: i64,
    profile: &str,
    ids: &[String],
) -> Result<HashMap<String, (bool, f64)>, String> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = s
        .pool
        .query(LIST_PROGRESS, &[&AnyInt(user), &profile, &ids])
        .await
        .map_err(failed)?;
    rows.into_iter()
        .map(|r| {
            Ok((
                r.try_get(1).map_err(failed)?,
                (r.try_get(4).map_err(failed)?, r.try_get(2).map_err(failed)?),
            ))
        })
        .collect()
}

async fn parent_unwatch(
    s: &Stack,
    user: i64,
    profile: &str,
    id: &str,
    kind: &str,
) -> Result<Vec<Leaf>, String> {
    let rows = s
        .pool
        .query(
            if kind == "series" {
                PARTITION_SERIES
            } else {
                PARTITION_SEASON
            },
            &[&id],
        )
        .await
        .map_err(failed)?;
    let (mut available, mut fileless) = (Vec::new(), Vec::new());
    for row in rows {
        let id: String = row.try_get(0).map_err(failed)?;
        if row.try_get::<_, bool>(1).map_err(failed)? {
            available.push(id);
        } else {
            fileless.push(id);
        }
    }
    for batch in fileless.chunks(1000) {
        let groups: serde_json::Value = batch
            .iter()
            .map(|id| (id.clone(), serde_json::json!([id])))
            .collect();
        let groups = groups.to_string();
        let rows = s
            .pool
            .query(LATEST_HISTORY, &[&AnyInt(user), &profile, &PgText(&groups)])
            .await
            .map_err(failed)?;
        let history: HashSet<String> = rows.iter().map(|r| r.get(0)).collect();
        let p = progress(s, user, profile, batch).await?;
        available.extend(
            batch
                .iter()
                .filter(|id| history.contains(*id) || p.contains_key(*id))
                .cloned(),
        );
    }
    Ok(available
        .into_iter()
        .map(|id| Leaf { id, duration: 0.0 })
        .collect())
}

fn runtime(row: &silo_pg::Row) -> f64 {
    row.get::<_, Option<AnyInt>>("runtime")
        .map_or(0.0, |v| v.0.max(0) as f64 * 60.0)
}

#[allow(clippy::too_many_arguments)]
async fn leaf_targets(
    s: &Stack,
    user: i64,
    profile: &str,
    content: &str,
    target: &Target,
    played: bool,
    filter: &AccessFilter,
    quality: &str,
) -> Result<Vec<Leaf>, String> {
    if target.kind == "series" || target.kind == "season" {
        if !played {
            return parent_unwatch(s, user, profile, content, &target.kind).await;
        }
        let rows = s
            .pool
            .query(
                if target.kind == "series" {
                    LIST_SERIES
                } else {
                    LIST_SEASON
                },
                &[&content],
            )
            .await
            .map_err(failed)?;
        let ids: Vec<String> = rows.iter().map(|r| r.get("content_id")).collect();
        let files = if ids.is_empty() {
            Vec::new()
        } else {
            s.pool
                .query(EPISODE_FILES, &[&ids])
                .await
                .unwrap_or_default()
        };
        return Ok(rows
            .iter()
            .map(|row| {
                let id: String = row.get("content_id");
                let duration = files
                    .iter()
                    .find_map(|file| {
                        let served: String = file.get(0);
                        let linked: Option<String> = file.get(3);
                        let duration = file.get::<_, Option<AnyInt>>("duration").map_or(0, |v| v.0);
                        (served == id && linked.as_deref() == Some(&id) && duration > 0)
                            .then_some(duration as f64)
                    })
                    .unwrap_or_else(|| runtime(row));
                Leaf { id, duration }
            })
            .collect());
    }
    if target.kind == "ebook" || (target.kind == "audiobook" && !played) {
        return Ok(vec![Leaf {
            id: content.to_owned(),
            duration: 0.0,
        }]);
    }
    let episode = target.kind == "episode";
    let rows = s
        .pool
        .query(if episode { GET_EPISODE } else { GET_ITEM }, &[&content])
        .await
        .map_err(failed)?;
    let fallback = rows.first().map_or(0.0, runtime);
    let files = if episode {
        s.pool
            .query(EPISODE_FILES, &[&vec![content.to_owned()]])
            .await
    } else {
        s.pool.query(GET_FILES, &[&content]).await
    };
    let files = if target.kind == "audiobook" {
        files.map_err(failed)?
    } else {
        files.unwrap_or_default()
    };
    let mut duration = 0.0;
    if target.kind == "audiobook" {
        let mut copies: HashMap<(i64, String), i64> = HashMap::new();
        for file in files {
            let folder = file.get::<_, AnyInt>("media_folder_id").0;
            let resolution: Option<String> = file.get("resolution");
            let rank =
                match silo_gocompat::strings::to_upper(trim_space(&resolution.unwrap_or_default()))
                    .as_str()
                {
                    "480P" => 1,
                    "720P" => 2,
                    "1080P" => 3,
                    "2160P" => 4,
                    "4320P" => 5,
                    _ => 0,
                };
            let ceiling = match trim_space(quality) {
                "1080p" => 3,
                "2160p" => 4,
                _ => i32::MAX,
            };
            if filter
                .allowed
                .as_ref()
                .is_some_and(|ids| !ids.contains(&(folder as i32)))
                || filter.disabled.contains(&(folder as i32))
                || rank > ceiling
            {
                continue;
            }
            let d = file.get::<_, Option<AnyInt>>("duration").map_or(0, |v| v.0);
            if d <= 0 {
                continue;
            }
            let root: String = file.get("canonical_root_path");
            let sum = copies.entry((folder, root)).or_default();
            *sum += d;
            duration = f64::max(duration, *sum as f64);
        }
    } else {
        for file in files {
            let d = file.get::<_, Option<AnyInt>>("duration").map_or(0, |v| v.0);
            let linked: Option<String> = if episode {
                file.get(3)
            } else {
                file.get("episode_id")
            };
            if d > 0 && (!episode || linked.as_deref() == Some(content)) {
                duration = d as f64;
                break;
            }
        }
    }
    Ok(vec![Leaf {
        id: content.to_owned(),
        duration: if duration > 0.0 { duration } else { fallback },
    }])
}

async fn identities(s: &Stack, ids: &[String]) -> HashMap<String, serde_json::Value> {
    let mut result = HashMap::new();
    let episodes = match s.pool.query(GET_EPISODES, &[&ids]).await {
        Ok(rows) => rows,
        Err(_) => {
            let mut rows = Vec::new();
            for id in ids {
                if let Ok(found) = s.pool.query(GET_EPISODE, &[id]).await {
                    rows.extend(found);
                }
            }
            rows
        }
    };
    let episode_map: HashMap<String, &silo_pg::Row> =
        episodes.iter().map(|r| (r.get("content_id"), r)).collect();
    let mut provider_targets: Vec<String> = episodes.iter().map(|r| r.get("series_id")).collect();
    provider_targets.extend(
        ids.iter()
            .filter(|id| !episode_map.contains_key(*id))
            .cloned(),
    );
    provider_targets.sort();
    provider_targets.dedup();
    let provider_rows = if provider_targets.is_empty() {
        Vec::new()
    } else {
        match s.pool.query(PROVIDER_IDS, &[&provider_targets]).await {
            Ok(rows) => rows,
            Err(_) => {
                let mut rows = Vec::new();
                for id in &provider_targets {
                    if let Ok(found) = s.pool.query(PROVIDER_ID, &[id]).await {
                        rows.extend(found);
                    }
                }
                rows
            }
        }
    };
    let mut providers: HashMap<String, serde_json::Map<String, serde_json::Value>> = HashMap::new();
    for row in provider_rows {
        let provider: String = row.get("provider");
        let value: String = row.get("provider_id");
        if !trim_space(&provider).is_empty() && !trim_space(&value).is_empty() {
            providers.entry(row.get("content_id")).or_default().insert(
                trim_space(&provider).to_owned(),
                serde_json::json!(trim_space(&value)),
            );
        }
    }
    for id in ids {
        if let Some(row) = episode_map.get(id) {
            let mut own = serde_json::Map::new();
            for (column, key) in [
                ("imdb_id", "imdb"),
                ("tmdb_id", "tmdb"),
                ("tvdb_id", "tvdb"),
            ] {
                if let Some(value) = row
                    .get::<_, Option<String>>(column)
                    .filter(|v| !trim_space(v).is_empty())
                {
                    own.insert(key.to_owned(), serde_json::json!(trim_space(&value)));
                }
            }
            let series: String = row.get("series_id");
            let parent = providers.get(&series).cloned().unwrap_or_default();
            if own.is_empty() && parent.is_empty() {
                continue;
            }
            let mut identity = serde_json::json!({"stable_type":"episode","season":row.get::<_,i32>("season_number"),"episode":row.get::<_,i32>("episode_number")});
            if !own.is_empty() {
                identity["provider_ids"] = own.into();
            }
            if !parent.is_empty() {
                identity["series_provider_ids"] = parent.into();
            }
            result.insert(id.clone(), identity);
        } else if let Some(provider) = providers.get(id).filter(|p| !p.is_empty())
            && let Ok(rows) = s.pool.query(GET_ITEM, &[id]).await
            && rows
                .first()
                .is_some_and(|r| r.get::<_, String>("type") == "movie")
        {
            result.insert(
                id.clone(),
                serde_json::json!({"stable_type":"movie","provider_ids":provider}),
            );
        }
    }
    result
}

fn needs_mark(current: Option<&(bool, f64)>, rewatch: bool) -> bool {
    current.is_none_or(|(completed, position)| !completed || (rewatch && *position > 0.0))
}

async fn mark_watched(
    s: &Stack,
    user: i64,
    profile: &str,
    mut targets: Vec<Leaf>,
    rewatch: bool,
) -> Result<(), String> {
    let watched_at = SystemTime::UNIX_EPOCH
        + Duration::from_secs(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    let ids: Vec<String> = targets.iter().map(|t| t.id.clone()).collect();
    let current = progress(s, user, profile, &ids).await?;
    targets.retain(|t| needs_mark(current.get(&t.id), rewatch));
    // The transactional store compacts IDs before constructing its target arrays.
    let mut seen = HashSet::new();
    targets = targets
        .into_iter()
        .filter_map(|mut target| {
            target.id = trim_space(&target.id).to_owned();
            (!target.id.is_empty() && seen.insert(target.id.clone())).then_some(target)
        })
        .collect();
    if targets.is_empty() {
        return Ok(());
    }
    let ids: Vec<String> = targets.iter().map(|t| t.id.clone()).collect();
    let identities = identities(s, &ids).await;
    let durations: Vec<f64> = targets.iter().map(|t| t.duration.max(0.0)).collect();
    let history_ids: Vec<String> = ids
        .iter()
        .map(|_| uuid::Uuid::new_v4().to_string())
        .collect();
    let dates = vec![watched_at; ids.len()];
    let completed = vec![true; ids.len()];
    let sources = vec!["manual"; ids.len()];
    let identity_json: Vec<serde_json::Value> = ids
        .iter()
        .map(|id| {
            identities
                .get(id)
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}))
        })
        .collect();
    let identity_strings: Vec<String> = identity_json.iter().map(ToString::to_string).collect();
    let identity_json: Vec<PgText<'_>> = identity_strings.iter().map(|s| PgText(s)).collect();
    let event_dates: Vec<Option<SystemTime>> = vec![None; ids.len()];
    let rewatch_ids = if rewatch { ids.clone() } else { Vec::new() };
    let mut connection = s.pool.acquire().await.map_err(failed)?;
    let mut tx = connection.begin().await.map_err(failed)?;
    let marked: Vec<String> = tx
        .query(
            MARK_BATCH,
            &[
                &AnyInt(user),
                &profile,
                &ids,
                &durations,
                &SystemTime::now(),
                &event_dates,
                &rewatch_ids,
            ],
        )
        .await
        .map_err(failed)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut written = Vec::new();
    if !marked.is_empty() {
        for row in tx
            .query(
                HISTORY_BATCH,
                &[
                    &AnyInt(user),
                    &profile,
                    &history_ids,
                    &ids,
                    &dates,
                    &durations,
                    &completed,
                    &sources,
                    &identity_json,
                    &marked,
                ],
            )
            .await
            .map_err(failed)?
        {
            written.push(row.get::<_, String>(1));
        }
    }
    tx.commit().await.map_err(failed)?;
    for id in &written {
        interest::queue_item(user, profile, id);
    }
    completion::notify_completed(s, user, profile, &written).await;
    Ok(())
}

async fn unmark_watched(
    s: &Stack,
    user: i64,
    profile: &str,
    targets: Vec<Leaf>,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    let ids: Vec<String> = targets
        .into_iter()
        .map(|t| trim_space(&t.id).to_owned())
        .filter(|id| !id.is_empty() && seen.insert(id.clone()))
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    let now = SystemTime::now();
    let mut connection = s.pool.acquire().await.map_err(failed)?;
    let mut tx = connection.begin().await.map_err(failed)?;
    tx.execute(LOCK_CUTOFF, &[&AnyInt(user), &profile])
        .await
        .map_err(failed)?;
    tx.execute(RAISE_CUTOFF, &[&AnyInt(user), &profile, &ids, &now, &false])
        .await
        .map_err(failed)?;
    tx.execute(DELETE_PROGRESS, &[&AnyInt(user), &profile, &ids])
        .await
        .map_err(failed)?;
    tx.commit().await.map_err(failed)?;
    for id in ids {
        interest::queue_item(user, profile, &id);
    }
    Ok(())
}

async fn set_watched(s: &Stack, r: &Request, played: bool) -> Result<(), ApiError> {
    let content = r.url_param("id");
    let user = user_of(r);
    let profile = get_profile_id(r);
    let filter = access_of(r);
    let not_found = || api(404, "not_found", "Item not found");
    let failure = |e: String| {
        tracing::error!(component="api",content_id=content,error=%e,"update watched state failed");
        api(500, INTERNAL, "Failed to update watched state")
    };
    if content.contains('\0') {
        return Err(not_found());
    }
    let target = match lookup_target(s, content, &filter).await.map_err(failure)? {
        Lookup::Found(t) => t,
        Lookup::NotFound => return Err(not_found()),
    };
    let quality = r
        .extensions
        .get::<Arc<silo_store::access::Scope>>()
        .map_or("", |scope| scope.max_playback_quality.as_str());
    let quality = silo_gate::mw::viewer::normalize_playback_quality(quality);
    let targets = leaf_targets(
        s, user, &profile, content, &target, played, &filter, &quality,
    )
    .await
    .map_err(failure)?;
    if target.kind == "ebook" {
        ebook::set_ebook_read_state(s, user, &profile, content, played, &filter, &quality).await?;
    } else if played {
        mark_watched(
            s,
            user,
            &profile,
            targets,
            matches!(target.kind.as_str(), "movie" | "episode" | "audiobook"),
        )
        .await
        .map_err(failure)?;
    } else {
        unmark_watched(s, user, &profile, targets)
            .await
            .map_err(failure)?;
    }
    mark_profile_stale(s, user, &profile).await;
    publish_state(
        s,
        user,
        &profile,
        content,
        &target.series,
        "watched",
        None,
        None,
        Some(played),
    )
    .await;
    Ok(())
}

const PROVIDER_ID: &str = r#"
		SELECT content_id, item_type, provider, provider_id, created_at, updated_at
		FROM media_item_provider_ids
		WHERE content_id = $1
		ORDER BY
			CASE LOWER(provider)
				WHEN 'tmdb' THEN 0
				WHEN 'tvdb' THEN 1
				WHEN 'imdb' THEN 2
				ELSE 3
			END,
			LOWER(provider) ASC,
			provider_id ASC
	"#;

#[cfg(test)]
mod tests {
    use super::needs_mark;
    #[test]
    fn completed_marks_only_record_a_rewatch_with_resume_progress() {
        assert!(needs_mark(None, false));
        assert!(needs_mark(Some(&(false, 0.0)), false));
        assert!(!needs_mark(Some(&(true, 0.0)), true));
        assert!(!needs_mark(Some(&(true, 12.0)), false));
        assert!(needs_mark(Some(&(true, 12.0)), true));
    }
}
