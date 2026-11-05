//! Marker contribution audit reads and MediaFileAuthorizer's parent/file access checks.
//! No plugin host or remote provider is consulted by the listing.
use crate::catalog::access::{AccessFilter, ensure_accessible};
use silo_pg::Pool;
use std::time::SystemTime;
use uuid::Uuid;

const FILE_SQL: &str = r#"SELECT id, content_id, episode_id, extra_id, season_number, episode_number,
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
	first_seen_scan_run_id, created_at, updated_at FROM media_files WHERE id = $1"#;
const EPISODE_SQL: &str = r#"SELECT content_id, series_id, season_id, season_number, episode_number,
	title, default_metadata_language, overview, air_date, runtime,
	rating_imdb, rating_tmdb,
	imdb_id, tmdb_id, tvdb_id,
	still_path, still_source_path, still_thumbhash,
	metadata_s3_path, metadata_etag, metadata_source,
	created_at, updated_at
		FROM episodes
		WHERE content_id = $1"#;
const EXTRA_SQL: &str = r#"
		SELECT content_id, parent_id, kind, title, sort_order,
			still_path, still_source, still_thumbhash
		FROM media_extras
		WHERE content_id = $1"#;

pub async fn authorize(
    pool: &Pool,
    file_id: i64,
    filter: &AccessFilter,
    quality: &str,
) -> Result<bool, String> {
    // `media_files.id` is bigint.
    let rows = pool
        .query(FILE_SQL, &[&file_id])
        .await
        .map_err(|e| e.to_string())?;
    let Some(row) = rows.first() else {
        return Ok(false);
    };
    let missing: Option<SystemTime> = row.get("missing_since");
    if missing.is_some() {
        return Ok(false);
    }
    let episode: String = row
        .get::<_, Option<String>>("episode_id")
        .unwrap_or_default();
    let content: String = row
        .get::<_, Option<String>>("content_id")
        .unwrap_or_default();
    let extra: String = row.get::<_, Option<String>>("extra_id").unwrap_or_default();
    let parent = if !episode.is_empty() {
        let rows = pool
            .query(EPISODE_SQL, &[&episode])
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = rows.first() else {
            return Ok(false);
        };
        row.get::<_, String>("series_id")
    } else if !content.is_empty() {
        content
    } else if !extra.is_empty() {
        let rows = pool
            .query(EXTRA_SQL, &[&extra])
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = rows.first() else {
            return Ok(false);
        };
        row.get::<_, String>("parent_id")
    } else {
        return Ok(false);
    };
    if !ensure_accessible(pool, &parent, filter).await? {
        return Ok(false);
    }
    let folder: i32 = row.get("media_folder_id");
    let resolution = row
        .get::<_, Option<String>>("resolution")
        .unwrap_or_default();
    Ok(!filter
        .allowed
        .as_ref()
        .is_some_and(|ids| !ids.contains(&folder))
        && !filter.disabled.contains(&folder)
        && quality_allowed(&resolution, quality))
}

fn quality_allowed(file: &str, ceiling: &str) -> bool {
    let normalized = silo_gocompat::strings::to_upper(silo_gocompat::strings::trim_space(ceiling));
    let max = match normalized.as_str() {
        "STANDARD" | "480P" | "720P" | "1080P" => 3,
        "4K" | "UHD" | "2160P" | "4320P" => 4,
        _ => return true,
    };
    let rank =
        match silo_gocompat::strings::to_upper(silo_gocompat::strings::trim_space(file)).as_str() {
            "480P" => 1,
            "720P" => 2,
            "1080P" => 3,
            "2160P" => 4,
            "4320P" => 5,
            _ => 0,
        };
    rank <= max
}

pub struct Contribution {
    pub id: String,
    pub media_file_id: i32,
    pub provider: String,
    pub segment: String,
    pub source: String,
    pub submitted_start_ms: Option<i64>,
    pub submitted_end_ms: Option<i64>,
    pub video_duration_ms: Option<i64>,
    pub content_hash: String,
    pub submission_id: Option<String>,
    pub status: String,
    pub http_status: Option<i32>,
    pub error: Option<String>,
    pub submitted_at: SystemTime,
    pub updated_at: SystemTime,
}

pub async fn list(
    pool: &Pool,
    file_id: i64,
    limit: i64,
    updated_at: Option<SystemTime>,
    after: &str,
) -> Result<(Vec<Contribution>, bool), String> {
    if !(1..=200).contains(&limit) {
        return Err("invalid contribution page limit".into());
    }
    let id = i32::try_from(file_id).map_err(|e| e.to_string())?;
    let after = if after.is_empty() {
        Uuid::nil()
    } else {
        Uuid::parse_str(after).map_err(|e| e.to_string())?
    };
    let rows = pool
        .query(
            r#"
		SELECT id, media_file_id, provider, segment_kind, source,
		       submitted_start_ms, submitted_end_ms, video_duration_ms,
		       content_hash, submission_id, status, http_status, error,
		       submitted_at, updated_at
		FROM marker_contributions WHERE media_file_id = $1
		AND ($2::timestamptz IS NULL OR (updated_at, id) < ($2, $3::uuid))
 ORDER BY updated_at DESC, id DESC LIMIT $4"#,
            &[&id, &updated_at, &after, &(limit + 1)],
        )
        .await
        .map_err(|e| e.to_string())?;
    let more = rows.len() > limit as usize;
    let rows = rows
        .iter()
        .take(limit as usize)
        .map(|r| Contribution {
            id: r.get::<_, Uuid>(0).to_string(),
            media_file_id: r.get(1),
            provider: r.get(2),
            segment: r.get(3),
            source: r.get(4),
            submitted_start_ms: r.get(5),
            submitted_end_ms: r.get(6),
            video_duration_ms: r.get(7),
            content_hash: r.get(8),
            submission_id: r.get(9),
            status: r.get(10),
            http_status: r.get(11),
            error: r.get(12),
            submitted_at: r.get(13),
            updated_at: r.get(14),
        })
        .collect();
    Ok((rows, more))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_quality_respects_normalized_policy_presets() {
        for (file, ceiling, allowed) in [
            ("2160p", "standard", false),
            ("1080p", "480p", true),
            ("4320p", "4320p", false),
            ("2160p", " UHD ", true),
            ("unknown", "1080p", true),
            ("4320p", "any", true),
        ] {
            assert_eq!(quality_allowed(file, ceiling), allowed, "{file}/{ceiling}");
        }
    }
}
