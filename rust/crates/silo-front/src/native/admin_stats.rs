//! The dashboard aggregates: `admin_stats.go`, `admin_stats_downloads.go`, `admin_stats_playback.go`,
//! `admin_stats_top.go`, `admin_stats_timeseries.go`, `internal/apiusage`, and v2 `admin_dashboard_stats.go`,
//! `admin_dashboard_insights.go`, `admin_api_clients.go`.
//!
//! Each aggregate keeps Go's in-process TTL cache and bus invalidation, so a read after a write is as stale
//! here as it is on Go. `watch_providers` comes from stored rows only: the provider registry needs the plugin
//! host, so the Gate keeps `/admin/stats` on Go while any plugin is installed.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use silo_api_v2::problem::{Problem, internal_error};
use silo_api_v2::wire::{Id, Instant, NullableInstant};
use silo_gate::mw::auth::get_claims;
use silo_gocompat::strings::trim_space;
use silo_gocompat::time::GoTime;
use silo_http::chi::Mux;
use silo_http::{BoxHandler, Request, handler_fn};
use silo_pg::{AnyInt, Pool, Row};
use silo_runtime::cache::event_bus::EventBus;
use silo_runtime::cache::ttlcache::TtlCache;
use time::OffsetDateTime;

use super::auth::write_v1_error;
use super::chain::{Stack, Step, V2Class, write_problem, write_v1_json, write_v2_json};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/stats"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/stats/downloads"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/stats/playback-activity"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/stats/timeseries"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/stats/top-activity"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/stats"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/stats/api-clients"),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/admin/stats/api-clients/{session_id}/endpoints",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/stats/downloads"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/stats/playback-activity"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/stats/timeseries"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/stats/top-activity"),
];

const V1_ACTING_ADMIN: &[Step] = &[Step::ActingAdmin];
const STATS_TTL: Duration = Duration::from_secs(15);
const DOWNLOADS_TTL: Duration = Duration::from_secs(60);
const PLAYBACK_TTL: Duration = Duration::from_secs(60);
const TOP_TTL: Duration = Duration::from_secs(300);
const TIMESERIES_TTL: Duration = Duration::from_secs(30);

const CHANNEL_CATALOG: &str = "silo:catalog";
const CHANNEL_ADMIN: &str = "silo:admin";
const CHANNEL_PLAYBACK: &str = "silo:playback";

const STATS_SQL: &str = r#"
		WITH user_stats AS (
			SELECT COUNT(*)::bigint AS total_users
			FROM users
		),
		item_stats AS (
			SELECT
				COUNT(*)::bigint AS total_items,
				COUNT(*) FILTER (WHERE type = 'movie')::bigint AS total_movies,
				COUNT(*) FILTER (WHERE type = 'series')::bigint AS total_shows,
				COUNT(*) FILTER (WHERE type IN ('movie', 'series') AND advisory_age IS NOT NULL)::bigint AS advisory_titles
			FROM media_items
		),
		file_stats AS (
			SELECT
				COUNT(*)::bigint AS total_files,
				COUNT(*) FILTER (WHERE file_kind = 'movie')::bigint AS total_movie_files,
				COUNT(*) FILTER (WHERE file_kind = 'series')::bigint AS total_show_files,
				COALESCE(SUM(file_size), 0)::bigint AS total_storage_bytes
			FROM (
				SELECT
					media_files.file_size,
					CASE
						WHEN lower(trim(COALESCE(NULLIF(media_items.type, ''), ''))) = 'movie'
							THEN 'movie'
						WHEN lower(trim(COALESCE(NULLIF(media_items.type, ''), ''))) = 'series'
							THEN 'series'
						WHEN episodes.content_id IS NOT NULL
							THEN 'series'
						WHEN lower(trim(COALESCE(NULLIF(media_files.base_type, ''), ''))) IN ('movie', 'movies')
							THEN 'movie'
						WHEN lower(trim(COALESCE(NULLIF(media_files.base_type, ''), ''))) IN ('series', 'tv', 'show', 'shows', 'tvshows')
							THEN 'series'
						WHEN lower(trim(media_folders.type)) IN ('movie', 'movies')
							THEN 'movie'
						WHEN lower(trim(media_folders.type)) IN ('series', 'tv', 'show', 'shows', 'tvshows')
							THEN 'series'
						ELSE ''
					END AS file_kind
				FROM media_files
				JOIN media_folders ON media_folders.id = media_files.media_folder_id
				LEFT JOIN media_items ON media_items.content_id = media_files.content_id
				LEFT JOIN episodes ON episodes.content_id = media_files.episode_id
			) classified_files
		),
		session_stats AS (
			SELECT COUNT(*)::bigint AS active_streams
			FROM playback_sessions_sync
		)
		SELECT
			user_stats.total_users,
			item_stats.total_items,
			file_stats.total_files,
			item_stats.total_movies,
			file_stats.total_movie_files,
			item_stats.total_shows,
			file_stats.total_show_files,
			item_stats.advisory_titles,
			session_stats.active_streams,
			file_stats.total_storage_bytes
		FROM user_stats
		CROSS JOIN item_stats
		CROSS JOIN file_stats
		CROSS JOIN session_stats
	"#;

const WATCH_PROVIDERS_READY_SQL: &str = r#"
		SELECT bool_and(to_regclass(table_name) IS NOT NULL)
		FROM unnest($1::text[]) AS table_name
	"#;

const WATCH_PROVIDERS_SQL: &str = r#"
		WITH watch_provider_connection_stats AS (
			SELECT
				provider,
				COUNT(*)::bigint AS connected_profiles,
				COUNT(*) FILTER (
					WHERE import_watched_enabled
					   OR import_progress_enabled
					   OR export_watched_enabled
					   OR scrobble_enabled
				)::bigint AS enabled_profiles,
				COUNT(*) FILTER (WHERE export_watched_enabled)::bigint AS export_enabled_profiles,
				COUNT(*) FILTER (WHERE scrobble_enabled)::bigint AS scrobble_enabled_profiles
			FROM watch_provider_connections
			GROUP BY provider
		),
		watch_provider_sync_stats AS (
			SELECT
				provider,
				MAX(completed_at) AS last_sync_completed_at,
				COUNT(*) FILTER (WHERE started_at >= now() - interval '24 hours')::bigint AS sync_runs_24h,
				COUNT(*) FILTER (
					WHERE status = 'failed'
					  AND started_at >= now() - interval '24 hours'
				)::bigint AS sync_errors_24h,
				COALESCE(SUM(inbound_watched_imported) FILTER (
					WHERE started_at >= now() - interval '24 hours'
				), 0)::bigint AS imported_watched_24h,
				COALESCE(SUM(inbound_progress_imported) FILTER (
					WHERE started_at >= now() - interval '24 hours'
				), 0)::bigint AS imported_progress_24h,
				COALESCE(SUM(outbound_sent) FILTER (
					WHERE started_at >= now() - interval '24 hours'
				), 0)::bigint AS exported_watched_24h
			FROM watch_provider_sync_runs
			GROUP BY provider
		),
		watch_provider_export_stats AS (
			SELECT
				c.provider,
				COUNT(*) FILTER (WHERE e.status = 'pending')::bigint AS pending_exports,
				COUNT(*) FILTER (WHERE e.status = 'failed')::bigint AS failed_exports
			FROM watch_provider_history_exports e
			JOIN watch_provider_connections c ON c.id = e.connection_id
			GROUP BY c.provider
		),
		watch_provider_scrobble_stats AS (
			SELECT
				c.provider,
				COUNT(*) FILTER (WHERE s.stop_sent_at IS NULL)::bigint AS open_scrobbles,
				COUNT(*) FILTER (WHERE s.updated_at >= now() - interval '24 hours')::bigint AS scrobbles_24h
			FROM watch_provider_scrobble_sessions s
			JOIN watch_provider_connections c ON c.id = s.connection_id
			GROUP BY c.provider
		),
		watch_provider_keys AS (
			SELECT provider FROM watch_provider_connection_stats
			UNION
			SELECT provider FROM watch_provider_sync_stats
			UNION
			SELECT provider FROM watch_provider_export_stats
			UNION
			SELECT provider FROM watch_provider_scrobble_stats
		)
		SELECT
			k.provider,
			COALESCE(c.connected_profiles, 0),
			COALESCE(c.enabled_profiles, 0),
			COALESCE(c.export_enabled_profiles, 0),
			COALESCE(c.scrobble_enabled_profiles, 0),
			s.last_sync_completed_at,
			COALESCE(s.sync_runs_24h, 0),
			COALESCE(s.sync_errors_24h, 0),
			COALESCE(s.imported_watched_24h, 0),
			COALESCE(s.imported_progress_24h, 0),
			COALESCE(s.exported_watched_24h, 0),
			COALESCE(e.pending_exports, 0),
			COALESCE(e.failed_exports, 0),
			COALESCE(sc.open_scrobbles, 0),
			COALESCE(sc.scrobbles_24h, 0)
		FROM watch_provider_keys k
		LEFT JOIN watch_provider_connection_stats c ON c.provider = k.provider
		LEFT JOIN watch_provider_sync_stats s ON s.provider = k.provider
		LEFT JOIN watch_provider_export_stats e ON e.provider = k.provider
		LEFT JOIN watch_provider_scrobble_stats sc ON sc.provider = k.provider
		ORDER BY k.provider
	"#;

const DOWNLOADS_SCALARS_SQL: &str = r#"
		SELECT
			COUNT(DISTINCT user_id) FILTER (WHERE device_id IS NOT NULL AND status IN ('queued', 'preparing', 'ready', 'downloading', 'completed')),
			COUNT(*)                FILTER (WHERE device_id IS NOT NULL AND status IN ('queued', 'preparing', 'ready', 'downloading', 'completed')),
			COALESCE(SUM(GREATEST(file_size, 0)) FILTER (WHERE device_id IS NOT NULL AND status = 'completed'), 0)::bigint,
			COUNT(*) FILTER (WHERE created_at >= now() - interval '24 hours'),
			COUNT(*) FILTER (WHERE status = 'completed' AND completed_at >= now() - interval '24 hours')
		FROM downloads
	"#;

const DOWNLOADS_TOP_SQL: &str = r#"
		SELECT d.user_id,
		       COALESCE(u.username, '') AS username,
		       COUNT(*)::bigint AS downloads,
		       COALESCE(SUM(GREATEST(d.file_size, 0)) FILTER (WHERE d.status = 'completed'), 0)::bigint AS total_bytes
		FROM downloads d
		LEFT JOIN users u ON u.id = d.user_id
		WHERE d.device_id IS NOT NULL AND d.status IN ('queued', 'preparing', 'ready', 'downloading', 'completed')
		GROUP BY d.user_id, u.username
		ORDER BY downloads DESC, total_bytes DESC, d.user_id
		LIMIT $1
	"#;

const SESSIONS_CTE: &str = r#"
	WITH history AS (
		SELECT session_id, started_at, play_method, completed, user_id, profile_id, FALSE AS live
		FROM admin_playback_history
		WHERE started_at >= now() - make_interval(hours => $1)
	),
	sessions AS (
		SELECT started_at, play_method, completed, user_id, profile_id, live FROM history
		UNION ALL
		SELECT COALESCE(s.started_at, s.updated_at) AS started_at, s.play_method, FALSE, s.user_id, s.profile_id, TRUE
		FROM playback_sessions_sync s
		WHERE COALESCE(s.started_at, s.updated_at) >= now() - make_interval(hours => $1)
		  AND NOT EXISTS (SELECT 1 FROM history h WHERE h.session_id = s.session_id)
	)"#;

const PLAYBACK_BUCKETS_SQL: &str = r#"
		SELECT date_trunc($2, started_at, 'UTC') AS bucket,
		       COALESCE(play_method, '') AS play_method,
		       COUNT(*)::bigint AS sessions
		FROM sessions
		WHERE started_at IS NOT NULL
		GROUP BY 1, 2
		ORDER BY 1
	"#;

const PLAYBACK_RELIABILITY_SQL: &str = r#",
		reliability AS (
			SELECT
				COUNT(*)::bigint AS sessions_started,
				COUNT(*) FILTER (WHERE play_method = 'transcode')::bigint AS transcode_starts,
				COUNT(*) FILTER (WHERE NOT live)::bigint AS finalized_sessions,
				COUNT(*) FILTER (WHERE NOT live AND completed)::bigint AS completed_sessions,
				COUNT(DISTINCT (user_id, profile_id))::bigint AS unique_profiles
			FROM sessions
		),
		active_profiles AS (
			SELECT COUNT(DISTINCT (user_id, profile_id))::bigint AS profiles_active_24h
			FROM user_watch_history
			WHERE watched_at >= now() - interval '24 hours'
			  AND COALESCE(source, 'legacy') IN ('legacy', 'manual', 'playback', 'jellycompat')
		)
		SELECT
			reliability.sessions_started,
			reliability.transcode_starts,
			reliability.finalized_sessions,
			reliability.completed_sessions,
			reliability.unique_profiles,
			active_profiles.profiles_active_24h,
			now() - make_interval(hours => $1) AS window_from,
			now() AS window_to
		FROM reliability
		CROSS JOIN active_profiles
	"#;

const TOP_TITLES_SQL: &str = r#"
		WITH ranked AS (
			SELECT COALESCE(ep.series_id, h.media_item_id) AS item_id,
			       bool_or(ep.content_id IS NOT NULL) AS is_series,
			       COUNT(*)::bigint AS plays
			FROM user_watch_history h
			LEFT JOIN episodes ep ON ep.content_id = h.media_item_id
			WHERE h.watched_at >= now() - make_interval(days => $1)
			  AND COALESCE(h.source, 'legacy') IN ('legacy', 'playback')
			GROUP BY 1
			ORDER BY plays DESC, item_id
			LIMIT $2
		),
		watched AS (
			SELECT COALESCE(ep.series_id, p.media_item_id) AS item_id,
			       SUM(CASE WHEN p.measured THEN p.played_seconds ELSE LEAST(GREATEST(p.watched_seconds, 0),
		GREATEST(EXTRACT(EPOCH FROM (p.ended_at - p.started_at)), 0)) END) AS total_seconds
			FROM admin_playback_history p
			LEFT JOIN episodes ep ON ep.content_id = p.media_item_id
			WHERE p.ended_at >= now() - make_interval(days => $1)
			  AND COALESCE(ep.series_id, p.media_item_id) IN (SELECT item_id FROM ranked)
			GROUP BY 1
		)
		SELECT r.item_id,
		       COALESCE(mi.title, '') AS title,
		       COALESCE(CASE WHEN r.is_series THEN 'series' ELSE mi.type END, '') AS media_type,
		       r.plays,
		       COALESCE(w.total_seconds, 0)::bigint AS total_seconds
		FROM ranked r
		LEFT JOIN media_items mi ON mi.content_id = r.item_id
		LEFT JOIN watched w ON w.item_id = r.item_id
		ORDER BY r.plays DESC, total_seconds DESC, r.item_id
	"#;

const TOP_PROFILES_SQL: &str = r#"
		WITH ranked AS (
			SELECT h.user_id,
			       h.profile_id,
			       COUNT(*)::bigint AS plays
			FROM user_watch_history h
			WHERE h.watched_at >= now() - make_interval(days => $1)
			  AND COALESCE(h.source, 'legacy') IN ('legacy', 'playback')
			GROUP BY 1, 2
			ORDER BY plays DESC, h.user_id, h.profile_id
			LIMIT $2
		),
		watched AS (
			SELECT p.user_id,
			       p.profile_id,
			       SUM(CASE WHEN p.measured THEN p.played_seconds ELSE LEAST(GREATEST(p.watched_seconds, 0),
		GREATEST(EXTRACT(EPOCH FROM (p.ended_at - p.started_at)), 0)) END) AS total_seconds
			FROM admin_playback_history p
			WHERE p.ended_at >= now() - make_interval(days => $1)
			  AND EXISTS (
				SELECT 1 FROM ranked r
				WHERE r.user_id = p.user_id AND r.profile_id = p.profile_id
			  )
			GROUP BY 1, 2
		)
		SELECT r.user_id,
		       COALESCE(u.username, '') AS username,
		       r.profile_id,
		       COALESCE(pn.profile_name, r.profile_id) AS profile_name,
		       r.plays,
		       COALESCE(w.total_seconds, 0)::bigint AS total_seconds
		FROM ranked r
		LEFT JOIN users u ON u.id = r.user_id
		LEFT JOIN watched w ON w.user_id = r.user_id AND w.profile_id = r.profile_id
		LEFT JOIN LATERAL (
			SELECT p.profile_name
			FROM admin_playback_history p
			WHERE p.user_id = r.user_id
			  AND p.profile_id = r.profile_id
			  AND p.profile_name <> ''
			ORDER BY p.ended_at DESC
			LIMIT 1
		) pn ON TRUE
		ORDER BY r.plays DESC, total_seconds DESC, r.user_id, r.profile_id
	"#;

const TIMESERIES_SQL: &str = r#"
		WITH minutes AS (
			SELECT bucket,
			       MAX(streams_total)     FILTER (WHERE source = 'shared') AS streams_total,
			       MAX(streams_direct)    FILTER (WHERE source = 'shared') AS streams_direct,
			       MAX(streams_remux)     FILTER (WHERE source = 'shared') AS streams_remux,
			       MAX(streams_transcode) FILTER (WHERE source = 'shared') AS streams_transcode,
			       COALESCE(SUM(egress_kbps), 0)::bigint AS egress_kbps,
			       COALESCE(SUM(download_egress_kbps), 0)::bigint AS download_egress_kbps
			FROM dashboard_metric_samples
			WHERE bucket >= now() - make_interval(hours => $1)
			GROUP BY bucket
		)
		SELECT date_bin(make_interval(secs => $2), bucket, 'epoch') AS display_bucket,
		       MAX(streams_total),
		       MAX(streams_direct),
		       MAX(streams_remux),
		       MAX(streams_transcode),
		       MAX(egress_kbps)::bigint,
		       MAX(download_egress_kbps)::bigint,
		       SUM(egress_kbps)::bigint,
		       SUM(download_egress_kbps)::bigint
		FROM minutes
		GROUP BY display_bucket
		ORDER BY display_bucket
	"#;

const EGRESS_PARTS_SQL: &str = r#"
	SELECT bucket, 'api' AS source_key, egress_kbps
	FROM dashboard_metric_samples
	WHERE source LIKE 'proc:%' AND bucket >= now() - make_interval(hours => $1)
	UNION ALL
	SELECT bucket, 'node:' || node_id, egress_kbps
	FROM dashboard_node_egress_samples
	WHERE bucket >= now() - make_interval(hours => $1)
"#;

const EGRESS_PEAKS_SQL: &str = r#"
		WITH minutes AS (
			SELECT bucket, SUM(egress_kbps) AS egress_kbps
			FROM dashboard_metric_samples
			WHERE bucket >= now() - make_interval(hours => $1)
			GROUP BY bucket
		), peaks AS (
			SELECT DISTINCT ON (display_bucket) display_bucket, bucket
			FROM (
				SELECT date_bin(make_interval(secs => $2), bucket, 'epoch') AS display_bucket, bucket, egress_kbps
				FROM minutes
			) binned
			ORDER BY display_bucket, egress_kbps DESC, bucket
		), parts AS ("#;

const EGRESS_PEAKS_TAIL_SQL: &str = r#")
		SELECT peaks.display_bucket, parts.source_key, SUM(parts.egress_kbps)::bigint
		FROM peaks
		JOIN parts ON parts.bucket = peaks.bucket
		GROUP BY 1, 2
	"#;

const WINDOW_SQL: &str = r#"
		SELECT MIN(bucket),
		       now() - make_interval(hours => $1),
		       now()
		FROM dashboard_metric_samples
	"#;

/// `ratelimit.QuotaExemptPathPattern`.
const QUOTA_EXEMPT: &str = concat!(
    r"^/api/v[12]/(stream|playback)(/|$)",
    r"|^/api/v[12]/auth/(provider-)?logout$",
    r"|^/api/v[12]/direct-download(-proxy)?$",
    r"|^/api/v[12]/downloads/[^/]+/(file|file-proxy)$",
    r"|^/api/v[12]/downloads/[^/]+/subtitles/",
    r"|^/api/v2/catalog/items/[^/]+/themes/[^/]+/audio$",
    r"|^/api/v1/ebooks/[^/]+/files/[^/]+/read$",
);

const CLIENTS_TOTAL_SQL: &str =
    "SELECT coalesce(sum(requests), 0) FROM api_client_usage_hourly WHERE hour >= $1";

const CLIENTS_SQL: &str = r#"
		WITH top AS (
			SELECT session_id, max(user_id) AS user_id, sum(requests) AS requests, sum(refused) AS refused,
			       max(requests) AS peak_hour, min(hour) AS first_hour, max(hour) AS last_hour,
			       (array_agg(user_agent ORDER BY hour DESC))[1] AS user_agent
			FROM api_client_usage_hourly
			WHERE hour >= $1
			GROUP BY session_id
			ORDER BY sum(requests) DESC, session_id
			LIMIT $2
		)
		SELECT top.session_id, coalesce(top.user_id, 0), coalesce(u.username, ''),
		       coalesce(s.device_name, ''), coalesce(s.device_platform, ''), top.user_agent,
		       top.requests, top.refused, top.peak_hour, top.first_hour, top.last_hour,
		       s.id IS NOT NULL AND s.revoked_at IS NULL AND s.expires_at > now()
		FROM top
		LEFT JOIN users u ON u.id = top.user_id
		LEFT JOIN auth_sessions s ON s.id = top.session_id
		ORDER BY top.requests DESC, top.session_id"#;

const CLIENT_USER_SQL: &str =
    "SELECT max(user_id) FROM api_client_usage_hourly WHERE session_id = $1 AND hour >= $2";

const CLIENT_ENDPOINTS_SQL: &str = r#"
		SELECT method, coalesce(nullif(path_pattern, ''), path), count(*), count(*) FILTER (WHERE status_code = 429)
		FROM activity_log
		WHERE user_id = $1 AND "timestamp" >= $2 AND session_id = $3
		  AND impersonator_user_id IS NULL AND path !~ $4
		GROUP BY 1, 2
		ORDER BY 3 DESC, 1, 2
		LIMIT $5"#;

/// `apiusage.MaxEndpointHours` and `endpointLimit`.
const MAX_ENDPOINT_HOURS: i64 = 24;
const ENDPOINT_LIMIT: i64 = 10;

type Failed = String;

fn err(e: impl std::fmt::Display) -> Failed {
    e.to_string()
}

fn gt<'a, T: silo_pg::pg_types::FromSql<'a>>(row: &'a Row, i: usize) -> Result<T, Failed> {
    row.try_get::<_, T>(i).map_err(err)
}

fn go_time(t: OffsetDateTime) -> GoTime {
    GoTime::from_system_time(SystemTime::from(t))
}

fn ts(row: &Row, i: usize) -> Result<OffsetDateTime, Failed> {
    Ok(OffsetDateTime::from(gt::<SystemTime>(row, i)?))
}

fn ts_opt(row: &Row, i: usize) -> Result<Option<OffsetDateTime>, Failed> {
    Ok(gt::<Option<SystemTime>>(row, i)?.map(OffsetDateTime::from))
}

#[derive(Clone, Default, Serialize)]
pub struct WatchProvider {
    provider: String,
    display_name: String,
    registered: bool,
    scrobbling: bool,
    exporting: bool,
    connected_profiles: i64,
    enabled_profiles: i64,
    export_enabled_profiles: i64,
    scrobble_enabled_profiles: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_sync_completed_at: Option<GoTime>,
    sync_runs_24h: i64,
    sync_errors_24h: i64,
    imported_watched_24h: i64,
    imported_progress_24h: i64,
    exported_watched_24h: i64,
    pending_exports: i64,
    failed_exports: i64,
    open_scrobbles: i64,
    scrobbles_24h: i64,
}

#[derive(Clone, Default, Serialize)]
pub struct Stats {
    total_items: i64,
    total_files: i64,
    total_users: i64,
    total_movies: i64,
    total_movie_files: i64,
    total_shows: i64,
    total_show_files: i64,
    #[serde(skip)]
    advisory_titles: i64,
    active_streams: i64,
    total_storage_bytes: i64,
    watch_providers: Vec<WatchProvider>,
}

async fn watch_provider_activity(pool: &Pool) -> Result<Vec<WatchProvider>, Failed> {
    let tables = vec![
        "public.watch_provider_connections",
        "public.watch_provider_sync_runs",
        "public.watch_provider_history_exports",
        "public.watch_provider_scrobble_sessions",
    ];
    let rows = pool
        .query(WATCH_PROVIDERS_READY_SQL, &[&tables])
        .await
        .map_err(err)?;
    let ready: Option<bool> = gt(&rows[0], 0)?;
    if ready != Some(true) {
        return Ok(Vec::new());
    }
    let rows = pool.query(WATCH_PROVIDERS_SQL, &[]).await.map_err(err)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        let provider: String = gt(row, 0)?;
        let at = ts_opt(row, 5)?;
        out.push(WatchProvider {
            // `mergeWatchProviderStats`, with no registered providers.
            display_name: provider.clone(),
            provider,
            connected_profiles: gt(row, 1)?,
            enabled_profiles: gt(row, 2)?,
            export_enabled_profiles: gt(row, 3)?,
            scrobble_enabled_profiles: gt(row, 4)?,
            last_sync_completed_at: at.map(go_time),
            sync_runs_24h: gt(row, 6)?,
            sync_errors_24h: gt(row, 7)?,
            imported_watched_24h: gt(row, 8)?,
            imported_progress_24h: gt(row, 9)?,
            exported_watched_24h: gt(row, 10)?,
            pending_exports: gt(row, 11)?,
            failed_exports: gt(row, 12)?,
            open_scrobbles: gt(row, 13)?,
            scrobbles_24h: gt(row, 14)?,
            ..WatchProvider::default()
        });
    }
    Ok(out)
}

async fn query_stats(pool: &Pool) -> Result<Stats, Failed> {
    let rows = pool.query(STATS_SQL, &[]).await.map_err(err)?;
    let row = rows.first().ok_or("no row")?;
    let activity = match watch_provider_activity(pool).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(component = "api", error = %e, "failed to query watch provider admin stats");
            Vec::new()
        }
    };
    let mut watch_providers: Vec<WatchProvider> = activity
        .into_iter()
        .filter(|p| !p.provider.is_empty())
        .collect();
    watch_providers.sort_by(|a, b| a.provider.cmp(&b.provider));
    Ok(Stats {
        total_users: gt(row, 0)?,
        total_items: gt(row, 1)?,
        total_files: gt(row, 2)?,
        total_movies: gt(row, 3)?,
        total_movie_files: gt(row, 4)?,
        total_shows: gt(row, 5)?,
        total_show_files: gt(row, 6)?,
        advisory_titles: gt(row, 7)?,
        active_streams: gt(row, 8)?,
        total_storage_bytes: gt(row, 9)?,
        watch_providers,
    })
}

#[derive(Clone, Serialize)]
struct DownloadsUser {
    user_id: i64,
    username: String,
    downloads: i64,
    total_bytes: i64,
}

#[derive(Clone, Serialize)]
struct Downloads {
    users_with_downloads: i64,
    active_downloads: i64,
    total_bytes: i64,
    downloads_started_24h: i64,
    downloads_completed_24h: i64,
    limit: i64,
    top_users: Vec<DownloadsUser>,
}

async fn query_downloads(pool: &Pool, limit: i64) -> Result<Downloads, Failed> {
    let rows = pool.query(DOWNLOADS_SCALARS_SQL, &[]).await.map_err(err)?;
    let row = rows.first().ok_or("no row")?;
    let mut out = Downloads {
        users_with_downloads: gt(row, 0)?,
        active_downloads: gt(row, 1)?,
        total_bytes: gt(row, 2)?,
        downloads_started_24h: gt(row, 3)?,
        downloads_completed_24h: gt(row, 4)?,
        limit,
        top_users: Vec::new(),
    };
    for row in &pool
        .query(DOWNLOADS_TOP_SQL, &[&AnyInt(limit)])
        .await
        .map_err(err)?
    {
        out.top_users.push(DownloadsUser {
            user_id: gt::<AnyInt>(row, 0)?.0,
            username: gt(row, 1)?,
            downloads: gt(row, 2)?,
            total_bytes: gt(row, 3)?,
        });
    }
    Ok(out)
}

#[derive(Clone, Serialize)]
struct PlaybackBucket {
    hour: GoTime,
    direct: i64,
    remux: i64,
    transcode: i64,
}

#[derive(Clone, Default, Serialize)]
struct Reliability {
    sessions_started: i64,
    transcode_starts: i64,
    finalized_sessions: i64,
    completed_sessions: i64,
    completion_rate: f64,
    unique_profiles: i64,
}

#[derive(Clone, Serialize)]
struct Playback {
    hours: i64,
    bucket_seconds: i64,
    from: GoTime,
    to: GoTime,
    buckets: Vec<PlaybackBucket>,
    reliability: Reliability,
    profiles_active_24h: i64,
    #[serde(skip)]
    instants: (Instant, Instant, Vec<Instant>),
}

fn completion_rate(completed: i64, finalized: i64) -> f64 {
    if finalized <= 0 {
        return 0.0;
    }
    (completed as f64 / finalized as f64 * 10000.0).round() / 10000.0
}

async fn query_playback(pool: &Pool, hours: i64) -> Result<Playback, Failed> {
    let bucket_seconds = if hours <= 48 { 3600 } else { 86400 };
    let mut session = pool.acquire().await.map_err(err)?;
    session
        .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await
        .map_err(err)?;
    let result = async {
        let field = if bucket_seconds >= 86400 {
            "day"
        } else {
            "hour"
        };
        let sql = format!("{SESSIONS_CTE}{PLAYBACK_BUCKETS_SQL}");
        let rows = session
            .query(&sql, &[&AnyInt(hours), &field])
            .await
            .map_err(err)?;
        let mut buckets: Vec<PlaybackBucket> = Vec::new();
        let mut instants = Vec::new();
        let mut index: HashMap<OffsetDateTime, usize> = HashMap::new();
        for row in &rows {
            let hour = ts(row, 0)?;
            let method: String = gt(row, 1)?;
            let count: i64 = gt(row, 2)?;
            let pos = *index.entry(hour).or_insert_with(|| {
                buckets.push(PlaybackBucket {
                    hour: go_time(hour),
                    direct: 0,
                    remux: 0,
                    transcode: 0,
                });
                instants.push(Instant::new(hour));
                buckets.len() - 1
            });
            match method.as_str() {
                "direct" => buckets[pos].direct += count,
                "remux" => buckets[pos].remux += count,
                "transcode" => buckets[pos].transcode += count,
                _ => {}
            }
        }
        let sql = format!("{SESSIONS_CTE}{PLAYBACK_RELIABILITY_SQL}");
        let rows = session.query(&sql, &[&AnyInt(hours)]).await.map_err(err)?;
        let row = rows.first().ok_or("no row")?;
        let from = ts(row, 6)?;
        let to = ts(row, 7)?;
        let completed: i64 = gt(row, 3)?;
        let finalized: i64 = gt(row, 2)?;
        Ok(Playback {
            hours,
            bucket_seconds,
            from: go_time(from),
            to: go_time(to),
            buckets,
            reliability: Reliability {
                sessions_started: gt(row, 0)?,
                transcode_starts: gt(row, 1)?,
                finalized_sessions: finalized,
                completed_sessions: completed,
                completion_rate: completion_rate(completed, finalized),
                unique_profiles: gt(row, 4)?,
            },
            profiles_active_24h: gt(row, 5)?,
            instants: (Instant::new(from), Instant::new(to), instants),
        })
    }
    .await;
    let _ = session.batch_execute("ROLLBACK").await;
    result
}

#[derive(Clone, Serialize)]
struct TopTitle {
    media_item_id: String,
    title: String,
    media_type: String,
    plays: i64,
    total_seconds: i64,
}

#[derive(Clone, Serialize)]
struct TopProfile {
    user_id: i64,
    username: String,
    profile_id: String,
    profile_name: String,
    plays: i64,
    total_seconds: i64,
}

#[derive(Clone, Serialize)]
struct Top {
    days: i64,
    limit: i64,
    titles: Vec<TopTitle>,
    profiles: Vec<TopProfile>,
}

async fn query_top(pool: &Pool, days: i64, limit: i64) -> Result<Top, Failed> {
    let mut out = Top {
        days,
        limit,
        titles: Vec::new(),
        profiles: Vec::new(),
    };
    for row in &pool
        .query(TOP_TITLES_SQL, &[&AnyInt(days), &AnyInt(limit)])
        .await
        .map_err(err)?
    {
        out.titles.push(TopTitle {
            media_item_id: gt(row, 0)?,
            title: gt(row, 1)?,
            media_type: gt(row, 2)?,
            plays: gt(row, 3)?,
            total_seconds: gt(row, 4)?,
        });
    }
    for row in &pool
        .query(TOP_PROFILES_SQL, &[&AnyInt(days), &AnyInt(limit)])
        .await
        .map_err(err)?
    {
        out.profiles.push(TopProfile {
            user_id: gt::<AnyInt>(row, 0)?.0,
            username: gt(row, 1)?,
            profile_id: gt(row, 2)?,
            profile_name: gt(row, 3)?,
            plays: gt(row, 4)?,
            total_seconds: gt(row, 5)?,
        });
    }
    Ok(out)
}

#[derive(Clone, Serialize)]
struct Point {
    t: GoTime,
    streams: i64,
    direct: i64,
    remux: i64,
    transcode: i64,
    egress_kbps: i64,
    download_egress_kbps: i64,
    #[serde(skip)]
    instant: Option<Instant>,
    #[serde(skip)]
    egress_by_source: BTreeMap<String, i64>,
}

#[derive(Clone, Serialize)]
struct EgressSource {
    key: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<Id>,
    name: String,
    egress_bytes: i64,
}

#[derive(Clone, Serialize)]
struct Timeseries {
    resolution_seconds: i64,
    from: GoTime,
    to: GoTime,
    oldest_sample_at: Option<GoTime>,
    #[serde(skip)]
    egress_bytes: i64,
    #[serde(skip)]
    download_egress_bytes: i64,
    #[serde(skip)]
    egress_sources: Vec<EgressSource>,
    points: Vec<Point>,
    #[serde(skip)]
    instants: (Option<Instant>, Option<Instant>, Option<Instant>),
}

/// `timeseriesBucketSeconds`.
fn timeseries_bucket_seconds(hours: i64) -> i64 {
    if hours <= 2 {
        60
    } else if hours <= 48 {
        300
    } else if hours <= 336 {
        1800
    } else {
        7200
    }
}

const BYTES_PER_KBPS_MINUTE: i64 = 1000 * 60 / 8;

async fn query_timeseries(pool: &Pool, hours: i64) -> Result<Timeseries, Failed> {
    let bucket_seconds = timeseries_bucket_seconds(hours);
    let mut session = pool.acquire().await.map_err(err)?;
    session
        .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await
        .map_err(err)?;
    let result = async {
        let h = AnyInt(hours);
        let secs = bucket_seconds as f64;
        let rows = session
            .query(TIMESERIES_SQL, &[&h, &secs])
            .await
            .map_err(err)?;
        let mut points = Vec::with_capacity(rows.len());
        let (mut egress_bytes, mut download_bytes) = (0i64, 0i64);
        let mut peaks: Vec<OffsetDateTime> = Vec::with_capacity(rows.len());
        for row in &rows {
            let bucket = ts(row, 0)?;
            peaks.push(bucket);
            let n = |i: usize| -> Result<i64, Failed> {
                Ok(gt::<Option<AnyInt>>(row, i)?.map_or(0, |v| v.0))
            };
            egress_bytes += n(7)? * BYTES_PER_KBPS_MINUTE;
            download_bytes += n(8)? * BYTES_PER_KBPS_MINUTE;
            points.push(Point {
                t: go_time(bucket),
                streams: n(1)?,
                direct: n(2)?,
                remux: n(3)?,
                transcode: n(4)?,
                egress_kbps: n(5)?,
                download_egress_kbps: n(6)?,
                instant: Some(Instant::new(bucket)),
                egress_by_source: BTreeMap::new(),
            });
        }
        let sql = format!("{EGRESS_PEAKS_SQL}{EGRESS_PARTS_SQL}{EGRESS_PEAKS_TAIL_SQL}");
        let mut by_bucket: HashMap<OffsetDateTime, BTreeMap<String, i64>> = HashMap::new();
        for row in &session.query(&sql, &[&h, &secs]).await.map_err(err)? {
            by_bucket
                .entry(ts(row, 0)?)
                .or_default()
                .insert(gt(row, 1)?, gt(row, 2)?);
        }
        for (point, bucket) in points.iter_mut().zip(&peaks) {
            point.egress_by_source = by_bucket.remove(bucket).unwrap_or_default();
        }
        let sql = format!(
            "SELECT source_key, SUM(egress_kbps)::bigint FROM ({EGRESS_PARTS_SQL}) parts GROUP BY 1"
        );
        let mut totals: Vec<(String, i64)> = Vec::new();
        for row in &session.query(&sql, &[&h]).await.map_err(err)? {
            totals.push((gt(row, 0)?, gt::<i64>(row, 1)? * BYTES_PER_KBPS_MINUTE));
        }
        let mut sources = Vec::with_capacity(totals.len());
        let mut node_ids: Vec<(i64, i64)> = Vec::new();
        for (key, total) in &totals {
            if key == "api" {
                sources.push(EgressSource {
                    key: key.clone(),
                    kind: "api",
                    node_id: None,
                    name: "API server".to_owned(),
                    egress_bytes: *total,
                });
                continue;
            }
            let id = key
                .strip_prefix("node:")
                .unwrap_or(key)
                .parse::<i64>()
                .map_err(err)?;
            node_ids.push((id, *total));
        }
        let mut names: HashMap<i64, String> = HashMap::new();
        if !node_ids.is_empty() {
            let ids: Vec<i32> = node_ids.iter().map(|(id, _)| *id as i32).collect();
            for row in &session
                .query(
                    "SELECT id, name FROM stream_nodes WHERE id = ANY($1)",
                    &[&ids],
                )
                .await
                .map_err(err)?
            {
                names.insert(gt::<AnyInt>(row, 0)?.0, gt(row, 1)?);
            }
        }
        for (id, total) in node_ids {
            sources.push(EgressSource {
                key: format!("node:{id}"),
                kind: "node",
                node_id: Some(Id::from_int(id)),
                name: names
                    .remove(&id)
                    .unwrap_or_else(|| format!("Removed node {id}")),
                egress_bytes: total,
            });
        }
        sources.sort_by(|a, b| {
            (a.kind != "api", &a.name, &a.key).cmp(&(b.kind != "api", &b.name, &b.key))
        });
        let rows = session.query(WINDOW_SQL, &[&h]).await.map_err(err)?;
        let row = rows.first().ok_or("no row")?;
        let oldest = ts_opt(row, 0)?;
        let from = ts(row, 1)?;
        let to = ts(row, 2)?;
        Ok(Timeseries {
            resolution_seconds: bucket_seconds,
            from: go_time(from),
            to: go_time(to),
            oldest_sample_at: oldest.map(go_time),
            egress_bytes,
            download_egress_bytes: download_bytes,
            egress_sources: sources,
            points,
            instants: (
                oldest.map(Instant::new),
                Some(Instant::new(from)),
                Some(Instant::new(to)),
            ),
        })
    }
    .await;
    let _ = session.batch_execute("ROLLBACK").await;
    result
}

/// The providers' caches, one per aggregate, with each one's channels.
struct Caches {
    stats: TtlCache<Arc<Stats>>,
    downloads: TtlCache<Arc<Downloads>>,
    playback: TtlCache<Arc<Playback>>,
    top: TtlCache<Arc<Top>>,
    timeseries: TtlCache<Arc<Timeseries>>,
}

static CACHES: OnceLock<Arc<Caches>> = OnceLock::new();

fn caches(s: &Stack) -> Arc<Caches> {
    CACHES
        .get_or_init(|| {
            let caches = Arc::new(Caches {
                stats: TtlCache::new(),
                downloads: TtlCache::new(),
                playback: TtlCache::new(),
                top: TtlCache::new(),
                timeseries: TtlCache::new(),
            });
            if let Some(bus) = s.bus.clone() {
                let held = caches.clone();
                tokio::spawn(async move { subscribe(bus, held).await });
            }
            caches
        })
        .clone()
}

async fn subscribe(bus: Arc<dyn EventBus>, caches: Arc<Caches>) {
    for channel in [CHANNEL_CATALOG, CHANNEL_ADMIN, CHANNEL_PLAYBACK] {
        let caches = caches.clone();
        let handler = Arc::new(move |_| {
            caches.stats.invalidate("global");
            // Downloads subscribes to the admin channel only; a playback or catalog event leaves it.
            if channel == CHANNEL_ADMIN {
                caches.downloads.invalidate_prefix("downloads-limit=");
            }
            if channel != CHANNEL_CATALOG {
                caches.playback.invalidate_prefix("hours=");
                caches.top.invalidate_prefix("days=");
                caches.timeseries.invalidate_prefix("hours=");
            }
        });
        if let Err(e) = bus.subscribe(channel, handler).await {
            tracing::warn!(component = "front", error = %e, "subscribing the admin stats caches failed");
        }
    }
}

async fn read_stats(s: &Stack, refresh: bool) -> Result<Arc<Stats>, Failed> {
    let c = caches(s);
    if refresh {
        c.stats.invalidate("global");
    }
    if let Some(v) = c.stats.get("global") {
        return Ok(v);
    }
    let v = Arc::new(query_stats(&s.pool).await?);
    c.stats.set("global", v.clone(), STATS_TTL);
    Ok(v)
}

async fn read_downloads(s: &Stack, limit: i64, refresh: bool) -> Result<Arc<Downloads>, Failed> {
    let c = caches(s);
    if refresh {
        c.downloads.invalidate_prefix("downloads-limit=");
    }
    let limit = limit.clamp(1, 25);
    let key = format!("downloads-limit={limit}");
    if let Some(v) = c.downloads.get(&key) {
        return Ok(v);
    }
    let v = Arc::new(query_downloads(&s.pool, limit).await?);
    c.downloads.set(&key, v.clone(), DOWNLOADS_TTL);
    Ok(v)
}

async fn read_playback(s: &Stack, hours: i64, refresh: bool) -> Result<Arc<Playback>, Failed> {
    let c = caches(s);
    if refresh {
        c.playback.invalidate_prefix("hours=");
    }
    let hours = hours.clamp(1, 744);
    let key = format!("hours={hours}");
    if let Some(v) = c.playback.get(&key) {
        return Ok(v);
    }
    let v = Arc::new(query_playback(&s.pool, hours).await?);
    c.playback.set(&key, v.clone(), PLAYBACK_TTL);
    Ok(v)
}

async fn read_top(s: &Stack, days: i64, limit: i64, refresh: bool) -> Result<Arc<Top>, Failed> {
    let c = caches(s);
    if refresh {
        c.top.invalidate_prefix("days=");
    }
    let days = days.clamp(1, 30);
    let limit = limit.clamp(1, 25);
    let key = format!("days={days}&limit={limit}");
    if let Some(v) = c.top.get(&key) {
        return Ok(v);
    }
    let v = Arc::new(query_top(&s.pool, days, limit).await?);
    c.top.set(&key, v.clone(), TOP_TTL);
    Ok(v)
}

async fn read_timeseries(s: &Stack, hours: i64, refresh: bool) -> Result<Arc<Timeseries>, Failed> {
    let c = caches(s);
    if refresh {
        c.timeseries.invalidate_prefix("hours=");
    }
    let hours = hours.clamp(1, 744);
    let key = format!("hours={hours}");
    if let Some(v) = c.timeseries.get(&key) {
        return Ok(v);
    }
    let v = Arc::new(query_timeseries(&s.pool, hours).await.inspect_err(|e| {
        tracing::warn!(component = "front", error = %e, "querying timeseries failed");
    })?);
    c.timeseries.set(&key, v.clone(), TIMESERIES_TTL);
    Ok(v)
}

fn query_param(r: &Request, name: &str) -> String {
    let (values, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    values
        .get(name)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
}

/// `isTruthyQuery`.
fn truthy(r: &Request) -> bool {
    let raw = query_param(r, "refresh");
    matches!(
        silo_gocompat::strings::to_lower(trim_space(&raw)).as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// `parseClampedIntQuery`: `Err` is the refusal's message.
fn clamped(r: &Request, key: &str, fallback: i64, min: i64, max: i64) -> Result<i64, String> {
    let raw = query_param(r, key);
    let raw = trim_space(&raw);
    if raw.is_empty() {
        return Ok(fallback.clamp(min, max));
    }
    raw.parse::<i64>()
        .map(|n| n.clamp(min, max))
        .map_err(|_| format!("Invalid {key}"))
}

/// A v2 query integer the validator already judged, or its default.
fn v2_int(r: &Request, key: &str, fallback: i64) -> i64 {
    query_param(r, key).parse().unwrap_or(fallback)
}

/// The v2 `refresh` query, a Huma `bool` the validator already judged: `strconv.ParseBool`'s true spellings.
fn v2_refresh_requested(r: &Request) -> bool {
    parse_bool_true(&query_param(r, "refresh"))
}

/// `strconv.ParseBool` returning true.
fn parse_bool_true(raw: &str) -> bool {
    matches!(raw, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

/// `cacheRefresh`.
fn v2_refresh(r: &Request) -> bool {
    v2_refresh_requested(r) && get_claims(r).is_none_or(|c| c.api_key_scopes.is_empty())
}

#[derive(Serialize)]
struct V2Stats<'a> {
    total_items: i64,
    total_files: i64,
    total_users: i64,
    total_movies: i64,
    total_movie_files: i64,
    total_shows: i64,
    total_show_files: i64,
    advisory_titles: i64,
    active_streams: i64,
    total_storage_bytes: i64,
    watch_providers: Vec<V2Provider<'a>>,
}

#[derive(Serialize)]
struct V2Provider<'a> {
    #[serde(flatten)]
    base: &'a WatchProvider,
}

fn v2_stats(s: &Stats) -> V2Stats<'_> {
    V2Stats {
        total_items: s.total_items,
        total_files: s.total_files,
        total_users: s.total_users,
        total_movies: s.total_movies,
        total_movie_files: s.total_movie_files,
        total_shows: s.total_shows,
        total_show_files: s.total_show_files,
        advisory_titles: s.advisory_titles,
        active_streams: s.active_streams,
        total_storage_bytes: s.total_storage_bytes,
        watch_providers: s
            .watch_providers
            .iter()
            .map(|base| V2Provider { base })
            .collect(),
    }
}

fn dashboard_problem() -> Problem {
    Problem::new(internal_error(), "Dashboard statistics could not be read")
}

macro_rules! h {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

/// Mounts on the `/api/v1/admin` subrouter.
pub fn mount_v1(stack: &Arc<Stack>, admin: &Mux) {
    let v1 = |at: &str, handler: BoxHandler| stack.v1(at, V1_ACTING_ADMIN, handler);
    admin.get(
        "/stats",
        v1(
            "/api/v1/admin/stats",
            h!(stack, |s, w, r| {
                match read_stats(&s, truthy(r)).await {
                    Ok(v) => write_v1_json(w, 200, &*v).await,
                    Err(_) => write_v1_error(w, 500, "internal_error", "Failed to get stats").await,
                }
            }),
        ),
    );
    admin.get(
        "/stats/downloads",
        v1(
            "/api/v1/admin/stats/downloads",
            h!(stack, |s, w, r| {
                let limit = match clamped(r, "limit", 10, 1, 25) {
                    Ok(v) => v,
                    Err(m) => return write_v1_error(w, 400, "bad_request", &m).await,
                };
                match read_downloads(&s, limit, truthy(r)).await {
                    Ok(v) => write_v1_json(w, 200, &*v).await,
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to get downloads stats")
                            .await
                    }
                }
            }),
        ),
    );
    admin.get(
        "/stats/playback-activity",
        v1(
            "/api/v1/admin/stats/playback-activity",
            h!(stack, |s, w, r| {
                let hours = match clamped(r, "hours", 24, 1, 744) {
                    Ok(v) => v,
                    Err(m) => return write_v1_error(w, 400, "bad_request", &m).await,
                };
                match read_playback(&s, hours, truthy(r)).await {
                    Ok(v) => write_v1_json(w, 200, &*v).await,
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to get playback activity")
                            .await
                    }
                }
            }),
        ),
    );
    admin.get(
        "/stats/top-activity",
        v1(
            "/api/v1/admin/stats/top-activity",
            h!(stack, |s, w, r| {
                let days = match clamped(r, "days", 7, 1, 30) {
                    Ok(v) => v,
                    Err(m) => return write_v1_error(w, 400, "bad_request", &m).await,
                };
                let limit = match clamped(r, "limit", 10, 1, 25) {
                    Ok(v) => v,
                    Err(m) => return write_v1_error(w, 400, "bad_request", &m).await,
                };
                match read_top(&s, days, limit, truthy(r)).await {
                    Ok(v) => write_v1_json(w, 200, &*v).await,
                    Err(_) => {
                        write_v1_error(w, 500, "internal_error", "Failed to get top activity").await
                    }
                }
            }),
        ),
    );
    admin.get(
        "/stats/timeseries",
        v1(
            "/api/v1/admin/stats/timeseries",
            h!(stack, |s, w, r| {
                let hours = match clamped(r, "hours", 24, 1, 744) {
                    Ok(v) => v,
                    Err(m) => return write_v1_error(w, 400, "bad_request", &m).await,
                };
                match read_timeseries(&s, hours, truthy(r)).await {
                    Ok(v) => write_v1_json(w, 200, &*v).await,
                    Err(_) => {
                        write_v1_error(
                            w,
                            500,
                            "internal_error",
                            "Failed to get dashboard timeseries",
                        )
                        .await
                    }
                }
            }),
        ),
    );
}

fn mount_v2_insights(stack: &Arc<Stack>, v2: &Mux) {
    #[derive(Serialize)]
    struct V2Point<'a> {
        t: Instant,
        streams: i64,
        direct: i64,
        remux: i64,
        transcode: i64,
        egress_kbps: i64,
        download_egress_kbps: i64,
        egress_by_source: &'a BTreeMap<String, i64>,
    }
    #[derive(Serialize)]
    struct V2Timeseries<'a> {
        resolution_seconds: i64,
        from: Instant,
        to: Instant,
        oldest_sample_at: NullableInstant,
        egress_bytes: i64,
        download_egress_bytes: i64,
        egress_sources: &'a [EgressSource],
        points: Vec<V2Point<'a>>,
    }
    let path = "/api/v2/admin/stats/timeseries";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            h!(stack, |s, w, r| {
                match read_timeseries(&s, v2_int(r, "hours", 24), v2_refresh(r)).await {
                    Ok(t) => {
                        let (oldest, from, to) = t.instants;
                        let body = V2Timeseries {
                            resolution_seconds: t.resolution_seconds,
                            from: from.expect("set"),
                            to: to.expect("set"),
                            oldest_sample_at: NullableInstant {
                                valid: oldest.is_some(),
                                time: oldest,
                            },
                            egress_bytes: t.egress_bytes,
                            download_egress_bytes: t.download_egress_bytes,
                            egress_sources: &t.egress_sources,
                            points: t
                                .points
                                .iter()
                                .map(|p| V2Point {
                                    t: p.instant.expect("set"),
                                    streams: p.streams,
                                    direct: p.direct,
                                    remux: p.remux,
                                    transcode: p.transcode,
                                    egress_kbps: p.egress_kbps,
                                    download_egress_kbps: p.download_egress_kbps,
                                    egress_by_source: &p.egress_by_source,
                                })
                                .collect(),
                        };
                        write_v2_json(w, &body).await;
                    }
                    Err(_) => write_problem(w, r, dashboard_problem()).await,
                }
            }),
        ),
    );

    #[derive(Serialize)]
    struct V2Bucket {
        hour: Instant,
        direct: i64,
        remux: i64,
        transcode: i64,
    }
    #[derive(Serialize)]
    struct V2Playback<'a> {
        hours: i64,
        bucket_seconds: i64,
        from: Instant,
        to: Instant,
        buckets: Vec<V2Bucket>,
        reliability: &'a Reliability,
        profiles_active_24h: i64,
    }
    let path = "/api/v2/admin/stats/playback-activity";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            h!(stack, |s, w, r| {
                match read_playback(&s, v2_int(r, "hours", 24), v2_refresh(r)).await {
                    Ok(p) => {
                        let body = V2Playback {
                            hours: p.hours,
                            bucket_seconds: p.bucket_seconds,
                            from: p.instants.0,
                            to: p.instants.1,
                            buckets: p
                                .buckets
                                .iter()
                                .zip(&p.instants.2)
                                .map(|(b, hour)| V2Bucket {
                                    hour: *hour,
                                    direct: b.direct,
                                    remux: b.remux,
                                    transcode: b.transcode,
                                })
                                .collect(),
                            reliability: &p.reliability,
                            profiles_active_24h: p.profiles_active_24h,
                        };
                        write_v2_json(w, &body).await;
                    }
                    Err(_) => write_problem(w, r, dashboard_problem()).await,
                }
            }),
        ),
    );

    #[derive(Serialize)]
    struct V2TopProfile<'a> {
        user_id: Id,
        username: &'a str,
        profile_id: &'a str,
        profile_name: &'a str,
        plays: i64,
        total_seconds: i64,
    }
    #[derive(Serialize)]
    struct V2Top<'a> {
        days: i64,
        limit: i64,
        titles: &'a [TopTitle],
        profiles: Vec<V2TopProfile<'a>>,
    }
    let path = "/api/v2/admin/stats/top-activity";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            h!(stack, |s, w, r| {
                let (days, limit) = (v2_int(r, "days", 7), v2_int(r, "limit", 10));
                match read_top(&s, days, limit, v2_refresh(r)).await {
                    Ok(t) => {
                        let body = V2Top {
                            days: t.days,
                            limit: t.limit,
                            titles: &t.titles,
                            profiles: t
                                .profiles
                                .iter()
                                .map(|p| V2TopProfile {
                                    user_id: Id::from_int(p.user_id),
                                    username: &p.username,
                                    profile_id: &p.profile_id,
                                    profile_name: &p.profile_name,
                                    plays: p.plays,
                                    total_seconds: p.total_seconds,
                                })
                                .collect(),
                        };
                        write_v2_json(w, &body).await;
                    }
                    Err(_) => write_problem(w, r, dashboard_problem()).await,
                }
            }),
        ),
    );

    #[derive(Serialize)]
    struct V2DownloadsUser<'a> {
        user_id: Id,
        username: &'a str,
        downloads: i64,
        total_bytes: i64,
    }
    #[derive(Serialize)]
    struct V2Downloads<'a> {
        users_with_downloads: i64,
        active_downloads: i64,
        total_bytes: i64,
        downloads_started_24h: i64,
        downloads_completed_24h: i64,
        limit: i64,
        top_users: Vec<V2DownloadsUser<'a>>,
    }
    let path = "/api/v2/admin/stats/downloads";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            h!(stack, |s, w, r| {
                match read_downloads(&s, v2_int(r, "limit", 10), v2_refresh(r)).await {
                    Ok(d) => {
                        let body = V2Downloads {
                            users_with_downloads: d.users_with_downloads,
                            active_downloads: d.active_downloads,
                            total_bytes: d.total_bytes,
                            downloads_started_24h: d.downloads_started_24h,
                            downloads_completed_24h: d.downloads_completed_24h,
                            limit: d.limit,
                            top_users: d
                                .top_users
                                .iter()
                                .map(|u| V2DownloadsUser {
                                    user_id: Id::from_int(u.user_id),
                                    username: &u.username,
                                    downloads: u.downloads,
                                    total_bytes: u.total_bytes,
                                })
                                .collect(),
                        };
                        write_v2_json(w, &body).await;
                    }
                    Err(_) => write_problem(w, r, dashboard_problem()).await,
                }
            }),
        ),
    );
}

/// `windowStart`: the hour the window begins in.
fn window_start(now: OffsetDateTime, hours: i64) -> OffsetDateTime {
    let start = now - time::Duration::hours(hours);
    let secs = start.unix_timestamp().div_euclid(3600) * 3600;
    OffsetDateTime::from_unix_timestamp(secs).expect("in range")
}

fn mount_v2_clients(stack: &Arc<Stack>, v2: &Mux) {
    #[derive(Serialize)]
    struct V2Client {
        session_id: Id,
        user_id: Id,
        username: String,
        device_name: String,
        device_platform: String,
        user_agent: String,
        requests: i64,
        refused: i64,
        peak_hour_requests: i64,
        first_hour: Instant,
        last_hour: Instant,
        session_active: bool,
    }
    #[derive(Serialize)]
    struct V2Clients {
        hours: i64,
        from: Instant,
        total_requests: i64,
        clients: Vec<V2Client>,
    }
    async fn top(s: &Stack, hours: i64, limit: i64) -> Result<V2Clients, Failed> {
        let from = window_start(OffsetDateTime::now_utc(), hours);
        let from_sql = SystemTime::from(from);
        let rows = s
            .pool
            .query(CLIENTS_TOTAL_SQL, &[&from_sql])
            .await
            .map_err(err)?;
        let total: i64 = gt(&rows[0], 0)?;
        let mut clients = Vec::new();
        for row in &s
            .pool
            .query(CLIENTS_SQL, &[&from_sql, &AnyInt(limit)])
            .await
            .map_err(err)?
        {
            clients.push(V2Client {
                session_id: Id(gt(row, 0)?),
                user_id: Id::from_int(gt::<AnyInt>(row, 1)?.0),
                username: gt(row, 2)?,
                device_name: gt(row, 3)?,
                device_platform: gt(row, 4)?,
                user_agent: gt(row, 5)?,
                requests: gt(row, 6)?,
                refused: gt(row, 7)?,
                peak_hour_requests: gt::<AnyInt>(row, 8)?.0,
                first_hour: Instant::new(ts(row, 9)?),
                last_hour: Instant::new(ts(row, 10)?),
                session_active: gt(row, 11)?,
            });
        }
        Ok(V2Clients {
            hours,
            from: Instant::new(from),
            total_requests: total,
            clients,
        })
    }
    let path = "/api/v2/admin/stats/api-clients";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            h!(stack, |s, w, r| {
                match top(&s, v2_int(r, "hours", 24), v2_int(r, "limit", 10)).await {
                    Ok(body) => write_v2_json(w, &body).await,
                    Err(_) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(internal_error(), "API usage could not be read"),
                        )
                        .await
                    }
                }
            }),
        ),
    );

    #[derive(Serialize)]
    struct V2Endpoint {
        method: String,
        route: String,
        requests: i64,
        refused: i64,
    }
    #[derive(Serialize)]
    struct V2Endpoints {
        session_id: Id,
        hours: i64,
        endpoints: Vec<V2Endpoint>,
    }
    async fn endpoints(s: &Stack, id: &str, hours: i64) -> Result<Option<Vec<V2Endpoint>>, Failed> {
        let hours = hours.min(MAX_ENDPOINT_HOURS);
        let now = OffsetDateTime::now_utc();
        let rows = s
            .pool
            .query(
                CLIENT_USER_SQL,
                &[&id, &SystemTime::from(window_start(now, hours))],
            )
            .await
            .map_err(err)?;
        let Some(user) = gt::<Option<AnyInt>>(&rows[0], 0)? else {
            return Ok(None);
        };
        let since = SystemTime::from(now - time::Duration::hours(hours));
        let mut out = Vec::new();
        for row in &s
            .pool
            .query(
                CLIENT_ENDPOINTS_SQL,
                &[&user, &since, &id, &QUOTA_EXEMPT, &AnyInt(ENDPOINT_LIMIT)],
            )
            .await
            .map_err(err)?
        {
            out.push(V2Endpoint {
                method: gt(row, 0)?,
                route: gt(row, 1)?,
                requests: gt(row, 2)?,
                refused: gt(row, 3)?,
            });
        }
        Ok(Some(out))
    }
    let path = "/api/v2/admin/stats/api-clients/{session_id}/endpoints";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            h!(stack, |s, w, r| {
                let id = r.url_param("session_id").to_owned();
                let hours = v2_int(r, "hours", 24);
                match endpoints(&s, &id, hours).await {
                    Ok(Some(list)) => {
                        write_v2_json(
                            w,
                            &V2Endpoints {
                                session_id: Id(id),
                                hours,
                                endpoints: list,
                            },
                        )
                        .await;
                    }
                    Ok(None) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(
                                super::chain::problem_type("not_found"),
                                "This session made no API requests in the window.",
                            ),
                        )
                        .await;
                    }
                    Err(_) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(internal_error(), "API usage could not be read"),
                        )
                        .await;
                    }
                }
            }),
        ),
    );
}

pub fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/admin/stats";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            h!(stack, |s, w, r| {
                match read_stats(&s, v2_refresh_requested(r)).await {
                    Ok(v) => write_v2_json(w, &v2_stats(&v)).await,
                    Err(_) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(internal_error(), "An unexpected error occurred."),
                        )
                        .await
                    }
                }
            }),
        ),
    );
    mount_v2_insights(stack, v2);
    mount_v2_clients(stack, v2);
}

#[cfg(test)]
mod tests {
    use super::parse_bool_true;

    /// Huma parses the v2 `refresh` query with `strconv.ParseBool` (M4 review, L3).
    #[test]
    fn refresh_takes_every_parse_bool_true_spelling() {
        for raw in ["1", "t", "T", "TRUE", "true", "True"] {
            assert!(parse_bool_true(raw), "{raw}");
        }
        for raw in ["", "0", "f", "false", "False", "yes", "tRUE"] {
            assert!(!parse_bool_true(raw), "{raw}");
        }
    }
}
