//! SQL templates copied verbatim from the Go sources by a one-off extraction, so their tabs and
//! line breaks are Go's. Each names the file and line its backtick literal starts on.

/// `query_builder.go` line 211.
pub(crate) const USER_HISTORY_CTE: &str = r#"user_last_watched AS (
	SELECT watched.media_item_id, MAX(GREATEST(src.uwh_at, src.uwp_at)) AS last_watched
	FROM (
		-- Only finished plays count, as on the episode path: a title, or a
		-- show through its episodes, is dated by when it was last finished.
		SELECT uwh.media_item_id, uwh.watched_at AS uwh_at, NULL::timestamptz AS uwp_at
		FROM user_watch_history uwh
		WHERE uwh.user_id = $%d AND uwh.profile_id = $%d AND uwh.completed = TRUE
		UNION ALL
		SELECT uwp.media_item_id, NULL::timestamptz, uwp.updated_at
		FROM user_watch_progress uwp
		WHERE uwp.user_id = $%d AND uwp.profile_id = $%d AND uwp.completed = TRUE
		UNION ALL
		SELECT erp.content_id AS media_item_id, NULL::timestamptz, erp.updated_at
		FROM ebook_reader_progress erp
		WHERE erp.user_id = $%d AND erp.profile_id = $%d AND erp.progress >= %s
	) src
	LEFT JOIN episodes ep ON ep.content_id = src.media_item_id
	CROSS JOIN LATERAL (VALUES (src.media_item_id), (ep.series_id)) AS watched(media_item_id)
	WHERE watched.media_item_id IS NOT NULL
	  AND NOT EXISTS (
		SELECT 1 FROM user_history_hidden_items hhi
		WHERE hhi.user_id = $%d AND hhi.profile_id = $%d
		  AND hhi.media_item_id = src.media_item_id
		  AND COALESCE(src.uwh_at, src.uwp_at) <= hhi.hidden_before
	)
	GROUP BY watched.media_item_id
)"#;

/// `query_builder.go` line 543.
pub(crate) const PERSON_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM item_people ip
		WHERE ip.content_id = %s.content_id
		  AND ip.kind = %d
		  AND ip.person_id IN (
			SELECT p.id
			FROM people p
			WHERE LOWER(p.name) = LOWER($%d)
		  )
	)"#;

/// `query_builder.go` line 567.
pub(crate) const PERSON_KIND_SORT_JOIN: &str = r#"LEFT JOIN LATERAL (
			SELECT p.name
			FROM item_people ip
			JOIN people p ON p.id = ip.person_id
			WHERE ip.content_id = %s.content_id
			  AND ip.kind = %d
			  AND p.name IS NOT NULL
			  AND BTRIM(p.name) <> ''
			ORDER BY p.name ASC
			LIMIT 1
		) %s ON TRUE"#;

/// `query_builder.go` line 591.
pub(crate) const BOOK_SERIES_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM %s s
		WHERE s.content_id = %s.content_id
		  AND LOWER(BTRIM(s.series_name)) = LOWER(BTRIM($%d))
)"#;

/// `query_builder.go` line 611.
pub(crate) const RESOLUTION_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM media_files mf
		WHERE %s
		  AND mf.missing_since IS NULL
		  AND %s
		  AND %s = $%d
	)"#;

/// `query_builder.go` line 629.
pub(crate) const MEDIA_FILE_EQUALITY_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM media_files mf
		WHERE %s
		  AND mf.missing_since IS NULL
		  AND %s
		  AND %s = $%d
	)"#;

/// `query_builder.go` line 650.
pub(crate) const MEDIA_FILE_COMPARISON_CLAUSE: &str = r#"EXISTS (
			SELECT 1
			FROM media_files mf
			WHERE %s
			  AND mf.missing_since IS NULL
			  AND %s
			  AND %s %s $%d
		)"#;

/// `query_builder.go` line 666.
pub(crate) const MEDIA_FILE_BETWEEN_CLAUSE: &str = r#"EXISTS (
			SELECT 1
			FROM media_files mf
			WHERE %s
			  AND mf.missing_since IS NULL
			  AND %s
			  AND %s >= $%d
			  AND %s <= $%d
		)"#;

/// `query_builder.go` line 689.
pub(crate) const DOLBY_VISION_INNER: &str = r#"EXISTS (
		SELECT 1
		FROM jsonb_array_elements(COALESCE(mf.video_tracks, '[]'::jsonb)) AS vt
		WHERE NULLIF(BTRIM(vt->>'dolby_vision'), '') IS NOT NULL
	)"#;

/// `query_builder.go` line 698.
pub(crate) const DOLBY_VISION_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM media_files mf
		WHERE %s
		  AND mf.missing_since IS NULL
		  AND %s
		  AND %s
	)"#;

/// `query_builder.go` line 719.
pub(crate) const AUDIO_LANGUAGE_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM media_files mf
		WHERE %s
		  AND mf.missing_since IS NULL
		  AND %s
		  AND mf.audio_language_codes @> ARRAY[$%d]::text[]
	)"#;

/// `query_builder.go` line 744.
pub(crate) const SUBTITLE_LANGUAGE_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM media_files mf
		WHERE %s
		  AND mf.missing_since IS NULL
		  AND %s
		  AND (
			mf.subtitle_language_codes @> ARRAY[$%d]::text[]
			OR EXISTS (
				SELECT 1
				FROM jsonb_array_elements(COALESCE(mf.external_subtitles, '[]'::jsonb)) AS track
				WHERE LOWER(COALESCE(track->>'language', '')) = $%d
			)
		  )
	)"#;

/// `query_builder.go` line 807.
pub(crate) const SAME_FILE_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM media_files mf
		WHERE %s
	)"#;

/// `query_builder.go` line 839.
pub(crate) const SAME_FILE_DOLBY_VISION: &str = r#"EXISTS (
			SELECT 1
			FROM jsonb_array_elements(COALESCE(%s.video_tracks, '[]'::jsonb)) AS vt
			WHERE NULLIF(BTRIM(vt->>'dolby_vision'), '') IS NOT NULL
		)"#;

/// `query_builder.go` line 871.
pub(crate) const SAME_FILE_SUBTITLE: &str = r#"(
			%s.subtitle_language_codes @> ARRAY[$%d]::text[]
			OR EXISTS (
				SELECT 1
				FROM jsonb_array_elements(COALESCE(%s.external_subtitles, '[]'::jsonb)) AS track
				WHERE LOWER(COALESCE(track->>'language', '')) = $%d
			)
		)"#;

/// `query_builder.go` line 942.
pub(crate) const NORMALIZED_RESOLUTION: &str = r#"CASE LOWER(NULLIF(BTRIM(%s), ''))
		WHEN '4k' THEN '2160p'
		WHEN 'uhd' THEN '2160p'
		ELSE LOWER(NULLIF(BTRIM(%s), ''))
	END"#;

/// `query_builder.go` line 989.
pub(crate) const FAVORITE_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM user_favorites uf
		WHERE uf.user_id = $%d
		  AND uf.profile_id = $%d
		  AND uf.media_item_id = %s.content_id
	)"#;

/// `query_builder.go` line 1012.
pub(crate) const WATCHLIST_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM user_watchlist uw
		WHERE uw.user_id = $%d
		  AND uw.profile_id = $%d
		  AND uw.media_item_id = %s.content_id
	)"#;

/// `query_builder.go` line 1038.
pub(crate) const IN_PROGRESS_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM user_watch_progress uwp
		WHERE uwp.user_id = $%d
		  AND uwp.profile_id = $%d
		  AND uwp.media_item_id = %s.content_id
		  AND uwp.position_seconds > 0
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = $%d
			  AND hhi.profile_id = $%d
			  AND hhi.media_item_id = uwp.media_item_id
			  AND uwp.updated_at <= hhi.hidden_before
		  )
	)"#;

/// `query_builder.go` line 1063.
pub(crate) const EBOOK_IN_PROGRESS_CLAUSE: &str = r#"EXISTS (
		SELECT 1
		FROM ebook_reader_progress erp
		WHERE erp.user_id = $%d
		  AND erp.profile_id = $%d
		  AND erp.content_id = %s.content_id
		  AND erp.progress > 0
		  AND erp.progress < %s
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = $%d
			  AND hhi.profile_id = $%d
			  AND hhi.media_item_id = erp.content_id
			  AND erp.updated_at <= hhi.hidden_before
		  )
	)"#;

/// `query_builder.go` line 1304.
pub(crate) const COMPLETION_CASE: &str = r#"(CASE
		WHEN %[1]s.type = 'series' THEN %[2]s
		WHEN %[1]s.type = 'season' THEN %[3]s
		WHEN %[1]s.type = 'ebook' THEN %[4]s
		ELSE %[5]s
	END)"#;

/// `query_builder.go` line 1325.
pub(crate) const VIDEO_LEAF_COMPLETION: &str = r#"(
		EXISTS (
			SELECT 1
			FROM user_watch_progress uwp
			WHERE uwp.user_id = $%[1]d
			  AND uwp.profile_id = $%[2]d
			  AND uwp.media_item_id = %[3]s
			  AND uwp.completed = TRUE
			  AND NOT EXISTS (
				SELECT 1
				FROM user_history_hidden_items hhi
				WHERE hhi.user_id = $%[1]d
				  AND hhi.profile_id = $%[2]d
				  AND hhi.media_item_id = uwp.media_item_id
				  AND uwp.updated_at <= hhi.hidden_before
			  )
		)
		OR EXISTS (
			SELECT 1
			FROM user_watch_history uwh
			WHERE uwh.user_id = $%[1]d
			  AND uwh.profile_id = $%[2]d
			  AND uwh.media_item_id = %[3]s
			  AND uwh.completed = TRUE
			  AND NOT EXISTS (
				SELECT 1
				FROM user_history_hidden_items hhi
				WHERE hhi.user_id = $%[1]d
				  AND hhi.profile_id = $%[2]d
				  AND hhi.media_item_id = uwh.media_item_id
				  AND uwh.watched_at <= hhi.hidden_before
			  )
		)
	)"#;

/// `query_builder.go` line 1364.
pub(crate) const EBOOK_LEAF_COMPLETION: &str = r#"EXISTS (
		SELECT 1
		FROM ebook_reader_progress erp
		WHERE erp.user_id = $%[1]d
		  AND erp.profile_id = $%[2]d
		  AND erp.content_id = %[3]s
		  AND erp.progress >= %[4]s
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = $%[1]d
			  AND hhi.profile_id = $%[2]d
			  AND hhi.media_item_id = erp.content_id
			  AND erp.updated_at <= hhi.hidden_before
		  )
	)"#;

/// `query_builder.go` line 1398.
pub(crate) const EPISODE_ROLLUP_COMPLETION: &str = r#"(
		EXISTS (
			SELECT 1
			FROM episodes
			WHERE episodes.%[1]s = %[2]s.content_id
			  AND %[3]s
		)
		AND NOT EXISTS (
			SELECT 1
			FROM episodes
			WHERE episodes.%[1]s = %[2]s.content_id
			  AND %[3]s
			  AND NOT %[4]s
		)
	)"#;

/// `query_builder.go` line 1525.
pub(crate) const ADDED_EPISODE_SINGLE_JOIN: &str = r#"JOIN episode_libraries sort_added ON sort_added.episode_id = %s.content_id AND sort_added.media_folder_id = %s"#;

/// `query_builder.go` line 1533.
pub(crate) const ADDED_EPISODE_MULTI_JOIN: &str = r#"LEFT JOIN (
				SELECT el.episode_id AS content_id, MIN(el.first_seen_at) AS added_at
				FROM episode_libraries el
				WHERE el.media_folder_id IN (%s)
				GROUP BY el.episode_id
			) sort_added ON sort_added.content_id = %s.content_id"#;

/// `query_builder.go` line 1553.
pub(crate) const ADDED_SINGLE_JOIN: &str = r#"JOIN media_item_libraries sort_added ON sort_added.content_id = %s AND sort_added.media_folder_id = %s"#;

/// `query_builder.go` line 1561.
pub(crate) const ADDED_MULTI_JOIN: &str = r#"LEFT JOIN (
			SELECT mil.content_id, MIN(mil.first_seen_at) AS added_at
			FROM media_item_libraries mil
			WHERE mil.media_folder_id IN (%s)
			GROUP BY mil.content_id
		) sort_added ON sort_added.content_id = %s"#;

/// `query_builder.go` line 1589.
pub(crate) const RESOLUTION_RANK: &str = r#"MAX(
		CASE UPPER(CASE LOWER(NULLIF(BTRIM(mf.resolution), ''))
			WHEN '4k' THEN '2160p'
			WHEN 'uhd' THEN '2160p'
			ELSE LOWER(NULLIF(BTRIM(mf.resolution), ''))
		END)
			WHEN '480P' THEN 1
			WHEN '720P' THEN 2
			WHEN '1080P' THEN 3
			WHEN '2160P' THEN 4
			WHEN '4320P' THEN 5
			ELSE NULL
		END
	)"#;

/// `query_builder.go` line 1616.
pub(crate) const MEDIA_FILE_SORT_JOIN: &str = r#"LEFT JOIN (
			SELECT %s AS content_id, %s AS %s
			FROM media_files mf
			WHERE %s
			GROUP BY %s
		) sort_files ON sort_files.content_id = %s.content_id"#;

/// `query_builder.go` line 1648.
pub(crate) const PROGRESS_SORT_JOIN: &str = r#"LEFT JOIN (
			SELECT uwp.media_item_id AS content_id,
				CASE
					WHEN uwp.position_seconds > 0
					  AND COALESCE(uwp.duration_seconds, 0) > 0
					  AND (hhi.media_item_id IS NULL OR uwp.updated_at > hhi.hidden_before)
					THEN uwp.position_seconds::double precision / NULLIF(uwp.duration_seconds, 0)
					ELSE NULL
				END AS progress_ratio
			FROM user_watch_progress uwp
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $%d
			   AND hhi.profile_id = $%d
			   AND hhi.media_item_id = uwp.media_item_id
			WHERE uwp.user_id = $%d
			  AND uwp.profile_id = $%d
		) sort_progress ON sort_progress.content_id = %s.content_id"#;

/// `query_builder.go` line 1676.
pub(crate) const EBOOK_PROGRESS_SORT_JOIN: &str = r#"LEFT JOIN (
			SELECT erp.content_id,
				CASE
					WHEN erp.progress > 0
					  AND erp.progress < %s
					  AND (hhi.media_item_id IS NULL OR erp.updated_at > hhi.hidden_before)
					THEN erp.progress::double precision
					ELSE NULL
				END AS progress_ratio
			FROM ebook_reader_progress erp
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $%d
			   AND hhi.profile_id = $%d
			   AND hhi.media_item_id = erp.content_id
			WHERE erp.user_id = $%d
			  AND erp.profile_id = $%d
		) sort_progress ON sort_progress.content_id = %s.content_id"#;

/// `query_builder.go` line 1708.
pub(crate) const DATE_VIEWED_HISTORY_JOIN: &str = r#"LEFT JOIN (
			SELECT uwh.media_item_id AS content_id, MAX(uwh.watched_at) AS viewed_at
			FROM user_watch_history uwh
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $%d
			   AND hhi.profile_id = $%d
			   AND hhi.media_item_id = uwh.media_item_id
			WHERE uwh.user_id = $%d
			  AND uwh.profile_id = $%d
			  AND uwh.completed = TRUE
			  AND (hhi.media_item_id IS NULL OR uwh.watched_at > hhi.hidden_before)
			GROUP BY uwh.media_item_id
		) sort_history_viewed ON sort_history_viewed.content_id = %s.content_id"#;

/// `query_builder.go` line 1728.
pub(crate) const DATE_VIEWED_PROGRESS_JOIN: &str = r#"LEFT JOIN (
			SELECT uwp.media_item_id AS content_id,
				CASE
					WHEN uwp.completed = TRUE
					  AND (hhi.media_item_id IS NULL OR uwp.updated_at > hhi.hidden_before)
					THEN uwp.updated_at
					ELSE NULL
				END AS viewed_at
			FROM user_watch_progress uwp
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $%d
			   AND hhi.profile_id = $%d
			   AND hhi.media_item_id = uwp.media_item_id
			WHERE uwp.user_id = $%d
			  AND uwp.profile_id = $%d
		) sort_progress_viewed ON sort_progress_viewed.content_id = %s.content_id"#;

/// `query_builder.go` line 1750.
pub(crate) const DATE_VIEWED_EXPR: &str = r#"GREATEST(
		COALESCE(sort_history_viewed.viewed_at, '-infinity'::timestamptz),
		COALESCE(sort_progress_viewed.viewed_at, '-infinity'::timestamptz)
	)"#;

/// `query_builder.go` line 1759.
pub(crate) const EBOOK_DATE_VIEWED_JOIN: &str = r#"LEFT JOIN (
			SELECT erp.content_id,
				CASE
					WHEN erp.progress >= %s
					  AND (hhi.media_item_id IS NULL OR erp.updated_at > hhi.hidden_before)
					THEN erp.updated_at
					ELSE NULL
				END AS viewed_at
			FROM ebook_reader_progress erp
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $%d
			   AND hhi.profile_id = $%d
			   AND hhi.media_item_id = erp.content_id
			WHERE erp.user_id = $%d
			  AND erp.profile_id = $%d
		) sort_ebook_viewed ON sort_ebook_viewed.content_id = %s.content_id"#;

/// `query_builder.go` line 1790.
pub(crate) const PLAYS_HISTORY_JOIN: &str = r#"LEFT JOIN (
			SELECT uwh.media_item_id AS content_id, COUNT(*) AS play_count
			FROM user_watch_history uwh
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $%d
			   AND hhi.profile_id = $%d
			   AND hhi.media_item_id = uwh.media_item_id
			WHERE uwh.user_id = $%d
			  AND uwh.profile_id = $%d
			  AND uwh.completed = TRUE
			  AND (hhi.media_item_id IS NULL OR uwh.watched_at > hhi.hidden_before)
			GROUP BY uwh.media_item_id
		) sort_history_plays ON sort_history_plays.content_id = %s.content_id"#;

/// `query_builder.go` line 1810.
pub(crate) const PLAYS_PROGRESS_JOIN: &str = r#"LEFT JOIN (
			SELECT uwp.media_item_id AS content_id,
				CASE
					WHEN uwp.completed = TRUE
					  AND (hhi.media_item_id IS NULL OR uwp.updated_at > hhi.hidden_before)
					THEN 1
					ELSE 0
				END AS completed_play_count
			FROM user_watch_progress uwp
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $%d
			   AND hhi.profile_id = $%d
			   AND hhi.media_item_id = uwp.media_item_id
			WHERE uwp.user_id = $%d
			  AND uwp.profile_id = $%d
		) sort_progress_plays ON sort_progress_plays.content_id = %s.content_id"#;

/// `query_builder.go` line 1832.
pub(crate) const PLAYS_EXPR: &str = r#"NULLIF(GREATEST(
		COALESCE(sort_history_plays.play_count, 0),
		COALESCE(sort_progress_plays.completed_play_count, 0)
	), 0)"#;

/// `query_builder.go` line 1841.
pub(crate) const EBOOK_PLAYS_JOIN: &str = r#"LEFT JOIN (
			SELECT erp.content_id,
				CASE
					WHEN erp.progress >= %s
					  AND (hhi.media_item_id IS NULL OR erp.updated_at > hhi.hidden_before)
					THEN 1
					ELSE 0
				END AS completed_play_count
			FROM ebook_reader_progress erp
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $%d
			   AND hhi.profile_id = $%d
			   AND hhi.media_item_id = erp.content_id
			WHERE erp.user_id = $%d
			  AND erp.profile_id = $%d
		) sort_ebook_plays ON sort_ebook_plays.content_id = %s.content_id"#;

/// `episode_catalog_source.go` line 20.
pub(crate) const EPISODE_CATALOG_SELECT_BODY: &str = r#"(
	SELECT
		e.content_id,
		e.air_date AS episode_air_date,
		e.series_id AS episode_series_id,
		LOWER(COALESCE(NULLIF(BTRIM(si.sort_title), ''), si.title)) AS episode_series_sort_key,
		e.season_number AS episode_season_number,
		e.episode_number,
		'episode'::text AS type,
		COALESCE(NULLIF(BTRIM(e.title), ''), 'Episode ' || e.episode_number::text) AS title,
		COALESCE(NULLIF(BTRIM(e.title), ''), 'Episode ' || e.episode_number::text) AS sort_title,
		LOWER(COALESCE(NULLIF(BTRIM(e.title), ''), 'Episode ' || e.episode_number::text)) AS sort_key,
		COALESCE(NULLIF(BTRIM(e.default_metadata_language), ''), COALESCE(si.default_metadata_language, '')) AS default_metadata_language,
		''::text AS original_title,
		COALESCE(si.year, EXTRACT(YEAR FROM e.air_date)::integer, 0) AS year,
		COALESCE(si.genres, '{}'::text[]) AS genres,
		COALESCE(si.content_rating, '') AS content_rating,
		si.content_rating_age,
		si.advisory_age,
		COALESCE(si.advisory_source, '') AS advisory_source,
		COALESCE(NULLIF(e.runtime, 0), COALESCE(si.runtime, 0)) AS runtime,
		COALESCE(e.overview, '') AS overview,
		''::text AS tagline,
		e.rating_imdb,
		e.rating_tmdb,
		NULL::integer AS rating_rt_critic,
		NULL::integer AS rating_rt_audience,
		COALESCE(e.imdb_id, '') AS imdb_id,
		COALESCE(e.tmdb_id, '') AS tmdb_id,
		COALESCE(e.tvdb_id, '') AS tvdb_id,
		COALESCE(NULLIF(s.poster_path, ''), NULLIF(si.poster_path, ''), NULLIF(e.still_path, ''), '') AS poster_path,
		''::text AS poster_source_path,
		COALESCE(NULLIF(s.poster_thumbhash, ''), NULLIF(si.poster_thumbhash, ''), NULLIF(e.still_thumbhash, ''), '') AS poster_thumbhash,
		COALESCE(si.backdrop_path, '') AS backdrop_path,
		COALESCE(si.backdrop_source_path, '') AS backdrop_source_path,
		COALESCE(si.backdrop_thumbhash, '') AS backdrop_thumbhash,
		COALESCE(si.logo_path, '') AS logo_path,
		COALESCE(si.logo_source_path, '') AS logo_source_path,
		''::text AS banner_path,
		''::text AS banner_source_path,
		''::text AS banner_thumbhash,
		''::text AS thumb_path,
		''::text AS thumb_source_path,
		''::text AS thumb_thumbhash,
		''::text AS clearart_path,
		''::text AS clearart_source_path,
		''::text AS disc_path,
		''::text AS disc_source_path,
		COALESCE(e.metadata_s3_path, '') AS metadata_s3_path,
		COALESCE(e.metadata_etag, '') AS metadata_etag,
		NULL::integer AS season_count,
		COALESCE(si.studios, '{}'::text[]) AS studios,
		COALESCE(si.networks, '{}'::text[]) AS networks,
		COALESCE(si.countries, '{}'::text[]) AS countries,
		COALESCE(si.keywords, '{}'::text[]) AS keywords,
		COALESCE(si.original_language, '') AS original_language,
		CASE WHEN e.air_date IS NULL THEN NULL ELSE e.air_date::text END AS release_date,
		NULL::text AS first_air_date,
		NULL::text AS last_air_date,
		e.air_date AS last_air_date_at,
		e.air_date AS latest_available_episode_air_date_at,
		si.air_time,
		si.air_timezone,
		COALESCE(si.show_status, '') AS show_status,
		si.matched_at,
		si.last_refreshed,
		si.refresh_failures,
		si.episode_metadata_incomplete,
		si.episode_metadata_last_checked_at,
		COALESCE(si.locked_fields, '{}'::integer[]) AS locked_fields,
		COALESCE(NULLIF(BTRIM(si.status), ''), 'matched') AS status,
		e.created_at,
		e.updated_at
	FROM episodes e
	JOIN media_items si ON si.content_id = e.series_id
	LEFT JOIN seasons s ON s.content_id = e.season_id
	WHERE (%s)
	  AND si.type = 'series'
) mi"#;

/// `episode_catalog_source.go` line 104.
pub(crate) const EPISODE_CATALOG_SERIES_PARENT_GUARD: &str = r#"EXISTS (
		SELECT 1
		FROM media_items si
		WHERE si.content_id = ece.series_id
		  AND si.type = 'series'
	)"#;

/// `episode_catalog_source.go` line 111.
pub(crate) const EPISODE_CATALOG_ACTIVE_LIBRARY_EXISTS: &str = r#"EXISTS (
		SELECT 1
		FROM episode_libraries el
		WHERE el.episode_id = e.content_id
	)"#;

/// `episode_catalog_source.go` line 146.
pub(crate) const EPISODE_SCOPE_IN: &str = r#"EXISTS (
		SELECT 1
		FROM episode_libraries el_scope_in
		WHERE el_scope_in.episode_id = e.content_id
		  AND el_scope_in.media_folder_id = ANY($%d)
	)"#;

/// `episode_catalog_source.go` line 159.
pub(crate) const EPISODE_SCOPE_OUT: &str = r#"NOT EXISTS (
		SELECT 1
		FROM episode_libraries el_scope_out
		WHERE el_scope_out.episode_id = e.content_id
		  AND el_scope_out.media_folder_id = ANY($%d)
	)"#;

/// `query_executor.go` line 289.
pub(crate) const DEFERRED_EPISODE_PAGE: &str = r#"WITH page_ids AS MATERIALIZED (
			SELECT mi.content_id %s %s %s LIMIT $%d%s
		) SELECT %s %s
		JOIN page_ids ON page_ids.content_id = mi.content_id
		%s"#;

/// `episode_repo.go` line 189.
pub(crate) const EPISODE_AVAILABILITY_PREDICATE: &str = r#"EXISTS (
		SELECT 1
		FROM episode_libraries el
		WHERE el.episode_id = episodes.content_id
	)"#;

/// `episode_catalog_entries_executor.go` line 402.
pub(crate) const ECE_PAGE: &str = r#"%sSELECT ece.episode_id, ece.added_at
		%s%s
		%s
		%s
		LIMIT $%d%s"#;

/// `episode_catalog_entries_executor.go` line 471.
pub(crate) const ECE_COUNT_LIMIT: &str = r#"%sSELECT COUNT(*)
			FROM (SELECT 1 %s %s LIMIT $%d) sub"#;

/// `episode_catalog_entries_executor.go` line 480.
pub(crate) const ECE_COUNT: &str = r#"%sSELECT COUNT(*)
		%s
		%s"#;

/// `episode_catalog_entries_executor.go` line 659.
pub(crate) const ECE_PROGRESS_RATIO_GATE: &str = r#"
				  AND COALESCE(uwp.duration_seconds, 0) > 0"#;

/// `episode_catalog_entries_executor.go` line 662.
pub(crate) const ECE_PROGRESS_CTE: &str = r#"user_progress AS (
				SELECT uwp.media_item_id AS episode_id,
					uwp.position_seconds::double precision / NULLIF(uwp.duration_seconds, 0) AS progress_ratio
				FROM user_watch_progress uwp
			LEFT JOIN user_history_hidden_items hhi
				ON hhi.user_id = $1
			   AND hhi.profile_id = $2
			   AND hhi.media_item_id = uwp.media_item_id
			WHERE uwp.user_id = $1
				  AND uwp.profile_id = $2
				  AND uwp.position_seconds > 0%s
				  AND (hhi.media_item_id IS NULL OR uwp.updated_at > hhi.hidden_before)
			)"#;

/// `episode_catalog_entries_executor.go` line 676.
pub(crate) const ECE_VIEWED_CTE: &str = r#"user_viewed AS (
			SELECT src.episode_id,
				MAX(src.last_watched) AS last_watched,
				NULLIF(GREATEST(
					COALESCE(MAX(src.history_play_count), 0),
					COALESCE(MAX(src.progress_play_count), 0)
				), 0) AS play_count
			FROM (
				SELECT uwh.media_item_id AS episode_id,
					MAX(uwh.watched_at) AS last_watched,
					COUNT(*)::integer AS history_play_count,
					NULL::integer AS progress_play_count
				FROM user_watch_history uwh
				LEFT JOIN user_history_hidden_items hhi
					ON hhi.user_id = $1
				   AND hhi.profile_id = $2
				   AND hhi.media_item_id = uwh.media_item_id
				WHERE uwh.user_id = $1
				  AND uwh.profile_id = $2
				  AND uwh.completed = TRUE
				  AND (hhi.media_item_id IS NULL OR uwh.watched_at > hhi.hidden_before)
				GROUP BY uwh.media_item_id
				UNION ALL
				SELECT uwp.media_item_id AS episode_id,
					uwp.updated_at AS last_watched,
					NULL::integer AS history_play_count,
					1 AS progress_play_count
				FROM user_watch_progress uwp
				LEFT JOIN user_history_hidden_items hhi
					ON hhi.user_id = $1
				   AND hhi.profile_id = $2
				   AND hhi.media_item_id = uwp.media_item_id
				WHERE uwp.user_id = $1
				  AND uwp.profile_id = $2
				  AND uwp.completed = TRUE
				  AND (hhi.media_item_id IS NULL OR uwp.updated_at > hhi.hidden_before)
			) src
			GROUP BY src.episode_id
		)"#;
