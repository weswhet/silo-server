//! Seek-preview administrator library status query from `internal/trickplay/admin.go`.

use silo_pg::Pool;

pub struct LibraryStatus {
    pub library_id: i64,
    pub name: String,
    pub pending: i64,
    pub running: i64,
    pub ready: i64,
    pub unusable: i64,
    pub sheet_bytes: i64,
}

pub async fn library_statuses(pool: &Pool) -> Result<Vec<LibraryStatus>, String> {
    // The aliases are Go's videoLibraryTypes, bound as PostgreSQL text[].
    let video_library_types = [
        "movie", "movies", "series", "tv", "show", "tvshows", "mixed",
    ];
    let rows = pool.query(
        r#"
		WITH files AS (
			SELECT f.id AS library_id, f.name, t.sheet_bytes,
			       CASE WHEN mf.missing_since IS NULL AND mf.probe_updated_at IS NOT NULL AND mf.duration > 0
			              AND jsonb_typeof(mf.video_tracks) = 'array' AND jsonb_array_length(mf.video_tracks) > 0
			            THEN COALESCE(t.state, 'pending')
			            WHEN t.media_file_id IS NOT NULL THEN 'unusable' END AS state
			FROM public.media_folders f
			LEFT JOIN public.media_files mf ON mf.media_folder_id = f.id
			LEFT JOIN public.media_file_trickplay t ON t.media_file_id = mf.id
			WHERE f.trickplay_enabled AND f.enabled IS NOT FALSE
			  AND lower(btrim(f.type)) = ANY($1::text[])
		)
		SELECT library_id, name,
		       count(*) FILTER (WHERE state = 'pending'),
		       count(*) FILTER (WHERE state = 'running'),
		       count(*) FILTER (WHERE state = 'ready'),
		       count(*) FILTER (WHERE state = 'unusable'),
		       COALESCE(sum(sheet_bytes), 0)::bigint
		FROM files
		GROUP BY library_id, name
		ORDER BY library_id"#,
        &[&video_library_types.as_slice()],
    ).await.map_err(|e| e.to_string())?;
    rows.iter()
        .map(|row| {
            Ok(LibraryStatus {
                library_id: row.try_get(0)?,
                name: row.try_get(1)?,
                pending: row.try_get(2)?,
                running: row.try_get(3)?,
                ready: row.try_get(4)?,
                unusable: row.try_get(5)?,
                sheet_bytes: row.try_get(6)?,
            })
        })
        .collect::<Result<Vec<_>, silo_pg::DriverError>>()
        .map_err(|e| e.to_string())
}
