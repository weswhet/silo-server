//! The administrator library reads: matcher queues (`metadata.MovieMatchQueueRepository`,
//! `SeriesRootMatchQueueRepository`, `scanner.FileRepository`), scanned roots and overrides
//! (`scanner`), skipped roots and stale IDs (`metadata`), provider chains (`metadata/chain.go`), the
//! monitor's reports (`librarymonitor`), and `adminjob.Repository.GetByID`.

use std::collections::HashMap;
use std::time::SystemTime;

use silo_pg::{AnyInt, Pool, Row, TextValue};

/// A failed read, by message: every caller maps it to its route's own refusal.
pub type Result<T> = std::result::Result<T, String>;

fn db(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn int(row: &Row, i: usize) -> Result<i64> {
    row.try_get::<_, AnyInt>(i).map(|v| v.0).map_err(db)
}

fn text(row: &Row, i: usize) -> Result<String> {
    row.try_get(i).map_err(db)
}

fn when(row: &Row, i: usize) -> Result<SystemTime> {
    row.try_get(i).map_err(db)
}

fn when_opt(row: &Row, i: usize) -> Result<Option<SystemTime>> {
    row.try_get(i).map_err(db)
}

fn json_opt(row: &Row, i: usize) -> Result<Option<String>> {
    row.try_get::<_, Option<TextValue>>(i)
        .map(|v| v.map(|t| t.0))
        .map_err(db)
}

/// `MatchQueueStateCounts`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateCounts {
    pub pending: i64,
    pub parked: i64,
}

/// `RawMatchBacklogMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawBacklogMode {
    Generic,
    NonSeries,
    Mixed,
}

impl RawBacklogMode {
    fn as_str(self) -> &'static str {
        match self {
            RawBacklogMode::Generic => "generic",
            RawBacklogMode::NonSeries => "non_series",
            RawBacklogMode::Mixed => "mixed",
        }
    }
}

async fn state_counts(pool: &Pool, sql: &str, ids: &[i32]) -> Result<HashMap<i32, StateCounts>> {
    let mut counts = HashMap::new();
    if ids.is_empty() {
        return Ok(counts);
    }
    let ids = ids.to_vec();
    for row in pool.query(sql, &[&ids]).await.map_err(db)? {
        counts.insert(
            int(&row, 0)? as i32,
            StateCounts {
                pending: int(&row, 1)?,
                parked: int(&row, 2)?,
            },
        );
    }
    Ok(counts)
}

/// `MovieMatchQueueRepository.CountStatesByFolders`.
pub async fn movie_state_counts(pool: &Pool, ids: &[i32]) -> Result<HashMap<i32, StateCounts>> {
    state_counts(
        pool,
        "
		SELECT
			media_folder_id,
			COUNT(*) FILTER (WHERE state = 'pending'),
			COUNT(*) FILTER (WHERE state = 'parked')
		FROM movie_match_queue
		WHERE media_folder_id = ANY($1)
		GROUP BY media_folder_id
	",
        ids,
    )
    .await
}

/// `SeriesRootMatchQueueRepository.CountStatesByFolders`.
pub async fn series_state_counts(pool: &Pool, ids: &[i32]) -> Result<HashMap<i32, StateCounts>> {
    state_counts(
        pool,
        "
		SELECT
			media_folder_id,
			COUNT(*) FILTER (WHERE state = 'pending'),
			COUNT(*) FILTER (WHERE state = 'parked')
		FROM series_root_match_queue
		WHERE media_folder_id = ANY($1)
		GROUP BY media_folder_id
	",
        ids,
    )
    .await
}

const RAW_BACKLOG_ELIGIBLE: &str = "
		  AND (mf.content_id IS NULL OR mf.content_id = '') AND mf.extra_id IS NULL
		  AND mf.missing_since IS NULL
		  AND mf.match_suppressed_at IS NULL
		  AND folders.enabled = true
		  AND (
			$2 = 'generic'
			OR ($2 = 'non_series' AND lower(trim(folders.type)) NOT IN ('series', 'tv', 'show', 'tvshows'))
			OR (
				$2 = 'mixed'
				AND lower(trim(folders.type)) NOT IN ('series', 'tv', 'show', 'tvshows', 'movie', 'movies')
				AND lower(trim(COALESCE(mf.base_type, ''))) NOT IN ('series', 'movie')
			)
		  )";

/// `FileRepository.CountUnmatchedMatchBacklogByFolders`.
pub async fn raw_backlog_counts(
    pool: &Pool,
    ids: &[i32],
    mode: RawBacklogMode,
) -> Result<HashMap<i32, i64>> {
    let mut counts = HashMap::new();
    if ids.is_empty() {
        return Ok(counts);
    }
    let sql = format!(
        "
		SELECT mf.media_folder_id, COUNT(*)
		FROM media_files mf
		JOIN media_folders folders ON folders.id = mf.media_folder_id
		WHERE mf.media_folder_id = ANY($1){RAW_BACKLOG_ELIGIBLE}
		GROUP BY mf.media_folder_id
	"
    );
    let ids = ids.to_vec();
    let mode = mode.as_str();
    for row in pool.query(&sql, &[&ids, &mode]).await.map_err(db)? {
        counts.insert(int(&row, 0)? as i32, int(&row, 1)?);
    }
    Ok(counts)
}

/// `models.MovieMatchQueueEntry`, and with `path` the series root entry.
#[derive(Clone, Debug)]
pub struct QueueEntry {
    pub media_file_id: i64,
    pub media_folder_id: i64,
    /// `FilePath` or `ObservedRootPath`.
    pub path: String,
    pub first_queued_at: SystemTime,
    pub available_at: SystemTime,
    pub last_attempted_at: Option<SystemTime>,
    pub attempt_count: i64,
    pub last_error: String,
    pub state: String,
    pub failure_kind: String,
    pub failure_detail: Option<String>,
    pub deterministic_attempt_count: i64,
    pub matcher_revision: i64,
    pub parked_at: Option<SystemTime>,
    pub updated_at: SystemTime,
}

/// `MovieMatchQueueRepository.ListByFolder`.
pub async fn list_movie_queue(
    pool: &Pool,
    folder: i32,
    limit: i64,
    offset: i64,
) -> Result<(Vec<QueueEntry>, i64)> {
    if folder <= 0 {
        return Err("folder id must be positive".to_owned());
    }
    let total = pool
        .query(
            "
		SELECT COUNT(*) FROM movie_match_queue WHERE media_folder_id = $1
	",
            &[&folder],
        )
        .await
        .map_err(db)?;
    let total = total.first().map_or(Ok(0), |r| int(r, 0))?;
    let rows = pool
        .query(
            "
		SELECT
			q.media_file_id,
			q.media_folder_id,
			COALESCE(mf.file_path, '') AS file_path,
			q.first_queued_at,
			q.available_at,
			q.last_attempted_at,
			q.attempt_count,
			q.last_error,
			q.state,
			q.failure_kind,
			q.failure_detail,
			q.deterministic_attempt_count,
			q.input_fingerprint,
			q.matcher_revision,
			q.parked_at,
			q.updated_at
		FROM movie_match_queue q
		LEFT JOIN media_files mf ON mf.id = q.media_file_id
		WHERE q.media_folder_id = $1
		ORDER BY (q.state = 'parked') DESC, q.available_at ASC, q.last_attempted_at ASC NULLS FIRST, q.media_file_id ASC
		LIMIT $2 OFFSET $3
	",
            &[&folder, &limit, &offset],
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(QueueEntry {
            media_file_id: int(r, 0)?,
            media_folder_id: int(r, 1)?,
            path: text(r, 2)?,
            first_queued_at: when(r, 3)?,
            available_at: when(r, 4)?,
            last_attempted_at: when_opt(r, 5)?,
            attempt_count: int(r, 6)?,
            last_error: text(r, 7)?,
            state: text(r, 8)?,
            failure_kind: text(r, 9)?,
            failure_detail: json_opt(r, 10)?,
            deterministic_attempt_count: int(r, 11)?,
            matcher_revision: int(r, 13)?,
            parked_at: when_opt(r, 14)?,
            updated_at: when(r, 15)?,
        });
    }
    Ok((out, total))
}

/// `SeriesRootMatchQueueRepository.ListByFolder`.
pub async fn list_series_queue(
    pool: &Pool,
    folder: i32,
    limit: i64,
    offset: i64,
) -> Result<(Vec<QueueEntry>, i64)> {
    if folder <= 0 {
        return Err("folder id must be positive".to_owned());
    }
    let total = pool
        .query(
            "
		SELECT COUNT(*) FROM series_root_match_queue WHERE media_folder_id = $1
	",
            &[&folder],
        )
        .await
        .map_err(db)?;
    let total = total.first().map_or(Ok(0), |r| int(r, 0))?;
    let rows = pool
        .query(
            "
		SELECT media_folder_id, observed_root_path, first_queued_at, available_at, last_attempted_at, attempt_count, last_error,
			state, failure_kind, failure_detail, deterministic_attempt_count, input_fingerprint, matcher_revision, parked_at, updated_at
		FROM series_root_match_queue
		WHERE media_folder_id = $1
		ORDER BY (state = 'parked') DESC, available_at ASC, last_attempted_at ASC NULLS FIRST, observed_root_path ASC
		LIMIT $2 OFFSET $3
	",
            &[&folder, &limit, &offset],
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(QueueEntry {
            media_file_id: 0,
            media_folder_id: int(r, 0)?,
            path: text(r, 1)?,
            first_queued_at: when(r, 2)?,
            available_at: when(r, 3)?,
            last_attempted_at: when_opt(r, 4)?,
            attempt_count: int(r, 5)?,
            last_error: text(r, 6)?,
            state: text(r, 7)?,
            failure_kind: text(r, 8)?,
            failure_detail: json_opt(r, 9)?,
            deterministic_attempt_count: int(r, 10)?,
            matcher_revision: int(r, 12)?,
            parked_at: when_opt(r, 13)?,
            updated_at: when(r, 14)?,
        });
    }
    Ok((out, total))
}

/// The columns of `models.MediaFile` the raw backlog shows.
#[derive(Clone, Debug)]
pub struct RawBacklogFile {
    pub id: i64,
    pub media_folder_id: i64,
    pub file_path: String,
    pub base_title: String,
    pub base_year: i64,
    pub base_type: String,
    pub match_attempted_at: Option<SystemTime>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

/// `FileRepository.ListUnmatchedMatchBacklogByFolder`.
pub async fn list_raw_backlog(
    pool: &Pool,
    folder: i32,
    mode: RawBacklogMode,
    limit: i64,
    offset: i64,
) -> Result<(Vec<RawBacklogFile>, i64)> {
    let (limit, offset) = (if limit <= 0 { 50 } else { limit }, offset.max(0));
    let mode = mode.as_str();
    let sql = format!(
        "
		SELECT COUNT(*)
		FROM media_files mf
		JOIN media_folders folders ON folders.id = mf.media_folder_id
		WHERE mf.media_folder_id = $1{RAW_BACKLOG_ELIGIBLE}
	"
    );
    let total = pool.query(&sql, &[&folder, &mode]).await.map_err(db)?;
    let total = total.first().map_or(Ok(0), |r| int(r, 0))?;
    let sql = format!(
        "
		SELECT mf.id, mf.media_folder_id, mf.file_path, COALESCE(mf.base_title, ''), COALESCE(mf.base_year, 0), COALESCE(mf.base_type, ''),
		       mf.match_attempted_at, mf.created_at, mf.updated_at
		FROM media_files mf
		JOIN media_folders folders ON folders.id = mf.media_folder_id
		WHERE mf.media_folder_id = $1{RAW_BACKLOG_ELIGIBLE}
		ORDER BY mf.match_attempted_at ASC NULLS FIRST, mf.id ASC
		LIMIT $3 OFFSET $4
	"
    );
    let rows = pool
        .query(&sql, &[&folder, &mode, &limit, &offset])
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(RawBacklogFile {
            id: int(r, 0)?,
            media_folder_id: int(r, 1)?,
            file_path: text(r, 2)?,
            base_title: text(r, 3)?,
            base_year: int(r, 4)?,
            base_type: text(r, 5)?,
            match_attempted_at: when_opt(r, 6)?,
            created_at: when(r, 7)?,
            updated_at: when(r, 8)?,
        });
    }
    Ok((out, total))
}

/// `models.ScannedMediaGroup`.
#[derive(Clone, Debug)]
pub struct ScannedGroup {
    pub group_key_version: i64,
    pub content_group_key: String,
    pub state: String,
    pub inferred_type: String,
    pub type_confidence: String,
    pub base_title: String,
    pub base_year: i64,
    pub tmdb_id: String,
    pub imdb_id: String,
    pub tvdb_id: String,
    pub observed_file_count: i64,
    pub sample_file_path: String,
    pub sample_observed_root_path: String,
    pub evidence_json: Option<String>,
    pub override_source: String,
    pub first_seen_at: SystemTime,
    pub last_seen_at: SystemTime,
}

/// `escapeLikePattern`.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// `ScannedGroupRepository.ListByFolder`.
pub async fn list_scanned_groups(
    pool: &Pool,
    folder: i32,
    state: &str,
    search: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ScannedGroup>, i64)> {
    let state = silo_gocompat::strings::trim_space(state).to_owned();
    let search = silo_gocompat::strings::trim_space(search);
    let pattern = format!("%{}%", escape_like(search));
    let mut filter = "WHERE media_folder_id = $1".to_owned();
    let mut args: Vec<&(dyn silo_pg::ToSql + Sync)> = vec![&folder];
    if !state.is_empty() {
        args.push(&state);
        filter.push_str(&format!(" AND state = ${}", args.len()));
    }
    if !search.is_empty() {
        args.push(&pattern);
        let n = args.len();
        filter.push_str(&format!(
            " AND (sample_observed_root_path ILIKE ${n} ESCAPE '\\' OR base_title ILIKE ${n} ESCAPE '\\' OR sample_file_path ILIKE ${n} ESCAPE '\\')"
        ));
    }
    let count = pool
        .query(
            &format!("SELECT COUNT(*) FROM scanned_media_groups {filter}"),
            &args,
        )
        .await
        .map_err(db)?;
    let total = count.first().map_or(Ok(0), |r| int(r, 0))?;
    let at = args.len() + 1;
    args.push(&limit);
    args.push(&offset);
    let rows = pool
        .query(
            &format!(
                "
		SELECT media_folder_id, group_key_version, content_group_key, state, inferred_type,
	type_confidence, base_title, base_year, tmdb_id, imdb_id, tvdb_id, observed_file_count,
	sample_file_path, sample_observed_root_path, evidence_json, override_source, first_seen_at, last_seen_at
		FROM scanned_media_groups
		{filter} ORDER BY last_seen_at DESC, sample_observed_root_path ASC, content_group_key ASC LIMIT ${at} OFFSET ${}",
                at + 1
            ),
            &args,
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(ScannedGroup {
            group_key_version: int(r, 1)?,
            content_group_key: text(r, 2)?,
            state: text(r, 3)?,
            inferred_type: text(r, 4)?,
            type_confidence: text(r, 5)?,
            base_title: text(r, 6)?,
            base_year: int(r, 7)?,
            tmdb_id: text(r, 8)?,
            imdb_id: text(r, 9)?,
            tvdb_id: text(r, 10)?,
            observed_file_count: int(r, 11)?,
            sample_file_path: text(r, 12)?,
            sample_observed_root_path: text(r, 13)?,
            evidence_json: json_opt(r, 14)?,
            override_source: text(r, 15)?,
            first_seen_at: when(r, 16)?,
            last_seen_at: when(r, 17)?,
        });
    }
    Ok((out, total))
}

/// `models.MediaGroupOverride`, what the listing shows of it.
#[derive(Clone, Debug)]
pub struct GroupOverride {
    pub group_key_version: i64,
    pub content_group_key: String,
    pub forced_type: String,
    pub forced_title: String,
    pub forced_year: i64,
    pub forced_tmdb_id: String,
    pub forced_imdb_id: String,
    pub forced_tvdb_id: String,
    pub note: String,
}

/// `MediaGroupOverrideRepository.ListByFolder`.
pub async fn list_group_overrides(pool: &Pool, folder: i32) -> Result<Vec<GroupOverride>> {
    let rows = pool
        .query(
            "
		SELECT media_folder_id, group_key_version, content_group_key,
	forced_type, forced_title, forced_year, forced_tmdb_id, forced_imdb_id, forced_tvdb_id,
	note, created_by_user_id, updated_by_user_id, created_at, updated_at
		FROM media_group_overrides
		WHERE media_folder_id = $1
		ORDER BY group_key_version ASC, content_group_key ASC
	",
            &[&folder],
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(GroupOverride {
            group_key_version: int(r, 1)?,
            content_group_key: text(r, 2)?,
            forced_type: text(r, 3)?,
            forced_title: text(r, 4)?,
            forced_year: int(r, 5)?,
            forced_tmdb_id: text(r, 6)?,
            forced_imdb_id: text(r, 7)?,
            forced_tvdb_id: text(r, 8)?,
            note: text(r, 9)?,
        });
    }
    Ok(out)
}

/// The claim query of `ListLibraryRoots`, as (version, key, content id).
pub async fn list_group_claims(pool: &Pool, folder: i32) -> Result<Vec<(i64, String, String)>> {
    let rows = pool
        .query(
            "
			SELECT group_key_version, content_group_key, content_id
			FROM media_item_groups
			WHERE media_folder_id = $1
		",
            &[&folder],
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push((int(r, 0)?, text(r, 1)?, text(r, 2)?));
    }
    Ok(out)
}

/// `models.SkippedMediaRoot`.
#[derive(Clone, Debug)]
pub struct SkippedRoot {
    pub media_folder_id: i64,
    pub root_path: String,
    pub reason: String,
    pub sample_file_path: String,
    pub file_count: i64,
    pub first_seen_at: SystemTime,
    pub last_seen_at: SystemTime,
}

const SKIPPED_ROOT_COLUMNS: &str =
    "media_folder_id, root_path, reason, sample_file_path, file_count, first_seen_at, last_seen_at";
const SKIPPED_ROOT_SEARCH: &str =
    "$1 = '' OR strpos(lower(root_path), lower($1)) > 0 OR strpos(lower(reason), lower($1)) > 0
 OR media_folder_id IN (SELECT id FROM media_folders WHERE strpos(lower(name), lower($1)) > 0)";

fn scan_skipped(rows: &[Row]) -> Result<Vec<SkippedRoot>> {
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(SkippedRoot {
            media_folder_id: int(r, 0)?,
            root_path: text(r, 1)?,
            reason: text(r, 2)?,
            sample_file_path: text(r, 3)?,
            file_count: int(r, 4)?,
            first_seen_at: when(r, 5)?,
            last_seen_at: when(r, 6)?,
        });
    }
    Ok(out)
}

/// `SkippedRootRepository.ListAll`.
pub async fn list_all_skipped(pool: &Pool) -> Result<Vec<SkippedRoot>> {
    let sql = format!(
        "
		SELECT {SKIPPED_ROOT_COLUMNS}
		FROM skipped_media_roots
		ORDER BY last_seen_at DESC, media_folder_id ASC, root_path ASC
	"
    );
    scan_skipped(&pool.query(&sql, &[]).await.map_err(db)?)
}

/// `SkippedRootRepository.ListPage`.
pub async fn list_skipped_page(
    pool: &Pool,
    search: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<SkippedRoot>> {
    let sql = format!(
        "SELECT {SKIPPED_ROOT_COLUMNS} FROM skipped_media_roots
 WHERE {SKIPPED_ROOT_SEARCH}
 ORDER BY last_seen_at DESC, media_folder_id ASC, root_path ASC LIMIT $2 OFFSET $3"
    );
    let offset = offset.max(0);
    scan_skipped(
        &pool
            .query(&sql, &[&search, &limit, &offset])
            .await
            .map_err(db)?,
    )
}

/// `SkippedRootRepository.Count`.
pub async fn count_skipped(pool: &Pool, search: &str) -> Result<i64> {
    let sql = format!("SELECT COUNT(*) FROM skipped_media_roots WHERE {SKIPPED_ROOT_SEARCH}");
    let rows = pool.query(&sql, &[&search]).await.map_err(db)?;
    rows.first().map_or(Ok(0), |r| int(r, 0))
}

/// `models.StaleMediaID`.
#[derive(Clone, Debug)]
pub struct StaleId {
    pub content_id: String,
    pub provider: String,
    pub provider_id: String,
    pub first_seen_at: SystemTime,
    pub last_seen_at: SystemTime,
}

/// The item fields of `listAllStaleIDs`.
#[derive(Clone, Debug, Default)]
pub struct StaleItem {
    pub title: String,
    pub year: i64,
    pub content_type: String,
    pub status: String,
    pub tmdb_id: String,
    pub tvdb_id: String,
    pub imdb_id: String,
    pub library_id: i64,
    pub library_name: String,
}

/// `StaleMediaIDRepository.ListAll`.
pub async fn list_all_stale(pool: &Pool) -> Result<Vec<StaleId>> {
    let rows = pool
        .query(
            "
		SELECT content_id, provider, provider_id, first_seen_at, last_seen_at
		FROM stale_media_ids
		ORDER BY last_seen_at DESC, content_id ASC
	",
            &[],
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(StaleId {
            content_id: text(r, 0)?,
            provider: text(r, 1)?,
            provider_id: text(r, 2)?,
            first_seen_at: when(r, 3)?,
            last_seen_at: when(r, 4)?,
        });
    }
    Ok(out)
}

/// The item query of `listAllStaleIDs`.
pub async fn stale_items(pool: &Pool, ids: &[String]) -> Result<HashMap<String, StaleItem>> {
    let ids = ids.to_vec();
    let rows = pool
        .query(
            "
		SELECT mi.content_id, mi.title, mi.year, mi.type, COALESCE(mi.status, ''),
		       COALESCE(mi.tmdb_id, ''), COALESCE(mi.tvdb_id, ''), COALESCE(mi.imdb_id, ''),
		       COALESCE(mf_lib.folder_id, 0),
		       COALESCE(mf_lib.folder_name, '')
		FROM media_items mi
		LEFT JOIN LATERAL (
			SELECT mf2.media_folder_id AS folder_id, f.name AS folder_name
			FROM media_files mf2
			JOIN media_folders f ON f.id = mf2.media_folder_id
			WHERE mf2.content_id = mi.content_id
			LIMIT 1
		) mf_lib ON true
		WHERE mi.content_id = ANY($1)
	",
            &[&ids],
        )
        .await
        .map_err(db)?;
    let mut out = HashMap::new();
    for r in &rows {
        // Go logs a row it cannot scan and goes on.
        let item = (|| {
            Ok::<_, String>(StaleItem {
                title: text(r, 1)?,
                year: int(r, 2)?,
                content_type: text(r, 3)?,
                status: text(r, 4)?,
                tmdb_id: text(r, 5)?,
                tvdb_id: text(r, 6)?,
                imdb_id: text(r, 7)?,
                library_id: int(r, 8)?,
                library_name: text(r, 9)?,
            })
        })();
        if let (Ok(id), Ok(item)) = (text(r, 0), item) {
            out.insert(id, item);
        }
    }
    Ok(out)
}

/// `ActionableStaleMediaID`.
#[derive(Clone, Debug)]
pub struct ActionableStale {
    pub stale: StaleId,
    pub title: String,
    pub year: i64,
    pub content_type: String,
    pub library_id: i64,
    pub library_name: String,
}

/// `actionableStaleIDSearchFrom`.
const ACTIONABLE_STALE_FROM: &str = r"
		FROM stale_media_ids s
		LEFT JOIN media_items mi ON mi.content_id = s.content_id
		LEFT JOIN LATERAL (
			SELECT mf.media_folder_id AS folder_id, f.name AS folder_name
			FROM media_files mf
			JOIN media_folders f ON f.id = mf.media_folder_id
			WHERE mf.content_id = s.content_id
			LIMIT 1
		) lib ON true
		WHERE 
	btrim(s.provider_id) <> ''
	AND lower(btrim(s.provider)) IN ('tmdb', 'tvdb', 'imdb')
	AND (
		(
			btrim(s.content_id) ~ '^(movie|series)-(tmdb|tvdb)-[0-9]+$|^season-(tmdb|tvdb)-[0-9]+-[0-9]+$|^episode-(tmdb|tvdb)-[0-9]+-[0-9]+-[0-9]+$|^(movie|series)-imdb-[tT][tT][0-9]+$|^season-imdb-[tT][tT][0-9]+-[0-9]+$|^episode-imdb-[tT][tT][0-9]+-[0-9]+-[0-9]+$'
			AND split_part(btrim(s.content_id), '-', 2) = lower(btrim(s.provider))
			AND CASE WHEN lower(btrim(s.provider)) = 'imdb'
				THEN lower(split_part(btrim(s.content_id), '-', 3)) = lower(btrim(s.provider_id))
				ELSE split_part(btrim(s.content_id), '-', 3) = btrim(s.provider_id)
			END
		)
		OR CASE lower(btrim(s.provider))
			WHEN 'tmdb' THEN btrim(COALESCE(mi.tmdb_id, '')) = btrim(s.provider_id)
			WHEN 'tvdb' THEN btrim(COALESCE(mi.tvdb_id, '')) = btrim(s.provider_id)
			ELSE lower(btrim(COALESCE(mi.imdb_id, ''))) = lower(btrim(s.provider_id))
		END
		OR lower(btrim(COALESCE(mi.status, ''))) <> 'matched'
	)
		AND ($1 = '' OR strpos(lower(COALESCE(mi.title, '')), lower($1)) > 0 OR strpos(lower(s.provider), lower($1)) > 0 OR strpos(lower(s.provider_id), lower($1)) > 0 OR strpos(lower(COALESCE(lib.folder_name, '')), lower($1)) > 0)";

/// `StaleMediaIDRepository.ListActionable`.
pub async fn list_actionable_stale(
    pool: &Pool,
    limit: i64,
    offset: i64,
    search: &str,
) -> Result<Vec<ActionableStale>> {
    let sql = format!(
        "
		SELECT s.content_id, s.provider, s.provider_id, s.first_seen_at, s.last_seen_at,
		       COALESCE(mi.title, ''), COALESCE(mi.year, 0), COALESCE(mi.type, ''),
		       COALESCE(lib.folder_id, 0), COALESCE(lib.folder_name, '')
		{ACTIONABLE_STALE_FROM}
		ORDER BY s.last_seen_at DESC, s.content_id ASC, s.provider ASC, s.provider_id ASC
		LIMIT $2 OFFSET $3
	"
    );
    let rows = pool
        .query(&sql, &[&search, &limit, &offset])
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(ActionableStale {
            stale: StaleId {
                content_id: text(r, 0)?,
                provider: text(r, 1)?,
                provider_id: text(r, 2)?,
                first_seen_at: when(r, 3)?,
                last_seen_at: when(r, 4)?,
            },
            title: text(r, 5)?,
            year: int(r, 6)?,
            content_type: text(r, 7)?,
            library_id: int(r, 8)?,
            library_name: text(r, 9)?,
        });
    }
    Ok(out)
}

/// `StaleMediaIDRepository.CountActionable`.
pub async fn count_actionable_stale(pool: &Pool, search: &str) -> Result<i64> {
    let sql = format!("SELECT COUNT(*) {ACTIONABLE_STALE_FROM}");
    let rows = pool.query(&sql, &[&search]).await.map_err(db)?;
    rows.first().map_or(Ok(0), |r| int(r, 0))
}

fn numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `contentid.ProviderAnchor`.
fn provider_anchor(content_id: &str) -> Option<(String, String)> {
    let id = silo_gocompat::strings::trim_space(content_id);
    let (kind, rest) = id.split_once('-')?;
    let parts: Vec<&str> = rest.split('-').collect();
    let want = match kind {
        "movie" | "series" => 2,
        "season" => 3,
        "episode" => 4,
        _ => return None,
    };
    if parts.len() != want {
        return None;
    }
    let raw = silo_gocompat::strings::trim_space(parts[1]);
    let valid = match parts[0] {
        "imdb" => {
            let lower = silo_gocompat::strings::to_lower(raw);
            lower.strip_prefix("tt").is_some_and(numeric)
        }
        "tmdb" | "tvdb" => numeric(raw),
        _ => false,
    };
    if !valid || !parts[2..].iter().all(|n| numeric(n)) {
        return None;
    }
    Some((parts[0].to_owned(), parts[1].to_owned()))
}

/// `metadata.IsActionableStaleProviderID`.
pub fn is_actionable_stale(content_id: &str, item: &StaleItem, stale: &StaleId) -> bool {
    use silo_gocompat::strings::{equal_fold, trim_space};
    let provider_id = trim_space(&stale.provider_id);
    if provider_id.is_empty() {
        return false;
    }
    let provider = silo_gocompat::strings::to_lower(trim_space(&stale.provider));
    if !matches!(provider.as_str(), "tmdb" | "tvdb" | "imdb") {
        return false;
    }
    let norm = |value: &str| -> String {
        let value = trim_space(value);
        if provider == "imdb" {
            silo_gocompat::strings::to_lower(value)
        } else {
            value.to_owned()
        }
    };
    let same = |left: &str, right: &str| {
        let (left, right) = (norm(left), norm(right));
        !left.is_empty() && !right.is_empty() && left == right
    };
    if let Some((anchor_provider, anchor_id)) = provider_anchor(content_id)
        && provider == anchor_provider
        && same(provider_id, &anchor_id)
    {
        return true;
    }
    let current = match provider.as_str() {
        "tmdb" => &item.tmdb_id,
        "tvdb" => &item.tvdb_id,
        _ => &item.imdb_id,
    };
    if same(provider_id, current) {
        return true;
    }
    !equal_fold(trim_space(&item.status), "matched")
}

/// `metadata.ChainEntry`, as the library rows show it.
#[derive(Clone, Debug)]
pub struct ChainEntry {
    pub plugin_installation_id: i64,
    pub capability_id: String,
    pub content_level: String,
    pub priority: i64,
    pub enabled: bool,
    pub local: bool,
}

/// `ChainRepository.GetAllChainEntries`.
pub async fn all_chain_entries(pool: &Pool, folder: i32) -> Result<Vec<ChainEntry>> {
    let rows = pool
        .query(
            "SELECT c.plugin_installation_id, c.capability_id, c.capability_type, c.content_level, c.priority, c.enabled,
		        COALESCE(pi.kind = 'builtin', false)
		 FROM library_provider_chains c
		 LEFT JOIN plugin_installations pi ON pi.id = c.plugin_installation_id
		 WHERE c.media_folder_id = $1
		 ORDER BY c.content_level, c.priority ASC",
            &[&folder],
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(ChainEntry {
            plugin_installation_id: int(r, 0)?,
            capability_id: text(r, 1)?,
            content_level: text(r, 3)?,
            priority: int(r, 4)?,
            enabled: r.try_get(5).map_err(db)?,
            local: r.try_get(6).map_err(db)?,
        });
    }
    Ok(out)
}

/// `metadata.ContentLevelsForLibraryType`.
pub fn content_levels(library_type: &str) -> &'static [&'static str] {
    match library_type {
        "series" => &["series", "season", "episode"],
        "movies" | "movie" => &["movie"],
        "audiobooks" | "audiobook" => &["audiobook"],
        "ebooks" | "ebook" => &["ebook"],
        "manga" => &["manga"],
        "mixed" => &["movie", "series", "season", "episode", "audiobook", "ebook"],
        _ => &[],
    }
}

/// `capabilityMetadataField`. Go's `json.Unmarshal` into maps of raw messages.
fn capability_field(metadata: &[u8], key: &str) -> Option<silo_gocompat::json::RawMessage> {
    use silo_gocompat::json::{RawMessage, unmarshal};
    let meta: HashMap<String, RawMessage> = unmarshal(metadata).ok()?;
    if let Some(raw) = meta.get(key) {
        return Some(raw.clone());
    }
    let inner: HashMap<String, RawMessage> =
        unmarshal(meta.get("metadata")?.as_bytes().unwrap_or(b"null")).ok()?;
    inner.get(key).cloned()
}

/// `declaredPriorityLevels`.
fn declared_priority_levels(metadata: &[u8]) -> (HashMap<String, f64>, bool) {
    let parsed = capability_field(metadata, "default_priority").and_then(|raw| {
        silo_gocompat::json::unmarshal::<Option<HashMap<String, f64>>>(
            raw.as_bytes().unwrap_or(b"null"),
        )
        .ok()
    });
    let levels = parsed.flatten().unwrap_or_default();
    let declared = !levels.is_empty();
    (levels, declared)
}

/// One candidate of `seedDefaultChain` at a level.
#[derive(Clone, Debug)]
struct SeedCandidate {
    installation_id: i64,
    capability_id: String,
    local: bool,
    declared_priority: i64,
    default_enabled: bool,
}

/// `seedDefaultChain`, from `ListEnabledMetadataCapabilities` and `LookupSeedPlacement`. A failed capability read
/// seeds nothing, as in Go; a failed metadata fetch is a provider with no manifest.
pub async fn seed_default_chain(pool: &Pool, library_type: &str) -> Vec<ChainEntry> {
    let Ok(caps) = pool
        .query(
            "SELECT pc.plugin_installation_id, pc.capability_id,
		        COALESCE(NULLIF(pc.metadata->>'display_name', ''), pc.capability_id),
		        pc.metadata, pi.kind = 'builtin'
		 FROM plugin_capabilities pc
		 JOIN plugin_installations pi ON pi.id = pc.plugin_installation_id
		 WHERE pc.capability_type = 'metadata_provider.v1'
		   AND pi.enabled = true
		 ORDER BY pc.plugin_installation_id, pc.capability_id",
            &[],
        )
        .await
    else {
        return Vec::new();
    };
    let mut caps_read = Vec::with_capacity(caps.len());
    for r in &caps {
        let (Ok(id), Ok(cap), Ok(builtin)) = (int(r, 0), text(r, 1), r.try_get::<_, bool>(4))
        else {
            return Vec::new();
        };
        caps_read.push((id, cap, builtin));
    }
    let mut entries = Vec::new();
    for level in content_levels(library_type) {
        let mut ranked = Vec::with_capacity(caps_read.len());
        for (installation, capability, builtin) in &caps_read {
            let md: Vec<u8> = pool
                .query(
                    "SELECT metadata FROM plugin_capabilities
		 WHERE plugin_installation_id = $1
		   AND capability_id = $2
		   AND capability_type = 'metadata_provider.v1'",
                    &[&AnyInt(*installation), capability],
                )
                .await
                .ok()
                .and_then(|rows| {
                    rows.first().and_then(|r| {
                        r.try_get::<_, Option<TextValue>>(0)
                            .ok()
                            .flatten()
                            .map(|t| t.0.into_bytes())
                    })
                })
                .unwrap_or_default();
            let (levels, declared) = declared_priority_levels(&md);
            let priority = levels.get(*level).copied().unwrap_or(0.0);
            if declared && priority <= 0.0 {
                continue;
            }
            let default_enabled = capability_field(&md, "default_enabled")
                .and_then(|raw| {
                    silo_gocompat::json::unmarshal::<Option<bool>>(
                        raw.as_bytes().unwrap_or(b"null"),
                    )
                    .ok()
                })
                .is_none_or(|v| v.unwrap_or(false));
            let declared_priority = if priority > 0.0 { priority as i64 } else { 0 };
            ranked.push(if declared_priority > 0 {
                SeedCandidate {
                    installation_id: *installation,
                    capability_id: capability.clone(),
                    local: *builtin,
                    declared_priority,
                    default_enabled,
                }
            } else {
                SeedCandidate {
                    installation_id: *installation,
                    capability_id: capability.clone(),
                    local: *builtin,
                    declared_priority: 999,
                    default_enabled: false,
                }
            });
        }
        ranked.sort_by(|a, b| {
            b.local
                .cmp(&a.local)
                .then(a.declared_priority.cmp(&b.declared_priority))
        });
        for (i, c) in ranked.into_iter().enumerate() {
            entries.push(ChainEntry {
                plugin_installation_id: c.installation_id,
                capability_id: c.capability_id,
                content_level: (*level).to_owned(),
                priority: i as i64,
                enabled: c.declared_priority > 0 && c.default_enabled,
                local: c.local,
            });
        }
    }
    entries
}

/// `librarymonitor.NodeReport`.
#[derive(Clone, Debug)]
pub struct NodeReport {
    pub node_id: String,
    pub library_id: i64,
    pub state: String,
    pub backend: String,
    pub detail: String,
    pub directories: i64,
    pub updated_at: SystemTime,
}

/// `StatusStore.FreshReports`. `StatusFreshness` is passed in seconds.
pub async fn fresh_reports(pool: &Pool, freshness_seconds: f64) -> Result<Vec<NodeReport>> {
    let rows = pool
        .query(
            "
		SELECT node_id, library_id, state, backend, detail, directories, updated_at
		FROM library_monitor_status
		WHERE updated_at > now() - make_interval(secs => $1)
		ORDER BY library_id, node_id",
            &[&freshness_seconds],
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(NodeReport {
            node_id: text(r, 0)?,
            library_id: int(r, 1)?,
            state: text(r, 2)?,
            backend: text(r, 3)?,
            detail: text(r, 4)?,
            directories: int(r, 5)?,
            updated_at: when(r, 6)?,
        });
    }
    Ok(out)
}

/// `models.AdminJob`, what the v2 projection reads.
#[derive(Clone, Debug)]
pub struct AdminJob {
    pub id: String,
    pub job_type: String,
    pub status: String,
    pub result_payload: Option<String>,
    pub progress_current: i64,
    pub progress_total: i64,
    pub requested_at: SystemTime,
    pub started_at: Option<SystemTime>,
    pub completed_at: Option<SystemTime>,
    pub cancel_requested: bool,
}

/// `Repository.GetByID`; `None` is `ErrJobNotFound`.
pub async fn admin_job(pool: &Pool, id: &str) -> Result<Option<AdminJob>> {
    let rows = pool
        .query(
            "SELECT id, job_type, status, created_by_user_id, request_payload,
	result_payload, message, error_message, progress_current, progress_total,
	artifact_bucket, artifact_key, artifact_size_bytes,
	public_url, requested_at, started_at, completed_at, heartbeat_at, expires_at,
	published_at, updated_at, cancel_requested, claim_generation FROM admin_jobs WHERE id = $1",
            &[&id],
        )
        .await
        .map_err(db)?;
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    Ok(Some(AdminJob {
        id: text(r, 0)?,
        job_type: text(r, 1)?,
        status: text(r, 2)?,
        result_payload: json_opt(r, 5)?,
        progress_current: int(r, 8)?,
        progress_total: int(r, 9)?,
        requested_at: when(r, 14)?,
        started_at: when_opt(r, 15)?,
        completed_at: when_opt(r, 16)?,
        cancel_requested: r.try_get(21).map_err(db)?,
    }))
}

/// `listLibraryPlaybackPreferences`' legacy row.
#[derive(Clone, Debug, Default)]
pub struct LegacyPlaybackPref {
    pub profile_id: String,
    pub library_id: i64,
    pub audio_language: Option<String>,
    pub subtitle_language: Option<String>,
    pub subtitle_mode: Option<String>,
    pub show_forced_subtitles: Option<bool>,
    pub updated_at: String,
}

/// `PostgresUserStore.ListLibraryPlaybackPreferences`.
pub async fn legacy_playback_prefs(
    pool: &Pool,
    user_id: i32,
    profile_id: &str,
) -> Result<Vec<LegacyPlaybackPref>> {
    let rows = pool
        .query(
            "
		SELECT profile_id, library_id, audio_language, subtitle_language,
		       subtitle_mode, show_forced_subtitles, updated_at
		FROM user_library_playback_preferences
		WHERE user_id = $1 AND profile_id = $2
		ORDER BY library_id",
            &[&user_id, &profile_id],
        )
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(LegacyPlaybackPref {
            profile_id: text(r, 0)?,
            library_id: int(r, 1)?,
            audio_language: r.try_get(2).map_err(db)?,
            subtitle_language: r.try_get(3).map_err(db)?,
            subtitle_mode: r.try_get(4).map_err(db)?,
            show_forced_subtitles: r.try_get(5).map_err(db)?,
            updated_at: silo_gocompat::time::GoTime::from_system_time(when(r, 6)?)
                .to_utc()
                .rfc3339(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stale(provider: &str, id: &str) -> StaleId {
        StaleId {
            content_id: String::new(),
            provider: provider.to_owned(),
            provider_id: id.to_owned(),
            first_seen_at: SystemTime::UNIX_EPOCH,
            last_seen_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn a_stale_id_is_actionable_when_it_is_the_items_identity() {
        let matched = StaleItem {
            status: "Matched".to_owned(),
            imdb_id: "TT1".to_owned(),
            ..StaleItem::default()
        };
        // The anchor, the denormalized column case-folded for IMDb, and neither.
        assert!(is_actionable_stale(
            "movie-tmdb-5",
            &matched,
            &stale("tmdb", " 5 ")
        ));
        assert!(is_actionable_stale(
            "movie-tmdb-5",
            &matched,
            &stale("IMDB", "tt1")
        ));
        assert!(!is_actionable_stale(
            "movie-tmdb-5",
            &matched,
            &stale("tvdb", "5")
        ));
        // An unmatched item keeps every failure, but only for a provider that can be its identity.
        assert!(is_actionable_stale(
            "local-x",
            &StaleItem::default(),
            &stale("tvdb", "5")
        ));
        assert!(!is_actionable_stale(
            "local-x",
            &StaleItem::default(),
            &stale("omdb", "5")
        ));
        assert!(!is_actionable_stale(
            "local-x",
            &StaleItem::default(),
            &stale("tvdb", " ")
        ));
    }

    #[test]
    fn provider_anchors_take_goes_shapes() {
        assert!(provider_anchor("episode-tvdb-1-2-3").is_some());
        assert!(provider_anchor("movie-imdb-tt77").is_some());
        assert!(provider_anchor("movie-tmdb-x").is_none());
        assert!(provider_anchor("season-tmdb-1").is_none());
        assert!(provider_anchor("local-abc").is_none());
    }
}
