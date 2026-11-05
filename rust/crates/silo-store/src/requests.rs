//! The request store's reads, cancellation, route administration, and server deletion:
//! `internal/requests/{repository,routes_admin,routing_repository,editor_concurrency,targets,follows}.go`
//! and the catalog presence lookups. The SQL is Go's, apart from `::text` casts where this driver has no
//! JSON type to scan or bind.
//!
//! Approval, retry, decline, creation, and server saves stay in Go: they reach the router plugin or the
//! notification system.

use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use silo_core::secret::Cipher;
use silo_gocompat::json::{marshal, unmarshal};
use silo_gocompat::strings::trim_space;
use silo_pg::{AnyInt, Error as PgError, Pool, Row, Tx};

/// `requests.Err*` and the errors the stores answer.
#[derive(Debug)]
pub enum Error {
    InvalidMediaType,
    InvalidInput(String),
    RequestsDisabled,
    Forbidden,
    NotFound,
    InvalidState,
    StaleRevision,
    Validation {
        fields: BTreeMap<String, String>,
        form: String,
    },
    Internal(String),
}

impl From<PgError> for Error {
    fn from(e: PgError) -> Self {
        Error::Internal(e.to_string())
    }
}

fn form_error(message: impl Into<String>) -> Error {
    Error::Validation {
        fields: BTreeMap::new(),
        form: message.into(),
    }
}

/// `requests.Viewer`.
#[derive(Clone, Debug, Default)]
pub struct Viewer {
    pub user_id: i64,
    pub profile_id: String,
    pub is_admin: bool,
}

pub type Config = BTreeMap<String, Value>;

/// What `json.Unmarshal` into `any` makes of a number: a float64, which encodes without a trailing `.0`.
fn as_go_any(value: Value) -> Value {
    match value {
        Value::Number(n) => n
            .as_f64()
            .and_then(serde_json::Number::from_f64)
            .map_or(Value::Null, Value::Number),
        Value::Array(items) => Value::Array(items.into_iter().map(as_go_any).collect()),
        Value::Object(map) => {
            Value::Object(map.into_iter().map(|(k, v)| (k, as_go_any(v))).collect())
        }
        other => other,
    }
}

fn decode_config(raw: &str) -> Result<Config, Error> {
    let map: Option<Config> =
        unmarshal(raw.as_bytes()).map_err(|e| Error::Internal(e.to_string()))?;
    Ok(map
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k, as_go_any(v)))
        .collect())
}

pub fn go_any_config(config: Config) -> Config {
    config.into_iter().map(|(k, v)| (k, as_go_any(v))).collect()
}

/// `requests.DownloadProgress`.
#[derive(Clone, Debug)]
pub struct Download {
    pub phase: String,
    pub bytes_total: i64,
    pub bytes_left: i64,
    pub estimated: Option<SystemTime>,
    pub downloads: i32,
    pub updated_at: SystemTime,
}

/// `requests.Target`.
#[derive(Clone, Debug)]
pub struct Target {
    pub id: i64,
    pub request_id: String,
    pub integration_id: String,
    pub integration_kind: String,
    pub instance_name: String,
    pub quality: String,
    pub is_anime: bool,
    pub external_id: String,
    pub external_status: String,
    pub status: String,
    pub last_error: String,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub route_name: String,
    pub download: Option<Download>,
}

const TARGET_COLUMNS: &str = "t.id, t.request_id, t.integration_id, t.integration_kind,
	COALESCE(ri.name, ''), t.quality, t.is_anime, t.external_id, t.external_status,
	t.status, t.last_error, t.created_at, t.updated_at, COALESCE(t.route_id, ''), t.route_name,
	t.download_phase, t.download_bytes_total, t.download_bytes_left, t.download_eta,
	t.download_count, t.download_updated_at";

fn scan_target(row: &Row) -> Target {
    let phase: Option<String> = row.get(15);
    Target {
        id: row.get(0),
        request_id: row.get(1),
        integration_id: row.get::<_, Option<String>>(2).unwrap_or_default(),
        integration_kind: row.get(3),
        instance_name: row.get(4),
        quality: row.get(5),
        is_anime: row.get(6),
        external_id: row.get(7),
        external_status: row.get(8),
        status: row.get(9),
        last_error: row.get(10),
        created_at: row.get(11),
        updated_at: row.get(12),
        route_name: row.get(14),
        download: phase.map(|phase| Download {
            phase,
            bytes_total: row.get::<_, Option<i64>>(16).unwrap_or(0),
            bytes_left: row.get::<_, Option<i64>>(17).unwrap_or(0),
            estimated: row.get(18),
            downloads: row.get::<_, Option<i32>>(19).unwrap_or(0),
            updated_at: row
                .get::<_, Option<SystemTime>>(20)
                .unwrap_or(SystemTime::UNIX_EPOCH),
        }),
    }
}

/// `requests.SeasonProgress`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SeasonProgress {
    pub season: i32,
    pub aired: i64,
    pub upcoming: i64,
    pub have: i64,
}

impl SeasonProgress {
    /// `SeasonCounts.Complete`.
    fn complete(&self) -> bool {
        self.aired > 0 && self.have >= self.aired
    }
}

/// `requests.Request`.
#[derive(Clone, Debug)]
pub struct MediaRequest {
    pub id: String,
    pub provider: String,
    pub media_type: String,
    pub tmdb_id: i32,
    pub tvdb_id: Option<i32>,
    pub imdb_id: String,
    pub title: String,
    pub year: Option<i32>,
    pub overview: String,
    pub poster_path: String,
    pub backdrop_path: String,
    pub status: String,
    pub outcome: String,
    pub requested_by_user_id: i32,
    pub requested_by_profile_id: String,
    pub is_anime: bool,
    pub last_error: String,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub approved_at: Option<SystemTime>,
    pub completed_at: Option<SystemTime>,
    pub outcome_reason: String,
    pub seasons: Vec<i32>,
    pub source: String,
    pub targets: Vec<Target>,
    pub library_content_id: String,
    pub season_progress: Vec<SeasonProgress>,
}

const REQUEST_COLUMNS: &str = "id, provider, media_type, tmdb_id, tvdb_id, imdb_id, title, year,
	        overview, poster_path, backdrop_path, status, outcome,
	        requested_by_user_id, requested_by_profile_id, is_anime,
	        last_error, created_at, updated_at, approved_at, completed_at,
	        submit_attempts, submit_lease_until, next_submit_at, outcome_reason, routing_facts::text, seasons, source";

fn scan_request(row: &Row) -> MediaRequest {
    MediaRequest {
        id: row.get(0),
        provider: row.get(1),
        media_type: row.get(2),
        tmdb_id: row.get(3),
        tvdb_id: row.get(4),
        imdb_id: row.get(5),
        title: row.get(6),
        year: row.get(7),
        overview: row.get(8),
        poster_path: row.get(9),
        backdrop_path: row.get(10),
        status: row.get(11),
        outcome: row.get(12),
        requested_by_user_id: row.get(13),
        requested_by_profile_id: row.get(14),
        is_anime: row.get(15),
        last_error: row.get(16),
        created_at: row.get(17),
        updated_at: row.get(18),
        approved_at: row.get(19),
        completed_at: row.get(20),
        outcome_reason: row.get(24),
        seasons: row.get(26),
        source: row.get(27),
        targets: Vec::new(),
        library_content_id: String::new(),
        season_progress: Vec::new(),
    }
}

impl MediaRequest {
    /// `Request.State`.
    pub fn state(&self) -> &'static str {
        match self.outcome.as_str() {
            "declined" => return "declined",
            "cancelled" => return "cancelled",
            "failed" => return "failed",
            _ => {}
        }
        if self.status == "pending" {
            return "pending";
        }
        if !self.season_progress.is_empty() {
            let done = self.status == "completed";
            if self
                .season_progress
                .iter()
                .all(|p| p.complete() || (done && p.have > 0))
            {
                return "available";
            }
            if self.season_progress.iter().any(|p| p.have > 0) {
                return "partially_available";
            }
        }
        match self.status.as_str() {
            "approved" => "approved",
            "completed" if !self.library_content_id.is_empty() && self.seasons.is_empty() => {
                "available"
            }
            _ => "processing",
        }
    }

    /// `Request.Download`.
    pub fn download(&self) -> Option<Download> {
        fn rank(phase: &str) -> i32 {
            match phase {
                "import_blocked" => 5,
                "stalled" => 4,
                "importing" => 2,
                "paused" => 1,
                "queued" => 0,
                _ => 3,
            }
        }
        let mut out: Option<Download> = None;
        let mut size_known = true;
        for t in &self.targets {
            if t.status != "queued" && t.status != "downloading" {
                continue;
            }
            let Some(d) = &t.download else {
                size_known = false;
                continue;
            };
            if d.bytes_total <= 0 {
                size_known = false;
            }
            let Some(sum) = &mut out else {
                out = Some(d.clone());
                continue;
            };
            if rank(&d.phase) > rank(&sum.phase) {
                sum.phase = d.phase.clone();
            }
            sum.bytes_total += d.bytes_total;
            sum.bytes_left += d.bytes_left;
            sum.downloads += d.downloads;
            if d.estimated.is_some() && (sum.estimated.is_none() || d.estimated > sum.estimated) {
                sum.estimated = d.estimated;
            }
            if d.updated_at < sum.updated_at {
                sum.updated_at = d.updated_at;
            }
        }
        if let Some(sum) = &mut out
            && !size_known
        {
            sum.bytes_total = 0;
            sum.bytes_left = 0;
        }
        out
    }
}

/// `requests.ListFilter`.
#[derive(Clone, Debug, Default)]
pub struct ListFilter {
    pub before: Option<(SystemTime, String)>,
    pub status: String,
    pub outcome: String,
    pub view: String,
    pub query: String,
    pub media_type: String,
    pub requested_by_user_id: i64,
    pub limit: i64,
    pub offset: i64,
}

/// `normalizeListFilter`.
fn normalized(mut filter: ListFilter) -> ListFilter {
    if filter.limit <= 0 {
        filter.limit = 50;
    }
    filter.limit = filter.limit.min(100);
    filter.offset = filter.offset.max(0);
    filter
}

fn view_condition(view: &str) -> &'static str {
    match view {
        "needs_approval" => "(outcome = 'active' AND status = 'pending')",
        "in_progress" => "(outcome = 'active' AND status IN ('approved', 'queued', 'downloading'))",
        "failed" => "(outcome = 'failed')",
        "done" => {
            "((outcome = 'active' AND status = 'completed') OR outcome IN ('declined', 'cancelled'))"
        }
        _ => "",
    }
}

/// `buildRequestListSQL` and the read after it.
async fn list(
    pool: &Pool,
    owner: Option<i64>,
    filter: &ListFilter,
) -> Result<Vec<MediaRequest>, Error> {
    use silo_pg::ToSql;
    let mut args: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let mut conditions = vec![if let Some(owner) = owner {
        args.push(Box::new(AnyInt(owner)));
        "requested_by_user_id = $1".to_owned()
    } else {
        "true".to_owned()
    }];
    if !filter.status.is_empty() {
        args.push(Box::new(filter.status.clone()));
        conditions.push(format!("status = ${}", args.len()));
    }
    if !filter.outcome.is_empty() {
        args.push(Box::new(filter.outcome.clone()));
        conditions.push(format!("outcome = ${}", args.len()));
    }
    let view = view_condition(&filter.view);
    if !view.is_empty() {
        conditions.push(view.to_owned());
    }
    if !filter.media_type.is_empty() {
        args.push(Box::new(filter.media_type.clone()));
        conditions.push(format!("media_type = ${}", args.len()));
    }
    if filter.requested_by_user_id > 0 {
        args.push(Box::new(AnyInt(filter.requested_by_user_id)));
        conditions.push(format!("requested_by_user_id = ${}", args.len()));
    }
    let q = trim_space(&filter.query);
    if !q.is_empty() {
        let escaped = q
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        args.push(Box::new(format!("%{escaped}%")));
        let mut cond = format!("title ILIKE ${}", args.len());
        // TMDB IDs are 4-byte integers; a longer number is only a title search.
        if let Some(tmdb) = q.parse::<i32>().ok().filter(|v| *v > 0).map(i64::from) {
            args.push(Box::new(AnyInt(tmdb)));
            cond = format!("({cond} OR tmdb_id = ${})", args.len());
        }
        conditions.push(cond);
    }
    if let Some((created, id)) = &filter.before {
        args.push(Box::new(*created));
        args.push(Box::new(id.clone()));
        conditions.push(format!(
            "(created_at, id) < (${}, ${})",
            args.len() - 1,
            args.len()
        ));
    }
    let mut limit = filter.limit;
    if limit <= 0 || limit > 100 {
        limit = 50;
    }
    args.push(Box::new(limit));
    args.push(Box::new(filter.offset.max(0)));
    let sql = format!(
        "SELECT {REQUEST_COLUMNS} FROM media_requests 
		WHERE {}
		ORDER BY created_at DESC, id DESC
		LIMIT ${} OFFSET ${}",
        conditions.join(" AND "),
        args.len() - 1,
        args.len()
    );
    let params: Vec<&(dyn ToSql + Sync)> = args
        .iter()
        .map(|a| -> &(dyn ToSql + Sync) { a.as_ref() })
        .collect();
    let rows = pool.query(&sql, &params).await?;
    Ok(rows.iter().map(scan_request).collect())
}

async fn attach_targets(pool: &Pool, reqs: &mut [MediaRequest]) -> Result<(), Error> {
    if reqs.is_empty() {
        return Ok(());
    }
    let ids: Vec<String> = reqs.iter().map(|r| r.id.clone()).collect();
    let sql = format!(
        "SELECT {TARGET_COLUMNS}
		FROM media_request_targets t
		LEFT JOIN request_integrations ri ON ri.id = t.integration_id
		WHERE t.request_id = ANY($1) ORDER BY t.request_id, t.quality"
    );
    let rows = pool.query(&sql, &[&ids]).await?;
    let mut by: HashMap<String, Vec<Target>> = HashMap::new();
    for row in &rows {
        let t = scan_target(row);
        by.entry(t.request_id.clone()).or_default().push(t);
    }
    for r in reqs {
        r.targets = by.remove(&r.id).unwrap_or_default();
    }
    Ok(())
}

const LOOKUP_EXTERNAL_IDS: &str = "
		WITH requested(query_tmdb_id, provider, provider_id, ord) AS (
			SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::int[])
		),
		direct_matches AS (
			SELECT r.query_tmdb_id, mi.content_id, r.provider, mil.media_folder_id::text, mi.title, r.ord,
			       CASE r.provider WHEN 'tmdb' THEN 0 WHEN 'tvdb' THEN 1 WHEN 'imdb' THEN 2 ELSE 3 END AS provider_rank
			FROM requested r
			JOIN media_items mi
			  ON mi.type = $5
			 AND (
				(r.provider = 'tmdb' AND mi.tmdb_id <> '' AND mi.tmdb_id = r.provider_id)
				OR (r.provider = 'tvdb' AND mi.tvdb_id <> '' AND mi.tvdb_id = r.provider_id)
				OR (r.provider = 'imdb' AND mi.imdb_id <> '' AND mi.imdb_id = r.provider_id)
			 )
			JOIN media_item_libraries mil ON mil.content_id = mi.content_id
			JOIN media_folders mf ON mf.id = mil.media_folder_id
			WHERE mf.enabled = true
		),
		provider_matches AS (
			SELECT r.query_tmdb_id, mi.content_id, r.provider, mil.media_folder_id::text, mi.title, r.ord,
			       CASE r.provider WHEN 'tmdb' THEN 0 WHEN 'tvdb' THEN 1 WHEN 'imdb' THEN 2 ELSE 3 END AS provider_rank
			FROM requested r
			JOIN media_item_provider_ids mip
			  ON mip.provider = r.provider
			 AND mip.provider_id = r.provider_id
			 AND mip.item_type = $5
			JOIN media_items mi ON mi.content_id = mip.content_id AND mi.type = $5
			JOIN media_item_libraries mil ON mil.content_id = mi.content_id
			JOIN media_folders mf ON mf.id = mil.media_folder_id
			WHERE mf.enabled = true
		)
		SELECT DISTINCT ON (query_tmdb_id)
		       query_tmdb_id, content_id, provider, media_folder_id, title
		FROM (
			SELECT * FROM direct_matches
			UNION ALL
			SELECT * FROM provider_matches
		) matches
		ORDER BY query_tmdb_id, provider_rank ASC, ord ASC, content_id ASC, media_folder_id ASC";

const SEASON_AVAILABILITY: &str = "
		WITH present AS (
			SELECT el.episode_id AS content_id
			FROM episode_libraries el
			JOIN episodes e ON e.content_id = el.episode_id
			JOIN media_folders f ON f.id = el.media_folder_id AND f.enabled
			WHERE e.series_id = ANY($1) AND e.season_number > 0
			UNION
			SELECT covered.content_id
			FROM episodes first
			JOIN media_files mf ON mf.episode_id = first.content_id
			     AND mf.missing_since IS NULL
			     AND mf.multi_episode_end > mf.multi_episode_start
			JOIN media_folders f ON f.id = mf.media_folder_id AND f.enabled
			JOIN episodes covered ON covered.series_id = first.series_id
			     AND covered.season_number = first.season_number
			     AND covered.episode_number BETWEEN mf.multi_episode_start AND mf.multi_episode_end
			WHERE first.series_id = ANY($1) AND first.season_number > 0
		)
		SELECT e.series_id, e.season_number,
		       count(*) FILTER (WHERE e.air_date <= current_date),
		       count(*) FILTER (WHERE e.air_date > current_date),
		       count(p.content_id),
		       count(p.content_id) FILTER (WHERE e.air_date <= current_date)
		FROM episodes e
		LEFT JOIN present p ON p.content_id = e.content_id
		WHERE e.series_id = ANY($1) AND e.season_number > 0
		GROUP BY e.series_id, e.season_number
	";

/// `ProviderIDRepository.AttachTMDBID`. Go logs a failure and goes on, so the caller does too.
async fn attach_tmdb_id(
    pool: &Pool,
    content_id: &str,
    item_type: &str,
    tmdb_id: i32,
) -> Result<(), String> {
    let mut session = pool.acquire().await.map_err(|e| e.to_string())?;
    let mut tx = session.begin().await.map_err(|e| e.to_string())?;
    let text = tmdb_id.to_string();
    let rows = tx
        .query(
            "SELECT type, COALESCE(tmdb_id, '')
		FROM media_items
		WHERE content_id = $1
		FOR UPDATE",
            &[&content_id],
        )
        .await
        .map_err(|e| e.to_string())?;
    let Some(row) = rows.first() else {
        return Err("loading media item for tmdb attach: content not found".to_owned());
    };
    let (existing_type, existing): (String, String) = (row.get(0), row.get(1));
    let same = |have: &str| have == text || have.split('-').next() == Some(text.as_str());
    if existing_type != item_type {
        return Err(format!(
            "media item type mismatch: got {existing_type:?}, want {item_type:?}"
        ));
    }
    if !existing.is_empty() && !same(&existing) {
        return Err(format!(
            "media item tmdb id conflict: got {existing:?}, want {text:?}"
        ));
    }
    let rows = tx
        .query(
            "SELECT provider_id
		FROM media_item_provider_ids
		WHERE content_id = $1 AND provider = 'tmdb'
		FOR UPDATE",
            &[&content_id],
        )
        .await
        .map_err(|e| e.to_string())?;
    if let Some(row) = rows.first() {
        let have: String = row.get(0);
        if !have.is_empty() && !same(&have) {
            return Err(format!(
                "media item tmdb provider id conflict: got {have:?}, want {text:?}"
            ));
        }
    }
    let upper = (u64::try_from(tmdb_id).unwrap_or(0) + 1).to_string();
    let owners = if upper.len() == text.len() {
        tx.query(
            "SELECT content_id
			FROM media_items
			WHERE tmdb_id >= $1
			  AND tmdb_id < $2
			  AND type = $3
			  AND content_id <> $4
			  AND (tmdb_id = $1 OR tmdb_id LIKE $1 || '-%')
			LIMIT 1",
            &[&text, &upper, &item_type, &content_id],
        )
        .await
    } else {
        tx.query(
            "SELECT content_id
		FROM media_items
		WHERE tmdb_id >= $2
		  AND type = $1
		  AND content_id <> $3
		  AND (tmdb_id = $2 OR tmdb_id LIKE $2 || '-%')
		LIMIT 1",
            &[&item_type, &text, &content_id],
        )
        .await
    }
    .map_err(|e| e.to_string())?;
    if let Some(row) = owners.first() {
        let owner: String = row.get(0);
        return Err(format!(
            "tmdb id {text:?} already belongs to content_id {owner:?}"
        ));
    }
    tx.execute(
        "UPDATE media_items
		SET tmdb_id = $1,
		    updated_at = NOW()
		WHERE content_id = $2
		  AND type = $3",
        &[&text, &content_id, &item_type],
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO media_item_provider_ids (content_id, item_type, provider, provider_id, created_at, updated_at)
		VALUES ($1, $2, 'tmdb', $3, NOW(), NOW())
		ON CONFLICT (content_id, provider) DO UPDATE
		SET item_type = EXCLUDED.item_type,
		    provider_id = EXCLUDED.provider_id,
		    updated_at = NOW()",
        &[&content_id, &item_type, &text],
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())
}

/// `Service.attachLibraryContent`.
async fn attach_library(pool: &Pool, reqs: &mut [MediaRequest]) -> Result<(), Error> {
    let mut types: Vec<String> = Vec::new();
    for r in reqs.iter() {
        if r.tmdb_id > 0 && !types.contains(&r.media_type) {
            types.push(r.media_type.clone());
        }
    }
    let mut series: Vec<String> = Vec::new();
    for media_type in &types {
        let (mut q, mut providers, mut ids, mut ords) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut seen: Vec<i32> = Vec::new();
        for r in reqs
            .iter()
            .filter(|r| r.tmdb_id > 0 && &r.media_type == media_type)
        {
            if seen.contains(&r.tmdb_id) {
                continue;
            }
            let ord = seen.len() as i32;
            seen.push(r.tmdb_id);
            let tmdb = r.tmdb_id.to_string();
            let tvdb = r
                .tvdb_id
                .filter(|v| *v > 0)
                .map(|v| v.to_string())
                .unwrap_or_default();
            for (provider, id) in [
                ("tmdb", tmdb.as_str()),
                ("tvdb", tvdb.as_str()),
                ("imdb", trim_space(&r.imdb_id)),
            ] {
                if id.is_empty() {
                    continue;
                }
                q.push(tmdb.clone());
                providers.push(provider.to_owned());
                ids.push(id.to_owned());
                ords.push(ord);
            }
        }
        if ids.is_empty() {
            continue;
        }
        let rows = pool
            .query(
                LOOKUP_EXTERNAL_IDS,
                &[&q, &providers, &ids, &ords, media_type],
            )
            .await?;
        for row in &rows {
            let (tmdb, content, provider): (String, String, String) =
                (row.get(0), row.get(1), row.get(2));
            let Some(id) = tmdb.parse::<i32>().ok().filter(|v| *v > 0) else {
                continue;
            };
            if provider != "tmdb"
                && let Err(error) = attach_tmdb_id(pool, &content, media_type, id).await
            {
                tracing::warn!(component = "requests", content_id = %content, media_type = %media_type, tmdb_id = id, matched_provider = %provider, %error, "requests: failed to backfill tmdb id from presence lookup");
            }
            if trim_space(&content).is_empty() {
                continue;
            }
            for r in reqs
                .iter_mut()
                .filter(|r| r.tmdb_id == id && &r.media_type == media_type)
            {
                r.library_content_id = content.clone();
                if r.media_type == "series" && !r.seasons.is_empty() && !series.contains(&content) {
                    series.push(content.clone());
                }
            }
        }
    }
    if series.is_empty() {
        return Ok(());
    }
    let rows = pool.query(SEASON_AVAILABILITY, &[&series]).await?;
    let mut counts: HashMap<(String, i32), (i64, i64, i64)> = HashMap::new();
    for row in &rows {
        let (aired, have, have_aired): (i64, i64, i64) = (row.get(2), row.get(4), row.get(5));
        let have = if aired > 0 { have_aired } else { have };
        counts.insert((row.get(0), row.get(1)), (aired, row.get(3), have));
    }
    for r in reqs.iter_mut() {
        if r.media_type == "series" && !r.seasons.is_empty() && !r.library_content_id.is_empty() {
            r.season_progress = r
                .seasons
                .iter()
                .map(|season| {
                    let (aired, upcoming, have) = counts
                        .get(&(r.library_content_id.clone(), *season))
                        .copied()
                        .unwrap_or_default();
                    SeasonProgress {
                        season: *season,
                        aired,
                        upcoming,
                        have,
                    }
                })
                .collect();
        }
    }
    Ok(())
}

/// A request a mutation returns: Go logs a failed lookup and answers anyway. `Cancel` returns the row as updated.
async fn enrich(pool: &Pool, reqs: &mut [MediaRequest]) -> Result<(), Error> {
    attach_targets(pool, reqs).await?;
    attach_library(pool, reqs).await
}

/// `Service.ensureRequestsEnabled`.
pub async fn requests_enabled(pool: &Pool) -> Result<bool, Error> {
    let rows = pool
        .query(
            "SELECT requests_enabled FROM request_settings WHERE id = true",
            &[],
        )
        .await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}

/// `watchlist_requests` with `GetSettings`'s default.
pub async fn settings_flags(pool: &Pool) -> Result<(bool, bool), Error> {
    let rows = pool
        .query(
            "SELECT requests_enabled, watchlist_requests FROM request_settings WHERE id = true",
            &[],
        )
        .await?;
    Ok(rows.first().map_or((false, true), |r| (r.get(0), r.get(1))))
}

async fn ensure_enabled(pool: &Pool) -> Result<(), Error> {
    if requests_enabled(pool).await? {
        Ok(())
    } else {
        Err(Error::RequestsDisabled)
    }
}

/// `Service.userLimitBlocked`.
pub async fn user_limit_blocked(pool: &Pool, user: i64) -> Result<bool, Error> {
    let rows = pool
        .query(
            "SELECT limit_mode, approval_mode FROM request_user_limits WHERE user_id = $1",
            &[&AnyInt(user)],
        )
        .await?;
    Ok(rows
        .first()
        .is_some_and(|r| r.get::<_, String>(0) == "blocked" || r.get::<_, String>(1) == "blocked"))
}

/// `Service.ListMine`.
pub async fn list_mine(
    pool: &Pool,
    viewer: &Viewer,
    filter: ListFilter,
) -> Result<Vec<MediaRequest>, Error> {
    if viewer.user_id == 0 {
        return Err(Error::Forbidden);
    }
    ensure_enabled(pool).await?;
    let mut reqs = list(pool, Some(viewer.user_id), &normalized(filter)).await?;
    enrich(pool, &mut reqs).await?;
    Ok(reqs)
}

/// `Service.ListAdmin`.
pub async fn list_admin(
    pool: &Pool,
    viewer: &Viewer,
    mut filter: ListFilter,
) -> Result<Vec<MediaRequest>, Error> {
    if !viewer.is_admin {
        return Err(Error::Forbidden);
    }
    if !filter.media_type.is_empty() {
        filter.media_type = normalize_media_type(&filter.media_type)?.to_owned();
    }
    let mut reqs = list(pool, None, &normalized(filter)).await?;
    enrich(pool, &mut reqs).await?;
    Ok(reqs)
}

async fn get_request(pool: &Pool, id: &str) -> Result<MediaRequest, Error> {
    let sql = format!(
        "SELECT {REQUEST_COLUMNS} FROM media_requests 
		WHERE id = $1"
    );
    let rows = pool.query(&sql, &[&id]).await?;
    rows.first().map(scan_request).ok_or(Error::NotFound)
}

/// `Service.GetRequest`.
pub async fn get(pool: &Pool, viewer: &Viewer, id: &str) -> Result<MediaRequest, Error> {
    ensure_enabled(pool).await?;
    let req = get_request(pool, trim_space(id)).await?;
    if !viewer.is_admin && i64::from(req.requested_by_user_id) != viewer.user_id {
        return Err(Error::Forbidden);
    }
    let mut reqs = [req];
    enrich(pool, &mut reqs).await?;
    let [req] = reqs;
    Ok(req)
}

const GUARD_CONDITION: &str = "(cardinality($2::text[]) = 0 OR status = ANY($2::text[]))
		  AND (cardinality($3::text[]) = 0 OR outcome = ANY($3::text[]))
		  AND (NOT $4::boolean OR status <> 'approved' OR (
		    (submit_lease_until IS NULL OR submit_lease_until <= now())
		    AND NOT EXISTS (SELECT 1 FROM media_request_targets t WHERE t.request_id = media_requests.id)))";

/// `Service.cancel`. `close_failed` is `AdminCancel`.
pub async fn cancel(
    pool: &Pool,
    viewer: &Viewer,
    id: &str,
    reason: &str,
    close_failed: bool,
) -> Result<MediaRequest, Error> {
    if viewer.user_id == 0 {
        return Err(Error::Forbidden);
    }
    if !viewer.is_admin {
        ensure_enabled(pool).await?;
    }
    let req = get_request(pool, trim_space(id)).await?;
    if !viewer.is_admin && i64::from(req.requested_by_user_id) != viewer.user_id {
        return Err(Error::Forbidden);
    }
    let (statuses, outcomes, unsent): (Vec<String>, Vec<String>, bool) =
        if close_failed && req.outcome == "failed" {
            (Vec::new(), vec!["failed".to_owned()], false)
        } else {
            (
                vec!["pending".to_owned(), "approved".to_owned()],
                vec!["active".to_owned()],
                true,
            )
        };
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    let message = trim_space(reason);
    let outcome = "cancelled";
    let sql = format!(
        "UPDATE media_requests
		SET outcome = $5,
		    last_error = CASE
		      WHEN $5 = 'failed' THEN $6
		      WHEN $5 = 'active' THEN ''
		      -- Only a failed request keeps its error when closed; the quota
		      -- refunds exactly those (see quotaOutcomes).
		      WHEN $5 = 'cancelled' AND outcome <> 'failed' THEN ''
		      ELSE last_error
		    END,
		    outcome_reason = CASE
		      WHEN $5 IN ('declined', 'cancelled') THEN $6
		      WHEN $5 = 'active' THEN ''
		      ELSE outcome_reason
		    END,
		    updated_at = now()
		WHERE id = $1
		  AND {GUARD_CONDITION}
		RETURNING {REQUEST_COLUMNS}"
    );
    let rows = tx
        .query(
            &sql,
            &[&req.id, &statuses, &outcomes, &unsent, &outcome, &message],
        )
        .await?;
    let Some(row) = rows.first() else {
        let exists = tx
            .query(
                "SELECT EXISTS (SELECT 1 FROM media_requests WHERE id = $1)",
                &[&req.id],
            )
            .await?;
        return Err(if exists[0].get(0) {
            Error::InvalidState
        } else {
            Error::NotFound
        });
    };
    let updated = scan_request(row);
    tx.execute(
        "DELETE FROM media_request_follows WHERE request_id = $1",
        &[&updated.id],
    )
    .await?;
    let actor = (viewer.user_id > 0).then_some(AnyInt(viewer.user_id));
    let event = format!("outcome_{outcome}");
    tx.execute(
        "INSERT INTO media_request_events (
			request_id, event_type, actor_user_id, actor_profile_id, message
		)
		VALUES ($1, $2, $3, $4, $5)",
        &[&updated.id, &event, &actor, &viewer.profile_id, &message],
    )
    .await?;
    tx.commit().await?;
    Ok(updated)
}

/// `Repository.UnfollowTitle`, after `Service.Unfollow`'s checks.
pub async fn unfollow(
    pool: &Pool,
    viewer: &Viewer,
    media_type: &str,
    tmdb_id: i64,
) -> Result<(), Error> {
    if viewer.user_id == 0 {
        return Err(Error::Forbidden);
    }
    if trim_space(&viewer.profile_id).is_empty() {
        return Err(Error::InvalidInput("profile is required".to_owned()));
    }
    let media_type = normalize_media_type(media_type)?;
    if tmdb_id <= 0 {
        return Err(Error::InvalidInput("tmdb id is required".to_owned()));
    }
    pool.execute(
        "DELETE FROM media_request_follows
		WHERE media_type = $1 AND tmdb_id = $2 AND user_id = $3 AND profile_id = $4",
        &[
            &media_type,
            &AnyInt(tmdb_id),
            &AnyInt(viewer.user_id),
            &viewer.profile_id,
        ],
    )
    .await?;
    Ok(())
}

/// `Repository.CountAdminViews`: needs approval, in progress, failed, done.
pub async fn count_views(pool: &Pool) -> Result<[i64; 4], Error> {
    let sql = format!(
        "SELECT count(*) FILTER (WHERE {}),
		       count(*) FILTER (WHERE {}),
		       count(*) FILTER (WHERE {}),
		       count(*) FILTER (WHERE {})
		FROM media_requests",
        view_condition("needs_approval"),
        view_condition("in_progress"),
        view_condition("failed"),
        view_condition("done")
    );
    let rows = pool.query(&sql, &[]).await?;
    Ok([
        rows[0].get(0),
        rows[0].get(1),
        rows[0].get(2),
        rows[0].get(3),
    ])
}

/// `requests.RequestEvent`.
pub struct Event {
    pub id: i64,
    pub event_type: String,
    pub actor_user_id: Option<i32>,
    pub message: String,
    pub created_at: SystemTime,
    pub actor_username: String,
}

/// `Service.ListRequestEvents`.
pub async fn list_events(pool: &Pool, id: &str) -> Result<Vec<Event>, Error> {
    let id = trim_space(id);
    get_request(pool, id).await?;
    let rows = pool
        .query(
            "SELECT e.id, e.request_id, e.event_type, e.actor_user_id, e.actor_profile_id, e.message,
		       e.created_at, COALESCE(u.username, '')
		FROM media_request_events e
		LEFT JOIN users u ON u.id = e.actor_user_id
		WHERE e.request_id = $1
		ORDER BY e.created_at DESC, e.id DESC
		LIMIT $2",
            &[&id, &200_i64],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Event {
            id: r.get(0),
            event_type: r.get(2),
            actor_user_id: r.get(3),
            message: r.get(5),
            created_at: r.get(6),
            actor_username: r.get(7),
        })
        .collect())
}

/// `requests.Integration`, with its key only as whether it has one.
#[derive(Clone, Debug)]
pub struct Integration {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub base_url: String,
    pub has_api_key: bool,
    pub last_check_at: Option<SystemTime>,
    pub last_check_status: String,
    pub last_check_error: String,
    pub updated_at: SystemTime,
    pub capability_id: String,
    pub installation_id: Option<i32>,
    pub supported_media_types: Vec<String>,
    pub plugin_config: Config,
    pub revision: i64,
}

const INTEGRATION_COLUMNS: &str = "id, name, enabled, base_url, api_key_ref,
	last_check_at, last_check_status, last_check_error, updated_at,
	capability_id, installation_id, supported_media_types, plugin_config::text, revision";

/// `scanIntegration`: a key that will not decrypt fails the read, as in Go.
fn scan_integration(cipher: &Cipher, row: &Row) -> Result<Integration, Error> {
    let id: String = row.get(0);
    let stored: String = row.get(4);
    let aad = format!("request_integrations:api_key_ref:{id}");
    let key = cipher
        .decrypt_if_encrypted(&stored, &aad)
        .map_err(|e| Error::Internal(format!("decrypt request integration {id} api key: {e}")))?;
    let key = String::from_utf8_lossy(&key);
    let plugin_config = decode_config(&row.get::<_, String>(12))?;
    Ok(Integration {
        name: row.get(1),
        enabled: row.get(2),
        base_url: row.get(3),
        has_api_key: !trim_space(&key).is_empty(),
        last_check_at: row.get(5),
        last_check_status: row.get(6),
        last_check_error: row.get(7),
        updated_at: row.get(8),
        capability_id: row.get(9),
        installation_id: row.get(10),
        supported_media_types: row.get(11),
        plugin_config,
        revision: row.get(13),
        id,
    })
}

pub async fn list_integrations(pool: &Pool, cipher: &Cipher) -> Result<Vec<Integration>, Error> {
    let sql = format!("SELECT {INTEGRATION_COLUMNS} FROM request_integrations ORDER BY name");
    let rows = pool.query(&sql, &[]).await?;
    rows.iter().map(|r| scan_integration(cipher, r)).collect()
}

pub async fn get_integration(pool: &Pool, cipher: &Cipher, id: &str) -> Result<Integration, Error> {
    let sql = format!("SELECT {INTEGRATION_COLUMNS} FROM request_integrations WHERE id = $1");
    let rows = pool.query(&sql, &[&trim_space(id)]).await?;
    match rows.first() {
        Some(row) => scan_integration(cipher, row),
        None => Err(Error::NotFound),
    }
}

/// `lockRevision`.
async fn lock_revision(
    tx: &mut Tx<'_>,
    sql: &str,
    id: &str,
    expected: i64,
    allow_missing: bool,
) -> Result<(), Error> {
    let rows = tx.query(sql, &[&id]).await?;
    let Some(row) = rows.first() else {
        if allow_missing && (expected == 0 || expected == -1) {
            return Ok(());
        }
        return Err(if expected == -1 {
            Error::NotFound
        } else {
            Error::StaleRevision
        });
    };
    let revision: i64 = row.get(0);
    if expected != -1 && expected != revision {
        return Err(Error::StaleRevision);
    }
    Ok(())
}

async fn lock_routing_mode(tx: &mut Tx<'_>) -> Result<(), Error> {
    tx.query(
        "SELECT pg_advisory_xact_lock(hashtext('request-routing-mode'))",
        &[],
    )
    .await?;
    Ok(())
}

/// `deleteIntegration` under the mode lock.
async fn delete_integration_locked(tx: &mut Tx<'_>, id: &str) -> Result<(), Error> {
    let rows = tx
        .query(
            "SELECT id FROM request_integrations WHERE id = $1 FOR UPDATE",
            &[&id],
        )
        .await?;
    if rows.is_empty() {
        return Err(Error::NotFound);
    }
    let live = tx
        .query(
            "SELECT EXISTS (
			SELECT 1 FROM media_request_targets
			WHERE integration_id = $1 AND status IN ('queued', 'downloading')
		)",
            &[&id],
        )
        .await?;
    if live[0].get(0) {
        return Err(Error::InvalidState);
    }
    let rows = tx
        .query(
            "SELECT coalesce(plugin_config->>'service_kind', '') FROM request_integrations WHERE id = $1",
            &[&id],
        )
        .await?;
    let kind: String = rows[0].get(0);
    if !kind.is_empty() {
        tx.query(
            "SELECT pg_advisory_xact_lock(hashtext('request-routes-first-server:' || $1))",
            &[&kind],
        )
        .await?;
    }
    tx.execute(
        "DELETE FROM request_routes f
		WHERE f.is_fallback
		  AND $1 IN (f.hd_integration_id, f.uhd_integration_id)
		  AND coalesce(f.hd_integration_id, $1) = $1
		  AND coalesce(f.uhd_integration_id, $1) = $1
		  AND NOT EXISTS (SELECT 1 FROM request_routes r WHERE r.media_type = f.media_type AND NOT r.is_fallback)
		  AND NOT EXISTS (
			SELECT 1 FROM request_integrations i
			WHERE i.id <> $1
			  AND i.plugin_config->>'service_kind' = CASE f.media_type WHEN 'movie' THEN 'radarr' ELSE 'sonarr' END)",
        &[&id],
    )
    .await?;
    let rows = tx
        .query(
            "SELECT mode, revision, updated_at FROM request_routing WHERE id",
            &[],
        )
        .await?;
    let standard = rows
        .first()
        .is_some_and(|r| r.get::<_, String>(0) == "standard");
    if standard {
        tx.execute(
            "UPDATE request_routes SET
				hd_integration_id = NULLIF(hd_integration_id, $1),
				uhd_integration_id = NULLIF(uhd_integration_id, $1)
			WHERE is_fallback AND $1 IN (hd_integration_id, uhd_integration_id)",
            &[&id],
        )
        .await?;
    }
    let rows = tx
        .query(
            "SELECT name FROM request_routes
		WHERE hd_integration_id = $1 OR uhd_integration_id = $1
		ORDER BY media_type, is_fallback, position",
            &[&id],
        )
        .await?;
    let routes: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
    if !routes.is_empty() && standard {
        return Err(form_error(format!(
            "Paused routing rules still send requests to this server ({}). Switch to Advanced routing and send them elsewhere first.",
            routes.join(", ")
        )));
    }
    if !routes.is_empty() {
        return Err(form_error(format!(
            "Routing still sends requests to this server ({}); send them elsewhere first.",
            routes.join(", ")
        )));
    }
    tx.execute("DELETE FROM request_integrations WHERE id = $1", &[&id])
        .await?;
    Ok(())
}

/// `DeleteIntegration` (v1) and `DeleteIntegrationConditional` (v2).
pub async fn delete_integration(pool: &Pool, id: &str, expected: Option<i64>) -> Result<(), Error> {
    let id = trim_space(id);
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    lock_routing_mode(&mut tx).await?;
    if let Some(expected) = expected {
        lock_revision(
            &mut tx,
            "SELECT revision FROM request_integrations WHERE id=$1 FOR UPDATE",
            id,
            expected,
            false,
        )
        .await?;
    }
    delete_integration_locked(&mut tx, id).await?;
    tx.commit().await?;
    Ok(())
}

/// `requests.RouteConditions`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Conditions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anime: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub genre_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keyword_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub original_languages: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub origin_countries: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub year_from: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub year_to: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub company_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requester_user_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub series_statuses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_genre_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_keyword_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_original_languages: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_origin_countries: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_network_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_company_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_requester_user_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_series_statuses: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub max_content_rating: String,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// `requests.RouteDestination`.
#[derive(Clone, Debug, Default)]
pub struct Destination {
    pub integration_id: String,
    pub overrides: Option<Config>,
}

/// `requests.Route`.
#[derive(Clone, Debug, Default)]
pub struct Route {
    pub id: String,
    pub media_type: String,
    pub position: i64,
    pub name: String,
    pub enabled: bool,
    pub is_fallback: bool,
    pub conditions: Conditions,
    pub hd: Destination,
    pub uhd: Destination,
    pub skip_uhd: bool,
    pub revision: i64,
}

const ROUTE_COLUMNS: &str = "id, media_type, position, name, enabled, is_fallback, conditions::text,
	coalesce(hd_integration_id, ''), hd_overrides::text, coalesce(uhd_integration_id, ''), uhd_overrides::text,
	skip_uhd, revision";

fn scan_route(row: &Row) -> Result<Route, Error> {
    let conditions: String = row.get(6);
    Ok(Route {
        id: row.get(0),
        media_type: row.get(1),
        position: i64::from(row.get::<_, i32>(2)),
        name: row.get(3),
        enabled: row.get(4),
        is_fallback: row.get(5),
        conditions: unmarshal(conditions.as_bytes()).map_err(|e| Error::Internal(e.to_string()))?,
        hd: Destination {
            integration_id: row.get(7),
            overrides: Some(decode_config(&row.get::<_, String>(8))?),
        },
        uhd: Destination {
            integration_id: row.get(9),
            overrides: Some(decode_config(&row.get::<_, String>(10))?),
        },
        skip_uhd: row.get(11),
        revision: row.get(12),
    })
}

/// `normalizeMediaType`.
pub fn normalize_media_type(media_type: &str) -> Result<&'static str, Error> {
    match silo_gocompat::strings::to_lower(trim_space(media_type)).as_str() {
        "movie" => Ok("movie"),
        "series" | "tv" => Ok("series"),
        _ => Err(Error::InvalidMediaType),
    }
}

async fn list_routes(pool: &Pool) -> Result<Vec<Route>, Error> {
    let sql = format!(
        "SELECT {ROUTE_COLUMNS} FROM request_routes ORDER BY media_type, is_fallback, position, id"
    );
    let rows = pool.query(&sql, &[]).await?;
    rows.iter().map(scan_route).collect()
}

const FALLBACK_NAME: &str = "Everything else";

/// `FallbackRouteID`.
fn fallback_id(media_type: &str) -> String {
    format!("fallback-{media_type}")
}

fn unsaved_fallback(media_type: &str) -> Route {
    Route {
        id: fallback_id(media_type),
        media_type: media_type.to_owned(),
        position: 1000,
        name: FALLBACK_NAME.to_owned(),
        enabled: true,
        is_fallback: true,
        ..Route::default()
    }
}

/// `Service.ListRoutesAdmin`.
pub async fn list_routes_admin(pool: &Pool) -> Result<Vec<Route>, Error> {
    let routes = list_routes(pool).await?;
    let mut out = Vec::new();
    for media_type in ["movie", "series"] {
        let mut of_type: Vec<Route> = routes
            .iter()
            .filter(|r| r.media_type == media_type)
            .cloned()
            .collect();
        if !of_type.iter().any(|r| r.is_fallback) {
            of_type.push(unsaved_fallback(media_type));
        }
        // `orderRoutes`.
        of_type.sort_by(|a, b| {
            a.is_fallback
                .cmp(&b.is_fallback)
                .then(a.position.cmp(&b.position))
                .then(a.id.cmp(&b.id))
        });
        out.extend(of_type);
    }
    Ok(out)
}

async fn stored_route(pool: &Pool, id: &str) -> Result<Option<Route>, Error> {
    let sql = format!("SELECT {ROUTE_COLUMNS} FROM request_routes WHERE id = $1");
    let rows = pool.query(&sql, &[&id]).await?;
    rows.first().map(scan_route).transpose()
}

/// `Service.GetRoute`.
pub async fn get_route(pool: &Pool, id: &str) -> Result<Route, Error> {
    let id = trim_space(id);
    if let Some(route) = stored_route(pool, id).await? {
        return Ok(route);
    }
    for media_type in ["movie", "series"] {
        if id == fallback_id(media_type) {
            return Ok(unsaved_fallback(media_type));
        }
    }
    Err(Error::NotFound)
}

fn config_kind(config: &Config) -> &str {
    config
        .get("service_kind")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn is_4k_server(config: &Config) -> bool {
    ["is_4k", "is_default_4k"]
        .iter()
        .any(|key| match config.get(*key) {
            Some(Value::Bool(flag)) => *flag,
            Some(Value::String(s)) => s == "true",
            _ => false,
        })
}

fn kind_label(kind: &str) -> &str {
    match kind {
        "radarr" => "Radarr",
        "sonarr" => "Sonarr",
        other => other,
    }
}

fn plural(media_type: &str) -> &'static str {
    if media_type == "series" {
        "series"
    } else {
        "movies"
    }
}

/// What a destination check reads of a server.
struct Server {
    id: String,
    name: String,
    supported: Vec<String>,
    config: Config,
}

impl Server {
    fn supports(&self, media_type: &str) -> bool {
        self.supported.is_empty() || self.supported.iter().any(|m| m == media_type)
    }
}

/// `tierMismatch`.
fn tier_mismatch(s: &Server, uhd: bool) -> String {
    if config_kind(&s.config).is_empty() {
        return String::new();
    }
    let marked = is_4k_server(&s.config);
    if uhd && !marked {
        format!(
            "{} isn't marked 4K. Turn on \"4K server\" in its settings to send 4K versions to it.",
            s.name
        )
    } else if !uhd && marked {
        format!("{} is marked 4K; it can only take the 4K version.", s.name)
    } else {
        String::new()
    }
}

/// `destinationMismatch`.
fn destination_mismatch(s: &Server, media_type: &str, uhd: bool) -> String {
    let kind = config_kind(&s.config);
    if !kind.is_empty() {
        let want = match media_type {
            "movie" => "radarr",
            "series" => "sonarr",
            _ => "",
        };
        if !want.is_empty() && kind != want {
            return format!(
                "{} is a {} server; {} need {}.",
                s.name,
                kind_label(kind),
                plural(media_type),
                kind_label(want)
            );
        }
    }
    if !media_type.is_empty() && !s.supports(media_type) {
        return format!("{} does not take {}.", s.name, plural(media_type));
    }
    tier_mismatch(s, uhd)
}

const ROUTING_OWNED: [&str; 8] = [
    "service_kind",
    "is_default",
    "is_default_4k",
    "is_4k",
    "anime_enabled",
    "anime_root_folder",
    "anime_quality_profile_id",
    "anime_tags",
];

/// `validateDestination`.
fn validate_destination(
    field: &str,
    dest: &mut Destination,
    media_type: &str,
    servers: &[Server],
    fields: &mut BTreeMap<String, String>,
) {
    dest.integration_id = trim_space(&dest.integration_id).to_owned();
    if dest.integration_id.is_empty() {
        dest.overrides = None;
        return;
    }
    let Some(server) = servers.iter().rfind(|s| s.id == dest.integration_id) else {
        fields.insert(
            format!("{field}.integration_id"),
            "That server no longer exists.".to_owned(),
        );
        return;
    };
    let msg = destination_mismatch(server, media_type, field == "uhd");
    if !msg.is_empty() {
        fields.insert(format!("{field}.integration_id"), msg);
    }
    for key in ROUTING_OWNED {
        if dest.overrides.as_ref().is_some_and(|o| o.contains_key(key)) {
            fields.insert(
                format!("{field}.overrides.{key}"),
                format!("Routing sets {key} itself."),
            );
        }
    }
    if dest.overrides.as_ref().is_none_or(BTreeMap::is_empty) {
        dest.overrides = None;
    }
}

fn dedupe_strings(values: &[String], f: fn(&str) -> String) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        let v = f(trim_space(v));
        if !v.is_empty() && !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

fn sorted_ids(values: &[i64]) -> Vec<i64> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn lower(s: &str) -> String {
    silo_gocompat::strings::to_lower(s)
}

fn upper(s: &str) -> String {
    silo_gocompat::strings::to_upper(s)
}

/// `normalizeConditions`.
fn normalize_conditions(c: &mut Conditions) {
    c.genre_ids = sorted_ids(&c.genre_ids);
    c.keyword_ids = sorted_ids(&c.keyword_ids);
    c.network_ids = sorted_ids(&c.network_ids);
    c.company_ids = sorted_ids(&c.company_ids);
    c.requester_user_ids = sorted_ids(&c.requester_user_ids);
    c.original_languages = dedupe_strings(&c.original_languages, lower);
    c.origin_countries = dedupe_strings(&c.origin_countries, upper);
    c.exclude_genre_ids = sorted_ids(&c.exclude_genre_ids);
    c.exclude_keyword_ids = sorted_ids(&c.exclude_keyword_ids);
    c.exclude_network_ids = sorted_ids(&c.exclude_network_ids);
    c.exclude_company_ids = sorted_ids(&c.exclude_company_ids);
    c.exclude_requester_user_ids = sorted_ids(&c.exclude_requester_user_ids);
    c.exclude_original_languages = dedupe_strings(&c.exclude_original_languages, lower);
    c.exclude_origin_countries = dedupe_strings(&c.exclude_origin_countries, upper);
    c.series_statuses = dedupe_strings(&c.series_statuses, lower);
    c.exclude_series_statuses = dedupe_strings(&c.exclude_series_statuses, lower);
    c.max_content_rating = trim_space(&c.max_content_rating).to_owned();
}

fn language_ok(v: &str) -> bool {
    (2..=3).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_lowercase())
}

fn country_ok(v: &str) -> bool {
    v.len() == 2 && v.bytes().all(|b| b.is_ascii_uppercase())
}

const KNOWN_STATUSES: [&str; 5] = [
    "returning",
    "in_production",
    "upcoming",
    "ended",
    "cancelled",
];

/// `validateConditions` and `validateSeriesStatuses`.
fn validate_conditions(c: &Conditions, media_type: &str, fields: &mut BTreeMap<String, String>) {
    for (field, values) in [
        ("genre_ids", &c.genre_ids),
        ("keyword_ids", &c.keyword_ids),
        ("network_ids", &c.network_ids),
        ("company_ids", &c.company_ids),
        ("requester_user_ids", &c.requester_user_ids),
        ("exclude_genre_ids", &c.exclude_genre_ids),
        ("exclude_keyword_ids", &c.exclude_keyword_ids),
        ("exclude_network_ids", &c.exclude_network_ids),
        ("exclude_company_ids", &c.exclude_company_ids),
        ("exclude_requester_user_ids", &c.exclude_requester_user_ids),
    ] {
        if values.iter().any(|v| *v <= 0) {
            fields.insert(
                format!("conditions.{field}"),
                "IDs must be positive.".to_owned(),
            );
        }
    }
    for (field, values) in [
        ("original_languages", &c.original_languages),
        ("exclude_original_languages", &c.exclude_original_languages),
    ] {
        if values.iter().any(|v| !language_ok(v)) {
            fields.insert(
                format!("conditions.{field}"),
                "Use ISO 639-1 language codes such as ja or en.".to_owned(),
            );
        }
    }
    for (field, values) in [
        ("origin_countries", &c.origin_countries),
        ("exclude_origin_countries", &c.exclude_origin_countries),
    ] {
        if values.iter().any(|v| !country_ok(v)) {
            fields.insert(
                format!("conditions.{field}"),
                "Use ISO 3166-1 country codes such as JP or US.".to_owned(),
            );
        }
    }
    for (field, values) in [
        ("series_statuses", &c.series_statuses),
        ("exclude_series_statuses", &c.exclude_series_statuses),
    ] {
        if !values.is_empty() && media_type == "movie" {
            fields.insert(
                format!("conditions.{field}"),
                "Only series rules can match on status.".to_owned(),
            );
        } else if values.iter().any(|v| !KNOWN_STATUSES.contains(&v.as_str())) {
            fields.insert(
                format!("conditions.{field}"),
                format!("Use the statuses {}.", KNOWN_STATUSES.join(", ")),
            );
        }
    }
    const BOTH: &str = "Remove the values that are in both \u{201c}is any of\u{201d} and \u{201c}is none of\u{201d}.";
    let ints = |a: &[i64], b: &[i64]| a.iter().any(|v| b.contains(v));
    let texts = |a: &[String], b: &[String]| a.iter().any(|v| b.contains(v));
    if texts(&c.series_statuses, &c.exclude_series_statuses)
        || ints(&c.genre_ids, &c.exclude_genre_ids)
        || ints(&c.keyword_ids, &c.exclude_keyword_ids)
        || ints(&c.network_ids, &c.exclude_network_ids)
        || ints(&c.company_ids, &c.exclude_company_ids)
        || ints(&c.requester_user_ids, &c.exclude_requester_user_ids)
        || texts(&c.original_languages, &c.exclude_original_languages)
        || texts(&c.origin_countries, &c.exclude_origin_countries)
    {
        fields.insert("conditions".to_owned(), BOTH.to_owned());
    }
    if !c.max_content_rating.is_empty()
        && !crate::rating::normalize(&c.max_content_rating).is_some_and(|(_, age)| age.is_some())
    {
        fields.insert(
            "conditions.max_content_rating".to_owned(),
            "Choose a rating such as G, PG, PG-13 or TV-Y7.".to_owned(),
        );
    }
    for (field, year) in [("year_from", c.year_from), ("year_to", c.year_to)] {
        if year != 0 && !(1870..=2200).contains(&year) {
            fields.insert(
                format!("conditions.{field}"),
                "Use a year between 1870 and 2200.".to_owned(),
            );
        }
    }
    if c.year_from != 0 && c.year_to != 0 && c.year_from > c.year_to {
        fields.insert(
            "conditions.year_to".to_owned(),
            "The end year comes before the start year.".to_owned(),
        );
    }
}

fn conditions_empty(c: &Conditions) -> bool {
    let lists = c.genre_ids.len()
        + c.keyword_ids.len()
        + c.original_languages.len()
        + c.origin_countries.len()
        + c.network_ids.len()
        + c.company_ids.len()
        + c.requester_user_ids.len()
        + c.exclude_genre_ids.len()
        + c.exclude_keyword_ids.len()
        + c.exclude_original_languages.len()
        + c.exclude_origin_countries.len()
        + c.exclude_network_ids.len()
        + c.exclude_company_ids.len()
        + c.exclude_requester_user_ids.len()
        + c.series_statuses.len()
        + c.exclude_series_statuses.len();
    c.anime.is_none()
        && lists == 0
        && c.year_from == 0
        && c.year_to == 0
        && c.max_content_rating.is_empty()
}

async fn servers(pool: &Pool, cipher: &Cipher) -> Result<Vec<Server>, Error> {
    Ok(list_integrations(pool, cipher)
        .await?
        .into_iter()
        .map(|i| Server {
            id: i.id,
            name: i.name,
            supported: i.supported_media_types,
            config: i.plugin_config,
        })
        .collect())
}

/// `Service.validateRoute`.
async fn validate_route(pool: &Pool, cipher: &Cipher, route: &mut Route) -> Result<(), Error> {
    let mut fields = BTreeMap::new();
    route.name = trim_space(&route.name).to_owned();
    if route.is_fallback && route.name.is_empty() {
        route.name = FALLBACK_NAME.to_owned();
    }
    if route.name.is_empty() {
        fields.insert("name".to_owned(), "Give the rule a name.".to_owned());
    } else if route.name.chars().count() > 100 {
        fields.insert(
            "name".to_owned(),
            "Keep the name under 100 characters.".to_owned(),
        );
    }
    match normalize_media_type(&route.media_type) {
        Ok(m) => route.media_type = m.to_owned(),
        Err(_) => {
            fields.insert(
                "media_type".to_owned(),
                "Choose movies or series.".to_owned(),
            );
            route.media_type.clear();
        }
    }
    normalize_conditions(&mut route.conditions);
    validate_conditions(&route.conditions, &route.media_type, &mut fields);
    let all = servers(pool, cipher).await?;
    let media_type = route.media_type.clone();
    validate_destination("hd", &mut route.hd, &media_type, &all, &mut fields);
    validate_destination("uhd", &mut route.uhd, &media_type, &all, &mut fields);
    if route.is_fallback {
        route.enabled = true;
        route.skip_uhd = false;
        if !conditions_empty(&route.conditions) {
            fields.insert(
                "conditions".to_owned(),
                "Everything else takes every request; it can't have conditions.".to_owned(),
            );
        }
        if route.hd.integration_id.is_empty() && !fields.contains_key("hd.integration_id") {
            fields.insert(
                "hd.integration_id".to_owned(),
                "Choose the server that gets everything else.".to_owned(),
            );
        }
    } else {
        if conditions_empty(&route.conditions) {
            fields.insert(
                "conditions".to_owned(),
                "Add at least one condition. Requests no rule matches go to Everything else."
                    .to_owned(),
            );
        }
        if route.hd.integration_id.is_empty()
            && route.uhd.integration_id.is_empty()
            && !route.skip_uhd
        {
            fields.insert(
                "hd".to_owned(),
                "Choose where the HD and 4K versions go, or don't send a 4K version.".to_owned(),
            );
        }
        if route.skip_uhd && !route.uhd.integration_id.is_empty() {
            fields.insert(
                "uhd".to_owned(),
                "A rule can't both send 4K versions somewhere and skip them.".to_owned(),
            );
        }
    }
    if !fields.is_empty() {
        return Err(Error::Validation {
            fields,
            form: String::new(),
        });
    }
    Ok(())
}

fn overrides_json(d: &Destination) -> Result<String, Error> {
    let empty = Config::new();
    marshal(d.overrides.as_ref().unwrap_or(&empty))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|e| Error::Internal(e.to_string()))
}

/// `Repository.SaveRouteConditional`.
async fn save_route(pool: &Pool, route: &Route, expected: i64) -> Result<Route, Error> {
    let conditions = marshal(&route.conditions).map_err(|e| Error::Internal(e.to_string()))?;
    let conditions = String::from_utf8_lossy(&conditions).into_owned();
    let (hd_json, uhd_json) = (overrides_json(&route.hd)?, overrides_json(&route.uhd)?);
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .await?;
    let allow_missing = expected == 0 || route.is_fallback;
    // `ensureDestinationsFit`.
    let ids: Vec<String> = [&route.hd.integration_id, &route.uhd.integration_id]
        .into_iter()
        .filter(|id| !id.is_empty())
        .cloned()
        .collect();
    if !ids.is_empty() {
        let rows = tx
            .query(
                "SELECT id, name, supported_media_types, plugin_config::text FROM request_integrations WHERE id = ANY($1) ORDER BY id FOR SHARE",
                &[&ids],
            )
            .await?;
        let mut fields = BTreeMap::new();
        for row in &rows {
            let server = Server {
                id: row.get(0),
                name: row.get(1),
                supported: row.get(2),
                config: decode_config(&row.get::<_, String>(3))?,
            };
            for (field, dest, uhd) in [("hd", &route.hd, false), ("uhd", &route.uhd, true)] {
                if dest.integration_id == server.id {
                    let msg = destination_mismatch(&server, &route.media_type, uhd);
                    if !msg.is_empty() {
                        fields.insert(format!("{field}.integration_id"), msg);
                    }
                }
            }
        }
        if !fields.is_empty() {
            return Err(Error::Validation {
                fields,
                form: String::new(),
            });
        }
    }
    lock_revision(
        &mut tx,
        "SELECT revision FROM request_routes WHERE id = $1 FOR UPDATE",
        &route.id,
        expected,
        allow_missing,
    )
    .await?;
    let sql = format!(
        "INSERT INTO request_routes (id, media_type, position, name, enabled, is_fallback, conditions,
			hd_integration_id, hd_overrides, uhd_integration_id, uhd_overrides, skip_uhd)
		VALUES ($1, $2, $3, $4, $5, $6, $7::text::jsonb, nullif($8, ''), $9::text::jsonb, nullif($10, ''), $11::text::jsonb, $12)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name, enabled = EXCLUDED.enabled, conditions = EXCLUDED.conditions,
			hd_integration_id = EXCLUDED.hd_integration_id, hd_overrides = EXCLUDED.hd_overrides,
			uhd_integration_id = EXCLUDED.uhd_integration_id, uhd_overrides = EXCLUDED.uhd_overrides,
			skip_uhd = EXCLUDED.skip_uhd, updated_at = now()
		WHERE $13::bigint = -1 OR request_routes.revision = $13::bigint
		RETURNING {ROUTE_COLUMNS}"
    );
    let rows = tx
        .query(
            &sql,
            &[
                &route.id,
                &route.media_type,
                &AnyInt(route.position),
                &route.name,
                &route.enabled,
                &route.is_fallback,
                &conditions,
                &route.hd.integration_id,
                &hd_json,
                &route.uhd.integration_id,
                &uhd_json,
                &route.skip_uhd,
                &expected,
            ],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Err(Error::StaleRevision);
    };
    let saved = scan_route(row)?;
    tx.commit().await?;
    Ok(saved)
}

/// `Service.CreateRoute`. `id` is the caller's `idgen.NextID`.
pub async fn create_route(
    pool: &Pool,
    cipher: &Cipher,
    mut route: Route,
    id: String,
) -> Result<Route, Error> {
    route.id = id;
    route.is_fallback = false;
    validate_route(pool, cipher, &mut route).await?;
    let mut fallback_ready = false;
    let mut rules = 0;
    for existing in list_routes(pool).await? {
        if existing.media_type != route.media_type {
            continue;
        }
        if existing.is_fallback {
            fallback_ready = !existing.hd.integration_id.is_empty();
            continue;
        }
        rules += 1;
        if existing.position >= route.position {
            route.position = existing.position + 1;
        }
    }
    if rules >= 100 {
        return Err(form_error("A media type can have at most 100 rules."));
    }
    if !fallback_ready {
        return Err(form_error(
            "Choose where everything else goes before adding rules.",
        ));
    }
    save_route(pool, &route, 0).await
}

/// `Service.UpdateRouteConditional`.
pub async fn update_route(
    pool: &Pool,
    cipher: &Cipher,
    mut route: Route,
    expected: i64,
) -> Result<Route, Error> {
    route.is_fallback = route.id == fallback_id("movie") || route.id == fallback_id("series");
    match stored_route(pool, &route.id).await? {
        None if route.is_fallback => {
            route.media_type = route.id.trim_start_matches("fallback-").to_owned();
            route.position = 1000;
        }
        None => return Err(Error::NotFound),
        Some(current) => {
            route.media_type = current.media_type;
            route.position = current.position;
        }
    }
    validate_route(pool, cipher, &mut route).await?;
    save_route(pool, &route, expected).await
}

/// `Service.DeleteRouteConditional`.
pub async fn delete_route(pool: &Pool, id: &str, expected: i64) -> Result<(), Error> {
    let current = stored_route(pool, trim_space(id))
        .await?
        .ok_or(Error::NotFound)?;
    if current.is_fallback {
        return Err(form_error(
            "Everything else can't be deleted; change where it sends requests instead.",
        ));
    }
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .await?;
    lock_revision(
        &mut tx,
        "SELECT revision FROM request_routes WHERE id = $1 FOR UPDATE",
        &current.id,
        expected,
        false,
    )
    .await?;
    tx.execute(
        "DELETE FROM request_routes WHERE id = $1 AND NOT is_fallback",
        &[&current.id],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `Service.ReorderRoutes`.
pub async fn reorder_routes(
    pool: &Pool,
    media_type: &str,
    ids: &[String],
) -> Result<Vec<Route>, Error> {
    let media_type = normalize_media_type(media_type)?;
    let mut want: Vec<String> = list_routes(pool)
        .await?
        .into_iter()
        .filter(|r| r.media_type == media_type && !r.is_fallback)
        .map(|r| r.id)
        .collect();
    let mut got = ids.to_vec();
    want.sort();
    got.sort();
    if want != got {
        return Err(form_error(
            "The order must list every rule for this media type exactly once; reload and try again.",
        ));
    }
    pool.execute(
        "UPDATE request_routes r SET position = o.position - 1, updated_at = now()
		FROM unnest($2::text[]) WITH ORDINALITY AS o(id, position)
		WHERE r.id = o.id AND r.media_type = $1 AND NOT r.is_fallback",
        &[&media_type, &ids],
    )
    .await?;
    let mut all = list_routes_admin(pool).await?;
    all.retain(|r| r.media_type == media_type);
    Ok(all)
}

/// `ensureViewerRequestsAllowed`: an administrator always may; otherwise the account's override, then its group.
pub async fn requests_allowed(pool: &Pool, user: i64) -> Result<bool, Error> {
    let rows = pool
        .query(
            "SELECT u.role, u.requests_allowed, g.requests_allowed
             FROM users u LEFT JOIN access_groups g ON g.id = u.access_group_id WHERE u.id = $1",
            &[&AnyInt(user)],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(false);
    };
    let role: String = row.get(0);
    let own: Option<bool> = row.get(1);
    let group: Option<bool> = row.get(2);
    let base = if role == "admin" {
        true
    } else {
        group.unwrap_or(true)
    };
    Ok(own.unwrap_or(base))
}

/// Server-wide request editor settings, including a missing row's defaults.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub revision: i64,
    pub requests_enabled: bool,
    pub global_max_requests: i64,
    pub global_window_days: i64,
    pub global_auto_approval_enabled: bool,
    pub force_dual_quality: bool,
    pub watchlist_requests: bool,
    pub updated_at: Option<SystemTime>,
}

fn scan_settings(row: &Row) -> Settings {
    Settings {
        requests_enabled: row.get(0),
        global_max_requests: i64::from(row.get::<_, i32>(1)),
        global_window_days: i64::from(row.get::<_, i32>(2)),
        global_auto_approval_enabled: row.get(3),
        force_dual_quality: row.get(4),
        watchlist_requests: row.get(5),
        updated_at: Some(row.get(6)),
        revision: row.get(7),
    }
}

pub async fn get_settings(pool: &Pool) -> Result<Settings, Error> {
    let rows = pool.query(SETTINGS_GET_SQL, &[]).await?;
    Ok(rows.first().map(scan_settings).unwrap_or(Settings {
        global_max_requests: 5,
        global_window_days: 7,
        watchlist_requests: true,
        ..Settings::default()
    }))
}

// PostgreSQL integer columns must receive int4 parameters, even though Go's API integers are int64.
fn request_int4(value: i64) -> Result<i32, Error> {
    i32::try_from(value).map_err(|e| Error::Internal(e.to_string()))
}

async fn lock_default_revision(
    tx: &mut Tx<'_>,
    sql: &str,
    params: &[&(dyn silo_pg::ToSql + Sync)],
    expected: i64,
) -> Result<(), Error> {
    let rows = tx.query(sql, params).await?;
    let revision = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    if expected != -1 && expected != revision {
        return Err(Error::StaleRevision);
    }
    Ok(())
}

pub async fn update_settings_conditional(
    pool: &Pool,
    input: Settings,
    expected: i64,
) -> Result<Settings, Error> {
    if input.global_max_requests < 0 || input.global_window_days <= 0 {
        return Err(Error::InvalidInput("invalid request settings".into()));
    }
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    lock_default_revision(
        &mut tx,
        "SELECT revision FROM request_settings WHERE id=true FOR UPDATE",
        &[],
        expected,
    )
    .await?;
    let max = request_int4(input.global_max_requests)?;
    let window = request_int4(input.global_window_days)?;
    let rows = tx
        .query(
            SETTINGS_PUT_SQL,
            &[
                &input.requests_enabled,
                &max,
                &window,
                &input.global_auto_approval_enabled,
                &input.force_dual_quality,
                &expected,
                &input.watchlist_requests,
            ],
        )
        .await?;
    let output = scan_settings(rows.first().ok_or(Error::StaleRevision)?);
    tx.commit().await?;
    Ok(output)
}

#[derive(Clone, Debug, Default)]
pub struct UserLimit {
    pub revision: i64,
    pub user_id: i64,
    pub limit_mode: String,
    pub max_requests: Option<i64>,
    pub window_days: Option<i64>,
    pub approval_mode: String,
    pub updated_at: Option<SystemTime>,
}

fn scan_user_limit(row: &Row) -> UserLimit {
    UserLimit {
        user_id: i64::from(row.get::<_, i32>(0)),
        limit_mode: row.get(1),
        max_requests: row.get::<_, Option<i32>>(2).map(i64::from),
        window_days: row.get::<_, Option<i32>>(3).map(i64::from),
        approval_mode: row.get(4),
        updated_at: Some(row.get(5)),
        revision: row.get(6),
    }
}

pub async fn get_user_limit(pool: &Pool, user_id: i64) -> Result<UserLimit, Error> {
    if user_id <= 0 {
        return Err(Error::InvalidInput("invalid user id".into()));
    }
    let rows = pool
        .query(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)",
            &[&user_id],
        )
        .await?;
    if !rows[0].get::<_, bool>(0) {
        return Err(Error::NotFound);
    }
    let id = request_int4(user_id)?;
    let rows = pool.query(USER_LIMIT_GET_SQL, &[&id]).await?;
    Ok(rows.first().map(scan_user_limit).unwrap_or(UserLimit {
        user_id,
        limit_mode: "inherit".into(),
        approval_mode: "inherit".into(),
        ..UserLimit::default()
    }))
}

pub async fn upsert_user_limit_conditional(
    pool: &Pool,
    mut input: UserLimit,
    expected: i64,
) -> Result<UserLimit, Error> {
    if input.user_id <= 0 {
        return Err(Error::InvalidInput("invalid user id".into()));
    }
    match input.limit_mode.as_str() {
        "" | "inherit" | "unlimited" | "blocked" => {
            if input.limit_mode.is_empty() {
                input.limit_mode = "inherit".into();
            }
            input.max_requests = None;
            input.window_days = None;
        }
        "custom" => {
            if input.max_requests.is_none_or(|v| v < 0) || input.window_days.is_none_or(|v| v <= 0)
            {
                return Err(Error::InvalidInput(
                    "custom limits require max_requests >= 0 and window_days > 0".into(),
                ));
            }
        }
        _ => return Err(Error::InvalidInput("invalid limit mode".into())),
    }
    match input.approval_mode.as_str() {
        "" => input.approval_mode = "inherit".into(),
        "inherit" | "manual" | "auto" | "blocked" => {}
        _ => return Err(Error::InvalidInput("invalid approval mode".into())),
    }
    let id = request_int4(input.user_id)?;
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    if tx
        .query(
            "SELECT id FROM users WHERE id=$1 FOR KEY SHARE",
            &[&input.user_id],
        )
        .await?
        .is_empty()
    {
        return Err(Error::NotFound);
    }
    lock_default_revision(
        &mut tx,
        "SELECT revision FROM request_user_limits WHERE user_id=$1 FOR UPDATE",
        &[&id],
        expected,
    )
    .await?;
    let max = input.max_requests.map(request_int4).transpose()?;
    let window = input.window_days.map(request_int4).transpose()?;
    let rows = tx
        .query(
            USER_LIMIT_PUT_SQL,
            &[
                &id,
                &input.limit_mode,
                &max,
                &window,
                &input.approval_mode,
                &expected,
            ],
        )
        .await?;
    let output = scan_user_limit(rows.first().ok_or(Error::StaleRevision)?);
    tx.commit().await?;
    Ok(output)
}

#[derive(Clone, Debug, Default)]
pub struct GroupLimit {
    pub revision: i64,
    pub group_id: i64,
    pub limit_mode: String,
    pub max_requests: Option<i64>,
    pub window_days: Option<i64>,
    pub approval_mode: String,
    pub updated_at: Option<SystemTime>,
}

fn scan_group_limit(row: &Row) -> GroupLimit {
    GroupLimit {
        group_id: row.get(0),
        limit_mode: row.get(1),
        max_requests: row.get::<_, Option<i32>>(2).map(i64::from),
        window_days: row.get::<_, Option<i32>>(3).map(i64::from),
        approval_mode: row.get(4),
        updated_at: Some(row.get(5)),
        revision: row.get(6),
    }
}

pub async fn get_group_limit(pool: &Pool, group_id: i64) -> Result<GroupLimit, Error> {
    let rows = pool
        .query(
            "SELECT EXISTS(SELECT 1 FROM access_groups WHERE id=$1)",
            &[&group_id],
        )
        .await?;
    if !rows[0].get::<_, bool>(0) {
        return Err(Error::NotFound);
    }
    let rows = pool.query(GROUP_LIMIT_GET_SQL, &[&group_id]).await?;
    Ok(rows.first().map(scan_group_limit).unwrap_or(GroupLimit {
        group_id,
        limit_mode: "inherit".into(),
        approval_mode: "inherit".into(),
        ..GroupLimit::default()
    }))
}

pub async fn upsert_group_limit_conditional(
    pool: &Pool,
    mut input: GroupLimit,
    expected: i64,
) -> Result<GroupLimit, Error> {
    if input.group_id <= 0 {
        return Err(Error::InvalidInput("invalid access group id".into()));
    }
    match input.limit_mode.as_str() {
        "" | "inherit" | "unlimited" => {
            if input.limit_mode.is_empty() {
                input.limit_mode = "inherit".into();
            }
            input.max_requests = None;
            input.window_days = None;
        }
        "custom" => {
            if input.max_requests.is_none_or(|v| v < 0) || input.window_days.is_none_or(|v| v <= 0)
            {
                return Err(Error::Validation {
                    fields: BTreeMap::from([("max_requests".into(), "A custom limit needs a number of requests (0 or more) and a window of at least one day.".into())]),
                    form: String::new(),
                });
            }
        }
        _ => return Err(Error::InvalidInput("invalid limit mode".into())),
    }
    match input.approval_mode.as_str() {
        "" => input.approval_mode = "inherit".into(),
        "inherit" | "manual" | "auto" => {}
        _ => return Err(Error::InvalidInput("invalid approval mode".into())),
    }
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    if tx
        .query(
            "SELECT id FROM access_groups WHERE id=$1 FOR KEY SHARE",
            &[&input.group_id],
        )
        .await?
        .is_empty()
    {
        return Err(Error::NotFound);
    }
    lock_default_revision(
        &mut tx,
        "SELECT revision FROM request_group_limits WHERE group_id=$1 FOR UPDATE",
        &[&input.group_id],
        expected,
    )
    .await?;
    let max = input.max_requests.map(request_int4).transpose()?;
    let window = input.window_days.map(request_int4).transpose()?;
    let rows = tx
        .query(
            GROUP_LIMIT_PUT_SQL,
            &[
                &input.group_id,
                &input.limit_mode,
                &max,
                &window,
                &input.approval_mode,
                &expected,
            ],
        )
        .await?;
    let output = scan_group_limit(rows.first().ok_or(Error::StaleRevision)?);
    tx.commit().await?;
    Ok(output)
}

const SETTINGS_GET_SQL: &str = r#"
		SELECT requests_enabled, global_max_requests, global_window_days,
		       global_auto_approval_enabled, force_dual_quality, watchlist_requests, updated_at, revision
		FROM request_settings
		WHERE id = true
	"#;

const SETTINGS_PUT_SQL: &str = r#"
		INSERT INTO request_settings (
			id, requests_enabled, global_max_requests, global_window_days,
			global_auto_approval_enabled, force_dual_quality, watchlist_requests, updated_at
		)
		VALUES (true, $1, $2, $3, $4, $5, COALESCE($7::boolean, true), now())
		ON CONFLICT (id) DO UPDATE SET
			requests_enabled = EXCLUDED.requests_enabled,
			global_max_requests = EXCLUDED.global_max_requests,
			global_window_days = EXCLUDED.global_window_days,
			global_auto_approval_enabled = EXCLUDED.global_auto_approval_enabled,
			force_dual_quality = EXCLUDED.force_dual_quality,
			watchlist_requests = COALESCE($7::boolean, request_settings.watchlist_requests),
			updated_at = now()
		WHERE $6::bigint = -1 OR request_settings.revision = $6
		RETURNING requests_enabled, global_max_requests, global_window_days,
		          global_auto_approval_enabled, force_dual_quality, watchlist_requests, updated_at, revision
	"#;

const USER_LIMIT_GET_SQL: &str = r#"
		SELECT user_id, limit_mode, max_requests, window_days, approval_mode, updated_at, revision
		FROM request_user_limits
		WHERE user_id = $1
	"#;

const USER_LIMIT_PUT_SQL: &str = r#"
		INSERT INTO request_user_limits (
			user_id, limit_mode, max_requests, window_days, approval_mode, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (user_id) DO UPDATE SET
			limit_mode = EXCLUDED.limit_mode,
			max_requests = EXCLUDED.max_requests,
			window_days = EXCLUDED.window_days,
			approval_mode = EXCLUDED.approval_mode,
			updated_at = now()
		WHERE $6::bigint = -1 OR request_user_limits.revision = $6
		RETURNING user_id, limit_mode, max_requests, window_days, approval_mode, updated_at, revision
	"#;

const GROUP_LIMIT_GET_SQL: &str = r#"
		SELECT group_id, limit_mode, max_requests, window_days, approval_mode, updated_at, revision
		FROM request_group_limits WHERE group_id = $1"#;

const GROUP_LIMIT_PUT_SQL: &str = r#"
		INSERT INTO request_group_limits (group_id, limit_mode, max_requests, window_days, approval_mode, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (group_id) DO UPDATE SET
			limit_mode = EXCLUDED.limit_mode,
			max_requests = EXCLUDED.max_requests,
			window_days = EXCLUDED.window_days,
			approval_mode = EXCLUDED.approval_mode,
			updated_at = now()
		WHERE $6::bigint = -1 OR request_group_limits.revision = $6
		RETURNING group_id, limit_mode, max_requests, window_days, approval_mode, updated_at, revision"#;

#[derive(Clone, Debug)]
pub struct StandardDestination {
    pub media_type: String,
    pub hd_integration_id: String,
    pub uhd_integration_id: String,
}

#[derive(Clone, Debug)]
pub struct RoutingOverview {
    pub mode: String,
    pub revision: i64,
    pub standard: Vec<StandardDestination>,
    pub standard_blocker: String,
}

fn server_serves(server: &Integration, media_type: &str) -> bool {
    match config_kind(&server.plugin_config) {
        "" => {
            server.supported_media_types.is_empty()
                || server.supported_media_types.iter().any(|m| m == media_type)
        }
        kind => {
            kind == if media_type == "movie" {
                "radarr"
            } else {
                "sonarr"
            }
        }
    }
}

fn self_routed(server: &Integration) -> bool {
    config_kind(&server.plugin_config).is_empty()
}

fn split_services(hd: &Integration, uhd: &Integration) -> bool {
    if !self_routed(hd) && !self_routed(uhd) {
        return false;
    }
    self_routed(hd) != self_routed(uhd)
        || hd.installation_id.is_none()
        || uhd.installation_id.is_none()
        || hd.installation_id != uhd.installation_id
        || hd.capability_id != uhd.capability_id
}

fn server_names(servers: &[&Integration]) -> String {
    let mut names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
    names.sort();
    names.join(", ")
}

fn standard_layout(integrations: &[Integration]) -> (Vec<StandardDestination>, String) {
    let mut out = Vec::new();
    let mut problems = Vec::new();
    let mut split = false;
    for media_type in ["movie", "series"] {
        let (uhd, hd): (Vec<_>, Vec<_>) = integrations
            .iter()
            .filter(|s| s.enabled && server_serves(s, media_type))
            .partition(|s| is_4k_server(&s.plugin_config));
        let noun = plural(media_type);
        let capitalized = if media_type == "movie" {
            "Movies"
        } else {
            "Series"
        };
        if hd.len() > 1 {
            problems.push(format!(
                "{capitalized} can go to more than one server ({})",
                server_names(&hd)
            ));
        }
        if uhd.len() > 1 {
            problems.push(format!(
                "more than one 4K server takes {noun} ({})",
                server_names(&uhd)
            ));
        }
        if hd.len() > 1 || uhd.len() > 1 || hd.len() + uhd.len() == 0 {
            continue;
        }
        if hd.len() == 1 && uhd.len() == 1 && split_services(hd[0], uhd[0]) {
            split = true;
            problems.push(format!(
                "{noun} go to {} and their 4K versions to {}, which are different request services",
                hd[0].name, uhd[0].name
            ));
            continue;
        }
        out.push(StandardDestination {
            media_type: media_type.into(),
            hd_integration_id: hd.first().map(|s| s.id.clone()).unwrap_or_default(),
            uhd_integration_id: uhd.first().map(|s| s.id.clone()).unwrap_or_default(),
        });
    }
    if problems.is_empty() {
        return (out, String::new());
    }
    let mut blocker = problems.join("; ");
    blocker[..1].make_ascii_uppercase();
    blocker.push_str(". Standard sends each request to one server, plus one server marked 4K");
    if split {
        blocker.push_str(", through one request service. Switch to Advanced routing to send them to different services");
    }
    blocker.push('.');
    (Vec::new(), blocker)
}

pub async fn get_routing_overview(pool: &Pool, cipher: &Cipher) -> Result<RoutingOverview, Error> {
    let rows = pool
        .query(
            "SELECT mode, revision, updated_at FROM request_routing WHERE id",
            &[],
        )
        .await?;
    let (mode, revision) = rows
        .first()
        .map(|r| (r.get(0), r.get(1)))
        .unwrap_or(("advanced".into(), 0));
    let integrations = list_integrations(pool, cipher).await?;
    let (standard, standard_blocker) = standard_layout(&integrations);
    Ok(RoutingOverview {
        mode,
        revision,
        standard,
        standard_blocker,
    })
}

pub async fn update_routing_mode_conditional(
    pool: &Pool,
    cipher: &Cipher,
    mode: &str,
    expected: i64,
) -> Result<RoutingOverview, Error> {
    if !matches!(mode, "standard" | "advanced") {
        return Err(Error::InvalidInput("invalid routing mode".into()));
    }
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    lock_routing_mode(&mut tx).await?;
    lock_default_revision(
        &mut tx,
        "SELECT revision FROM request_routing WHERE id FOR UPDATE",
        &[],
        expected,
    )
    .await?;
    let sql = format!("SELECT {INTEGRATION_COLUMNS} FROM request_integrations ORDER BY name");
    let integrations = tx
        .query(&sql, &[])
        .await?
        .iter()
        .map(|r| scan_integration(cipher, r))
        .collect::<Result<Vec<_>, _>>()?;
    let (layout, blocker) = standard_layout(&integrations);
    if mode == "standard" && !blocker.is_empty() {
        return Err(Error::Validation {
            fields: BTreeMap::from([("mode".into(), blocker)]),
            form: String::new(),
        });
    }
    let rows = tx
        .query(
            "SELECT mode, revision, updated_at FROM request_routing WHERE id",
            &[],
        )
        .await?;
    if mode == "advanced"
        && rows
            .first()
            .is_some_and(|r| r.get::<_, String>(0) == "standard")
    {
        seed_advanced_from_standard(&mut tx, &layout, &integrations).await?;
    }
    tx.query(SET_ROUTING_MODE_SQL, &[&mode]).await?;
    tx.commit().await?;
    drop(session);
    get_routing_overview(pool, cipher).await
}

async fn seed_advanced_from_standard(
    tx: &mut Tx<'_>,
    layout: &[StandardDestination],
    integrations: &[Integration],
) -> Result<(), Error> {
    let mut marked = Vec::new();
    let mut unmarked = Vec::new();
    for server in integrations {
        if self_routed(server) {
            continue;
        }
        if is_4k_server(&server.plugin_config) {
            marked.push(server.id.clone());
        } else {
            unmarked.push(server.id.clone());
        }
    }
    tx.execute(CLEAR_CHANGED_TIERS_SQL, &[&marked, &unmarked])
        .await?;
    let usable = |id: &str, media_type: &str, four_k: bool| -> Option<String> {
        integrations
            .iter()
            .find(|s| s.id == id)
            .filter(|s| {
                !self_routed(s)
                    && s.enabled
                    && server_serves(s, media_type)
                    && is_4k_server(&s.plugin_config) == four_k
            })
            .map(|s| s.id.clone())
    };
    for dest in layout {
        let hd = usable(&dest.hd_integration_id, &dest.media_type, false);
        let uhd = usable(&dest.uhd_integration_id, &dest.media_type, true);
        if hd.is_none() && uhd.is_none() {
            continue;
        }
        tx.execute(
            SEED_STANDARD_FALLBACK_SQL,
            &[
                &fallback_id(&dest.media_type),
                &dest.media_type,
                &"Everything else",
                &hd,
                &uhd,
            ],
        )
        .await?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct EffectivePolicy {
    pub requests_enabled: bool,
    pub blocked: bool,
    pub unlimited: bool,
    pub used: i64,
    pub max_requests: i64,
    pub window_days: i64,
    pub window_start: SystemTime,
    pub remaining: i64,
    pub auto_approve: bool,
}

/// `resolvePolicy`, with the account already loaded by the admin account check.
pub async fn effective_policy(
    pool: &Pool,
    user_id: i64,
    role: &str,
    requests_allowed: Option<bool>,
    access_group_id: Option<i64>,
) -> Result<EffectivePolicy, Error> {
    let settings = get_settings(pool).await?;
    let id = request_int4(user_id)?;
    let rows = pool.query(USER_LIMIT_GET_SQL, &[&id]).await?;
    let limit = rows.first().map(scan_user_limit).unwrap_or_default();
    let mut base_allowed = true;
    let mut group = None;
    if role != "admin"
        && let Some(group_id) = access_group_id
    {
        let rows = pool.query(REQUEST_GROUP_POLICY_SQL, &[&user_id]).await?;
        if let Some(row) = rows.first() {
            base_allowed = row.get(13);
        }
        let rows = pool.query(GROUP_LIMIT_GET_SQL, &[&group_id]).await?;
        group = rows.first().map(scan_group_limit);
    }
    let mut policy = EffectivePolicy {
        requests_enabled: settings.requests_enabled,
        blocked: !requests_allowed.unwrap_or(base_allowed),
        unlimited: false,
        used: 0,
        max_requests: settings.global_max_requests,
        window_days: if settings.global_window_days > 0 {
            settings.global_window_days
        } else {
            7
        },
        window_start: SystemTime::UNIX_EPOCH,
        remaining: 0,
        auto_approve: settings.global_auto_approval_enabled,
    };
    let mut limit_mode = "inherit";
    let mut max_requests = None;
    let mut window_days = None;
    let mut approval = "inherit";
    let group_layer = group.as_ref().map(|g| {
        (
            g.limit_mode.as_str(),
            g.max_requests,
            g.window_days,
            g.approval_mode.as_str(),
        )
    });
    for (mode, max, days, approve) in group_layer.into_iter().chain(std::iter::once((
        limit.limit_mode.as_str(),
        limit.max_requests,
        limit.window_days,
        limit.approval_mode.as_str(),
    ))) {
        if !mode.is_empty() && mode != "inherit" {
            limit_mode = mode;
            max_requests = max;
            window_days = days;
        }
        if !approve.is_empty() && approve != "inherit" {
            approval = approve;
        }
    }
    match limit_mode {
        "blocked" => policy.blocked = true,
        "unlimited" => policy.unlimited = true,
        "custom" => {
            if let Some(max) = max_requests {
                policy.max_requests = max;
            }
            if let Some(days) = window_days.filter(|d| *d > 0) {
                policy.window_days = days;
            }
        }
        _ => {}
    }
    match approval {
        "blocked" => policy.blocked = true,
        "manual" => policy.auto_approve = false,
        "auto" => policy.auto_approve = true,
        _ => {}
    }
    // Go's service clock is UTC, so AddDate's days are exactly 24 hours.
    policy.window_start =
        SystemTime::now() - std::time::Duration::from_secs(policy.window_days as u64 * 86400);
    if !policy.unlimited {
        let user_id = request_int4(user_id)?;
        let rows = pool
            .query(COUNT_USER_REQUESTS_SQL, &[&user_id, &policy.window_start])
            .await?;
        policy.used = rows[0].get(0);
        policy.remaining = (policy.max_requests - policy.used).max(0);
    }
    Ok(policy)
}

const SET_ROUTING_MODE_SQL: &str = r#"
		INSERT INTO request_routing (id, mode, updated_at) VALUES (true, $1, now())
		ON CONFLICT (id) DO UPDATE SET mode = EXCLUDED.mode, updated_at = now()
		RETURNING mode, revision, updated_at"#;

const CLEAR_CHANGED_TIERS_SQL: &str = r#"
		UPDATE request_routes SET
			hd_integration_id = CASE WHEN hd_integration_id = ANY($1) THEN NULL ELSE hd_integration_id END,
			hd_overrides = CASE WHEN hd_integration_id = ANY($1) THEN '{}'::jsonb ELSE hd_overrides END,
			uhd_integration_id = CASE WHEN uhd_integration_id = ANY($2) THEN NULL ELSE uhd_integration_id END,
			uhd_overrides = CASE WHEN uhd_integration_id = ANY($2) THEN '{}'::jsonb ELSE uhd_overrides END
		WHERE hd_integration_id = ANY($1) OR uhd_integration_id = ANY($2)"#;

const SEED_STANDARD_FALLBACK_SQL: &str = r#"
			INSERT INTO request_routes (id, media_type, position, name, is_fallback, hd_integration_id, uhd_integration_id)
			VALUES ($1, $2, 1000, $3, true, $4, $5)
			ON CONFLICT (id) DO UPDATE SET
				hd_integration_id = coalesce(request_routes.hd_integration_id, EXCLUDED.hd_integration_id),
				uhd_integration_id = coalesce(request_routes.uhd_integration_id, EXCLUDED.uhd_integration_id)
			WHERE request_routes.hd_integration_id IS NULL
			   OR (request_routes.uhd_integration_id IS NULL AND EXCLUDED.uhd_integration_id IS NOT NULL AND NOT request_routes.skip_uhd)"#;

const REQUEST_GROUP_POLICY_SQL: &str = r#"
		SELECT g.id, g.library_ids, g.max_playback_quality, g.download_allowed,
			g.download_transcode_allowed, g.transcode_allowed, g.audio_transcode_allowed,
			g.max_streams, g.max_transcodes, g.max_remote_stream_bitrate_kbps, g.max_local_stream_bitrate_kbps,
			g.max_profiles, g.allowed_permissions, g.requests_allowed
		FROM users u
		JOIN access_groups g ON g.id = u.access_group_id
		WHERE u.id = $1"#;

const COUNT_USER_REQUESTS_SQL: &str = r#"
		SELECT COUNT(*)
		FROM media_requests
		WHERE requested_by_user_id = $1
		  AND created_at >= $2
		  AND (outcome = 'active' OR (outcome = 'cancelled' AND last_error = ''))"#;

// Discover layout reads and resets: internal/requests/discover_layout.go.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscoverChart {
    pub preset: String,
    pub media_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub time_window: String,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscoverFilter {
    pub media_type: String,
    pub sort_by: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub genre_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_genre_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keyword_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub company_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_ids: Vec<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub original_language: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub origin_countries: Vec<String>,
    #[serde(skip_serializing_if = "discover_is_zero")]
    pub year_from: i64,
    #[serde(skip_serializing_if = "discover_is_zero")]
    pub year_to: i64,
    #[serde(skip_serializing_if = "discover_is_zero")]
    pub vote_average_gte: f64,
    #[serde(skip_serializing_if = "discover_is_zero")]
    pub vote_count_gte: i64,
    #[serde(skip_serializing_if = "discover_is_zero")]
    pub runtime_gte: i64,
    #[serde(skip_serializing_if = "discover_is_zero")]
    pub runtime_lte: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub certification_lte: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub watch_provider_ids: Vec<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub watch_region: String,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscoverList {
    pub url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub order: String,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscoverRow {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "discover_is_zero")]
    pub limit: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub hide_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chart: Option<DiscoverChart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discover: Option<DiscoverFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<DiscoverList>,
}

fn discover_is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

pub struct DiscoverLayout {
    pub rows: Vec<DiscoverRow>,
    pub customized: bool,
    pub revision: i64,
    pub updated_at: Option<SystemTime>,
    pub sources: HashMap<String, DiscoverSource>,
}

pub struct DiscoverSource {
    pub state: &'static str,
    pub entries: i32,
    pub refreshed_at: Option<SystemTime>,
    pub error: String,
}

fn default_discover_rows() -> Vec<DiscoverRow> {
    let mut rows = Vec::new();
    for (id, title, preset, media_type, window) in [
        (
            "trending_movies",
            "Trending Movies",
            "trending",
            "movie",
            "week",
        ),
        (
            "trending_series",
            "Trending Series",
            "trending",
            "series",
            "week",
        ),
        ("popular_movies", "Popular Movies", "popular", "movie", ""),
        ("popular_series", "Popular Series", "popular", "series", ""),
        (
            "upcoming_movies",
            "Upcoming Movies",
            "upcoming",
            "movie",
            "",
        ),
        ("on_air_series", "On Air Series", "on_the_air", "series", ""),
    ] {
        rows.push(DiscoverRow {
            id: id.into(),
            kind: "tmdb_chart".into(),
            title: title.into(),
            enabled: true,
            limit: 20,
            chart: Some(DiscoverChart {
                preset: preset.into(),
                media_type: media_type.into(),
                time_window: window.into(),
            }),
            ..Default::default()
        });
    }
    for (id, title) in [
        ("studios", "Studios"),
        ("networks", "Networks"),
        ("genres", "Genres"),
    ] {
        rows.push(DiscoverRow {
            id: id.into(),
            kind: id.into(),
            title: title.into(),
            enabled: true,
            ..Default::default()
        });
    }
    rows
}

// `discoverrows.SourceKey`, including the collection URL allowlists. No URL is fetched here.
fn discover_source_key(row: &DiscoverRow) -> Option<String> {
    let list = row.list.as_ref()?;
    let raw = trim_space(&list.url);
    if row.kind == "tmdb_list" {
        let parse_id = |s: &str| {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse::<i64>().ok().filter(|id| *id > 0)
        };
        if let Some(id) = parse_id(raw) {
            return Some(format!("tmdb_list:{id}"));
        }
        let raw = if raw.contains("://") {
            raw.to_owned()
        } else {
            format!("https://{raw}")
        };
        let u = silo_gocompat::url::parse(&raw).ok()?;
        let host = silo_gocompat::strings::to_lower(u.host.split(':').next()?);
        if !matches!(u.scheme.as_str(), "http" | "https")
            || !matches!(
                host.strip_suffix('.').unwrap_or(&host),
                "themoviedb.org" | "www.themoviedb.org"
            )
        {
            return None;
        }
        let parts: Vec<_> = u.path.trim_matches('/').split('/').collect();
        if parts.len() != 2 || parts[0] != "list" {
            return None;
        }
        let id = parse_id(parts[1].split('-').next()?)?;
        return Some(format!("tmdb_list:{id}"));
    }
    if row.kind != "mdblist" || raw.is_empty() {
        return None;
    }
    let mut feed = raw.trim_end_matches('/').to_owned();
    while feed.ends_with("/json/json") {
        feed.truncate(feed.len() - 5);
    }
    if !feed.ends_with("/json") {
        feed.push_str("/json");
    }
    let u = silo_gocompat::url::parse(&feed).ok()?;
    let mut host_port = u.host.split(':');
    let host = silo_gocompat::strings::to_lower(host_port.next()?);
    let port = host_port.next().unwrap_or("");
    if !matches!(u.scheme.as_str(), "http" | "https")
        || u.user.is_some()
        || !matches!(
            host.strip_suffix('.').unwrap_or(&host),
            "mdblist.com" | "www.mdblist.com"
        )
        || !matches!(port, "" | "80" | "443")
        || !u.escaped_path().starts_with("/lists/")
    {
        return None;
    }
    Some(if list.order.is_empty() {
        format!("mdblist:{feed}")
    } else {
        format!("mdblist:{feed}?order={}", list.order)
    })
}

pub async fn get_discover_layout(pool: &Pool) -> Result<DiscoverLayout, Error> {
    let rows = pool
        .query(
            "SELECT rows, revision, updated_at FROM request_discover_layout WHERE id",
            &[],
        )
        .await?;
    let mut out = match rows.first() {
        Some(row) => DiscoverLayout {
            rows: unmarshal::<Option<Vec<DiscoverRow>>>(
                row.get::<_, silo_pg::TextValue>(0).0.as_bytes(),
            )
            .map_err(|e| Error::Internal(e.to_string()))?
            .unwrap_or_default(),
            customized: true,
            revision: row.get(1),
            updated_at: Some(row.get(2)),
            sources: HashMap::new(),
        },
        None => DiscoverLayout {
            rows: default_discover_rows(),
            customized: false,
            revision: 0,
            updated_at: None,
            sources: HashMap::new(),
        },
    };
    let keys: HashMap<String, String> = out
        .rows
        .iter()
        .filter_map(|row| discover_source_key(row).map(|key| (row.id.clone(), key)))
        .collect();
    if keys.is_empty() {
        return Ok(out);
    }
    let source_keys: Vec<String> = keys.values().cloned().collect();
    let statuses = pool.query("\n\t\tSELECT source_key, entry_count, refreshed_at, last_status, last_error\n\t\tFROM request_discover_list_snapshots WHERE source_key = ANY($1)", &[&source_keys]).await?;
    for (id, key) in keys {
        let mut status = DiscoverSource {
            state: "pending",
            entries: 0,
            refreshed_at: None,
            error: String::new(),
        };
        if let Some(row) = statuses.iter().find(|r| r.get::<_, String>(0) == key) {
            status.entries = row.get(1);
            status.refreshed_at = row.get(2);
            let last: String = row.get(3);
            if last == "error" {
                status.state = "error";
                status.error = row.get(4);
            } else if last == "empty" {
                status.state = "empty";
            } else if status.refreshed_at.is_some() {
                status.state = "ready";
            }
        }
        out.sources.insert(id, status);
    }
    Ok(out)
}

pub async fn reset_discover_layout(pool: &Pool, expected: i64) -> Result<(), Error> {
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .await?;
    let rows = tx
        .query(
            "SELECT revision FROM request_discover_layout WHERE id FOR UPDATE",
            &[],
        )
        .await?;
    match rows.first() {
        Some(row) if expected != -1 && expected != row.get::<_, i64>(0) => {
            return Err(Error::StaleRevision);
        }
        None if expected != 0 && expected != -1 => return Err(Error::StaleRevision),
        _ => {}
    }
    let affected = tx
        .execute(
            "DELETE FROM request_discover_layout WHERE id AND ($1::bigint = -1 OR revision = $1)",
            &[&expected],
        )
        .await?;
    if affected == 0 && expected != -1 {
        let rows = tx
            .query("SELECT EXISTS (SELECT 1 FROM request_discover_layout)", &[])
            .await?;
        if rows[0].get::<_, bool>(0) {
            return Err(Error::StaleRevision);
        }
    }
    tx.commit().await?;
    Ok(())
}
