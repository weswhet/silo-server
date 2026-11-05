//! Autoscan repository queries and persisted admin writes from `internal/autoscan`.
//! All six inspection rows use persisted state; none require the plugin host or scheduler.
use serde::{Deserialize, Serialize};
use silo_core::secret::{Cipher, aad::row as row_aad};
use silo_gocompat::{
    json::unmarshal,
    strings::{to_lower, trim_space},
};
use silo_pg::{Pool, Row, TextValue, ToSql};
use std::{
    collections::{BTreeMap, HashMap},
    time::SystemTime,
};
use uuid::Uuid;

pub type Error = String;
#[derive(Clone, Debug)]
pub struct Settings {
    pub enabled: bool,
    pub default_poll_interval_seconds: i32,
    pub debounce_seconds: i32,
}
#[derive(Clone, Debug)]
pub struct Connection {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub api_key_ref: String,
    pub request_integration_id: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PathRewrite {
    pub from: String,
    pub to: String,
}
#[derive(Clone, Debug)]
pub struct Source {
    pub id: String,
    pub plugin_id: String,
    pub capability_id: String,
    pub connection_id: Option<String>,
    pub enabled: bool,
    pub delivery_mode: String,
    pub poll_interval_seconds: Option<i32>,
    pub path_rewrites: Vec<PathRewrite>,
    pub source_config: BTreeMap<String, String>,
    pub label: String,
    pub marker: Option<String>,
    pub last_run_at: Option<SystemTime>,
    pub last_error: Option<String>,
}
#[derive(Clone, Debug)]
pub struct WebhookEndpoint {
    pub source_id: String,
    pub secret_suffix: String,
    pub created_at: SystemTime,
    pub rotated_at: Option<SystemTime>,
    pub last_received_at: Option<SystemTime>,
    pub last_error_at: Option<SystemTime>,
    pub last_error_message: String,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ChangeRecord {
    pub source_path: String,
    pub rewritten_path: String,
    pub scope: String,
    pub outcome: String,
    pub reason: String,
    pub detail: String,
    pub library_id: i64,
    pub target_mode: String,
    pub target_path: String,
    pub scan_run_id: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanResult {
    pub new: i64,
    pub updated: i64,
    pub unchanged: i64,
    pub missing: i64,
    pub missing_skipped_protected: i64,
    pub files_deleted: i64,
    pub items_deleted: i64,
    pub memberships_removed: i64,
    pub errors: i64,
    pub skipped: i64,
    #[serde(skip_serializing)]
    pub matched_files: i64,
    #[serde(skip_serializing)]
    pub retried_items: i64,
    #[serde(skip_serializing)]
    pub still_unmatched_warnings: i64,
    #[serde(skip_serializing)]
    pub phase: String,
    #[serde(skip_serializing)]
    pub message: String,
    #[serde(skip_serializing)]
    pub current_scope: String,
    #[serde(skip_serializing)]
    pub total_files: i64,
    #[serde(skip_serializing)]
    pub files_discovered: i64,
    #[serde(skip_serializing)]
    pub files_processed: i64,
}
#[derive(Clone, Debug)]
pub struct Event {
    pub id: i64,
    pub source_id: Option<String>,
    pub plugin_id: String,
    pub capability_id: String,
    pub started_at: SystemTime,
    pub completed_at: SystemTime,
    pub duration_ms: i64,
    pub status: String,
    pub delivery_mode: String,
    pub provider_event_type: String,
    pub changes_returned: i32,
    pub changes_resolved: i32,
    pub targets_claimed: i32,
    pub scans_created: i32,
    pub scans_reused: i32,
    pub scans_suppressed: i32,
    pub error_message: String,
    pub marker_before: Option<String>,
    pub marker_after: Option<String>,
    pub changes: Vec<ChangeRecord>,
    pub changes_truncated: bool,
}
#[derive(Clone, Debug)]
pub struct ScanRunSummary {
    pub id: String,
    pub media_folder_id: i32,
    pub mode: String,
    pub path: String,
    pub trigger: String,
    pub status: String,
    pub error_message: String,
    pub requested_at: Option<SystemTime>,
    pub started_at: Option<SystemTime>,
    pub completed_at: Option<SystemTime>,
    pub result: Option<ScanResult>,
}
#[derive(Clone, Debug)]
pub struct EventWithRuns {
    pub event: Event,
    pub runs: Vec<ScanRunSummary>,
}
#[derive(Clone, Debug)]
pub struct ScanWithEvent {
    pub run: ScanRunSummary,
    pub autoscan_event_id: Option<i64>,
    pub source_id: Option<String>,
    pub plugin_id: String,
    pub capability_id: String,
    pub event_status: String,
    pub event_completed_at: Option<SystemTime>,
}
#[derive(Clone, Debug, Default)]
pub struct EventListFilter {
    pub source_id: String,
    pub status: String,
    pub search: String,
    pub limit: i64,
    pub offset: i64,
}
#[derive(Clone, Debug, Default)]
pub struct ScanListFilter {
    pub status: String,
    pub search: String,
    pub limit: i64,
    pub offset: i64,
}
#[derive(Clone, Debug)]
pub struct QueueSummary {
    pub active: i32,
    pub accepted: i32,
    pub running: i32,
}

const CONNECTION_COLUMNS: &str = r#"id, name, kind, base_url, api_key_ref, request_integration_id"#;
const SOURCE_COLUMNS: &str = r#"id, plugin_id, capability_id, connection_id, enabled, delivery_mode,
	poll_interval_seconds, path_rewrites, source_config, label, marker, last_run_at, last_error"#;
const EVENT_COLUMNS: &str = r#"id, source_id, plugin_id, capability_id, started_at, completed_at,
	duration_ms, status, delivery_mode, provider_event_type, changes_returned, changes_resolved,
	targets_claimed, scans_created, scans_reused, scans_suppressed, error_message, marker_before, marker_after,
	change_log, change_log_truncated"#;
const WEBHOOK_COLUMNS: &str = r#"source_id, secret_suffix, created_at, rotated_at,
	last_received_at, last_error_at, last_error_message"#;

fn uuid_string(row: &Row, index: usize) -> String {
    row.get::<_, Uuid>(index).to_string()
}
fn optional_uuid(row: &Row, index: usize) -> Option<String> {
    row.get::<_, Option<Uuid>>(index).map(|id| id.to_string())
}
fn json_column(row: &Row, index: usize) -> String {
    row.get::<_, Option<TextValue>>(index)
        .map(|v| v.0)
        .unwrap_or_default()
}
fn decode_scan_result(status: &str, raw: &str) -> Option<ScanResult> {
    if status != "completed" || matches!(trim_space(raw), "" | "{}" | "null") {
        return None;
    }
    unmarshal(raw.as_bytes()).ok()
}
fn scan_source(row: &Row) -> Result<Source, Error> {
    let rewrites = json_column(row, 7);
    let config = json_column(row, 8);
    Ok(Source {
        id: uuid_string(row, 0),
        plugin_id: row.get(1),
        capability_id: row.get(2),
        connection_id: optional_uuid(row, 3),
        enabled: row.get(4),
        delivery_mode: row.get(5),
        poll_interval_seconds: row.get(6),
        path_rewrites: if rewrites.is_empty() {
            Vec::new()
        } else {
            unmarshal::<Option<Vec<PathRewrite>>>(rewrites.as_bytes())
                .map_err(|e| e.to_string())?
                .unwrap_or_default()
        },
        source_config: if config.is_empty() {
            BTreeMap::new()
        } else {
            unmarshal::<Option<BTreeMap<String, String>>>(config.as_bytes())
                .map_err(|e| e.to_string())?
                .unwrap_or_default()
        },
        label: row.get(9),
        marker: row.get(10),
        last_run_at: row.get(11),
        last_error: row.get(12),
    })
}
fn scan_event(row: &Row) -> Event {
    let changes = unmarshal::<Option<Vec<ChangeRecord>>>(json_column(row, 19).as_bytes())
        .ok()
        .flatten()
        .unwrap_or_default();
    Event {
        id: row.get(0),
        source_id: optional_uuid(row, 1),
        plugin_id: row.get(2),
        capability_id: row.get(3),
        started_at: row.get(4),
        completed_at: row.get(5),
        duration_ms: row.get(6),
        status: row.get(7),
        delivery_mode: row.get(8),
        provider_event_type: row.get(9),
        changes_returned: row.get(10),
        changes_resolved: row.get(11),
        targets_claimed: row.get(12),
        scans_created: row.get(13),
        scans_reused: row.get(14),
        scans_suppressed: row.get(15),
        error_message: row.get(16),
        marker_before: row.get(17),
        marker_after: row.get(18),
        changes,
        changes_truncated: row.get(20),
    }
}
fn scan_run(row: &Row, start: usize, result_index: usize) -> ScanRunSummary {
    let status: String = row.get(start + 5);
    let result = decode_scan_result(&status, &json_column(row, result_index));
    ScanRunSummary {
        id: row.get(start),
        media_folder_id: row.get(start + 1),
        mode: row.get(start + 2),
        path: row.get(start + 3),
        trigger: row.get(start + 4),
        status,
        error_message: row.get(start + 6),
        requested_at: row.get(start + 7),
        started_at: row.get(start + 8),
        completed_at: row.get(start + 9),
        result,
    }
}
pub async fn get_settings(pool: &Pool) -> Result<Settings, Error> {
    let rows = pool.query("\n\t\tSELECT enabled, default_poll_interval_seconds, debounce_seconds\n\t\tFROM autoscan_settings WHERE id = true", &[]).await.map_err(|e|e.to_string())?;
    Ok(rows
        .first()
        .map(|r| Settings {
            enabled: r.get(0),
            default_poll_interval_seconds: r.get(1),
            debounce_seconds: r.get(2),
        })
        .unwrap_or(Settings {
            enabled: false,
            default_poll_interval_seconds: 600,
            debounce_seconds: 60,
        }))
}
pub async fn list_sources(pool: &Pool) -> Result<Vec<Source>, Error> {
    pool.query(
        &format!(
            "SELECT {SOURCE_COLUMNS}\n\t\tFROM autoscan_sources ORDER BY plugin_id, capability_id"
        ),
        &[],
    )
    .await
    .map_err(|e| e.to_string())?
    .iter()
    .map(scan_source)
    .collect()
}
pub async fn list_connections(pool: &Pool, cipher: &Cipher) -> Result<Vec<Connection>, Error> {
    let rows = pool
        .query(
            &format!("SELECT {CONNECTION_COLUMNS}\n\t\tFROM autoscan_connections ORDER BY name"),
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    rows.iter()
        .map(|r| {
            let id = uuid_string(r, 0);
            let encrypted = r.get::<_, Option<String>>(4).unwrap_or_default();
            let plain = cipher
                .decrypt_if_encrypted(
                    &encrypted,
                    row_aad("autoscan_connections", "api_key_ref", &id),
                )
                .map_err(|e| e.to_string())?;
            Ok(Connection {
                id,
                name: r.get(1),
                kind: r.get(2),
                base_url: r.get::<_, Option<String>>(3).unwrap_or_default(),
                api_key_ref: String::from_utf8_lossy(&plain).into_owned(),
                request_integration_id: r.get(5),
            })
        })
        .collect()
}
pub async fn list_webhook_endpoints(pool: &Pool) -> Result<Vec<WebhookEndpoint>, Error> {
    let rows = pool
        .query(
            &format!("SELECT {WEBHOOK_COLUMNS}\n\t\tFROM autoscan_webhook_endpoints"),
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows
        .iter()
        .map(|r| WebhookEndpoint {
            source_id: uuid_string(r, 0),
            secret_suffix: r.get(1),
            created_at: r.get(2),
            rotated_at: r.get(3),
            last_received_at: r.get(4),
            last_error_at: r.get(5),
            last_error_message: r.get(6),
        })
        .collect())
}
pub async fn reveal_webhook_token(
    pool: &Pool,
    cipher: &Cipher,
    source_id: &str,
) -> Result<String, Error> {
    let id = Uuid::parse_str(source_id).map_err(|e| e.to_string())?;
    let row = query_one(
        pool,
        "SELECT secret_ref\n\t\tFROM autoscan_webhook_endpoints WHERE source_id = $1",
        &[&id],
    )
    .await
    .map_err(|e| e.to_string())?;
    let encrypted: String = row.get(0);
    let plain = cipher
        .decrypt(
            &encrypted,
            row_aad("autoscan_webhook_endpoints", "secret_ref", source_id),
        )
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}
pub async fn list_running_events(pool: &Pool) -> Result<Vec<Event>, Error> {
    Ok(pool.query(&format!("\n\t\tSELECT {EVENT_COLUMNS}\n\t\tFROM autoscan_events\n\t\tWHERE status = $1\n\t\tORDER BY started_at ASC, id ASC"),&[&"running"]).await.map_err(|e|e.to_string())?.iter().map(scan_event).collect())
}
pub async fn get_queue_summary(pool: &Pool) -> Result<QueueSummary, Error> {
    let row = query_one(pool, "\n\t\tSELECT\n\t\t\tCOUNT(*) FILTER (WHERE status = ANY($1))::int,\n\t\t\tCOUNT(*) FILTER (WHERE status = $2)::int,\n\t\t\tCOUNT(*) FILTER (WHERE status = $3)::int\n\t\tFROM scan_runs\n\t\tWHERE trigger = $4",&[&vec!["accepted","running"],&"accepted",&"running",&"autoscan"]).await.map_err(|e|e.to_string())?;
    Ok(QueueSummary {
        active: row.get(0),
        accepted: row.get(1),
        running: row.get(2),
    })
}
pub async fn latest_event_at(pool: &Pool) -> Result<Option<SystemTime>, Error> {
    Ok(query_one(
        pool,
        "SELECT max(completed_at) FROM autoscan_events WHERE status <> $1",
        &[&"running"],
    )
    .await
    .map_err(|e| e.to_string())?
    .get(0))
}

type Args = Vec<Box<dyn ToSql + Sync + Send>>;
fn params(args: &Args) -> Vec<&(dyn ToSql + Sync)> {
    args.iter()
        .map(|v| v.as_ref() as &(dyn ToSql + Sync))
        .collect()
}
fn event_filter(filter: &EventListFilter) -> Result<(String, Args), Error> {
    let mut clauses = vec!["true".to_owned()];
    let mut args: Args = Vec::new();
    if !trim_space(&filter.source_id).is_empty() {
        args.push(Box::new(
            Uuid::parse_str(trim_space(&filter.source_id)).map_err(|e| e.to_string())?,
        ));
        clauses.push(format!("source_id = ${}", args.len()));
    }
    if !filter.status.is_empty() {
        args.push(Box::new(filter.status.clone()));
        clauses.push(format!("status = ${}", args.len()));
    }
    let search = to_lower(trim_space(&filter.search));
    if !search.is_empty() {
        args.push(Box::new(format!("%{search}%")));
        let param = format!("${}", args.len());
        clauses.push(format!(
            r#"(
			lower(capability_id) LIKE {param}
			OR lower(status) LIKE {param}
			OR lower(error_message) LIKE {param}
			OR lower(COALESCE(source_id::text, '')) LIKE {param}
			OR EXISTS (
				SELECT 1
				FROM jsonb_array_elements(change_log) AS cl(change)
				WHERE lower(COALESCE(cl.change->>'source_path', '')) LIKE {param}
				   OR lower(COALESCE(cl.change->>'rewritten_path', '')) LIKE {param}
			)
			OR EXISTS (
				SELECT 1
				FROM scan_runs sr
				WHERE sr.autoscan_event_id = autoscan_events.id
				  AND (
					lower(sr.id) LIKE {param}
					OR lower(sr.mode) LIKE {param}
					OR lower(sr.path) LIKE {param}
					OR lower(sr.status) LIKE {param}
					OR lower(COALESCE(sr.error_message, '')) LIKE {param}
				  )
			)
		)"#
        ));
    }
    Ok((clauses.join(" AND "), args))
}
fn scan_filter(filter: &ScanListFilter) -> Result<(String, Args), Error> {
    let mut clauses = vec!["sr.trigger = 'autoscan'".to_owned()];
    let mut args: Args = Vec::new();
    if !trim_space(&filter.status).is_empty() {
        args.push(Box::new(trim_space(&filter.status).to_owned()));
        clauses.push(format!("sr.status = ${}", args.len()));
    }
    let search = to_lower(trim_space(&filter.search));
    if !search.is_empty() {
        args.push(Box::new(format!("%{search}%")));
        let param = format!("${}", args.len());
        clauses.push(format!(
            r#"(
			lower(sr.id) LIKE {param}
			OR lower(sr.mode) LIKE {param}
			OR lower(sr.path) LIKE {param}
			OR lower(sr.status) LIKE {param}
			OR lower(COALESCE(sr.error_message, '')) LIKE {param}
			OR lower(COALESCE(e.capability_id, '')) LIKE {param}
			OR lower(COALESCE(e.status, '')) LIKE {param}
			OR lower(COALESCE(e.source_id::text, '')) LIKE {param}
		)"#
        ));
    }
    Ok((clauses.join(" AND "), args))
}

pub async fn count_events(pool: &Pool, filter: &EventListFilter) -> Result<i64, Error> {
    let (clauses, args) = event_filter(filter)?;
    Ok(query_one(
        pool,
        &format!("\n\t\tSELECT COUNT(*)\n\t\tFROM autoscan_events\n\t\tWHERE {clauses}"),
        &params(&args),
    )
    .await
    .map_err(|e| e.to_string())?
    .get(0))
}
pub async fn count_autoscan_scans(pool: &Pool, filter: &ScanListFilter) -> Result<i64, Error> {
    let (clauses, args) = scan_filter(filter)?;
    Ok(query_one(pool, &format!("\n\t\tSELECT COUNT(*)\n\t\tFROM scan_runs sr\n\t\tLEFT JOIN autoscan_events e ON e.id = sr.autoscan_event_id\n\t\tWHERE {clauses}"),&params(&args)).await.map_err(|e|e.to_string())?.get(0))
}
fn add_page(args: &mut Args, limit: i64, offset: i64) -> (usize, usize) {
    args.push(Box::new(if limit <= 0 { 50 } else { limit.min(200) }));
    let limit_param = args.len();
    args.push(Box::new(offset.max(0)));
    (limit_param, args.len())
}
pub async fn list_events(
    pool: &Pool,
    filter: &EventListFilter,
) -> Result<Vec<EventWithRuns>, Error> {
    let (clauses, mut args) = event_filter(filter)?;
    let (limit, offset) = add_page(&mut args, filter.limit, filter.offset);
    let sql = format!(
        "\n\t\tSELECT {EVENT_COLUMNS}\n\t\tFROM autoscan_events\n\t\tWHERE {clauses}\n\t\tORDER BY completed_at DESC, id DESC\n\t\tLIMIT ${limit} OFFSET ${offset}"
    );
    let rows = pool
        .query(&sql, &params(&args))
        .await
        .map_err(|e| e.to_string())?;
    let mut events: Vec<EventWithRuns> = rows
        .iter()
        .map(|row| EventWithRuns {
            event: scan_event(row),
            runs: Vec::new(),
        })
        .collect();
    if events.is_empty() {
        return Ok(events);
    }
    let ids: Vec<i64> = events.iter().map(|e| e.event.id).collect();
    let index: HashMap<i64, usize> = ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    let rows = pool.query("\n\t\tSELECT autoscan_event_id, id, media_folder_id, mode, path, trigger, status,\n\t\t\tCOALESCE(error_message, ''), requested_at, started_at, completed_at, result_payload\n\t\tFROM scan_runs\n\t\tWHERE autoscan_event_id = ANY($1)\n\t\tORDER BY requested_at ASC",&[&ids]).await.map_err(|e|e.to_string())?;
    for row in &rows {
        if let Some(i) = index.get(&row.get::<_, i64>(0)) {
            events[*i].runs.push(scan_run(row, 1, 11));
        }
    }
    Ok(events)
}
pub async fn list_autoscan_scans(
    pool: &Pool,
    filter: &ScanListFilter,
) -> Result<Vec<ScanWithEvent>, Error> {
    let (clauses, mut args) = scan_filter(filter)?;
    let (limit, offset) = add_page(&mut args, filter.limit, filter.offset);
    let sql = format!(
        r#"
		SELECT
			sr.id,
			sr.media_folder_id,
			sr.mode,
			sr.path,
			sr.trigger,
			sr.status,
			COALESCE(sr.error_message, ''),
				sr.requested_at,
				sr.started_at,
				sr.completed_at,
				sr.autoscan_event_id,
				e.source_id,
				COALESCE(e.plugin_id, ''),
				COALESCE(e.capability_id, ''),
				COALESCE(e.status, ''),
				e.completed_at,
				sr.result_payload
		FROM scan_runs sr
		LEFT JOIN autoscan_events e ON e.id = sr.autoscan_event_id
		WHERE {clauses}
		ORDER BY COALESCE(sr.completed_at, sr.started_at, sr.requested_at) DESC, sr.id DESC
		LIMIT ${limit} OFFSET ${offset}"#
    );
    Ok(pool
        .query(&sql, &params(&args))
        .await
        .map_err(|e| e.to_string())?
        .iter()
        .map(|row| ScanWithEvent {
            run: scan_run(row, 0, 16),
            autoscan_event_id: row.get(10),
            source_id: optional_uuid(row, 11),
            plugin_id: row.get(12),
            capability_id: row.get(13),
            event_status: row.get(14),
            event_completed_at: row.get(15),
        })
        .collect())
}

async fn query_one(pool: &Pool, sql: &str, params: silo_pg::Params<'_>) -> Result<Row, Error> {
    pool.query(sql, params)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| "autoscan row not found".to_owned())
}

/// Repository writes distinguish absent identities from database and cipher failures.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("autoscan: not found")]
    NotFound,
    #[error("{0}")]
    Other(String),
}
impl From<silo_pg::Error> for WriteError {
    fn from(error: silo_pg::Error) -> Self {
        if matches!(error, silo_pg::Error::NoRows) {
            Self::NotFound
        } else {
            Self::Other(error.to_string())
        }
    }
}
fn write_id(id: &str) -> Result<Uuid, WriteError> {
    Uuid::parse_str(id).map_err(|_| WriteError::NotFound)
}
fn nullable(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}
fn scan_connection(row: &Row, cipher: &Cipher) -> Result<Connection, WriteError> {
    let id = uuid_string(row, 0);
    let encrypted = row.get::<_, Option<String>>(4).unwrap_or_default();
    let plain = cipher
        .decrypt_if_encrypted(
            &encrypted,
            row_aad("autoscan_connections", "api_key_ref", &id),
        )
        .map_err(|e| WriteError::Other(e.to_string()))?;
    Ok(Connection {
        id,
        name: row.get(1),
        kind: row.get(2),
        base_url: row.get::<_, Option<String>>(3).unwrap_or_default(),
        api_key_ref: String::from_utf8_lossy(&plain).into_owned(),
        request_integration_id: row.get(5),
    })
}
pub async fn create_connection(
    pool: &Pool,
    cipher: &Cipher,
    c: &Connection,
) -> Result<Connection, WriteError> {
    let id = if trim_space(&c.id).is_empty() {
        Uuid::new_v4().to_string()
    } else {
        trim_space(&c.id).to_owned()
    };
    let key = cipher
        .encrypt(
            trim_space(&c.api_key_ref),
            row_aad("autoscan_connections", "api_key_ref", &id),
        )
        .map_err(|e| WriteError::Other(e.to_string()))?;
    let uuid = Uuid::parse_str(&id).map_err(|e| WriteError::Other(e.to_string()))?;
    let row = write_query_one(
        pool,
        &format!(
            r#"
		INSERT INTO autoscan_connections (id, name, kind, base_url, api_key_ref, request_integration_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING {CONNECTION_COLUMNS}"#
        ),
        &[
            &uuid,
            &c.name,
            &c.kind,
            &nullable(&c.base_url),
            &nullable(&key),
            &c.request_integration_id,
        ],
    )
    .await?;
    scan_connection(&row, cipher)
}
fn comparable_base_url(raw: &str) -> String {
    let value = trim_space(raw);
    let Ok(mut url) = silo_gocompat::url::parse(value) else {
        return value.trim_end_matches('/').to_owned();
    };
    if url.host.is_empty() {
        return value.trim_end_matches('/').to_owned();
    }
    url.scheme = to_lower(&url.scheme);
    url.host = to_lower(&url.host);
    let escaped = url.escaped_path().trim_end_matches('/').to_owned();
    url.path =
        String::from_utf8_lossy(&silo_gocompat::url::path_unescape(&escaped).unwrap_or_default())
            .into_owned();
    url.raw_path = escaped;
    url.string()
}
fn upstream_differs(old_url: Option<&str>, old_link: Option<&str>, c: &Connection) -> bool {
    let old_link = trim_space(old_link.unwrap_or_default());
    let new_link = trim_space(c.request_integration_id.as_deref().unwrap_or_default());
    if !old_link.is_empty() || !new_link.is_empty() {
        return old_link != new_link;
    }
    comparable_base_url(old_url.unwrap_or_default()) != comparable_base_url(&c.base_url)
}
pub async fn update_connection(
    pool: &Pool,
    cipher: &Cipher,
    c: &Connection,
) -> Result<Connection, WriteError> {
    let id = write_id(&c.id)?;
    let key = cipher
        .encrypt(
            trim_space(&c.api_key_ref),
            row_aad("autoscan_connections", "api_key_ref", &c.id),
        )
        .map_err(|e| WriteError::Other(e.to_string()))?;
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    let old = tx
        .query_one(
            r#"
		SELECT base_url, request_integration_id
		FROM autoscan_connections
		WHERE id = $1
		FOR UPDATE"#,
            &[&id],
        )
        .await?;
    let row = tx
        .query_one(
            &format!(
                r#"
		UPDATE autoscan_connections
		SET name = $2, kind = $3, base_url = $4,
		    api_key_ref = CASE WHEN $5 = '' THEN api_key_ref ELSE $5 END,
		    request_integration_id = $6, updated_at = now()
		WHERE id = $1
		RETURNING {CONNECTION_COLUMNS}"#
            ),
            &[
                &id,
                &c.name,
                &c.kind,
                &nullable(&c.base_url),
                &key,
                &c.request_integration_id,
            ],
        )
        .await?;
    let out = scan_connection(&row, cipher)?;
    let old_url: Option<String> = old.get(0);
    let old_link: Option<String> = old.get(1);
    if upstream_differs(old_url.as_deref(), old_link.as_deref(), &out) {
        tx.execute(
            r#"
			UPDATE autoscan_sources
			SET marker = NULL, last_run_at = NULL, updated_at = now()
			WHERE connection_id = $1 AND (marker IS NOT NULL OR last_run_at IS NOT NULL)"#,
            &[&id],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(out)
}
pub async fn delete_connection(pool: &Pool, id: &str) -> Result<(), WriteError> {
    delete_row(pool, "DELETE FROM autoscan_connections WHERE id = $1", id).await
}
pub async fn delete_source(pool: &Pool, id: &str) -> Result<(), WriteError> {
    delete_row(pool, "DELETE FROM autoscan_sources WHERE id = $1", id).await
}
pub async fn delete_webhook_endpoint(pool: &Pool, id: &str) -> Result<(), WriteError> {
    delete_row(
        pool,
        "DELETE FROM autoscan_webhook_endpoints WHERE source_id = $1",
        id,
    )
    .await
}
async fn delete_row(pool: &Pool, sql: &str, id: &str) -> Result<(), WriteError> {
    let id = write_id(id)?;
    if pool.execute(sql, &[&id]).await? == 0 {
        return Err(WriteError::NotFound);
    }
    Ok(())
}
pub async fn get_source(pool: &Pool, id: &str) -> Result<Source, WriteError> {
    let id = write_id(id)?;
    let row = write_query_one(
        pool,
        &format!("SELECT {SOURCE_COLUMNS}\n\t\tFROM autoscan_sources WHERE id = $1"),
        &[&id],
    )
    .await?;
    scan_source(&row).map_err(WriteError::Other)
}
fn scan_webhook_endpoint(row: &Row) -> WebhookEndpoint {
    WebhookEndpoint {
        source_id: uuid_string(row, 0),
        secret_suffix: row.get(1),
        created_at: row.get(2),
        rotated_at: row.get(3),
        last_received_at: row.get(4),
        last_error_at: row.get(5),
        last_error_message: row.get(6),
    }
}
pub async fn get_webhook_endpoint(pool: &Pool, id: &str) -> Result<WebhookEndpoint, WriteError> {
    let id = write_id(id)?;
    let row = write_query_one(
        pool,
        &format!(
            "SELECT {WEBHOOK_COLUMNS}\n\t\tFROM autoscan_webhook_endpoints WHERE source_id = $1"
        ),
        &[&id],
    )
    .await?;
    Ok(scan_webhook_endpoint(&row))
}
fn new_webhook_token() -> Result<(String, String, String), WriteError> {
    let token = silo_core::apikey::mint_token(32)
        .ok_or_else(|| WriteError::Other("generate webhook token: random source failed".into()))?;
    let hash = silo_core::apikey::hash_webhook_token(token.as_bytes());
    let suffix = token[token.len() - silo_core::apikey::WEBHOOK_SECRET_SUFFIX_LEN..].to_owned();
    Ok((token, hash, suffix))
}
pub async fn create_webhook_endpoint(
    pool: &Pool,
    cipher: &Cipher,
    source_id: &str,
) -> Result<(WebhookEndpoint, String), WriteError> {
    let id = write_id(source_id)?;
    let (token, hash, suffix) = new_webhook_token()?;
    let encrypted = cipher
        .encrypt(
            &token,
            row_aad("autoscan_webhook_endpoints", "secret_ref", source_id),
        )
        .map_err(|e| WriteError::Other(e.to_string()))?;
    let result = write_query_one(
        pool,
        &format!(
            r#"
		INSERT INTO autoscan_webhook_endpoints (source_id, secret_hash, secret_ref, secret_suffix)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (source_id) DO NOTHING
		RETURNING {WEBHOOK_COLUMNS}"#
        ),
        &[&id, &hash, &encrypted, &suffix],
    )
    .await;
    match result {
        Ok(row) => Ok((scan_webhook_endpoint(&row), token)),
        Err(silo_pg::Error::NoRows) => {
            Ok((get_webhook_endpoint(pool, source_id).await?, String::new()))
        }
        Err(e) if e.code().is_some_and(|code| code.code() == "23503") => Err(WriteError::NotFound),
        Err(e) => Err(e.into()),
    }
}
pub async fn rotate_webhook_endpoint(
    pool: &Pool,
    cipher: &Cipher,
    source_id: &str,
) -> Result<(WebhookEndpoint, String), WriteError> {
    let id = write_id(source_id)?;
    let (token, hash, suffix) = new_webhook_token()?;
    let encrypted = cipher
        .encrypt(
            &token,
            row_aad("autoscan_webhook_endpoints", "secret_ref", source_id),
        )
        .map_err(|e| WriteError::Other(e.to_string()))?;
    let row = write_query_one(
        pool,
        &format!(
            r#"
		UPDATE autoscan_webhook_endpoints
		SET secret_hash = $2, secret_ref = $3, secret_suffix = $4, rotated_at = now()
		WHERE source_id = $1
		RETURNING {WEBHOOK_COLUMNS}"#
        ),
        &[&id, &hash, &encrypted, &suffix],
    )
    .await?;
    Ok((scan_webhook_endpoint(&row), token))
}

async fn write_query_one(
    pool: &Pool,
    sql: &str,
    params: silo_pg::Params<'_>,
) -> Result<Row, silo_pg::Error> {
    pool.query(sql, params)
        .await?
        .into_iter()
        .next()
        .ok_or(silo_pg::Error::NoRows)
}

#[cfg(test)]
mod write_tests {
    use super::*;

    #[test]
    fn upstream_identity_preserves_markers_only_for_the_same_server() {
        let mut connection = Connection {
            id: String::new(),
            name: String::new(),
            kind: String::new(),
            base_url: "https://EXAMPLE.test/path/".into(),
            api_key_ref: String::new(),
            request_integration_id: None,
        };
        assert!(!upstream_differs(
            Some(" HTTPS://example.test/path "),
            None,
            &connection
        ));
        assert!(upstream_differs(
            Some("https://example.test/path%2F"),
            None,
            &connection
        ));
        assert!(upstream_differs(
            Some("https://example.test/path?server=2"),
            None,
            &connection
        ));
        connection.request_integration_id = Some(" linked ".into());
        assert!(!upstream_differs(
            Some("https://different.test"),
            Some("linked"),
            &connection
        ));
        assert!(upstream_differs(
            Some(&connection.base_url),
            None,
            &connection
        ));
        assert!(upstream_differs(None, Some("other"), &connection));
    }

    #[test]
    fn webhook_tokens_keep_go_bearer_format_and_lookup_hash() {
        let (token, hash, suffix) = new_webhook_token().unwrap();
        assert_eq!(token.len(), 43);
        assert!(
            token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        // A 32-byte raw base64url encoding ends with two zero padding bits.
        assert!("AEIMQUYcgkosw048".contains(token.chars().last().unwrap()));
        assert_eq!(hash, silo_core::hexgo::sha256_hex(&token));
        assert_eq!(suffix, token[37..]);
        assert_ne!(token, new_webhook_token().unwrap().0);
    }
}
