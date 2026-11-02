//! `activitylog/middleware.go`'s filter and `consumer.go`'s batch writer: one row per request, written
//! off the request path, 100 rows or 2 seconds at a time.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use silo_pg::{Pool, ToSql};
use silo_runtime::logstream::{
    Hub, INSERT_TIMEOUT, RETRY_MAX_BACKOFF, RETRY_MIN_BACKOFF, Stream, retryable,
    safe_text as safe, value_rejected,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// `activitylog.LogEntry`.
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub client_ip: String,
    pub user_id: Option<i64>,
    pub impersonator_user_id: Option<i64>,
    pub session_id: String,
    pub request_id: String,
    pub node_id: String,
    pub method: String,
    pub path: String,
    pub path_pattern: String,
    pub status_code: i32,
    pub user_agent: String,
    pub duration_ms: i32,
    /// `Persisted`: the request's audited mutation already stored its row. It still counts as the
    /// account's activity.
    pub persisted: bool,
}

const EXCLUDED: &[&str] = &[
    "/api/v1/health",
    "/api/v1/ready",
    "/api/v1/admin/logs",
    "/api/v2/admin/logs",
];
const STREAMS: &[&str] = &[
    "/api/v1/stream/",
    "/api/v1/playback/transcode/",
    "/api/v2/stream/",
    "/api/v2/playback/transcode/",
];

/// Whether `NewFilteredMiddleware` records this path.
pub fn recorded(path: &str) -> bool {
    let chunk =
        path.contains("/segment/") || path.contains("/master.m3u8") || path.contains("/subtitles/");
    !EXCLUDED.iter().any(|p| path.starts_with(p))
        && !(chunk && STREAMS.iter().any(|p| path.starts_with(p)))
}

/// `activitylog.AuditEntry`, the fields a request row has, in its JSON order.
#[derive(Serialize)]
struct AuditEntry {
    id: i64,
    timestamp: String,
    client_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impersonator_user_id: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    playback_session_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    request_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    node_id: String,
    method: String,
    path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    path_pattern: String,
    status_code: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    user_agent: String,
    duration_ms: i32,
}

/// `activitylog.Writer`. A full queue drops the entry rather than block the request, as Go's does.
#[derive(Clone)]
pub struct ActivityWriter {
    tx: mpsc::Sender<LogEntry>,
}

impl ActivityWriter {
    pub fn start(pool: Arc<Pool>, hub: Arc<Hub>) -> Self {
        let (tx, rx) = mpsc::channel(4096);
        tokio::spawn(run(pool, hub, rx));
        Self { tx }
    }

    pub fn write(&self, entry: LogEntry) {
        let _ = self.tx.try_send(entry);
    }
}

async fn run(pool: Arc<Pool>, hub: Arc<Hub>, mut rx: mpsc::Receiver<LogEntry>) {
    let mut batch = Vec::with_capacity(100);
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            entry = rx.recv() => {
                let Some(entry) = entry else { break };
                batch.push(entry);
                if batch.len() >= 100 {
                    persist(&pool, &hub, &batch, false).await;
                    batch.clear();
                }
            }
            _ = tick.tick() => {
                persist(&pool, &hub, &batch, false).await;
                batch.clear();
            }
        }
    }
    persist(&pool, &hub, &batch, true).await;
}

/// `Drain.persist`: retries transient failures with backoff, while new entries wait in the channel, and
/// inserts the rows one at a time when the server rejects a value. Anything else drops the batch.
fn persist<'a>(
    pool: &'a Pool,
    hub: &'a Hub,
    batch: &'a [LogEntry],
    stopping: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        if batch.is_empty() {
            return;
        }
        let mut backoff = RETRY_MIN_BACKOFF;
        let mut attempt = 1;
        loop {
            let err = match timeout(INSERT_TIMEOUT, insert_batch(pool, hub, batch)).await {
                Ok(Ok(())) => return,
                Ok(Err(e)) => {
                    if batch.len() > 1 && value_rejected(&e) {
                        for row in batch.chunks(1) {
                            persist(pool, hub, row, stopping).await;
                        }
                        return;
                    }
                    if stopping || !retryable(&e) {
                        tracing::error!(component = "activitylog", entries = batch.len(), attempt, error = %e, "activity log batch insert failed; entries dropped");
                        return;
                    }
                    e.to_string()
                }
                Err(_) => {
                    if stopping {
                        tracing::error!(
                            component = "activitylog",
                            entries = batch.len(),
                            attempt,
                            error = "context deadline exceeded",
                            "activity log batch insert failed; entries dropped"
                        );
                        return;
                    }
                    "context deadline exceeded".to_owned()
                }
            };
            tracing::warn!(component = "activitylog", entries = batch.len(), attempt, retry_in = ?backoff, error = %err, "activity log batch insert failed; retrying");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RETRY_MAX_BACKOFF);
            attempt += 1;
        }
    })
}

/// `insertBatch`. The rows are stored once the first step succeeds, so a failure in the second only leaves
/// last activity stale until the account's next batch, and must not retry the insert.
async fn insert_batch(pool: &Pool, hub: &Hub, batch: &[LogEntry]) -> Result<(), silo_pg::Error> {
    insert_stored(pool, hub, batch).await?;
    if let Err(e) = record_last_activity(pool, batch).await {
        tracing::warn!(component = "activitylog", error = %e, "failed to record last activity");
    }
    Ok(())
}

/// The part of `insertBatch` that leaves out the rows a domain mutation already stored.
async fn insert_stored(pool: &Pool, hub: &Hub, batch: &[LogEntry]) -> Result<(), silo_pg::Error> {
    let stored: Vec<&LogEntry> = batch.iter().filter(|e| !e.persisted).collect();
    if stored.is_empty() {
        return Ok(());
    }
    insert_rows(pool, hub, &stored).await
}

/// `insertRows`: stores a batch and publishes the stored rows to the live tail.
async fn insert_rows(pool: &Pool, hub: &Hub, entries: &[&LogEntry]) -> Result<(), silo_pg::Error> {
    let mut sql = String::from(
        "INSERT INTO activity_log (timestamp, client_ip, user_id, impersonator_user_id, session_id, playback_session_id, request_id, node_id, method, path, path_pattern, status_code, user_agent, duration_ms) VALUES ",
    );
    let empty = String::new();
    let owned: Vec<[String; 8]> = entries
        .iter()
        .map(|e| {
            [
                safe(&e.client_ip),
                safe(&e.session_id),
                safe(&e.request_id),
                safe(&e.node_id),
                safe(&e.method),
                safe(&e.path),
                safe(&e.path_pattern),
                safe(&e.user_agent),
            ]
        })
        .collect();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(entries.len() * 14);
    for (i, (e, text)) in entries.iter().zip(&owned).enumerate() {
        if i > 0 {
            sql.push_str(", ");
        }
        let b = i * 14;
        sql.push_str(&format!(
            "(${}::timestamptz, ${}::text::inet, ${}::bigint, ${}::bigint, ${}::text, ${}::text, ${}::text, ${}::text, ${}::text, ${}::text, ${}::text, ${}::int, ${}::text, ${}::int)",
            b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7, b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14
        ));
        params.extend_from_slice(&[
            &e.timestamp,
            &text[0],
            &e.user_id,
            &e.impersonator_user_id,
            &text[1],
            &empty,
            &text[2],
            &text[3],
            &text[4],
            &text[5],
            &text[6],
            &e.status_code,
            &text[7],
            &e.duration_ms,
        ]);
    }
    sql.push_str(" RETURNING id, timestamp, client_ip::text, user_id::bigint, impersonator_user_id::bigint, COALESCE(session_id, ''), COALESCE(playback_session_id, ''), COALESCE(request_id, ''), COALESCE(node_id, ''), method, path, COALESCE(path_pattern, ''), COALESCE(status_code, 0), COALESCE(user_agent, ''), COALESCE(duration_ms, 0)");
    let rows = pool.query(&sql, &params).await?;
    let mut failed = 0;
    let mut last_error = String::new();
    for row in &rows {
        let stored = || -> Result<AuditEntry, silo_pg::DriverError> {
            let timestamp: SystemTime = row.try_get(1)?;
            Ok(AuditEntry {
                id: row.try_get(0)?,
                timestamp: silo_gocompat::time::GoTime::from_system_time(timestamp)
                    .format(silo_gocompat::time::RFC3339_NANO),
                client_ip: row.try_get(2)?,
                user_id: row.try_get(3)?,
                impersonator_user_id: row.try_get(4)?,
                session_id: row.try_get(5)?,
                playback_session_id: row.try_get(6)?,
                request_id: row.try_get(7)?,
                node_id: row.try_get(8)?,
                method: row.try_get(9)?,
                path: row.try_get(10)?,
                path_pattern: row.try_get(11)?,
                status_code: row.try_get(12)?,
                user_agent: row.try_get(13)?,
                duration_ms: row.try_get(14)?,
            })
        };
        let published = stored()
            .map_err(|e| e.to_string())
            .and_then(|entry| {
                silo_gocompat::json::marshal_to_string(&entry).map_err(|e| e.to_string())
            })
            .and_then(|json| hub.publish_append(Stream::Audit, json));
        if let Err(e) = published {
            failed += 1;
            last_error = e;
        }
    }
    if failed > 0 {
        tracing::warn!(component = "activitylog", failed, entries = rows.len(), error = %last_error, "activitylog: failed to publish log stream appends");
    }
    Ok(())
}

async fn record_last_activity(pool: &Pool, entries: &[LogEntry]) -> Result<(), silo_pg::Error> {
    let mut latest: BTreeMap<i64, SystemTime> = BTreeMap::new();
    for e in entries {
        if let Some(id) = e.user_id {
            let slot = latest.entry(id).or_insert(e.timestamp);
            if e.timestamp > *slot {
                *slot = e.timestamp;
            }
        }
    }
    if latest.is_empty() {
        return Ok(());
    }
    let ids: Vec<i64> = latest.keys().copied().collect();
    let times: Vec<SystemTime> = latest.values().copied().collect();
    pool.execute(
        "INSERT INTO user_last_activity (user_id, last_active_at)
         SELECT v.user_id, v.ts
         FROM unnest($1::bigint[], $2::timestamptz[]) WITH ORDINALITY AS v(user_id, ts, n)
         JOIN users u ON u.id = v.user_id
         ORDER BY v.n
         ON CONFLICT (user_id) DO UPDATE SET last_active_at = EXCLUDED.last_active_at
         WHERE user_last_activity.last_active_at < EXCLUDED.last_active_at",
        &[&ids, &times],
    )
    .await
    .map(|_| ())
}
