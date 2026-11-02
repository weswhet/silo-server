//! `activitylog/middleware.go`'s filter and `consumer.go`'s batch writer: one row per request, written
//! off the request path, 100 rows or 2 seconds at a time.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use silo_pg::{Pool, ToSql};
use tokio::sync::mpsc;

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

/// `logstream.SafeText`: Postgres text cannot hold NUL or invalid UTF-8; a Rust string only the first.
fn safe(text: &str) -> String {
    text.replace('\0', "")
}

/// `activitylog.Writer`. A full queue drops the entry rather than block the request, as Go's does.
#[derive(Clone)]
pub struct ActivityWriter {
    tx: mpsc::Sender<LogEntry>,
}

impl ActivityWriter {
    pub fn start(pool: Arc<Pool>) -> Self {
        let (tx, rx) = mpsc::channel(4096);
        tokio::spawn(run(pool, rx));
        Self { tx }
    }

    pub fn write(&self, entry: LogEntry) {
        let _ = self.tx.try_send(entry);
    }
}

async fn run(pool: Arc<Pool>, mut rx: mpsc::Receiver<LogEntry>) {
    let mut batch = Vec::with_capacity(100);
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            entry = rx.recv() => {
                let Some(entry) = entry else { break };
                batch.push(entry);
                if batch.len() >= 100 {
                    flush(&pool, &mut batch).await;
                }
            }
            _ = tick.tick() => flush(&pool, &mut batch).await,
        }
    }
    flush(&pool, &mut batch).await;
}

async fn flush(pool: &Pool, batch: &mut Vec<LogEntry>) {
    if batch.is_empty() {
        return;
    }
    if let Err(e) = insert_rows(pool, batch).await {
        tracing::error!(component = "activitylog", entries = batch.len(), error = %e, "activity log batch insert failed; entries dropped");
        batch.clear();
        return;
    }
    if let Err(e) = record_last_activity(pool, batch).await {
        tracing::warn!(component = "activitylog", error = %e, "failed to record last activity");
    }
    batch.clear();
}

async fn insert_rows(pool: &Pool, entries: &[LogEntry]) -> Result<(), silo_pg::Error> {
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
    pool.execute(&sql, &params).await.map(|_| ())
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
