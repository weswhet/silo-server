//! `internal/opslog`: tracing events go into a bounded queue, a task writes them to `operational_logs` in
//! batches, and each stored row goes to the admin live tail. A request's log line reaches the admin log view
//! from whichever process answered it.

use std::fmt::Debug;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};
use silo_gocompat::time::{GoTime, RFC3339_NANO};
use silo_pg::{AnyInt, Pool, ToSql};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::logstream::{
    Hub, INSERT_TIMEOUT, RETRY_MAX_BACKOFF, RETRY_MIN_BACKOFF, Stream, retryable, safe_text,
    value_rejected,
};

/// `logBufferSize`.
const BUFFER: usize = 4096;
/// `Consumer.batchSize`.
const BATCH: usize = 100;
/// `Consumer.interval`.
const INTERVAL: Duration = Duration::from_secs(2);
/// `logredact.Placeholder`.
const REDACTED: &str = "[REDACTED]";
/// `logredact.secretMarkers`.
const SECRET_MARKERS: [&str; 7] = [
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
];

/// `opslog.Entry`.
#[derive(Clone, Debug)]
pub struct Entry {
    pub timestamp: SystemTime,
    pub level: String,
    pub component: String,
    pub message: String,
    pub request_id: String,
    pub user_id: Option<i64>,
    pub session_id: String,
    pub playback_session_id: String,
    pub client_ip: String,
    pub node_id: String,
    pub attrs: Map<String, Value>,
}

/// `logredact.SecretKey`.
fn secret_key(key: &str) -> bool {
    let key = silo_gocompat::strings::to_lower(key);
    SECRET_MARKERS.iter().any(|marker| key.contains(marker))
}

/// `inferComponent`.
fn infer_component(message: &str) -> String {
    if let Some((prefix, _)) = message.split_once(':') {
        let prefix = silo_gocompat::strings::trim_space(prefix);
        if !prefix.is_empty() {
            return prefix.to_owned();
        }
    }
    "app".to_owned()
}

#[derive(Default)]
struct Fields {
    message: String,
    attrs: Map<String, Value>,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            value.clone_into(&mut self.message);
        } else {
            self.attrs
                .insert(field.name().to_owned(), Value::from(value));
        }
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.attrs
            .insert(field.name().to_owned(), Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.attrs
            .insert(field.name().to_owned(), Value::from(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.attrs
            .insert(field.name().to_owned(), Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.attrs
            .insert(field.name().to_owned(), Value::from(value));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        let text = format!("{value:?}");
        if field.name() == "message" {
            self.message = text;
        } else {
            self.attrs
                .insert(field.name().to_owned(), Value::from(text));
        }
    }
}

/// What `Handler.Handle` makes of one record.
fn entry_of(level: &str, fields: Fields, node_id: &str) -> Entry {
    let mut attrs = fields.attrs;
    for (key, value) in &mut attrs {
        if secret_key(key) {
            *value = Value::from(REDACTED);
        }
    }
    let text = |key: &str| attrs.get(key).and_then(Value::as_str).unwrap_or_default();
    let mut component = text("component").to_owned();
    if component.is_empty() {
        component = infer_component(&fields.message);
    }
    let mut client_ip = text("client_ip");
    if client_ip.is_empty() {
        client_ip = text("remote_addr");
    }
    let attr_node = text("node_id");
    Entry {
        timestamp: SystemTime::now(),
        level: level.to_owned(),
        component,
        request_id: text("request_id").to_owned(),
        user_id: attrs.get("user_id").and_then(Value::as_i64),
        session_id: text("session_id").to_owned(),
        playback_session_id: text("playback_session_id").to_owned(),
        client_ip: client_ip.to_owned(),
        node_id: if attr_node.is_empty() {
            node_id
        } else {
            attr_node
        }
        .to_owned(),
        message: fields.message,
        attrs,
    }
}

struct Shared {
    sender: mpsc::Sender<Entry>,
    node_id: String,
}

/// Fills once the database is open. What is logged before that goes to stderr only.
static SINK: OnceLock<Mutex<Option<Arc<Shared>>>> = OnceLock::new();
/// `opsCaptureLevel`, with `tracing`'s order: larger is more verbose.
static CAPTURE: AtomicU8 = AtomicU8::new(2);

fn rank(level: Level) -> u8 {
    match level {
        Level::ERROR => 0,
        Level::WARN => 1,
        Level::INFO => 2,
        _ => 3,
    }
}

/// `slog.Level.String`, lower-cased. `tracing`'s `trace` is below anything Go has.
fn level_name(level: Level) -> &'static str {
    match level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        _ => "debug",
    }
}

/// `Handler`, as a tracing layer. Events from outside this workspace (the HTTP and Postgres libraries) have no
/// Go counterpart. The consumer's own records and the front's messages about itself are not captured: the first
/// must not queue another entry behind a failed batch, and the second describe a process Go does not have.
pub struct CaptureLayer;

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if rank(*meta.level()) > CAPTURE.load(Ordering::Relaxed)
            || !meta.target().starts_with("silo")
        {
            return;
        }
        let Some(shared) = SINK
            .get()
            .and_then(|sink| sink.lock().unwrap_or_else(|e| e.into_inner()).clone())
        else {
            return;
        };
        let mut fields = Fields::default();
        event.record(&mut fields);
        if matches!(
            fields.attrs.get("component").and_then(Value::as_str),
            Some("opslog" | "front")
        ) {
            return;
        }
        let _ =
            shared
                .sender
                .try_send(entry_of(level_name(*meta.level()), fields, &shared.node_id));
    }
}

/// `configureOperationalLogging`'s capture level.
pub fn capture_rank(setting: &str) -> u8 {
    match silo_gocompat::strings::to_lower(silo_gocompat::strings::trim_space(setting)).as_str() {
        "debug" => 3,
        "warn" | "warning" => 1,
        "error" => 0,
        _ => 2,
    }
}

/// Starts the consumer and connects the layer to it.
pub fn start(pool: Arc<Pool>, hub: Arc<Hub>, node_id: String, capture_level: &str) {
    CAPTURE.store(capture_rank(capture_level), Ordering::Relaxed);
    let (sender, rx) = mpsc::channel(BUFFER);
    tokio::spawn(run(pool, hub, rx));
    let sink = SINK.get_or_init(|| Mutex::new(None));
    *sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(Shared { sender, node_id }));
}

async fn run(pool: Arc<Pool>, hub: Arc<Hub>, mut rx: mpsc::Receiver<Entry>) {
    let mut batch = Vec::with_capacity(BATCH);
    let mut tick = tokio::time::interval(INTERVAL);
    loop {
        tokio::select! {
            entry = rx.recv() => {
                let Some(entry) = entry else { break };
                batch.push(entry);
                if batch.len() >= BATCH {
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

/// `Drain.persist`.
fn persist<'a>(
    pool: &'a Pool,
    hub: &'a Hub,
    batch: &'a [Entry],
    stopping: bool,
) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        if batch.is_empty() {
            return;
        }
        let mut backoff = RETRY_MIN_BACKOFF;
        let mut attempt = 1;
        loop {
            let err = match tokio::time::timeout(INSERT_TIMEOUT, insert_batch(pool, hub, batch))
                .await
            {
                Ok(Ok(())) => return,
                Ok(Err(e)) => {
                    if batch.len() > 1 && value_rejected(&e) {
                        for row in batch.chunks(1) {
                            persist(pool, hub, row, stopping).await;
                        }
                        return;
                    }
                    if stopping || !retryable(&e) {
                        tracing::error!(component = "opslog", entries = batch.len(), attempt, error = %e, "opslog batch insert failed; entries dropped");
                        return;
                    }
                    e.to_string()
                }
                Err(_) => {
                    if stopping {
                        tracing::error!(
                            component = "opslog",
                            entries = batch.len(),
                            attempt,
                            error = "context deadline exceeded",
                            "opslog batch insert failed; entries dropped"
                        );
                        return;
                    }
                    "context deadline exceeded".to_owned()
                }
            };
            tracing::warn!(component = "opslog", entries = batch.len(), attempt, retry_in = ?backoff, error = %err, "opslog batch insert failed; retrying");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RETRY_MAX_BACKOFF);
            attempt += 1;
        }
    })
}

/// `Consumer.insertBatch`.
async fn insert_batch(pool: &Pool, hub: &Hub, entries: &[Entry]) -> Result<(), silo_pg::Error> {
    let mut sql = String::from(
        "INSERT INTO operational_logs (timestamp, level, component, message, request_id, user_id, session_id, playback_session_id, client_ip, node_id, attrs) VALUES ",
    );
    let owned: Vec<[String; 9]> = entries
        .iter()
        .map(|e| {
            [
                safe_text(&e.level),
                safe_text(&e.component),
                safe_text(&e.message),
                safe_text(&e.request_id),
                safe_text(&e.session_id),
                safe_text(&e.playback_session_id),
                safe_text(&e.client_ip),
                safe_text(&e.node_id),
                silo_gocompat::json::marshal_to_string(&e.attrs)
                    .unwrap_or_else(|_| "{}".to_owned())
                    .replace("\\u0000", "\\ufffd"),
            ]
        })
        .collect();
    let user_ids: Vec<Option<AnyInt>> = entries.iter().map(|e| e.user_id.map(AnyInt)).collect();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(entries.len() * 11);
    for (i, ((e, text), user)) in entries.iter().zip(&owned).zip(&user_ids).enumerate() {
        if i > 0 {
            sql.push_str(", ");
        }
        let b = i * 11;
        sql.push_str(&format!(
            "(${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, NULLIF(${}, '')::inet, ${}, ${}::text::jsonb)",
            b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7, b + 8, b + 9, b + 10, b + 11
        ));
        params.extend_from_slice(&[
            &e.timestamp,
            &text[0],
            &text[1],
            &text[2],
            &text[3],
            user,
            &text[4],
            &text[5],
            &text[6],
            &text[7],
            &text[8],
        ]);
    }
    sql.push_str(" RETURNING id, timestamp, level, component, message, COALESCE(request_id, ''), user_id, COALESCE(session_id, ''), COALESCE(playback_session_id, ''), COALESCE(client_ip::text, ''), COALESCE(node_id, ''), attrs::text");
    let rows = pool.query(&sql, &params).await?;
    let mut failed = 0;
    let mut last_error = String::new();
    for row in &rows {
        let json = (|| -> Result<String, String> {
            let e = |e: silo_pg::DriverError| e.to_string();
            let timestamp: SystemTime = row.try_get(1).map_err(e)?;
            let mut out = Map::new();
            let id: i64 = row.try_get(0).map_err(e)?;
            let user: Option<AnyInt> = row.try_get(6).map_err(e)?;
            let attrs: String = row.try_get(11).map_err(e)?;
            out.insert("id".to_owned(), Value::from(id));
            out.insert(
                "timestamp".to_owned(),
                Value::from(GoTime::from_system_time(timestamp).format(RFC3339_NANO)),
            );
            for (name, at) in [("level", 2), ("component", 3), ("message", 4)] {
                out.insert(
                    name.to_owned(),
                    Value::from(row.try_get::<_, String>(at).map_err(e)?),
                );
            }
            // `omitempty`.
            let request_id: String = row.try_get(5).map_err(e)?;
            if !request_id.is_empty() {
                out.insert("request_id".to_owned(), Value::from(request_id));
            }
            if let Some(user) = user {
                out.insert("user_id".to_owned(), Value::from(user.0));
            }
            for (name, at) in [
                ("session_id", 7),
                ("playback_session_id", 8),
                ("client_ip", 9),
                ("node_id", 10),
            ] {
                let text: String = row.try_get(at).map_err(e)?;
                if !text.is_empty() {
                    out.insert(name.to_owned(), Value::from(text));
                }
            }
            let attrs: Value =
                silo_gocompat::json::unmarshal(attrs.as_bytes()).map_err(|e| e.to_string())?;
            if attrs.as_object().is_some_and(|m| !m.is_empty()) {
                out.insert("attrs".to_owned(), attrs);
            }
            let ordered = ROW_ORDER
                .iter()
                .filter_map(|k| out.get(*k).map(|v| (*k, v)))
                .map(|(k, v)| {
                    Ok(format!(
                        "{}:{}",
                        silo_gocompat::json::marshal_to_string(&k).map_err(|e| e.to_string())?,
                        silo_gocompat::json::marshal_to_string(v).map_err(|e| e.to_string())?
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(format!("{{{}}}", ordered.join(",")))
        })();
        match json.and_then(|json| hub.publish_append(Stream::App, json)) {
            Ok(()) => {}
            Err(e) => {
                failed += 1;
                last_error = e;
            }
        }
    }
    if failed > 0 {
        tracing::warn!(component = "opslog", error = %last_error, failed, entries = rows.len(), "opslog: failed to publish log stream appends");
    }
    Ok(())
}

/// `EntryRow`'s field order.
const ROW_ORDER: [&str; 12] = [
    "id",
    "timestamp",
    "level",
    "component",
    "message",
    "request_id",
    "user_id",
    "session_id",
    "playback_session_id",
    "client_ip",
    "node_id",
    "attrs",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_reads_as_handle_reads_it() {
        let mut fields = Fields {
            message: "plugin: started".to_owned(),
            ..Fields::default()
        };
        fields
            .attrs
            .insert("api_token".to_owned(), Value::from("x"));
        fields.attrs.insert("user_id".to_owned(), Value::from(7));
        fields
            .attrs
            .insert("remote_addr".to_owned(), Value::from("10.0.0.1"));
        let entry = entry_of("info", fields, "node");
        assert_eq!(entry.component, "plugin");
        assert_eq!(entry.user_id, Some(7));
        assert_eq!(entry.client_ip, "10.0.0.1");
        assert_eq!(entry.node_id, "node");
        assert_eq!(entry.attrs["api_token"], REDACTED);
    }

    #[test]
    fn capture_level_setting() {
        assert_eq!(capture_rank(" WARNING "), 1);
        assert_eq!(capture_rank("nonsense"), 2);
    }
}
