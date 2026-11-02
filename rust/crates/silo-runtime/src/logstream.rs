//! `internal/logstream`'s hub and text cleaning: persisted log rows fan out to this process's live tail
//! subscribers and, through a bounded queue, to other processes on `silo:logs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use silo_core::redis::{CHANNEL_LOGS, Event};
use tokio::sync::mpsc;

use crate::cache::event_bus::EventBus;

/// `insertTimeout`.
pub const INSERT_TIMEOUT: Duration = Duration::from_secs(10);
/// `retryMinBackoff`.
pub const RETRY_MIN_BACKOFF: Duration = Duration::from_secs(1);
/// `retryMaxBackoff`.
pub const RETRY_MAX_BACKOFF: Duration = Duration::from_secs(10);

/// `retryable`: a failed insert that can succeed unchanged later. Postgres was unreachable or the
/// connection dropped, or the server refused work for a passing reason.
pub fn retryable(err: &silo_pg::Error) -> bool {
    match err {
        silo_pg::Error::Pg(_) => match err.code() {
            Some(code) => {
                let code = code.code();
                code == "25006" || matches!(code.get(..2), Some("08" | "40" | "53" | "57" | "58"))
            }
            None => true,
        },
        silo_pg::Error::Pool(_) => true,
        silo_pg::Error::Config(_) | silo_pg::Error::NoRows => false,
    }
}

/// `valueRejected`: class 22, a value in the statement. It says nothing about the batch's other rows.
pub fn value_rejected(err: &silo_pg::Error) -> bool {
    err.code().is_some_and(|code| code.code().starts_with("22"))
}

/// `Stream`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    App,
    Audit,
}

/// `cache.EventOperationalLogAppended` and `EventAuditLogAppended`.
pub const EVENT_APP_APPENDED: &str = "operational_log_appended";
pub const EVENT_AUDIT_APPENDED: &str = "audit_log_appended";

/// `remoteQueueSize`.
const REMOTE_QUEUE_SIZE: usize = 1024;
/// `remotePublishTimeout`.
const REMOTE_PUBLISH_TIMEOUT: Duration = Duration::from_secs(2);
/// A subscriber's buffer. A slow one misses rows rather than holding up the writer.
const SUBSCRIBER_BUFFER: usize = 64;

/// `appendEnvelope`, read back.
#[derive(Deserialize)]
struct IncomingEnvelope {
    #[serde(default)]
    source: String,
    stream: String,
    entry: serde_json::Value,
}

/// `Message`, the append kind this hub produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Append {
    pub stream: Stream,
    pub entry: String,
}

#[derive(Default)]
struct Subscribers {
    next: u64,
    senders: HashMap<u64, mpsc::Sender<Append>>,
}

/// `Hub`.
pub struct Hub {
    source_id: String,
    subscribers: Arc<Mutex<Subscribers>>,
    remote: Option<mpsc::Sender<(Stream, Event)>>,
    dropped: Arc<AtomicU64>,
}

/// Ends a subscription when dropped. `Subscribe`'s second result.
pub struct Subscription {
    pub rows: mpsc::Receiver<Append>,
    id: u64,
    subscribers: Arc<Mutex<Subscribers>>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.subscribers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .senders
            .remove(&self.id);
    }
}

fn fan_out(subscribers: &Mutex<Subscribers>, append: &Append) {
    let subscribers = subscribers.lock().unwrap_or_else(|e| e.into_inner());
    for sender in subscribers.senders.values() {
        let _ = sender.try_send(append.clone());
    }
}

impl Hub {
    /// `NewHub`. With a bus it starts the task that publishes this process's rows. Another process only
    /// shows a row whose source is not its own, so `source_id` must be unique to this process.
    pub fn new(source_id: String, bus: Option<Arc<dyn EventBus>>) -> Self {
        let dropped = Arc::new(AtomicU64::new(0));
        let remote = bus.map(|bus| {
            let (tx, rx) = mpsc::channel(REMOTE_QUEUE_SIZE);
            tokio::spawn(run_remote(bus, rx, dropped.clone()));
            tx
        });
        Self {
            source_id,
            subscribers: Arc::default(),
            remote,
            dropped,
        }
    }

    /// `Start`: rows from other processes reach this one's subscribers.
    pub async fn start(&self, bus: &Arc<dyn EventBus>) -> Result<(), crate::cache::Error> {
        let subscribers = self.subscribers.clone();
        let source = self.source_id.clone();
        bus.subscribe(
            CHANNEL_LOGS,
            Arc::new(move |event: Event| {
                if let Some(append) = incoming(&event, &source) {
                    fan_out(&subscribers, &append);
                }
            }),
        )
        .await
    }

    /// `Subscribe`.
    pub fn subscribe(&self) -> Subscription {
        let (tx, rows) = mpsc::channel(SUBSCRIBER_BUFFER);
        let mut subscribers = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        let id = subscribers.next;
        subscribers.next += 1;
        subscribers.senders.insert(id, tx);
        Subscription {
            rows,
            id,
            subscribers: self.subscribers.clone(),
        }
    }

    /// `PublishAppend`: `entry` is one row's JSON. It never waits on the bus; a full queue drops the row.
    pub fn publish_append(&self, stream: Stream, entry: String) -> Result<(), String> {
        silo_gocompat::json::unmarshal::<serde_json::Value>(entry.as_bytes())
            .map_err(|e| e.to_string())?;
        let source =
            silo_gocompat::json::marshal_to_string(&self.source_id).map_err(|e| e.to_string())?;
        let name = match stream {
            Stream::App => "app",
            Stream::Audit => "audit",
        };
        let payload = format!(r#"{{"source":{source},"stream":"{name}","entry":{entry}}}"#);
        fan_out(&self.subscribers, &Append { stream, entry });
        if let Some(remote) = &self.remote {
            let event = Event {
                event_type: match stream {
                    Stream::App => EVENT_APP_APPENDED,
                    Stream::Audit => EVENT_AUDIT_APPENDED,
                }
                .to_owned(),
                payload,
            };
            if remote.try_send((stream, event)).is_err() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    /// `silo_log_tail_publish_dropped_total`, summed.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// `handleEventBusMessage`.
fn incoming(event: &Event, source_id: &str) -> Option<Append> {
    if event.event_type != EVENT_APP_APPENDED && event.event_type != EVENT_AUDIT_APPENDED {
        return None;
    }
    let envelope: IncomingEnvelope =
        silo_gocompat::json::unmarshal(event.payload.as_bytes()).ok()?;
    if !envelope.source.is_empty() && envelope.source == source_id {
        return None;
    }
    Some(Append {
        stream: if envelope.stream == "app" {
            Stream::App
        } else {
            Stream::Audit
        },
        entry: silo_gocompat::json::marshal_to_string(&envelope.entry).ok()?,
    })
}

/// `runRemote`: logs only when publishing starts failing and when it recovers.
async fn run_remote(
    bus: Arc<dyn EventBus>,
    mut rx: mpsc::Receiver<(Stream, Event)>,
    dropped: Arc<AtomicU64>,
) {
    let mut healthy = true;
    while let Some((_stream, event)) = rx.recv().await {
        let published =
            tokio::time::timeout(REMOTE_PUBLISH_TIMEOUT, bus.publish(CHANNEL_LOGS, event)).await;
        match published {
            Ok(Ok(())) => {
                if !healthy {
                    tracing::info!(
                        component = "logstream",
                        "log stream: cross-node publish recovered"
                    );
                }
                healthy = true;
            }
            failed => {
                dropped.fetch_add(1, Ordering::Relaxed);
                if healthy {
                    let error = match failed {
                        Ok(Err(e)) => e.to_string(),
                        _ => "timed out".to_owned(),
                    };
                    tracing::warn!(
                        component = "logstream",
                        error,
                        "log stream: cross-node publish failing; other nodes' live tails miss this node's rows until it recovers"
                    );
                }
                healthy = false;
            }
        }
    }
}

/// `SafeText`: Postgres text rejects NUL and invalid UTF-8. A Rust string can only hold the first.
pub fn safe_text(text: &str) -> String {
    text.replace('\0', "\u{fffd}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_subscriber_gets_appends_and_its_own_source_is_ignored() {
        let hub = Hub::new("me".to_owned(), None);
        let mut sub = hub.subscribe();
        hub.publish_append(Stream::Audit, r#"{"id":1}"#.to_owned())
            .unwrap();
        let row = sub.rows.recv().await.unwrap();
        assert_eq!(row.stream, Stream::Audit);
        assert_eq!(row.entry, r#"{"id":1}"#);

        let event = |source: &str| Event {
            event_type: EVENT_AUDIT_APPENDED.to_owned(),
            payload: format!(r#"{{"source":"{source}","stream":"audit","entry":{{"id":2}}}}"#),
        };
        assert_eq!(incoming(&event("me"), "me"), None);
        assert_eq!(
            incoming(&event("other"), "me").unwrap().entry,
            r#"{"id":2}"#
        );
        hub.publish_append(Stream::App, "not json".to_owned())
            .unwrap_err();
    }

    #[test]
    fn safe_text_replaces_nul() {
        assert_eq!(safe_text("a\0b"), "a\u{fffd}b");
    }
}
