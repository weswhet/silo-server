//! The Redis pub/sub event bus, ported from `internal/cache/redis.go`'s `EventBus` family and
//! `internal/cache/observed_bus.go`.
//!
//! Every event this bus carries is [`silo_core::redis::Event`], the shared `{"type","payload"}`
//! shape, marshaled with [`silo_gocompat::json::marshal_to_string`] so the bytes on the wire match
//! Go's `encoding/json` output exactly. The channel name a subscriber or publisher actually uses is
//! [`silo_core::redis::channel`], which appends `@dbN` above database 0, exactly as Go's
//! `redisChannel` does, so two installs sharing one Redis server on different database numbers
//! never cross-deliver.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use silo_config::config::RedisConfig;
use silo_core::redis::Event;
use tokio::sync::Mutex;

use super::{Connector, Error};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A callback invoked for every event received on a subscribed channel, in a dedicated task.
/// `cache.EventHandler`.
pub type Handler = Arc<dyn Fn(Event) + Send + Sync>;

/// Publishes and subscribes to cache invalidation events. `cache.EventBus`.
pub trait EventBus: Send + Sync {
    /// Sends `event` on `channel`. `Publish`.
    fn publish<'a>(&'a self, channel: &'a str, event: Event) -> BoxFuture<'a, Result<(), Error>>;

    /// Registers `handler` for events on `channel`. The handler runs in a dedicated task. `Subscribe`.
    fn subscribe<'a>(
        &'a self,
        channel: &'a str,
        handler: Handler,
    ) -> BoxFuture<'a, Result<(), Error>>;

    /// Tears down the bus and stops every subscriber task. Safe to call more than once. `Close`.
    fn close(&self) -> BoxFuture<'_, Result<(), Error>>;
}

/// A silent [`EventBus`] used when Redis is not configured. Every call succeeds and does nothing.
/// `cache.NoopEventBus`.
#[derive(Default)]
pub struct NoopEventBus;

impl EventBus for NoopEventBus {
    fn publish<'a>(&'a self, _channel: &'a str, _event: Event) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }

    fn subscribe<'a>(
        &'a self,
        _channel: &'a str,
        _handler: Handler,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }
}

/// `NewEventBus`: a [`NoopEventBus`] when `cfg` has no URL, otherwise a live Redis bus.
pub fn new_event_bus(cfg: &RedisConfig) -> Box<dyn EventBus> {
    if silo_gocompat::strings::trim_space(&cfg.url).is_empty() {
        return Box::new(NoopEventBus);
    }
    Box::new(RedisEventBus::new(cfg))
}

/// How often a Sentinel-following bus re-asks Sentinel for the master address, so a promotion is
/// noticed even though this crate's Redis client has no raw-command access to the dedicated pub/sub
/// connection to ping it the way `internal/cache/redis.go`'s `keepAlive` does. `pingInterval`.
const SENTINEL_RECHECK_INTERVAL: Duration = Duration::from_secs(3);
/// Backoff between reconnect attempts after a subscription's connection ends, matching the order of
/// magnitude of Go's `redial`'s 100ms retry without hot-looping on a down Redis.
const RECONNECT_BACKOFF: Duration = Duration::from_millis(250);

/// [`EventBus`] backed by live Redis pub/sub. `cache.RedisEventBus`.
pub struct RedisEventBus {
    connector: Connector,
    db: i64,
    publish_conn: Mutex<Option<MultiplexedConnection>>,
    closed: Arc<AtomicBool>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl RedisEventBus {
    pub fn new(cfg: &RedisConfig) -> Self {
        let connector = Connector::from_config(cfg);
        let db = connector.database();
        Self {
            connector,
            db,
            publish_conn: Mutex::new(None),
            closed: Arc::new(AtomicBool::new(false)),
            tasks: Mutex::new(Vec::new()),
        }
    }

    async fn publish_connection(&self) -> Result<MultiplexedConnection, Error> {
        let mut guard = self.publish_conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let client = self.connector.client().await?;
        let conn = client.get_multiplexed_async_connection().await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn invalidate_publish_connection(&self) {
        *self.publish_conn.lock().await = None;
    }
}

impl EventBus for RedisEventBus {
    fn publish<'a>(&'a self, channel: &'a str, event: Event) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let data = silo_gocompat::json::marshal_to_string(&event)
                .map_err(|e| Error::Config(format!("marshaling event: {e}")))?;
            let scoped = silo_core::redis::channel(channel, self.db);
            let mut conn = self.publish_connection().await?;
            match conn.publish::<_, _, ()>(&scoped, &data).await {
                Ok(()) => Ok(()),
                Err(err) => {
                    // The cached connection may have died (a Sentinel failover, an idle timeout);
                    // retry once on a fresh one, as go-redis's pool would on its next checkout.
                    self.invalidate_publish_connection().await;
                    let mut conn = self.publish_connection().await?;
                    conn.publish::<_, _, ()>(&scoped, &data)
                        .await
                        .map_err(|_| Error::Redis(err))
                }
            }
        })
    }

    fn subscribe<'a>(
        &'a self,
        channel: &'a str,
        handler: Handler,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let scoped = silo_core::redis::channel(channel, self.db);
            // Confirm the subscription once, synchronously, the way Go's `Subscribe` waits for
            // `pubsub.Receive` before returning, so a refused subscription (an ACL denial) surfaces
            // to the caller instead of only to a background task's log.
            let mut pubsub = self.connector.client().await?.get_async_pubsub().await?;
            pubsub.subscribe(&scoped).await?;

            let closed = Arc::clone(&self.closed);
            let is_sentinel = self.connector.is_sentinel();
            let connector = self.connector.clone();
            let task = tokio::spawn(run_subscription(
                connector,
                scoped,
                pubsub,
                handler,
                closed,
                is_sentinel,
            ));
            self.tasks.lock().await.push(task);
            Ok(())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            if self.closed.swap(true, Ordering::SeqCst) {
                return Ok(()); // already closed
            }
            let tasks = std::mem::take(&mut *self.tasks.lock().await);
            for task in tasks {
                task.abort();
            }
            *self.publish_conn.lock().await = None;
            Ok(())
        })
    }
}

/// Delivers messages on one subscription until the bus closes. A dropped connection (a break, or a
/// Sentinel promotion this loop notices on its next recheck) is redialed and resubscribed, so the
/// caller's `subscribe` call stays effective for the bus's whole lifetime, matching go-redis's own
/// automatic reconnect for a standalone subscription and this crate's substitute for Go's
/// ping-and-deadline silent-master detection in Sentinel mode (`listenToMaster`/`keepAlive`).
async fn run_subscription(
    connector: Connector,
    channel: String,
    mut pubsub: redis::aio::PubSub,
    handler: Handler,
    closed: Arc<AtomicBool>,
    is_sentinel: bool,
) {
    loop {
        if closed.load(Ordering::SeqCst) {
            return;
        }
        let mut stream = pubsub.on_message();
        let next = if is_sentinel {
            tokio::time::timeout(SENTINEL_RECHECK_INTERVAL, stream.next()).await
        } else {
            Ok(stream.next().await)
        };
        match next {
            Ok(Some(msg)) => {
                drop(stream);
                let Ok(payload) = msg.get_payload::<String>() else {
                    continue;
                };
                if let Ok(event) = serde_json::from_str::<Event>(&payload) {
                    handler(event);
                }
            }
            Ok(None) => {
                drop(stream);
                // The connection ended. Redial (re-resolving the master, for Sentinel) and
                // resubscribe.
                if !redial(&connector, &channel, &mut pubsub, &closed).await {
                    return;
                }
            }
            Err(_elapsed) => {
                drop(stream);
                // Sentinel recheck tick: see whether the master moved.
                if !redial_if_moved(&connector, &channel, &mut pubsub, &closed).await {
                    return;
                }
            }
        }
    }
}

async fn redial(
    connector: &Connector,
    channel: &str,
    pubsub: &mut redis::aio::PubSub,
    closed: &Arc<AtomicBool>,
) -> bool {
    loop {
        if closed.load(Ordering::SeqCst) {
            return false;
        }
        match connect_and_subscribe(connector, channel).await {
            Ok(fresh) => {
                *pubsub = fresh;
                return true;
            }
            Err(_) => tokio::time::sleep(RECONNECT_BACKOFF).await,
        }
    }
}

async fn redial_if_moved(
    connector: &Connector,
    channel: &str,
    pubsub: &mut redis::aio::PubSub,
    closed: &Arc<AtomicBool>,
) -> bool {
    // This crate's pub/sub type has no raw-command access to ping the existing connection (see the
    // module doc), so a Sentinel bus redials unconditionally on every recheck tick instead of only
    // on a detected promotion. The tick interval (3s) bounds how stale a connection can go
    // unnoticed, trading a small, harmless resubscribe for certainty.
    redial(connector, channel, pubsub, closed).await
}

async fn connect_and_subscribe(
    connector: &Connector,
    channel: &str,
) -> Result<redis::aio::PubSub, Error> {
    let client = connector.client().await?;
    let mut pubsub = client.get_async_pubsub().await?;
    pubsub.subscribe(channel).await?;
    Ok(pubsub)
}

/// A callback given every event published through an [`ObservedEventBus`], whether or not Redis
/// carries it to other nodes. `cache.PublishObserver`.
pub type PublishObserver = Arc<dyn Fn(&str, &Event) + Send + Sync>;

/// Wraps an [`EventBus`] so every event published through it is also handed to an observer, whether
/// or not Redis carries it to other nodes. `cache.ObservedEventBus`.
pub struct ObservedEventBus {
    inner: Box<dyn EventBus>,
    observer: Mutex<Option<PublishObserver>>,
}

impl ObservedEventBus {
    pub fn new(inner: Box<dyn EventBus>) -> Self {
        Self {
            inner,
            observer: Mutex::new(None),
        }
    }

    /// Sets the observer, replacing any earlier one. It runs on the publisher's task and must not
    /// block. `ObservePublishes`.
    pub async fn observe_publishes(&self, observer: Option<PublishObserver>) {
        *self.observer.lock().await = observer;
    }
}

impl EventBus for ObservedEventBus {
    fn publish<'a>(&'a self, channel: &'a str, event: Event) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let result = self.inner.publish(channel, event.clone()).await;
            if let Some(observer) = self.observer.lock().await.as_ref() {
                observer(channel, &event);
            }
            result
        })
    }

    fn subscribe<'a>(
        &'a self,
        channel: &'a str,
        handler: Handler,
    ) -> BoxFuture<'a, Result<(), Error>> {
        self.inner.subscribe(channel, handler)
    }

    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        self.inner.close()
    }
}
