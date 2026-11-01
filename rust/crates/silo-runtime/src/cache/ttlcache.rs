//! Port of `internal/cache/ttlcache.go`: a generic in-process TTL cache with a background sweeper.
//! Pure in-process state with no wire format, so there is nothing here that must match Go bit for
//! bit; only the behavior (miss on expiry, periodic sweep, idempotent close) does.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct Entry<V> {
    value: V,
    expires_at: Instant,
}

struct Shared<V> {
    entries: Mutex<HashMap<String, Entry<V>>>,
}

/// A concurrency-safe, in-process cache with per-key time-to-live semantics. A background task
/// periodically sweeps out expired entries. Dropping the last handle stops the sweeper.
/// `cache.TTLCache[V]`.
pub struct TtlCache<V: Clone + Send + Sync + 'static> {
    shared: Arc<Shared<V>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl<V: Clone + Send + Sync + 'static> TtlCache<V> {
    /// Starts the background sweeper with the default 30-second interval. `NewTTLCache`.
    pub fn new() -> Self {
        Self::with_sweep_interval(DEFAULT_SWEEP_INTERVAL)
    }

    /// `newTTLCacheWithSweepInterval`: exposed for tests that want a fast sweeper.
    pub fn with_sweep_interval(interval: Duration) -> Self {
        let shared = Arc::new(Shared {
            entries: Mutex::new(HashMap::new()),
        });
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
        let sweep_shared = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = &mut stop_rx => return,
                    _ = ticker.tick() => sweep(&sweep_shared),
                }
            }
        });
        Self {
            shared,
            stop: Some(stop_tx),
            task: Some(task),
        }
    }

    /// A hit returns the value; a miss, including an expired entry, returns `None`. `Get`.
    pub fn get(&self, key: &str) -> Option<V> {
        let entries = self.shared.entries.lock().expect("ttlcache lock");
        let entry = entries.get(key)?;
        if Instant::now() > entry.expires_at {
            return None;
        }
        Some(entry.value.clone())
    }

    /// Stores `value` under `key` with the given TTL, overwriting and resetting the expiry if the key
    /// already exists. `Set`.
    pub fn set(&self, key: &str, value: V, ttl: Duration) {
        let mut entries = self.shared.entries.lock().expect("ttlcache lock");
        entries.insert(
            key.to_owned(),
            Entry {
                value,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// Removes a single key immediately. `Invalidate`.
    pub fn invalidate(&self, key: &str) {
        self.shared
            .entries
            .lock()
            .expect("ttlcache lock")
            .remove(key);
    }

    /// Removes every key that starts with `prefix`. `InvalidatePrefix`.
    pub fn invalidate_prefix(&self, prefix: &str) {
        self.shared
            .entries
            .lock()
            .expect("ttlcache lock")
            .retain(|k, _| !k.starts_with(prefix));
    }

    /// Stops the background sweeper. Idempotent. `Close`.
    pub fn close(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl<V: Clone + Send + Sync + 'static> Default for TtlCache<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Clone + Send + Sync + 'static> Drop for TtlCache<V> {
    fn drop(&mut self) {
        self.close();
    }
}

fn sweep<V>(shared: &Shared<V>) {
    let now = Instant::now();
    shared
        .entries
        .lock()
        .expect("ttlcache lock")
        .retain(|_, entry| now <= entry.expires_at);
}
