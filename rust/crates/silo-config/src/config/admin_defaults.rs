//! A per-node snapshot of the administrator's setting defaults.

use super::{BoxFuture, SettingError, SettingsMap};
use crate::settings::{admin_default_setting_key, load};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// How long a node serves its snapshot without re-reading it.
pub const ADMIN_DEFAULTS_CACHE_TTL: Duration = Duration::from_secs(10);
/// How long a failed refresh keeps serving the last snapshot before the next attempt.
pub const ADMIN_DEFAULTS_RETRY_DELAY: Duration = Duration::from_secs(5);
/// The bound on one refresh.
pub const ADMIN_DEFAULTS_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// `ManySettingReader`: reads several server settings in one query.
pub trait ManySettingReader: Send + Sync {
    fn get_many<'a>(
        &'a self,
        keys: &'a [String],
    ) -> BoxFuture<'a, Result<SettingsMap, SettingError>>;
}

#[derive(Clone)]
struct Snapshot {
    values: Arc<SettingsMap>,
    expires: Instant,
}

struct Refresh {
    inflight: Option<watch::Sender<bool>>,
    retry_at: Option<Instant>,
    started: u64,
    fence: u64,
}

struct Inner {
    settings: Option<Arc<dyn ManySettingReader>>,
    keys: Vec<String>,
    known: HashSet<String>,
    ttl: Duration,
    snapshot: RwLock<Option<Snapshot>>,
    mu: Mutex<Refresh>,
    reads: AtomicU64,
}

/// `AdminDefaults`: the administrator's defaults for every setting the contract marks
/// `admin_default`, from one per-node snapshot. A fresh snapshot is read without taking the refresh
/// lock, at most one refresh runs at a time, an expired snapshot is refreshed in the background while
/// callers keep it, and a failed refresh keeps the last snapshot and retries after the delay.
#[derive(Clone)]
pub struct AdminDefaults {
    inner: Arc<Inner>,
}

impl AdminDefaults {
    /// Binds the snapshot to a settings reader. No reader answers every key with "".
    pub fn new(settings: Option<Arc<dyn ManySettingReader>>) -> Self {
        Self::with_ttl(settings, ADMIN_DEFAULTS_CACHE_TTL)
    }

    /// As [`AdminDefaults::new`] with another TTL.
    pub fn with_ttl(settings: Option<Arc<dyn ManySettingReader>>, ttl: Duration) -> Self {
        let mut keys = Vec::new();
        let mut known = HashSet::new();
        match load() {
            Err(error) => {
                tracing::error!(component = "config", error = %error,
                    "administrator defaults disabled: loading the settings contract failed");
            }
            Ok(contract) => {
                for def in &contract.definitions {
                    if def.admin_default {
                        let key = admin_default_setting_key(&def.key);
                        known.insert(key.clone());
                        keys.push(key);
                    }
                }
            }
        }
        AdminDefaults {
            inner: Arc::new(Inner {
                settings,
                keys,
                known,
                ttl,
                snapshot: RwLock::new(None),
                mu: Mutex::new(Refresh {
                    inflight: None,
                    retry_at: None,
                    started: 0,
                    fence: 0,
                }),
                reads: AtomicU64::new(0),
            }),
        }
    }

    fn snapshot(&self) -> Option<Snapshot> {
        self.inner
            .snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The stored default for a key such as `defaults.ui.next_up_mode`, or "" when none is set. An
    /// unreadable snapshot answers with the last one read, and before any read succeeds, with "".
    pub async fn get(&self, key: &str) -> String {
        if self.inner.settings.is_none() || !self.inner.known.contains(key) {
            return String::new();
        }
        let now = Instant::now();
        let current = self.snapshot();
        if let Some(s) = &current
            && now < s.expires
        {
            return s.values.get(key).cloned().unwrap_or_default();
        }
        let mut wait = None;
        let mut generation = 0u64;
        {
            let mut r = self.inner.mu.lock().unwrap_or_else(|e| e.into_inner());
            let snap = self.snapshot();
            if let Some(s) = &snap
                && now < s.expires
            {
                return s.values.get(key).cloned().unwrap_or_default();
            }
            if let Some(tx) = &r.inflight {
                wait = Some(tx.subscribe());
            } else if r.retry_at.is_none_or(|t| now >= t) {
                generation = Self::begin_locked(&mut r);
            }
        }
        if let Some(s) = self.snapshot() {
            if generation != 0 {
                let this = self.clone();
                tokio::spawn(async move { this.read(generation).await });
            }
            return s.values.get(key).cloned().unwrap_or_default();
        }
        if generation != 0 {
            self.read(generation).await;
        } else if let Some(mut rx) = wait {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
        self.snapshot()
            .and_then(|s| s.values.get(key).cloned())
            .unwrap_or_default()
    }

    /// Reloads the snapshot when the key holds an administrator default, waiting for the read. Reads
    /// that began earlier can no longer publish, and if this read fails the next request retries.
    pub async fn changed(&self, server_setting_key: &str) {
        if self.inner.settings.is_none() || !self.inner.known.contains(server_setting_key) {
            return;
        }
        let generation;
        {
            let mut r = self.inner.mu.lock().unwrap_or_else(|e| e.into_inner());
            generation = Self::begin_locked(&mut r);
            r.fence = generation;
            r.retry_at = None;
        }
        self.read(generation).await;
    }

    /// Refreshes the snapshot every half TTL, so a node that missed another node's change event
    /// serves the new default within the TTL even while idle. Stop it by dropping the future.
    pub async fn run(&self) {
        if self.inner.settings.is_none() || self.inner.keys.is_empty() {
            return;
        }
        let mut ticker = tokio::time::interval(self.inner.ttl / 2);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let generation;
            {
                let mut r = self.inner.mu.lock().unwrap_or_else(|e| e.into_inner());
                if r.inflight.is_some() {
                    continue;
                }
                generation = Self::begin_locked(&mut r);
            }
            self.read(generation).await;
        }
    }

    fn begin_locked(r: &mut Refresh) -> u64 {
        r.started += 1;
        if r.inflight.is_none() {
            let (tx, _) = watch::channel(false);
            r.inflight = Some(tx);
        }
        r.started
    }

    async fn read(&self, generation: u64) {
        let settings = self.inner.settings.as_ref().map(Arc::clone);
        let Some(settings) = settings else {
            return;
        };
        self.inner.reads.fetch_add(1, Ordering::Relaxed);
        let outcome = tokio::time::timeout(
            ADMIN_DEFAULTS_READ_TIMEOUT,
            settings.get_many(&self.inner.keys),
        )
        .await;
        let outcome = match outcome {
            Ok(result) => result,
            Err(_) => Err("context deadline exceeded".into()),
        };
        let mut r = self.inner.mu.lock().unwrap_or_else(|e| e.into_inner());
        self.publish(&mut r, generation, outcome);
        if generation == r.started
            && let Some(tx) = r.inflight.take()
        {
            let _ = tx.send(true);
        }
    }

    fn publish(
        &self,
        r: &mut Refresh,
        generation: u64,
        outcome: Result<SettingsMap, SettingError>,
    ) {
        if generation < r.fence {
            return;
        }
        match outcome {
            Err(error) => {
                tracing::warn!(component = "config", error = %error,
                    "keeping the last administrator defaults: reading them failed");
                let retry = Instant::now() + ADMIN_DEFAULTS_RETRY_DELAY;
                r.retry_at = Some(retry);
                if generation == r.fence {
                    let mut snap = self
                        .inner
                        .snapshot
                        .write()
                        .unwrap_or_else(|e| e.into_inner());
                    if let Some(s) = snap.as_mut() {
                        s.expires = retry;
                    }
                }
            }
            Ok(values) => {
                r.fence = generation;
                let mut snap = self
                    .inner
                    .snapshot
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                *snap = Some(Snapshot {
                    values: Arc::new(values),
                    expires: Instant::now() + self.inner.ttl,
                });
            }
        }
    }
}

impl crate::resolve::ServerSettings for AdminDefaults {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<String, crate::resolve::ReadError>> {
        Box::pin(async move { Ok(AdminDefaults::get(self, key).await) })
    }
}
