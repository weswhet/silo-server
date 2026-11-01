//! One server setting, parsed, served from a per-node cache.

use super::BoxFuture;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

/// The error a settings reader returns.
pub type SettingError = Box<dyn std::error::Error + Send + Sync>;

/// `SettingReader`: reads one server setting by key.
pub trait SettingReader: Send + Sync {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<String, SettingError>>;
}

struct State<T> {
    value: Option<T>,
    expires: Option<Instant>,
    started: u64,
    published: u64,
}

/// `CachedSetting`: a successful read is cached for the TTL. A failed read answers with the value
/// last read successfully, or the parse of "" when none has been, and is not cached. The lock guards
/// only the cached value, so a slow database stalls the callers that need a fresh value rather than
/// queueing every caller behind one query.
pub struct CachedSetting<T> {
    settings: Option<Arc<dyn SettingReader>>,
    key: String,
    ttl: Duration,
    parse: Box<dyn Fn(&str) -> T + Send + Sync>,
    state: Mutex<State<T>>,
}

impl<T: Clone> CachedSetting<T> {
    /// Binds a cached read of `key` to a settings reader. No reader answers with the parse of "".
    pub fn new(
        settings: Option<Arc<dyn SettingReader>>,
        key: &str,
        ttl: Duration,
        parse: impl Fn(&str) -> T + Send + Sync + 'static,
    ) -> Self {
        CachedSetting {
            settings,
            key: key.to_owned(),
            ttl,
            parse: Box::new(parse),
            state: Mutex::new(State {
                value: None,
                expires: None,
                started: 0,
                published: 0,
            }),
        }
    }

    /// The parsed setting.
    pub async fn get(&self) -> T {
        let Some(settings) = &self.settings else {
            return (self.parse)("");
        };
        let generation;
        {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let (Some(v), Some(exp)) = (&s.value, s.expires)
                && Instant::now() < exp
            {
                return v.clone();
            }
            s.started += 1;
            generation = s.started;
        }
        let raw = match settings.get(&self.key).await {
            Ok(raw) => raw,
            Err(_) => {
                let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                return match &s.value {
                    Some(v) => v.clone(),
                    None => (self.parse)(""),
                };
            }
        };
        let value = (self.parse)(&raw);
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if generation < s.published
            && let Some(v) = &s.value
        {
            return v.clone();
        }
        s.value = Some(value.clone());
        s.published = generation;
        s.expires = Some(Instant::now() + self.ttl);
        value
    }
}
