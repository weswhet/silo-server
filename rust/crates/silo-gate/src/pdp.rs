//! `policy.PDP` and `policy.DecisionLogger`: typed decisions over the live engines, logged to
//! `policy_decisions` off the request path.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use sha2::{Digest, Sha256};
use silo_pg::{Pool, ToSql};
use tokio::sync::mpsc;

use crate::policy::{
    Domain, Engine, EvalError, PermissionDecision, PermissionInput, ScopeDecision, ScopeInput,
};

/// `DecisionName`.
pub const DECISION_SCOPE: &str = "silo.scope.decision";
pub const DECISION_PERMISSION: &str = "silo.permission.decision";

const BUFFER_SIZE: usize = 1024;
const BATCH_SIZE: usize = 128;
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_SCOPE_SAMPLE_RATE: u64 = 50;

/// `policy.Entry`.
#[derive(Clone, Debug)]
pub struct Entry {
    pub timestamp: SystemTime,
    pub decision_name: &'static str,
    pub policy_generation: i64,
    pub user_id: i64,
    pub profile_id: String,
    pub session_id: String,
    pub request_id: String,
    pub node_id: String,
    pub allowed: Option<bool>,
    pub eval_time_ns: i64,
    pub input_digest: String,
    pub input_sample: Option<String>,
    pub result_sample: Option<String>,
    pub error: String,
}

/// `policy.DecisionLogger`. A full queue drops the entry and counts it.
pub struct DecisionLogger {
    node_id: String,
    tx: mpsc::Sender<Entry>,
    verbose: std::sync::atomic::AtomicBool,
    sample_rate: AtomicU64,
    counter: AtomicU64,
    dropped: AtomicU64,
}

impl DecisionLogger {
    /// `NewDecisionLogger` and `Start`.
    pub fn start(pool: Arc<Pool>, node_id: String) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(BUFFER_SIZE);
        tokio::spawn(run(pool, rx));
        Arc::new(Self {
            node_id,
            tx,
            verbose: false.into(),
            sample_rate: DEFAULT_SCOPE_SAMPLE_RATE.into(),
            counter: 0.into(),
            dropped: 0.into(),
        })
    }

    /// `SetVerbosity`: anything but `verbose` is digest mode.
    pub fn set_verbosity(&self, value: &str) {
        let lower = silo_gocompat::strings::to_lower(silo_gocompat::strings::trim_space(value));
        self.verbose.store(lower == "verbose", Ordering::Relaxed);
    }

    /// `SetScopeSampleRate`: at most one logs every scope decision.
    pub fn set_scope_sample_rate(&self, rate: i64) {
        self.sample_rate
            .store(u64::try_from(rate).unwrap_or(1).max(1), Ordering::Relaxed);
    }

    /// `DroppedCount`.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// `shouldLog`.
    fn should_log(&self, name: &str, allowed: Option<bool>, error: &str) -> bool {
        if !error.is_empty() || allowed == Some(false) || name != DECISION_SCOPE {
            return true;
        }
        let rate = self.sample_rate.load(Ordering::Relaxed);
        rate <= 1
            || self
                .counter
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(rate)
    }

    /// `LogDecision`. It does no I/O and never blocks on the database.
    fn log<I: Serialize, R: Serialize>(&self, mut entry: Entry, input: &I, result: Option<&R>) {
        if !self.should_log(entry.decision_name, entry.allowed, &entry.error) {
            return;
        }
        let raw = silo_gocompat::json::marshal(input).unwrap_or_else(|e| {
            if entry.error.is_empty() {
                entry.error = format!("marshal policy input for decision log: {e}");
            }
            b"null".to_vec()
        });
        entry.input_digest = digest(&raw);
        if self.verbose.load(Ordering::Relaxed) {
            entry.input_sample = Some(String::from_utf8_lossy(&raw).into_owned());
            entry.result_sample = result
                .and_then(|r| silo_gocompat::json::marshal(r).ok())
                .map(|r| String::from_utf8_lossy(&r).into_owned());
        }
        entry.timestamp = SystemTime::now();
        entry.node_id.clone_from(&self.node_id);
        if self.tx.try_send(entry).is_err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                tracing::warn!(
                    component = "policy.decisionlog",
                    dropped,
                    "policy decision log buffer full; dropping entries"
                );
            }
        }
    }
}

/// `digestBytes`.
pub fn digest(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn run(pool: Arc<Pool>, mut rx: mpsc::Receiver<Entry>) {
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut tick = tokio::time::interval(FLUSH_INTERVAL);
    loop {
        tokio::select! {
            entry = rx.recv() => {
                let Some(entry) = entry else { break };
                batch.push(entry);
                if batch.len() >= BATCH_SIZE {
                    flush(&pool, &mut batch).await;
                }
            }
            _ = tick.tick() => flush(&pool, &mut batch).await,
        }
    }
    flush(&pool, &mut batch).await;
}

async fn flush(pool: &Pool, batch: &mut Vec<Entry>) {
    if batch.is_empty() {
        return;
    }
    if let Err(e) = insert(pool, batch).await {
        tracing::warn!(component = "policy.decisionlog", entries = batch.len(), error = %e, "policy decision log batch insert failed");
    }
    batch.clear();
}

/// `nullableString`.
fn nullable(text: &str) -> Option<&str> {
    (!text.is_empty()).then_some(text)
}

async fn insert(pool: &Pool, entries: &[Entry]) -> Result<(), silo_pg::Error> {
    let mut sql = String::from(
        r#"INSERT INTO policy_decisions ("timestamp", decision_name, policy_generation, user_id, profile_id, session_id, request_id, node_id, allowed, eval_time_ns, input_digest, input_sample, result_sample, error) VALUES "#,
    );
    struct Row<'a> {
        name: &'a str,
        profile: Option<&'a str>,
        session: Option<&'a str>,
        request: Option<&'a str>,
        node: Option<&'a str>,
        error: Option<&'a str>,
    }
    let rows: Vec<Row<'_>> = entries
        .iter()
        .map(|e| Row {
            name: e.decision_name,
            profile: nullable(&e.profile_id),
            session: nullable(&e.session_id),
            request: nullable(&e.request_id),
            node: nullable(&e.node_id),
            error: nullable(&e.error),
        })
        .collect();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(entries.len() * 14);
    for (i, (e, row)) in entries.iter().zip(&rows).enumerate() {
        if i > 0 {
            sql.push_str(", ");
        }
        let b = i * 14;
        sql.push_str(&format!(
            "(${}::timestamptz, ${}::text, ${}::bigint, ${}::bigint, ${}::text, ${}::text, ${}::text, ${}::text, ${}::boolean, ${}::bigint, ${}::text, ${}::text::jsonb, ${}::text::jsonb, ${}::text)",
            b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7, b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14
        ));
        params.extend_from_slice(&[
            &e.timestamp,
            &row.name,
            &e.policy_generation,
            &e.user_id,
            &row.profile,
            &row.session,
            &row.request,
            &row.node,
            &e.allowed,
            &e.eval_time_ns,
            &e.input_digest,
            &e.input_sample,
            &e.result_sample,
            &row.error,
        ]);
    }
    pool.execute(&sql, &params).await.map(|_| ())
}

/// `policy.PDP` over the live engines. An evaluation mutates its engine, so each decision has its own
/// lock and a slow permission check does not hold up viewer scopes.
pub struct Pdp {
    scope: Arc<Mutex<Engine>>,
    permission: Arc<Mutex<Engine>>,
    generation: AtomicI64,
    logger: Option<Arc<DecisionLogger>>,
}

fn lock(engine: &Mutex<Engine>) -> std::sync::MutexGuard<'_, Engine> {
    engine.lock().unwrap_or_else(|e| e.into_inner())
}

async fn evaluate<T: serde::de::DeserializeOwned + Send + 'static>(
    engine: Arc<Mutex<Engine>>,
    domain: Domain,
    value: serde_json::Value,
) -> Result<T, EvalError> {
    tokio::task::spawn_blocking(move || lock(&engine).evaluate::<T>(domain, &value))
        .await
        .map_err(|e| EvalError::Decode(e.to_string()))?
}

impl Pdp {
    /// `NewPDP`. The two engines hold the same sources.
    pub fn new(
        scope: Engine,
        permission: Engine,
        generation: i64,
        logger: Option<Arc<DecisionLogger>>,
    ) -> Self {
        Self {
            scope: Arc::new(Mutex::new(scope)),
            permission: Arc::new(Mutex::new(permission)),
            generation: generation.into(),
            logger,
        }
    }

    /// The vendor policy alone and no decision log.
    pub fn vendor() -> Result<Self, EvalError> {
        Ok(Self::new(Engine::new()?, Engine::new()?, 0, None))
    }

    /// `Engine.Reload`'s swap.
    pub fn swap(&self, scope: Engine, permission: Engine, generation: i64) {
        *lock(&self.scope) = scope;
        *lock(&self.permission) = permission;
        self.generation.store(generation, Ordering::Relaxed);
    }

    /// The store moved on with the same sources.
    pub fn set_generation(&self, generation: i64) {
        self.generation.store(generation, Ordering::Relaxed);
    }

    /// `Revision`.
    pub fn generation(&self) -> i64 {
        self.generation.load(Ordering::Relaxed)
    }

    fn entry(&self, name: &'static str, user_id: i64, request_id: &str, started: Instant) -> Entry {
        Entry {
            timestamp: SystemTime::UNIX_EPOCH,
            decision_name: name,
            policy_generation: self.generation(),
            user_id,
            profile_id: String::new(),
            session_id: String::new(),
            request_id: request_id.to_owned(),
            node_id: String::new(),
            allowed: None,
            eval_time_ns: i64::try_from(started.elapsed().as_nanos()).unwrap_or(i64::MAX),
            input_digest: String::new(),
            input_sample: None,
            result_sample: None,
            error: String::new(),
        }
    }

    /// `ResolveViewerScope`. Regorus is CPU work, so it runs off the async workers.
    pub async fn resolve_viewer_scope(
        &self,
        input: &ScopeInput,
        request_id: &str,
    ) -> Result<ScopeDecision, EvalError> {
        let value = serde_json::to_value(input).map_err(|e| EvalError::Decode(e.to_string()))?;
        let started = Instant::now();
        let result: Result<ScopeDecision, _> =
            evaluate(self.scope.clone(), Domain::Scope, value).await;
        if let Some(logger) = &self.logger {
            let mut entry = self.entry(DECISION_SCOPE, input.user_id, request_id, started);
            entry.profile_id.clone_from(&input.profile_id);
            entry.session_id.clone_from(&input.session_id);
            if let Err(e) = &result {
                entry.error = e.to_string();
            }
            logger.log(entry, input, result.as_ref().ok());
        }
        result
    }

    /// `CheckPermission`.
    pub async fn check_permission(
        &self,
        input: &PermissionInput,
        request_id: &str,
    ) -> Result<PermissionDecision, EvalError> {
        let value = serde_json::to_value(input).map_err(|e| EvalError::Decode(e.to_string()))?;
        let started = Instant::now();
        let result: Result<PermissionDecision, _> =
            evaluate(self.permission.clone(), Domain::Permission, value).await;
        if let Some(logger) = &self.logger {
            let mut entry = self.entry(DECISION_PERMISSION, input.user_id, request_id, started);
            entry.profile_id.clone_from(&input.declared_profile_id);
            entry.allowed = result.as_ref().ok().map(|d| d.allowed);
            if let Err(e) = &result {
                entry.error = e.to_string();
            }
            logger.log(entry, input, result.as_ref().ok());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logger(rate: i64) -> (Arc<DecisionLogger>, mpsc::Receiver<Entry>) {
        let (tx, rx) = mpsc::channel(8);
        let logger = Arc::new(DecisionLogger {
            node_id: "n".to_owned(),
            tx,
            verbose: false.into(),
            sample_rate: DEFAULT_SCOPE_SAMPLE_RATE.into(),
            counter: 0.into(),
            dropped: 0.into(),
        });
        logger.set_scope_sample_rate(rate);
        (logger, rx)
    }

    /// The first of each sample window, and never a refusal or an error's sample.
    #[tokio::test]
    async fn samples_scope_but_not_refusals() {
        let (log, mut rx) = logger(3);
        let pdp = Pdp::new(
            Engine::new().unwrap(),
            Engine::new().unwrap(),
            7,
            Some(log.clone()),
        );
        let input = ScopeInput {
            schema_version: 1,
            user_id: 2,
            profile_verified: true,
            ..ScopeInput::default()
        };
        for _ in 0..6 {
            pdp.resolve_viewer_scope(&input, "req").await.unwrap();
        }
        let mut seen = Vec::new();
        while let Ok(entry) = rx.try_recv() {
            seen.push(entry);
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].policy_generation, 7);
        assert_eq!(seen[0].request_id, "req");
        assert_eq!(seen[0].node_id, "n");
        assert_eq!(seen[0].decision_name, DECISION_SCOPE);
        assert_eq!(seen[0].input_digest.len(), 64);
        assert!(seen[0].input_sample.is_none());

        let permission = PermissionInput {
            schema_version: 1,
            permission: "nonsense".to_owned(),
            ..PermissionInput::default()
        };
        let denied = pdp.check_permission(&permission, "req").await.unwrap();
        assert!(!denied.allowed);
        let entry = rx.try_recv().expect("a refusal is always logged");
        assert_eq!(entry.allowed, Some(false));

        log.set_verbosity(" VERBOSE ");
        log.set_scope_sample_rate(1);
        pdp.resolve_viewer_scope(&input, "req").await.unwrap();
        let entry = rx.try_recv().expect("rate one logs every decision");
        assert!(entry.input_sample.is_some() && entry.result_sample.is_some());
    }

    /// `json.Marshal(ScopeInput)`, the digest's input, from the real type.
    #[test]
    fn scope_input_marshals_like_go() {
        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/access/access.json"
        ))
        .unwrap();
        let data: serde_json::Value = silo_gocompat::json::unmarshal(&raw).unwrap();
        let input = ScopeInput {
            schema_version: 1,
            user_id: 2,
            session_id: "s".to_owned(),
            profile_id: "p".to_owned(),
            request_time: "2026-01-02T03:04:05Z".to_owned(),
            ..ScopeInput::default()
        };
        assert_eq!(
            String::from_utf8(silo_gocompat::json::marshal(&input).unwrap()).unwrap(),
            data["scope_input"].as_str().unwrap()
        );
    }
}
