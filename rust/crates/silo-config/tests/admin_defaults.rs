//! The behavior `internal/config/admin_defaults_test.go` and `cached_setting_test.go` pin down: read
//! coalescing, refresh in the background, back-off, and the fence around an admin write.

use silo_config::config::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

const NEXT_UP: &str = "defaults.ui.next_up_mode";
const NEW_RELEASES: &str = "defaults.ui.next_up_new_releases_first";

type ReadResult = Result<HashMap<String, String>, String>;

#[derive(Default)]
struct Fake {
    values: Mutex<HashMap<String, String>>,
    fail: Mutex<bool>,
    per_call: Mutex<HashMap<u32, ReadResult>>,
    gates: Mutex<HashMap<u32, Arc<Notify>>>,
    calls: AtomicU32,
    keys: Mutex<Vec<String>>,
}

impl Fake {
    fn with(pairs: &[(&str, &str)]) -> Arc<Fake> {
        let f = Fake::default();
        *f.values.lock().unwrap() = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Arc::new(f)
    }

    fn set(&self, k: &str, v: &str) {
        self.values
            .lock()
            .unwrap()
            .insert(k.to_owned(), v.to_owned());
    }

    fn gate(&self, call: u32) -> Arc<Notify> {
        let n = Arc::new(Notify::new());
        self.gates.lock().unwrap().insert(call, n.clone());
        n
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ManySettingReader for Fake {
    fn get_many<'a>(
        &'a self,
        keys: &'a [String],
    ) -> BoxFuture<'a, Result<SettingsMap, SettingError>> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let gate = self.gates.lock().unwrap().get(&call).cloned();
            if let Some(gate) = gate {
                gate.notified().await;
            }
            *self.keys.lock().unwrap() = keys.to_vec();
            if let Some(r) = self.per_call.lock().unwrap().remove(&call) {
                return r.map_err(Into::into);
            }
            if *self.fail.lock().unwrap() {
                return Err("db down".into());
            }
            let values = self.values.lock().unwrap();
            Ok(keys
                .iter()
                .filter_map(|k| values.get(k).map(|v| (k.clone(), v.clone())))
                .collect())
        })
    }
}

async fn eventually(mut f: impl FnMut() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("condition never held");
}

#[tokio::test(start_paused = true)]
async fn one_query_per_ttl_and_expired_snapshots_answer_while_refreshing() {
    let fake = Fake::with(&[(NEXT_UP, r#""separate""#), (NEW_RELEASES, "true")]);
    let a = AdminDefaults::new(Some(fake.clone()));
    for _ in 0..3 {
        assert_eq!(a.get(NEXT_UP).await, r#""separate""#);
        assert_eq!(a.get(NEW_RELEASES).await, "true");
    }
    assert_eq!(fake.calls(), 1);
    for want in [NEXT_UP, NEW_RELEASES, "defaults.ui.title_art"] {
        assert!(
            fake.keys.lock().unwrap().iter().any(|k| k == want),
            "query missed {want}"
        );
    }

    fake.set(NEXT_UP, r#""combined""#);
    tokio::time::advance(ADMIN_DEFAULTS_CACHE_TTL).await;
    assert_eq!(
        a.get(NEXT_UP).await,
        r#""separate""#,
        "the expired snapshot answers while refreshing"
    );
    eventually(|| fake.calls() == 2).await;
    tokio::task::yield_now().await;
    let mut settled = String::new();
    for _ in 0..50 {
        tokio::task::yield_now().await;
        settled = a.get(NEXT_UP).await;
        if settled == r#""combined""# {
            break;
        }
    }
    assert_eq!(settled, r#""combined""#);

    assert_eq!(
        a.get("defaults.ui.theme").await,
        "",
        "a key holding no administrator default is never read"
    );
    assert_eq!(fake.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_failed_refresh_keeps_the_snapshot_and_backs_off() {
    let fake = Fake::with(&[(NEXT_UP, r#""separate""#)]);
    let a = AdminDefaults::new(Some(fake.clone()));
    a.get(NEXT_UP).await;
    *fake.fail.lock().unwrap() = true;
    tokio::time::advance(ADMIN_DEFAULTS_CACHE_TTL).await;
    a.get(NEXT_UP).await;
    eventually(|| fake.calls() == 2).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    for _ in 0..5 {
        assert_eq!(a.get(NEXT_UP).await, r#""separate""#);
    }
    assert_eq!(
        fake.calls(),
        2,
        "one failed refresh per delay, not one per request"
    );
    tokio::time::advance(ADMIN_DEFAULTS_RETRY_DELAY).await;
    a.get(NEXT_UP).await;
    eventually(|| fake.calls() == 3).await;
}

#[tokio::test(start_paused = true)]
async fn concurrent_first_reads_share_one_query() {
    let fake = Fake::with(&[(NEXT_UP, r#""separate""#)]);
    let a = AdminDefaults::new(Some(fake.clone()));
    let release = fake.gate(1);
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let a = a.clone();
        tasks.push(tokio::spawn(async move { a.get(NEXT_UP).await }));
    }
    eventually(|| fake.calls() == 1).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    release.notify_one();
    for t in tasks {
        assert_eq!(t.await.unwrap(), r#""separate""#);
    }
    assert_eq!(fake.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn an_admin_write_fences_off_older_reads_even_when_it_fails() {
    let fake = Fake::with(&[(NEW_RELEASES, "false")]);
    let a = AdminDefaults::new(Some(fake.clone()));
    a.get(NEW_RELEASES).await;

    tokio::time::advance(ADMIN_DEFAULTS_CACHE_TTL).await;
    let slow = fake.gate(2);
    a.get(NEW_RELEASES).await;
    eventually(|| fake.calls() == 2).await;
    fake.per_call.lock().unwrap().insert(
        2,
        Ok([(NEW_RELEASES.to_owned(), "false".to_owned())]
            .into_iter()
            .collect()),
    );
    fake.per_call
        .lock()
        .unwrap()
        .insert(3, Err("pool timeout".to_owned()));

    a.changed(NEW_RELEASES).await;
    slow.notify_one();
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }

    fake.set(NEW_RELEASES, "true");
    tokio::time::advance(ADMIN_DEFAULTS_RETRY_DELAY).await;
    a.get(NEW_RELEASES).await;
    eventually(|| fake.calls() == 4).await;
    let mut settled = String::new();
    for _ in 0..50 {
        tokio::task::yield_now().await;
        settled = a.get(NEW_RELEASES).await;
        if settled == "true" {
            break;
        }
    }
    assert_eq!(
        settled, "true",
        "the fenced read must not have published with a full TTL"
    );

    a.changed("server.name").await;
    assert_eq!(
        fake.calls(),
        4,
        "a key with no administrator default reads nothing"
    );
}

#[tokio::test(start_paused = true)]
async fn an_admin_write_is_visible_to_the_next_request() {
    let fake = Fake::with(&[(NEW_RELEASES, "false")]);
    let a = AdminDefaults::new(Some(fake.clone()));
    a.get(NEW_RELEASES).await;
    fake.set(NEW_RELEASES, "true");
    a.changed(NEW_RELEASES).await;
    assert_eq!(a.get(NEW_RELEASES).await, "true");
}

#[tokio::test(start_paused = true)]
async fn run_refreshes_a_node_that_serves_no_requests() {
    let fake = Fake::with(&[(NEXT_UP, r#""combined""#)]);
    let a = AdminDefaults::with_ttl(Some(fake.clone()), Duration::from_millis(40));
    a.get(NEXT_UP).await;
    fake.set(NEXT_UP, r#""separate""#);
    let runner = a.clone();
    let task = tokio::spawn(async move { runner.run().await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    eventually(|| fake.calls() >= 2).await;
    assert_eq!(a.get(NEXT_UP).await, r#""separate""#);
    task.abort();
}

#[tokio::test]
async fn no_reader_answers_empty() {
    let a = AdminDefaults::new(None);
    assert_eq!(a.get(NEXT_UP).await, "");
    a.changed(NEXT_UP).await;
    a.run().await;
}

struct Single {
    value: Mutex<Result<String, String>>,
    calls: AtomicU32,
}

impl SettingReader for Single {
    fn get<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<String, SettingError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let v = self.value.lock().unwrap().clone();
        Box::pin(async move { v.map_err(Into::into) })
    }
}

#[tokio::test(start_paused = true)]
async fn cached_setting_serves_the_last_good_value_through_a_failure() {
    let reader = Arc::new(Single {
        value: Mutex::new(Ok("allow".to_owned())),
        calls: AtomicU32::new(0),
    });
    let policy = UnratedContentPolicy::new(Some(reader.clone()));
    assert!(policy.allow_unrated_content().await);
    assert!(policy.allow_unrated_content().await);
    assert_eq!(
        reader.calls.load(Ordering::SeqCst),
        1,
        "a fresh value is not read again"
    );

    *reader.value.lock().unwrap() = Err("timeout".to_owned());
    tokio::time::advance(UNRATED_CONTENT_CACHE_TTL).await;
    assert!(
        policy.allow_unrated_content().await,
        "one slow lookup must not flip the choice to hide"
    );
    assert_eq!(reader.calls.load(Ordering::SeqCst), 2);
    assert!(policy.allow_unrated_content().await);
    assert_eq!(
        reader.calls.load(Ordering::SeqCst),
        3,
        "a failed read is not cached"
    );

    *reader.value.lock().unwrap() = Ok(" HIDE ".to_owned());
    assert!(!policy.allow_unrated_content().await);

    let never = UnratedContentPolicy::new(Some(Arc::new(Single {
        value: Mutex::new(Err("down".to_owned())),
        calls: AtomicU32::new(0),
    })));
    assert!(
        !never.allow_unrated_content().await,
        "before any read succeeds, the parse of the empty string"
    );
    assert!(
        !UnratedContentPolicy::new(None)
            .allow_unrated_content()
            .await
    );
}
