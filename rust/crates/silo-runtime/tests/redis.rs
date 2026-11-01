//! Exercises the Redis client factory and event bus against a real Redis. Set
//! `SILO_RUNTIME_TEST_REDIS_URL` to run these.

use silo_config::config::RedisConfig;
use silo_core::redis::Event;
use silo_runtime::cache;
use silo_runtime::cache::event_bus::EventBus as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn test_url() -> Option<String> {
    std::env::var("SILO_RUNTIME_TEST_REDIS_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

macro_rules! cfg_or_skip {
    () => {{
        let Some(url) = test_url() else {
            eprintln!("SILO_RUNTIME_TEST_REDIS_URL is not set; skipping");
            return;
        };
        RedisConfig {
            url,
            db: String::new(),
        }
    }};
}

#[tokio::test]
async fn publish_and_subscribe_round_trip_with_go_compatible_json() {
    let cfg = cfg_or_skip!();
    let bus = cache::event_bus::new_event_bus(&cfg);

    let received: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received);
    bus.subscribe(
        silo_core::redis::CHANNEL_ADMIN,
        Arc::new(move |event| received_clone.lock().unwrap().push(event)),
    )
    .await
    .unwrap();

    // Give the background subscriber task a moment to finish its SUBSCRIBE round trip beyond the
    // one `subscribe()` itself already confirms, since the publish below opens a separate
    // connection and there is no shared ordering guarantee between the two sockets.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let event = Event {
        event_type: "user_disabled".to_owned(),
        payload: "42".to_owned(),
    };
    bus.publish(silo_core::redis::CHANNEL_ADMIN, event.clone())
        .await
        .unwrap();

    for _ in 0..50 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got = received.lock().unwrap().clone();
    assert_eq!(got, vec![event]);

    bus.close().await.unwrap();
}

#[tokio::test]
async fn noop_event_bus_never_touches_the_network() {
    let bus = cache::event_bus::NoopEventBus;
    bus.publish("silo:admin", Event::default()).await.unwrap();
    bus.subscribe("silo:admin", Arc::new(|_| {})).await.unwrap();
    bus.close().await.unwrap();
}

#[tokio::test]
async fn scoped_channel_for_a_nonzero_database_matches_go() {
    assert_eq!(silo_core::redis::channel("silo:admin", 0), "silo:admin");
    assert_eq!(silo_core::redis::channel("silo:admin", -1), "silo:admin");
    assert_eq!(silo_core::redis::channel("silo:admin", 3), "silo:admin@db3");
}
