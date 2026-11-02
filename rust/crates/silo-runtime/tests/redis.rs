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

/// Needs `rust/conformance/harness/redis-sentinel/compose.yml` running, with
/// `SILO_RUNTIME_TEST_SENTINEL_URL=redis://127.0.0.1:26482/0?master_name=silomaster` and
/// `SILO_RUNTIME_TEST_SENTINEL_NODES=127.0.0.1:26480,127.0.0.1:26481`. Quiet periods must keep the
/// subscription's connection, and a real failover must move it to the new master.
#[tokio::test]
async fn sentinel_subscription_stays_on_its_connection_and_follows_a_failover() {
    let (Ok(url), Ok(nodes)) = (
        std::env::var("SILO_RUNTIME_TEST_SENTINEL_URL"),
        std::env::var("SILO_RUNTIME_TEST_SENTINEL_NODES"),
    ) else {
        eprintln!("SILO_RUNTIME_TEST_SENTINEL_URL is not set; skipping");
        return;
    };
    let cfg = RedisConfig {
        url: url.clone(),
        db: String::new(),
    };
    async fn connections_received(nodes: &str) -> i64 {
        let mut total = 0;
        for node in nodes.split(',') {
            let client = redis::Client::open(format!("redis://{node}/")).unwrap();
            let mut conn = client.get_multiplexed_async_connection().await.unwrap();
            let info: String = redis::cmd("INFO")
                .arg("stats")
                .query_async(&mut conn)
                .await
                .unwrap();
            total += info
                .lines()
                .find_map(|l| l.strip_prefix("total_connections_received:"))
                .unwrap()
                .trim()
                .parse::<i64>()
                .unwrap();
        }
        total
    }

    let subscriber = cache::event_bus::new_event_bus(&cfg);
    let publisher = cache::event_bus::new_event_bus(&cfg);
    let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);
    subscriber
        .subscribe(
            "silo:sentinel-test",
            Arc::new(move |event| sink.lock().unwrap().push(event.payload)),
        )
        .await
        .unwrap();
    let publish = |payload: String| {
        let event = Event {
            event_type: "t".to_owned(),
            payload,
        };
        let publisher = &publisher;
        async move { publisher.publish("silo:sentinel-test", event).await }
    };
    publish("before".to_owned()).await.unwrap();

    // More than three ping intervals of silence. Only this test's own INFO connections may appear:
    // the old loop opened one more connection on every tick.
    let start = connections_received(&nodes).await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    let opened = connections_received(&nodes).await - start;
    assert!(
        opened <= 2,
        "a quiet subscription must not redial; saw {opened} new connections"
    );

    // Messages published across those pings all arrive.
    for i in 0..200 {
        publish(format!("quiet-{i}")).await.unwrap();
    }
    for _ in 0..200 {
        if received.lock().unwrap().len() >= 201 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(received.lock().unwrap().len(), 201);

    // Failover, then wait until a published message reaches the old subscription's handler.
    let sentinel = redis::Client::open(url.split('?').next().unwrap().to_owned()).unwrap();
    let mut conn = sentinel.get_multiplexed_async_connection().await.unwrap();
    let _: String = redis::cmd("SENTINEL")
        .arg("FAILOVER")
        .arg("silomaster")
        .query_async(&mut conn)
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    let mut followed = false;
    let mut n = 0;
    while std::time::Instant::now() < deadline && !followed {
        n += 1;
        let marker = format!("after-{n}");
        let _ = publish(marker.clone()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        followed = received.lock().unwrap().contains(&marker);
        if followed {
            let client =
                redis::Client::open(format!("redis://{}/", nodes.split(',').next().unwrap()))
                    .unwrap();
            let mut old = client.get_multiplexed_async_connection().await.unwrap();
            let role: Vec<redis::Value> = redis::cmd("ROLE").query_async(&mut old).await.unwrap();
            // Delivery before the role change proves nothing about following the new master.
            followed = matches!(&role[0], redis::Value::BulkString(b) if b == b"slave");
        }
    }
    assert!(
        followed,
        "the subscription never received events after the failover"
    );
    subscriber.close().await.unwrap();
    publisher.close().await.unwrap();
}
