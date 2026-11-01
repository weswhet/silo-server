//! Server lifecycle that a single reply cannot show: `Shutdown`. Go's reply carries `Connection: close`
//! once shutdown has started, and an idle connection is dropped without one.

use std::time::Duration;

use silo_http::{Server, ServerConfig, handler_fn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

#[tokio::test]
async fn shutdown_closes_idle_connections_and_finishes_active_ones() {
    let release = std::sync::Arc::new(Notify::new());
    let entered = std::sync::Arc::new(Notify::new());
    let (r2, e2) = (release.clone(), entered.clone());
    let handler = handler_fn(move |w, _r| {
        let (release, entered) = (r2.clone(), e2.clone());
        Box::pin(async move {
            entered.notify_one();
            release.notified().await;
            let _ = w.write(b"done").await;
        })
    });
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    let srv = Server::new(handler, ServerConfig::default());
    let serving = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.serve(ln).await })
    };

    let mut idle = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    idle.write_all(b"GET /first HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    entered.notified().await;
    release.notify_one();
    let mut buf = vec![0u8; 1024];
    let n = idle.read(&mut buf).await.unwrap();
    assert!(n > 0 && buf.starts_with(b"HTTP/1.1 200 OK\r\n"));

    let mut active = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    active
        .write_all(b"GET /second HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    entered.notified().await;

    let stopping = {
        let srv = srv.clone();
        tokio::spawn(async move { srv.shutdown().await })
    };

    // The idle connection goes away with nothing more on it.
    let n = tokio::time::timeout(Duration::from_secs(5), idle.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);

    // The active one still gets its reply, marked as the last on this connection.
    release.notify_one();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), active.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&reply);
    assert!(text.contains("\r\nConnection: close\r\n"), "{text}");
    assert!(text.ends_with("done"), "{text}");

    tokio::time::timeout(Duration::from_secs(5), stopping)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
