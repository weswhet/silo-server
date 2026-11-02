//! The front against real Go and against scripted upstreams.
//!
//! - `spa_vectors`: native rows against bytes the real `internal/server` handler wrote.
//! - `forwarding_*`: the real `internal/clientip` resolves the same client on a direct connection and
//!   through the front. Needs `go` with the 1.26.7 toolchain.
//! - `relay_*`: what transparency means at the byte level, against an upstream that scripts its bytes.
//! - `reference_*`: raw comparison with a running Go server. Set `SILO_FRONT_TEST_REFERENCE` to
//!   `main_host:port,jellycompat_host:port,abs_host:port` and `DATABASE_URL`; without them they skip.

// Test paths are built from relative constants, where `Path::join` and Go's join agree.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::Engine;
use silo_front::frontend::{BrandingSource, WebDist};
use silo_front::http1::{RequestScan, scan_request};
use silo_front::native::{Gate, NativeInputs, main_handler};
use silo_front::{FrontConfig, FrontSpec, start};
use silo_http::{Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const WAIT: Duration = Duration::from_secs(10);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

fn temp_path(name: &str) -> PathBuf {
    let unique: u64 = rand_u64();
    std::env::temp_dir().join(format!("silo-front-{name}-{unique:x}"))
}

fn rand_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// `Date` changes between two runs of the same server, and nothing else in these answers may.
fn normalize_date(raw: &[u8]) -> Vec<u8> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);
    let (head, body) = raw.split_at(split);
    let mut out = Vec::with_capacity(raw.len());
    for line in head.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b"Date: ") {
            out.extend_from_slice(b"Date: <date>\r\n");
        } else {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(body);
    out
}

async fn read_to_end(stream: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut out)).await;
    out
}

#[tokio::test]
async fn spa_vectors_match_the_real_frontend_handler() {
    let path = repo_root().join("rust/conformance/vectors/front/spa.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("vectors")).expect("json");
    let files: Vec<(String, Vec<u8>)> = doc["files"]
        .as_object()
        .expect("files")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().expect("text").as_bytes().to_vec()))
        .collect();
    let branded: HashMap<String, String> = doc["branding"]
        .as_object()
        .expect("branding")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().expect("text").to_owned()))
        .collect();
    let inputs_for = |values: HashMap<String, String>| NativeInputs {
        identity: None,
        stack: None,
        spa: Some((
            WebDist::from_files(files.clone()),
            BrandingSource::Fixed(values),
        )),
    };
    let plain = inputs_for(HashMap::new());
    let plain_server = Server::new(main_handler(&plain), ServerConfig::default());
    let brand = inputs_for(branded);
    let brand_server = Server::new(main_handler(&brand), ServerConfig::default());
    let gate = Gate::new(&plain, Vec::new());

    let mut failures = Vec::new();
    let cases = doc["cases"].as_array().expect("cases");
    assert!(cases.len() > 150);
    for case in cases {
        let request = case["request"].as_str().expect("request");
        let want = base64::engine::general_purpose::STANDARD
            .decode(case["response_base64"].as_str().expect("response"))
            .expect("base64");
        let server = if case["variant"] == "branded" {
            &brand_server
        } else {
            &plain_server
        };

        let RequestScan::Complete(head) = scan_request(request.as_bytes()) else {
            panic!("the relay refuses a vector request: {request:?}");
        };
        let connect = head.method == "CONNECT";
        assert_eq!(
            gate.is_native(&head),
            !connect,
            "the gate disagrees about {request:?}"
        );
        if connect {
            continue;
        }

        let (mut near, far) = duplex(1 << 20);
        let server = server.clone();
        tokio::spawn(async move {
            server
                .serve_connection(far, "192.0.2.1:1234".to_owned(), None)
                .await;
        });
        near.write_all(request.as_bytes()).await.expect("write");
        let got = read_to_end(&mut near).await;
        if normalize_date(&got) != normalize_date(&want) {
            failures.push(format!(
                "{} {request:?}\n  go:   {:?}\n  rust: {:?}",
                case["variant"],
                String::from_utf8_lossy(&want),
                String::from_utf8_lossy(&got),
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

// ---- starting the front

struct Front {
    addrs: HashMap<String, SocketAddr>,
    origin_log: PathBuf,
}

impl Front {
    fn main(&self) -> SocketAddr {
        self.addrs["main"]
    }

    fn origins(&self) -> Vec<(String, String)> {
        std::fs::read_to_string(&self.origin_log)
            .unwrap_or_default()
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).expect("origin line");
                (
                    v["origin"].as_str().unwrap_or_default().to_owned(),
                    v["target"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect()
    }
}

async fn start_front(upstream: SocketAddr, trusted: &str) -> Front {
    start_front_with(upstream, trusted, Vec::new()).await
}

async fn start_front_with(
    upstream: SocketAddr,
    trusted: &str,
    force_go: Vec<silo_front::rows::Surface>,
) -> Front {
    let origin_log = temp_path("origin");
    let cfg = FrontConfig {
        fronts: vec![FrontSpec {
            name: "main".to_owned(),
            listen: "127.0.0.1:0".to_owned(),
            upstream: upstream.to_string(),
        }],
        trusted_proxies: Some(trusted.to_owned()),
        origin_log: Some(origin_log.clone()),
        force_go,
        ..FrontConfig::default()
    };
    let addrs = start(cfg).await.expect("front").into_iter().collect();
    Front { addrs, origin_log }
}

/// Accepts one connection and hands it to `script`.
async fn scripted_upstream<F, Fut>(script: F) -> SocketAddr
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        script(stream).await;
    });
    addr
}

/// Reads up to and including `until`.
async fn read_until(stream: &mut TcpStream, until: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(WAIT, stream.read(&mut byte))
            .await
            .expect("timed out")
            .expect("read");
        if n == 0 {
            return out;
        }
        out.push(byte[0]);
        if out.ends_with(until) {
            return out;
        }
    }
}

async fn read_exact_vec(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    tokio::time::timeout(WAIT, stream.read_exact(&mut out))
        .await
        .expect("timed out")
        .expect("read");
    out
}

// ---- transparency

#[tokio::test]
async fn relay_changes_no_byte_but_the_forwarding_line_and_keeps_the_connection() {
    let response: &[u8] = b"HTTP/1.1 200 Fine\r\nx-lower: a\r\nX-Lower: b\r\nTransfer-Encoding: chunked\r\n\r\n5;a=b\r\nhello\r\nA\r\n0123456789\r\n0\r\nT-Rail: v\r\n\r\n";
    let (seen_tx, seen_rx) = oneshot::channel();
    let upstream = scripted_upstream(move |mut s| async move {
        let first = read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(response).await.unwrap();
        let second = read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        seen_tx.send((first, second)).unwrap();
        let _ = s.read(&mut [0u8; 1]).await;
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;

    let mut c = TcpStream::connect(front.main()).await.unwrap();
    let request = b"GET /x%2Fy?a=1 HTTP/1.1\r\nhOsT: h.test\r\nzzz: 1\r\nAAA:   spaced  \r\nX-Fold: a\r\n  b\r\n\r\n";
    c.write_all(request).await.unwrap();
    assert_eq!(read_exact_vec(&mut c, response.len()).await, response);
    c.write_all(b"GET /second HTTP/1.1\r\nHost: h.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_until(&mut c, b"\r\n\r\n").await,
        b"HTTP/1.1 204 No Content\r\n\r\n"
    );
    let (first, second) = seen_rx.await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&first),
        "GET /x%2Fy?a=1 HTTP/1.1\r\nhOsT: h.test\r\nzzz: 1\r\nAAA:   spaced  \r\nX-Fold: a\r\n  b\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&second),
        "GET /second HTTP/1.1\r\nHost: h.test\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n"
    );
}

/// A client that pipelines several requests and then half-closes its write side (it has nothing
/// more to send, but still wants every response) must still get every response relayed. Go
/// serves pipelined requests after a half-close; the relay must stay transparent to that too.
#[tokio::test]
async fn relay_serves_a_pipelined_request_already_buffered_after_the_client_half_closes() {
    let upstream = scripted_upstream(move |mut s| async move {
        let first = read_until(&mut s, b"\r\n\r\n").await;
        assert!(first.starts_with(b"GET /first"), "{first:?}");
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let second = read_until(&mut s, b"\r\n\r\n").await;
        assert!(second.starts_with(b"GET /second"), "{second:?}");
        s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;

    let mut c = TcpStream::connect(front.main()).await.unwrap();
    // Both requests land in one write, so the second is still sitting in the relay's read buffer
    // when the first exchange finishes. Then the client shuts its write side down.
    c.write_all(b"GET /first HTTP/1.1\r\nHost: h\r\n\r\nGET /second HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    c.shutdown().await.unwrap();

    assert_eq!(
        read_until(&mut c, b"\r\n\r\n").await,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(
        read_until(&mut c, b"\r\n\r\n").await,
        b"HTTP/1.1 204 No Content\r\n\r\n"
    );
}

#[tokio::test]
async fn relay_streams_each_direction_without_waiting_for_the_other_end() {
    let (first_seen_tx, first_seen_rx) = oneshot::channel::<()>();
    let (body_part_tx, body_part_rx) = oneshot::channel::<Vec<u8>>();
    let upstream = scripted_upstream(move |mut s| async move {
        read_until(&mut s, b"\r\n\r\n").await;
        body_part_tx.send(read_exact_vec(&mut s, 8).await).unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n")
            .await
            .unwrap();
        first_seen_rx.await.unwrap();
        s.write_all(b"1\r\nb\r\n0\r\n\r\n").await.unwrap();
        read_until(&mut s, b"0\r\n\r\n").await;
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;

    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(b"POST /up HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
        .await
        .unwrap();
    // The upstream has the first chunk while the client has not finished the body.
    assert_eq!(
        tokio::time::timeout(WAIT, body_part_rx)
            .await
            .unwrap()
            .unwrap(),
        b"3\r\nabc\r\n"
    );
    // The client has the first response chunk while the upstream has not finished the response.
    read_until(&mut c, b"1\r\na\r\n").await;
    first_seen_tx.send(()).unwrap();
    read_until(&mut c, b"0\r\n\r\n").await;
    c.write_all(b"0\r\n\r\n").await.unwrap();
}

#[tokio::test]
async fn relay_tunnels_after_a_101_with_the_bytes_that_came_with_it() {
    let upstream = scripted_upstream(|mut s| async move {
        let head = read_until(&mut s, b"\r\n\r\n").await;
        assert!(head.starts_with(b"GET /ws HTTP/1.1"));
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nserver-first")
            .await
            .unwrap();
        let got = read_exact_vec(&mut s, 10).await;
        assert_eq!(got, b"client-one");
        s.write_all(b"server-two").await.unwrap();
        // Half-close from the client side reaches here as an end of stream.
        let rest = read_to_end(&mut s).await;
        assert_eq!(rest, b"client-two");
        s.write_all(b"server-bye").await.unwrap();
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(
        b"GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    )
    .await
    .unwrap();
    read_until(&mut c, b"\r\n\r\n").await;
    assert_eq!(read_exact_vec(&mut c, 12).await, b"server-first");
    c.write_all(b"client-one").await.unwrap();
    assert_eq!(read_exact_vec(&mut c, 10).await, b"server-two");
    c.write_all(b"client-two").await.unwrap();
    c.shutdown().await.unwrap();
    assert_eq!(read_to_end(&mut c).await, b"server-bye");
}

#[tokio::test]
async fn relay_cuts_the_client_off_where_the_upstream_stopped() {
    let upstream = scripted_upstream(|mut s| async move {
        read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly-this")
            .await
            .unwrap();
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    let got = read_to_end(&mut c).await;
    assert!(got.ends_with(b"\r\n\r\nonly-this"), "{got:?}");
}

#[tokio::test]
async fn relay_stops_forwarding_at_bad_chunk_framing() {
    let (seen_tx, seen_rx) = oneshot::channel();
    let upstream = scripted_upstream(move |mut s| async move {
        read_until(&mut s, b"\r\n\r\n").await;
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(400), async {
            let mut buf = [0u8; 256];
            loop {
                let n = s.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
        })
        .await;
        seen_tx.send(got).unwrap();
        let _ = s
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nokXX\r\nGET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n",
    )
    .await
    .unwrap();
    let got = seen_rx.await.unwrap();
    assert_eq!(
        got, b"2\r\nokX",
        "the bytes past the bad framing reached Go"
    );
    read_to_end(&mut c).await;
}

#[tokio::test]
async fn relay_gives_a_refused_head_gos_answer_and_never_shows_it_to_go() {
    let (seen_tx, seen_rx) = oneshot::channel();
    let upstream = scripted_upstream(move |mut s| async move {
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.unwrap_or(0);
        seen_tx.send(n).unwrap();
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let got = read_to_end(&mut c).await;
    assert_eq!(
        got,
        b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
    );
    drop(c);
    // The connection to Go closes with nothing written on it.
    assert_eq!(seen_rx.await.unwrap(), 0);
}

#[tokio::test]
async fn relay_tells_the_upstream_when_a_client_hangs_up_mid_response() {
    let (eof_tx, eof_rx) = oneshot::channel();
    let upstream = scripted_upstream(move |mut s| async move {
        read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n")
            .await
            .unwrap();
        let n = tokio::time::timeout(WAIT, s.read(&mut [0u8; 8])).await;
        eof_tx.send(matches!(n, Ok(Ok(0)) | Ok(Err(_)))).unwrap();
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(b"GET /sse HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    read_until(&mut c, b"1\r\na\r\n").await;
    drop(c);
    assert!(eof_rx.await.unwrap());
}

#[tokio::test]
async fn relay_closes_a_client_when_go_closes_it_idle() {
    let upstream = scripted_upstream(|s| async move {
        // What Go's read timeout does to a client that connects and says nothing.
        drop(s);
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    assert_eq!(read_to_end(&mut c).await, b"");
}

#[tokio::test]
async fn relay_passes_interim_responses_and_head_answers_with_no_body() {
    let upstream = scripted_upstream(|mut s| async move {
        read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.unwrap();
        read_exact_vec(&mut s, 2).await;
        s.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n")
            .await
            .unwrap();
        read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz")
            .await
            .unwrap();
        let _ = s.read(&mut [0u8; 1]).await;
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(
        b"POST /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(
        read_until(&mut c, b"\r\n\r\n").await,
        b"HTTP/1.1 100 Continue\r\n\r\n"
    );
    c.write_all(b"hi").await.unwrap();
    assert_eq!(
        read_until(&mut c, b"ok").await,
        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"
    );
    c.write_all(b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_until(&mut c, b"\r\n\r\n").await,
        b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"
    );
    // A HEAD answer ended at its head, so the next response starts here.
    c.write_all(b"GET /y HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    assert!(
        read_until(&mut c, b"z")
            .await
            .starts_with(b"HTTP/1.1 200 OK")
    );
}

#[tokio::test]
async fn relay_routes_each_request_on_a_connection_and_logs_who_answered_before_answering() {
    let upstream = scripted_upstream(|mut s| async move {
        read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\ngo")
            .await
            .unwrap();
        let _ = s.read(&mut [0u8; 1]).await;
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();

    c.write_all(b"HEAD /api/v2/docs HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    let native = read_until(&mut c, b"\r\n\r\n").await;
    assert!(
        native.windows(12).any(|w| w == b"X-Request-ID"),
        "{native:?}"
    );
    assert_eq!(
        front.origins(),
        [("native".to_owned(), "/api/v2/docs".to_owned())]
    );

    c.write_all(b"GET /api/v1/libraries HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    assert!(read_until(&mut c, b"go").await.ends_with(b"\r\n\r\ngo"));
    assert_eq!(
        front.origins()[1],
        ("go".to_owned(), "/api/v1/libraries".to_owned())
    );

    c.write_all(b"GET /metrics HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    assert!(
        read_until(&mut c, b"found\n")
            .await
            .starts_with(b"HTTP/1.1 404")
    );
    assert_eq!(
        front.origins()[2],
        ("native".to_owned(), "/metrics".to_owned())
    );
}

#[tokio::test]
async fn the_rollback_switch_sends_a_native_row_to_go() {
    let upstream = scripted_upstream(|mut s| async move {
        read_until(&mut s, b"\r\n\r\n").await;
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\ngo")
            .await
            .unwrap();
        let _ = s.read(&mut [0u8; 1]).await;
    })
    .await;
    let front = start_front_with(
        upstream,
        "127.0.0.0/8",
        silo_front::parse_force_go("all").unwrap(),
    )
    .await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(b"GET /api/v2/docs HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    assert!(read_until(&mut c, b"go").await.ends_with(b"\r\n\r\ngo"));
    assert_eq!(front.origins()[0].0, "go");
}

#[tokio::test]
async fn tls_on_the_main_port_reaches_go_only_from_a_peer_go_would_trust() {
    let hello: &[u8] = b"\x16\x03\x01\x00\x05hello";
    let upstream = scripted_upstream(move |mut s| async move {
        assert_eq!(read_exact_vec(&mut s, hello.len()).await, hello);
        s.write_all(b"\x16\x03\x03server").await.unwrap();
    })
    .await;
    let front = start_front(upstream, "127.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(hello).await.unwrap();
    assert_eq!(read_to_end(&mut c).await, b"\x16\x03\x03server");

    let upstream = scripted_upstream(|mut s| async move {
        let mut buf = [0u8; 16];
        assert_eq!(s.read(&mut buf).await.unwrap_or(0), 0);
    })
    .await;
    let front = start_front(upstream, "10.0.0.0/8").await;
    let mut c = TcpStream::connect(front.main()).await.unwrap();
    c.write_all(hello).await.unwrap();
    assert_eq!(read_to_end(&mut c).await, b"");
}

// ---- trust, with the real internal/clientip on both paths

fn clientip_binary() -> PathBuf {
    let root = repo_root();
    let bin = root.join("rust/target/silo-front-clientip");
    let status = Command::new("go")
        .current_dir(&root)
        .env("GOTOOLCHAIN", "go1.26.10")
        .env("CGO_ENABLED", "0")
        .args(["build", "-tags", "front_vectors", "-o"])
        .arg(&bin)
        .arg("./rust/conformance/vectors/generators/front/clientip")
        .status()
        .expect("go");
    assert!(status.success(), "building the clientip server failed");
    bin
}

struct GoEcho {
    child: std::process::Child,
    addr: SocketAddr,
}

impl Drop for GoEcho {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn go_echo(bin: &Path, trusted: &str) -> GoEcho {
    let mut child = Command::new(bin)
        .args(["-trusted", trusted])
        .stdout(Stdio::piped())
        .spawn()
        .expect("clientip server");
    let mut out = child.stdout.take().expect("stdout");
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while std::io::Read::read(&mut out, &mut byte).expect("read") == 1 && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    let addr = String::from_utf8(line)
        .expect("addr")
        .parse()
        .expect("addr");
    GoEcho { child, addr }
}

async fn resolve_through(addr: SocketAddr, headers: &[&str]) -> serde_json::Value {
    let mut c = TcpStream::connect(addr).await.expect("connect");
    let mut raw =
        String::from("GET /x HTTP/1.1\r\nHost: Direct.Host.test:8080\r\nConnection: close\r\n");
    for h in headers {
        raw.push_str(h);
        raw.push_str("\r\n");
    }
    raw.push_str("\r\n");
    c.write_all(raw.as_bytes()).await.expect("write");
    let got = read_to_end(&mut c).await;
    let split = got
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response")
        + 4;
    serde_json::from_slice(&got[split..]).unwrap_or_else(|e| {
        panic!("{e}: {:?}", String::from_utf8_lossy(&got));
    })
}

const FORWARDING_MATRIX: &[&[&str]] = &[
    &[],
    &["X-Forwarded-For: 203.0.113.9"],
    &["X-Forwarded-For: 203.0.113.9, 10.1.1.1"],
    &["X-Forwarded-For: 10.1.1.1"],
    &["X-Forwarded-For: 10.1.1.1, 10.2.2.2"],
    &["X-Forwarded-For: 198.51.100.4, 203.0.113.9"],
    &["X-Forwarded-For: 203.0.113.9", "X-Forwarded-For: 10.1.1.1"],
    &["X-Forwarded-For: junk"],
    &["X-Forwarded-For: 203.0.113.9, junk"],
    &["X-Forwarded-For: junk, 10.1.1.1"],
    &["X-Forwarded-For: junk, 203.0.113.9"],
    &["X-Forwarded-For: "],
    &["X-Forwarded-For: ,,"],
    &["X-Forwarded-For: [2001:db8::1]:1234"],
    &["X-Forwarded-For: 2001:db8::1"],
    &["X-Forwarded-For: 203.0.113.9:443"],
    &["x-forwarded-for: 203.0.113.9"],
    &["X-Real-IP: 203.0.113.9"],
    &["X-Real-IP: junk"],
    &["X-Real-IP: 203.0.113.9", "X-Real-IP: 203.0.113.10"],
    &["X-Real-IP: 203.0.113.9", "X-Forwarded-For: junk"],
    &["X-Real-IP: 203.0.113.9", "X-Forwarded-For: 198.51.100.4"],
    &["X-Real-IP: junk", "X-Forwarded-For: junk"],
    &["Forwarded: for=203.0.113.9"],
    &["Forwarded: for=203.0.113.9", "X-Forwarded-For: junk"],
    &["X-Forwarded-Host: public.example"],
    &["X-Forwarded-Host: a.example, b.example"],
    &["X-Forwarded-Host: a.example", "X-Forwarded-Host: b.example"],
    &["X-Forwarded-Proto: https"],
    &["X-Forwarded-Proto: http"],
    &["X-Forwarded-Proto: garbage"],
    &["X-Forwarded-Proto: https", "X-Forwarded-Proto: http"],
    &[
        "X-Forwarded-Proto: wss",
        "Connection: Upgrade",
        "Upgrade: websocket",
    ],
    &[
        "X-Forwarded-For: 203.0.113.9",
        "X-Forwarded-Host: public.example",
        "X-Forwarded-Proto: https",
        "X-Real-IP: 198.51.100.4",
        "Forwarded: for=x",
    ],
];

/// `listed` names the client's address (127.0.0.1) or not. `go_via_front` adds loopback, because the
/// reference trusts the relay in front of it, as the default list does.
async fn forwarding_matches_direct(listed: &str) {
    let bin = clientip_binary();
    let direct = go_echo(&bin, listed);
    let behind_front = go_echo(&bin, &format!("{listed},127.0.0.0/8"));
    let front = start_front(behind_front.addr, listed).await;
    let mut failures = Vec::new();
    for headers in FORWARDING_MATRIX {
        let want = resolve_through(direct.addr, headers).await;
        let got = resolve_through(front.main(), headers).await;
        if want != got {
            failures.push(format!("{headers:?}\n  direct: {want}\n  front:  {got}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn forwarding_from_an_untrusted_client_resolves_as_a_direct_connection() {
    forwarding_matches_direct("10.0.0.0/8").await;
}

#[tokio::test]
async fn forwarding_from_a_trusted_client_resolves_as_a_direct_connection() {
    forwarding_matches_direct("127.0.0.1/32,10.0.0.0/8").await;
}

// ---- a running reference

struct Reference {
    main: SocketAddr,
    jelly: SocketAddr,
    abs: SocketAddr,
    front: Front,
}

async fn reference() -> Option<Reference> {
    let raw = std::env::var("SILO_FRONT_TEST_REFERENCE").ok()?;
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let parts: Vec<SocketAddr> = raw.split(',').map(|p| p.parse().expect("addr")).collect();
    let [main, jelly, abs] = parts[..] else {
        panic!("SILO_FRONT_TEST_REFERENCE needs main,jellycompat,abs");
    };
    let dist = temp_path("dist");
    std::fs::create_dir_all(&dist).unwrap();
    // The stub the conformance image's Dockerfile builds with.
    std::fs::write(dist.join("index.html"), "<!doctype html>\n").unwrap();
    let origin_log = temp_path("origin");
    let spec = |name: &str, upstream: SocketAddr| FrontSpec {
        name: name.to_owned(),
        listen: "127.0.0.1:0".to_owned(),
        upstream: upstream.to_string(),
    };
    let addrs = start(FrontConfig {
        fronts: vec![
            spec("main", main),
            spec("jellycompat", jelly),
            spec("abs", abs),
        ],
        database_url: Some(database_url),
        web_dist: Some(dist),
        origin_log: Some(origin_log.clone()),
        ..FrontConfig::default()
    })
    .await
    .expect("front")
    .into_iter()
    .collect();
    Some(Reference {
        main,
        jelly,
        abs,
        front: Front { addrs, origin_log },
    })
}

/// `Date`, `X-Request-ID`, and the id in a problem's `instance` differ between two answers of one server.
fn normalize_volatile(raw: &[u8]) -> Vec<u8> {
    let out = normalize_date(raw);
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(out.len(), |p| p + 4);
    let (head, body) = out.split_at(split);
    let mut text = Vec::with_capacity(out.len());
    for line in head.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b"X-Request-ID: ") {
            assert_eq!(line.len(), "X-Request-ID: ".len() + 24 + 2, "{line:?}");
            text.extend_from_slice(b"X-Request-ID: <id>\r\n");
        } else {
            text.extend_from_slice(line);
        }
    }
    const INSTANCE: &[u8] = b"urn:silo:request:";
    let mut body = body.to_vec();
    if let Some(at) = body.windows(INSTANCE.len()).position(|w| w == INSTANCE) {
        let start = at + INSTANCE.len();
        body[start..start + 24].fill(b'x');
    }
    text.extend_from_slice(&body);
    text
}

async fn raw_exchange(addr: SocketAddr, request: &str) -> Vec<u8> {
    let mut c = TcpStream::connect(addr).await.expect("connect");
    c.write_all(request.as_bytes()).await.expect("write");
    read_to_end(&mut c).await
}

fn req(method: &str, target: &str, headers: &[&str]) -> String {
    let mut out =
        format!("{method} {target} HTTP/1.1\r\nHost: conformance.test\r\nConnection: close\r\n");
    for h in headers {
        out.push_str(h);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

async fn compare(
    reference: SocketAddr,
    front: SocketAddr,
    log: &Front,
    expect_origin: &str,
    requests: &[String],
) {
    let mut failures = Vec::new();
    for request in requests {
        let before = log.origins().len();
        let want = normalize_volatile(&raw_exchange(reference, request).await);
        let got = normalize_volatile(&raw_exchange(front, request).await);
        let origins = log.origins();
        let origin = origins[before..].first().map_or("none", |o| o.0.as_str());
        if origin != expect_origin {
            failures.push(format!(
                "{request:?}: answered by {origin}, expected {expect_origin}"
            ));
        }
        if want != got {
            let cut = |b: &[u8]| String::from_utf8_lossy(&b[..b.len().min(700)]).into_owned();
            failures.push(format!(
                "{request:?}\n  go:    {}\n  front: {}",
                cut(&want),
                cut(&got)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn reference_native_rows_match_on_the_wire() {
    let Some(r) = reference().await else {
        eprintln!("skipped: SILO_FRONT_TEST_REFERENCE and DATABASE_URL are not set");
        return;
    };
    let mut requests = Vec::new();
    let asset_paths = [
        "/api/v2/docs",
        "/api/v2/docs/init.js",
        "/api/v2/docs/swagger-ui-bundle.js",
        "/api/v2/docs/swagger-ui.css",
        "/api/v2/docs/swagger-ui-bundle.js.LICENSE.txt",
    ];
    for p in asset_paths {
        requests.push(req("GET", p, &[]));
        requests.push(req("HEAD", p, &[]));
        requests.push(req("GET", &format!("{p}?x=1"), &[]));
        requests.push(req("GET", p, &["Authorization: Bearer not-a-token"]));
    }
    for headers in [
        &[][..],
        &["Authorization: Bearer not-a-token"],
        &["Accept: application/json"],
        &["Accept: */*"],
        &["Accept-Encoding: gzip"],
        &["Accept-Encoding: br, zstd, gzip"],
    ] {
        requests.push(req("GET", "/api/v2/openapi.json", headers));
    }
    for headers in [
        &[][..],
        &["Authorization: Bearer not-a-token"],
        &["X-Forwarded-For: 203.0.113.9"],
    ] {
        requests.push(req("GET", "/api/v1/health", headers));
    }
    requests.push(req("GET", "/api/v1/health?x=1", &[]));
    for m in [
        "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "QUERY", "TRACE",
    ] {
        requests.push(req(m, "/api/v1/health", &[]));
    }
    requests.push(req("GET", "/api/v1/health/", &[]));
    requests.push(req("POST", "/api/v1/health/", &[]));
    requests.push(req(
        "OPTIONS",
        "/api/v1/health",
        &[
            "Origin: https://a.test",
            "Access-Control-Request-Method: GET",
        ],
    ));
    for p in [
        "/api/v2/openapi.json",
        "/api/v2/docs",
        "/api/v2/docs/init.js",
    ] {
        for m in [
            "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "QUERY", "TRACE",
        ] {
            requests.push(req(m, p, &[]));
        }
        requests.push(req("GET", &format!("{p}/"), &[]));
        requests.push(req("HEAD", &format!("{p}/"), &[]));
        requests.push(req("POST", &format!("{p}/?x=1"), &[]));
    }
    requests.push(req("HEAD", "/api/v2/openapi.json", &[]));
    requests.push(req("OPTIONS", "/api/v2/openapi.json?x=1", &[]));
    for h in [
        r#"If-None-Match: "eb3cb4a524d15602a87abd1e37c877ded646c098fba8a6cdbc35a1e659bbcccf""#,
        "If-None-Match: *",
        r#"If-Match: "x""#,
        "Range: bytes=0-3",
    ] {
        requests.push(req("GET", "/api/v2/openapi.json", &[h]));
        requests.push(req("GET", "/api/v2/docs", &[h]));
    }
    for m in [
        "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "QUERY", "TRACE",
    ] {
        requests.push(req(m, "/", &[]));
        requests.push(req(m, "/metrics", &[]));
        requests.push(req(m, "/some/app/route", &[]));
    }
    // Only the connection close header differs from how a keep-alive client asks.
    requests.push("GET /api/v1/health HTTP/1.0\r\nHost: conformance.test\r\n\r\n".to_owned());
    requests.push("GET / HTTP/1.0\r\n\r\n".to_owned());
    compare(r.main, r.front.addrs["main"], &r.front, "native", &requests).await;

    // Codings are compared decoded elsewhere; here only what negotiation put in the head.
    for coding in ["gzip", "br", "zstd"] {
        let accept = format!("Accept-Encoding: {coding}");
        let request = req("GET", "/api/v2/docs", &[accept.as_str()]);
        let want = raw_exchange(r.main, &request).await;
        let got = raw_exchange(r.front.addrs["main"], &request).await;
        let head = |b: &[u8]| {
            let split = b.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let text = String::from_utf8_lossy(&b[..split]).into_owned();
            text.lines()
                .filter(|l| {
                    !l.starts_with("Date:")
                        && !l.starts_with("X-Request-ID:")
                        && !l.starts_with("Content-Length:")
                })
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(head(&want), head(&got), "{coding}");
    }
}

#[tokio::test]
async fn reference_a_gated_native_row_goes_to_go_and_matches() {
    let Some(r) = reference().await else {
        eprintln!("skipped: SILO_FRONT_TEST_REFERENCE and DATABASE_URL are not set");
        return;
    };
    let requests: Vec<String> = [
        req("GET", "/api/v1/health", &["X-Silo-Ingress-Token: nope"]),
        req("GET", "/api/v1/ready", &[]),
        req("CONNECT", "/", &[]),
        req("CONNECT", "/metrics", &[]),
        req("CONNECT", "/some/app/route", &[]),
        req("CONNECT", "/api/v1/health", &[]),
        req("CONNECT", "/api/v2/docs", &[]),
        req("GET", "/api", &[]),
        req("GET", "/api/", &[]),
        req("GET", "//x", &[]),
        req("GET", "/a/../b", &[]),
        req("GET", "/%61pi/v1/health", &[]),
    ]
    .to_vec();
    compare(r.main, r.front.addrs["main"], &r.front, "go", &requests).await;

    // These were Go's until the row went native. They still have to answer as Go does.
    let native: Vec<String> = [
        req("GET", "/api/v2/openapi.json?x=1", &[]),
        req("GET", "/api/v2/openapi.json", &["Accept: text/html"]),
        req("GET", "/api/v2/openapi.json", &["Accept-Encoding: identity;q=0"]),
        req("GET", "/api/v2/openapi.json", &["X-Silo-Device-Id: bad value"]),
        req("GET", "/api/v2/docs", &["X-Silo-Device-Id: bad value"]),
        req("GET", "/api/v2/openapi.json/", &["X-Silo-Device-Id: bad value"]),
        req("POST", "/api/v2/docs", &["X-Silo-Device-Id: bad value"]),
        "POST /api/v1/health HTTP/1.1\r\nHost: conformance.test\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi".to_owned(),
    ]
    .to_vec();
    compare(r.main, r.front.addrs["main"], &r.front, "native", &native).await;
}

#[tokio::test]
async fn reference_forwarded_rows_match_on_every_listener() {
    let Some(r) = reference().await else {
        eprintln!("skipped: SILO_FRONT_TEST_REFERENCE and DATABASE_URL are not set");
        return;
    };
    let main: Vec<String> = [
        req("GET", "/api/v1/libraries", &[]),
        req("GET", "/api/v2/libraries", &[]),
        req("GET", "/api/v2/capabilities", &[]),
        req(
            "OPTIONS",
            "/api/v2/capabilities",
            &[
                "Origin: https://a.test",
                "Access-Control-Request-Method: GET",
            ],
        ),
        req("POST", "/api/v2/auth/login", &["Content-Type: text/plain"]),
    ]
    .to_vec();
    compare(r.main, r.front.addrs["main"], &r.front, "go", &main).await;
    let jelly: Vec<String> = [
        req("GET", "/System/Ping", &[]),
        req("GET", "/system/info/public", &[]),
        req("HEAD", "/Users/Public", &[]),
        req(
            "OPTIONS",
            "/Users/Public",
            &[
                "Origin: https://a.test",
                "Access-Control-Request-Method: GET",
            ],
        ),
    ]
    .to_vec();
    compare(
        r.jelly,
        r.front.addrs["jellycompat"],
        &r.front,
        "go",
        &jelly,
    )
    .await;
    let abs: Vec<String> = [
        req("GET", "/ping", &[]),
        req("GET", "/healthcheck", &[]),
        req("GET", "/status", &[]),
        req("GET", "/abs/api/libraries", &[]),
    ]
    .to_vec();
    compare(r.abs, r.front.addrs["abs"], &r.front, "go", &abs).await;
}

#[tokio::test]
async fn reference_a_websocket_upgrade_passes_through() {
    let Some(r) = reference().await else {
        eprintln!("skipped: SILO_FRONT_TEST_REFERENCE and DATABASE_URL are not set");
        return;
    };
    let upgrade = "GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: conformance.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    let mut direct = TcpStream::connect(r.abs).await.unwrap();
    direct.write_all(upgrade.as_bytes()).await.unwrap();
    let want = read_until(&mut direct, b"\r\n\r\n").await;
    let mut through = TcpStream::connect(r.front.addrs["abs"]).await.unwrap();
    through.write_all(upgrade.as_bytes()).await.unwrap();
    let got = read_until(&mut through, b"\r\n\r\n").await;
    assert_eq!(
        String::from_utf8_lossy(&normalize_date(&got)),
        String::from_utf8_lossy(&normalize_date(&want))
    );
    assert!(
        got.starts_with(b"HTTP/1.1 101 "),
        "{}",
        String::from_utf8_lossy(&got)
    );
    // The engine.io open packet arrives as a server frame: unmasked text, starting with '0'.
    let frame = read_exact_vec(&mut through, 3).await;
    assert_eq!(frame[0], 0x81, "{frame:?}");
    assert_eq!(frame[2], b'0', "{frame:?}");
}
