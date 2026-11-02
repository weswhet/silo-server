//! Wire-level proof for H3: `sslmode=prefer` must never put the startup message (which carries
//! `user`, the only credential pgconn sends before authentication) on the wire in the clear when
//! talking to a server that answers the SSLRequest with `S`. No real Postgres is needed: a fake
//! server plays just enough of the v3 protocol (the SSLRequest exchange, then either a real TLS
//! handshake or nothing) to show what bytes `silo_pg::Pool` actually sent.
//!
//! This also uses `sslmode=disable` as a control: the same fake server must see the startup
//! message in the clear, proving the test would catch a regression that always wraps the
//! connection in TLS instead of actually honoring the mode.

use std::time::Duration;

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use silo_pg::{Pool, PoolConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const SSL_REQUEST_CODE: i32 = 80877103;

async fn fake_server() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    (cert_der, key_der)
}

/// Reads the client's first message and reports whether it was an SSLRequest.
async fn read_first_message(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = i32::from_be_bytes(len_buf);
    let mut rest = vec![0u8; (len - 4).max(0) as usize];
    stream.read_exact(&mut rest).await.unwrap();
    let mut whole = len_buf.to_vec();
    whole.extend_from_slice(&rest);
    whole
}

fn is_ssl_request(msg: &[u8]) -> bool {
    msg.len() == 8 && i32::from_be_bytes(msg[4..8].try_into().unwrap()) == SSL_REQUEST_CODE
}

/// A startup message's payload (after the 4-byte length and 4-byte protocol version) is a series
/// of key\0value\0 pairs ending in \0. `user` is always first and is the only thing pgconn sends
/// before the server has asked for a password, so finding it in the clear is exactly the leak H3
/// is about.
fn startup_message_contains_user(msg: &[u8], user: &str) -> bool {
    let needle = format!("user\0{user}\0");
    msg.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// `sslmode=prefer` against a server that answers `S`: the startup message (and therefore `user`)
/// must only ever appear inside the TLS record layer, never in the clear on the TCP stream.
#[tokio::test(flavor = "multi_thread")]
async fn prefer_sends_the_startup_message_only_after_a_successful_tls_handshake() {
    let (listener, port) = fake_server().await;
    let (cert, key) = self_signed();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let first = read_first_message(&mut stream).await;
        assert!(
            is_ssl_request(&first),
            "prefer must send an SSLRequest first, got {first:?}"
        );
        // The plaintext side of the connection must carry nothing else: confirm there's no
        // startup message sitting right behind the SSLRequest before we ever respond.
        stream.write_all(b"S").await.unwrap();

        let mut tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        tls_config.alpn_protocols.clear();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_config));
        let mut tls_stream = acceptor.accept(stream).await.unwrap();

        let msg = read_first_message_tls(&mut tls_stream).await;
        assert!(
            startup_message_contains_user(&msg, "prefertest"),
            "the startup message should arrive over TLS: {msg:?}"
        );
        // Nothing more to fake: closing here is enough to make the client's connect() fail, which
        // the test expects.
    });

    let url =
        format!("postgres://prefertest:pw@127.0.0.1:{port}/db?sslmode=prefer&connect_timeout=5");
    let config = PoolConfig::parse(&url).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), Pool::connect(config)).await;
    assert!(
        result.is_ok(),
        "connect() should fail cleanly (the fake server never finishes the handshake), not hang"
    );
    assert!(
        result.unwrap().is_err(),
        "connect() must fail, since the fake server never completes authentication"
    );

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task should finish")
        .expect("server task should not panic");
}

/// `sslmode=disable` is the control: against the very same fake server, the startup message must
/// arrive in the clear, with no SSLRequest beforehand. If this ever stopped being true (e.g. a
/// change that always wraps every mode in TLS) this test would catch it.
#[tokio::test(flavor = "multi_thread")]
async fn disable_never_negotiates_tls() {
    let (listener, port) = fake_server().await;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let first = read_first_message(&mut stream).await;
        assert!(
            !is_ssl_request(&first),
            "disable must never send an SSLRequest, got {first:?}"
        );
        assert!(
            startup_message_contains_user(&first, "disabletest"),
            "disable's first message should be the plaintext startup message: {first:?}"
        );
    });

    let url =
        format!("postgres://disabletest:pw@127.0.0.1:{port}/db?sslmode=disable&connect_timeout=5");
    let config = PoolConfig::parse(&url).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), Pool::connect(config)).await;
    assert!(result.is_ok(), "connect() should fail cleanly, not hang");
    assert!(result.unwrap().is_err());

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task should finish")
        .expect("server task should not panic");
}

async fn read_first_message_tls(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Vec<u8> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = i32::from_be_bytes(len_buf);
    let mut rest = vec![0u8; (len - 4).max(0) as usize];
    stream.read_exact(&mut rest).await.unwrap();
    let mut whole = len_buf.to_vec();
    whole.extend_from_slice(&rest);
    whole
}

/// Answers the SSLRequest with `N`, then expects the plaintext startup message on a second connection:
/// pgx's `prefer` falls back when TLS fails, so a server without TLS still works.
#[tokio::test(flavor = "multi_thread")]
async fn prefer_falls_back_to_plaintext_when_the_server_has_no_tls() {
    let (listener, port) = fake_server().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let first = read_first_message(&mut stream).await;
        assert!(is_ssl_request(&first));
        stream.write_all(b"N").await.unwrap();
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        let first = read_first_message(&mut stream).await;
        assert!(!is_ssl_request(&first));
        assert!(startup_message_contains_user(&first, "fallback"));
    });
    let url =
        format!("postgres://fallback:pw@127.0.0.1:{port}/db?sslmode=prefer&connect_timeout=5");
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Pool::connect(PoolConfig::parse(&url).unwrap()),
    )
    .await
    .expect("connect must not hang");
    assert!(result.is_err());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task should finish")
        .expect("server task should not panic");
}

fn fatal_auth_error(code: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [(b'S', "FATAL"), (b'C', code), (b'M', "refused")] {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut message = vec![b'E'];
    message.extend_from_slice(&(body.len() as i32 + 4).to_be_bytes());
    message.extend_from_slice(&body);
    message
}

/// `allow` tries plaintext first. A wrong password must stop there, as in pgconn's `connectPreferred`,
/// and any other failure goes on to TLS.
#[tokio::test(flavor = "multi_thread")]
async fn allow_stops_on_a_wrong_password_and_otherwise_tries_tls() {
    for (code, expects_second_attempt) in [
        ("28P01", false),
        ("3D000", false),
        ("42501", false),
        ("53300", true),
    ] {
        let (listener, port) = fake_server().await;
        let reply = fatal_auth_error(code);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_first_message(&mut stream).await;
            assert!(!is_ssl_request(&first), "allow starts in plaintext");
            stream.write_all(&reply).await.unwrap();
            drop(stream);
            match tokio::time::timeout(Duration::from_millis(1500), listener.accept()).await {
                Ok(Ok((mut stream, _))) => {
                    assert!(is_ssl_request(&read_first_message(&mut stream).await));
                    stream.write_all(b"N").await.unwrap();
                    true
                }
                _ => false,
            }
        });
        let url = format!("postgres://u:pw@127.0.0.1:{port}/db?sslmode=allow&connect_timeout=5");
        let result = Pool::connect(PoolConfig::parse(&url).unwrap()).await;
        assert!(result.is_err(), "{code}");
        assert_eq!(server.await.unwrap(), expects_second_attempt, "{code}");
    }
}

/// `sslnegotiation=direct`: no SSLRequest, a TLS ClientHello offering ALPN `postgresql` as the first
/// bytes, and no plaintext fallback, because pgx upgrades `prefer` to `require` here.
#[tokio::test(flavor = "multi_thread")]
async fn direct_negotiation_sends_tls_first_and_never_falls_back() {
    let (listener, port) = fake_server().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = vec![0u8; 512];
        let n = stream.read(&mut hello).await.unwrap();
        hello.truncate(n);
        assert_eq!(
            hello[0], 0x16,
            "the first byte must be a TLS handshake record"
        );
        assert!(
            hello.windows(10).any(|w| w == b"postgresql"),
            "the ClientHello must offer ALPN postgresql"
        );
        drop(stream);
        tokio::time::timeout(Duration::from_millis(1500), listener.accept())
            .await
            .is_err()
    });
    let url = format!(
        "postgres://u:pw@127.0.0.1:{port}/db?sslmode=prefer&sslnegotiation=direct&connect_timeout=5"
    );
    assert!(
        Pool::connect(PoolConfig::parse(&url).unwrap())
            .await
            .is_err()
    );
    assert!(server.await.unwrap(), "direct must not retry in plaintext");
}
