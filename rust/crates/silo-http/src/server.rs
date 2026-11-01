//! Port of the server half of `net/http/server.go`: `http.Server`, `conn.serve`, `response`, and
//! `chunkWriter`. Go 1.26.7 is the reference.

use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant as StdInstant};

use futures_util::FutureExt;
use silo_gocompat::time::GoTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::bufio::{BoxedIo, BufReader, ConnReader, ConnWriter, Deadline, lock};
use crate::header::{
    Header, TIME_FORMAT, TRAILER_PREFIX, canonical_header_key, foreach_header_element, has_token,
    header_values_contains_token, valid_header_field_name, valid_header_field_value,
    valid_host_header, valid_trailer_header,
};
use crate::request::{
    BodyInner, BodyKind, BodyKindCell, ExpectContinue, MAX_POST_HANDLER_READ_BYTES, ReqError,
    Request, core_close, core_read, is_body_read_after_close, max_bytes_reader, read_request,
};
use crate::response::{AbortHandler, BoxFuture, BoxHandler, Hijacked, ResponseWriter, WriteError};
use crate::sniff::{SNIFF_LEN, detect_content_type};
use crate::status::status_text;

/// `bufferBeforeChunkingSize`.
const BUFFER_BEFORE_CHUNKING_SIZE: usize = 2048;

/// `http.DefaultMaxHeaderBytes`.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 1 << 20;

/// `rstAvoidanceDelay`.
const RST_AVOIDANCE_DELAY: Duration = Duration::from_millis(500);

/// The fields of `http.Server` that change behavior on the wire.
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// `ReadTimeout`.
    pub read_timeout: Option<Duration>,
    /// `ReadHeaderTimeout`.
    pub read_header_timeout: Option<Duration>,
    /// `WriteTimeout`.
    pub write_timeout: Option<Duration>,
    /// `IdleTimeout`.
    pub idle_timeout: Option<Duration>,
    /// `MaxHeaderBytes`; zero means `DEFAULT_MAX_HEADER_BYTES`.
    pub max_header_bytes: usize,
    /// `DisableGeneralOptionsHandler`.
    pub disable_general_options_handler: bool,
}

struct ServerInner {
    handler: BoxHandler,
    config: ServerConfig,
    in_shutdown: AtomicBool,
    disable_keep_alives: AtomicBool,
    /// Wakes idle connections and the accept loop when shutdown starts.
    shutdown_notify: Notify,
    active_conns: AtomicUsize,
    conns_changed: Notify,
}

impl ServerInner {
    fn do_keep_alives(&self) -> bool {
        !self.disable_keep_alives.load(Ordering::SeqCst) && !self.shutting_down()
    }
    fn shutting_down(&self) -> bool {
        self.in_shutdown.load(Ordering::SeqCst)
    }
    fn idle_timeout(&self) -> Option<Duration> {
        self.config.idle_timeout.or(self.config.read_timeout)
    }
    fn read_header_timeout(&self) -> Option<Duration> {
        self.config.read_header_timeout.or(self.config.read_timeout)
    }
    fn initial_read_limit_size(&self) -> i64 {
        let max = if self.config.max_header_bytes > 0 {
            self.config.max_header_bytes
        } else {
            DEFAULT_MAX_HEADER_BYTES
        };
        max as i64 + 4096
    }
}

/// `http.Server`.
#[derive(Clone)]
pub struct Server {
    inner: Arc<ServerInner>,
}

impl Server {
    /// `&http.Server{Handler: handler, ...}`.
    pub fn new(handler: BoxHandler, config: ServerConfig) -> Self {
        Self {
            inner: Arc::new(ServerInner {
                handler,
                config,
                in_shutdown: AtomicBool::new(false),
                disable_keep_alives: AtomicBool::new(false),
                shutdown_notify: Notify::new(),
                active_conns: AtomicUsize::new(0),
                conns_changed: Notify::new(),
            }),
        }
    }

    /// `srv.SetKeepAlivesEnabled`.
    pub fn set_keep_alives_enabled(&self, enabled: bool) {
        self.inner
            .disable_keep_alives
            .store(!enabled, Ordering::SeqCst);
        self.inner.shutdown_notify.notify_waiters();
    }

    /// `srv.Serve(listener)`. Returns when shutdown starts.
    pub async fn serve(&self, listener: TcpListener) -> io::Result<()> {
        let mut backoff = Duration::ZERO;
        loop {
            if self.inner.shutting_down() {
                return Ok(());
            }
            let accepted = tokio::select! {
                a = listener.accept() => a,
                () = self.inner.shutdown_notify.notified() => continue,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // Go backs off from 5 ms to 1 s on a temporary accept error.
                    if is_temporary_accept_error(&e) {
                        backoff = if backoff.is_zero() {
                            Duration::from_millis(5)
                        } else {
                            backoff * 2
                        };
                        backoff = backoff.min(Duration::from_secs(1));
                        tracing::error!(error = %e, ?backoff, "http: Accept error");
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    return Err(e);
                }
            };
            backoff = Duration::ZERO;
            // net.TCPConn defaults to TCP_NODELAY; tokio does not.
            let _ = stream.set_nodelay(true);
            let local = stream.local_addr().ok();
            let this = self.clone();
            tokio::spawn(async move {
                this.serve_connection(stream, peer.to_string(), local).await;
            });
        }
    }

    /// `c.serve`, for a stream accepted elsewhere (a TLS session, the LAN sniffer).
    pub async fn serve_connection<S>(
        &self,
        io: S,
        remote_addr: String,
        local_addr: Option<SocketAddr>,
    ) where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.inner.active_conns.fetch_add(1, Ordering::SeqCst);
        let boxed: BoxedIo = Box::new(io);
        serve_conn(self.inner.clone(), boxed, remote_addr, local_addr).await;
        self.inner.active_conns.fetch_sub(1, Ordering::SeqCst);
        self.inner.conns_changed.notify_waiters();
    }

    /// `srv.Shutdown`: stops accepting, ends idle connections, and waits for the rest.
    pub async fn shutdown(&self) {
        self.inner.in_shutdown.store(true, Ordering::SeqCst);
        self.inner.shutdown_notify.notify_waiters();
        loop {
            let changed = self.inner.conns_changed.notified();
            if self.inner.active_conns.load(Ordering::SeqCst) == 0 {
                return;
            }
            tokio::select! {
                () = changed => {}
                () = tokio::time::sleep(Duration::from_millis(50)) => self.inner.shutdown_notify.notify_waiters(),
            }
        }
    }
}

fn is_temporary_accept_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
    ) || matches!(e.raw_os_error(), Some(23 | 24))
}

/// What the connection and its current response share.
struct ConnShared {
    reader: Arc<AsyncMutex<BufReader>>,
    conn_reader: Arc<Mutex<ConnReader>>,
    bufw: Arc<AsyncMutex<ConnWriter>>,
    write_deadline: Arc<Mutex<Deadline>>,
    werr: Arc<AtomicBool>,
    hijacked: AtomicBool,
    server: Arc<ServerInner>,
}

impl ConnShared {
    fn set_read_deadline(&self, at: Option<Instant>) {
        lock(&self.conn_reader).set_deadline(at);
    }
    fn set_write_deadline(&self, at: Option<Instant>) {
        lock(&self.write_deadline).set(at);
    }
}

async fn serve_conn(
    server: Arc<ServerInner>,
    io: BoxedIo,
    remote_addr: String,
    local_addr: Option<SocketAddr>,
) {
    let conn_cancel = CancellationToken::new();
    let close_notify = Arc::new(AtomicBool::new(false));
    let (rd, wr) = tokio::io::split(io);
    let conn_reader = Arc::new(Mutex::new(ConnReader::new(
        rd,
        conn_cancel.clone(),
        close_notify,
    )));
    let reader = Arc::new(AsyncMutex::new(BufReader::new(conn_reader.clone())));
    let write_deadline = Arc::new(Mutex::new(Deadline::default()));
    let werr = Arc::new(AtomicBool::new(false));
    let bufw = Arc::new(AsyncMutex::new(ConnWriter::new(
        wr,
        write_deadline.clone(),
        werr.clone(),
        conn_cancel.clone(),
    )));
    let c = Arc::new(ConnShared {
        reader,
        conn_reader,
        bufw,
        write_deadline,
        werr,
        hijacked: AtomicBool::new(false),
        server: server.clone(),
    });

    serve_loop(&c, &conn_cancel, remote_addr, local_addr).await;
    conn_cancel.cancel();
}

fn after(d: Duration) -> Instant {
    Instant::now() + d
}

/// `c.close`.
async fn close_conn(c: &ConnShared) {
    let mut w = c.bufw.lock().await;
    let _ = w.flush().await;
    w.close();
    // Dropping the read half with the write half closes the socket.
    drop(lock(&c.conn_reader).take_for_hijack());
}

/// `c.closeWriteAndWait`.
async fn close_write_and_wait(c: &ConnShared) {
    {
        let mut w = c.bufw.lock().await;
        let _ = w.flush().await;
        w.close_write().await;
    }
    tokio::time::sleep(RST_AVOIDANCE_DELAY).await;
}

async fn serve_loop(
    c: &Arc<ConnShared>,
    conn_cancel: &CancellationToken,
    remote_addr: String,
    local_addr: Option<SocketAddr>,
) {
    if let Some(d) = c.server.read_header_timeout() {
        c.set_read_deadline(Some(after(d)));
    }
    let mut last_method = String::new();

    loop {
        let read =
            conn_read_request(c, conn_cancel, &remote_addr, local_addr, &mut last_method).await;
        if c.server.shutting_down() {
            close_conn(c).await;
            return;
        }
        let (mut req, mut w) = match read {
            Ok(pair) => pair,
            Err(err) => {
                write_read_error(c, err).await;
                close_conn(c).await;
                return;
            }
        };

        if req.expects_continue() {
            if req.proto_at_least(1, 1) && req.content_length != 0 {
                let ec = Arc::new(ExpectContinue {
                    can_write: AtomicBool::new(true),
                    closed: AtomicBool::new(false),
                    saw_eof: AtomicBool::new(false),
                    mu: AsyncMutex::new(()),
                    bufw: c.bufw.clone(),
                });
                req.set_expect_body(ec.clone());
                w.ec = Some(ec);
            }
        } else if !req.header.get_raw("Expect").is_empty() {
            w.send_expectation_failed().await;
            close_conn(c).await;
            return;
        }

        // Start the read that notices a client hanging up. With a body it waits for the body's EOF.
        match &w.req_body {
            Some(body) => {
                let mut b = body.lock().await;
                if b.saw_eof {
                    lock(&c.conn_reader).start_background_read();
                } else {
                    b.start_bg_on_eof = Some(c.conn_reader.clone());
                }
            }
            None => lock(&c.conn_reader).start_background_read(),
        }

        let req_cancel = req.cancel.clone();
        let panicked = run_handler(c, &mut w, &mut req).await;
        req_cancel.cancel();

        if let Some(payload) = panicked {
            if !payload.is::<AbortHandler>() {
                tracing::error!(remote = %remote_addr, panic = %panic_message(payload.as_ref()), "http: panic serving");
            }
            if let Some(ec) = &w.ec {
                w.disable_write_continue_for(ec).await;
            }
            if !c.hijacked.load(Ordering::SeqCst) {
                lock(&c.conn_reader).abort_pending_read();
                if let Some(body) = &w.req_body {
                    let _ = core_close(body).await;
                }
                close_conn(c).await;
            }
            return;
        }

        if c.hijacked.load(Ordering::SeqCst) {
            return;
        }
        w.finish_request().await;
        c.set_write_deadline(None);
        if !w.should_reuse_connection().await {
            if w.request_body_limit_hit || w.closed_request_body_early().await {
                close_write_and_wait(c).await;
            }
            close_conn(c).await;
            return;
        }

        if !c.server.do_keep_alives() {
            close_conn(c).await;
            return;
        }

        c.set_read_deadline(c.server.idle_timeout().map(after));

        // Wait for the client to speak again before any header timeout starts. A pending shutdown
        // ends the wait, the way Shutdown closes an idle connection.
        let idle_reader = c.reader.clone();
        let peeked = {
            let mut br = idle_reader.lock().await;
            let shutdown = c.server.shutdown_notify.notified();
            tokio::pin!(shutdown);
            let keep_going = |server: &ServerInner| server.do_keep_alives();
            tokio::select! {
                (_, err) = br.peek(4) => err.is_none(),
                () = &mut shutdown => keep_going(&c.server),
            }
        };
        if !peeked {
            close_conn(c).await;
            return;
        }

        c.set_read_deadline(c.server.read_header_timeout().map(after));
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic".to_owned()
    }
}

/// Runs `serverHandler.ServeHTTP` with the background read polled alongside it. Returns the panic
/// payload if the handler panicked.
async fn run_handler(
    c: &Arc<ConnShared>,
    w: &mut Response,
    req: &mut Request,
) -> Option<Box<dyn std::any::Any + Send>> {
    let server = c.server.clone();
    let handler = server.handler.clone();
    let mut fut =
        std::pin::pin!(AssertUnwindSafe(serve_handler(&server, handler, w, req)).catch_unwind());
    let result = poll_fn(|cx| {
        if let Poll::Ready(res) = fut.as_mut().poll(cx) {
            return Poll::Ready(res);
        }
        lock(&c.conn_reader).poll_background(cx);
        Poll::Pending
    })
    .await;
    result.err()
}

/// `serverHandler.ServeHTTP`.
async fn serve_handler(
    server: &ServerInner,
    handler: BoxHandler,
    w: &mut Response,
    req: &mut Request,
) {
    if !server.config.disable_general_options_handler
        && req.request_uri == b"*"
        && req.method == "OPTIONS"
    {
        // globalOptionsHandler.
        w.header().set("Content-Length", "0");
        if req.content_length != 0 {
            let mut mb = max_bytes_reader(&*w, req.take_body(), 4 << 10);
            let mut buf = vec![0u8; 4096];
            loop {
                match mb.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        return;
    }
    handler.serve_http(w, req).await;
}

/// The error branches of `conn.serve`, which write to the socket directly.
async fn write_read_error(c: &ConnShared, err: ReqError) {
    const ERROR_HEADERS: &str =
        "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n";
    let write = |s: String| async move {
        let mut w = c.bufw.lock().await;
        w.write_direct(s.as_bytes()).await;
    };
    match err {
        ReqError::TooLarge => {
            const PUBLIC: &str = "431 Request Header Fields Too Large";
            write(format!("HTTP/1.1 {PUBLIC}{ERROR_HEADERS}{PUBLIC}")).await;
            close_write_and_wait(c).await;
        }
        ReqError::UnsupportedTe => {
            write(format!(
                "HTTP/1.1 501 Not Implemented{ERROR_HEADERS}Unsupported transfer encoding"
            ))
            .await;
        }
        ReqError::Eof | ReqError::NetRead => {}
        ReqError::Status(code, text) => {
            let st = status_text(code);
            write(format!(
                "HTTP/1.1 {code} {st}: {text}{ERROR_HEADERS}{code} {st}: {text}"
            ))
            .await;
        }
        ReqError::Bad => {
            const PUBLIC: &str = "400 Bad Request";
            write(format!("HTTP/1.1 {PUBLIC}{ERROR_HEADERS}{PUBLIC}")).await;
        }
    }
}

/// `c.readRequest`.
async fn conn_read_request(
    c: &Arc<ConnShared>,
    conn_cancel: &CancellationToken,
    remote_addr: &str,
    local_addr: Option<SocketAddr>,
    last_method: &mut String,
) -> Result<(Request, Response), ReqError> {
    let cfg = &c.server.config;
    let whole_req_deadline = cfg.read_timeout.map(after);
    let write_timeout = cfg.write_timeout;

    lock(&c.conn_reader).set_read_limit(c.server.initial_read_limit_size());
    if last_method == "POST" {
        // RFC 7230 section 3 tolerance for old buggy clients.
        let mut br = c.reader.lock().await;
        let (peek, _) = br.peek(4).await;
        let n = peek
            .iter()
            .take_while(|&&b| b == b'\r' || b == b'\n')
            .count();
        br.discard_buffered(n);
    }

    let req_cancel = conn_cancel.child_token();
    let result = read_request(&c.reader, req_cancel, remote_addr.to_owned(), local_addr).await;
    if let Some(d) = write_timeout {
        c.set_write_deadline(Some(after(d)));
    }
    let (mut req, core) = match result {
        Ok(pair) => pair,
        Err(e) => {
            if lock(&c.conn_reader).hit_read_limit() {
                return Err(ReqError::TooLarge);
            }
            return Err(e);
        }
    };

    // http1ServerSupportsRequest.
    let supported = req.proto_major == 1
        || (req.proto_major == 2
            && req.proto_minor == 0
            && req.method == "PRI"
            && req.request_uri == b"*");
    if !supported {
        return Err(ReqError::Status(505, "unsupported protocol version"));
    }

    last_method.clone_from(&req.method);
    lock(&c.conn_reader).set_infinite_read_limit();

    let hosts = req.header.values_raw("Host").map(<[Vec<u8>]>::to_vec);
    let is_h2_upgrade = req.is_h2_upgrade();
    if req.proto_at_least(1, 1)
        && hosts.as_ref().is_none_or(Vec::is_empty)
        && !is_h2_upgrade
        && req.method != "CONNECT"
    {
        return Err(ReqError::Status(400, "missing required Host header"));
    }
    if let Some(hosts) = &hosts
        && hosts.len() == 1
        && !valid_host_header(&hosts[0])
    {
        return Err(ReqError::Status(400, "malformed Host header"));
    }
    for (k, vv) in req.header.iter() {
        if !valid_header_field_name(k.as_bytes()) {
            return Err(ReqError::Status(400, "invalid header name"));
        }
        if !vv.iter().all(|v| valid_header_field_value(v)) {
            return Err(ReqError::Status(400, "invalid header value"));
        }
    }
    req.header.del_raw("Host");

    if let Some(core) = &core {
        core.lock().await.do_early_close = true;
    }

    c.set_read_deadline(whole_req_deadline);

    let w = Response {
        conn: c.clone(),
        is_head: req.method == "HEAD",
        is_connect: req.method == "CONNECT",
        proto_major: req.proto_major,
        proto_minor: req.proto_minor,
        req_content_length: req.content_length,
        req_body: core,
        body_kind: req.body_kind_cell(),
        ec: None,
        wrote_header: false,
        wants_10_keep_alive: req.wants_http10_keep_alive(),
        wants_close: req.wants_close(),
        handler_header: Header::new(),
        called_header: false,
        w_buf: Vec::with_capacity(BUFFER_BEFORE_CHUNKING_SIZE),
        w_err: None,
        cw_header: None,
        cw_wrote_header: false,
        cw_chunking: false,
        written: 0,
        content_length: -1,
        status: 0,
        close_after_reply: is_h2_upgrade,
        full_duplex: false,
        request_body_limit_hit: false,
        too_large: Arc::new(AtomicBool::new(false)),
        trailers: Vec::new(),
        handler_done: false,
        hijacked_local: false,
    };
    Ok((req, w))
}

/// `extraHeader`.
#[derive(Default)]
struct ExtraHeader {
    content_type: Option<&'static str>,
    connection: Option<&'static str>,
    transfer_encoding: Option<&'static str>,
    date: Option<String>,
    content_length: Option<String>,
}

impl ExtraHeader {
    /// `extraHeader.Write`: Date, Content-Length, Content-Type, Connection, Transfer-Encoding.
    fn write(&self, out: &mut Vec<u8>) {
        if let Some(date) = &self.date {
            out.extend_from_slice(b"Date: ");
            out.extend_from_slice(date.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if let Some(cl) = &self.content_length {
            out.extend_from_slice(b"Content-Length: ");
            out.extend_from_slice(cl.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        for (key, value) in [
            ("Content-Type", self.content_type),
            ("Connection", self.connection),
            ("Transfer-Encoding", self.transfer_encoding),
        ] {
            if let Some(v) = value
                && !v.is_empty()
            {
                out.extend_from_slice(key.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(v.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }
    }
}

/// `writeStatusLine`.
fn write_status_line(out: &mut Vec<u8>, is11: bool, code: u16) {
    out.extend_from_slice(if is11 { b"HTTP/1.1 " } else { b"HTTP/1.0 " });
    let text = status_text(code);
    if text.is_empty() {
        out.extend_from_slice(format!("{code:03} status code {code}\r\n").as_bytes());
    } else {
        out.extend_from_slice(format!("{code} {text}\r\n").as_bytes());
    }
}

/// `bodyAllowedForStatus`.
fn body_allowed_for_status(status: u16) -> bool {
    !((100..=199).contains(&status) || status == 204 || status == 304)
}

/// `response` and its `chunkWriter`, as one struct: Go wires them with a back pointer.
struct Response {
    conn: Arc<ConnShared>,
    is_head: bool,
    /// `isCONNECT := w.conn.lastMethod == "CONNECT"` (go1.26.10). Nothing in this crate mutates
    /// the request method after parsing, so reading it once at creation, like `is_head`, matches
    /// consulting the connection's last method.
    is_connect: bool,
    proto_major: u8,
    proto_minor: u8,
    req_content_length: i64,
    /// `w.reqBody`: the server's own body, whatever the handler later puts on the request.
    req_body: Option<Arc<AsyncMutex<BodyInner>>>,
    body_kind: Arc<BodyKindCell>,
    ec: Option<Arc<ExpectContinue>>,
    wrote_header: bool,
    wants_10_keep_alive: bool,
    wants_close: bool,
    handler_header: Header,
    called_header: bool,
    /// `w.w`: the 2 KiB `bufio.Writer` in front of the chunk writer.
    w_buf: Vec<u8>,
    w_err: Option<(io::ErrorKind, String)>,
    /// `cw.header`.
    cw_header: Option<Header>,
    cw_wrote_header: bool,
    cw_chunking: bool,
    written: i64,
    content_length: i64,
    status: u16,
    close_after_reply: bool,
    full_duplex: bool,
    request_body_limit_hit: bool,
    /// Set by `MaxBytesReader`; applied as `requestTooLarge` at the next point Go's result is visible.
    too_large: Arc<AtomicBool>,
    trailers: Vec<String>,
    handler_done: bool,
    hijacked_local: bool,
}

impl Response {
    fn proto_at_least(&self, major: u8, minor: u8) -> bool {
        self.proto_major > major || (self.proto_major == major && self.proto_minor >= minor)
    }

    fn apply_too_large(&mut self) {
        if self.too_large.swap(false, Ordering::SeqCst) {
            self.request_too_large();
        }
    }

    /// `w.requestTooLarge`.
    fn request_too_large(&mut self) {
        self.close_after_reply = true;
        self.request_body_limit_hit = true;
        if !self.wrote_header {
            self.header_inner().set("Connection", "close");
        }
    }

    /// `w.Header`.
    fn header_inner(&mut self) -> &mut Header {
        if self.cw_header.is_none() && self.wrote_header && !self.cw_wrote_header {
            self.cw_header = Some(self.handler_header.clone());
        }
        self.called_header = true;
        &mut self.handler_header
    }

    /// `w.disableWriteContinue`.
    async fn disable_write_continue_for(&self, ec: &ExpectContinue) {
        let _guard = ec.mu.lock().await;
        ec.can_write.store(false, Ordering::SeqCst);
    }

    async fn disable_write_continue(&self) {
        if let Some(ec) = &self.ec {
            self.disable_write_continue_for(ec).await;
        }
    }

    /// `w.WriteHeader`.
    async fn write_header_inner(&mut self, code: u16) {
        if self.conn.hijacked.load(Ordering::SeqCst) {
            tracing::warn!("http: response.WriteHeader on hijacked connection");
            return;
        }
        if self.wrote_header {
            tracing::warn!("http: superfluous response.WriteHeader call");
            return;
        }
        self.apply_too_large();
        // checkWriteHeaderCode: Go panics, ending the connection.
        assert!(
            (100..=999).contains(&code),
            "invalid WriteHeader code {code}"
        );

        if !(101..=199).contains(&code) {
            self.disable_write_continue().await;
        }

        if (100..=199).contains(&code) && code != 101 {
            let mut out = Vec::new();
            write_status_line(&mut out, self.proto_at_least(1, 1), code);
            self.handler_header
                .write_subset(&mut out, &["Content-Length", "Transfer-Encoding"]);
            out.extend_from_slice(b"\r\n");
            let mut bw = self.conn.bufw.lock().await;
            let _ = bw.write(&out).await;
            let _ = bw.flush().await;
            return;
        }

        self.wrote_header = true;
        self.status = code;

        if self.called_header && self.cw_header.is_none() {
            self.cw_header = Some(self.handler_header.clone());
        }

        let cl = self.handler_header.get_raw("Content-Length").to_vec();
        if !cl.is_empty() {
            match parse_int64(&cl) {
                Some(v) if v >= 0 => self.content_length = v,
                _ => {
                    tracing::warn!(value = %String::from_utf8_lossy(&cl), "http: invalid Content-Length");
                    self.handler_header.del("Content-Length");
                }
            }
        }
    }

    /// `cw.writeHeader`.
    async fn cw_write_header(&mut self, p: &[u8]) {
        if self.cw_wrote_header {
            return;
        }
        self.cw_wrote_header = true;
        self.apply_too_large();

        let keep_alives_enabled = self.conn.server.do_keep_alives();
        let is_head = self.is_head;

        // Go reads from cw.header when it owns a snapshot and from handlerHeader otherwise, but
        // handlerHeader can only hold values when a snapshot exists. See header_inner.
        let mut header = self.cw_header.take().unwrap_or_default();
        let mut set = ExtraHeader::default();

        let mut trailers = false;
        let mut exclude: Vec<String> = Vec::new();
        for (k, _) in header.iter() {
            if k.starts_with(TRAILER_PREFIX) {
                exclude.push(k.to_owned());
                trailers = true;
            }
        }
        if let Some(values) = header.values_raw("Trailer").map(<[Vec<u8>]>::to_vec) {
            for v in values {
                trailers = true;
                foreach_header_element(&v, |k| {
                    let k = canonical_header_key(&String::from_utf8_lossy(k));
                    if valid_trailer_header(&k) {
                        self.trailers.push(k);
                    }
                });
            }
        }

        let te = header.get_raw("Transfer-Encoding").to_vec();
        let has_te = !te.is_empty();

        if self.handler_done
            && !trailers
            && !has_te
            && body_allowed_for_status(self.status)
            && !header.has_raw("Content-Length")
            && (!is_head || !p.is_empty())
        {
            self.content_length = p.len() as i64;
            set.content_length = Some(p.len().to_string());
        }

        if self.wants_10_keep_alive && keep_alives_enabled {
            let sent_length = !header.get_raw("Content-Length").is_empty();
            if sent_length && header.get_raw("Connection") == b"keep-alive" {
                self.close_after_reply = false;
            }
        }

        let mut has_cl = self.content_length != -1;

        if self.wants_10_keep_alive && (is_head || has_cl || !body_allowed_for_status(self.status))
        {
            if !header.has_raw("Connection") {
                set.connection = Some("keep-alive");
            }
        } else if !self.proto_at_least(1, 1) || self.wants_close {
            self.close_after_reply = true;
        }

        if header.get_raw("Connection") == b"close" || !keep_alives_enabled {
            self.close_after_reply = true;
        }

        // A client that wanted 100-continue and whose body we did not finish reading: do not reuse.
        if let Some(ec) = &self.ec
            && self.body_kind.get() == BodyKind::Expect
            && !ec.saw_eof.load(Ordering::SeqCst)
        {
            self.close_after_reply = true;
        }

        if self.is_connect {
            // Don't reuse a connection after a CONNECT, even if we reject it.
            self.close_after_reply = true;
        }

        if self.req_content_length != 0 && !self.close_after_reply && !self.full_duplex {
            let mut discard = false;
            let mut too_big = false;
            match self.body_kind.get() {
                BodyKind::Expect => {}
                BodyKind::Core => {
                    if let Some(body) = &self.req_body {
                        let b = body.lock().await;
                        if b.closed {
                            if !b.saw_eof {
                                self.close_after_reply = true;
                            }
                        } else if b.unread_data_size() >= MAX_POST_HANDLER_READ_BYTES {
                            too_big = true;
                        } else {
                            discard = true;
                        }
                    } else {
                        discard = true;
                    }
                }
                BodyKind::Other => discard = true,
            }

            if discard {
                match self.discard_req_body().await {
                    DiscardResult::MoreLeft => too_big = true,
                    DiscardResult::AfterClose => {}
                    DiscardResult::Eof => {
                        let closed = match &self.req_body {
                            Some(body) => core_close(body).await,
                            None => Ok(()),
                        };
                        if closed.is_err() {
                            self.close_after_reply = true;
                        }
                    }
                    DiscardResult::Failed => self.close_after_reply = true,
                }
            }

            if too_big {
                self.request_too_large();
                header.del("Connection");
                set.connection = Some("close");
            }
        }

        let code = self.status;
        if body_allowed_for_status(code) {
            let have_type = header.has_raw("Content-Type");
            let has_ce = !header.get("Content-Encoding").is_empty();
            if !has_ce && !have_type && !has_te && !p.is_empty() {
                set.content_type = Some(detect_content_type(p));
            }
        } else {
            let suppressed: &[&str] = if code == 304 {
                &["Content-Type", "Content-Length", "Transfer-Encoding"]
            } else {
                &["Content-Length", "Transfer-Encoding"]
            };
            for k in suppressed {
                header.del(k);
            }
        }

        if !header.has_raw("Date") {
            set.date = Some(GoTime::now_utc().format(TIME_FORMAT));
        }

        if has_cl && has_te && te != b"identity" {
            tracing::warn!(
                te = %String::from_utf8_lossy(&te),
                content_length = self.content_length,
                "http: WriteHeader called with both Transfer-Encoding and a Content-Length"
            );
            header.del("Content-Length");
            has_cl = false;
        }

        let is_successful_connect = self.is_connect && (200..300).contains(&code);
        if is_successful_connect {
            // Tunnel established, connection is no longer HTTP.
            header.del("Transfer-Encoding");
            header.del("Content-Length");
            set.content_length = None;
        } else if self.is_head || !body_allowed_for_status(code) || code == 204 || has_cl {
            // No body, or a length that makes chunking unnecessary.
            header.del("Transfer-Encoding");
        } else if self.proto_at_least(1, 1) {
            if has_te && te == b"identity" {
                self.cw_chunking = false;
                self.close_after_reply = true;
                header.del("Transfer-Encoding");
            } else {
                self.cw_chunking = true;
                set.transfer_encoding = Some("chunked");
                if has_te && te == b"chunked" {
                    header.del("Transfer-Encoding");
                }
            }
        } else {
            self.close_after_reply = true;
            header.del("Transfer-Encoding");
        }

        if self.cw_chunking {
            header.del("Content-Length");
        }
        if !self.proto_at_least(1, 0) {
            self.cw_header = Some(header);
            return;
        }

        let del_connection = self.close_after_reply
            && (!keep_alives_enabled || !has_token(header.get_raw("Connection"), b"close"))
            && !is_protocol_switch_response(self.status, &header);
        if del_connection {
            header.del("Connection");
            // Don't set Connection: close on a 2xx CONNECT response, even though the connection
            // closes anyway if the handler doesn't hijack it: hijacking makes Connection: close
            // confusing. The `else` here is load-bearing on HTTP/1.0 (go1.26.10, fixed from
            // go1.26.7): it must clear a `keep-alive` staged above by the wants10KeepAlive branch
            // when a later conflict (e.g. Transfer-Encoding plus Content-Length) forces the
            // connection closed after all.
            if self.proto_at_least(1, 1) && !is_successful_connect {
                set.connection = Some("close");
            } else {
                set.connection = None;
            }
        }

        let mut out = Vec::with_capacity(256);
        write_status_line(&mut out, self.proto_at_least(1, 1), code);
        let exclude_refs: Vec<&str> = exclude.iter().map(String::as_str).collect();
        header.write_subset(&mut out, &exclude_refs);
        set.write(&mut out);
        out.extend_from_slice(b"\r\n");
        self.cw_header = Some(header);
        let mut bw = self.conn.bufw.lock().await;
        let _ = bw.write(&out).await;
    }

    /// `io.CopyN(io.Discard, w.reqBody, maxPostHandlerReadBytes+1)` and its error switch.
    async fn discard_req_body(&mut self) -> DiscardResult {
        let Some(body) = self.req_body.clone() else {
            return DiscardResult::Eof;
        };
        let limit = MAX_POST_HANDLER_READ_BYTES + 1;
        let mut total = 0i64;
        let mut buf = vec![0u8; 32 * 1024];
        while total < limit {
            let want = usize::try_from(limit - total).unwrap_or(0).min(buf.len());
            match core_read(&body, &mut buf[..want]).await {
                Ok(0) => return DiscardResult::Eof,
                Ok(n) => total += n as i64,
                Err(e) if is_body_read_after_close(&e) => return DiscardResult::AfterClose,
                Err(_) => return DiscardResult::Failed,
            }
        }
        DiscardResult::MoreLeft
    }

    /// `cw.Write`.
    async fn cw_write(&mut self, p: &[u8]) -> io::Result<usize> {
        if !self.cw_wrote_header {
            self.cw_write_header(p).await;
        }
        if self.is_head {
            return Ok(p.len());
        }
        let chunking = self.cw_chunking;
        let mut bw = self.conn.bufw.lock().await;
        let res = async {
            if chunking {
                bw.write(format!("{:x}\r\n", p.len()).as_bytes()).await?;
            }
            bw.write(p).await?;
            if chunking {
                bw.write(b"\r\n").await?;
            }
            Ok::<usize, io::Error>(p.len())
        }
        .await;
        if res.is_err() {
            bw.close();
        }
        res
    }

    /// `cw.flush`.
    async fn cw_flush(&mut self) -> io::Result<()> {
        if !self.cw_wrote_header {
            self.cw_write_header(&[]).await;
        }
        self.conn.bufw.lock().await.flush().await
    }

    /// `cw.close`.
    async fn cw_close(&mut self) {
        if !self.cw_wrote_header {
            self.cw_write_header(&[]).await;
        }
        if self.cw_chunking {
            let trailers = self.final_trailers();
            let mut out = b"0\r\n".to_vec();
            if let Some(t) = trailers {
                t.write_subset(&mut out, &[]);
            }
            out.extend_from_slice(b"\r\n");
            let _ = self.conn.bufw.lock().await.write(&out).await;
        }
    }

    /// `w.finalTrailers`.
    fn final_trailers(&self) -> Option<Header> {
        let mut t: Option<Header> = None;
        for (k, vv) in self.handler_header.iter() {
            if let Some(kk) = k.strip_prefix(TRAILER_PREFIX) {
                t.get_or_insert_with(Header::new).set_raw(kk, vv.to_vec());
            }
        }
        for k in &self.trailers {
            let t = t.get_or_insert_with(Header::new);
            for v in self.handler_header.values_raw(k).unwrap_or(&[]) {
                t.add(k, v);
            }
        }
        t
    }

    /// `w.w.Flush`.
    async fn w_flush(&mut self) -> io::Result<()> {
        if let Some((k, m)) = &self.w_err {
            return Err(io::Error::new(*k, m.clone()));
        }
        if self.w_buf.is_empty() {
            return Ok(());
        }
        let data = std::mem::take(&mut self.w_buf);
        let res = self.cw_write(&data).await;
        self.w_buf = data;
        self.w_buf.clear();
        if let Err(e) = &res {
            self.w_err = Some((e.kind(), e.to_string()));
        }
        res.map(|_| ())
    }

    /// `w.w.Write`.
    async fn w_write(&mut self, mut p: &[u8]) -> Result<usize, WriteError> {
        let mut nn = 0;
        while p.len() > BUFFER_BEFORE_CHUNKING_SIZE - self.w_buf.len() && self.w_err.is_none() {
            let n;
            if self.w_buf.is_empty() {
                match self.cw_write(p).await {
                    Ok(k) => n = k,
                    Err(e) => {
                        self.w_err = Some((e.kind(), e.to_string()));
                        n = 0;
                    }
                }
            } else {
                n = BUFFER_BEFORE_CHUNKING_SIZE - self.w_buf.len();
                self.w_buf.extend_from_slice(&p[..n]);
                let _ = self.w_flush().await;
            }
            nn += n;
            p = &p[n..];
        }
        if let Some((k, m)) = &self.w_err {
            return Err(WriteError::Io(io::Error::new(*k, m.clone())));
        }
        self.w_buf.extend_from_slice(p);
        Ok(nn + p.len())
    }

    /// `w.w.WriteString`: `chunkWriter` is no `io.StringWriter`, so a long string fills the buffer
    /// and flushes every 2 KiB instead of going past it.
    async fn w_write_string(&mut self, mut s: &[u8]) -> Result<usize, WriteError> {
        let mut nn = 0;
        while s.len() > BUFFER_BEFORE_CHUNKING_SIZE - self.w_buf.len() && self.w_err.is_none() {
            let n = BUFFER_BEFORE_CHUNKING_SIZE - self.w_buf.len();
            self.w_buf.extend_from_slice(&s[..n]);
            let _ = self.w_flush().await;
            nn += n;
            s = &s[n..];
        }
        if let Some((k, m)) = &self.w_err {
            return Err(WriteError::Io(io::Error::new(*k, m.clone())));
        }
        self.w_buf.extend_from_slice(s);
        Ok(nn + s.len())
    }

    /// The checks at the top of `w.write`.
    async fn before_write(&mut self, len: usize) -> Result<bool, WriteError> {
        if self.conn.hijacked.load(Ordering::SeqCst) {
            if len > 0 {
                tracing::warn!("http: response.Write on hijacked connection");
            }
            return Err(WriteError::Hijacked);
        }
        if self
            .ec
            .as_ref()
            .is_some_and(|ec| ec.can_write.load(Ordering::SeqCst))
        {
            self.disable_write_continue().await;
        }
        if !self.wrote_header {
            self.write_header_inner(200).await;
        }
        if len == 0 {
            return Ok(false);
        }
        if !body_allowed_for_status(self.status) {
            return Err(WriteError::BodyNotAllowed);
        }
        self.written += len as i64;
        if self.content_length != -1 && self.written > self.content_length {
            return Err(WriteError::ContentLength);
        }
        Ok(true)
    }

    /// `w.finishRequest`.
    async fn finish_request(&mut self) {
        self.handler_done = true;
        if !self.wrote_header {
            self.write_header_inner(200).await;
        }
        let _ = self.w_flush().await;
        self.cw_close().await;
        let _ = self.conn.bufw.lock().await.flush().await;

        lock(&self.conn.conn_reader).abort_pending_read();

        if let Some(body) = &self.req_body {
            let _ = core_close(body).await;
        }
        self.apply_too_large();
    }

    /// `w.shouldReuseConnection`.
    async fn should_reuse_connection(&self) -> bool {
        if self.close_after_reply {
            return false;
        }
        if !self.is_head
            && self.content_length != -1
            && body_allowed_for_status(self.status)
            && self.content_length != self.written
        {
            return false;
        }
        if self.conn.werr.load(Ordering::SeqCst) {
            return false;
        }
        !self.closed_request_body_early().await
    }

    /// `w.closedRequestBodyEarly`. Go asserts on `w.req.Body`, so a wrapped body never reports it.
    async fn closed_request_body_early(&self) -> bool {
        if self.body_kind.get() != BodyKind::Core {
            return false;
        }
        match &self.req_body {
            Some(body) => body.lock().await.early_close,
            None => false,
        }
    }

    /// `w.sendExpectationFailed`.
    async fn send_expectation_failed(&mut self) {
        self.header_inner().set("Connection", "close");
        self.write_header_inner(417).await;
        self.finish_request().await;
    }

    /// `w.ReadFrom`.
    async fn read_from_inner(
        &mut self,
        src: &mut (dyn AsyncRead + Send + Unpin),
    ) -> Result<i64, WriteError> {
        let mut buf = vec![0u8; 32 * 1024];
        let mut n = 0i64;

        if !self.cw_wrote_header {
            let mut n0 = 0usize;
            while n0 < SNIFF_LEN {
                let want = (SNIFF_LEN - n0).min(buf.len());
                let k = src.read(&mut buf[..want]).await.map_err(WriteError::Io)?;
                if k == 0 {
                    break;
                }
                self.write_inner(&buf[..k]).await?;
                n0 += k;
            }
            n += n0 as i64;
            if n0 < SNIFF_LEN {
                return Ok(n);
            }
        }

        let _ = self.w_flush().await;
        let _ = self.cw_flush().await;

        if !self.cw_chunking && body_allowed_for_status(self.status) && !self.is_head {
            // Go hands the socket to rf.ReadFrom here, which is where sendfile happens. The buffer
            // above is empty, so these writes reach the stream in order, and uncounted by `write`.
            loop {
                let k = src.read(&mut buf).await.map_err(WriteError::Io)?;
                if k == 0 {
                    return Ok(n);
                }
                self.conn
                    .bufw
                    .lock()
                    .await
                    .write(&buf[..k])
                    .await
                    .map_err(WriteError::Io)?;
                n += k as i64;
                self.written += k as i64;
            }
        }

        loop {
            let k = src.read(&mut buf).await.map_err(WriteError::Io)?;
            if k == 0 {
                return Ok(n);
            }
            self.write_inner(&buf[..k]).await?;
            n += k as i64;
        }
    }

    async fn write_inner(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        if !self.before_write(data.len()).await? {
            return Ok(0);
        }
        self.w_write(data).await
    }

    /// `w.Hijack`.
    async fn hijack_inner(&mut self) -> Result<Hijacked, WriteError> {
        assert!(
            !self.handler_done,
            "net/http: Hijack called after ServeHTTP finished"
        );
        self.disable_write_continue().await;
        if self.wrote_header {
            let _ = self.cw_flush().await;
        }
        if self.conn.hijacked.swap(true, Ordering::SeqCst) {
            return Err(WriteError::Hijacked);
        }
        self.hijacked_local = true;
        let (rd, byte) = lock(&self.conn.conn_reader).take_for_hijack();
        let wr = self.conn.bufw.lock().await.take_for_hijack();
        let mut read_buf = self.conn.reader.lock().await.take_buffered();
        if let Some(b) = byte {
            read_buf.push(b);
        }
        match (rd, wr) {
            (Some(rd), Some(wr)) => Ok(Hijacked {
                io: rd.unsplit(wr),
                read_buf,
            }),
            _ => Err(WriteError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection already closed",
            ))),
        }
    }
}

enum DiscardResult {
    MoreLeft,
    AfterClose,
    Eof,
    Failed,
}

/// `isProtocolSwitchResponse`.
fn is_protocol_switch_response(code: u16, h: &Header) -> bool {
    code == 101
        && !h.get("Upgrade").is_empty()
        && header_values_contains_token(h.values_raw("Connection").unwrap_or(&[]), b"Upgrade")
}

/// `strconv.ParseInt(s, 10, 64)`.
fn parse_int64(s: &[u8]) -> Option<i64> {
    std::str::from_utf8(s)
        .ok()?
        .parse::<i64>()
        .ok()
        .filter(|_| !s.starts_with(b"+") || s.len() > 1)
}

fn to_tokio(at: StdInstant) -> Instant {
    Instant::from_std(at)
}

impl ResponseWriter for Response {
    fn header(&mut self) -> &mut Header {
        self.header_inner()
    }

    fn write_header(&mut self, code: u16) -> BoxFuture<'_, ()> {
        Box::pin(self.write_header_inner(code))
    }

    fn write<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, Result<usize, WriteError>> {
        Box::pin(self.write_inner(data))
    }

    fn write_string<'a>(&'a mut self, data: &'a str) -> BoxFuture<'a, Result<usize, WriteError>> {
        Box::pin(async move {
            if !self.before_write(data.len()).await? {
                return Ok(0);
            }
            self.w_write_string(data.as_bytes()).await
        })
    }

    fn read_from<'a>(
        &'a mut self,
        src: &'a mut (dyn AsyncRead + Send + Unpin),
    ) -> BoxFuture<'a, Result<i64, WriteError>> {
        Box::pin(self.read_from_inner(src))
    }

    fn flush(&mut self) -> BoxFuture<'_, Result<(), WriteError>> {
        Box::pin(async move {
            if !self.wrote_header {
                self.write_header_inner(200).await;
            }
            let first = self.w_flush().await;
            let second = self.cw_flush().await;
            first.and(second).map_err(WriteError::Io)
        })
    }

    fn hijack(&mut self) -> BoxFuture<'_, Result<Hijacked, WriteError>> {
        Box::pin(self.hijack_inner())
    }

    fn set_read_deadline(&mut self, at: Option<StdInstant>) -> Result<(), WriteError> {
        self.conn.set_read_deadline(at.map(to_tokio));
        Ok(())
    }

    fn set_write_deadline(&mut self, at: Option<StdInstant>) -> Result<(), WriteError> {
        self.conn.set_write_deadline(at.map(to_tokio));
        Ok(())
    }

    fn enable_full_duplex(&mut self) -> Result<(), WriteError> {
        self.full_duplex = true;
        Ok(())
    }

    fn too_large_signal(&self) -> Option<Arc<AtomicBool>> {
        Some(self.too_large.clone())
    }
}
