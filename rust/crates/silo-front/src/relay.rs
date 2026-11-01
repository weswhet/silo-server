//! The connection engine: one client connection maps to one connection to Go, plus an in-process
//! connection to the native handlers when a request needs them.
//!
//! Requests are routed one at a time, but the bytes are relayed as they arrive in both directions: a
//! head is forwarded with only its forwarding headers rewritten, and bodies and responses are never
//! parsed past their framing, buffered, or decoded. A `101` turns the connection into a raw tunnel.
//! Go's timeouts apply to the client because a closed upstream closes the client.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use silo_http::{BoxedIo, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, duplex, split};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::sync::CancellationToken;

use crate::http1::{
    ChunkStatus, ChunkWalker, Framing, RequestHead, RequestScan, ResponseBody, ResponseScan,
    scan_request, scan_response,
};
use crate::native::Gate;
use crate::origin::{Origin, OriginLog};
use crate::trust::{self, TrustList};

const READ_CHUNK: usize = 64 * 1024;
/// Bytes of a next request held while the current one is answered.
const PIPELINE_LIMIT: usize = 64 * 1024;
/// `rstAvoidanceDelay`: how long a closing connection waits for the client to finish.
const RST_AVOIDANCE: Duration = Duration::from_millis(500);
/// How long a tunnel stays open after one side has finished.
const TUNNEL_LINGER: Duration = Duration::from_secs(60);
const TLS_HANDSHAKE_RECORD: u8 = 0x16;

/// What one listener needs for its connections.
pub struct ListenerCtx {
    pub name: String,
    pub upstream: SocketAddr,
    pub trust: Arc<TrustList>,
    pub origin: Option<Arc<OriginLog>>,
    /// The native handlers and their gate. Only the main listener has any.
    pub native: Option<(Server, Arc<Gate>)>,
    /// silo-http's reader, which gives requests the relay refused Go's answer.
    pub refusals: Server,
    pub distinct_sources: bool,
    /// The main listener also answers TLS on the same port (`lantls.NewListener`).
    pub tunnels_tls: bool,
}

struct Backend {
    rd: ReadHalf<BoxedIo>,
    wr: WriteHalf<BoxedIo>,
    /// Bytes read from the backend and not yet relayed.
    pending: Vec<u8>,
}

impl Backend {
    fn new(io: BoxedIo) -> Self {
        let (rd, wr) = split(io);
        Self {
            rd,
            wr,
            pending: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Go,
    Native,
}

struct Conn {
    ctx: Arc<ListenerCtx>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    crd: OwnedReadHalf,
    cwr: OwnedWriteHalf,
    cbuf: Vec<u8>,
    client_eof: bool,
    go: Option<Backend>,
    native: Option<Backend>,
    last: Option<Which>,
    /// Go discards up to four CR or LF bytes after a POST.
    after_post: bool,
}

/// What a request's body direction ended with.
#[derive(Default)]
struct RequestEnd {
    client_eof: bool,
    /// The body stopped at bad framing or a dead upstream, so the stream cannot carry another request.
    broken: bool,
}

#[derive(Default)]
struct ResponseEnd {
    upgraded: bool,
    close: bool,
    client_gone: bool,
    upstream_eof: bool,
}

/// Signals between the two directions of one exchange.
struct Signals {
    body_done: CancellationToken,
    response_done: CancellationToken,
    abort: CancellationToken,
}

/// Forwards the request body to the backend, then watches the client for a next request or a hangup.
async fn pump_request(
    crd: &mut OwnedReadHalf,
    cbuf: &mut Vec<u8>,
    wr: &mut WriteHalf<BoxedIo>,
    framing: Framing,
    sig: &Signals,
) -> RequestEnd {
    let mut end = RequestEnd::default();
    let mut left = match framing {
        Framing::Length(n) => n,
        _ => 0,
    };
    let mut walker = (framing == Framing::Chunked).then(ChunkWalker::default);
    let mut done = walker.is_none() && left == 0;

    while !done {
        if !cbuf.is_empty() {
            let (n, status) = match &mut walker {
                Some(w) => w.feed(cbuf),
                None => {
                    let n = usize::try_from(left).unwrap_or(usize::MAX).min(cbuf.len());
                    left -= n as u64;
                    let status = if left == 0 {
                        ChunkStatus::Done
                    } else {
                        ChunkStatus::More
                    };
                    (n, status)
                }
            };
            tokio::select! {
                r = wr.write_all(&cbuf[..n]) => {
                    if r.is_err() {
                        end.broken = true;
                        return end;
                    }
                }
                () = sig.abort.cancelled() => {
                    end.broken = true;
                    return end;
                }
            }
            cbuf.drain(..n);
            match status {
                ChunkStatus::Done => done = true,
                ChunkStatus::Malformed => {
                    // Go fails the body here and closes. Nothing after this point may reach it.
                    cbuf.clear();
                    end.broken = true;
                    return end;
                }
                ChunkStatus::More => {}
            }
            continue;
        }
        cbuf.reserve(READ_CHUNK);
        tokio::select! {
            r = crd.read_buf(cbuf) => match r {
                Ok(0) | Err(_) => {
                    let _ = wr.shutdown().await;
                    end.client_eof = true;
                    end.broken = true;
                    return end;
                }
                Ok(_) => {}
            },
            () = sig.abort.cancelled() => {
                end.broken = true;
                return end;
            }
        }
    }
    sig.body_done.cancel();

    // Go's background read: a hangup cancels the handler, so the backend must see it too.
    while cbuf.len() < PIPELINE_LIMIT && !end.client_eof {
        cbuf.reserve(READ_CHUNK);
        tokio::select! {
            r = crd.read_buf(cbuf) => {
                if matches!(r, Ok(0) | Err(_)) {
                    end.client_eof = true;
                    let _ = wr.shutdown().await;
                }
            }
            () = sig.response_done.cancelled() => return end,
            () = sig.abort.cancelled() => return end,
        }
    }
    tokio::select! {
        () = sig.response_done.cancelled() => {}
        () = sig.abort.cancelled() => {}
    }
    end
}

async fn read_more(rd: &mut ReadHalf<BoxedIo>, pending: &mut Vec<u8>) -> bool {
    pending.reserve(READ_CHUNK);
    matches!(rd.read_buf(pending).await, Ok(n) if n > 0)
}

/// Relays response bytes as they arrive, and leaves when the response ends.
async fn pump_response(
    rd: &mut ReadHalf<BoxedIo>,
    pending: &mut Vec<u8>,
    cwr: &mut OwnedWriteHalf,
    head_request: bool,
    sig: &Signals,
) -> ResponseEnd {
    let mut end = ResponseEnd::default();
    let client_gone = |end: &mut ResponseEnd| {
        end.client_gone = true;
        end.close = true;
        sig.abort.cancel();
    };

    // 1xx responses are relayed and followed by the real one.
    let head = loop {
        match scan_response(pending, head_request) {
            ResponseScan::Complete(h) => {
                if cwr.write_all(&pending[..h.head_len]).await.is_err() {
                    client_gone(&mut end);
                    sig.response_done.cancel();
                    return end;
                }
                pending.drain(..h.head_len);
                if h.status == 101 {
                    end.upgraded = true;
                    sig.response_done.cancel();
                    return end;
                }
                if (100..200).contains(&h.status) {
                    continue;
                }
                break Some(h);
            }
            ResponseScan::Garbage => break None,
            ResponseScan::Incomplete => {
                if !read_more(rd, pending).await {
                    let _ = cwr.write_all(pending).await;
                    pending.clear();
                    end.close = true;
                    end.upstream_eof = true;
                    sig.abort.cancel();
                    sig.response_done.cancel();
                    return end;
                }
            }
        }
    };

    let body = head.map_or(ResponseBody::Eof, |h| h.body);
    end.close = head.is_none_or(|h| h.close);
    let mut left = match body {
        ResponseBody::Length(n) => n,
        _ => 0,
    };
    let mut walker = (body == ResponseBody::Chunked).then(ChunkWalker::default);
    let mut done = matches!(body, ResponseBody::None | ResponseBody::Length(0));
    while !done {
        if !pending.is_empty() {
            let n = match (&mut walker, body) {
                (Some(w), _) => {
                    let (n, status) = w.feed(pending);
                    done = status != ChunkStatus::More;
                    // Past bad framing, nothing says where the next response starts.
                    end.close |= status == ChunkStatus::Malformed;
                    n
                }
                (None, ResponseBody::Eof) => pending.len(),
                (None, _) => {
                    let n = usize::try_from(left)
                        .unwrap_or(usize::MAX)
                        .min(pending.len());
                    left -= n as u64;
                    done = left == 0;
                    n
                }
            };
            if cwr.write_all(&pending[..n]).await.is_err() {
                client_gone(&mut end);
                sig.response_done.cancel();
                return end;
            }
            pending.drain(..n);
            continue;
        }
        if !read_more(rd, pending).await {
            // A body cut short reaches the client cut short.
            end.close = true;
            end.upstream_eof = true;
            sig.abort.cancel();
            sig.response_done.cancel();
            return end;
        }
    }
    sig.response_done.cancel();

    // The body direction may still be going. An upstream that gives up on it ends this exchange.
    tokio::select! {
        () = sig.body_done.cancelled() => {}
        () = sig.abort.cancelled() => {}
        alive = read_more(rd, pending) => {
            if !alive {
                end.upstream_eof = true;
                end.close = true;
                sig.abort.cancel();
            }
        }
    }
    end
}

/// Pumps bytes both ways until both sides finish, or one has been gone long enough.
async fn tunnel(
    crd: &mut OwnedReadHalf,
    cwr: &mut OwnedWriteHalf,
    cbuf: &mut Vec<u8>,
    backend: &mut Backend,
) {
    let up = async {
        if !cbuf.is_empty() {
            let _ = backend.wr.write_all(cbuf).await;
            cbuf.clear();
        }
        let _ = tokio::io::copy(crd, &mut backend.wr).await;
        let _ = backend.wr.shutdown().await;
    };
    let down = async {
        if !backend.pending.is_empty() {
            let _ = cwr.write_all(&backend.pending).await;
            backend.pending.clear();
        }
        let _ = tokio::io::copy(&mut backend.rd, cwr).await;
        let _ = cwr.shutdown().await;
    };
    tokio::pin!(up);
    tokio::pin!(down);
    tokio::select! {
        () = &mut up => { let _ = tokio::time::timeout(TUNNEL_LINGER, down).await; }
        () = &mut down => { let _ = tokio::time::timeout(TUNNEL_LINGER, up).await; }
    }
}

impl Conn {
    async fn dial_go(&mut self) -> bool {
        match crate::peer::dial(self.ctx.upstream, self.peer.ip(), self.ctx.distinct_sources).await
        {
            Ok(stream) => {
                self.go = Some(Backend::new(Box::new(stream)));
                true
            }
            Err(e) => {
                tracing::warn!(listener = %self.ctx.name, error = %e, "dialing the Go reference failed");
                false
            }
        }
    }

    fn open_engine(&self, server: &Server) -> Backend {
        let (near, far) = duplex(READ_CHUNK);
        let server = server.clone();
        let remote = self.peer.to_string();
        let local = self.local;
        tokio::spawn(async move { server.serve_connection(far, remote, local).await });
        Backend::new(Box::new(near))
    }

    /// `lantls.NewListener` looks at a connection's first byte only.
    fn starts_tls(&self) -> bool {
        self.ctx.tunnels_tls
            && self.last.is_none()
            && self.cbuf.first() == Some(&TLS_HANDSHAKE_RECORD)
    }

    fn record(&self, origin: Origin, method: &str, target: &[u8]) {
        if let Some(log) = &self.ctx.origin {
            log.record(&self.ctx.name, origin, method, target, self.peer.ip());
        }
    }

    /// Reads until a whole head is buffered. `None` ends the connection.
    async fn read_head(&mut self) -> Option<RequestScan> {
        loop {
            if self.after_post {
                let strip = self
                    .cbuf
                    .iter()
                    .take(4)
                    .take_while(|&&b| b == b'\r' || b == b'\n')
                    .count();
                if strip > 0 {
                    self.cbuf.drain(..strip);
                }
                if !self.cbuf.is_empty() {
                    self.after_post = false;
                }
            }
            if self.starts_tls() {
                return Some(RequestScan::Reject);
            }
            if !self.cbuf.is_empty() {
                match scan_request(&self.cbuf) {
                    RequestScan::Incomplete => {}
                    other => return Some(other),
                }
            }
            if self.client_eof {
                // Go answers a head cut short with its 400, and says nothing to a clean close.
                return if self.cbuf.is_empty() {
                    None
                } else {
                    Some(RequestScan::Reject)
                };
            }
            self.cbuf.reserve(READ_CHUNK);
            let mut go_buf = Vec::new();
            let mut native_buf = Vec::new();
            enum Wake {
                Client(std::io::Result<usize>),
                Go(bool),
                Native(bool),
            }
            let wake = {
                let go = self.go.as_mut();
                let native = self.native.as_mut();
                tokio::select! {
                    r = self.crd.read_buf(&mut self.cbuf) => Wake::Client(r),
                    alive = async {
                        match go {
                            Some(b) => read_more(&mut b.rd, &mut go_buf).await,
                            None => std::future::pending().await,
                        }
                    } => Wake::Go(alive),
                    alive = async {
                        match native {
                            Some(b) => read_more(&mut b.rd, &mut native_buf).await,
                            None => std::future::pending().await,
                        }
                    } => Wake::Native(alive),
                }
            };
            if let Some(b) = self.go.as_mut() {
                b.pending.append(&mut go_buf);
            }
            if let Some(b) = self.native.as_mut() {
                b.pending.append(&mut native_buf);
            }
            match wake {
                Wake::Client(Ok(0) | Err(_)) => self.client_eof = true,
                Wake::Client(Ok(_)) | Wake::Go(true) | Wake::Native(true) => {}
                // An upstream that closes an idle connection closes the client's too, which is how
                // Go's read and idle timeouts reach it. One the client wasn't using just goes away.
                Wake::Go(false) => {
                    self.go = None;
                    if self.last != Some(Which::Native) {
                        return None;
                    }
                }
                Wake::Native(false) => {
                    self.native = None;
                    if self.last != Some(Which::Go) {
                        return None;
                    }
                }
            }
        }
    }

    /// Gives the buffered bytes to silo-http's reader and relays what it says until it closes.
    async fn refuse(&mut self) {
        self.record(Origin::Reject, "", b"");
        let mut engine = self.open_engine(&self.ctx.refusals.clone());
        if self.client_eof {
            let _ = engine.wr.write_all(&self.cbuf).await;
            self.cbuf.clear();
            let _ = engine.wr.shutdown().await;
            let _ = tokio::io::copy(&mut engine.rd, &mut self.cwr).await;
            return;
        }
        tunnel(&mut self.crd, &mut self.cwr, &mut self.cbuf, &mut engine).await;
    }

    /// Closes after giving the client time to read what was sent.
    async fn close_gracefully(mut self) {
        let _ = self.cwr.shutdown().await;
        let drain = async {
            let mut sink = vec![0u8; READ_CHUNK];
            while matches!(self.crd.read(&mut sink).await, Ok(n) if n > 0) {}
        };
        let _ = tokio::time::timeout(RST_AVOIDANCE, drain).await;
    }

    /// Runs one request and response. True when the connection can take another.
    async fn exchange(&mut self, head: RequestHead) -> bool {
        let native = self
            .ctx
            .native
            .as_ref()
            .filter(|(_, gate)| gate.is_native(&head))
            .map(|(server, _)| server.clone());
        let which = if native.is_some() {
            Which::Native
        } else {
            Which::Go
        };
        let origin = if native.is_some() {
            Origin::Native
        } else {
            Origin::Go
        };
        self.record(origin, &head.method, &head.target);

        let out = if let Some(server) = native {
            if self.native.is_none() {
                self.native = Some(self.open_engine(&server));
            }
            self.cbuf[..head.head_len].to_vec()
        } else {
            if self.go.is_none() && !self.dial_go().await {
                self.write_bad_gateway().await;
                return false;
            }
            let peer: IpAddr = self.peer.ip();
            let rewrite = trust::plan(&self.ctx.trust, peer, &head);
            trust::apply(&self.cbuf, &head, &rewrite)
        };
        self.cbuf.drain(..head.head_len);
        self.after_post = head.method == "POST";
        self.last = Some(which);

        let backend = match which {
            Which::Go => self.go.as_mut(),
            Which::Native => self.native.as_mut(),
        };
        let Some(backend) = backend else {
            return false;
        };
        if backend.wr.write_all(&out).await.is_err() {
            match which {
                Which::Go => self.go = None,
                Which::Native => self.native = None,
            }
            self.write_bad_gateway().await;
            return false;
        }

        let sig = Signals {
            body_done: CancellationToken::new(),
            response_done: CancellationToken::new(),
            abort: CancellationToken::new(),
        };
        let head_request = head.method == "HEAD";
        let (req_end, resp_end) = tokio::join!(
            pump_request(
                &mut self.crd,
                &mut self.cbuf,
                &mut backend.wr,
                head.framing,
                &sig
            ),
            pump_response(
                &mut backend.rd,
                &mut backend.pending,
                &mut self.cwr,
                head_request,
                &sig
            ),
        );

        if resp_end.upgraded {
            tunnel(&mut self.crd, &mut self.cwr, &mut self.cbuf, backend).await;
            return false;
        }
        self.client_eof |= req_end.client_eof;
        let reusable = !resp_end.close
            && !resp_end.upstream_eof
            && !resp_end.client_gone
            && !req_end.broken
            && !self.client_eof;
        if !reusable {
            match which {
                Which::Go => self.go = None,
                Which::Native => self.native = None,
            }
        }
        reusable
    }

    async fn write_bad_gateway(&mut self) {
        let body = "the Go reference is unreachable\n";
        let reply = format!(
            "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = self.cwr.write_all(reply.as_bytes()).await;
    }
}

/// Serves one client connection.
pub async fn serve_client(ctx: Arc<ListenerCtx>, client: TcpStream, peer: SocketAddr) {
    let _ = client.set_nodelay(true);
    let local = client.local_addr().ok();
    let (crd, cwr) = client.into_split();
    let mut conn = Conn {
        ctx,
        peer,
        local,
        crd,
        cwr,
        cbuf: Vec::new(),
        client_eof: false,
        go: None,
        native: None,
        last: None,
        after_post: false,
    };
    // Dialed up front so Go's read timeout covers a client that connects and says nothing.
    conn.dial_go().await;

    loop {
        let scan = match conn.read_head().await {
            Some(scan) => scan,
            None => break,
        };
        if conn.starts_tls() {
            serve_tls(&mut conn).await;
            return;
        }
        match scan {
            RequestScan::Complete(head) => {
                if !conn.exchange(*head).await {
                    break;
                }
            }
            RequestScan::Reject => {
                conn.refuse().await;
                break;
            }
            RequestScan::Incomplete => unreachable!("read_head waits past an incomplete head"),
        }
    }
    conn.close_gracefully().await;
}

/// TLS on the main port is Go's for now. The bytes inside can't be sanitized, so only a peer Go would
/// trust with its forwarding headers anyway gets through.
async fn serve_tls(conn: &mut Conn) {
    if !conn.ctx.trust.is_trusted(conn.peer.ip()) {
        tracing::warn!(peer = %conn.peer, "refusing TLS from an untrusted peer: this relay cannot sanitize it");
        return;
    }
    conn.record(Origin::Tunnel, "TLS", b"");
    if conn.go.is_none() && !conn.dial_go().await {
        return;
    }
    if let Some(backend) = conn.go.as_mut() {
        tunnel(&mut conn.crd, &mut conn.cwr, &mut conn.cbuf, backend).await;
    }
}
