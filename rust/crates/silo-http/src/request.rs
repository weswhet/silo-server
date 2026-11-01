//! Ports of `http.Request`, `readRequest`, and the request half of `net/http/transfer.go`, plus the
//! chunked reader from `net/http/internal`.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http::Extensions;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use crate::bufio::{BufReader, ConnReader, ConnWriter, MimeError, ReadErr, lock};
use crate::chi::Context as RouteContext;
use crate::header::{
    Header, ascii_equal_fold, canonical_header_key, foreach_header_element, has_token,
    header_values_contains_token, trim_string, valid_header_field_name,
};
use crate::response::{BoxFuture, ResponseWriter};
use crate::url::{Url, parse_request_uri};

/// `maxPostHandlerReadBytes`.
pub(crate) const MAX_POST_HANDLER_READ_BYTES: i64 = 256 << 10;

/// `http.ErrBodyReadAfterClose`'s text.
const BODY_READ_AFTER_CLOSE: &str = "http: invalid Read on closed Body";

pub(crate) fn body_read_after_close() -> io::Error {
    io::Error::other(BODY_READ_AFTER_CLOSE)
}

pub(crate) fn is_body_read_after_close(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::Other && e.to_string() == BODY_READ_AFTER_CLOSE
}

fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// `io.ReadCloser`, the type of `r.Body`. `read` returning `Ok(0)` is `io.EOF`.
pub trait ReadCloser: Send + Sync {
    /// `r.Read`.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>>;
    /// `r.Close`.
    fn close(&mut self) -> BoxFuture<'_, io::Result<()>>;
}

/// `r.Body`.
pub type Body = Box<dyn ReadCloser>;

/// `http.NoBody`.
pub struct NoBody;

impl ReadCloser for NoBody {
    fn read<'a>(&'a mut self, _buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async { Ok(0) })
    }
    fn close(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// What `w.req.Body` holds, which Go checks with a type switch when it writes the response header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BodyKind {
    Core = 0,
    Expect = 1,
    Other = 2,
}

/// Lets the response see which body type the handler left on the request.
#[derive(Debug, Default)]
pub(crate) struct BodyKindCell(AtomicU8);

impl BodyKindCell {
    pub(crate) fn set(&self, k: BodyKind) {
        self.0.store(k as u8, Ordering::SeqCst);
    }
    pub(crate) fn get(&self) -> BodyKind {
        match self.0.load(Ordering::SeqCst) {
            0 => BodyKind::Core,
            1 => BodyKind::Expect,
            _ => BodyKind::Other,
        }
    }
}

/// `http.Request` on the server side.
pub struct Request {
    /// `r.Method`. Any token, and case-sensitive.
    pub method: String,
    /// `r.URL`.
    pub url: Url,
    /// `r.Proto`.
    pub proto: String,
    pub proto_major: u8,
    pub proto_minor: u8,
    /// `r.Header`, with `Host` and `Transfer-Encoding` removed as Go removes them.
    pub header: Header,
    /// `r.ContentLength`: -1 for chunked.
    pub content_length: i64,
    /// `r.TransferEncoding`.
    pub transfer_encoding: Vec<String>,
    /// `r.Close`.
    pub close: bool,
    /// `r.Host`.
    pub host: Vec<u8>,
    /// `r.RemoteAddr`.
    pub remote_addr: String,
    /// `r.RequestURI`, untouched.
    pub request_uri: Vec<u8>,
    /// `r.Pattern`.
    pub pattern: String,
    /// `http.LocalAddrContextKey`.
    pub local_addr: Option<std::net::SocketAddr>,
    /// `r.Context().Value`: request-scoped values.
    pub extensions: Extensions,
    /// `r.Context().Done()`: fires when the client hangs up or the handler returns.
    pub cancel: CancellationToken,
    pub(crate) route_ctx: Option<Box<RouteContext>>,
    pub(crate) path_values: Vec<(String, Vec<u8>)>,
    body: Body,
    body_kind: Arc<BodyKindCell>,
    trailer: Arc<Mutex<Option<Header>>>,
}

impl Request {
    /// `r.Body`.
    pub fn body(&mut self) -> &mut dyn ReadCloser {
        self.body.as_mut()
    }

    /// `r.Body = b`. Go's server treats a replaced body differently when it writes the header.
    pub fn set_body(&mut self, b: Body) {
        self.body = b;
        self.body_kind.set(BodyKind::Other);
    }

    /// Takes `r.Body` out so it can be wrapped and put back with [`Request::set_body`].
    pub fn take_body(&mut self) -> Body {
        std::mem::replace(&mut self.body, Box::new(NoBody))
    }

    /// `io.ReadAll(r.Body)`: the bytes before any error, then the error if one ended the read.
    pub async fn read_all(&mut self) -> (Vec<u8>, Option<io::Error>) {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            match self.body.read(&mut buf).await {
                Ok(0) => return (out, None),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return (out, Some(e)),
            }
        }
    }

    /// `r.Trailer`: keys announced by `Trailer`, with values once the body has been read.
    pub fn trailer(&self) -> Option<Header> {
        lock(&self.trailer).clone()
    }

    /// `r.ProtoAtLeast`.
    pub fn proto_at_least(&self, major: u8, minor: u8) -> bool {
        self.proto_major > major || (self.proto_major == major && self.proto_minor >= minor)
    }

    /// `r.PathValue`.
    pub fn path_value(&self, name: &str) -> &[u8] {
        self.path_values
            .iter()
            .find(|(k, _)| k == name)
            .map_or(&[], |(_, v)| v.as_slice())
    }

    /// `r.SetPathValue`.
    pub fn set_path_value(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        let value = value.into();
        if let Some(entry) = self.path_values.iter_mut().find(|(k, _)| k == name) {
            entry.1 = value;
        } else {
            self.path_values.push((name.to_owned(), value));
        }
    }

    /// `chi.RouteContext(r.Context())`.
    pub fn route_context(&self) -> Option<&RouteContext> {
        self.route_ctx.as_deref()
    }

    /// `chi.RouteContext(r.Context())`, for middleware that rewrites `RoutePath` or `RouteMethod`.
    pub fn route_context_mut(&mut self) -> Option<&mut RouteContext> {
        self.route_ctx.as_deref_mut()
    }

    /// `chi.URLParam` as bytes, which is what a decoded path segment can hold.
    pub fn url_param_bytes(&self, key: &str) -> &[u8] {
        self.route_ctx.as_ref().map_or(&[], |c| c.url_param(key))
    }

    /// `chi.URLParam`. A value that is not UTF-8 reads as empty; see [`Request::url_param_bytes`].
    pub fn url_param(&self, key: &str) -> &str {
        std::str::from_utf8(self.url_param_bytes(key)).unwrap_or("")
    }

    /// `r.Cookie`, `r.FormValue` and friends parse from these; `r.URL.RawQuery` as text.
    pub fn raw_query_str(&self) -> &str {
        std::str::from_utf8(&self.url.raw_query).unwrap_or("")
    }

    /// `r.wantsHttp10KeepAlive`.
    pub(crate) fn wants_http10_keep_alive(&self) -> bool {
        self.proto_major == 1
            && self.proto_minor == 0
            && has_token(self.header.get_raw("Connection"), b"keep-alive")
    }

    /// `r.wantsClose`.
    pub(crate) fn wants_close(&self) -> bool {
        self.close || has_token(self.header.get_raw("Connection"), b"close")
    }

    /// `r.expectsContinue`.
    pub(crate) fn expects_continue(&self) -> bool {
        has_token(self.header.get_raw("Expect"), b"100-continue")
    }

    /// `r.isH2Upgrade`.
    pub(crate) fn is_h2_upgrade(&self) -> bool {
        self.method == "PRI"
            && self.header.is_empty()
            && self.url.path == b"*"
            && self.proto == "HTTP/2.0"
    }

    pub(crate) fn set_expect_body(&mut self, shared: Arc<ExpectContinue>) {
        let inner = self.take_body();
        self.body = Box::new(ExpectContinueReader { inner, shared });
        self.body_kind.set(BodyKind::Expect);
    }

    pub(crate) fn body_kind_cell(&self) -> Arc<BodyKindCell> {
        self.body_kind.clone()
    }

    /// Builds a request with no connection behind it, for `httptest.NewRequest`-style handler tests.
    pub fn new_for_test(method: &str, target: &str) -> Self {
        let url = parse_request_uri(target.as_bytes()).unwrap_or_default();
        Self {
            method: method.to_owned(),
            host: b"example.com".to_vec(),
            proto: "HTTP/1.1".to_owned(),
            proto_major: 1,
            proto_minor: 1,
            header: Header::new(),
            content_length: 0,
            transfer_encoding: Vec::new(),
            close: false,
            remote_addr: "192.0.2.1:1234".to_owned(),
            request_uri: target.as_bytes().to_vec(),
            pattern: String::new(),
            local_addr: None,
            extensions: Extensions::new(),
            cancel: CancellationToken::new(),
            route_ctx: None,
            path_values: Vec::new(),
            body: Box::new(NoBody),
            body_kind: Arc::new(BodyKindCell::default()),
            trailer: Arc::new(Mutex::new(None)),
            url,
        }
    }
}

/// Why `readRequest` failed, in the classes `conn.serve` tells apart.
#[derive(Debug)]
pub(crate) enum ReqError {
    /// `io.EOF` on the request line: the client went away between requests. No reply.
    Eof,
    /// A socket read error or timeout. No reply.
    NetRead,
    /// `errTooLarge`.
    TooLarge,
    /// `unsupportedTEError`.
    UnsupportedTe,
    /// `statusError`.
    Status(u16, &'static str),
    /// Anything else: a plain 400.
    Bad,
}

fn from_read_err(e: ReadErr) -> ReqError {
    match e {
        // A read error here is an *net.OpError with Op "read", or a timeout.
        ReadErr::Io(_) => ReqError::NetRead,
        // EOF past the request line becomes io.ErrUnexpectedEOF, which is not a common read error.
        ReadErr::Eof | ReadErr::BufferFull => ReqError::Bad,
    }
}

fn parse_http_version(vers: &[u8]) -> Option<(u8, u8)> {
    match vers {
        b"HTTP/1.1" => return Some((1, 1)),
        b"HTTP/1.0" => return Some((1, 0)),
        _ => {}
    }
    if !vers.starts_with(b"HTTP/") || vers.len() != 8 || vers[6] != b'.' {
        return None;
    }
    if !vers[5].is_ascii_digit() || !vers[7].is_ascii_digit() {
        return None;
    }
    Some((vers[5] - b'0', vers[7] - b'0'))
}

/// `parseContentLength`.
fn parse_content_length(values: &[Vec<u8>]) -> Result<i64, ReqError> {
    let Some(first) = values.first() else {
        return Ok(-1);
    };
    let cl = trim_string(first);
    if cl.is_empty() || !cl.iter().all(u8::is_ascii_digit) {
        return Err(ReqError::Bad);
    }
    // strconv.ParseUint(cl, 10, 63).
    let mut n: u64 = 0;
    for &c in cl {
        n = n.checked_mul(10).ok_or(ReqError::Bad)?;
        n = n.checked_add(u64::from(c - b'0')).ok_or(ReqError::Bad)?;
        if n >= 1 << 63 {
            return Err(ReqError::Bad);
        }
    }
    Ok(n as i64)
}

/// `readRequest` and `readTransfer`. The caller handles the checks in `conn.readRequest`.
pub(crate) async fn read_request(
    reader: &Arc<AsyncMutex<BufReader>>,
    cancel: CancellationToken,
    remote_addr: String,
    local_addr: Option<std::net::SocketAddr>,
) -> Result<(Request, Option<Arc<AsyncMutex<BodyInner>>>), ReqError> {
    let mut br = reader.lock().await;
    let line = match br.read_full_line().await {
        Ok(l) => l,
        Err(ReadErr::Eof) => return Err(ReqError::Eof),
        Err(e) => return Err(from_read_err(e)),
    };
    // Past this point an EOF is io.ErrUnexpectedEOF.

    let (method, rest) = cut(&line, b' ').ok_or(ReqError::Bad)?;
    let (request_uri, proto) = cut(rest, b' ').ok_or(ReqError::Bad)?;
    if !valid_header_field_name(method) {
        return Err(ReqError::Bad);
    }
    let method = String::from_utf8_lossy(method).into_owned();
    let (proto_major, proto_minor) = parse_http_version(proto).ok_or(ReqError::Bad)?;
    let proto = String::from_utf8_lossy(proto).into_owned();

    let just_authority = method == "CONNECT" && !request_uri.starts_with(b"/");
    let mut url = if just_authority {
        let mut raw = b"http://".to_vec();
        raw.extend_from_slice(request_uri);
        parse_request_uri(&raw).map_err(|_| ReqError::Bad)?
    } else {
        parse_request_uri(request_uri).map_err(|_| ReqError::Bad)?
    };
    if just_authority {
        url.scheme.clear();
    }

    let mut header = br.read_mime_header().await.map_err(|e| match e {
        MimeError::Read(e) => from_read_err(e),
        MimeError::Protocol(_) => ReqError::Bad,
    })?;
    if header.values_raw("Host").is_some_and(|h| h.len() > 1) {
        return Err(ReqError::Bad);
    }
    let host = if url.host.is_empty() {
        header.get_raw("Host").to_vec()
    } else {
        url.host.clone()
    };

    // fixPragmaCacheControl.
    if header
        .values_raw("Pragma")
        .and_then(|p| p.first())
        .is_some_and(|p| p == b"no-cache")
        && !header.has_raw("Cache-Control")
    {
        header.set_raw("Cache-Control", vec![b"no-cache".to_vec()]);
    }

    // shouldClose(major, minor, header, false).
    let conn_values = header.values_raw("Connection").unwrap_or(&[]);
    let has_close = header_values_contains_token(conn_values, b"close");
    let mut close = if proto_major < 1 {
        true
    } else if proto_major == 1 && proto_minor == 0 {
        has_close || !header_values_contains_token(conn_values, b"keep-alive")
    } else {
        has_close
    };

    // parseTransferEncoding.
    let mut chunked = false;
    if let Some(raw) = header
        .values_raw("Transfer-Encoding")
        .map(<[Vec<u8>]>::to_vec)
    {
        header.del_raw("Transfer-Encoding");
        if proto_major > 1 || (proto_major == 1 && proto_minor >= 1) {
            if raw.len() != 1 || !ascii_equal_fold(&raw[0], b"chunked") {
                return Err(ReqError::UnsupportedTe);
            }
            chunked = true;
        }
    }

    // fixLength for a request, which transfer.go treats as a 200 response to `method`.
    let mut content_lens = header
        .values_raw("Content-Length")
        .map(<[Vec<u8>]>::to_vec)
        .unwrap_or_default();
    if content_lens.len() > 1 {
        let first = trim_string(&content_lens[0]).to_vec();
        if content_lens[1..]
            .iter()
            .any(|ct| trim_string(ct) != first.as_slice())
        {
            return Err(ReqError::Bad);
        }
        header.set_raw("Content-Length", vec![first.clone()]);
        content_lens = vec![first];
    }
    let mut n = 0;
    if !content_lens.is_empty() {
        n = parse_content_length(&content_lens)?;
    }
    let real_length = if chunked {
        header.del_raw("Content-Length");
        -1
    } else if !content_lens.is_empty() {
        n
    } else {
        header.del_raw("Content-Length");
        0
    };

    // fixTrailer.
    let mut trailer: Option<Header> = None;
    if let Some(vv) = header.values_raw("Trailer").map(<[Vec<u8>]>::to_vec)
        && chunked
    {
        header.del_raw("Trailer");
        let mut t = Header::new();
        let mut bad = false;
        for v in &vv {
            foreach_header_element(v, |key| {
                let key = canonical_header_key(&String::from_utf8_lossy(key));
                if matches!(
                    key.as_str(),
                    "Transfer-Encoding" | "Trailer" | "Content-Length"
                ) {
                    bad = true;
                    return;
                }
                t.set_raw(key, Vec::new());
            });
        }
        if bad {
            return Err(ReqError::Bad);
        }
        if !t.is_empty() {
            trailer = Some(t);
        }
    }

    let trailer = Arc::new(Mutex::new(trailer));
    let mut content_length = real_length;
    let inner = if chunked {
        Some(BodySrc::Chunked(ChunkedReader::default()))
    } else if real_length > 0 {
        Some(BodySrc::Limited(real_length))
    } else {
        None
    };
    drop(br);

    let core = inner.map(|src| {
        Arc::new(AsyncMutex::new(BodyInner {
            has_hdr: matches!(src, BodySrc::Chunked(_)),
            src,
            reader: reader.clone(),
            closing: close,
            do_early_close: false,
            saw_eof: false,
            closed: false,
            early_close: false,
            start_bg_on_eof: None,
            trailer: trailer.clone(),
            pending_err: None,
        }))
    });
    let body: Body = match &core {
        Some(inner) => Box::new(CoreBody(inner.clone())),
        None => Box::new(NoBody),
    };

    let mut req = Request {
        method,
        url,
        proto,
        proto_major,
        proto_minor,
        header,
        content_length,
        transfer_encoding: if chunked {
            vec!["chunked".to_owned()]
        } else {
            Vec::new()
        },
        close,
        host,
        remote_addr,
        request_uri: request_uri.to_vec(),
        pattern: String::new(),
        local_addr,
        extensions: Extensions::new(),
        cancel,
        route_ctx: None,
        path_values: Vec::new(),
        body,
        body_kind: Arc::new(BodyKindCell::default()),
        trailer,
    };
    if req.is_h2_upgrade() {
        content_length = -1;
        close = true;
        req.content_length = content_length;
        req.close = close;
    }
    Ok((req, core))
}

fn cut(s: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let i = s.iter().position(|&b| b == sep)?;
    Some((&s[..i], &s[i + 1..]))
}

pub(crate) enum BodySrc {
    /// `io.LimitReader(r, n)`, holding the bytes remaining.
    Limited(i64),
    Chunked(ChunkedReader),
}

/// The state of `http.body`, shared by the handler's reader and the response, which drains it.
pub(crate) struct BodyInner {
    src: BodySrc,
    reader: Arc<AsyncMutex<BufReader>>,
    /// `b.hdr != nil`: a trailer is still to come.
    has_hdr: bool,
    closing: bool,
    pub(crate) do_early_close: bool,
    pub(crate) saw_eof: bool,
    pub(crate) closed: bool,
    pub(crate) early_close: bool,
    /// `b.onHitEOF`: `startBackgroundRead`.
    pub(crate) start_bg_on_eof: Option<Arc<Mutex<ConnReader>>>,
    trailer: Arc<Mutex<Option<Header>>>,
    /// Go can return data and an error from one Read. This holds the error for the next call.
    pending_err: Option<io::Error>,
}

impl BodyInner {
    /// `b.unreadDataSizeLocked`.
    pub(crate) fn unread_data_size(&self) -> i64 {
        match self.src {
            BodySrc::Limited(n) => n,
            BodySrc::Chunked(_) => -1,
        }
    }

    fn hit_eof(&mut self) {
        if let Some(cr) = &self.start_bg_on_eof {
            lock(cr).start_background_read();
        }
    }

    /// `b.readLocked`.
    async fn read_locked(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.saw_eof {
            return Ok(0);
        }
        let reader = self.reader.clone();
        let mut br = reader.lock().await;
        let (n, err): (usize, Option<SrcErr>) = match &mut self.src {
            BodySrc::Limited(remaining) => {
                if *remaining <= 0 {
                    (0, Some(SrcErr::Eof))
                } else {
                    let max = p
                        .len()
                        .min(usize::try_from(*remaining).unwrap_or(usize::MAX));
                    match br.read(&mut p[..max]).await {
                        Ok(n) => {
                            *remaining -= n as i64;
                            (n, None)
                        }
                        Err(ReadErr::Eof) => (0, Some(SrcErr::Eof)),
                        Err(ReadErr::BufferFull) => (
                            0,
                            Some(SrcErr::Other(io::Error::other("bufio: buffer full"))),
                        ),
                        Err(ReadErr::Io(e)) => (0, Some(SrcErr::Other(e))),
                    }
                }
            }
            BodySrc::Chunked(cr) => cr.read(&mut br, p).await,
        };
        let mut result_err: Option<io::Error> = None;
        match err {
            Some(SrcErr::Eof) => {
                self.saw_eof = true;
                if self.has_hdr {
                    if let Err(e) = read_trailer(&mut br, &self.trailer).await {
                        // Nothing more may be read from this body or this connection.
                        self.saw_eof = false;
                        self.closed = true;
                        result_err = Some(e);
                    }
                    self.has_hdr = false;
                } else if let BodySrc::Limited(remaining) = self.src
                    && remaining > 0
                {
                    result_err = Some(unexpected_eof());
                }
            }
            Some(SrcErr::Other(e)) => result_err = Some(e),
            None => {
                if n > 0
                    && let BodySrc::Limited(0) = self.src
                {
                    self.saw_eof = true;
                }
            }
        }
        drop(br);
        if self.saw_eof {
            self.hit_eof();
        }
        match result_err {
            Some(e) if n > 0 => {
                self.pending_err = Some(e);
                Ok(n)
            }
            Some(e) => Err(e),
            None => Ok(n),
        }
    }

    /// `b.Close`.
    async fn close_locked(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        let mut res = Ok(());
        if self.saw_eof || (!self.has_hdr && self.closing) {
            // Nothing left to read, or the connection is closing with no trailer to look for.
        } else if self.do_early_close {
            if let BodySrc::Limited(n) = self.src
                && n > MAX_POST_HANDLER_READ_BYTES
            {
                self.early_close = true;
            } else {
                let mut total: i64 = 0;
                let mut buf = vec![0u8; 32 * 1024];
                let mut err = None;
                while total < MAX_POST_HANDLER_READ_BYTES {
                    let want = usize::try_from(MAX_POST_HANDLER_READ_BYTES - total)
                        .unwrap_or(0)
                        .min(buf.len());
                    match self.read_locked(&mut buf[..want]).await {
                        Ok(0) => break,
                        Ok(n) => total += n as i64,
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = err {
                    res = Err(e);
                }
                if total == MAX_POST_HANDLER_READ_BYTES {
                    self.early_close = true;
                }
            }
        } else {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match self.read_locked(&mut buf).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => {
                        res = Err(e);
                        break;
                    }
                }
            }
        }
        self.closed = true;
        res
    }
}

enum SrcErr {
    Eof,
    Other(io::Error),
}

/// `http.body`, as the handler sees it.
pub(crate) struct CoreBody(pub(crate) Arc<AsyncMutex<BodyInner>>);

impl ReadCloser for CoreBody {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(core_read(&self.0, buf))
    }
    fn close(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(core_close(&self.0))
    }
}

/// `b.Read`.
pub(crate) async fn core_read(inner: &AsyncMutex<BodyInner>, buf: &mut [u8]) -> io::Result<usize> {
    let mut b = inner.lock().await;
    // An error Go returned along with the last data comes first, even if it also closed the body.
    if let Some(e) = b.pending_err.take() {
        return Err(e);
    }
    if b.closed {
        return Err(body_read_after_close());
    }
    b.read_locked(buf).await
}

/// `b.Close`.
pub(crate) async fn core_close(inner: &AsyncMutex<BodyInner>) -> io::Result<()> {
    inner.lock().await.close_locked().await
}

/// `seeUpcomingDoubleCRLF`.
async fn see_upcoming_double_crlf(br: &mut BufReader) -> bool {
    let mut peek_size = 4;
    loop {
        let (buf, err) = br.peek(peek_size).await;
        if buf.ends_with(b"\r\n\r\n") {
            return true;
        }
        if err.is_some() {
            return false;
        }
        peek_size += 1;
    }
}

/// `b.readTrailer`.
async fn read_trailer(br: &mut BufReader, trailer: &Mutex<Option<Header>>) -> io::Result<()> {
    let trailer_eof = || io::Error::other("http: unexpected EOF reading trailer");
    let (buf, err) = br.peek(2).await;
    if buf == b"\r\n" {
        br.discard_buffered(2);
        return Ok(());
    }
    if buf.len() < 2 {
        return Err(trailer_eof());
    }
    if let Some(e) = err {
        return Err(match e {
            ReadErr::Io(e) => e,
            _ => trailer_eof(),
        });
    }
    if !see_upcoming_double_crlf(br).await {
        return Err(io::Error::other(
            "http: suspiciously long trailer after chunked body",
        ));
    }
    let hdr = br.read_mime_header().await.map_err(|e| match e {
        MimeError::Read(ReadErr::Eof) => trailer_eof(),
        MimeError::Read(ReadErr::Io(e)) => e,
        MimeError::Read(ReadErr::BufferFull) => io::Error::other("bufio: buffer full"),
        MimeError::Protocol(m) => io::Error::other(m),
    })?;
    let mut t = lock(trailer);
    match t.as_mut() {
        None => *t = Some(hdr),
        Some(dst) => {
            for (k, v) in hdr.iter() {
                dst.set_raw(k, v.to_vec());
            }
        }
    }
    Ok(())
}

/// `net/http/internal.chunkedReader`.
#[derive(Default)]
pub(crate) struct ChunkedReader {
    n: u64,
    err: Option<ChunkErr>,
    check_end: bool,
    excess: i64,
}

#[derive(Debug, Clone)]
enum ChunkErr {
    Eof,
    Unexpected,
    Msg(&'static str),
    Io(io::ErrorKind, String),
}

impl ChunkErr {
    fn to_src(&self) -> SrcErr {
        match self {
            ChunkErr::Eof => SrcErr::Eof,
            ChunkErr::Unexpected => SrcErr::Other(unexpected_eof()),
            ChunkErr::Msg(m) => SrcErr::Other(io::Error::other(*m)),
            ChunkErr::Io(k, m) => SrcErr::Other(io::Error::new(*k, m.clone())),
        }
    }
}

impl From<ReadErr> for ChunkErr {
    fn from(e: ReadErr) -> Self {
        match e {
            ReadErr::Eof => ChunkErr::Eof,
            ReadErr::BufferFull => ChunkErr::Msg("bufio: buffer full"),
            ReadErr::Io(e) => ChunkErr::Io(e.kind(), e.to_string()),
        }
    }
}

const MAX_LINE_LENGTH: usize = 4096;

impl ChunkedReader {
    async fn read_chunk_line(br: &mut BufReader) -> Result<Vec<u8>, ChunkErr> {
        let line = br.read_slice_for_chunk().await;
        let p = match line {
            Err(ReadErr::Eof) => return Err(ChunkErr::Unexpected),
            Err(ReadErr::BufferFull) => return Err(ChunkErr::Msg("header line too long")),
            Err(e) => return Err(e.into()),
            Ok(p) => p,
        };
        match p.iter().position(|&b| b == b'\r') {
            None => return Err(ChunkErr::Msg("chunked line ends with bare LF")),
            Some(idx) if idx != p.len() - 2 => {
                return Err(ChunkErr::Msg("invalid CR in chunked line"));
            }
            Some(_) => {}
        }
        let p = p[..p.len() - 2].to_vec();
        if p.len() >= MAX_LINE_LENGTH {
            return Err(ChunkErr::Msg("header line too long"));
        }
        Ok(p)
    }

    async fn begin_chunk(&mut self, br: &mut BufReader) {
        let line = match Self::read_chunk_line(br).await {
            Ok(l) => l,
            Err(e) => {
                self.err = Some(e);
                return;
            }
        };
        self.excess += line.len() as i64 + 2;
        let mut line = line.as_slice();
        while let [rest @ .., b' ' | b'\t'] = line {
            line = rest;
        }
        let line = line.split(|&b| b == b';').next().unwrap_or(&[]);
        let n = match parse_hex_uint(line) {
            Ok(n) => n,
            Err(m) => {
                self.err = Some(ChunkErr::Msg(m));
                return;
            }
        };
        self.n = n;
        self.excess -= 16i64.wrapping_add(2i64.wrapping_mul(n as i64));
        self.excess = self.excess.max(0);
        if self.excess > 16 * 1024 {
            self.err = Some(ChunkErr::Msg("chunked encoding contains too much non-data"));
        }
        if self.n == 0 {
            self.err = Some(ChunkErr::Eof);
        }
    }

    async fn read(&mut self, br: &mut BufReader, mut b: &mut [u8]) -> (usize, Option<SrcErr>) {
        let mut n = 0;
        while self.err.is_none() {
            if self.check_end {
                if n > 0 && br.buffered() < 2 {
                    break;
                }
                let mut two = [0u8; 2];
                let mut got = 0;
                let mut failed = None;
                while got < 2 {
                    match br.read(&mut two[got..]).await {
                        Ok(0) => {}
                        Ok(k) => got += k,
                        Err(e) => {
                            failed = Some((e, got));
                            break;
                        }
                    }
                }
                if let Some((e, got)) = failed {
                    self.err = Some(match e {
                        // io.ReadFull: EOF with nothing read stays EOF, which the code above turns
                        // into ErrUnexpectedEOF anyway; EOF part way is ErrUnexpectedEOF.
                        ReadErr::Eof => ChunkErr::Unexpected,
                        other => {
                            let _ = got;
                            other.into()
                        }
                    });
                    break;
                }
                if two != *b"\r\n" {
                    self.err = Some(ChunkErr::Msg("malformed chunked encoding"));
                    break;
                }
                self.check_end = false;
            }
            if self.n == 0 {
                if n > 0 && !br.chunk_header_available() {
                    break;
                }
                self.begin_chunk(br).await;
                continue;
            }
            if b.is_empty() {
                break;
            }
            let max = usize::try_from(self.n).unwrap_or(usize::MAX).min(b.len());
            let n0 = match br.read(&mut b[..max]).await {
                Ok(k) => k,
                Err(e) => {
                    self.err = Some(match e {
                        ReadErr::Eof => ChunkErr::Unexpected,
                        other => other.into(),
                    });
                    0
                }
            };
            n += n0;
            b = &mut b[n0..];
            self.n -= n0 as u64;
            if self.n == 0 && self.err.is_none() {
                self.check_end = true;
            }
        }
        (n, self.err.as_ref().map(ChunkErr::to_src))
    }
}

fn parse_hex_uint(v: &[u8]) -> Result<u64, &'static str> {
    if v.is_empty() {
        return Err("empty hex number for chunk length");
    }
    let mut n: u64 = 0;
    for (i, &b) in v.iter().enumerate() {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err("invalid byte in chunk length"),
        };
        if i == 16 {
            return Err("http chunk length too large");
        }
        n = (n << 4) | u64::from(d);
    }
    Ok(n)
}

/// State `expectContinueReader` shares with the response.
pub(crate) struct ExpectContinue {
    pub(crate) can_write: AtomicBool,
    pub(crate) closed: AtomicBool,
    pub(crate) saw_eof: AtomicBool,
    /// `writeContinueMu`.
    pub(crate) mu: AsyncMutex<()>,
    pub(crate) bufw: Arc<AsyncMutex<ConnWriter>>,
}

/// `expectContinueReader`: sends `100 Continue` on the first read.
struct ExpectContinueReader {
    inner: Body,
    shared: Arc<ExpectContinue>,
}

impl ReadCloser for ExpectContinueReader {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            if self.shared.closed.load(Ordering::SeqCst) {
                return Err(body_read_after_close());
            }
            if self.shared.can_write.load(Ordering::SeqCst) {
                let _guard = self.shared.mu.lock().await;
                if self.shared.can_write.load(Ordering::SeqCst) {
                    let mut w = self.shared.bufw.lock().await;
                    let _ = w.write(b"HTTP/1.1 100 Continue\r\n\r\n").await;
                    let _ = w.flush().await;
                    self.shared.can_write.store(false, Ordering::SeqCst);
                }
            }
            let n = self.inner.read(buf).await?;
            if n == 0 {
                self.shared.saw_eof.store(true, Ordering::SeqCst);
            }
            Ok(n)
        })
    }
    fn close(&mut self) -> BoxFuture<'_, io::Result<()>> {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.inner.close()
    }
}

/// `http.MaxBytesError`'s text, which Go documents as fixed.
pub const MAX_BYTES_ERROR: &str = "http: request body too large";

/// `http.MaxBytesReader`. Wrap with `r.set_body(max_bytes_reader(w, r.take_body(), n))`.
///
/// Go tells the response to close the connection only when `w` is the server's own writer, so behind
/// a wrapping middleware such as the compressor it does not. [`ResponseWriter::too_large_signal`]
/// keeps that difference.
pub fn max_bytes_reader(w: &dyn ResponseWriter, r: Body, n: i64) -> Body {
    let n = n.max(0);
    Box::new(MaxBytesBody {
        r,
        n,
        err: None,
        signal: w.too_large_signal(),
    })
}

struct MaxBytesBody {
    r: Body,
    n: i64,
    err: Option<(io::ErrorKind, String)>,
    signal: Option<Arc<AtomicBool>>,
}

impl ReadCloser for MaxBytesBody {
    fn read<'a>(&'a mut self, p: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            if let Some((k, m)) = &self.err {
                return Err(io::Error::new(*k, m.clone()));
            }
            if p.is_empty() {
                return Ok(0);
            }
            let mut p = p;
            if (p.len() as i64) - 1 > self.n {
                let cut = usize::try_from(self.n + 1).unwrap_or(p.len());
                p = &mut p[..cut];
            }
            let n = match self.r.read(p).await {
                Ok(n) => n,
                Err(e) => {
                    self.err = Some((e.kind(), e.to_string()));
                    return Err(e);
                }
            };
            if n as i64 <= self.n {
                self.n -= n as i64;
                return Ok(n);
            }
            let keep = usize::try_from(self.n).unwrap_or(0);
            self.n = 0;
            if let Some(s) = &self.signal {
                s.store(true, Ordering::SeqCst);
            }
            self.err = Some((io::ErrorKind::Other, MAX_BYTES_ERROR.to_owned()));
            if keep == 0 {
                return Err(io::Error::other(MAX_BYTES_ERROR));
            }
            // Go returned these bytes together with the error, which the next call reports.
            Ok(keep)
        })
    }
    fn close(&mut self) -> BoxFuture<'_, io::Result<()>> {
        self.r.close()
    }
}

type PendingRead = (Body, Vec<u8>, io::Result<usize>);

/// `r.Body` as an `AsyncRead`, for code that wants the tokio traits.
pub struct BodyReader {
    fut: Option<BoxFuture<'static, PendingRead>>,
    body: Option<Body>,
    buf: Vec<u8>,
}

impl BodyReader {
    /// Wraps a body taken with [`Request::take_body`].
    pub fn new(body: Body) -> Self {
        Self {
            fut: None,
            body: Some(body),
            buf: vec![0; 32 * 1024],
        }
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if let Some(fut) = this.fut.as_mut() {
                let (body, buf, res) = std::task::ready!(fut.as_mut().poll(cx));
                this.fut = None;
                this.body = Some(body);
                this.buf = buf;
                let n = res?;
                if n > out.remaining() {
                    return Poll::Ready(Err(io::Error::other(
                        "BodyReader read buffer shrank between polls",
                    )));
                }
                out.put_slice(&this.buf[..n]);
                return Poll::Ready(Ok(()));
            }
            let Some(mut body) = this.body.take() else {
                return Poll::Ready(Ok(()));
            };
            let mut buf = std::mem::take(&mut this.buf);
            let want = out.remaining().min(buf.len());
            this.fut = Some(Box::pin(async move {
                let res = body.read(&mut buf[..want]).await;
                (body, buf, res)
            }));
        }
    }
}
