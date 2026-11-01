//! The `http.Handler` and `http.ResponseWriter` model, and the helpers that write through it:
//! `http.Error`, `http.NotFound`, `http.Redirect`, `http.StripPrefix`.

use std::future::Future;
use std::io;
use std::panic::resume_unwind;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use silo_gocompat::path;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::bufio::BoxedIo;
use crate::header::Header;
use crate::request::Request;
use crate::status::status_text;
use crate::url::parse_url;

/// A boxed `Send` future, what every async trait method here returns so the traits stay object safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors `ResponseWriter.Write` reports.
#[derive(Debug)]
pub enum WriteError {
    /// `http.ErrBodyNotAllowed`.
    BodyNotAllowed,
    /// `http.ErrContentLength`.
    ContentLength,
    /// `http.ErrHijacked`.
    Hijacked,
    /// `http.ErrNotSupported`.
    NotSupported,
    /// The connection failed.
    Io(io::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::BodyNotAllowed => {
                f.write_str("http: request method or response status code does not allow body")
            }
            WriteError::ContentLength => {
                f.write_str("http: wrote more than the declared Content-Length")
            }
            WriteError::Hijacked => f.write_str("http: connection has been hijacked"),
            WriteError::NotSupported => f.write_str("feature not supported"),
            WriteError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WriteError {}

/// What `Hijack` hands over: the stream and any bytes read past the request.
pub struct Hijacked {
    /// The stream. The server no longer owns it.
    pub io: BoxedIo,
    /// Bytes the server had buffered from the client, which the new owner reads first.
    pub read_buf: Vec<u8>,
}

/// `http.ResponseWriter`, with the optional interfaces Go finds by type assertion
/// (`http.Flusher`, `http.Hijacker`, `io.ReaderFrom`, `io.StringWriter`, and the methods
/// `http.ResponseController` reaches) as trait methods with a not-supported default.
///
/// Wrappers forward what the Go wrapper exposes and nothing else: a wrapper without `Hijack` in Go
/// makes the upgrader answer 500, and one without `ReadFrom` turns a file copy into 32 KiB writes.
pub trait ResponseWriter: Send {
    /// `w.Header()`.
    fn header(&mut self) -> &mut Header;

    /// `w.WriteHeader(code)`. Async because an informational status goes straight to the socket.
    fn write_header(&mut self, code: u16) -> BoxFuture<'_, ()>;

    /// `w.Write(data)`.
    fn write<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, Result<usize, WriteError>>;

    /// `io.WriteString(w, s)`. The server's own writer treats this differently from `write` for a
    /// large string: it goes through the 2 KiB buffer rather than past it, which changes chunking.
    fn write_string<'a>(&'a mut self, data: &'a str) -> BoxFuture<'a, Result<usize, WriteError>> {
        self.write(data.as_bytes())
    }

    /// `io.Copy(w, src)`, which reaches `w.ReadFrom` when `w` has one.
    fn read_from<'a>(
        &'a mut self,
        src: &'a mut (dyn AsyncRead + Send + Unpin),
    ) -> BoxFuture<'a, Result<i64, WriteError>> {
        Box::pin(async move {
            let mut buf = vec![0u8; 32 * 1024];
            let mut total = 0i64;
            loop {
                let n = src.read(&mut buf).await.map_err(WriteError::Io)?;
                if n == 0 {
                    return Ok(total);
                }
                self.write(&buf[..n]).await?;
                total += n as i64;
            }
        })
    }

    /// `http.NewResponseController(w).Flush()`.
    fn flush(&mut self) -> BoxFuture<'_, Result<(), WriteError>> {
        Box::pin(async { Err(WriteError::NotSupported) })
    }

    /// `http.NewResponseController(w).Hijack()`.
    fn hijack(&mut self) -> BoxFuture<'_, Result<Hijacked, WriteError>> {
        Box::pin(async { Err(WriteError::NotSupported) })
    }

    /// `http.NewResponseController(w).SetReadDeadline`. `None` clears it.
    fn set_read_deadline(&mut self, _at: Option<Instant>) -> Result<(), WriteError> {
        Err(WriteError::NotSupported)
    }

    /// `http.NewResponseController(w).SetWriteDeadline`. `None` clears it.
    fn set_write_deadline(&mut self, _at: Option<Instant>) -> Result<(), WriteError> {
        Err(WriteError::NotSupported)
    }

    /// `http.NewResponseController(w).EnableFullDuplex`.
    fn enable_full_duplex(&mut self) -> Result<(), WriteError> {
        Err(WriteError::NotSupported)
    }

    /// The `requestTooLarger` assertion in `http.MaxBytesReader`: only the server's own writer has it.
    fn too_large_signal(&self) -> Option<Arc<AtomicBool>> {
        None
    }
}

/// `http.Handler`.
pub trait Handler: Send + Sync + 'static {
    /// `h.ServeHTTP(w, r)`.
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()>;

    /// `h.(*chi.ChainHandler)`, which `chi.Walk` looks for.
    fn as_chain(&self) -> Option<&crate::chi::ChainHandler> {
        None
    }
}

/// A shareable handler.
pub type BoxHandler = Arc<dyn Handler>;

struct HandlerFn<F>(F);

impl<F> Handler for HandlerFn<F>
where
    F: for<'a> Fn(&'a mut dyn ResponseWriter, &'a mut Request) -> BoxFuture<'a, ()>
        + Send
        + Sync
        + 'static,
{
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        (self.0)(w, r)
    }
}

/// `http.HandlerFunc`: `handler_fn(|w, r| Box::pin(async move { ... }))`.
pub fn handler_fn<F>(f: F) -> BoxHandler
where
    F: for<'a> Fn(&'a mut dyn ResponseWriter, &'a mut Request) -> BoxFuture<'a, ()>
        + Send
        + Sync
        + 'static,
{
    Arc::new(HandlerFn(f))
}

/// The value `panic(http.ErrAbortHandler)` raises.
#[derive(Debug, Clone, Copy)]
pub struct AbortHandler;

/// `panic(http.ErrAbortHandler)`: ends the response by dropping the connection, without a stack trace.
pub fn abort_handler() -> ! {
    resume_unwind(Box::new(AbortHandler))
}

/// `http.Error`.
pub async fn error(w: &mut dyn ResponseWriter, message: &str, code: u16) {
    let h = w.header();
    h.del("Content-Length");
    h.set("Content-Type", "text/plain; charset=utf-8");
    h.set("X-Content-Type-Options", "nosniff");
    w.write_header(code).await;
    let mut body = Vec::with_capacity(message.len() + 1);
    body.extend_from_slice(message.as_bytes());
    body.push(b'\n');
    let _ = w.write(&body).await;
}

/// `http.NotFound`.
pub async fn not_found(w: &mut dyn ResponseWriter, _r: &mut Request) {
    error(w, "404 page not found", 404).await;
}

/// `http.NotFoundHandler`.
pub fn not_found_handler() -> BoxHandler {
    handler_fn(|w, r| Box::pin(not_found(w, r)))
}

fn hex_escape_non_ascii(s: &str) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b >= 0x80 {
            out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
        } else {
            out.push(b);
        }
    }
    out
}

/// `htmlReplacer`.
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `http.Redirect`.
pub async fn redirect(w: &mut dyn ResponseWriter, r: &Request, url: &str, code: u16) {
    let mut url = url.to_owned();
    if let Ok(u) = parse_url(url.as_bytes())
        && u.scheme.is_empty()
        && u.host.is_empty()
    {
        let mut oldpath = String::from_utf8_lossy(&r.url.escaped_path()).into_owned();
        if oldpath.is_empty() {
            oldpath = "/".to_owned();
        }
        if !url.starts_with('/') {
            let (olddir, _) = path::split(&oldpath);
            url = format!("{olddir}{url}");
        }
        let mut query = String::new();
        if let Some(i) = url.find('?') {
            query = url[i..].to_owned();
            url.truncate(i);
        }
        let trailing = url.ends_with('/');
        url = path::clean(&url);
        if trailing && !url.ends_with('/') {
            url.push('/');
        }
        url.push_str(&query);
    }

    let h = w.header();
    let had_ct = h.has_raw("Content-Type");
    h.set("Location", hex_escape_non_ascii(&url));
    if !had_ct && (r.method == "GET" || r.method == "HEAD") {
        h.set("Content-Type", "text/html; charset=utf-8");
    }
    w.write_header(code).await;
    if !had_ct && r.method == "GET" {
        let body = format!(
            "<a href=\"{}\">{}</a>.\n\n",
            html_escape(&url),
            status_text(code)
        );
        let _ = w.write(body.as_bytes()).await;
    }
}

/// `http.RedirectHandler`.
pub fn redirect_handler(url: String, code: u16) -> BoxHandler {
    Arc::new(RedirectHandler { url, code })
}

struct RedirectHandler {
    url: String,
    code: u16,
}

impl Handler for RedirectHandler {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(redirect(w, r, &self.url, self.code))
    }
}

/// `http.StripPrefix`.
pub fn strip_prefix(prefix: &str, h: BoxHandler) -> BoxHandler {
    if prefix.is_empty() {
        return h;
    }
    Arc::new(StripPrefix {
        prefix: prefix.as_bytes().to_vec(),
        h,
    })
}

struct StripPrefix {
    prefix: Vec<u8>,
    h: BoxHandler,
}

impl Handler for StripPrefix {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let p = r
                .url
                .path
                .strip_prefix(self.prefix.as_slice())
                .map(<[u8]>::to_vec);
            let rp = r
                .url
                .raw_path
                .strip_prefix(self.prefix.as_slice())
                .map(<[u8]>::to_vec);
            if let Some(p) = p
                && (r.url.raw_path.is_empty() || rp.is_some())
            {
                // Go hands the next handler a copy, so restore the caller's view afterward.
                let saved = (
                    std::mem::replace(&mut r.url.path, p),
                    r.url.raw_path.clone(),
                );
                r.url.raw_path = rp.unwrap_or_else(|| r.url.raw_path.clone());
                self.h.serve_http(w, r).await;
                r.url.path = saved.0;
                r.url.raw_path = saved.1;
            } else {
                not_found(w, r).await;
            }
        })
    }
}
