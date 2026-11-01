//! Port of `net/http/fs.go`: `http.ServeContent`, `http.ServeFile`, and `http.FileServer` over the
//! operating system's file system.

use std::fs::Metadata;
use std::io::{self, SeekFrom};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::RngCore;
use silo_gocompat::time::GoTime;
use silo_gocompat::{filepath, path};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, ReadBuf};

use crate::header::{TIME_FORMAT, parse_time, trim_string};
use crate::mime::type_by_extension;
use crate::request::Request;
use crate::response::{
    BoxFuture, BoxHandler, Handler, ResponseWriter, error, html_escape, not_found,
};
use crate::sniff::{SNIFF_LEN, detect_content_type};

/// `io.ReadSeeker`.
pub trait ReadSeek: AsyncRead + AsyncSeek + Send + Unpin {}
impl<T: AsyncRead + AsyncSeek + Send + Unpin> ReadSeek for T {}

/// `serveError`: drops the headers meant for a successful reply, then `http.Error`.
async fn serve_error(w: &mut dyn ResponseWriter, text: &str, code: u16) {
    let h = w.header();
    for k in ["Cache-Control", "Content-Encoding", "Etag", "Last-Modified"] {
        h.del_raw(k);
    }
    error(w, text, code).await;
}

/// `http.ServeContent`. `modtime` of `None` is Go's zero time.
pub async fn serve_content(
    w: &mut dyn ResponseWriter,
    r: &Request,
    name: &str,
    modtime: Option<GoTime>,
    content: &mut dyn ReadSeek,
) {
    let size = async {
        let size = content.seek(SeekFrom::End(0)).await?;
        content.seek(SeekFrom::Start(0)).await?;
        Ok::<i64, io::Error>(i64::try_from(size).unwrap_or(i64::MAX))
    }
    .await
    .map_err(|_| "seeker can't seek");
    serve_content_inner(w, r, name, modtime, size, content).await;
}

/// `serveContent`. Go computes the size lazily, after the preconditions; here it comes in computed,
/// and its error is reported at the point Go would call `sizeFunc`.
async fn serve_content_inner(
    w: &mut dyn ResponseWriter,
    r: &Request,
    name: &str,
    modtime: Option<GoTime>,
    size: Result<i64, &'static str>,
    content: &mut dyn ReadSeek,
) {
    set_last_modified(w, modtime);
    let (done, range_req) = check_preconditions(w, r, modtime).await;
    if done {
        return;
    }

    let mut code = 200;

    let ctype = match w
        .header()
        .values_raw("Content-Type")
        .map(<[Vec<u8>]>::to_vec)
    {
        None => {
            let mut ctype = type_by_extension(filepath::ext(name));
            if ctype.is_empty() {
                let mut buf = [0u8; SNIFF_LEN];
                let mut n = 0;
                while n < buf.len() {
                    match content.read(&mut buf[n..]).await {
                        Ok(0) | Err(_) => break,
                        Ok(k) => n += k,
                    }
                }
                ctype = detect_content_type(&buf[..n]).to_owned();
                if content.seek(SeekFrom::Start(0)).await.is_err() {
                    serve_error(w, "seeker can't seek", 500).await;
                    return;
                }
            }
            w.header().set("Content-Type", &ctype);
            ctype.into_bytes()
        }
        Some(ctypes) => ctypes.into_iter().next().unwrap_or_default(),
    };

    let size = match size {
        Ok(s) => s,
        Err(msg) => {
            serve_error(w, msg, 500).await;
            return;
        }
    };
    if size < 0 {
        serve_error(w, "negative content size computed", 500).await;
        return;
    }

    let mut send_size = size;
    let mut ranges = match parse_range(&range_req, size) {
        Ok(r) => r,
        Err(RangeError::NoOverlap) => {
            if size == 0 {
                Vec::new()
            } else {
                w.header().set("Content-Range", format!("bytes */{size}"));
                serve_error(w, "invalid range: failed to overlap", 416).await;
                return;
            }
        }
        Err(RangeError::Invalid) => {
            serve_error(w, "invalid range", 416).await;
            return;
        }
    };

    if ranges.iter().map(|r| r.length).sum::<i64>() > size {
        ranges.clear();
    }

    let mut multipart: Option<(Vec<HttpRange>, String)> = None;
    if ranges.len() == 1 {
        let ra = ranges[0];
        if let Err(e) = content.seek(SeekFrom::Start(ra.start as u64)).await {
            serve_error(w, &e.to_string(), 416).await;
            return;
        }
        send_size = ra.length;
        code = 206;
        w.header().set("Content-Range", ra.content_range(size));
    } else if ranges.len() > 1 {
        send_size = ranges_mime_size(&ranges, &ctype, size);
        code = 206;
        let boundary = random_boundary();
        w.header().set(
            "Content-Type",
            format!("multipart/byteranges; boundary={boundary}"),
        );
        multipart = Some((ranges.clone(), boundary));
    }

    w.header().set("Accept-Ranges", "bytes");

    if !ranges.is_empty() || w.header().get("Content-Encoding").is_empty() {
        w.header().set("Content-Length", send_size.to_string());
    }
    w.write_header(code).await;

    if r.method != "HEAD" {
        let mut limited: LimitedRead<'_> = match multipart {
            Some((ranges, boundary)) => LimitedRead {
                inner: Inner::Multipart(MultipartReader::new(
                    content, ranges, boundary, ctype, size,
                )),
                remaining: send_size,
            },
            None => LimitedRead {
                inner: Inner::Plain(content),
                remaining: send_size,
            },
        };
        let _ = w.read_from(&mut limited).await;
    }
}

/// `io.LimitReader` for `io.CopyN(w, sendContent, sendSize)`.
struct LimitedRead<'a> {
    inner: Inner<'a>,
    remaining: i64,
}

enum Inner<'a> {
    Plain(&'a mut dyn ReadSeek),
    Multipart(MultipartReader<'a>),
}

impl AsyncRead for LimitedRead<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.remaining <= 0 {
            return Poll::Ready(Ok(()));
        }
        let max = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.remaining());
        let mut sub = buf.take(max);
        let this = &mut *self;
        let res = match &mut this.inner {
            Inner::Plain(c) => Pin::new(&mut **c).poll_read(cx, &mut sub),
            Inner::Multipart(m) => Pin::new(m).poll_read(cx, &mut sub),
        };
        let n = sub.filled().len();
        std::task::ready!(res)?;
        // `take` hands out a separate view, so the parent learns the count here.
        // SAFETY: `sub` wrote `n` initialized bytes into `buf`'s unfilled region.
        unsafe { buf.assume_init(n) };
        buf.advance(n);
        this.remaining -= n as i64;
        Poll::Ready(Ok(()))
    }
}

/// The goroutine `serveContent` starts for a multi-range reply, as a reader: each part header
/// followed by that range of the content, then the closing boundary.
struct MultipartReader<'a> {
    content: &'a mut dyn ReadSeek,
    ranges: std::vec::IntoIter<HttpRange>,
    boundary: String,
    ctype: Vec<u8>,
    size: i64,
    first: bool,
    closed: bool,
    pending: Vec<u8>,
    pending_pos: usize,
    remaining_in_part: i64,
    seek_to: Option<u64>,
    seek_started: bool,
}

impl<'a> MultipartReader<'a> {
    fn new(
        content: &'a mut dyn ReadSeek,
        ranges: Vec<HttpRange>,
        boundary: String,
        ctype: Vec<u8>,
        size: i64,
    ) -> Self {
        Self {
            content,
            ranges: ranges.into_iter(),
            boundary,
            ctype,
            size,
            first: true,
            closed: false,
            pending: Vec::new(),
            pending_pos: 0,
            remaining_in_part: 0,
            seek_to: None,
            seek_started: false,
        }
    }
}

impl AsyncRead for MultipartReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.pending_pos < this.pending.len() {
                let n = (this.pending.len() - this.pending_pos).min(buf.remaining());
                buf.put_slice(&this.pending[this.pending_pos..this.pending_pos + n]);
                this.pending_pos += n;
                return Poll::Ready(Ok(()));
            }
            if let Some(to) = this.seek_to {
                if !this.seek_started {
                    Pin::new(&mut *this.content).start_seek(SeekFrom::Start(to))?;
                    this.seek_started = true;
                }
                std::task::ready!(Pin::new(&mut *this.content).poll_complete(cx))?;
                this.seek_to = None;
                this.seek_started = false;
            }
            if this.remaining_in_part > 0 {
                let max = usize::try_from(this.remaining_in_part)
                    .unwrap_or(usize::MAX)
                    .min(buf.remaining());
                let mut sub = buf.take(max);
                std::task::ready!(Pin::new(&mut *this.content).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")));
                }
                // SAFETY: `sub` wrote `n` initialized bytes into `buf`'s unfilled region.
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                this.remaining_in_part -= n as i64;
                return Poll::Ready(Ok(()));
            }
            this.pending.clear();
            this.pending_pos = 0;
            if let Some(ra) = this.ranges.next() {
                write_part_header(
                    &mut this.pending,
                    &this.boundary,
                    this.first,
                    &ra,
                    &this.ctype,
                    this.size,
                );
                this.first = false;
                this.seek_to = Some(ra.start as u64);
                this.remaining_in_part = ra.length;
                continue;
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            this.closed = true;
            this.pending.extend_from_slice(b"\r\n--");
            this.pending.extend_from_slice(this.boundary.as_bytes());
            this.pending.extend_from_slice(b"--\r\n");
        }
    }
}

/// `multipart.Writer.CreatePart` with `httpRange.mimeHeader`: `Content-Range` sorts first.
fn write_part_header(
    out: &mut Vec<u8>,
    boundary: &str,
    first: bool,
    ra: &HttpRange,
    ctype: &[u8],
    size: i64,
) {
    if !first {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"--");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"\r\nContent-Range: ");
    out.extend_from_slice(ra.content_range(size).as_bytes());
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(ctype);
    out.extend_from_slice(b"\r\n\r\n");
}

/// `multipart.randomBoundary`.
fn random_boundary() -> String {
    let mut bytes = [0u8; 30];
    rand::rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(60);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `rangesMIMESize`.
fn ranges_mime_size(ranges: &[HttpRange], ctype: &[u8], size: i64) -> i64 {
    let boundary = "0".repeat(60);
    let mut enc: i64 = 0;
    let mut scratch = Vec::new();
    for (i, ra) in ranges.iter().enumerate() {
        scratch.clear();
        write_part_header(&mut scratch, &boundary, i == 0, ra, ctype, size);
        enc += scratch.len() as i64 + ra.length;
    }
    // mw.Close: "\r\n--boundary--\r\n".
    enc + 2 + 2 + 60 + 2 + 2
}

/// `httpRange`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpRange {
    pub start: i64,
    pub length: i64,
}

impl HttpRange {
    fn content_range(&self, size: i64) -> String {
        format!(
            "bytes {}-{}/{}",
            self.start,
            self.start + self.length - 1,
            size
        )
    }
}

/// How `parseRange` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeError {
    /// `errors.New("invalid range")`.
    Invalid,
    /// `errNoOverlap`.
    NoOverlap,
}

/// `strconv.ParseInt(s, 10, 64)`.
fn parse_i64(s: &[u8]) -> Option<i64> {
    let (neg, digits) = match s {
        [b'+', rest @ ..] => (false, rest),
        [b'-', rest @ ..] => (true, rest),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: i64 = 0;
    for &d in digits {
        n = n.checked_mul(10)?;
        n = if neg {
            n.checked_sub(i64::from(d - b'0'))?
        } else {
            n.checked_add(i64::from(d - b'0'))?
        };
    }
    Some(n)
}

/// `defaultMaxContentRanges`. Go's `httpservecontentmaxranges` GODEBUG knob can override this at
/// runtime; Silo does not expose that knob, so this crate only ever applies the default.
const MAX_CONTENT_RANGES: usize = 200;

/// `parseRange`.
pub fn parse_range(s: &[u8], size: i64) -> Result<Vec<HttpRange>, RangeError> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let Some(spec) = s.strip_prefix(b"bytes=") else {
        return Err(RangeError::Invalid);
    };
    let num_ranges = spec.iter().filter(|&&b| b == b',').count() + 1;
    if num_ranges > MAX_CONTENT_RANGES {
        // Go: "ignore header with too many ranges" -- serve the full content instead of
        // rejecting the request.
        return Ok(Vec::new());
    }
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for ra in spec.split(|&b| b == b',') {
        let ra = trim_string(ra);
        if ra.is_empty() {
            continue;
        }
        let Some(dash) = ra.iter().position(|&b| b == b'-') else {
            return Err(RangeError::Invalid);
        };
        let start = trim_string(&ra[..dash]);
        let end = trim_string(&ra[dash + 1..]);
        let mut r = HttpRange {
            start: 0,
            length: 0,
        };
        if start.is_empty() {
            if end.is_empty() || end[0] == b'-' {
                return Err(RangeError::Invalid);
            }
            let Some(mut i) = parse_i64(end).filter(|i| *i >= 0) else {
                return Err(RangeError::Invalid);
            };
            if i > size {
                i = size;
            }
            r.start = size - i;
            r.length = size - r.start;
        } else {
            let Some(i) = parse_i64(start).filter(|i| *i >= 0) else {
                return Err(RangeError::Invalid);
            };
            if i >= size {
                no_overlap = true;
                continue;
            }
            r.start = i;
            if end.is_empty() {
                r.length = size - r.start;
            } else {
                let Some(mut i) = parse_i64(end).filter(|i| r.start <= *i) else {
                    return Err(RangeError::Invalid);
                };
                if i >= size {
                    i = size - 1;
                }
                r.length = i - r.start + 1;
            }
        }
        ranges.push(r);
    }
    if no_overlap && ranges.is_empty() {
        return Err(RangeError::NoOverlap);
    }
    Ok(ranges)
}

/// `scanETag`: the tag and what follows it, or `None` if `s` does not start with one.
fn scan_etag(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let s = trim_string(s);
    let start = if s.starts_with(b"W/") { 2 } else { 0 };
    if s.len() - start < 2 || s[start] != b'"' {
        return None;
    }
    for i in start + 1..s.len() {
        let c = s[i];
        if c == 0x21 || (0x23..=0x7E).contains(&c) || c >= 0x80 {
            continue;
        }
        if c == b'"' {
            return Some((&s[..=i], &s[i + 1..]));
        }
        return None;
    }
    None
}

fn etag_strong_match(a: &[u8], b: &[u8]) -> bool {
    a == b && !a.is_empty() && a[0] == b'"'
}

fn etag_weak_match(a: &[u8], b: &[u8]) -> bool {
    a.strip_prefix(b"W/").unwrap_or(a) == b.strip_prefix(b"W/").unwrap_or(b)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cond {
    None,
    True,
    False,
}

fn check_if_match(w: &mut dyn ResponseWriter, r: &Request) -> Cond {
    let mut im = r.header.get("If-Match");
    if im.is_empty() {
        return Cond::None;
    }
    let tag = w.header().get("Etag").to_vec();
    loop {
        im = trim_string(im);
        if im.is_empty() {
            break;
        }
        if im[0] == b',' {
            im = &im[1..];
            continue;
        }
        if im[0] == b'*' {
            return Cond::True;
        }
        let Some((etag, remain)) = scan_etag(im) else {
            break;
        };
        if etag_strong_match(etag, &tag) {
            return Cond::True;
        }
        im = remain;
    }
    Cond::False
}

fn text(b: &[u8]) -> Option<&str> {
    std::str::from_utf8(b).ok()
}

fn is_zero_time(t: Option<GoTime>) -> bool {
    t.is_none_or(|t| t.is_zero() || t.unix() == 0 && t.nanosecond() == 0)
}

/// `modtime.Truncate(time.Second).Compare(t)` is at most zero.
fn not_after(modtime: GoTime, t: GoTime) -> bool {
    (modtime.unix(), 0) <= (t.unix(), t.nanosecond())
}

fn check_if_unmodified_since(r: &Request, modtime: Option<GoTime>) -> Cond {
    let ius = r.header.get("If-Unmodified-Since");
    if ius.is_empty() || is_zero_time(modtime) {
        return Cond::None;
    }
    let (Some(t), Some(modtime)) = (text(ius).and_then(parse_time), modtime) else {
        return Cond::None;
    };
    if not_after(modtime, t) {
        Cond::True
    } else {
        Cond::False
    }
}

fn check_if_none_match(w: &mut dyn ResponseWriter, r: &Request) -> Cond {
    let mut buf = r.header.get_raw("If-None-Match");
    if buf.is_empty() {
        return Cond::None;
    }
    let tag = w.header().get_raw("Etag").to_vec();
    loop {
        buf = trim_string(buf);
        if buf.is_empty() {
            break;
        }
        if buf[0] == b',' {
            buf = &buf[1..];
            continue;
        }
        if buf[0] == b'*' {
            return Cond::False;
        }
        let Some((etag, remain)) = scan_etag(buf) else {
            break;
        };
        if etag_weak_match(etag, &tag) {
            return Cond::False;
        }
        buf = remain;
    }
    Cond::True
}

fn check_if_modified_since(r: &Request, modtime: Option<GoTime>) -> Cond {
    if r.method != "GET" && r.method != "HEAD" {
        return Cond::None;
    }
    let ims = r.header.get("If-Modified-Since");
    if ims.is_empty() || is_zero_time(modtime) {
        return Cond::None;
    }
    let (Some(t), Some(modtime)) = (text(ims).and_then(parse_time), modtime) else {
        return Cond::None;
    };
    if not_after(modtime, t) {
        Cond::False
    } else {
        Cond::True
    }
}

fn check_if_range(w: &mut dyn ResponseWriter, r: &Request, modtime: Option<GoTime>) -> Cond {
    if r.method != "GET" && r.method != "HEAD" {
        return Cond::None;
    }
    let ir = r.header.get_raw("If-Range");
    if ir.is_empty() {
        return Cond::None;
    }
    if let Some((etag, _)) = scan_etag(ir) {
        let tag = w.header().get("Etag").to_vec();
        return if etag_strong_match(etag, &tag) {
            Cond::True
        } else {
            Cond::False
        };
    }
    let Some(modtime) = modtime.filter(|m| !m.is_zero()) else {
        return Cond::False;
    };
    match text(ir).and_then(parse_time) {
        Some(t) if t.unix() == modtime.unix() => Cond::True,
        _ => Cond::False,
    }
}

fn set_last_modified(w: &mut dyn ResponseWriter, modtime: Option<GoTime>) {
    if !is_zero_time(modtime)
        && let Some(modtime) = modtime
    {
        w.header()
            .set("Last-Modified", modtime.to_utc().format(TIME_FORMAT));
    }
}

async fn write_not_modified(w: &mut dyn ResponseWriter) {
    let h = w.header();
    h.del_raw("Content-Type");
    h.del_raw("Content-Length");
    h.del_raw("Content-Encoding");
    if !h.get("Etag").is_empty() {
        h.del_raw("Last-Modified");
    }
    w.write_header(304).await;
}

/// `checkPreconditions`: whether a reply was sent, and the `Range` header to honor.
async fn check_preconditions(
    w: &mut dyn ResponseWriter,
    r: &Request,
    modtime: Option<GoTime>,
) -> (bool, Vec<u8>) {
    let mut ch = check_if_match(w, r);
    if ch == Cond::None {
        ch = check_if_unmodified_since(r, modtime);
    }
    if ch == Cond::False {
        w.write_header(412).await;
        return (true, Vec::new());
    }
    match check_if_none_match(w, r) {
        Cond::False => {
            if r.method == "GET" || r.method == "HEAD" {
                write_not_modified(w).await;
            } else {
                w.write_header(412).await;
            }
            return (true, Vec::new());
        }
        Cond::None => {
            if check_if_modified_since(r, modtime) == Cond::False {
                write_not_modified(w).await;
                return (true, Vec::new());
            }
        }
        Cond::True => {}
    }
    let range = r.header.get_raw("Range").to_vec();
    if !range.is_empty() && check_if_range(w, r, modtime) == Cond::False {
        return (false, Vec::new());
    }
    (false, range)
}

/// `http.Dir`.
#[derive(Clone, Debug)]
pub struct Dir(pub PathBuf);

enum OpenError {
    NotExist,
    Permission,
    Other,
}

fn to_http_error(e: &OpenError) -> (&'static str, u16) {
    match e {
        OpenError::NotExist => ("404 page not found", 404),
        OpenError::Permission => ("403 Forbidden", 403),
        OpenError::Other => ("500 Internal Server Error", 500),
    }
}

fn classify(e: &io::Error) -> OpenError {
    match e.kind() {
        io::ErrorKind::NotFound => OpenError::NotExist,
        io::ErrorKind::PermissionDenied => OpenError::Permission,
        _ => OpenError::Other,
    }
}

impl Dir {
    /// `Dir.Open`, with `mapOpenError` turning "not a directory" into not-exist.
    async fn open(&self, name: &str) -> Result<(File, Metadata, PathBuf), OpenError> {
        let cleaned = path::clean(&format!("/{name}"));
        let rel = cleaned.trim_start_matches('/');
        let rel = if rel.is_empty() { "." } else { rel };
        // filepath.Localize refuses a NUL on Unix, the one thing a clean path can still hold.
        if rel.contains('\0') {
            return Err(OpenError::NotExist);
        }
        let dir = self.0.to_string_lossy();
        let dir = if dir.is_empty() { "." } else { dir.as_ref() };
        let full = filepath::join(&[dir, rel]);
        let file = match File::open(&full).await {
            Ok(f) => f,
            Err(e) => {
                let kind = classify(&e);
                if matches!(kind, OpenError::Other) {
                    // mapOpenError: a file used as a directory component does not exist.
                    let mut prefix = String::new();
                    for part in full.split('/') {
                        if !prefix.is_empty() || full.starts_with('/') {
                            prefix.push('/');
                        }
                        if part.is_empty() {
                            continue;
                        }
                        prefix.push_str(part);
                        match tokio::fs::metadata(&prefix).await {
                            Ok(m) if !m.is_dir() => return Err(OpenError::NotExist),
                            Ok(_) => {}
                            Err(_) => return Err(kind),
                        }
                    }
                }
                return Err(kind);
            }
        };
        let meta = file.metadata().await.map_err(|e| classify(&e))?;
        Ok((file, meta, PathBuf::from(full)))
    }
}

fn modtime_of(meta: &Metadata) -> Option<GoTime> {
    let d = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(GoTime::from_unix(
        i64::try_from(d.as_secs()).ok()?,
        d.subsec_nanos(),
    ))
}

async fn local_redirect(w: &mut dyn ResponseWriter, r: &Request, new_path: &str) {
    let mut location = new_path.to_owned();
    if !r.url.raw_query.is_empty() {
        location.push('?');
        location.push_str(&String::from_utf8_lossy(&r.url.raw_query));
    }
    w.header().set("Location", location);
    w.write_header(301).await;
}

fn contains_dot_dot(v: &[u8]) -> bool {
    v.windows(2).any(|p| p == b"..") && v.split(|&b| b == b'/' || b == b'\\').any(|e| e == b"..")
}

/// `http.ServeFile`.
pub async fn serve_file(w: &mut dyn ResponseWriter, r: &Request, name: &str) {
    if contains_dot_dot(&r.url.path) {
        serve_error(w, "invalid URL path", 400).await;
        return;
    }
    let (dir, file) = filepath::split(name);
    serve_file_inner(w, r, &Dir(PathBuf::from(dir)), file, false).await;
}

/// `serveFile`.
async fn serve_file_inner(
    w: &mut dyn ResponseWriter,
    r: &Request,
    fs: &Dir,
    name: &str,
    redirect: bool,
) {
    const INDEX_PAGE: &str = "/index.html";

    if r.url.path.ends_with(INDEX_PAGE.as_bytes()) {
        local_redirect(w, r, "./").await;
        return;
    }

    let (mut f, mut d, mut opened) = match fs.open(name).await {
        Ok(x) => x,
        Err(e) => {
            let (msg, code) = to_http_error(&e);
            serve_error(w, msg, code).await;
            return;
        }
    };

    let url_path = String::from_utf8_lossy(&r.url.path).into_owned();
    if redirect {
        if d.is_dir() {
            if !url_path.ends_with('/') {
                local_redirect(w, r, &format!("{}/", path::base(&url_path))).await;
                return;
            }
        } else if url_path.ends_with('/') {
            let base = path::base(&url_path);
            if base == "/" || base == "." {
                serve_error(w, "http: attempting to traverse a non-directory", 500).await;
                return;
            }
            local_redirect(w, r, &format!("../{base}")).await;
            return;
        }
    }

    if d.is_dir() {
        if !url_path.ends_with('/') {
            local_redirect(w, r, &format!("{}/", path::base(&url_path))).await;
            return;
        }
        let index = format!("{}{INDEX_PAGE}", name.trim_end_matches('/'));
        if let Ok((ff, dd, p)) = fs.open(&index).await {
            f = ff;
            d = dd;
            opened = p;
        }
    }

    if d.is_dir() {
        if check_if_modified_since(r, modtime_of(&d)) == Cond::False {
            write_not_modified(w).await;
            return;
        }
        set_last_modified(w, modtime_of(&d));
        dir_list(w, &opened).await;
        return;
    }

    let size = i64::try_from(d.len()).map_err(|_| "negative content size computed");
    let opened_name = opened.to_string_lossy().into_owned();
    let base = filepath::base(&opened_name);
    serve_content_inner(w, r, base, modtime_of(&d), size, &mut f).await;
}

/// `dirList`.
async fn dir_list(w: &mut dyn ResponseWriter, dir: &std::path::Path) {
    let mut names: Vec<(String, bool)> = Vec::new();
    match tokio::fs::read_dir(dir).await {
        Ok(mut rd) => loop {
            match rd.next_entry().await {
                Ok(Some(entry)) => {
                    let is_dir = entry.file_type().await.is_ok_and(|t| t.is_dir());
                    names.push((entry.file_name().to_string_lossy().into_owned(), is_dir));
                }
                Ok(None) => break,
                Err(_) => {
                    error(w, "Error reading directory", 500).await;
                    return;
                }
            }
        },
        Err(_) => {
            error(w, "Error reading directory", 500).await;
            return;
        }
    }
    names.sort();
    w.header().set("Content-Type", "text/html; charset=utf-8");
    let _ = w.write(b"<!doctype html>\n").await;
    let _ = w
        .write(b"<meta name=\"viewport\" content=\"width=device-width\">\n")
        .await;
    let _ = w.write(b"<pre>\n").await;
    for (name, is_dir) in names {
        let name = if is_dir { format!("{name}/") } else { name };
        let mut u = crate::url::Url {
            path: name.clone().into_bytes(),
            ..Default::default()
        };
        u.raw_path.clear();
        let href = String::from_utf8_lossy(&u.string()).into_owned();
        let line = format!("<a href=\"{}\">{}</a>\n", href, html_escape(&name));
        let _ = w.write(line.as_bytes()).await;
    }
    let _ = w.write(b"</pre>\n").await;
}

/// `http.FileServer(http.Dir(root))`.
pub fn file_server(root: PathBuf) -> BoxHandler {
    std::sync::Arc::new(FileHandler { root: Dir(root) })
}

struct FileHandler {
    root: Dir,
}

impl Handler for FileHandler {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !r.url.path.starts_with(b"/") {
                let mut p = b"/".to_vec();
                p.extend_from_slice(&r.url.path);
                r.url.path = p;
            }
            let upath = String::from_utf8_lossy(&r.url.path).into_owned();
            serve_file_inner(w, r, &self.root, &path::clean(&upath), true).await;
        })
    }
}

/// `http.NotFound`, exported here for handlers that fall back from a file lookup.
pub async fn file_not_found(w: &mut dyn ResponseWriter, r: &mut Request) {
    not_found(w, r).await;
}
