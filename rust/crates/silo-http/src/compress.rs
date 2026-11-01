//! Port of `internal/httpstream/compress.go` and `codings.go`: the content-coding negotiation, the
//! decision of which responses to encode, and the encoder selection.
//!
//! Encoded bytes are not meant to match Go's: the encoders are different implementations. Clients
//! decode, so the comparison that matters is decoded body plus negotiation.

use std::io::{self, Write};
use std::sync::Arc;

use silo_gocompat::strings::{equal_fold, to_lower, trim_space};

use crate::header::Header;
use crate::request::Request;
use crate::response::{BoxFuture, BoxHandler, Handler, Hijacked, ResponseWriter, WriteError};

const GZIP_LEVEL: u32 = 6;
const BROTLI_LEVEL: u32 = 3;
/// `brotliBlock`: the input held back before committing to the block encoder.
const BROTLI_BLOCK: usize = 1 << 16;
const BROTLI_BLOCK_LGWIN: u32 = 20;
const BROTLI_STREAM_QUALITY: u32 = 4;
const BROTLI_STREAM_LGWIN: u32 = 18;
/// `zstdWindow`, as a window log: 1 << 19.
const ZSTD_WINDOW_LOG: u32 = 19;
/// `minEncodedLength`.
pub const MIN_ENCODED_LENGTH: i64 = 256;

/// A content coding the compressor offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    Zstd,
    Brotli,
    Gzip,
}

impl Coding {
    /// The token sent in `Content-Encoding`.
    pub fn name(self) -> &'static str {
        match self {
            Coding::Zstd => "zstd",
            Coding::Brotli => "br",
            Coding::Gzip => "gzip",
        }
    }

    fn alias(self) -> Option<&'static str> {
        match self {
            Coding::Gzip => Some("x-gzip"),
            _ => None,
        }
    }
}

/// `codings`, in preference order when a client weights several equally.
const CODINGS: [Coding; 3] = [Coding::Zstd, Coding::Brotli, Coding::Gzip];

/// `defaultCompressibleTypes`.
pub const DEFAULT_COMPRESSIBLE_TYPES: &[&str] = &[
    "text/html",
    "text/css",
    "text/plain",
    "text/javascript",
    "text/markdown",
    "text/csv",
    "text/vtt",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/problem+json",
    "application/manifest+json",
    "application/wasm",
    "application/atom+xml",
    "application/rss+xml",
    "application/xml",
    "text/xml",
    "image/svg+xml",
];

/// `strconv.ParseFloat(s, 64)` for what a q-value can be. Go also accepts hex floats, underscores'
/// absence aside, and `inf` and `nan`, none of which end up in `[0, 1]` except hex forms, so hex is
/// parsed too.
fn parse_q(s: &str) -> Option<f64> {
    if s.is_empty() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let unsigned = lower.trim_start_matches(['+', '-']);
    if unsigned.starts_with("0x") {
        return parse_hex_float(&lower);
    }
    // Rust's parser accepts these spellings as well, with the same meaning: inf, infinity, nan.
    s.parse::<f64>().ok()
}

fn parse_hex_float(s: &str) -> Option<f64> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let s = s.strip_prefix("0x")?;
    // Go requires a p exponent on a hex float.
    let (mantissa, exp) = s.split_once('p')?;
    let exp: i32 = exp.parse().ok()?;
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    let mut v = 0f64;
    for c in int.chars() {
        v = v * 16.0 + f64::from(c.to_digit(16)?);
    }
    let mut scale = 1.0 / 16.0;
    for c in frac.chars() {
        v += f64::from(c.to_digit(16)?) * scale;
        scale /= 16.0;
    }
    let v = v * 2f64.powi(exp);
    Some(if neg { -v } else { v })
}

/// `qValue`.
fn q_value(params: &str) -> Option<f64> {
    let mut q = 1.0;
    for param in params.split(';') {
        let param = trim_space(param);
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        if !equal_fold(trim_space(key), "q") {
            continue;
        }
        let v = parse_q(trim_space(value))?;
        if !(0.0..=1.0).contains(&v) {
            return None;
        }
        q = v;
    }
    Some(q)
}

/// `negotiate`: the coding to apply, `None` for identity, and whether the field refused identity.
pub fn negotiate(values: &[Vec<u8>]) -> (Option<Coding>, bool) {
    let mut weights = [-1.0f64; CODINGS.len()];
    let (mut star, mut identity) = (-1.0f64, -1.0f64);
    for value in values {
        let value = silo_gocompat::strings::decode_runes(value);
        for element in value.split(',') {
            let (name, params) = element.split_once(';').unwrap_or((element, ""));
            let name = trim_space(name);
            let Some(q) = q_value(params) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if name == "*" {
                star = q;
                continue;
            }
            if equal_fold(name, "identity") {
                identity = q;
                continue;
            }
            for (i, c) in CODINGS.iter().enumerate() {
                if equal_fold(name, c.name()) || c.alias().is_some_and(|a| equal_fold(name, a)) {
                    weights[i] = q;
                }
            }
        }
    }
    let mut best = None;
    let mut best_q = 0.0;
    for (i, &q) in weights.iter().enumerate() {
        let q = if q < 0.0 { star } else { q };
        if q > best_q {
            best = Some(CODINGS[i]);
            best_q = q;
        }
    }
    if identity < 0.0 {
        identity = star;
    }
    if identity > best_q {
        best = None;
    }
    (best, identity == 0.0)
}

/// A request predicate for `skipRequest`.
pub type SkipRequest = Arc<dyn Fn(&Request) -> bool + Send + Sync>;
/// A predicate on the request's method and path and the response header, for `skipResponse`.
pub type SkipResponse = Arc<dyn Fn(&ResponseInfo, &Header) -> bool + Send + Sync>;

/// What `skipResponse` can see of the request once the handler holds it.
#[derive(Clone, Debug)]
pub struct ResponseInfo {
    pub method: String,
    pub path: Vec<u8>,
}

struct Compressor {
    types: Vec<String>,
    skip_response: Option<SkipResponse>,
}

impl Compressor {
    /// `c.negotiates`.
    fn negotiates(&self, status: u16, h: &Header) -> bool {
        if matches!(status, 204 | 206 | 304) {
            return false;
        }
        if !h.get("Content-Encoding").is_empty() || !h.get("Content-Range").is_empty() {
            return false;
        }
        let ct = h.get("Content-Type");
        let ct = silo_gocompat::strings::decode_runes(ct);
        let media_type = ct.split(';').next().unwrap_or("");
        let key = to_lower(trim_space(media_type));
        self.types.contains(&key)
    }
}

/// `httpstream.CompressExcept`.
pub fn compress_except(skip: Option<SkipRequest>, types: &[&str]) -> crate::chi::Middleware {
    compress_with_exclusions(skip, None, types)
}

/// `httpstream.CompressWithExclusions`.
pub fn compress_with_exclusions(
    skip_request: Option<SkipRequest>,
    skip_response: Option<SkipResponse>,
    types: &[&str],
) -> crate::chi::Middleware {
    let types = if types.is_empty() {
        DEFAULT_COMPRESSIBLE_TYPES
    } else {
        types
    };
    let c = Arc::new(Compressor {
        types: types.iter().map(|t| (*t).to_owned()).collect(),
        skip_response,
    });
    crate::chi::middleware_fn(move |next: BoxHandler| -> BoxHandler {
        Arc::new(CompressHandler {
            c: c.clone(),
            skip_request: skip_request.clone(),
            next,
        })
    })
}

struct CompressHandler {
    c: Arc<Compressor>,
    skip_request: Option<SkipRequest>,
    next: BoxHandler,
}

impl Handler for CompressHandler {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if self.skip_request.as_ref().is_some_and(|skip| skip(r)) {
                self.next.serve_http(w, r).await;
                return;
            }
            let (coding, identity_refused) = negotiate(r.header.values("Accept-Encoding"));
            let info = ResponseInfo {
                method: r.method.clone(),
                path: r.url.path.clone(),
            };
            let mut cw = CompressWriter {
                w,
                info,
                c: self.c.clone(),
                coding,
                identity_refused,
                enc: None,
                decided: false,
            };
            self.next.serve_http(&mut cw, r).await;
            cw.close().await;
        })
    }
}

/// `compressWriter`.
struct CompressWriter<'a> {
    w: &'a mut dyn ResponseWriter,
    info: ResponseInfo,
    c: Arc<Compressor>,
    coding: Option<Coding>,
    identity_refused: bool,
    enc: Option<Encoder>,
    decided: bool,
}

impl CompressWriter<'_> {
    /// `w.encodes`.
    fn encodes(&self, h: &Header) -> bool {
        if self.coding.is_none() {
            return false;
        }
        if self.identity_refused {
            return true;
        }
        match std::str::from_utf8(h.get("Content-Length"))
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
        {
            Some(n) => n >= MIN_ENCODED_LENGTH,
            None => true,
        }
    }

    async fn write_header_inner(&mut self, status: u16) {
        if !self.decided && status >= 200 {
            self.decided = true;
            let negotiates = {
                let h = self.w.header();
                let skipped = self
                    .c
                    .skip_response
                    .as_ref()
                    .is_some_and(|skip| skip(&self.info, h));
                !skipped && self.c.negotiates(status, h)
            };
            if negotiates {
                self.w.header().add("Vary", "Accept-Encoding");
                let snapshot = self.w.header().clone();
                if self.encodes(&snapshot)
                    && let Some(coding) = self.coding
                {
                    let h = self.w.header();
                    h.set("Content-Encoding", coding.name());
                    h.del("Content-Length");
                    self.enc = Some(Encoder::new(coding));
                }
            }
        }
        self.w.write_header(status).await;
    }

    async fn drain(&mut self) -> Result<(), WriteError> {
        let Some(enc) = self.enc.as_mut() else {
            return Ok(());
        };
        let out = enc.take_output();
        if !out.is_empty() {
            self.w.write(&out).await?;
        }
        Ok(())
    }

    /// `w.close`.
    async fn close(&mut self) {
        let Some(enc) = self.enc.as_mut() else {
            return;
        };
        let _ = enc.finish();
        let _ = self.drain().await;
        self.enc = None;
    }
}

impl ResponseWriter for CompressWriter<'_> {
    fn header(&mut self) -> &mut Header {
        self.w.header()
    }

    fn write_header(&mut self, code: u16) -> BoxFuture<'_, ()> {
        Box::pin(self.write_header_inner(code))
    }

    fn write<'b>(&'b mut self, data: &'b [u8]) -> BoxFuture<'b, Result<usize, WriteError>> {
        Box::pin(async move {
            if !self.decided {
                self.write_header_inner(200).await;
            }
            if let Some(enc) = self.enc.as_mut() {
                enc.write(data).map_err(WriteError::Io)?;
                self.drain().await?;
                return Ok(data.len());
            }
            self.w.write(data).await
        })
    }

    fn flush(&mut self) -> BoxFuture<'_, Result<(), WriteError>> {
        Box::pin(async move {
            if !self.decided {
                self.write_header_inner(200).await;
            }
            if let Some(enc) = self.enc.as_mut() {
                let _ = enc.flush();
                let _ = self.drain().await;
            }
            self.w.flush().await
        })
    }

    fn hijack(&mut self) -> BoxFuture<'_, Result<Hijacked, WriteError>> {
        self.w.hijack()
    }

    fn set_read_deadline(&mut self, at: Option<std::time::Instant>) -> Result<(), WriteError> {
        self.w.set_read_deadline(at)
    }

    fn set_write_deadline(&mut self, at: Option<std::time::Instant>) -> Result<(), WriteError> {
        self.w.set_write_deadline(at)
    }

    fn enable_full_duplex(&mut self) -> Result<(), WriteError> {
        self.w.enable_full_duplex()
    }
}

/// A sink the encoders write into. `take_output` hands its contents to the response.
type Sink = Vec<u8>;

enum Encoder {
    Gzip(flate2::write::GzEncoder<Sink>),
    Zstd(zstd::stream::write::Encoder<'static, Sink>),
    Brotli(Box<BrotliWriter>),
    /// The last bytes after `finish`.
    Finished(Vec<u8>),
    Done,
}

impl Encoder {
    fn new(coding: Coding) -> Self {
        match coding {
            Coding::Gzip => Encoder::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(GZIP_LEVEL),
            )),
            Coding::Zstd => match new_zstd() {
                Ok(e) => Encoder::Zstd(e),
                // Only an allocation failure in the C library gets here. Go panics in the same spot.
                Err(e) => panic!("zstd encoder: {e}"),
            },
            Coding::Brotli => Encoder::Brotli(Box::default()),
        }
    }

    fn write(&mut self, p: &[u8]) -> io::Result<()> {
        match self {
            Encoder::Gzip(e) => e.write_all(p),
            Encoder::Zstd(e) => e.write_all(p),
            Encoder::Brotli(e) => e.write(p),
            Encoder::Finished(_) | Encoder::Done => Ok(()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Encoder::Gzip(e) => e.flush(),
            Encoder::Zstd(e) => e.flush(),
            Encoder::Brotli(e) => e.flush(),
            Encoder::Finished(_) | Encoder::Done => Ok(()),
        }
    }

    fn take_output(&mut self) -> Vec<u8> {
        match self {
            Encoder::Gzip(e) => std::mem::take(e.get_mut()),
            Encoder::Zstd(e) => std::mem::take(e.get_mut()),
            Encoder::Brotli(e) => e.take_output(),
            Encoder::Finished(v) => std::mem::take(v),
            Encoder::Done => Vec::new(),
        }
    }

    /// `enc.Close`. The final output stays available from `take_output`.
    fn finish(&mut self) -> io::Result<()> {
        match std::mem::replace(self, Encoder::Done) {
            Encoder::Gzip(e) => {
                let out = e.finish()?;
                *self = Encoder::Finished(out);
                Ok(())
            }
            Encoder::Zstd(e) => {
                let out = e.finish()?;
                *self = Encoder::Finished(out);
                Ok(())
            }
            Encoder::Brotli(mut e) => {
                e.close()?;
                *self = Encoder::Finished(e.take_output());
                Ok(())
            }
            other => {
                *self = other;
                Ok(())
            }
        }
    }
}

fn new_zstd() -> io::Result<zstd::stream::write::Encoder<'static, Sink>> {
    let mut e = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
    e.window_log(ZSTD_WINDOW_LOG)?;
    e.include_checksum(false)?;
    Ok(e)
}

type BrotliEnc = brotli::CompressorWriter<Sink>;

/// `brotliWriter`: holds back the first 64 KiB so a body that ends without a flush goes through the
/// fast settings, and a body that flushes first switches to the settings that can stream.
#[derive(Default)]
struct BrotliWriter {
    held: Vec<u8>,
    block: Option<BrotliEnc>,
    stream: Option<BrotliEnc>,
    done: Vec<u8>,
}

fn new_brotli(quality: u32, lgwin: u32) -> BrotliEnc {
    brotli::CompressorWriter::new(Vec::new(), 16 * 1024, quality, lgwin)
}

impl BrotliWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<()> {
        if let Some(s) = self.stream.as_mut() {
            return s.write_all(p);
        }
        if let Some(b) = self.block.as_mut() {
            return b.write_all(p);
        }
        if self.held.len() + p.len() <= BROTLI_BLOCK {
            self.held.extend_from_slice(p);
            return Ok(());
        }
        self.start_blocks()?;
        match self.block.as_mut() {
            Some(b) => b.write_all(p),
            None => Ok(()),
        }
    }

    fn start_blocks(&mut self) -> io::Result<()> {
        let mut b = new_brotli(BROTLI_LEVEL, BROTLI_BLOCK_LGWIN);
        let held = std::mem::take(&mut self.held);
        if !held.is_empty() {
            b.write_all(&held)?;
        }
        self.block = Some(b);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(s) = self.stream.as_mut() {
            return s.flush();
        }
        if self.block.is_some() || self.held.is_empty() {
            return Ok(());
        }
        let mut s = new_brotli(BROTLI_STREAM_QUALITY, BROTLI_STREAM_LGWIN);
        let held = std::mem::take(&mut self.held);
        s.write_all(&held)?;
        s.flush()?;
        self.stream = Some(s);
        Ok(())
    }

    fn take_output(&mut self) -> Vec<u8> {
        if !self.done.is_empty() {
            return std::mem::take(&mut self.done);
        }
        if let Some(s) = self.stream.as_mut() {
            return std::mem::take(s.get_mut());
        }
        if let Some(b) = self.block.as_mut() {
            return std::mem::take(b.get_mut());
        }
        Vec::new()
    }

    fn close(&mut self) -> io::Result<()> {
        if self.stream.is_none() && self.block.is_none() {
            self.start_blocks()?;
        }
        if let Some(s) = self.stream.take() {
            self.done = s.into_inner();
        } else if let Some(b) = self.block.take() {
            self.done = b.into_inner();
        }
        Ok(())
    }
}
