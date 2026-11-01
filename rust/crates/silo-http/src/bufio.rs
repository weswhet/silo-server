//! Ports of `bufio.Reader`, `bufio.Writer`, `net/http.connReader`, and `textproto.Reader`, over a
//! split tokio stream. Read and write deadlines live here because Go sets them on the `net.Conn`.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use silo_gocompat::strconv::quote_bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::time::{Instant, Sleep};
use tokio_util::sync::CancellationToken;

use crate::header::{Header, canonical_mime_header_key, valid_header_value_byte};

/// The stream a connection runs on.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// A connection stream with its concrete type erased.
pub type BoxedIo = Box<dyn Io>;

/// Locks a mutex whose holders only run non-panicking code, so poisoning cannot leave it torn.
pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `net.Conn.SetReadDeadline` and `SetWriteDeadline` state for one direction.
#[derive(Default)]
pub(crate) struct Deadline {
    at: Option<Instant>,
    sleep: Option<Pin<Box<Sleep>>>,
    waker: Option<Waker>,
}

impl Deadline {
    pub(crate) fn set(&mut self, at: Option<Instant>) {
        self.at = at;
        self.sleep = None;
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }

    fn poll_expired(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(at) = self.at else {
            self.waker = None;
            return false;
        };
        if Instant::now() >= at {
            return true;
        }
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
        self.waker = Some(cx.waker().clone());
        sleep.as_mut().poll(cx).is_ready()
    }
}

fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

/// The error a `bufio.Reader` can hold. `Eof` is `io.EOF`.
#[derive(Debug)]
pub(crate) enum ReadErr {
    Eof,
    BufferFull,
    Io(io::Error),
}

/// `net/http.connReader`: a read limit for headers, plus the single-byte background read that
/// detects a client hanging up while a handler runs.
pub(crate) struct ConnReader {
    rd: Option<ReadHalf<BoxedIo>>,
    pub(crate) remain: i64,
    has_byte: bool,
    byte_buf: u8,
    deadline: Deadline,
    /// `startBackgroundRead` has been asked for and has not finished.
    bg_active: bool,
    /// Cancels the connection's context on a read error, as `handleReadErrorLocked` does.
    cancel: CancellationToken,
    close_notify: Arc<AtomicBool>,
}

impl ConnReader {
    pub(crate) fn new(
        rd: ReadHalf<BoxedIo>,
        cancel: CancellationToken,
        close_notify: Arc<AtomicBool>,
    ) -> Self {
        Self {
            rd: Some(rd),
            remain: 0,
            has_byte: false,
            byte_buf: 0,
            deadline: Deadline::default(),
            bg_active: false,
            cancel,
            close_notify,
        }
    }

    pub(crate) fn set_read_limit(&mut self, remain: i64) {
        self.remain = remain;
    }

    pub(crate) fn set_infinite_read_limit(&mut self) {
        self.remain = i64::MAX;
    }

    pub(crate) fn hit_read_limit(&self) -> bool {
        self.remain <= 0
    }

    pub(crate) fn set_deadline(&mut self, at: Option<Instant>) {
        self.deadline.set(at);
    }

    fn handle_read_error(&self) {
        self.cancel.cancel();
        self.close_notify.store(true, Ordering::SeqCst);
    }

    fn poll_read(&mut self, cx: &mut Context<'_>, p: &mut [u8]) -> Poll<Result<usize, ReadErr>> {
        if self.hit_read_limit() {
            return Poll::Ready(Err(ReadErr::Eof));
        }
        if p.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let max = if (p.len() as i64) > self.remain {
            self.remain as usize
        } else {
            p.len()
        };
        let p = &mut p[..max];
        if self.has_byte {
            p[0] = self.byte_buf;
            self.has_byte = false;
            return Poll::Ready(Ok(1));
        }
        if self.deadline.poll_expired(cx) {
            self.handle_read_error();
            return Poll::Ready(Err(ReadErr::Io(timeout_error())));
        }
        let Some(rd) = self.rd.as_mut() else {
            return Poll::Ready(Err(ReadErr::Eof));
        };
        let mut buf = ReadBuf::new(p);
        match Pin::new(rd).poll_read(cx, &mut buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len();
                if n == 0 {
                    self.handle_read_error();
                    return Poll::Ready(Err(ReadErr::Eof));
                }
                self.remain -= n as i64;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                self.handle_read_error();
                Poll::Ready(Err(ReadErr::Io(e)))
            }
        }
    }

    /// `startBackgroundRead`.
    pub(crate) fn start_background_read(&mut self) {
        if self.has_byte {
            return;
        }
        self.bg_active = true;
        self.deadline.set(None);
    }

    /// One step of `backgroundRead`, polled next to the handler. Reads never block a thread here,
    /// so `abortPendingRead` is only clearing the flag.
    pub(crate) fn poll_background(&mut self, cx: &mut Context<'_>) {
        if !self.bg_active {
            return;
        }
        let Some(rd) = self.rd.as_mut() else {
            self.bg_active = false;
            return;
        };
        let mut one = [0u8; 1];
        let mut buf = ReadBuf::new(&mut one);
        match Pin::new(rd).poll_read(cx, &mut buf) {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.bg_active = false;
                if buf.filled().len() == 1 {
                    // A pipelined request. Go stopped treating this as a hangup in 1.11.
                    self.has_byte = true;
                    self.byte_buf = one[0];
                } else {
                    self.handle_read_error();
                }
            }
            Poll::Ready(Err(_)) => {
                self.bg_active = false;
                self.handle_read_error();
            }
        }
    }

    pub(crate) fn abort_pending_read(&mut self) {
        self.bg_active = false;
    }

    /// Gives up the stream for `Hijack`, returning the byte a background read took, if any.
    pub(crate) fn take_for_hijack(&mut self) -> (Option<ReadHalf<BoxedIo>>, Option<u8>) {
        self.bg_active = false;
        let byte = self.has_byte.then_some(self.byte_buf);
        self.has_byte = false;
        (self.rd.take(), byte)
    }
}

/// `bufio.Reader` over a [`ConnReader`], with Go's 4 KiB default size.
pub(crate) struct BufReader {
    cr: Arc<Mutex<ConnReader>>,
    buf: Box<[u8]>,
    r: usize,
    w: usize,
    err: Option<ReadErr>,
    last_byte: i32,
}

const BUF_SIZE: usize = 4096;

impl BufReader {
    pub(crate) fn new(cr: Arc<Mutex<ConnReader>>) -> Self {
        Self {
            cr,
            buf: vec![0; BUF_SIZE].into_boxed_slice(),
            r: 0,
            w: 0,
            err: None,
            last_byte: -1,
        }
    }

    pub(crate) fn buffered(&self) -> usize {
        self.w - self.r
    }

    /// The bytes still buffered, for `Hijack`.
    pub(crate) fn take_buffered(&mut self) -> Vec<u8> {
        let v = self.buf[self.r..self.w].to_vec();
        self.r = self.w;
        v
    }

    fn read_err(&mut self) -> Result<(), ReadErr> {
        match self.err.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn raw_read(cr: &Mutex<ConnReader>, p: &mut [u8]) -> Result<usize, ReadErr> {
        poll_fn(|cx| lock(cr).poll_read(cx, p)).await
    }

    async fn fill(&mut self) {
        if self.r > 0 {
            self.buf.copy_within(self.r..self.w, 0);
            self.w -= self.r;
            self.r = 0;
        }
        let w = self.w;
        match Self::raw_read(&self.cr, &mut self.buf[w..]).await {
            Ok(n) => self.w += n,
            Err(e) => self.err = Some(e),
        }
    }

    /// `b.Peek`.
    pub(crate) async fn peek(&mut self, n: usize) -> (&[u8], Option<ReadErr>) {
        self.last_byte = -1;
        while self.w - self.r < n && self.w - self.r < self.buf.len() && self.err.is_none() {
            self.fill().await;
        }
        if n > self.buf.len() {
            return (&self.buf[self.r..self.w], Some(ReadErr::BufferFull));
        }
        let avail = self.w - self.r;
        if avail < n {
            let e = self.read_err().err().unwrap_or(ReadErr::BufferFull);
            return (&self.buf[self.r..self.r + avail], Some(e));
        }
        (&self.buf[self.r..self.r + n], None)
    }

    /// `b.Discard`, for a count already known to be buffered.
    pub(crate) fn discard_buffered(&mut self, n: usize) {
        self.r += n.min(self.buffered());
    }

    /// `b.ReadSlice`.
    async fn read_slice(&mut self, delim: u8) -> (Vec<u8>, Option<ReadErr>) {
        let mut s = 0;
        loop {
            if let Some(i) = self.buf[self.r + s..self.w]
                .iter()
                .position(|&b| b == delim)
            {
                let i = i + s;
                let line = self.buf[self.r..=self.r + i].to_vec();
                self.r += i + 1;
                self.note_last_byte(&line);
                return (line, None);
            }
            if self.err.is_some() {
                let line = self.buf[self.r..self.w].to_vec();
                self.r = self.w;
                let e = self.read_err().err();
                self.note_last_byte(&line);
                return (line, e);
            }
            if self.buffered() >= self.buf.len() {
                self.r = self.w;
                let line = self.buf.to_vec();
                self.note_last_byte(&line);
                return (line, Some(ReadErr::BufferFull));
            }
            s = self.w - self.r;
            self.fill().await;
        }
    }

    fn note_last_byte(&mut self, line: &[u8]) {
        if let Some(&b) = line.last() {
            self.last_byte = i32::from(b);
        }
    }

    /// `b.ReadSlice('\n')` as `readChunkLine` uses it: a line, or the error that ended it.
    pub(crate) async fn read_slice_for_chunk(&mut self) -> Result<Vec<u8>, ReadErr> {
        let (line, err) = self.read_slice(b'\n').await;
        match err {
            Some(e) => Err(e),
            None => Ok(line),
        }
    }

    /// `chunkedReader.chunkHeaderAvailable`.
    pub(crate) fn chunk_header_available(&self) -> bool {
        self.buf[self.r..self.w].contains(&b'\n')
    }

    /// `b.ReadLine`: `(line, is_prefix)`.
    async fn read_line(&mut self) -> Result<(Vec<u8>, bool), ReadErr> {
        let (mut line, err) = self.read_slice(b'\n').await;
        if matches!(err, Some(ReadErr::BufferFull)) {
            if line.last() == Some(&b'\r') {
                self.r -= 1;
                line.pop();
            }
            return Ok((line, true));
        }
        if line.is_empty() {
            return match err {
                Some(e) => Err(e),
                None => Ok((line, false)),
            };
        }
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        Ok((line, false))
    }

    /// `b.ReadByte`.
    async fn read_byte(&mut self) -> Result<u8, ReadErr> {
        while self.r == self.w {
            if self.err.is_some() {
                self.read_err()?;
            }
            self.fill().await;
        }
        let c = self.buf[self.r];
        self.r += 1;
        self.last_byte = i32::from(c);
        Ok(c)
    }

    /// `b.UnreadByte`, right after a successful `read_byte`.
    fn unread_byte(&mut self) {
        if self.r > 0 {
            self.r -= 1;
        }
    }

    /// `b.Read`: at most one read of the stream.
    pub(crate) async fn read(&mut self, p: &mut [u8]) -> Result<usize, ReadErr> {
        if p.is_empty() {
            if self.buffered() > 0 {
                return Ok(0);
            }
            self.read_err()?;
            return Ok(0);
        }
        if self.r == self.w {
            self.read_err()?;
            if p.len() >= self.buf.len() {
                return Self::raw_read(&self.cr, p).await;
            }
            self.r = 0;
            self.w = 0;
            let n = Self::raw_read(&self.cr, &mut self.buf).await?;
            self.w += n;
        }
        let n = p.len().min(self.w - self.r);
        p[..n].copy_from_slice(&self.buf[self.r..self.r + n]);
        self.r += n;
        Ok(n)
    }

    /// `textproto.Reader.readLineSlice(-1)`, and so `ReadLine`.
    pub(crate) async fn read_full_line(&mut self) -> Result<Vec<u8>, ReadErr> {
        let mut out: Option<Vec<u8>> = None;
        loop {
            let (l, more) = self.read_line().await?;
            if out.is_none() && !more {
                return Ok(l);
            }
            out.get_or_insert_with(Vec::new).extend_from_slice(&l);
            if !more {
                return Ok(out.unwrap_or_default());
            }
        }
    }

    /// `textproto.Reader.skipSpace`.
    async fn skip_space(&mut self) -> usize {
        let mut n = 0;
        loop {
            match self.read_byte().await {
                Err(e) => {
                    // Go leaves the error in place for the next read, so a later read sees it again.
                    self.err = Some(e);
                    return n;
                }
                Ok(c) if c != b' ' && c != b'\t' => {
                    self.unread_byte();
                    return n;
                }
                Ok(_) => n += 1,
            }
        }
    }

    /// `textproto.Reader.readContinuedLineSlice` with `mustHaveFieldNameColon`.
    async fn read_continued_line(&mut self) -> Result<Vec<u8>, MimeError> {
        let line = self.read_full_line().await.map_err(MimeError::Read)?;
        if line.is_empty() {
            return Ok(line);
        }
        if !line.contains(&b':') {
            return Err(MimeError::Protocol(format!(
                "malformed MIME header: missing colon: {}",
                quote_bytes(&line)
            )));
        }
        if self.buffered() > 1 {
            let (peek, _) = self.peek(2).await;
            if (!peek.is_empty() && (peek[0].is_ascii_alphabetic() || peek[0] == b'\n'))
                || (peek.len() == 2 && peek[0] == b'\r' && peek[1] == b'\n')
            {
                return Ok(trim(&line).to_vec());
            }
        }
        let mut buf = trim(&line).to_vec();
        while self.skip_space().await > 0 {
            buf.push(b' ');
            let Ok(next) = self.read_full_line().await else {
                break;
            };
            buf.extend_from_slice(trim(&next));
        }
        Ok(buf)
    }

    /// `textproto.Reader.ReadMIMEHeader`. On error the partial header is dropped, which the server
    /// path does too: every error from here ends the request.
    pub(crate) async fn read_mime_header(&mut self) -> Result<Header, MimeError> {
        // upcomingHeaderKeys forces a buffer load before anything else.
        let _ = self.peek(1).await;
        let (first, _) = self.peek(1).await;
        if matches!(first, [b' ' | b'\t', ..]) {
            let line = self.read_full_line().await.map_err(MimeError::Read)?;
            let shown = &line[..line.len().min(80)];
            return Err(MimeError::Protocol(format!(
                "malformed MIME header initial line: {}",
                quote_bytes(shown)
            )));
        }
        let mut m = Header::new();
        loop {
            let kv = self.read_continued_line().await?;
            if kv.is_empty() {
                return Ok(m);
            }
            let bad_line =
                || MimeError::Protocol(format!("malformed MIME header line: {}", quote_bytes(&kv)));
            let Some(colon) = kv.iter().position(|&b| b == b':') else {
                return Err(bad_line());
            };
            let mut k = kv[..colon].to_vec();
            let v = &kv[colon + 1..];
            let (key, ok) = canonical_mime_header_key(&mut k);
            if !ok || !v.iter().all(|&c| valid_header_value_byte(c)) {
                return Err(bad_line());
            }
            let start = v
                .iter()
                .position(|&b| b != b' ' && b != b'\t')
                .unwrap_or(v.len());
            let value = v[start..].to_vec();
            // canonical_mime_header_key accepted only tokens and spaces, all ASCII.
            let key = String::from_utf8_lossy(&key).into_owned();
            let mut values = m
                .values_raw(&key)
                .map(<[Vec<u8>]>::to_vec)
                .unwrap_or_default();
            values.push(value);
            m.set_raw(key, values);
        }
    }
}

/// How `ReadMIMEHeader` failed.
#[derive(Debug)]
pub(crate) enum MimeError {
    Read(ReadErr),
    /// `textproto.ProtocolError`.
    Protocol(String),
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// `conn.bufw`: a 4 KiB `bufio.Writer` over the stream, with `checkConnErrorWriter`'s bookkeeping.
pub(crate) struct ConnWriter {
    wr: Option<WriteHalf<BoxedIo>>,
    buf: Vec<u8>,
    err: Option<(io::ErrorKind, String)>,
    deadline: Arc<Mutex<Deadline>>,
    werr: Arc<AtomicBool>,
    cancel: CancellationToken,
}

const WRITE_BUF_SIZE: usize = 4096;

impl ConnWriter {
    pub(crate) fn new(
        wr: WriteHalf<BoxedIo>,
        deadline: Arc<Mutex<Deadline>>,
        werr: Arc<AtomicBool>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            wr: Some(wr),
            buf: Vec::with_capacity(WRITE_BUF_SIZE),
            err: None,
            deadline,
            werr,
            cancel,
        }
    }

    fn sticky(&self) -> io::Result<()> {
        match &self.err {
            Some((kind, msg)) => Err(io::Error::new(*kind, msg.clone())),
            None => Ok(()),
        }
    }

    fn note_error(&mut self, e: &io::Error) {
        self.err = Some((e.kind(), e.to_string()));
        self.werr.store(true, Ordering::SeqCst);
        self.cancel.cancel();
    }

    async fn raw_write(&mut self, mut data: &[u8]) -> io::Result<()> {
        let Some(wr) = self.wr.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "use of closed network connection",
            ));
        };
        let deadline = self.deadline.clone();
        while !data.is_empty() {
            let n = poll_fn(|cx| {
                if lock(&deadline).poll_expired(cx) {
                    return Poll::Ready(Err(timeout_error()));
                }
                Pin::new(&mut *wr).poll_write(cx, data)
            })
            .await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
            }
            data = &data[n..];
        }
        poll_fn(|cx| {
            if lock(&deadline).poll_expired(cx) {
                return Poll::Ready(Err(timeout_error()));
            }
            Pin::new(&mut *wr).poll_flush(cx)
        })
        .await
    }

    /// `bufw.Write`.
    pub(crate) async fn write(&mut self, mut p: &[u8]) -> io::Result<()> {
        self.sticky()?;
        while p.len() > WRITE_BUF_SIZE - self.buf.len() {
            if self.buf.is_empty() {
                if let Err(e) = self.raw_write(p).await {
                    self.note_error(&e);
                    return Err(e);
                }
                return Ok(());
            }
            let n = WRITE_BUF_SIZE - self.buf.len();
            self.buf.extend_from_slice(&p[..n]);
            p = &p[n..];
            self.flush().await?;
        }
        self.buf.extend_from_slice(p);
        Ok(())
    }

    /// `bufw.Flush`.
    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        self.sticky()?;
        if self.buf.is_empty() {
            return Ok(());
        }
        let data = std::mem::take(&mut self.buf);
        let res = self.raw_write(&data).await;
        self.buf = data;
        self.buf.clear();
        if let Err(e) = res {
            self.note_error(&e);
            return Err(e);
        }
        Ok(())
    }

    /// Writes straight to the stream, past the buffer, for `fmt.Fprintf(c.rwc, ...)` error replies.
    pub(crate) async fn write_direct(&mut self, data: &[u8]) {
        let _ = self.raw_write(data).await;
    }

    /// `tcp.CloseWrite`.
    pub(crate) async fn close_write(&mut self) {
        if let Some(wr) = self.wr.as_mut() {
            let _ = wr.shutdown().await;
        }
    }

    /// `rwc.Close`: a later write fails.
    pub(crate) fn close(&mut self) {
        self.wr = None;
    }

    /// Gives up the stream for `Hijack`; `c.bufw.Reset` drops whatever was buffered.
    pub(crate) fn take_for_hijack(&mut self) -> Option<WriteHalf<BoxedIo>> {
        self.buf.clear();
        self.wr.take()
    }
}
