//! HTTP/1.1 framing for a byte relay: where a head ends and where a body ends, by the rules Go's
//! server applies. Nothing here decodes or rewrites a body.
//!
//! The request side must agree with Go about message boundaries, or bytes this relay treated as a
//! body would reach Go as a request it never sanitized. So it follows `readRequest`, `readTransfer`,
//! and `textproto.ReadMIMEHeader`, and anything it cannot vouch for is [`RequestScan::Reject`]: the
//! caller gives those to silo-http's port of the same reader for Go's refusal, and Go never sees them.

use std::ops::Range;

use silo_http::canonical_header_key;
use silo_http::header::{valid_header_field_name, valid_header_field_value, valid_host_header};
use silo_http::url::parse_request_uri;

/// `http.DefaultMaxHeaderBytes` plus the 4096 the server adds.
pub const MAX_HEAD_BYTES: usize = (1 << 20) + 4096;
/// `maxLineLength` in `net/http/internal/chunked.go`.
const MAX_CHUNK_LINE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
}

#[derive(Clone, Debug)]
pub struct Field {
    /// The name as sent.
    pub name: Vec<u8>,
    /// The value, with folded lines joined as Go joins them.
    pub value: Vec<u8>,
    /// The whole logical line in the head, folds and line ending included.
    pub span: Range<usize>,
}

#[derive(Clone, Debug)]
pub struct RequestHead {
    pub method: String,
    /// The request target, untouched.
    pub target: Vec<u8>,
    pub fields: Vec<Field>,
    /// Bytes up to and including the blank line.
    pub head_len: usize,
    /// Where the blank line starts.
    pub terminator: usize,
    pub framing: Framing,
}

impl RequestHead {
    /// The values of a header, by case-insensitive name, in order.
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.fields
            .iter()
            .filter(move |f| name_eq(&f.name, name))
            .map(|f| f.value.as_slice())
    }

    pub fn has(&self, name: &str) -> bool {
        self.fields.iter().any(|f| name_eq(&f.name, name))
    }

    /// The target's path, before any `?`. `None` unless the target is in origin form.
    pub fn origin_path(&self) -> Option<&[u8]> {
        if !self.target.starts_with(b"/") {
            return None;
        }
        Some(
            self.target
                .split(|&b| b == b'?')
                .next()
                .unwrap_or(&self.target),
        )
    }

    pub fn query(&self) -> Option<&[u8]> {
        let at = self.target.iter().position(|&b| b == b'?')?;
        Some(&self.target[at + 1..])
    }
}

fn name_eq(name: &[u8], want: &str) -> bool {
    name.eq_ignore_ascii_case(want.as_bytes())
}

#[derive(Debug)]
pub enum RequestScan {
    Incomplete,
    Complete(Box<RequestHead>),
    Reject,
}

fn cut(s: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let at = s.iter().position(|&b| b == sep)?;
    Some((&s[..at], &s[at + 1..]))
}

fn trim_ws(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// The next line in `buf` from `at`: the content without its ending, and the offset after the ending.
fn next_line(buf: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let rel = buf[at..].iter().position(|&b| b == b'\n')?;
    let end = at + rel + 1;
    let mut line = &buf[at..at + rel];
    if let [rest @ .., b'\r'] = line {
        line = rest;
    }
    Some((line, end))
}

fn http_minor(version: &[u8]) -> Option<(u8, u8)> {
    if !version.starts_with(b"HTTP/") || version.len() != 8 || version[6] != b'.' {
        return None;
    }
    if !version[5].is_ascii_digit() || !version[7].is_ascii_digit() {
        return None;
    }
    Some((version[5] - b'0', version[7] - b'0'))
}

/// `parseContentLength`, on a trimmed value.
fn content_length(cl: &[u8]) -> Option<u64> {
    if cl.is_empty() || !cl.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: u64 = 0;
    for &c in cl {
        n = n.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
        if n >= 1 << 63 {
            return None;
        }
    }
    Some(n)
}

/// Scans the request at the start of `buf`.
pub fn scan_request(buf: &[u8]) -> RequestScan {
    let scan_len = buf.len().min(MAX_HEAD_BYTES);
    let window = &buf[..scan_len];
    let incomplete = || {
        if buf.len() >= MAX_HEAD_BYTES {
            RequestScan::Reject
        } else {
            RequestScan::Incomplete
        }
    };

    let Some((request_line, first_end)) = next_line(window, 0) else {
        return incomplete();
    };

    // Group the header lines before validating anything, so a partial head is never judged.
    let mut groups: Vec<(Range<usize>, Vec<u8>)> = Vec::new();
    let mut at = first_end;
    let terminator;
    let head_len;
    loop {
        let Some((line, next)) = next_line(window, at) else {
            return incomplete();
        };
        if line.is_empty() {
            terminator = at;
            head_len = next;
            break;
        }
        match line[0] {
            b' ' | b'\t' => {
                // A continuation with nothing before it is `malformed MIME header initial line`.
                let Some((span, joined)) = groups.last_mut() else {
                    return RequestScan::Reject;
                };
                joined.push(b' ');
                joined.extend_from_slice(trim_ws(line));
                span.end = next;
            }
            _ => groups.push((at..next, trim_ws(line).to_vec())),
        }
        at = next;
    }

    let Some((method, rest)) = cut(request_line, b' ') else {
        return RequestScan::Reject;
    };
    let Some((target, version)) = cut(rest, b' ') else {
        return RequestScan::Reject;
    };
    if !valid_header_field_name(method) {
        return RequestScan::Reject;
    }
    let Some((major, minor)) = http_minor(version) else {
        return RequestScan::Reject;
    };
    // `http1ServerSupportsRequest` also lets through the h2c preface, which the server refuses.
    if major != 1 {
        return RequestScan::Reject;
    }
    let method_text = String::from_utf8_lossy(method).into_owned();
    let authority = method_text == "CONNECT" && !target.starts_with(b"/");
    let parsed = if authority {
        let mut raw = b"http://".to_vec();
        raw.extend_from_slice(target);
        parse_request_uri(&raw)
    } else {
        parse_request_uri(target)
    };
    if parsed.is_err() {
        return RequestScan::Reject;
    }

    let mut fields = Vec::with_capacity(groups.len());
    for (span, kv) in groups {
        let Some((name, value)) = cut(&kv, b':') else {
            return RequestScan::Reject;
        };
        if !valid_header_field_name(name) {
            return RequestScan::Reject;
        }
        let value = trim_ws(value);
        if !valid_header_field_value(value) {
            return RequestScan::Reject;
        }
        fields.push(Field {
            name: name.to_vec(),
            value: value.to_vec(),
            span,
        });
    }
    let mut head = RequestHead {
        method: method_text,
        target: target.to_vec(),
        fields,
        head_len,
        terminator,
        framing: Framing::None,
    };

    // conn.readRequest's Host checks.
    let hosts: Vec<&[u8]> = head.values("Host").collect();
    let at_least_11 = minor >= 1;
    // server.go's readRequest: a missing Host on HTTP/1.1+ is a 400, except for CONNECT. (Go also
    // excepts an h2 upgrade, which this scanner does not otherwise distinguish.) Duplicate Host
    // headers are rejected unconditionally, by Go's own request parser rather than this check, so
    // CONNECT gets no exception from that.
    if hosts.len() > 1 || (at_least_11 && hosts.is_empty() && head.method != "CONNECT") {
        return RequestScan::Reject;
    }
    if let Some(host) = hosts.first()
        && !valid_host_header(host)
    {
        return RequestScan::Reject;
    }

    // parseTransferEncoding.
    let mut chunked = false;
    let te: Vec<&[u8]> = head.values("Transfer-Encoding").collect();
    if !te.is_empty() && at_least_11 {
        if te.len() != 1 || !te[0].eq_ignore_ascii_case(b"chunked") {
            return RequestScan::Reject;
        }
        chunked = true;
    }

    // fixLength.
    let lens: Vec<&[u8]> = head.values("Content-Length").map(trim_string).collect();
    if lens.len() > 1 && lens[1..].iter().any(|l| *l != lens[0]) {
        return RequestScan::Reject;
    }
    let mut length = 0;
    if let Some(first) = lens.first() {
        match content_length(first) {
            Some(n) => length = n,
            None => return RequestScan::Reject,
        }
    }

    // fixTrailer.
    if chunked {
        for value in head.values("Trailer") {
            for key in value.split(|&b| b == b',') {
                let key = canonical_header_key(&String::from_utf8_lossy(trim_string(key)));
                if matches!(
                    key.as_str(),
                    "Transfer-Encoding" | "Trailer" | "Content-Length"
                ) {
                    return RequestScan::Reject;
                }
            }
        }
    }

    head.framing = if chunked {
        Framing::Chunked
    } else if length > 0 {
        Framing::Length(length)
    } else {
        Framing::None
    };
    RequestScan::Complete(Box::new(head))
}

fn trim_string(s: &[u8]) -> &[u8] {
    silo_http::header::trim_string(s)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseBody {
    None,
    Length(u64),
    Chunked,
    /// Ends when the upstream closes.
    Eof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub head_len: usize,
    pub body: ResponseBody,
    /// The connection ends after this response.
    pub close: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseScan {
    Incomplete,
    Complete(ResponseHead),
    /// Not an HTTP/1 response. The caller relays it to the end of the stream.
    Garbage,
}

fn has_token(value: &[u8], token: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|t| trim_ws(t).eq_ignore_ascii_case(token))
}

/// Scans the response at the start of `buf`, the answer to a request with this method.
pub fn scan_response(buf: &[u8], head_request: bool) -> ResponseScan {
    let Some((status_line, first_end)) = next_line(buf, 0) else {
        return if buf.len() > MAX_HEAD_BYTES {
            ResponseScan::Garbage
        } else {
            ResponseScan::Incomplete
        };
    };
    let mut parts = status_line.splitn(3, |&b| b == b' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    let Some((1, minor)) = http_minor(version) else {
        return ResponseScan::Garbage;
    };
    let status: Option<u16> = std::str::from_utf8(code).ok().and_then(|c| c.parse().ok());
    let Some(status) = status else {
        return ResponseScan::Garbage;
    };

    let mut at = first_end;
    let mut length = None;
    let mut chunked = false;
    let mut close = false;
    let mut keep_alive = false;
    let head_len = loop {
        let Some((line, next)) = next_line(buf, at) else {
            return if buf.len() > MAX_HEAD_BYTES {
                ResponseScan::Garbage
            } else {
                ResponseScan::Incomplete
            };
        };
        if line.is_empty() {
            break next;
        }
        if let Some((name, value)) = cut(line, b':') {
            let value = trim_ws(value);
            if name.eq_ignore_ascii_case(b"Content-Length") {
                length = content_length(value);
            } else if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
                chunked |= has_token(value, b"chunked");
            } else if name.eq_ignore_ascii_case(b"Connection") {
                close |= has_token(value, b"close");
                keep_alive |= has_token(value, b"keep-alive");
            }
        }
        at = next;
    };
    let body = if head_request || (100..200).contains(&status) || status == 204 || status == 304 {
        ResponseBody::None
    } else if chunked {
        ResponseBody::Chunked
    } else if let Some(n) = length {
        ResponseBody::Length(n)
    } else {
        ResponseBody::Eof
    };
    ResponseScan::Complete(ResponseHead {
        status,
        head_len,
        body,
        close: close || (minor == 0 && !keep_alive) || body == ResponseBody::Eof,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkStatus {
    More,
    Done,
    /// Go refuses the bytes up to here, so nothing past them may be forwarded.
    Malformed,
}

#[derive(Clone, Debug)]
enum ChunkState {
    SizeLine,
    Data(u64),
    DataCr,
    DataLf,
    Trailer,
}

/// Walks a chunked body without decoding it. `net/http/internal/chunked.go` is the rule for what is
/// malformed, and `readTrailer` for where the trailer ends.
#[derive(Clone, Debug)]
pub struct ChunkWalker {
    state: ChunkState,
    line: Vec<u8>,
}

impl Default for ChunkWalker {
    fn default() -> Self {
        Self {
            state: ChunkState::SizeLine,
            line: Vec::new(),
        }
    }
}

impl ChunkWalker {
    /// Consumes bytes from `data` and returns how many, and where the body stands after them.
    pub fn feed(&mut self, data: &[u8]) -> (usize, ChunkStatus) {
        let mut i = 0;
        while i < data.len() {
            match self.state {
                ChunkState::SizeLine => {
                    let b = data[i];
                    i += 1;
                    self.line.push(b);
                    if b == b'\n' {
                        match parse_size_line(&self.line) {
                            Some(0) => {
                                self.state = ChunkState::Trailer;
                                self.line.clear();
                            }
                            Some(n) => {
                                self.state = ChunkState::Data(n);
                                self.line.clear();
                            }
                            None => return (i, ChunkStatus::Malformed),
                        }
                    } else if self.line.len() > MAX_CHUNK_LINE + 2 {
                        return (i, ChunkStatus::Malformed);
                    }
                }
                ChunkState::Data(n) => {
                    let take = usize::try_from(n).unwrap_or(usize::MAX).min(data.len() - i);
                    i += take;
                    let left = n - take as u64;
                    self.state = if left == 0 {
                        ChunkState::DataCr
                    } else {
                        ChunkState::Data(left)
                    };
                }
                ChunkState::DataCr => {
                    i += 1;
                    if data[i - 1] != b'\r' {
                        return (i, ChunkStatus::Malformed);
                    }
                    self.state = ChunkState::DataLf;
                }
                ChunkState::DataLf => {
                    i += 1;
                    if data[i - 1] != b'\n' {
                        return (i, ChunkStatus::Malformed);
                    }
                    self.state = ChunkState::SizeLine;
                }
                ChunkState::Trailer => {
                    let b = data[i];
                    i += 1;
                    if b != b'\n' {
                        self.line.push(b);
                        if self.line.len() > MAX_HEAD_BYTES {
                            return (i, ChunkStatus::Malformed);
                        }
                        continue;
                    }
                    let empty = self.line.is_empty() || self.line == b"\r";
                    self.line.clear();
                    if empty {
                        return (i, ChunkStatus::Done);
                    }
                }
            }
        }
        (i, ChunkStatus::More)
    }
}

/// `readChunkLine` and `begin_chunk`: the chunk size, or `None` where Go fails the body.
fn parse_size_line(line: &[u8]) -> Option<u64> {
    let cr = line.iter().position(|&b| b == b'\r')?;
    if cr != line.len() - 2 {
        return None;
    }
    let mut p = &line[..cr];
    if p.len() >= MAX_CHUNK_LINE {
        return None;
    }
    while let [rest @ .., b' ' | b'\t'] = p {
        p = rest;
    }
    let p = p.split(|&b| b == b';').next().unwrap_or(&[]);
    if p.is_empty() || p.len() > 16 {
        return None;
    }
    let mut n: u64 = 0;
    for &b in p {
        let d = (b as char).to_digit(16)?;
        n = (n << 4) | u64::from(d);
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(raw: &[u8]) -> RequestHead {
        match scan_request(raw) {
            RequestScan::Complete(h) => *h,
            other => panic!("{other:?} for {:?}", String::from_utf8_lossy(raw)),
        }
    }

    fn rejected(raw: &[u8]) -> bool {
        matches!(scan_request(raw), RequestScan::Reject)
    }

    #[test]
    fn framing_follows_go_where_a_disagreement_would_smuggle() {
        // Chunked beats Content-Length, as readTransfer does.
        let h = complete(
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(h.framing, Framing::Chunked);
        // HTTP/1.0 ignores Transfer-Encoding, and so must this, or a 1.0 request's body runs on.
        let h =
            complete(b"POST / HTTP/1.0\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(h.framing, Framing::Length(2));
        // Repeated equal lengths are one length; different ones are refused.
        let h = complete(
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
        );
        assert_eq!(h.framing, Framing::Length(3));
        assert!(rejected(
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n"
        ));
        for bad in [
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +3\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x3\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTrailer: Content-Length\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            b"GET / HTTP/2.0\r\nHost: a\r\n\r\n",
            b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
            b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
            b"GET / HTTP/1.1\r\n Host: a\r\n\r\n",
        ] {
            assert!(rejected(bad), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_folded_header_is_one_field_and_its_value_counts() {
        let h = complete(b"POST / HTTP/1.1\nHost: a\nContent-Length:\n  7\nX-A: b\n\n");
        assert_eq!(h.framing, Framing::Length(7));
        assert_eq!(h.fields[1].value, b"7");
        assert_eq!(h.head_len, 52);
    }

    #[test]
    fn connect_is_the_only_exception_to_the_missing_host_400() {
        // server.go's readRequest: HTTP/1.1 with no Host is a 400 -- except for CONNECT.
        assert!(rejected(b"GET / HTTP/1.1\r\n\r\n"));
        let h = complete(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n");
        assert_eq!(h.method, "CONNECT");
        // CONNECT still gets no exception from the separate, unconditional check that two Host
        // headers (regardless of value) are a 400: that one isn't about a missing Host at all.
        assert!(rejected(
            b"CONNECT example.test:443 HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"
        ));
        // HTTP/1.0 never required Host in the first place, CONNECT or not.
        let h = complete(b"GET / HTTP/1.0\r\n\r\n");
        assert_eq!(h.method, "GET");
    }

    #[test]
    fn a_partial_head_waits() {
        assert!(matches!(
            scan_request(b"GET / HTTP/1.1\r\nHost: a\r\n"),
            RequestScan::Incomplete
        ));
    }

    #[test]
    fn chunk_walker_stops_exactly_at_the_end_and_at_bad_framing() {
        let mut w = ChunkWalker::default();
        let body = b"5;ext=1\r\nhello\r\n0\r\nX-T: v\r\n\r\nGET / HTTP/1.1\r\n";
        let (n, st) = w.feed(body);
        assert_eq!(st, ChunkStatus::Done);
        assert_eq!(&body[n..], b"GET / HTTP/1.1\r\n");

        // One byte at a time reaches the same place.
        let mut w = ChunkWalker::default();
        let mut used = 0;
        for b in body.iter() {
            let (n, st) = w.feed(std::slice::from_ref(b));
            used += n;
            if st == ChunkStatus::Done {
                break;
            }
        }
        assert_eq!(&body[used..], b"GET / HTTP/1.1\r\n");

        for bad in [
            &b"5\nhello\r\n"[..],
            b"5\r\nhelloXX",
            b"zz\r\n",
            b"\r\n",
            b"11111111111111111\r\n",
            b"5\r\r\n",
        ] {
            let mut w = ChunkWalker::default();
            assert_eq!(
                w.feed(bad).1,
                ChunkStatus::Malformed,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn response_framing() {
        let scan = |raw: &[u8], head| match scan_response(raw, head) {
            ResponseScan::Complete(h) => h,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            scan(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", false).body,
            ResponseBody::Length(4)
        );
        assert_eq!(
            scan(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", true).body,
            ResponseBody::None
        );
        assert_eq!(
            scan(
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 4\r\n\r\n",
                false
            )
            .body,
            ResponseBody::None
        );
        let eof = scan(b"HTTP/1.1 200 OK\r\n\r\n", false);
        assert_eq!(eof.body, ResponseBody::Eof);
        assert!(eof.close);
        assert!(
            scan(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                false
            )
            .close
        );
        assert!(scan(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", false).close);
        assert!(
            !scan(
                b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
                false
            )
            .close
        );
        assert_eq!(
            scan(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                false
            )
            .body,
            ResponseBody::Chunked
        );
        assert_eq!(scan_response(b"SSH-2.0\r\n", false), ResponseScan::Garbage);
    }
}
