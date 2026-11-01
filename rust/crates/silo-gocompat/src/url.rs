//! Port of the escaping functions in Go's `net/url`.

use crate::strconv::quote_bytes;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    QueryComponent,
    PathSegment,
}

fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            // The RFC allows : @ & = + $ but saves / ; , for assigning meaning to individual path
            // segments.
            Mode::PathSegment => matches!(c, b'/' | b';' | b',' | b'?'),
            // The RFC reserves everything here, so the query component escapes it all.
            Mode::QueryComponent => true,
        },
        _ => true,
    }
}

fn escape(bytes: &[u8], mode: Mode) -> String {
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &c in bytes {
        if c == b' ' && mode == Mode::QueryComponent {
            out.push('+');
        } else if should_escape(c, mode) {
            out.push('%');
            out.push(UPPER_HEX[usize::from(c >> 4)] as char);
            out.push(UPPER_HEX[usize::from(c & 15)] as char);
        } else {
            out.push(c as char);
        }
    }
    out
}

/// `url.QueryEscape`. Accepts bytes because Go strings need not be valid UTF-8.
pub fn query_escape(s: impl AsRef<[u8]>) -> String {
    escape(s.as_ref(), Mode::QueryComponent)
}

/// `url.PathEscape`. Accepts bytes because Go strings need not be valid UTF-8.
pub fn path_escape(s: impl AsRef<[u8]>) -> String {
    escape(s.as_ref(), Mode::PathSegment)
}

/// `url.EscapeError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscapeError(Vec<u8>);

impl std::fmt::Display for EscapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid URL escape {}", quote_bytes(&self.0))
    }
}

impl std::error::Error for EscapeError {}

fn unhex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn unescape(s: &[u8], mode: Mode) -> Result<Vec<u8>, EscapeError> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let valid = i + 2 < s.len() && unhex(s[i + 1]).is_some() && unhex(s[i + 2]).is_some();
            if !valid {
                let end = (i + 3).min(s.len());
                return Err(EscapeError(s[i..end].to_vec()));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                let hi = unhex(s[i + 1]).unwrap_or(0);
                let lo = unhex(s[i + 2]).unwrap_or(0);
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' if mode == Mode::QueryComponent => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// `url.QueryUnescape`. Returns bytes because `%ff` decodes to a byte that is not valid UTF-8,
/// which a Go string holds as is.
pub fn query_unescape(s: impl AsRef<[u8]>) -> Result<Vec<u8>, EscapeError> {
    unescape(s.as_ref(), Mode::QueryComponent)
}

/// `url.PathUnescape`. Returns bytes for the same reason as [`query_unescape`].
pub fn path_unescape(s: impl AsRef<[u8]>) -> Result<Vec<u8>, EscapeError> {
    unescape(s.as_ref(), Mode::PathSegment)
}

/// `url.Values.Encode` over `(key, value)` pairs. Keys sort bytewise and a key's values keep their
/// relative order, as if the pairs were collected into a `url.Values` in slice order.
pub fn values_encode<K: AsRef<[u8]>, V: AsRef<[u8]>>(pairs: &[(K, V)]) -> String {
    let mut sorted: Vec<&(K, V)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
    let mut out = String::new();
    for (key, value) in sorted {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&query_escape(key));
        out.push('=');
        out.push_str(&query_escape(value));
    }
    out
}
