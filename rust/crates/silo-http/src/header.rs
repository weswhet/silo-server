//! Port of `net/http.Header`, `net/textproto` key canonicalization, and `httpguts`.
//!
//! Go strings hold arbitrary bytes and clients do send non-UTF-8 header values, so values here are
//! bytes. Keys are `String` because every key that survives request parsing is an ASCII token and
//! response keys come from code.

use std::collections::BTreeMap;

use silo_gocompat::time::{GoTime, parse};

/// `http.TimeFormat`.
pub const TIME_FORMAT: &str = "Mon, 02 Jan 2006 15:04:05 GMT";

/// `http.TrailerPrefix`.
pub const TRAILER_PREFIX: &str = "Trailer:";

/// `http.Header`. Iteration is sorted by key, the order `Header.Write` emits.
///
/// A key can be present with no values, as `w.Header()["Date"] = nil` is in Go: that suppresses the
/// automatic header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header(BTreeMap<String, Vec<Vec<u8>>>);

impl Header {
    /// `make(http.Header)`.
    pub fn new() -> Self {
        Self::default()
    }

    /// `h.Add`.
    pub fn add(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.0
            .entry(canonical_header_key(key))
            .or_default()
            .push(value.as_ref().to_vec());
    }

    /// `h.Set`.
    pub fn set(&mut self, key: &str, value: impl AsRef<[u8]>) {
        self.0
            .insert(canonical_header_key(key), vec![value.as_ref().to_vec()]);
    }

    /// `h.Get`: the first value, or empty if absent.
    pub fn get(&self, key: &str) -> &[u8] {
        self.get_raw(&canonical_header_key(key))
    }

    /// `h.Get` for callers that compare with text. A value that is not UTF-8 reads as empty, which
    /// compares unequal to every non-empty text just as the Go string would. Use [`Header::get`]
    /// when the bytes themselves matter.
    pub fn get_str(&self, key: &str) -> &str {
        std::str::from_utf8(self.get(key)).unwrap_or("")
    }

    /// `h[key]`: the values under this exact spelling.
    pub fn get_raw_values(&self, key: &str) -> &[Vec<u8>] {
        self.0.get(key).map_or(&[], Vec::as_slice)
    }

    /// `h.Values`.
    pub fn values(&self, key: &str) -> &[Vec<u8>] {
        self.0
            .get(&canonical_header_key(key))
            .map_or(&[], Vec::as_slice)
    }

    /// `h.Del`.
    pub fn del(&mut self, key: &str) {
        self.0.remove(&canonical_header_key(key));
    }

    /// `h.get`: `key` must already be canonical.
    pub fn get_raw(&self, key: &str) -> &[u8] {
        self.0
            .get(key)
            .and_then(|v| v.first())
            .map_or(&[], Vec::as_slice)
    }

    /// `h.has`, and `_, ok := h[key]`: true even if the key holds no values.
    pub fn has_raw(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// `h[key]`.
    pub fn values_raw(&self, key: &str) -> Option<&[Vec<u8>]> {
        self.0.get(key).map(Vec::as_slice)
    }

    /// `h[key] = values`, with no canonicalization. Empty `values` is Go's `h[key] = nil`.
    pub fn set_raw(&mut self, key: impl Into<String>, values: Vec<Vec<u8>>) {
        self.0.insert(key.into(), values);
    }

    /// `delete(h, key)`.
    pub fn del_raw(&mut self, key: &str) {
        self.0.remove(key);
    }

    /// All keys and values, sorted by key.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[Vec<u8>])> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// `len(h)`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `len(h) == 0`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `h.WriteSubset`: sorted keys, invalid names dropped, newlines in values turned into spaces,
    /// values trimmed.
    pub(crate) fn write_subset(&self, out: &mut Vec<u8>, exclude: &[&str]) {
        for (key, values) in &self.0 {
            if exclude.contains(&key.as_str()) || !valid_header_field_name(key.as_bytes()) {
                continue;
            }
            for value in values {
                let cleaned: Vec<u8> = value
                    .iter()
                    .map(|&b| if b == b'\n' || b == b'\r' { b' ' } else { b })
                    .collect();
                out.extend_from_slice(key.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(trim_string(&cleaned));
                out.extend_from_slice(b"\r\n");
            }
        }
    }
}

/// `http.CanonicalHeaderKey`.
pub fn canonical_header_key(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut upper = true;
    for &c in bytes {
        if !valid_header_field_byte(c) {
            return s.to_owned();
        }
        if (upper && c.is_ascii_lowercase()) || (!upper && c.is_ascii_uppercase()) {
            let mut owned = bytes.to_vec();
            let (key, _) = canonical_mime_header_key(&mut owned);
            return String::from_utf8_lossy(&key).into_owned();
        }
        upper = c == b'-';
    }
    s.to_owned()
}

/// `textproto.canonicalMIMEHeaderKey`: the key and whether it is acceptable.
pub(crate) fn canonical_mime_header_key(a: &mut [u8]) -> (Vec<u8>, bool) {
    if a.is_empty() {
        return (Vec::new(), false);
    }
    let mut no_canon = false;
    for &c in a.iter() {
        if valid_header_field_byte(c) {
            continue;
        }
        if c == b' ' {
            // Go accepts a space before the colon but will not canonicalize such a key.
            no_canon = true;
            continue;
        }
        return (a.to_vec(), false);
    }
    if no_canon {
        return (a.to_vec(), true);
    }
    let mut upper = true;
    for c in a.iter_mut() {
        if upper && c.is_ascii_lowercase() {
            *c -= 32;
        } else if !upper && c.is_ascii_uppercase() {
            *c += 32;
        }
        upper = *c == b'-';
    }
    (a.to_vec(), true)
}

/// `textproto.validHeaderFieldByte`, the RFC 7230 `tchar` set.
pub(crate) fn valid_header_field_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// `textproto.validHeaderValueByte`.
pub(crate) fn valid_header_value_byte(c: u8) -> bool {
    c >= 0x80 || c == b'\t' || (0x20..0x7f).contains(&c)
}

/// `httpguts.ValidHeaderFieldName`, also `http.isToken`.
pub fn valid_header_field_name(v: &[u8]) -> bool {
    !v.is_empty() && v.iter().all(|&c| valid_header_field_byte(c))
}

/// `httpguts.ValidHeaderFieldValue`.
pub fn valid_header_field_value(v: &[u8]) -> bool {
    v.iter()
        .all(|&b| !((b < b' ' || b == 0x7f) && b != b' ' && b != b'\t'))
}

/// `httpguts.ValidHostHeader`.
pub fn valid_host_header(h: &[u8]) -> bool {
    h.iter().all(|&c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'!' | b'$'
                    | b'%'
                    | b'&'
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b'-'
                    | b'.'
                    | b':'
                    | b';'
                    | b'='
                    | b'['
                    | b'\''
                    | b']'
                    | b'_'
                    | b'~'
            )
    })
}

/// `httpguts.ValidTrailerHeader`.
pub(crate) fn valid_trailer_header(name: &str) -> bool {
    let name = canonical_header_key(name);
    !(name.starts_with("If-")
        || matches!(
            name.as_str(),
            "Authorization"
                | "Cache-Control"
                | "Connection"
                | "Content-Encoding"
                | "Content-Length"
                | "Content-Range"
                | "Content-Type"
                | "Expect"
                | "Host"
                | "Keep-Alive"
                | "Max-Forwards"
                | "Pragma"
                | "Proxy-Authenticate"
                | "Proxy-Authorization"
                | "Proxy-Connection"
                | "Range"
                | "Realm"
                | "Te"
                | "Trailer"
                | "Transfer-Encoding"
                | "Www-Authenticate"
        ))
}

/// `textproto.TrimString`.
pub fn trim_string(mut s: &[u8]) -> &[u8] {
    fn space(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\n' | b'\r')
    }
    while let [first, rest @ ..] = s {
        if !space(*first) {
            break;
        }
        s = rest;
    }
    while let [rest @ .., last] = s {
        if !space(*last) {
            break;
        }
        s = rest;
    }
    s
}

/// `net/http.hasToken`: token appears in v with space or comma boundaries, ASCII case-insensitive.
/// `token` must be lowercase.
pub(crate) fn has_token(v: &[u8], token: &[u8]) -> bool {
    if token.len() > v.len() || token.is_empty() {
        return false;
    }
    if v == token {
        return true;
    }
    let boundary = |b: u8| matches!(b, b' ' | b',' | b'\t');
    for sp in 0..=v.len() - token.len() {
        let b = v[sp];
        if b != token[0] && b | 0x20 != token[0] {
            continue;
        }
        if sp > 0 && !boundary(v[sp - 1]) {
            continue;
        }
        let end = sp + token.len();
        if end != v.len() && !boundary(v[end]) {
            continue;
        }
        if ascii_equal_fold(&v[sp..end], token) {
            return true;
        }
    }
    false
}

/// `net/http/internal/ascii.EqualFold`.
pub(crate) fn ascii_equal_fold(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// `httpguts.HeaderValuesContainsToken`.
pub(crate) fn header_values_contains_token(values: &[Vec<u8>], token: &[u8]) -> bool {
    values.iter().any(|v| {
        let trim = |mut x: &[u8]| -> Vec<u8> {
            while let [b' ' | b'\t', rest @ ..] = x {
                x = rest;
            }
            while let [rest @ .., b' ' | b'\t'] = x {
                x = rest;
            }
            x.to_vec()
        };
        // tokenEqual treats any non-ASCII byte in the candidate as no match, which a comparison with
        // an ASCII token already does.
        v.split(|&b| b == b',')
            .any(|part| ascii_equal_fold(&trim(part), token))
    })
}

/// `net/http.foreachHeaderElement`.
pub(crate) fn foreach_header_element(v: &[u8], mut f: impl FnMut(&[u8])) {
    let v = trim_string(v);
    if v.is_empty() {
        return;
    }
    if !v.contains(&b',') {
        f(v);
        return;
    }
    for part in v.split(|&b| b == b',') {
        let part = trim_string(part);
        if !part.is_empty() {
            f(part);
        }
    }
}

/// `http.ParseTime`: tries `TimeFormat`, `time.RFC850`, and `time.ANSIC` in order.
pub fn parse_time(text: &str) -> Option<GoTime> {
    const ANSIC: &str = "Mon Jan _2 15:04:05 2006";
    parse(TIME_FORMAT, text)
        .ok()
        .or_else(|| parse_rfc850(text))
        .or_else(|| parse(ANSIC, text).ok())
}

/// `time.Parse(time.RFC850, text)`. `silo_gocompat::time::parse` reads only `UTC` in a zone position,
/// and RFC 850 dates carry `GMT` or any abbreviation. Go checks the abbreviation's shape, then, unless
/// the local zone defines it, takes the wall clock as UTC whatever the abbreviation says. A local zone
/// that defines the abbreviation is the one case not reproduced: the server runs in UTC.
fn parse_rfc850(text: &str) -> Option<GoTime> {
    let (wall, zone) = text.rsplit_once(' ')?;
    if !valid_zone_abbreviation(zone) {
        return None;
    }
    parse("Monday, 02-Jan-06 15:04:05", wall).ok()
}

/// `time.parseTimeZone`, requiring it to consume the whole value.
fn valid_zone_abbreviation(value: &str) -> bool {
    fn signed_offset(v: &str) -> bool {
        let Some(digits) = v.strip_prefix(['+', '-']) else {
            return false;
        };
        !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && digits.parse::<u32>().is_ok_and(|x| x <= 23)
    }
    if value.starts_with("UTC") {
        return value == "UTC";
    }
    if value.len() < 3 {
        return false;
    }
    if value == "ChST" || value == "MeST" {
        return true;
    }
    if let Some(rest) = value.strip_prefix("GMT") {
        return rest.is_empty() || signed_offset(rest);
    }
    if value.starts_with(['+', '-']) {
        return signed_offset(value);
    }
    if !value.bytes().all(|b| b.is_ascii_uppercase()) {
        return false;
    }
    match value.len() {
        3 => true,
        4 => value.ends_with('T') || value == "WITA",
        5 => value.ends_with('T'),
        _ => false,
    }
}

/// `t.UTC().Format(http.TimeFormat)`.
pub fn format_time(t: GoTime) -> String {
    t.to_utc().format(TIME_FORMAT)
}
