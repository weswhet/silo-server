//! Port of Go's `net/url`: percent-escaping, `Parse`, the `URL` struct, `Query`, and
//! `ResolveReference`.
//!
//! `Url`'s string-shaped fields (`path`, `host`, `fragment`, ...) are Rust `String`s, while a Go
//! `url.URL`'s matching fields are plain Go strings that can hold arbitrary bytes (a `%`-escaped
//! path can decode to invalid UTF-8). This port replaces an invalid byte with `\u{FFFD}` at the
//! point a field is set, which only matters for the rare URL whose decoded path, host, or
//! userinfo is not valid UTF-8; [`query_unescape`] and [`path_unescape`] below keep Go's raw byte
//! semantics for that reason. [`parse`] and [`Url::string`] (`url.Parse` and `URL.String`),
//! [`Url::query`] (`URL.Query`), and [`Url::resolve_reference`] (`URL.ResolveReference`) are
//! ported; `Hostname`, `Port`, `RequestURI`, and `JoinPath` are not.
//!
//! IPv6 literal validation (the host-in-brackets case) uses `std::net::Ipv6Addr`'s parser rather
//! than a port of `net/netip`, so the exact wording of a bracket-host error can differ from Go's,
//! though whether a given literal is accepted should not.

use crate::strconv::{quote, quote_bytes};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    PathSegment,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, Mode::Host | Mode::Zone)
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => {
            return match mode {
                Mode::Path => c == b'?',
                Mode::PathSegment => matches!(c, b'/' | b';' | b',' | b'?'),
                Mode::UserPassword => matches!(c, b'@' | b'/' | b'?' | b':'),
                Mode::QueryComponent => true,
                Mode::Fragment => false,
                Mode::Host | Mode::Zone => true,
            };
        }
        _ => {}
    }
    if mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
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

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// The two errors `unescape` raises: an invalid or incomplete `%XX` escape (every mode), or a
/// raw byte that needed escaping in a host or zone (`url.InvalidHostError`).
enum RawUnescapeError {
    Escape(Vec<u8>),
    Host(u8),
}

impl RawUnescapeError {
    fn message(&self) -> String {
        match self {
            RawUnescapeError::Escape(b) => format!("invalid URL escape {}", quote_bytes(b)),
            RawUnescapeError::Host(c) => {
                format!(
                    "invalid character {} in host name",
                    quote(&char::from(*c).to_string())
                )
            }
        }
    }
}

/// `unescape` in `net/url`, generalized over every mode `Parse` needs.
fn unescape_bytes(s: &[u8], mode: Mode) -> Result<Vec<u8>, RawUnescapeError> {
    let mut n = 0usize;
    let mut has_plus = false;
    let mut i = 0usize;
    while i < s.len() {
        match s[i] {
            b'%' => {
                n += 1;
                if i + 2 >= s.len() || !is_hex(s[i + 1]) || !is_hex(s[i + 2]) {
                    let end = (i + 3).min(s.len());
                    return Err(RawUnescapeError::Escape(s[i..end].to_vec()));
                }
                if mode == Mode::Host && unhex(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                    return Err(RawUnescapeError::Escape(s[i..i + 3].to_vec()));
                }
                if mode == Mode::Zone {
                    let v = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    if &s[i..i + 3] != b"%25" && v != b' ' && should_escape(v, Mode::Host) {
                        return Err(RawUnescapeError::Escape(s[i..i + 3].to_vec()));
                    }
                }
                i += 3;
            }
            b'+' => {
                has_plus = mode == Mode::QueryComponent;
                i += 1;
            }
            c => {
                if matches!(mode, Mode::Host | Mode::Zone) && c < 0x80 && should_escape(c, mode) {
                    return Err(RawUnescapeError::Host(c));
                }
                i += 1;
            }
        }
    }
    if n == 0 && !has_plus {
        return Ok(s.to_vec());
    }
    let unescaped_plus: u8 = if mode == Mode::QueryComponent {
        b' '
    } else {
        b'+'
    };
    let mut out = Vec::with_capacity(s.len().saturating_sub(2 * n));
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                out.push(unhex(s[i + 1]) << 4 | unhex(s[i + 2]));
                i += 3;
            }
            b'+' => {
                out.push(unescaped_plus);
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

fn unescape(s: &[u8], mode: Mode) -> Result<Vec<u8>, EscapeError> {
    unescape_bytes(s, mode).map_err(|e| match e {
        RawUnescapeError::Escape(b) => EscapeError(b),
        // Host/Zone errors never reach the query- and path-component callers below.
        RawUnescapeError::Host(_) => unreachable!("host-only error in a non-host mode"),
    })
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

// ---------------------------------------------------------------------------------------------
// Parse, the URL struct, String, Query, and ResolveReference.
// ---------------------------------------------------------------------------------------------

/// `strings.Cut`.
fn cut<'a>(s: &'a str, sep: &str) -> (&'a str, &'a str, bool) {
    match s.find(sep) {
        Some(i) => (&s[..i], &s[i + sep.len()..], true),
        None => (s, "", false),
    }
}

fn unescape_str(s: &str, mode: Mode) -> Result<String, String> {
    unescape_bytes(s.as_bytes(), mode)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|e| e.message())
}

/// `url.Userinfo`: an immutable username, and an optional password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Userinfo {
    username: String,
    password: String,
    password_set: bool,
}

impl Userinfo {
    /// `url.User`.
    pub fn user(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: String::new(),
            password_set: false,
        }
    }

    /// `url.UserPassword`.
    pub fn user_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            password_set: true,
        }
    }

    /// `Userinfo.Username`.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// `Userinfo.Password`.
    pub fn password(&self) -> Option<&str> {
        self.password_set.then_some(self.password.as_str())
    }

    /// `Userinfo.String`.
    pub fn string(&self) -> String {
        let mut s = escape(self.username.as_bytes(), Mode::UserPassword);
        if self.password_set {
            s.push(':');
            s.push_str(&escape(self.password.as_bytes(), Mode::UserPassword));
        }
        s
    }
}

/// `url.Values`: Go's map is unordered, so this holds query parameters in a `BTreeMap` instead.
pub type Values = std::collections::BTreeMap<String, Vec<String>>;

/// `url.URL`. See the module docs for how its fields diverge from Go's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub opaque: String,
    pub user: Option<Userinfo>,
    pub host: String,
    pub path: String,
    pub raw_path: String,
    pub omit_host: bool,
    pub force_query: bool,
    pub raw_query: String,
    pub fragment: String,
    pub raw_fragment: String,
}

/// `url.Error`: `Parse`'s error, wrapping the operation and the URL text it failed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    op: &'static str,
    url: String,
    err: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.op, quote(&self.url), self.err)
    }
}

impl std::error::Error for Error {}

fn get_scheme(raw_url: &str) -> Result<(String, &str), String> {
    let bytes = raw_url.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok((String::new(), raw_url));
                }
            }
            b':' => {
                if i == 0 {
                    return Err("missing protocol scheme".to_string());
                }
                return Ok((raw_url[..i].to_string(), &raw_url[i + 1..]));
            }
            _ => return Ok((String::new(), raw_url)),
        }
    }
    Ok((String::new(), raw_url))
}

fn valid_optional_port(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    let b = port.as_bytes();
    if b[0] != b':' {
        return false;
    }
    b[1..].iter().all(u8::is_ascii_digit)
}

fn valid_userinfo(s: &str) -> bool {
    s.chars().all(|r| {
        r.is_ascii_alphanumeric()
            || matches!(
                r,
                '-' | '.'
                    | '_'
                    | ':'
                    | '~'
                    | '!'
                    | '$'
                    | '&'
                    | '\''
                    | '('
                    | ')'
                    | '*'
                    | '+'
                    | ','
                    | ';'
                    | '='
                    | '%'
                    | '@'
            )
    })
}

/// A conservative stand-in for `net/netip`'s address grammar: accepts what `std::net::Ipv6Addr`
/// accepts, which matches Go on every literal the generator covers. `std::net::Ipv6Addr` has no
/// notion of RFC 6874 zones, so a zone suffix (`%eth0`) is split off and left unvalidated, as
/// Go's `netip` mostly leaves it too.
fn is_valid_ipv6_literal(s: &str) -> bool {
    let addr = s.split('%').next().unwrap_or(s);
    addr.parse::<std::net::Ipv6Addr>().is_ok()
}

fn parse_host(scheme: &str, host: &str) -> Result<String, String> {
    if let Some(open) = host.rfind('[') {
        if open > 0 {
            return Err("invalid IP-literal".to_string());
        }
        let close = host
            .rfind(']')
            .ok_or_else(|| "missing ']' in host".to_string())?;
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {} after host", quote(colon_port)));
        }
        let unescaped_colon_port = unescape_str(colon_port, Mode::Host)?;
        let hostname = &host[1..close];
        let unescaped_hostname = if let Some(zone_idx) = hostname.find("%25") {
            let host_part = unescape_str(&hostname[..zone_idx], Mode::Host)?;
            let zone_part = unescape_str(&hostname[zone_idx..], Mode::Zone)?;
            host_part + &zone_part
        } else {
            unescape_str(hostname, Mode::Host)?
        };
        if unescaped_hostname.parse::<std::net::Ipv4Addr>().is_ok() {
            return Err("invalid IP-literal".to_string());
        }
        if unescaped_hostname.ends_with('%') || !is_valid_ipv6_literal(&unescaped_hostname) {
            return Err(format!("invalid host: {unescaped_hostname}"));
        }
        return Ok(format!("[{unescaped_hostname}]{unescaped_colon_port}"));
    }
    if let Some(mut i) = host.find(':') {
        let last_colon = host.rfind(':').expect("find succeeded above");
        if last_colon != i && scheme != "http" && scheme != "https" {
            i = last_colon;
        }
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {} after host", quote(colon_port)));
        }
    }
    unescape_str(host, Mode::Host)
}

fn parse_authority(scheme: &str, authority: &str) -> Result<(Option<Userinfo>, String), String> {
    let at = authority.rfind('@');
    let host = match at {
        Some(i) => parse_host(scheme, &authority[i + 1..])?,
        None => parse_host(scheme, authority)?,
    };
    let Some(at) = at else {
        return Ok((None, host));
    };
    let userinfo = &authority[..at];
    if !valid_userinfo(userinfo) {
        return Err("net/url: invalid userinfo".to_string());
    }
    let user = if !userinfo.contains(':') {
        Userinfo::user(unescape_str(userinfo, Mode::UserPassword)?)
    } else {
        let (username, password, _) = cut(userinfo, ":");
        Userinfo::user_password(
            unescape_str(username, Mode::UserPassword)?,
            unescape_str(password, Mode::UserPassword)?,
        )
    };
    Ok((Some(user), host))
}

fn valid_encoded(s: &str, mode: Mode) -> bool {
    for &b in s.as_bytes() {
        match b {
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
            | b'@' | b'[' | b']' | b'%' => {}
            _ => {
                if should_escape(b, mode) {
                    return false;
                }
            }
        }
    }
    true
}

impl Url {
    fn set_path(&mut self, p: &str) -> Result<(), String> {
        let path = unescape_str(p, Mode::Path)?;
        let esc = escape(path.as_bytes(), Mode::Path);
        self.path = path;
        self.raw_path = if p == esc {
            String::new()
        } else {
            p.to_string()
        };
        Ok(())
    }

    fn set_fragment(&mut self, f: &str) -> Result<(), String> {
        let frag = unescape_str(f, Mode::Fragment)?;
        let esc = escape(frag.as_bytes(), Mode::Fragment);
        self.fragment = frag;
        self.raw_fragment = if f == esc {
            String::new()
        } else {
            f.to_string()
        };
        Ok(())
    }

    /// `URL.EscapedPath`.
    pub fn escaped_path(&self) -> String {
        if !self.raw_path.is_empty()
            && valid_encoded(&self.raw_path, Mode::Path)
            && let Ok(p) = unescape_str(&self.raw_path, Mode::Path)
            && p == self.path
        {
            return self.raw_path.clone();
        }
        if self.path == "*" {
            return "*".to_string();
        }
        escape(self.path.as_bytes(), Mode::Path)
    }

    /// `URL.EscapedFragment`.
    pub fn escaped_fragment(&self) -> String {
        if !self.raw_fragment.is_empty()
            && valid_encoded(&self.raw_fragment, Mode::Fragment)
            && let Ok(f) = unescape_str(&self.raw_fragment, Mode::Fragment)
            && f == self.fragment
        {
            return self.raw_fragment.clone();
        }
        escape(self.fragment.as_bytes(), Mode::Fragment)
    }

    /// `URL.IsAbs`.
    pub fn is_abs(&self) -> bool {
        !self.scheme.is_empty()
    }

    /// `URL.String`.
    pub fn string(&self) -> String {
        let mut buf = String::new();
        if !self.scheme.is_empty() {
            buf.push_str(&self.scheme);
            buf.push(':');
        }
        if !self.opaque.is_empty() {
            buf.push_str(&self.opaque);
        } else {
            if (!self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some())
                && !(self.omit_host && self.host.is_empty() && self.user.is_none())
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    buf.push_str("//");
                }
                if let Some(ui) = &self.user {
                    buf.push_str(&ui.string());
                    buf.push('@');
                }
                if !self.host.is_empty() {
                    buf.push_str(&escape(self.host.as_bytes(), Mode::Host));
                }
            }
            let path = self.escaped_path();
            if !path.is_empty() && !path.starts_with('/') && !self.host.is_empty() {
                buf.push('/');
            }
            if buf.is_empty() {
                let (segment, _, _) = cut(&path, "/");
                if segment.contains(':') {
                    buf.push_str("./");
                }
            }
            buf.push_str(&path);
        }
        if self.force_query || !self.raw_query.is_empty() {
            buf.push('?');
            buf.push_str(&self.raw_query);
        }
        if !self.fragment.is_empty() {
            buf.push('#');
            buf.push_str(&self.escaped_fragment());
        }
        buf
    }

    /// `URL.Query`: parse errors in `RawQuery` are silently discarded, as in Go.
    pub fn query(&self) -> Values {
        let mut m = Values::new();
        let _ = parse_query_into(&mut m, &self.raw_query);
        m
    }

    /// `URL.ResolveReference`.
    pub fn resolve_reference(&self, reference: &Url) -> Url {
        let mut url = reference.clone();
        if reference.scheme.is_empty() {
            url.scheme = self.scheme.clone();
        }
        if !reference.scheme.is_empty() || !reference.host.is_empty() || reference.user.is_some() {
            let _ = url.set_path(&resolve_path(&reference.escaped_path(), ""));
            return url;
        }
        if !reference.opaque.is_empty() {
            url.user = None;
            url.host.clear();
            url.path.clear();
            return url;
        }
        if reference.path.is_empty() && !reference.force_query && reference.raw_query.is_empty() {
            url.raw_query = self.raw_query.clone();
            if reference.fragment.is_empty() {
                url.fragment = self.fragment.clone();
                url.raw_fragment = self.raw_fragment.clone();
            }
        }
        if reference.path.is_empty() && !self.opaque.is_empty() {
            url.opaque = self.opaque.clone();
            url.user = None;
            url.host.clear();
            url.path.clear();
            return url;
        }
        url.host = self.host.clone();
        url.user = self.user.clone();
        let _ = url.set_path(&resolve_path(
            &self.escaped_path(),
            &reference.escaped_path(),
        ));
        url
    }

    /// `URL.Parse`: parses `reference` and resolves it against `self`.
    pub fn parse_ref(&self, reference: &str) -> Result<Url, Error> {
        let reference = parse(reference)?;
        Ok(self.resolve_reference(&reference))
    }
}

/// `resolvePath`.
fn resolve_path(base: &str, reference: &str) -> String {
    let full = if reference.is_empty() {
        base.to_string()
    } else if !reference.starts_with('/') {
        match base.rfind('/') {
            Some(i) => format!("{}{}", &base[..i + 1], reference),
            None => reference.to_string(),
        }
    } else {
        reference.to_string()
    };
    if full.is_empty() {
        return String::new();
    }

    let mut dst: Vec<u8> = Vec::with_capacity(full.len() + 1);
    dst.push(b'/');
    let mut elem: &str = "";
    let mut remaining: &str = &full;
    let mut found = true;
    let mut first = true;
    while found {
        let (e, r, f) = cut(remaining, "/");
        elem = e;
        remaining = r;
        found = f;
        match elem {
            "." => {
                first = false;
            }
            ".." => {
                if let Some(i) = dst[1..].iter().rposition(|&b| b == b'/') {
                    dst.truncate(i + 1);
                } else {
                    dst.truncate(1);
                }
                first = dst.len() == 1;
            }
            _ => {
                if !first {
                    dst.push(b'/');
                }
                dst.extend_from_slice(elem.as_bytes());
                first = false;
            }
        }
    }
    if elem == "." || elem == ".." {
        dst.push(b'/');
    }
    let text = String::from_utf8(dst).expect("path bytes stay valid UTF-8");
    if text.len() > 1 && text.as_bytes()[1] == b'/' {
        text[1..].to_string()
    } else {
        text
    }
}

fn parse_query_into(m: &mut Values, query: &str) -> Result<(), String> {
    let mut first_err: Option<String> = None;
    for key_part in query.split('&') {
        if key_part.contains(';') {
            if first_err.is_none() {
                first_err = Some("invalid semicolon separator in query".to_string());
            }
            continue;
        }
        if key_part.is_empty() {
            continue;
        }
        let (k, v, _) = cut(key_part, "=");
        let key = match query_unescape(k.as_bytes()) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e.to_string());
                }
                continue;
            }
        };
        let value = match query_unescape(v.as_bytes()) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e.to_string());
                }
                continue;
            }
        };
        m.entry(key).or_default().push(value);
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `ParseQuery`.
pub fn parse_query(query: &str) -> (Values, Option<String>) {
    let mut m = Values::new();
    let err = parse_query_into(&mut m, query).err();
    (m, err)
}

fn parse_inner(raw_url: &str, via_request: bool) -> Result<Url, String> {
    if raw_url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("net/url: invalid control character in URL".to_string());
    }
    if raw_url.is_empty() && via_request {
        return Err("empty url".to_string());
    }
    let mut url = Url::default();
    if raw_url == "*" {
        url.path = "*".to_string();
        return Ok(url);
    }

    let (scheme, rest0) = get_scheme(raw_url)?;
    url.scheme = scheme.to_ascii_lowercase();

    let mut rest: &str = rest0;
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        url.force_query = true;
        rest = &rest[..rest.len() - 1];
    } else {
        let (a, b, _) = cut(rest, "?");
        rest = a;
        url.raw_query = b.to_string();
    }

    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_string();
            return Ok(url);
        }
        if via_request {
            return Err("invalid URI for request".to_string());
        }
        let (segment, _, _) = cut(rest, "/");
        if segment.contains(':') {
            return Err("first path segment in URL cannot contain colon".to_string());
        }
    }

    if (!url.scheme.is_empty() || (!via_request && !rest.starts_with("///")))
        && rest.starts_with("//")
    {
        let mut authority: &str = &rest[2..];
        rest = "";
        if let Some(i) = authority.find('/') {
            let (a, b) = authority.split_at(i);
            authority = a;
            rest = b;
        }
        let (user, host) = parse_authority(&url.scheme, authority)?;
        url.user = user;
        url.host = host;
    } else if !url.scheme.is_empty() && rest.starts_with('/') {
        url.omit_host = true;
    }

    url.set_path(rest)?;
    Ok(url)
}

/// `url.Parse`.
pub fn parse(raw_url: &str) -> Result<Url, Error> {
    let (u, frag) = match raw_url.find('#') {
        Some(i) => (&raw_url[..i], &raw_url[i + 1..]),
        None => (raw_url, ""),
    };
    let mut url = parse_inner(u, false).map_err(|err| Error {
        op: "parse",
        url: u.to_string(),
        err,
    })?;
    if frag.is_empty() {
        return Ok(url);
    }
    url.set_fragment(frag).map_err(|err| Error {
        op: "parse",
        url: raw_url.to_string(),
        err,
    })?;
    Ok(url)
}

/// `url.ParseRequestURI`.
pub fn parse_request_uri(raw_url: &str) -> Result<Url, Error> {
    parse_inner(raw_url, true).map_err(|err| Error {
        op: "parse",
        url: raw_url.to_string(),
        err,
    })
}
