//! Port of the parts of `net/url` that `net/http` servers rely on: `ParseRequestURI`, `Parse`,
//! `URL.EscapedPath`, and `URL.String`, on bytes because a decoded Go path can hold any byte.

use std::net::{Ipv4Addr, Ipv6Addr};

use silo_gocompat::strconv::quote_bytes;
use silo_gocompat::strings::to_lower;

use crate::url_table::{
    ENCODE_FRAGMENT, ENCODE_HOST, ENCODE_PATH, ENCODE_USER_PASSWORD, ENCODE_ZONE, TABLE,
};

/// `url.URL`. `Fragment` is parsed only to reject bad escapes, as `http.Redirect` needs nothing more.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub opaque: Vec<u8>,
    pub user: Option<(Vec<u8>, Option<Vec<u8>>)>,
    pub host: Vec<u8>,
    pub path: Vec<u8>,
    pub raw_path: Vec<u8>,
    pub omit_host: bool,
    pub force_query: bool,
    pub raw_query: Vec<u8>,
}

/// Why a URL did not parse. Handlers never see these texts on the wire, because the server answers
/// a bad request target with a fixed body, so a message is enough.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlError(pub String);

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UrlError {}

fn err<T>(msg: impl Into<String>) -> Result<T, UrlError> {
    Err(UrlError(msg.into()))
}

fn should_escape(c: u8, mode: u8) -> bool {
    TABLE[usize::from(c)] & mode == 0
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// `url.unescape` for the modes other than query, so `+` always stays `+`.
pub(crate) fn unescape(s: &[u8], mode: u8) -> Result<Vec<u8>, UrlError> {
    let mut n = 0;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                n += 1;
                if i + 2 >= s.len() || !is_hex(s[i + 1]) || !is_hex(s[i + 2]) {
                    let end = (i + 3).min(s.len());
                    return err(format!("invalid URL escape {}", quote_bytes(&s[i..end])));
                }
                if mode == ENCODE_HOST && unhex(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                    return err(format!("invalid URL escape {}", quote_bytes(&s[i..i + 3])));
                }
                if mode == ENCODE_ZONE {
                    let v = (unhex(s[i + 1]) << 4) | unhex(s[i + 2]);
                    if &s[i..i + 3] != b"%25" && v != b' ' && should_escape(v, ENCODE_HOST) {
                        return err(format!("invalid URL escape {}", quote_bytes(&s[i..i + 3])));
                    }
                }
                i += 3;
            }
            c => {
                if (mode == ENCODE_HOST || mode == ENCODE_ZONE)
                    && c < 0x80
                    && should_escape(c, mode)
                {
                    return err(format!(
                        "invalid character {} in host name",
                        quote_bytes(&s[i..=i])
                    ));
                }
                i += 1;
            }
        }
    }
    if n == 0 {
        return Ok(s.to_vec());
    }
    let mut out = Vec::with_capacity(s.len() - 2 * n);
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            out.push((unhex(s[i + 1]) << 4) | unhex(s[i + 2]));
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// `url.escape` for the modes other than query.
pub(crate) fn escape(s: &[u8], mode: u8) -> Vec<u8> {
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if should_escape(c, mode) {
            out.extend_from_slice(&[
                b'%',
                UPPER_HEX[usize::from(c >> 4)],
                UPPER_HEX[usize::from(c & 15)],
            ]);
        } else {
            out.push(c);
        }
    }
    out
}

/// `url.PathUnescape`.
pub(crate) fn path_unescape(s: &[u8]) -> Result<Vec<u8>, UrlError> {
    unescape(s, crate::url_table::ENCODE_PATH_SEGMENT)
}

fn get_scheme(raw: &[u8]) -> Result<(String, &[u8]), UrlError> {
    for (i, &c) in raw.iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok((String::new(), raw));
                }
            }
            b':' => {
                if i == 0 {
                    return err("missing protocol scheme");
                }
                return Ok((
                    String::from_utf8_lossy(&raw[..i]).into_owned(),
                    &raw[i + 1..],
                ));
            }
            _ => return Ok((String::new(), raw)),
        }
    }
    Ok((String::new(), raw))
}

fn valid_optional_port(port: &[u8]) -> bool {
    match port {
        [] => true,
        [b':', digits @ ..] => digits.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

/// `netip.ParseAddr`, reduced to what `parseHost` asks: `Some(true)` for IPv4, `Some(false)` for IPv6
/// with or without a zone.
fn parse_addr_is4(s: &[u8]) -> Option<bool> {
    let s = std::str::from_utf8(s).ok()?;
    if s.contains(':') {
        let (addr, zone) = s.split_once('%').map_or((s, None), |(a, z)| (a, Some(z)));
        if zone == Some("") {
            return None;
        }
        addr.parse::<Ipv6Addr>().ok()?;
        return Some(false);
    }
    s.parse::<Ipv4Addr>().ok()?;
    Some(true)
}

fn parse_host(scheme: &str, host: &[u8]) -> Result<Vec<u8>, UrlError> {
    let open = host.iter().rposition(|&b| b == b'[');
    if let Some(open) = open {
        if open > 0 {
            return err("invalid IP-literal");
        }
        let Some(close) = host.iter().rposition(|&b| b == b']') else {
            return err("missing ']' in host");
        };
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return err(format!(
                "invalid port {} after host",
                quote_bytes(colon_port)
            ));
        }
        let unescaped_port = unescape(colon_port, ENCODE_HOST)?;
        if close < 1 {
            return err("invalid host");
        }
        let hostname = &host[1..close];
        let zone = hostname.windows(3).position(|w| w == b"%25");
        let unescaped = if let Some(z) = zone {
            let mut h = unescape(&hostname[..z], ENCODE_HOST)?;
            h.extend(unescape(&hostname[z..], ENCODE_ZONE)?);
            h
        } else {
            unescape(hostname, ENCODE_HOST)?
        };
        match parse_addr_is4(&unescaped) {
            None => return err("invalid host"),
            Some(true) => return err("invalid IP-literal"),
            Some(false) => {}
        }
        let mut out = vec![b'['];
        out.extend_from_slice(&unescaped);
        out.push(b']');
        out.extend_from_slice(&unescaped_port);
        return Ok(out);
    }
    if let Some(first) = host.iter().position(|&b| b == b':') {
        // RFC 3986 allows no colons in a host. Go tolerates them outside http and https, where
        // databases put host lists, and judges only the part after the last colon as a port.
        let last = host.iter().rposition(|&b| b == b':').unwrap_or(first);
        let i = if scheme == "http" || scheme == "https" {
            first
        } else {
            last
        };
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return err(format!(
                "invalid port {} after host",
                quote_bytes(colon_port)
            ));
        }
    }
    unescape(host, ENCODE_HOST)
}

fn valid_userinfo(s: &[u8]) -> bool {
    s.iter().all(|&r| {
        r.is_ascii_alphanumeric()
            || matches!(
                r,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

type Authority = (Option<(Vec<u8>, Option<Vec<u8>>)>, Vec<u8>);

fn parse_authority(scheme: &str, authority: &[u8]) -> Result<Authority, UrlError> {
    let at = authority.iter().rposition(|&b| b == b'@');
    let host = parse_host(scheme, at.map_or(authority, |i| &authority[i + 1..]))?;
    let Some(at) = at else {
        return Ok((None, host));
    };
    let userinfo = &authority[..at];
    if !valid_userinfo(userinfo) {
        return err("net/url: invalid userinfo");
    }
    let user = match userinfo.iter().position(|&b| b == b':') {
        None => (unescape(userinfo, ENCODE_USER_PASSWORD)?, None),
        Some(c) => (
            unescape(&userinfo[..c], ENCODE_USER_PASSWORD)?,
            Some(unescape(&userinfo[c + 1..], ENCODE_USER_PASSWORD)?),
        ),
    };
    Ok((Some(user), host))
}

fn parse(raw: &[u8], via_request: bool) -> Result<Url, UrlError> {
    if raw.iter().any(|&b| b < b' ' || b == 0x7f) {
        return err("net/url: invalid control character in URL");
    }
    if raw.is_empty() && via_request {
        return err("empty url");
    }
    let mut url = Url::default();
    if raw == b"*" {
        url.path = b"*".to_vec();
        return Ok(url);
    }
    let (scheme, mut rest) = get_scheme(raw)?;
    url.scheme = to_lower(&scheme);

    let question_marks = rest.iter().filter(|&&b| b == b'?').count();
    if rest.ends_with(b"?") && question_marks == 1 {
        url.force_query = true;
        rest = &rest[..rest.len() - 1];
    } else if let Some(q) = rest.iter().position(|&b| b == b'?') {
        url.raw_query = rest[q + 1..].to_vec();
        rest = &rest[..q];
    }

    if !rest.starts_with(b"/") {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_vec();
            return Ok(url);
        }
        if via_request {
            return err("invalid URI for request");
        }
        let segment = rest.split(|&b| b == b'/').next().unwrap_or(&[]);
        if segment.contains(&b':') {
            return err("first path segment in URL cannot contain colon");
        }
    }

    if (!url.scheme.is_empty() || (!via_request && !rest.starts_with(b"///")))
        && rest.starts_with(b"//")
    {
        let after = &rest[2..];
        let (authority, tail) = match after.iter().position(|&b| b == b'/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, &after[after.len()..]),
        };
        let (user, host) = parse_authority(&url.scheme, authority)?;
        url.user = user;
        url.host = host;
        rest = tail;
    } else if !url.scheme.is_empty() && rest.starts_with(b"/") {
        url.omit_host = true;
    }

    url.set_path(rest)?;
    Ok(url)
}

/// `url.ParseRequestURI`.
pub fn parse_request_uri(raw: &[u8]) -> Result<Url, UrlError> {
    parse(raw, true)
}

/// `url.Parse`.
pub fn parse_url(raw: &[u8]) -> Result<Url, UrlError> {
    let (u, frag) = match raw.iter().position(|&b| b == b'#') {
        Some(i) => (&raw[..i], &raw[i + 1..]),
        None => (raw, &raw[raw.len()..]),
    };
    let url = parse(u, false)?;
    if !frag.is_empty() {
        unescape(frag, ENCODE_FRAGMENT)?;
    }
    Ok(url)
}

impl Url {
    /// `u.setPath`.
    pub(crate) fn set_path(&mut self, p: &[u8]) -> Result<(), UrlError> {
        let path = unescape(p, ENCODE_PATH)?;
        self.raw_path = if escape(&path, ENCODE_PATH) == p {
            Vec::new()
        } else {
            p.to_vec()
        };
        self.path = path;
        Ok(())
    }

    /// `u.EscapedPath`. Always ASCII.
    pub fn escaped_path(&self) -> Vec<u8> {
        if !self.raw_path.is_empty()
            && valid_encoded(&self.raw_path)
            && unescape(&self.raw_path, ENCODE_PATH).is_ok_and(|p| p == self.path)
        {
            return self.raw_path.clone();
        }
        if self.path == b"*" {
            return b"*".to_vec();
        }
        escape(&self.path, ENCODE_PATH)
    }

    /// `u.String` for a URL with no fragment, matching Go 1.26.
    pub fn string(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if !self.scheme.is_empty() {
            buf.extend_from_slice(self.scheme.as_bytes());
            buf.push(b':');
        }
        if !self.opaque.is_empty() {
            buf.extend_from_slice(&self.opaque);
        } else {
            if (!self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some())
                && !(self.omit_host && self.host.is_empty() && self.user.is_none())
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    buf.extend_from_slice(b"//");
                }
                if let Some((user, password)) = &self.user {
                    buf.extend(escape(user, ENCODE_USER_PASSWORD));
                    if let Some(password) = password {
                        buf.push(b':');
                        buf.extend(escape(password, ENCODE_USER_PASSWORD));
                    }
                    buf.push(b'@');
                }
                if !self.host.is_empty() {
                    buf.extend(escape(&self.host, ENCODE_HOST));
                }
            }
            let path = self.escaped_path();
            if !path.is_empty() && path[0] != b'/' && !self.host.is_empty() {
                buf.push(b'/');
            }
            if buf.is_empty() {
                let segment = path.split(|&b| b == b'/').next().unwrap_or(&[]);
                if segment.contains(&b':') {
                    buf.extend_from_slice(b"./");
                }
            }
            buf.extend_from_slice(&path);
        }
        if self.force_query || !self.raw_query.is_empty() {
            buf.push(b'?');
            buf.extend_from_slice(&self.raw_query);
        }
        buf
    }
}

fn valid_encoded(s: &[u8]) -> bool {
    s.iter().all(|&c| {
        matches!(
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
                | b'@'
                | b'['
                | b']'
                | b'%'
        ) || !should_escape(c, ENCODE_PATH)
    })
}
