//! The parts of `net/url` that signed formats depend on: escaping a path as a whole, and reading the
//! escaped path back out of a URL.

use silo_gocompat::url::path_unescape;

/// `shouldEscape(c, encodePath)`.
fn should_escape_path(c: u8) -> bool {
    !(c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'-' | b'_'
                | b'.'
                | b'~'
                | b'$'
                | b'&'
                | b'+'
                | b','
                | b'/'
                | b':'
                | b';'
                | b'='
                | b'@'
        ))
}

/// `escape(s, encodePath)`.
pub fn escape_path(s: impl AsRef<[u8]>) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &b in s.as_ref() {
        if should_escape_path(b) {
            out.push('%');
            out.push(char::from(UPPER[usize::from(b >> 4)]));
            out.push(char::from(UPPER[usize::from(b & 15)]));
        } else {
            out.push(char::from(b));
        }
    }
    out
}

/// `url.URL{Path: path}.EscapedPath()`.
pub fn escaped_path_of(path: impl AsRef<[u8]>) -> String {
    if path.as_ref() == b"*" {
        return "*".to_owned();
    }
    escape_path(path)
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
        ) || !should_escape_path(c)
    })
}

/// The URL could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

fn get_scheme(raw: &str) -> Result<(&str, &str), ParseError> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok(("", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err(ParseError);
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

fn ishex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// `unescape(host, encodeHost)` as a validity check.
fn valid_host_escapes(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                if i + 2 >= s.len() || !ishex(s[i + 1]) || !ishex(s[i + 2]) {
                    return false;
                }
                let high = (s[i + 1] as char).to_digit(16).unwrap_or(0);
                if high < 8 && &s[i..i + 3] != b"%25" {
                    return false;
                }
                i += 3;
            }
            c => {
                if c < 0x80 && !host_byte_ok(c) {
                    return false;
                }
                i += 1;
            }
        }
    }
    true
}

fn host_byte_ok(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'-' | b'_'
                | b'.'
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
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
}

fn valid_optional_port(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    let Some(digits) = port.strip_prefix(':') else {
        return false;
    };
    digits.bytes().all(|b| b.is_ascii_digit())
}

fn valid_authority(scheme: &str, authority: &str) -> bool {
    let (userinfo, host) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };
    let host_ok = if let Some(open) = host.rfind('[') {
        if open > 0 {
            false
        } else {
            match host.rfind(']') {
                None => false,
                Some(close) => {
                    let inner = &host[1..close];
                    let inner_no_zone = inner.split("%25").next().unwrap_or("");
                    valid_optional_port(&host[close + 1..])
                        && inner_no_zone.parse::<std::net::Ipv6Addr>().is_ok()
                }
            }
        }
    } else {
        let colon = match (host.find(':'), host.rfind(':')) {
            (Some(first), Some(last)) if first != last => {
                if scheme == "http" || scheme == "https" {
                    Some(first)
                } else {
                    Some(last)
                }
            }
            (Some(first), _) => Some(first),
            _ => None,
        };
        colon.is_none_or(|i| valid_optional_port(&host[i..])) && valid_host_escapes(host.as_bytes())
    };
    if !host_ok {
        return false;
    }
    let Some(userinfo) = userinfo else {
        return true;
    };
    let valid_user = userinfo.bytes().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
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
    });
    valid_user && path_unescape(userinfo.split(':').next().unwrap_or("")).is_ok()
}

/// `url.Parse(raw)` followed by `EscapedPath()`. A URL with a scheme and no leading slash is opaque
/// and has no path.
pub fn parse_escaped_path(raw: &str) -> Result<String, ParseError> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ParseError);
    }
    let (without_fragment, fragment) = match raw.split_once('#') {
        Some((u, f)) => (u, Some(f)),
        None => (raw, None),
    };
    if let Some(f) = fragment
        && path_unescape(f).is_err()
    {
        return Err(ParseError);
    }
    if without_fragment == "*" {
        return Ok("*".to_owned());
    }
    let (scheme, rest) = get_scheme(without_fragment)?;
    let scheme_lower = silo_gocompat::strings::to_lower(scheme);
    let rest = if rest.ends_with('?') && rest.matches('?').count() == 1 {
        &rest[..rest.len() - 1]
    } else {
        rest.split_once('?').map_or(rest, |(path, _)| path)
    };
    if !rest.starts_with('/') {
        if !scheme.is_empty() {
            return Ok(String::new());
        }
        if rest.split('/').next().unwrap_or("").contains(':') {
            return Err(ParseError);
        }
    }
    let mut path = rest;
    if (!scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let after = &rest[2..];
        let (authority, tail) = match after.find('/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, ""),
        };
        if !valid_authority(&scheme_lower, authority) {
            return Err(ParseError);
        }
        path = tail;
    }
    let decoded = path_unescape(path).map_err(|_| ParseError)?;
    let escaped = escape_path(&decoded);
    if path == escaped || path.is_empty() {
        return Ok(escaped_path_of(&decoded));
    }
    if valid_encoded(path.as_bytes()) && path_unescape(path).is_ok() {
        return Ok(path.to_owned());
    }
    Ok(escaped_path_of(&decoded))
}
