//! The parts of Go's `net/url` and `net` that settings validation and Redis URLs depend on.

use silo_gocompat::strconv::quote;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// `url.Userinfo`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Userinfo {
    pub username: String,
    pub password: Option<String>,
}

/// `url.URL`, without the raw-path hints nothing here reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Url {
    pub scheme: String,
    pub opaque: String,
    pub user: Option<Userinfo>,
    pub host: String,
    pub path: String,
    pub omit_host: bool,
    pub force_query: bool,
    pub raw_query: String,
    pub fragment: String,
}

/// `url.Error` from a failed parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlError {
    pub url: String,
    pub err: String,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse {}: {}", quote(&self.url), self.err)
    }
}

impl std::error::Error for UrlError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Path,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn should_escape_host(c: u8) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    !matches!(
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
            | b'-'
            | b'_'
            | b'.'
            | b'~'
    )
}

fn quote_bytes(b: &[u8]) -> String {
    silo_gocompat::strconv::quote_bytes(b)
}

fn unescape(s: &str, mode: Encoding) -> Result<String, String> {
    let b = s.as_bytes();
    let mut n = 0;
    let mut has_plus = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                n += 1;
                if i + 2 >= b.len() || !is_hex(b[i + 1]) || !is_hex(b[i + 2]) {
                    let rest = &b[i..];
                    let shown = &rest[..rest.len().min(3)];
                    return Err(format!("invalid URL escape {}", quote_bytes(shown)));
                }
                if mode == Encoding::Host && unhex(b[i + 1]) < 8 && &b[i..i + 3] != b"%25" {
                    return Err(format!("invalid URL escape {}", quote_bytes(&b[i..i + 3])));
                }
                if mode == Encoding::Zone {
                    let v = unhex(b[i + 1]) << 4 | unhex(b[i + 2]);
                    if &b[i..i + 3] != b"%25" && v != b' ' && should_escape_host(v) {
                        return Err(format!("invalid URL escape {}", quote_bytes(&b[i..i + 3])));
                    }
                }
                i += 3;
            }
            b'+' => {
                has_plus = mode == Encoding::QueryComponent;
                i += 1;
            }
            c => {
                if (mode == Encoding::Host || mode == Encoding::Zone)
                    && c < 0x80
                    && should_escape_host(c)
                {
                    return Err(format!(
                        "invalid character {} in host name",
                        quote_bytes(&b[i..i + 1])
                    ));
                }
                i += 1;
            }
        }
    }
    if n == 0 && !has_plus {
        return Ok(s.to_owned());
    }
    let plus = if mode == Encoding::QueryComponent {
        b' '
    } else {
        b'+'
    };
    let mut t = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                t.push(unhex(b[i + 1]) << 4 | unhex(b[i + 2]));
                i += 3;
            }
            b'+' => {
                t.push(plus);
                i += 1;
            }
            c => {
                t.push(c);
                i += 1;
            }
        }
    }
    Ok(String::from_utf8_lossy(&t).into_owned())
}

fn contains_ctl(s: &str) -> bool {
    s.bytes().any(|b| b < b' ' || b == 0x7f)
}

fn get_scheme(raw: &str) -> Result<(&str, &str), String> {
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
                    return Err("missing protocol scheme".to_owned());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
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

fn parse_host(scheme: &str, host: &str) -> Result<String, String> {
    match host.rfind('[') {
        Some(open) if open > 0 => return Err("invalid IP-literal".to_owned()),
        Some(_) => {
            let close = host
                .rfind(']')
                .ok_or_else(|| "missing ']' in host".to_owned())?;
            let colon_port = &host[close + 1..];
            if !valid_optional_port(colon_port) {
                return Err(format!("invalid port {} after host", quote(colon_port)));
            }
            let unescaped_port = unescape(colon_port, Encoding::Host)?;
            let hostname = &host[1..close];
            let unescaped = match hostname.find("%25") {
                Some(zone) => {
                    let host_part = unescape(&hostname[..zone], Encoding::Host)?;
                    let zone_part = unescape(&hostname[zone..], Encoding::Zone)?;
                    host_part + &zone_part
                }
                None => unescape(hostname, Encoding::Host)?,
            };
            let addr = parse_addr(&unescaped).map_err(|e| format!("invalid host: {e}"))?;
            if matches!(addr, IpAddress::V4(_)) {
                return Err("invalid IP-literal".to_owned());
            }
            return Ok(format!("[{unescaped}]{unescaped_port}"));
        }
        None => {}
    }
    if let Some(mut i) = host.find(':') {
        let last = host.rfind(':').unwrap_or(i);
        if last != i && scheme != "http" && scheme != "https" {
            i = last;
        }
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {} after host", quote(colon_port)));
        }
    }
    unescape(host, Encoding::Host)
}

fn parse_authority(scheme: &str, authority: &str) -> Result<(Option<Userinfo>, String), String> {
    let at = authority.rfind('@');
    let host = match at {
        None => parse_host(scheme, authority)?,
        Some(i) => parse_host(scheme, &authority[i + 1..])?,
    };
    let Some(i) = at else {
        return Ok((None, host));
    };
    let userinfo = &authority[..i];
    if !valid_userinfo(userinfo) {
        return Err("net/url: invalid userinfo".to_owned());
    }
    let user = match userinfo.split_once(':') {
        None => Userinfo {
            username: unescape(userinfo, Encoding::UserPassword)?,
            password: None,
        },
        Some((u, p)) => Userinfo {
            username: unescape(u, Encoding::UserPassword)?,
            password: Some(unescape(p, Encoding::UserPassword)?),
        },
    };
    Ok((Some(user), host))
}

fn parse_inner(raw: &str) -> Result<Url, String> {
    if contains_ctl(raw) {
        return Err("net/url: invalid control character in URL".to_owned());
    }
    let mut url = Url::default();
    if raw == "*" {
        url.path = "*".to_owned();
        return Ok(url);
    }
    let (scheme, mut rest) = get_scheme(raw)?;
    url.scheme = silo_gocompat::strings::to_lower(scheme);
    if rest.ends_with('?') && rest.bytes().filter(|&b| b == b'?').count() == 1 {
        url.force_query = true;
        rest = &rest[..rest.len() - 1];
    } else if let Some((r, q)) = rest.split_once('?') {
        rest = r;
        url.raw_query = q.to_owned();
    }
    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_owned();
            return Ok(url);
        }
        let segment = rest.split('/').next().unwrap_or("");
        if segment.contains(':') {
            return Err("first path segment in URL cannot contain colon".to_owned());
        }
    }
    if (!url.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let mut authority = &rest[2..];
        rest = "";
        if let Some(i) = authority.find('/') {
            rest = &authority[i..];
            authority = &authority[..i];
        }
        let (user, host) = parse_authority(&url.scheme, authority)?;
        url.user = user;
        url.host = host;
    } else if !url.scheme.is_empty() && rest.starts_with('/') {
        url.omit_host = true;
    }
    url.path = unescape(rest, Encoding::Path)?;
    Ok(url)
}

impl Url {
    /// `url.Parse`.
    pub fn parse(raw: &str) -> Result<Url, UrlError> {
        let (u, frag) = match raw.split_once('#') {
            Some((u, f)) => (u, f),
            None => (raw, ""),
        };
        let mut url = parse_inner(u).map_err(|err| UrlError {
            url: u.to_owned(),
            err,
        })?;
        if frag.is_empty() {
            return Ok(url);
        }
        url.fragment = unescape(frag, Encoding::Fragment).map_err(|err| UrlError {
            url: raw.to_owned(),
            err,
        })?;
        Ok(url)
    }

    /// `url.URL.Hostname`.
    pub fn hostname(&self) -> &str {
        split_host_port_lenient(&self.host).0
    }

    /// `url.URL.Port`.
    pub fn port(&self) -> &str {
        split_host_port_lenient(&self.host).1
    }

    /// `url.URL.Query`: the values `url.ParseQuery` keeps, dropping any error.
    pub fn query(&self) -> Values {
        parse_query(&self.raw_query).0
    }
}

fn split_host_port_lenient(host_port: &str) -> (&str, &str) {
    let mut host = host_port;
    let mut port = "";
    if let Some(colon) = host.rfind(':')
        && valid_optional_port(&host[colon..])
    {
        port = &host[colon + 1..];
        host = &host[..colon];
    }
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

/// `url.Values`, keeping each key's values in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Values(pub Vec<(String, Vec<String>)>);

impl Values {
    pub fn has(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }

    pub fn get(&self, key: &str) -> Option<&Vec<String>> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn remove(&mut self, key: &str) -> Option<Vec<String>> {
        let i = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(i).1)
    }

    fn push(&mut self, key: String, value: String) {
        if let Some((_, v)) = self.0.iter_mut().find(|(k, _)| *k == key) {
            v.push(value);
        } else {
            self.0.push((key, vec![value]));
        }
    }
}

/// `url.ParseQuery`: the values read and the first error, which does not stop parsing.
pub fn parse_query(query: &str) -> (Values, Option<String>) {
    let mut m = Values::default();
    let mut err: Option<String> = None;
    let mut rest = query;
    while !rest.is_empty() {
        let key;
        (key, rest) = match rest.split_once('&') {
            Some((k, r)) => (k, r),
            None => (rest, ""),
        };
        if key.contains(';') {
            // Go overwrites any earlier error here.
            err = Some("invalid semicolon separator in query".to_owned());
            continue;
        }
        if key.is_empty() {
            continue;
        }
        let (k, v) = match key.split_once('=') {
            Some((k, v)) => (k, v),
            None => (key, ""),
        };
        let k = match unescape(k, Encoding::QueryComponent) {
            Ok(k) => k,
            Err(e) => {
                err.get_or_insert(e);
                continue;
            }
        };
        let v = match unescape(v, Encoding::QueryComponent) {
            Ok(v) => v,
            Err(e) => {
                err.get_or_insert(e);
                continue;
            }
        };
        m.push(k, v);
    }
    (m, err)
}

/// `net.AddrError` text from [`split_host_port`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrError {
    pub err: &'static str,
    pub addr: String,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.addr.is_empty() {
            return f.write_str(self.err);
        }
        write!(f, "address {}: {}", self.addr, self.err)
    }
}

/// `net.SplitHostPort`.
pub fn split_host_port(hostport: &str) -> Result<(String, String), AddrError> {
    let addr_err = |why: &'static str| AddrError {
        err: why,
        addr: hostport.to_owned(),
    };
    let Some(i) = hostport.rfind(':') else {
        return Err(addr_err("missing port in address"));
    };
    let b = hostport.as_bytes();
    let (host, j, k);
    if b[0] == b'[' {
        let Some(end) = hostport.find(']') else {
            return Err(addr_err("missing ']' in address"));
        };
        if end + 1 == hostport.len() {
            return Err(addr_err("missing port in address"));
        } else if end + 1 != i {
            if b[end + 1] == b':' {
                return Err(addr_err("too many colons in address"));
            }
            return Err(addr_err("missing port in address"));
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return Err(addr_err("too many colons in address"));
        }
        j = 0;
        k = 0;
    }
    if hostport[j..].contains('[') {
        return Err(addr_err("unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(addr_err("unexpected ']' in address"));
    }
    Ok((host.to_owned(), hostport[i + 1..].to_owned()))
}

/// `net.JoinHostPort`.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A parsed `netip.Addr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr, String),
}

impl IpAddress {
    /// `netip.Addr.IsLoopback`.
    pub fn is_loopback(&self) -> bool {
        match self {
            IpAddress::V4(a) => a.octets()[0] == 127,
            IpAddress::V6(a, _) => match a.to_ipv4_mapped() {
                Some(v4) => v4.octets()[0] == 127,
                None => *a == Ipv6Addr::LOCALHOST,
            },
        }
    }

    pub fn zone(&self) -> &str {
        match self {
            IpAddress::V4(_) => "",
            IpAddress::V6(_, z) => z,
        }
    }

    pub fn bit_len(&self) -> i64 {
        match self {
            IpAddress::V4(_) => 32,
            IpAddress::V6(..) => 128,
        }
    }
}

/// `netip.ParseAddr`. The error names the input the way Go's does.
pub fn parse_addr(s: &str) -> Result<IpAddress, String> {
    let bad = |msg: &str| format!("ParseAddr({}): {msg}", quote(s));
    for c in s.bytes() {
        match c {
            b'.' => {
                return Ipv4Addr::from_str(s)
                    .map(IpAddress::V4)
                    .map_err(|_| bad("invalid IPv4 address"));
            }
            b':' => {
                let (addr, zone) = match s.split_once('%') {
                    Some((_, "")) => return Err(bad("zone must be a non-empty string")),
                    Some((a, z)) => (a, z),
                    None => (s, ""),
                };
                return Ipv6Addr::from_str(addr)
                    .map(|a| IpAddress::V6(a, zone.to_owned()))
                    .map_err(|_| bad("invalid IPv6 address"));
            }
            b'%' => return Err(bad("missing IPv6 address")),
            _ => {}
        }
    }
    Err(bad("unable to parse IP"))
}

/// Whether `net.ParseCIDR` accepts `s`.
pub fn valid_cidr(s: &str) -> bool {
    let Some((addr, mask)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = parse_addr(addr) else {
        return false;
    };
    if !ip.zone().is_empty() || mask.is_empty() || !mask.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if mask.len() > 7 {
        return false;
    }
    mask.parse::<i64>().is_ok_and(|n| n <= ip.bit_len())
}

/// Whether `mail.ParseAddress(value)` succeeds with `Address` equal to `value`, the only outcome
/// `email.from_address` validation accepts. A display name, angle brackets, a comment, a quoted
/// local part, or surrounding space all make the parsed address differ from the input, so only a
/// bare dot-atom or domain-literal address can pass.
pub fn mail_address_equals_input(value: &str) -> bool {
    fn is_atext(r: char) -> bool {
        if r == '.' {
            return true;
        }
        if matches!(
            r,
            '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '"'
        ) {
            return false;
        }
        ('!'..='~').contains(&r) || (r as u32) >= 0x80
    }
    fn is_dtext(r: char) -> bool {
        if matches!(r, '[' | ']' | '\\') {
            return false;
        }
        ('!'..='~').contains(&r) || (r as u32) >= 0x80
    }
    fn atom_ok(atom: &str) -> bool {
        !atom.is_empty() && !atom.starts_with('.') && !atom.contains("..") && !atom.ends_with('.')
    }
    let end = value.find(|r| !is_atext(r)).unwrap_or(value.len());
    let (local, rest) = value.split_at(end);
    if !atom_ok(local) {
        return false;
    }
    let Some(domain) = rest.strip_prefix('@') else {
        return false;
    };
    if let Some(literal) = domain.strip_prefix('[') {
        let Some(dtext) = literal.strip_suffix(']') else {
            return false;
        };
        if !dtext.chars().all(is_dtext) {
            return false;
        }
        return parse_addr(dtext).is_ok_and(|a| a.zone().is_empty());
    }
    domain.chars().all(is_atext) && atom_ok(domain)
}
