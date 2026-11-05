//! `internal/netguard`: keeps server-originated requests to user-supplied addresses away from the
//! server's own network. See `docs/architecture/outbound-address-guard.md`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// The trust class of a destination address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Public,
    Private,
    Blocked,
}

/// `ErrPrivateDestination` and `ErrBlockedDestination`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Private,
    Blocked,
}

impl Refused {
    pub fn message(self) -> &'static str {
        match self {
            Refused::Private => "destination is on the server's local network",
            Refused::Blocked => "destination address is not allowed",
        }
    }
}

/// A CIDR prefix over the 16-byte form; IPv4 prefixes match only IPv4 addresses, as `netip.Prefix`.
struct Prefix {
    v4: bool,
    bytes: [u8; 16],
    bits: u32,
}

const fn v4(a: u8, b: u8, c: u8, d: u8, bits: u32) -> Prefix {
    Prefix {
        v4: true,
        bytes: [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        bits,
    }
}

const fn v6(segs: [u16; 8], bits: u32) -> Prefix {
    let mut bytes = [0u8; 16];
    let mut i = 0;
    while i < 8 {
        bytes[i * 2] = (segs[i] >> 8) as u8;
        bytes[i * 2 + 1] = segs[i] as u8;
        i += 1;
    }
    Prefix {
        v4: false,
        bytes,
        bits,
    }
}

impl Prefix {
    fn contains(&self, addr: &IpAddr) -> bool {
        let (is_v4, bytes) = match addr {
            IpAddr::V4(a) => {
                let o = a.octets();
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&o);
                (true, b)
            }
            IpAddr::V6(a) => (false, a.octets()),
        };
        if is_v4 != self.v4 {
            return false;
        }
        let full = (self.bits / 8) as usize;
        if bytes[..full] != self.bytes[..full] {
            return false;
        }
        let rest = self.bits % 8;
        if rest == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - rest);
        bytes[full] & mask == self.bytes[full] & mask
    }
}

const BLOCKED: &[Prefix] = &[
    v4(0, 0, 0, 0, 8),
    v4(169, 254, 0, 0, 16),
    v4(224, 0, 0, 0, 4),
    v4(240, 0, 0, 0, 4),
    v4(100, 100, 100, 200, 32),
    v6([0, 0, 0, 0, 0, 0, 0, 0], 128),
    v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
    v6([0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254], 128),
    v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
];

const PRIVATE: &[Prefix] = &[
    v4(10, 0, 0, 0, 8),
    v4(100, 64, 0, 0, 10),
    v4(127, 0, 0, 0, 8),
    v4(172, 16, 0, 0, 12),
    v4(192, 0, 0, 0, 24),
    v4(192, 0, 2, 0, 24),
    v4(192, 88, 99, 0, 24),
    v4(192, 168, 0, 0, 16),
    v4(198, 18, 0, 0, 15),
    v4(198, 51, 100, 0, 24),
    v4(203, 0, 113, 0, 24),
    v6([0, 0, 0, 0, 0, 0, 0, 1], 128),
    v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
    v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
];

const NAT64: Prefix = v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96);
const IPV4_COMPATIBLE: Prefix = v6([0, 0, 0, 0, 0, 0, 0, 0], 96);

/// `netip.Addr.Unmap`.
fn unmap(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(a),
        },
        other => other,
    }
}

/// `Classify`. IPv4-mapped IPv6 addresses classify as their IPv4 form.
pub fn classify(addr: IpAddr) -> Class {
    let addr = unmap(addr);
    if BLOCKED.iter().any(|p| p.contains(&addr)) {
        return Class::Blocked;
    }
    if NAT64.contains(&addr) {
        let IpAddr::V6(a) = addr else { unreachable!() };
        let b = a.octets();
        if classify(IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]))) == Class::Blocked {
            return Class::Blocked;
        }
        return Class::Private;
    }
    if PRIVATE.iter().any(|p| p.contains(&addr)) {
        return Class::Private;
    }
    if IPV4_COMPATIBLE.contains(&addr) {
        return Class::Blocked;
    }
    Class::Public
}

/// `CheckAddr`.
pub fn check_addr(addr: IpAddr, allow_private: bool) -> Result<(), Refused> {
    match classify(addr) {
        Class::Blocked => Err(Refused::Blocked),
        Class::Private if !allow_private => Err(Refused::Private),
        Class::Public if !allow_private && host_address(unmap(addr)) => Err(Refused::Private),
        _ => Ok(()),
    }
}

/// `hostAddress`: whether `addr` is assigned to one of this machine's interfaces. An enumeration
/// failure counts as a match, so the check fails closed.
fn host_address(addr: IpAddr) -> bool {
    // SAFETY: getifaddrs fills a list freed below with freeifaddrs; each entry's address is read
    // according to its family.
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return true;
        }
        let mut found = false;
        let mut cur = list;
        while !cur.is_null() {
            let sa = (*cur).ifa_addr;
            if !sa.is_null() {
                let ip = match i32::from((*sa).sa_family) {
                    libc::AF_INET => {
                        let sin = sa as *const libc::sockaddr_in;
                        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            (*sin).sin_addr.s_addr,
                        ))))
                    }
                    libc::AF_INET6 => {
                        let sin6 = sa as *const libc::sockaddr_in6;
                        Some(IpAddr::V6(Ipv6Addr::from((*sin6).sin6_addr.s6_addr)))
                    }
                    _ => None,
                };
                if ip.is_some_and(|ip| unmap(ip) == addr) {
                    found = true;
                    break;
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(list);
        found
    }
}

/// `netip.ParseAddr`: IPv4 in dotted decimal without leading zeros, or IPv6 with an optional
/// non-empty zone. The zone does not take part in any check.
pub fn parse_addr(s: &str) -> Option<IpAddr> {
    if s.contains(':') {
        let (addr, zone) = match s.split_once('%') {
            Some((a, z)) => (a, Some(z)),
            None => (s, None),
        };
        if zone.is_some_and(str::is_empty) {
            return None;
        }
        return addr.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    s.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// `url.URL.Hostname`: the host without its port, and without brackets around an IPv6 literal.
pub fn hostname(host: &str) -> &str {
    let (host, _) = split_host_port(host);
    host
}

/// `url.URL.Port` and `Hostname` together.
fn split_host_port(host: &str) -> (&str, &str) {
    let mut h = host;
    let mut port = "";
    if let Some(colon) = h.rfind(':') {
        let p = &h[colon + 1..];
        if p.bytes().all(|b| b.is_ascii_digit()) {
            port = p;
            h = &h[..colon];
        }
    }
    if let Some(inner) = h.strip_prefix('[').and_then(|i| i.strip_suffix(']')) {
        return (inner, port);
    }
    (h, port)
}

/// `net.DefaultResolver.LookupNetIP(ctx, "ip", host)` within `timeout`, as Go's pure resolver
/// answers it with `hosts: files dns`. `None` is a failure or an empty answer.
pub async fn lookup(host: &str, timeout: Duration) -> Option<Vec<IpAddr>> {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    lookup_with_hosts(host, &hosts, timeout).await
}

/// [`lookup`] against the given hosts file text.
pub async fn lookup_with_hosts(host: &str, hosts: &str, timeout: Duration) -> Option<Vec<IpAddr>> {
    match go_lookup_plan(host, hosts) {
        LookupPlan::Files(addrs) => Some(addrs),
        LookupPlan::Fail => None,
        LookupPlan::Dns => {
            let target = format!("{host}:0");
            let found = tokio::time::timeout(timeout, tokio::net::lookup_host(target))
                .await
                .ok()?
                .ok()?;
            let addrs: Vec<IpAddr> = found.map(|a| a.ip()).collect();
            (!addrs.is_empty()).then_some(addrs)
        }
    }
}

enum LookupPlan {
    Files(Vec<IpAddr>),
    Fail,
    Dns,
}

/// Go's resolver answers a name from `/etc/hosts` (`lookupStaticHost`) or from DNS, never from a
/// numeric spelling. The C library's `getaddrinfo` reads `inet_aton` forms (`0177.0.0.1`,
/// `0x7f000001`, `2130706433`, `127.1`) as addresses, matches the hosts file with its own rules
/// (`localhost.`), and answers `.localhost` and `.local` names itself on some platforms. Those
/// names reach DNS in Go, where no resolver answers them, so they fail here before `getaddrinfo`.
fn go_lookup_plan(host: &str, hosts: &str) -> LookupPlan {
    let files = go_hosts(hosts);
    let key = abs_domain_name(&host.to_ascii_lowercase());
    if let Some(addrs) = files.iter().find(|(name, _)| *name == key).map(|(_, a)| a) {
        return LookupPlan::Files(addrs.clone());
    }
    if !is_domain_name(host) {
        return LookupPlan::Fail;
    }
    let lower = host.to_ascii_lowercase();
    let bare = lower.strip_suffix('.').unwrap_or(&lower);
    if inet_aton_form(bare)
        || files
            .iter()
            .any(|(name, _)| name.trim_end_matches('.') == bare)
        || bare == "localhost"
        || bare.ends_with(".localhost")
        || bare.ends_with(".local")
    {
        return LookupPlan::Fail;
    }
    LookupPlan::Dns
}

/// `readHosts`: each name, lowercased and made absolute, with its addresses in file order.
fn go_hosts(text: &str) -> Vec<(String, Vec<IpAddr>)> {
    let mut out: Vec<(String, Vec<IpAddr>)> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let f: Vec<&str> = line
            .split([' ', '\r', '\t', '\n'])
            .filter(|s| !s.is_empty())
            .collect();
        if f.len() < 2 {
            continue;
        }
        let Some(addr) = parse_addr(f[0]) else {
            continue;
        };
        for name in &f[1..] {
            let key = abs_domain_name(&name.to_ascii_lowercase());
            match out.iter_mut().find(|(n, _)| *n == key) {
                Some((_, addrs)) => addrs.push(addr),
                None => out.push((key, vec![addr])),
            }
        }
    }
    out
}

/// `absDomainName`: a name with an inner dot gets a trailing one.
fn abs_domain_name(s: &str) -> String {
    if s.contains('.') && !s.ends_with('.') {
        format!("{s}.")
    } else {
        s.to_owned()
    }
}

/// `isDomainName`.
fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let b = s.as_bytes();
    let l = b.len();
    if l == 0 || l > 254 || (l == 254 && b[l - 1] != b'.') {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut partlen = 0;
    for &c in b {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                partlen += 1;
            }
            b'0'..=b'9' => partlen += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                partlen += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || partlen > 63 || partlen == 0 {
                    return false;
                }
                partlen = 0;
            }
            _ => return false,
        }
        last = c;
    }
    last != b'-' && partlen <= 63 && non_numeric
}

/// One to four dot-separated parts, each decimal, octal, or `0x` hex: the shapes `inet_aton`
/// may read as an address. No DNS name of this shape exists, since no top-level domain has it.
fn inet_aton_form(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    (1..=4).contains(&parts.len())
        && parts.iter().all(|p| {
            if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
                hex.bytes().all(|c| c.is_ascii_hexdigit())
            } else {
                !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit())
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rust/conformance/vectors/generators/netguard` writes these from the real `internal/netguard`.
    #[test]
    fn matches_go_vectors() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../conformance/vectors/netguard/classify.json"
        ))
        .unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let input = v["input"].as_str().unwrap();
            let parsed = parse_addr(input);
            assert_eq!(parsed.is_some(), v["valid"].as_bool().unwrap(), "{input}");
            if let Some(addr) = parsed {
                let want = match v["class"].as_str().unwrap() {
                    "public" => Class::Public,
                    "private" => Class::Private,
                    _ => Class::Blocked,
                };
                assert_eq!(classify(addr), want, "{input}");
            }
        }
    }

    /// `rust/conformance/vectors/generators/webhookguard` writes these from Go's resolver inside
    /// the Go server's container, whose hosts file maps `localhost` to 127.0.0.1 and ::1.
    #[tokio::test]
    async fn lookup_matches_go_vectors() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../conformance/vectors/netguard/lookup.json"
        ))
        .unwrap();
        assert!(!vectors.is_empty());
        let hosts = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n";
        let canon = |a: IpAddr| match a {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(a, IpAddr::V4),
            v4 => v4,
        };
        for v in vectors {
            let host = v["host"].as_str().unwrap();
            assert_eq!(
                parse_addr(host).is_some(),
                v["parsed_ip"].as_bool().unwrap(),
                "{host}"
            );
            if parse_addr(host).is_some() {
                continue;
            }
            let got = lookup_with_hosts(host, hosts, Duration::from_secs(2)).await;
            let want = v["resolved"].as_bool().unwrap().then(|| {
                let mut a: Vec<IpAddr> = v["addrs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| canon(s.as_str().unwrap().parse().unwrap()))
                    .collect();
                a.sort();
                a
            });
            let got = got.map(|mut a| {
                a = a.into_iter().map(canon).collect();
                a.sort();
                a
            });
            assert_eq!(got, want, "{host}");
        }
    }

    #[test]
    fn hostname_drops_port_and_brackets() {
        assert_eq!(hostname("[::1]:443"), "::1");
        assert_eq!(hostname("example.com:8443"), "example.com");
        assert_eq!(hostname("example.com"), "example.com");
    }
}
