//! `internal/clientip`: resolves the real client IP from an HTTP request behind trusted reverse
//! proxies, and the request scheme/host a trusted proxy asserted.
//!
//! Ported from `resolver.go`, `middleware.go`, and `config.go`. The HTTP middleware itself
//! (`Middleware`, which calls [`Resolver::resolve`]/[`Resolver::request_scheme`]/
//! [`Resolver::request_host`] once per request and stashes the results in the request context)
//! is not ported here: `silo-gate` has no HTTP stack dependency yet (that is `silo-front`'s and
//! `silo-http`'s layer, ported separately), so only the pure resolution logic — the part the
//! critique (finding 2) calls the actual security boundary — is ported. A caller wires this the
//! way Go's `clientip.Middleware` does: resolve the scheme and host from the *original*
//! `RemoteAddr` before replacing it with the resolved client IP.

use std::net::IpAddr;
use std::sync::RwLock;

use silo_gocompat::strings::equal_fold;

/// A parsed CIDR block, matching Go's `*net.IPNet` as `(*net.IPNet).Contains` compares it: an
/// IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is normalized to IPv4 before comparison against an
/// IPv4 network (Go's `ip.To4()`), so `::ffff:10.0.0.1` matches `10.0.0.0/8`. No `IpNet` with
/// containment exists in a lower crate (checked `silo-config::gonet`, which has `valid_cidr` but no
/// containment type), so it is defined here rather than duplicated from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    V4 { network: u32, prefix_len: u8 },
    V6 { network: u128, prefix_len: u8 },
}

impl IpNet {
    /// `net.ParseCIDR`, keeping only the network (Go discards the host bits too, since
    /// `ParseCIDR` returns `*IPNet` with the masked network address).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, len) = s.split_once('/')?;
        let prefix_len: u8 = len.parse().ok()?;
        match addr.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => {
                if prefix_len > 32 {
                    return None;
                }
                let mask = v4_mask(prefix_len);
                Some(Self::V4 {
                    network: u32::from(ip) & mask,
                    prefix_len,
                })
            }
            IpAddr::V6(ip) => {
                if prefix_len > 128 {
                    return None;
                }
                let mask = v6_mask(prefix_len);
                Some(Self::V6 {
                    network: u128::from(ip) & mask,
                    prefix_len,
                })
            }
        }
    }

    /// `(*net.IPNet).Contains`.
    pub fn contains(&self, ip: IpAddr) -> bool {
        // Go's To4(): an IPv4-mapped IPv6 address is treated as IPv4 for comparison purposes.
        let as_v4 = match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        match (self, as_v4, ip) {
            (
                Self::V4 {
                    network,
                    prefix_len,
                },
                Some(v4),
                _,
            ) => u32::from(v4) & v4_mask(*prefix_len) == *network,
            (
                Self::V6 {
                    network,
                    prefix_len,
                },
                None,
                IpAddr::V6(v6),
            ) => u128::from(v6) & v6_mask(*prefix_len) == *network,
            // Length mismatch (network is v4 but ip is real IPv6, or vice versa): no match.
            _ => false,
        }
    }
}

fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

/// `clientip.HasForwardingHeaders`: whether any header line the resolver reads at all names a
/// forwarded client, regardless of trust. `headers` is every value of a repeated header, exactly
/// as `http.Header.Values` would return them (one entry per header line, unsplit).
pub fn has_forwarding_headers(
    x_forwarded_for: &[&str],
    x_real_ip: &[&str],
    forwarded: &[&str],
) -> bool {
    has_forwarded_entry(x_forwarded_for)
        || has_forwarded_entry(x_real_ip)
        || has_forwarded_entry(forwarded)
}

fn has_forwarded_entry(values: &[&str]) -> bool {
    values.iter().any(|v| {
        !v.trim_matches(|c: char| c == ',' || c.is_whitespace())
            .is_empty()
    })
}

/// What [`Resolver::resolve`] returns: the client IP (already normalized) and whether it names a
/// forwarder whose own client the resolver could not identify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub ip: IpAddr,
    /// `clientip.ForwardedClientUnknown`: true when the returned IP is a forwarder's own address
    /// because entries to its left could not be attributed, or its headers named no usable
    /// address at all while still being present.
    pub forwarded_client_unknown: bool,
}

/// `clientip.Resolver`. Thread-safe: the trusted list can be swapped live (`UpdateTrustedCIDRs`)
/// while resolutions are in flight.
#[derive(Debug, Default)]
pub struct Resolver {
    trusted: RwLock<Vec<IpNet>>,
}

impl Resolver {
    /// `clientip.NewResolver`.
    pub fn new(trusted: Vec<IpNet>) -> Self {
        Self {
            trusted: RwLock::new(trusted),
        }
    }

    /// `Resolver.UpdateTrustedCIDRs`.
    pub fn update_trusted_cidrs(&self, cidrs: Vec<IpNet>) {
        *self.trusted.write().expect("trusted lock") = cidrs;
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted
            .read()
            .expect("trusted lock")
            .iter()
            .any(|net| net.contains(ip))
    }

    /// `Resolver.ClientIP`: resolved IP only, normalized to its canonical string form. `remote_addr`
    /// is `r.RemoteAddr` (host or host:port, as the Go listener would report it); `x_forwarded_for`
    /// and `x_real_ip` are every value of their respective repeated headers, in request order,
    /// unsplit.
    pub fn client_ip(
        &self,
        remote_addr: &str,
        x_forwarded_for: &[&str],
        x_real_ip: &[&str],
    ) -> String {
        normalize(Some(
            self.resolve(remote_addr, x_forwarded_for, x_real_ip).ip,
        ))
    }

    /// `Resolver.resolve`.
    pub fn resolve(
        &self,
        remote_addr: &str,
        x_forwarded_for: &[&str],
        x_real_ip: &[&str],
    ) -> Resolved {
        let remote_ip = parse_remote_addr(remote_addr);
        let forwarding_present = has_forwarding_headers(x_forwarded_for, x_real_ip, &[]);

        if !self.is_trusted(remote_ip) {
            return Resolved {
                ip: remote_ip,
                forwarded_client_unknown: forwarding_present,
            };
        }

        if let Some((ip, forwarded)) = self.forwarded_for(x_forwarded_for) {
            return Resolved {
                ip,
                forwarded_client_unknown: forwarded,
            };
        }

        if x_real_ip.len() == 1
            && let Some(parsed) = parse_forwarded_addr(x_real_ip[0].trim())
        {
            return Resolved {
                ip: parsed,
                forwarded_client_unknown: false,
            };
        }

        Resolved {
            ip: remote_ip,
            forwarded_client_unknown: forwarding_present,
        }
    }

    /// `Resolver.forwardedFor`: walks the X-Forwarded-For lines right to left. `lines` are the
    /// header's values in request order (one per header line, each possibly comma-separated).
    fn forwarded_for(&self, lines: &[&str]) -> Option<(IpAddr, bool)> {
        let mut last: Option<IpAddr> = None;
        for i in (0..lines.len()).rev() {
            let entries: Vec<&str> = lines[i].split(',').collect();
            for j in (0..entries.len()).rev() {
                let entry = entries[j].trim();
                if entry.is_empty() {
                    continue;
                }
                let Some(ip) = parse_forwarded_addr(entry) else {
                    return Some((last.unwrap_or(IpAddr::from([0, 0, 0, 0])), true));
                };
                if !self.is_trusted(ip) {
                    let forwarded =
                        has_forwarded_entry(&entries[..j]) || has_forwarded_entry(&lines[..i]);
                    return Some((ip, forwarded));
                }
                last = Some(ip);
            }
        }
        last.map(|ip| (ip, false))
    }

    /// `Resolver.peerTrusted`: whether the transport peer of `remote_addr` is trusted. `remote_addr`
    /// is the raw peer address (host:port or bare host), exactly as `req.RemoteAddr` would read
    /// before `Middleware` overwrites it.
    pub fn peer_trusted(&self, remote_addr: &str) -> bool {
        let host = split_host_port(remote_addr).unwrap_or(remote_addr);
        match host.parse::<IpAddr>() {
            Ok(ip) => self.is_trusted(ip),
            Err(_) => false,
        }
    }

    /// `Resolver.requestScheme`. `tls` is whether the transport connection used TLS.
    /// `x_forwarded_proto` is the header's values in order. `is_websocket_upgrade` tells it whether
    /// the request is a WebSocket upgrade, for the Traefik `ws`/`wss` exception.
    pub fn request_scheme(
        &self,
        remote_addr: &str,
        tls: bool,
        x_forwarded_proto: &[&str],
        is_websocket_upgrade: bool,
    ) -> String {
        let scheme = if tls { "https" } else { "http" };
        if !self.peer_trusted(remote_addr) {
            return scheme.to_owned();
        }
        if x_forwarded_proto.is_empty() {
            return scheme.to_owned();
        }
        if x_forwarded_proto.len() != 1 {
            return String::new();
        }
        match x_forwarded_proto[0] {
            "http" | "https" => x_forwarded_proto[0].to_owned(),
            "ws" if is_websocket_upgrade => "http".to_owned(),
            "wss" if is_websocket_upgrade => "https".to_owned(),
            _ => String::new(),
        }
    }

    /// `Resolver.requestHost`. `host_header` is the request's `Host` field (as read by the Go
    /// server, i.e. including a `:port` when the client sent one).
    pub fn request_host(
        &self,
        remote_addr: &str,
        host_header: &str,
        x_forwarded_host: &[&str],
    ) -> String {
        if !self.peer_trusted(remote_addr) {
            return host_header.to_owned();
        }
        if x_forwarded_host.len() != 1 {
            return host_header.to_owned();
        }
        let host = x_forwarded_host[0].trim();
        if host.is_empty() || host.contains([',', '/', '?', '#', '@', ' ', '\t']) {
            return host_header.to_owned();
        }
        host.to_owned()
    }
}

/// `clientip.isWebSocketUpgrade`.
pub fn is_websocket_upgrade(upgrade_header: &str, connection_values: &[&str]) -> bool {
    if !equal_fold(upgrade_header.trim(), "websocket") {
        return false;
    }
    connection_values.iter().any(|value| {
        value
            .split(',')
            .any(|token| equal_fold(token.trim(), "upgrade"))
    })
}

/// `clientip.SerializeOrigin`.
pub fn serialize_origin(scheme: &str, host: &str) -> String {
    let scheme = scheme.trim().to_ascii_lowercase();
    let host = host.trim();
    // url.URL{Host: host}.Hostname()/.Port(): split on the last ':' unless the host is a
    // bracketed IPv6 literal, in which case the brackets are stripped for Hostname() and the
    // trailing :port (if any) is Port().
    let (mut name, port) = split_host_port_go(host);
    name = name.to_ascii_lowercase();
    let port = if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
        String::new()
    } else {
        port
    };
    if name.contains(':') {
        name = format!("[{name}]");
    }
    let mut out = format!("{scheme}://{name}");
    if !port.is_empty() {
        out.push(':');
        out.push_str(&port);
    }
    out
}

/// Mirrors `net/url.URL{Host: host}.Hostname()`/`.Port()` closely enough for [`serialize_origin`]:
/// a bracketed IPv6 literal's brackets are stripped for the hostname, and a trailing `:port` (if
/// any, after removing a bracketed literal) becomes the port.
fn split_host_port_go(host: &str) -> (String, String) {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let hostname = &rest[..end];
            let after = &rest[end + 1..];
            let port = after.strip_prefix(':').unwrap_or("");
            return (hostname.to_owned(), port.to_owned());
        }
        return (host.to_owned(), String::new());
    }
    match host.rfind(':') {
        Some(i) if !host[i + 1..].contains(':') => (host[..i].to_owned(), host[i + 1..].to_owned()),
        _ => (host.to_owned(), String::new()),
    }
}

/// `clientip.parseForwardedAddr`.
fn parse_forwarded_addr(addr: &str) -> Option<IpAddr> {
    if let Some(host) = split_host_port(addr) {
        return parse_unzoned_ip(host);
    }
    let unbracketed = if addr.len() > 1 && addr.starts_with('[') && addr.ends_with(']') {
        &addr[1..addr.len() - 1]
    } else {
        addr
    };
    parse_unzoned_ip(unbracketed)
}

/// `net.SplitHostPort`, as far as the two forms `clientip` ever feeds it need: `host:port` and
/// `[host]:port`. Returns `None` when there is no `:port` suffix to split off (bare IP, or an
/// unterminated bracket) — the caller then tries the whole string as a bare address.
fn split_host_port(addr: &str) -> Option<&str> {
    if let Some(rest) = addr.strip_prefix('[') {
        let end = rest.find(']')?;
        let after = &rest[end + 1..];
        if after.strip_prefix(':').is_some() {
            return Some(&rest[..end]);
        }
        return None;
    }
    let colon = addr.rfind(':')?;
    if addr[..colon].contains(':') {
        // More than one colon outside brackets: not host:port (an unbracketed IPv6 literal).
        return None;
    }
    Some(&addr[..colon])
}

/// `clientip.parseUnzonedIP`: parses an IP, dropping an IPv6 zone (`fe80::1%eth0`).
fn parse_unzoned_ip(addr: &str) -> Option<IpAddr> {
    let addr = match addr.find('%') {
        Some(i) if addr[..i].contains(':') => &addr[..i],
        _ => addr,
    };
    addr.parse().ok()
}

/// `clientip.parseRemoteAddr`: never fails — an unparsable address becomes `0.0.0.0`, matching
/// Go's `net.IPv4zero` fallback.
fn parse_remote_addr(addr: &str) -> IpAddr {
    let host = split_host_port(addr).unwrap_or(addr);
    host.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

/// `clientip.normalize`.
pub fn normalize(ip: Option<IpAddr>) -> String {
    match ip {
        Some(ip) => ip.to_string(),
        None => "0.0.0.0".to_owned(),
    }
}

/// `clientip.DefaultTrustedProxies`.
pub const DEFAULT_TRUSTED_PROXIES: &str =
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128";
/// `clientip.SettingTrustedProxies`.
pub const SETTING_TRUSTED_PROXIES: &str = "clientip.trusted_proxies";
/// `clientip.EnvTrustedProxies`.
pub const ENV_TRUSTED_PROXIES: &str = "SILO_TRUSTED_PROXIES";

/// `clientip.ParseCIDRs`/`NormalizeCIDRList`'s shared parse step: one invalid entry fails the
/// whole list, matching Go's `net.ParseCIDR` error there.
#[derive(Debug, thiserror::Error)]
#[error("invalid CIDR {0:?}")]
pub struct InvalidCidr(pub String);

/// `clientip.ParseCIDRs`.
pub fn parse_cidrs(raw: &str) -> Result<Vec<IpNet>, InvalidCidr> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let net = IpNet::parse(part).ok_or_else(|| InvalidCidr(part.to_owned()))?;
        out.push(net);
    }
    Ok(out)
}

/// `clientip.NormalizeCIDRList`.
pub fn normalize_cidr_list(raw: &str) -> Result<String, InvalidCidr> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if IpNet::parse(part).is_none() {
            return Err(InvalidCidr(part.to_owned()));
        }
        out.push(part.to_owned());
    }
    Ok(out.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(cidrs: &str) -> Resolver {
        Resolver::new(parse_cidrs(cidrs).unwrap())
    }

    #[test]
    fn untrusted_peer_ignores_forwarding_headers() {
        let r = resolver("10.0.0.0/8");
        let resolved = r.resolve("8.8.8.8:1234", &["1.2.3.4"], &[]);
        assert_eq!(resolved.ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert!(resolved.forwarded_client_unknown);
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_xff_entry() {
        let r = resolver("10.0.0.0/8");
        let resolved = r.resolve("10.0.0.1:1234", &["1.2.3.4, 10.0.0.2"], &[]);
        assert_eq!(resolved.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert!(!resolved.forwarded_client_unknown);
    }

    #[test]
    fn trusted_peer_falls_back_to_x_real_ip() {
        let r = resolver("10.0.0.0/8");
        let resolved = r.resolve("10.0.0.1:1234", &[], &["1.2.3.4"]);
        assert_eq!(resolved.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn x_real_ip_never_overrides_a_present_xff_entry() {
        let r = resolver("10.0.0.0/8");
        let resolved = r.resolve("10.0.0.1:1234", &["10.0.0.2"], &["9.9.9.9"]);
        // All XFF entries trusted and no untrusted hop: leftmost (only) trusted entry is reported.
        assert_eq!(resolved.ip, "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn serialize_origin_drops_default_ports_and_brackets_ipv6() {
        assert_eq!(
            serialize_origin("HTTPS", "Example.com:443"),
            "https://example.com"
        );
        assert_eq!(
            serialize_origin("http", "example.com:8080"),
            "http://example.com:8080"
        );
        assert_eq!(
            serialize_origin("https", "[::1]:8443"),
            "https://[::1]:8443"
        );
    }
}
