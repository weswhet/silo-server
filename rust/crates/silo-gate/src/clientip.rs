//! `internal/clientip`: resolves the real client IP from an HTTP request behind trusted reverse
//! proxies, and the request scheme/host a trusted proxy asserted.
//!
//! Ported from `resolver.go`, `middleware.go`, and `config.go`, and checked against the real
//! `clientip.Middleware` by `tests/clientip_differential.rs`. `silo-gate` has no HTTP stack
//! dependency, so [`Resolver::middleware`] takes the request fields Go's `Middleware` reads
//! ([`RequestFields`]) and returns what Go stores in the request context ([`RequestContext`]). The
//! caller replaces its remote address with [`RequestContext::client_ip`] afterwards.

use std::net::IpAddr;
use std::sync::RwLock;

use silo_gocompat::strings::{equal_fold, to_lower, trim_space};

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
    /// `net.ParseCIDR`, keeping only the network. Go masks with the parsed address's own bit
    /// length, then `(*net.IPNet).Contains` looks at `IP.To4()`: an IPv4-mapped network with a prefix
    /// of at least 96 therefore acts as an IPv4 network with `prefix - 96` bits, while a shorter
    /// prefix leaves the masked network unmapped and acts as IPv6. A mask length follows Go's
    /// `dtoi`: ASCII digits only, so `+8` is refused and `08` is accepted.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, len) = s.split_once('/')?;
        if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix_len: u32 = len.parse().ok()?;
        match parse_ip(addr)? {
            ParsedIp::V4(ip) => {
                if prefix_len > 32 {
                    return None;
                }
                let prefix_len = prefix_len as u8;
                Some(Self::V4 {
                    network: u32::from(ip) & v4_mask(prefix_len),
                    prefix_len,
                })
            }
            ParsedIp::V6(ip) => {
                if prefix_len > 128 {
                    return None;
                }
                let prefix_len = prefix_len as u8;
                let network = u128::from(ip) & v6_mask(prefix_len);
                let masked = std::net::Ipv6Addr::from(network);
                if let Some(v4) = masked.to_ipv4_mapped() {
                    // `network` keeps its `::ffff:0:0` prefix only when prefix_len >= 96.
                    return Some(Self::V4 {
                        network: u32::from(v4),
                        prefix_len: prefix_len - 96,
                    });
                }
                Some(Self::V6 {
                    network,
                    prefix_len,
                })
            }
        }
    }

    /// `(*net.IPNet).Contains`. Addresses from this module are already canonical, but `ip` is
    /// public input, so an IPv4-mapped address is still treated as IPv4 here.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip.to_canonical()) {
            (
                Self::V4 {
                    network,
                    prefix_len,
                },
                IpAddr::V4(v4),
            ) => u32::from(v4) & v4_mask(*prefix_len) == *network,
            (
                Self::V6 {
                    network,
                    prefix_len,
                },
                IpAddr::V6(v6),
            ) => u128::from(v6) & v6_mask(*prefix_len) == *network,
            // Length mismatch (network is v4 but ip is real IPv6, or vice versa): no match.
            _ => false,
        }
    }
}

/// `net.ParseIP`'s result before Go's `To4` normalization: `IpNet::parse` needs the address family
/// as written, because a mapped address parses as a 128-bit address with a 128-bit prefix.
enum ParsedIp {
    V4(std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr),
}

fn parse_ip(s: &str) -> Option<ParsedIp> {
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) => Some(ParsedIp::V4(ip)),
        IpAddr::V6(ip) => Some(ParsedIp::V6(ip)),
    }
}

/// `net.ParseIP`, canonicalized the way `net.IP.String` prints it: an IPv4-mapped address becomes
/// its IPv4 form, so one client cannot hold two rate-limit keys.
fn parse_canonical_ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
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
        !v.trim_matches(|c: char| c == ',' || silo_gocompat::unicode::is_space(c as u32))
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

/// The request fields `clientip.Middleware` reads. Header slices hold every value of that header in
/// request order, unsplit.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestFields<'a> {
    pub remote_addr: &'a str,
    pub host: &'a str,
    pub tls: bool,
    pub x_forwarded_for: &'a [&'a str],
    pub x_real_ip: &'a [&'a str],
    pub forwarded: &'a [&'a str],
    pub x_forwarded_proto: &'a [&'a str],
    pub x_forwarded_host: &'a [&'a str],
    pub upgrade: &'a [&'a str],
    pub connection: &'a [&'a str],
}

/// The values `clientip.Middleware` stores in the request context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// `FromContext`, also the value Go writes to `r.RemoteAddr`.
    pub client_ip: String,
    /// `ForwardedClientUnknown`.
    pub forwarded_client_unknown: bool,
    /// The raw context value behind `RequestScheme`: empty means ambiguous proxy metadata.
    pub scheme: String,
    /// The raw context value behind `RequestHost`.
    pub host: String,
    /// `PeerFromContext`.
    pub peer: String,
}

impl RequestContext {
    /// `clientip.PeerIP`: the transport peer's IP, or empty when the peer is not an IP address.
    pub fn peer_ip(&self) -> String {
        let host = split_host_port(&self.peer).unwrap_or(&self.peer);
        parse_canonical_ip(host)
            .map(|ip| ip.to_string())
            .unwrap_or_default()
    }

    /// `clientip.RequestHost`: an empty context value falls back to `r.Host`, which `Middleware` set
    /// it from, so the context value already is the answer.
    pub fn request_host(&self) -> &str {
        &self.host
    }

    /// `clientip.RequestOrigin`: ambiguous proxy scheme metadata names the transport's scheme.
    pub fn request_origin(&self, tls: bool) -> String {
        let scheme = if self.scheme.is_empty() {
            if tls { "https" } else { "http" }
        } else {
            self.scheme.as_str()
        };
        serialize_origin(scheme, &self.host)
    }
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
    /// is `r.RemoteAddr`; the header slices hold every value of the header, in request order,
    /// unsplit.
    pub fn client_ip(
        &self,
        remote_addr: &str,
        x_forwarded_for: &[&str],
        x_real_ip: &[&str],
        forwarded: &[&str],
    ) -> String {
        normalize(Some(
            self.resolve(remote_addr, x_forwarded_for, x_real_ip, forwarded)
                .ip,
        ))
    }

    /// `Resolver.resolve`.
    pub fn resolve(
        &self,
        remote_addr: &str,
        x_forwarded_for: &[&str],
        x_real_ip: &[&str],
        forwarded: &[&str],
    ) -> Resolved {
        let remote_ip = parse_remote_addr(remote_addr);
        let forwarding_present = has_forwarding_headers(x_forwarded_for, x_real_ip, forwarded);

        if !self.is_trusted(remote_ip) {
            return Resolved {
                ip: remote_ip,
                forwarded_client_unknown: forwarding_present,
            };
        }

        let (ip, unknown) = self.forwarded_for(x_forwarded_for);
        if let Some(ip) = ip {
            return Resolved {
                ip,
                forwarded_client_unknown: unknown,
            };
        }

        if x_real_ip.len() == 1
            && let Some(parsed) = parse_forwarded_addr(trim_space(x_real_ip[0]))
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

    /// `Resolver.forwardedFor`: walks the X-Forwarded-For lines right to left. It returns `None` for
    /// the address when the peer named no address, including when the rightmost entry is junk, so
    /// `resolve` falls through to `X-Real-IP` and then the peer.
    fn forwarded_for(&self, lines: &[&str]) -> (Option<IpAddr>, bool) {
        let mut last: Option<IpAddr> = None;
        for i in (0..lines.len()).rev() {
            let entries: Vec<&str> = lines[i].split(',').collect();
            for j in (0..entries.len()).rev() {
                let entry = trim_space(entries[j]);
                if entry.is_empty() {
                    continue;
                }
                let Some(ip) = parse_forwarded_addr(entry) else {
                    return (last, true);
                };
                if !self.is_trusted(ip) {
                    let forwarded =
                        has_forwarded_entry(&entries[..j]) || has_forwarded_entry(&lines[..i]);
                    return (Some(ip), forwarded);
                }
                last = Some(ip);
            }
        }
        (last, false)
    }

    /// `clientip.Middleware`, as one call: what Go stores in the request context, with scheme and
    /// host computed from the original peer before the client IP replaces it.
    pub fn middleware(&self, request: &RequestFields<'_>) -> RequestContext {
        let websocket = is_websocket_upgrade(
            request.upgrade.first().copied().unwrap_or(""),
            request.connection,
        );
        let scheme = self.request_scheme(
            request.remote_addr,
            request.tls,
            request.x_forwarded_proto,
            websocket,
        );
        let host = self.request_host(request.remote_addr, request.host, request.x_forwarded_host);
        let resolved = self.resolve(
            request.remote_addr,
            request.x_forwarded_for,
            request.x_real_ip,
            request.forwarded,
        );
        RequestContext {
            client_ip: normalize(Some(resolved.ip)),
            forwarded_client_unknown: resolved.forwarded_client_unknown,
            scheme,
            host,
            peer: request.remote_addr.to_owned(),
        }
    }

    /// `Resolver.peerTrusted`: whether the transport peer of `remote_addr` is trusted. `remote_addr`
    /// is the raw peer address (host:port or bare host), exactly as `req.RemoteAddr` would read
    /// before `Middleware` overwrites it.
    pub fn peer_trusted(&self, remote_addr: &str) -> bool {
        let host = split_host_port(remote_addr).unwrap_or(remote_addr);
        parse_canonical_ip(host).is_some_and(|ip| self.is_trusted(ip))
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
        let host = trim_space(x_forwarded_host[0]);
        if host.is_empty() || host.contains([',', '/', '?', '#', '@', ' ', '\t']) {
            return host_header.to_owned();
        }
        host.to_owned()
    }
}

/// `clientip.isWebSocketUpgrade`.
pub fn is_websocket_upgrade(upgrade_header: &str, connection_values: &[&str]) -> bool {
    if !equal_fold(trim_space(upgrade_header), "websocket") {
        return false;
    }
    connection_values.iter().any(|value| {
        value
            .split(',')
            .any(|token| equal_fold(trim_space(token), "upgrade"))
    })
}

/// `clientip.SerializeOrigin`.
pub fn serialize_origin(scheme: &str, host: &str) -> String {
    let scheme = to_lower(trim_space(scheme));
    let (name, port) = url_split_host_port(trim_space(host));
    let mut name = to_lower(name);
    let port = if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
        ""
    } else {
        port
    };
    if name.contains(':') {
        name = format!("[{name}]");
    }
    if port.is_empty() {
        format!("{scheme}://{name}")
    } else {
        format!("{scheme}://{name}:{port}")
    }
}

/// `net/url`'s private `splitHostPort`, behind `URL.Hostname` and `URL.Port`.
fn url_split_host_port(host_port: &str) -> (&str, &str) {
    let mut host = host_port;
    let mut port = "";
    if let Some(colon) = host.rfind(':') {
        let candidate = &host[colon + 1..];
        if candidate.bytes().all(|b| b.is_ascii_digit()) {
            port = candidate;
            host = &host[..colon];
        }
    }
    if host.len() >= 2 && host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    (host, port)
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

/// `net.SplitHostPort`, returning the host; `None` where Go returns an error. A port of Go's control
/// flow, because the error cases decide whether the caller retries the whole string as an address.
fn split_host_port(hostport: &str) -> Option<&str> {
    let colon = hostport.rfind(':')?;
    let (host, after_open, after_close) = if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        if end + 1 != colon {
            return None;
        }
        (&hostport[1..end], 1, end + 1)
    } else {
        let host = &hostport[..colon];
        if host.contains(':') {
            return None;
        }
        (host, 0, 0)
    };
    if hostport[after_open..].contains('[') || hostport[after_close..].contains(']') {
        return None;
    }
    Some(host)
}

/// `clientip.parseUnzonedIP`: parses an IP, dropping an IPv6 zone (`fe80::1%eth0`).
fn parse_unzoned_ip(addr: &str) -> Option<IpAddr> {
    let addr = match addr.find('%') {
        Some(i) if addr[..i].contains(':') => &addr[..i],
        _ => addr,
    };
    parse_canonical_ip(addr)
}

/// `clientip.parseRemoteAddr`: never fails. An unparsable address becomes `0.0.0.0`, Go's
/// `net.IPv4zero` fallback.
fn parse_remote_addr(addr: &str) -> IpAddr {
    let host = split_host_port(addr).unwrap_or(addr);
    parse_canonical_ip(host).unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

/// `clientip.normalize`.
pub fn normalize(ip: Option<IpAddr>) -> String {
    match ip {
        Some(ip) => ip.to_canonical().to_string(),
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
        let resolved = r.resolve("8.8.8.8:1234", &["1.2.3.4"], &[], &[]);
        assert_eq!(resolved.ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert!(resolved.forwarded_client_unknown);
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_xff_entry() {
        let r = resolver("10.0.0.0/8");
        let resolved = r.resolve("10.0.0.1:1234", &["1.2.3.4, 10.0.0.2"], &[], &[]);
        assert_eq!(resolved.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert!(!resolved.forwarded_client_unknown);
    }

    #[test]
    fn trusted_peer_falls_back_to_x_real_ip() {
        let r = resolver("10.0.0.0/8");
        let resolved = r.resolve("10.0.0.1:1234", &[], &["1.2.3.4"], &[]);
        assert_eq!(resolved.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn x_real_ip_never_overrides_a_present_xff_entry() {
        let r = resolver("10.0.0.0/8");
        let resolved = r.resolve("10.0.0.1:1234", &["10.0.0.2"], &["9.9.9.9"], &[]);
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
