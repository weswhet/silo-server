//! The trust decision a relay takes away from Go, made here instead.
//!
//! Go's default trusted list includes loopback, so a relay on loopback would make every client a
//! trusted peer: `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP` from anyone would be honored.
//! This module evaluates the same list Go reads and rewrites the forwarding headers so Go resolves
//! what it would have resolved from the client's own connection. `tests/gateway_differential.rs` runs
//! the real `internal/clientip` on both paths and compares them.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use silo_config::gonet::split_host_port;

use crate::http1::RequestHead;

/// `clientip.SettingTrustedProxies`.
pub const SETTING_TRUSTED_PROXIES: &str = "clientip.trusted_proxies";
/// `clientip.DefaultTrustedProxies`.
pub const DEFAULT_TRUSTED_PROXIES: &str =
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128";

/// A `net.IPNet`, with the address in its shortest form as `networkNumberAndMask` compares it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cidr {
    ip: Vec<u8>,
    mask: Vec<u8>,
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn parse_cidr(raw: &str) -> Result<Cidr, String> {
    let bad = || format!("invalid CIDR {raw:?}");
    let (addr, bits) = raw.split_once('/').ok_or_else(bad)?;
    let ip: IpAddr = addr.parse().map_err(|_| bad())?;
    let total: u32 = if ip.is_ipv4() { 32 } else { 128 };
    if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: u32 = bits.parse().map_err(|_| bad())?;
    if n > total {
        return Err(bad());
    }
    let mut mask = vec![0u8; (total / 8) as usize];
    for (i, b) in mask.iter_mut().enumerate() {
        let i = i as u32 * 8;
        *b = if n >= i + 8 {
            0xff
        } else if n > i {
            0xffu8 << (8 - (n - i))
        } else {
            0
        };
    }
    let bytes = ip_bytes(ip);
    // A mapped address with a 16-byte mask compares on its low four bytes.
    if bytes.len() == 4 && mask.len() == 16 {
        mask = mask[12..].to_vec();
    }
    let ip = bytes.iter().zip(&mask).map(|(a, m)| a & m).collect();
    Ok(Cidr { ip, mask })
}

impl Cidr {
    fn contains(&self, ip: IpAddr) -> bool {
        let x = ip_bytes(ip);
        x.len() == self.ip.len()
            && x.iter()
                .zip(&self.mask)
                .zip(&self.ip)
                .all(|((a, m), n)| a & m == *n)
    }
}

/// `clientip.ParseCIDRs`.
fn parse_cidrs(raw: &str) -> Result<Vec<Cidr>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(parse_cidr)
        .collect()
}

/// The live trusted list. A failed reload keeps the last valid one, as `ReloadTrustedCIDRs` does.
#[derive(Debug)]
pub struct TrustList(RwLock<Arc<Vec<Cidr>>>);

impl TrustList {
    pub fn parse(raw: &str) -> Result<Self, String> {
        Ok(Self(RwLock::new(Arc::new(parse_cidrs(raw)?))))
    }

    /// `LoadTrustedCIDRs`'s value handling: empty means the defaults.
    pub fn update(&self, raw: &str) -> Result<(), String> {
        let raw = if raw.is_empty() {
            DEFAULT_TRUSTED_PROXIES
        } else {
            raw
        };
        let next = Arc::new(parse_cidrs(raw)?);
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = next;
        Ok(())
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let list = self.0.read().unwrap_or_else(|e| e.into_inner()).clone();
        list.iter().any(|c| c.contains(ip))
    }
}

/// `parseUnzonedIP`.
fn parse_unzoned_ip(addr: &str) -> Option<IpAddr> {
    let addr = match addr.find('%') {
        Some(i) if addr[..i].contains(':') => &addr[..i],
        _ => addr,
    };
    addr.parse().ok()
}

/// `parseForwardedAddr`.
fn parse_forwarded_addr(addr: &str) -> Option<IpAddr> {
    if let Ok((host, _)) = split_host_port(addr) {
        return parse_unzoned_ip(&host);
    }
    let bracketed = addr.len() > 1 && addr.starts_with('[') && addr.ends_with(']');
    parse_unzoned_ip(if bracketed {
        &addr[1..addr.len() - 1]
    } else {
        addr
    })
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `resolver.forwardedFor`.
fn forwarded_for(trust: &TrustList, lines: &[String]) -> Option<IpAddr> {
    let mut last = None;
    for line in lines.iter().rev() {
        for entry in line.split(',').rev() {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some(ip) = parse_forwarded_addr(entry) else {
                return last;
            };
            if !trust.is_trusted(ip) {
                return Some(ip);
            }
            last = Some(ip);
        }
    }
    last
}

fn has_forwarded_entry(values: &[String]) -> bool {
    values
        .iter()
        .any(|v| v.chars().any(|c| c != ',' && !c.is_whitespace()))
}

/// What to do to a request's forwarding headers before Go sees it.
#[derive(Debug, PartialEq, Eq)]
pub struct Rewrite {
    /// The peer is outside the list: Go must not see anything the client wrote in these.
    pub strip_forwarding: bool,
    /// The value of an `X-Forwarded-For` line to add after any already there.
    pub add_forwarded_for: Option<String>,
    /// The value of an `X-Forwarded-Host` line to add. See `unrewritten_host`.
    pub add_forwarded_host: Option<String>,
}

const FORWARDING_HEADERS: [&str; 5] = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Real-IP",
    "Forwarded",
];

/// An entry that is not an address: to its left the resolver reports the client as unknown
/// (`ForwardedClientUnknown`), which `streamlocation` reads.
const UNKNOWN_ENTRY: &str = "unknown";

/// `url.URL.Hostname` followed by `netip.ParseAddr`.
fn host_is_address(host: &str) -> bool {
    let name = match host.rfind(':') {
        Some(i) if host[i + 1..].bytes().all(|b| b.is_ascii_digit()) => &host[..i],
        _ => host,
    };
    let name = name
        .strip_prefix('[')
        .and_then(|n| n.strip_suffix(']'))
        .unwrap_or(name);
    let unzoned = match name.split_once('%') {
        Some((addr, zone)) if addr.contains(':') && !zone.is_empty() => addr,
        _ => name,
    };
    unzoned.parse::<IpAddr>().is_ok()
}

/// `http.Request.Host`: an absolute-form target's authority, else the `Host` header.
fn request_host(head: &RequestHead) -> Option<String> {
    let target = lossy(&head.target);
    if let Some((scheme, rest)) = target.split_once("://")
        && !scheme.contains('/')
    {
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        let host = authority.rsplit('@').next().unwrap_or_default();
        if !host.is_empty() {
            return Some(host.to_owned());
        }
    }
    head.values("Host").next().map(lossy)
}

/// `bandwidthProbeBaseURL` takes an address in `Host` with any forwarding header and no
/// `X-Forwarded-Host` to mean a proxy rewrote `Host`, and leaves it for the public URL. The header this
/// relay adds must not read as that. Naming the same host keeps every other reader's answer, because
/// each falls back to `Host` when the header is absent.
fn unrewritten_host(head: &RequestHead, stripped: bool) -> Option<String> {
    if !stripped && head.has("X-Forwarded-Host") {
        return None;
    }
    request_host(head).filter(|host| host_is_address(host))
}

/// Works out the rewrite so Go, seeing this relay as a trusted peer, resolves what it would have
/// resolved from `peer` directly. Each branch of `resolver.resolve` has a case here.
pub fn plan(trust: &TrustList, peer: IpAddr, head: &RequestHead) -> Rewrite {
    let peer_text = peer.to_canonical().to_string();
    let forwarded: Vec<String> = head.values("X-Forwarded-For").map(lossy).collect();
    let real_ip: Vec<String> = head.values("X-Real-IP").map(lossy).collect();
    let rfc7239: Vec<String> = head.values("Forwarded").map(lossy).collect();
    let forwarding_named = has_forwarded_entry(&forwarded)
        || has_forwarded_entry(&real_ip)
        || has_forwarded_entry(&rfc7239);

    if !trust.is_trusted(peer) {
        // Go resolves the peer and flags the client unknown if it sent forwarding headers.
        return Rewrite {
            strip_forwarding: true,
            add_forwarded_for: Some(if forwarding_named {
                format!("{UNKNOWN_ENTRY}, {peer_text}")
            } else {
                peer_text
            }),
            add_forwarded_host: if forwarding_named {
                None
            } else {
                unrewritten_host(head, true)
            },
        };
    }

    if forwarded_for(trust, &forwarded).is_some() {
        // The peer is trusted, so the walk steps over it and carries on exactly as it would have.
        return Rewrite {
            strip_forwarding: false,
            add_forwarded_for: Some(peer_text),
            add_forwarded_host: None,
        };
    }

    // The walk named nobody, so Go would read X-Real-IP, then fall back to the peer.
    let real_ip_names_client =
        real_ip.len() == 1 && parse_forwarded_addr(real_ip[0].trim()).is_some();
    if real_ip_names_client {
        return Rewrite {
            strip_forwarding: false,
            add_forwarded_for: None,
            add_forwarded_host: None,
        };
    }
    let junk_rightmost = forwarded
        .iter()
        .flat_map(|l| l.split(','))
        .any(|e| !e.trim().is_empty());
    let add = if forwarding_named && !junk_rightmost {
        format!("{UNKNOWN_ENTRY}, {peer_text}")
    } else {
        peer_text
    };
    Rewrite {
        strip_forwarding: false,
        add_forwarded_for: Some(add),
        add_forwarded_host: if forwarding_named {
            None
        } else {
            unrewritten_host(head, false)
        },
    }
}

/// The request head with the rewrite applied. Every other byte stays as the client sent it.
pub fn apply(buf: &[u8], head: &RequestHead, rewrite: &Rewrite) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.head_len + 64);
    let mut at = 0;
    if rewrite.strip_forwarding {
        for field in &head.fields {
            let forwarding = FORWARDING_HEADERS
                .iter()
                .any(|h| field.name.eq_ignore_ascii_case(h.as_bytes()));
            if forwarding {
                out.extend_from_slice(&buf[at..field.span.start]);
                at = field.span.end;
            }
        }
    }
    out.extend_from_slice(&buf[at..head.terminator]);
    if let Some(value) = &rewrite.add_forwarded_for {
        out.extend_from_slice(b"X-Forwarded-For: ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if let Some(value) = &rewrite.add_forwarded_host {
        out.extend_from_slice(b"X-Forwarded-Host: ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(&buf[head.terminator..head.head_len]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_contains_matches_net_ipnet() {
        let c = parse_cidr("127.0.0.0/8").unwrap();
        assert!(c.contains("127.9.8.7".parse().unwrap()));
        assert!(c.contains("::ffff:127.9.8.7".parse().unwrap()));
        assert!(!c.contains("128.0.0.1".parse().unwrap()));
        let m = parse_cidr("::ffff:10.1.2.3/120").unwrap();
        assert!(m.contains("10.1.2.200".parse().unwrap()));
        assert!(!m.contains("10.1.3.1".parse().unwrap()));
        let v6 = parse_cidr("::1/128").unwrap();
        assert!(v6.contains("::1".parse().unwrap()));
        assert!(!v6.contains("127.0.0.1".parse().unwrap()));
        assert!(parse_cidr("127.0.0.1").is_err());
        assert!(parse_cidr("127.0.0.1/33").is_err());
    }

    #[test]
    fn host_is_address_reads_host_as_the_probe_url_does() {
        for host in [
            "192.0.2.50",
            "192.0.2.50:8080",
            "192.0.2.50:",
            "[2001:db8::1]:8080",
            "[2001:db8::1]",
            "[fe80::1%25en0]:80",
        ] {
            assert!(host_is_address(host), "{host}");
        }
        for host in [
            "silo.example.test",
            "silo.example.test:8080",
            "2001:db8::1",
            "192.0.2.050",
            "[silo.example.test]",
            "",
        ] {
            assert!(!host_is_address(host), "{host}");
        }
    }

    #[test]
    fn a_failed_update_keeps_the_last_list() {
        let t = TrustList::parse("10.0.0.0/8").unwrap();
        assert!(t.update("not a cidr").is_err());
        assert!(t.is_trusted("10.1.1.1".parse().unwrap()));
        t.update("").unwrap();
        assert!(t.is_trusted("127.0.0.1".parse().unwrap()));
    }
}
