//! A distinct loopback source address per client, so Go's peer-keyed checks (rate-limit buckets, the
//! Jellyfin stream grant) do not see every client as one. Linux binds any address in 127/8; macOS only
//! binds configured ones, so there this falls back to the default source and says so at startup.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};
use tokio::net::{TcpSocket, TcpStream};

/// The address `client` connects to Go from. Never 127.0.0.1, which stays this process's own.
pub fn source_for(client: IpAddr) -> Ipv4Addr {
    let digest = Sha256::digest(client.to_canonical().to_string().as_bytes());
    // .0 and .255 are avoided so no address looks like a network or broadcast address.
    let last = 1 + digest[2] % 254;
    let (a, b) = (digest[0], digest[1]);
    if (a, b, last) == (0, 0, 1) {
        return Ipv4Addr::new(127, 0, 1, 1);
    }
    Ipv4Addr::new(127, a, b, last)
}

/// Whether distinct sources work on this host, found out by trying.
pub async fn distinct_sources_available() -> bool {
    let Ok(socket) = TcpSocket::new_v4() else {
        return false;
    };
    socket
        .bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 83, 83, 83)),
            0,
        ))
        .is_ok()
}

static BIND_FAILED: AtomicBool = AtomicBool::new(false);

/// Connects to `upstream`, from the client's source address when `upstream` is on loopback.
pub async fn dial(upstream: SocketAddr, client: IpAddr, distinct: bool) -> io::Result<TcpStream> {
    let stream = if distinct && upstream.ip().is_loopback() && upstream.is_ipv4() {
        let socket = TcpSocket::new_v4()?;
        let source = SocketAddr::new(IpAddr::V4(source_for(client)), 0);
        if let Err(e) = socket.bind(source)
            && !BIND_FAILED.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(error = %e, %source, "binding a per-client source failed; using the default source");
        }
        socket.connect(upstream).await?
    } else {
        TcpStream::connect(upstream).await?
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clients_get_stable_distinct_loopback_sources() {
        let a = source_for("203.0.113.7".parse().unwrap());
        let b = source_for("203.0.113.8".parse().unwrap());
        assert_ne!(a, b);
        assert_eq!(a, source_for("203.0.113.7".parse().unwrap()));
        assert_eq!(a, source_for("::ffff:203.0.113.7".parse().unwrap()));
        assert!(a.is_loopback());
        assert_ne!(a, Ipv4Addr::new(127, 0, 0, 1));
    }
}
