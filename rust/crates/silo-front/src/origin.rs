//! The origin log: which side answered each request, written outside the response so it cannot
//! change the header set the harness compares. Enabled only by `SILO_FRONT_ORIGIN_LOG`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Answered by Rust.
    Native,
    /// Forwarded to Go.
    Go,
    /// Refused by the relay's own request reader; neither row nor Go saw it.
    Reject,
    /// Not HTTP on this port: a raw tunnel to Go.
    Tunnel,
}

impl Origin {
    fn name(self) -> &'static str {
        match self {
            Origin::Native => "native",
            Origin::Go => "go",
            Origin::Reject => "reject",
            Origin::Tunnel => "tunnel",
        }
    }
}

#[derive(Serialize)]
struct Line<'a> {
    listener: &'a str,
    origin: &'a str,
    method: &'a str,
    target: &'a str,
    peer: String,
}

/// Appends one JSON line per request. Each line is a single `write` on an `O_APPEND` file, done before
/// the request goes anywhere, so a client holding a response can read the line for it.
#[derive(Debug)]
pub struct OriginLog(File);

impl OriginLog {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map(Self)
    }

    pub fn record(
        &self,
        listener: &str,
        origin: Origin,
        method: &str,
        target: &[u8],
        peer: IpAddr,
    ) {
        let target = String::from_utf8_lossy(target);
        let line = Line {
            listener,
            origin: origin.name(),
            method,
            target: &target,
            peer: peer.to_string(),
        };
        let Ok(mut text) = silo_gocompat::json::marshal(&line) else {
            return;
        };
        text.push(b'\n');
        if let Err(e) = (&self.0).write_all(&text) {
            tracing::error!(error = %e, "origin log write failed");
        }
    }
}
