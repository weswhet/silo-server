//! `internal/nodeauth`: HMAC signatures on the internal calls API servers and proxies make to workers.
//!
//! The MAC key is HKDF of `auth.jwt_secret` under its own label, so it can sign nothing else. The
//! caller supplies the path and query in their final wire form, because a signature over any other
//! spelling fails on the worker.

use silo_gocompat::strings::{equal_fold, trim_space};

use crate::gourl::parse_escaped_path;
use crate::hexgo::{
    ct_eq, decode as hex_decode, encode as hex_encode, hkdf_sha256, hmac_sha256, sha256,
};

/// The Authorization scheme of a signed worker request.
pub const SCHEME: &str = "Silo-Node-HMAC-SHA256";

const MAX_SKEW_SECONDS: i128 = 30;
/// A receiver buffers at most this much body to check its hash.
pub const MAX_BODY_BYTES: usize = 1 << 20;
const KEY_LABEL: &[u8] = b"silo/node-request-auth/v1";
const CANONICAL_VERSION: &str = "silo-node-request-v1";

/// `nodeauth.ErrUnauthorized` and `ErrNoSecret`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NoSecret,
    Unauthorized,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSecret => f.write_str("node auth: shared secret is not configured"),
            Self::Unauthorized => f.write_str("node auth: unauthorized"),
        }
    }
}

impl std::error::Error for Error {}

/// `workerPath`: the escaped path without the path prefix of `node_url`, if it has one. The signature
/// covers the path the worker serves, because a reverse proxy strips its prefix first.
pub fn worker_path(target_escaped_path: &str, node_url: &str) -> String {
    let Ok(base) = parse_escaped_path(node_url) else {
        return target_escaped_path.to_owned();
    };
    let prefix = base.trim_end_matches('/');
    if !prefix.is_empty() {
        let with_slash = format!("{prefix}/");
        if target_escaped_path.starts_with(&with_slash) {
            return target_escaped_path[prefix.len()..].to_owned();
        }
    }
    target_escaped_path.to_owned()
}

/// `requestMAC`. An empty path is the root, which is what a client puts on the wire for it.
pub fn request_mac(
    secret: &str,
    timestamp: &str,
    method: &str,
    path: &str,
    raw_query: &str,
    body_hash: &str,
) -> [u8; 32] {
    let mut key = [0u8; 32];
    hkdf_sha256(secret.as_bytes(), KEY_LABEL, &mut key);
    let path = if path.is_empty() { "/" } else { path };
    let canonical =
        format!("{CANONICAL_VERSION}\n{timestamp}\n{method}\n{path}\n{raw_query}\n{body_hash}");
    hmac_sha256(&key, &[canonical.as_bytes()])
}

/// `Sign`: the Authorization header value, or `None` without a secret. `body` is the final body;
/// `None` means no body.
pub fn sign(
    method: &str,
    target_escaped_path: &str,
    raw_query: &str,
    body: Option<&[u8]>,
    node_url: &str,
    secret: &str,
    now_unix: i64,
) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    let body_hash = hex_encode(sha256(body.unwrap_or_default()));
    let timestamp = now_unix.to_string();
    let path = worker_path(target_escaped_path, node_url);
    let mac = request_mac(secret, &timestamp, method, &path, raw_query, &body_hash);
    Some(format!(
        "{SCHEME} t={timestamp},b={body_hash},sig={}",
        hex_encode(mac)
    ))
}

/// A request whose credential checked out, up to the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// A valid signature. The body must still match with [`Signed::body_matches`].
    Signed(Signed),
    /// The legacy `Bearer <secret>` credential from the previous release.
    LegacyBearer,
}

/// The signed body hash of a request that passed the MAC check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    body_hash: Vec<u8>,
}

impl Signed {
    /// `bodyMatches`. `None` means no body. A body over [`MAX_BODY_BYTES`] never matches.
    pub fn body_matches(&self, body: Option<&[u8]>) -> bool {
        let body = body.unwrap_or_default();
        if body.len() > MAX_BODY_BYTES {
            return false;
        }
        ct_eq(&self.body_hash, &sha256(body))
    }
}

fn parse_params(params: &str) -> Option<(&str, &str, &str)> {
    let (mut timestamp, mut body, mut signature) = ("", "", "");
    for part in params.split(',') {
        let (name, value) = trim_space(part).split_once('=')?;
        match name {
            "t" => timestamp = value,
            "b" => body = value,
            "sig" => signature = value,
            _ => {}
        }
    }
    (!timestamp.is_empty() && !body.is_empty() && !signature.is_empty())
        .then_some((timestamp, body, signature))
}

/// `Verify` up to the body: the MAC is checked before any body is read, so a caller without the secret
/// cannot make a worker buffer one.
pub fn verify_credential(
    authorization: &str,
    method: &str,
    escaped_path: &str,
    raw_query: &str,
    secret: &str,
    now_unix_nanos: i128,
) -> Result<Verified, Error> {
    if secret.is_empty() {
        return Err(Error::NoSecret);
    }
    let (scheme, params) = authorization.split_once(' ').unwrap_or((authorization, ""));
    if equal_fold(scheme, SCHEME) {
        let (timestamp, body, signature) = parse_params(params).ok_or(Error::Unauthorized)?;
        let seconds: i64 = timestamp.parse().map_err(|_| Error::Unauthorized)?;
        let got = hex_decode(signature)
            .filter(|g| g.len() == 32)
            .ok_or(Error::Unauthorized)?;
        let body_hash = hex_decode(body)
            .filter(|b| b.len() == 32)
            .ok_or(Error::Unauthorized)?;
        let want = request_mac(secret, timestamp, method, escaped_path, raw_query, body);
        if !ct_eq(&got, &want) {
            return Err(Error::Unauthorized);
        }
        let skew = now_unix_nanos - i128::from(seconds) * 1_000_000_000;
        if skew.abs() > MAX_SKEW_SECONDS * 1_000_000_000 {
            return Err(Error::Unauthorized);
        }
        return Ok(Verified::Signed(Signed { body_hash }));
    }
    if equal_fold(scheme, "Bearer") {
        if !ct_eq(params.as_bytes(), secret.as_bytes()) {
            return Err(Error::Unauthorized);
        }
        return Ok(Verified::LegacyBearer);
    }
    Err(Error::Unauthorized)
}
