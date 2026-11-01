//! `internal/lantls`: the deployment's local-network TLS key, derived from `SECRET_KEY`, and its pin.
//!
//! Clients learn the pin from the connections document and accept a LAN address only when TLS there
//! presents the same key, so a different derivation locks every client out. The certificate around
//! the key is minted per process and belongs to the listener.

use p256::SecretKey;
use silo_jwt::base64go::std_encode;

use crate::hexgo::{hkdf_sha256, sha256};
use crate::secret::MIN_MASTER_KEY_LEN;

const HKDF_INFO: &str = "silo/lan-tls/v1";
const MAX_DERIVE_ATTEMPTS: usize = 16;
/// The fixed DER prefix of a P-256 SubjectPublicKeyInfo before the uncompressed point.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The master key is short, or no HKDF output was a valid scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// `deriveKey`: moves to the next counter in the rare case the output is not a valid scalar.
pub fn derive_key(master_key: &[u8]) -> Result<SecretKey, Error> {
    if master_key.len() < MIN_MASTER_KEY_LEN {
        return Err(Error(format!(
            "lantls: master key must be at least {MIN_MASTER_KEY_LEN} bytes, got {}",
            master_key.len()
        )));
    }
    for attempt in 0..MAX_DERIVE_ATTEMPTS {
        let info = if attempt > 0 {
            format!("{HKDF_INFO}#{attempt}")
        } else {
            HKDF_INFO.to_owned()
        };
        let mut scalar = [0u8; 32];
        hkdf_sha256(master_key, info.as_bytes(), &mut scalar);
        if let Ok(key) = SecretKey::from_slice(&scalar) {
            return Ok(key);
        }
    }
    Err(Error(format!(
        "lantls: derive key: no valid scalar after {MAX_DERIVE_ATTEMPTS} attempts"
    )))
}

/// The SubjectPublicKeyInfo DER of `key`.
pub fn spki_der(key: &SecretKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = key.public_key().to_encoded_point(false);
    let mut der = Vec::with_capacity(SPKI_PREFIX.len() + point.len());
    der.extend_from_slice(&SPKI_PREFIX);
    der.extend_from_slice(point.as_bytes());
    der
}

/// `lantls.Pin` of the derived key: the standard base64 SHA-256 of the SubjectPublicKeyInfo.
pub fn pin(master_key: &[u8]) -> Result<String, Error> {
    Ok(std_encode(sha256(spki_der(&derive_key(master_key)?))))
}
