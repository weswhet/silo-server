//! `github.com/google/uuid`: parsing, name-based IDs, and the canonical text.

use sha1::{Digest, Sha1};
use silo_gocompat::strings::equal_fold;

/// A UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uuid(pub [u8; 16]);

/// `uuid.NameSpaceURL`.
pub const NAMESPACE_URL: Uuid = Uuid([
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);
/// `uuid.NameSpaceOID`.
pub const NAMESPACE_OID: Uuid = Uuid([
    0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

fn xtob(a: u8, b: u8) -> Option<u8> {
    let high = (a as char).to_digit(16)?;
    let low = (b as char).to_digit(16)?;
    Some((high << 4 | low) as u8)
}

impl Uuid {
    /// `uuid.NewSHA1`.
    pub fn new_sha1(space: Uuid, data: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha1::new();
        hasher.update(space.0);
        hasher.update(data);
        let digest = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out[6] = (out[6] & 0x0f) | 0x50;
        out[8] = (out[8] & 0x3f) | 0x80;
        Self(out)
    }

    /// `uuid.Parse`: dashed, `urn:uuid:`, braced (the closing brace is not checked), or compact.
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        let body: &[u8] = match b.len() {
            36 => b,
            45 => {
                let prefix = std::str::from_utf8(&b[..9]).ok()?;
                if !equal_fold(prefix, "urn:uuid:") {
                    return None;
                }
                &b[9..]
            }
            38 => &b[1..],
            32 => {
                let mut out = [0u8; 16];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = xtob(b[i * 2], b[i * 2 + 1])?;
                }
                return Some(Self(out));
            }
            _ => return None,
        };
        if body[8] != b'-' || body[13] != b'-' || body[18] != b'-' || body[23] != b'-' {
            return None;
        }
        const OFFSETS: [usize; 16] = [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34];
        let mut out = [0u8; 16];
        for (slot, x) in out.iter_mut().zip(OFFSETS) {
            *slot = xtob(body[x], body[x + 1])?;
        }
        Some(Self(out))
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = crate::hexgo::encode(self.0);
        write!(
            f,
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        )
    }
}
