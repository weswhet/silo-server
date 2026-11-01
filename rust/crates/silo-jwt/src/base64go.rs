//! `encoding/base64` decoding rules that the `base64` crate does not offer.
//!
//! Go's non-strict decoder skips `\r` and `\n` anywhere in the input and ignores non-zero trailing
//! bits. JWT segments, `enc:v1` bodies, and cursors are all decoded this way, so an input Go accepts
//! has to be accepted here too.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// A byte that is not in the alphabet, or a length no encoder could produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("illegal base64 data")
    }
}

impl std::error::Error for DecodeError {}

fn url_value(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some(u32::from(b - b'A')),
        b'a'..=b'z' => Some(u32::from(b - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(b - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn decode_groups(chars: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if chars.len() % 4 == 1 {
        return Err(DecodeError);
    }
    let mut out = Vec::with_capacity(chars.len() / 4 * 3 + 2);
    for group in chars.chunks(4) {
        let mut acc = 0u32;
        for &c in group {
            acc = (acc << 6) | url_value(c).ok_or(DecodeError)?;
        }
        acc <<= 6 * (4 - group.len()) as u32;
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..group.len()]);
    }
    Ok(out)
}

fn without_newlines(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .filter(|b| *b != b'\r' && *b != b'\n')
        .collect()
}

/// `base64.RawURLEncoding.DecodeString`.
pub fn raw_url_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    decode_groups(&without_newlines(input.as_ref()))
}

/// `base64.URLEncoding.DecodeString`: padding is required.
pub fn url_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    let chars = without_newlines(input.as_ref());
    if !chars.len().is_multiple_of(4) {
        return Err(DecodeError);
    }
    let pad = chars.iter().rev().take_while(|c| **c == b'=').count();
    if pad > 2 {
        return Err(DecodeError);
    }
    decode_groups(&chars[..chars.len() - pad])
}

/// `base64.RawURLEncoding.EncodeToString`.
pub fn raw_url_encode(input: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// `base64.StdEncoding.EncodeToString`.
pub fn std_encode(input: impl AsRef<[u8]>) -> String {
    STANDARD.encode(input)
}
