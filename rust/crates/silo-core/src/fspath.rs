//! `internal/fspath`: file names that are not valid UTF-8, carried as UTF-8 text.
//!
//! An invalid byte `b` becomes U+10FE00+b, and a real code point in U+10FE80..U+10FEFF is escaped byte
//! by byte so that `decode(encode(raw)) == raw` for every input. Every stored path and every
//! `ForLocal` input passes through this.

use std::path::PathBuf;

use crate::utf8go::{RUNE_ERROR, decode_rune, push_rune};

const ESCAPE_BASE: u32 = 0x10FE00;
const ESCAPE_FIRST: u32 = ESCAPE_BASE + 0x80;
const ESCAPE_LAST: u32 = ESCAPE_BASE + 0xff;
const ESCAPE_LEAD_BYTE: u8 = 0xf4;

fn is_escape(r: u32) -> bool {
    (ESCAPE_FIRST..=ESCAPE_LAST).contains(&r)
}

/// `fspath.Encode`. The result is always valid UTF-8.
pub fn encode(raw: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(raw)
        && !raw.contains(&ESCAPE_LEAD_BYTE)
    {
        return text.to_owned();
    }
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 2);
    let mut i = 0;
    while i < raw.len() {
        let (r, size) = decode_rune(&raw[i..]);
        if r == RUNE_ERROR && size == 1 {
            push_rune(&mut out, ESCAPE_BASE + u32::from(raw[i]));
        } else if is_escape(r) {
            for b in &raw[i..i + size] {
                push_rune(&mut out, ESCAPE_BASE + u32::from(*b));
            }
        } else {
            out.extend_from_slice(&raw[i..i + size]);
        }
        i += size;
    }
    String::from_utf8(out).expect("every branch appends valid UTF-8")
}

/// `fspath.Decode`. Input without reserved code points comes back unchanged, raw paths included.
pub fn decode(path: impl AsRef<[u8]>) -> Vec<u8> {
    let path = path.as_ref();
    if !path.contains(&ESCAPE_LEAD_BYTE) {
        return path.to_vec();
    }
    let mut out = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        let (r, size) = decode_rune(&path[i..]);
        if is_escape(r) {
            out.push((r - ESCAPE_BASE) as u8);
        } else {
            out.extend_from_slice(&path[i..i + size]);
        }
        i += size;
    }
    out
}

/// `charmap.Windows1252.DecodeByte` for the high half.
fn windows_1252(b: u8) -> u32 {
    const HIGH: [u32; 32] = [
        0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160,
        0x2039, 0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
        0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
    ];
    if (0x80..0xa0).contains(&b) {
        HIGH[usize::from(b - 0x80)]
    } else {
        u32::from(b)
    }
}

/// `fspath.Display`: each escaped byte reads as Windows-1252, and a byte with no printable character
/// there becomes U+FFFD. Input without escapes comes back unchanged.
pub fn display(path: impl AsRef<[u8]>) -> Vec<u8> {
    let path = path.as_ref();
    if !path.contains(&ESCAPE_LEAD_BYTE) {
        return path.to_vec();
    }
    let mut out = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        let (r, size) = decode_rune(&path[i..]);
        i += size;
        if !is_escape(r) {
            push_rune(&mut out, r);
            continue;
        }
        let decoded = windows_1252((r - ESCAPE_BASE) as u8);
        let control = decoded < 0x20 || (0x7f..0xa0).contains(&decoded);
        push_rune(&mut out, if control { RUNE_ERROR } else { decoded });
    }
    out
}

/// `fspath.IsEncoded`.
pub fn is_encoded(path: impl AsRef<[u8]>) -> bool {
    let path = path.as_ref();
    if !path.contains(&ESCAPE_LEAD_BYTE) {
        return false;
    }
    let mut i = 0;
    while i < path.len() {
        let (r, size) = decode_rune(&path[i..]);
        if is_escape(r) {
            return true;
        }
        i += size;
    }
    false
}

/// The path to hand a system call: what the Go wrappers (`fspath.Open`, `Stat`, `Command`, ...) pass
/// after decoding.
#[cfg(unix)]
pub fn os_path(path: impl AsRef<[u8]>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_vec(decode(path)))
}
