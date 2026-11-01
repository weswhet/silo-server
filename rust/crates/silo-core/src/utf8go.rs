//! `unicode/utf8.DecodeRune` for byte strings that may not be valid UTF-8.

/// U+FFFD, which Go returns with a size of 1 for an invalid byte.
pub const RUNE_ERROR: u32 = 0xfffd;

/// `utf8.DecodeRune`: the first rune and its width. Empty input is `(RUNE_ERROR, 0)`.
pub fn decode_rune(p: &[u8]) -> (u32, usize) {
    let Some(&b0) = p.first() else {
        return (RUNE_ERROR, 0);
    };
    if b0 < 0x80 {
        return (u32::from(b0), 1);
    }
    let (len, low, high) = match b0 {
        0xc2..=0xdf => (2, 0x80, 0xbf),
        0xe0 => (3, 0xa0, 0xbf),
        0xe1..=0xec | 0xee | 0xef => (3, 0x80, 0xbf),
        0xed => (3, 0x80, 0x9f),
        0xf0 => (4, 0x90, 0xbf),
        0xf1..=0xf3 => (4, 0x80, 0xbf),
        0xf4 => (4, 0x80, 0x8f),
        _ => return (RUNE_ERROR, 1),
    };
    if p.len() < len || !(low..=high).contains(&p[1]) {
        return (RUNE_ERROR, 1);
    }
    let mut rune = u32::from(b0) & (0xff >> (len + 1));
    rune = (rune << 6) | u32::from(p[1] & 0x3f);
    for &b in &p[2..len] {
        if !(0x80..=0xbf).contains(&b) {
            return (RUNE_ERROR, 1);
        }
        rune = (rune << 6) | u32::from(b & 0x3f);
    }
    (rune, len)
}

/// Appends `rune` as UTF-8 the way `strings.Builder.WriteRune` does.
pub fn push_rune(out: &mut Vec<u8>, rune: u32) {
    let c = char::from_u32(rune).unwrap_or('\u{fffd}');
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}
