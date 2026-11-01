//! Port of the case-mapping and whitespace parts of Go's `strings` package.

use std::borrow::Cow;

use crate::unicode::{is_space, simple_fold, to_lower_rune, to_upper_rune};

fn map_runes(s: &str, mapping: fn(u32) -> u32) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        // Go's case maps never produce a surrogate or an out-of-range rune.
        out.push(char::from_u32(mapping(c as u32)).unwrap_or(c));
    }
    out
}

/// `strings.ToLower`. Maps rune by rune with `unicode.ToLower`: `İ` becomes `i`, not `i̇`, and a
/// final `Σ` becomes `σ`, not `ς`.
pub fn to_lower(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    map_runes(s, to_lower_rune)
}

/// `strings.ToUpper`. Maps rune by rune with `unicode.ToUpper`: `ß` stays `ß`, not `SS`.
pub fn to_upper(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_uppercase();
    }
    map_runes(s, to_upper_rune)
}

/// `strings.EqualFold`. Compares by Unicode simple folding, so `K` (U+212A) equals `k` and `ſ`
/// (U+017F) equals `s`, but `ß` does not equal `SS`.
pub fn equal_fold(s: &str, t: &str) -> bool {
    let mut left = s.chars();
    let mut right = t.chars();
    loop {
        let (sc, tc) = match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(sc), Some(tc)) => (sc as u32, tc as u32),
            _ => return false,
        };
        if sc == tc {
            continue;
        }
        let (lo, hi) = if tc < sc { (tc, sc) } else { (sc, tc) };
        if hi < 0x80 {
            if (0x41..=0x5A).contains(&lo) && hi == lo + 0x20 {
                continue;
            }
            return false;
        }
        // simple_fold(x) returns the next equivalent rune > x or wraps around to smaller values.
        let mut r = simple_fold(lo);
        while r != lo && r < hi {
            r = simple_fold(r);
        }
        if r != hi {
            return false;
        }
    }
}

/// `strings.TrimSpace`.
pub fn trim_space(s: &str) -> &str {
    s.trim_matches(|c| is_space(c as u32))
}

/// `strings.Fields`.
pub fn fields(s: &str) -> Vec<&str> {
    s.split(|c| is_space(c as u32))
        .filter(|field| !field.is_empty())
        .collect()
}

/// Converts bytes to the string Go sees when it decodes them rune by rune (`for range`,
/// `[]rune(s)`, `strings.Map`): each undecodable byte becomes one U+FFFD.
///
/// `String::from_utf8_lossy` is not equivalent, because it replaces a maximal invalid sequence
/// with a single U+FFFD. `to_lower(&decode_runes(b))` and `equal_fold` over decoded bytes match
/// Go's results on the same invalid input.
pub fn decode_runes(mut bytes: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => {
            let mut out = String::with_capacity(bytes.len());
            while !bytes.is_empty() {
                match std::str::from_utf8(bytes) {
                    Ok(s) => {
                        out.push_str(s);
                        break;
                    }
                    Err(e) => {
                        let (valid, rest) = bytes.split_at(e.valid_up_to());
                        out.push_str(std::str::from_utf8(valid).unwrap_or_default());
                        out.push('\u{FFFD}');
                        bytes = &rest[1..];
                    }
                }
            }
            Cow::Owned(out)
        }
    }
}
