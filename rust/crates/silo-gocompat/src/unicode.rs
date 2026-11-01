//! Port of the parts of Go's `unicode` package the server uses, on Go's own tables.
//!
//! Rust's `char` methods differ from Go on purpose-built points (full versus simple case mapping,
//! `Alphabetic` versus category `L`) and track a different Unicode version. Everything here takes
//! `u32` because Go runes can hold surrogates, which `regexp/syntax` iterates over.

use crate::unicode_tables::{CASE_ORBIT, CASE_RANGES, CATEGORIES, RangeTable, WHITE_SPACE};

pub use crate::unicode_tables::{GO_VERSION, UNICODE_VERSION};

/// `unicode.MaxRune`.
pub const MAX_RUNE: u32 = 0x10FFFF;
/// `unicode.ReplacementChar`.
pub const REPLACEMENT: u32 = 0xFFFD;

const UPPER_CASE: usize = 0;
const LOWER_CASE: usize = 1;
const TITLE_CASE: usize = 2;
/// `unicode.UpperLower`, the sentinel delta for alternating upper/lower runs.
const UPPER_LOWER: i32 = MAX_RUNE as i32 + 1;

fn to_case(case: usize, r: u32) -> u32 {
    let idx = CASE_RANGES.partition_point(|range| range.1 < r);
    match CASE_RANGES.get(idx) {
        Some(&(lo, _, delta)) if lo <= r => {
            let d = delta[case];
            if d > MAX_RUNE as i32 {
                // Even offsets in an upper/lower run are upper case and odd offsets are lower
                // case. UPPER_CASE and TITLE_CASE are even, LOWER_CASE is odd.
                debug_assert_eq!(d, UPPER_LOWER);
                lo + (((r - lo) & !1) | (case as u32 & 1))
            } else {
                r.wrapping_add_signed(d)
            }
        }
        _ => r,
    }
}

/// `unicode.ToLower`.
pub fn to_lower_rune(r: u32) -> u32 {
    if r <= 0x7F {
        if (0x41..=0x5A).contains(&r) {
            r + 0x20
        } else {
            r
        }
    } else {
        to_case(LOWER_CASE, r)
    }
}

/// `unicode.ToUpper`.
pub fn to_upper_rune(r: u32) -> u32 {
    if r <= 0x7F {
        if (0x61..=0x7A).contains(&r) {
            r - 0x20
        } else {
            r
        }
    } else {
        to_case(UPPER_CASE, r)
    }
}

/// `unicode.ToTitle`.
pub fn to_title_rune(r: u32) -> u32 {
    if r <= 0x7F {
        if (0x61..=0x7A).contains(&r) {
            r - 0x20
        } else {
            r
        }
    } else {
        to_case(TITLE_CASE, r)
    }
}

/// `unicode.SimpleFold`: the next rune in `r`'s case-fold orbit.
pub fn simple_fold(r: u32) -> u32 {
    if r > MAX_RUNE {
        return r;
    }
    if let Ok(i) = CASE_ORBIT.binary_search_by_key(&r, |entry| entry.0) {
        return CASE_ORBIT[i].1;
    }
    let l = to_lower_rune(r);
    if l != r { l } else { to_upper_rune(r) }
}

/// `unicode.Is`.
pub fn in_table(table: RangeTable, r: u32) -> bool {
    let idx = table.partition_point(|range| range.1 < r);
    match table.get(idx) {
        Some(&(lo, _, stride)) if lo <= r => stride == 1 || (r - lo).is_multiple_of(stride),
        _ => false,
    }
}

/// Looks up an entry in one of the sorted generated table maps.
pub(crate) fn lookup_table(
    map: &'static [(&'static str, RangeTable)],
    name: &str,
) -> Option<RangeTable> {
    map.binary_search_by_key(&name, |entry| entry.0)
        .ok()
        .map(|i| map[i].1)
}

fn category(name: &str) -> RangeTable {
    lookup_table(CATEGORIES, name).expect("generated category table")
}

macro_rules! category_predicate {
    ($(#[$doc:meta])* $fn_name:ident, $cat:literal) => {
        $(#[$doc])*
        pub fn $fn_name(r: u32) -> bool {
            static TABLE: std::sync::LazyLock<RangeTable> = std::sync::LazyLock::new(|| category($cat));
            in_table(*TABLE, r)
        }
    };
}

category_predicate!(
    /// `unicode.IsLetter`: category L. Rust's `char::is_alphabetic` is a wider property.
    is_letter, "L");
category_predicate!(
    /// `unicode.IsDigit`: category Nd.
    is_digit, "Nd");
category_predicate!(
    /// `unicode.IsNumber`: category N. Rust's `char::is_numeric` tracks a different Unicode version.
    is_number, "N");
category_predicate!(
    /// `unicode.IsUpper`: category Lu. Rust's `char::is_uppercase` is a wider property.
    is_upper, "Lu");
category_predicate!(
    /// `unicode.IsLower`: category Ll. Rust's `char::is_lowercase` is a wider property.
    is_lower, "Ll");
category_predicate!(
    /// `unicode.IsTitle`: category Lt.
    is_title, "Lt");
category_predicate!(
    /// `unicode.IsPunct`: category P.
    is_punct, "P");
category_predicate!(
    /// `unicode.IsSymbol`: category S.
    is_symbol, "S");
category_predicate!(
    /// `unicode.IsMark`: category M.
    is_mark, "M");
category_predicate!(
    /// Category Zs, part of `unicode.GraphicRanges`.
    is_zs, "Zs");

/// `unicode.IsSpace`.
pub fn is_space(r: u32) -> bool {
    if r <= 0xFF {
        matches!(r, 0x09..=0x0D | 0x20 | 0x85 | 0xA0)
    } else {
        in_table(WHITE_SPACE, r)
    }
}

/// `unicode.IsControl`: only the Latin-1 C0 and C1 controls.
pub fn is_control(r: u32) -> bool {
    r < 0x20 || (0x7F..=0x9F).contains(&r)
}

/// `unicode.IsPrint`: letters, marks, numbers, punctuation, symbols, and ASCII space.
pub fn is_print(r: u32) -> bool {
    r == 0x20 || is_letter(r) || is_mark(r) || is_number(r) || is_punct(r) || is_symbol(r)
}

/// `unicode.IsGraphic`: [`is_print`] plus the spacing category Zs.
pub fn is_graphic(r: u32) -> bool {
    is_letter(r) || is_mark(r) || is_number(r) || is_punct(r) || is_symbol(r) || is_zs(r)
}
