//! `strconv` number and boolean parsing with Go's grammar and error text.

use silo_gocompat::strconv::quote;
use std::fmt;

/// Why a `strconv` parse failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumErrorKind {
    Syntax,
    Range,
}

/// `strconv.NumError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumError {
    pub func: &'static str,
    pub num: String,
    pub kind: NumErrorKind,
}

impl fmt::Display for NumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err = match self.kind {
            NumErrorKind::Syntax => "invalid syntax",
            NumErrorKind::Range => "value out of range",
        };
        write!(
            f,
            "strconv.{}: parsing {}: {}",
            self.func,
            quote(&self.num),
            err
        )
    }
}

impl std::error::Error for NumError {}

fn err(func: &'static str, s: &str, kind: NumErrorKind) -> NumError {
    NumError {
        func,
        num: s.to_owned(),
        kind,
    }
}

fn lower(c: u8) -> u8 {
    c | (b'x' - b'X')
}

/// `strconv.ParseUint`. `bits` of 0 means 64.
pub fn parse_uint(s: &str, base: u32, bits: u32) -> Result<u64, NumError> {
    parse_uint_named("ParseUint", s, base, bits)
}

fn parse_uint_named(func: &'static str, s0: &str, base: u32, bits: u32) -> Result<u64, NumError> {
    if s0.is_empty() {
        return Err(err(func, s0, NumErrorKind::Syntax));
    }
    let base0 = base == 0;
    let mut s = s0.as_bytes();
    let mut base = base;
    if base == 0 {
        base = 10;
        if s[0] == b'0' {
            if s.len() >= 3 && lower(s[1]) == b'b' {
                base = 2;
                s = &s[2..];
            } else if s.len() >= 3 && lower(s[1]) == b'o' {
                base = 8;
                s = &s[2..];
            } else if s.len() >= 3 && lower(s[1]) == b'x' {
                base = 16;
                s = &s[2..];
            } else {
                base = 8;
                s = &s[1..];
            }
        }
    }
    let bits = if bits == 0 { 64 } else { bits };
    let max_val: u64 = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let cutoff = u64::MAX / u64::from(base) + 1;
    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in s {
        let d = match c {
            b'_' if base0 => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => c - b'0',
            _ if lower(c).is_ascii_lowercase() => lower(c) - b'a' + 10,
            _ => return Err(err(func, s0, NumErrorKind::Syntax)),
        };
        if u32::from(d) >= base {
            return Err(err(func, s0, NumErrorKind::Syntax));
        }
        if n >= cutoff {
            return Err(err(func, s0, NumErrorKind::Range));
        }
        n *= u64::from(base);
        let n1 = n.wrapping_add(u64::from(d));
        if n1 < n || n1 > max_val {
            return Err(err(func, s0, NumErrorKind::Range));
        }
        n = n1;
    }
    if underscores && !underscore_ok(s0) {
        return Err(err(func, s0, NumErrorKind::Syntax));
    }
    Ok(n)
}

/// `strconv.ParseInt`. `bits` of 0 means 64.
pub fn parse_int(s: &str, base: u32, bits: u32) -> Result<i64, NumError> {
    parse_int_named("ParseInt", s, base, bits)
}

fn parse_int_named(func: &'static str, s0: &str, base: u32, bits: u32) -> Result<i64, NumError> {
    if s0.is_empty() {
        return Err(err(func, s0, NumErrorKind::Syntax));
    }
    let (neg, rest) = match s0.as_bytes()[0] {
        b'+' => (false, &s0[1..]),
        b'-' => (true, &s0[1..]),
        _ => (false, s0),
    };
    let un = parse_uint_named(func, rest, base, bits).map_err(|e| err(func, s0, e.kind))?;
    let bits = if bits == 0 { 64 } else { bits };
    let cutoff = 1u64 << (bits - 1);
    if !neg && un >= cutoff {
        return Err(err(func, s0, NumErrorKind::Range));
    }
    if neg && un > cutoff {
        return Err(err(func, s0, NumErrorKind::Range));
    }
    let n = un as i64;
    Ok(if neg { n.wrapping_neg() } else { n })
}

/// `strconv.Atoi` on a 64-bit platform.
pub fn atoi(s: &str) -> Result<i64, NumError> {
    parse_int_named("Atoi", s, 10, 0)
}

/// `strconv.ParseBool`.
pub fn parse_bool(s: &str) -> Result<bool, NumError> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(err("ParseBool", s, NumErrorKind::Syntax)),
    }
}

fn underscore_ok(s: &str) -> bool {
    let mut i = 0u8;
    let b = s.as_bytes();
    let mut p = 0;
    if !b.is_empty() && (b[0] == b'-' || b[0] == b'+') {
        p = 1;
    }
    let mut hex = false;
    if b.len() - p >= 2 && b[p] == b'0' && matches!(lower(b[p + 1]), b'b' | b'o' | b'x') {
        i = b'0';
        hex = lower(b[p + 1]) == b'x';
        p += 2;
    }
    while p < b.len() {
        let c = b[p];
        if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&lower(c))) {
            i = b'0';
        } else if c == b'_' {
            if i != b'0' {
                return false;
            }
            i = b'_';
        } else {
            if i == b'_' {
                return false;
            }
            i = b'!';
        }
        p += 1;
    }
    i != b'_'
}

fn common_prefix_len_ignore_case(s: &[u8], prefix: &[u8]) -> usize {
    let n = prefix.len().min(s.len());
    for i in 0..n {
        let mut c = s[i];
        if c.is_ascii_uppercase() {
            c += b'a' - b'A';
        }
        if c != prefix[i] {
            return i;
        }
    }
    n
}

fn special(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    let (sign, rest, nsign, signed) = match b[0] {
        b'+' => (1.0, &b[1..], 1, true),
        b'-' => (-1.0, &b[1..], 1, true),
        _ => (1.0, b, 0, false),
    };
    let first = b[0];
    if signed || first == b'i' || first == b'I' {
        let mut n = common_prefix_len_ignore_case(rest, b"infinity");
        if 3 < n && n < 8 {
            n = 3;
        }
        if (n == 3 || n == 8) && nsign + n == b.len() {
            return Some(f64::INFINITY * sign);
        }
        return None;
    }
    if (first == b'n' || first == b'N')
        && common_prefix_len_ignore_case(b, b"nan") == 3
        && b.len() == 3
    {
        return Some(f64::NAN);
    }
    None
}

/// `strconv.ParseFloat(s, 64)`. A value too large returns a range error, a value too small rounds
/// to zero, and hexadecimal floats are accepted, as in Go.
pub fn parse_float(s: &str) -> Result<f64, NumError> {
    const FUNC: &str = "ParseFloat";
    if let Some(v) = special(s) {
        return Ok(v);
    }
    let syntax = || err(FUNC, s, NumErrorKind::Syntax);
    let range = || err(FUNC, s, NumErrorKind::Range);
    let b = s.as_bytes();
    let mut i = 0;
    if b.is_empty() {
        return Err(syntax());
    }
    let neg = b[0] == b'-';
    if b[0] == b'+' || b[0] == b'-' {
        i = 1;
    }
    let mut hex = false;
    if i + 2 < b.len() && b[i] == b'0' && lower(b[i + 1]) == b'x' {
        hex = true;
        i += 2;
    }
    let start = i;
    let mut sawdot = false;
    let mut sawdigits = false;
    let mut underscores = false;
    let mut mantissa: u64 = 0;
    let mut nd = 0usize;
    let mut nd_mant = 0usize;
    let mut dp = 0i64;
    let mut trunc = false;
    while i < b.len() {
        let c = b[i];
        match c {
            b'_' => {
                underscores = true;
                i += 1;
                continue;
            }
            b'.' => {
                if sawdot {
                    break;
                }
                sawdot = true;
                dp = nd as i64;
                i += 1;
                continue;
            }
            b'0'..=b'9' => {
                sawdigits = true;
                if c == b'0' && nd == 0 {
                    dp -= 1;
                    i += 1;
                    continue;
                }
                nd += 1;
                if nd_mant < 16 {
                    mantissa = mantissa * if hex { 16 } else { 10 } + u64::from(c - b'0');
                    nd_mant += 1;
                } else if c != b'0' {
                    trunc = true;
                }
                i += 1;
                continue;
            }
            _ if hex && (b'a'..=b'f').contains(&lower(c)) => {
                sawdigits = true;
                nd += 1;
                if nd_mant < 16 {
                    mantissa = mantissa * 16 + u64::from(lower(c) - b'a' + 10);
                    nd_mant += 1;
                } else {
                    trunc = true;
                }
                i += 1;
                continue;
            }
            _ => break,
        }
    }
    if !sawdigits {
        return Err(syntax());
    }
    if !sawdot {
        dp = nd as i64;
    }
    if hex {
        dp *= 4;
        nd_mant *= 4;
    }
    let mut exp_seen = false;
    let mut exp_value: i64 = 0;
    if i < b.len() && lower(b[i]) == if hex { b'p' } else { b'e' } {
        i += 1;
        if i >= b.len() {
            return Err(syntax());
        }
        let mut esign = 1i64;
        if b[i] == b'+' {
            i += 1;
        } else if b[i] == b'-' {
            i += 1;
            esign = -1;
        }
        if i >= b.len() || !b[i].is_ascii_digit() {
            return Err(syntax());
        }
        let mut e = 0i64;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
            if b[i] == b'_' {
                underscores = true;
                i += 1;
                continue;
            }
            if e < 10000 {
                e = e * 10 + i64::from(b[i] - b'0');
            }
            i += 1;
        }
        exp_value = e * esign;
        exp_seen = true;
    } else if hex {
        return Err(syntax());
    }
    if i != b.len() {
        return Err(syntax());
    }
    if underscores && !underscore_ok(s) {
        return Err(syntax());
    }
    let _ = start;
    if hex {
        let mut exp = 0i64;
        if mantissa != 0 {
            exp = dp - nd_mant as i64 + exp_value;
        }
        let _ = exp_seen;
        return atof_hex(mantissa, exp, neg, trunc).map_err(|()| range());
    }
    let plain = if underscores {
        s.replace('_', "")
    } else {
        s.to_owned()
    };
    match plain.parse::<f64>() {
        Ok(v) if v.is_infinite() => Err(range()),
        Ok(v) => Ok(v),
        Err(_) => Err(syntax()),
    }
}

// atofHex from strconv, for float64.
fn atof_hex(mut mantissa: u64, mut exp: i64, neg: bool, trunc: bool) -> Result<f64, ()> {
    const MANTBITS: i64 = 52;
    const EXPBITS: i64 = 11;
    const BIAS: i64 = -1023;
    let maxexp = (1i64 << EXPBITS) + BIAS - 2;
    let minexp = BIAS + 1;
    exp += MANTBITS;
    while mantissa != 0 && mantissa >> (MANTBITS + 2) == 0 {
        mantissa <<= 1;
        exp -= 1;
    }
    if trunc {
        mantissa |= 1;
    }
    while mantissa >> (1 + MANTBITS + 2) != 0 {
        mantissa = (mantissa >> 1) | (mantissa & 1);
        exp += 1;
    }
    while mantissa > 1 && exp < minexp - 2 {
        mantissa = (mantissa >> 1) | (mantissa & 1);
        exp += 1;
    }
    let mut round = mantissa & 3;
    mantissa >>= 2;
    round |= mantissa & 1;
    exp += 2;
    if round == 3 {
        mantissa += 1;
        if mantissa == 1u64 << (1 + MANTBITS) {
            mantissa >>= 1;
            exp += 1;
        }
    }
    if mantissa >> MANTBITS == 0 {
        exp = BIAS;
    }
    if exp > maxexp {
        return Err(());
    }
    let mut bits = mantissa & ((1u64 << MANTBITS) - 1);
    bits |= (((exp - BIAS) as u64) & ((1u64 << EXPBITS) - 1)) << MANTBITS;
    if neg {
        bits |= 1u64 << 63;
    }
    Ok(f64::from_bits(bits))
}

/// `%g` and `%v` for a float64 in Go's fmt.
pub fn fmt_g(f: f64) -> String {
    silo_gocompat::strconv::format_float(f, b'g', -1, 64)
}
