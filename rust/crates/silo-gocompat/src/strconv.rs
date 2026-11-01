//! Port of the `strconv` formatting functions the server depends on.

use crate::unicode::is_print;

/// `strconv.Quote` for a string.
pub fn quote(s: &str) -> String {
    quote_bytes(s.as_bytes())
}

/// `strconv.Quote` for arbitrary bytes, the form Go strings can take.
pub fn quote_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    let mut rest = bytes;
    while let Some(&first) = rest.first() {
        if first < 0x80 {
            push_escaped_rune(&mut out, u32::from(first));
            rest = &rest[1..];
            continue;
        }
        match first_rune(rest) {
            Some(c) => {
                push_escaped_rune(&mut out, c as u32);
                rest = &rest[c.len_utf8()..];
            }
            None => {
                out.push_str(&format!("\\x{first:02x}"));
                rest = &rest[1..];
            }
        }
    }
    out.push('"');
    out
}

fn first_rune(bytes: &[u8]) -> Option<char> {
    let len = bytes.len().min(4);
    let prefix = &bytes[..len];
    let valid = match std::str::from_utf8(prefix) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&prefix[..e.valid_up_to()]).ok()?,
    };
    valid.chars().next()
}

fn push_escaped_rune(out: &mut String, r: u32) {
    match r {
        0x22 => out.push_str("\\\""),
        0x5C => out.push_str("\\\\"),
        _ if is_print(r) => out.push(char::from_u32(r).unwrap_or('\u{FFFD}')),
        0x07 => out.push_str("\\a"),
        0x08 => out.push_str("\\b"),
        0x0C => out.push_str("\\f"),
        0x0A => out.push_str("\\n"),
        0x0D => out.push_str("\\r"),
        0x09 => out.push_str("\\t"),
        0x0B => out.push_str("\\v"),
        _ if r < 0x20 || r == 0x7F => out.push_str(&format!("\\x{r:02x}")),
        _ if r < 0x10000 => out.push_str(&format!("\\u{r:04x}")),
        _ => out.push_str(&format!("\\U{r:08x}")),
    }
}

struct Digits {
    digits: Vec<u8>,
    /// Decimal point position, as in Go's `decimalSlice.dp`.
    dp: i32,
}

/// Parses Rust's `{:e}` output for a finite positive value into digits and a decimal point.
fn parse_exp(text: &str) -> Digits {
    let (mantissa, exp) = text.split_once('e').unwrap_or((text, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: Vec<u8> = mantissa.bytes().filter(u8::is_ascii_digit).collect();
    let mut digits = digits;
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits.pop();
    }
    if digits == *b"0" {
        return Digits {
            digits: Vec::new(),
            dp: 0,
        };
    }
    Digits {
        digits,
        dp: exp + 1,
    }
}

/// The shortest digits that round-trip, closest to the exact value, as Go's Dragonbox picks them.
///
/// Rust's `{:e}` finds the same digit count and the same closest candidate, except that it rounds an
/// exact tie up where Go rounds it to even: 2041628.25 as a float32 is `2041628.2` in Go. A tie needs
/// a value whose exact expansion is one digit longer than the shortest form, which takes about as many
/// digits as the type can carry, so shorter results skip this check.
fn shortest_digits(abs: f64, bits: u32) -> Digits {
    let (digits, min_tie_digits) = if bits == 32 {
        (parse_exp(&format!("{:e}", abs as f32)), 6)
    } else {
        (parse_exp(&format!("{abs:e}")), 15)
    };
    if digits.digits.len() < min_tie_digits {
        return digits;
    }
    // A float32 widens to f64 exactly, so this is the exact value in both cases.
    let exact = exact_decimal(abs);
    let n = digits.digits.len();
    if exact.digits.len() != n + 1 || exact.digits[n] != b'5' {
        return digits;
    }
    let mut even = exact;
    round_digits(&mut even, n as i32);
    let round_trips = {
        let text = format!(
            "{}e{}",
            std::str::from_utf8(&even.digits).unwrap_or("0"),
            i64::from(even.dp) - even.digits.len() as i64
        );
        if bits == 32 {
            text.parse::<f32>().is_ok_and(|v| v == abs as f32)
        } else {
            text.parse::<f64>().is_ok_and(|v| v == abs)
        }
    };
    if round_trips { even } else { digits }
}

/// Exact decimal expansion of a finite positive float, as digit string and decimal point.
fn exact_decimal(abs: f64) -> Digits {
    // No f64 has more than 767 significant decimal digits, so this precision prints the exact
    // binary value. parse_exp removes the trailing zeros.
    parse_exp(&format!("{abs:.800e}"))
}

/// Port of Go's `decimal.Round`: an exact tie rounds to even, and a negative `nd` changes nothing.
fn round_digits(d: &mut Digits, nd: i32) {
    if nd < 0 || nd as usize >= d.digits.len() {
        return;
    }
    let nd = nd as usize;
    let up = if d.digits[nd] == b'5' && nd + 1 == d.digits.len() {
        nd > 0 && !(d.digits[nd - 1] - b'0').is_multiple_of(2)
    } else {
        d.digits[nd] >= b'5'
    };
    if up {
        for i in (0..nd).rev() {
            if d.digits[i] < b'9' {
                d.digits[i] += 1;
                d.digits.truncate(i + 1);
                return;
            }
        }
        // All nines, or no digit to carry into: a single 1 with an adjusted decimal point.
        d.digits.truncate(1);
        d.digits[0] = b'1';
        d.dp += 1;
    } else {
        d.digits.truncate(nd);
        while d.digits.last() == Some(&b'0') {
            d.digits.pop();
        }
        if d.digits.is_empty() {
            d.dp = 0;
        }
    }
}

fn fmt_e(out: &mut String, neg: bool, d: &Digits, prec: i32, fmt: u8) {
    if neg {
        out.push('-');
    }
    out.push(if d.digits.is_empty() {
        '0'
    } else {
        d.digits[0] as char
    });
    if prec > 0 {
        out.push('.');
        let mut i = 1usize;
        let end = d.digits.len().min(prec as usize + 1);
        if i < end {
            out.push_str(std::str::from_utf8(&d.digits[i..end]).unwrap_or_default());
            i = end;
        }
        while i <= prec as usize {
            out.push('0');
            i += 1;
        }
    }
    out.push(fmt as char);
    let mut exp = d.dp - 1;
    if d.digits.is_empty() {
        exp = 0;
    }
    if exp < 0 {
        out.push('-');
        exp = -exp;
    } else {
        out.push('+');
    }
    if exp < 10 {
        out.push('0');
    }
    out.push_str(&exp.to_string());
}

fn fmt_f(out: &mut String, neg: bool, d: &Digits, prec: i32) {
    if neg {
        out.push('-');
    }
    if d.dp > 0 {
        let dp = d.dp as usize;
        let m = d.digits.len().min(dp);
        out.push_str(std::str::from_utf8(&d.digits[..m]).unwrap_or_default());
        for _ in m..dp {
            out.push('0');
        }
    } else {
        out.push('0');
    }
    if prec > 0 {
        out.push('.');
        for i in 0..prec {
            let j = i64::from(d.dp) + i64::from(i);
            let ch = if j >= 0 && (j as usize) < d.digits.len() {
                d.digits[j as usize]
            } else {
                b'0'
            };
            out.push(ch as char);
        }
    }
}

/// `strconv.FormatFloat` for the formats `e`, `E`, `f`, `g`, and `G`.
///
/// `bits` is 32 or 64. With `bits == 32` the value is treated as a `float32`.
pub fn format_float(f: f64, fmt: u8, prec: i32, bits: u32) -> String {
    let f = if bits == 32 { f64::from(f as f32) } else { f };
    if f.is_nan() {
        return "NaN".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 {
            "+Inf".to_string()
        } else {
            "-Inf".to_string()
        };
    }
    let neg = f.is_sign_negative();
    let abs = f.abs();
    let shortest = prec < 0;
    let mut prec = prec;
    let digs = if shortest {
        let d = if abs == 0.0 {
            Digits {
                digits: Vec::new(),
                dp: 0,
            }
        } else {
            shortest_digits(abs, bits)
        };
        match fmt {
            b'e' | b'E' => prec = d.digits.len() as i32 - 1,
            b'f' => prec = (d.digits.len() as i32 - d.dp).max(0),
            b'g' | b'G' => prec = d.digits.len() as i32,
            _ => {}
        }
        d
    } else {
        let mut d = if abs == 0.0 {
            Digits {
                digits: Vec::new(),
                dp: 0,
            }
        } else {
            exact_decimal(abs)
        };
        match fmt {
            b'e' | b'E' => round_digits(&mut d, prec.saturating_add(1)),
            b'f' => {
                let nd = d.dp.saturating_add(prec);
                round_digits(&mut d, nd);
            }
            b'g' | b'G' => {
                if prec == 0 {
                    prec = 1;
                }
                round_digits(&mut d, prec);
            }
            _ => {}
        }
        d
    };
    let mut out = String::new();
    match fmt {
        b'e' | b'E' => fmt_e(&mut out, neg, &digs, prec, fmt),
        b'f' => fmt_f(&mut out, neg, &digs, prec),
        b'g' | b'G' => {
            let mut eprec = prec;
            if eprec > digs.digits.len() as i32 && digs.digits.len() as i32 >= digs.dp {
                eprec = digs.digits.len() as i32;
            }
            // %e is used if the exponent from the conversion is less than -4 or greater than or
            // equal to the precision. If precision was the shortest possible, use precision 6
            // for this decision.
            if shortest {
                eprec = 6;
            }
            let exp = digs.dp - 1;
            if exp < -4 || exp >= eprec {
                if prec > digs.digits.len() as i32 {
                    prec = digs.digits.len() as i32;
                }
                let e = if fmt == b'g' { b'e' } else { b'E' };
                fmt_e(&mut out, neg, &digs, prec - 1, e);
            } else {
                if prec > digs.dp {
                    prec = digs.digits.len() as i32;
                }
                fmt_f(&mut out, neg, &digs, (prec - digs.dp).max(0));
            }
        }
        _ => {
            out.push('%');
            out.push(fmt as char);
        }
    }
    out
}
