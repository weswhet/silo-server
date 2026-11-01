//! The input checks `encoding/json` will not make: duplicate keys, lone surrogates, quoted numbers.

use silo_gocompat::strconv::quote;

/// `rejectQuotedNumber`.
pub fn reject_quoted_number(raw: &[u8]) -> Result<(), String> {
    if raw.first() == Some(&b'"') {
        return Err("a numeric setting must not be sent as a JSON string".to_owned());
    }
    Ok(())
}

const MAX_JSON_DEPTH: usize = 64;

struct Dup<'a> {
    b: &'a [u8],
    i: usize,
}

// Err carries a finding. A malformed document stops the scan quietly, because the caller's real
// decode reports it with its own message.
enum Stop {
    Malformed,
    Found(String),
}

impl Dup<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }

    fn string(&mut self) -> Result<String, Stop> {
        let start = self.i;
        self.i += 1;
        loop {
            match self.b.get(self.i) {
                None => return Err(Stop::Malformed),
                Some(b'"') => {
                    self.i += 1;
                    let node = crate::gojson::parse(&self.b[start..self.i])
                        .map_err(|_| Stop::Malformed)?;
                    return match node.value {
                        crate::gojson::Value::String(s) => Ok(s),
                        _ => Err(Stop::Malformed),
                    };
                }
                Some(b'\\') => self.i += 2,
                Some(0..=0x1f) => return Err(Stop::Malformed),
                Some(_) => self.i += 1,
            }
        }
    }

    fn scalar(&mut self) -> Result<(), Stop> {
        let start = self.i;
        while self.i < self.b.len()
            && !matches!(
                self.b[self.i],
                b',' | b'}' | b']' | b':' | b' ' | b'\t' | b'\r' | b'\n'
            )
        {
            self.i += 1;
        }
        if silo_gocompat::json::valid(&self.b[start..self.i]) {
            Ok(())
        } else {
            Err(Stop::Malformed)
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), Stop> {
        self.ws();
        match self.b.get(self.i) {
            None => Err(Stop::Malformed),
            Some(b'"') => self.string().map(|_| ()),
            Some(b'{') => {
                if depth >= MAX_JSON_DEPTH {
                    return Err(Stop::Found(too_deep()));
                }
                self.i += 1;
                let mut seen = std::collections::HashSet::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(());
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return Err(Stop::Malformed);
                    }
                    let name = self.string()?;
                    if !seen.insert(name.clone()) {
                        return Err(Stop::Found(format!(
                            "object repeats the property {}",
                            quote(&name)
                        )));
                    }
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(Stop::Malformed);
                    }
                    self.i += 1;
                    self.value(depth + 1)?;
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(());
                        }
                        _ => return Err(Stop::Malformed),
                    }
                }
            }
            Some(b'[') => {
                if depth >= MAX_JSON_DEPTH {
                    return Err(Stop::Found(too_deep()));
                }
                self.i += 1;
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(());
                }
                loop {
                    self.value(depth + 1)?;
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(());
                        }
                        _ => return Err(Stop::Malformed),
                    }
                }
            }
            Some(_) => self.scalar(),
        }
    }
}

fn too_deep() -> String {
    format!("JSON nests deeper than {MAX_JSON_DEPTH} levels")
}

/// `rejectDuplicateKeys`.
pub fn reject_duplicate_keys(raw: &[u8]) -> Result<(), String> {
    let mut d = Dup { b: raw, i: 0 };
    match d.value(0) {
        Err(Stop::Found(msg)) => Err(msg),
        _ => Ok(()),
    }
}

fn parse_hex4(raw: &[u8], at: usize) -> Result<u64, String> {
    if at + 4 > raw.len() {
        return Err("incomplete \\u escape".to_owned());
    }
    let h = &raw[at..at + 4];
    let text = std::str::from_utf8(h).ok();
    match text.and_then(|t| crate::goparse::parse_uint(t, 16, 32).ok()) {
        Some(v) => Ok(v),
        None => Err(format!(
            "malformed \\u escape {}",
            silo_gocompat::strconv::quote_bytes(h)
        )),
    }
}

/// `rejectLoneSurrogates`.
pub fn reject_lone_surrogates(raw: &[u8]) -> Result<(), String> {
    let mut in_string = false;
    let mut i = 0;
    while i < raw.len() {
        if !in_string {
            if raw[i] == b'"' {
                in_string = true;
            }
        } else if raw[i] == b'"' {
            in_string = false;
        } else if raw[i] == b'\\' {
            if i + 1 >= raw.len() {
                return Err("string ends in an incomplete escape".to_owned());
            }
            if raw[i + 1] != b'u' {
                i += 2;
                continue;
            }
            let code = parse_hex4(raw, i + 2)?;
            i += 5;
            if !(0xD800..0xE000).contains(&code) {
                i += 1;
                continue;
            }
            if code >= 0xDC00 {
                return Err(format!(
                    "\\u{code:04X} is a trailing surrogate with no leading surrogate before it"
                ));
            }
            if i + 6 >= raw.len() || raw[i + 1] != b'\\' || raw[i + 2] != b'u' {
                return Err(format!(
                    "\\u{code:04X} is a leading surrogate with no trailing surrogate after it"
                ));
            }
            let low = parse_hex4(raw, i + 3)?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(format!(
                    "\\u{code:04X} is followed by \\u{low:04X}, which is not a trailing surrogate"
                ));
            }
            i += 6;
        }
        i += 1;
    }
    Ok(())
}

/// `bytes.TrimSpace`.
pub fn trim_space_bytes(mut b: &[u8]) -> &[u8] {
    fn is_space_rune(r: char) -> bool {
        silo_gocompat::unicode::is_space(r as u32)
    }
    loop {
        let Some(&c) = b.first() else {
            return b;
        };
        if c < 0x80 {
            if matches!(c, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ') {
                b = &b[1..];
                continue;
            }
            break;
        }
        let n = b.len().min(4);
        let Some(r) = first_rune(&b[..n]) else {
            break;
        };
        if is_space_rune(r) {
            b = &b[r.len_utf8()..];
        } else {
            break;
        }
    }
    loop {
        let Some(&c) = b.last() else {
            return b;
        };
        if c < 0x80 {
            if matches!(c, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ') {
                b = &b[..b.len() - 1];
                continue;
            }
            return b;
        }
        let mut start = b.len() - 1;
        while start > 0 && b.len() - start < 4 && b[start] & 0xC0 == 0x80 {
            start -= 1;
        }
        match std::str::from_utf8(&b[start..])
            .ok()
            .and_then(|s| s.chars().next())
        {
            Some(r) if is_space_rune(r) => b = &b[..start],
            _ => return b,
        }
    }
}

fn first_rune(b: &[u8]) -> Option<char> {
    for len in 1..=b.len() {
        if let Ok(s) = std::str::from_utf8(&b[..len]) {
            return s.chars().next();
        }
    }
    None
}
