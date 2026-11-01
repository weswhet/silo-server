//! `internal/settingscontract`'s canonical JSON and contract ETag.
//!
//! This is the repository's own reading of RFC 8785: keys sort by Go's `sort.Strings` byte order rather
//! than UTF-16 code units, and strings escape only what `JSON.stringify` must. Two servers built from
//! the same manifest produce identical bytes, which is what makes the ETag comparable.

use std::collections::BTreeMap;

use silo_gocompat::strconv::format_float;

use crate::hexgo::encode as hex_encode;

/// Canonicalization refused the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// A JSON tree that keeps number text and rejects what `decodeJSON` rejects.
enum Node {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<Node>),
    Object(BTreeMap<Vec<u8>, Node>),
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> u8 {
        self.data.get(self.pos).copied().unwrap_or(0)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), b' ' | b'\t' | b'\r' | b'\n') {
            self.pos += 1;
        }
    }

    fn string(&mut self) -> Result<String, Error> {
        let start = self.pos;
        self.pos += 1;
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b'\\' => {
                    if self.data[self.pos + 1] == b'u' {
                        let hi = self.hex4(self.pos + 2);
                        if (0xdc00..0xe000).contains(&hi) {
                            return Err(Error(
                                "canonicalization refused a lone surrogate".to_owned(),
                            ));
                        }
                        if (0xd800..0xdc00).contains(&hi) {
                            let paired = self.data.get(self.pos + 6) == Some(&b'\\')
                                && self.data.get(self.pos + 7) == Some(&b'u')
                                && (0xdc00..0xe000).contains(&self.hex4(self.pos + 8));
                            if !paired {
                                return Err(Error(
                                    "canonicalization refused a lone surrogate".to_owned(),
                                ));
                            }
                            self.pos += 6;
                        }
                        self.pos += 6;
                    } else {
                        self.pos += 2;
                    }
                }
                b'"' => {
                    self.pos += 1;
                    break;
                }
                _ => self.pos += 1,
            }
        }
        let value = silo_jwt::gojson::parse_value(&self.data[start..self.pos])
            .map_err(|e| Error(e.to_string()))?;
        Ok(value.as_str().unwrap_or_default().to_owned())
    }

    fn hex4(&self, at: usize) -> u32 {
        self.data
            .get(at..at + 4)
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap_or(0)
    }

    fn value(&mut self) -> Result<Node, Error> {
        self.ws();
        match self.peek() {
            b'n' => {
                self.pos += 4;
                Ok(Node::Null)
            }
            b't' => {
                self.pos += 4;
                Ok(Node::Bool(true))
            }
            b'f' => {
                self.pos += 5;
                Ok(Node::Bool(false))
            }
            b'"' => Ok(Node::Str(self.string()?)),
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.ws();
                    match self.peek() {
                        b']' => {
                            self.pos += 1;
                            return Ok(Node::Array(items));
                        }
                        b',' => self.pos += 1,
                        _ => items.push(self.value()?),
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                let mut map = BTreeMap::new();
                loop {
                    self.ws();
                    match self.peek() {
                        b'}' => {
                            self.pos += 1;
                            return Ok(Node::Object(map));
                        }
                        b',' => self.pos += 1,
                        _ => {
                            let key = self.string()?;
                            self.ws();
                            self.pos += 1;
                            let value = self.value()?;
                            if map.insert(key.clone().into_bytes(), value).is_some() {
                                return Err(Error(format!(
                                    "canonicalization refused a duplicate key: {key}"
                                )));
                            }
                        }
                    }
                }
            }
            _ => {
                let start = self.pos;
                while matches!(self.peek(), b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                    self.pos += 1;
                }
                Ok(Node::Number(
                    String::from_utf8_lossy(&self.data[start..self.pos]).into_owned(),
                ))
            }
        }
    }
}

fn parse(raw: &[u8]) -> Result<Node, Error> {
    silo_gocompat::json::check_valid(raw)
        .map_err(|e| Error(format!("parsing JSON for canonicalization: {e}")))?;
    let mut parser = Parser { data: raw, pos: 0 };
    parser.value()
}

fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `formatECMAScript`: ECMA-262 `Number::toString` for radix 10.
pub fn format_ecmascript(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    let (sign, value) = if value < 0.0 {
        ("-", -value)
    } else {
        ("", value)
    };
    let scientific = format_float(value, b'e', -1, 64);
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("'e' format always has an exponent");
    let exponent: i32 = exponent.parse().expect("the exponent is an integer");
    let digits = mantissa.replacen('.', "", 1);
    let k = digits.len() as i32;
    let n = exponent + 1;
    if k <= n && n <= 21 {
        return format!("{sign}{digits}{}", "0".repeat((n - k) as usize));
    }
    if 0 < n && n <= 21 {
        return format!("{sign}{}.{}", &digits[..n as usize], &digits[n as usize..]);
    }
    if -6 < n && n <= 0 {
        return format!("{sign}0.{}{digits}", "0".repeat((-n) as usize));
    }
    let suffix = if n - 1 < 0 {
        format!("e-{}", 1 - n)
    } else {
        format!("e+{}", n - 1)
    };
    if k == 1 {
        return format!("{sign}{digits}{suffix}");
    }
    format!("{sign}{}.{}{suffix}", &digits[..1], &digits[1..])
}

fn write_node(out: &mut String, node: &Node) -> Result<(), Error> {
    match node {
        Node::Null => out.push_str("null"),
        Node::Bool(true) => out.push_str("true"),
        Node::Bool(false) => out.push_str("false"),
        Node::Number(text) => {
            let parsed: f64 = text
                .parse()
                .map_err(|_| Error(format!("parsing number {text}")))?;
            if parsed.is_infinite() || parsed.is_nan() {
                return Err(Error(format!("parsing number {text}: value out of range")));
            }
            out.push_str(&format_ecmascript(parsed));
        }
        Node::Str(s) => write_string(out, s),
        Node::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_node(out, item)?;
            }
            out.push(']');
        }
        Node::Object(map) => {
            out.push('{');
            for (i, (key, value)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, std::str::from_utf8(key).unwrap_or_default());
                out.push(':');
                write_node(out, value)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `canonicalize`.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let node = parse(raw)?;
    let mut out = String::new();
    write_node(&mut out, &node)?;
    Ok(out.into_bytes())
}

/// `buildPublic`: the manifest without its maintainer-only `notes`.
pub fn canonicalize_public(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let mut node = parse(raw)?;
    if let Node::Object(root) = &mut node
        && let Some(Node::Array(definitions)) = root.get_mut(b"definitions".as_slice())
    {
        for def in definitions {
            if let Node::Object(map) = def {
                map.remove(b"notes".as_slice());
            }
        }
    }
    let mut out = String::new();
    write_node(&mut out, &node)?;
    Ok(out.into_bytes())
}

/// `digestWithSchemas`: `"<sha256 hex>"` of a canonical manifest and every value schema, keyed by file
/// name. `schemas` holds `(file name, raw bytes)` and need not be sorted.
pub fn digest_with_schemas(
    manifest: &[u8],
    schemas: &[(String, Vec<u8>)],
) -> Result<String, Error> {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&(String, Vec<u8>)> = schemas.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut digest = Sha256::new();
    digest.update(manifest);
    for (name, raw) in sorted {
        let canonical = canonicalize(raw)?;
        digest.update(format!("\n{}:{name}\n{}:", name.len(), canonical.len()).as_bytes());
        digest.update(&canonical);
    }
    Ok(format!("\"{}\"", hex_encode(digest.finalize())))
}
