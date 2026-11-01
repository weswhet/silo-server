//! A JSON value tree with the properties settings code relies on from `encoding/json` with
//! `UseNumber`: number literals stay text, and each node remembers its bytes, the way a
//! `json.RawMessage` field does. serde_json would either round floats or need `arbitrary_precision`,
//! which changes behavior for every crate in the workspace.

use silo_gocompat::json::check_valid;

/// One decoded value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Node>),
    /// Members in document order. A repeated name keeps only its last value, at the first position.
    Object(Vec<(String, Node)>),
}

/// A value and where it sits in the source.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub value: Value,
    pub start: usize,
    pub end: usize,
}

impl Node {
    pub fn raw<'a>(&self, source: &'a [u8]) -> &'a [u8] {
        &source[self.start..self.end]
    }

    pub fn get(&self, name: &str) -> Option<&Node> {
        match &self.value {
            Value::Object(m) => m.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The name `encoding/json` uses for this kind in a type error.
    pub fn kind_name(&self) -> &'static str {
        match self.value {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

const MAX_DEPTH: usize = 10000;

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Node, ()> {
        if depth > MAX_DEPTH {
            return Err(());
        }
        self.ws();
        let start = self.i;
        let c = *self.b.get(self.i).ok_or(())?;
        let value = match c {
            b'n' => {
                self.lit(b"null")?;
                Value::Null
            }
            b't' => {
                self.lit(b"true")?;
                Value::Bool(true)
            }
            b'f' => {
                self.lit(b"false")?;
                Value::Bool(false)
            }
            b'"' => Value::String(self.string()?),
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                } else {
                    loop {
                        items.push(self.value(depth + 1)?);
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err(()),
                        }
                    }
                }
                Value::Array(items)
            }
            b'{' => {
                self.i += 1;
                let mut members: Vec<(String, Node)> = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        if self.b.get(self.i) != Some(&b'"') {
                            return Err(());
                        }
                        let name = self.string()?;
                        self.ws();
                        if self.b.get(self.i) != Some(&b':') {
                            return Err(());
                        }
                        self.i += 1;
                        let v = self.value(depth + 1)?;
                        if let Some(slot) = members.iter_mut().find(|(k, _)| *k == name) {
                            slot.1 = v;
                        } else {
                            members.push((name, v));
                        }
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err(()),
                        }
                    }
                }
                Value::Object(members)
            }
            b'-' | b'0'..=b'9' => Value::Number(self.number()?),
            _ => return Err(()),
        };
        Ok(Node {
            value,
            start,
            end: self.i,
        })
    }

    fn lit(&mut self, want: &[u8]) -> Result<(), ()> {
        if self.b[self.i..].starts_with(want) {
            self.i += want.len();
            Ok(())
        } else {
            Err(())
        }
    }

    fn number(&mut self) -> Result<String, ()> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(()),
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                return Err(());
            }
            while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                return Err(());
            }
            while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        std::str::from_utf8(&self.b[start..self.i])
            .map(str::to_owned)
            .map_err(|_| ())
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        let h = self.b.get(at..at + 4)?;
        let mut v = 0u32;
        for &c in h {
            v = v * 16 + (c as char).to_digit(16)?;
        }
        Some(v)
    }

    // Like encoding/json's unquote: invalid UTF-8 and lone surrogates become U+FFFD.
    fn string(&mut self) -> Result<String, ()> {
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i).ok_or(())?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(silo_gocompat::strings::decode_runes(&out).into_owned());
                }
                b'\\' => {
                    let e = *self.b.get(self.i + 1).ok_or(())?;
                    self.i += 2;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.hex4(self.i).ok_or(())?;
                            self.i += 4;
                            let mut ch = cp;
                            if (0xD800..0xDC00).contains(&cp)
                                && self.b.get(self.i) == Some(&b'\\')
                                && self.b.get(self.i + 1) == Some(&b'u')
                                && let Some(lo) = self.hex4(self.i + 2)
                                && (0xDC00..0xE000).contains(&lo)
                            {
                                ch = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                self.i += 6;
                            }
                            let r = char::from_u32(ch).unwrap_or('\u{FFFD}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(r.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(()),
                    }
                }
                0..=0x1f => return Err(()),
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }
}

/// Decodes one value and requires nothing but whitespace after it, as `json.Unmarshal` does.
pub fn parse(source: &[u8]) -> Result<Node, String> {
    check_valid(source).map_err(|e| e.to_string())?;
    let mut p = Parser { b: source, i: 0 };
    let node = p.value(0).map_err(|()| "invalid JSON".to_owned())?;
    Ok(node)
}

/// What `json.Decoder.Decode` then a look for trailing tokens would say about `source`: the first
/// value, or the decoder's error text.
pub fn decode_first(source: &[u8]) -> Result<(Node, usize), String> {
    let mut p = Parser { b: source, i: 0 };
    p.ws();
    if p.i == source.len() {
        return Err("EOF".to_owned());
    }
    if let Ok(node) = p.value(0) {
        return Ok((node, p.i));
    }
    // The scanner reports the same first error for a prefix as for the whole document, except that a
    // truncated stream is the decoder's EOF rather than the end-of-input syntax error.
    match check_valid(source) {
        Err(e) => {
            let msg = e.to_string();
            if msg == "unexpected end of JSON input" {
                Err("unexpected EOF".to_owned())
            } else {
                Err(msg)
            }
        }
        Ok(()) => Err("invalid JSON".to_owned()),
    }
}

/// Whether `source` holds exactly one value and only whitespace after it, for callers whose decode
/// target has already been checked. `strict_unmarshal` in `settingscontract` is built on this.
pub fn only_whitespace_after(source: &[u8], end: usize) -> bool {
    source[end..]
        .iter()
        .all(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
}
