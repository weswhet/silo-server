//! The parts of `encoding/json`'s decoder that the settings code depends on.
//!
//! Stored settings are arbitrary legacy strings, and Go's decoder errors end up in the
//! `user_setting_migration_rejects.reason` column. This reproduces its grammar, its messages, and
//! its token API: `silo_gocompat::json` covers encoding and whole-document validation, not this.

use std::collections::BTreeMap;

use silo_gocompat::json::check_valid;

/// A decoded document with `UseNumber`: number literals stay as written, and a repeated object key
/// keeps its last value. Objects iterate in key order; Go's maps have no order.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

const MAX_NESTING_DEPTH: usize = 10_000;

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

enum Fail {
    /// A syntax error at this byte offset.
    At(usize),
    /// The input ended inside the value.
    Eof,
}

enum Frame {
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>, Option<String>),
}

// Reads one value starting at `pos`, stopping right after it.
fn read_value(raw: &[u8], pos: usize) -> Result<(Value, usize), Fail> {
    let mut i = pos;
    let mut stack: Vec<Frame> = Vec::new();
    loop {
        // A value starts here.
        while i < raw.len() && is_space(raw[i]) {
            i += 1;
        }
        let Some(&c) = raw.get(i) else {
            return Err(Fail::Eof);
        };
        let mut value = match c {
            b'{' => {
                if stack.len() >= MAX_NESTING_DEPTH {
                    return Err(Fail::At(i));
                }
                i += 1;
                while i < raw.len() && is_space(raw[i]) {
                    i += 1;
                }
                match raw.get(i) {
                    None => return Err(Fail::Eof),
                    Some(b'}') => {
                        i += 1;
                        Value::Object(BTreeMap::new())
                    }
                    Some(b'"') => {
                        let (key, end) = read_string(raw, i)?;
                        i = read_colon(raw, end)?;
                        stack.push(Frame::Object(BTreeMap::new(), Some(key)));
                        continue;
                    }
                    Some(_) => return Err(Fail::At(i)),
                }
            }
            b'[' => {
                if stack.len() >= MAX_NESTING_DEPTH {
                    return Err(Fail::At(i));
                }
                i += 1;
                while i < raw.len() && is_space(raw[i]) {
                    i += 1;
                }
                match raw.get(i) {
                    None => return Err(Fail::Eof),
                    Some(b']') => {
                        i += 1;
                        Value::Array(Vec::new())
                    }
                    Some(_) => {
                        stack.push(Frame::Array(Vec::new()));
                        continue;
                    }
                }
            }
            b'"' => {
                let (text, end) = read_string(raw, i)?;
                i = end;
                Value::String(text)
            }
            b't' => {
                i = read_literal(raw, i, b"true")?;
                Value::Bool(true)
            }
            b'f' => {
                i = read_literal(raw, i, b"false")?;
                Value::Bool(false)
            }
            b'n' => {
                i = read_literal(raw, i, b"null")?;
                Value::Null
            }
            b'-' | b'0'..=b'9' => {
                let end = read_number(raw, i)?;
                let text = String::from_utf8_lossy(&raw[i..end]).into_owned();
                i = end;
                Value::Number(text)
            }
            _ => return Err(Fail::At(i)),
        };

        // A value ended. Attach it to its container, closing containers as they end.
        loop {
            let Some(top) = stack.last_mut() else {
                return Ok((value, i));
            };
            while i < raw.len() && is_space(raw[i]) {
                i += 1;
            }
            let next = raw.get(i).copied();
            match top {
                Frame::Array(items) => {
                    items.push(value);
                    match next {
                        None => return Err(Fail::Eof),
                        Some(b',') => {
                            i += 1;
                            break;
                        }
                        Some(b']') => {
                            i += 1;
                            let Some(Frame::Array(items)) = stack.pop() else {
                                unreachable!("top of stack is an array");
                            };
                            value = Value::Array(items);
                        }
                        Some(_) => return Err(Fail::At(i)),
                    }
                }
                Frame::Object(map, key) => {
                    if let Some(key) = key.take() {
                        map.insert(key, value);
                    }
                    match next {
                        None => return Err(Fail::Eof),
                        Some(b',') => {
                            i += 1;
                            while i < raw.len() && is_space(raw[i]) {
                                i += 1;
                            }
                            match raw.get(i) {
                                None => return Err(Fail::Eof),
                                Some(b'"') => {
                                    let (name, end) = read_string(raw, i)?;
                                    i = read_colon(raw, end)?;
                                    *key = Some(name);
                                    break;
                                }
                                Some(_) => return Err(Fail::At(i)),
                            }
                        }
                        Some(b'}') => {
                            i += 1;
                            let Some(Frame::Object(map, _)) = stack.pop() else {
                                unreachable!("top of stack is an object");
                            };
                            value = Value::Object(map);
                        }
                        Some(_) => return Err(Fail::At(i)),
                    }
                }
            }
        }
    }
}

fn read_colon(raw: &[u8], mut i: usize) -> Result<usize, Fail> {
    while i < raw.len() && is_space(raw[i]) {
        i += 1;
    }
    match raw.get(i) {
        None => Err(Fail::Eof),
        Some(b':') => Ok(i + 1),
        Some(_) => Err(Fail::At(i)),
    }
}

fn read_literal(raw: &[u8], start: usize, literal: &[u8]) -> Result<usize, Fail> {
    for (n, want) in literal.iter().enumerate() {
        match raw.get(start + n) {
            None => return Err(Fail::Eof),
            Some(c) if c == want => {}
            Some(_) => return Err(Fail::At(start + n)),
        }
    }
    Ok(start + literal.len())
}

fn read_number(raw: &[u8], start: usize) -> Result<usize, Fail> {
    let mut i = start;
    if raw[i] == b'-' {
        i += 1;
    }
    match raw.get(i) {
        None => return Err(Fail::Eof),
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while matches!(raw.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        Some(_) => return Err(Fail::At(i)),
    }
    if raw.get(i) == Some(&b'.') {
        i += 1;
        match raw.get(i) {
            None => return Err(Fail::Eof),
            Some(b'0'..=b'9') => {
                while matches!(raw.get(i), Some(b'0'..=b'9')) {
                    i += 1;
                }
            }
            Some(_) => return Err(Fail::At(i)),
        }
    }
    if matches!(raw.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(raw.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        match raw.get(i) {
            None => return Err(Fail::Eof),
            Some(b'0'..=b'9') => {
                while matches!(raw.get(i), Some(b'0'..=b'9')) {
                    i += 1;
                }
            }
            Some(_) => return Err(Fail::At(i)),
        }
    }
    Ok(i)
}

fn hex4(raw: &[u8], at: usize) -> Option<u32> {
    let mut v = 0;
    for offset in 0..4 {
        let digit = char::from(*raw.get(at + offset)?).to_digit(16)?;
        v = v * 16 + digit;
    }
    Some(v)
}

// Reads a string literal: the scan half of Go's scanner and the decode half of unquote.
fn read_string(raw: &[u8], start: usize) -> Result<(String, usize), Fail> {
    let mut i = start + 1;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let Some(&c) = raw.get(i) else {
            return Err(Fail::Eof);
        };
        match c {
            b'"' => return Ok((decode_utf8_lossy(&out), i + 1)),
            b'\\' => {
                let Some(&escape) = raw.get(i + 1) else {
                    return Err(Fail::Eof);
                };
                match escape {
                    b'"' | b'\\' | b'/' => {
                        out.push(escape);
                        i += 2;
                    }
                    b'b' => {
                        out.push(0x08);
                        i += 2;
                    }
                    b'f' => {
                        out.push(0x0c);
                        i += 2;
                    }
                    b'n' => {
                        out.push(b'\n');
                        i += 2;
                    }
                    b'r' => {
                        out.push(b'\r');
                        i += 2;
                    }
                    b't' => {
                        out.push(b'\t');
                        i += 2;
                    }
                    b'u' => {
                        // Scan the digits first, for the error offset.
                        for offset in 2..6 {
                            match raw.get(i + offset) {
                                None => return Err(Fail::Eof),
                                Some(d) if d.is_ascii_hexdigit() => {}
                                Some(_) => return Err(Fail::At(i + offset)),
                            }
                        }
                        let first = hex4(raw, i + 2).expect("scanned hex digits");
                        i += 6;
                        let mut decoded = first;
                        if (0xD800..0xE000).contains(&first) {
                            decoded = 0xFFFD;
                            // A valid pair consumes both escapes. Anything else leaves the second
                            // escape for the next turn, and the first becomes U+FFFD.
                            if first < 0xDC00
                                && raw.get(i) == Some(&b'\\')
                                && raw.get(i + 1) == Some(&b'u')
                                && let Some(low) = hex4(raw, i + 2)
                                && (0xDC00..0xE000).contains(&low)
                            {
                                decoded = 0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00);
                                i += 6;
                            }
                        }
                        let ch = char::from_u32(decoded).unwrap_or('\u{FFFD}');
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                    _ => return Err(Fail::At(i + 1)),
                }
            }
            c if c < 0x20 => return Err(Fail::At(i)),
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
}

// Go replaces each byte of an invalid sequence with U+FFFD.
fn decode_utf8_lossy(mut bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    loop {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                out.push_str(valid);
                return out;
            }
            Err(err) => {
                let (good, rest) = bytes.split_at(err.valid_up_to());
                out.push_str(std::str::from_utf8(good).expect("validated prefix"));
                out.push('\u{FFFD}');
                bytes = &rest[1..];
            }
        }
    }
}

fn syntax_message(raw: &[u8], start: usize, at: usize) -> String {
    match check_valid(&raw[start..=at]) {
        Err(err) => err.to_string(),
        // The scanner and read_value disagree, which would be a bug here. Don't report success.
        Ok(()) => "invalid JSON".to_string(),
    }
}

/// `Decoder.Decode`: the first value and the offset just past it, or Go's error text.
pub fn decode(raw: &[u8]) -> Result<(Value, usize), String> {
    match read_value(raw, 0) {
        Ok(done) => Ok(done),
        Err(Fail::At(at)) => Err(syntax_message(raw, 0, at)),
        Err(Fail::Eof) => {
            if raw.iter().all(|c| is_space(*c)) {
                Err("EOF".to_string())
            } else {
                Err("unexpected EOF".to_string())
            }
        }
    }
}

/// Whether only whitespace follows `end`.
pub fn only_space_after(raw: &[u8], end: usize) -> bool {
    raw[end..].iter().all(|c| is_space(*c))
}

/// `json.Unmarshal` into `any`: the whole input must be valid, numbers become `f64`, and a number
/// that doesn't fit is a type error. Returns the value with numbers still as literals.
pub fn unmarshal_any(raw: &[u8]) -> Result<Value, String> {
    check_valid(raw).map_err(|e| e.to_string())?;
    let (value, _) = decode(raw)?;
    if let Some(bad) = first_number_overflow(&value) {
        return Err(format!(
            "json: cannot unmarshal number {bad} into Go value of type float64"
        ));
    }
    Ok(value)
}

fn first_number_overflow(value: &Value) -> Option<&str> {
    match value {
        Value::Number(n) => n
            .parse::<f64>()
            .ok()
            .filter(|f| f.is_infinite())
            .map(|_| n.as_str()),
        Value::Array(items) => items.iter().find_map(first_number_overflow),
        Value::Object(map) => map.values().find_map(first_number_overflow),
        _ => None,
    }
}

// --- The Token API, for the duplicate-key scan ---

#[derive(Clone, Copy, Eq, PartialEq)]
enum TokenState {
    TopValue,
    ArrayStart,
    ArrayValue,
    ArrayComma,
    ObjectStart,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectComma,
}

/// The token API found a syntax error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenError;

/// A token from [`TokenDecoder::token`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Token {
    Delim(u8),
    String(String),
    Other,
}

/// `json.Decoder`'s `Token` and `More`. An error is [`TokenError`] with no details, because the
/// duplicate-key scan ignores decoder errors: the real decode reports them.
pub struct TokenDecoder<'a> {
    raw: &'a [u8],
    scanp: usize,
    state: TokenState,
    stack: Vec<TokenState>,
    sticky_err: bool,
}

impl<'a> TokenDecoder<'a> {
    pub fn new(raw: &'a [u8]) -> Self {
        Self {
            raw,
            scanp: 0,
            state: TokenState::TopValue,
            stack: Vec::new(),
            sticky_err: false,
        }
    }

    fn peek(&mut self) -> Option<u8> {
        while let Some(&c) = self.raw.get(self.scanp) {
            if !is_space(c) {
                return Some(c);
            }
            self.scanp += 1;
        }
        None
    }

    /// `Decoder.More`.
    pub fn more(&mut self) -> bool {
        matches!(self.peek(), Some(c) if c != b']' && c != b'}')
    }

    fn value_allowed(&self) -> bool {
        matches!(
            self.state,
            TokenState::TopValue
                | TokenState::ArrayStart
                | TokenState::ArrayValue
                | TokenState::ObjectValue
        )
    }

    fn value_end(&mut self) {
        match self.state {
            TokenState::ArrayStart | TokenState::ArrayValue => self.state = TokenState::ArrayComma,
            TokenState::ObjectValue => self.state = TokenState::ObjectComma,
            _ => {}
        }
    }

    // Decoder.Decode from the current position, as the token API uses it.
    fn decode_scalar(&mut self) -> Result<Value, TokenError> {
        if self.sticky_err {
            return Err(TokenError);
        }
        match read_value(&self.raw[self.scanp..], 0) {
            Ok((value, end)) => {
                self.scanp += end;
                Ok(value)
            }
            Err(_) => {
                self.sticky_err = true;
                Err(TokenError)
            }
        }
    }

    /// `Decoder.Token`.
    pub fn token(&mut self) -> Result<Token, TokenError> {
        loop {
            let c = self.peek().ok_or(TokenError)?;
            match c {
                b'[' => {
                    if !self.value_allowed() {
                        return Err(TokenError);
                    }
                    self.scanp += 1;
                    self.stack.push(self.state);
                    self.state = TokenState::ArrayStart;
                    return Ok(Token::Delim(b'['));
                }
                b']' => {
                    if self.state != TokenState::ArrayStart && self.state != TokenState::ArrayComma
                    {
                        return Err(TokenError);
                    }
                    self.scanp += 1;
                    self.state = self.stack.pop().ok_or(TokenError)?;
                    self.value_end();
                    return Ok(Token::Delim(b']'));
                }
                b'{' => {
                    if !self.value_allowed() {
                        return Err(TokenError);
                    }
                    self.scanp += 1;
                    self.stack.push(self.state);
                    self.state = TokenState::ObjectStart;
                    return Ok(Token::Delim(b'{'));
                }
                b'}' => {
                    if self.state != TokenState::ObjectStart
                        && self.state != TokenState::ObjectComma
                    {
                        return Err(TokenError);
                    }
                    self.scanp += 1;
                    self.state = self.stack.pop().ok_or(TokenError)?;
                    self.value_end();
                    return Ok(Token::Delim(b'}'));
                }
                b':' => {
                    if self.state != TokenState::ObjectColon {
                        return Err(TokenError);
                    }
                    self.scanp += 1;
                    self.state = TokenState::ObjectValue;
                }
                b',' => {
                    if self.state == TokenState::ArrayComma {
                        self.scanp += 1;
                        self.state = TokenState::ArrayValue;
                    } else if self.state == TokenState::ObjectComma {
                        self.scanp += 1;
                        self.state = TokenState::ObjectKey;
                    } else {
                        return Err(TokenError);
                    }
                }
                b'"' if matches!(self.state, TokenState::ObjectStart | TokenState::ObjectKey) => {
                    let value = self.decode_scalar()?;
                    self.state = TokenState::ObjectColon;
                    return match value {
                        Value::String(s) => Ok(Token::String(s)),
                        _ => Err(TokenError),
                    };
                }
                _ => {
                    if !self.value_allowed() {
                        return Err(TokenError);
                    }
                    let value = self.decode_scalar()?;
                    self.value_end();
                    return Ok(match value {
                        Value::String(s) => Token::String(s),
                        _ => Token::Other,
                    });
                }
            }
        }
    }
}
