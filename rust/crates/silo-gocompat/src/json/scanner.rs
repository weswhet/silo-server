//! Port of `encoding/json`'s scanner, `Compact`, `Indent`, and `HTMLEscape`.

use crate::strconv::quote;

const SCAN_CONTINUE: u8 = 0;
const SCAN_BEGIN_LITERAL: u8 = 1;
const SCAN_BEGIN_OBJECT: u8 = 2;
const SCAN_OBJECT_KEY: u8 = 3;
const SCAN_OBJECT_VALUE: u8 = 4;
const SCAN_END_OBJECT: u8 = 5;
const SCAN_BEGIN_ARRAY: u8 = 6;
const SCAN_ARRAY_VALUE: u8 = 7;
const SCAN_END_ARRAY: u8 = 8;
const SCAN_SKIP_SPACE: u8 = 9;
const SCAN_END: u8 = 10;
const SCAN_ERROR: u8 = 11;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Parse {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

const MAX_NESTING_DEPTH: usize = 10000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    BeginValueOrEmpty,
    BeginValue,
    BeginStringOrEmpty,
    BeginString,
    EndValue,
    EndTop,
    InString,
    InStringEsc,
    InStringEscU(u8),
    Neg,
    One,
    Zero,
    Dot,
    Dot0,
    E,
    ESign,
    E0,
    Literal(&'static [u8], &'static str, usize),
    Error,
}

/// `json.SyntaxError`, without its offset, which never reaches the error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError(pub(crate) String);

impl std::fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SyntaxError {}

struct Scanner {
    state: State,
    end_top: bool,
    parse_state: Vec<Parse>,
    err: Option<SyntaxError>,
}

pub(crate) fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

fn quote_char(c: u8) -> String {
    match c {
        b'\'' => r"'\''".to_string(),
        b'"' => "'\"'".to_string(),
        _ => {
            // Go converts the byte to a rune here, so 0xE9 quotes as é, not as a raw byte.
            let quoted = quote(&char::from(c).to_string());
            format!("'{}'", &quoted[1..quoted.len() - 1])
        }
    }
}

impl Scanner {
    fn new() -> Self {
        Self {
            state: State::BeginValue,
            end_top: false,
            parse_state: Vec::new(),
            err: None,
        }
    }

    fn error(&mut self, c: u8, context: &str) -> u8 {
        self.state = State::Error;
        self.err = Some(SyntaxError(format!(
            "invalid character {} {context}",
            quote_char(c)
        )));
        SCAN_ERROR
    }

    fn eof(&mut self) -> u8 {
        if self.err.is_some() {
            return SCAN_ERROR;
        }
        if self.end_top {
            return SCAN_END;
        }
        self.step(b' ');
        if self.end_top {
            return SCAN_END;
        }
        if self.err.is_none() {
            self.err = Some(SyntaxError("unexpected end of JSON input".to_string()));
        }
        SCAN_ERROR
    }

    fn push_parse_state(&mut self, c: u8, state: Parse, success: u8) -> u8 {
        self.parse_state.push(state);
        if self.parse_state.len() <= MAX_NESTING_DEPTH {
            return success;
        }
        self.error(c, "exceeded max depth")
    }

    fn pop_parse_state(&mut self) {
        self.parse_state.pop();
        if self.parse_state.is_empty() {
            self.state = State::EndTop;
            self.end_top = true;
        } else {
            self.state = State::EndValue;
        }
    }

    fn begin_value(&mut self, c: u8) -> u8 {
        if is_space(c) {
            return SCAN_SKIP_SPACE;
        }
        match c {
            b'{' => {
                self.state = State::BeginStringOrEmpty;
                self.push_parse_state(c, Parse::ObjectKey, SCAN_BEGIN_OBJECT)
            }
            b'[' => {
                self.state = State::BeginValueOrEmpty;
                self.push_parse_state(c, Parse::ArrayValue, SCAN_BEGIN_ARRAY)
            }
            b'"' => {
                self.state = State::InString;
                SCAN_BEGIN_LITERAL
            }
            b'-' => {
                self.state = State::Neg;
                SCAN_BEGIN_LITERAL
            }
            b'0' => {
                self.state = State::Zero;
                SCAN_BEGIN_LITERAL
            }
            b't' => {
                self.state = State::Literal(b"true", "true", 1);
                SCAN_BEGIN_LITERAL
            }
            b'f' => {
                self.state = State::Literal(b"false", "false", 1);
                SCAN_BEGIN_LITERAL
            }
            b'n' => {
                self.state = State::Literal(b"null", "null", 1);
                SCAN_BEGIN_LITERAL
            }
            b'1'..=b'9' => {
                self.state = State::One;
                SCAN_BEGIN_LITERAL
            }
            _ => self.error(c, "looking for beginning of value"),
        }
    }

    fn end_value(&mut self, c: u8) -> u8 {
        let Some(&ps) = self.parse_state.last() else {
            // Completed the top-level value before seeing this byte.
            self.state = State::EndTop;
            self.end_top = true;
            return self.end_top_step(c);
        };
        if is_space(c) {
            self.state = State::EndValue;
            return SCAN_SKIP_SPACE;
        }
        match ps {
            Parse::ObjectKey => {
                if c == b':' {
                    *self.parse_state.last_mut().expect("nonempty") = Parse::ObjectValue;
                    self.state = State::BeginValue;
                    return SCAN_OBJECT_KEY;
                }
                self.error(c, "after object key")
            }
            Parse::ObjectValue => {
                if c == b',' {
                    *self.parse_state.last_mut().expect("nonempty") = Parse::ObjectKey;
                    self.state = State::BeginString;
                    return SCAN_OBJECT_VALUE;
                }
                if c == b'}' {
                    self.pop_parse_state();
                    return SCAN_END_OBJECT;
                }
                self.error(c, "after object key:value pair")
            }
            Parse::ArrayValue => {
                if c == b',' {
                    self.state = State::BeginValue;
                    return SCAN_ARRAY_VALUE;
                }
                if c == b']' {
                    self.pop_parse_state();
                    return SCAN_END_ARRAY;
                }
                self.error(c, "after array element")
            }
        }
    }

    fn end_top_step(&mut self, c: u8) -> u8 {
        if !is_space(c) {
            self.error(c, "after top-level value");
        }
        SCAN_END
    }

    fn step(&mut self, c: u8) -> u8 {
        match self.state {
            State::BeginValueOrEmpty => {
                if is_space(c) {
                    return SCAN_SKIP_SPACE;
                }
                if c == b']' {
                    return self.end_value(c);
                }
                self.begin_value(c)
            }
            State::BeginValue => self.begin_value(c),
            State::BeginStringOrEmpty => {
                if is_space(c) {
                    return SCAN_SKIP_SPACE;
                }
                if c == b'}' {
                    *self.parse_state.last_mut().expect("nonempty") = Parse::ObjectValue;
                    return self.end_value(c);
                }
                self.begin_string(c)
            }
            State::BeginString => self.begin_string(c),
            State::EndValue => self.end_value(c),
            State::EndTop => self.end_top_step(c),
            State::InString => {
                if c == b'"' {
                    self.state = State::EndValue;
                    return SCAN_CONTINUE;
                }
                if c == b'\\' {
                    self.state = State::InStringEsc;
                    return SCAN_CONTINUE;
                }
                if c < 0x20 {
                    return self.error(c, "in string literal");
                }
                SCAN_CONTINUE
            }
            State::InStringEsc => match c {
                b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => {
                    self.state = State::InString;
                    SCAN_CONTINUE
                }
                b'u' => {
                    self.state = State::InStringEscU(0);
                    SCAN_CONTINUE
                }
                _ => self.error(c, "in string escape code"),
            },
            State::InStringEscU(n) => {
                if c.is_ascii_hexdigit() {
                    self.state = if n == 3 {
                        State::InString
                    } else {
                        State::InStringEscU(n + 1)
                    };
                    return SCAN_CONTINUE;
                }
                self.error(c, "in \\u hexadecimal character escape")
            }
            State::Neg => {
                if c == b'0' {
                    self.state = State::Zero;
                    return SCAN_CONTINUE;
                }
                if c.is_ascii_digit() {
                    self.state = State::One;
                    return SCAN_CONTINUE;
                }
                self.error(c, "in numeric literal")
            }
            State::One => {
                if c.is_ascii_digit() {
                    return SCAN_CONTINUE;
                }
                self.zero(c)
            }
            State::Zero => self.zero(c),
            State::Dot => {
                if c.is_ascii_digit() {
                    self.state = State::Dot0;
                    return SCAN_CONTINUE;
                }
                self.error(c, "after decimal point in numeric literal")
            }
            State::Dot0 => {
                if c.is_ascii_digit() {
                    return SCAN_CONTINUE;
                }
                if c == b'e' || c == b'E' {
                    self.state = State::E;
                    return SCAN_CONTINUE;
                }
                self.end_value(c)
            }
            State::E => {
                if c == b'+' || c == b'-' {
                    self.state = State::ESign;
                    return SCAN_CONTINUE;
                }
                self.e_sign(c)
            }
            State::ESign => self.e_sign(c),
            State::E0 => {
                if c.is_ascii_digit() {
                    return SCAN_CONTINUE;
                }
                self.end_value(c)
            }
            State::Literal(word, name, i) => {
                if c == word[i] {
                    self.state = if i + 1 == word.len() {
                        State::EndValue
                    } else {
                        State::Literal(word, name, i + 1)
                    };
                    return SCAN_CONTINUE;
                }
                let context = format!("in literal {name} (expecting '{}')", char::from(word[i]));
                self.error(c, &context)
            }
            State::Error => SCAN_ERROR,
        }
    }

    fn begin_string(&mut self, c: u8) -> u8 {
        if is_space(c) {
            return SCAN_SKIP_SPACE;
        }
        if c == b'"' {
            self.state = State::InString;
            return SCAN_BEGIN_LITERAL;
        }
        self.error(c, "looking for beginning of object key string")
    }

    fn zero(&mut self, c: u8) -> u8 {
        if c == b'.' {
            self.state = State::Dot;
            return SCAN_CONTINUE;
        }
        if c == b'e' || c == b'E' {
            self.state = State::E;
            return SCAN_CONTINUE;
        }
        self.end_value(c)
    }

    fn e_sign(&mut self, c: u8) -> u8 {
        if c.is_ascii_digit() {
            self.state = State::E0;
            return SCAN_CONTINUE;
        }
        self.error(c, "in exponent of numeric literal")
    }
}

/// `Decoder.readValue`'s scanning loop, resumable across reads.
pub(crate) struct ValueScan(Scanner);

impl ValueScan {
    pub(crate) fn new() -> Self {
        Self(Scanner::new())
    }

    /// Scans more of the value. `Ok(Some(n))` means it ended after `n` bytes of `data`, and
    /// `Ok(None)` means it needs more input.
    pub(crate) fn run(&mut self, data: &[u8]) -> Result<Option<usize>, SyntaxError> {
        for (i, &c) in data.iter().enumerate() {
            match self.0.step(c) {
                SCAN_END => return Ok(Some(i)),
                // The end of an object or array needs no lookahead, which might block.
                SCAN_END_OBJECT | SCAN_END_ARRAY if self.0.parse_state.is_empty() => {
                    return Ok(Some(i + 1));
                }
                SCAN_ERROR => {
                    return Err(self
                        .0
                        .err
                        .take()
                        .unwrap_or_else(|| SyntaxError(String::new())));
                }
                _ => {}
            }
        }
        Ok(None)
    }

    /// At the end of input: true when what was scanned is a complete value, such as a number.
    pub(crate) fn eof(&mut self) -> bool {
        self.0.step(b' ') == SCAN_END
    }
}

/// `json.Valid`.
pub fn valid(data: &[u8]) -> bool {
    check_valid(data).is_ok()
}

/// `checkValid`: `Err` carries Go's syntax error text.
pub fn check_valid(data: &[u8]) -> Result<(), SyntaxError> {
    let mut scan = Scanner::new();
    for &c in data {
        if scan.step(c) == SCAN_ERROR {
            return Err(scan
                .err
                .take()
                .unwrap_or_else(|| SyntaxError(String::new())));
        }
    }
    if scan.eof() == SCAN_ERROR {
        return Err(scan
            .err
            .take()
            .unwrap_or_else(|| SyntaxError(String::new())));
    }
    Ok(())
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_u00(dst: &mut Vec<u8>, c: u8) {
    dst.extend_from_slice(b"\\u00");
    dst.push(HEX[usize::from(c >> 4)]);
    dst.push(HEX[usize::from(c & 0xF)]);
}

/// `appendCompact`, the path every `MarshalJSON` result and `json.RawMessage` goes through.
pub(crate) fn append_compact(
    dst: &mut Vec<u8>,
    src: &[u8],
    escape: bool,
) -> Result<(), SyntaxError> {
    let orig_len = dst.len();
    let mut scan = Scanner::new();
    let mut start = 0;
    for (i, &c) in src.iter().enumerate() {
        if escape && (c == b'<' || c == b'>' || c == b'&') {
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            push_u00(dst, c);
            start = i + 1;
        }
        // Convert U+2028 and U+2029 (E2 80 A8 and E2 80 A9).
        if escape && c == 0xE2 && i + 2 < src.len() && src[i + 1] == 0x80 && src[i + 2] & !1 == 0xA8
        {
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            dst.extend_from_slice(b"\\u202");
            dst.push(HEX[usize::from(src[i + 2] & 0xF)]);
            start = i + 3;
        }
        let v = scan.step(c);
        if v >= SCAN_SKIP_SPACE {
            if v == SCAN_ERROR {
                break;
            }
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            start = i + 1;
        }
    }
    if scan.eof() == SCAN_ERROR {
        dst.truncate(orig_len);
        return Err(scan
            .err
            .take()
            .unwrap_or_else(|| SyntaxError(String::new())));
    }
    if start < src.len() {
        dst.extend_from_slice(&src[start..]);
    }
    Ok(())
}

/// `json.Compact`.
pub fn compact(src: &[u8]) -> Result<Vec<u8>, SyntaxError> {
    let mut dst = Vec::with_capacity(src.len());
    append_compact(&mut dst, src, false)?;
    Ok(dst)
}

fn append_newline(dst: &mut Vec<u8>, prefix: &str, indent: &str, depth: usize) {
    dst.push(b'\n');
    dst.extend_from_slice(prefix.as_bytes());
    for _ in 0..depth {
        dst.extend_from_slice(indent.as_bytes());
    }
}

/// `json.Indent`.
pub fn indent(src: &[u8], prefix: &str, indent: &str) -> Result<Vec<u8>, SyntaxError> {
    let mut dst = Vec::with_capacity(src.len() * 2);
    let mut scan = Scanner::new();
    let mut need_indent = false;
    let mut depth = 0usize;
    for &c in src {
        let v = scan.step(c);
        if v == SCAN_SKIP_SPACE {
            continue;
        }
        if v == SCAN_ERROR {
            break;
        }
        if need_indent && v != SCAN_END_OBJECT && v != SCAN_END_ARRAY {
            need_indent = false;
            depth += 1;
            append_newline(&mut dst, prefix, indent, depth);
        }
        // Emit semantically uninteresting bytes, like punctuation in strings, unmodified.
        if v == SCAN_CONTINUE {
            dst.push(c);
            continue;
        }
        match c {
            b'{' | b'[' => {
                // Delay the indent so that empty objects and arrays print as {} and [].
                need_indent = true;
                dst.push(c);
            }
            b',' => {
                dst.push(c);
                append_newline(&mut dst, prefix, indent, depth);
            }
            b':' => {
                dst.push(c);
                dst.push(b' ');
            }
            b'}' | b']' => {
                if need_indent {
                    need_indent = false;
                } else {
                    depth = depth.saturating_sub(1);
                    append_newline(&mut dst, prefix, indent, depth);
                }
                dst.push(c);
            }
            _ => dst.push(c),
        }
    }
    if scan.eof() == SCAN_ERROR {
        return Err(scan
            .err
            .take()
            .unwrap_or_else(|| SyntaxError(String::new())));
    }
    Ok(dst)
}

/// `json.HTMLEscape`.
pub fn html_escape(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(src.len());
    let mut start = 0;
    for (i, &c) in src.iter().enumerate() {
        if c == b'<' || c == b'>' || c == b'&' {
            dst.extend_from_slice(&src[start..i]);
            push_u00(&mut dst, c);
            start = i + 1;
        }
        if c == 0xE2 && i + 2 < src.len() && src[i + 1] == 0x80 && src[i + 2] & !1 == 0xA8 {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(b"\\u202");
            dst.push(HEX[usize::from(src[i + 2] & 0xF)]);
            start = i + 3;
        }
    }
    dst.extend_from_slice(&src[start..]);
    dst
}

/// `isValidNumber`: the JSON number grammar, with Go's quirk of accepting `1e` handled as in Go.
pub(crate) fn is_valid_number(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut s = s;
    if s[0] == b'-' {
        s = &s[1..];
        if s.is_empty() {
            return false;
        }
    }
    match s[0] {
        b'0' => s = &s[1..],
        b'1'..=b'9' => {
            s = &s[1..];
            while s.first().is_some_and(u8::is_ascii_digit) {
                s = &s[1..];
            }
        }
        _ => return false,
    }
    if s.len() >= 2 && s[0] == b'.' && s[1].is_ascii_digit() {
        s = &s[2..];
        while s.first().is_some_and(u8::is_ascii_digit) {
            s = &s[1..];
        }
    }
    if s.len() >= 2 && (s[0] == b'e' || s[0] == b'E') {
        s = &s[1..];
        if s[0] == b'+' || s[0] == b'-' {
            s = &s[1..];
            if s.is_empty() {
                return false;
            }
        }
        while s.first().is_some_and(u8::is_ascii_digit) {
            s = &s[1..];
        }
    }
    s.is_empty()
}
