//! `json.Unmarshal` into a Go struct, for payloads whose keys and values serde would read differently.
//!
//! Go matches object keys against struct fields exactly first and then case-insensitively, ignores
//! unknown keys without looking at their values beyond syntax, lets a later duplicate key overwrite an
//! earlier one, treats `null` as a no-op for a non-pointer field, and replaces invalid UTF-8 and lone
//! surrogates with U+FFFD. [`normalize_object`] applies those rules and returns an object with
//! canonical field names that serde can then deserialize strictly.

use serde::de::DeserializeOwned;
use serde_json::{Map, Number, Value};
use silo_gocompat::json::check_valid;
use silo_gocompat::strings::{decode_runes, equal_fold};

/// One JSON-visible field of the Go struct being decoded.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// The `json:"..."` name.
    pub name: &'static str,
    /// Whether the Go field is a pointer: `null` clears it instead of leaving it alone.
    pub pointer: bool,
}

/// A field that is not a pointer, for `const` tables.
pub const fn value(name: &'static str) -> Field {
    Field {
        name,
        pointer: false,
    }
}

/// A pointer field, for `const` tables.
pub const fn pointer(name: &'static str) -> Field {
    Field {
        name,
        pointer: true,
    }
}

/// A syntax or type error, with text for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

/// What a payload's top-level JSON value was.
#[derive(Debug, Clone, PartialEq)]
pub enum Normalized {
    /// An object, reduced to canonical field names.
    Object(Map<String, Value>),
    /// The literal `null`, which leaves a Go struct untouched.
    Null,
}

/// Applies Go's field matching to a payload. Anything but an object or `null` is the type error
/// `json.Unmarshal` would report.
pub fn normalize_object(data: &[u8], fields: &[Field]) -> Result<Normalized, DecodeError> {
    check_valid(data).map_err(|e| DecodeError(e.to_string()))?;
    let mut reader = Reader { data, pos: 0 };
    reader.skip_ws();
    match reader.peek() {
        b'{' => {}
        b'n' => return Ok(Normalized::Null),
        _ => {
            return Err(DecodeError(
                "json: cannot unmarshal non-object into Go value".to_owned(),
            ));
        }
    }
    reader.pos += 1;
    let mut out = Map::new();
    loop {
        reader.skip_ws();
        if reader.peek() == b'}' {
            break;
        }
        if reader.peek() == b',' {
            reader.pos += 1;
            continue;
        }
        let key = reader.string();
        reader.skip_ws();
        reader.pos += 1; // ':'
        reader.skip_ws();
        let Some(field) = resolve_field(fields, &key) else {
            reader.skip_value();
            continue;
        };
        if reader.peek() == b'n' {
            reader.pos += 4;
            if field.pointer {
                out.remove(field.name);
            }
            continue;
        }
        let value = reader.value()?;
        out.insert(field.name.to_owned(), value);
    }
    Ok(Normalized::Object(out))
}

/// Decodes a payload into `T` under Go's rules. `null` decodes to `T::default()`.
pub fn unmarshal<T: DeserializeOwned + Default>(
    data: &[u8],
    fields: &[Field],
) -> Result<T, DecodeError> {
    match normalize_object(data, fields)? {
        Normalized::Null => Ok(T::default()),
        Normalized::Object(map) => {
            serde_json::from_value(Value::Object(map)).map_err(|e| DecodeError(e.to_string()))
        }
    }
}

/// Decodes any valid JSON value with Go's string rules, into a map-ordered tree. Syntax errors are
/// reported the way `json.Unmarshal` would report them.
pub fn parse_value(data: &[u8]) -> Result<Value, DecodeError> {
    check_valid(data).map_err(|e| DecodeError(e.to_string()))?;
    let mut reader = Reader { data, pos: 0 };
    reader.skip_ws();
    reader.value()
}

fn resolve_field<'a>(fields: &'a [Field], key: &str) -> Option<&'a Field> {
    fields
        .iter()
        .find(|f| f.name == key)
        .or_else(|| fields.iter().find(|f| equal_fold(f.name, key)))
}

/// Walks input that `check_valid` has already accepted, so structural surprises cannot occur.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn peek(&self) -> u8 {
        self.data.get(self.pos).copied().unwrap_or(0)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), b' ' | b'\t' | b'\r' | b'\n') {
            self.pos += 1;
        }
    }

    fn skip_string(&mut self) {
        self.pos += 1;
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b'\\' => self.pos += 2,
                b'"' => {
                    self.pos += 1;
                    return;
                }
                _ => self.pos += 1,
            }
        }
    }

    fn skip_value(&mut self) {
        let mut depth = 0usize;
        loop {
            self.skip_ws();
            match self.peek() {
                b'"' => self.skip_string(),
                b'{' | b'[' => {
                    depth += 1;
                    self.pos += 1;
                }
                b'}' | b']' => {
                    depth -= 1;
                    self.pos += 1;
                }
                b',' | b':' => self.pos += 1,
                b'n' => self.pos += 4,
                b't' => self.pos += 4,
                b'f' => self.pos += 5,
                _ => {
                    while self.pos < self.data.len()
                        && matches!(
                            self.data[self.pos],
                            b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
                        )
                    {
                        self.pos += 1;
                    }
                }
            }
            if depth == 0 {
                return;
            }
        }
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        let slice = self.data.get(at..at + 4)?;
        let text = std::str::from_utf8(slice).ok()?;
        u32::from_str_radix(text, 16).ok()
    }

    /// `encoding/json`'s `unquote`.
    fn string(&mut self) -> String {
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        let push_char = |out: &mut Vec<u8>, c: u32| {
            let c = char::from_u32(c).unwrap_or('\u{fffd}');
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        };
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            match b {
                b'"' => {
                    self.pos += 1;
                    break;
                }
                b'\\' => {
                    let esc = self.data[self.pos + 1];
                    self.pos += 2;
                    match esc {
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let first = self.hex4(self.pos).unwrap_or(0xfffd);
                            self.pos += 4;
                            if (0xd800..0xe000).contains(&first) {
                                let mut low = None;
                                if self.data.get(self.pos) == Some(&b'\\')
                                    && self.data.get(self.pos + 1) == Some(&b'u')
                                {
                                    low = self.hex4(self.pos + 2);
                                }
                                match low {
                                    Some(second)
                                        if (0xd800..0xdc00).contains(&first)
                                            && (0xdc00..0xe000).contains(&second) =>
                                    {
                                        self.pos += 6;
                                        let joined =
                                            0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
                                        push_char(&mut out, joined);
                                    }
                                    _ => push_char(&mut out, 0xfffd),
                                }
                            } else {
                                push_char(&mut out, first);
                            }
                        }
                        other => out.push(other),
                    }
                }
                _ => {
                    out.push(b);
                    self.pos += 1;
                }
            }
        }
        decode_runes(&out).into_owned()
    }

    fn number(&mut self) -> Result<Value, DecodeError> {
        let start = self.pos;
        while self.pos < self.data.len()
            && matches!(
                self.data[self.pos],
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
            )
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.data[start..self.pos]).unwrap_or("");
        if text == "-0" {
            return Ok(Value::Number(Number::from(0)));
        }
        serde_json::from_str::<Value>(text)
            .map_err(|_| DecodeError(format!("json: number {text} out of range")))
    }

    fn value(&mut self) -> Result<Value, DecodeError> {
        self.skip_ws();
        match self.peek() {
            b'"' => Ok(Value::String(self.string())),
            b'n' => {
                self.pos += 4;
                Ok(Value::Null)
            }
            b't' => {
                self.pos += 4;
                Ok(Value::Bool(true))
            }
            b'f' => {
                self.pos += 5;
                Ok(Value::Bool(false))
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek() {
                        b']' => {
                            self.pos += 1;
                            return Ok(Value::Array(items));
                        }
                        b',' => self.pos += 1,
                        _ => items.push(self.value()?),
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                let mut map = Map::new();
                loop {
                    self.skip_ws();
                    match self.peek() {
                        b'}' => {
                            self.pos += 1;
                            return Ok(Value::Object(map));
                        }
                        b',' => self.pos += 1,
                        _ => {
                            let key = self.string();
                            self.skip_ws();
                            self.pos += 1;
                            let value = self.value()?;
                            map.insert(key, value);
                        }
                    }
                }
            }
            _ => self.number(),
        }
    }
}
