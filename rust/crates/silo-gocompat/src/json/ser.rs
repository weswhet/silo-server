//! The serde serializer behind [`marshal`] and [`Encoder`].

use std::io::Write;

use serde::Serialize;
use serde::ser::{self, Impossible};

use super::scanner::{append_compact, indent as indent_json, is_valid_number};
use super::{BYTE_STRING_TOKEN, NUMBER_TOKEN, RAW_MESSAGE_TOKEN, SERDE_JSON_RAW_TOKEN};
use crate::strconv::{format_float, quote};

/// A marshaling error with the text Go would report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

impl From<super::SyntaxError> for Error {
    fn from(err: super::SyntaxError) -> Self {
        Self(err.0)
    }
}

/// `json.Marshal`.
pub fn marshal<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(128);
    value.serialize(&mut GoSerializer {
        out: &mut out,
        escape_html: true,
    })?;
    Ok(out)
}

/// `json.Marshal`, as a string. The output is always valid UTF-8.
pub fn marshal_to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    let bytes = marshal(value)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `json.MarshalIndent`.
pub fn marshal_indent<T: Serialize + ?Sized>(
    value: &T,
    prefix: &str,
    indent: &str,
) -> Result<Vec<u8>, Error> {
    let bytes = marshal(value)?;
    Ok(indent_json(&bytes, prefix, indent)?)
}

/// `json.Encoder`: one document per [`Encoder::encode`], each followed by a newline.
pub struct Encoder<W> {
    writer: W,
    escape_html: bool,
    prefix: String,
    indent: String,
}

impl<W: Write> Encoder<W> {
    /// `json.NewEncoder`.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            escape_html: true,
            prefix: String::new(),
            indent: String::new(),
        }
    }

    /// `Encoder.SetEscapeHTML`. U+2028 and U+2029 stay escaped either way.
    pub fn set_escape_html(&mut self, on: bool) {
        self.escape_html = on;
    }

    /// `Encoder.SetIndent`.
    pub fn set_indent(&mut self, prefix: &str, indent: &str) {
        self.prefix = prefix.to_string();
        self.indent = indent.to_string();
    }

    /// `Encoder.Encode`.
    pub fn encode<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let mut out = Vec::with_capacity(128);
        value.serialize(&mut GoSerializer {
            out: &mut out,
            escape_html: self.escape_html,
        })?;
        out.push(b'\n');
        if !self.prefix.is_empty() || !self.indent.is_empty() {
            out = indent_json(&out, &self.prefix, &self.indent)?;
        }
        self.writer
            .write_all(&out)
            .map_err(|err| Error(err.to_string()))
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// `appendString`. Takes bytes because a Go string can hold invalid UTF-8.
fn append_string(dst: &mut Vec<u8>, src: &[u8], escape_html: bool) {
    dst.push(b'"');
    let mut start = 0;
    let mut i = 0;
    while i < src.len() {
        let b = src[i];
        if b < 0x80 {
            let safe = (0x20..0x7F).contains(&b) && b != b'"' && b != b'\\' || b == 0x7F;
            if safe && !(escape_html && matches!(b, b'<' | b'>' | b'&')) {
                i += 1;
                continue;
            }
            dst.extend_from_slice(&src[start..i]);
            match b {
                b'\\' | b'"' => dst.extend_from_slice(&[b'\\', b]),
                0x08 => dst.extend_from_slice(b"\\b"),
                0x0C => dst.extend_from_slice(b"\\f"),
                b'\n' => dst.extend_from_slice(b"\\n"),
                b'\r' => dst.extend_from_slice(b"\\r"),
                b'\t' => dst.extend_from_slice(b"\\t"),
                _ => {
                    dst.extend_from_slice(b"\\u00");
                    dst.push(HEX[usize::from(b >> 4)]);
                    dst.push(HEX[usize::from(b & 0xF)]);
                }
            }
            i += 1;
            start = i;
            continue;
        }
        let window = &src[i..src.len().min(i + 4)];
        let valid = match std::str::from_utf8(window) {
            Ok(s) => s,
            Err(e) => std::str::from_utf8(&window[..e.valid_up_to()]).unwrap_or_default(),
        };
        let Some(c) = valid.chars().next() else {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(b"\\ufffd");
            i += 1;
            start = i;
            continue;
        };
        if c == '\u{2028}' || c == '\u{2029}' {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(b"\\u202");
            dst.push(HEX[(c as usize) & 0xF]);
            i += c.len_utf8();
            start = i;
            continue;
        }
        i += c.len_utf8();
    }
    dst.extend_from_slice(&src[start..]);
    dst.push(b'"');
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn append_base64(dst: &mut Vec<u8>, src: &[u8]) {
    for chunk in src.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        dst.push(BASE64[(n >> 18) as usize & 63]);
        dst.push(BASE64[(n >> 12) as usize & 63]);
        dst.push(if chunk.len() > 1 {
            BASE64[(n >> 6) as usize & 63]
        } else {
            b'='
        });
        dst.push(if chunk.len() > 2 {
            BASE64[n as usize & 63]
        } else {
            b'='
        });
    }
}

/// `floatEncoder.encode`.
fn append_float(dst: &mut Vec<u8>, f: f64, bits: u32) -> Result<(), Error> {
    if f.is_nan() || f.is_infinite() {
        return Err(Error(format!(
            "json: unsupported value: {}",
            format_float(f, b'g', -1, bits)
        )));
    }
    let abs = f.abs();
    let mut fmt = b'f';
    if abs != 0.0 {
        let exponent_form = if bits == 64 {
            abs < 1e-6 || abs >= 1e21
        } else {
            (abs as f32) < 1e-6_f32 || (abs as f32) >= 1e21_f32
        };
        if exponent_form {
            fmt = b'e';
        }
    }
    let mut text = format_float(f, fmt, -1, bits).into_bytes();
    if fmt == b'e' {
        // Clean up e-09 to e-9.
        let n = text.len();
        if n >= 4 && text[n - 4] == b'e' && text[n - 3] == b'-' && text[n - 2] == b'0' {
            text[n - 2] = text[n - 1];
            text.truncate(n - 1);
        }
    }
    dst.extend_from_slice(&text);
    Ok(())
}

struct GoSerializer<'a> {
    out: &'a mut Vec<u8>,
    escape_html: bool,
}

impl GoSerializer<'_> {
    fn write_raw_message(&mut self, bytes: &[u8]) -> Result<(), Error> {
        append_compact(self.out, bytes, self.escape_html).map_err(|err| {
            Error(format!(
                "json: error calling MarshalJSON for type json.RawMessage: {err}"
            ))
        })
    }

    fn write_number(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let text: &[u8] = if bytes.is_empty() { b"0" } else { bytes };
        if !is_valid_number(text) {
            let quoted = quote(&String::from_utf8_lossy(text));
            return Err(Error(format!("json: invalid number literal {quoted}")));
        }
        self.out.extend_from_slice(text);
        Ok(())
    }

    fn write_display<T: std::fmt::Display>(&mut self, v: T) -> Result<(), Error> {
        write!(self.out, "{v}").map_err(|err| Error(err.to_string()))
    }
}

impl<'a, 'b> ser::Serializer for &'a mut GoSerializer<'b> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = SeqSerializer<'a, 'b>;
    type SerializeTuple = SeqSerializer<'a, 'b>;
    type SerializeTupleStruct = SeqSerializer<'a, 'b>;
    type SerializeTupleVariant = VariantSerializer<SeqSerializer<'a, 'b>>;
    type SerializeMap = MapSerializer<'a, 'b>;
    type SerializeStruct = StructSerializer<'a, 'b>;
    type SerializeStructVariant = VariantSerializer<StructSerializer<'a, 'b>>;

    fn serialize_bool(self, v: bool) -> Result<(), Error> {
        self.out
            .extend_from_slice(if v { b"true" } else { b"false" });
        Ok(())
    }
    fn serialize_i8(self, v: i8) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_i16(self, v: i16) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_i32(self, v: i32) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_i64(self, v: i64) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_i128(self, v: i128) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_u128(self, v: u128) -> Result<(), Error> {
        self.write_display(v)
    }
    fn serialize_f32(self, v: f32) -> Result<(), Error> {
        append_float(self.out, f64::from(v), 32)
    }
    fn serialize_f64(self, v: f64) -> Result<(), Error> {
        append_float(self.out, v, 64)
    }
    fn serialize_char(self, v: char) -> Result<(), Error> {
        let mut buf = [0u8; 4];
        self.serialize_str(v.encode_utf8(&mut buf))
    }
    fn serialize_str(self, v: &str) -> Result<(), Error> {
        append_string(self.out, v.as_bytes(), self.escape_html);
        Ok(())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
        self.out.push(b'"');
        append_base64(self.out, v);
        self.out.push(b'"');
        Ok(())
    }
    fn serialize_none(self) -> Result<(), Error> {
        self.serialize_unit()
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Error> {
        self.out.extend_from_slice(b"null");
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        self.serialize_str(variant)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        match name {
            RAW_MESSAGE_TOKEN => {
                let bytes = value.serialize(StringCapture)?;
                self.write_raw_message(&bytes)
            }
            NUMBER_TOKEN => {
                let bytes = value.serialize(StringCapture)?;
                self.write_number(&bytes)
            }
            BYTE_STRING_TOKEN => {
                let bytes = value.serialize(StringCapture)?;
                append_string(self.out, &bytes, self.escape_html);
                Ok(())
            }
            _ => value.serialize(self),
        }
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.out.push(b'{');
        append_string(self.out, variant.as_bytes(), self.escape_html);
        self.out.push(b':');
        value.serialize(&mut *self)?;
        self.out.push(b'}');
        Ok(())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        self.out.push(b'[');
        Ok(SeqSerializer {
            ser: self,
            first: true,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        self.out.push(b'{');
        append_string(self.out, variant.as_bytes(), self.escape_html);
        self.out.push(b':');
        Ok(VariantSerializer(self.serialize_seq(Some(len))?))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        if len.is_some() {
            Ok(MapSerializer::Sorted {
                ser: self,
                entries: Vec::with_capacity(len.unwrap_or(0)),
                key: None,
            })
        } else {
            // serde's flatten and other unsized maps: this is struct-like, so keep the order.
            self.out.push(b'{');
            Ok(MapSerializer::Ordered {
                ser: self,
                first: true,
            })
        }
    }
    fn serialize_struct(
        self,
        name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        if name == SERDE_JSON_RAW_TOKEN {
            return Ok(StructSerializer::SerdeJsonRaw { ser: self });
        }
        self.out.push(b'{');
        Ok(StructSerializer::Fields {
            ser: self,
            first: true,
        })
    }
    fn serialize_struct_variant(
        self,
        name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        self.out.push(b'{');
        append_string(self.out, variant.as_bytes(), self.escape_html);
        self.out.push(b':');
        Ok(VariantSerializer(self.serialize_struct(name, len)?))
    }
}

struct SeqSerializer<'a, 'b> {
    ser: &'a mut GoSerializer<'b>,
    first: bool,
}

impl SeqSerializer<'_, '_> {
    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        if !self.first {
            self.ser.out.push(b',');
        }
        self.first = false;
        // A value decoded from a document can nest as deep as Go's 10,000-level limit.
        stacker::maybe_grow(256 * 1024, 4 * 1024 * 1024, || {
            value.serialize(&mut *self.ser)
        })
    }

    fn close(self) {
        self.ser.out.push(b']');
    }
}

impl ser::SerializeSeq for SeqSerializer<'_, '_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.close();
        Ok(())
    }
}

impl ser::SerializeTuple for SeqSerializer<'_, '_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.close();
        Ok(())
    }
}

impl ser::SerializeTupleStruct for SeqSerializer<'_, '_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.close();
        Ok(())
    }
}

/// Closes the `{"Variant":` wrapper around an inner compound.
struct VariantSerializer<S>(S);

impl ser::SerializeTupleVariant for VariantSerializer<SeqSerializer<'_, '_>> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.0.element(value)
    }
    fn end(self) -> Result<(), Error> {
        let inner = self.0;
        inner.ser.out.extend_from_slice(b"]}");
        Ok(())
    }
}

impl ser::SerializeStructVariant for VariantSerializer<StructSerializer<'_, '_>> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.0.field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        if let StructSerializer::Fields { ser, .. } = self.0 {
            ser.out.extend_from_slice(b"}}");
        }
        Ok(())
    }
}

enum StructSerializer<'a, 'b> {
    Fields {
        ser: &'a mut GoSerializer<'b>,
        first: bool,
    },
    SerdeJsonRaw {
        ser: &'a mut GoSerializer<'b>,
    },
}

impl StructSerializer<'_, '_> {
    fn field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        match self {
            Self::Fields { ser, first } => {
                if !*first {
                    ser.out.push(b',');
                }
                *first = false;
                append_string(ser.out, key.as_bytes(), ser.escape_html);
                ser.out.push(b':');
                value.serialize(&mut **ser)
            }
            Self::SerdeJsonRaw { ser } => {
                let bytes = value.serialize(StringCapture)?;
                ser.write_raw_message(&bytes)
            }
        }
    }
}

impl ser::SerializeStruct for StructSerializer<'_, '_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        if let Self::Fields { ser, .. } = self {
            ser.out.push(b'}');
        }
        Ok(())
    }
}

/// A resolved map key and its encoded value.
type MapEntry = (Vec<u8>, Result<Vec<u8>, Error>);

enum MapSerializer<'a, 'b> {
    /// A real map: Go sorts by the resolved key string.
    ///
    /// A value's failure waits in its entry, so the error reported is the first in key order, as in
    /// Go, and not the first in this map's iteration order.
    Sorted {
        ser: &'a mut GoSerializer<'b>,
        entries: Vec<MapEntry>,
        key: Option<Vec<u8>>,
    },
    /// An unsized map, which is how serde writes a struct with `flatten`.
    Ordered {
        ser: &'a mut GoSerializer<'b>,
        first: bool,
    },
}

impl ser::SerializeMap for MapSerializer<'_, '_> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        let resolved = key.serialize(StringCapture)?;
        match self {
            Self::Sorted { key, .. } => *key = Some(resolved),
            Self::Ordered { ser, first } => {
                if !*first {
                    ser.out.push(b',');
                }
                *first = false;
                append_string(ser.out, &resolved, ser.escape_html);
                ser.out.push(b':');
            }
        }
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        match self {
            Self::Sorted { ser, entries, key } => {
                let mut buf = Vec::new();
                let encoded = stacker::maybe_grow(256 * 1024, 4 * 1024 * 1024, || {
                    value.serialize(&mut GoSerializer {
                        out: &mut buf,
                        escape_html: ser.escape_html,
                    })
                });
                entries.push((key.take().unwrap_or_default(), encoded.map(|()| buf)));
            }
            Self::Ordered { ser, .. } => {
                stacker::maybe_grow(256 * 1024, 4 * 1024 * 1024, || value.serialize(&mut **ser))?;
            }
        }
        Ok(())
    }

    fn end(self) -> Result<(), Error> {
        match self {
            Self::Sorted {
                ser, mut entries, ..
            } => {
                entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                ser.out.push(b'{');
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        ser.out.push(b',');
                    }
                    append_string(ser.out, key, ser.escape_html);
                    ser.out.push(b':');
                    match value {
                        Ok(bytes) => ser.out.extend_from_slice(bytes),
                        Err(err) => return Err(err.clone()),
                    }
                }
                ser.out.push(b'}');
            }
            Self::Ordered { ser, .. } => ser.out.push(b'}'),
        }
        Ok(())
    }
}

/// Resolves map keys the way `resolveKeyName` does, and unwraps this crate's marker newtypes.
struct StringCapture;

fn unsupported_key() -> Error {
    Error("json: unsupported type: map key is not a string or integer".to_string())
}

impl ser::Serializer for StringCapture {
    type Ok = Vec<u8>;
    type Error = Error;
    type SerializeSeq = Impossible<Vec<u8>, Error>;
    type SerializeTuple = Impossible<Vec<u8>, Error>;
    type SerializeTupleStruct = Impossible<Vec<u8>, Error>;
    type SerializeTupleVariant = Impossible<Vec<u8>, Error>;
    type SerializeMap = Impossible<Vec<u8>, Error>;
    type SerializeStruct = Impossible<Vec<u8>, Error>;
    type SerializeStructVariant = Impossible<Vec<u8>, Error>;

    fn serialize_bool(self, _v: bool) -> Result<Vec<u8>, Error> {
        Err(unsupported_key())
    }
    fn serialize_i8(self, v: i8) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_i16(self, v: i16) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_i32(self, v: i32) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_i64(self, v: i64) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_u8(self, v: u8) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_u16(self, v: u16) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_u32(self, v: u32) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_u64(self, v: u64) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_f32(self, _v: f32) -> Result<Vec<u8>, Error> {
        Err(unsupported_key())
    }
    fn serialize_f64(self, _v: f64) -> Result<Vec<u8>, Error> {
        Err(unsupported_key())
    }
    fn serialize_char(self, v: char) -> Result<Vec<u8>, Error> {
        Ok(v.to_string().into_bytes())
    }
    fn serialize_str(self, v: &str) -> Result<Vec<u8>, Error> {
        Ok(v.as_bytes().to_vec())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(v.to_vec())
    }
    fn serialize_none(self) -> Result<Vec<u8>, Error> {
        Err(unsupported_key())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>, Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Vec<u8>, Error> {
        Err(unsupported_key())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Vec<u8>, Error> {
        Err(unsupported_key())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Vec<u8>, Error> {
        Ok(variant.as_bytes().to_vec())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Vec<u8>, Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Vec<u8>, Error> {
        Err(unsupported_key())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(unsupported_key())
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(unsupported_key())
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(unsupported_key())
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(unsupported_key())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(unsupported_key())
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Err(unsupported_key())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(unsupported_key())
    }
}
