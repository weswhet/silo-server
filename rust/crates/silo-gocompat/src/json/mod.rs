//! Output-side port of Go's `encoding/json`, on top of serde.
//!
//! Serialize any `#[derive(Serialize)]` type with [`marshal`] and get the bytes `json.Marshal`
//! would produce for the matching Go type:
//!
//! - Whole floats print without a fraction (`120`, not `120.0`), and very large or small ones use
//!   Go's exponent form (`1e+21`, `1e-7`).
//! - `<`, `>`, `&`, U+2028, and U+2029 are escaped. Only U+2028 and U+2029 stay escaped with
//!   [`Encoder::set_escape_html`]`(false)`.
//! - Maps sort by key bytes. Struct fields keep declaration order.
//! - NaN and infinities are errors with Go's text.
//!
//! What a Go struct's tags mean in serde terms:
//!
//! | Go | Rust |
//! |---|---|
//! | `omitempty` | `#[serde(skip_serializing_if = "omit_empty")]` |
//! | `omitempty` on a nil-able slice or map | `#[serde(skip_serializing_if = "omit_nil_or_empty")]` |
//! | `omitzero` on `time.Time` | `#[serde(skip_serializing_if = "GoTime::is_zero")]` |
//! | embedded struct | `#[serde(flatten)]`, which keeps field position |
//! | nil slice or map, nil pointer | `Option<..>` set to `None`, which prints `null` |
//! | `[]byte` | `#[serde(with = "bytes")]`, or [`Bytes`] for a nil-able value |
//! | `json.RawMessage` | [`RawMessage`] |
//! | `json.Number` | [`Number`] |
//! | `time.Time` | [`crate::time::GoTime`], which also omits nothing under `omitempty` |
//! | `string` holding invalid UTF-8 | [`ByteString`] |
//!
//! `#[serde(flatten)]` serializes through an unsized map, so the serializer keeps those maps in
//! insertion order. It does not apply Go's rules for conflicting embedded field names.
//!
//! Decoding is [`decode`]'s job: [`unmarshal`], [`Decoder`], and [`Stream`] reproduce
//! `json.Unmarshal` and `json.Decoder` on top of `#[derive(Deserialize)]`, which
//! `serde_json::from_slice` does not. That module's docs give the field conventions and the known
//! differences.

mod decode;
mod scanner;
mod ser;

pub use decode::{Decoder, Error as DecodeError, Stream, unmarshal};
pub use scanner::{SyntaxError, check_valid, compact, html_escape, indent, valid};
pub use ser::{Encoder, Error, marshal, marshal_indent, marshal_to_string};

use serde::de::{Deserializer, SeqAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

pub(crate) const RAW_MESSAGE_TOKEN: &str = "$silo_gocompat::json::RawMessage";
pub(crate) const NUMBER_TOKEN: &str = "$silo_gocompat::json::Number";
pub(crate) const BYTE_STRING_TOKEN: &str = "$silo_gocompat::json::ByteString";
pub(crate) const TIME_TOKEN: &str = "$silo_gocompat::json::Time";
pub(crate) const SERDE_JSON_RAW_TOKEN: &str = "$serde_json::private::RawValue";

/// Passes a byte slice through serde so the Go-compatible serializer can pick it up.
struct RawBytes<'a>(&'a [u8]);

impl Serialize for RawBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

/// `json.RawMessage`. `nil` prints `null`. Other values are validated, compacted, and HTML-escaped
/// by the encoder, exactly like a Go `MarshalJSON` result, so a stored document does not come out
/// byte-identical if it has whitespace or `<`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawMessage(Option<Vec<u8>>);

impl RawMessage {
    /// The nil message.
    pub const fn nil() -> Self {
        Self(None)
    }

    /// The raw bytes, `None` for nil.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }

    /// True for a nil message, which `len(m) == 0` also covers for an empty one in Go.
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_none_or(Vec::is_empty)
    }
}

impl From<Vec<u8>> for RawMessage {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Some(bytes))
    }
}

impl From<&[u8]> for RawMessage {
    fn from(bytes: &[u8]) -> Self {
        Self(Some(bytes.to_vec()))
    }
}

impl From<&str> for RawMessage {
    fn from(text: &str) -> Self {
        Self(Some(text.as_bytes().to_vec()))
    }
}

impl From<String> for RawMessage {
    fn from(text: String) -> Self {
        Self(Some(text.into_bytes()))
    }
}

impl Serialize for RawMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            None => serializer.serialize_unit(),
            Some(bytes) => serializer.serialize_newtype_struct(RAW_MESSAGE_TOKEN, &RawBytes(bytes)),
        }
    }
}

impl<'de> Deserialize<'de> for RawMessage {
    /// Keeps the value's exact document bytes, like `RawMessage.UnmarshalJSON`, through
    /// [`unmarshal`] or [`Decoder`]. Other deserializers must be `serde_json`'s.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawMessage;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<RawMessage, E> {
                Ok(RawMessage(Some(v)))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<RawMessage, E> {
                Ok(RawMessage(None))
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                d: D,
            ) -> Result<RawMessage, D::Error> {
                let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
                Ok(RawMessage(Some(raw.get().as_bytes().to_vec())))
            }
        }
        deserializer.deserialize_newtype_struct(RAW_MESSAGE_TOKEN, V)
    }
}

/// `json.Number`: printed verbatim after a grammar check. The empty value prints `0`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Number(pub String);

impl Serialize for Number {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_struct(NUMBER_TOKEN, &RawBytes(self.0.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for Number {
    /// Keeps a number literal's exact text and accepts a string holding a valid number, like
    /// `json.Unmarshal` into a `json.Number`. `null` is a no-op. Deserializers other than
    /// [`unmarshal`] and [`Decoder`] must be `serde_json`'s.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Number;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON number")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Number, E> {
                Ok(Number(v.to_string()))
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Number, D::Error> {
                let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
                let text = raw.get();
                match text.as_bytes().first() {
                    Some(b'n') => Ok(Number::default()),
                    Some(b'"') => {
                        #[allow(clippy::disallowed_methods)] // Unquoting serde_json's own raw text.
                        let unquoted: String =
                            serde_json::from_str(text).map_err(serde::de::Error::custom)?;
                        if !scanner::is_valid_number(unquoted.as_bytes()) {
                            return Err(serde::de::Error::custom(format!(
                                "json: invalid number literal, trying to unmarshal {} into Number",
                                crate::strconv::quote(text)
                            )));
                        }
                        Ok(Number(unquoted))
                    }
                    Some(b'-' | b'0'..=b'9') => Ok(Number(text.to_string())),
                    _ => Err(serde::de::Error::custom(
                        "json: cannot unmarshal value into Go value of type json.Number",
                    )),
                }
            }
        }
        deserializer.deserialize_newtype_struct(NUMBER_TOKEN, V)
    }
}

/// A Go `string` that may hold invalid UTF-8, such as a raw file path. The encoder writes each
/// invalid byte as `�`, while a valid U+FFFD stays as its UTF-8 bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ByteString(pub Vec<u8>);

impl Serialize for ByteString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_struct(BYTE_STRING_TOKEN, &RawBytes(&self.0))
    }
}

/// A Go `[]byte` value: standard base64, `null` when nil, `""` when empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bytes(pub Option<Vec<u8>>);

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            None => serializer.serialize_unit(),
            Some(bytes) => serializer.serialize_bytes(bytes),
        }
    }
}

/// Accepts what Go accepts for `[]byte`: standard base64, or an array of numbers.
struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a base64 string or an array of bytes")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        decode::base64_decode_standard(v.as_bytes()).map_err(E::custom)
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        decode::base64_decode_standard(v).map_err(E::custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
        let mut out = Vec::new();
        while let Some(b) = seq.next_element()? {
            out.push(b);
        }
        Ok(out)
    }
}

struct NonNilBytes(Vec<u8>);

impl<'de> Deserialize<'de> for NonNilBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_byte_buf(BytesVisitor).map(Self)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(
            Option::<NonNilBytes>::deserialize(deserializer)?.map(|b| b.0),
        ))
    }
}

/// `#[serde(with = "silo_gocompat::json::bytes")]` for a non-nil `[]byte` field. Serde's default for
/// `Vec<u8>` is an array of numbers, which is what Go prints for `[N]byte`, not `[]byte`.
pub mod bytes {
    use serde::Serializer;

    /// Writes the bytes as standard base64.
    pub fn serialize<T: AsRef<[u8]>, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value.as_ref())
    }

    /// Reads standard base64, or an array of numbers, as Go does for `[]byte`.
    pub fn deserialize<'de, T: From<Vec<u8>>, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        deserializer
            .deserialize_byte_buf(super::BytesVisitor)
            .map(T::from)
    }
}

/// Go's `omitempty` test, for use as `#[serde(skip_serializing_if = "omit_empty")]`.
pub fn omit_empty<T: OmitEmpty + ?Sized>(value: &T) -> bool {
    value.omit_empty()
}

/// Go's `omitempty` test for a nil-able slice or map held as `Option<Vec<T>>` or `Option<HashMap<..>>`:
/// nil and empty both drop, unlike [`omit_empty`] on an `Option`, which models a pointer and drops
/// only nil.
pub fn omit_nil_or_empty<T: OmitEmpty>(value: &Option<T>) -> bool {
    value.as_ref().is_none_or(OmitEmpty::omit_empty)
}

/// The values `omitempty` drops: false, 0, nil pointers and interfaces, and empty strings, slices,
/// arrays, and maps. `time.Time` and other structs have no implementation because Go never drops
/// them under `omitempty`.
pub trait OmitEmpty {
    /// True when Go's `isEmptyValue` is true for this value.
    fn omit_empty(&self) -> bool;
}

macro_rules! omit_empty_eq {
    ($zero:expr; $($t:ty),* $(,)?) => {
        $(impl OmitEmpty for $t {
            fn omit_empty(&self) -> bool {
                *self == $zero
            }
        })*
    };
}

omit_empty_eq!(0; i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);
omit_empty_eq!(false; bool);
omit_empty_eq!(0.0; f32, f64);

macro_rules! omit_empty_len {
    ($([$($gen:tt)*] $t:ty),* $(,)?) => {
        $(impl<$($gen)*> OmitEmpty for $t {
            fn omit_empty(&self) -> bool {
                self.is_empty()
            }
        })*
    };
}

omit_empty_len!(
    [] String,
    [] str,
    [T] Vec<T>,
    [T] [T],
    [K, V, H] std::collections::HashMap<K, V, H>,
    [K, V] std::collections::BTreeMap<K, V>,
    [] serde_json::Map<String, serde_json::Value>,
    [] RawMessage,
);

impl<T> OmitEmpty for Option<T> {
    /// Covers a nil pointer, interface, slice, or map.
    fn omit_empty(&self) -> bool {
        self.is_none()
    }
}

impl OmitEmpty for Number {
    fn omit_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl OmitEmpty for Bytes {
    fn omit_empty(&self) -> bool {
        self.0.as_ref().is_none_or(Vec::is_empty)
    }
}

impl OmitEmpty for serde_json::Value {
    /// A `serde_json::Value` stands in for `any`, which only `nil` makes empty.
    fn omit_empty(&self) -> bool {
        self.is_null()
    }
}

impl OmitEmpty for crate::time::Duration {
    fn omit_empty(&self) -> bool {
        self.0 == 0
    }
}
