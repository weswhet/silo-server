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
//! Decoding is not covered here, apart from `Deserialize` on [`RawMessage`], [`Number`], and
//! [`crate::time::GoTime`]. `serde_json::from_slice` differs from `json.Unmarshal` on key case folding,
//! duplicate keys, lone surrogates, and `null` into non-pointers.

mod scanner;
mod ser;

pub use scanner::{SyntaxError, check_valid, compact, html_escape, indent, valid};
pub use ser::{Encoder, Error, marshal, marshal_indent, marshal_to_string};

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

pub(crate) const RAW_MESSAGE_TOKEN: &str = "$silo_gocompat::json::RawMessage";
pub(crate) const NUMBER_TOKEN: &str = "$silo_gocompat::json::Number";
pub(crate) const BYTE_STRING_TOKEN: &str = "$silo_gocompat::json::ByteString";
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
    /// Keeps the document's bytes as received, like `RawMessage.UnmarshalJSON`. It needs a
    /// `serde_json` deserializer.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        Ok(Self(Some(raw.get().as_bytes().to_vec())))
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
    /// `json.Unmarshal` into a `json.Number`. `null` leaves it empty. It needs a `serde_json`
    /// deserializer.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        let text = raw.get();
        match text.as_bytes().first() {
            Some(b'n') => Ok(Self::default()),
            Some(b'"') => {
                let unquoted: String =
                    serde_json::from_str(text).map_err(serde::de::Error::custom)?;
                if !scanner::is_valid_number(unquoted.as_bytes()) {
                    return Err(serde::de::Error::custom(format!(
                        "json: invalid number literal, trying to unmarshal {} into Number",
                        crate::strconv::quote(text)
                    )));
                }
                Ok(Self(unquoted))
            }
            Some(b'-' | b'0'..=b'9') => Ok(Self(text.to_string())),
            _ => Err(serde::de::Error::custom(
                "json: cannot unmarshal value into Go value of type json.Number",
            )),
        }
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
