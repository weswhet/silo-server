//! Parameter and column types for places where pgx's looser conversions matter.
//!
//! `tokio-postgres` checks Rust types against column types strictly. pgx converts: a Go `int` binds
//! to `int4` or `int8`, and a Go `string` binds to `jsonb` or `text`. Verbatim SQL from Go relies on
//! that, so these wrappers reproduce it.

use std::error::Error as StdError;

use bytes::{BufMut, BytesMut};
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type, to_sql_checked};

type BoxError = Box<dyn StdError + Sync + Send>;

/// A Go `int` parameter or column: binds to `int2`, `int4`, or `int8`, with a range check.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnyInt(pub i64);

impl ToSql for AnyInt {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, BoxError> {
        match *ty {
            Type::INT2 => out.put_i16(i16::try_from(self.0)?),
            Type::INT4 => out.put_i32(i32::try_from(self.0)?),
            Type::INT8 => out.put_i64(self.0),
            _ => return Err(format!("cannot bind an integer to {ty}").into()),
        }
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::INT2 | Type::INT4 | Type::INT8)
    }

    to_sql_checked!();
}

impl<'a> FromSql<'a> for AnyInt {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        let value = match *ty {
            Type::INT2 => i64::from(i16::from_be_bytes(raw.try_into()?)),
            Type::INT4 => i64::from(i32::from_be_bytes(raw.try_into()?)),
            Type::INT8 => i64::from_be_bytes(raw.try_into()?),
            _ => return Err(format!("cannot scan {ty} into an integer").into()),
        };
        Ok(AnyInt(value))
    }

    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::INT2 | Type::INT4 | Type::INT8)
    }
}

/// A Go `string` parameter: binds to text-like columns and to `json` and `jsonb`.
#[derive(Clone, Copy, Debug)]
pub struct PgText<'a>(pub &'a str);

impl ToSql for PgText<'_> {
    fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, BoxError> {
        if *ty == Type::JSONB {
            out.put_u8(1);
        }
        out.put_slice(self.0.as_bytes());
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        is_text_like(ty) || matches!(*ty, Type::JSON | Type::JSONB)
    }

    to_sql_checked!();
}

/// A column read as its text: text-like columns, plus `json` and `jsonb`, whose text is what Go's
/// `[]byte` and `string` scans see.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextValue(pub String);

impl<'a> FromSql<'a> for TextValue {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        let body = if *ty == Type::JSONB {
            match raw.split_first() {
                Some((1, rest)) => rest,
                _ => return Err("unsupported jsonb version".into()),
            }
        } else {
            raw
        };
        Ok(TextValue(std::str::from_utf8(body)?.to_owned()))
    }

    fn accepts(ty: &Type) -> bool {
        is_text_like(ty) || matches!(*ty, Type::JSON | Type::JSONB)
    }
}

fn is_text_like(ty: &Type) -> bool {
    matches!(
        *ty,
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::UNKNOWN
    ) || ty.name() == "citext"
}

/// pgvector's `vector`, in its binary form: dimension, a reserved zero, then big-endian `f32`s.
#[derive(Clone, Debug, PartialEq)]
pub struct Vector(pub Vec<f32>);

/// pgvector's `halfvec`, in its binary form: dimension, a reserved zero, then big-endian `f16`s.
///
/// A halfvec parameter has to be this type to go in binary, as in Go.
#[derive(Clone, Debug, PartialEq)]
pub struct HalfVector(pub Vec<f32>);

fn vector_header(raw: &[u8], element: usize) -> Result<&[u8], BoxError> {
    if raw.len() < 4 {
        return Err("vector value is shorter than its header".into());
    }
    let dim = usize::from(u16::from_be_bytes([raw[0], raw[1]]));
    if u16::from_be_bytes([raw[2], raw[3]]) != 0 {
        return Err("expected unused to be 0".into());
    }
    let body = &raw[4..];
    if body.len() != dim * element {
        return Err(format!("vector has {} value bytes for dimension {dim}", body.len()).into());
    }
    Ok(body)
}

fn put_header(out: &mut BytesMut, len: usize) -> Result<(), BoxError> {
    out.put_u16(u16::try_from(len)?);
    out.put_u16(0);
    Ok(())
}

impl ToSql for Vector {
    fn to_sql(&self, _: &Type, out: &mut BytesMut) -> Result<IsNull, BoxError> {
        put_header(out, self.0.len())?;
        for value in &self.0 {
            out.put_f32(*value);
        }
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "vector"
    }

    to_sql_checked!();
}

impl<'a> FromSql<'a> for Vector {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        let body = vector_header(raw, 4)?;
        Ok(Vector(
            body.as_chunks::<4>()
                .0
                .iter()
                .map(|c| f32::from_be_bytes(*c))
                .collect(),
        ))
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "vector"
    }
}

impl ToSql for HalfVector {
    fn to_sql(&self, _: &Type, out: &mut BytesMut) -> Result<IsNull, BoxError> {
        put_header(out, self.0.len())?;
        for value in &self.0 {
            out.put_u16(half::f16::from_f32(*value).to_bits());
        }
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "halfvec"
    }

    to_sql_checked!();
}

impl<'a> FromSql<'a> for HalfVector {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        let body = vector_header(raw, 2)?;
        Ok(HalfVector(
            body.as_chunks::<2>()
                .0
                .iter()
                .map(|c| half::f16::from_bits(u16::from_be_bytes(*c)).to_f32())
                .collect(),
        ))
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "halfvec"
    }
}
