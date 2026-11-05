//! A bound argument, carrying the Go type pgx would have encoded it from.

use bytes::{BufMut, BytesMut};
use serde_json::Value;
use silo_pg::pg_types::{Format, IsNull, ToSql, Type, to_sql_checked};

/// One query argument. `Value` is a `QueryRule.Value` passed through as Go's `any`: a JSON number is a
/// Go `float64`, an array `[]interface {}`, and so on.
#[derive(Clone, Debug, PartialEq)]
pub enum Arg {
    /// A Go `int`.
    Int(i64),
    Str(String),
    Bool(bool),
    /// A Go `[]int`.
    Ints(Vec<i64>),
    Strs(Vec<String>),
    Value(Value),
    /// A Go `time.Time`.
    Time(silo_gocompat::time::GoTime),
}

impl Arg {
    /// The Go type name, as `%T` prints it.
    pub fn go_type(&self) -> &'static str {
        match self {
            Arg::Int(_) => "int",
            Arg::Str(_) => "string",
            Arg::Bool(_) => "bool",
            Arg::Ints(_) => "[]int",
            Arg::Strs(_) => "[]string",
            Arg::Time(_) => "time.Time",
            Arg::Value(v) => match v {
                Value::Null => "<nil>",
                Value::Bool(_) => "bool",
                Value::Number(n) if n.is_f64() => "float64",
                Value::Number(_) => "int",
                Value::String(_) => "string",
                Value::Array(_) => "[]interface {}",
                Value::Object(_) => "map[string]interface {}",
            },
        }
    }

    /// The value as JSON, as the vectors record it.
    pub fn json(&self) -> Value {
        match self {
            Arg::Int(v) => Value::from(*v),
            Arg::Str(v) => Value::from(v.clone()),
            Arg::Bool(v) => Value::from(*v),
            Arg::Ints(v) => Value::from(v.clone()),
            Arg::Strs(v) => Value::from(v.clone()),
            Arg::Value(v) => v.clone(),
            Arg::Time(t) => Value::from(t.rfc3339_nano()),
        }
    }

    /// The argument in PostgreSQL's text input syntax, or `None` for SQL NULL. Arguments bind in text
    /// format, so the server parses them for the parameter type it inferred, as pgx's text encoding
    /// of a Go value into a foreign type does.
    fn text(&self) -> Option<String> {
        fn array<T: AsRef<str>>(items: &[T]) -> String {
            let quoted: Vec<String> = items
                .iter()
                .map(|s| {
                    let s = s.as_ref();
                    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
                })
                .collect();
            format!("{{{}}}", quoted.join(","))
        }
        fn number(v: &serde_json::Number) -> String {
            match v.as_f64() {
                Some(f) if f.fract() == 0.0 && f.abs() < 1e15 => format!("{}", f as i64),
                Some(f) => format!("{f}"),
                None => v.to_string(),
            }
        }
        Some(match self {
            Arg::Int(v) => v.to_string(),
            Arg::Str(v) => v.clone(),
            Arg::Bool(v) => v.to_string(),
            Arg::Ints(v) => format!(
                "{{{}}}",
                v.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
            ),
            Arg::Strs(v) => array(v),
            Arg::Time(t) => t.rfc3339_nano(),
            Arg::Value(v) => match v {
                Value::Null => return None,
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => number(n),
                Value::String(s) => s.clone(),
                Value::Array(items) => array(
                    &items
                        .iter()
                        .map(|i| match i {
                            Value::String(s) => s.clone(),
                            Value::Number(n) => number(n),
                            other => other.to_string(),
                        })
                        .collect::<Vec<_>>(),
                ),
                Value::Object(_) => v.to_string(),
            },
        })
    }
}

impl ToSql for Arg {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self.text() {
            None => Ok(IsNull::Yes),
            Some(text) => {
                out.put_slice(text.as_bytes());
                Ok(IsNull::No)
            }
        }
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }

    fn encode_format(&self, _ty: &Type) -> Format {
        Format::Text
    }

    to_sql_checked!();
}
