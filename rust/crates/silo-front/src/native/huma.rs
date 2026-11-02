//! What Huma does between the middlewares and a handler: parameters, body read, schema validation.
//!
//! The validator covers the schema vocabulary the mounted operations' parameters and bodies use, read
//! from the contract, and errors are in Huma's order: parameters, then the body's properties sorted.

use std::collections::BTreeMap;

use serde_json::Value;
use silo_api_v2::problem::{
    ErrorDetail, HTTP_MAX_BYTES_MESSAGE, HumaErr, Problem, from_huma_error,
};
use silo_http::Request;

/// `MaxJSONBodyBytes`.
pub const MAX_JSON_BODY_BYTES: i64 = 1 << 20;

/// The raw body Huma read, for `rejectNonNullableNulls` and the handler's decode.
#[derive(Clone)]
pub struct RawBody(pub Vec<u8>);

fn schemas() -> &'static Value {
    static DOC: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DOC.get_or_init(|| {
        silo_gocompat::json::unmarshal(silo_contracts::embedded::openapi_v2())
            .expect("the embedded contract is JSON")
    })
}

fn deref(schema: &Value) -> &Value {
    let mut s = schema;
    while let Some(reference) = s["$ref"].as_str() {
        let name = reference.rsplit('/').next().unwrap_or_default();
        s = &schemas()["components"]["schemas"][name];
    }
    s
}

struct Result_ {
    errors: Vec<HumaErr>,
}

impl Result_ {
    fn add(&mut self, location: &str, message: impl Into<String>) {
        self.errors.push(HumaErr::Detail(ErrorDetail {
            location: location.to_owned(),
            message: message.into(),
        }));
    }
}

/// The contract's `pattern`s on the operations this file serves. A pattern not named here is not judged,
/// so a new one has to be added here before its row can be native.
fn matches_pattern(pattern: &str, s: &str) -> bool {
    match pattern {
        "^[1-9][0-9]*$" => {
            let b = s.as_bytes();
            !b.is_empty() && (b'1'..=b'9').contains(&b[0]) && b.iter().all(u8::is_ascii_digit)
        }
        _ => {
            static COMPILED: std::sync::OnceLock<
                std::sync::Mutex<
                    std::collections::HashMap<
                        String,
                        std::sync::Arc<silo_gocompat::regexp::GoRegex>,
                    >,
                >,
            > = std::sync::OnceLock::new();
            let cache = COMPILED.get_or_init(Default::default);
            let mut cache = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !cache.contains_key(pattern) {
                match silo_gocompat::regexp::GoRegex::compile(pattern) {
                    Ok(re) => {
                        cache.insert(pattern.to_owned(), std::sync::Arc::new(re));
                    }
                    Err(_) => return true,
                }
            }
            cache[pattern].match_string(s)
        }
    }
}

fn go_float(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        v.to_string()
    }
}

/// `huma.Validate`.
fn validate(schema: &Value, path: &str, value: &Value, res: &mut Result_) {
    let s = deref(schema);
    // A nullable schema's type is `["string", "null"]`: null passes, and anything else is judged as the type.
    let kind = match &s["type"] {
        Value::Array(types) => {
            if value.is_null() && types.iter().any(|t| t == "null") {
                return;
            }
            types
                .iter()
                .find_map(|t| t.as_str().filter(|t| *t != "null"))
                .unwrap_or_default()
        }
        other => other.as_str().unwrap_or_default(),
    };
    match kind {
        "boolean" => {
            if !value.is_boolean() {
                res.add(path, "expected boolean");
                return;
            }
        }
        "integer" | "number" => {
            let Some(n) = value.as_f64() else {
                res.add(
                    path,
                    if kind == "integer" {
                        "expected integer"
                    } else {
                        "expected number"
                    },
                );
                return;
            };
            if let Some(min) = s["minimum"].as_f64()
                && n < min
            {
                res.add(path, format!("expected number >= {}", go_float(min)));
            }
            if let Some(max) = s["maximum"].as_f64()
                && n > max
            {
                res.add(path, format!("expected number <= {}", go_float(max)));
            }
        }
        "string" => {
            let Some(text) = value.as_str() else {
                res.add(path, "expected string");
                return;
            };
            let length = text.chars().count() as i64;
            if let Some(min) = s["minLength"].as_i64()
                && length < min
            {
                res.add(path, format!("expected length >= {min}"));
            }
            if let Some(max) = s["maxLength"].as_i64()
                && length > max
            {
                res.add(path, format!("expected length <= {max}"));
            }
            if let Some(pattern) = s["pattern"].as_str()
                && !matches_pattern(pattern, text)
            {
                res.add(path, format!("expected string to match pattern {pattern}"));
            }
        }
        "array" => {
            let Some(items) = value.as_array() else {
                res.add(path, "expected array");
                return;
            };
            if let Some(min) = s["minItems"].as_i64()
                && (items.len() as i64) < min
            {
                res.add(path, format!("expected array length >= {min}"));
            }
            if let Some(max) = s["maxItems"].as_i64()
                && (items.len() as i64) > max
            {
                res.add(path, format!("expected array length <= {max}"));
            }
            for (i, item) in items.iter().enumerate() {
                validate(&s["items"], &format!("{path}[{i}]"), item, res);
            }
        }
        "object" => {
            let Some(map) = value.as_object() else {
                res.add(path, "expected object");
                return;
            };
            validate_object(s, path, map, res);
        }
        _ => {}
    }
    if let Some(list) = s["enum"].as_array()
        && !list.contains(value)
    {
        let names: Vec<String> = list
            .iter()
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_owned))
            .collect();
        res.add(
            path,
            format!("expected value to be one of \"{}\"", names.join(", ")),
        );
    }
}

/// `handleMapString`.
fn validate_object(s: &Value, path: &str, map: &serde_json::Map<String, Value>, res: &mut Result_) {
    let empty = serde_json::Map::new();
    let properties = s["properties"].as_object().unwrap_or(&empty);
    let required: Vec<&str> = s["required"]
        .as_array()
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    // `propertyNames` is sorted, and matching a key ignores case.
    let ordered: BTreeMap<&String, &Value> = properties.iter().collect();
    for (name, schema) in ordered {
        let found = map.get(name).or_else(|| {
            map.iter()
                .find(|(k, _)| silo_gocompat::strings::equal_fold(k, name))
                .map(|(_, v)| v)
        });
        let is_required = required.contains(&name.as_str());
        let Some(value) = found else {
            if is_required {
                res.add(
                    path,
                    format!("expected required property {name} to be present"),
                );
            }
            continue;
        };
        if value.is_null() && !is_required {
            continue;
        }
        validate(schema, &format!("{path}.{name}"), value, res);
    }
    if s["additionalProperties"] == Value::Bool(false) {
        for key in map.keys() {
            let known = properties.contains_key(key)
                || properties
                    .keys()
                    .any(|name| silo_gocompat::strings::equal_fold(key, name));
            if !known {
                res.add(&format!("{path}.{key}"), "unexpected property");
            }
        }
    }
}

fn request_id(r: &Request) -> String {
    super::chain::request_id_of(r)
}

/// Reads and judges what the operation declares. The body goes on the request as [`RawBody`].
pub async fn read_input(
    r: &mut Request,
    params: &[(String, String, Value, bool)],
    body: Option<&Value>,
    body_required: bool,
) -> Result<(), Problem> {
    let mut res = Result_ { errors: Vec::new() };
    let (query, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    for (location, name, schema, required) in params {
        let raw = match location.as_str() {
            "path" => r.url_param(name).to_owned(),
            "header" => String::from_utf8_lossy(r.header.get(name)).into_owned(),
            _ => query
                .get(name)
                .and_then(|v| v.first().cloned())
                .unwrap_or_default(),
        };
        let at = format!("{location}.{name}");
        if raw.is_empty() {
            // The guards answer a missing validator with 428 and the gates a missing profile, before Huma.
            let gated = matches!(name.as_str(), "If-Match" | "If-None-Match" | "X-Profile-Id");
            if *required && !gated {
                res.add(&at, format!("required {location} parameter is missing"));
            }
            continue;
        }
        let s = deref(schema);
        let parsed = match s["type"].as_str().unwrap_or_default() {
            "integer" => match raw.parse::<i64>() {
                Ok(n) => Value::from(n),
                Err(_) => {
                    res.add(&at, "invalid integer");
                    continue;
                }
            },
            // `strconv.ParseBool`.
            "boolean" => match raw.as_str() {
                "1" | "t" | "T" | "TRUE" | "true" | "True" => Value::Bool(true),
                "0" | "f" | "F" | "FALSE" | "false" | "False" => Value::Bool(false),
                _ => {
                    res.add(&at, "invalid boolean");
                    continue;
                }
            },
            "array" => Value::Array(
                query
                    .get(name)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
            _ => Value::String(raw),
        };
        validate(schema, &at, &parsed, &mut res);
    }
    let mut status = 422;
    if let Some(schema) = body {
        let limit = MAX_JSON_BODY_BYTES + 1;
        let (bytes, read_error) = r.read_all().await;
        if bytes.len() as i64 >= limit {
            return Err(from_huma_error(
                &request_id(r),
                413,
                "request body is too large",
                &[],
                MAX_JSON_BODY_BYTES,
                HTTP_MAX_BYTES_MESSAGE,
            ));
        }
        if read_error.is_some() {
            return Err(from_huma_error(
                &request_id(r),
                500,
                "cannot read request body",
                &[],
                MAX_JSON_BODY_BYTES,
                HTTP_MAX_BYTES_MESSAGE,
            ));
        }
        if bytes.is_empty() {
            if body_required {
                return Err(from_huma_error(
                    &request_id(r),
                    400,
                    "request body is required",
                    &res.errors,
                    MAX_JSON_BODY_BYTES,
                    HTTP_MAX_BYTES_MESSAGE,
                ));
            }
        } else {
            match silo_gocompat::json::unmarshal::<Value>(&bytes) {
                Err(e) => {
                    status = 400;
                    res.add("body", e.to_string());
                }
                Ok(parsed) => validate(schema, "body", &parsed, &mut res),
            }
        }
        r.extensions.insert(RawBody(bytes));
    }
    if res.errors.is_empty() {
        return Ok(());
    }
    Err(from_huma_error(
        &request_id(r),
        status,
        "validation failed",
        &res.errors,
        MAX_JSON_BODY_BYTES,
        HTTP_MAX_BYTES_MESSAGE,
    ))
}

/// `rejectNonNullableNulls` with nothing nullable.
pub fn reject_nulls(raw: &[u8]) -> Option<Problem> {
    reject_nulls_except(raw, &[])
}

/// `rejectNonNullableNulls`.
pub fn reject_nulls_except(raw: &[u8], nullable: &[&str]) -> Option<Problem> {
    let members: serde_json::Map<String, Value> = silo_gocompat::json::unmarshal(raw).ok()?;
    let mut errors: Vec<silo_api_v2::problem::ProblemError> = members
        .iter()
        .filter(|(name, v)| v.is_null() && !nullable.contains(&name.as_str()))
        .map(|(name, _)| silo_api_v2::problem::ProblemError {
            location: format!("body.{name}"),
            code: "invalid_type".to_owned(),
            detail: "null is not a value for this member; omit it to leave it unchanged".to_owned(),
        })
        .collect();
    if errors.is_empty() {
        return None;
    }
    errors.sort_by(|a, b| a.location.cmp(&b.location));
    Some(
        Problem::new(
            silo_api_v2::problem::validation_failed(),
            "The request did not pass validation; see errors.",
        )
        .with_errors(errors),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(schema: Value, value: Value) -> Vec<(String, String)> {
        let mut res = Result_ { errors: Vec::new() };
        validate(&schema, "body", &value, &mut res);
        res.errors
            .into_iter()
            .map(|e| match e {
                HumaErr::Detail(d) => (d.location, d.message),
                HumaErr::Other(t) => (String::new(), t),
            })
            .collect()
    }

    #[test]
    fn messages_are_humas() {
        let login = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["username", "password"],
            "properties": {
                "username": {"type": "string", "minLength": 1, "maxLength": 3},
                "password": {"type": "string"},
                "flag": {"type": "boolean"},
                "kind": {"type": "string", "enum": ["a", "b"]},
            },
        });
        assert_eq!(
            run(login.clone(), json!([])),
            [("body".to_owned(), "expected object".to_owned())]
        );
        assert_eq!(
            run(
                login.clone(),
                json!({"USERNAME": "abcd", "x": 1, "flag": 1, "kind": "c"})
            ),
            [
                ("body.flag".to_owned(), "expected boolean".to_owned()),
                (
                    "body.kind".to_owned(),
                    "expected value to be one of \"a, b\"".to_owned()
                ),
                (
                    "body".to_owned(),
                    "expected required property password to be present".to_owned()
                ),
                (
                    "body.username".to_owned(),
                    "expected length <= 3".to_owned()
                ),
                ("body.x".to_owned(), "unexpected property".to_owned()),
            ]
        );
        // A required field that is null is judged; an optional one is not.
        assert_eq!(
            run(
                login,
                json!({"username": null, "password": "p", "flag": null})
            ),
            [("body.username".to_owned(), "expected string".to_owned())]
        );
    }

    #[test]
    fn numeric_id_pattern() {
        assert!(matches_pattern("^[1-9][0-9]*$", "12"));
        assert!(!matches_pattern("^[1-9][0-9]*$", "012"));
        assert!(!matches_pattern("^[1-9][0-9]*$", ""));
        assert!(!matches_pattern("^[1-9][0-9]*$", "1a"));
    }
}
