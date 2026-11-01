//! Generates request values from OpenAPI schemas. Only required fields are filled:
//! the point is a body that passes validation, not one that exercises every field.
//! Well-known id fields become `${fact}` placeholders, filled per server at send time.

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

const MAX_DEPTH: usize = 8;

pub fn deref<'a>(root: &'a Value, v: &'a Value) -> &'a Value {
    let mut cur = v;
    for _ in 0..16 {
        let Some(r) = cur.get("$ref").and_then(Value::as_str) else {
            return cur;
        };
        let Some(pointer) = r.strip_prefix('#') else {
            return cur;
        };
        match root.pointer(pointer) {
            Some(next) => cur = next,
            None => return cur,
        }
    }
    cur
}

fn fact_for_key(key: &str, integer: bool) -> Option<String> {
    let k = key.to_ascii_lowercase();
    let fact = match k.as_str() {
        "content_id" | "item_id" | "media_item_id" | "source_content_id" | "target_content_id"
        | "play_content_id" => "movie_id",
        "series_id" => "series_id",
        "episode_id" => "episode_id",
        "file_id" | "media_file_id" | "fileid" => "file_id",
        "library_id" => "library_id",
        "profile_id" => "user_profile_id",
        "user_id" | "account_id" => "member_user_id",
        _ => return None,
    };
    Some(if integer {
        format!("${{{fact}:int}}")
    } else {
        format!("${{{fact}}}")
    })
}

/// A short stable tag derived from the operation, so two created resources do not
/// collide on a unique name while staying identical on both servers.
fn string_for_key(key: &str, tag: &str) -> Option<String> {
    Some(match key.to_ascii_lowercase().as_str() {
        "name" | "title" | "label" | "display_name" => format!("Conformance {tag}"),
        "username" => format!("conf_{}", tag.to_ascii_lowercase()),
        "email" => format!("conf-{}@example.test", tag.to_ascii_lowercase()),
        "password" | "new_password" => "conformance-generated-password".to_string(),
        "current_password" => "conformance-user-password".to_string(),
        "url" | "uri" | "endpoint" | "base_url" | "redirect_uri" => {
            "https://example.test/hook".to_string()
        }
        _ => return None,
    })
}

pub fn generate(root: &Value, schema: &Value, tag: &str) -> Value {
    gen(root, schema, tag, "", 0, &mut BTreeSet::new())
}

fn gen(
    root: &Value,
    schema: &Value,
    tag: &str,
    key: &str,
    depth: usize,
    seen: &mut BTreeSet<String>,
) -> Value {
    let reference = schema
        .get("$ref")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(r) = &reference {
        if !seen.insert(r.clone()) {
            return Value::Null;
        }
    }
    let result = gen_inner(root, deref(root, schema), tag, key, depth, seen);
    if let Some(r) = &reference {
        seen.remove(r);
    }
    result
}

fn gen_inner(
    root: &Value,
    s: &Value,
    tag: &str,
    key: &str,
    depth: usize,
    seen: &mut BTreeSet<String>,
) -> Value {
    if depth > MAX_DEPTH {
        return Value::Null;
    }
    if let Some(v) = s.get("const") {
        return v.clone();
    }
    if let Some(v) = s
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|e| e.first())
    {
        return v.clone();
    }
    if let Some(all) = s.get("allOf").and_then(Value::as_array) {
        let mut merged = Map::new();
        for part in all {
            if let Value::Object(o) = gen(root, part, tag, key, depth + 1, seen) {
                merged.extend(o);
            }
        }
        return Value::Object(merged);
    }
    for alt in ["oneOf", "anyOf"] {
        if let Some(options) = s.get(alt).and_then(Value::as_array) {
            let pick = options
                .iter()
                .find(|o| deref(root, o).get("type").and_then(Value::as_str) != Some("null"))
                .or_else(|| options.first());
            if let Some(p) = pick {
                return gen(root, p, tag, key, depth + 1, seen);
            }
        }
    }
    let ty = match s.get("type") {
        Some(Value::String(t)) => t.as_str(),
        Some(Value::Array(ts)) => ts
            .iter()
            .filter_map(Value::as_str)
            .find(|t| *t != "null")
            .unwrap_or("null"),
        _ if s.get("properties").is_some() => "object",
        _ => "object",
    };
    match ty {
        "object" => {
            let mut out = Map::new();
            let props = s.get("properties").and_then(Value::as_object);
            if let (Some(req), Some(props)) = (s.get("required").and_then(Value::as_array), props) {
                for name in req.iter().filter_map(Value::as_str) {
                    if let Some(p) = props.get(name) {
                        out.insert(name.to_string(), gen(root, p, tag, name, depth + 1, seen));
                    }
                }
            }
            Value::Object(out)
        }
        "array" => {
            let min = s.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            match (s.get("items"), min) {
                (Some(item), n) if n > 0 => {
                    Value::Array(vec![
                        gen(root, item, tag, key, depth + 1, seen);
                        n.min(2) as usize
                    ])
                }
                _ => json!([]),
            }
        }
        "integer" | "number" => {
            if let Some(f) = fact_for_key(key, true) {
                return Value::String(f);
            }
            if let Some(ex) = s
                .get("examples")
                .and_then(Value::as_array)
                .and_then(|e| e.first())
            {
                if ex.is_number() {
                    return ex.clone();
                }
            }
            json!(s.get("minimum").and_then(Value::as_i64).unwrap_or(1).max(1))
        }
        "boolean" => json!(false),
        "null" => Value::Null,
        _ => {
            if let Some(f) = fact_for_key(key, false) {
                return Value::String(f);
            }
            if let Some(v) = string_for_key(key, tag) {
                return Value::String(v);
            }
            if let Some(ex) = s
                .get("examples")
                .and_then(Value::as_array)
                .and_then(|e| e.first())
                .filter(|e| e.is_string())
            {
                return ex.clone();
            }
            let by_format = match s.get("format").and_then(Value::as_str) {
                Some("uuid") => "c0f00000-0000-4000-8000-0000000000ff",
                Some("date-time") => "2030-01-01T00:00:00Z",
                Some("date") => "2030-01-01",
                Some("email") => "conformance@example.test",
                Some("uri") | Some("url") => "https://example.test/",
                Some("binary") | Some("byte") => "AAAA",
                _ => "conformance",
            };
            let min = s.get("minLength").and_then(Value::as_u64).unwrap_or(0) as usize;
            let mut v = by_format.to_string();
            while v.len() < min {
                v.push('x');
            }
            Value::String(v)
        }
    }
}

/// Builds a multipart body from generated JSON fields; binary fields get a tiny file.
pub fn multipart(fields: &Value, boundary: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(o) = fields.as_object() {
        for (k, v) in o {
            let text = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let file = k == "file" || k == "image" || k == "upload" || k == "chunk";
            let disposition = if file {
                format!("form-data; name=\"{k}\"; filename=\"conformance.bin\"")
            } else {
                format!("form-data; name=\"{k}\"")
            };
            out.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: {disposition}\r\n\r\n{text}\r\n")
                    .as_bytes(),
            );
        }
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_only_required_and_follows_refs_and_nullable_unions() {
        let root = json!({"components":{"schemas":{
            "Thing":{"type":"object","required":["name","count","kind","inner"],"properties":{
                "name":{"type":"string"},
                "count":{"type":["integer","null"],"minimum":3},
                "kind":{"enum":["first","second"]},
                "inner":{"oneOf":[{"type":"null"},{"$ref":"#/components/schemas/Inner"}]},
                "optional":{"type":"string"}
            }},
            "Inner":{"type":"object","required":["library_id"],"properties":{"library_id":{"type":"integer"}}}
        }}});
        let got = generate(&root, &json!({"$ref":"#/components/schemas/Thing"}), "Op");
        assert_eq!(
            got,
            json!({
                "name":"Conformance Op","count":3,"kind":"first","inner":{"library_id":"${library_id:int}"}
            })
        );
    }

    #[test]
    fn recursive_schemas_terminate() {
        let root = json!({"components":{"schemas":{"N":{"type":"object","required":["next"],"properties":{"next":{"$ref":"#/components/schemas/N"}}}}}});
        let got = generate(&root, &json!({"$ref":"#/components/schemas/N"}), "t");
        assert_eq!(got, json!({"next":null}));
    }
}
