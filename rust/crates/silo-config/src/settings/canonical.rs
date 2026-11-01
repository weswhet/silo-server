//! RFC 8785 canonical bytes of the manifest, its public projection, and their entity tags.

use crate::gojson::{self, Node, Value};
use crate::settings::load::{MANIFEST_JSON, SCHEMA_FILES};
use crate::settings::strictjson::{reject_duplicate_keys, reject_lone_surrogates};
use sha2::{Digest, Sha256};
use silo_gocompat::strconv::format_float;
use std::sync::OnceLock;

struct Canonical {
    manifest: Vec<u8>,
    public: Vec<u8>,
    etag: String,
    public_etag: String,
}

static CANONICAL: OnceLock<Result<Canonical, String>> = OnceLock::new();

fn compute() -> Result<Canonical, String> {
    crate::settings::load::load()?;
    let manifest = canonicalize(MANIFEST_JSON)?;
    let public = build_public(MANIFEST_JSON)?;
    let etag = digest_with_schemas(&manifest)?;
    let public_etag = digest_with_schemas(&public)?;
    Ok(Canonical {
        manifest,
        public,
        etag,
        public_etag,
    })
}

fn canonical() -> Result<&'static Canonical, String> {
    CANONICAL
        .get_or_init(compute)
        .as_ref()
        .map_err(String::clone)
}

/// `settingscontract.CanonicalBytes`.
pub fn canonical_bytes() -> Result<Vec<u8>, String> {
    canonical().map(|c| c.manifest.clone())
}

/// `settingscontract.ETag`, a strong HTTP entity tag.
pub fn etag() -> Result<String, String> {
    canonical().map(|c| c.etag.clone())
}

/// `settingscontract.PublicBytes`: the canonical manifest with `notes` removed.
pub fn public_bytes() -> Result<Vec<u8>, String> {
    canonical().map(|c| c.public.clone())
}

/// `settingscontract.PublicETag`.
pub fn public_etag() -> Result<String, String> {
    canonical().map(|c| c.public_etag.clone())
}

fn build_public(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut doc = decode_json(raw)?;
    if let Value::Object(root) = &mut doc.value
        && let Some((_, defs)) = root.iter_mut().find(|(k, _)| k == "definitions")
        && let Value::Array(items) = &mut defs.value
    {
        for item in items {
            if let Value::Object(def) = &mut item.value {
                def.retain(|(k, _)| k != "notes");
            }
        }
    }
    canonicalize_value(&doc)
}

fn digest_with_schemas(manifest: &[u8]) -> Result<String, String> {
    let mut names: Vec<&(&str, &[u8])> = SCHEMA_FILES.iter().collect();
    names.sort_by_key(|f| f.0);
    let mut digest = Sha256::new();
    digest.update(manifest);
    for (name, body) in names {
        let canon =
            canonicalize(body).map_err(|e| format!("canonicalizing value schema {name}: {e}"))?;
        digest.update(format!("\n{}:{}\n{}:", name.len(), name, canon.len()).as_bytes());
        digest.update(&canon);
    }
    let sum = digest.finalize();
    let hex: String = sum.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("\"{hex}\""))
}

fn decode_json(raw: &[u8]) -> Result<Node, String> {
    reject_lone_surrogates(raw)
        .map_err(|e| format!("canonicalization refused a lone surrogate: {e}"))?;
    reject_duplicate_keys(raw)
        .map_err(|e| format!("canonicalization refused a duplicate key: {e}"))?;
    let (node, _) =
        gojson::decode_first(raw).map_err(|e| format!("parsing JSON for canonicalization: {e}"))?;
    Ok(node)
}

/// The JCS canonicalization of a JSON document.
pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, String> {
    let doc = decode_json(raw)?;
    canonicalize_value(&doc)
}

fn canonicalize_value(doc: &Node) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    write_canonical(&mut out, &doc.value)?;
    Ok(out)
}

fn write_canonical(out: &mut Vec<u8>, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(canonical_number(n)?.as_bytes()),
        Value::String(s) => write_canonical_string(out, s),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(out, &item.value)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<&(String, Node)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (key, member)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical_string(out, key);
                out.push(b':');
                write_canonical(out, &member.value)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_canonical_string(out: &mut Vec<u8>, value: &str) {
    out.push(b'"');
    for r in value.chars() {
        match r {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn canonical_number(number: &str) -> Result<String, String> {
    let parsed =
        crate::goparse::parse_float(number).map_err(|e| format!("parsing number {number}: {e}"))?;
    if parsed.is_nan() || parsed.is_infinite() {
        return Err(format!(
            "NaN and infinities cannot be canonicalized: {number}"
        ));
    }
    format_ecmascript(parsed)
}

fn format_ecmascript(value: f64) -> Result<String, String> {
    if value == 0.0 {
        return Ok("0".to_owned());
    }
    let (sign, value) = if value < 0.0 {
        ("-", -value)
    } else {
        ("", value)
    };
    let scientific = format_float(value, b'e', -1, 64);
    let (mantissa, exp) = scientific
        .split_once('e')
        .ok_or_else(|| format!("unexpected float formatting for {value}"))?;
    let exponent: i32 = exp
        .parse()
        .map_err(|e| format!("parsing exponent of {value}: {e}"))?;
    let digits = mantissa.replacen('.', "", 1);
    let k = digits.len() as i32;
    let n = exponent + 1;
    if k <= n && n <= 21 {
        return Ok(format!("{sign}{digits}{}", "0".repeat((n - k) as usize)));
    }
    if 0 < n && n <= 21 {
        return Ok(format!(
            "{sign}{}.{}",
            &digits[..n as usize],
            &digits[n as usize..]
        ));
    }
    if -6 < n && n <= 0 {
        return Ok(format!("{sign}0.{}{digits}", "0".repeat((-n) as usize)));
    }
    let suffix = if n - 1 < 0 {
        format!("e-{}", 1 - n)
    } else {
        format!("e+{}", n - 1)
    };
    if k == 1 {
        return Ok(format!("{sign}{digits}{suffix}"));
    }
    Ok(format!("{sign}{}.{}{suffix}", &digits[..1], &digits[1..]))
}
