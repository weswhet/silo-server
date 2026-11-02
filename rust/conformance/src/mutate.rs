//! The faults `conformance-mutproxy` injects into candidate answers, to prove the
//! differ reports them. Each one changes one response the way a port could, and logs
//! what it did so `check` can confirm the same case reported a difference there.
//!
//! Faults apply only to requests the runner tagged with its case id (`--tag-cases`),
//! so logins and liveness probes stay honest and every fault maps to one case.

use crate::normalize::{b64url_encode, render_path, Format, Rule, Rules, Step};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const CASE_TAG_HEADER: &str = "X-Conformance-Case";

/// One fault per response at one site, chosen by a hash of the case id.
pub const SINGLE_SITE: &[&str] = &[
    "drop_field",
    "rename_field",
    "field_case",
    "extra_field",
    "int_to_string",
    "int_to_float",
    "number_change",
    "bool_flip",
    "string_change",
    "null_to_missing",
    "value_to_null",
    "empty_array_to_null",
    "null_to_empty_array",
    "array_drop_last",
    "enum_reorder",
    "enum_value_case",
    "changed_status",
    "problem_code",
    "content_type",
    "content_type_drop",
    "drop_etag",
    "weaken_etag",
    "unquote_etag",
    "ignore_if_none_match",
    "cursor_shape",
    "timestamp_format",
    "redirect_change",
    "trailing_slash",
    "jf_auth_case",
    "bytes_flip",
    "truncate_body",
    "duplicate_key",
    "drop_header",
    "add_header",
    "header_value",
    "head_content_length",
    "created_id_format",
    "reused_created_id",
    "id_not_requested",
];

/// Every site a normalizer covers, in one response.
pub const RULE_PROBES: &[&str] = &["rule_out_of_format", "rule_in_format"];

/// Changes that must not be reported, to prove the proxy itself is transparent.
pub const CONTROLS: &[&str] = &["none", "reserialize"];

/// Faults in the request the candidate receives: the answer stays right, and the write is wrong.
pub const REQUEST_FAULTS: &[&str] = &["wrong_write"];

/// `wrong_write`: changes one written value, so an empty 204 can only show the fault in the row it stored.
pub fn apply_request_fault(case: &str, method: &str, body: &[u8]) -> Option<(Vec<u8>, Applied)> {
    if !matches!(method, "PUT" | "PATCH" | "POST") {
        return None;
    }
    let mut doc: Value = serde_json::from_slice(body).ok()?;
    let object = doc.as_object_mut()?;
    let (field, before, after) = if let Some(flag) = object.get("value").and_then(Value::as_bool) {
        object.insert("value".to_string(), Value::Bool(!flag));
        ("value", flag.to_string(), (!flag).to_string())
    } else {
        let field = ["name", "label", "title"]
            .into_iter()
            .find(|k| object.get(*k).is_some_and(Value::is_string))?;
        let text = object[field].as_str()?.to_string();
        let changed = format!("{text}x");
        object.insert(field.to_string(), Value::String(changed.clone()));
        (field, text, changed)
    };
    Some((
        serde_json::to_vec(&doc).ok()?,
        Applied {
            case: case.to_string(),
            mutation: "wrong_write".to_string(),
            at: "effect".to_string(),
            before: format!("{field}: {before}"),
            after: format!("{field}: {after}"),
            by_design: false,
            rule: None,
            feed_fault: None,
        },
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Applied {
    pub case: String,
    pub mutation: String,
    /// Where the differ should report it: a JSON path, `status`, `body`, `header:<name>`.
    pub at: String,
    pub before: String,
    pub after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// A rule knowingly accepts this value; it is reported as what the rule allows.
    #[serde(default)]
    pub by_design: bool,
    /// How a feed probe changed the feed, so the check can tell whether the reference could show it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed_fault: Option<FeedFault>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFault {
    Emptied,
    KeyDropped(String),
    KeyRetyped(String),
}

impl FeedFault {
    /// Whether `feeds_alike` can report this fault given the reference's feed. It compares a feed to
    /// the other side's, so a candidate changed to what the reference already has is still alike.
    pub fn observable(&self, reference: &crate::normalize::FeedSummary) -> bool {
        match self {
            FeedFault::Emptied => !reference.empty,
            FeedFault::KeyDropped(k) => reference.universal.contains(k),
            FeedFault::KeyRetyped(k) => reference.typed.contains(k),
        }
    }
}

/// What the proxy saw of the request, with the case id taken apart.
pub struct Req<'a> {
    pub case_id: &'a str,
    pub case_name: &'a str,
    pub surface: &'a str,
    pub method_path: String,
    /// The method on the wire, which a CORS preflight case differs from its route's.
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub headers: &'a [(String, String)],
}

impl<'a> Req<'a> {
    pub fn parse(
        case_id: &'a str,
        method: &'a str,
        path_and_query: &'a str,
        headers: &'a [(String, String)],
    ) -> Option<Req<'a>> {
        let (route, case_name) = case_id.split_once('#')?;
        let (surface, method_path) = route.split_once(' ')?;
        Some(Req {
            case_id,
            case_name,
            surface,
            method_path: method_path.to_string(),
            method,
            path_and_query,
            headers,
        })
    }

    fn path(&self) -> &str {
        self.path_and_query
            .split('?')
            .next()
            .unwrap_or(self.path_and_query)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_etag_replay(&self) -> bool {
        self.header("if-none-match").is_some()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Declare the whole length, send this many bytes, and hang up.
    pub truncate_at: Option<usize>,
    /// Sent as is, for a body serde_json cannot express such as a duplicate key.
    pub raw_json_prefix: Option<Vec<u8>>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
    }

    fn is_json(&self) -> bool {
        self.header("content-type")
            .is_some_and(|v| v.to_ascii_lowercase().contains("json"))
    }
}

/// Headers about the connection, not the answer. Never mutated.
const FRAMING: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "date",
];

fn hash(parts: &[&str], salt: u64) -> u64 {
    let mut h = 0xcbf29ce484222325u64 ^ salt.wrapping_mul(0x100000001b3);
    for p in parts {
        for b in p.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn clip(s: &str) -> String {
    s.chars().take(120).collect()
}

/// Every node with its location, the root included.
fn nodes(v: &Value) -> Vec<Vec<Step>> {
    fn go(v: &Value, here: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
        out.push(here.clone());
        match v {
            Value::Object(m) => {
                for (k, c) in m {
                    here.push(Step::Key(k.clone()));
                    go(c, here, out);
                    here.pop();
                }
            }
            Value::Array(a) => {
                for (i, c) in a.iter().enumerate() {
                    here.push(Step::Index(i));
                    go(c, here, out);
                    here.pop();
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    go(v, &mut Vec::new(), &mut out);
    out
}

fn get<'v>(root: &'v Value, steps: &[Step]) -> Option<&'v Value> {
    let mut v = root;
    for s in steps {
        v = match s {
            Step::Key(k) => v.get(k)?,
            Step::Index(i) => v.get(*i)?,
        };
    }
    Some(v)
}

fn get_mut<'v>(root: &'v mut Value, steps: &[Step]) -> Option<&'v mut Value> {
    let mut v = root;
    for s in steps {
        v = match s {
            Step::Key(k) => v.get_mut(k)?,
            Step::Index(i) => v.get_mut(*i)?,
        };
    }
    Some(v)
}

fn last_key(steps: &[Step]) -> Option<&str> {
    match steps.last() {
        Some(Step::Key(k)) => Some(k),
        _ => None,
    }
}

fn toggle_case(k: &str) -> Option<String> {
    let first = k.chars().next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    let toggled = if first.is_ascii_lowercase() {
        first.to_ascii_uppercase()
    } else {
        first.to_ascii_lowercase()
    };
    Some(format!("{toggled}{}", &k[first.len_utf8()..]))
}

fn is_rfc3339(s: &str) -> bool {
    OffsetDateTime::parse(s, &Rfc3339).is_ok()
}

/// A spelling of the same instant that a strict client parser would treat differently.
fn respell_timestamp(s: &str, pick: u64) -> Option<String> {
    let parsed = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    let whole_seconds = |t: &str| match (t.find('.'), t.rfind(['Z', '+'])) {
        (Some(dot), Some(end)) if dot < end => format!("{}{}", &t[..dot], &t[end..]),
        _ => t.to_string(),
    };
    let candidates = [
        s.strip_suffix('Z').map(|b| format!("{b}+00:00")),
        (whole_seconds(s) != s).then(|| whole_seconds(s)),
        (!s.contains('.')).then(|| s.replacen('Z', ".000Z", 1)),
        Some(s.replacen('T', " ", 1)),
        Some(parsed.unix_timestamp().to_string()),
    ];
    let usable: Vec<String> = candidates
        .into_iter()
        .flatten()
        .filter(|c| c != s)
        .collect();
    (!usable.is_empty()).then(|| usable[pick as usize % usable.len()].clone())
}

fn status_after(s: u16) -> u16 {
    match s {
        200 => 201,
        201 => 200,
        202 => 200,
        204 => 200,
        301 | 308 => 302,
        302 => 301,
        303 | 307 => 302,
        400 => 422,
        401 => 403,
        403 => 401,
        404 => 410,
        405 => 404,
        409 => 400,
        422 => 400,
        500 => 503,
        503 => 500,
        other => other + 1,
    }
}

fn is_cursor_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k.contains("cursor") || k == "completion_token" || k == "next_page_token"
}

/// True when the request authenticates to Jellyfin some way other than the one
/// spelling the harness uses for its identities.
fn noncanonical_jf_auth(req: &Req) -> bool {
    if req.surface != "jellycompat" {
        return false;
    }
    if ["authorization", "x-emby-token", "x-mediabrowser-token"]
        .iter()
        .any(|h| req.header(h).is_some())
    {
        return true;
    }
    if req.header("x-emby-authorization").is_some_and(|v| {
        v.contains("oken") && (!v.contains(", Token=\"") || !v.starts_with("Media"))
    }) {
        return true;
    }
    let q = req
        .path_and_query
        .split_once('?')
        .map_or("", |(_, q)| q)
        .to_ascii_lowercase();
    q.split('&')
        .any(|kv| kv.starts_with("api_key=") || kv.starts_with("apikey="))
}

struct Ctx<'a> {
    name: &'a str,
    req: &'a Req<'a>,
    pick: u64,
    out: Vec<Applied>,
}

impl Ctx<'_> {
    fn log(&mut self, at: impl Into<String>, before: impl AsRef<str>, after: impl AsRef<str>) {
        self.out.push(Applied {
            case: self.req.case_id.to_string(),
            mutation: self.name.to_string(),
            at: at.into(),
            before: clip(before.as_ref()),
            after: clip(after.as_ref()),
            rule: None,
            by_design: false,
            feed_fault: None,
        });
    }

    fn choose<T>(&self, mut items: Vec<T>) -> Option<T> {
        if items.is_empty() {
            return None;
        }
        let i = self.pick as usize % items.len();
        Some(items.swap_remove(i))
    }
}

/// Replaces the value at one chosen site that `want` accepts.
fn replace_leaf(
    ctx: &mut Ctx,
    doc: &mut Value,
    want: impl Fn(&[Step], &Value) -> bool,
    to: impl Fn(&Value) -> Option<Value>,
) -> bool {
    let sites: Vec<Vec<Step>> = nodes(doc)
        .into_iter()
        .filter(|s| get(doc, s).is_some_and(|v| want(s, v) && to(v).is_some()))
        .collect();
    let Some(site) = ctx.choose(sites) else {
        return false;
    };
    let Some(slot) = get_mut(doc, &site) else {
        return false;
    };
    let Some(next) = to(slot) else { return false };
    let before = slot.to_string();
    *slot = next.clone();
    ctx.log(render_path(&site), before, next.to_string());
    true
}

/// Applies a fault to one key of one object.
fn rekey(
    ctx: &mut Ctx,
    doc: &mut Value,
    rename: impl Fn(&str, &Value) -> Option<Option<String>>,
) -> bool {
    let sites: Vec<Vec<Step>> = nodes(doc)
        .into_iter()
        .filter(|s| {
            last_key(s).is_some_and(|k| {
                let v = get(doc, s).unwrap();
                rename(k, v).is_some()
            })
        })
        .collect();
    let Some(site) = ctx.choose(sites) else {
        return false;
    };
    let (parent, key) = site.split_at(site.len() - 1);
    let Step::Key(key) = &key[0] else {
        return false;
    };
    let Some(Value::Object(map)) = get_mut(doc, parent) else {
        return false;
    };
    let Some(value) = map.get(key).cloned() else {
        return false;
    };
    let Some(action) = rename(key, &value) else {
        return false;
    };
    if action.as_ref().is_some_and(|n| map.contains_key(n)) {
        return false;
    }
    map.remove(key);
    let before = value.to_string();
    match action {
        Some(new_key) => {
            let shown = new_key.clone();
            map.insert(new_key, value);
            ctx.log(render_path(&site), format!("{key}: {before}"), shown);
        }
        None => ctx.log(render_path(&site), before, "<absent>"),
    }
    true
}

fn looks_like_id_key(k: &str) -> bool {
    k == "id" || k == "token" || k == "key" || k == "code" || k.ends_with("_id")
}

fn mutate_json(ctx: &mut Ctx, doc: &mut Value, status: u16, name: &str) -> bool {
    match name {
        "drop_field" => rekey(ctx, doc, |_, _| Some(None)),
        "rename_field" => rekey(ctx, doc, |k, _| Some(Some(format!("{k}_renamed")))),
        "field_case" => rekey(ctx, doc, |k, _| toggle_case(k).map(Some)),
        "null_to_missing" => rekey(ctx, doc, |_, v| v.is_null().then_some(None)),
        "extra_field" => {
            let sites: Vec<Vec<Step>> = nodes(doc)
                .into_iter()
                .filter(|s| get(doc, s).is_some_and(Value::is_object))
                .collect();
            let Some(site) = ctx.choose(sites) else {
                return false;
            };
            if let Some(Value::Object(m)) = get_mut(doc, &site) {
                m.insert("conformance_extra".to_string(), json!(1));
            }
            let mut at = site;
            at.push(Step::Key("conformance_extra".to_string()));
            ctx.log(render_path(&at), "<absent>", "1");
            true
        }
        "int_to_string" => replace_leaf(
            ctx,
            doc,
            |_, v| v.is_number(),
            |v| Some(json!(v.to_string())),
        ),
        "int_to_float" => replace_leaf(
            ctx,
            doc,
            |_, v| v.is_i64() || v.is_u64(),
            |v| v.as_f64().map(|f| json!(f)),
        ),
        "number_change" => replace_leaf(
            ctx,
            doc,
            |_, v| v.is_number(),
            |v| match v.as_i64() {
                Some(i) => Some(json!(i.saturating_add(1))),
                None => v.as_f64().map(|f| json!(f + 1.5)),
            },
        ),
        "bool_flip" => replace_leaf(
            ctx,
            doc,
            |_, v| v.is_boolean(),
            |v| v.as_bool().map(|b| json!(!b)),
        ),
        "string_change" => replace_leaf(
            ctx,
            doc,
            |_, v| v.is_string(),
            |v| v.as_str().map(|s| json!(format!("{s}x"))),
        ),
        "value_to_null" => replace_leaf(
            ctx,
            doc,
            |s, v| !s.is_empty() && !v.is_null(),
            |_| Some(Value::Null),
        ),
        "empty_array_to_null" => replace_leaf(
            ctx,
            doc,
            |s, v| !s.is_empty() && v.as_array().is_some_and(Vec::is_empty),
            |_| Some(Value::Null),
        ),
        "null_to_empty_array" => replace_leaf(ctx, doc, |_, v| v.is_null(), |_| Some(json!([]))),
        "array_drop_last" => replace_leaf(
            ctx,
            doc,
            |_, v| v.as_array().is_some_and(|a| !a.is_empty()),
            |v| {
                let mut a = v.as_array()?.clone();
                a.pop();
                Some(Value::Array(a))
            },
        ),
        "enum_reorder" => replace_leaf(
            ctx,
            doc,
            |_, v| {
                // Reversing a palindrome changes nothing, so it would be no fault at all.
                v.as_array().is_some_and(|a| a.iter().ne(a.iter().rev()))
            },
            |v| {
                let mut a = v.as_array()?.clone();
                a.reverse();
                Some(Value::Array(a))
            },
        ),
        "enum_value_case" => replace_leaf(
            ctx,
            doc,
            |_, v| {
                v.as_str().is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 32
                        && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
                })
            },
            |v| v.as_str().map(|s| json!(s.to_ascii_uppercase())),
        ),
        "problem_code" => {
            if status < 400 {
                return false;
            }
            for key in ["code", "error_code", "type", "error", "title"] {
                if let Some(Value::String(s)) = doc.get_mut(key) {
                    let before = s.clone();
                    // Stay in the same alphabet, so a format rule cannot excuse it.
                    let after = if before.len() >= 2 {
                        let mut swapped: Vec<char> = before.chars().collect();
                        let last = swapped.len() - 1;
                        swapped.swap(0, last);
                        if swapped[0] == swapped[last] {
                            swapped[0] = if swapped[0] == 'Z' { 'Y' } else { 'Z' };
                        }
                        swapped.into_iter().collect()
                    } else {
                        format!("{before}x")
                    };
                    *s = after.clone();
                    ctx.log(format!("$.{key}"), before, after);
                    return true;
                }
            }
            false
        }
        "cursor_shape" => replace_leaf(
            ctx,
            doc,
            |s, v| v.is_string() && last_key(s).is_some_and(is_cursor_key),
            |v| {
                v.as_str()
                    .filter(|s| !s.is_empty())
                    .map(|_| json!("cursor:page=2"))
            },
        ),
        "timestamp_format" => {
            let pick = ctx.pick;
            replace_leaf(
                ctx,
                doc,
                |_, v| v.as_str().is_some_and(is_rfc3339),
                |v| {
                    v.as_str()
                        .and_then(|s| respell_timestamp(s, pick))
                        .map(|t| json!(t))
                },
            )
        }
        "created_id_format" => {
            if !matches!(
                ctx.req.method_path.split(' ').next(),
                Some("POST" | "PUT" | "PATCH")
            ) {
                return false;
            }
            replace_leaf(
                ctx,
                doc,
                |s, v| {
                    v.as_str().is_some_and(|x| x.len() >= 8)
                        && s.len() <= 2
                        && last_key(s).is_some_and(looks_like_id_key)
                },
                |_| Some(json!("not-a-generated-id")),
            )
        }
        "reused_created_id" => {
            // One fixed, well-formed id for every generated id the candidate returns.
            if !matches!(
                ctx.req.method_path.split(' ').next(),
                Some("POST" | "PUT" | "PATCH")
            ) {
                return false;
            }
            replace_leaf(
                ctx,
                doc,
                |s, v| {
                    v.as_str().is_some_and(|x| x.len() == 36)
                        && s.len() <= 2
                        && last_key(s) == Some("id")
                },
                |_| Some(json!("c0f00000-0000-4000-8000-0000000c1d00")),
            )
        }
        "id_not_requested" => {
            // Answers about an object other than the one the request named.
            let path = ctx.req.path().to_string();
            replace_leaf(
                ctx,
                doc,
                |s, v| {
                    last_key(s) == Some("id")
                        && s.len() <= 2
                        && v.as_str()
                            .is_some_and(|x| x.len() == 36 && path.contains(x))
                },
                |_| Some(json!("c0f00000-0000-4000-8000-0000000c1d01")),
            )
        }
        _ => false,
    }
}

fn mutate_headers(ctx: &mut Ctx, resp: &mut Resp, name: &str) -> bool {
    let etag = resp.header("etag").map(str::to_string);
    match name {
        "changed_status" => {
            let (before, after) = (resp.status, status_after(resp.status));
            resp.status = after;
            ctx.log("status", before.to_string(), after.to_string());
            true
        }
        "content_type" => {
            let Some(before) = resp.header("content-type").map(str::to_string) else {
                return false;
            };
            let low = before.to_ascii_lowercase();
            let after = if low.contains("problem+json") {
                "application/json".to_string()
            } else if low.contains("json") {
                if ctx.pick.is_multiple_of(2) {
                    "text/plain; charset=utf-8".to_string()
                } else {
                    "application/json; charset=utf-8".to_string()
                }
            } else {
                "application/octet-stream".to_string()
            };
            if after == before {
                return false;
            }
            resp.set_header("Content-Type", &after);
            ctx.log("header:content-type", before, after);
            true
        }
        "content_type_drop" => {
            let Some(before) = resp.header("content-type").map(str::to_string) else {
                return false;
            };
            resp.headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
            ctx.log("header:content-type", before, "<absent>");
            true
        }
        "head_content_length" => {
            if ctx.req.method != "HEAD" {
                return false;
            }
            let Some(before) = resp.header("content-length").map(str::to_string) else {
                return false;
            };
            let after = format!("{before}0");
            resp.set_header("Content-Length", &after);
            ctx.log("header:content-length", before, after);
            true
        }
        "drop_etag" => {
            let Some(before) = etag else { return false };
            resp.headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("etag"));
            ctx.log("header:etag", before, "<absent>");
            true
        }
        "weaken_etag" => {
            let Some(before) = etag else { return false };
            let after = before
                .strip_prefix("W/")
                .map_or_else(|| format!("W/{before}"), str::to_string);
            resp.set_header("ETag", &after);
            ctx.log("header:etag", before, after);
            true
        }
        "unquote_etag" => {
            let Some(before) = etag else { return false };
            let after = before
                .trim_start_matches("W/")
                .trim_matches('"')
                .to_string();
            resp.set_header("ETag", &after);
            ctx.log("header:etag", before, after);
            true
        }
        "redirect_change" => {
            if !(300..400).contains(&resp.status) {
                return false;
            }
            let Some(before) = resp.header("location").map(str::to_string) else {
                return false;
            };
            let after = match before.split_once('?') {
                Some((p, q)) => format!("{p}/?{q}"),
                None => format!("{before}/"),
            };
            resp.set_header("Location", &after);
            ctx.log("header:location", before, after);
            true
        }
        "drop_header" | "header_value" | "add_header" => {
            if name == "add_header" {
                resp.headers
                    .push(("X-Conformance-Extra".to_string(), "1".to_string()));
                ctx.log("header:x-conformance-extra", "<absent>", "1");
                return true;
            }
            let names: Vec<String> = resp
                .headers
                .iter()
                .map(|(k, _)| k.to_ascii_lowercase())
                .filter(|k| !FRAMING.contains(&k.as_str()) && k != "etag")
                .filter(|k| {
                    name == "drop_header" || !crate::diff::VOLATILE_HEADERS.contains(&k.as_str())
                })
                .collect();
            let Some(target) = ctx.choose(names) else {
                return false;
            };
            let before = resp.header(&target).unwrap_or("").to_string();
            if name == "drop_header" {
                resp.headers
                    .retain(|(k, _)| !k.eq_ignore_ascii_case(&target));
                ctx.log(format!("header:{target}"), before, "<absent>");
            } else {
                let after = format!("{before}-changed");
                resp.set_header(&target, &after);
                ctx.log(format!("header:{target}"), before, after);
            }
            true
        }
        _ => false,
    }
}

fn mutate_request_shape(ctx: &mut Ctx, resp: &mut Resp, name: &str) -> bool {
    match name {
        "trailing_slash" => {
            let path = ctx.req.path().to_string();
            let is_variant = ctx.req.case_name.starts_with("slash_variant");
            let slash_form = path.len() > 1 && path.ends_with('/');
            if !(is_variant || slash_form) || (300..400).contains(&resp.status) {
                return false;
            }
            let location = if slash_form {
                path.trim_end_matches('/').to_string()
            } else {
                format!("{path}/")
            };
            let before = resp.status;
            resp.status = 308;
            resp.body.clear();
            resp.set_header("Location", &location);
            ctx.log("status", before.to_string(), format!("308 to {location}"));
            true
        }
        "jf_auth_case" => {
            if !noncanonical_jf_auth(ctx.req) || resp.status == 401 {
                return false;
            }
            let before = resp.status;
            resp.status = 401;
            resp.body = b"{\"error\":\"Unauthorized\"}".to_vec();
            resp.set_header("Content-Type", "application/json");
            ctx.log(
                "status",
                before.to_string(),
                "401 for a noncanonical auth spelling",
            );
            true
        }
        _ => false,
    }
}

fn mutate_bytes(ctx: &mut Ctx, resp: &mut Resp, name: &str) -> bool {
    match name {
        "bytes_flip" => {
            if resp.is_json() {
                return false;
            }
            let Some(last) = resp.body.last_mut() else {
                return false;
            };
            *last ^= 0x01;
            ctx.log("body", "last byte", "last byte flipped");
            true
        }
        "truncate_body" => {
            if resp.body.len() < 2 {
                return false;
            }
            let at = resp.body.len() / 2;
            resp.truncate_at = Some(at);
            ctx.log(
                "body",
                format!("{} bytes", resp.body.len()),
                format!("cut at {at}"),
            );
            true
        }
        "duplicate_key" => {
            // An earlier copy of the first key: a last-wins parser sees no change, and
            // a first-wins parser sees a different value.
            if !resp.is_json() || !resp.body.starts_with(b"{\"") {
                return false;
            }
            let Some(end) = resp.body[2..].iter().position(|b| *b == b'"') else {
                return false;
            };
            let key = String::from_utf8_lossy(&resp.body[2..2 + end]).to_string();
            if key.contains('\\') {
                return false;
            }
            ctx.log("body", "no repeated key", format!("{key} sent twice"));
            resp.raw_json_prefix = Some(format!("{{\"{key}\":\"first copy\",").into_bytes());
            true
        }
        _ => false,
    }
}

/// Applies one named fault. Returns what changed, empty when the response has no
/// site for it.
pub fn apply_single(
    name: &str,
    req: &Req,
    resp: &mut Resp,
    rules: &Rules,
    salt: u64,
) -> Vec<Applied> {
    let pick = hash(&[req.case_id, name], salt);
    let mut ctx = Ctx {
        name,
        req,
        pick,
        out: Vec::new(),
    };
    let same_length_body = rules.rules.iter().any(|r| {
        r.spec.body
            && matches!(r.spec.format, Format::SameLength)
            && r.applies_to_route(req.surface, &req.method_path)
    });
    let changed = mutate_headers(&mut ctx, resp, name)
        || mutate_request_shape(&mut ctx, resp, name)
        || mutate_bytes(&mut ctx, resp, name);
    if changed && name == "bytes_flip" && same_length_body {
        for a in &mut ctx.out {
            a.by_design = true;
        }
    }
    if !changed && resp.is_json() {
        if let Ok(mut doc) = serde_json::from_slice::<Value>(&resp.body) {
            let before = doc.clone();
            if mutate_json(&mut ctx, &mut doc, resp.status, name) {
                excuse_what_a_rule_allows(&mut ctx.out, req, rules, &before, &doc);
                resp.body = doc.to_string().into_bytes();
            }
        }
    }
    ctx.out
}

fn parse_at(at: &str) -> Vec<Step> {
    let mut out = Vec::new();
    for part in at
        .trim_start_matches('$')
        .split('.')
        .filter(|p| !p.is_empty())
    {
        let (key, rest) = part.split_once('[').map_or((part, ""), |(k, r)| (k, r));
        if !key.is_empty() {
            out.push(Step::Key(key.to_string()));
        }
        for idx in rest.split('[').filter(|i| !i.is_empty()) {
            if let Ok(i) = idx.trim_end_matches(']').parse() {
                out.push(Step::Index(i));
            }
        }
    }
    out
}

/// Marks a fault that lands inside a feed, or that a leaf rule still accepts, so the
/// check reports it under the rule that allows it rather than as an escape.
fn excuse_what_a_rule_allows(
    applied: &mut [Applied],
    req: &Req,
    rules: &Rules,
    before: &Value,
    after: &Value,
) {
    for a in applied {
        let steps = parse_at(&a.at);
        if let Some(rule) = rules.feed_covering(req.surface, &req.method_path, &steps) {
            a.by_design = true;
            a.rule = Some(rule.spec.id.clone());
            continue;
        }
        if let Some(parent) = steps.split_last().and_then(|(_, up)| get(before, up)) {
            if let Some(rule) = rules.unordered_at(
                req.surface,
                &req.method_path,
                &steps,
                [Some(parent), Some(parent)],
            ) {
                a.by_design = a.mutation == "enum_reorder";
                a.rule = Some(rule.spec.id.clone());
                if a.by_design {
                    continue;
                }
            }
        }
        if let (Some(x), Some(y)) = (get(before, &steps), get(after, &steps)) {
            if let Some(rule) = rules.matching_leaf(req.surface, &req.method_path, &steps, x, y, 0)
            {
                a.by_design = true;
                a.rule = Some(rule.spec.id.clone());
            }
        }
    }
}

/// Every fault in one run: each case gets one, chosen by its id.
pub fn apply_round_robin(req: &Req, resp: &mut Resp, rules: &Rules, salt: u64) -> Vec<Applied> {
    let start = hash(&[req.case_id], salt) as usize;
    for i in 0..SINGLE_SITE.len() {
        let name = SINGLE_SITE[(start + i) % SINGLE_SITE.len()];
        let done = apply_single(name, req, resp, rules, salt);
        if !done.is_empty() {
            return done;
        }
    }
    Vec::new()
}

// ---- normalizer probes ---------------------------------------------------------

const JUNK: &str = "!! out of format !!";

fn rules_at<'a>(rules: &'a Rules, req: &Req, steps: &[Step]) -> Vec<&'a Rule> {
    rules
        .rules
        .iter()
        .filter(|r| r.at_path(steps) && r.applies_to_route(req.surface, &req.method_path))
        .collect()
}

/// A value of the same JSON type that no format rule should accept here.
fn out_of_format(rule: &Rule, v: &Value) -> Option<Value> {
    match (&rule.spec.format, v) {
        (Format::AnyNumber, Value::Number(_)) => Some(json!("not a number")),
        (Format::EpochRunTime { .. } | Format::EpochMsRunTime { .. }, Value::Number(_)) => {
            Some(json!(0))
        }
        (Format::UnorderedArray { .. } | Format::ArrayOfObjects { .. }, _) => None,
        (Format::SameLength, _) => None,
        (Format::Rfc3339RunTime { .. } | Format::Rfc3339Near { .. }, Value::String(_)) => {
            Some(json!("not a timestamp"))
        }
        (_, Value::String(_)) => Some(json!(JUNK)),
        _ => None,
    }
}

fn uuid_upper(s: &str) -> String {
    s.to_ascii_uppercase()
}

fn uuid_other_version(s: &str) -> String {
    let mut b: Vec<char> = s.chars().collect();
    if b.len() == 36 {
        b[14] = if b[14] == '1' { '7' } else { '1' };
    }
    b.into_iter().collect()
}

/// A well-formed JWT whose header or claims are not the original's.
fn jwt_tampered(s: &str, pick: u64) -> Option<String> {
    let parts: Vec<&str> = s.split('.').collect();
    let header = crate::normalize::b64url_decode(parts.first()?)?;
    let payload = crate::normalize::b64url_decode(parts.get(1)?)?;
    let mut header: Value = serde_json::from_slice(&header).ok()?;
    let mut payload: Value = serde_json::from_slice(&payload).ok()?;
    match pick % 3 {
        0 => header["alg"] = json!("none"),
        1 => {
            let keys: Vec<String> = payload.as_object()?.keys().cloned().collect();
            let k = keys.first()?.clone();
            payload.as_object_mut()?.remove(&k);
        }
        _ => {
            let exp = payload["exp"].as_i64()?;
            payload["exp"] = json!(exp + 86_400 * 30);
        }
    }
    Some(format!(
        "{}.{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(payload.to_string().as_bytes()),
        parts[2]
    ))
}

/// A value still inside the rule's format that a client could still notice, and
/// whether the rule is meant to allow it.
fn in_format(rule: &Rule, v: &Value, pick: u64) -> Option<(Value, bool)> {
    match (&rule.spec.format, v) {
        (Format::AnyNumber, Value::Number(n)) => {
            if pick.is_multiple_of(2) {
                Some((json!(-1), false))
            } else {
                let f = n.as_f64()?;
                Some((json!(f * 2.0 + 3.0), true))
            }
        }
        (Format::EpochMsRunTime { .. }, Value::Number(n)) => {
            // Seconds where milliseconds belong.
            Some((json!(n.as_i64()? / 1000), false))
        }
        (Format::EpochRunTime { .. }, Value::Number(n)) => Some((json!(n.as_i64()? * 1000), false)),
        (Format::Uuid, Value::String(s)) => Some((
            json!(if pick.is_multiple_of(2) {
                uuid_upper(s)
            } else {
                uuid_other_version(s)
            }),
            false,
        )),
        (Format::Jwt, Value::String(s)) => Some((json!(jwt_tampered(s, pick)?), false)),
        (Format::Hex { .. }, Value::String(s)) => Some((json!(format!("{s}{s}")), false)),
        (Format::Rfc3339RunTime { .. } | Format::Rfc3339Near { .. }, Value::String(s)) => {
            if pick.is_multiple_of(2) {
                Some((json!(respell_timestamp(s, pick)?), false))
            } else {
                let t = OffsetDateTime::parse(s, &Rfc3339).ok()?;
                let later = t + time::Duration::days(1);
                Some((json!(later.format(&Rfc3339).ok()?), false))
            }
        }
        (Format::Regex { .. }, Value::String(s)) => {
            let shrunk = rule.shrink_groups(s)?;
            Some((json!(shrunk), rule.allows_any_length()))
        }
        _ => None,
    }
}

type ArrayProbe = (Value, bool, Option<FeedFault>);

fn array_probe(rule: &Rule, v: &Value, pick: u64, out_of: bool) -> Option<ArrayProbe> {
    let items = v.as_array()?;
    match &rule.spec.format {
        Format::UnorderedArray { .. } => {
            let mut a = items.clone();
            if a.is_empty() {
                return None;
            }
            a.pop();
            Some((Value::Array(a), false, None))
        }
        Format::ArrayOfObjects {
            required_keys,
            keys_vary,
        } => {
            if items.is_empty() {
                return None;
            }
            let mut a = items.clone();
            if out_of {
                let key = required_keys.get(pick as usize % required_keys.len().max(1))?;
                a[0].as_object_mut()?.remove(key);
                return Some((Value::Array(a), false, None));
            }
            match pick % 3 {
                0 => Some((json!([]), false, Some(FeedFault::Emptied))),
                1 => {
                    let key = required_keys.get(pick as usize % required_keys.len().max(1))?;
                    for e in a.iter_mut() {
                        let old = e.as_object_mut()?.get_mut(key)?;
                        *old = match old {
                            Value::String(_) => json!(1),
                            Value::Number(_) => json!("1"),
                            Value::Bool(_) => json!("true"),
                            Value::Null => json!(1),
                            _ => json!("x"),
                        };
                    }
                    Some((
                        Value::Array(a),
                        false,
                        Some(FeedFault::KeyRetyped(key.clone())),
                    ))
                }
                _ => {
                    // A key outside the required list, gone from every entry. Only one
                    // that every entry had is checked; one some entries had is allowed.
                    let optional: Vec<String> = a[0]
                        .as_object()?
                        .keys()
                        .filter(|k| !required_keys.contains(k))
                        .cloned()
                        .collect();
                    let everywhere = optional
                        .iter()
                        .find(|k| a.iter().all(|e| e.get(k.as_str()).is_some()));
                    let extra = everywhere.or(optional.first())?.clone();
                    let allowed = *keys_vary || everywhere.is_none();
                    for e in a.iter_mut() {
                        e.as_object_mut()?.remove(&extra);
                    }
                    Some((Value::Array(a), allowed, Some(FeedFault::KeyDropped(extra))))
                }
            }
        }
        _ => None,
    }
}

/// Mutates every leaf any rule covers in this response.
pub fn apply_rule_probe(
    name: &str,
    req: &Req,
    resp: &mut Resp,
    rules: &Rules,
    salt: u64,
) -> Vec<Applied> {
    let out_of = name == "rule_out_of_format";
    let mut out = Vec::new();
    let log = |at: String,
               rule: &Rule,
               before: String,
               after: String,
               by_design: bool,
               out: &mut Vec<Applied>| {
        out.push(Applied {
            case: req.case_id.to_string(),
            mutation: name.to_string(),
            at,
            before: clip(&before),
            after: clip(&after),
            rule: Some(rule.spec.id.clone()),
            by_design,
            feed_fault: None,
        });
    };
    if !resp.is_json() {
        for rule in rules
            .rules
            .iter()
            .filter(|r| r.spec.body && r.applies_to_route(req.surface, &req.method_path))
        {
            if resp.body.is_empty() {
                continue;
            }
            let before = format!("{} bytes", resp.body.len());
            if out_of {
                resp.body.pop();
                log(
                    "body".to_string(),
                    rule,
                    before,
                    "one byte shorter".to_string(),
                    false,
                    &mut out,
                );
            } else {
                for b in resp.body.iter_mut() {
                    *b = 0;
                }
                log(
                    "body".to_string(),
                    rule,
                    before,
                    "same length, all zero".to_string(),
                    true,
                    &mut out,
                );
            }
            break;
        }
        return out;
    }
    let Ok(mut doc) = serde_json::from_slice::<Value>(&resp.body) else {
        return out;
    };
    for site in nodes(&doc) {
        // Inside a feed nothing is compared by design; the feed's own probes cover it.
        if !site.is_empty()
            && rules
                .feed_covering(req.surface, &req.method_path, &site[..site.len() - 1])
                .is_some()
        {
            continue;
        }
        let Some(v) = get(&doc, &site).cloned() else {
            continue;
        };
        let matching = rules_at(rules, req, &site);
        let Some(rule) = matching.first() else {
            continue;
        };
        let pick = hash(&[req.case_id, &render_path(&site)], salt);
        let replacement = if v.is_array() {
            array_probe(rule, &v, pick, out_of)
        } else if out_of {
            out_of_format(rule, &v).map(|x| (x, false, None))
        } else {
            in_format(rule, &v, pick).map(|(x, by_design)| (x, by_design, None))
        };
        let Some((next, by_design, feed_fault)) = replacement else {
            continue;
        };
        if next == v {
            continue;
        }
        if let Some(slot) = get_mut(&mut doc, &site) {
            *slot = next.clone();
        }
        log(
            render_path(&site),
            rule,
            v.to_string(),
            next.to_string(),
            by_design,
            &mut out,
        );
        if let Some(applied) = out.last_mut() {
            applied.feed_fault = feed_fault;
        }
    }
    if !out.is_empty() {
        resp.body = doc.to_string().into_bytes();
    }
    out
}

pub fn apply(name: &str, req: &Req, resp: &mut Resp, rules: &Rules, salt: u64) -> Vec<Applied> {
    match name {
        "none" => Vec::new(),
        "reserialize" => {
            if resp.is_json() {
                if let Ok(doc) = serde_json::from_slice::<Value>(&resp.body) {
                    let newline = resp.body.last() == Some(&b'\n');
                    resp.body = serde_json::to_vec_pretty(&doc).unwrap_or_default();
                    if newline {
                        resp.body.push(b'\n');
                    }
                }
            }
            Vec::new()
        }
        "all" => apply_round_robin(req, resp, rules, salt),
        _ if RULE_PROBES.contains(&name) => apply_rule_probe(name, req, resp, rules, salt),
        _ => apply_single(name, req, resp, rules, salt),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_feed_fault_only_shows_where_the_reference_has_what_it_removed() {
        use crate::normalize::FeedSummary;
        let reference = FeedSummary::of(&[
            json!({"id": 1, "request_id": "x", "attrs": null}),
            json!({"id": 2, "attrs": null}),
        ]);
        let cases = [
            (FeedFault::Emptied, true),
            (FeedFault::KeyDropped("id".into()), true),
            // Some reference entries lack it, so no entry having it is allowed.
            (FeedFault::KeyDropped("request_id".into()), false),
            (FeedFault::KeyRetyped("id".into()), true),
            // Never non-null on the reference, so it has no type to disagree with.
            (FeedFault::KeyRetyped("attrs".into()), false),
        ];
        for (fault, shows) in cases {
            assert_eq!(fault.observable(&reference), shows, "{fault:?}");
        }
        assert!(!FeedFault::Emptied.observable(&FeedSummary::of(&[])));
    }

    use super::*;

    fn req<'a>(id: &'a str, path: &'a str, headers: &'a [(String, String)]) -> Req<'a> {
        Req::parse(id, "GET", path, headers).unwrap()
    }

    fn json_resp(body: &str) -> Resp {
        Resp {
            status: 200,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: body.as_bytes().to_vec(),
            ..Resp::default()
        }
    }

    /// Every fault must change something it says it changed, or the accounting lies.
    #[test]
    fn each_body_fault_changes_the_body_at_its_logged_path() {
        let body = r#"{"a":1,"b":"movie","c":null,"d":[],"e":[1,2],"f":true,"next_cursor":"eyJh","t":"2026-11-01T00:00:00Z"}"#;
        for name in [
            "drop_field",
            "rename_field",
            "field_case",
            "extra_field",
            "int_to_string",
            "int_to_float",
            "number_change",
            "bool_flip",
            "string_change",
            "null_to_missing",
            "value_to_null",
            "empty_array_to_null",
            "null_to_empty_array",
            "array_drop_last",
            "enum_reorder",
            "enum_value_case",
            "cursor_shape",
            "timestamp_format",
        ] {
            let r = req("api_v2 GET /x#admin", "/x", &[]);
            let mut resp = json_resp(body);
            let done = apply_single(name, &r, &mut resp, &Rules::default(), 0);
            assert_eq!(done.len(), 1, "{name}");
            assert_ne!(
                serde_json::from_slice::<Value>(&resp.body).unwrap(),
                serde_json::from_str::<Value>(body).unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn a_fault_with_no_site_logs_nothing() {
        let r = req("api_v2 GET /x#admin", "/x", &[]);
        let mut resp = json_resp(r#"{"a":1}"#);
        let rules = Rules::default();
        assert!(apply_single("drop_etag", &r, &mut resp, &rules, 0).is_empty());
        assert!(apply_single("cursor_shape", &r, &mut resp, &rules, 0).is_empty());
        assert!(apply_single("redirect_change", &r, &mut resp, &rules, 0).is_empty());
    }

    #[test]
    fn timestamp_respellings_are_the_same_instant_or_a_format_change() {
        let s = "2026-11-01T00:00:00.5Z";
        for pick in 0..8 {
            let t = respell_timestamp(s, pick).unwrap();
            assert_ne!(t, s);
        }
    }

    #[test]
    fn jf_auth_fault_ignores_the_harness_own_spelling() {
        let canonical = vec![(
            "X-Emby-Authorization".to_string(),
            "MediaBrowser Client=\"c\", Device=\"d\", DeviceId=\"1\", Version=\"1\", Token=\"t\""
                .to_string(),
        )];
        let r = req("jellycompat GET /Users/Me#user", "/Users/Me", &canonical);
        assert!(!noncanonical_jf_auth(&r));
        let lower = vec![(
            "X-Emby-Authorization".to_string(),
            "mediabrowser token=\"t\"".to_string(),
        )];
        let r = req("jellycompat GET /Users/Me#auth", "/Users/Me", &lower);
        assert!(noncanonical_jf_auth(&r));
        let r = req("jellycompat GET /Users/Me#auth", "/Users/Me?API_KEY=t", &[]);
        assert!(noncanonical_jf_auth(&r));
    }
}
