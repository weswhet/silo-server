//! Compares one reference exchange with one candidate exchange.

use crate::http::Exchange;
use crate::normalize::{render_path, FeedSummary, Rules, Step};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Status,
    Header,
    EtagBehaviour,
    MissingKey,
    ExtraKey,
    TypeMismatch,
    ValueMismatch,
    ArrayLength,
    BodyKind,
    Bytes,
    Transport,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Diff {
    pub kind: DiffKind,
    pub at: String,
    pub reference: String,
    pub candidate: String,
}

impl Diff {
    /// Identifies this difference without its values, for flake bookkeeping.
    pub fn signature(&self) -> String {
        format!("{:?} {}", self.kind, self.at)
    }
}

/// Headers about one connection rather than the answer. Every other response header
/// is compared, so a dropped or added header is a difference.
const FRAMING_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "date",
    "keep-alive",
    "transfer-encoding",
];

/// Compared by presence: their values differ on every answer.
pub const VOLATILE_HEADERS: &[&str] = &[
    "expires",
    "last-modified",
    "retry-after",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-request-id",
];

#[derive(Default, Debug, Clone)]
pub struct Aliases {
    /// candidate value -> reference value, for server-generated identifiers.
    pairs: Vec<(String, String)>,
}

impl Aliases {
    pub fn add(&mut self, reference: &str, candidate: &str) {
        if reference != candidate
            && candidate.len() >= 8
            && !self.pairs.iter().any(|(c, _)| c == candidate)
        {
            self.pairs
                .push((candidate.to_string(), reference.to_string()));
        }
    }

    pub fn apply(&self, s: &str) -> String {
        let mut out = s.to_string();
        for (c, r) in &self.pairs {
            if out.contains(c.as_str()) {
                out = out.replace(c.as_str(), r);
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// True when either value is already paired with something else: the candidate
    /// reused an id, or answered about a different object than before.
    pub fn conflicts(&self, reference: &str, candidate: &str) -> bool {
        self.pairs
            .iter()
            .any(|(c, r)| (c == candidate) != (r == reference))
    }
}

/// Whether two generated ids could come from the same generator. A pair that could
/// not is not an alias: it is the difference the run exists to report.
pub fn same_id_shape(a: &str, b: &str) -> bool {
    let digits = |s: &str| s.bytes().all(|c| c.is_ascii_digit());
    // Letters and digits mix freely in a random id; punctuation must line up.
    a.len() == b.len()
        && digits(a) == digits(b)
        && a.chars()
            .zip(b.chars())
            .all(|(x, y)| x == y || (x.is_ascii_alphanumeric() && y.is_ascii_alphanumeric()))
}

pub struct Ctx<'a> {
    pub rules: &'a Rules,
    pub surface: &'a str,
    pub method_path: &'a str,
    pub run_start: i64,
    /// A strangler's marker. Handled by the runner, so it is not a difference here.
    pub proxy_header: &'a str,
    /// What each side was asked for, to tell an id it named from one it generated.
    pub reference_path: &'a str,
    pub candidate_path: &'a str,
}

#[derive(Default, Debug)]
pub struct Outcome {
    pub diffs: Vec<Diff>,
    pub rule_hits: BTreeMap<String, u64>,
    pub body_compared: bool,
    pub body_skip_reason: Option<String>,
    /// A feed rule names this route, so its contents do not count as compared.
    pub feed_relaxed: bool,
    /// What each feed on the reference side held, by location.
    pub feed_reference: BTreeMap<String, FeedSummary>,
}

fn clip(s: &str) -> String {
    const MAX: usize = 240;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes)", &s[..end], s.len())
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub fn compare(
    ctx: &Ctx,
    aliases: &mut Aliases,
    r: &Exchange,
    c: &Exchange,
    skip_body: Option<&str>,
) -> Outcome {
    let mut out = Outcome::default();
    match (&r.error, &c.error) {
        (Some(_), Some(_)) => {
            out.body_skip_reason = Some("both sides failed at the transport level".to_string());
            return out;
        }
        (Some(_), None) | (None, Some(_)) => {
            out.diffs.push(Diff {
                kind: DiffKind::Transport,
                at: "transport".to_string(),
                reference: r.error.clone().unwrap_or_else(|| r.status.to_string()),
                candidate: c.error.clone().unwrap_or_else(|| c.status.to_string()),
            });
            return out;
        }
        (None, None) => {}
    }
    if r.status != c.status {
        out.diffs.push(Diff {
            kind: DiffKind::Status,
            at: "status".to_string(),
            reference: r.status.to_string(),
            candidate: c.status.to_string(),
        });
    }
    // The body first: an id it registers as an alias can recur in a Location header.
    compare_body(ctx, aliases, r, c, skip_body, &mut out);
    compare_headers(ctx, aliases, r, c, skip_body.is_some(), &mut out);
    out
}

/// A cookie's name and attributes are contract; its value is a secret or an id.
fn cookie_shape(v: &str) -> String {
    v.split(", ")
        .map(|cookie| {
            let (pair, attrs) = cookie.split_once(';').unwrap_or((cookie, ""));
            let name = pair.split('=').next().unwrap_or("");
            format!("{name}=;{attrs}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn method_set(v: &str) -> Vec<&str> {
    let mut methods: Vec<&str> = v.split(',').map(str::trim).collect();
    methods.sort_unstable();
    methods
}

fn etag_well_formed(v: &str) -> bool {
    let tag = v.strip_prefix("W/").unwrap_or(v);
    tag.len() >= 2 && tag.starts_with('"') && tag.ends_with('"')
}

fn compare_headers(
    ctx: &Ctx,
    aliases: &Aliases,
    r: &Exchange,
    c: &Exchange,
    body_skipped: bool,
    out: &mut Outcome,
) {
    let mut names: Vec<String> = r
        .headers
        .iter()
        .chain(c.headers.iter())
        .map(|(k, _)| k.to_ascii_lowercase())
        .filter(|k| {
            k != "etag"
                && !FRAMING_HEADERS.contains(&k.as_str())
                && !k.eq_ignore_ascii_case(ctx.proxy_header)
        })
        .collect();
    names.sort();
    names.dedup();
    for name in &names {
        let name = name.as_str();
        let rv = r.header(name);
        let cv = c.header(name).map(|v| aliases.apply(&v));
        if rv == cv {
            continue;
        }
        if let (Some(a), Some(b)) = (&rv, &cv) {
            if VOLATILE_HEADERS.contains(&name) {
                continue;
            }
            if name == "set-cookie" && cookie_shape(a) == cookie_shape(b) {
                continue;
            }
            // Go builds this from a map, so its order differs between two requests.
            if name == "allow" && method_set(a) == method_set(b) {
                continue;
            }
            if let Some(rule) =
                ctx.rules
                    .matching_header(ctx.surface, ctx.method_path, name, a, b, ctx.run_start)
            {
                *out.rule_hits.entry(rule.spec.id.clone()).or_default() += 1;
                continue;
            }
        }
        out.diffs.push(Diff {
            kind: DiffKind::Header,
            at: format!("header:{name}"),
            reference: rv.unwrap_or_else(|| "<absent>".to_string()),
            candidate: cv.unwrap_or_else(|| "<absent>".to_string()),
        });
    }
    // A HEAD answer has no body, so its declared length is the only thing to compare.
    if ctx.method_path.starts_with("HEAD ")
        && !body_skipped
        && r.body.is_empty()
        && c.body.is_empty()
        && r.header("content-length") != c.header("content-length")
    {
        out.diffs.push(Diff {
            kind: DiffKind::Header,
            at: "header:content-length".to_string(),
            reference: r
                .header("content-length")
                .unwrap_or_else(|| "<absent>".to_string()),
            candidate: c
                .header("content-length")
                .unwrap_or_else(|| "<absent>".to_string()),
        });
    }
    match (r.header("etag"), c.header("etag")) {
        (None, None) => {}
        (Some(a), Some(b)) => {
            if a.starts_with("W/") != b.starts_with("W/")
                || etag_well_formed(&a) != etag_well_formed(&b)
            {
                out.diffs.push(Diff {
                    kind: DiffKind::EtagBehaviour,
                    at: "header:etag".to_string(),
                    reference: clip(&a),
                    candidate: clip(&b),
                });
            }
        }
        (a, b) => out.diffs.push(Diff {
            kind: DiffKind::EtagBehaviour,
            at: "header:etag".to_string(),
            reference: a.unwrap_or_else(|| "<absent>".to_string()),
            candidate: b.unwrap_or_else(|| "<absent>".to_string()),
        }),
    }
}

fn looks_json(e: &Exchange) -> bool {
    e.header("content-type")
        .is_some_and(|v| v.to_ascii_lowercase().contains("json"))
}

fn compare_body(
    ctx: &Ctx,
    aliases: &mut Aliases,
    r: &Exchange,
    c: &Exchange,
    skip_body: Option<&str>,
    out: &mut Outcome,
) {
    if r.truncated != c.truncated {
        // A body that stopped early on one side only is an answer a client cannot use.
        out.diffs.push(Diff {
            kind: DiffKind::BodyKind,
            at: "body".to_string(),
            reference: if r.truncated { "cut off" } else { "complete" }.to_string(),
            candidate: if c.truncated { "cut off" } else { "complete" }.to_string(),
        });
        return;
    }
    if let Some(reason) = skip_body {
        out.body_skip_reason = Some(reason.to_string());
        return;
    }
    if r.truncated {
        out.body_skip_reason = Some("stream or oversized body was cut off".to_string());
        return;
    }
    out.body_compared = true;
    out.feed_relaxed = ctx.rules.route_has_feed(ctx.surface, ctx.method_path);
    if r.body == c.body {
        return;
    }
    if looks_json(r) || looks_json(c) {
        let (a, b) = (
            serde_json::from_slice::<Value>(&r.body),
            serde_json::from_slice::<Value>(&c.body),
        );
        match (a, b) {
            (Ok(a), Ok(b)) => {
                // Parsers disagree on a repeated key, and `Value` keeps only the last.
                let (dup_r, dup_c) = (repeated_key(&r.body), repeated_key(&c.body));
                if dup_r != dup_c {
                    out.diffs.push(Diff {
                        kind: DiffKind::BodyKind,
                        at: "body".to_string(),
                        reference: dup_r.unwrap_or_else(|| "no repeated key".to_string()),
                        candidate: dup_c.unwrap_or_else(|| "no repeated key".to_string()),
                    });
                }
                let mut steps = Vec::new();
                walk(ctx, aliases, &a, &b, [None, None], &mut steps, out);
                return;
            }
            (Err(_), Err(_)) => {}
            (a, b) => {
                out.diffs.push(Diff {
                    kind: DiffKind::BodyKind,
                    at: "body".to_string(),
                    reference: if a.is_ok() { "json" } else { "not json" }.to_string(),
                    candidate: if b.is_ok() { "json" } else { "not json" }.to_string(),
                });
                return;
            }
        }
    }
    // Bytes, after substituting known identifier aliases.
    let aliased: Vec<u8> = match std::str::from_utf8(&c.body) {
        Ok(text) if !aliases.is_empty() => aliases.apply(text).into_bytes(),
        _ => c.body.clone(),
    };
    if r.body == aliased {
        return;
    }
    if let Some(rule) = ctx.rules.matching_body(
        ctx.surface,
        ctx.method_path,
        &r.body,
        &aliased,
        ctx.run_start,
    ) {
        *out.rule_hits.entry(rule.spec.id.clone()).or_default() += 1;
        return;
    }
    let (reference, candidate) = match (std::str::from_utf8(&r.body), std::str::from_utf8(&aliased))
    {
        (Ok(a), Ok(b)) => (clip(a), clip(b)),
        _ => (digest(&r.body), digest(&aliased)),
    };
    out.diffs.push(Diff {
        kind: DiffKind::Bytes,
        at: "body".to_string(),
        reference,
        candidate,
    });
}

/// The first object key sent twice, if any. A parse failure is reported elsewhere.
fn repeated_key(body: &[u8]) -> Option<String> {
    use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    struct Scan<'a>(&'a RefCell<Option<String>>);

    impl<'de> DeserializeSeed<'de> for Scan<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Scan<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            let mut seen = BTreeSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key.clone()) {
                    self.0.borrow_mut().get_or_insert(key);
                }
                map.next_value_seed(Scan(self.0))?;
            }
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            while seq.next_element_seed(Scan(self.0))?.is_some() {}
            Ok(())
        }
        fn visit_bool<E>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E>(self) -> Result<(), E> {
            Ok(())
        }
    }

    let found = RefCell::new(None);
    let mut de = serde_json::Deserializer::from_slice(body);
    let _ = Scan(&found).deserialize(&mut de);
    found.into_inner()
}

fn digest(b: &[u8]) -> String {
    let hash = Sha256::digest(b);
    let hex: String = hash.iter().take(8).map(|x| format!("{x:02x}")).collect();
    format!("{} bytes sha256:{hex}", b.len())
}

fn walk(
    ctx: &Ctx,
    aliases: &mut Aliases,
    a: &Value,
    b: &Value,
    parents: [Option<&Value>; 2],
    steps: &mut Vec<Step>,
    out: &mut Outcome,
) {
    if json_type(a) != json_type(b) {
        out.diffs.push(Diff {
            kind: DiffKind::TypeMismatch,
            at: render_path(steps),
            reference: format!("{}: {}", json_type(a), clip(&a.to_string())),
            candidate: format!("{}: {}", json_type(b), clip(&b.to_string())),
        });
        return;
    }
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, v) in x {
                steps.push(Step::Key(k.clone()));
                match y.get(k) {
                    Some(w) => walk(ctx, aliases, v, w, [Some(a), Some(b)], steps, out),
                    None => out.diffs.push(Diff {
                        kind: DiffKind::MissingKey,
                        at: render_path(steps),
                        reference: clip(&v.to_string()),
                        candidate: "<absent>".to_string(),
                    }),
                }
                steps.pop();
            }
            for (k, w) in y {
                if !x.contains_key(k) {
                    steps.push(Step::Key(k.clone()));
                    out.diffs.push(Diff {
                        kind: DiffKind::ExtraKey,
                        at: render_path(steps),
                        reference: "<absent>".to_string(),
                        candidate: clip(&w.to_string()),
                    });
                    steps.pop();
                }
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if let Some(rule) = ctx.rules.feed_at(ctx.surface, ctx.method_path, steps, x, y) {
                if x != y {
                    *out.rule_hits.entry(rule.spec.id.clone()).or_default() += 1;
                }
                out.feed_reference
                    .insert(render_path(steps), FeedSummary::of(x));
                return;
            }
            if x.len() != y.len() {
                out.diffs.push(Diff {
                    kind: DiffKind::ArrayLength,
                    at: render_path(steps),
                    reference: x.len().to_string(),
                    candidate: y.len().to_string(),
                });
            }
            if let Some(rule) = ctx
                .rules
                .unordered_at(ctx.surface, ctx.method_path, steps, parents)
            {
                let sorted = |v: &Vec<Value>| {
                    let mut items = v.clone();
                    items.sort_by_key(|e| e.to_string());
                    items
                };
                let (sx, sy) = (sorted(x), sorted(y));
                if x != &sx || y != &sy {
                    *out.rule_hits.entry(rule.spec.id.clone()).or_default() += 1;
                }
                walk_elements(ctx, aliases, &sx, &sy, steps, out);
            } else {
                walk_elements(ctx, aliases, x, y, steps, out);
            }
        }
        _ => {
            if a == b {
                return;
            }
            if let (Value::String(x), Value::String(y)) = (a, b) {
                if x == &aliases.apply(y) {
                    return;
                }
            }
            let rule = ctx
                .rules
                .matching_leaf(ctx.surface, ctx.method_path, steps, a, b, ctx.run_start)
                .filter(|rule| match (rule.spec.alias, a, b) {
                    (true, Value::String(x), Value::String(y)) => {
                        !aliases.conflicts(x, y) && names_same_object(ctx, x, y)
                    }
                    _ => true,
                });
            if let Some(rule) = rule {
                *out.rule_hits.entry(rule.spec.id.clone()).or_default() += 1;
                if rule.spec.alias {
                    if let (Value::String(x), Value::String(y)) = (a, b) {
                        aliases.add(x, y);
                    }
                }
                return;
            }
            out.diffs.push(Diff {
                kind: DiffKind::ValueMismatch,
                at: render_path(steps),
                reference: clip(&a.to_string()),
                candidate: clip(&b.to_string()),
            });
        }
    }
}

/// An id the request named must come back as the id that side's request named: a
/// rule that lets generated ids differ must not let a server answer about another object.
fn names_same_object(ctx: &Ctx, reference: &str, candidate: &str) -> bool {
    !ctx.reference_path.contains(reference) || ctx.candidate_path.contains(candidate)
}

fn walk_elements(
    ctx: &Ctx,
    aliases: &mut Aliases,
    x: &[Value],
    y: &[Value],
    steps: &mut Vec<Step>,
    out: &mut Outcome,
) {
    for (i, (v, w)) in x.iter().zip(y.iter()).enumerate() {
        steps.push(Step::Index(i));
        walk(ctx, aliases, v, w, [None, None], steps, out);
        steps.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn exchange(status: u16, body: &str) -> Exchange {
        Exchange {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            ..Exchange::default()
        }
    }

    fn rules(rules: serde_json::Value) -> Rules {
        Rules::parse(&json!({ "rules": rules }).to_string()).unwrap()
    }

    fn run(rs: &Rules, a: &str, b: &str) -> Outcome {
        let ctx = Ctx {
            rules: rs,
            surface: "api_v2",
            method_path: "GET /api/v2/thing",
            run_start: 1_000_000,
            proxy_header: "x-marker",
            reference_path: "/",
            candidate_path: "/",
        };
        compare(
            &ctx,
            &mut Aliases::default(),
            &exchange(200, a),
            &exchange(200, b),
            None,
        )
    }

    fn kinds(o: &Outcome) -> Vec<(DiffKind, String)> {
        o.diffs
            .iter()
            .map(|d| (d.kind.clone(), d.at.clone()))
            .collect()
    }

    #[test]
    fn reports_presence_type_and_value_separately() {
        let rs = Rules::default();
        let o = run(
            &rs,
            r#"{"gone":1,"t":"1","v":1,"a":[1,2],"same":[{"x":1}]}"#,
            r#"{"new":1,"t":1,"v":2,"a":[1],"same":[{"x":1}]}"#,
        );
        assert_eq!(
            kinds(&o),
            vec![
                (DiffKind::ArrayLength, "$.a".to_string()),
                (DiffKind::MissingKey, "$.gone".to_string()),
                (DiffKind::TypeMismatch, "$.t".to_string()),
                (DiffKind::ValueMismatch, "$.v".to_string()),
                (DiffKind::ExtraKey, "$.new".to_string()),
            ]
        );
    }

    #[test]
    fn distinguishes_integer_and_float_and_null() {
        let rs = Rules::default();
        assert_eq!(kinds(&run(&rs, r#"{"n":1}"#, r#"{"n":1.0}"#)).len(), 1);
        assert_eq!(
            kinds(&run(&rs, r#"{"n":null}"#, r#"{"n":1}"#)),
            vec![(DiffKind::TypeMismatch, "$.n".to_string())]
        );
    }

    #[test]
    fn key_order_does_not_matter_but_array_order_does() {
        let rs = Rules::default();
        assert!(run(&rs, r#"{"a":1,"b":2}"#, r#"{"b":2,"a":1}"#)
            .diffs
            .is_empty());
        assert_eq!(run(&rs, "[1,2]", "[2,1]").diffs.len(), 2);
    }

    #[test]
    fn normalizer_only_relaxes_a_matching_path_and_format() {
        let rs = rules(json!([{
            "id": "token", "why": "t", "route": "GET /api/v2/thing",
            "json_paths": ["$.items[*].token"], "format": {"kind": "uuid"},
        }]));
        let u1 = "11111111-1111-4111-8111-111111111111";
        let u2 = "22222222-2222-4222-8222-222222222222";
        // Matching path and format on both sides: allowed, and counted.
        let ok = run(
            &rs,
            &format!(r#"{{"items":[{{"token":"{u1}"}}]}}"#),
            &format!(r#"{{"items":[{{"token":"{u2}"}}]}}"#),
        );
        assert!(ok.diffs.is_empty());
        assert_eq!(ok.rule_hits["token"], 1);
        // Wrong path.
        assert_eq!(
            run(
                &rs,
                &format!(r#"{{"token":"{u1}"}}"#),
                &format!(r#"{{"token":"{u2}"}}"#)
            )
            .diffs
            .len(),
            1
        );
        // Right path, one side loses the format.
        assert_eq!(
            run(
                &rs,
                &format!(r#"{{"items":[{{"token":"{u1}"}}]}}"#),
                r#"{"items":[{"token":"plain"}]}"#
            )
            .diffs
            .len(),
            1
        );
        // Presence and type are still compared at a normalized path.
        assert_eq!(
            kinds(&run(
                &rs,
                &format!(r#"{{"items":[{{"token":"{u1}"}}]}}"#),
                r#"{"items":[{}]}"#
            )),
            vec![(DiffKind::MissingKey, "$.items[0].token".to_string())]
        );
        assert_eq!(
            kinds(&run(
                &rs,
                &format!(r#"{{"items":[{{"token":"{u1}"}}]}}"#),
                r#"{"items":[{"token":7}]}"#
            )),
            vec![(DiffKind::TypeMismatch, "$.items[0].token".to_string())]
        );
    }

    #[test]
    fn normalizer_does_not_leak_to_another_route() {
        let rs = rules(json!([{
            "id": "t", "why": "t", "route": "GET /api/v2/other",
            "json_paths": ["$.at"], "format": {"kind": "jwt"},
        }]));
        assert_eq!(
            run(&rs, r#"{"at":"eyJa.b.c"}"#, r#"{"at":"eyJd.e.f"}"#)
                .diffs
                .len(),
            1
        );
    }

    #[test]
    fn run_time_format_rejects_seed_timestamps_and_large_skew() {
        let rs = rules(json!([{
            "id": "ts", "why": "t", "route": "GET /api/v2/thing",
            "json_paths": ["$.at"], "format": {"kind": "rfc3339_run_time", "max_skew_seconds": 60},
        }]));
        let t = |s: &str| format!(r#"{{"at":"{s}"}}"#);
        // Both after run start and close together.
        assert!(
            run(&rs, &t("2026-11-01T00:00:00Z"), &t("2026-11-01T00:00:30Z"))
                .diffs
                .is_empty()
        );
        // Too far apart: a real difference such as a different token lifetime.
        assert_eq!(
            run(&rs, &t("2026-11-01T00:00:00Z"), &t("2026-11-02T00:00:00Z"))
                .diffs
                .len(),
            1
        );
        // Before the run started: a stored value, which must match exactly.
        assert_eq!(
            run(&rs, &t("1970-01-01T00:00:00Z"), &t("1970-01-01T00:00:30Z"))
                .diffs
                .len(),
            1
        );
    }

    #[test]
    fn regex_format_keeps_everything_outside_its_groups_compared() {
        let rs = rules(json!([{
            "id": "art", "why": "t", "route": "GET /api/v2/thing", "json_paths": ["$.u"],
            "format": {"kind": "regex", "pattern": r"^/art/x\.webp\?exp=([0-9]+)&sig=([A-Za-z0-9_-]+)$"},
        }]));
        let u = |s: &str| format!(r#"{{"u":"{s}"}}"#);
        assert!(run(
            &rs,
            &u("/art/x.webp?exp=1&sig=a"),
            &u("/art/x.webp?exp=2&sig=b")
        )
        .diffs
        .is_empty());
        assert_eq!(
            run(
                &rs,
                &u("/art/x.webp?exp=1&sig=a"),
                &u("/art/y.webp?exp=2&sig=b")
            )
            .diffs
            .len(),
            1
        );
    }

    #[test]
    fn any_depth_path_matches_only_that_key() {
        let rs = rules(json!([{
            "id": "t", "why": "t", "route": "GET /api/v2/thing",
            "json_paths": ["$..at"], "format": {"kind": "uuid"},
        }]));
        let (u1, u2) = (
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        );
        assert!(run(
            &rs,
            &format!(r#"{{"a":[{{"at":"{u1}"}}]}}"#),
            &format!(r#"{{"a":[{{"at":"{u2}"}}]}}"#)
        )
        .diffs
        .is_empty());
        assert_eq!(
            run(
                &rs,
                &format!(r#"{{"not_at":"{u1}"}}"#),
                &format!(r#"{{"not_at":"{u2}"}}"#)
            )
            .diffs
            .len(),
            1
        );
    }

    #[test]
    fn a_feed_rule_still_requires_an_array_of_well_formed_objects() {
        let rs = rules(json!([{
            "id": "feed", "why": "t", "route": "GET /api/v2/thing",
            "json_paths": ["$.items"], "format": {"kind": "array_of_objects", "required_keys": ["id"]},
        }]));
        assert!(run(
            &rs,
            r#"{"items":[{"id":1},{"id":2}]}"#,
            r#"{"items":[{"id":9}]}"#
        )
        .diffs
        .is_empty());
        // A missing required key falls through to the normal comparison.
        assert!(
            !run(&rs, r#"{"items":[{"id":1}]}"#, r#"{"items":[{"other":1}]}"#)
                .diffs
                .is_empty()
        );
        assert!(run(&rs, r#"{"items":[]}"#, r#"{"items":[]}"#).feed_relaxed);
        assert_eq!(
            kinds(&run(&rs, r#"{"items":[]}"#, r#"{"items":{}}"#)),
            vec![(DiffKind::TypeMismatch, "$.items".to_string())]
        );
        assert_eq!(
            kinds(&run(&rs, r#"{"items":[]}"#, r#"{}"#)),
            vec![(DiffKind::MissingKey, "$.items".to_string())]
        );
    }

    #[test]
    fn rule_files_cannot_be_global_or_lack_a_target() {
        for bad in [
            json!([{"id":"a","why":"","json_paths":["$.x"],"format":{"kind":"jwt"}}]),
            json!([{"id":"a","why":"","route":".*","format":{"kind":"jwt"}}]),
            json!([{"id":"a","why":"","route":".*","json_paths":["$"],"format":{"kind":"jwt"}}]),
            json!([{"id":"a","why":"","route":".*","json_paths":["$.x"],"format":{"kind":"regex","pattern":".*"}}]),
            json!([{"id":"a","why":"","route":".*","json_paths":["$.x"],"format":{"kind":"same_length"}}]),
        ] {
            assert!(
                Rules::parse(&json!({"rules": bad}).to_string()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn alias_rule_makes_the_value_equal_where_it_recurs_only() {
        let rs = rules(json!([{
            "id": "new-id", "why": "t", "route": "GET /api/v2/thing",
            "json_paths": ["$.id"], "format": {"kind": "uuid"}, "alias": true,
        }]));
        let (u1, u2) = (
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        );
        let ctx = Ctx {
            rules: &rs,
            surface: "api_v2",
            method_path: "GET /api/v2/thing",
            run_start: 0,
            proxy_header: "x-marker",
            reference_path: "/",
            candidate_path: "/",
        };
        let mut aliases = Aliases::default();
        let a = exchange(200, &format!(r#"{{"id":"{u1}","url":"/x/{u1}"}}"#));
        let b = exchange(200, &format!(r#"{{"id":"{u2}","url":"/x/{u2}"}}"#));
        assert!(compare(&ctx, &mut aliases, &a, &b, None).diffs.is_empty());
        // A different server-generated id is still a difference.
        let b2 = exchange(
            200,
            &format!(r#"{{"id":"{u2}","url":"/x/33333333-3333-4333-8333-333333333333"}}"#),
        );
        assert_eq!(compare(&ctx, &mut aliases, &a, &b2, None).diffs.len(), 1);
    }

    #[test]
    fn non_json_bodies_compare_as_bytes_and_json_versus_text_is_flagged() {
        let rs = Rules::default();
        let ctx = Ctx {
            rules: &rs,
            surface: "api_v2",
            method_path: "GET /x",
            run_start: 0,
            proxy_header: "x-marker",
            reference_path: "/",
            candidate_path: "/",
        };
        let text = |b: &[u8]| Exchange {
            status: 200,
            headers: vec![("content-type".into(), "image/webp".into())],
            body: b.to_vec(),
            ..Exchange::default()
        };
        let o = compare(
            &ctx,
            &mut Aliases::default(),
            &text(&[0, 159, 1]),
            &text(&[0, 159, 2]),
            None,
        );
        assert_eq!(o.diffs[0].kind, DiffKind::Bytes);
        let o = compare(
            &ctx,
            &mut Aliases::default(),
            &exchange(200, "{}"),
            &exchange(200, "<html>"),
            None,
        );
        assert_eq!(o.diffs[0].kind, DiffKind::BodyKind);
    }

    #[test]
    fn etag_is_compared_as_behaviour_not_value() {
        let rs = Rules::default();
        let ctx = Ctx {
            rules: &rs,
            surface: "api_v2",
            method_path: "GET /x",
            run_start: 0,
            proxy_header: "x-marker",
            reference_path: "/",
            candidate_path: "/",
        };
        let with = |tag: Option<&str>| {
            let mut e = exchange(200, "{}");
            if let Some(t) = tag {
                e.headers.push(("etag".into(), t.into()));
            }
            e
        };
        let same = compare(
            &ctx,
            &mut Aliases::default(),
            &with(Some("\"a\"")),
            &with(Some("\"b\"")),
            None,
        );
        assert!(same.diffs.is_empty());
        let missing = compare(
            &ctx,
            &mut Aliases::default(),
            &with(Some("\"a\"")),
            &with(None),
            None,
        );
        assert_eq!(missing.diffs[0].kind, DiffKind::EtagBehaviour);
        let weak = compare(
            &ctx,
            &mut Aliases::default(),
            &with(Some("\"a\"")),
            &with(Some("W/\"a\"")),
            None,
        );
        assert_eq!(weak.diffs[0].kind, DiffKind::EtagBehaviour);
    }

    #[test]
    fn both_sides_failing_is_not_evidence_of_a_match() {
        let rs = Rules::default();
        let ctx = Ctx {
            rules: &rs,
            surface: "api_v2",
            method_path: "GET /x",
            run_start: 0,
            proxy_header: "x-marker",
            reference_path: "/",
            candidate_path: "/",
        };
        let bad = Exchange {
            error: Some("timeout".into()),
            ..Exchange::default()
        };
        let o = compare(&ctx, &mut Aliases::default(), &bad, &bad, None);
        assert!(o.diffs.is_empty());
        assert!(!o.body_compared);
        assert!(o.body_skip_reason.is_some());
    }
}
