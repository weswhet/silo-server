//! Narrow rules that let a known-volatile value differ. A rule names a JSON path
//! (or header) and a value format, and only applies when both sides' values have
//! that format. Type and presence are always compared first: rules only ever relax
//! the value of two leaves of the same JSON type.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleFile {
    pub rules: Vec<RuleSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub why: String,
    #[serde(default)]
    pub surfaces: Vec<String>,
    /// Regex over `METHOD /route/template`. Required so no rule is global.
    pub route: String,
    /// `$.a.b`, `$.items[*].x`, `$.map.*`, or `$..key` for a key at any depth.
    #[serde(default)]
    pub json_paths: Vec<String>,
    #[serde(default)]
    pub header: Option<String>,
    /// The whole non-JSON body.
    #[serde(default)]
    pub body: bool,
    pub format: Format,
    /// After a match, treat this pair of values as equal everywhere they recur.
    #[serde(default)]
    pub alias: bool,
    /// The value only differs because of the baseline's topology. In the peer lab both servers see the
    /// same client, so the rule does not apply there.
    #[serde(default)]
    pub not_in_peer_lab: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Format {
    Jwt,
    Uuid,
    Ipv4,
    /// Lower-case hex of at least `min_len` characters.
    Hex {
        min_len: usize,
    },
    /// RFC 3339 at or after the run's start, on both sides, at most this far apart.
    Rfc3339RunTime {
        max_skew_seconds: i64,
    },
    /// RFC 3339 at most this far apart, for windows computed back from the clock.
    Rfc3339Near {
        max_skew_seconds: i64,
    },
    /// Unix seconds at or after the run's start, at most this far apart.
    EpochRunTime {
        max_skew_seconds: i64,
    },
    /// Unix milliseconds, with the same limits.
    EpochMsRunTime {
        max_skew_seconds: i64,
    },
    /// Both values match the anchored pattern and agree outside its capture groups.
    /// Each group must also have the same length on both sides, unless `any_length`
    /// says the value's length really varies, as a cursor's or an address's does.
    Regex {
        pattern: String,
        #[serde(default)]
        any_length: bool,
    },
    /// Numbers of the same sign on both sides, for gauges such as memory use.
    AnyNumber,
    /// Same-length arrays holding the same elements in any order.
    UnorderedArray {
        /// Only where the array's parent object has this key with this value, so a
        /// list that really is ordered, next to one that shuffles, stays compared.
        when_sibling: SiblingValue,
    },
    /// Arrays of objects that each have these keys, of the same JSON types on both
    /// sides, both empty or both not, and with no key every entry on one side has and
    /// no entry on the other does. Length and contents are not compared, so this is
    /// only for feeds of the run's own asynchronous activity.
    ArrayOfObjects {
        required_keys: Vec<String>,
        /// Entries change keys as background work progresses, so the last check is off.
        #[serde(default)]
        keys_vary: bool,
    },
    /// Whole body of the same length, for random filler such as a bandwidth probe.
    SameLength,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiblingValue {
    pub key: String,
    pub equals: String,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub spec: RuleSpec,
    route: Regex,
    paths: Vec<ParsedPath>,
    pattern: Option<Regex>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsedPath {
    /// `$..key`: the segments may start at any depth.
    pub any_depth: bool,
    pub segs: Vec<PathSeg>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PathSeg {
    Key(String),
    AnyKey,
    AnyIndex,
}

/// A concrete location inside a body, built as the diff walks both documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Key(String),
    Index(usize),
}

pub fn render_path(steps: &[Step]) -> String {
    let mut out = String::from("$");
    for s in steps {
        match s {
            Step::Key(k) => {
                out.push('.');
                out.push_str(k);
            }
            Step::Index(i) => out.push_str(&format!("[{i}]")),
        }
    }
    out
}

pub fn parse_path(pattern: &str) -> Result<ParsedPath, String> {
    let rest = pattern
        .strip_prefix('$')
        .ok_or_else(|| format!("json path {pattern:?} must start with $"))?;
    let (any_depth, rest) = match rest.strip_prefix("..") {
        Some(tail) => (true, format!(".{tail}")),
        None => (false, rest.to_string()),
    };
    let mut segs = Vec::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' => {
                let mut key = String::new();
                while let Some(&n) = chars.peek() {
                    if n == '.' || n == '[' {
                        break;
                    }
                    key.push(n);
                    chars.next();
                }
                if key.is_empty() {
                    return Err(format!("json path {pattern:?} has an empty key"));
                }
                segs.push(if key == "*" {
                    PathSeg::AnyKey
                } else {
                    PathSeg::Key(key)
                });
            }
            '[' => {
                if chars.next() != Some('*') || chars.next() != Some(']') {
                    return Err(format!("json path {pattern:?}: only [*] is allowed"));
                }
                segs.push(PathSeg::AnyIndex);
            }
            _ => return Err(format!("json path {pattern:?}: unexpected {c:?}")),
        }
    }
    Ok(ParsedPath { any_depth, segs })
}

fn path_matches(path: &ParsedPath, steps: &[Step]) -> bool {
    if steps.len() < path.segs.len() || (!path.any_depth && steps.len() != path.segs.len()) {
        return false;
    }
    let tail = &steps[steps.len() - path.segs.len()..];
    path.segs.iter().zip(tail).all(|(p, s)| match (p, s) {
        (PathSeg::Key(k), Step::Key(v)) => k == v,
        (PathSeg::AnyKey, Step::Key(_)) => true,
        (PathSeg::AnyIndex, Step::Index(_)) => true,
        _ => false,
    })
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=chunk.len() {
            out.push(B64URL[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B64URL.iter().position(|x| *x == c)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits & 0xff) as u8);
        }
    }
    Some(out)
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn is_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_lower_hex(s: &str, min_len: usize) -> bool {
    s.len() >= min_len && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// UUIDs from one implementation share a spelling and version. A client that stores
/// ids as strings notices upper case, and a v4 turned v7 is a different generator.
fn uuids_alike(x: &str, y: &str) -> bool {
    let lower = |s: &str| !s.bytes().any(|c| c.is_ascii_uppercase());
    is_uuid(x) && is_uuid(y) && lower(x) == lower(y) && x.as_bytes()[14] == y.as_bytes()[14]
}

fn jwt_part(part: &str) -> Option<Value> {
    serde_json::from_slice(&b64url_decode(part)?).ok()
}

/// Claim contents are volatile, but the algorithm, the set of claims and the lifetime
/// are the token's contract. A value that does not decode is not a JWT.
fn jwts_alike(x: &str, y: &str) -> bool {
    if !is_jwt(x) || !is_jwt(y) {
        return false;
    }
    let parts = |s: &str| -> Option<(Value, Value)> {
        let mut it = s.split('.');
        Some((jwt_part(it.next()?)?, jwt_part(it.next()?)?))
    };
    let (Some((hx, px)), Some((hy, py))) = (parts(x), parts(y)) else {
        return false;
    };
    if hx != hy {
        return false;
    }
    let keys =
        |v: &Value| -> Option<Vec<String>> { Some(v.as_object()?.keys().cloned().collect()) };
    if keys(&px).is_none() || keys(&px) != keys(&py) {
        return false;
    }
    let lifetime = |v: &Value| Some(v.get("exp")?.as_i64()? - v.get("iat")?.as_i64()?);
    match (lifetime(&px), lifetime(&py)) {
        (Some(a), Some(b)) => (a - b).abs() <= 60,
        (None, None) => true,
        _ => false,
    }
}

/// The spelling of an RFC 3339 value without its digits: separator, whether it has a
/// fraction, and its offset. Digit counts are not compared because Go trims trailing
/// zeros, so one server's `.5Z` and another's `.25Z` come from the same format.
fn rfc3339_spelling(s: &str) -> Option<(char, bool, String)> {
    let sep = s.chars().nth(10)?;
    let rest = s.get(19..)?;
    let fraction = rest.starts_with('.');
    let offset = rest
        .trim_start_matches('.')
        .trim_start_matches(|c: char| c.is_ascii_digit());
    Some((sep, fraction, offset.to_string()))
}

fn rfc3339_pair(x: &str, y: &str) -> Option<(OffsetDateTime, OffsetDateTime)> {
    if rfc3339_spelling(x)? != rfc3339_spelling(y)? {
        return None;
    }
    Some((
        OffsetDateTime::parse(x, &Rfc3339).ok()?,
        OffsetDateTime::parse(y, &Rfc3339).ok()?,
    ))
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// What a feed's rule can hold another side to: see `feeds_alike`. The fault check needs it, because a
/// fault that removes what the rule asks of only one side can only show if the reference had it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedSummary {
    pub empty: bool,
    /// Keys every entry has.
    pub universal: BTreeSet<String>,
    /// Keys some entry has a non-null value for.
    pub typed: BTreeSet<String>,
}

impl FeedSummary {
    pub fn of(items: &[Value]) -> FeedSummary {
        let mut typed = BTreeSet::new();
        for e in items.iter().filter_map(Value::as_object) {
            for (k, v) in e {
                if !v.is_null() {
                    typed.insert(k.clone());
                }
            }
        }
        let universal = items
            .first()
            .and_then(Value::as_object)
            .map(|first| {
                first
                    .keys()
                    .filter(|k| items.iter().all(|e| e.get(k.as_str()).is_some()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        FeedSummary {
            empty: items.is_empty(),
            universal,
            typed,
        }
    }
}

/// See `Format::ArrayOfObjects`.
fn feeds_alike(required: &[String], keys_vary: bool, a: &[Value], b: &[Value]) -> bool {
    let well_formed = |items: &[Value]| {
        items.iter().all(|e| {
            e.as_object()
                .is_some_and(|o| required.iter().all(|k| o.contains_key(k)))
        })
    };
    if !well_formed(a) || !well_formed(b) || a.is_empty() != b.is_empty() {
        return false;
    }
    if a.is_empty() {
        return true;
    }
    // A nullable key may be null on one side only; a key that changed type may not.
    let kinds = |items: &[Value], k: &str| -> std::collections::BTreeSet<&'static str> {
        items
            .iter()
            .filter_map(|e| e.get(k))
            .map(json_kind)
            .filter(|t| *t != "null")
            .collect()
    };
    let types_agree = required.iter().all(|k| {
        let (x, y) = (kinds(a, k), kinds(b, k));
        x.is_empty() || y.is_empty() || x == y
    });
    let universal = |items: &[Value]| -> Vec<String> {
        let first = items[0].as_object().expect("well formed");
        first
            .keys()
            .filter(|k| items.iter().all(|e| e.get(k.as_str()).is_some()))
            .cloned()
            .collect()
    };
    let somewhere = |items: &[Value], k: &str| items.iter().any(|e| e.get(k).is_some());
    types_agree
        && (keys_vary
            || (universal(a).iter().all(|k| somewhere(b, k))
                && universal(b).iter().all(|k| somewhere(a, k))))
}

/// Replaces each capture group with a marker so two values can be compared with
/// their volatile parts removed. The marker keeps the group's length unless told not to.
fn strip_groups(re: &Regex, s: &str, any_length: bool) -> Option<String> {
    let caps = re.captures(s)?;
    let whole = caps.get(0)?;
    if whole.start() != 0 || whole.end() != s.len() {
        return None;
    }
    let mut out = String::new();
    let mut at = 0;
    for g in caps.iter().skip(1).flatten() {
        out.push_str(&s[at..g.start()]);
        out.push('\u{0}');
        if !any_length {
            out.push_str(&g.len().to_string());
            out.push('\u{0}');
        }
        at = g.end();
    }
    out.push_str(&s[at..]);
    Some(out)
}

impl Rule {
    pub fn compile(spec: RuleSpec) -> Result<Rule, String> {
        let targets =
            !spec.json_paths.is_empty() as u8 + spec.header.is_some() as u8 + spec.body as u8;
        if targets != 1 {
            return Err(format!(
                "rule {}: exactly one of json_paths, header, body",
                spec.id
            ));
        }
        if matches!(spec.format, Format::SameLength) != spec.body
            && !matches!(spec.format, Format::Regex { .. })
        {
            return Err(format!(
                "rule {}: same_length is the only non-regex body format",
                spec.id
            ));
        }
        for s in &spec.surfaces {
            if crate::model::Surface::parse(s).is_none() {
                return Err(format!("rule {}: unknown surface {s}", spec.id));
            }
        }
        let route = Regex::new(&format!("^(?:{})$", spec.route))
            .map_err(|e| format!("rule {}: route: {e}", spec.id))?;
        let paths = spec
            .json_paths
            .iter()
            .map(|p| parse_path(p).map_err(|e| format!("rule {}: {e}", spec.id)))
            .collect::<Result<Vec<_>, _>>()?;
        // Only a feed may be the whole document; a leaf rule at `$` would be "ignore the body".
        if paths.iter().any(|p| p.segs.is_empty())
            && !matches!(spec.format, Format::ArrayOfObjects { .. })
        {
            return Err(format!("rule {}: json path must name a location", spec.id));
        }
        let pattern = match &spec.format {
            Format::Regex { pattern, .. } => {
                let re = Regex::new(pattern).map_err(|e| format!("rule {}: {e}", spec.id))?;
                if re.captures_len() < 2 {
                    return Err(format!(
                        "rule {}: a regex format must capture its volatile parts",
                        spec.id
                    ));
                }
                Some(re)
            }
            _ => None,
        };
        Ok(Rule {
            spec,
            route,
            paths,
            pattern,
        })
    }

    /// For the mutation tests: the same value with each captured part halved, when
    /// that still matches. A rule that accepts it does not care about those lengths.
    pub fn shrink_groups(&self, s: &str) -> Option<String> {
        let re = self.pattern.as_ref()?;
        let caps = re.captures(s)?;
        let mut out = String::new();
        let mut at = 0;
        let mut changed = false;
        for g in caps.iter().skip(1).flatten() {
            out.push_str(&s[at..g.start()]);
            let text = g.as_str();
            let keep = text.char_indices().nth(text.chars().count() / 2);
            match keep {
                Some((i, _)) if i > 0 => {
                    out.push_str(&text[..i]);
                    changed = true;
                }
                _ => out.push_str(text),
            }
            at = g.end();
        }
        out.push_str(&s[at..]);
        (changed && re.is_match(&out)).then_some(out)
    }

    pub fn allows_any_length(&self) -> bool {
        matches!(
            self.spec.format,
            Format::Regex {
                any_length: true,
                ..
            }
        )
    }

    pub fn at_path(&self, steps: &[Step]) -> bool {
        self.paths.iter().any(|p| path_matches(p, steps))
    }

    pub fn applies_to_route(&self, surface: &str, method_path: &str) -> bool {
        (self.spec.surfaces.is_empty() || self.spec.surfaces.iter().any(|s| s == surface))
            && self.route.is_match(method_path)
    }

    /// True when both values have this rule's format, so their difference is allowed.
    pub fn values_equivalent(&self, a: &Value, b: &Value, run_start: i64) -> bool {
        match (&self.spec.format, a, b) {
            (Format::AnyNumber, Value::Number(x), Value::Number(y)) => {
                match (x.as_f64(), y.as_f64()) {
                    (Some(x), Some(y)) => (x < 0.0) == (y < 0.0),
                    _ => false,
                }
            }
            (Format::EpochRunTime { max_skew_seconds }, Value::Number(x), Value::Number(y)) => {
                match (x.as_i64(), y.as_i64()) {
                    (Some(x), Some(y)) => {
                        x >= run_start && y >= run_start && (x - y).abs() <= *max_skew_seconds
                    }
                    _ => false,
                }
            }
            (Format::EpochMsRunTime { max_skew_seconds }, Value::Number(x), Value::Number(y)) => {
                match (x.as_i64(), y.as_i64()) {
                    (Some(x), Some(y)) => {
                        x / 1000 >= run_start
                            && y / 1000 >= run_start
                            && (x - y).abs() <= max_skew_seconds * 1000
                    }
                    _ => false,
                }
            }
            (_, Value::String(x), Value::String(y)) => self.strings_equivalent(x, y, run_start),
            _ => false,
        }
    }

    pub fn strings_equivalent(&self, x: &str, y: &str, run_start: i64) -> bool {
        match &self.spec.format {
            Format::Jwt => jwts_alike(x, y),
            Format::Uuid => uuids_alike(x, y),
            Format::Ipv4 => is_ipv4(x) && is_ipv4(y),
            Format::Hex { min_len } => {
                x.len() == y.len() && is_lower_hex(x, *min_len) && is_lower_hex(y, *min_len)
            }
            Format::Rfc3339RunTime { max_skew_seconds } => {
                let Some((a, b)) = rfc3339_pair(x, y) else {
                    return false;
                };
                a.unix_timestamp() >= run_start
                    && b.unix_timestamp() >= run_start
                    && (a - b).whole_seconds().abs() <= *max_skew_seconds
            }
            Format::Rfc3339Near { max_skew_seconds } => {
                let Some((a, b)) = rfc3339_pair(x, y) else {
                    return false;
                };
                (a - b).whole_seconds().abs() <= *max_skew_seconds
            }
            Format::Regex { any_length, .. } => {
                let re = self.pattern.as_ref().expect("compiled with the rule");
                match (
                    strip_groups(re, x, *any_length),
                    strip_groups(re, y, *any_length),
                ) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                }
            }
            Format::EpochRunTime { .. }
            | Format::EpochMsRunTime { .. }
            | Format::AnyNumber
            | Format::UnorderedArray { .. }
            | Format::ArrayOfObjects { .. }
            | Format::SameLength => false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Rules {
    pub rules: Vec<Rule>,
}

impl Rules {
    /// The rules for a run through the peer lab.
    pub fn for_peer_lab(mut self) -> Rules {
        self.rules.retain(|r| !r.spec.not_in_peer_lab);
        self
    }

    pub fn parse(json: &str) -> Result<Rules, String> {
        let file: RuleFile = serde_json::from_str(json).map_err(|e| format!("normalizers: {e}"))?;
        let mut rules = Vec::new();
        let mut seen = BTreeMap::new();
        for spec in file.rules {
            if seen.insert(spec.id.clone(), ()).is_some() {
                return Err(format!("duplicate rule id {}", spec.id));
            }
            rules.push(Rule::compile(spec)?);
        }
        Ok(Rules { rules })
    }

    pub fn matching_leaf<'a>(
        &'a self,
        surface: &str,
        method_path: &str,
        steps: &[Step],
        a: &Value,
        b: &Value,
        run_start: i64,
    ) -> Option<&'a Rule> {
        self.rules.iter().find(|r| {
            r.at_path(steps)
                && r.applies_to_route(surface, method_path)
                && r.values_equivalent(a, b, run_start)
        })
    }

    /// `parents` holds the array's parent object on each side.
    pub fn unordered_at(
        &self,
        surface: &str,
        method_path: &str,
        steps: &[Step],
        parents: [Option<&Value>; 2],
    ) -> Option<&Rule> {
        self.rules.iter().find(|r| {
            let Format::UnorderedArray { when_sibling } = &r.spec.format else {
                return false;
            };
            r.at_path(steps)
                && r.applies_to_route(surface, method_path)
                && parents.iter().all(|p| {
                    p.and_then(|v| v.get(&when_sibling.key))
                        .and_then(Value::as_str)
                        == Some(when_sibling.equals.as_str())
                })
        })
    }

    /// A feed rule at this path whose required keys both arrays satisfy.
    pub fn feed_at(
        &self,
        surface: &str,
        method_path: &str,
        steps: &[Step],
        a: &[Value],
        b: &[Value],
    ) -> Option<&Rule> {
        self.rules.iter().find(|r| {
            let Format::ArrayOfObjects {
                required_keys,
                keys_vary,
            } = &r.spec.format
            else {
                return false;
            };
            r.at_path(steps)
                && r.applies_to_route(surface, method_path)
                && feeds_alike(required_keys, *keys_vary, a, b)
        })
    }

    /// Whether a feed rule names this route. Decided by the route rather than by this
    /// answer, so an empty feed that happened to match byte for byte is no better evidence.
    pub fn route_has_feed(&self, surface: &str, method_path: &str) -> bool {
        self.rules.iter().any(|r| {
            matches!(r.spec.format, Format::ArrayOfObjects { .. })
                && r.applies_to_route(surface, method_path)
        })
    }

    /// The feed rule, if any, that leaves this location's contents uncompared.
    pub fn feed_covering(&self, surface: &str, method_path: &str, steps: &[Step]) -> Option<&Rule> {
        self.rules.iter().find(|r| {
            matches!(r.spec.format, Format::ArrayOfObjects { .. })
                && r.applies_to_route(surface, method_path)
                && (0..=steps.len()).any(|n| r.at_path(&steps[..n]))
        })
    }

    pub fn matching_header<'a>(
        &'a self,
        surface: &str,
        method_path: &str,
        header: &str,
        a: &str,
        b: &str,
        run_start: i64,
    ) -> Option<&'a Rule> {
        self.rules.iter().find(|r| {
            r.spec
                .header
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(header))
                && r.applies_to_route(surface, method_path)
                && r.strings_equivalent(a, b, run_start)
        })
    }

    pub fn matching_body<'a>(
        &'a self,
        surface: &str,
        method_path: &str,
        a: &[u8],
        b: &[u8],
        run_start: i64,
    ) -> Option<&'a Rule> {
        self.rules.iter().find(|r| {
            if !r.spec.body || !r.applies_to_route(surface, method_path) {
                return false;
            }
            if matches!(r.spec.format, Format::SameLength) {
                return a.len() == b.len();
            }
            match (std::str::from_utf8(a), std::str::from_utf8(b)) {
                (Ok(x), Ok(y)) => r.strings_equivalent(x, y, run_start),
                _ => false,
            }
        })
    }
}
