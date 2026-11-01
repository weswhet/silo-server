//! The JSON Schema draft 2020-12 subset the settings contract uses, with the validation order and
//! error text of `santhosh-tekuri/jsonschema/v6`. Patterns compile as Go regular expressions, as
//! that validator's do, and `format` is an annotation, not an assertion.
//!
//! A schema with a keyword this subset does not implement fails to compile instead of being
//! silently ignored, so a contract change that needs one is caught at startup and in the tests.

use crate::gojson::{Node, Value};
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strconv::{format_float, quote};
use std::cmp::Ordering;
use std::collections::HashMap;

/// An arbitrary-precision decimal, the part of `big.Rat` these schemas need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dec {
    neg: bool,
    digits: Vec<u8>,
    exp: i64,
}

impl Dec {
    /// Parses a JSON number literal.
    pub fn parse(s: &str) -> Option<Dec> {
        let (neg, s) = match s.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, s),
        };
        let (mantissa, e) = match s.find(['e', 'E']) {
            Some(i) => (&s[..i], s[i + 1..].parse::<i64>().ok()?),
            None => (s, 0),
        };
        let (ip, fp) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let mut digits: Vec<u8> = ip.bytes().chain(fp.bytes()).map(|c| c - b'0').collect();
        let mut exp = e - fp.len() as i64;
        while digits.last() == Some(&0) {
            digits.pop();
            exp += 1;
        }
        let lead = digits.iter().take_while(|&&d| d == 0).count();
        digits.drain(..lead);
        if digits.is_empty() {
            return Some(Dec {
                neg: false,
                digits,
                exp: 0,
            });
        }
        Some(Dec { neg, digits, exp })
    }

    pub fn is_integer(&self) -> bool {
        self.digits.is_empty() || self.exp >= 0
    }

    fn cmp_abs(&self, other: &Dec) -> Ordering {
        if self.digits.is_empty() || other.digits.is_empty() {
            return self.digits.len().cmp(&other.digits.len());
        }
        let a = self.digits.len() as i64 + self.exp;
        let b = other.digits.len() as i64 + other.exp;
        if a != b {
            return a.cmp(&b);
        }
        let n = self.digits.len().max(other.digits.len());
        for i in 0..n {
            let x = self.digits.get(i).copied().unwrap_or(0);
            let y = other.digits.get(i).copied().unwrap_or(0);
            if x != y {
                return x.cmp(&y);
            }
        }
        Ordering::Equal
    }

    pub fn compare(&self, other: &Dec) -> Ordering {
        match (self.neg, other.neg) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => self.cmp_abs(other),
            (true, true) => other.cmp_abs(self),
        }
    }

    fn to_f64(&self) -> f64 {
        let mut s = String::new();
        if self.neg {
            s.push('-');
        }
        if self.digits.is_empty() {
            return 0.0;
        }
        for d in &self.digits {
            s.push((b'0' + d) as char);
        }
        s.push_str(&format!("e{}", self.exp));
        s.parse().unwrap_or(0.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Additional {
    Unset,
    Bool(bool),
    Schema(usize),
}

#[derive(Debug, Clone)]
struct Schema {
    location: String,
    types: Vec<String>,
    const_: Option<Value>,
    enum_: Option<Vec<Value>>,
    ref_: Option<usize>,
    min_properties: Option<usize>,
    max_properties: Option<usize>,
    required: Vec<String>,
    properties: HashMap<String, usize>,
    additional: Additional,
    property_names: Option<usize>,
    min_items: Option<usize>,
    max_items: Option<usize>,
    unique_items: bool,
    items: Option<usize>,
    contains: Option<usize>,
    min_contains: Option<usize>,
    max_contains: Option<usize>,
    min_length: Option<usize>,
    max_length: Option<usize>,
    pattern: Option<GoRegex>,
    minimum: Option<Dec>,
    maximum: Option<Dec>,
    exclusive_minimum: Option<Dec>,
    one_of: Vec<usize>,
}

/// A compiled schema document.
#[derive(Debug)]
pub struct CompiledSchema {
    arena: Vec<Schema>,
    root: usize,
}

struct Compiler<'a> {
    root_doc: &'a Node,
    base: String,
    arena: Vec<Schema>,
    by_pointer: HashMap<String, usize>,
}

fn escape_token(tok: &str) -> String {
    tok.replace('~', "~0").replace('/', "~1")
}

fn as_uint(node: &Node) -> Result<usize, String> {
    if let Value::Number(n) = &node.value
        && let Ok(v) = n.parse::<usize>()
    {
        return Ok(v);
    }
    Err("expected a non-negative integer".to_owned())
}

fn strip_spans(v: &Value) -> Value {
    match v {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|n| Node {
                    value: strip_spans(&n.value),
                    start: 0,
                    end: 0,
                })
                .collect(),
        ),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, n)| {
                    (
                        k.clone(),
                        Node {
                            value: strip_spans(&n.value),
                            start: 0,
                            end: 0,
                        },
                    )
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

impl Compiler<'_> {
    fn resolve_pointer(&self, ptr: &str) -> Result<&Node, String> {
        let mut node = self.root_doc;
        for tok in ptr.split('/').skip(1) {
            let tok = tok.replace("~1", "/").replace("~0", "~");
            node = match &node.value {
                Value::Array(items) => tok.parse::<usize>().ok().and_then(|i| items.get(i)),
                _ => node.get(&tok),
            }
            .ok_or_else(|| format!("no schema at #{ptr}"))?;
        }
        Ok(node)
    }

    fn compile(&mut self, ptr: &str) -> Result<usize, String> {
        if let Some(&id) = self.by_pointer.get(ptr) {
            return Ok(id);
        }
        let node = self.resolve_pointer(ptr)?.clone();
        let id = self.arena.len();
        self.by_pointer.insert(ptr.to_owned(), id);
        let location = format!("{}#{}", self.base, ptr);
        self.arena.push(Schema {
            location,
            types: Vec::new(),
            const_: None,
            enum_: None,
            ref_: None,
            min_properties: None,
            max_properties: None,
            required: Vec::new(),
            properties: HashMap::new(),
            additional: Additional::Unset,
            property_names: None,
            min_items: None,
            max_items: None,
            unique_items: false,
            items: None,
            contains: None,
            min_contains: None,
            max_contains: None,
            min_length: None,
            max_length: None,
            pattern: None,
            minimum: None,
            maximum: None,
            exclusive_minimum: None,
            one_of: Vec::new(),
        });
        let Value::Object(members) = &node.value else {
            return Err(format!("schema at #{ptr} is not an object"));
        };
        for (kw, v) in members {
            let child = |sub: &str| format!("{ptr}/{sub}");
            match kw.as_str() {
                "$schema" | "$id" | "$comment" | "$defs" | "title" | "description" | "default"
                | "format" | "deprecated" | "examples" => {}
                "type" => {
                    let types = match &v.value {
                        Value::String(s) => vec![s.clone()],
                        Value::Array(a) => a
                            .iter()
                            .filter_map(|n| match &n.value {
                                Value::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .collect(),
                        _ => return Err(format!("bad type at #{ptr}")),
                    };
                    self.arena[id].types = types;
                }
                "const" => self.arena[id].const_ = Some(strip_spans(&v.value)),
                "enum" => {
                    let Value::Array(items) = &v.value else {
                        return Err(format!("bad enum at #{ptr}"));
                    };
                    self.arena[id].enum_ =
                        Some(items.iter().map(|n| strip_spans(&n.value)).collect());
                }
                "$ref" => {
                    let Value::String(r) = &v.value else {
                        return Err(format!("bad $ref at #{ptr}"));
                    };
                    let Some(target) = r.strip_prefix('#') else {
                        return Err(format!("unsupported $ref {r} at #{ptr}"));
                    };
                    let target = target.to_owned();
                    let rid = self.compile(&target)?;
                    self.arena[id].ref_ = Some(rid);
                }
                "minProperties" => self.arena[id].min_properties = Some(as_uint(v)?),
                "maxProperties" => self.arena[id].max_properties = Some(as_uint(v)?),
                "required" => {
                    let Value::Array(items) = &v.value else {
                        return Err(format!("bad required at #{ptr}"));
                    };
                    self.arena[id].required = items
                        .iter()
                        .filter_map(|n| match &n.value {
                            Value::String(s) => Some(s.clone()),
                            _ => None,
                        })
                        .collect();
                }
                "properties" => {
                    let Value::Object(props) = &v.value else {
                        return Err(format!("bad properties at #{ptr}"));
                    };
                    for (name, _) in props {
                        let sub = child(&format!("properties/{}", escape_token(name)));
                        let pid = self.compile(&sub)?;
                        self.arena[id].properties.insert(name.clone(), pid);
                    }
                }
                "additionalProperties" => {
                    self.arena[id].additional = match &v.value {
                        Value::Bool(b) => Additional::Bool(*b),
                        _ => Additional::Schema(self.compile(&child("additionalProperties"))?),
                    };
                }
                "propertyNames" => {
                    let pid = self.compile(&child("propertyNames"))?;
                    self.arena[id].property_names = Some(pid);
                }
                "minItems" => self.arena[id].min_items = Some(as_uint(v)?),
                "maxItems" => self.arena[id].max_items = Some(as_uint(v)?),
                "uniqueItems" => self.arena[id].unique_items = matches!(v.value, Value::Bool(true)),
                "items" => {
                    let pid = self.compile(&child("items"))?;
                    self.arena[id].items = Some(pid);
                }
                "contains" => {
                    let pid = self.compile(&child("contains"))?;
                    self.arena[id].contains = Some(pid);
                }
                "minContains" => self.arena[id].min_contains = Some(as_uint(v)?),
                "maxContains" => self.arena[id].max_contains = Some(as_uint(v)?),
                "minLength" => self.arena[id].min_length = Some(as_uint(v)?),
                "maxLength" => self.arena[id].max_length = Some(as_uint(v)?),
                "pattern" => {
                    let Value::String(p) = &v.value else {
                        return Err(format!("bad pattern at #{ptr}"));
                    };
                    let re =
                        GoRegex::compile(p).map_err(|e| format!("invalid regex at #{ptr}: {e}"))?;
                    self.arena[id].pattern = Some(re);
                }
                "minimum" | "maximum" | "exclusiveMinimum" => {
                    let Value::Number(n) = &v.value else {
                        return Err(format!("bad {kw} at #{ptr}"));
                    };
                    let d = Dec::parse(n).ok_or_else(|| format!("bad {kw} at #{ptr}"))?;
                    match kw.as_str() {
                        "minimum" => self.arena[id].minimum = Some(d),
                        "maximum" => self.arena[id].maximum = Some(d),
                        _ => self.arena[id].exclusive_minimum = Some(d),
                    }
                }
                "oneOf" => {
                    let Value::Array(items) = &v.value else {
                        return Err(format!("bad oneOf at #{ptr}"));
                    };
                    let mut ids = Vec::with_capacity(items.len());
                    for i in 0..items.len() {
                        ids.push(self.compile(&child(&format!("oneOf/{i}")))?);
                    }
                    self.arena[id].one_of = ids;
                }
                other => {
                    return Err(format!(
                        "unsupported JSON Schema keyword {other:?} at #{ptr}"
                    ));
                }
            }
        }
        Ok(id)
    }
}

/// One validation failure, in the tree the validator's `Error()` prints.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    location: Vec<String>,
    kind: Kind,
    causes: Vec<ValidationError>,
}

#[derive(Debug, Clone, PartialEq)]
enum Kind {
    Schema(String),
    Group,
    Reference,
    Message(String),
}

fn sb_quote(s: &str) -> String {
    let q = quote(s);
    let q = q.replace("\\\"", "\"").replace('\'', "\\'");
    format!("'{}'", &q[1..q.len() - 1])
}

fn join_quoted(items: &[String]) -> String {
    items
        .iter()
        .map(|s| sb_quote(s))
        .collect::<Vec<_>>()
        .join(", ")
}

// x/text message printers group the digits of %d, and %v of a float64 prints the same shortest
// digits with grouping in the integer part.
fn grouped(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn grouped_float(f: f64) -> String {
    let s = format_float(f, b'f', -1, 64);
    let (neg, body) = match s.strip_prefix('-') {
        Some(b) => ("-", b),
        None => ("", s.as_str()),
    };
    let (ip, fp) = body.split_once('.').unwrap_or((body, ""));
    let mut out = String::from(neg);
    for (i, c) in ip.chars().enumerate() {
        if i > 0 && (ip.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if !fp.is_empty() {
        out.push('.');
        out.push_str(fp);
    }
    out
}

fn display_value(v: &Value) -> String {
    match v {
        Value::String(s) => sb_quote(s),
        Value::Array(_) | Value::Object(_) => "value".to_owned(),
        Value::Null => "<nil>".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.clone(),
    }
}

impl ValidationError {
    fn skip(&self) -> bool {
        self.causes.len() == 1 && self.kind == Kind::Reference
    }

    fn display(&self, sb: &mut String, indent: usize) {
        let mut indent = indent;
        if !self.skip() {
            if indent > 0 {
                sb.push('\n');
                for _ in 0..indent - 1 {
                    sb.push_str("  ");
                }
                sb.push_str("- ");
            }
            indent += 1;
            if let Kind::Schema(loc) = &self.kind {
                sb.push_str(&format!(
                    "jsonschema validation failed with {}",
                    sb_quote(loc)
                ));
            } else {
                let mut ptr = String::new();
                for tok in &self.location {
                    ptr.push('/');
                    ptr.push_str(&escape_token(tok));
                }
                sb.push_str(&format!("at {}: ", sb_quote(&ptr)));
                match &self.kind {
                    Kind::Group => sb.push_str("validation failed"),
                    Kind::Reference => {
                        sb.push_str("validation failed");
                    }
                    Kind::Message(m) => sb.push_str(m),
                    Kind::Schema(_) => {}
                }
            }
        }
        for cause in &self.causes {
            cause.display(sb, indent);
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut sb = String::new();
        self.display(&mut sb, 0);
        f.write_str(&sb)
    }
}

impl std::error::Error for ValidationError {}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn number_is_integer(n: &str) -> bool {
    Dec::parse(n).is_some_and(|d| d.is_integer())
}

fn json_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => match (Dec::parse(x), Dec::parse(y)) {
            (Some(p), Some(q)) => p.compare(&q) == Ordering::Equal,
            _ => false,
        },
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_equal(&p.value, &q.value))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, v)| {
                    y.iter()
                        .find(|(l, _)| l == k)
                        .is_some_and(|(_, w)| json_equal(&v.value, &w.value))
                })
        }
        _ => false,
    }
}

impl CompiledSchema {
    /// Compiles a schema document. `base` is its URL in error text.
    pub fn compile(doc: &Node, base: &str) -> Result<CompiledSchema, String> {
        let mut c = Compiler {
            root_doc: doc,
            base: base.to_owned(),
            arena: Vec::new(),
            by_pointer: HashMap::new(),
        };
        let root = c.compile("")?;
        Ok(CompiledSchema {
            arena: c.arena,
            root,
        })
    }

    /// Validates a decoded value, the way `Schema.Validate` does.
    pub fn validate(&self, v: &Value) -> Result<(), ValidationError> {
        self.validate_from(self.root, v)
    }

    fn validate_from(&self, id: usize, v: &Value) -> Result<(), ValidationError> {
        let mut vloc = Vec::new();
        match self.run(id, v, &mut vloc) {
            Ok(()) => Ok(()),
            Err(err) => {
                let causes = if err.kind == Kind::Group {
                    err.causes
                } else {
                    vec![err]
                };
                Err(ValidationError {
                    location: Vec::new(),
                    kind: Kind::Schema(self.arena[id].location.clone()),
                    causes,
                })
            }
        }
    }

    fn run(&self, id: usize, v: &Value, vloc: &mut Vec<String>) -> Result<(), ValidationError> {
        let s = &self.arena[id];
        let err = |vloc: &[String], msg: String| ValidationError {
            location: vloc.to_vec(),
            kind: Kind::Message(msg),
            causes: Vec::new(),
        };
        if !s.types.is_empty() {
            let t = type_name(v);
            let matched = s.types.iter().any(|w| {
                w == t || (w == "integer" && matches!(v, Value::Number(n) if number_is_integer(n)))
            });
            if !matched {
                return Err(err(vloc, format!("got {t}, want {}", s.types.join(" or "))));
            }
        }
        if let Some(c) = &s.const_
            && !json_equal(v, c)
        {
            let msg = match c {
                Value::Array(_) | Value::Object(_) => "'const' failed".to_owned(),
                other => format!("value must be {}", display_value(other)),
            };
            return Err(err(vloc, msg));
        }
        if let Some(values) = &s.enum_
            && !values.iter().any(|w| json_equal(v, w))
        {
            let primitive = values
                .iter()
                .all(|w| !matches!(w, Value::Array(_) | Value::Object(_)));
            let msg = if !primitive {
                "'enum' failed".to_owned()
            } else if values.len() == 1 {
                format!("value must be {}", display_value(&values[0]))
            } else {
                let want: Vec<String> = values.iter().map(display_value).collect();
                format!("value must be one of {}", want.join(", "))
            };
            return Err(err(vloc, msg));
        }
        let mut errors: Vec<ValidationError> = Vec::new();
        if let Some(r) = s.ref_
            && let Err(e) = self.run(r, v, vloc)
        {
            let causes = if e.kind == Kind::Group {
                e.causes
            } else {
                vec![e]
            };
            errors.push(ValidationError {
                location: vloc.clone(),
                kind: Kind::Reference,
                causes,
            });
        }
        match v {
            Value::Object(obj) => self.obj(s, obj, vloc, &mut errors),
            Value::Array(arr) => self.arr(s, arr, vloc, &mut errors),
            Value::String(st) => {
                if s.min_length.is_some() || s.max_length.is_some() {
                    let n = st.chars().count();
                    if let Some(min) = s.min_length
                        && n < min
                    {
                        errors.push(err(
                            vloc,
                            format!("minLength: got {}, want {}", grouped(n), grouped(min)),
                        ));
                    }
                    if let Some(max) = s.max_length
                        && n > max
                    {
                        errors.push(err(
                            vloc,
                            format!("maxLength: got {}, want {}", grouped(n), grouped(max)),
                        ));
                    }
                }
                if let Some(p) = &s.pattern
                    && !p.match_string(st)
                {
                    errors.push(err(
                        vloc,
                        format!(
                            "{} does not match pattern {}",
                            sb_quote(st),
                            sb_quote(p.as_str())
                        ),
                    ));
                }
            }
            Value::Number(n) => {
                if let Some(num) = Dec::parse(n) {
                    if let Some(min) = &s.minimum
                        && num.compare(min) == Ordering::Less
                    {
                        errors.push(err(
                            vloc,
                            format!(
                                "minimum: got {}, want {}",
                                grouped_float(num.to_f64()),
                                grouped_float(min.to_f64())
                            ),
                        ));
                    }
                    if let Some(max) = &s.maximum
                        && num.compare(max) == Ordering::Greater
                    {
                        errors.push(err(
                            vloc,
                            format!(
                                "maximum: got {}, want {}",
                                grouped_float(num.to_f64()),
                                grouped_float(max.to_f64())
                            ),
                        ));
                    }
                    if let Some(min) = &s.exclusive_minimum
                        && num.compare(min) != Ordering::Greater
                    {
                        errors.push(err(
                            vloc,
                            format!(
                                "exclusiveMinimum: got {}, want {}",
                                grouped_float(num.to_f64()),
                                grouped_float(min.to_f64())
                            ),
                        ));
                    }
                }
            }
            _ => {}
        }
        if !s.one_of.is_empty() {
            let mut matched: Option<usize> = None;
            let mut causes = Vec::new();
            let mut both = None;
            for (i, sub) in s.one_of.iter().enumerate() {
                match self.run(*sub, v, vloc) {
                    Err(e) => {
                        if matched.is_none() {
                            causes.push(e);
                        }
                    }
                    Ok(()) => {
                        if let Some(first) = matched {
                            both = Some((first, i));
                            break;
                        }
                        matched = Some(i);
                    }
                }
            }
            if let Some((a, b)) = both {
                errors.push(err(
                    vloc,
                    format!("'oneOf' failed, subschemas {a}, {b} matched"),
                ));
            } else if matched.is_none() {
                errors.push(ValidationError {
                    location: vloc.clone(),
                    kind: Kind::Message("'oneOf' failed, none matched".to_owned()),
                    causes,
                });
            }
        }
        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.remove(0)),
            _ => Err(ValidationError {
                location: vloc.clone(),
                kind: Kind::Group,
                causes: errors,
            }),
        }
    }

    fn obj(
        &self,
        s: &Schema,
        obj: &[(String, Node)],
        vloc: &mut Vec<String>,
        errors: &mut Vec<ValidationError>,
    ) {
        let err = |vloc: &[String], msg: String| ValidationError {
            location: vloc.to_vec(),
            kind: Kind::Message(msg),
            causes: Vec::new(),
        };
        if let Some(min) = s.min_properties
            && obj.len() < min
        {
            errors.push(err(
                vloc,
                format!(
                    "minProperties: got {}, want {}",
                    grouped(obj.len()),
                    grouped(min)
                ),
            ));
        }
        if let Some(max) = s.max_properties
            && obj.len() > max
        {
            errors.push(err(
                vloc,
                format!(
                    "maxProperties: got {}, want {}",
                    grouped(obj.len()),
                    grouped(max)
                ),
            ));
        }
        if !s.required.is_empty() {
            let missing: Vec<String> = s
                .required
                .iter()
                .filter(|p| !obj.iter().any(|(k, _)| k == *p))
                .cloned()
                .collect();
            if missing.len() == 1 {
                errors.push(err(
                    vloc,
                    format!("missing property {}", sb_quote(&missing[0])),
                ));
            } else if missing.len() > 1 {
                errors.push(err(
                    vloc,
                    format!("missing properties {}", join_quoted(&missing)),
                ));
            }
        }
        let mut additional: Vec<String> = Vec::new();
        for (name, value) in obj {
            if let Some(&pid) = s.properties.get(name) {
                vloc.push(name.clone());
                if let Err(e) = self.run(pid, &value.value, vloc) {
                    errors.push(e);
                }
                vloc.pop();
            } else {
                match s.additional {
                    Additional::Unset | Additional::Bool(true) => {}
                    Additional::Bool(false) => additional.push(name.clone()),
                    Additional::Schema(aid) => {
                        vloc.push(name.clone());
                        if let Err(e) = self.run(aid, &value.value, vloc) {
                            errors.push(e);
                        }
                        vloc.pop();
                    }
                }
            }
        }
        if !additional.is_empty() {
            // Go walks a map here, so its order is random. Sorted is one of the orders it can print.
            additional.sort();
            errors.push(err(
                vloc,
                format!(
                    "additional properties {} not allowed",
                    join_quoted(&additional)
                ),
            ));
        }
        if let Some(pid) = s.property_names {
            for (name, _) in obj {
                let name_value = Value::String(name.clone());
                if let Err(e) = self.validate_from(pid, &name_value) {
                    errors.push(ValidationError {
                        location: vloc.clone(),
                        kind: Kind::Message(format!("invalid propertyName {}", sb_quote(name))),
                        causes: e.causes,
                    });
                }
            }
        }
    }

    fn arr(
        &self,
        s: &Schema,
        arr: &[Node],
        vloc: &mut Vec<String>,
        errors: &mut Vec<ValidationError>,
    ) {
        let err = |vloc: &[String], msg: String| ValidationError {
            location: vloc.to_vec(),
            kind: Kind::Message(msg),
            causes: Vec::new(),
        };
        if let Some(min) = s.min_items
            && arr.len() < min
        {
            errors.push(err(
                vloc,
                format!(
                    "minItems: got {}, want {}",
                    grouped(arr.len()),
                    grouped(min)
                ),
            ));
        }
        if let Some(max) = s.max_items
            && arr.len() > max
        {
            errors.push(err(
                vloc,
                format!(
                    "maxItems: got {}, want {}",
                    grouped(arr.len()),
                    grouped(max)
                ),
            ));
        }
        if s.unique_items && arr.len() > 1 {
            'outer: for i in 1..arr.len() {
                for j in 0..i {
                    if json_equal(&arr[i].value, &arr[j].value) {
                        errors.push(err(vloc, format!("items at {j} and {i} are equal")));
                        break 'outer;
                    }
                }
            }
        }
        if let Some(items) = s.items {
            for (i, item) in arr.iter().enumerate() {
                vloc.push(i.to_string());
                if let Err(e) = self.run(items, &item.value, vloc) {
                    errors.push(e);
                }
                vloc.pop();
            }
        }
        if let Some(contains) = s.contains {
            let mut causes = Vec::new();
            let mut matched: Vec<usize> = Vec::new();
            for (i, item) in arr.iter().enumerate() {
                vloc.push(i.to_string());
                match self.run(contains, &item.value, vloc) {
                    Err(e) => causes.push(e),
                    Ok(()) => matched.push(i),
                }
                vloc.pop();
            }
            let list = |m: &[usize]| m.iter().map(usize::to_string).collect::<Vec<_>>().join(" ");
            if let Some(min) = s.min_contains {
                if matched.len() < min {
                    let msg = if matched.is_empty() {
                        format!(
                            "min {min} items required to match contains schema, but none matched"
                        )
                    } else {
                        format!(
                            "min {min} items required to match contains schema, but matched {} items at {}",
                            matched.len(),
                            list(&matched)
                        )
                    };
                    errors.push(ValidationError {
                        location: vloc.clone(),
                        kind: Kind::Message(msg),
                        causes,
                    });
                }
            } else if matched.is_empty() {
                errors.push(ValidationError {
                    location: vloc.clone(),
                    kind: Kind::Message("no items match contains schema".to_owned()),
                    causes,
                });
            }
            if let Some(max) = s.max_contains
                && matched.len() > max
            {
                errors.push(err(
                        vloc,
                        format!(
                            "max {max} items required to match contains schema, but matched {} items at {}",
                            matched.len(),
                            list(&matched)
                        ),
                    ));
            }
        }
    }
}
