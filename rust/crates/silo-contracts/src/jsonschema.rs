//! The part of `santhosh-tekuri/jsonschema/v6` the settings value schemas use, with its error text.
//!
//! The text matters because it lands in `user_setting_migration_rejects.reason`. The `jsonschema`
//! crate words errors differently. Keywords no embedded schema uses aren't ported, and compiling a
//! schema that uses one fails, so a contract change can't silently lose a check.
//!
//! Go iterates objects as maps, so when several properties fail, its order of causes and of names in
//! `additional properties` is random. This port uses key order.

use std::collections::BTreeMap;

use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strconv::{format_float, quote as go_quote};

use crate::embedded::contract_dir;
use crate::gojson::{self, Value};

const IGNORED_KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "$comment",
    "$defs",
    "title",
    "description",
    "deprecated",
];

#[derive(Clone, Debug)]
enum Additional {
    None,
    Bool(bool),
    Schema(usize),
}

#[derive(Clone, Debug)]
struct Schema {
    bool_schema: Option<bool>,
    types: Vec<String>,
    constant: Option<Value>,
    enumeration: Option<Vec<Value>>,
    reference: Option<usize>,
    min_properties: Option<usize>,
    max_properties: Option<usize>,
    required: Vec<String>,
    properties: BTreeMap<String, usize>,
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
    pattern: Option<(GoRegex, String)>,
    minimum: Option<Dec>,
    maximum: Option<Dec>,
    one_of: Vec<usize>,
}

impl Schema {
    fn empty() -> Self {
        Schema {
            bool_schema: None,
            types: Vec::new(),
            constant: None,
            enumeration: None,
            reference: None,
            min_properties: None,
            max_properties: None,
            required: Vec::new(),
            properties: BTreeMap::new(),
            additional: Additional::None,
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
            one_of: Vec::new(),
        }
    }
}

/// A decimal value, as `big.Rat` holds it for comparison: `0.digits * 10^exp`.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Dec {
    negative: bool,
    digits: Vec<u8>,
    exp: i64,
}

impl Dec {
    /// `new(big.Rat).SetString` for a JSON number literal. `None` is its refusal of an exponent past
    /// 1e6.
    fn parse(literal: &str) -> Option<Dec> {
        let (negative, rest) = match literal.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, literal),
        };
        let (mantissa, exponent) = match rest.find(['e', 'E']) {
            Some(at) => (&rest[..at], rest[at + 1..].parse::<i64>().ok()?),
            None => (rest, 0),
        };
        let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if (exponent - frac.len() as i64).abs() > 1_000_000 {
            return None;
        }
        let mut digits: Vec<u8> = int.bytes().chain(frac.bytes()).map(|c| c - b'0').collect();
        let mut exp = exponent + int.len() as i64;
        let leading = digits.iter().take_while(|d| **d == 0).count();
        digits.drain(..leading);
        exp -= leading as i64;
        while digits.last() == Some(&0) {
            digits.pop();
        }
        if digits.is_empty() {
            return Some(Dec {
                negative: false,
                digits,
                exp: 0,
            });
        }
        Some(Dec {
            negative,
            digits,
            exp,
        })
    }

    fn is_int(&self) -> bool {
        self.digits.is_empty() || self.digits.len() as i64 <= self.exp
    }

    fn cmp(&self, other: &Dec) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        match (self.negative, other.negative) {
            (true, false) => return Less,
            (false, true) => return Greater,
            _ => {}
        }
        let magnitude = match (self.digits.is_empty(), other.digits.is_empty()) {
            (true, true) => Equal,
            (true, false) => Less,
            (false, true) => Greater,
            (false, false) => self
                .exp
                .cmp(&other.exp)
                .then_with(|| self.digits.cmp(&other.digits)),
        };
        if self.negative {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
}

// fmt.Sprint(json.Number) through Rat.SetString. A literal it refuses is a nil Rat, and Go's next call
// on it panics. Every embedded schema with a bound also says "type": "integer", and that check fails
// first for such a literal, so neither program gets here with one.
fn num(literal: &str) -> Dec {
    Dec::parse(literal)
        .unwrap_or_else(|| panic!("jsonschema: big.Rat refused the number {literal}"))
}

fn equals(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|other| equals(v, other)))
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| equals(p, q))
        }
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => match (Dec::parse(x), Dec::parse(y)) {
            (Some(p), Some(q)) => p.cmp(&q).is_eq(),
            _ => false,
        },
        _ => false,
    }
}

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

// quote in the kind package.
fn quote(s: &str) -> String {
    let q = go_quote(s).replace("\\\"", "\"").replace('\'', "\\'");
    format!("'{}'", &q[1..q.len() - 1])
}

// display in the kind package, for primitives.
fn display(v: &Value) -> String {
    match v {
        Value::String(s) => quote(s),
        Value::Array(_) | Value::Object(_) => "value".to_string(),
        Value::Number(n) => n.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "<nil>".to_string(),
    }
}

fn join_quoted(items: &[String]) -> String {
    items
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(", ")
}

// message.Printer's %d in English: digit grouping.
fn group_int(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    if n < 0 {
        out.push('-');
    }
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn superscript(digits: &str) -> String {
    digits
        .chars()
        .map(|c| match c {
            '0' => '⁰',
            '1' => '¹',
            '2' => '²',
            '3' => '³',
            '4' => '⁴',
            '5' => '⁵',
            '6' => '⁶',
            '7' => '⁷',
            '8' => '⁸',
            '9' => '⁹',
            other => other,
        })
        .collect()
}

// message.Printer's %v for a float64 in English: fmtVariableFloat.
fn message_float(v: f64) -> String {
    let text = format_float(v, b'e', -1, 64);
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let exp: i32 = exponent.parse().unwrap_or(0);
    let (negative, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if !(-4..6).contains(&exp) {
        out.push_str(mantissa);
        out.push('×');
        out.push_str("10");
        let abs = exp.abs();
        if exp < 0 {
            out.push('⁻');
        }
        out.push_str(&superscript(&format!("{abs:02}")));
        return out;
    }
    if exp < 0 {
        out.push_str("0.");
        for _ in 0..(-exp - 1) {
            out.push('0');
        }
        out.push_str(&digits);
        return out;
    }
    let int_len = exp as usize + 1;
    let (int, frac) = if digits.len() > int_len {
        (digits[..int_len].to_string(), digits[int_len..].to_string())
    } else {
        (format!("{digits:0<width$}", width = int_len), String::new())
    };
    for (i, c) in int.chars().enumerate() {
        if i > 0 && (int.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if !frac.is_empty() {
        out.push('.');
        out.push_str(&frac);
    }
    out
}

fn float_of(literal: &str) -> f64 {
    literal.parse().unwrap_or(f64::INFINITY)
}

fn json_ptr(tokens: &[String]) -> String {
    let mut out = String::new();
    for token in tokens {
        out.push('/');
        out.push_str(&token.replace('~', "~0").replace('/', "~1"));
    }
    out
}

#[derive(Clone, Debug)]
enum Kind {
    Schema,
    Group,
    Reference,
    FalseSchema,
    Type {
        got: &'static str,
        want: Vec<String>,
    },
    Const(String),
    Enum(String),
    MinProperties(usize, usize),
    MaxProperties(usize, usize),
    Required(Vec<String>),
    AdditionalProperties(Vec<String>),
    PropertyNames(String),
    MinItems(usize, usize),
    MaxItems(usize, usize),
    UniqueItems(usize, usize),
    MinContains(Vec<usize>, usize),
    MaxContains(Vec<usize>, usize),
    Contains,
    MinLength(usize, usize),
    MaxLength(usize, usize),
    Pattern(String, String),
    Minimum(f64, f64),
    Maximum(f64, f64),
    OneOfNone,
    OneOfMany(usize, usize),
}

impl Kind {
    fn text(&self, location: &str) -> String {
        match self {
            Kind::Schema => format!("jsonschema validation failed with {}", quote(location)),
            Kind::Group | Kind::Reference => "validation failed".to_string(),
            Kind::FalseSchema => "false schema".to_string(),
            Kind::Type { got, want } => format!("got {got}, want {}", want.join(" or ")),
            Kind::Const(text) | Kind::Enum(text) => text.clone(),
            Kind::MinProperties(g, w) => {
                format!("minProperties: got {}, want {}", group(*g), group(*w))
            }
            Kind::MaxProperties(g, w) => {
                format!("maxProperties: got {}, want {}", group(*g), group(*w))
            }
            Kind::Required(missing) => {
                if missing.len() == 1 {
                    format!("missing property {}", quote(&missing[0]))
                } else {
                    format!("missing properties {}", join_quoted(missing))
                }
            }
            Kind::AdditionalProperties(names) => {
                format!("additional properties {} not allowed", join_quoted(names))
            }
            Kind::PropertyNames(name) => format!("invalid propertyName {}", quote(name)),
            Kind::MinItems(g, w) => format!("minItems: got {}, want {}", group(*g), group(*w)),
            Kind::MaxItems(g, w) => format!("maxItems: got {}, want {}", group(*g), group(*w)),
            Kind::UniqueItems(i, j) => {
                format!("items at {} and {} are equal", group(*i), group(*j))
            }
            Kind::Contains => "no items match contains schema".to_string(),
            Kind::MinContains(got, want) => {
                if got.is_empty() {
                    format!(
                        "min {} items required to match contains schema, but none matched",
                        group(*want)
                    )
                } else {
                    format!(
                        "min {} items required to match contains schema, but matched {} items at {}",
                        group(*want),
                        group(got.len()),
                        space_list(got)
                    )
                }
            }
            Kind::MaxContains(got, want) => format!(
                "max {} items required to match contains schema, but matched {} items at {}",
                group(*want),
                group(got.len()),
                space_list(got)
            ),
            Kind::MinLength(g, w) => format!("minLength: got {}, want {}", group(*g), group(*w)),
            Kind::MaxLength(g, w) => format!("maxLength: got {}, want {}", group(*g), group(*w)),
            Kind::Pattern(got, want) => {
                format!("{} does not match pattern {}", quote(got), quote(want))
            }
            Kind::Minimum(g, w) => format!(
                "minimum: got {}, want {}",
                message_float(*g),
                message_float(*w)
            ),
            Kind::Maximum(g, w) => format!(
                "maximum: got {}, want {}",
                message_float(*g),
                message_float(*w)
            ),
            Kind::OneOfNone => "'oneOf' failed, none matched".to_string(),
            Kind::OneOfMany(a, b) => format!(
                "'oneOf' failed, subschemas {}, {} matched",
                group(*a),
                group(*b)
            ),
        }
    }
}

fn group(n: usize) -> String {
    group_int(n as i64)
}

fn space_list(items: &[usize]) -> String {
    items
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug)]
struct VError {
    location: Vec<String>,
    kind: Kind,
    causes: Vec<VError>,
}

impl VError {
    fn skip(&self) -> bool {
        self.causes.len() == 1 && matches!(self.kind, Kind::Reference)
    }

    fn display(&self, out: &mut String, indent: usize, root: &str) {
        let mut indent = indent;
        if !self.skip() {
            if indent > 0 {
                out.push('\n');
                for _ in 0..indent - 1 {
                    out.push_str("  ");
                }
                out.push_str("- ");
            }
            indent += 1;
            if matches!(self.kind, Kind::Schema) {
                out.push_str(&self.kind.text(root));
            } else {
                out.push_str("at ");
                out.push_str(&quote(&json_ptr(&self.location)));
                out.push_str(": ");
                out.push_str(&self.kind.text(root));
            }
        }
        for cause in &self.causes {
            cause.display(out, indent, root);
        }
    }
}

/// The compiled value schemas, keyed by `schema_ref`.
pub struct SchemaSet {
    schemas: Vec<Schema>,
    roots: BTreeMap<String, (usize, String)>,
}

/// `os.Getwd`: `$PWD` when it names the current directory, else the system's answer.
pub fn go_getwd() -> String {
    let dot = std::fs::metadata(".");
    if let Ok(pwd) = std::env::var("PWD")
        && pwd.starts_with('/')
        && let (Ok(a), Ok(b)) = (std::fs::metadata(&pwd), dot.as_ref())
    {
        use std::os::unix::fs::MetadataExt;
        if a.dev() == b.dev() && a.ino() == b.ino() {
            return pwd;
        }
    }
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl SchemaSet {
    /// Compiles every file under `contracts/settings/v1/schemas`.
    ///
    /// Go registers each schema under its bare file name, which `jsonschema` resolves against the
    /// working directory. That location is part of its error text, so `cwd` is too.
    pub fn compile_embedded(cwd: &str) -> Result<Self, String> {
        let mut set = SchemaSet {
            schemas: Vec::new(),
            roots: BTreeMap::new(),
        };
        for (name, bytes) in contract_dir("settings/v1/schemas") {
            if !name.ends_with(".json") {
                continue;
            }
            let (doc, _) = gojson::decode(bytes).map_err(|e| format!("parsing {name}: {e}"))?;
            let mut compiler = Compiler {
                root: &doc,
                set: &mut set,
                done: BTreeMap::new(),
            };
            let id = compiler
                .compile(&doc, "")
                .map_err(|e| format!("compiling value schema {name}: {e}"))?;
            let location = format!("file://{cwd}/{name}#");
            set.roots.insert(name.to_string(), (id, location));
        }
        Ok(set)
    }

    /// Whether `schema_ref` names a compiled schema.
    pub fn contains(&self, schema_ref: &str) -> bool {
        self.roots.contains_key(schema_ref)
    }

    /// `Schema.Validate`: `Err` carries the error's text.
    pub fn validate(&self, schema_ref: &str, doc: &Value) -> Result<(), String> {
        let (root, location) = self
            .roots
            .get(schema_ref)
            .ok_or_else(|| format!("no compiled schema for {schema_ref}"))?;
        let Err(err) = self.run(*root, doc, &[]) else {
            return Ok(());
        };
        let causes = if matches!(err.kind, Kind::Group) {
            err.causes
        } else {
            vec![err]
        };
        let top = VError {
            location: Vec::new(),
            kind: Kind::Schema,
            causes,
        };
        let mut out = String::new();
        top.display(&mut out, 0, location);
        Err(out)
    }

    fn run(&self, id: usize, v: &Value, vloc: &[String]) -> Result<(), VError> {
        let s = &self.schemas[id];
        let error = |kind: Kind| VError {
            location: vloc.to_vec(),
            kind,
            causes: Vec::new(),
        };

        if let Some(allowed) = s.bool_schema {
            return if allowed {
                Ok(())
            } else {
                Err(error(Kind::FalseSchema))
            };
        }

        if !s.types.is_empty() {
            let t = type_name(v);
            let matched = s.types.iter().any(|w| w == t)
                || (s.types.iter().any(|w| w == "integer")
                    && matches!(v, Value::Number(n) if Dec::parse(n).is_some_and(|d| d.is_int())));
            if !matched {
                return Err(error(Kind::Type {
                    got: t,
                    want: s.types.clone(),
                }));
            }
        }

        if let Some(want) = &s.constant
            && !equals(v, want)
        {
            let text = match want {
                Value::Array(_) | Value::Object(_) => "'const' failed".to_string(),
                _ => format!("value must be {}", display(want)),
            };
            return Err(error(Kind::Const(text)));
        }

        if let Some(values) = &s.enumeration
            && !values.iter().any(|item| equals(v, item))
        {
            let primitive = values
                .iter()
                .all(|item| !matches!(item, Value::Array(_) | Value::Object(_)));
            let text = if !primitive {
                "'enum' failed".to_string()
            } else if values.len() == 1 {
                format!("value must be {}", display(&values[0]))
            } else {
                format!(
                    "value must be one of {}",
                    values.iter().map(display).collect::<Vec<_>>().join(", ")
                )
            };
            return Err(error(Kind::Enum(text)));
        }

        let mut errors: Vec<VError> = Vec::new();

        if let Some(target) = s.reference
            && let Err(err) = self.run(target, v, vloc)
        {
            let causes = if matches!(err.kind, Kind::Group) {
                err.causes
            } else {
                vec![err]
            };
            errors.push(VError {
                location: vloc.to_vec(),
                kind: Kind::Reference,
                causes,
            });
        }

        match v {
            Value::Object(obj) => self.object(s, obj, vloc, &mut errors, &error),
            Value::Array(arr) => self.array(s, arr, vloc, &mut errors, &error),
            Value::String(text) => {
                if s.min_length.is_some() || s.max_length.is_some() {
                    let len = text.chars().count();
                    if let Some(min) = s.min_length
                        && len < min
                    {
                        errors.push(error(Kind::MinLength(len, min)));
                    }
                    if let Some(max) = s.max_length
                        && len > max
                    {
                        errors.push(error(Kind::MaxLength(len, max)));
                    }
                }
                if let Some((regex, source)) = &s.pattern
                    && !regex.match_string(text)
                {
                    errors.push(error(Kind::Pattern(text.clone(), source.clone())));
                }
            }
            Value::Number(literal) => {
                if let Some(min) = &s.minimum
                    && num(literal).cmp(min).is_lt()
                {
                    errors.push(error(Kind::Minimum(float_of(literal), dec_float(min))));
                }
                if let Some(max) = &s.maximum
                    && num(literal).cmp(max).is_gt()
                {
                    errors.push(error(Kind::Maximum(float_of(literal), dec_float(max))));
                }
            }
            _ => {}
        }

        if !s.one_of.is_empty() {
            let mut matched: Option<usize> = None;
            let mut sub_errors = Vec::new();
            for (i, sub) in s.one_of.iter().enumerate() {
                match self.run(*sub, v, vloc) {
                    Err(err) => {
                        if matched.is_none() {
                            sub_errors.push(err);
                        }
                    }
                    Ok(()) => {
                        if let Some(first) = matched {
                            errors.push(error(Kind::OneOfMany(first, i)));
                            break;
                        }
                        matched = Some(i);
                    }
                }
            }
            if matched.is_none() {
                errors.push(VError {
                    location: vloc.to_vec(),
                    kind: Kind::OneOfNone,
                    causes: sub_errors,
                });
            }
        }

        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.pop().expect("one error")),
            _ => Err(VError {
                location: vloc.to_vec(),
                kind: Kind::Group,
                causes: errors,
            }),
        }
    }

    fn object(
        &self,
        s: &Schema,
        obj: &BTreeMap<String, Value>,
        vloc: &[String],
        errors: &mut Vec<VError>,
        error: &dyn Fn(Kind) -> VError,
    ) {
        if let Some(min) = s.min_properties
            && obj.len() < min
        {
            errors.push(error(Kind::MinProperties(obj.len(), min)));
        }
        if let Some(max) = s.max_properties
            && obj.len() > max
        {
            errors.push(error(Kind::MaxProperties(obj.len(), max)));
        }
        let missing: Vec<String> = s
            .required
            .iter()
            .filter(|name| !obj.contains_key(*name))
            .cloned()
            .collect();
        if !missing.is_empty() {
            errors.push(error(Kind::Required(missing)));
        }

        let mut additional = Vec::new();
        for (name, value) in obj {
            let mut child = vloc.to_vec();
            child.push(name.clone());
            if let Some(sub) = s.properties.get(name) {
                if let Err(err) = self.run(*sub, value, &child) {
                    errors.push(err);
                }
                continue;
            }
            match &s.additional {
                Additional::None => {}
                Additional::Bool(true) => {}
                Additional::Bool(false) => additional.push(name.clone()),
                Additional::Schema(sub) => {
                    if let Err(err) = self.run(*sub, value, &child) {
                        errors.push(err);
                    }
                }
            }
        }
        if !additional.is_empty() {
            errors.push(error(Kind::AdditionalProperties(additional)));
        }

        if let Some(names) = s.property_names {
            for name in obj.keys() {
                // A nested Schema.Validate: its causes report at the root of the name.
                if let Err(err) = self.run(names, &Value::String(name.clone()), &[]) {
                    let causes = if matches!(err.kind, Kind::Group) {
                        err.causes
                    } else {
                        vec![err]
                    };
                    errors.push(VError {
                        location: vloc.to_vec(),
                        kind: Kind::PropertyNames(name.clone()),
                        causes,
                    });
                }
            }
        }
    }

    fn array(
        &self,
        s: &Schema,
        arr: &[Value],
        vloc: &[String],
        errors: &mut Vec<VError>,
        error: &dyn Fn(Kind) -> VError,
    ) {
        if let Some(min) = s.min_items
            && arr.len() < min
        {
            errors.push(error(Kind::MinItems(arr.len(), min)));
        }
        if let Some(max) = s.max_items
            && arr.len() > max
        {
            errors.push(error(Kind::MaxItems(arr.len(), max)));
        }
        if s.unique_items && arr.len() > 1 {
            'dups: for i in 1..arr.len() {
                for j in 0..i {
                    if equals(&arr[i], &arr[j]) {
                        errors.push(error(Kind::UniqueItems(j, i)));
                        break 'dups;
                    }
                }
            }
        }
        if let Some(items) = s.items {
            for (i, item) in arr.iter().enumerate() {
                let mut child = vloc.to_vec();
                child.push(i.to_string());
                if let Err(err) = self.run(items, item, &child) {
                    errors.push(err);
                }
            }
        }
        if let Some(contains) = s.contains {
            let mut sub_errors = Vec::new();
            let mut matched = Vec::new();
            for (i, item) in arr.iter().enumerate() {
                let mut child = vloc.to_vec();
                child.push(i.to_string());
                match self.run(contains, item, &child) {
                    Err(err) => sub_errors.push(err),
                    Ok(()) => matched.push(i),
                }
            }
            if let Some(min) = s.min_contains {
                if matched.len() < min {
                    errors.push(VError {
                        location: vloc.to_vec(),
                        kind: Kind::MinContains(matched.clone(), min),
                        causes: sub_errors,
                    });
                }
            } else if matched.is_empty() {
                errors.push(VError {
                    location: vloc.to_vec(),
                    kind: Kind::Contains,
                    causes: sub_errors,
                });
            }
            if let Some(max) = s.max_contains
                && matched.len() > max
            {
                errors.push(error(Kind::MaxContains(matched, max)));
            }
        }
    }
}

fn dec_float(d: &Dec) -> f64 {
    let digits: String = d.digits.iter().map(|x| char::from(b'0' + x)).collect();
    let digits = if digits.is_empty() {
        "0".to_string()
    } else {
        digits
    };
    let sign = if d.negative { "-" } else { "" };
    format!("{sign}0.{digits}e{}", d.exp)
        .parse()
        .unwrap_or(f64::INFINITY)
}

struct Compiler<'a> {
    root: &'a Value,
    set: &'a mut SchemaSet,
    done: BTreeMap<String, usize>,
}

fn usize_of(v: &Value, keyword: &str) -> Result<usize, String> {
    match v {
        Value::Number(n) => n
            .parse()
            .map_err(|_| format!("{keyword} is not an integer")),
        _ => Err(format!("{keyword} is not a number")),
    }
}

fn strings_of(v: &Value, keyword: &str) -> Result<Vec<String>, String> {
    match v {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => Ok(s.clone()),
                _ => Err(format!("{keyword} holds a non-string")),
            })
            .collect(),
        _ => Err(format!("{keyword} is not a string list")),
    }
}

const TYPE_ORDER: &[&str] = &[
    "null", "boolean", "number", "integer", "string", "array", "object",
];

impl Compiler<'_> {
    fn resolve(&self, pointer: &str) -> Result<&'_ Value, String> {
        let mut at = self.root;
        for token in pointer.split('/').skip(1) {
            let token = token.replace("~1", "/").replace("~0", "~");
            at = match at {
                Value::Object(map) => map
                    .get(&token)
                    .ok_or_else(|| format!("no {pointer} in the schema"))?,
                _ => return Err(format!("no {pointer} in the schema")),
            };
        }
        Ok(at)
    }

    fn compile(&mut self, doc: &Value, pointer: &str) -> Result<usize, String> {
        if let Some(id) = self.done.get(pointer) {
            return Ok(*id);
        }
        let id = self.set.schemas.len();
        self.set.schemas.push(Schema::empty());
        self.done.insert(pointer.to_string(), id);

        let mut s = Schema::empty();
        match doc {
            Value::Bool(b) => s.bool_schema = Some(*b),
            Value::Object(map) => {
                for (keyword, value) in map {
                    let child = format!("{pointer}/{keyword}");
                    match keyword.as_str() {
                        k if IGNORED_KEYWORDS.contains(&k) => {}
                        "type" => {
                            let wanted = strings_of(value, keyword)?;
                            s.types = TYPE_ORDER
                                .iter()
                                .filter(|t| wanted.iter().any(|w| w == *t))
                                .map(|t| (*t).to_string())
                                .collect();
                        }
                        "const" => s.constant = Some(value.clone()),
                        "enum" => {
                            let Value::Array(items) = value else {
                                return Err("enum is not a list".to_string());
                            };
                            s.enumeration = Some(items.clone());
                        }
                        "$ref" => {
                            let Value::String(target) = value else {
                                return Err("$ref is not a string".to_string());
                            };
                            let Some(local) = target.strip_prefix('#') else {
                                return Err(format!("unsupported $ref {target}"));
                            };
                            let local = local.to_string();
                            let resolved = self.resolve(&local)?.clone();
                            s.reference = Some(self.compile(&resolved, &local)?);
                        }
                        "minProperties" => s.min_properties = Some(usize_of(value, keyword)?),
                        "maxProperties" => s.max_properties = Some(usize_of(value, keyword)?),
                        "required" => s.required = strings_of(value, keyword)?,
                        "properties" => {
                            let Value::Object(props) = value else {
                                return Err("properties is not an object".to_string());
                            };
                            for (name, sub) in props {
                                let at = format!("{child}/{name}");
                                let compiled = self.compile(sub, &at)?;
                                s.properties.insert(name.clone(), compiled);
                            }
                        }
                        "additionalProperties" => {
                            s.additional = match value {
                                Value::Bool(b) => Additional::Bool(*b),
                                other => Additional::Schema(self.compile(other, &child)?),
                            };
                        }
                        "propertyNames" => {
                            s.property_names = Some(self.compile(value, &child)?);
                        }
                        "minItems" => s.min_items = Some(usize_of(value, keyword)?),
                        "maxItems" => s.max_items = Some(usize_of(value, keyword)?),
                        "uniqueItems" => s.unique_items = matches!(value, Value::Bool(true)),
                        "items" => s.items = Some(self.compile(value, &child)?),
                        "contains" => s.contains = Some(self.compile(value, &child)?),
                        "minContains" => s.min_contains = Some(usize_of(value, keyword)?),
                        "maxContains" => s.max_contains = Some(usize_of(value, keyword)?),
                        "minLength" => s.min_length = Some(usize_of(value, keyword)?),
                        "maxLength" => s.max_length = Some(usize_of(value, keyword)?),
                        "pattern" => {
                            let Value::String(source) = value else {
                                return Err("pattern is not a string".to_string());
                            };
                            let regex = GoRegex::compile(source)
                                .map_err(|e| format!("pattern {source}: {e}"))?;
                            s.pattern = Some((regex, source.clone()));
                        }
                        "minimum" => {
                            let Value::Number(n) = value else {
                                return Err("minimum is not a number".to_string());
                            };
                            s.minimum = Some(Dec::parse(n).ok_or("minimum is out of range")?);
                        }
                        "maximum" => {
                            let Value::Number(n) = value else {
                                return Err("maximum is not a number".to_string());
                            };
                            s.maximum = Some(Dec::parse(n).ok_or("maximum is out of range")?);
                        }
                        "oneOf" => {
                            let Value::Array(items) = value else {
                                return Err("oneOf is not a list".to_string());
                            };
                            for (i, sub) in items.iter().enumerate() {
                                let at = format!("{child}/{i}");
                                let compiled = self.compile(sub, &at)?;
                                s.one_of.push(compiled);
                            }
                        }
                        other => return Err(format!("keyword {other} is not ported")),
                    }
                }
                // Go compiles minContains and maxContains only beside contains.
                if s.contains.is_none() {
                    s.min_contains = None;
                    s.max_contains = None;
                }
            }
            _ => return Err("a schema must be an object or a boolean".to_string()),
        }
        self.set.schemas[id] = s;
        Ok(id)
    }
}
