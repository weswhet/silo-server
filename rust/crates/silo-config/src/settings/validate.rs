//! `Manifest.Validate`, `ValueSchema.ValidateValue`, and the comparison the resolver's constraints
//! run through.

use crate::gojson::{self, Node, Value};
use crate::goparse::{fmt_g, parse_float, parse_int};
use crate::lang;
use crate::settings::contract::*;
use crate::settings::load::ObjectSchemas;
use crate::settings::strictjson::*;
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strconv::{format_float, quote};
use std::collections::{HashMap, HashSet};

/// A regular expression compiled when the manifest loads.
#[derive(Debug, Clone)]
pub struct CompiledPattern(pub GoRegex);

fn join_errors(errs: Vec<String>) -> Result<(), String> {
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n"))
    }
}

impl Manifest {
    /// `Manifest.Validate`: every invariant the manifest schema cannot express.
    pub fn validate(&mut self, object_schemas: &ObjectSchemas) -> Result<(), String> {
        let mut errs = Vec::new();
        if self.api_version < 1 {
            errs.push(format!(
                "api_version must be at least 1, got {}",
                self.api_version
            ));
        }
        if self.revision < 1 {
            errs.push(format!(
                "revision must be at least 1, got {}",
                self.revision
            ));
        }
        if self.definitions.is_empty() {
            errs.push("manifest declares no definitions".to_owned());
        }
        for (name, set) in &self.option_sets {
            if let Err(e) = validate_option_set(set, name, self.revision) {
                errs.push(e);
            }
        }
        let revision = self.revision;
        let option_sets = self.option_sets.clone();
        for def in &mut self.definitions {
            if let Err(e) = def.validate(revision, object_schemas) {
                errs.push(format!("{}: {e}", def.key));
            }
            if let Err(e) = def.validate_presentation(&option_sets) {
                errs.push(format!("{}: {e}", def.key));
            }
        }
        join_errors(errs)
    }
}

fn validate_option_set(s: &OptionSet, name: &str, manifest_revision: i64) -> Result<(), String> {
    let mut errs = Vec::new();
    if s.type_ != ValueType::LANGUAGE_TAG {
        errs.push(format!(
            "option set {} has unsupported type {}",
            quote(name),
            quote(s.type_.as_str())
        ));
    }
    if s.options.is_empty() {
        errs.push(format!("option set {} has no options", quote(name)));
    }
    let mut seen = HashSet::new();
    for option in &s.options {
        if option.introduced_in < 1 || option.introduced_in > manifest_revision {
            errs.push(format!(
                "option set {} value {} has introduced_in {} outside 1..{}",
                quote(name),
                quote(&option.value),
                option.introduced_in,
                manifest_revision
            ));
        }
        if s.type_ == ValueType::LANGUAGE_TAG {
            match normalize_language_tag(&option.value) {
                None => errs.push(format!(
                    "option set {} value {} is not a language tag",
                    quote(name),
                    quote(&option.value)
                )),
                Some(normalized) if normalized != option.value => errs.push(format!(
                    "option set {} value {} is not canonical; use {}",
                    quote(name),
                    quote(&option.value),
                    quote(&normalized)
                )),
                _ => {}
            }
        }
        if !seen.insert(option.value.clone()) {
            errs.push(format!(
                "option set {} repeats value {}",
                quote(name),
                quote(&option.value)
            ));
        }
    }
    join_errors(errs)
}

impl Definition {
    fn validate_presentation(
        &self,
        option_sets: &std::collections::BTreeMap<String, OptionSet>,
    ) -> Result<(), String> {
        let mut errs = Vec::new();
        if !self.suggested_options.is_empty() {
            match option_sets.get(&self.suggested_options) {
                None => errs.push(format!(
                    "suggested_options references unknown option set {}",
                    quote(&self.suggested_options)
                )),
                Some(set) if set.type_ != self.value_schema.type_ => errs.push(format!(
                    "suggested_options {} has type {}, want {}",
                    quote(&self.suggested_options),
                    quote(set.type_.as_str()),
                    quote(self.value_schema.type_.as_str())
                )),
                _ => {}
            }
        }
        if !self.unset_label.is_empty() && !self.value_schema.nullable {
            errs.push("unset_label requires a nullable value schema".to_owned());
        }
        join_errors(errs)
    }

    fn validate(
        &mut self,
        manifest_revision: i64,
        object_schemas: &ObjectSchemas,
    ) -> Result<(), String> {
        let mut errs = Vec::new();
        if self.introduced_in < 1 || self.introduced_in > manifest_revision {
            errs.push(format!(
                "introduced_in {} is outside 1..{} (the manifest revision)",
                self.introduced_in, manifest_revision
            ));
        }
        errs.extend(self.validate_scopes(manifest_revision));
        errs.extend(self.validate_resolution_order());
        let introduced = self.introduced_in;
        errs.extend(
            self.value_schema
                .validate(introduced, manifest_revision, object_schemas),
        );
        errs.extend(self.validate_default(object_schemas));
        errs.extend(self.validate_constraint());
        if self.admin_default && !self.is_remote() {
            errs.push("admin_default requires remote persistence".to_owned());
        }
        join_errors(errs)
    }

    fn validate_scopes(&self, manifest_revision: i64) -> Vec<String> {
        if self.allowed_scopes.is_empty() {
            return vec!["allowed_scopes is empty".to_owned()];
        }
        let mut errs = Vec::new();
        let mut seen = HashSet::new();
        for entry in &self.allowed_scopes {
            if !seen.insert(entry.scope.clone()) {
                errs.push(format!(
                    "allowed_scopes repeats {}",
                    quote(entry.scope.as_str())
                ));
            }
            if entry.introduced_in != 0 {
                if entry.introduced_in < self.introduced_in {
                    errs.push(format!(
                        "scope {} claims introduced_in {}, before the definition's own {}",
                        quote(entry.scope.as_str()),
                        entry.introduced_in,
                        self.introduced_in
                    ));
                }
                if entry.introduced_in > manifest_revision {
                    errs.push(format!(
                        "scope {} claims introduced_in {}, after the manifest revision {}",
                        quote(entry.scope.as_str()),
                        entry.introduced_in,
                        manifest_revision
                    ));
                }
            }
        }
        if self.persistence == Persistence::REMOTE {
            for entry in &self.allowed_scopes {
                if !entry.scope.is_remote() {
                    errs.push(format!(
                        "remote setting allows non-remote scope {}",
                        quote(entry.scope.as_str())
                    ));
                }
            }
        } else if self.persistence == Persistence::CLIENT_LOCAL {
            if self.allowed_scopes.len() != 1 || self.allowed_scopes[0].scope != Scope::CLIENT_LOCAL
            {
                errs.push(
                    r#"client_local setting must declare exactly one scope, "client_local""#
                        .to_owned(),
                );
            }
            if self.constrained_by.is_some() {
                errs.push("client_local setting declares constrained_by, but the server never resolves it".to_owned());
            }
        } else {
            errs.push(format!(
                "unknown persistence {}",
                quote(self.persistence.as_str())
            ));
        }
        errs
    }

    fn validate_resolution_order(&self) -> Vec<String> {
        let order = &self.resolution_order;
        let Some(last) = order.last() else {
            return vec!["resolution_order is empty".to_owned()];
        };
        if *last != Scope::DEFAULT {
            return vec![format!(
                "resolution_order must end with {}, got {}",
                quote(Scope::DEFAULT.as_str()),
                quote(last.as_str())
            )];
        }
        let mut errs = Vec::new();
        let mut seen = HashSet::new();
        for scope in &order[..order.len() - 1] {
            if !seen.insert(scope.clone()) {
                errs.push(format!(
                    "resolution_order repeats {}",
                    quote(scope.as_str())
                ));
            }
            if *scope == Scope::DEFAULT {
                errs.push(r#"resolution_order lists "default" before the end"#.to_owned());
                continue;
            }
            if !self.allows_scope(scope) {
                errs.push(format!(
                    "resolution_order resolves {}, which is not in allowed_scopes",
                    quote(scope.as_str())
                ));
            }
        }
        for entry in &self.allowed_scopes {
            if !seen.contains(&entry.scope) {
                errs.push(format!(
                    "scope {} is writable but never read: missing from resolution_order",
                    quote(entry.scope.as_str())
                ));
            }
        }
        errs
    }

    fn validate_default(&self, object_schemas: &ObjectSchemas) -> Vec<String> {
        let raw = trim_space_bytes(&self.default_value);
        if raw.is_empty() {
            return vec!["default_value is required; use null for a nullable setting".to_owned()];
        }
        if raw == b"null" {
            if !self.value_schema.nullable {
                return vec![
                    "default_value is null but the value schema is not nullable".to_owned(),
                ];
            }
            return Vec::new();
        }
        match self.value_schema.validate_value(raw, object_schemas) {
            Ok(()) => Vec::new(),
            Err(e) => vec![format!("default_value is invalid: {e}")],
        }
    }

    fn validate_constraint(&self) -> Vec<String> {
        let Some(c) = &self.constrained_by else {
            return Vec::new();
        };
        let mut errs = Vec::new();
        if c.constraint == ConstraintKind::CEILING || c.constraint == ConstraintKind::FLOOR {
            let t = &self.value_schema.type_;
            let ordered = *t == ValueType::INTEGER
                || *t == ValueType::NUMBER
                || (*t == ValueType::ENUM && self.value_schema.ordered);
            if !ordered {
                errs.push(format!(
                    "{} constraint requires a numeric type or an ordered enum, got {}",
                    c.constraint, t
                ));
            }
        } else if c.constraint != ConstraintKind::ALLOWLIST
            && c.constraint != ConstraintKind::LOCKED
        {
            errs.push(format!(
                "unknown constraint {}",
                quote(c.constraint.as_str())
            ));
        }
        if silo_gocompat::strings::trim_space(&c.policy_input).is_empty() {
            errs.push("constrained_by requires a policy_input".to_owned());
        }
        errs
    }
}

fn validate_bound(
    b: &Bound,
    label: &str,
    widens_up: bool,
    definition_revision: i64,
    manifest_revision: i64,
) -> Vec<String> {
    if b.history.is_empty() {
        return vec![format!("{label} has no value")];
    }
    let mut errs = Vec::new();
    let mut previous_revision = 0;
    for (i, entry) in b.history.iter().enumerate() {
        if i == 0 {
            if entry.introduced_in != 0 && entry.introduced_in != definition_revision {
                errs.push(format!(
                    "{label} history starts at revision {}, but the definition was introduced in {definition_revision}",
                    entry.introduced_in
                ));
            }
            previous_revision = definition_revision;
        } else {
            if entry.introduced_in == 0 {
                errs.push(format!(
                    "{label} history entry {i} must declare introduced_in"
                ));
                continue;
            }
            if entry.introduced_in <= previous_revision {
                errs.push(format!(
                    "{label} history is not ordered: entry {i} claims introduced_in {}, at or before {previous_revision}",
                    entry.introduced_in
                ));
            }
            previous_revision = entry.introduced_in;
        }
        if entry.introduced_in > manifest_revision {
            errs.push(format!(
                "{label} history entry {i} claims introduced_in {}, after the manifest revision {manifest_revision}",
                entry.introduced_in
            ));
        }
        if i > 0 {
            let previous = b.history[i - 1].value;
            if (widens_up && entry.value < previous) || (!widens_up && entry.value > previous) {
                errs.push(format!(
                    "{label} narrows from {} to {} at revision {}; a narrowing needs a new key",
                    fmt_g(previous),
                    fmt_g(entry.value),
                    entry.introduced_in
                ));
            }
        }
    }
    errs
}

fn enum_token(value: &Value) -> String {
    match value {
        Value::String(s) => format!("s:{s}"),
        Value::Bool(b) => format!("b:{b}"),
        Value::Number(n) => match parse_float(n) {
            Ok(f) => format!("n:{}", format_float(f, b'g', -1, 64)),
            Err(_) => format!("n:{n}"),
        },
        other => format!("?:{}", fmt_any(other)),
    }
}

// fmt's %v of a value decoded into `any`.
fn fmt_any(v: &Value) -> String {
    match v {
        Value::Null => "<nil>".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.clone(),
        Value::String(s) => s.clone(),
        Value::Array(a) => {
            let items: Vec<String> = a.iter().map(|n| fmt_any(&n.value)).collect();
            format!("[{}]", items.join(" "))
        }
        Value::Object(o) => {
            let mut members: Vec<(&String, String)> =
                o.iter().map(|(k, n)| (k, fmt_any(&n.value))).collect();
            members.sort_by(|a, b| a.0.cmp(b.0));
            let items: Vec<String> = members
                .into_iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect();
            format!("map[{}]", items.join(" "))
        }
    }
}

// A manifest member's number was decoded without UseNumber in Go, so a float64 %v prints it.
fn display_member(value: &Value) -> String {
    match value {
        Value::String(s) => quote(s),
        Value::Number(n) => match parse_float(n) {
            Ok(f) => fmt_g(f),
            Err(_) => n.clone(),
        },
        other => fmt_any(other),
    }
}

fn display_got(value: &Value) -> String {
    match value {
        Value::String(s) => quote(s),
        other => fmt_any(other),
    }
}

fn enum_matches(value: &Value, member: &Value) -> bool {
    match (value, member) {
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => match (parse_float(a), parse_float(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        },
        _ => false,
    }
}

/// `strictUnmarshal` for an `any` target: the first value, refusing trailing content.
fn strict_any(raw: &[u8]) -> Result<Node, String> {
    let (node, end) = gojson::decode_first(raw)?;
    if !gojson::only_whitespace_after(raw, end) {
        return Err("unexpected trailing content".to_owned());
    }
    Ok(node)
}

fn type_error(node: &Node, target: &str) -> String {
    format!(
        "json: cannot unmarshal {} into Go value of type {target}",
        node.kind_name()
    )
}

/// `strictUnmarshal` for a bool target.
fn strict_bool(raw: &[u8]) -> Result<bool, String> {
    let (node, end) = gojson::decode_first(raw)?;
    let out = match node.value {
        Value::Bool(b) => b,
        Value::Null => false,
        _ => return Err(type_error(&node, "bool")),
    };
    if !gojson::only_whitespace_after(raw, end) {
        return Err("unexpected trailing content".to_owned());
    }
    Ok(out)
}

/// `strictUnmarshal` for a string target.
fn strict_string(raw: &[u8]) -> Result<String, String> {
    let (node, end) = gojson::decode_first(raw)?;
    let out = match node.value {
        Value::String(s) => s,
        Value::Null => String::new(),
        _ => return Err(type_error(&node, "string")),
    };
    if !gojson::only_whitespace_after(raw, end) {
        return Err("unexpected trailing content".to_owned());
    }
    Ok(out)
}

fn is_valid_number(s: &str) -> bool {
    !s.is_empty()
        && matches!(
            gojson::parse(s.as_bytes()),
            Ok(Node {
                value: Value::Number(_),
                ..
            })
        )
}

/// `strictUnmarshal` for a `json.Number` target.
fn strict_number(raw: &[u8]) -> Result<String, String> {
    let (node, end) = gojson::decode_first(raw)?;
    let out = match &node.value {
        Value::Number(n) => n.clone(),
        Value::Null => String::new(),
        Value::String(s) => {
            if !is_valid_number(s) {
                return Err(format!(
                    "json: invalid number literal, trying to unmarshal {} into Number",
                    silo_gocompat::strconv::quote_bytes(node.raw(raw))
                ));
            }
            s.clone()
        }
        _ => return Err(type_error(&node, "json.Number")),
    };
    if !gojson::only_whitespace_after(raw, end) {
        return Err("unexpected trailing content".to_owned());
    }
    Ok(out)
}

/// `NormalizeLanguageTag`.
pub fn normalize_language_tag(tag: &str) -> Option<String> {
    let canonical = lang::canonical_tag(tag);
    if canonical.is_empty() {
        None
    } else {
        Some(canonical)
    }
}

const STEP_TOLERANCE: f64 = 1e-9;

/// `StepAligned`: whether `value` sits on the grid of `step` anchored at `base`.
pub fn step_aligned(value: f64, base: f64, step: f64) -> bool {
    if step <= 0.0 {
        return true;
    }
    let steps = (value - base) / step;
    (steps - go_round(steps)).abs() * step <= STEP_TOLERANCE
}

// math.Round: halves round away from zero, like f64::round.
fn go_round(x: f64) -> f64 {
    x.round()
}

#[derive(PartialEq, Eq, Hash)]
struct NavigationIdentity {
    type_: String,
    destination: String,
    library_id: i64,
    has_library_id: bool,
    section_id: String,
    collection_id: String,
}

fn nav_string(item: &Node, name: &str) -> String {
    match item.get(name).map(|n| &n.value) {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn validate_object_semantics(schema_ref: &str, raw: &[u8]) -> Result<(), String> {
    if schema_ref != "primary-menu.json" && schema_ref != "navigation-shortcuts.json" {
        return Ok(());
    }
    let wrap = |e: String| format!("decoding navigation document: {e}");
    let doc = strict_any(raw).map_err(wrap)?;
    let items: &[Node] = match doc.get("items").map(|n| &n.value) {
        Some(Value::Array(a)) => a,
        _ => &[],
    };
    let mut library_ids: Vec<Option<i64>> = Vec::with_capacity(items.len());
    for item in items {
        library_ids.push(match item.get("library_id").map(|n| &n.value) {
            Some(Value::Number(n)) => Some(parse_int(n, 10, 64).map_err(|_| {
                wrap(format!(
                    "json: cannot unmarshal number {n} into Go struct field navigationItem.items.library_id of type int"
                ))
            })?),
            _ => None,
        });
    }
    let mut seen: HashMap<NavigationIdentity, usize> = HashMap::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let type_ = nav_string(item, "type");
        let mut identity = NavigationIdentity {
            type_: type_.clone(),
            destination: String::new(),
            library_id: 0,
            has_library_id: false,
            section_id: String::new(),
            collection_id: String::new(),
        };
        let lib = library_ids[index];
        match type_.as_str() {
            "builtin" => identity.destination = nav_string(item, "destination"),
            "library" => {
                let Some(id) = lib else {
                    return Err(format!("items[{index}]: library is missing library_id"));
                };
                identity.library_id = id;
                identity.has_library_id = true;
            }
            "section" => {
                let Some(id) = lib else {
                    return Err(format!("items[{index}]: section is missing library_id"));
                };
                identity.library_id = id;
                identity.has_library_id = true;
                identity.section_id = nav_string(item, "section_id");
            }
            "collection" => {
                identity.collection_id = nav_string(item, "collection_id");
                if let Some(id) = lib {
                    identity.library_id = id;
                    identity.has_library_id = true;
                }
            }
            other => {
                return Err(format!(
                    "items[{index}]: unknown navigation item type {}",
                    quote(other)
                ));
            }
        }
        if let Some(first) = seen.get(&identity) {
            return Err(format!(
                "items[{index}] repeats the destination from items[{first}]"
            ));
        }
        seen.insert(identity, index);
    }
    Ok(())
}

impl ValueSchema {
    fn validate(
        &mut self,
        definition_revision: i64,
        manifest_revision: i64,
        object_schemas: &ObjectSchemas,
    ) -> Vec<String> {
        let mut errs = Vec::new();
        let t = self.type_.clone();
        if t == ValueType::BOOLEAN || t == ValueType::LANGUAGE_TAG {
            // No constraints beyond nullability.
        } else if t == ValueType::INTEGER || t == ValueType::NUMBER {
            let (Some(min), Some(max)) = (&self.minimum, &self.maximum) else {
                errs.push(format!("{t} requires minimum and maximum"));
                return errs;
            };
            errs.extend(validate_bound(
                min,
                "minimum",
                false,
                definition_revision,
                manifest_revision,
            ));
            errs.extend(validate_bound(
                max,
                "maximum",
                true,
                definition_revision,
                manifest_revision,
            ));
            if let (Some(a), Some(b)) = (min.current(), max.current())
                && a > b
            {
                errs.push(format!("minimum {} exceeds maximum {}", fmt_g(a), fmt_g(b)));
            }
            if let Some(step) = self.step
                && step <= 0.0
            {
                errs.push(format!("step must be positive, got {}", fmt_g(step)));
            }
        } else if t == ValueType::STRING {
            match self.max_length {
                None => errs.push("string requires max_length".to_owned()),
                Some(m) if m < 1 => errs.push(format!("max_length must be positive, got {m}")),
                _ => {}
            }
            if let (Some(a), Some(b)) = (self.min_length, self.max_length)
                && a > b
            {
                errs.push(format!("min_length {a} exceeds max_length {b}"));
            }
            if !self.pattern.is_empty() {
                match GoRegex::compile(&self.pattern) {
                    Err(e) => errs.push(format!("pattern does not compile: {e}")),
                    Ok(re) => self.compiled_pattern = Some(CompiledPattern(re)),
                }
            }
        } else if t == ValueType::ENUM {
            if self.values.is_empty() {
                errs.push("enum requires at least one member".to_owned());
            }
            let mut seen = HashSet::new();
            for member in &self.values {
                if !seen.insert(enum_token(&member.value)) {
                    errs.push(format!(
                        "enum repeats value {}",
                        display_member(&member.value)
                    ));
                }
                if member.introduced_in != 0 {
                    if member.introduced_in < definition_revision {
                        errs.push(format!(
                            "enum member {} claims introduced_in {}, before the definition's own {definition_revision}",
                            display_member(&member.value),
                            member.introduced_in
                        ));
                    }
                    if member.introduced_in > manifest_revision {
                        errs.push(format!(
                            "enum member {} claims introduced_in {}, after the manifest revision {manifest_revision}",
                            display_member(&member.value),
                            member.introduced_in
                        ));
                    }
                }
            }
        } else if t == ValueType::OBJECT {
            if self.schema_ref.is_empty() {
                errs.push("object requires schema_ref".to_owned());
                return errs;
            }
            if !object_schemas.contains_key(&self.schema_ref) {
                errs.push(format!(
                    "schema_ref {} has no file under contracts/settings/v1/schemas",
                    quote(&self.schema_ref)
                ));
            }
        } else {
            errs.push(format!("unknown value type {}", quote(t.as_str())));
        }
        errs
    }

    /// `ValueSchema.ValidateValue`: the single validation path for a JSON value.
    pub fn validate_value(&self, raw: &[u8], object_schemas: &ObjectSchemas) -> Result<(), String> {
        let trimmed = trim_space_bytes(raw);
        if trimmed == b"null" {
            if self.nullable {
                return Ok(());
            }
            return Err("null is not allowed for this setting".to_owned());
        }
        if std::str::from_utf8(trimmed).is_err() {
            return Err("value is not valid UTF-8".to_owned());
        }
        reject_lone_surrogates(trimmed)?;

        let t = &self.type_;
        if *t == ValueType::BOOLEAN {
            strict_bool(trimmed).map_err(|e| format!("expected a boolean: {e}"))?;
        } else if *t == ValueType::INTEGER {
            let value = strict_number(trimmed).map_err(|e| format!("expected an integer: {e}"))?;
            reject_quoted_number(trimmed).map_err(|e| format!("expected an integer: {e}"))?;
            let parsed = parse_int(&value, 10, 64)
                .map_err(|_| format!("expected an integer, got {value}"))?;
            return self.check_range(parsed as f64);
        } else if *t == ValueType::NUMBER {
            let value = strict_number(trimmed).map_err(|e| format!("expected a number: {e}"))?;
            reject_quoted_number(trimmed).map_err(|e| format!("expected a number: {e}"))?;
            let parsed =
                parse_float(&value).map_err(|_| format!("expected a number, got {value}"))?;
            return self.check_range(parsed);
        } else if *t == ValueType::STRING {
            let value = strict_string(trimmed).map_err(|e| format!("expected a string: {e}"))?;
            return self.check_string(&value);
        } else if *t == ValueType::ENUM {
            let node = strict_any(trimmed).map_err(|e| format!("expected an enum value: {e}"))?;
            if self
                .values
                .iter()
                .any(|m| enum_matches(&node.value, &m.value))
            {
                return Ok(());
            }
            return Err(format!(
                "{} is not one of {}",
                display_got(&node.value),
                self.enum_tokens()
            ));
        } else if *t == ValueType::LANGUAGE_TAG {
            let value =
                strict_string(trimmed).map_err(|e| format!("expected a language tag: {e}"))?;
            if normalize_language_tag(&value).is_none() {
                return Err(format!(
                    "{} is not a well-formed BCP 47 language tag",
                    quote(&value)
                ));
            }
        } else if *t == ValueType::OBJECT {
            let Some(schema) = object_schemas.get(&self.schema_ref) else {
                return Err(format!(
                    "no compiled schema for {}",
                    quote(&self.schema_ref)
                ));
            };
            reject_duplicate_keys(trimmed)?;
            let node =
                strict_for_schema(trimmed).map_err(|e| format!("expected an object: {e}"))?;
            schema
                .validate(&node.value)
                .map_err(|e| format!("does not satisfy {}: {e}", self.schema_ref))?;
            validate_object_semantics(&self.schema_ref, trimmed)
                .map_err(|e| format!("does not satisfy {}: {e}", self.schema_ref))?;
        } else {
            return Err(format!("unknown value type {}", quote(t.as_str())));
        }
        Ok(())
    }

    /// `ValueSchema.NormalizeValue`: validates a value and returns the form to store.
    pub fn normalize_value(
        &self,
        raw: &[u8],
        object_schemas: &ObjectSchemas,
    ) -> Result<Vec<u8>, String> {
        self.validate_value(raw, object_schemas)?;
        let trimmed = trim_space_bytes(raw);
        if self.type_ != ValueType::LANGUAGE_TAG || trimmed == b"null" {
            return Ok(trimmed.to_vec());
        }
        let tag = strict_string(trimmed).map_err(|e| format!("expected a language tag: {e}"))?;
        let Some(normalized) = normalize_language_tag(&tag) else {
            return Err(format!(
                "{} is not a well-formed BCP 47 language tag",
                quote(&tag)
            ));
        };
        silo_gocompat::json::marshal(&normalized)
            .map_err(|e| format!("encoding normalized language tag: {e}"))
    }

    fn check_range(&self, value: f64) -> Result<(), String> {
        let minimum = self.minimum.as_ref().and_then(Bound::current);
        if let Some(min) = minimum
            && value < min
        {
            return Err(format!(
                "{} is below the minimum {}",
                fmt_g(value),
                fmt_g(min)
            ));
        }
        if let Some(max) = self.maximum.as_ref().and_then(Bound::current)
            && value > max
        {
            return Err(format!(
                "{} is above the maximum {}",
                fmt_g(value),
                fmt_g(max)
            ));
        }
        if let Some(step) = self.step {
            let base = minimum.unwrap_or(0.0);
            if !step_aligned(value, base, step) {
                return Err(format!(
                    "{} is not a multiple of the step {} from {}",
                    fmt_g(value),
                    fmt_g(step),
                    fmt_g(base)
                ));
            }
        }
        Ok(())
    }

    fn check_string(&self, value: &str) -> Result<(), String> {
        let length = value.chars().count() as i64;
        if let Some(min) = self.min_length
            && length < min
        {
            return Err(format!("is shorter than the minimum {min} characters"));
        }
        if let Some(max) = self.max_length
            && length > max
        {
            return Err(format!("is longer than the maximum {max} characters"));
        }
        if !self.pattern.is_empty() {
            let compiled;
            let matcher = match &self.compiled_pattern {
                Some(p) => &p.0,
                None => {
                    compiled = GoRegex::compile(&self.pattern)
                        .map_err(|e| format!("pattern does not compile: {e}"))?;
                    &compiled
                }
            };
            if !matcher.match_string(value) {
                return Err(format!("does not match {}", self.pattern));
            }
        }
        Ok(())
    }

    fn enum_tokens(&self) -> String {
        self.values
            .iter()
            .map(|m| display_member(&m.value))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `ValueSchema.CompareValues`: negative when `a` sorts below `b`.
    pub fn compare_values(&self, a: &[u8], b: &[u8]) -> i32 {
        if self.type_ == ValueType::INTEGER || self.type_ == ValueType::NUMBER {
            let (Some(left), Some(right)) = (decode_float(a), decode_float(b)) else {
                return 0;
            };
            return if left < right {
                -1
            } else if left > right {
                1
            } else {
                0
            };
        }
        if self.type_ == ValueType::ENUM {
            if !self.ordered {
                return 0;
            }
            let (Some(left), Some(right)) = (self.enum_index(a), self.enum_index(b)) else {
                return 0;
            };
            return match left.cmp(&right) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => 0,
            };
        }
        0
    }

    fn enum_index(&self, raw: &[u8]) -> Option<usize> {
        let node = strict_any(trim_space_bytes(raw)).ok()?;
        self.values
            .iter()
            .position(|m| enum_matches(&node.value, &m.value))
    }
}

// jsonschema.UnmarshalJSON: one value and then end of input.
fn strict_for_schema(raw: &[u8]) -> Result<Node, String> {
    let (node, end) = gojson::decode_first(raw)?;
    if !gojson::only_whitespace_after(raw, end) {
        return Err("invalid character after top-level value".to_owned());
    }
    Ok(node)
}

fn decode_float(raw: &[u8]) -> Option<f64> {
    let number = strict_number(trim_space_bytes(raw)).ok()?;
    parse_float(&number).ok()
}
