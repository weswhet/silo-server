//! Port of `internal/settingscontract`: the embedded user-settings manifest and value validation.
//!
//! Only what the settings backfill and later read paths need is ported: loading, lookup, and
//! `ValidateValue` with its messages, which are stored in `user_setting_migration_rejects.reason`.
//! `Manifest.Validate` guards the checked-in contract itself, and the contract tests in Go cover it.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use serde::Deserialize;
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strconv::{format_float, quote};

use crate::embedded::contract;
use crate::gojson::{self, Token, TokenDecoder, Value};
use crate::jsonschema::{SchemaSet, go_getwd};
use crate::lang::canonical_tag;
use crate::settingskeys;

/// The storage identity a value is attached to.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Account,
    Profile,
    ProfileClient,
    ProfileDevice,
    ProfileLibrary,
    ProfileSeries,
    ClientLocal,
    Default,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Account => "account",
            Scope::Profile => "profile",
            Scope::ProfileClient => "profile_client",
            Scope::ProfileDevice => "profile_device",
            Scope::ProfileLibrary => "profile_library",
            Scope::ProfileSeries => "profile_series",
            Scope::ClientLocal => "client_local",
            Scope::Default => "default",
        }
    }
}

/// Who stores a setting's value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Persistence {
    Remote,
    ClientLocal,
}

/// A value schema's type tag.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Boolean,
    Integer,
    Number,
    String,
    Enum,
    LanguageTag,
    Object,
}

/// A scope, optionally tagged with the revision that added it.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ScopeEntry {
    Bare(Scope),
    Tagged {
        scope: Scope,
        #[serde(default)]
        introduced_in: i64,
    },
}

impl ScopeEntry {
    pub fn scope(&self) -> Scope {
        match self {
            ScopeEntry::Bare(scope) | ScopeEntry::Tagged { scope, .. } => *scope,
        }
    }
}

/// One value of a bound and the revision that introduced it.
#[derive(Clone, Debug, Deserialize)]
pub struct BoundEntry {
    pub value: f64,
    #[serde(default)]
    pub introduced_in: i64,
}

/// A numeric limit and its history, written as a bare number or a list.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Bound {
    Bare(f64),
    History(Vec<BoundEntry>),
}

impl Bound {
    /// The bound in force on this manifest.
    pub fn current(&self) -> Option<f64> {
        match self {
            Bound::Bare(value) => Some(*value),
            Bound::History(history) => history.last().map(|entry| entry.value),
        }
    }
}

/// One allowed enum value. Go decodes numbers here as `float64`.
#[derive(Clone, Debug, Deserialize)]
pub struct EnumMember {
    pub value: serde_json::Value,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub introduced_in: i64,
    #[serde(default)]
    pub deprecated: bool,
}

/// The tagged type system for setting values.
#[derive(Clone, Debug, Deserialize)]
pub struct ValueSchema {
    #[serde(rename = "type")]
    pub value_type: ValueType,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub minimum: Option<Bound>,
    #[serde(default)]
    pub maximum: Option<Bound>,
    #[serde(default)]
    pub step: Option<f64>,
    #[serde(default)]
    pub min_length: Option<i64>,
    #[serde(default)]
    pub max_length: Option<i64>,
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub values: Vec<EnumMember>,
    #[serde(default)]
    pub ordered: bool,
    #[serde(default)]
    pub schema_ref: String,
    #[serde(skip)]
    compiled_pattern: Option<GoRegex>,
}

/// The contract for one setting.
#[derive(Clone, Debug, Deserialize)]
pub struct Definition {
    pub key: String,
    pub introduced_in: i64,
    pub persistence: Persistence,
    pub allowed_scopes: Vec<ScopeEntry>,
    pub resolution_order: Vec<Scope>,
    pub value_schema: ValueSchema,
    #[serde(default)]
    pub default_value: serde_json::Value,
    #[serde(default)]
    pub admin_default: bool,
    #[serde(default)]
    pub deprecated: bool,
}

impl Definition {
    /// Whether the definition may store a value at `scope`.
    pub fn allows_scope(&self, scope: Scope) -> bool {
        self.allowed_scopes.iter().any(|e| e.scope() == scope)
    }

    /// Whether the server stores this setting's values.
    pub fn is_remote(&self) -> bool {
        self.persistence == Persistence::Remote
    }
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    api_version: i64,
    revision: i64,
    definitions: Vec<Definition>,
}

/// The canonical settings contract.
#[derive(Debug)]
pub struct Manifest {
    pub api_version: i64,
    pub revision: i64,
    pub definitions: Vec<Definition>,
    by_key: HashMap<String, usize>,
}

impl Manifest {
    /// The definition for `key`.
    pub fn lookup(&self, key: &str) -> Option<&Definition> {
        self.by_key.get(key).map(|i| &self.definitions[*i])
    }
}

/// The embedded manifest and its compiled value schemas.
pub struct Contract {
    pub manifest: Manifest,
    pub schemas: SchemaSet,
}

static CONTRACT: LazyLock<Contract> = LazyLock::new(|| {
    load().unwrap_or_else(|err| panic!("settingscontract: embedded manifest is invalid: {err}"))
});

/// `settingscontract.Load`: the embedded contract, parsed once per process.
pub fn load_contract() -> &'static Contract {
    &CONTRACT
}

fn load() -> Result<Contract, String> {
    let raw = contract("settings/v1/manifest.json").ok_or("missing embedded manifest")?;
    let file: ManifestFile =
        serde_json::from_slice(raw).map_err(|e| format!("parsing manifest: {e}"))?;
    let mut by_key = HashMap::with_capacity(file.definitions.len());
    let mut definitions = file.definitions;
    for (i, def) in definitions.iter_mut().enumerate() {
        if by_key.insert(def.key.clone(), i).is_some() {
            return Err(format!("duplicate setting key {}", quote(&def.key)));
        }
        if !def.value_schema.pattern.is_empty() {
            let compiled = GoRegex::compile(&def.value_schema.pattern)
                .map_err(|e| format!("{}: pattern does not compile: {e}", def.key))?;
            def.value_schema.compiled_pattern = Some(compiled);
        }
    }
    let schemas = SchemaSet::compile_embedded(&go_getwd())?;
    Ok(Contract {
        manifest: Manifest {
            api_version: file.api_version,
            revision: file.revision,
            definitions,
            by_key,
        },
        schemas,
    })
}

const MAX_JSON_DEPTH: usize = 64;

fn reject_lone_surrogates(raw: &[u8]) -> Result<(), String> {
    let mut in_string = false;
    let mut i = 0;
    while i < raw.len() {
        if !in_string {
            if raw[i] == b'"' {
                in_string = true;
            }
        } else if raw[i] == b'"' {
            in_string = false;
        } else if raw[i] == b'\\' {
            if i + 1 >= raw.len() {
                return Err("string ends in an incomplete escape".to_string());
            }
            if raw[i + 1] != b'u' {
                i += 2;
                continue;
            }
            let code = parse_hex4(raw, i + 2)?;
            i += 5;
            if !(0xD800..0xE000).contains(&code) {
                i += 1;
                continue;
            }
            if code >= 0xDC00 {
                return Err(format!(
                    "\\u{code:04X} is a trailing surrogate with no leading surrogate before it"
                ));
            }
            if i + 6 >= raw.len() || raw[i + 1] != b'\\' || raw[i + 2] != b'u' {
                return Err(format!(
                    "\\u{code:04X} is a leading surrogate with no trailing surrogate after it"
                ));
            }
            let low = parse_hex4(raw, i + 3)?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(format!(
                    "\\u{code:04X} is followed by \\u{low:04X}, which is not a trailing surrogate"
                ));
            }
            i += 6;
        }
        i += 1;
    }
    Ok(())
}

// parseHex4 uses strconv.ParseUint(s, 16, 32), which takes a sign-free run of hex digits.
fn parse_hex4(raw: &[u8], at: usize) -> Result<u32, String> {
    if at + 4 > raw.len() {
        return Err("incomplete \\u escape".to_string());
    }
    let digits = &raw[at..at + 4];
    let text = String::from_utf8_lossy(digits);
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(format!(
            "malformed \\u escape {}",
            silo_gocompat::strconv::quote_bytes(digits)
        ));
    }
    u32::from_str_radix(&text, 16).map_err(|e| e.to_string())
}

fn reject_duplicate_keys(raw: &[u8]) -> Result<(), String> {
    let mut decoder = TokenDecoder::new(raw);
    let Ok(token) = decoder.token() else {
        return Ok(());
    };
    scan_duplicate_keys(&mut decoder, &token, 0)
}

fn scan_duplicate_keys(
    decoder: &mut TokenDecoder<'_>,
    token: &Token,
    depth: usize,
) -> Result<(), String> {
    let Token::Delim(delim) = token else {
        return Ok(());
    };
    if depth >= MAX_JSON_DEPTH {
        return Err(format!("JSON nests deeper than {MAX_JSON_DEPTH} levels"));
    }
    match delim {
        b'{' => {
            let mut seen: Vec<String> = Vec::new();
            while decoder.more() {
                let Ok(name) = decoder.token() else {
                    return Ok(());
                };
                let Token::String(name) = name else {
                    return Ok(());
                };
                if seen.contains(&name) {
                    return Err(format!("object repeats the property {}", quote(&name)));
                }
                seen.push(name);
                let Ok(value) = decoder.token() else {
                    return Ok(());
                };
                scan_duplicate_keys(decoder, &value, depth + 1)?;
            }
        }
        b'[' => {
            while decoder.more() {
                let Ok(item) = decoder.token() else {
                    return Ok(());
                };
                scan_duplicate_keys(decoder, &item, depth + 1)?;
            }
        }
        _ => {}
    }
    let _ = decoder.token();
    Ok(())
}

// strictUnmarshal decodes first, so a type error in the first value wins over trailing content.
fn no_trailing(raw: &[u8], end: usize) -> Result<(), String> {
    if gojson::only_space_after(raw, end) {
        Ok(())
    } else {
        Err("unexpected trailing content".to_string())
    }
}

fn strict_decode(raw: &[u8]) -> Result<Value, String> {
    let (value, end) = gojson::decode(raw)?;
    no_trailing(raw, end)?;
    Ok(value)
}

fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn cannot_unmarshal(value: &Value, into: &str) -> String {
    format!(
        "json: cannot unmarshal {} into Go value of type {into}",
        kind_name(value)
    )
}

// isValidNumber in encoding/json.
fn is_valid_number(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    match gojson::decode(s.as_bytes()) {
        Ok((Value::Number(_), end)) => end == s.len(),
        _ => false,
    }
}

// A json.Number target: numbers, and strings that spell a number. Null leaves it empty.
fn strict_number(raw: &[u8]) -> Result<String, String> {
    let (value, end) = gojson::decode(raw)?;
    let number = match value {
        Value::Number(n) => n,
        Value::Null => String::new(),
        Value::String(s) => {
            if !is_valid_number(&s) {
                return Err(format!(
                    "json: invalid number literal, trying to unmarshal {} into Number",
                    quote(&quote(&s))
                ));
            }
            s
        }
        other => return Err(cannot_unmarshal(&other, "json.Number")),
    };
    no_trailing(raw, end)?;
    Ok(number)
}

fn strict_string(raw: &[u8]) -> Result<String, String> {
    let (value, end) = gojson::decode(raw)?;
    let text = match value {
        Value::String(s) => s,
        Value::Null => String::new(),
        other => return Err(cannot_unmarshal(&other, "string")),
    };
    no_trailing(raw, end)?;
    Ok(text)
}

fn strict_bool(raw: &[u8]) -> Result<(), String> {
    let (value, end) = gojson::decode(raw)?;
    match value {
        Value::Bool(_) | Value::Null => {}
        other => return Err(cannot_unmarshal(&other, "bool")),
    }
    no_trailing(raw, end)
}

/// `NormalizeLanguageTag`: the strict canonicalizer, with `None` for an invalid tag.
pub fn normalize_language_tag(tag: &str) -> Option<String> {
    let canonical = canonical_tag(tag);
    (!canonical.is_empty()).then_some(canonical)
}

const STEP_TOLERANCE: f64 = 1e-9;

/// `settingscontract.StepAligned`.
pub fn step_aligned(value: f64, base: f64, step: f64) -> bool {
    if step <= 0.0 {
        return true;
    }
    let steps = (value - base) / step;
    (steps - steps.round()).abs() * step <= STEP_TOLERANCE
}

fn g(v: f64) -> String {
    format_float(v, b'g', -1, 64)
}

fn trim_json_space(raw: &[u8]) -> &[u8] {
    // bytes.TrimSpace trims Unicode space. Trim the ASCII set, plus U+0085 and U+00A0 when the input
    // is valid UTF-8, through the same helper the rest of the port uses.
    match std::str::from_utf8(raw) {
        Ok(text) => silo_gocompat::strings::trim_space(text).as_bytes(),
        Err(_) => raw.trim_ascii(),
    }
}

impl ValueSchema {
    /// `ValueSchema.ValidateValue`: the single validation path, with Go's messages.
    pub fn validate_value(&self, raw: &[u8], schemas: &SchemaSet) -> Result<(), String> {
        let trimmed = trim_json_space(raw);
        if trimmed == b"null" {
            if self.nullable {
                return Ok(());
            }
            return Err("null is not allowed for this setting".to_string());
        }
        if std::str::from_utf8(trimmed).is_err() {
            return Err("value is not valid UTF-8".to_string());
        }
        reject_lone_surrogates(trimmed)?;

        match self.value_type {
            ValueType::Boolean => {
                strict_bool(trimmed).map_err(|e| format!("expected a boolean: {e}"))?;
            }
            ValueType::Integer => {
                let value =
                    strict_number(trimmed).map_err(|e| format!("expected an integer: {e}"))?;
                reject_quoted_number(trimmed).map_err(|e| format!("expected an integer: {e}"))?;
                let parsed: i64 = go_parse_int(&value)
                    .ok_or_else(|| format!("expected an integer, got {value}"))?;
                return self.check_range(parsed as f64);
            }
            ValueType::Number => {
                let value =
                    strict_number(trimmed).map_err(|e| format!("expected a number: {e}"))?;
                reject_quoted_number(trimmed).map_err(|e| format!("expected a number: {e}"))?;
                let parsed = crate::settingsmigrate::go_parse_float(&value)
                    .ok_or_else(|| format!("expected a number, got {value}"))?;
                return self.check_range(parsed);
            }
            ValueType::String => {
                let value =
                    strict_string(trimmed).map_err(|e| format!("expected a string: {e}"))?;
                return self.check_string(&value);
            }
            ValueType::Enum => {
                let value =
                    strict_decode(trimmed).map_err(|e| format!("expected an enum value: {e}"))?;
                if self.values.iter().any(|m| enum_matches(&value, &m.value)) {
                    return Ok(());
                }
                return Err(format!(
                    "{} is not one of {}",
                    display_decoded(&value),
                    self.enum_tokens()
                ));
            }
            ValueType::LanguageTag => {
                let value =
                    strict_string(trimmed).map_err(|e| format!("expected a language tag: {e}"))?;
                if normalize_language_tag(&value).is_none() {
                    return Err(format!(
                        "{} is not a well-formed BCP 47 language tag",
                        quote(&value)
                    ));
                }
            }
            ValueType::Object => {
                if !schemas.contains(&self.schema_ref) {
                    return Err(format!(
                        "no compiled schema for {}",
                        quote(&self.schema_ref)
                    ));
                }
                reject_duplicate_keys(trimmed)?;
                let doc = unmarshal_schema_doc(trimmed)
                    .map_err(|e| format!("expected an object: {e}"))?;
                schemas
                    .validate(&self.schema_ref, &doc)
                    .map_err(|e| format!("does not satisfy {}: {e}", self.schema_ref))?;
                validate_object_semantics(&self.schema_ref, &doc)
                    .map_err(|e| format!("does not satisfy {}: {e}", self.schema_ref))?;
            }
        }
        Ok(())
    }

    fn check_range(&self, value: f64) -> Result<(), String> {
        let minimum = self.minimum.as_ref().and_then(Bound::current);
        if let Some(minimum) = minimum
            && value < minimum
        {
            return Err(format!("{} is below the minimum {}", g(value), g(minimum)));
        }
        if let Some(maximum) = self.maximum.as_ref().and_then(Bound::current)
            && value > maximum
        {
            return Err(format!("{} is above the maximum {}", g(value), g(maximum)));
        }
        if let Some(step) = self.step {
            let base = minimum.unwrap_or(0.0);
            if !step_aligned(value, base, step) {
                return Err(format!(
                    "{} is not a multiple of the step {} from {}",
                    g(value),
                    g(step),
                    g(base)
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
        if let Some(pattern) = &self.compiled_pattern
            && !pattern.match_string(value)
        {
            return Err(format!("does not match {}", self.pattern));
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
}

// jsonschema.UnmarshalJSON
fn unmarshal_schema_doc(raw: &[u8]) -> Result<Value, String> {
    let (doc, end) = gojson::decode(raw)?;
    if !gojson::only_space_after(raw, end) {
        return Err("invalid character after top-level value".to_string());
    }
    Ok(doc)
}

fn reject_quoted_number(raw: &[u8]) -> Result<(), String> {
    if raw.first() == Some(&b'"') {
        return Err("a numeric setting must not be sent as a JSON string".to_string());
    }
    Ok(())
}

/// `strconv.ParseInt(s, 10, 64)`.
pub(crate) fn go_parse_int(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn enum_matches(value: &Value, member: &serde_json::Value) -> bool {
    match value {
        Value::String(got) => member.as_str() == Some(got.as_str()),
        Value::Bool(got) => member.as_bool() == Some(*got),
        Value::Number(got) => {
            let (Some(want), Some(have)) =
                (member.as_f64(), crate::settingsmigrate::go_parse_float(got))
            else {
                return false;
            };
            have == want
        }
        _ => false,
    }
}

// displayEnumValue for a decoded value. Lists and maps print as Go's %v does.
fn display_decoded(value: &Value) -> String {
    match value {
        Value::String(s) => quote(s),
        Value::Number(n) => n.clone(),
        other => go_v(other),
    }
}

fn go_v(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.clone(),
        Value::String(s) => s.clone(),
        Value::Array(items) => {
            format!("[{}]", items.iter().map(go_v).collect::<Vec<_>>().join(" "))
        }
        Value::Object(map) => format!(
            "map[{}]",
            map.iter()
                .map(|(k, v)| format!("{k}:{}", go_v(v)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

// displayEnumValue for a member: strings quoted, and numbers as a Go float64 prints with %v.
fn display_member(member: &serde_json::Value) -> String {
    match member {
        serde_json::Value::String(s) => quote(s),
        serde_json::Value::Number(n) => n
            .as_f64()
            .map_or_else(|| n.to_string(), |f| format_float(f, b'g', -1, 64)),
        other => other.to_string(),
    }
}

// validateObjectSemantics: repeated destinations in a navigation document.
fn validate_object_semantics(schema_ref: &str, doc: &Value) -> Result<(), String> {
    if schema_ref != "primary-menu.json" && schema_ref != "navigation-shortcuts.json" {
        return Ok(());
    }
    let items: &[Value] = match doc {
        Value::Object(map) => match map.get("items") {
            Some(Value::Array(items)) => items,
            _ => &[],
        },
        _ => &[],
    };
    let mut decoded = Vec::with_capacity(items.len());
    for item in items {
        decoded.push(
            NavigationItem::decode(item)
                .map_err(|e| format!("decoding navigation document: {e}"))?,
        );
    }
    let mut seen: BTreeMap<NavigationIdentity, usize> = BTreeMap::new();
    for (index, item) in decoded.iter().enumerate() {
        let identity = item
            .identity()
            .map_err(|e| format!("items[{index}]: {e}"))?;
        if let Some(first) = seen.get(&identity) {
            return Err(format!(
                "items[{index}] repeats the destination from items[{first}]"
            ));
        }
        seen.insert(identity, index);
    }
    Ok(())
}

#[derive(Default)]
struct NavigationItem {
    item_type: String,
    destination: String,
    library_id: Option<i64>,
    section_id: String,
    collection_id: String,
}

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct NavigationIdentity {
    item_type: String,
    destination: String,
    library_id: i64,
    has_library_id: bool,
    section_id: String,
    collection_id: String,
}

impl NavigationItem {
    fn decode(value: &Value) -> Result<Self, String> {
        let mut item = NavigationItem::default();
        let Value::Object(map) = value else {
            return Ok(item);
        };
        let text = |key: &str| match map.get(key) {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        item.item_type = text("type");
        item.destination = text("destination");
        item.section_id = text("section_id");
        item.collection_id = text("collection_id");
        if let Some(Value::Number(n)) = map.get("library_id") {
            match go_parse_int(n) {
                Some(id) => item.library_id = Some(id),
                None => {
                    return Err(format!(
                        "json: cannot unmarshal number {n} into Go struct field navigationItem.items.library_id of type int"
                    ));
                }
            }
        }
        Ok(item)
    }

    fn identity(&self) -> Result<NavigationIdentity, String> {
        let mut identity = NavigationIdentity {
            item_type: self.item_type.clone(),
            ..NavigationIdentity::default()
        };
        match self.item_type.as_str() {
            "builtin" => identity.destination = self.destination.clone(),
            "library" => {
                let id = self.library_id.ok_or("library is missing library_id")?;
                identity.library_id = id;
                identity.has_library_id = true;
            }
            "section" => {
                let id = self.library_id.ok_or("section is missing library_id")?;
                identity.library_id = id;
                identity.has_library_id = true;
                identity.section_id = self.section_id.clone();
            }
            "collection" => {
                identity.collection_id = self.collection_id.clone();
                if let Some(id) = self.library_id {
                    identity.library_id = id;
                    identity.has_library_id = true;
                }
            }
            other => {
                return Err(format!("unknown navigation item type {}", quote(other)));
            }
        }
        Ok(identity)
    }
}

// --- mirror.go ---

/// A companion row implied by writing another key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirroredWrite {
    pub key: &'static str,
    pub value: String,
}

/// `settingscontract.MirrorKey`.
pub fn mirror_key(key: &str) -> Option<&'static str> {
    match key {
        settingskeys::PLAYBACK_AUTO_SKIP_INTRO => Some(settingskeys::PLAYBACK_INTRO_SKIP_MODE),
        settingskeys::PLAYBACK_INTRO_SKIP_MODE => Some(settingskeys::PLAYBACK_AUTO_SKIP_INTRO),
        _ => None,
    }
}

/// `settingscontract.MirrorWrite`. `Ok(None)` means `key` has no mirror.
pub fn mirror_write(key: &str, value: &str) -> Result<Option<MirroredWrite>, String> {
    let Some(mirror) = mirror_key(key) else {
        return Ok(None);
    };
    match key {
        settingskeys::PLAYBACK_AUTO_SKIP_INTRO => {
            let Ok(Value::Bool(enabled)) = gojson::unmarshal_any(value.as_bytes()) else {
                return Err(format!(
                    "{key}: mirroring to {mirror} needs a boolean, got {value}"
                ));
            };
            let mode = if enabled { "always" } else { "ask" };
            Ok(Some(MirroredWrite {
                key: mirror,
                value: format!("\"{mode}\""),
            }))
        }
        _ => {
            let Ok(Value::String(mode)) = gojson::unmarshal_any(value.as_bytes()) else {
                return Err(format!(
                    "{key}: mirroring to {mirror} needs a string, got {value}"
                ));
            };
            match mode.as_str() {
                "never" | "ask" | "always" => {}
                _ => return Err(format!("{key}: {} is not an intro skip mode", quote(&mode))),
            }
            Ok(Some(MirroredWrite {
                key: mirror,
                value: if mode == "always" { "true" } else { "false" }.to_string(),
            }))
        }
    }
}
