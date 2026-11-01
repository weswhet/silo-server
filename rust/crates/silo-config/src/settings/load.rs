//! Loading the embedded manifest and its value schemas.

use crate::gojson::{self, Node, Value};
use crate::settings::contract::*;
use crate::settings::jsonschema::CompiledSchema;
use silo_gocompat::strconv::quote;
use std::collections::HashMap;
use std::sync::OnceLock;

/// The manifest as checked in.
pub const MANIFEST_JSON: &[u8] =
    include_bytes!("../../../../../contracts/settings/v1/manifest.json");
/// The manifest's own JSON Schema.
pub const MANIFEST_SCHEMA_JSON: &[u8] =
    include_bytes!("../../../../../contracts/settings/v1/manifest.schema.json");

macro_rules! schema_file {
    ($name:literal) => {
        (
            $name,
            include_bytes!(concat!(
                "../../../../../contracts/settings/v1/schemas/",
                $name
            )) as &[u8],
        )
    };
}

/// Every value schema, sorted by file name as `fs.ReadDir` returns them. A test keeps this in step
/// with the directory.
pub const SCHEMA_FILES: &[(&str, &[u8])] = &[
    schema_file!("card-overlays.json"),
    schema_file!("card-presentation.json"),
    schema_file!("library-id-list.json"),
    schema_file!("library-page-state.json"),
    schema_file!("metadata-language-overrides.json"),
    schema_file!("navigation-shortcuts.json"),
    schema_file!("primary-menu.json"),
    schema_file!("sidebar-pins.json"),
    schema_file!("subtitle-appearance.json"),
    schema_file!("theme-var-overrides.json"),
];

/// Compiled object schemas, keyed by `schema_ref`.
pub type ObjectSchemas = HashMap<String, CompiledSchema>;

struct Loaded {
    manifest: Manifest,
    schemas: ObjectSchemas,
}

static LOADED: OnceLock<Result<Loaded, String>> = OnceLock::new();

// jsonschema's AddResource resolves a relative name against the working directory, and Location is
// what its errors print.
fn resource_url(name: &str) -> String {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("file://{cwd}/{name}")
}

fn load_embedded() -> Result<Loaded, String> {
    let doc = gojson::parse(MANIFEST_JSON).map_err(|e| format!("parsing manifest: {e}"))?;
    let schema_doc =
        gojson::parse(MANIFEST_SCHEMA_JSON).map_err(|e| format!("parsing manifest schema: {e}"))?;
    let schema = CompiledSchema::compile(&schema_doc, &resource_url("manifest.schema.json"))
        .map_err(|e| format!("compiling manifest schema: {e}"))?;
    schema
        .validate(&doc.value)
        .map_err(|e| format!("manifest does not satisfy manifest.schema.json: {e}"))?;

    let mut manifest = decode_manifest(MANIFEST_JSON)?;
    manifest.index()?;

    let mut schemas = ObjectSchemas::new();
    for (name, body) in SCHEMA_FILES {
        let doc = gojson::parse(body).map_err(|e| format!("parsing value schema {name}: {e}"))?;
        let compiled = CompiledSchema::compile(&doc, &resource_url(name))
            .map_err(|e| format!("compiling value schema {name}: {e}"))?;
        schemas.insert((*name).to_owned(), compiled);
    }

    manifest.validate(&schemas)?;
    Ok(Loaded { manifest, schemas })
}

fn loaded() -> Result<&'static Loaded, &'static str> {
    LOADED
        .get_or_init(load_embedded)
        .as_ref()
        .map_err(String::as_str)
}

/// `settingscontract.Load`: the embedded manifest, parsed and validated once per process.
pub fn load() -> Result<&'static Manifest, String> {
    loaded().map(|l| &l.manifest).map_err(str::to_owned)
}

/// `settingscontract.MustLoad`.
pub fn must_load() -> &'static Manifest {
    match load() {
        Ok(m) => m,
        Err(e) => panic!("settingscontract: embedded manifest is invalid: {e}"),
    }
}

/// `settingscontract.ObjectSchemas`.
pub fn object_schemas() -> Option<&'static ObjectSchemas> {
    loaded().ok().map(|l| &l.schemas)
}

/// `settingscontract.ObjectSchema`.
pub fn object_schema(reference: &str) -> Option<&'static CompiledSchema> {
    object_schemas()?.get(reference)
}

fn unknown_field(name: &str) -> String {
    format!("parsing manifest: json: unknown field {}", quote(name))
}

fn want_string(n: &Node) -> Result<String, String> {
    match &n.value {
        Value::String(s) => Ok(s.clone()),
        Value::Null => Ok(String::new()),
        _ => Err(format!(
            "parsing manifest: expected a string, got {}",
            n.kind_name()
        )),
    }
}

fn want_bool(n: &Node) -> Result<bool, String> {
    match n.value {
        Value::Bool(b) => Ok(b),
        Value::Null => Ok(false),
        _ => Err(format!(
            "parsing manifest: expected a boolean, got {}",
            n.kind_name()
        )),
    }
}

fn want_int(n: &Node) -> Result<i64, String> {
    match &n.value {
        Value::Number(s) => s
            .parse()
            .map_err(|_| format!("parsing manifest: json: cannot unmarshal number {s} into int")),
        Value::Null => Ok(0),
        _ => Err(format!(
            "parsing manifest: expected an integer, got {}",
            n.kind_name()
        )),
    }
}

fn want_float(n: &Node) -> Result<f64, String> {
    match &n.value {
        Value::Number(s) => {
            crate::goparse::parse_float(s).map_err(|e| format!("parsing manifest: {e}"))
        }
        _ => Err(format!(
            "parsing manifest: expected a number, got {}",
            n.kind_name()
        )),
    }
}

fn want_array(n: &Node) -> Result<&[Node], String> {
    match &n.value {
        Value::Array(a) => Ok(a),
        Value::Null => Ok(&[]),
        _ => Err(format!(
            "parsing manifest: expected an array, got {}",
            n.kind_name()
        )),
    }
}

fn want_object(n: &Node) -> Result<&[(String, Node)], String> {
    match &n.value {
        Value::Object(o) => Ok(o),
        _ => Err(format!(
            "parsing manifest: expected an object, got {}",
            n.kind_name()
        )),
    }
}

fn decode_scope_entry(n: &Node) -> Result<ScopeEntry, String> {
    match &n.value {
        Value::String(s) => Ok(ScopeEntry {
            scope: Scope::new(s.clone()),
            introduced_in: 0,
        }),
        Value::Object(members) => {
            let mut entry = ScopeEntry::default();
            for (k, v) in members {
                match k.as_str() {
                    "scope" => entry.scope = Scope::new(want_string(v)?),
                    "introduced_in" => entry.introduced_in = want_int(v)?,
                    _ => {}
                }
            }
            Ok(entry)
        }
        _ => Err("parsing manifest: scope entry must be a string or an object".to_owned()),
    }
}

fn decode_bound(n: &Node) -> Result<Bound, String> {
    if let Value::Number(_) = n.value {
        return Ok(Bound {
            history: vec![BoundEntry {
                value: want_float(n)?,
                introduced_in: 0,
            }],
        });
    }
    let mut history = Vec::new();
    for item in want_array(n)? {
        let mut entry = BoundEntry::default();
        for (k, v) in want_object(item)? {
            match k.as_str() {
                "value" => entry.value = want_float(v)?,
                "introduced_in" => entry.introduced_in = want_int(v)?,
                _ => {}
            }
        }
        history.push(entry);
    }
    Ok(Bound { history })
}

fn decode_value_schema(n: &Node) -> Result<ValueSchema, String> {
    let mut s = ValueSchema::default();
    for (k, v) in want_object(n)? {
        match k.as_str() {
            "type" => s.type_ = ValueType::new(want_string(v)?),
            "nullable" => s.nullable = want_bool(v)?,
            "minimum" => s.minimum = Some(decode_bound(v)?),
            "maximum" => s.maximum = Some(decode_bound(v)?),
            "step" => s.step = Some(want_float(v)?),
            "min_length" => s.min_length = Some(want_int(v)?),
            "max_length" => s.max_length = Some(want_int(v)?),
            "pattern" => s.pattern = want_string(v)?,
            "ordered" => s.ordered = want_bool(v)?,
            "schema_ref" => s.schema_ref = want_string(v)?,
            "values" => {
                for item in want_array(v)? {
                    let mut member = EnumMember {
                        value: Value::Null,
                        label: String::new(),
                        introduced_in: 0,
                        deprecated: false,
                    };
                    for (mk, mv) in want_object(item)? {
                        match mk.as_str() {
                            "value" => member.value = mv.value.clone(),
                            "label" => member.label = want_string(mv)?,
                            "introduced_in" => member.introduced_in = want_int(mv)?,
                            "deprecated" => member.deprecated = want_bool(mv)?,
                            other => return Err(unknown_field(other)),
                        }
                    }
                    s.values.push(member);
                }
            }
            other => return Err(unknown_field(other)),
        }
    }
    Ok(s)
}

fn decode_definition(n: &Node, source: &[u8]) -> Result<Definition, String> {
    let mut d = Definition::default();
    for (k, v) in want_object(n)? {
        match k.as_str() {
            "key" => d.key = want_string(v)?,
            "introduced_in" => d.introduced_in = want_int(v)?,
            "persistence" => d.persistence = Persistence::new(want_string(v)?),
            "allowed_scopes" => {
                d.allowed_scopes = want_array(v)?
                    .iter()
                    .map(decode_scope_entry)
                    .collect::<Result<_, _>>()?;
            }
            "resolution_order" => {
                d.resolution_order = want_array(v)?
                    .iter()
                    .map(|s| want_string(s).map(Scope::new))
                    .collect::<Result<_, _>>()?;
            }
            "value_schema" => d.value_schema = decode_value_schema(v)?,
            "default_value" => d.default_value = v.raw(source).to_vec(),
            "constrained_by" => {
                let mut c = Constraint::default();
                for (ck, cv) in want_object(v)? {
                    match ck.as_str() {
                        "policy_input" => c.policy_input = want_string(cv)?,
                        "constraint" => c.constraint = ConstraintKind::new(want_string(cv)?),
                        other => return Err(unknown_field(other)),
                    }
                }
                d.constrained_by = Some(c);
            }
            "platforms" => {
                d.platforms = want_array(v)?
                    .iter()
                    .map(want_string)
                    .collect::<Result<_, _>>()?;
            }
            "category" => d.category = want_string(v)?,
            "label" => d.label = want_string(v)?,
            "description" => d.description = want_string(v)?,
            "unit" => d.unit = want_string(v)?,
            "recommended_control" => d.control = want_string(v)?,
            "suggested_options" => d.suggested_options = want_string(v)?,
            "unset_label" => d.unset_label = want_string(v)?,
            "admin_default" => d.admin_default = want_bool(v)?,
            "deprecated" => d.deprecated = want_bool(v)?,
            "notes" => d.notes = want_string(v)?,
            other => return Err(unknown_field(other)),
        }
    }
    Ok(d)
}

/// Decodes a manifest document, refusing unknown fields as `DisallowUnknownFields` does.
pub fn decode_manifest(source: &[u8]) -> Result<Manifest, String> {
    let doc = gojson::parse(source).map_err(|e| format!("parsing manifest: {e}"))?;
    let mut m = Manifest::default();
    for (k, v) in want_object(&doc)? {
        match k.as_str() {
            "api_version" => m.api_version = want_int(v)?,
            "revision" => m.revision = want_int(v)?,
            "definitions" => {
                m.definitions = want_array(v)?
                    .iter()
                    .map(|d| decode_definition(d, source))
                    .collect::<Result<_, _>>()?;
            }
            "option_sets" => {
                for (name, set) in want_object(v)? {
                    let mut os = OptionSet::default();
                    for (sk, sv) in want_object(set)? {
                        match sk.as_str() {
                            "type" => os.type_ = ValueType::new(want_string(sv)?),
                            "options" => {
                                for item in want_array(sv)? {
                                    let mut o = SuggestedOption::default();
                                    for (ok, ov) in want_object(item)? {
                                        match ok.as_str() {
                                            "value" => o.value = want_string(ov)?,
                                            "introduced_in" => o.introduced_in = want_int(ov)?,
                                            other => return Err(unknown_field(other)),
                                        }
                                    }
                                    os.options.push(o);
                                }
                            }
                            other => return Err(unknown_field(other)),
                        }
                    }
                    m.option_sets.insert(name.clone(), os);
                }
            }
            other => return Err(unknown_field(other)),
        }
    }
    Ok(m)
}
