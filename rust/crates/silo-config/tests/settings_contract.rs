//! The settings contract and resolver: the language-neutral conformance fixture, and differential
//! vectors from the real Go packages.

// Test paths and fixture re-encoding are plain Rust; nothing here is compared to Go through them.
#![allow(clippy::disallowed_methods)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use silo_config::config::BoxFuture;
use silo_config::resolve::*;
use silo_config::settings::*;
use silo_gocompat::json::marshal_to_string;
use std::path::PathBuf;
use std::sync::Arc;

fn root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../..");
    path
}

fn vector(name: &str) -> Value {
    let path = root().join("rust/conformance/vectors/config").join(name);
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_slice(&raw).unwrap()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

struct FakeStore {
    rows: Vec<SettingValue>,
}

impl Store for FakeStore {
    fn list_setting_values_for_resolution<'a>(
        &'a self,
        query: &'a SettingResolutionQuery,
    ) -> BoxFuture<'a, Result<Vec<SettingValue>, ReadError>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for r in &self.rows {
                if query.keys.contains(&r.identity.key) {
                    out.push(r.clone());
                }
            }
            Ok(out)
        })
    }
}

struct FakeSettings(std::collections::HashMap<String, String>);

impl ServerSettings for FakeSettings {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<String, ReadError>> {
        Box::pin(async move { Ok(self.0.get(key).cloned().unwrap_or_default()) })
    }
}

fn rows_of(stored: &Value) -> Vec<SettingValue> {
    stored
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| SettingValue {
                    identity: SettingIdentity {
                        key: s(r, "key").to_owned(),
                        scope: Scope::new(s(r, "scope")),
                        profile_id: s(r, "profile_id").to_owned(),
                        client_family: ClientFamily::new(s(r, "client_family")),
                        device_id: s(r, "device_id").to_owned(),
                        library_id: r.get("library_id").and_then(Value::as_i64).unwrap_or(0),
                        series_id: s(r, "series_id").to_owned(),
                    },
                    value: match r.get("value_text").and_then(Value::as_str) {
                        Some(text) => text.as_bytes().to_vec(),
                        None => raw_json(&r["value"]),
                    },
                    updated_at: s(r, "updated_at").to_owned(),
                    ..Default::default()
                })
                .collect()
        })
        .unwrap_or_default()
}

// The fixture's JSON values, re-encoded. Comparison is structural, as in the Go runner.
fn raw_json(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn context_of(v: Option<&Value>) -> Context {
    let Some(v) = v.filter(|c| !c.is_null()) else {
        return Context::default();
    };
    Context {
        profile_id: s(v, "profile_id").to_owned(),
        client_family: ClientFamily::new(s(v, "client_family")),
        device_id: s(v, "device_id").to_owned(),
        library_ids: v
            .get("library_ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default(),
        series_ids: v
            .get("series_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn keys_of(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

fn constraints_of(v: Option<&Value>) -> Constraints {
    v.and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, x)| (k.clone(), raw_json(x))).collect())
        .unwrap_or_default()
}

fn json_eq(a: &[u8], b: &Value) -> bool {
    serde_json::from_slice::<Value>(a).is_ok_and(|x| &x == b)
}

/// The exit gate: every case in `contracts/settings/v1/conformance.json`, strictly decoded, resolved
/// through the real resolver against the embedded manifest.
#[tokio::test]
async fn conformance_fixture_passes_in_full() {
    let raw = std::fs::read(root().join("contracts/settings/v1/conformance.json")).unwrap();
    let fixture: Value = serde_json::from_slice(&raw).unwrap();
    let manifest = must_load();
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(
        fixture["manifest_revision"], manifest.revision,
        "re-derive the fixture expectations"
    );

    const TOP: [&str; 4] = [
        "fixture_version",
        "manifest_revision",
        "description",
        "cases",
    ];
    for k in fixture.as_object().unwrap().keys() {
        assert!(TOP.contains(&k.as_str()), "unknown fixture field {k}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    let resolver = Resolver::new(manifest);
    let mut seen = std::collections::HashSet::new();
    let mut failures = Vec::new();
    for tc in cases {
        let name = s(tc, "name");
        assert!(!name.is_empty(), "case with no name");
        assert!(seen.insert(name.to_owned()), "duplicate case {name}");
        const FIELDS: [&str; 8] = [
            "name",
            "description",
            "keys",
            "context",
            "stored",
            "constraints",
            "constraint_bindings",
            "expected",
        ];
        for k in tc.as_object().unwrap().keys() {
            assert!(FIELDS.contains(&k.as_str()), "{name}: unknown field {k}");
        }
        let keys = keys_of(&tc["keys"]);
        let expected = tc["expected"].as_array().unwrap();
        assert!(
            !keys.is_empty() && !expected.is_empty(),
            "{name}: empty case"
        );
        let rc = context_of(tc.get("context"));
        let store = FakeStore {
            rows: rows_of(&tc["stored"]),
        };
        let constraints = constraints_of(tc.get("constraints"));
        let bindings = tc.get("constraint_bindings").and_then(Value::as_array);
        let effs = if let Some(bindings) = bindings.filter(|b| !b.is_empty()) {
            let unconstrained = resolver
                .resolve(&store, &rc, &keys, &Constraints::new())
                .await
                .unwrap();
            unconstrained
                .into_iter()
                .map(|eff| {
                    let mut def = manifest.lookup(&eff.key).unwrap().clone();
                    if let Some(b) = bindings.iter().find(|b| s(b, "key") == eff.key) {
                        def.constrained_by = Some(Constraint {
                            policy_input: s(b, "policy_input").to_owned(),
                            constraint: ConstraintKind::new(s(b, "constraint")),
                        });
                    }
                    apply_constraint(&def, eff, &constraints)
                })
                .collect::<Vec<_>>()
        } else {
            resolver
                .resolve(&store, &rc, &keys, &constraints)
                .await
                .unwrap()
        };
        if effs.len() != expected.len() {
            failures.push(format!(
                "{name}: resolved {} settings, want {}",
                effs.len(),
                expected.len()
            ));
            continue;
        }
        for exp in expected {
            let key = s(exp, "key");
            let Some(eff) = effs.iter().find(|e| e.key == key) else {
                failures.push(format!("{name}/{key}: no resolved value"));
                continue;
            };
            if !json_eq(eff.value.as_bytes().unwrap(), &exp["value"]) {
                failures.push(format!(
                    "{name}/{key}: value {} want {}",
                    String::from_utf8_lossy(eff.value.as_bytes().unwrap()),
                    exp["value"]
                ));
            }
            if eff.source.as_str() != s(exp, "source") {
                failures.push(format!(
                    "{name}/{key}: source {} want {}",
                    eff.source,
                    s(exp, "source")
                ));
            }
            let want_constrained = exp
                .get("constrained")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if eff.constrained != want_constrained {
                failures.push(format!(
                    "{name}/{key}: constrained {} want {want_constrained}",
                    eff.constrained
                ));
            }
            if eff.constraint_kind.as_str() != s(exp, "constraint_kind") {
                failures.push(format!(
                    "{name}/{key}: kind {} want {}",
                    eff.constraint_kind,
                    s(exp, "constraint_kind")
                ));
            }
            if want_constrained {
                match exp.get("stored_value") {
                    None => failures.push(format!("{name}/{key}: fixture lacks stored_value")),
                    Some(v) if !json_eq(eff.stored_value.as_bytes().unwrap_or_default(), v) => {
                        failures.push(format!("{name}/{key}: stored_value differs"));
                    }
                    _ => {}
                }
            } else if !eff.stored_value.is_empty() {
                failures.push(format!("{name}/{key}: stored_value without a constraint"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(
        cases.len(),
        51,
        "the fixture has grown; check this gate still means what it says"
    );
}

#[tokio::test]
async fn resolver_output_is_byte_identical_to_go() {
    let rows = vector("resolver.json");
    let manifest = must_load();
    let mut failures = Vec::new();
    for c in rows.as_array().unwrap() {
        let mut resolver = Resolver::new(manifest);
        if let Some(defaults) = c.get("admin_defaults").and_then(Value::as_object) {
            let map = defaults
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
                .collect();
            resolver = resolver.with_admin_defaults(Arc::new(FakeSettings(map)));
        }
        let store = FakeStore {
            rows: rows_of(&c["stored"]),
        };
        let keys = keys_of(&c["keys"]);
        let constraints = constraints_of(c.get("constraints"));
        let want = s(c, "result");
        let got = if let Some(contexts) = c.get("contexts").and_then(Value::as_array) {
            let contexts: Vec<Context> = contexts.iter().map(|x| context_of(Some(x))).collect();
            let out = resolver
                .resolve_contexts(&store, &contexts, &keys, &constraints)
                .await
                .unwrap();
            marshal_to_string(&out.iter().map(Nilable).collect::<Vec<_>>()).unwrap()
        } else if let Some(profiles) = c.get("profiles").filter(|p| !p.is_null()) {
            let out = resolver
                .resolve_profiles(&store, &keys_of(profiles), &keys, &constraints)
                .await
                .unwrap();
            let sorted: std::collections::BTreeMap<_, _> = out.into_iter().collect();
            marshal_to_string(&sorted).unwrap()
        } else {
            let out = resolver
                .resolve(&store, &context_of(c.get("context")), &keys, &constraints)
                .await
                .unwrap();
            for (eff, id) in out.iter().zip(c["identities"].as_array().unwrap()) {
                if eff.identity.is_some() == id.as_str().unwrap().is_empty() {
                    failures.push(format!(
                        "{}: identity presence differs for {}",
                        s(c, "name"),
                        eff.key
                    ));
                }
            }
            marshal_to_string(&Nilable(&out)).unwrap()
        };
        if got != want {
            failures.push(format!("{}\n  got: {got}\n want: {want}", s(c, "name")));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// Resolve answers a nil slice when no key is known, which encodes as null. An empty Vec is that answer.
struct Nilable<'a>(&'a Vec<Effective>);

impl serde::Serialize for Nilable<'_> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        if self.0.is_empty() {
            ser.serialize_none()
        } else {
            self.0.serialize(ser)
        }
    }
}

#[test]
fn entity_tags_and_canonical_bytes_match_go() {
    let doc = vector("settings_contract.json");
    assert_eq!(doc["revision"], must_load().revision);
    assert_eq!(doc["api_version"], must_load().api_version);
    assert_eq!(etag().unwrap(), s(&doc, "etag"));
    assert_eq!(public_etag().unwrap(), s(&doc, "public_etag"));
    let sum = |b: &[u8]| {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    };
    assert_eq!(sum(&canonical_bytes().unwrap()), s(&doc, "canonical_sha"));
    assert_eq!(sum(&public_bytes().unwrap()), s(&doc, "public_sha"));
}

#[test]
fn definitions_and_generated_keys_match_go() {
    let doc = vector("settings_contract.json");
    let m = must_load();
    let defs = doc["definitions"].as_array().unwrap();
    assert_eq!(defs.len(), m.definitions.len());
    for (d, want) in m.definitions.iter().zip(defs) {
        assert_eq!(d.key, s(want, "key"));
        assert_eq!(
            d.is_remote(),
            want["remote"].as_bool().unwrap(),
            "{}",
            d.key
        );
        assert_eq!(
            d.admin_default,
            want["admin_default"].as_bool().unwrap(),
            "{}",
            d.key
        );
        assert_eq!(
            String::from_utf8_lossy(&d.default_value),
            s(want, "default_value"),
            "{}",
            d.key
        );
        let scopes: Vec<String> = d
            .scopes_at_revision(1)
            .iter()
            .map(|x| x.to_string())
            .collect();
        assert_eq!(scopes, keys_of(&want["scopes_r1"]), "{}", d.key);
    }
    assert_eq!(keys::REVISION, m.revision);
    assert_eq!(
        keys::REMOTE
            .iter()
            .map(|x| (*x).to_owned())
            .collect::<Vec<_>>(),
        keys_of(&doc["remote"])
    );
    assert_eq!(
        keys::CLIENT_LOCAL
            .iter()
            .map(|x| (*x).to_owned())
            .collect::<Vec<_>>(),
        keys_of(&doc["client_local"])
    );
    assert_eq!(
        keys::DEPRECATED
            .iter()
            .map(|x| (*x).to_owned())
            .collect::<Vec<_>>(),
        keys_of(&doc["deprecated"])
    );
    for key in keys::REMOTE.iter().chain(keys::CLIENT_LOCAL) {
        assert!(m.lookup(key).is_some(), "{key} is not in the manifest");
    }
}

#[test]
fn revision_filtering_matches_go() {
    let doc = vector("settings_contract.json");
    let m = must_load();
    let mut failures = Vec::new();
    for row in doc["revisions"].as_array().unwrap() {
        let def = m.lookup(s(row, "key")).unwrap();
        let rev = row["revision"].as_i64().unwrap();
        let scopes: Vec<String> = def
            .scopes_at_revision(rev)
            .iter()
            .map(|x| x.to_string())
            .collect();
        let mut enums = Vec::new();
        for member in def.enum_values_at_revision(rev) {
            enums.push(
                serde_json::from_slice::<Value>(member.value_json().as_slice())
                    .unwrap()
                    .to_string(),
            );
        }
        let want_enums: Vec<String> = keys_of(&row["enum"]);
        let min = def
            .value_schema
            .minimum
            .as_ref()
            .and_then(|b| b.at_revision(rev));
        let max = def
            .value_schema
            .maximum
            .as_ref()
            .and_then(|b| b.at_revision(rev));
        if def.visible_at_revision(rev) != row["visible"].as_bool().unwrap()
            || scopes != keys_of(&row["scopes"])
            || enums != want_enums
            || min != row["minimum"].as_f64()
            || max != row["maximum"].as_f64()
        {
            failures.push(format!("{row}: got {scopes:?} {enums:?} {min:?} {max:?}"));
        }
    }
    for (name, want) in doc["options"].as_object().unwrap() {
        let (set, rev) = name.rsplit_once('@').unwrap();
        let got = m.option_sets[set].options_at_revision(rev.parse().unwrap());
        let got: Vec<(String, i64)> = got
            .into_iter()
            .map(|o| (o.value, o.introduced_in))
            .collect();
        let want: Vec<(String, i64)> = want
            .as_array()
            .unwrap()
            .iter()
            .map(|o| {
                (
                    s(o, "value").to_owned(),
                    o["introduced_in"].as_i64().unwrap(),
                )
            })
            .collect();
        if got != want {
            failures.push(format!("options {name}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_schema_file_is_embedded() {
    let dir = root().join("contracts/settings/v1/schemas");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    let embedded: Vec<String> = SCHEMA_FILES.iter().map(|f| f.0.to_owned()).collect();
    assert_eq!(names, embedded);
}

fn normalize_cwd(msg: &str) -> String {
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let msg = msg.replace(&cwd, "<CWD>");
    let mut lines: Vec<&str> = msg.split('\n').collect();
    let head = lines.len().min(1);
    lines[head..].sort_unstable();
    lines.join("\n")
}

#[test]
fn values_validate_and_normalize_like_go() {
    let doc = vector("settings_contract.json");
    let m = must_load();
    let schemas = object_schemas().unwrap();
    let mut failures = Vec::new();
    for row in doc["values"].as_array().unwrap() {
        let def = m.lookup(s(row, "key")).unwrap();
        let value = s(row, "value");
        let hex = s(row, "value_hex");
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let got = def.value_schema.normalize_value(&bytes, schemas);
        let (got_ok, got_err) = match got {
            Ok(v) => (String::from_utf8_lossy(&v).into_owned(), String::new()),
            Err(e) => (String::new(), normalize_cwd(&e)),
        };
        if got_ok != s(row, "normalized") || got_err != s(row, "error") {
            failures.push(format!(
                "{} = {value:?}\n   got: {got_ok:?} / {got_err:?}\n  want: {:?} / {:?}",
                s(row, "key"),
                s(row, "normalized"),
                s(row, "error")
            ));
        }
    }
    let shown: Vec<&String> = failures.iter().take(40).collect();
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        shown
            .iter()
            .map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn comparisons_mirrors_and_steps_match_go() {
    let doc = vector("settings_contract.json");
    let m = must_load();
    let mut failures = Vec::new();
    for row in doc["compares"].as_array().unwrap() {
        let def = m.lookup(s(row, "key")).unwrap();
        let got = def
            .value_schema
            .compare_values(s(row, "a").as_bytes(), s(row, "b").as_bytes());
        if i64::from(got) != row["out"].as_i64().unwrap() {
            failures.push(format!("compare {row}: got {got}"));
        }
    }
    for row in doc["mirrors"].as_array().unwrap() {
        let key = s(row, "key");
        if mirror::mirror_key(key).unwrap_or("") != s(row, "mirror") {
            failures.push(format!("mirror key {key}"));
        }
        if mirror::logical_key(key) != s(row, "logical") {
            failures.push(format!("logical key {key}"));
        }
        match mirror::mirror_write(key, s(row, "value").as_bytes()) {
            Ok(None) => {
                if row["has"].as_bool().unwrap() || !s(row, "error").is_empty() {
                    failures.push(format!("mirror write {row}: got none"));
                }
            }
            Ok(Some(w)) => {
                let text = format!("{}={}", w.key, String::from_utf8_lossy(&w.value));
                if text != s(row, "write") {
                    failures.push(format!("mirror write {row}: got {text}"));
                }
            }
            Err(e) => {
                if e != s(row, "error") {
                    failures.push(format!("mirror write {row}: got {e}"));
                }
            }
        }
    }
    for row in doc["steps"].as_array().unwrap() {
        let got = step_aligned(
            row["value"].as_f64().unwrap(),
            row["base"].as_f64().unwrap(),
            row["step"].as_f64().unwrap(),
        );
        if got != row["out"].as_bool().unwrap() {
            failures.push(format!("step {row}: got {got}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn malformed_manifests_fail_like_go() {
    let doc = vector("settings_contract.json");
    let schemas = object_schemas().unwrap();
    let mut failures = Vec::new();
    for row in doc["manifests"].as_array().unwrap() {
        let source = s(row, "doc");
        let want = s(row, "error");
        let doc = silo_config::gojson::parse(source.as_bytes()).unwrap();
        let schema_source = silo_config::gojson::parse(MANIFEST_SCHEMA_JSON).unwrap();
        let cwd = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let schema = jsonschema::CompiledSchema::compile(
            &schema_source,
            &format!("file://{cwd}/manifest.schema.json"),
        )
        .unwrap();
        let schema_error = schema
            .validate(&doc.value)
            .err()
            .map(|e| normalize_cwd(&e.to_string()))
            .unwrap_or_default();
        if schema_error != s(row, "schema_error") {
            failures.push(format!(
                "{source}\n   got: {schema_error:?}\n  want: {:?}",
                s(row, "schema_error")
            ));
        }
        let got = match load::decode_manifest(source.as_bytes()) {
            Err(e) => format!("decode: {e}"),
            Ok(mut m) => match m.validate(schemas) {
                Ok(()) => String::new(),
                Err(e) => normalize_cwd(&e),
            },
        };
        if want.starts_with("decode: ") {
            if !got.starts_with("decode: ") {
                failures.push(format!(
                    "{source}\n   got: {got:?}\n  want a decode failure"
                ));
            }
        } else if got != want {
            failures.push(format!("{source}\n   got: {got:?}\n  want: {want:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

struct Reader(std::sync::Mutex<Vec<&'static str>>);

impl ServerSettings for Reader {
    fn get<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<String, ReadError>> {
        self.0.lock().unwrap().push("read");
        Box::pin(async { Err::<String, ReadError>("db down".into()) })
    }
}

#[tokio::test]
async fn a_failed_admin_default_read_falls_back_and_only_admin_keys_are_read() {
    let manifest = must_load();
    let reader = Arc::new(Reader(std::sync::Mutex::new(Vec::new())));
    let resolver = Resolver::new(manifest).with_admin_defaults(reader.clone());
    let store = FakeStore { rows: Vec::new() };
    let keys = vec![
        keys::UI_TITLE_ART.to_owned(),
        keys::PLAYBACK_AUTO_PLAY_NEXT.to_owned(),
    ];
    let got = resolver
        .resolve(&store, &Context::default(), &keys, &Constraints::new())
        .await
        .unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].source, Scope::DEFAULT);
    assert_eq!(
        got[0].value.as_bytes().unwrap(),
        manifest
            .lookup(keys::UI_TITLE_ART)
            .unwrap()
            .default_value
            .as_slice()
    );
    assert_eq!(
        reader.0.lock().unwrap().len(),
        1,
        "a key without admin_default must not cost a read"
    );
}

#[tokio::test]
async fn batched_contexts_must_share_a_device_and_family() {
    let resolver = Resolver::new(must_load());
    let store = FakeStore { rows: Vec::new() };
    let keys = vec![keys::UI_TITLE_ART.to_owned()];
    let a = Context {
        device_id: "a".to_owned(),
        ..Default::default()
    };
    let b = Context {
        device_id: "b".to_owned(),
        ..Default::default()
    };
    let err = resolver
        .resolve_contexts(&store, &[a.clone(), b], &keys, &Constraints::new())
        .await
        .unwrap_err();
    assert_eq!(
        err,
        "settingsresolve: batched contexts use different devices"
    );
    let c = Context {
        device_id: "a".to_owned(),
        client_family: ClientFamily::TV,
        ..Default::default()
    };
    let err = resolver
        .resolve_contexts(&store, &[a, c], &keys, &Constraints::new())
        .await
        .unwrap_err();
    assert_eq!(
        err,
        "settingsresolve: batched contexts use different client families"
    );
}
