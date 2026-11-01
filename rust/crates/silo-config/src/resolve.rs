//! `internal/settingsresolve`: turns stored setting values into effective ones.
//!
//! It holds no storage of its own. It takes candidate rows and a contract, and returns decisions.

use crate::config::BoxFuture;
use crate::gojson::{self, Value};
use crate::settings::strictjson::trim_space_bytes;
use crate::settings::*;
use serde::Serialize;
use silo_gocompat::json::RawMessage;
use std::collections::HashMap;
use std::sync::Arc;

/// The error a store or settings reader returns.
pub type ReadError = Box<dyn std::error::Error + Send + Sync>;

/// `userstore.SettingIdentity`: one canonical setting row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingIdentity {
    pub key: String,
    pub scope: Scope,
    pub profile_id: String,
    pub client_family: ClientFamily,
    pub device_id: String,
    pub library_id: i64,
    pub series_id: String,
}

/// `userstore.SettingValue`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingValue {
    pub identity: SettingIdentity,
    /// The stored JSON.
    pub value: Vec<u8>,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// `userstore.SettingResolutionQuery`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingResolutionQuery {
    pub keys: Vec<String>,
    pub profile_ids: Vec<String>,
    pub client_family: ClientFamily,
    pub device_id: String,
    pub library_ids: Vec<i64>,
    pub series_ids: Vec<String>,
}

/// The identity a resolution happens against. An absent field drops the scopes that need it.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub profile_id: String,
    pub client_family: ClientFamily,
    pub device_id: String,
    pub library_ids: Vec<i64>,
    pub series_ids: Vec<String>,
}

/// Policy inputs a definition's `constrained_by` may reference, by `policy_input` name.
pub type Constraints = HashMap<String, Vec<u8>>;

/// One resolved setting. Its JSON shape is the public settings values contract.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Effective {
    pub key: String,
    pub value: RawMessage,
    pub source: Scope,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    pub stored_value: RawMessage,
    #[serde(skip_serializing_if = "is_false")]
    pub constrained: bool,
    #[serde(skip_serializing_if = "is_empty_kind")]
    pub constraint_kind: ConstraintKind,
    #[serde(skip_serializing_if = "RawMessage::is_empty")]
    pub requested_value: RawMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constrained_by: Option<Constraint>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permitted_values: Vec<RawMessage>,
    pub definition_revision: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
    #[serde(skip)]
    pub identity: Option<SettingIdentity>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_empty_kind(k: &ConstraintKind) -> bool {
    k.as_str().is_empty()
}

/// The read surface this module needs. A store of any backend, or a fake in tests.
pub trait Store: Sync {
    fn list_setting_values_for_resolution<'a>(
        &'a self,
        query: &'a SettingResolutionQuery,
    ) -> BoxFuture<'a, Result<Vec<SettingValue>, ReadError>>;
}

/// The read surface for administrator defaults. A key without a value reads as "".
pub trait ServerSettings: Send + Sync {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<String, ReadError>>;
}

/// Resolves against one contract.
#[derive(Clone)]
pub struct Resolver {
    contract: Option<&'static Manifest>,
    server_settings: Option<Arc<dyn ServerSettings>>,
}

impl Resolver {
    /// A resolver over the given contract.
    pub fn new(contract: &'static Manifest) -> Self {
        Resolver {
            contract: Some(contract),
            server_settings: None,
        }
    }

    /// A resolver that lets the administrator's defaults stand in for `default_value` on definitions
    /// declaring `admin_default`.
    pub fn with_admin_defaults(&self, settings: Arc<dyn ServerSettings>) -> Self {
        Resolver {
            contract: self.contract,
            server_settings: Some(settings),
        }
    }

    /// The effective value for each requested key, in one batched store read. Unknown keys are
    /// omitted, so a newer client asking for a setting this server does not have gets a short answer.
    pub async fn resolve<S: Store + ?Sized>(
        &self,
        store: &S,
        rc: &Context,
        keys: &[String],
        constraints: &Constraints,
    ) -> Result<Vec<Effective>, String> {
        let contract = self.contract.ok_or("settingsresolve: no contract")?;
        let (known, defs) = known_keys(contract, keys);
        if known.is_empty() {
            return Ok(Vec::new());
        }
        let query = SettingResolutionQuery {
            keys: known.clone(),
            profile_ids: non_empty(&rc.profile_id),
            client_family: rc.client_family.clone(),
            device_id: rc.device_id.clone(),
            library_ids: rc.library_ids.clone(),
            series_ids: rc.series_ids.clone(),
        };
        let stored = store
            .list_setting_values_for_resolution(&query)
            .await
            .map_err(|e| format!("settingsresolve: reading candidates: {e}"))?;
        let defaults = self.admin_defaults(&known, &defs).await;
        Ok(rank(
            contract,
            &known,
            &defs,
            &stored,
            &defaults,
            rc,
            constraints,
        ))
    }

    /// The same keys for several content contexts in one candidate read. The contexts may vary by
    /// profile, library, or series, but must share a device and client family.
    pub async fn resolve_contexts<S: Store + ?Sized>(
        &self,
        store: &S,
        contexts: &[Context],
        keys: &[String],
        constraints: &Constraints,
    ) -> Result<Vec<Vec<Effective>>, String> {
        let contract = self.contract.ok_or("settingsresolve: no contract")?;
        if contexts.is_empty() {
            return Ok(Vec::new());
        }
        let (known, defs) = known_keys(contract, keys);
        if known.is_empty() {
            return Ok(vec![Vec::new(); contexts.len()]);
        }
        let device_id = contexts[0].device_id.clone();
        let client_family = contexts[0].client_family.clone();
        let mut query = SettingResolutionQuery {
            keys: known.clone(),
            client_family: client_family.clone(),
            device_id: device_id.clone(),
            ..Default::default()
        };
        for rc in contexts {
            if rc.device_id != device_id {
                return Err("settingsresolve: batched contexts use different devices".to_owned());
            }
            if rc.client_family != client_family {
                return Err(
                    "settingsresolve: batched contexts use different client families".to_owned(),
                );
            }
            if !rc.profile_id.is_empty() {
                query.profile_ids.push(rc.profile_id.clone());
            }
            query.library_ids.extend_from_slice(&rc.library_ids);
            query.series_ids.extend_from_slice(&rc.series_ids);
        }
        let stored = store
            .list_setting_values_for_resolution(&query)
            .await
            .map_err(|e| format!("settingsresolve: reading candidates: {e}"))?;
        let defaults = self.admin_defaults(&known, &defs).await;
        Ok(contexts
            .iter()
            .map(|rc| rank(contract, &known, &defs, &stored, &defaults, rc, constraints))
            .collect())
    }

    /// The same keys for several profiles in one store read, keyed by profile id.
    pub async fn resolve_profiles<S: Store + ?Sized>(
        &self,
        store: &S,
        profile_ids: &[String],
        keys: &[String],
        constraints: &Constraints,
    ) -> Result<HashMap<String, Vec<Effective>>, String> {
        let contract = self.contract.ok_or("settingsresolve: no contract")?;
        if profile_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let (known, defs) = known_keys(contract, keys);
        if known.is_empty() {
            return Ok(HashMap::new());
        }
        let query = SettingResolutionQuery {
            keys: known.clone(),
            profile_ids: profile_ids.to_vec(),
            ..Default::default()
        };
        let stored = store
            .list_setting_values_for_resolution(&query)
            .await
            .map_err(|e| format!("settingsresolve: reading candidates: {e}"))?;
        let defaults = self.admin_defaults(&known, &defs).await;
        let mut out = HashMap::with_capacity(profile_ids.len());
        for profile_id in profile_ids {
            if out.contains_key(profile_id) {
                continue;
            }
            let rc = Context {
                profile_id: profile_id.clone(),
                ..Default::default()
            };
            out.insert(
                profile_id.clone(),
                rank(
                    contract,
                    &known,
                    &defs,
                    &stored,
                    &defaults,
                    &rc,
                    constraints,
                ),
            );
        }
        Ok(out)
    }

    async fn admin_defaults(
        &self,
        known: &[String],
        defs: &HashMap<String, &'static Definition>,
    ) -> HashMap<String, Vec<u8>> {
        let mut out = HashMap::new();
        let Some(settings) = &self.server_settings else {
            return out;
        };
        let Some(schemas) = object_schemas() else {
            return out;
        };
        for key in known {
            let def = defs[key];
            if !def.admin_default {
                continue;
            }
            let value = match settings.get(&admin_default_setting_key(key)).await {
                Ok(v) => v,
                Err(error) => {
                    tracing::warn!(
                        component = "settingsresolve",
                        key = %key,
                        error = %error,
                        "using the contract default: reading the administrator default failed"
                    );
                    continue;
                }
            };
            let raw = trim_space_bytes(value.as_bytes());
            if raw.is_empty() {
                continue;
            }
            if let Err(error) = def.value_schema.validate_value(raw, schemas) {
                tracing::warn!(
                    component = "settingsresolve",
                    key = %key,
                    error = %error,
                    "using the contract default: the administrator default is invalid"
                );
                continue;
            }
            out.insert(key.clone(), raw.to_vec());
        }
        out
    }
}

fn known_keys(
    contract: &'static Manifest,
    keys: &[String],
) -> (Vec<String>, HashMap<String, &'static Definition>) {
    let mut known = Vec::with_capacity(keys.len());
    let mut defs = HashMap::with_capacity(keys.len());
    for key in keys {
        let Some(def) = contract.lookup(key) else {
            continue;
        };
        if def.persistence != Persistence::REMOTE || defs.contains_key(key) {
            continue;
        }
        defs.insert(key.clone(), def);
        known.push(key.clone());
    }
    (known, defs)
}

fn non_empty(value: &str) -> Vec<String> {
    if value.is_empty() {
        Vec::new()
    } else {
        vec![value.to_owned()]
    }
}

fn rank(
    contract: &Manifest,
    known: &[String],
    defs: &HashMap<String, &'static Definition>,
    stored: &[SettingValue],
    admin_defaults: &HashMap<String, Vec<u8>>,
    rc: &Context,
    constraints: &Constraints,
) -> Vec<Effective> {
    let mut by_key: HashMap<&str, Vec<&SettingValue>> = HashMap::with_capacity(known.len());
    for row in stored {
        by_key
            .entry(row.identity.key.as_str())
            .or_default()
            .push(row);
    }
    known
        .iter()
        .map(|key| {
            resolve_one(
                contract,
                defs[key],
                by_key.get(key.as_str()).map(Vec::as_slice).unwrap_or(&[]),
                admin_defaults.get(key).map(Vec::as_slice),
                rc,
                constraints,
            )
        })
        .collect()
}

fn resolve_one(
    contract: &Manifest,
    def: &Definition,
    candidates: &[&SettingValue],
    admin_default: Option<&[u8]>,
    rc: &Context,
    constraints: &Constraints,
) -> Effective {
    let inherited = match admin_default {
        Some(a) if !a.is_empty() => a,
        _ => def.default_value.as_slice(),
    };
    let mut eff = Effective {
        key: def.key.clone(),
        value: RawMessage::from(inherited),
        source: Scope::DEFAULT,
        definition_revision: contract.revision,
        ..Default::default()
    };
    for scope in &def.resolution_order {
        if *scope == Scope::DEFAULT {
            break;
        }
        let Some(row) = pick_for_scope(scope, candidates, rc) else {
            continue;
        };
        eff.value = RawMessage::from(row.value.as_slice());
        eff.source = scope.clone();
        eff.updated_at.clone_from(&row.updated_at);
        eff.identity = Some(row.identity.clone());
        break;
    }
    apply_constraint(def, eff, constraints)
}

fn pick_for_scope<'a>(
    scope: &Scope,
    candidates: &[&'a SettingValue],
    rc: &Context,
) -> Option<&'a SettingValue> {
    let mut matches: Vec<&SettingValue> = Vec::with_capacity(2);
    for row in candidates {
        let id = &row.identity;
        if id.scope != *scope {
            continue;
        }
        let keep = match scope.as_str() {
            "account" => true,
            "profile" => id.profile_id == rc.profile_id,
            "profile_client" => {
                id.profile_id == rc.profile_id
                    && id.client_family == rc.client_family
                    && rc.client_family.valid()
            }
            "profile_device" => {
                id.profile_id == rc.profile_id
                    && id.device_id == rc.device_id
                    && !rc.device_id.is_empty()
            }
            "profile_library" => {
                id.profile_id == rc.profile_id && rc.library_ids.contains(&id.library_id)
            }
            "profile_series" => {
                id.profile_id == rc.profile_id && rc.series_ids.contains(&id.series_id)
            }
            _ => false,
        };
        if keep {
            matches.push(row);
        }
    }
    if matches.len() > 1 {
        matches.sort_by(|a, b| {
            a.identity
                .library_id
                .cmp(&b.identity.library_id)
                .then_with(|| a.identity.series_id.cmp(&b.identity.series_id))
        });
    }
    matches.first().copied()
}

/// `applyConstraint`: narrows an effective value to what policy permits. The stored value is reported
/// alongside the cap, never destroyed, so a preference capped today takes effect the day the cap lifts.
pub fn apply_constraint(
    def: &Definition,
    mut eff: Effective,
    constraints: &Constraints,
) -> Effective {
    let Some(bound) = &def.constrained_by else {
        return eff;
    };
    if constraints.is_empty() {
        return eff;
    }
    let Some(limit) = constraints
        .get(&bound.policy_input)
        .filter(|l| !l.is_empty())
    else {
        return eff;
    };
    eff.constrained_by = Some(bound.clone());
    eff.permitted_values = permitted_values(def, bound, limit);

    let current = eff.value.as_bytes().unwrap_or_default().to_vec();
    let Some(narrow) = narrow_value(def, bound, &current, limit) else {
        return eff;
    };
    eff.stored_value = eff.value.clone();
    eff.requested_value = eff.value.clone();
    eff.value = RawMessage::from(narrow);
    eff.constrained = true;
    eff.constraint_kind = bound.constraint.clone();
    eff
}

// json.Unmarshal into []json.RawMessage: None when it would error or decode to no entries.
fn allowed_entries(limit: &[u8]) -> Option<Vec<Vec<u8>>> {
    let node = gojson::parse(limit).ok()?;
    let Value::Array(items) = &node.value else {
        return None;
    };
    if items.is_empty() {
        return None;
    }
    Some(items.iter().map(|n| n.raw(limit).to_vec()).collect())
}

fn permitted_values(def: &Definition, bound: &Constraint, limit: &[u8]) -> Vec<RawMessage> {
    let kind = &bound.constraint;
    if *kind == ConstraintKind::ALLOWLIST {
        return allowed_entries(limit)
            .map(|a| a.into_iter().map(RawMessage::from).collect())
            .unwrap_or_default();
    }
    if *kind == ConstraintKind::LOCKED {
        return vec![RawMessage::from(limit)];
    }
    if *kind == ConstraintKind::CEILING || *kind == ConstraintKind::FLOOR {
        if def.value_schema.type_ != ValueType::ENUM {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(def.value_schema.values.len());
        for member in &def.value_schema.values {
            let Ok(raw) = marshal_member(&member.value) else {
                continue;
            };
            let comparison = def.value_schema.compare_values(&raw, limit);
            if (*kind == ConstraintKind::CEILING && comparison <= 0)
                || (*kind == ConstraintKind::FLOOR && comparison >= 0)
            {
                out.push(RawMessage::from(raw));
            }
        }
        return out;
    }
    Vec::new()
}

pub(crate) fn marshal_member(v: &Value) -> Result<Vec<u8>, String> {
    match v {
        Value::String(s) => silo_gocompat::json::marshal(s).map_err(|e| e.to_string()),
        Value::Bool(b) => Ok(b.to_string().into_bytes()),
        Value::Number(n) => {
            let f = crate::goparse::parse_float(n).map_err(|e| e.to_string())?;
            silo_gocompat::json::marshal(&f).map_err(|e| e.to_string())
        }
        Value::Null => Ok(b"null".to_vec()),
        _ => Err("unsupported enum member".to_owned()),
    }
}

// The permitted value when it differs from the stored one.
fn narrow_value(
    def: &Definition,
    bound: &Constraint,
    value: &[u8],
    limit: &[u8],
) -> Option<Vec<u8>> {
    let kind = &bound.constraint;
    let is_null = trim_space_bytes(value) == b"null";
    let numeric =
        def.value_schema.type_ == ValueType::INTEGER || def.value_schema.type_ == ValueType::NUMBER;
    if *kind == ConstraintKind::LOCKED {
        if trim_space_bytes(value) == trim_space_bytes(limit) {
            return None;
        }
        return Some(limit.to_vec());
    }
    if *kind == ConstraintKind::CEILING {
        if is_null && numeric {
            return Some(limit.to_vec());
        }
        if def.value_schema.compare_values(value, limit) <= 0 {
            return None;
        }
        return Some(limit.to_vec());
    }
    if *kind == ConstraintKind::FLOOR {
        if is_null && numeric {
            return None;
        }
        if def.value_schema.compare_values(value, limit) >= 0 {
            return None;
        }
        return Some(limit.to_vec());
    }
    if *kind == ConstraintKind::ALLOWLIST {
        let allowed = allowed_entries(limit)?;
        let trimmed = trim_space_bytes(value);
        if allowed.iter().any(|e| trim_space_bytes(e) == trimmed) {
            return None;
        }
        return allowed.into_iter().next();
    }
    None
}
