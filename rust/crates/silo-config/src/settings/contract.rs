//! `internal/settingscontract`: the types of the canonical settings manifest and access to them.

use crate::gojson::Value;
use crate::settings::validate::CompiledPattern;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

macro_rules! string_type {
    ($(#[$m:meta])* $name:ident { $($(#[$cm:meta])* $cname:ident = $val:literal),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub Cow<'static, str>);
        impl $name {
            $($(#[$cm])* pub const $cname: $name = $name(Cow::Borrowed($val));)*
            pub fn new(s: impl Into<String>) -> Self { Self(Cow::Owned(s.into())) }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl Default for $name {
            fn default() -> Self { Self(Cow::Borrowed("")) }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
        }
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&self.0) }
        }
    };
}

string_type!(
    /// The storage identity a value is attached to.
    Scope {
        ACCOUNT = "account",
        PROFILE = "profile",
        PROFILE_CLIENT = "profile_client",
        PROFILE_DEVICE = "profile_device",
        PROFILE_LIBRARY = "profile_library",
        PROFILE_SERIES = "profile_series",
        /// Not addressable by the server values API.
        CLIENT_LOCAL = "client_local",
        /// Terminates every resolution order.
        DEFAULT = "default",
    }
);

impl Scope {
    /// Whether the scope is stored and authorized by the server.
    pub fn is_remote(&self) -> bool {
        matches!(
            self.as_str(),
            "account"
                | "profile"
                | "profile_client"
                | "profile_device"
                | "profile_library"
                | "profile_series"
        )
    }
}

string_type!(
    /// A class of like clients whose preferences roam together.
    ClientFamily {
        TV = "tv",
        MOBILE = "mobile",
        TABLET = "tablet",
        DESKTOP = "desktop",
        WEB = "web",
    }
);

impl ClientFamily {
    /// Whether this is one of the canonical lower-case wire values.
    pub fn valid(&self) -> bool {
        matches!(
            self.as_str(),
            "tv" | "mobile" | "tablet" | "desktop" | "web"
        )
    }
}

string_type!(
    /// Who stores a setting's value.
    Persistence {
        REMOTE = "remote",
        CLIENT_LOCAL = "client_local",
    }
);

string_type!(
    /// The tag of a value schema.
    ValueType {
        BOOLEAN = "boolean",
        INTEGER = "integer",
        NUMBER = "number",
        STRING = "string",
        ENUM = "enum",
        LANGUAGE_TAG = "language_tag",
        OBJECT = "object",
    }
);

string_type!(
    /// How a policy input narrows a setting.
    ConstraintKind {
        CEILING = "ceiling",
        FLOOR = "floor",
        ALLOWLIST = "allowlist",
        LOCKED = "locked",
    }
);

/// The canonical settings contract.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub api_version: i64,
    pub revision: i64,
    pub option_sets: BTreeMap<String, OptionSet>,
    /// Ordered as authored; use [`Manifest::lookup`] for access by key.
    pub definitions: Vec<Definition>,
    pub(crate) by_key: HashMap<String, usize>,
}

/// The canonical contract for one setting.
#[derive(Debug, Clone, Default)]
pub struct Definition {
    pub key: String,
    pub introduced_in: i64,
    pub persistence: Persistence,
    pub allowed_scopes: Vec<ScopeEntry>,
    pub resolution_order: Vec<Scope>,
    pub value_schema: ValueSchema,
    /// The raw `default_value` JSON, as authored.
    pub default_value: Vec<u8>,
    pub constrained_by: Option<Constraint>,
    pub platforms: Vec<String>,
    pub category: String,
    pub label: String,
    pub description: String,
    pub unit: String,
    pub control: String,
    pub suggested_options: String,
    pub unset_label: String,
    pub admin_default: bool,
    pub deprecated: bool,
    pub notes: String,
}

/// An ordered, advisory list of values a client may present for an open setting.
#[derive(Debug, Clone, Default)]
pub struct OptionSet {
    pub type_: ValueType,
    pub options: Vec<SuggestedOption>,
}

/// One presentation value and the earliest revision it is safe to offer against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuggestedOption {
    pub value: String,
    pub introduced_in: i64,
}

impl OptionSet {
    /// The authored suggestions visible to a peer at `revision`, in manifest order.
    pub fn options_at_revision(&self, revision: i64) -> Vec<SuggestedOption> {
        self.options
            .iter()
            .filter(|o| o.introduced_in <= revision)
            .cloned()
            .collect()
    }
}

/// A scope, optionally tagged with the revision that added it to its definition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeEntry {
    pub scope: Scope,
    pub introduced_in: i64,
}

/// The tagged type system for setting values.
#[derive(Debug, Clone, Default)]
pub struct ValueSchema {
    pub type_: ValueType,
    pub nullable: bool,
    pub minimum: Option<Bound>,
    pub maximum: Option<Bound>,
    pub step: Option<f64>,
    pub min_length: Option<i64>,
    pub max_length: Option<i64>,
    pub pattern: String,
    pub values: Vec<EnumMember>,
    pub ordered: bool,
    pub schema_ref: String,
    pub(crate) compiled_pattern: Option<CompiledPattern>,
}

/// A numeric limit together with every earlier value it has had, oldest first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bound {
    pub history: Vec<BoundEntry>,
}

/// One value of a bound and the revision that introduced it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct BoundEntry {
    pub value: f64,
    pub introduced_in: i64,
}

impl Bound {
    /// The bound in force on this manifest.
    pub fn current(&self) -> Option<f64> {
        self.history.last().map(|e| e.value)
    }

    /// The bound a peer at `revision` enforces.
    pub fn at_revision(&self, revision: i64) -> Option<f64> {
        self.history
            .iter()
            .rfind(|e| e.introduced_in <= revision)
            .map(|e| e.value)
    }
}

/// One allowed enum value.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumMember {
    pub value: Value,
    pub label: String,
    pub introduced_in: i64,
    pub deprecated: bool,
}

impl EnumMember {
    /// The member's value as `json.Marshal` writes it.
    pub fn value_json(&self) -> Vec<u8> {
        crate::resolve::marshal_member(&self.value).unwrap_or_default()
    }
}

/// Binds a definition to a policy input that narrows it at resolution time.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Constraint {
    pub policy_input: String,
    pub constraint: ConstraintKind,
}

const ADMIN_DEFAULT_PREFIX: &str = "defaults.";

/// The server-settings key holding the administrator's default for a setting, as JSON text.
pub fn admin_default_setting_key(key: &str) -> String {
    format!("{ADMIN_DEFAULT_PREFIX}{key}")
}

impl Manifest {
    /// The definition for `key`.
    pub fn lookup(&self, key: &str) -> Option<&Definition> {
        self.by_key.get(key).map(|&i| &self.definitions[i])
    }

    /// Every definition key in manifest order.
    pub fn keys(&self) -> Vec<String> {
        self.definitions.iter().map(|d| d.key.clone()).collect()
    }

    pub(crate) fn index(&mut self) -> Result<(), String> {
        self.by_key = HashMap::with_capacity(self.definitions.len());
        for (i, def) in self.definitions.iter().enumerate() {
            if self.by_key.contains_key(&def.key) {
                return Err(format!(
                    "duplicate setting key {}",
                    silo_gocompat::strconv::quote(&def.key)
                ));
            }
            self.by_key.insert(def.key.clone(), i);
        }
        Ok(())
    }

    /// The definition whose administrator default the server-settings key holds.
    pub fn admin_default_for(&self, server_setting_key: &str) -> Option<&Definition> {
        let key = server_setting_key.strip_prefix(ADMIN_DEFAULT_PREFIX)?;
        self.lookup(key).filter(|d| d.admin_default)
    }
}

impl Definition {
    /// Whether the definition may store a value at `scope`.
    pub fn allows_scope(&self, scope: &Scope) -> bool {
        self.allowed_scopes.iter().any(|e| &e.scope == scope)
    }

    /// Whether the server stores this setting's values.
    pub fn is_remote(&self) -> bool {
        self.persistence == Persistence::REMOTE
    }

    /// Whether a client pinned to `revision` may surface this definition.
    pub fn visible_at_revision(&self, revision: i64) -> bool {
        self.introduced_in <= revision
    }

    /// The scopes valid against a peer at `revision`.
    pub fn scopes_at_revision(&self, revision: i64) -> Vec<Scope> {
        self.allowed_scopes
            .iter()
            .filter(|e| e.introduced_in <= revision)
            .map(|e| e.scope.clone())
            .collect()
    }

    /// The enum members valid against a peer at `revision`, or nothing for a non-enum.
    pub fn enum_values_at_revision(&self, revision: i64) -> Vec<EnumMember> {
        if self.value_schema.type_ != ValueType::ENUM {
            return Vec::new();
        }
        self.value_schema
            .values
            .iter()
            .filter(|m| m.introduced_in <= revision)
            .cloned()
            .collect()
    }
}
