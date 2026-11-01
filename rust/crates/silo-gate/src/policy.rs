//! `internal/policy`: the vendored Rego policy bundle (`silo.scope`/`silo.permission`/
//! `silo.action`), evaluated with `regorus` instead of OPA, plus `CompileCheck`, the fail-closed
//! static check a stored administrator-authored policy source must pass before it is ever loaded.
//!
//! # Scope
//!
//! Ported:
//! - The vendor `.rego` modules themselves, copied byte-for-byte into `vendor/` (not a Rust port —
//!   these are policy *data*, the actual authority, not logic to translate; they must stay
//!   byte-identical to `internal/policy/vendor` or the two engines are no longer evaluating the
//!   same policy).
//! - [`Engine`]: loads the vendor bundle plus per-domain custom sources (or the vendor's own
//!   always-`false` stub when a domain has none active) and evaluates the three decisions, mirroring
//!   `engine.go`'s `swap`/`Evaluate`.
//! - [`compile_check`]: `compile.go`'s `CompileCheck` — domain validation, the size limit, the
//!   `silo_custom.<domain>` package-name check, and a locked builtin denylist mirroring
//!   `LockedCapabilities` (every builtin OPA's `ast.Builtin.Nondeterministic` flags, plus
//!   `rego.parse_module(s)`). After those checks, `compile_check` also *tries to compile and
//!   evaluate* the candidate against the full vendor bundle (`regorus::Engine::add_policy` +
//!   `eval_rule`) across a battery of representative inputs, which catches the undefined-reference
//!   and most-arity errors Go's `ast.Compiler` finds statically.
//!
//! Not ported: [`decisionlog`], the Postgres-backed [`store`]/[`document_mutations`] CRUD for admin
//! policy sources, [`viewer_resolver`] (the Go-side caller that builds a [`ScopeInput`] from
//! catalog/userstore/access state — those crates don't exist yet), and [`system`]/[`pdp`] (the
//! service wiring `NewEngineFromStore`/`Reload`/`PDP.CheckAction` etc. around the engine). Those
//! each need crates this session's dependency graph doesn't have (catalog, userstore wiring,
//! Postgres document storage for custom sources).
//!
//! # `CompileCheck`'s capability/arity/type gap (read before trusting this in production)
//!
//! Go's `ast.Compiler` performs whole-program static type inference: an administrator's Rego is
//! rejected at save time if *any* reachable-or-not code path calls an unknown function, passes the
//! wrong arity, or type-mismatches, regardless of which branches a given input would actually take.
//! `regorus` 0.14 has no public capability-restriction or standalone type-checker API (confirmed by
//! reading its public surface before writing this), so [`compile_check`] approximates Go's static
//! check by *running* the candidate across a battery of representative inputs and treating any
//! runtime error (undefined function/arity/type) as a rejection. This is strictly a narrowing in one
//! direction and a gap in the other:
//! - A branch the battery never exercises can hide a defect regorus would otherwise have caught,
//!   which **is** a live "Rust accepts what Go refuses" risk for adversarial sources crafted to hide
//!   bad code behind an untested condition. This is the one honestly unresolved gap in this port;
//!   see the port report's `divergences`.
//! - Conversely, the locked-builtin denylist is a pure substring/token scan over the source text
//!   rather than an AST walk, so it can flag a builtin name that only appears inside a string
//!   literal or comment. That direction is safe (only ever rejects something Go would accept), so it
//!   is left as-is rather than fixed: fail-closed is supposed to over-reject, never under-reject.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// `policy.DomainScope`/`DomainPermission`/`DomainAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Domain {
    Scope,
    Permission,
    Action,
}

impl Domain {
    /// `policy.validPolicyDomain` plus the string it matched; `ValidDomain`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "scope" => Some(Self::Scope),
            "permission" => Some(Self::Permission),
            "action" => Some(Self::Action),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scope => "scope",
            Self::Permission => "permission",
            Self::Action => "action",
        }
    }

    fn decision_query(self) -> &'static str {
        match self {
            Self::Scope => "data.silo.scope.decision",
            Self::Permission => "data.silo.permission.decision",
            Self::Action => "data.silo.action.decision",
        }
    }

    /// `customModulePath`.
    fn custom_module_path(self) -> String {
        format!("custom/{}.rego", self.as_str())
    }

    fn vendor_stub(self) -> (&'static str, &'static str) {
        match self {
            Self::Scope => ("custom_stub.rego", vendor::CUSTOM_SCOPE_STUB),
            Self::Permission => (
                "custom_permission_stub.rego",
                vendor::CUSTOM_PERMISSION_STUB,
            ),
            Self::Action => ("custom_action_stub.rego", vendor::CUSTOM_ACTION_STUB),
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The vendored Rego modules, embedded at build time. Keep byte-identical to
/// `internal/policy/vendor`; a drift here silently changes what access control actually allows.
pub mod vendor {
    pub const SCOPE: &str = include_str!("../vendor/scope.rego");
    pub const PERMISSION: &str = include_str!("../vendor/permission.rego");
    pub const ACTION: &str = include_str!("../vendor/action.rego");
    pub const QUALITY: &str = include_str!("../vendor/lib/quality.rego");
    pub const CUSTOM_SCOPE_STUB: &str = include_str!("../vendor/custom_stub.rego");
    pub const CUSTOM_PERMISSION_STUB: &str = include_str!("../vendor/custom_permission_stub.rego");
    pub const CUSTOM_ACTION_STUB: &str = include_str!("../vendor/custom_action_stub.rego");

    /// The base vendor modules every engine loads, independent of custom sources:
    /// `(path, source)` pairs for `scope.rego`/`permission.rego`/`action.rego`/`lib/quality.rego`.
    pub fn base_modules() -> [(&'static str, &'static str); 4] {
        [
            ("scope.rego", SCOPE),
            ("permission.rego", PERMISSION),
            ("action.rego", ACTION),
            ("lib/quality.rego", QUALITY),
        ]
    }
}

/// An error evaluating a decision: `ErrPolicyEvalFailed`'s class, without `engine.go`'s timeout
/// plumbing (no wall-clock budget is enforced here; see the module doc on what is not ported).
#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    #[error("compiling policy bundle: {0}")]
    Compile(String),
    #[error("evaluating {domain} decision: {source}")]
    Eval {
        domain: Domain,
        #[source]
        source: anyhow::Error,
    },
    #[error("{domain} decision is undefined for this input (missing required input fields?)")]
    Undefined { domain: Domain },
    #[error("decoding decision result: {0}")]
    Decode(String),
}

/// `policy.Engine`: compiled Rego queries for the three decisions, loaded from the vendor bundle
/// plus whatever per-domain custom sources are active. Unlike Go's `Engine`, this type is not
/// internally mutable/swappable — a caller reloads by constructing a new one and replacing the
/// `Arc`/`RwLock` that holds it, same as Go's `e.mu.Lock(); e.queries = queries`.
pub struct Engine {
    inner: regorus::Engine,
}

impl Engine {
    /// `policy.NewEngine`: vendor bundle only, every domain on its always-`false` stub.
    pub fn new() -> Result<Self, EvalError> {
        Self::with_custom(&BTreeMap::new())
    }

    /// `policy.NewEngineWithCustom`. `custom` maps an active domain to its administrator-authored
    /// Rego source; a domain missing from the map uses the vendor stub. Unlike Go, a source that
    /// fails [`compile_check`] here is a hard error rather than a boot-time skip: callers that want
    /// Go's "skip invalid sources, keep booting" behavior must call [`compile_check`] themselves
    /// per source first and only pass the ones that pass.
    pub fn with_custom(custom: &BTreeMap<Domain, String>) -> Result<Self, EvalError> {
        let mut inner = regorus::Engine::new();
        for (path, source) in vendor::base_modules() {
            inner
                .add_policy(path.to_owned(), source.to_owned())
                .map_err(|e| EvalError::Compile(e.to_string()))?;
        }
        for domain in [Domain::Scope, Domain::Permission, Domain::Action] {
            match custom.get(&domain) {
                Some(source) => {
                    inner
                        .add_policy(domain.custom_module_path(), source.clone())
                        .map_err(|e| EvalError::Compile(e.to_string()))?;
                }
                None => {
                    let (path, source) = domain.vendor_stub();
                    inner
                        .add_policy(path.to_owned(), source.to_owned())
                        .map_err(|e| EvalError::Compile(e.to_string()))?;
                }
            }
        }
        Ok(Self { inner })
    }

    /// `Engine.Evaluate`: evaluates one decision against `input` and decodes the result into `T`.
    /// `input` and `T` are the pair the caller is responsible for keeping matched — see
    /// [`ScopeInput`]/[`ScopeDecision`] etc. for the vendor bundle's own shapes.
    pub fn evaluate<T: serde::de::DeserializeOwned>(
        &mut self,
        domain: Domain,
        input: &serde_json::Value,
    ) -> Result<T, EvalError> {
        let value = self.evaluate_json(domain, input)?;
        serde_json::from_value(value).map_err(|e| EvalError::Decode(e.to_string()))
    }

    /// [`Self::evaluate`] without decoding, for callers that just want the raw decision document
    /// (as the differential tests against real-OPA vectors do).
    pub fn evaluate_json(
        &mut self,
        domain: Domain,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, EvalError> {
        self.inner.set_input(regorus::Value::from(input.clone()));
        let result = self
            .inner
            .eval_rule(domain.decision_query().to_owned())
            .map_err(|source| EvalError::Eval { domain, source })?;
        if matches!(result, regorus::Value::Undefined) {
            return Err(EvalError::Undefined { domain });
        }
        let text = result
            .to_json_str()
            .map_err(|e| EvalError::Eval { domain, source: e })?;
        // `text` is regorus's own JSON serialization of an in-process `regorus::Value`, not
        // Go-authored JSON, so `json.Unmarshal`'s key-folding/duplicate-key/surrogate quirks do
        // not apply here; `silo_gocompat::json::unmarshal` is used anyway for consistency with
        // the workspace-wide lint, not because any of those quirks are reachable through this
        // particular round trip.
        silo_gocompat::json::unmarshal::<serde_json::Value>(text.as_bytes())
            .map_err(|e| EvalError::Decode(e.to_string()))
    }
}

// --- `input.go`'s pure data shapes, for a caller that wants typed input/output instead of raw
// --- `serde_json::Value`. Field names and `#[serde(rename)]`s mirror the Go JSON tags exactly.

/// `policy.ScopeInput`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeInput {
    pub schema_version: i32,
    pub user_id: i64,
    pub session_id: String,
    pub profile_id: String,
    pub account_library_ids: Vec<i64>,
    pub account_restricted: bool,
    #[serde(rename = "account_max_playback_quality")]
    pub account_max_quality: String,
    pub access_policy_revision: i64,
    pub disabled_library_ids: Vec<i64>,
    pub profile_present: bool,
    #[serde(rename = "profile_max_content_rating")]
    pub profile_max_rating: String,
    pub profile_max_advisory_age: i32,
    #[serde(rename = "profile_max_playback_quality")]
    pub profile_max_quality: String,
    #[serde(rename = "profile_library_restricted")]
    pub profile_library_limited: bool,
    #[serde(rename = "profile_allowed_library_ids")]
    pub profile_library_ids: Vec<i64>,
    pub profile_has_pin: bool,
    pub profile_verified: bool,
    #[serde(rename = "profile_preferred_metadata_language")]
    pub profile_metadata_lang: String,
    pub request_time: String,
    pub device_id: String,
    pub client_ip: String,
    pub is_api_key: bool,
}

/// `policy.ScopeDecision`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScopeDecision {
    pub schema_version: i32,
    pub unrestricted: bool,
    pub allowed_library_ids: Vec<i64>,
    pub disabled_library_ids: Vec<i64>,
    pub hidden_library_ids: Vec<i64>,
    pub libraries_restricted: bool,
    pub max_content_rating: String,
    pub max_content_rating_override: String,
    pub max_advisory_age: i32,
    pub max_playback_quality: String,
    pub preferred_metadata_language: String,
    pub policy_revision: i64,
    pub profile_verified: bool,
}

/// `policy.PermissionInput`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionInput {
    pub schema_version: i32,
    pub user_id: i64,
    pub role: String,
    pub user_enabled: bool,
    pub assigned_permissions: Vec<String>,
    pub permission: String,
    pub declared_profile_id: String,
    pub acting_as_primary: bool,
    pub household_requires_profile: bool,
    pub target_library_ids: Vec<i64>,
    pub user_library_ids: Vec<i64>,
    pub user_libraries_restricted: bool,
    pub request_time: String,
    pub device_id: String,
    pub client_ip: String,
}

/// `policy.PermissionDecision`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionDecision {
    pub allowed: bool,
    pub reason: String,
    pub reason_code: String,
}

/// `policy.ActionInput`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionInput {
    pub schema_version: i32,
    pub action: String,
    pub user_id: i64,
    pub download_allowed: bool,
    pub download_transcode_allowed: bool,
    pub max_streams: i32,
    pub max_transcodes: i32,
    pub transcode_allowed: bool,
    pub audio_transcode_allowed: bool,
    pub downloads_enabled: bool,
    pub transcode_enabled: bool,
    pub artifacts_available: bool,
    pub current_active_streams: i32,
    pub current_active_transcodes: i32,
    pub requested_action: String,
    pub requested_quality: String,
    pub file_quality: String,
    pub max_playback_quality: String,
    pub content_rating: String,
    pub max_content_rating: String,
    pub content_rating_within_ceiling: bool,
    pub request_time: String,
    pub device_id: String,
    pub client_ip: String,
}

/// `policy.ActionDecision`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActionDecision {
    pub allowed: bool,
    pub reason: String,
    pub reason_code: String,
    pub quality_ceiling: String,
}

// --- CompileCheck ---

/// `policy.CompileIssue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileIssue {
    pub message: String,
    pub row: Option<u32>,
    pub col: Option<u32>,
}

/// `policy.CompileError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("policy compile check failed: {}", issues_text(issues))]
pub struct CompileError {
    pub issues: Vec<CompileIssue>,
}

fn issues_text(issues: &[CompileIssue]) -> String {
    issues
        .iter()
        .map(|i| i.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

fn single_issue(message: impl Into<String>) -> CompileError {
    CompileError {
        issues: vec![CompileIssue {
            message: message.into(),
            row: None,
            col: None,
        }],
    }
}

/// `compile.maxPolicySourceBytes`.
pub const MAX_POLICY_SOURCE_BYTES: usize = 256 * 1024;

/// Every builtin name Go's `LockedCapabilities` excludes by being in OPA's `Nondeterministic` set,
/// plus the two always-excluded parse builtins. This is `lockedBuiltin`'s *effect* as a literal
/// name table, not a port of its mechanism: OPA carries a per-builtin `Nondeterministic` flag in
/// its capabilities JSON that regorus has no equivalent registry for (see the module doc's gap
/// section), so the table is hand-maintained against the OPA v1.18.2 builtin list (every builtin
/// under the `time`, `rand`, `uuid`, `opa`, `http`, `net` (lookup only), `graphql` (parses+network),
/// and `trace`/`print`-adjacent nondeterministic families) and must be re-checked against OPA's
/// capabilities.json on every OPA upgrade — the same obligation Go's own comment places on itself
/// ("a future OPA upgrade cannot silently expose a new impure builtin" does NOT hold here the way
/// it holds for Go's reflective exclusion; this table needs a human to update it).
const LOCKED_BUILTIN_PREFIXES: &[&str] = &[
    "http.send",
    "net.lookup_ip_addr",
    "net.cidr_expand", // amplification, excluded defensively alongside lookups
    "opa.runtime",
    "time.now_ns",
    "time.clock",
    "time.date",
    "time.diff",
    "time.weekday",
    "time.add_date",
    "time.parse_ns",
    "time.parse_rfc3339_ns",
    "time.parse_duration_ns",
    "rand.intn",
    "uuid.rfc4122",
    "rego.parse_module",
    "rego.parse_modules",
    "trace.now_ns",
    "print(",
];

fn source_uses_locked_builtin(source: &str) -> Option<&'static str> {
    LOCKED_BUILTIN_PREFIXES
        .iter()
        .find(|needle| source.contains(*needle))
        .copied()
}

/// `policy.CompileCheck`. `representative_inputs` is this port's substitute for Go's static whole-
/// program type check (see the module doc): every one of them is run through the candidate's
/// `override` rule, and a runtime error from any of them fails the check. Pass at least one input
/// per shape the domain's vendor policy can produce (the empty object counts as one).
pub fn compile_check(
    domain: &str,
    source: &str,
    representative_inputs: &[serde_json::Value],
) -> Result<(), CompileError> {
    let Some(domain) = Domain::parse(domain) else {
        return Err(single_issue(format!(
            "unsupported policy domain {domain:?}"
        )));
    };
    if source.len() > MAX_POLICY_SOURCE_BYTES {
        return Err(single_issue(format!(
            "policy source exceeds {MAX_POLICY_SOURCE_BYTES} byte limit"
        )));
    }
    if source.trim().is_empty() {
        return Err(single_issue("policy source is empty"));
    }
    if let Some(builtin) = source_uses_locked_builtin(source) {
        return Err(single_issue(format!(
            "policy source uses a disallowed builtin: {builtin}"
        )));
    }

    // Package-name check, cheaply: parsing into a throwaway engine both validates syntax and
    // yields the canonical `data.`-prefixed package path via `add_policy`'s return value.
    let candidate_path = domain.custom_module_path();
    let mut probe = regorus::Engine::new();
    let package = probe
        .add_policy(candidate_path.clone(), source.to_owned())
        .map_err(|e| single_issue(format!("parse error: {e}")))?;
    let expected = format!("data.silo_custom.{domain}");
    if package != expected {
        return Err(single_issue(format!(
            "policy package must be silo_custom.{domain}, got {}",
            package.strip_prefix("data.").unwrap_or(&package)
        )));
    }

    // Compile against the full vendor bundle and force evaluation of `override` across the
    // representative battery, so an undefined reference or an arity/type error on any exercised
    // path fails closed instead of loading.
    let mut engine = regorus::Engine::new();
    for (path, src) in vendor::base_modules() {
        engine
            .add_policy(path.to_owned(), src.to_owned())
            .map_err(|e| single_issue(format!("internal: vendor bundle failed to load: {e}")))?;
    }
    engine
        .add_policy(candidate_path, source.to_owned())
        .map_err(|e| single_issue(format!("parse error: {e}")))?;

    let override_query =
        format!("data.silo_custom.{domain}.override(data.silo.{domain}.base_decision, input)");
    let base_query = format!("data.silo.{domain}.decision");
    let inputs: Vec<serde_json::Value> = if representative_inputs.is_empty() {
        vec![serde_json::Value::Object(Default::default())]
    } else {
        representative_inputs.to_vec()
    };
    for input in &inputs {
        engine.set_input(regorus::Value::from(input.clone()));
        if let Err(e) = engine.eval_query(override_query.clone(), false) {
            return Err(single_issue(format!("compile error: {e}")));
        }
        // Also evaluate the whole decision through `tighten`, which is the only caller of
        // `override` and exercises its result rather than just its own body.
        if let Err(e) = engine.eval_rule(base_query.clone()) {
            return Err(single_issue(format!("compile error: {e}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_custom_sources_matches_base_decision_shape() {
        let mut engine = Engine::new().unwrap();
        let input = serde_json::json!({
            "schema_version": 1,
            "account_library_ids": [],
            "account_restricted": false,
            "account_max_playback_quality": "",
            "access_policy_revision": 1,
            "disabled_library_ids": [],
            "profile_present": false,
            "profile_max_content_rating": "",
            "profile_max_advisory_age": 0,
            "profile_max_playback_quality": "",
            "profile_library_restricted": false,
            "profile_allowed_library_ids": [],
            "profile_verified": true,
        });
        let decision: ScopeDecision = engine.evaluate(Domain::Scope, &input).unwrap();
        assert!(decision.unrestricted);
        assert!(decision.profile_verified);
    }

    #[test]
    fn unknown_permission_denies() {
        let mut engine = Engine::new().unwrap();
        let input = serde_json::json!({"permission": "nonsense"});
        let decision: PermissionDecision = engine.evaluate(Domain::Permission, &input).unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason_code, "unknown_permission");
    }

    #[test]
    fn compile_check_rejects_wrong_package() {
        let err = compile_check(
            "scope",
            "package silo_custom.wrong\nimport rego.v1\noverride(_, _) := {}",
            &[],
        );
        assert!(err.is_err());
    }

    #[test]
    fn compile_check_rejects_locked_builtin() {
        let src =
            "package silo_custom.scope\nimport rego.v1\noverride(_, _) := {\"t\": time.now_ns()}";
        assert!(compile_check("scope", src, &[]).is_err());
    }

    #[test]
    fn compile_check_rejects_unknown_domain() {
        assert!(compile_check("bogus", "package silo_custom.bogus\n", &[]).is_err());
    }

    #[test]
    fn compile_check_accepts_a_valid_override() {
        let src = "package silo_custom.scope\nimport rego.v1\noverride(base, i) := {\"unrestricted\": false} if { i.user_id == 1 } else := {}";
        assert!(
            compile_check(
                "scope",
                src,
                &[
                    serde_json::json!({"user_id": 1}),
                    serde_json::json!({"user_id": 2})
                ]
            )
            .is_ok()
        );
    }
}
