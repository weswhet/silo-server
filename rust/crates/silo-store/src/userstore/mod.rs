//! `internal/userstore`: the canonical cross-platform user-settings store.
//!
//! The row types ([`SettingIdentity`], [`SettingValue`], [`SettingResolutionQuery`]) already live
//! in `silo_config::resolve` (that crate was built before this one and needed a minimal copy to
//! define its `Store` trait — see that crate's public API notes). This module re-exports them
//! rather than redefining them, adds the identity validation and mutation-record types Go keeps in
//! `internal/userstore/settingvalues.go`, and [`pgstore`] is the Postgres backend
//! (`internal/userstore/pgstore`).
//!
//! Scope actually ported, and what is deferred, is documented on [`pgstore`].

pub mod pgstore;
pub mod prefs;
pub mod profiles;

pub use silo_config::resolve::{
    ReadError, ServerSettings, SettingIdentity, SettingResolutionQuery, SettingValue, Store,
};
use silo_config::settings::Scope;
use silo_gocompat::strings::trim_space;

/// `userstore.ErrInvalidSettingIdentity`.
/// `userstore.ErrInvalidSettingValue`.
/// `userstore.ErrSettingValueRevisionConflict`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid setting identity: {0}")]
    InvalidIdentity(String),
    #[error("invalid setting value: {0}")]
    InvalidValue(String),
    #[error("setting value revision conflict")]
    RevisionConflict,
}

/// `SettingIdentity.Validate`: reports whether the identity is addressable. It mirrors the scope
/// CHECK constraint on `user_setting_values` so an invalid identity is rejected before it reaches
/// either backend, and rejects ids not already in canonical (trimmed) form, since the write path
/// binds fields verbatim while resolution queries bind their trimmed forms.
pub fn validate_identity(id: &SettingIdentity) -> Result<(), Error> {
    for (field, value) in [
        ("key", id.key.as_str()),
        ("profile id", id.profile_id.as_str()),
        ("client family", id.client_family.as_str()),
        ("device id", id.device_id.as_str()),
        ("series id", id.series_id.as_str()),
    ] {
        if value != trim_space(value) {
            return Err(Error::InvalidIdentity(format!(
                "{field} {value:?} has surrounding whitespace"
            )));
        }
    }
    if id.key.is_empty() {
        return Err(Error::InvalidIdentity("key is required".to_owned()));
    }
    if !id.scope.is_remote() {
        return Err(Error::InvalidIdentity(format!(
            "{:?} is not a remote scope",
            id.scope.as_str()
        )));
    }

    let need_profile = id.scope != Scope::ACCOUNT;
    if need_profile && id.profile_id.is_empty() {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} requires a profile id",
            id.scope.as_str()
        )));
    }
    if !need_profile && !id.profile_id.is_empty() {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} must not carry a profile id",
            id.scope.as_str()
        )));
    }

    let want_client_family = id.scope == Scope::PROFILE_CLIENT;
    if want_client_family && !id.client_family.valid() {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} requires client family tv, mobile, tablet, desktop or web",
            id.scope.as_str()
        )));
    }
    if !want_client_family && !id.client_family.as_str().is_empty() {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} must not carry a client family",
            id.scope.as_str()
        )));
    }

    let want_device = id.scope == Scope::PROFILE_DEVICE;
    if want_device && id.device_id.is_empty() {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} requires a device id",
            id.scope.as_str()
        )));
    }
    if !want_device && !id.device_id.is_empty() {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} must not carry a device id",
            id.scope.as_str()
        )));
    }

    let want_library = id.scope == Scope::PROFILE_LIBRARY;
    if want_library && id.library_id <= 0 {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} requires a library id",
            id.scope.as_str()
        )));
    }
    if !want_library && id.library_id != 0 {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} must not carry a library id",
            id.scope.as_str()
        )));
    }

    let want_series = id.scope == Scope::PROFILE_SERIES;
    if want_series && id.series_id.is_empty() {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} requires a series id",
            id.scope.as_str()
        )));
    }
    if !want_series && !id.series_id.is_empty() {
        return Err(Error::InvalidIdentity(format!(
            "scope {:?} must not carry a series id",
            id.scope.as_str()
        )));
    }
    Ok(())
}

/// `userstore.ValidateScopeListing`: whether `(profile_id, scope)` names a profile-anchored set of
/// rows `list_setting_values_by_scope` can list.
pub fn validate_scope_listing(profile_id: &str, scope: &Scope) -> Result<(), Error> {
    if !scope.is_remote() || *scope == Scope::ACCOUNT {
        return Err(Error::InvalidIdentity(format!(
            "{:?} is not a profile-anchored scope",
            scope.as_str()
        )));
    }
    if profile_id.is_empty() || profile_id != trim_space(profile_id) {
        return Err(Error::InvalidIdentity(format!(
            "profile id {profile_id:?} is required in canonical form"
        )));
    }
    Ok(())
}

/// `userstore.ValidateSettingValueJSON`: the store's only value check — whether a value satisfies
/// its definition is the settings-contract layer's job.
pub fn validate_setting_value_json(raw: &[u8]) -> Result<(), Error> {
    if raw.is_empty() {
        return Err(Error::InvalidValue("value is required".to_owned()));
    }
    if !silo_gocompat::json::valid(raw) {
        return Err(Error::InvalidValue(
            "value is not well-formed JSON".to_owned(),
        ));
    }
    Ok(())
}

/// `userstore.SettingMutationRecord`: the idempotency receipt for one mutation. A `mutation_id` is
/// idempotent for at least 30 days; `DeleteExpiredSettingMutations` sweeps rows past `expires_at`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingMutationRecord {
    pub mutation_id: String,
    pub request_hash: String,
    /// The serialized per-mutation result returned to a repeat of the same request.
    pub result: Vec<u8>,
    /// RFC3339 UTC, set by the store on insert.
    pub created_at: String,
    /// RFC3339 UTC.
    pub expires_at: String,
}

impl SettingMutationRecord {
    /// `SettingMutationRecord.Validate`.
    pub fn validate(&self) -> Result<(), Error> {
        if trim_space(&self.mutation_id).is_empty() {
            return Err(Error::InvalidIdentity("mutation id is required".to_owned()));
        }
        if trim_space(&self.request_hash).is_empty() {
            return Err(Error::InvalidIdentity(
                "request hash is required".to_owned(),
            ));
        }
        if self.expires_at.is_empty() {
            return Err(Error::InvalidIdentity("expires_at is required".to_owned()));
        }
        validate_setting_value_json(&self.result)
    }
}

/// `userstore.SettingResolutionQuery.Normalized`: blanks removed, duplicates collapsed, in a
/// stable (sorted) order, so a given request always binds the same SQL array literals.
pub fn normalized(query: &SettingResolutionQuery) -> SettingResolutionQuery {
    SettingResolutionQuery {
        keys: compact_strings(&query.keys),
        profile_ids: compact_strings(&query.profile_ids),
        client_family: silo_config::settings::ClientFamily::new(
            trim_space(query.client_family.as_str()).to_owned(),
        ),
        device_id: trim_space(&query.device_id).to_owned(),
        library_ids: compact_positive_ints(&query.library_ids),
        series_ids: compact_strings(&query.series_ids),
    }
}

fn compact_strings(values: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(values.len());
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = trim_space(value);
        if trimmed.is_empty() || !seen.insert(trimmed.to_owned()) {
            continue;
        }
        out.push(trimmed.to_owned());
    }
    out.sort();
    out
}

fn compact_positive_ints(values: &[i64]) -> Vec<i64> {
    let mut seen = std::collections::HashSet::with_capacity(values.len());
    let mut out = Vec::with_capacity(values.len());
    for &value in values {
        if value <= 0 || !seen.insert(value) {
            continue;
        }
        out.push(value);
    }
    out.sort_unstable();
    out
}
