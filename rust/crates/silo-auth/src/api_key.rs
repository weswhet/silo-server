//! `internal/auth/api_key_scopes.go`: the API key scope catalog and normalization.
//!
//! The hashing/format primitives (`api_keys.key_hash`/`key_prefix`, the `sa_`-prefixed minted
//! format, `ValidTextKey`) already live in `silo_core::apikey` and are not re-ported here — see
//! that module for `api_key_hash`/`api_key_prefix`/`format_api_key`/`valid_text_key`.
//! The store is [`crate::api_key_store`].

/// `auth.Scope*` constants.
pub const SCOPE_ADMIN_USERS: &str = "admin:users";
pub const SCOPE_ADMIN_ACCESS_GROUPS_READ: &str = "admin:access-groups:read";
pub const SCOPE_ADMIN_SESSIONS_SUMMARY_READ: &str = "admin:sessions:summary:read";
pub const SCOPE_LIBRARIES_READ: &str = "libraries:read";
pub const SCOPE_ADMIN_MONITOR_READ: &str = "admin:monitor:read";
pub const SCOPE_ADMIN_SESSIONS_CONTROL: &str = "admin:sessions:control";

/// `auth.APIKeyScope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyScope {
    pub name: &'static str,
    pub description: &'static str,
}

/// `auth.APIKeyScopeCatalog`, in Go's exact declared order (the stable order the feature-
/// detection endpoint and client UIs depend on).
pub fn api_key_scope_catalog() -> Vec<ApiKeyScope> {
    vec![
        ApiKeyScope {
            name: SCOPE_ADMIN_SESSIONS_SUMMARY_READ,
            description: "Read live playback summaries without diagnostic details or session control.",
        },
        ApiKeyScope {
            name: SCOPE_LIBRARIES_READ,
            description: "Discover libraries visible to the account or selected profile, without storage metadata.",
        },
        ApiKeyScope {
            name: SCOPE_ADMIN_USERS,
            description: "Manage user accounts: create, list, read, update, and delete users and read their \
                profiles. Cannot create or modify admin accounts.",
        },
        ApiKeyScope {
            name: SCOPE_ADMIN_ACCESS_GROUPS_READ,
            description: "Read access groups and their policies.",
        },
        ApiKeyScope {
            name: SCOPE_ADMIN_MONITOR_READ,
            description: "Monitor the server read-only: live sessions, playback history, activity stats, \
                accounts, devices, downloads, node and host health, and the catalog listing. Never exposes \
                filesystem paths, node addresses, storage keys, setting values or credentials.",
        },
        ApiKeyScope {
            name: SCOPE_ADMIN_SESSIONS_CONTROL,
            description: "Pause, resume, stop, message and terminate live playback sessions.",
        },
    ]
}

/// `auth.V1APIKeyScopeCatalog`.
pub fn v1_api_key_scope_catalog() -> Vec<ApiKeyScope> {
    vec![
        ApiKeyScope {
            name: SCOPE_ADMIN_USERS,
            description: "Manage user accounts: create, list, read, update, and delete users and read their \
                profiles. Cannot create or modify admin accounts.",
        },
        ApiKeyScope {
            name: SCOPE_ADMIN_ACCESS_GROUPS_READ,
            description: "Read access groups and their policies.",
        },
    ]
}

/// `auth.UnknownAPIKeyScopeError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown api key scope {0:?}")]
pub struct UnknownApiKeyScope(pub String);

/// `auth.ValidAPIKeyScopes`.
pub fn valid_api_key_scopes() -> Vec<&'static str> {
    api_key_scope_catalog()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

fn normalize_against(scopes: &[String], valid: &[&str]) -> Result<Vec<String>, UnknownApiKeyScope> {
    if scopes.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for s in scopes {
        if !valid.contains(&s.as_str()) {
            return Err(UnknownApiKeyScope(s.clone()));
        }
        if !out.contains(s) {
            out.push(s.clone());
        }
    }
    out.sort();
    Ok(out)
}

/// `auth.NormalizeV1APIKeyScopes`.
pub fn normalize_v1_api_key_scopes(scopes: &[String]) -> Result<Vec<String>, UnknownApiKeyScope> {
    normalize_against(scopes, &[SCOPE_ADMIN_USERS, SCOPE_ADMIN_ACCESS_GROUPS_READ])
}

/// `auth.NormalizeAPIKeyScopes`: `nil`/empty input is valid and means "unscoped" (full access).
pub fn normalize_api_key_scopes(scopes: &[String]) -> Result<Vec<String>, UnknownApiKeyScope> {
    let valid = valid_api_key_scopes();
    normalize_against(scopes, &valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_dedups_and_sorts() {
        let scopes = vec![
            SCOPE_LIBRARIES_READ.to_owned(),
            SCOPE_ADMIN_USERS.to_owned(),
            SCOPE_LIBRARIES_READ.to_owned(),
        ];
        let got = normalize_api_key_scopes(&scopes).unwrap();
        assert_eq!(
            got,
            vec![
                SCOPE_ADMIN_USERS.to_owned(),
                SCOPE_LIBRARIES_READ.to_owned()
            ]
        );
    }

    #[test]
    fn normalize_rejects_unknown_scope() {
        assert!(normalize_api_key_scopes(&["bogus".to_owned()]).is_err());
    }

    #[test]
    fn empty_scopes_means_unscoped() {
        assert_eq!(normalize_api_key_scopes(&[]).unwrap(), Vec::<String>::new());
    }
}
