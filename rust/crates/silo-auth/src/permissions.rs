//! `internal/auth/permissions.go`: the assignable permission set (`marker_edit`,
//! `metadata_curation`), and the pure logic over a user's role/enabled/permissions. The `admin`
//! role has every assignable permission implicitly; a disabled user has none.
//!
//! This module takes `role`/`enabled`/`permissions` as plain parameters rather than a `models::User`
//! struct, since no models crate exists in this session's dependency graph yet; a caller adapts its
//! own user type into these three fields.

/// `auth.Permission`.
pub const PERMISSION_MARKER_EDIT: &str = "marker_edit";
pub const PERMISSION_METADATA_CURATION: &str = "metadata_curation";

const ASSIGNABLE: [&str; 2] = [PERMISSION_MARKER_EDIT, PERMISSION_METADATA_CURATION];

/// `isAssignablePermission`.
pub fn is_assignable_permission(permission: &str) -> bool {
    ASSIGNABLE.contains(&permission)
}

/// `assignablePermissionList`: sorted, matching Go's `sort.Strings` over the map's keys.
fn assignable_permission_list() -> Vec<String> {
    let mut out: Vec<String> = ASSIGNABLE.iter().map(|s| (*s).to_owned()).collect();
    out.sort();
    out
}

/// `auth.NormalizePermissions`: trims, drops blanks and duplicates, and sorts. Any value that is
/// not an assignable permission after trimming is an error (not silently dropped), matching Go's
/// `fmt.Errorf("unknown permission %q", key)`.
pub fn normalize_permissions(values: &[String]) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for raw in values {
        let key = raw.trim();
        if key.is_empty() {
            continue;
        }
        if !is_assignable_permission(key) {
            return Err(format!("unknown permission {key:?}"));
        }
        if !seen.insert(key.to_owned()) {
            continue;
        }
        out.push(key.to_owned());
    }
    out.sort();
    Ok(out)
}

/// `auth.DefaultUserPermissions`.
pub fn default_user_permissions() -> Vec<String> {
    vec![PERMISSION_MARKER_EDIT.to_owned()]
}

/// `auth.HasAssignedPermission`.
pub fn has_assigned_permission(user_permissions: &[String], permission: &str) -> bool {
    user_permissions.iter().any(|v| v == permission)
}

/// `auth.HasEffectivePermission`.
pub fn has_effective_permission(
    role: &str,
    enabled: bool,
    user_permissions: &[String],
    permission: &str,
) -> bool {
    if !enabled {
        return false;
    }
    if role == "admin" {
        return is_assignable_permission(permission);
    }
    has_assigned_permission(user_permissions, permission)
}

/// `auth.EffectivePermissions`.
pub fn effective_permissions(
    role: &str,
    enabled: bool,
    user_permissions: &[String],
) -> Vec<String> {
    if !enabled {
        return Vec::new();
    }
    if role == "admin" {
        return assignable_permission_list();
    }
    normalize_permissions(user_permissions).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_every_assignable_permission_implicitly() {
        assert!(has_effective_permission(
            "admin",
            true,
            &[],
            PERMISSION_MARKER_EDIT
        ));
        assert!(has_effective_permission(
            "admin",
            true,
            &[],
            PERMISSION_METADATA_CURATION
        ));
    }

    #[test]
    fn disabled_user_has_none() {
        assert!(!has_effective_permission(
            "admin",
            false,
            &[PERMISSION_MARKER_EDIT.to_owned()],
            PERMISSION_MARKER_EDIT
        ));
    }

    #[test]
    fn normalize_rejects_unknown_and_dedups() {
        let values = vec![
            "marker_edit".to_owned(),
            " marker_edit ".to_owned(),
            "".to_owned(),
        ];
        assert_eq!(
            normalize_permissions(&values).unwrap(),
            vec!["marker_edit".to_owned()]
        );
        assert!(normalize_permissions(&["bogus".to_owned()]).is_err());
    }
}
