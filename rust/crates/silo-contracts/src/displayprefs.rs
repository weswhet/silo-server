//! Port of `internal/jellycompat/displayprefs`: the storage identity of Jellyfin DisplayPreferences
//! blobs under their legacy `user_settings` keys.

/// Marks every legacy `user_settings` row that belonged to the Jellyfin compatibility layer.
pub const NAMESPACE_PREFIX: &str = "jellycompat:";

const LEGACY_KEY_PREFIX: &str = "jellycompat:displayprefs:";

/// The SQL `LIKE` pattern matching every legacy jellycompat row.
pub fn legacy_key_pattern() -> String {
    format!("{NAMESPACE_PREFIX}%")
}

/// The `user_settings` key a blob was stored under.
pub fn legacy_key(prefs_id: &str, client: &str) -> String {
    format!("{LEGACY_KEY_PREFIX}{prefs_id}:{client}")
}

/// One DisplayPreferences document moved to the dedicated table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blob {
    pub prefs_id: String,
    pub client: String,
    pub value: String,
}

/// A jellycompat row that does not parse as a DisplayPreferences blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reject {
    pub key: String,
    pub value: String,
    pub reason: String,
}

/// Classifies one legacy row. The key splits at the last colon after the prefix.
pub fn plan_legacy_row(key: &str, value: &str) -> Result<Blob, Reject> {
    let Some(remainder) = key.strip_prefix(LEGACY_KEY_PREFIX) else {
        return Err(Reject {
            key: key.to_string(),
            value: value.to_string(),
            reason: format!(
                "jellycompat row is not a {LEGACY_KEY_PREFIX}* key; only the removed legacy settings extension bag could have written it"
            ),
        });
    };
    let Some(sep) = remainder.rfind(':') else {
        return Err(Reject {
            key: key.to_string(),
            value: value.to_string(),
            reason: "displayprefs key has no id:client separator; the DisplayPreferences handler never wrote this shape".to_string(),
        });
    };
    Ok(Blob {
        prefs_id: remainder[..sep].to_string(),
        client: remainder[sep + 1..].to_string(),
        value: value.to_string(),
    })
}
