//! Config builders and titles from `internal/sections/generated.go`.

pub const GENERATED_HOME_LIBRARY_RECENT_SOURCE: &str = "home_library_recent";
pub const KIND_RELEASED_EPISODES: &str = "recently_released_episodes";

/// `GeneratedHomeLibraryRecentConfig`.
pub fn home_library_recent_config(library_id: i64) -> String {
    format!(
        r#"{{"filter_library_id":{library_id},"generated_library_id":null,"generated_kind":"","generated_source":"{GENERATED_HOME_LIBRARY_RECENT_SOURCE}"}}"#
    )
}

/// `GeneratedHomeLibraryRecentConfigScoped` (normalized QueryDefinition, added_at desc).
pub fn home_library_recent_config_scoped(library_id: i64, media_scope: &str) -> String {
    format!(
        r#"{{"library_ids":[{library_id}],"media_scope":"{media_scope}","match":"all","groups":[],"sort":{{"field":"added_at","order":"desc"}},"generated_library_id":{library_id},"generated_source":"{GENERATED_HOME_LIBRARY_RECENT_SOURCE}"}}"#
    )
}

/// `GeneratedHomeLibraryRecentEpisodesConfig`.
pub fn home_library_recent_episodes_config(library_id: i64) -> String {
    format!(
        r#"{{"library_ids":[{library_id}],"media_scope":"episode","match":"all","groups":[],"sort":{{"field":"release_date","order":"desc"}},"generated_library_id":{library_id},"generated_kind":"{KIND_RELEASED_EPISODES}","generated_source":"{GENERATED_HOME_LIBRARY_RECENT_SOURCE}"}}"#
    )
}

/// `GeneratedHomeLibraryRecentTitle`.
pub fn home_library_recent_title(section_type: &str, library_name: &str) -> String {
    match section_type {
        "recently_added" => format!("Recently Added in {library_name}"),
        "recently_released" => format!("Recently Released in {library_name}"),
        other => other.to_string(),
    }
}
