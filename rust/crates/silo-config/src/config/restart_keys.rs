//! Which `server_settings` keys need a restart to take effect.

use super::types::{DOWNLOAD_ARTIFACT_DIR_SETTING_KEY, PLAYBACK_TRANSCODE_DIR_SETTING_KEY};

const RESTART_REQUIRED_KEYS: &[&str] = &[
    "server.listen",
    "server.mode",
    "server.log_format",
    "opslog.capture_level",
    "auth.jwt_secret",
    "ratelimit.enabled",
    "ratelimit.backend",
    "playback.ffmpeg_path",
    "playback.hw_accel",
    "playback.hw_device",
    PLAYBACK_TRANSCODE_DIR_SETTING_KEY,
    DOWNLOAD_ARTIFACT_DIR_SETTING_KEY,
    "playback.chapter_thumbnail_workers",
    "scanner.max_concurrent_libraries",
    "scanner.max_concurrent_scoped",
    "scanner.empty_trash_after_scan",
    "scanner.file_removal_grace",
    "matcher.enable_tv_series_root_queue",
    "matcher.enable_tv_series_group_queue",
    "tmdb.api_key",
    super::SERVER_LAN_DISCOVERY_SETTING_KEY,
    "audiobookshelf_compat.enabled",
    "jellyfin_compat.enabled",
    "jellyfin_compat.listen",
    "jellyfin_compat.server_id",
    "jellyfin_compat.session_ttl",
    "jellyfin_compat.playback_session_ttl",
    "ai.max_concurrent_jobs",
    "subtitle_ai.max_concurrent_jobs",
    "catalog.search.provider",
    "catalog.search.meilisearch.url",
    "catalog.search.meilisearch.api_key",
    "catalog.search.meilisearch.index",
    "catalog.search.meilisearch.timeout_ms",
    "catalog.search.meilisearch.matching_strategy",
    "catalog.search.meilisearch.index_types",
    "catalog.search.meilisearch.semantic_enabled",
    "catalog.search.meilisearch.semantic_ratio",
    "catalog.search.meilisearch.embedder",
    "catalog.search.meilisearch.binary_quantized",
];

const RESTART_REQUIRED_PREFIXES: &[&str] = &[
    "database.",
    "userdb.",
    "s3.",
    "artwork.",
    "redis.",
    "recommendations.",
];

/// Whether changing the given `server_settings` key requires a restart.
pub fn restart_required(key: &str) -> bool {
    RESTART_REQUIRED_KEYS.contains(&key)
        || RESTART_REQUIRED_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// The sorted exact keys that require a restart.
pub fn restart_required_keys() -> Vec<String> {
    let mut keys: Vec<String> = RESTART_REQUIRED_KEYS
        .iter()
        .map(|k| (*k).to_owned())
        .collect();
    keys.sort();
    keys
}

/// The sorted key prefixes whose whole namespace requires a restart.
pub fn restart_required_prefixes() -> Vec<String> {
    let mut prefixes: Vec<String> = RESTART_REQUIRED_PREFIXES
        .iter()
        .map(|k| (*k).to_owned())
        .collect();
    prefixes.sort();
    prefixes
}
