//! Admin setting keys, effective defaults, and validation of admin writes.

use super::*;
use crate::gonet::{Url, mail_address_equals_input};
use crate::goparse::{atoi, fmt_g, parse_bool, parse_float, parse_int};
use crate::settings::{self, Definition};
use silo_gocompat::filepath;
use silo_gocompat::strconv::{format_float, quote};
use silo_gocompat::strings::{equal_fold, to_lower, trim_space};
use silo_gocompat::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

pub const PLAYBACK_SEGMENT_RETENTION_SETTING_KEY: &str = "playback.segment_retention_seconds";
pub const CHAPTER_THUMBNAIL_SOFTWARE_TONE_MAP_SETTING_KEY: &str =
    "playback.chapter_thumbnail_software_tone_map_enabled";
pub const PLAYBACK_TRANSCODE_HARDWARE_TONE_MAP_SETTING_KEY: &str =
    "playback.transcode_hardware_tone_map_enabled";
pub const PLAYBACK_TRANSCODE_SOFTWARE_TONE_MAP_SETTING_KEY: &str =
    "playback.transcode_software_tone_map_enabled";
pub const SETUP_COMPLETED_SETTING_KEY: &str = "setup.completed";
pub const DASHBOARD_HIDDEN_ATTENTION_SETTING_KEY: &str = "ui.dashboard.hidden_attention";
const MAX_DASHBOARD_HIDDEN_ATTENTION_IDS: usize = 32;
const MAX_DASHBOARD_HIDDEN_ATTENTION_ID_LEN: usize = 64;
pub const CATALOG_SCOPE_VERSIONS_TO_LIBRARY_SETTING_KEY: &str = "catalog.scope_versions_to_library";
pub const ACCESS_UNRATED_CONTENT_SETTING_KEY: &str = "access.unrated_content";
pub const ACCESS_UNRATED_CONTENT_HIDE: &str = "hide";
pub const ACCESS_UNRATED_CONTENT_ALLOW: &str = "allow";
pub const PLAYBACK_KEYFRAME_PLAYLIST_SETTING_KEY: &str = "playback.copy_keyframe_playlist";
pub const PLAYBACK_BANDWIDTH_PROBE_AUTOMATIC_SETTING_KEY: &str =
    "playback.bandwidth_probe_automatic";
pub const PLAYBACK_BANDWIDTH_PROBE_MAX_AGE_DAYS_SETTING_KEY: &str =
    "playback.bandwidth_probe_max_age_days";
pub const DEFAULT_BANDWIDTH_PROBE_MAX_AGE_DAYS: i64 = 7;
pub(crate) const MAX_BANDWIDTH_PROBE_MAX_AGE_DAYS: i64 = 30;
pub const CATALOG_EXTRA_RATING_SOURCES_SETTING_KEY: &str = "catalog.extra_rating_sources";
pub const ALLOW_4K_TRANSCODE_SETTING_KEY: &str = "allow_4k_transcode";
pub const PLAYBACK_ALLOW_HEVC_ENCODING_SETTING_KEY: &str = "playback.allow_hevc_encoding";
pub const PLAYBACK_PREFER_LOWER_VERSION_TRANSCODE_SETTING_KEY: &str =
    "playback.prefer_lower_version_transcode";
pub const DOWNLOAD_LOCAL_TRANSCODE_FALLBACK_SETTING_KEY: &str = "download.local_transcode_fallback";
pub const ARTWORK_STORAGE_RECONCILE_CHECKPOINT_KEY: &str = "s3.public_storage_reconcile_checkpoint";
pub const STORAGE_TRANSITION_TARGET_KEY: &str = "storage.transition.target";
pub const ARTWORK_STORAGE_SWEEP_CHECKPOINT_KEY: &str = "artwork.storage_sweep_checkpoint";
pub const MEDIA_IMAGE_SWEEP_CHECKPOINT_KEY: &str = "media_images.sweep_checkpoint";
pub const CHAPTER_THUMBNAIL_ORIGINALS_CLEANUP_KEY: &str =
    "chapter_thumbnails.originals_cleanup_checkpoint";
pub const METADATA_IMAGE_WORKERS_SETTING_KEY: &str = "metadata.image_workers";
pub const METADATA_PERSON_REFRESH_PER_MINUTE_SETTING_KEY: &str =
    "metadata.person_refresh_per_minute";
pub const METADATA_FALLBACK_LANGUAGE_SETTING_KEY: &str = "metadata.fallback_language";
pub const METADATA_FALLBACK_ORIGINAL: &str = "original";
pub const PREVIEW_IMAGE_WIDTH_SETTING_KEY: &str = "playback.preview_image_width";
pub const DEFAULT_PREVIEW_IMAGE_WIDTH: i64 = 300;
pub const MIN_PREVIEW_IMAGE_WIDTH: i64 = 160;
pub const MAX_PREVIEW_IMAGE_WIDTH: i64 = 640;
pub const MARKERS_DETECTION_WORKERS_SETTING_KEY: &str = "markers.detection_workers";
pub const SERVER_LAN_DISCOVERY_SETTING_KEY: &str = "server.lan_discovery";
pub const SERVER_LOCAL_URL_SETTING_KEY: &str = "server.local_url";
pub const AUTH_LOCAL_PASSWORD_LOGIN_SETTING_KEY: &str = "auth.local_password_login";
pub const AUTH_EMAIL_AUTO_MATCH_SETTING_KEY: &str = "auth.email_auto_match";
pub const AUTH_PROVIDER_RECHECK_INTERVAL_SETTING_KEY: &str = "auth.provider_recheck_interval";
pub const AUTH_PROVIDER_RECHECK_OUTAGE_POLICY_SETTING_KEY: &str =
    "auth.provider_recheck_outage_policy";
pub const AUTH_REFRESH_TOKEN_EXPIRY_SETTING_KEY: &str = "auth.refresh_token_expiry";
pub const AUTH_RECHECK_FAIL_OPEN: &str = "fail_open";
pub const AUTH_RECHECK_FAIL_CLOSED: &str = "fail_closed";
pub const DEFAULT_AUTH_PROVIDER_RECHECK_INTERVAL: Duration = Duration(12 * Duration::HOUR.0);
pub const DEFAULT_AUTH_REFRESH_TOKEN_EXPIRY: Duration = Duration(30 * 24 * Duration::HOUR.0);
/// The advisory lock general settings mutations hold for their transaction.
pub const SERVER_SETTINGS_MUTATION_LOCK: &str = "silo:server_settings:mutation";
pub const REDIS_DB_SETTING_KEY: &str = "redis.db";

/// `playback.TranscodeThrottleEnabledSettingKey`.
pub const TRANSCODE_THROTTLE_ENABLED_SETTING_KEY: &str = "enable_transcode_throttle";
/// `playback.TranscodeThrottleSecondsSettingKey`.
pub const TRANSCODE_THROTTLE_SECONDS_SETTING_KEY: &str = "transcode_throttle_seconds";
pub const DEFAULT_TRANSCODE_THROTTLE_ENABLED: bool = true;
pub const DEFAULT_TRANSCODE_THROTTLE_SECONDS: i64 = 300;

const CLOUDFLARE_URL_MODE: &str = "cloudflare_token";

/// `ParseRatingSourceList`: source names, dropping blanks, duplicates, and malformed names.
pub fn parse_rating_source_list(raw: &str) -> Vec<String> {
    split_rating_source_list(raw).0
}

fn valid_rating_source_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.is_empty() || b.len() > 32 || !b[0].is_ascii_lowercase() {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn split_rating_source_list(raw: &str) -> (Vec<String>, String) {
    let mut seen = HashSet::new();
    let mut sources = Vec::new();
    let mut malformed = String::new();
    for entry in raw.split(',') {
        let source = to_lower(trim_space(entry));
        if source.is_empty() {
            continue;
        }
        if !valid_rating_source_id(&source) {
            if malformed.is_empty() {
                malformed = source;
            }
            continue;
        }
        if seen.insert(source.clone()) {
            sources.push(source);
        }
    }
    (sources, malformed)
}

/// `PreviewImageWidth`: an unset or unparsable value is the default, and any other is brought within
/// bounds and made even.
pub fn preview_image_width(value: &str) -> i64 {
    match atoi(trim_space(value)) {
        Err(_) => DEFAULT_PREVIEW_IMAGE_WIDTH,
        Ok(width) => width.clamp(MIN_PREVIEW_IMAGE_WIDTH, MAX_PREVIEW_IMAGE_WIDTH) & !1,
    }
}

/// `AuthProviderRecheckInterval`: an empty or invalid value is the default.
pub fn auth_provider_recheck_interval(raw: &str) -> Duration {
    match parse_duration(trim_space(raw)) {
        Ok(d) if d.0 > 0 => d,
        _ => DEFAULT_AUTH_PROVIDER_RECHECK_INTERVAL,
    }
}

/// `AuthRefreshTokenExpiry`: an empty or invalid value is the default.
pub fn auth_refresh_token_expiry(raw: &str) -> Duration {
    match parse_duration(trim_space(raw)) {
        Ok(d) if d.0 > 0 => d,
        _ => DEFAULT_AUTH_REFRESH_TOKEN_EXPIRY,
    }
}

/// The effective value the Admin UI shows when no row exists, as `(key, value)`. Keep these aligned
/// with the runtime readers that own each setting.
pub const ADMIN_SETTING_DEFAULTS: &[(&str, &str)] = &[
    ("auth.access_token_expiry", "8h"),
    ("auth.refresh_token_expiry", "30d"),
    ("server.log_level", "info"),
    ("server.log_quiet", ""),
    ("server.public_url", ""),
    ("branding.server_name", "Silo"),
    (
        "branding.login_subtitle",
        "Sign in with an existing account.",
    ),
    (
        "clientip.trusted_proxies",
        "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1/128",
    ),
    ("theme.catalog_url", DEFAULT_THEME_CATALOG_URL),
    (SERVER_LAN_DISCOVERY_SETTING_KEY, "true"),
    (SERVER_LOCAL_URL_SETTING_KEY, ""),
    (AUTH_LOCAL_PASSWORD_LOGIN_SETTING_KEY, "true"),
    (AUTH_EMAIL_AUTO_MATCH_SETTING_KEY, "false"),
    (AUTH_PROVIDER_RECHECK_INTERVAL_SETTING_KEY, "12h"),
    (
        AUTH_PROVIDER_RECHECK_OUTAGE_POLICY_SETTING_KEY,
        AUTH_RECHECK_FAIL_OPEN,
    ),
    ("database.max_connections", "20"),
    ("s3.public_path_style", "true"),
    ("s3.public_url_auth", "presigned"),
    ("s3.public_token_param", "verify"),
    ("s3.public_token_ttl", "10800"),
    ("s3.private_path_style", "true"),
    ("s3.metadata_presign_expiry", "4h"),
    ("s3.user_db_path_style", "true"),
    ("userdb.backend", "postgres"),
    ("userdb.pool_max_open", "500"),
    ("userdb.idle_timeout", "12h"),
    ("scanner.workers", "8"),
    (METADATA_IMAGE_WORKERS_SETTING_KEY, "0"),
    ("scanner.max_concurrent_libraries", "1"),
    ("scanner.max_concurrent_scoped", "2"),
    ("scanner.file_removal_grace", "24h"),
    ("scanner.empty_trash_after_scan", "true"),
    ("scanner.realtime_monitoring", "true"),
    ("matcher.workers", "8"),
    ("matcher.batch_size", "500"),
    ("matcher.enable_tv_series_root_queue", "true"),
    ("matcher.enable_tv_series_group_queue", "false"),
    ("metadata.cache_images", "true"),
    ("artwork.storage_backend", "auto"),
    ("artwork.local_path", "/var/lib/silo/artwork"),
    ("markers.mode", "both"),
    ("markers.lazy_playback", "true"),
    (MARKERS_DETECTION_WORKERS_SETTING_KEY, "1"),
    ("markers.online_storage", "stored"),
    ("markers.detect_intros", "true"),
    ("markers.detect_credits", "true"),
    ("markers.share_by_default", ""),
    (METADATA_PERSON_REFRESH_PER_MINUTE_SETTING_KEY, "120"),
    (METADATA_FALLBACK_LANGUAGE_SETTING_KEY, "en"),
    ("playback.ffmpeg_path", ""),
    (PLAYBACK_TRANSCODE_DIR_SETTING_KEY, DEFAULT_TRANSCODE_DIR),
    (PLAYBACK_SEGMENT_RETENTION_SETTING_KEY, "600"),
    ("playback.hw_accel", "auto"),
    ("playback.transcode_enabled", "true"),
    (PLAYBACK_ALLOW_HEVC_ENCODING_SETTING_KEY, "false"),
    (PLAYBACK_PREFER_LOWER_VERSION_TRANSCODE_SETTING_KEY, "true"),
    (
        PLAYBACK_ROUTING_DIRECT_PLAY_EGRESS_SETTING_KEY,
        PLAYBACK_EGRESS_PREFER_PROXY,
    ),
    (
        PLAYBACK_ROUTING_REMUX_EXECUTION_SETTING_KEY,
        PLAYBACK_EXECUTION_PREFER_TRANSCODE,
    ),
    (
        PLAYBACK_ROUTING_REMUX_EGRESS_SETTING_KEY,
        PLAYBACK_EGRESS_PREFER_PROXY,
    ),
    (
        PLAYBACK_ROUTING_VIDEO_TRANSCODE_EXECUTION_SETTING_KEY,
        PLAYBACK_EXECUTION_PREFER_TRANSCODE,
    ),
    (
        PLAYBACK_ROUTING_VIDEO_TRANSCODE_EGRESS_SETTING_KEY,
        PLAYBACK_EGRESS_PREFER_PROXY,
    ),
    ("playback.chapter_thumbnail_workers", "1"),
    ("playback.chapter_thumbnail_execution", "local"),
    ("playback.chapter_thumbnail_node_capacity", "1"),
    ("playback.chapter_thumbnail_hdr_policy", "best_effort"),
    ("playback.preview_image_width", "300"),
    ("playback.trickplay_interval_seconds", "10"),
    ("playback.trickplay_workers", "1"),
    ("playback.trickplay_execution", "local"),
    (CHAPTER_THUMBNAIL_SOFTWARE_TONE_MAP_SETTING_KEY, "true"),
    (PLAYBACK_TRANSCODE_HARDWARE_TONE_MAP_SETTING_KEY, "true"),
    (PLAYBACK_TRANSCODE_SOFTWARE_TONE_MAP_SETTING_KEY, "true"),
    (CATALOG_SCOPE_VERSIONS_TO_LIBRARY_SETTING_KEY, "false"),
    (
        ACCESS_UNRATED_CONTENT_SETTING_KEY,
        ACCESS_UNRATED_CONTENT_HIDE,
    ),
    (CATALOG_EXTRA_RATING_SOURCES_SETTING_KEY, ""),
    ("playback.watched_threshold", "90"),
    ("playback.min_resume_threshold", "5"),
    (ALLOW_4K_TRANSCODE_SETTING_KEY, "true"),
    (TRANSCODE_THROTTLE_ENABLED_SETTING_KEY, "true"),
    (TRANSCODE_THROTTLE_SECONDS_SETTING_KEY, "300"),
    ("audiobookshelf_compat.enabled", "true"),
    ("jellyfin_compat.enabled", "true"),
    ("jellyfin_compat.public_url", "http://127.0.0.1:8096"),
    (
        "jellyfin_compat.emulated_server_version",
        DEFAULT_JELLYFIN_COMPAT_EMULATED_SERVER_VERSION,
    ),
    ("jellyfin_compat.server_name", "Silo"),
    ("jellyfin_compat.web_enabled", "true"),
    ("jellyfin_compat.web_version", DEFAULT_JELLYFIN_WEB_VERSION),
    (
        "jellyfin_compat.web_install_dir",
        DEFAULT_JELLYFIN_WEB_INSTALL_DIR,
    ),
    ("jellyfin_compat.session_ttl", "87600h"),
    (
        "jellyfin_compat.playback_session_ttl",
        DEFAULT_JELLYFIN_COMPAT_PLAYBACK_SESSION_TTL,
    ),
    ("recommendations.enabled", "false"),
    ("recommendations.embeddings_job_timeout", "24h"),
    ("recommendations.embeddings_cron", "0 3 * * *"),
    ("recommendations.taste_profiles_cron", "0 4 * * *"),
    ("recommendations.cowatch_cron", "30 4 * * *"),
    ("recommendations.recommendations_cron", "0 5 * * *"),
    ("recommendations.taste_decay_half_life_days", "180"),
    ("recommendations.diversity_lambda", "0.7"),
    ("ai.auth_mode", "api_key"),
    ("ai.reasoning_effort", ""),
    (AI_SERVICE_TIER_SETTING_KEY, ""),
    ("ai.chat_model", "gpt-6-luna"),
    ("ai.asr_model", "whisper-1"),
    ("ai.max_concurrent_jobs", "2"),
    ("subtitle_ai.enabled", "false"),
    ("subtitle_ai.transcribe_enabled", "false"),
    ("subtitle_ai.batch_size", "40"),
    ("subtitle_ai.context_neighbors", "2"),
    ("subtitle_ai.asr_chunk_seconds", "600"),
    ("subtitle_ai.live_asr_chunk_seconds", "30"),
    ("subtitle_ai.transcribe_quota_jobs", "0"),
    ("subtitle_ai.transcribe_quota_period", "day"),
    ("subtitles.auto_sync", "true"),
    ("subtitles.sync_execution", "prefer_transcode_nodes"),
    ("subtitles.sync_node_capacity", "1"),
    ("metadata_ai.enabled", "false"),
    ("metadata_ai.on_view", "off"),
    ("download.enabled", "false"),
    ("download.server_bandwidth_mbps", "0"),
    ("download.user_bandwidth_mbps", "0"),
    ("download.max_concurrent_per_user", "3"),
    ("download.max_per_period", "0"),
    ("download.period_duration", "24h"),
    ("download.transcode_enabled", "false"),
    (DOWNLOAD_LOCAL_TRANSCODE_FALLBACK_SETTING_KEY, "true"),
    ("download.max_concurrent_prepares", "2"),
    ("download.artifact_max_bytes", "0"),
    (DOWNLOAD_ARTIFACT_CACHE_HOURS_SETTING_KEY, "72"),
    (DOWNLOAD_ARTIFACT_DISK_CEILING_SETTING_KEY, "85"),
    ("policy.editor_enabled", "false"),
    ("policy.eval_timeout_ms", "100"),
    ("policy.decision_log_verbosity", "digest"),
    ("policy.decision_log_scope_sample_rate", "50"),
    ("policy.decision_log_retention_days", "14"),
    ("email.enabled", "false"),
    ("email.smtp_port", "587"),
    ("email.smtp_security", "starttls"),
    ("email.from_name", "Silo"),
    ("notifications.release_events_enabled", "true"),
    ("notifications.fanout_enabled", "true"),
    ("notifications.ui_enabled", "true"),
    ("notifications.fanout.settle_seconds", "30"),
    ("notifications.fanout.max_series_burst", "3"),
    ("notifications.fanout.max_event_age_hours", "72"),
    ("notifications.retention.read_days", "90"),
    ("notifications.retention.unread_days", "180"),
    ("notifications.retention.event_days", "30"),
    ("notifications.webhooks_enabled", "false"),
    ("notifications.webhooks.max_per_profile", "10"),
    ("notifications.webhooks.allow_private_destinations", "false"),
    (
        "notifications.webhooks.deliveries_per_minute_per_profile",
        "60",
    ),
    ("notifications.email_enabled", "true"),
    ("notifications.email.allow_per_episode", "true"),
    ("notifications.email.digest_hour", "8"),
    ("notifications.discord_enabled", "false"),
    ("notifications.discord.allow_per_episode", "true"),
    ("notifications.discord.digest_hour", "8"),
    ("notifications.discord.poster_mode", "provider"),
    ("notifications.server_channels_enabled", "true"),
    ("notifications.server_channels.batch_seconds", "300"),
    ("notifications.server_channels.mention_requesters", "false"),
    ("notifications.web_push_enabled", "true"),
    ("notifications.apple_push_delivery_enabled", "true"),
    ("notifications.android_push_delivery_enabled", "true"),
    ("taskmanager.history_retention_days", "30"),
    ("taskmanager.history_keep_per_task", "1000"),
    ("autoscan.events_retention_days", "30"),
    ("media_servers.allow_private_destinations", "false"),
    ("opslog.capture_level", "info"),
    ("opslog.retention_days", "7"),
    ("opslog.cleanup_interval_minutes", "15"),
    ("opslog.max_rows", "1000000"),
    ("opslog.max_size_mb", "1024"),
    ("overlays.enabled", "true"),
    ("signup.enabled", "false"),
    (SETUP_COMPLETED_SETTING_KEY, "false"),
    ("password_reset.self_service_enabled", "false"),
    ("catalog.search.provider", "postgres"),
    ("catalog.search.meilisearch.index", "silo_media_items"),
    ("catalog.search.meilisearch.timeout_ms", "800"),
    ("catalog.search.meilisearch.matching_strategy", "last"),
    ("catalog.search.meilisearch.sync_batch_size", "500"),
    ("catalog.search.meilisearch.rebuild_batch_size", "5000"),
    ("catalog.search.meilisearch.rebuild_task_queue_depth", "4"),
    ("catalog.search.meilisearch.semantic_enabled", "false"),
    ("catalog.search.meilisearch.semantic_ratio", "0.5"),
    (
        "catalog.search.meilisearch.embedder",
        "silo_recommendations",
    ),
    ("catalog.search.meilisearch.binary_quantized", "false"),
    (PLAYBACK_KEYFRAME_PLAYLIST_SETTING_KEY, "false"),
    (PLAYBACK_BANDWIDTH_PROBE_AUTOMATIC_SETTING_KEY, "true"),
    (PLAYBACK_BANDWIDTH_PROBE_MAX_AGE_DAYS_SETTING_KEY, "7"),
];

fn defaults_map() -> &'static HashMap<&'static str, &'static str> {
    static M: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    M.get_or_init(|| ADMIN_SETTING_DEFAULTS.iter().copied().collect())
}

const LEGACY_ADMIN_SETTING_FALLBACKS: &[(&str, &str)] = &[
    ("s3.public_endpoint", "s3.operational_endpoint"),
    ("s3.public_read_endpoint", "s3.operational_public_endpoint"),
    ("s3.public_region", "s3.operational_region"),
    ("s3.public_path_style", "s3.operational_path_style"),
    ("s3.public_bucket", "s3.operational_bucket"),
    ("s3.public_key_prefix", "s3.operational_key_prefix"),
    ("s3.public_access_key", "s3.operational_access_key"),
    ("s3.public_secret_key", "s3.operational_secret_key"),
    ("s3.public_url_auth", "s3.operational_url_auth"),
    ("s3.public_token_secret", "s3.operational_token_secret"),
    ("s3.public_token_param", "s3.operational_token_param"),
    ("s3.public_token_ttl", "s3.operational_token_ttl"),
    ("s3.private_endpoint", "s3.operational_endpoint"),
    ("s3.private_region", "s3.operational_region"),
    ("s3.private_path_style", "s3.operational_path_style"),
    ("s3.private_bucket", "s3.operational_bucket"),
    ("s3.private_key_prefix", "s3.operational_key_prefix"),
    ("s3.private_access_key", "s3.operational_access_key"),
    ("s3.private_secret_key", "s3.operational_secret_key"),
    ("ai.chat_model", "subtitle_ai.chat_model"),
];

/// `EffectiveAdminSettings`: persisted values over the runtime defaults. An empty persisted value
/// means "use the default" for keys that have one.
pub fn effective_admin_settings(stored: &SettingsMap) -> SettingsMap {
    let defaults = defaults_map();
    let mut effective = SettingsMap::with_capacity(defaults.len() + stored.len());
    for (k, v) in ADMIN_SETTING_DEFAULTS {
        effective.insert((*k).to_owned(), (*v).to_owned());
    }
    for (key, value) in stored {
        if value.is_empty() && defaults.contains_key(key.as_str()) {
            continue;
        }
        effective.insert(key.clone(), value.clone());
    }
    for (canonical, legacy) in LEGACY_ADMIN_SETTING_FALLBACKS {
        if !m_get(stored, canonical).is_empty() {
            continue;
        }
        let value = m_get(stored, legacy);
        if !value.is_empty() {
            effective.insert((*canonical).to_owned(), value.to_owned());
        }
    }
    apply_legacy_positive_int_fallback(
        &mut effective,
        stored,
        "ai.max_concurrent_jobs",
        "subtitle_ai.max_concurrent_jobs",
    );
    effective
}

/// `AdminSettingEnabled`: a stored boolean as the Admin UI shows it.
pub fn admin_setting_enabled(key: &str, stored: &str) -> bool {
    let value = trim_space(stored);
    let value = if value.is_empty() {
        defaults_map().get(key).copied().unwrap_or("")
    } else {
        value
    };
    equal_fold(value, "true")
}

fn apply_legacy_positive_int_fallback(
    effective: &mut SettingsMap,
    stored: &SettingsMap,
    canonical: &str,
    legacy: &str,
) {
    let value = m_get(stored, canonical);
    if !value.is_empty() {
        match atoi(value) {
            Err(_) => return,
            Ok(parsed) if parsed > 0 => return,
            Ok(_) => {}
        }
    }
    let fallback = m_get(stored, legacy);
    if !fallback.is_empty() {
        effective.insert(canonical.to_owned(), fallback.to_owned());
        return;
    }
    if let Some(d) = defaults_map().get(canonical) {
        effective.insert(canonical.to_owned(), (*d).to_owned());
    }
}

const BOOL_KEYS: &[&str] = &[
    "metadata.cache_images",
    "playback.transcode_enabled",
    PLAYBACK_ALLOW_HEVC_ENCODING_SETTING_KEY,
    PLAYBACK_PREFER_LOWER_VERSION_TRANSCODE_SETTING_KEY,
    PLAYBACK_KEYFRAME_PLAYLIST_SETTING_KEY,
    PLAYBACK_BANDWIDTH_PROBE_AUTOMATIC_SETTING_KEY,
    CHAPTER_THUMBNAIL_SOFTWARE_TONE_MAP_SETTING_KEY,
    PLAYBACK_TRANSCODE_HARDWARE_TONE_MAP_SETTING_KEY,
    PLAYBACK_TRANSCODE_SOFTWARE_TONE_MAP_SETTING_KEY,
    CATALOG_SCOPE_VERSIONS_TO_LIBRARY_SETTING_KEY,
    ALLOW_4K_TRANSCODE_SETTING_KEY,
    TRANSCODE_THROTTLE_ENABLED_SETTING_KEY,
    "audiobookshelf_compat.enabled",
    "jellyfin_compat.enabled",
    "jellyfin_compat.web_enabled",
    "recommendations.enabled",
    "subtitle_ai.enabled",
    "subtitle_ai.transcribe_enabled",
    "metadata_ai.enabled",
    "subtitles.auto_sync",
    "download.enabled",
    "download.transcode_enabled",
    DOWNLOAD_LOCAL_TRANSCODE_FALLBACK_SETTING_KEY,
    "email.enabled",
    "signup.enabled",
    "password_reset.self_service_enabled",
    SETUP_COMPLETED_SETTING_KEY,
    "scanner.empty_trash_after_scan",
    "scanner.realtime_monitoring",
    "matcher.enable_tv_series_root_queue",
    "matcher.enable_tv_series_group_queue",
    "policy.editor_enabled",
    "overlays.enabled",
    "notifications.release_events_enabled",
    "notifications.fanout_enabled",
    "notifications.ui_enabled",
    "notifications.webhooks_enabled",
    "notifications.webhooks.allow_private_destinations",
    "media_servers.allow_private_destinations",
    "notifications.email_enabled",
    "notifications.email.allow_per_episode",
    "notifications.discord_enabled",
    "notifications.discord.allow_per_episode",
    "notifications.server_channels_enabled",
    "notifications.server_channels.mention_requesters",
    "notifications.web_push_enabled",
    "notifications.apple_push_delivery_enabled",
    "notifications.android_push_delivery_enabled",
    "catalog.search.meilisearch.semantic_enabled",
    "catalog.search.meilisearch.binary_quantized",
    "s3.public_path_style",
    "s3.private_path_style",
    "s3.user_db_path_style",
    AUTH_LOCAL_PASSWORD_LOGIN_SETTING_KEY,
    AUTH_EMAIL_AUTO_MATCH_SETTING_KEY,
    SERVER_LAN_DISCOVERY_SETTING_KEY,
];

const I32_MAX: i64 = i32::MAX as i64;

// The bounds of normalizeAdminInt keys, a table rather than the Go switch.
fn int_bounds(key: &str) -> Option<(i64, i64)> {
    Some(match key {
        "database.max_connections" => (1, 10000),
        "userdb.pool_max_open" => (1, 100000),
        "scanner.workers"
        | "matcher.workers"
        | "scanner.max_concurrent_libraries"
        | "scanner.max_concurrent_scoped" => (1, 1024),
        "matcher.batch_size" => (1, 100000),
        METADATA_IMAGE_WORKERS_SETTING_KEY => (0, 256),
        METADATA_PERSON_REFRESH_PER_MINUTE_SETTING_KEY => (1, 6000),
        MARKERS_DETECTION_WORKERS_SETTING_KEY => (1, 64),
        "playback.chapter_thumbnail_workers"
        | "playback.chapter_thumbnail_node_capacity"
        | "subtitles.sync_node_capacity" => (1, 1024),
        "playback.trickplay_interval_seconds" => (5, 60),
        PLAYBACK_BANDWIDTH_PROBE_MAX_AGE_DAYS_SETTING_KEY => (1, MAX_BANDWIDTH_PROBE_MAX_AGE_DAYS),
        "playback.trickplay_workers" => (1, 64),
        "playback.watched_threshold" => (1, 100),
        "playback.min_resume_threshold" => (1, 99),
        TRANSCODE_THROTTLE_SECONDS_SETTING_KEY => (60, 86400),
        "ai.max_concurrent_jobs" | "subtitle_ai.max_concurrent_jobs" => (1, 1024),
        "subtitle_ai.batch_size" => (1, 1000),
        "subtitle_ai.context_neighbors" => (0, 100),
        "subtitle_ai.asr_chunk_seconds" => (60, 600),
        "subtitle_ai.live_asr_chunk_seconds" => (15, 600),
        "subtitle_ai.transcribe_quota_jobs" => (0, I32_MAX),
        DOWNLOAD_ARTIFACT_CACHE_HOURS_SETTING_KEY => (0, MAX_DOWNLOAD_ARTIFACT_CACHE_HOURS),
        DOWNLOAD_ARTIFACT_DISK_CEILING_SETTING_KEY => (
            MIN_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT,
            MAX_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT,
        ),
        "policy.decision_log_scope_sample_rate" | "policy.decision_log_retention_days" => {
            (1, I32_MAX)
        }
        "policy.eval_timeout_ms" => (1, 60000),
        "email.smtp_port" => (1, 65535),
        "notifications.fanout.settle_seconds" => (0, 3600),
        "notifications.fanout.max_series_burst" => (1, 1000),
        "notifications.fanout.max_event_age_hours" => (1, 24 * 365),
        "notifications.retention.read_days"
        | "notifications.retention.unread_days"
        | "notifications.retention.event_days" => (1, 3650),
        "notifications.webhooks.max_per_profile" => (1, 100),
        "notifications.webhooks.deliveries_per_minute_per_profile" => (1, 10000),
        "notifications.email.digest_hour" | "notifications.discord.digest_hour" => (0, 23),
        "notifications.server_channels.batch_seconds" => (120, 3600),
        "catalog.search.meilisearch.timeout_ms" => (1, I32_MAX),
        "catalog.search.meilisearch.sync_batch_size" => (1, 10000),
        "catalog.search.meilisearch.rebuild_batch_size" => (1, 25000),
        "catalog.search.meilisearch.rebuild_task_queue_depth" => (1, 16),
        "taskmanager.history_retention_days" | "autoscan.events_retention_days" => (1, 3650),
        "taskmanager.history_keep_per_task" => (1, I32_MAX),
        "opslog.retention_days" | "opslog.cleanup_interval_minutes" => (1, I32_MAX),
        "s3.public_token_ttl" => (1, I32_MAX),
        _ => return None,
    })
}

fn int64_bounds(key: &str) -> Option<(i64, i64)> {
    Some(match key {
        "download.server_bandwidth_mbps" | "download.user_bandwidth_mbps" => {
            (0, 73_786_976_294_838)
        }
        "download.max_concurrent_per_user"
        | "download.max_per_period"
        | "download.max_concurrent_prepares"
        | "download.artifact_max_bytes" => (0, i64::MAX),
        "opslog.max_rows" | "opslog.max_size_mb" => (1, i64::MAX),
        _ => return None,
    })
}

fn enum_values(key: &str) -> Option<&'static [&'static str]> {
    Some(match key {
        AUTH_PROVIDER_RECHECK_OUTAGE_POLICY_SETTING_KEY => {
            &[AUTH_RECHECK_FAIL_OPEN, AUTH_RECHECK_FAIL_CLOSED]
        }
        ACCESS_UNRATED_CONTENT_SETTING_KEY => {
            &[ACCESS_UNRATED_CONTENT_HIDE, ACCESS_UNRATED_CONTENT_ALLOW]
        }
        "artwork.storage_backend" => &["auto", "local", "s3"],
        "server.log_level" => &["debug", "info", "warn", "error"],
        "opslog.capture_level" => &["debug", "info", "warn", "warning", "error"],
        "userdb.backend" => &["postgres", "sqlite"],
        "playback.hw_accel" => &["auto", "qsv", "vaapi", "nvenc", "videotoolbox", "none"],
        PLAYBACK_ROUTING_REMUX_EXECUTION_SETTING_KEY
        | PLAYBACK_ROUTING_VIDEO_TRANSCODE_EXECUTION_SETTING_KEY => &[
            PLAYBACK_EXECUTION_PREFER_WORKER,
            PLAYBACK_EXECUTION_PREFER_TRANSCODE,
            PLAYBACK_EXECUTION_WORKER_ONLY,
            PLAYBACK_EXECUTION_PREFER_API,
            PLAYBACK_EXECUTION_API_ONLY,
        ],
        PLAYBACK_ROUTING_DIRECT_PLAY_EGRESS_SETTING_KEY
        | PLAYBACK_ROUTING_REMUX_EGRESS_SETTING_KEY
        | PLAYBACK_ROUTING_VIDEO_TRANSCODE_EGRESS_SETTING_KEY => &[
            PLAYBACK_EGRESS_PREFER_PROXY,
            PLAYBACK_EGRESS_PROXY_ONLY,
            PLAYBACK_EGRESS_PREFER_API,
            PLAYBACK_EGRESS_API_ONLY,
        ],
        "playback.chapter_thumbnail_execution"
        | "playback.trickplay_execution"
        | "subtitles.sync_execution" => {
            &["local", "prefer_transcode_nodes", "transcode_nodes_only"]
        }
        "playback.chapter_thumbnail_hdr_policy" => &["disabled", "best_effort"],
        "metadata_ai.on_view" => &["off", "button", "auto"],
        "ai.auth_mode" => &["api_key", AI_AUTH_MODE_CHATGPT],
        "ai.reasoning_effort" => &[
            "", "none", "minimal", "low", "medium", "high", "xhigh", "max",
        ],
        AI_SERVICE_TIER_SETTING_KEY => &["", "priority", "ultrafast"],
        "subtitle_ai.transcribe_quota_period" => &["day", "week", "month"],
        "policy.decision_log_verbosity" => &["digest", "verbose"],
        "email.smtp_security" => &["starttls", "tls", "none"],
        "notifications.discord.poster_mode" => &["off", "provider", "server"],
        "catalog.search.provider" => &["postgres", "meilisearch"],
        "catalog.search.meilisearch.matching_strategy" => &["last", "all"],
        "s3.public_url_auth" => &["", "presigned", "public", "cloudflare_token"],
        _ => return None,
    })
}

/// `NormalizeAdminSetting`: validates and canonicalizes settings shared by the generic single and
/// batch Admin endpoints.
pub fn normalize_admin_setting(key: &str, raw: &str) -> Result<String, String> {
    let value = trim_space(raw);

    if BOOL_KEYS.contains(&key) {
        return normalize_admin_bool(key, value);
    }
    if let Some((min, max)) = int_bounds(key) {
        return normalize_admin_int(key, value, min, max);
    }
    if let Some((min, max)) = int64_bounds(key) {
        return normalize_admin_int64(key, value, min, max);
    }
    if let Some(allowed) = enum_values(key) {
        return normalize_admin_enum(key, value, allowed);
    }

    match key {
        AUTH_PROVIDER_RECHECK_INTERVAL_SETTING_KEY => match parse_duration(value) {
            Ok(p) if p.0 >= 5 * Duration::MINUTE.0 && p.0 <= 30 * 24 * Duration::HOUR.0 => {
                Ok(value.to_owned())
            }
            _ => Err(format!("{key} must be a duration between 5m and 30d")),
        },
        CATALOG_EXTRA_RATING_SOURCES_SETTING_KEY => {
            let (sources, malformed) = split_rating_source_list(value);
            if !malformed.is_empty() {
                return Err(format!(
                    "{key}: {} is not a rating source name",
                    quote(&malformed)
                ));
            }
            Ok(sources.join(","))
        }
        "artwork.local_path" => {
            if value.is_empty() || !filepath::is_abs(value) {
                return Err(format!("{key} must be an absolute path"));
            }
            Ok(filepath::clean(value))
        }
        PREVIEW_IMAGE_WIDTH_SETTING_KEY => {
            let normalized =
                normalize_admin_int(key, value, MIN_PREVIEW_IMAGE_WIDTH, MAX_PREVIEW_IMAGE_WIDTH)?;
            if atoi(&normalized).unwrap_or(0) % 2 != 0 {
                return Err(format!("{key} must be an even number of pixels"));
            }
            Ok(normalized)
        }
        PLAYBACK_SEGMENT_RETENTION_SETTING_KEY => {
            let normalized = normalize_admin_int(key, value, 0, 86400)?;
            let seconds = atoi(&normalized).unwrap_or(0);
            if seconds != 0 && seconds < 120 {
                return Err(format!("{key} must be 0 or between 120 and 86400"));
            }
            Ok(normalized)
        }
        "recommendations.taste_decay_half_life_days" => {
            normalize_admin_float(key, value, 5e-324, f64::MAX)
        }
        "recommendations.diversity_lambda" | "catalog.search.meilisearch.semantic_ratio" => {
            normalize_admin_float(key, value, 0.0, 1.0)
        }
        "auth.access_token_expiry"
        | "auth.refresh_token_expiry"
        | "userdb.idle_timeout"
        | "download.period_duration"
        | "jellyfin_compat.session_ttl"
        | "jellyfin_compat.playback_session_ttl"
        | "s3.metadata_presign_expiry"
        | "recommendations.embeddings_job_timeout" => match parse_duration(value) {
            Ok(p) if p.0 > 0 => Ok(value.to_owned()),
            _ => Err(format!("{key} must be a positive duration")),
        },
        "scanner.file_removal_grace" => {
            if parse_duration(value).is_err() {
                return Err(format!("{key} must be a duration"));
            }
            Ok(value.to_owned())
        }
        METADATA_FALLBACK_LANGUAGE_SETTING_KEY => {
            let lowered = to_lower(value);
            if lowered.is_empty()
                || lowered == METADATA_FALLBACK_ORIGINAL
                || (lowered.len() == 2 && crate::lang::registered_tag(&lowered) == lowered)
            {
                return Ok(lowered);
            }
            Err(format!(
                "{key} must be a two-letter ISO 639-1 code or {}",
                quote(METADATA_FALLBACK_ORIGINAL)
            ))
        }
        "recommendations.embeddings_cron"
        | "recommendations.taste_profiles_cron"
        | "recommendations.cowatch_cron"
        | "recommendations.recommendations_cron" => match crate::cron::parse_standard(value) {
            Ok(_) => Ok(value.to_owned()),
            Err(e) => Err(format!(
                "{key} must be a valid five-field cron expression: {e}"
            )),
        },
        LEGACY_AI_TEXT_URL_SETTING
        | LEGACY_AI_TEXT_KEY_SETTING
        | LEGACY_AI_SPEECH_URL_SETTING
        | LEGACY_AI_SPEECH_KEY_SETTING
        | LEGACY_SUBTITLE_URL_SETTING
        | LEGACY_SUBTITLE_KEY_SETTING => Err(format!(
            "{key} was replaced by AI providers; connect the provider in AI Services"
        )),
        LEGACY_EMBEDDING_URL_SETTING
        | LEGACY_EMBEDDING_TOKEN_SETTING
        | LEGACY_OPENAI_EMBEDDING_MODEL
        | LEGACY_OPENAI_EMBEDDING_TOKEN
        | LEGACY_EMBEDDING_PROVIDER_SETTING => Err(format!(
            "{key} was replaced by AI providers; choose the embedding provider on Recommendations"
        )),
        AI_TEXT_PROVIDER_SETTING_KEY
        | AI_SPEECH_PROVIDER_SETTING_KEY
        | EMBEDDING_PROVIDER_SETTING_KEY => Ok(value.to_owned()),
        "server.public_url"
        | "jellyfin_compat.public_url"
        | "s3.public_endpoint"
        | "s3.public_read_endpoint"
        | "s3.private_endpoint"
        | "s3.user_db_endpoint"
        | "catalog.search.meilisearch.url" => normalize_admin_url(key, value),
        SERVER_LOCAL_URL_SETTING_KEY => normalize_local_url(value),
        "redis.url" => normalize_redis_url(value),
        REDIS_DB_SETTING_KEY => normalize_redis_db(value),
        "theme.catalog_url" => normalize_admin_theme_url(key, value),
        "email.from_address" => {
            if value.is_empty() {
                return Ok(String::new());
            }
            if !mail_address_equals_input(value) {
                return Err(format!("{key} must be a valid email address"));
            }
            Ok(value.to_owned())
        }
        DASHBOARD_HIDDEN_ATTENTION_SETTING_KEY => normalize_dashboard_hidden_attention(value),
        "defaults.card_overlays" | "opslog.bucket_policies" | "ui.admin_theme_vars" => {
            if value.is_empty() {
                return Ok(String::new());
            }
            let node = crate::gojson::parse(value.as_bytes())
                .map_err(|e| format!("{key} must be valid JSON: {e}"))?;
            if let Some(n) = out_of_range_number(&node.value) {
                return Err(format!(
                    "{key} must be valid JSON: json: cannot unmarshal number {n} into Go value of type float64"
                ));
            }
            Ok(value.to_owned())
        }
        _ => {
            if let Some(def) = admin_default_definition(key) {
                return normalize_admin_default(def, value);
            }
            Ok(raw.to_owned())
        }
    }
}

// json.Unmarshal into `any` makes every number a float64, and refuses one too large for it.
fn out_of_range_number(v: &crate::gojson::Value) -> Option<&str> {
    use crate::gojson::Value;
    match v {
        Value::Number(n) => parse_float(n).is_err().then_some(n.as_str()),
        Value::Array(items) => items.iter().find_map(|i| out_of_range_number(&i.value)),
        Value::Object(members) => members
            .iter()
            .find_map(|(_, m)| out_of_range_number(&m.value)),
        _ => None,
    }
}

fn admin_default_definition(key: &str) -> Option<&'static Definition> {
    settings::load().ok()?.admin_default_for(key)
}

fn normalize_admin_default(def: &Definition, value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let schemas = settings::object_schemas().ok_or("settings contract failed to load")?;
    match def.value_schema.normalize_value(value.as_bytes(), schemas) {
        Ok(n) => Ok(String::from_utf8_lossy(&n).into_owned()),
        Err(e) => Err(format!(
            "{} must be a valid {} value: {e}",
            settings::admin_default_setting_key(&def.key),
            def.key
        )),
    }
}

/// `AdminSettingsCapabilities`: durable bootstrap configuration absent from the flat settings map.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdminSettingsCapabilities {
    pub redis_bootstrap_available: bool,
}

/// `ValidateAdminSettings`.
pub fn validate_admin_settings(values: &SettingsMap) -> Result<(), String> {
    validate_admin_settings_with_capabilities(values, AdminSettingsCapabilities::default())
}

/// `ValidateAdminSettingsWithCapabilities`: the complete prospective settings snapshot.
pub fn validate_admin_settings_with_capabilities(
    values: &SettingsMap,
    capabilities: AdminSettingsCapabilities,
) -> Result<(), String> {
    load_from_db(values)?;
    let effective = effective_admin_settings(values);

    let access = match parse_duration(m_get(&effective, "auth.access_token_expiry")) {
        Ok(d) if d.0 > 0 => d,
        _ => return Err("auth.access_token_expiry must be a positive duration".to_owned()),
    };
    let refresh = match parse_duration(m_get(&effective, "auth.refresh_token_expiry")) {
        Ok(d) if d.0 > 0 => d,
        _ => return Err("auth.refresh_token_expiry must be a positive duration".to_owned()),
    };
    if refresh.0 < access.0 {
        return Err(
            "auth.refresh_token_expiry must be greater than or equal to auth.access_token_expiry"
                .to_owned(),
        );
    }

    let watched = atoi(m_get(&effective, "playback.watched_threshold")).unwrap_or(0);
    if watched > 0 {
        let resume = atoi(m_get(&effective, "playback.min_resume_threshold")).unwrap_or(0);
        if resume >= watched {
            return Err(
                "playback.min_resume_threshold must be less than playback.watched_threshold"
                    .to_owned(),
            );
        }
    }

    validate_reasoning(
        m_get(&effective, "ai.chat_model"),
        m_get(&effective, "ai.reasoning_effort"),
    )?;
    validate_ai_provider_bindings(&effective)?;
    for prefix in ["s3.public", "s3.private"] {
        let get =
            |suffix: &str| trim_space(m_get(&effective, &format!("{prefix}_{suffix}"))).to_owned();
        if get("endpoint").is_empty() != get("bucket").is_empty() {
            return Err(format!(
                "{} endpoint and bucket must be configured together",
                prefix.replace('.', " ")
            ));
        }
        if get("access_key").is_empty() != get("secret_key").is_empty() {
            return Err(format!(
                "{} access key and secret key must be configured together",
                prefix.replace('.', " ")
            ));
        }
    }

    validate_artwork_storage_settings(&effective)?;

    match m_get(&effective, "s3.public_url_auth") {
        "" | "presigned" => {}
        mode @ ("public" | CLOUDFLARE_URL_MODE) => {
            if trim_space(m_get(&effective, "s3.public_read_endpoint")).is_empty() {
                return Err(format!(
                    "s3.public_read_endpoint is required for {mode} URL authentication"
                ));
            }
            if mode == CLOUDFLARE_URL_MODE
                && trim_space(m_get(&effective, "s3.public_token_secret")).is_empty()
            {
                return Err(
                    "s3.public_token_secret is required for Cloudflare Token URL authentication"
                        .to_owned(),
                );
            }
        }
        _ => {
            return Err(
                "s3.public_url_auth must be presigned, public, or cloudflare_token".to_owned(),
            );
        }
    }
    if m_get(&effective, "email.enabled") == "true" {
        if trim_space(m_get(&effective, "email.smtp_host")).is_empty() {
            return Err("email.smtp_host is required when email is enabled".to_owned());
        }
        if trim_space(m_get(&effective, "email.from_address")).is_empty() {
            return Err("email.from_address is required when email is enabled".to_owned());
        }
    }
    if trim_space(m_get(&effective, "watchsync.simkl.client_id")).is_empty()
        != trim_space(m_get(&effective, "watchsync.simkl.client_secret")).is_empty()
    {
        return Err(
            "watchsync.simkl client ID and client secret must be configured together".to_owned(),
        );
    }
    validate_redis_rate_limit_transport(&effective, capabilities.redis_bootstrap_available)
}

/// `reasoning.Validate`: an empty effort is the provider's default.
pub fn validate_reasoning(model: &str, effort: &str) -> Result<(), String> {
    const LEVELS: [&str; 7] = ["none", "minimal", "low", "medium", "high", "xhigh", "max"];
    if effort.is_empty() {
        return Ok(());
    }
    if !LEVELS.contains(&effort) {
        return Err(format!("unsupported reasoning effort {}", quote(effort)));
    }
    if !reasoning_levels_for_model(model).contains(&effort) {
        return Err(format!(
            "model {} does not support reasoning effort {}",
            quote(model),
            quote(effort)
        ));
    }
    Ok(())
}

/// `reasoning.ForModel`: known supported levels, or the whole vocabulary for a custom model.
pub fn reasoning_levels_for_model(model: &str) -> Vec<&'static str> {
    let lowered = to_lower(model);
    let m = lowered.strip_prefix("openai/").unwrap_or(&lowered);
    let starts = |p: &str| m.starts_with(p);
    if m == "chat-latest"
        || (starts("gpt-") && m.ends_with("-chat-latest"))
        || starts("gpt-4")
        || starts("gpt-3")
    {
        return vec![];
    }
    if starts("gpt-6.1-sol") || starts("gpt-6-astra") {
        return vec!["low", "medium", "high", "xhigh", "max"];
    }
    if starts("gpt-6-sol") || starts("gpt-6-luna") || starts("gpt-5.6") {
        return vec!["none", "low", "medium", "high", "xhigh", "max"];
    }
    if starts("gpt-5-pro") {
        return vec!["high"];
    }
    if starts("gpt-5.2-pro") || starts("gpt-5.4-pro") || starts("gpt-5.5-pro") {
        return vec!["medium", "high", "xhigh"];
    }
    if starts("gpt-5.2") || starts("gpt-5.4") || starts("gpt-5.5") {
        return vec!["none", "low", "medium", "high", "xhigh"];
    }
    if starts("gpt-5.1") {
        return vec!["none", "low", "medium", "high"];
    }
    if m == "gpt-5" || starts("gpt-5-mini") || starts("gpt-5-nano") || starts("gpt-5-20") {
        return vec!["minimal", "low", "medium", "high"];
    }
    if starts("o1") || starts("o3") || starts("o4") {
        return vec!["low", "medium", "high"];
    }
    vec!["none", "minimal", "low", "medium", "high", "xhigh", "max"]
}

/// `ValidateRedisRateLimitTransport`: a persisted Redis limiter must have a usable transport after a
/// restart.
pub fn validate_redis_rate_limit_transport(
    values: &SettingsMap,
    redis_bootstrap_available: bool,
) -> Result<(), String> {
    let effective = effective_admin_settings(values);
    let redis_url = normalize_redis_url(m_get(&effective, "redis.url"))?;
    if equal_fold(trim_space(m_get(&effective, "ratelimit.backend")), "redis")
        && redis_url.is_empty()
        && !redis_bootstrap_available
    {
        return Err(
            "redis.url or a bootstrap REDIS_URL is required when ratelimit.backend is redis"
                .to_owned(),
        );
    }
    Ok(())
}

/// `ValidateArtworkStorageSettings`.
pub fn validate_artwork_storage_settings(effective: &SettingsMap) -> Result<(), String> {
    if to_lower(trim_space(m_get(effective, "artwork.storage_backend"))) != "s3" {
        return Ok(());
    }
    if trim_space(m_get(effective, "s3.public_bucket")).is_empty() {
        return Err("artwork.storage_backend s3 requires s3.public_bucket".to_owned());
    }
    Ok(())
}

fn normalize_admin_bool(key: &str, value: &str) -> Result<String, String> {
    match parse_bool(&to_lower(value)) {
        Ok(b) => Ok(b.to_string()),
        Err(_) => Err(format!("{key} must be true or false")),
    }
}

fn normalize_admin_int(key: &str, value: &str, min: i64, max: i64) -> Result<String, String> {
    match atoi(value) {
        Ok(p) if p >= min && p <= max => Ok(p.to_string()),
        _ => Err(format!("{key} must be an integer between {min} and {max}")),
    }
}

fn normalize_admin_int64(key: &str, value: &str, min: i64, max: i64) -> Result<String, String> {
    match parse_int(value, 10, 64) {
        Ok(p) if p >= min && p <= max => Ok(p.to_string()),
        _ => Err(format!("{key} must be an integer between {min} and {max}")),
    }
}

fn normalize_admin_float(key: &str, value: &str, min: f64, max: f64) -> Result<String, String> {
    match parse_float(value) {
        Ok(p) if !p.is_nan() && !p.is_infinite() && p >= min && p <= max => {
            Ok(format_float(p, b'f', -1, 64))
        }
        _ => Err(format!(
            "{key} must be a number between {} and {}",
            fmt_g(min),
            fmt_g(max)
        )),
    }
}

fn normalize_admin_enum(key: &str, value: &str, allowed: &[&str]) -> Result<String, String> {
    let normalized = to_lower(value);
    if allowed.contains(&normalized.as_str()) {
        return Ok(normalized);
    }
    Err(format!("{key} must be one of: {}", allowed.join(", ")))
}

fn normalize_dashboard_hidden_attention(value: &str) -> Result<String, String> {
    use crate::gojson::Value;
    if value.is_empty() {
        return Ok(String::new());
    }
    let not_strings =
        || format!("{DASHBOARD_HIDDEN_ATTENTION_SETTING_KEY} must be a JSON array of strings");
    let node = crate::gojson::parse(value.as_bytes()).map_err(|_| not_strings())?;
    let Value::Array(items) = &node.value else {
        return Err(not_strings());
    };
    let mut kept: Vec<String> = Vec::with_capacity(items.len());
    let mut seen = HashSet::new();
    for element in items {
        let Value::String(id) = &element.value else {
            return Err(not_strings());
        };
        let id = trim_space(id);
        if id.is_empty() || seen.contains(id) {
            continue;
        }
        if id.len() > MAX_DASHBOARD_HIDDEN_ATTENTION_ID_LEN {
            return Err(format!(
                "{DASHBOARD_HIDDEN_ATTENTION_SETTING_KEY} ids must be at most {MAX_DASHBOARD_HIDDEN_ATTENTION_ID_LEN} characters"
            ));
        }
        seen.insert(id.to_owned());
        kept.push(id.to_owned());
    }
    if kept.len() > MAX_DASHBOARD_HIDDEN_ATTENTION_IDS {
        return Err(format!(
            "{DASHBOARD_HIDDEN_ATTENTION_SETTING_KEY} may list at most {MAX_DASHBOARD_HIDDEN_ATTENTION_IDS} ids"
        ));
    }
    if kept.is_empty() {
        return Ok(String::new());
    }
    silo_gocompat::json::marshal_to_string(&kept).map_err(|e| e.to_string())
}

fn normalize_local_url(value: &str) -> Result<String, String> {
    let normalized = normalize_admin_url(SERVER_LOCAL_URL_SETTING_KEY, value)?;
    if normalized.is_empty() {
        return Ok(normalized);
    }
    let parsed = Url::parse(&normalized).map_err(|_| {
        format!("{SERVER_LOCAL_URL_SETTING_KEY} must include a URL scheme and host")
    })?;
    if !parsed.path.is_empty()
        || !parsed.raw_query.is_empty()
        || !parsed.fragment.is_empty()
        || parsed.user.is_some()
    {
        return Err(format!(
            "{SERVER_LOCAL_URL_SETTING_KEY} must be a scheme, host and optional port, such as http://192.168.1.20:8080"
        ));
    }
    Ok(normalized)
}

/// `normalizeAdminURL`.
pub(crate) fn normalize_admin_url(key: &str, value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let parsed = match Url::parse(value) {
        Ok(p) if !p.scheme.is_empty() && !p.host.is_empty() => p,
        _ => return Err(format!("{key} must include a URL scheme and host")),
    };
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return Err(format!("{key} must use http or https"));
    }
    Ok(value.trim_end_matches('/').to_owned())
}
