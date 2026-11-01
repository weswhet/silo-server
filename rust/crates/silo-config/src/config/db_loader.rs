//! `LoadFromDB`: a `Config` from a map of `server_settings` rows.

use super::*;
use crate::goparse::{atoi, parse_bool, parse_float, parse_int};
use silo_gocompat::filepath;
use silo_gocompat::strconv::quote;
use silo_gocompat::strings::{to_lower, trim_space};
use silo_gocompat::time::Duration;

pub(crate) fn string_or(m: &SettingsMap, key: &str, fallback: &str) -> String {
    match m.get(key) {
        Some(v) if !v.is_empty() => v.clone(),
        _ => fallback.to_owned(),
    }
}

fn first_configured_string(m: &SettingsMap, fallback: &str, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = m.get(*key)
            && !v.is_empty()
        {
            return v.clone();
        }
    }
    fallback.to_owned()
}

fn int_or(m: &SettingsMap, key: &str, fallback: i64) -> Result<i64, String> {
    match m.get(key) {
        Some(v) if !v.is_empty() => {
            atoi(v).map_err(|e| format!("invalid int for {}: {e}", quote(key)))
        }
        _ => Ok(fallback),
    }
}

fn bool_or(m: &SettingsMap, key: &str, fallback: bool) -> Result<bool, String> {
    match m.get(key) {
        Some(v) if !v.is_empty() => {
            parse_bool(v).map_err(|e| format!("invalid bool for {}: {e}", quote(key)))
        }
        _ => Ok(fallback),
    }
}

fn jellyfin_compat_enabled_or_legacy_default(m: &SettingsMap) -> Result<bool, String> {
    if let Some(v) = m.get("jellyfin_compat.enabled")
        && !v.is_empty()
    {
        return parse_bool(v)
            .map_err(|e| format!("invalid bool for {}: {e}", quote("jellyfin_compat.enabled")));
    }
    Ok(!string_or(m, "jellyfin_compat.listen", ":8096").is_empty())
}

fn first_configured_bool(m: &SettingsMap, fallback: bool, keys: &[&str]) -> Result<bool, String> {
    for key in keys {
        if let Some(v) = m.get(*key)
            && !v.is_empty()
        {
            return parse_bool(v).map_err(|e| format!("invalid bool for {}: {e}", quote(key)));
        }
    }
    Ok(fallback)
}

fn int64_or(m: &SettingsMap, key: &str, fallback: i64) -> Result<i64, String> {
    match m.get(key) {
        Some(v) if !v.is_empty() => {
            parse_int(v, 10, 64).map_err(|e| format!("invalid int64 for {}: {e}", quote(key)))
        }
        _ => Ok(fallback),
    }
}

fn first_configured_int(m: &SettingsMap, fallback: i64, keys: &[&str]) -> Result<i64, String> {
    for key in keys {
        if let Some(v) = m.get(*key)
            && !v.is_empty()
        {
            return atoi(v).map_err(|e| format!("invalid int for {}: {e}", quote(key)));
        }
    }
    Ok(fallback)
}

fn float_or(m: &SettingsMap, key: &str, fallback: f64) -> Result<f64, String> {
    match m.get(key) {
        Some(v) if !v.is_empty() => {
            parse_float(v).map_err(|e| format!("invalid float for {}: {e}", quote(key)))
        }
        _ => Ok(fallback),
    }
}

fn duration_or(m: &SettingsMap, key: &str, fallback: Duration) -> Result<Duration, String> {
    match m.get(key) {
        Some(v) if !v.is_empty() => {
            parse_duration(v).map_err(|e| format!("invalid duration for {}: {e}", quote(key)))
        }
        _ => Ok(fallback),
    }
}

const fn hours(n: i64) -> Duration {
    Duration(n * Duration::HOUR.0)
}

const QUOTA_PERIOD_DAY: &str = "day";

fn valid_quota_period(p: &str) -> bool {
    matches!(p, "day" | "week" | "month")
}

/// `LoadFromDB`: missing or empty keys fall back to the runtime defaults.
pub fn load_from_db(m: &SettingsMap) -> Result<Config, String> {
    let mut cfg = Config::default();

    cfg.server.listen = string_or(m, "server.listen", ":8080");
    cfg.server.mode = string_or(m, "server.mode", "integrated");
    cfg.server.log_level = string_or(m, "server.log_level", "info");
    cfg.server.log_format = string_or(m, "server.log_format", "text");
    cfg.server.log_quiet = string_or(m, "server.log_quiet", "");

    cfg.database.url = string_or(m, "database.url", "");
    cfg.database.max_connections = int_or(m, "database.max_connections", 20)?;

    let public = &mut cfg.s3.public;
    public.bucket.endpoint =
        first_configured_string(m, "", &["s3.public_endpoint", "s3.operational_endpoint"]);
    public.read_endpoint = first_configured_string(
        m,
        "",
        &["s3.public_read_endpoint", "s3.operational_public_endpoint"],
    );
    public.bucket.region =
        first_configured_string(m, "", &["s3.public_region", "s3.operational_region"]);
    public.bucket.path_style = first_configured_bool(
        m,
        true,
        &["s3.public_path_style", "s3.operational_path_style"],
    )?;
    public.bucket.bucket =
        first_configured_string(m, "", &["s3.public_bucket", "s3.operational_bucket"]);
    public.bucket.key_prefix = first_configured_string(
        m,
        "",
        &["s3.public_key_prefix", "s3.operational_key_prefix"],
    );
    public.bucket.access_key = first_configured_string(
        m,
        "",
        &["s3.public_access_key", "s3.operational_access_key"],
    );
    public.bucket.secret_key = first_configured_string(
        m,
        "",
        &["s3.public_secret_key", "s3.operational_secret_key"],
    );
    public.url_auth =
        first_configured_string(m, "", &["s3.public_url_auth", "s3.operational_url_auth"]);
    public.token_secret = first_configured_string(
        m,
        "",
        &["s3.public_token_secret", "s3.operational_token_secret"],
    );
    public.token_param = first_configured_string(
        m,
        "",
        &["s3.public_token_param", "s3.operational_token_param"],
    );
    public.token_ttl =
        first_configured_int(m, 0, &["s3.public_token_ttl", "s3.operational_token_ttl"])?;
    cfg.s3.metadata_presign_expiry = duration_or(m, "s3.metadata_presign_expiry", hours(4))?;

    let private = &mut cfg.s3.private;
    private.endpoint =
        first_configured_string(m, "", &["s3.private_endpoint", "s3.operational_endpoint"]);
    private.region =
        first_configured_string(m, "", &["s3.private_region", "s3.operational_region"]);
    private.path_style = first_configured_bool(
        m,
        true,
        &["s3.private_path_style", "s3.operational_path_style"],
    )?;
    private.bucket =
        first_configured_string(m, "", &["s3.private_bucket", "s3.operational_bucket"]);
    private.key_prefix = first_configured_string(
        m,
        "",
        &["s3.private_key_prefix", "s3.operational_key_prefix"],
    );
    private.access_key = first_configured_string(
        m,
        "",
        &["s3.private_access_key", "s3.operational_access_key"],
    );
    private.secret_key = first_configured_string(
        m,
        "",
        &["s3.private_secret_key", "s3.operational_secret_key"],
    );

    let user_db = &mut cfg.s3.user_db;
    user_db.endpoint = string_or(m, "s3.user_db_endpoint", "");
    user_db.region = string_or(m, "s3.user_db_region", "");
    user_db.path_style = bool_or(m, "s3.user_db_path_style", true)?;
    user_db.bucket = string_or(m, "s3.user_db_bucket", "");
    user_db.key_prefix = string_or(m, "s3.user_db_key_prefix", "");
    user_db.access_key = string_or(m, "s3.user_db_access_key", "");
    user_db.secret_key = string_or(m, "s3.user_db_secret_key", "");

    cfg.client_ip.trusted_proxies = string_or(m, "clientip.trusted_proxies", "");
    cfg.server.public_url = string_or(m, "server.public_url", "");
    cfg.server.local_url = string_or(m, SERVER_LOCAL_URL_SETTING_KEY, "");
    cfg.server.lan_discovery = bool_or(m, SERVER_LAN_DISCOVERY_SETTING_KEY, true)?;

    cfg.tmdb_api_key = string_or(m, "tmdb.api_key", "");
    cfg.mdblist_api_key = string_or(m, "mdblist.api_key", "");

    cfg.user_db.backend = string_or(m, "userdb.backend", "postgres");
    cfg.user_db.pool_max_open = int_or(m, "userdb.pool_max_open", 500)?;
    cfg.user_db.idle_timeout = duration_or(m, "userdb.idle_timeout", hours(12))?;
    cfg.user_db.litestream_sync = duration_or(m, "userdb.litestream_sync", Duration::SECOND)?;
    cfg.user_db.stale_grace_seconds = int_or(m, "userdb.stale_grace_seconds", 120)?;

    cfg.scanner.workers = int_or(m, "scanner.workers", 8)?;
    cfg.scanner.max_concurrent_libraries = int_or(m, "scanner.max_concurrent_libraries", 1)?;
    cfg.scanner.max_concurrent_scoped = int_or(m, "scanner.max_concurrent_scoped", 2)?;
    cfg.scanner.empty_trash_after_scan = bool_or(m, "scanner.empty_trash_after_scan", true)?;
    let mut file_removal_grace = duration_or(m, "scanner.file_removal_grace", hours(24))?;
    if file_removal_grace.0 < 0 {
        tracing::warn!(value = %m_get(m, "scanner.file_removal_grace"),
            "negative scanner.file_removal_grace setting; missing files will be deleted immediately");
        file_removal_grace = Duration(0);
    }
    cfg.scanner.file_removal_grace = file_removal_grace;
    cfg.scanner.realtime_monitoring = bool_or(m, "scanner.realtime_monitoring", true)?;

    cfg.matcher.workers = int_or(m, "matcher.workers", 8)?;
    cfg.matcher.batch_size = int_or(m, "matcher.batch_size", 500)?;
    let mut root_queue = bool_or(m, "matcher.enable_tv_series_root_queue", true)?;
    if !root_queue {
        root_queue = bool_or(m, "matcher.enable_tv_series_group_queue", false)?;
    }
    cfg.matcher.enable_tv_series_root_queue = root_queue;

    cfg.artwork.storage_backend = string_or(m, "artwork.storage_backend", "auto");
    cfg.artwork.local_path = string_or(m, "artwork.local_path", "/var/lib/silo/artwork");

    cfg.metadata.cache_images = bool_or(m, "metadata.cache_images", true)?;
    cfg.metadata.image_workers = int_or(m, METADATA_IMAGE_WORKERS_SETTING_KEY, 0)?;
    cfg.metadata.person_refresh_per_minute =
        int_or(m, METADATA_PERSON_REFRESH_PER_MINUTE_SETTING_KEY, 120)?;
    cfg.metadata.fallback_language =
        to_lower(&string_or(m, METADATA_FALLBACK_LANGUAGE_SETTING_KEY, "en"));
    if cfg.metadata.fallback_language == METADATA_FALLBACK_ORIGINAL {
        cfg.metadata.fallback_language = String::new();
    }
    cfg.markers.detection_workers = int_or(m, MARKERS_DETECTION_WORKERS_SETTING_KEY, 1)?;

    cfg.playback.ffmpeg_path = string_or(m, "playback.ffmpeg_path", "");
    cfg.playback.transcode_dir =
        string_or(m, PLAYBACK_TRANSCODE_DIR_SETTING_KEY, DEFAULT_TRANSCODE_DIR);
    let segment_retention = int_or(m, PLAYBACK_SEGMENT_RETENTION_SETTING_KEY, 600)?;
    if segment_retention != 0 && !(120..=86400).contains(&segment_retention) {
        return Err(format!(
            "{PLAYBACK_SEGMENT_RETENTION_SETTING_KEY} must be 0 or between 120 and 86400"
        ));
    }
    cfg.playback.segment_retention_seconds = segment_retention;
    cfg.playback.keyframe_playlist = bool_or(m, PLAYBACK_KEYFRAME_PLAYLIST_SETTING_KEY, false)?;
    cfg.playback.automatic_bandwidth_probe_off =
        !bool_or(m, PLAYBACK_BANDWIDTH_PROBE_AUTOMATIC_SETTING_KEY, true)?;
    let probe_days = int_or(
        m,
        PLAYBACK_BANDWIDTH_PROBE_MAX_AGE_DAYS_SETTING_KEY,
        DEFAULT_BANDWIDTH_PROBE_MAX_AGE_DAYS,
    )?;
    if !(1..=MAX_BANDWIDTH_PROBE_MAX_AGE_DAYS).contains(&probe_days) {
        return Err(format!(
            "{PLAYBACK_BANDWIDTH_PROBE_MAX_AGE_DAYS_SETTING_KEY} must be between 1 and {MAX_BANDWIDTH_PROBE_MAX_AGE_DAYS}"
        ));
    }
    cfg.playback.bandwidth_probe_max_age_days = probe_days;
    cfg.playback.hw_accel = string_or(m, "playback.hw_accel", "auto");
    cfg.playback.hw_device = string_or(m, "playback.hw_device", "");
    cfg.playback.chapter_thumbnail_workers = int_or(m, "playback.chapter_thumbnail_workers", 1)?;
    cfg.playback.chapter_thumbnail_execution =
        string_or(m, "playback.chapter_thumbnail_execution", "local");
    cfg.playback.chapter_thumbnail_node_capacity =
        int_or(m, "playback.chapter_thumbnail_node_capacity", 1)?;
    cfg.playback.subtitle_sync_node_capacity = int_or(m, "subtitles.sync_node_capacity", 1)?;
    cfg.playback.transcode_enabled = bool_or(m, "playback.transcode_enabled", true)?;
    cfg.playback.routing = playback_routing_policy_from_settings(m);
    validate_playback_routing_policy(&cfg.playback.routing)?;

    cfg.redis.url = string_or(m, "redis.url", "");
    cfg.redis.db = string_or(m, REDIS_DB_SETTING_KEY, "");

    cfg.rate_limit.enabled = bool_or(m, "ratelimit.enabled", true)?;
    cfg.rate_limit.backend = string_or(m, "ratelimit.backend", "memory");

    cfg.auth.jwt_secret = string_or(m, "auth.jwt_secret", "");
    cfg.auth.access_token_expiry = duration_or(m, "auth.access_token_expiry", hours(8))?;
    cfg.auth.refresh_token_expiry = duration_or(m, "auth.refresh_token_expiry", hours(30 * 24))?;

    if bool_or(m, "audiobookshelf_compat.enabled", true)? {
        cfg.audiobookshelf_compat.listen = ":13378".to_owned();
    }

    cfg.jellyfin_compat.enabled = jellyfin_compat_enabled_or_legacy_default(m)?;
    cfg.jellyfin_compat.listen = string_or(m, "jellyfin_compat.listen", ":8096");
    cfg.jellyfin_compat.public_url =
        string_or(m, "jellyfin_compat.public_url", "http://127.0.0.1:8096");
    cfg.jellyfin_compat.emulated_server_version = string_or(
        m,
        "jellyfin_compat.emulated_server_version",
        DEFAULT_JELLYFIN_COMPAT_EMULATED_SERVER_VERSION,
    );
    cfg.jellyfin_compat.server_id = string_or(
        m,
        "jellyfin_compat.server_id",
        DEFAULT_JELLYFIN_COMPAT_SERVER_ID,
    );
    cfg.jellyfin_compat.server_name = string_or(m, "jellyfin_compat.server_name", "Silo");
    cfg.jellyfin_compat.web_enabled = bool_or(m, "jellyfin_compat.web_enabled", true)?;
    cfg.jellyfin_compat.web_version = string_or(
        m,
        "jellyfin_compat.web_version",
        DEFAULT_JELLYFIN_WEB_VERSION,
    );
    cfg.jellyfin_compat.web_dir = string_or(m, "jellyfin_compat.web_dir", DEFAULT_JELLYFIN_WEB_DIR);
    cfg.jellyfin_compat.web_install_dir = string_or(
        m,
        "jellyfin_compat.web_install_dir",
        DEFAULT_JELLYFIN_WEB_INSTALL_DIR,
    );
    cfg.jellyfin_compat.session_ttl = duration_or(m, "jellyfin_compat.session_ttl", hours(87600))?;
    cfg.jellyfin_compat.playback_session_ttl =
        duration_or(m, "jellyfin_compat.playback_session_ttl", hours(24))?;

    let ai_providers = parse_ai_provider_registry(m_get(m, AI_PROVIDERS_SETTING_KEY))?;

    cfg.recommendations.enabled = bool_or(m, "recommendations.enabled", false)?;
    cfg.recommendations.embedding_provider_id =
        trim_space(m_get(m, EMBEDDING_PROVIDER_SETTING_KEY)).to_owned();
    if let Some((url, key)) = ai_providers.resolve(
        &cfg.recommendations.embedding_provider_id,
        AI_CAPABILITY_EMBEDDINGS,
    ) {
        cfg.recommendations.embedding_base_url = url;
        cfg.recommendations.embedding_auth_token = key;
    }
    cfg.recommendations.embedding_model =
        trim_space(m_get(m, "recommendations.embedding_model")).to_owned();
    cfg.recommendations.embeddings_cron =
        string_or(m, "recommendations.embeddings_cron", "0 3 * * *");
    cfg.recommendations.embeddings_job_timeout =
        duration_or(m, "recommendations.embeddings_job_timeout", hours(24))?;
    cfg.recommendations.taste_profiles_cron =
        string_or(m, "recommendations.taste_profiles_cron", "0 4 * * *");
    cfg.recommendations.recommendations_cron =
        string_or(m, "recommendations.recommendations_cron", "0 5 * * *");
    cfg.recommendations.taste_decay_half_life_days =
        float_or(m, "recommendations.taste_decay_half_life_days", 180.0)?;
    cfg.recommendations.diversity_lambda = float_or(m, "recommendations.diversity_lambda", 0.7)?;
    cfg.recommendations.cowatch_cron = string_or(m, "recommendations.cowatch_cron", "30 4 * * *");

    cfg.ai.auth_mode = string_or(m, "ai.auth_mode", "api_key");
    cfg.ai.reasoning_effort = string_or(m, "ai.reasoning_effort", "");
    cfg.ai.service_tier = resolve_ai_service_tier(m);
    cfg.ai.text_provider_id = trim_space(m_get(m, AI_TEXT_PROVIDER_SETTING_KEY)).to_owned();
    if let Some((url, key)) = ai_providers.resolve(&cfg.ai.text_provider_id, AI_CAPABILITY_CHAT) {
        cfg.ai.base_url = url;
        cfg.ai.api_key = key;
    }
    cfg.ai.chat_model = string_or(
        m,
        "ai.chat_model",
        &string_or(m, "subtitle_ai.chat_model", "gpt-6-luna"),
    );
    cfg.ai.speech_provider_id = trim_space(m_get(m, AI_SPEECH_PROVIDER_SETTING_KEY)).to_owned();
    if let Some((url, key)) = ai_providers.resolve(&cfg.ai.speech_provider_id, AI_CAPABILITY_SPEECH)
    {
        cfg.ai.asr_base_url = url;
        cfg.ai.asr_api_key = key;
    }
    cfg.ai.asr_model = string_or(m, "ai.asr_model", "whisper-1");
    let mut ai_max = int_or(m, "ai.max_concurrent_jobs", 0)?;
    if ai_max <= 0 {
        ai_max = int_or(m, "subtitle_ai.max_concurrent_jobs", 2)?;
    }
    cfg.ai.max_concurrent_jobs = ai_max;

    cfg.subtitle_ai.enabled = bool_or(m, "subtitle_ai.enabled", false)?;
    cfg.subtitle_ai.transcribe_enabled = bool_or(m, "subtitle_ai.transcribe_enabled", false)?;
    cfg.subtitle_ai.batch_size = int_or(m, "subtitle_ai.batch_size", 40)?;
    cfg.subtitle_ai.context_neighbors = int_or(m, "subtitle_ai.context_neighbors", 2)?;
    cfg.subtitle_ai.asr_chunk_seconds = int_or(m, "subtitle_ai.asr_chunk_seconds", 600)?;
    cfg.subtitle_ai.live_asr_chunk_seconds = int_or(m, "subtitle_ai.live_asr_chunk_seconds", 30)?;
    // A bad quota row must not block startup.
    let quota_jobs = match int_or(m, "subtitle_ai.transcribe_quota_jobs", 0) {
        Ok(n) if n >= 0 => n,
        other => {
            tracing::warn!(value = %m_get(m, "subtitle_ai.transcribe_quota_jobs"), error = ?other.err(),
                "invalid subtitle_ai.transcribe_quota_jobs setting; quota disabled");
            0
        }
    };
    cfg.subtitle_ai.transcribe_quota_jobs = quota_jobs;
    let mut period = string_or(m, "subtitle_ai.transcribe_quota_period", QUOTA_PERIOD_DAY);
    if !valid_quota_period(&period) {
        tracing::warn!(value = %period, "invalid subtitle_ai.transcribe_quota_period setting; using day");
        period = QUOTA_PERIOD_DAY.to_owned();
    }
    cfg.subtitle_ai.transcribe_quota_period = period;

    cfg.metadata_ai.enabled = bool_or(m, "metadata_ai.enabled", false)?;
    let on_view = string_or(m, "metadata_ai.on_view", "off");
    cfg.metadata_ai.on_view = match on_view.as_str() {
        "off" | "button" | "auto" => on_view,
        _ => {
            tracing::warn!(value = %on_view, "invalid metadata_ai.on_view setting; using off");
            "off".to_owned()
        }
    };

    cfg.download.enabled = bool_or(m, "download.enabled", false)?;
    let server_mbps = int64_or(m, "download.server_bandwidth_mbps", 0)?;
    let user_mbps = int64_or(m, "download.user_bandwidth_mbps", 0)?;
    let max_concurrent = int_or(m, "download.max_concurrent_per_user", 3)?;
    let max_per_period = int_or(m, "download.max_per_period", 0)?;
    let period_duration = duration_or(m, "download.period_duration", hours(24))?;
    let non_negative =
        |key: &str| format!("invalid value for {}: must be non-negative", quote(key));
    if server_mbps < 0 {
        return Err(non_negative("download.server_bandwidth_mbps"));
    }
    if user_mbps < 0 {
        return Err(non_negative("download.user_bandwidth_mbps"));
    }
    const MAX_MBPS: i64 = 73_786_976_294_838;
    if server_mbps > MAX_MBPS {
        return Err(format!(
            "invalid value for {}: exceeds maximum",
            quote("download.server_bandwidth_mbps")
        ));
    }
    if user_mbps > MAX_MBPS {
        return Err(format!(
            "invalid value for {}: exceeds maximum",
            quote("download.user_bandwidth_mbps")
        ));
    }
    if max_concurrent < 0 {
        return Err(non_negative("download.max_concurrent_per_user"));
    }
    if max_per_period < 0 {
        return Err(non_negative("download.max_per_period"));
    }
    if max_per_period > 0 && period_duration.0 <= 0 {
        return Err(format!(
            "invalid config: {} requires a positive {}",
            quote("download.max_per_period"),
            quote("download.period_duration")
        ));
    }
    cfg.download.server_bandwidth_bps = server_mbps * 125_000;
    cfg.download.user_bandwidth_bps = user_mbps * 125_000;
    cfg.download.max_concurrent_per_user = max_concurrent;
    cfg.download.max_per_period = max_per_period;
    cfg.download.period_duration = period_duration;

    cfg.download.transcode_enabled = bool_or(m, "download.transcode_enabled", false)?;
    let max_prepares = int_or(m, "download.max_concurrent_prepares", 2)?;
    let artifact_max_bytes = int64_or(m, "download.artifact_max_bytes", 0)?;
    if max_prepares < 0 {
        return Err(non_negative("download.max_concurrent_prepares"));
    }
    if artifact_max_bytes < 0 {
        return Err(non_negative("download.artifact_max_bytes"));
    }
    let cache_hours = int_or(
        m,
        DOWNLOAD_ARTIFACT_CACHE_HOURS_SETTING_KEY,
        DEFAULT_DOWNLOAD_ARTIFACT_CACHE_HOURS,
    )?;
    if !(0..=MAX_DOWNLOAD_ARTIFACT_CACHE_HOURS).contains(&cache_hours) {
        return Err(format!(
            "invalid value for {}: must be 0 to {MAX_DOWNLOAD_ARTIFACT_CACHE_HOURS}",
            quote(DOWNLOAD_ARTIFACT_CACHE_HOURS_SETTING_KEY)
        ));
    }
    let ceiling = int_or(
        m,
        DOWNLOAD_ARTIFACT_DISK_CEILING_SETTING_KEY,
        DEFAULT_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT,
    )?;
    if !(MIN_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT..=MAX_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT)
        .contains(&ceiling)
    {
        return Err(format!(
            "invalid value for {}: must be {MIN_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT} to {MAX_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT}",
            quote(DOWNLOAD_ARTIFACT_DISK_CEILING_SETTING_KEY)
        ));
    }
    let artifact_dir = trim_space(&string_or(m, DOWNLOAD_ARTIFACT_DIR_SETTING_KEY, "")).to_owned();
    if !artifact_dir.is_empty() && !filepath::is_abs(&artifact_dir) {
        return Err(format!(
            "invalid value for {}: must be an absolute path",
            quote(DOWNLOAD_ARTIFACT_DIR_SETTING_KEY)
        ));
    }
    cfg.download.artifact_dir = artifact_dir;
    cfg.download.max_concurrent_prepares = max_prepares;
    cfg.download.artifact_max_bytes = artifact_max_bytes;
    cfg.download.artifact_cache_hours = cache_hours;
    cfg.download.artifact_disk_ceiling_percent = ceiling;
    cfg.download.allow_4k_transcode = admin_setting_enabled(
        ALLOW_4K_TRANSCODE_SETTING_KEY,
        m_get(m, ALLOW_4K_TRANSCODE_SETTING_KEY),
    );
    cfg.download.allow_hevc_encoding = admin_setting_enabled(
        PLAYBACK_ALLOW_HEVC_ENCODING_SETTING_KEY,
        m_get(m, PLAYBACK_ALLOW_HEVC_ENCODING_SETTING_KEY),
    );

    cfg.policy.eval_timeout_ms = int_or(m, "policy.eval_timeout_ms", 100)?;
    cfg.policy.editor_enabled = bool_or(m, "policy.editor_enabled", false)?;
    cfg.policy.decision_log_verbosity = string_or(m, "policy.decision_log_verbosity", "digest");
    cfg.policy.decision_log_scope_sample_rate =
        int_or(m, "policy.decision_log_scope_sample_rate", 50)?;
    cfg.policy.decision_log_retention_days = int_or(m, "policy.decision_log_retention_days", 14)?;

    Ok(cfg)
}
