//! The `Config` model. Field and JSON names follow the Go structs, because a vector test compares
//! `encoding/json` output of the real `Config` to this one byte for byte.

use super::playback_routing::PlaybackRoutingPolicy;
use serde::{Serialize, Serializer};
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::time::{Duration, parse_duration as go_parse_duration};
use std::sync::OnceLock;

pub(crate) fn ser_duration<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i64(d.0)
}

/// `ArtworkBackendAuto` selects S3 when a public bucket is configured and local storage otherwise.
pub const ARTWORK_BACKEND_AUTO: &str = "auto";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ServerConfig {
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "Mode")]
    pub mode: String,
    #[serde(rename = "LogLevel")]
    pub log_level: String,
    #[serde(rename = "LogFormat")]
    pub log_format: String,
    #[serde(rename = "LogQuiet")]
    pub log_quiet: String,
    #[serde(rename = "PublicURL")]
    pub public_url: String,
    #[serde(rename = "LANDiscovery")]
    pub lan_discovery: bool,
    #[serde(rename = "LocalURL")]
    pub local_url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DatabaseConfig {
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(rename = "MaxConnections")]
    pub max_connections: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct S3BucketSettings {
    #[serde(rename = "Endpoint")]
    pub endpoint: String,
    #[serde(rename = "Region")]
    pub region: String,
    #[serde(rename = "PathStyle")]
    pub path_style: bool,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "KeyPrefix")]
    pub key_prefix: String,
    #[serde(rename = "AccessKey")]
    pub access_key: String,
    #[serde(rename = "SecretKey")]
    pub secret_key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct S3PublicAssetsSettings {
    #[serde(flatten)]
    pub bucket: S3BucketSettings,
    #[serde(rename = "ReadEndpoint")]
    pub read_endpoint: String,
    #[serde(rename = "URLAuth")]
    pub url_auth: String,
    #[serde(rename = "TokenSecret")]
    pub token_secret: String,
    #[serde(rename = "TokenParam")]
    pub token_param: String,
    #[serde(rename = "TokenTTL")]
    pub token_ttl: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct S3Config {
    #[serde(rename = "Public")]
    pub public: S3PublicAssetsSettings,
    #[serde(rename = "Private")]
    pub private: S3BucketSettings,
    #[serde(rename = "UserDB")]
    pub user_db: S3BucketSettings,
    #[serde(rename = "MetadataPresignExpiry", serialize_with = "ser_duration")]
    pub metadata_presign_expiry: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UserDBConfig {
    #[serde(rename = "Backend")]
    pub backend: String,
    #[serde(rename = "PoolMaxOpen")]
    pub pool_max_open: i64,
    #[serde(rename = "IdleTimeout", serialize_with = "ser_duration")]
    pub idle_timeout: Duration,
    #[serde(rename = "LitestreamSync", serialize_with = "ser_duration")]
    pub litestream_sync: Duration,
    #[serde(rename = "StaleGraceSeconds")]
    pub stale_grace_seconds: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScannerConfig {
    #[serde(rename = "Workers")]
    pub workers: i64,
    #[serde(rename = "MaxConcurrentLibraries")]
    pub max_concurrent_libraries: i64,
    #[serde(rename = "MaxConcurrentScoped")]
    pub max_concurrent_scoped: i64,
    #[serde(rename = "EmptyTrashAfterScan")]
    pub empty_trash_after_scan: bool,
    #[serde(rename = "FileRemovalGrace", serialize_with = "ser_duration")]
    pub file_removal_grace: Duration,
    #[serde(rename = "RealtimeMonitoring")]
    pub realtime_monitoring: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MatcherConfig {
    #[serde(rename = "Workers")]
    pub workers: i64,
    #[serde(rename = "BatchSize")]
    pub batch_size: i64,
    #[serde(rename = "EnableTVSeriesRootQueue")]
    pub enable_tv_series_root_queue: bool,
    #[serde(rename = "EnableTVSeriesGroupQueueLegacy")]
    pub enable_tv_series_group_queue_legacy: bool,
}

impl MatcherConfig {
    pub fn tv_series_root_queue_enabled(&self) -> bool {
        self.enable_tv_series_root_queue || self.enable_tv_series_group_queue_legacy
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PlaybackConfig {
    #[serde(rename = "FFmpegPath")]
    pub ffmpeg_path: String,
    #[serde(rename = "TranscodeDir")]
    pub transcode_dir: String,
    #[serde(rename = "SegmentRetentionSeconds")]
    pub segment_retention_seconds: i64,
    #[serde(rename = "HWAccel")]
    pub hw_accel: String,
    #[serde(rename = "HWDevice")]
    pub hw_device: String,
    #[serde(rename = "ChapterThumbnailWorkers")]
    pub chapter_thumbnail_workers: i64,
    #[serde(rename = "ChapterThumbnailExecution")]
    pub chapter_thumbnail_execution: String,
    #[serde(rename = "ChapterThumbnailNodeCapacity")]
    pub chapter_thumbnail_node_capacity: i64,
    #[serde(rename = "SubtitleSyncNodeCapacity")]
    pub subtitle_sync_node_capacity: i64,
    #[serde(rename = "TranscodeEnabled")]
    pub transcode_enabled: bool,
    #[serde(rename = "Routing")]
    pub routing: PlaybackRoutingPolicy,
    #[serde(rename = "KeyframePlaylist")]
    pub keyframe_playlist: bool,
    #[serde(rename = "AutomaticBandwidthProbeOff")]
    pub automatic_bandwidth_probe_off: bool,
    #[serde(rename = "BandwidthProbeMaxAgeDays")]
    pub bandwidth_probe_max_age_days: i64,
}

impl PlaybackConfig {
    /// How long a connection speed reading lasts.
    pub fn bandwidth_probe_max_age(&self) -> Duration {
        let mut days = self.bandwidth_probe_max_age_days;
        if days <= 0 {
            days = super::DEFAULT_BANDWIDTH_PROBE_MAX_AGE_DAYS;
        }
        Duration(days.wrapping_mul(24).wrapping_mul(Duration::HOUR.0))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RedisConfig {
    /// One Redis server or a Sentinel deployment; see [`super::parse_redis_url`].
    #[serde(rename = "URL")]
    pub url: String,
    /// The `redis.db` setting. When not empty it replaces the database number in `url`.
    #[serde(rename = "DB")]
    pub db: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RateLimitConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Backend")]
    pub backend: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AuthConfig {
    #[serde(rename = "JWTSecret")]
    pub jwt_secret: String,
    #[serde(rename = "AccessTokenExpiry", serialize_with = "ser_duration")]
    pub access_token_expiry: Duration,
    #[serde(rename = "RefreshTokenExpiry", serialize_with = "ser_duration")]
    pub refresh_token_expiry: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AudiobookshelfCompatConfig {
    /// Empty means the listener is disabled.
    #[serde(rename = "Listen")]
    pub listen: String,
}

impl AudiobookshelfCompatConfig {
    /// The config of a process started with `ABS_PORT`: an enabled listener moves, a disabled one
    /// stays disabled, and an empty `listen` changes nothing.
    pub fn with_bootstrap_listen(&self, listen: &str) -> Self {
        let mut c = self.clone();
        if !c.listen.is_empty() && !listen.is_empty() {
            c.listen = listen.to_owned();
        }
        c
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct JellyfinCompatConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "PublicURL")]
    pub public_url: String,
    #[serde(rename = "EmulatedServerVersion")]
    pub emulated_server_version: String,
    #[serde(rename = "ServerID")]
    pub server_id: String,
    #[serde(rename = "ServerName")]
    pub server_name: String,
    #[serde(rename = "WebEnabled")]
    pub web_enabled: bool,
    #[serde(rename = "WebVersion")]
    pub web_version: String,
    #[serde(rename = "WebDir")]
    pub web_dir: String,
    #[serde(rename = "WebInstallDir")]
    pub web_install_dir: String,
    #[serde(rename = "SessionTTL", serialize_with = "ser_duration")]
    pub session_ttl: Duration,
    #[serde(rename = "PlaybackSessionTTL", serialize_with = "ser_duration")]
    pub playback_session_ttl: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RecommendationsConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "EmbeddingProviderID")]
    pub embedding_provider_id: String,
    #[serde(rename = "EmbeddingBaseURL")]
    pub embedding_base_url: String,
    #[serde(rename = "EmbeddingModel")]
    pub embedding_model: String,
    #[serde(rename = "EmbeddingAuthToken")]
    pub embedding_auth_token: String,
    #[serde(rename = "EmbeddingsCron")]
    pub embeddings_cron: String,
    #[serde(rename = "TasteProfilesCron")]
    pub taste_profiles_cron: String,
    #[serde(rename = "RecommendationsCron")]
    pub recommendations_cron: String,
    #[serde(rename = "TasteDecayHalfLifeDays")]
    pub taste_decay_half_life_days: f64,
    #[serde(rename = "DiversityLambda")]
    pub diversity_lambda: f64,
    #[serde(rename = "CowatchCron")]
    pub cowatch_cron: String,
    #[serde(rename = "EmbeddingsJobTimeout", serialize_with = "ser_duration")]
    pub embeddings_job_timeout: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AIConfig {
    #[serde(rename = "AuthMode")]
    pub auth_mode: String,
    #[serde(rename = "ReasoningEffort")]
    pub reasoning_effort: String,
    #[serde(rename = "ServiceTier")]
    pub service_tier: String,
    #[serde(rename = "TextProviderID")]
    pub text_provider_id: String,
    #[serde(rename = "BaseURL")]
    pub base_url: String,
    #[serde(rename = "APIKey")]
    pub api_key: String,
    #[serde(rename = "ChatModel")]
    pub chat_model: String,
    #[serde(rename = "SpeechProviderID")]
    pub speech_provider_id: String,
    #[serde(rename = "ASRBaseURL")]
    pub asr_base_url: String,
    #[serde(rename = "ASRAPIKey")]
    pub asr_api_key: String,
    #[serde(rename = "ASRModel")]
    pub asr_model: String,
    #[serde(rename = "MaxConcurrentJobs")]
    pub max_concurrent_jobs: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SubtitleAIConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "TranscribeEnabled")]
    pub transcribe_enabled: bool,
    #[serde(rename = "BatchSize")]
    pub batch_size: i64,
    #[serde(rename = "ContextNeighbors")]
    pub context_neighbors: i64,
    #[serde(rename = "ASRChunkSeconds")]
    pub asr_chunk_seconds: i64,
    #[serde(rename = "LiveASRChunkSeconds")]
    pub live_asr_chunk_seconds: i64,
    #[serde(rename = "TranscribeQuotaJobs")]
    pub transcribe_quota_jobs: i64,
    #[serde(rename = "TranscribeQuotaPeriod")]
    pub transcribe_quota_period: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MetadataAIConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "OnView")]
    pub on_view: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DownloadConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "ServerBandwidthBPS")]
    pub server_bandwidth_bps: i64,
    #[serde(rename = "UserBandwidthBPS")]
    pub user_bandwidth_bps: i64,
    #[serde(rename = "MaxConcurrentPerUser")]
    pub max_concurrent_per_user: i64,
    #[serde(rename = "MaxPerPeriod")]
    pub max_per_period: i64,
    #[serde(rename = "PeriodDuration", serialize_with = "ser_duration")]
    pub period_duration: Duration,
    #[serde(rename = "TranscodeEnabled")]
    pub transcode_enabled: bool,
    #[serde(rename = "ArtifactDir")]
    pub artifact_dir: String,
    #[serde(rename = "MaxConcurrentPrepares")]
    pub max_concurrent_prepares: i64,
    #[serde(rename = "ArtifactMaxBytes")]
    pub artifact_max_bytes: i64,
    #[serde(rename = "ArtifactCacheHours")]
    pub artifact_cache_hours: i64,
    #[serde(rename = "ArtifactDiskCeilingPercent")]
    pub artifact_disk_ceiling_percent: i64,
    #[serde(rename = "Allow4KTranscode")]
    pub allow_4k_transcode: bool,
    #[serde(rename = "AllowHEVCEncoding")]
    pub allow_hevc_encoding: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PolicyConfig {
    #[serde(rename = "EvalTimeoutMS")]
    pub eval_timeout_ms: i64,
    #[serde(rename = "EditorEnabled")]
    pub editor_enabled: bool,
    #[serde(rename = "DecisionLogVerbosity")]
    pub decision_log_verbosity: String,
    #[serde(rename = "DecisionLogScopeSampleRate")]
    pub decision_log_scope_sample_rate: i64,
    #[serde(rename = "DecisionLogRetentionDays")]
    pub decision_log_retention_days: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MarkersConfig {
    #[serde(rename = "DetectionWorkers")]
    pub detection_workers: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MetadataConfig {
    #[serde(rename = "CacheImages")]
    pub cache_images: bool,
    #[serde(rename = "ImageWorkers")]
    pub image_workers: i64,
    #[serde(rename = "PersonRefreshPerMinute")]
    pub person_refresh_per_minute: i64,
    #[serde(rename = "FallbackLanguage")]
    pub fallback_language: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClientIPConfig {
    #[serde(rename = "TrustedProxies")]
    pub trusted_proxies: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ArtworkConfig {
    #[serde(rename = "StorageBackend")]
    pub storage_backend: String,
    #[serde(rename = "LocalPath")]
    pub local_path: String,
}

/// The top-level configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Config {
    #[serde(rename = "Server")]
    pub server: ServerConfig,
    #[serde(rename = "Database")]
    pub database: DatabaseConfig,
    #[serde(rename = "S3")]
    pub s3: S3Config,
    #[serde(rename = "UserDB")]
    pub user_db: UserDBConfig,
    #[serde(rename = "Scanner")]
    pub scanner: ScannerConfig,
    #[serde(rename = "Matcher")]
    pub matcher: MatcherConfig,
    #[serde(rename = "Artwork")]
    pub artwork: ArtworkConfig,
    #[serde(rename = "Metadata")]
    pub metadata: MetadataConfig,
    #[serde(rename = "Markers")]
    pub markers: MarkersConfig,
    #[serde(rename = "Playback")]
    pub playback: PlaybackConfig,
    #[serde(rename = "Redis")]
    pub redis: RedisConfig,
    #[serde(rename = "RateLimit")]
    pub rate_limit: RateLimitConfig,
    #[serde(rename = "Auth")]
    pub auth: AuthConfig,
    #[serde(rename = "JellyfinCompat")]
    pub jellyfin_compat: JellyfinCompatConfig,
    #[serde(rename = "AudiobookshelfCompat")]
    pub audiobookshelf_compat: AudiobookshelfCompatConfig,
    #[serde(rename = "Recommendations")]
    pub recommendations: RecommendationsConfig,
    #[serde(rename = "AI")]
    pub ai: AIConfig,
    #[serde(rename = "SubtitleAI")]
    pub subtitle_ai: SubtitleAIConfig,
    #[serde(rename = "MetadataAI")]
    pub metadata_ai: MetadataAIConfig,
    #[serde(rename = "Download")]
    pub download: DownloadConfig,
    #[serde(rename = "Policy")]
    pub policy: PolicyConfig,
    #[serde(rename = "ClientIP")]
    pub client_ip: ClientIPConfig,
    #[serde(rename = "TMDBAPIKey")]
    pub tmdb_api_key: String,
    #[serde(rename = "MDBListAPIKey")]
    pub mdblist_api_key: String,
}

const VALID_MODES: [&str; 5] = ["api", "frontend", "integrated", "proxy", "transcode"];

impl Config {
    /// `Config.Validate`: all required fields are set and values are valid.
    pub fn validate(&self) -> Result<(), String> {
        let mode = self.server.mode.as_str();
        let mut errs = Vec::new();
        if !VALID_MODES.contains(&mode) {
            errs.push(format!(
                "server.mode {} is invalid; must be one of: {}",
                silo_gocompat::strconv::quote(mode),
                VALID_MODES.join(", ")
            ));
        }
        let needs_db = matches!(mode, "integrated" | "api" | "proxy" | "transcode");
        if needs_db && self.database.url.is_empty() {
            errs.push(format!("database.url is required for {mode} mode"));
        }
        if matches!(mode, "proxy" | "transcode") && self.redis.url.is_empty() {
            errs.push(format!("redis.url is required for {mode} mode"));
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

pub const PLAYBACK_TRANSCODE_DIR_SETTING_KEY: &str = "playback.transcode_dir";
pub const DOWNLOAD_ARTIFACT_DIR_SETTING_KEY: &str = "download.artifact_dir";

pub const DOWNLOAD_ARTIFACT_CACHE_HOURS_SETTING_KEY: &str = "download.artifact_cache_hours";
pub const DOWNLOAD_ARTIFACT_DISK_CEILING_SETTING_KEY: &str =
    "download.artifact_disk_ceiling_percent";
pub const DEFAULT_DOWNLOAD_ARTIFACT_CACHE_HOURS: i64 = 72;
pub const MAX_DOWNLOAD_ARTIFACT_CACHE_HOURS: i64 = 720;
pub const DEFAULT_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT: i64 = 85;
pub const MIN_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT: i64 = 50;
pub const MAX_DOWNLOAD_ARTIFACT_DISK_CEILING_PERCENT: i64 = 95;

/// The fallback `playback.transcode_dir`.
pub const DEFAULT_TRANSCODE_DIR: &str = "/tmp/silo-transcode";

/// The shared prepared-download artifact root, derived the same way by API and transcode nodes.
pub fn effective_download_artifact_dir(artifact_dir: &str, transcode_dir: &str) -> String {
    use silo_gocompat::filepath;
    if !artifact_dir.is_empty() {
        return artifact_dir.to_owned();
    }
    let transcode_dir = if transcode_dir.is_empty() {
        DEFAULT_TRANSCODE_DIR
    } else {
        transcode_dir
    };
    filepath::join(&[
        filepath::dir(&filepath::clean(transcode_dir)).as_str(),
        "silo-download-artifacts",
    ])
}

pub const DEFAULT_JELLYFIN_COMPAT_EMULATED_SERVER_VERSION: &str = "12.1.0";
pub const DEFAULT_JELLYFIN_WEB_VERSION: &str = "12.1";
pub const DEFAULT_JELLYFIN_WEB_INSTALL_DIR: &str = "/var/lib/silo/compat/jellyfin-web";
pub const DEFAULT_JELLYFIN_WEB_DIR: &str = "/var/lib/silo/compat/jellyfin-web/current";
pub(crate) const DEFAULT_JELLYFIN_COMPAT_PLAYBACK_SESSION_TTL: &str = "24h";
/// `uuid.NewSHA1(uuid.NameSpaceURL, "https://silo.local/jellycompat")`. A vector pins it.
pub const DEFAULT_JELLYFIN_COMPAT_SERVER_ID: &str = "b2d9e6c9-1237-5add-a687-5dae547ece33";

fn day_regexp() -> &'static GoRegex {
    static RE: OnceLock<GoRegex> = OnceLock::new();
    RE.get_or_init(|| GoRegex::must_compile(r"^(\d+)d$"))
}

/// `config.parseDuration`: Go's durations plus `Nd` for days.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("empty duration string".to_owned());
    }
    if let Some(m) = day_regexp().find_string_submatch(s) {
        return match crate::goparse::atoi(m[1]) {
            Ok(days) => Ok(Duration(
                days.wrapping_mul(24).wrapping_mul(Duration::HOUR.0),
            )),
            Err(e) => Err(format!(
                "invalid day duration {}: {e}",
                silo_gocompat::strconv::quote(s)
            )),
        };
    }
    go_parse_duration(s)
        .map_err(|e| format!("invalid duration {}: {e}", silo_gocompat::strconv::quote(s)))
}
