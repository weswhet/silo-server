//! `internal/settingskeys`, one constant per manifest definition. A test checks this against the
//! embedded manifest, so it cannot drift. `cmd/settingsgen` is the generator for the Go original.

/// The manifest revision these bindings were generated from.
pub const REVISION: i64 = 24;

/// Blur unwatched episode images
pub const CATALOG_HIDE_UNWATCHED_EPISODE_IMAGES: &str = "catalog.hide_unwatched_episode_images";
/// Hide unwatched episode descriptions
pub const CATALOG_HIDE_UNWATCHED_EPISODE_OVERVIEWS: &str =
    "catalog.hide_unwatched_episode_overviews";
/// Metadata language
pub const CATALOG_METADATA_LANGUAGE: &str = "catalog.metadata_language";
/// Metadata language exceptions
pub const CATALOG_METADATA_LANGUAGE_OVERRIDES: &str = "catalog.metadata_language_overrides";
/// Show advisory age
pub const CATALOG_SHOW_ADVISORY_AGE: &str = "catalog.show_advisory_age";
/// Download quality
pub const DOWNLOADS_DEFAULT_QUALITY: &str = "downloads.default_quality";
/// Keep watched downloads
pub const DOWNLOADS_KEEP_WATCHED: &str = "downloads.keep_watched";
/// Download over Wi-Fi only
pub const DOWNLOADS_WIFI_ONLY: &str = "downloads.wifi_only";
/// Hide watched items from Home
pub const HOME_HIDE_WATCHED_ITEMS: &str = "home.hide_watched_items";
/// Primary menu
pub const NAV_PRIMARY_MENU: &str = "nav.primary_menu";
/// Navigation shortcuts
pub const NAV_SHORTCUTS: &str = "nav.shortcuts";
/// Show audiobooks
pub const NAV_SHOW_AUDIOBOOKS: &str = "nav.show_audiobooks";
/// Preferred audio language
pub const PLAYBACK_AUDIO_LANGUAGE: &str = "playback.audio_language";
/// Auto-play next episode
pub const PLAYBACK_AUTO_PLAY_NEXT: &str = "playback.auto_play_next";
/// Preview next episode
pub const PLAYBACK_AUTO_PLAY_NEXT_PREVIEW: &str = "playback.auto_play_next_preview";
/// Auto-skip credits
pub const PLAYBACK_AUTO_SKIP_CREDITS: &str = "playback.auto_skip_credits";
/// Auto-skip intros
pub const PLAYBACK_AUTO_SKIP_INTRO: &str = "playback.auto_skip_intro";
/// Auto-skip recaps
pub const PLAYBACK_AUTO_SKIP_RECAP: &str = "playback.auto_skip_recap";
/// Lower quality when buffering
pub const PLAYBACK_BUFFERING_QUALITY_MODE: &str = "playback.buffering_quality_mode";
/// Cellular maximum bitrate
pub const PLAYBACK_CELLULAR_MAX_BITRATE_KBPS: &str = "playback.cellular_max_bitrate_kbps";
/// Cellular quality
pub const PLAYBACK_CELLULAR_PREFERRED_QUALITY: &str = "playback.cellular_preferred_quality";
/// Skip intros
pub const PLAYBACK_INTRO_SKIP_MODE: &str = "playback.intro_skip_mode";
/// Maximum bitrate
pub const PLAYBACK_MAX_BITRATE_KBPS: &str = "playback.max_bitrate_kbps";
/// Next up prompt
pub const PLAYBACK_NEXT_UP_PROMPT_SECONDS: &str = "playback.next_up_prompt_seconds";
/// Preferred quality
pub const PLAYBACK_PREFERRED_QUALITY: &str = "playback.preferred_quality";
/// Show forced subtitles
pub const PLAYBACK_SHOW_FORCED_SUBTITLES: &str = "playback.show_forced_subtitles";
/// Show marker confidence
pub const PLAYBACK_SHOW_MARKER_CONFIDENCE: &str = "playback.show_marker_confidence";
/// Show marker source
pub const PLAYBACK_SHOW_MARKER_SOURCE: &str = "playback.show_marker_source";
/// Subtitle appearance
pub const PLAYBACK_SUBTITLE_APPEARANCE: &str = "playback.subtitle_appearance";
/// Preferred subtitle language
pub const PLAYBACK_SUBTITLE_LANGUAGE: &str = "playback.subtitle_language";
/// Subtitles
pub const PLAYBACK_SUBTITLE_MODE: &str = "playback.subtitle_mode";
/// Audio sync offset
pub const PLAYER_AUDIO_SYNC_MS: &str = "player.audio_sync_ms";
/// Audiobook rewind interval
pub const PLAYER_AUDIOBOOK_SKIP_BACK_SECONDS: &str = "player.audiobook_skip_back_seconds";
/// Audiobook fast-forward interval
pub const PLAYER_AUDIOBOOK_SKIP_FORWARD_SECONDS: &str = "player.audiobook_skip_forward_seconds";
/// Dolby Vision
pub const PLAYER_DOLBY_VISION_ENABLED: &str = "player.dolby_vision_enabled";
/// Dolby Vision Profile 7 fallback
pub const PLAYER_DV_PROFILE7_HDR10_FALLBACK: &str = "player.dv_profile7_hdr10_fallback";
/// HDR
pub const PLAYER_HDR_ENABLED: &str = "player.hdr_enabled";
/// Match content frame rate
pub const PLAYER_MATCH_FRAME_RATE: &str = "player.match_frame_rate";
/// Screen orientation
pub const PLAYER_ORIENTATION_MODE: &str = "player.orientation_mode";
/// Still watching prompt
pub const PLAYER_PASSOUT_THRESHOLD: &str = "player.passout_threshold";
/// Picture in picture
pub const PLAYER_PICTURE_IN_PICTURE_ENABLED: &str = "player.picture_in_picture_enabled";
/// Playback speed
pub const PLAYER_PLAYBACK_SPEED: &str = "player.playback_speed";
/// Rewind on resume
pub const PLAYER_RESUME_REWIND_SECONDS: &str = "player.resume_rewind_seconds";
/// Seek cache
pub const PLAYER_SEEK_CACHE_ENABLED: &str = "player.seek_cache_enabled";
/// Default sleep timer
pub const PLAYER_SLEEP_TIMER_DEFAULT_MINUTES: &str = "player.sleep_timer_default_minutes";
/// Subtitle sync offset
pub const PLAYER_SUBTITLE_SYNC_MS: &str = "player.subtitle_sync_ms";
/// Video sizing
pub const PLAYER_VIDEO_GRAVITY: &str = "player.video_gravity";
/// Video rewind interval
pub const PLAYER_VIDEO_SKIP_BACK_SECONDS: &str = "player.video_skip_back_seconds";
/// Video fast-forward interval
pub const PLAYER_VIDEO_SKIP_FORWARD_SECONDS: &str = "player.video_skip_forward_seconds";
/// Request titles I add to my watchlist
pub const REQUESTS_WATCHLIST_AUTO_REQUEST: &str = "requests.watchlist_auto_request";
/// Search scope
pub const SEARCH_MEDIA_SCOPE: &str = "search.media_scope";
/// Match device caption settings
pub const SUBTITLE_MATCHES_DEVICE: &str = "subtitle.matches_device";
/// Poster badges
pub const UI_CARD_OVERLAYS: &str = "ui.card_overlays";
/// Card overlays enabled
pub const UI_CARD_OVERLAYS_ENABLED: &str = "ui.card_overlays_enabled";
/// Media cards
pub const UI_CARD_PRESENTATION: &str = "ui.card_presentation";
/// Card quick actions
pub const UI_CARD_QUICK_ACTIONS: &str = "ui.card_quick_actions";
/// Card quick actions enabled
pub const UI_CARD_QUICK_ACTIONS_ENABLED: &str = "ui.card_quick_actions_enabled";
/// Custom CSS
pub const UI_CUSTOM_CSS: &str = "ui.custom_css";
/// Custom theme variables
pub const UI_CUSTOM_THEME_VARS: &str = "ui.custom_theme_vars";
/// Date format
pub const UI_DATE_FORMAT: &str = "ui.date_format";
/// Hidden libraries
pub const UI_DISABLED_LIBRARY_IDS: &str = "ui.disabled_library_ids";
/// High contrast
pub const UI_HIGH_CONTRAST: &str = "ui.high_contrast";
/// Library order
pub const UI_LIBRARY_ORDER: &str = "ui.library_order";
/// Remembered library view
pub const UI_LIBRARY_PAGE_STATE: &str = "ui.library_page_state";
/// Next up episodes
pub const UI_NEXT_UP_MODE: &str = "ui.next_up_mode";
/// Show new episodes first
pub const UI_NEXT_UP_NEW_RELEASES_FIRST: &str = "ui.next_up_new_releases_first";
/// Remember library view
pub const UI_REMEMBER_LIBRARY_PAGE_STATE: &str = "ui.remember_library_page_state";
/// Pinned sidebar items
pub const UI_SIDEBAR_PINS: &str = "ui.sidebar_pins";
/// Text size
pub const UI_TEXT_SCALE: &str = "ui.text_scale";
/// Text weight
pub const UI_TEXT_WEIGHT: &str = "ui.text_weight";
/// Theme
pub const UI_THEME: &str = "ui.theme";
/// Theme music
pub const UI_THEME_MUSIC_ENABLED: &str = "ui.theme_music_enabled";
/// Loop theme music
pub const UI_THEME_MUSIC_LOOP: &str = "ui.theme_music_loop";
/// Time format
pub const UI_TIME_FORMAT: &str = "ui.time_format";
/// Show title art
pub const UI_TITLE_ART: &str = "ui.title_art";

/// Every key the server stores.
pub const REMOTE: &[&str] = &[
    CATALOG_HIDE_UNWATCHED_EPISODE_IMAGES,
    CATALOG_HIDE_UNWATCHED_EPISODE_OVERVIEWS,
    CATALOG_METADATA_LANGUAGE,
    CATALOG_METADATA_LANGUAGE_OVERRIDES,
    CATALOG_SHOW_ADVISORY_AGE,
    HOME_HIDE_WATCHED_ITEMS,
    NAV_PRIMARY_MENU,
    NAV_SHORTCUTS,
    PLAYBACK_AUDIO_LANGUAGE,
    PLAYBACK_AUTO_PLAY_NEXT,
    PLAYBACK_AUTO_PLAY_NEXT_PREVIEW,
    PLAYBACK_AUTO_SKIP_CREDITS,
    PLAYBACK_AUTO_SKIP_INTRO,
    PLAYBACK_AUTO_SKIP_RECAP,
    PLAYBACK_BUFFERING_QUALITY_MODE,
    PLAYBACK_CELLULAR_MAX_BITRATE_KBPS,
    PLAYBACK_CELLULAR_PREFERRED_QUALITY,
    PLAYBACK_INTRO_SKIP_MODE,
    PLAYBACK_MAX_BITRATE_KBPS,
    PLAYBACK_NEXT_UP_PROMPT_SECONDS,
    PLAYBACK_PREFERRED_QUALITY,
    PLAYBACK_SHOW_FORCED_SUBTITLES,
    PLAYBACK_SHOW_MARKER_CONFIDENCE,
    PLAYBACK_SHOW_MARKER_SOURCE,
    PLAYBACK_SUBTITLE_APPEARANCE,
    PLAYBACK_SUBTITLE_LANGUAGE,
    PLAYBACK_SUBTITLE_MODE,
    PLAYER_AUDIO_SYNC_MS,
    PLAYER_AUDIOBOOK_SKIP_BACK_SECONDS,
    PLAYER_AUDIOBOOK_SKIP_FORWARD_SECONDS,
    PLAYER_DOLBY_VISION_ENABLED,
    PLAYER_DV_PROFILE7_HDR10_FALLBACK,
    PLAYER_HDR_ENABLED,
    PLAYER_MATCH_FRAME_RATE,
    PLAYER_ORIENTATION_MODE,
    PLAYER_PLAYBACK_SPEED,
    PLAYER_SEEK_CACHE_ENABLED,
    PLAYER_SLEEP_TIMER_DEFAULT_MINUTES,
    PLAYER_SUBTITLE_SYNC_MS,
    PLAYER_VIDEO_GRAVITY,
    PLAYER_VIDEO_SKIP_BACK_SECONDS,
    PLAYER_VIDEO_SKIP_FORWARD_SECONDS,
    REQUESTS_WATCHLIST_AUTO_REQUEST,
    SEARCH_MEDIA_SCOPE,
    UI_CARD_OVERLAYS,
    UI_CARD_OVERLAYS_ENABLED,
    UI_CARD_PRESENTATION,
    UI_CARD_QUICK_ACTIONS,
    UI_CARD_QUICK_ACTIONS_ENABLED,
    UI_CUSTOM_CSS,
    UI_CUSTOM_THEME_VARS,
    UI_DATE_FORMAT,
    UI_DISABLED_LIBRARY_IDS,
    UI_HIGH_CONTRAST,
    UI_LIBRARY_ORDER,
    UI_LIBRARY_PAGE_STATE,
    UI_NEXT_UP_MODE,
    UI_NEXT_UP_NEW_RELEASES_FIRST,
    UI_REMEMBER_LIBRARY_PAGE_STATE,
    UI_SIDEBAR_PINS,
    UI_TEXT_SCALE,
    UI_TEXT_WEIGHT,
    UI_THEME,
    UI_THEME_MUSIC_ENABLED,
    UI_THEME_MUSIC_LOOP,
    UI_TIME_FORMAT,
    UI_TITLE_ART,
];

/// Keys the contract defines but the server never stores.
pub const CLIENT_LOCAL: &[&str] = &[
    DOWNLOADS_DEFAULT_QUALITY,
    DOWNLOADS_KEEP_WATCHED,
    DOWNLOADS_WIFI_ONLY,
    NAV_SHOW_AUDIOBOOKS,
    PLAYER_PASSOUT_THRESHOLD,
    PLAYER_PICTURE_IN_PICTURE_ENABLED,
    PLAYER_RESUME_REWIND_SECONDS,
    SUBTITLE_MATCHES_DEVICE,
];

/// Keys another definition has superseded.
pub const DEPRECATED: &[&str] = &[
    PLAYBACK_AUTO_SKIP_INTRO,
    UI_CUSTOM_CSS,
    UI_CUSTOM_THEME_VARS,
    UI_THEME,
];
