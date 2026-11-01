//go:build silo_config_vectors

package main

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"

	"github.com/Silo-Server/silo-server/internal/config"
)

func trimBytes(b []byte) []byte { return bytes.TrimFunc(b, unicode.IsSpace) }

type settingsMapCase struct {
	Settings  map[string]string `json:"settings"`
	Config    string            `json:"config,omitempty"`
	Error     string            `json:"error,omitempty"`
	Effective string            `json:"effective"`
	Validate  string            `json:"validate"`
	ValidateR string            `json:"validate_with_redis"`
}

func settingsCase(m map[string]string) settingsMapCase {
	c := settingsMapCase{Settings: m}
	cfg, err := config.LoadFromDB(m)
	if err != nil {
		c.Error = err.Error()
	} else {
		c.Config = goJSON(cfg)
	}
	c.Effective = goJSON(config.EffectiveAdminSettings(m))
	if err := config.ValidateAdminSettings(m); err != nil {
		c.Validate = err.Error()
	}
	if err := config.ValidateAdminSettingsWithCapabilities(m, config.AdminSettingsCapabilities{RedisBootstrapAvailable: true}); err != nil {
		c.ValidateR = err.Error()
	}
	return c
}

func writeSettingsMapVectors() {
	maps := []map[string]string{
		{},
		{"server.listen": ":1", "server.mode": "api", "server.log_level": "debug", "server.log_format": "json", "server.log_quiet": "a", "database.url": "postgres://x", "database.max_connections": "7"},
		{"s3.public_endpoint": "https://p", "s3.public_bucket": "b", "s3.public_access_key": "a", "s3.public_secret_key": "s", "s3.public_read_endpoint": "https://r", "s3.public_url_auth": "public", "s3.public_token_ttl": "60", "s3.public_token_param": "t", "s3.metadata_presign_expiry": "1h"},
		{"s3.operational_endpoint": "https://o", "s3.operational_bucket": "ob", "s3.operational_access_key": "oa", "s3.operational_secret_key": "os", "s3.operational_path_style": "false", "s3.operational_public_endpoint": "https://opub", "s3.operational_url_auth": "cloudflare_token", "s3.operational_token_secret": "ts", "s3.operational_token_ttl": "9", "s3.operational_region": "r", "s3.operational_key_prefix": "k"},
		{"s3.public_endpoint": "", "s3.operational_endpoint": "https://o", "s3.operational_bucket": "b"},
		{"s3.public_path_style": "nope"},
		{"s3.public_token_ttl": "x"},
		{"s3.metadata_presign_expiry": "x"},
		{"s3.user_db_path_style": "false", "s3.user_db_endpoint": "e", "s3.user_db_bucket": "b", "s3.user_db_region": "r", "s3.user_db_key_prefix": "k", "s3.user_db_access_key": "a", "s3.user_db_secret_key": "s"},
		{"userdb.backend": "sqlite", "userdb.pool_max_open": "1", "userdb.idle_timeout": "1d", "userdb.litestream_sync": "2s", "userdb.stale_grace_seconds": "3"},
		{"userdb.idle_timeout": "99999999d"},
		{"scanner.workers": "1", "scanner.max_concurrent_libraries": "2", "scanner.max_concurrent_scoped": "3", "scanner.empty_trash_after_scan": "0", "scanner.file_removal_grace": "-1h", "scanner.realtime_monitoring": "F"},
		{"scanner.workers": "x"},
		{"scanner.file_removal_grace": "bad"},
		{"matcher.workers": "1", "matcher.batch_size": "2", "matcher.enable_tv_series_root_queue": "false", "matcher.enable_tv_series_group_queue": "true"},
		{"matcher.enable_tv_series_root_queue": "false"},
		{"matcher.enable_tv_series_root_queue": "false", "matcher.enable_tv_series_group_queue": "x"},
		{"artwork.storage_backend": "s3"},
		{"artwork.storage_backend": "S3", "s3.public_bucket": "b", "s3.public_endpoint": "e"},
		{"metadata.cache_images": "false", "metadata.image_workers": "4", "metadata.person_refresh_per_minute": "1", "metadata.fallback_language": "ORIGINAL", "markers.detection_workers": "2"},
		{"metadata.fallback_language": "FR"},
		{"playback.ffmpeg_path": "/f", "playback.transcode_dir": "/t", "playback.segment_retention_seconds": "0", "playback.hw_accel": "qsv", "playback.hw_device": "/d", "playback.chapter_thumbnail_workers": "2", "playback.chapter_thumbnail_execution": "x", "playback.chapter_thumbnail_node_capacity": "3", "subtitles.sync_node_capacity": "4", "playback.transcode_enabled": "f", "playback.copy_keyframe_playlist": "1", "playback.bandwidth_probe_automatic": "0", "playback.bandwidth_probe_max_age_days": "30"},
		{"playback.segment_retention_seconds": "60"},
		{"playback.segment_retention_seconds": "86401"},
		{"playback.bandwidth_probe_max_age_days": "0"},
		{"playback.bandwidth_probe_max_age_days": "31"},
		{"playback.routing.remux_execution": "api_only", "playback.routing.remux_egress": "proxy_only"},
		{"playback.routing.video_transcode_execution": "api_only", "playback.routing.video_transcode_egress": "proxy_only"},
		{"playback.routing.remux_execution": "banana"},
		{"playback.routing.direct_play_egress": "banana"},
		{"playback.routing.direct_play_egress": "api_only", "playback.routing.remux_execution": "worker_only", "playback.routing.remux_egress": "prefer_api", "playback.routing.video_transcode_execution": "prefer_worker", "playback.routing.video_transcode_egress": "proxy_only"},
		{"redis.url": "redis://h:1/2", "redis.db": "3", "ratelimit.enabled": "false", "ratelimit.backend": "redis"},
		{"ratelimit.backend": "REDIS"},
		{"ratelimit.backend": "redis", "redis.url": "bad://x"},
		{"auth.jwt_secret": "s", "auth.access_token_expiry": "1h", "auth.refresh_token_expiry": "2h"},
		{"auth.access_token_expiry": "2h", "auth.refresh_token_expiry": "1h"},
		{"auth.access_token_expiry": "0s"},
		{"auth.refresh_token_expiry": "-1h"},
		{"auth.access_token_expiry": "x"},
		{"audiobookshelf_compat.enabled": "false"},
		{"jellyfin_compat.enabled": "false", "jellyfin_compat.listen": ":1", "jellyfin_compat.public_url": "u", "jellyfin_compat.emulated_server_version": "v", "jellyfin_compat.server_id": "i", "jellyfin_compat.server_name": "n", "jellyfin_compat.web_enabled": "0", "jellyfin_compat.web_version": "w", "jellyfin_compat.web_dir": "d", "jellyfin_compat.web_install_dir": "id", "jellyfin_compat.session_ttl": "1h", "jellyfin_compat.playback_session_ttl": "2h"},
		{"jellyfin_compat.enabled": "x"},
		{"jellyfin_compat.session_ttl": "x"},
		{"recommendations.enabled": "1", "recommendations.embedding_model": " m ", "recommendations.embeddings_cron": "a", "recommendations.embeddings_job_timeout": "1h", "recommendations.taste_profiles_cron": "b", "recommendations.recommendations_cron": "c", "recommendations.taste_decay_half_life_days": "1.5", "recommendations.diversity_lambda": "0.25", "recommendations.cowatch_cron": "d"},
		{"recommendations.diversity_lambda": "x"},
		{"recommendations.taste_decay_half_life_days": "1e999"},
		{"ai.providers": `{"version":2,"providers":[{"id":"openai-1","type":"openai","name":"O","base_url":"https://api.openai.com","api_key":"k","capabilities":[]},{"id":"gem","type":"gemini","name":"G","base_url":"https://g","api_key":"gk"},{"id":"cus","type":"custom","name":"C","base_url":"https://c","capabilities":["speech"]},{"id":"weird","type":"nope","name":"W","base_url":"https://w","capabilities":["chat"]}]}`, "ai.text_provider_id": " gem ", "ai.speech_provider_id": "cus", "recommendations.embedding_provider_id": "openai-1", "ai.service_tier": "priority", "ai.chat_model": "m", "ai.asr_model": "a", "ai.auth_mode": "api_key", "ai.reasoning_effort": "low"},
		{"ai.providers": `{"providers":[{"id":"openai-1","type":"openai","name":"O","base_url":"https://api.openai.com","api_key":"k"}]}`, "ai.text_provider_id": "openai-1", "ai.service_tier": "priority"},
		{"ai.providers": `{"providers":[{"id":"openai-1","type":"openai","name":"O","base_url":"https://api.openai.com","api_key":"k"}]}`, "ai.text_provider_id": "openai-1", "ai.service_tier": "priority", "ai.auth_mode": "chatgpt"},
		{"ai.providers": `not json`},
		{"ai.providers": `[]`},
		{"ai.providers": `{"version":"x"}`},
		{"ai.providers": `{"providers":{}}`},
		{"ai.text_provider_id": "missing"},
		{"ai.providers": `{"providers":[{"id":"w","type":"whisper","name":"W","base_url":"http://w"}]}`, "ai.text_provider_id": "w"},
		{"subtitle_ai.chat_model": "legacy-model"},
		{"ai.chat_model": "", "subtitle_ai.chat_model": "legacy-model"},
		{"ai.chat_model": "gpt-4o", "ai.reasoning_effort": "low"},
		{"ai.chat_model": "gpt-5", "ai.reasoning_effort": "none"},
		{"ai.reasoning_effort": "bogus"},
		{"ai.max_concurrent_jobs": "0", "subtitle_ai.max_concurrent_jobs": "5"},
		{"ai.max_concurrent_jobs": "3", "subtitle_ai.max_concurrent_jobs": "5"},
		{"ai.max_concurrent_jobs": "", "subtitle_ai.max_concurrent_jobs": "5"},
		{"ai.max_concurrent_jobs": "x", "subtitle_ai.max_concurrent_jobs": "5"},
		{"ai.max_concurrent_jobs": "-1"},
		{"ai.max_concurrent_jobs": "0", "subtitle_ai.max_concurrent_jobs": "x"},
		{"subtitle_ai.enabled": "1", "subtitle_ai.transcribe_enabled": "T", "subtitle_ai.batch_size": "1", "subtitle_ai.context_neighbors": "2", "subtitle_ai.asr_chunk_seconds": "60", "subtitle_ai.live_asr_chunk_seconds": "15", "subtitle_ai.transcribe_quota_jobs": "4", "subtitle_ai.transcribe_quota_period": "week"},
		{"subtitle_ai.transcribe_quota_jobs": "x", "subtitle_ai.transcribe_quota_period": "decade"},
		{"subtitle_ai.transcribe_quota_jobs": "-1", "subtitle_ai.transcribe_quota_period": "MONTH"},
		{"metadata_ai.enabled": "1", "metadata_ai.on_view": "auto"},
		{"metadata_ai.on_view": "AUTO"},
		{"download.enabled": "1", "download.server_bandwidth_mbps": "8", "download.user_bandwidth_mbps": "4", "download.max_concurrent_per_user": "0", "download.max_per_period": "2", "download.period_duration": "1h", "download.transcode_enabled": "t", "download.max_concurrent_prepares": "1", "download.artifact_max_bytes": "9", "download.artifact_cache_hours": "0", "download.artifact_disk_ceiling_percent": "50", "download.artifact_dir": " /a ", "allow_4k_transcode": "FALSE", "playback.allow_hevc_encoding": " True "},
		{"download.server_bandwidth_mbps": "-1"},
		{"download.user_bandwidth_mbps": "-1"},
		{"download.server_bandwidth_mbps": "73786976294839"},
		{"download.user_bandwidth_mbps": "73786976294839"},
		{"download.max_concurrent_per_user": "-1"},
		{"download.max_per_period": "-1"},
		{"download.max_per_period": "1", "download.period_duration": "0s"},
		{"download.max_concurrent_prepares": "-1"},
		{"download.artifact_max_bytes": "-1"},
		{"download.artifact_cache_hours": "721"},
		{"download.artifact_disk_ceiling_percent": "96"},
		{"download.artifact_dir": "relative"},
		{"allow_4k_transcode": "maybe", "playback.allow_hevc_encoding": "1"},
		{"policy.eval_timeout_ms": "1", "policy.editor_enabled": "1", "policy.decision_log_verbosity": "verbose", "policy.decision_log_scope_sample_rate": "2", "policy.decision_log_retention_days": "3"},
		{"clientip.trusted_proxies": "1.1.1.1/32", "server.public_url": "https://x", "server.local_url": "http://l", "server.lan_discovery": "false", "tmdb.api_key": "t", "mdblist.api_key": "m"},
		{"server.lan_discovery": "x"},
		{"s3.public_endpoint": "e"},
		{"s3.public_bucket": "b"},
		{"s3.public_access_key": "a"},
		{"s3.private_endpoint": "e"},
		{"s3.private_secret_key": "s"},
		{"s3.public_url_auth": "public"},
		{"s3.public_url_auth": "cloudflare_token", "s3.public_read_endpoint": "r"},
		{"s3.public_url_auth": "cloudflare_token", "s3.public_read_endpoint": "r", "s3.public_token_secret": "t"},
		{"s3.public_url_auth": "bogus"},
		{"email.enabled": "true"},
		{"email.enabled": "true", "email.smtp_host": "h"},
		{"email.enabled": "true", "email.smtp_host": "h", "email.from_address": "a@b"},
		{"watchsync.simkl.client_id": "i"},
		{"watchsync.simkl.client_id": "i", "watchsync.simkl.client_secret": "s"},
		{"playback.watched_threshold": "5", "playback.min_resume_threshold": "5"},
		{"playback.watched_threshold": "x", "playback.min_resume_threshold": "99"},
		{"server.log_level": "", "branding.server_name": "", "unknown.key": "", "another.key": "v"},
		{"overlays.enabled": "false", "markers.mode": "x"},
	}
	out := make([]settingsMapCase, 0, len(maps))
	for _, m := range maps {
		out = append(out, settingsCase(m))
	}

	defaults := config.EffectiveAdminSettings(nil)
	restart := map[string]bool{}
	keys := sortedKeys(defaults)
	keys = append(keys, "unknown.key", "database.anything", "userdb.x", "s3.y", "artwork.z", "redis.q", "recommendations.r", "server.listen", "server.mode", "server.public_url", "auth.jwt_secret", "auth.access_token_expiry", "tmdb.api_key", "catalog.search.meilisearch.url", "catalog.search.meilisearch.index_types", "download.artifact_dir")
	for _, k := range keys {
		restart[k] = config.RestartRequired(k)
	}
	misc := map[string]any{
		"defaults":         defaults,
		"restart_keys":     config.RestartRequiredKeys(),
		"restart_prefixes": config.RestartRequiredPrefixes(),
		"restart_required": restart,
		"server_id":        goJSON(mustLoad(map[string]string{}).JellyfinCompat.ServerID),
	}
	enabled := []map[string]any{}
	for _, c := range [][2]string{{"allow_4k_transcode", ""}, {"allow_4k_transcode", " true "}, {"allow_4k_transcode", "TRUE"}, {"allow_4k_transcode", "1"}, {"playback.allow_hevc_encoding", ""}, {"unknown", ""}, {"unknown", "true"}} {
		enabled = append(enabled, map[string]any{"key": c[0], "stored": c[1], "enabled": config.AdminSettingEnabled(c[0], c[1])})
	}
	misc["enabled"] = enabled
	widths := map[string]int{}
	for _, v := range []string{"", " ", "abc", "300", " 301 ", "100", "1000", "160", "640", "-5", "1e3", "99999999999999999999"} {
		widths[v] = config.PreviewImageWidth(v)
	}
	misc["preview_widths"] = widths
	durs := map[string]string{}
	for _, v := range []string{"", " ", "1h", "1d", "30d", "0d", "-1d", "1.5d", "00030d", "99999999d", "9223372036854775807d", "9223372036854775808d", "1h30m", "bad", "5", "0", "1dd", "d", "100000000d"} {
		d, _ := parseDur(v)
		durs[v] = d
	}
	misc["durations"] = durs
	recheck := map[string]int64{}
	refresh := map[string]int64{}
	for _, v := range []string{"", " ", "1h", " 1d ", "0s", "-1h", "bad"} {
		recheck[v] = int64(config.AuthProviderRecheckInterval(v))
		refresh[v] = int64(config.AuthRefreshTokenExpiry(v))
	}
	misc["recheck"] = recheck
	misc["refresh"] = refresh
	lists := map[string][]string{}
	for _, v := range []string{"", ",", "a", "A, b ,a,, c_1", "1bad,ok", strings.Repeat("a", 33), strings.Repeat("a", 32)} {
		l := config.ParseRatingSourceList(v)
		if l == nil {
			l = []string{}
		}
		lists[v] = l
	}
	misc["rating_lists"] = lists
	artifacts := [][3]string{}
	for _, c := range [][2]string{{"", ""}, {"/a", "/t"}, {"", "/srv/transcode"}, {"", "/srv/transcode/"}, {"", "relative/x"}, {"", "/"}, {"", "x"}} {
		artifacts = append(artifacts, [3]string{c[0], c[1], config.EffectiveDownloadArtifactDir(c[0], c[1])})
	}
	misc["artifact_dirs"] = artifacts
	validateModes := []map[string]any{}
	for _, c := range []config.Config{
		{}, {Server: config.ServerConfig{Mode: "banana"}}, {Server: config.ServerConfig{Mode: "api"}}, {Server: config.ServerConfig{Mode: "frontend"}},
		{Server: config.ServerConfig{Mode: "proxy"}}, {Server: config.ServerConfig{Mode: "proxy"}, Database: config.DatabaseConfig{URL: "d"}},
		{Server: config.ServerConfig{Mode: "transcode"}, Database: config.DatabaseConfig{URL: "d"}, Redis: config.RedisConfig{URL: "r"}},
		{Server: config.ServerConfig{Mode: "integrated"}, Database: config.DatabaseConfig{URL: "d"}},
	} {
		msg := ""
		if err := c.Validate(); err != nil {
			msg = err.Error()
		}
		validateModes = append(validateModes, map[string]any{"mode": c.Server.Mode, "db": c.Database.URL, "redis": c.Redis.URL, "error": msg})
	}
	misc["validate"] = validateModes
	misc["abs_listen"] = [][3]string{
		{"", ":1", (config.AudiobookshelfCompatConfig{}).WithBootstrapListen(":1").Listen},
		{":2", ":1", (config.AudiobookshelfCompatConfig{Listen: ":2"}).WithBootstrapListen(":1").Listen},
		{":2", "", (config.AudiobookshelfCompatConfig{Listen: ":2"}).WithBootstrapListen("").Listen},
	}
	probes := map[string]int64{}
	for _, d := range []int{0, -1, 1, 30} {
		probes[fmt.Sprint(d)] = int64(config.PlaybackConfig{BandwidthProbeMaxAgeDays: d}.BandwidthProbeMaxAge())
	}
	misc["probe_ages"] = probes
	write("settings_maps.json", map[string]any{"cases": out, "misc": misc})
}

func mustLoad(m map[string]string) *config.Config {
	c, err := config.LoadFromDB(m)
	if err != nil {
		panic(err)
	}
	return c
}

// parseDur reaches config's unexported parseDuration through the setting that uses it unclamped.
func parseDur(v string) (string, error) {
	c, err := config.LoadFromDB(map[string]string{"auth.access_token_expiry": v})
	if err != nil {
		return "error: " + err.Error(), nil
	}
	return fmt.Sprint(int64(c.Auth.AccessTokenExpiry)), nil
}

type normalizeVector struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	result
}

func normalize(key, value string) normalizeVector {
	return normalizeVector{Key: key, Value: value, result: catch(func() result {
		v, err := config.NormalizeAdminSetting(key, value)
		if err != nil {
			return result{Error: err.Error()}
		}
		return result{Ok: v}
	})}
}

func writeNormalizeVectors() {
	keys := sortedKeys(config.EffectiveAdminSettings(nil))
	keys = append(keys,
		"s3.public_endpoint", "s3.public_read_endpoint", "s3.private_endpoint", "s3.user_db_endpoint", "catalog.search.meilisearch.url", "redis.url", "redis.db", "email.from_address", "defaults.card_overlays", "opslog.bucket_policies", "ui.admin_theme_vars", "ui.dashboard.hidden_attention",
		"ai.base_url", "ai.api_key", "ai.asr_base_url", "ai.asr_api_key", "subtitle_ai.base_url", "subtitle_ai.api_key", "recommendations.embedding_base_url", "recommendations.embedding_auth_token", "recommendations.openai_model", "recommendations.openai_api_key", "recommendations.embedding_provider",
		"ai.text_provider_id", "ai.speech_provider_id", "recommendations.embedding_provider_id", "subtitle_ai.max_concurrent_jobs",
		"defaults.ui.title_art", "defaults.ui.next_up_mode", "defaults.ui.next_up_new_releases_first", "defaults.ui.theme", "defaults.nope", "unknown.key", "playback.ffmpeg_path")
	values := []string{"", " ", "true", " TRUE ", "T", "0", "1", "maybe", "-1", "2", "60", "120", "300", "301", "1000", "99999999999999999999", "0.5", "1.5", "1e999", "nan", "inf", "12h", "4m", "5m", "30d", "31d", "0s", "-1h", "soon",
		"auto", "S3", "Local", "none", "off", "Hide", "ALLOW", "digest", "VERBOSE", "postgres", "/abs/path/../x", "rel/path", "http://h/", "https://h///", "ftp://h", "h", "http://", "http://u@h", "http://h/p", "http://h?q=1", "http://h#f",
		"redis://h:1/2", "bad://x", "0 3 * * *", "@every 1h", "@every x", "CRON_TZ=UTC 0 3 * * *", "CRON_TZ=UTC", "TZ=Nope/Nope 0 3 * * *", "* * * *", "en", "FR", "xx", "original", "fra", "a@b.com", "A <a@b.com>", "a b",
		"[]", `["a"," a ","b",""]`, `[1]`, `[null]`, "null", `{"a":1}`, "{", `"combined"`, `"separate"`, "false", `"x"`, "imdb, TMDB ,imdb", "1bad", "api_only", "prefer_worker", "prefer_proxy", "best_effort", "priority", "xhigh", "chatgpt", "https://raw.githubusercontent.com/x/", "https://evil.example/x", "http://github.com/x", "starttls", "meilisearch", "ALL", "button", "week", "error", "warning", "local", "transcode_nodes_only", "server", "fail_closed", "cloudflare_token",
	}
	out := make([]normalizeVector, 0, len(keys)*len(values))
	for _, k := range keys {
		for _, v := range values {
			out = append(out, normalize(k, v))
		}
	}
	hidden := []string{"[" + strings.Repeat(`"a",`, 40) + `"a"]`, `["` + strings.Repeat("x", 65) + `"]`, `["` + strings.Repeat("x", 64) + `"]`}
	longIDs := make([]string, 33)
	for i := range longIDs {
		longIDs[i] = fmt.Sprintf(`"id%d"`, i)
	}
	hidden = append(hidden, "["+strings.Join(longIDs, ",")+"]", "["+strings.Join(longIDs[:32], ",")+"]", `["<b>&"]`)
	for _, v := range hidden {
		out = append(out, normalize("ui.dashboard.hidden_attention", v))
	}
	write("normalize_admin.json", out)
}
