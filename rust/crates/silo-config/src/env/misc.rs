//! The remaining startup environment reads, one function per Go reader.

use super::{Env, bool_default};
use crate::config::normalize_admin_setting;
use crate::gonet::{parse_addr, split_host_port, valid_cidr};
use crate::goparse::{atoi, parse_float};
use silo_gocompat::strconv::quote;
use silo_gocompat::strings::trim_space;
use silo_gocompat::time::{Duration, parse_duration};
use std::collections::BTreeMap;

const MAX_DURATION_SECONDS: i64 = i64::MAX / Duration::SECOND.0;

/// `SILO_METRICS_LISTEN`, trimmed. Empty means no metrics listener.
pub fn metrics_listen(env: &Env) -> String {
    trim_space(env.get("SILO_METRICS_LISTEN")).to_owned()
}

fn seconds_or_duration(value: &str, default: Duration, env_name: &str) -> Duration {
    let value = trim_space(value);
    if value.is_empty() {
        return default;
    }
    if let Ok(seconds) = atoi(value)
        && (0..=MAX_DURATION_SECONDS).contains(&seconds)
    {
        return Duration(seconds * Duration::SECOND.0);
    }
    if let Ok(d) = parse_duration(value)
        && d.0 >= 0
    {
        return d;
    }
    tracing::warn!(
        env = env_name,
        value = value,
        "invalid duration; using the default"
    );
    default
}

/// `apiShutdownDelay` on `SILO_SHUTDOWN_DELAY`: a Go duration or whole seconds; empty or invalid is 5s.
pub fn api_shutdown_delay(value: &str) -> Duration {
    seconds_or_duration(
        value,
        Duration(5 * Duration::SECOND.0),
        "SILO_SHUTDOWN_DELAY",
    )
}

/// `nodeDrainTimeout` on `SILO_NODE_DRAIN_TIMEOUT`: a Go duration or whole seconds; empty or invalid
/// is 10 minutes, and 0 turns the drain off.
pub fn node_drain_timeout(value: &str) -> Duration {
    seconds_or_duration(
        value,
        Duration(10 * Duration::MINUTE.0),
        "SILO_NODE_DRAIN_TIMEOUT",
    )
}

/// `resolveNodeIdentity`: `SILO_NODE_NAME`, then `NODE_NAME`, then the host name.
pub fn resolve_node_identity(env: &Env, hostname: &str) -> String {
    let v = env.get("SILO_NODE_NAME");
    if !v.is_empty() {
        return v.to_owned();
    }
    let v = env.get("NODE_NAME");
    if !v.is_empty() {
        return v.to_owned();
    }
    hostname.to_owned()
}

/// `SILO_PLUGIN_CACHE_DIR`, trimmed. Empty means the private directory `silo-plugins` under the temp dir.
pub fn plugin_cache_dir_override(env: &Env) -> String {
    trim_space(env.get("SILO_PLUGIN_CACHE_DIR")).to_owned()
}

/// `MigrationTimeout` on `SILO_MIGRATE_TIMEOUT`: unset or unparseable is 20 minutes, and 0 or a
/// negative value disables the deadline.
pub fn migration_timeout(env: &Env) -> Duration {
    const DEFAULT: Duration = Duration(20 * Duration::MINUTE.0);
    let raw = trim_space(env.get("SILO_MIGRATE_TIMEOUT"));
    if raw.is_empty() {
        return DEFAULT;
    }
    match parse_duration(raw) {
        Ok(d) => d,
        Err(error) => {
            tracing::warn!(env = "SILO_MIGRATE_TIMEOUT", value = raw, default = %DEFAULT, error = %error,
                "invalid migration timeout; using default");
            DEFAULT
        }
    }
}

/// `SILO_QUERY_ATTRIBUTION_ENABLED`, off by default.
pub fn query_attribution_enabled(env: &Env) -> bool {
    bool_default(env, "SILO_QUERY_ATTRIBUTION_ENABLED", false)
}

/// `debugserver.Config`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DebugServerConfig {
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "BlockRate")]
    pub block_rate: i64,
    #[serde(rename = "MutexFraction")]
    pub mutex_fraction: i64,
}

fn sampling_setting(raw: &str, name: &str, min: i64, max: i64) -> Result<i64, String> {
    if raw.is_empty() || raw == "0" {
        return Ok(0);
    }
    match atoi(raw) {
        Ok(n) if n >= min && n <= max => Ok(n),
        _ => Err(format!(
            "{name} must be 0 (disabled) or an integer between {min} and {max}"
        )),
    }
}

fn loopback_authority(authority: &str) -> bool {
    let Ok((host, port)) = split_host_port(authority) else {
        return false;
    };
    let Ok(ip) = parse_addr(&host) else {
        return false;
    };
    if !ip.zone().is_empty() || !ip.is_loopback() {
        return false;
    }
    if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    atoi(&port).is_ok_and(|n| n > 0 && n <= 65535)
}

/// `debugserver.LoadConfig`: only a literal loopback address may host the profiler.
pub fn debug_server_config(env: &Env) -> Result<DebugServerConfig, String> {
    let mut c = DebugServerConfig {
        listen: env.get("SILO_DEBUG_LISTEN").to_owned(),
        ..Default::default()
    };
    c.block_rate = sampling_setting(
        env.get("SILO_DEBUG_BLOCK_RATE"),
        "SILO_DEBUG_BLOCK_RATE",
        1_000_000,
        1_000_000_000,
    )?;
    c.mutex_fraction = sampling_setting(
        env.get("SILO_DEBUG_MUTEX_FRACTION"),
        "SILO_DEBUG_MUTEX_FRACTION",
        100,
        1_000_000,
    )?;
    if c.listen.is_empty() {
        if c.block_rate != 0 || c.mutex_fraction != 0 {
            return Err("contention sampling requires SILO_DEBUG_LISTEN".to_owned());
        }
        return Ok(c);
    }
    if !loopback_authority(&c.listen) {
        return Err(
            "SILO_DEBUG_LISTEN must be a literal loopback IP and port from 1 to 65535".to_owned(),
        );
    }
    Ok(c)
}

/// `clientip.EnvTrustedProxies`.
pub const ENV_TRUSTED_PROXIES: &str = "SILO_TRUSTED_PROXIES";
/// `clientip.SettingTrustedProxies`.
pub const SETTING_TRUSTED_PROXIES: &str = "clientip.trusted_proxies";
/// `clientip.DefaultTrustedProxies`.
pub const DEFAULT_TRUSTED_PROXIES: &str =
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128";

/// `clientip.NormalizeCIDRList`.
pub fn normalize_cidr_list(raw: &str) -> Result<String, String> {
    let mut out = Vec::new();
    for p in raw.split(',') {
        let p = trim_space(p);
        if p.is_empty() {
            continue;
        }
        if !valid_cidr(p) {
            return Err(format!(
                "invalid CIDR {} (expected e.g. 203.0.113.7/32)",
                quote(p)
            ));
        }
        out.push(p);
    }
    Ok(out.join(", "))
}

/// `SILO_TRUSTED_PROXIES` as `cmd/silo` reads it: `None` when unset, and a startup failure when set
/// to a list that does not parse.
pub fn trusted_proxies_from_env(env: &Env) -> Result<Option<String>, String> {
    let raw = trim_space(env.get(ENV_TRUSTED_PROXIES));
    if raw.is_empty() {
        return Ok(None);
    }
    normalize_cidr_list(raw)
        .map(Some)
        .map_err(|e| format!("invalid {ENV_TRUSTED_PROXIES}: {e}"))
}

const SEARCH_SETTING_ENV_VARS: [(&str, &str); 3] = [
    ("SILO_SEARCH_PROVIDER", "catalog.search.provider"),
    ("SILO_MEILISEARCH_URL", "catalog.search.meilisearch.url"),
    (
        "SILO_MEILISEARCH_API_KEY",
        "catalog.search.meilisearch.api_key",
    ),
];

/// `catalog.SearchSettingsFromEnv`: the search settings the environment sets, normalized as an admin
/// save normalizes them.
pub fn search_settings_from_env(env: &Env) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    for (name, key) in SEARCH_SETTING_ENV_VARS {
        let raw = trim_space(env.get(name));
        if raw.is_empty() {
            continue;
        }
        let normalized =
            normalize_admin_setting(key, raw).map_err(|e| format!("invalid {name}: {e}"))?;
        values.insert(key.to_owned(), normalized);
    }
    Ok(values)
}

fn positive_int(env: &Env, name: &str) -> Option<i64> {
    let v = env.get(name);
    if v.is_empty() {
        return None;
    }
    atoi(v).ok().filter(|n| *n > 0)
}

/// `httpstream.StallWindow` on `SILO_STREAM_WRITE_STALL_TIMEOUT`, whole seconds, 180s by default.
pub fn stream_stall_window(env: &Env) -> Duration {
    match positive_int(env, "SILO_STREAM_WRITE_STALL_TIMEOUT") {
        Some(secs) => Duration(secs.wrapping_mul(Duration::SECOND.0)),
        None => Duration(180 * Duration::SECOND.0),
    }
}

/// `ebooks.rateLimitCooldownFloor` on `SILO_EBOOK_RATE_LIMIT_COOLDOWN`.
pub fn ebook_rate_limit_cooldown(env: &Env) -> Duration {
    let v = env.get("SILO_EBOOK_RATE_LIMIT_COOLDOWN");
    if !v.is_empty()
        && let Ok(p) = parse_duration(v)
        && p.0 > 0
    {
        return p;
    }
    Duration(15 * Duration::MINUTE.0)
}

/// `ebooks.ebookEnrichWorkers`.
pub fn ebook_enrich_workers(env: &Env) -> i64 {
    positive_int(env, "SILO_EBOOK_ENRICH_WORKERS")
        .unwrap_or(4)
        .min(5000)
}

/// `audiobooks.audiobookEnrichBatchSize`.
pub fn audiobook_enrich_batch_size(env: &Env) -> i64 {
    positive_int(env, "SILO_AUDIOBOOK_ENRICH_BATCH_SIZE").unwrap_or(250)
}

/// `audiobooks.audiobookEnrichWorkers`, capped to the active batch size.
pub fn audiobook_enrich_workers(env: &Env, batch_size: i64) -> i64 {
    let n = positive_int(env, "SILO_AUDIOBOOK_ENRICH_WORKERS").unwrap_or(4);
    if batch_size > 0 && n > batch_size {
        batch_size
    } else {
        n
    }
}

/// `manga.mangaEnrichBatchSize`.
pub fn manga_enrich_batch_size(env: &Env) -> i64 {
    positive_int(env, "SILO_MANGA_ENRICH_BATCH").unwrap_or(140)
}

/// `manga.mangaEnrichWorkers`.
pub fn manga_enrich_workers(env: &Env) -> i64 {
    positive_int(env, "SILO_MANGA_ENRICH_WORKERS")
        .unwrap_or(4)
        .min(manga_enrich_batch_size(env))
}

/// `scanner.audiobookScanWorkers`, 8 by default.
pub fn audiobook_scan_workers(env: &Env) -> i64 {
    positive_int(env, "SILO_AUDIOBOOK_SCAN_WORKERS").unwrap_or(8)
}

/// `scanner.ebookScanWorkers`, falling back to the audiobook setting.
pub fn ebook_scan_workers(env: &Env) -> i64 {
    positive_int(env, "SILO_EBOOK_SCAN_WORKERS").unwrap_or_else(|| audiobook_scan_workers(env))
}

/// `metadata.matchThreshold`: an out-of-range value is ignored, and the calibrated default is 0.5.
pub fn metadata_match_threshold(env: &Env) -> f64 {
    const MIN_TITLE_SCORE: f64 = 0.5;
    let raw = trim_space(env.get("SILO_METADATA_MATCH_MIN_SCORE"));
    if raw.is_empty() {
        return MIN_TITLE_SCORE;
    }
    match parse_float(raw) {
        Ok(v) if !v.is_nan() && !v.is_infinite() && v > 0.0 && v <= 1.0 => v,
        _ => MIN_TITLE_SCORE,
    }
}

/// `tasks.parseEbookBackfillMaxClaims` on `SILO_EBOOK_BACKFILL_MAX_CLAIMS`.
pub fn ebook_backfill_max_claims(raw: &str) -> Result<i64, String> {
    let raw = trim_space(raw);
    if raw.is_empty() {
        return Ok(0);
    }
    match atoi(raw) {
        Ok(v) if v > 0 => Ok(v),
        _ => Err(format!(
            "SILO_EBOOK_BACKFILL_MAX_CLAIMS must be a positive integer, got {}",
            quote(raw)
        )),
    }
}

/// `tasks.parseEbookBackfillBatchDelay` on `SILO_EBOOK_BACKFILL_BATCH_DELAY`.
pub fn ebook_backfill_batch_delay(raw: &str) -> Result<Duration, String> {
    let raw = trim_space(raw);
    if raw.is_empty() {
        return Ok(Duration(0));
    }
    match parse_duration(raw) {
        Ok(v) if v.0 > 0 => Ok(v),
        _ => Err(format!(
            "SILO_EBOOK_BACKFILL_BATCH_DELAY must be a positive Go duration, got {}",
            quote(raw)
        )),
    }
}

/// `JELLYCOMPAT_DEBUG_LOG` and `JELLYCOMPAT_DEBUG_USER_AGENT`.
pub fn jellycompat_debug_log(env: &Env) -> Option<(String, String)> {
    let path = env.get("JELLYCOMPAT_DEBUG_LOG");
    if path.is_empty() {
        return None;
    }
    Some((
        path.to_owned(),
        env.get("JELLYCOMPAT_DEBUG_USER_AGENT").to_owned(),
    ))
}

/// `SILO_PUSH_RELAY_DEVELOPMENT_URL`, as the push sender and admin handler read it.
pub fn push_relay_development_url(env: &Env) -> String {
    env.get("SILO_PUSH_RELAY_DEVELOPMENT_URL").to_owned()
}
