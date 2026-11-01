//! `internal/streamtelemetry`'s configuration.

use super::{Env, bool_default, env_bool, is_set};
use crate::config::types_ser_duration as ser_duration;
use crate::goparse::{atoi, parse_int};
use serde::Serialize;
use silo_gocompat::strings::{to_lower, trim_space};
use silo_gocompat::time::{Duration, parse_duration};
use std::collections::{BTreeMap, HashSet};

const ENABLED_ENV: &str = "SILO_STREAM_TELEMETRY_ENABLED";
const FAMILIES_ENV: &str = "SILO_STREAM_TELEMETRY_FAMILIES";
const SWEEP_INTERVAL_ENV: &str = "SILO_STREAM_TELEMETRY_SWEEP_INTERVAL";
const RETENTION_ENV: &str = "SILO_STREAM_TELEMETRY_RETENTION";
const MAX_SESSIONS_ENV: &str = "SILO_STREAM_TELEMETRY_MAX_SESSIONS";
const MAX_TRANSFERS_ENV: &str = "SILO_STREAM_TELEMETRY_MAX_TRANSFERS";
const MAX_OBSERVATIONS_ENV: &str = "SILO_STREAM_TELEMETRY_MAX_OBSERVATIONS";
const DISTRIBUTED_ENV: &str = "SILO_STREAM_TELEMETRY_DISTRIBUTED";
const FRESHNESS_ENV: &str = "SILO_STREAM_TELEMETRY_FRESHNESS";
const MEMBERSHIP_TTL_ENV: &str = "SILO_STREAM_TELEMETRY_MEMBERSHIP_TTL";
const KEY_PREFIX_ENV: &str = "SILO_STREAM_TELEMETRY_KEY_PREFIX";
const FULL_RESYNC_EVERY_ENV: &str = "SILO_STREAM_TELEMETRY_FULL_RESYNC_EVERY";
const MAX_PUBLISHERS_ENV: &str = "SILO_STREAM_TELEMETRY_MAX_PUBLISHERS";
const MAX_MERGED_SESSIONS_ENV: &str = "SILO_STREAM_TELEMETRY_MAX_MERGED_SESSIONS";
const MAX_MERGED_TRANSFERS_ENV: &str = "SILO_STREAM_TELEMETRY_MAX_MERGED_TRANSFERS";
const VIEW_TTL_ENV: &str = "SILO_STREAM_TELEMETRY_VIEW_TTL";

const FAMILY_NAMES: [&str; 5] = ["native", "jellycompat", "proxy", "abs", "transcode_node"];

/// `streamtelemetry.Config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Config {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "NodeID")]
    pub node_id: String,
    #[serde(rename = "PublisherID")]
    pub publisher_id: String,
    #[serde(rename = "PublisherEpoch")]
    pub publisher_epoch: i64,
    #[serde(rename = "Distributed")]
    pub distributed: bool,
    #[serde(rename = "DistributedExplicit")]
    pub distributed_explicit: bool,
    /// The observed families; empty means every declared family.
    #[serde(rename = "Families")]
    pub families: Option<BTreeMap<String, bool>>,
    #[serde(rename = "SweepInterval", serialize_with = "ser_duration")]
    pub sweep_interval: Duration,
    #[serde(rename = "Retention", serialize_with = "ser_duration")]
    pub retention: Duration,
    #[serde(rename = "Freshness", serialize_with = "ser_duration")]
    pub freshness: Duration,
    #[serde(rename = "MembershipTTL", serialize_with = "ser_duration")]
    pub membership_ttl: Duration,
    #[serde(rename = "KeyPrefix")]
    pub key_prefix: String,
    #[serde(rename = "ViewTTL", serialize_with = "ser_duration")]
    pub view_ttl: Duration,
    #[serde(rename = "FullResyncEvery")]
    pub full_resync_every: i64,
    #[serde(rename = "MaxPublishers")]
    pub max_publishers: i64,
    #[serde(rename = "MaxMergedSessions")]
    pub max_merged_sessions: i64,
    #[serde(rename = "MaxMergedTransfers")]
    pub max_merged_transfers: i64,
    #[serde(rename = "MaxSessions")]
    pub max_sessions: i64,
    #[serde(rename = "MaxTransfers")]
    pub max_transfers: i64,
    #[serde(rename = "MaxObservations")]
    pub max_observations: i64,
    #[serde(rename = "MaxObservationsPerSession")]
    pub max_observations_per_session: i64,
    #[serde(rename = "MaxViewerIPsPerSession")]
    pub max_viewer_ips_per_session: i64,
    #[serde(rename = "MaxIdentityConflictsPerSession")]
    pub max_identity_conflicts_per_session: i64,
    #[serde(rename = "MaxDeviceIDsPerSession")]
    pub max_device_ids_per_session: i64,
    #[serde(rename = "MaxClientVariantsPerSession")]
    pub max_client_variants_per_session: i64,
    #[serde(rename = "MaxMediaFileIDsPerSession")]
    pub max_media_file_ids_per_session: i64,
    #[serde(rename = "MaxPlayMethodsPerSession")]
    pub max_play_methods_per_session: i64,
    #[serde(rename = "MaxTokenIssuedAtPerSession")]
    pub max_token_issued_at_per_session: i64,
    #[serde(rename = "MaxRoutesPerSession")]
    pub max_routes_per_session: i64,
}

/// `streamtelemetry.DefaultConfig`.
pub fn default_config(node_id: &str) -> Config {
    Config {
        enabled: false,
        node_id: node_id.to_owned(),
        publisher_id: String::new(),
        publisher_epoch: 0,
        distributed: false,
        distributed_explicit: false,
        families: None,
        sweep_interval: Duration::SECOND,
        retention: Duration(5 * Duration::MINUTE.0),
        freshness: Duration(5 * Duration::SECOND.0),
        membership_ttl: Duration::MINUTE,
        key_prefix: "silo:stelem".to_owned(),
        view_ttl: Duration(5 * Duration::SECOND.0),
        full_resync_every: 60,
        max_publishers: 256,
        max_merged_sessions: 50_000,
        max_merged_transfers: 50_000,
        max_sessions: 10_000,
        max_transfers: 10_000,
        max_observations: 50_000,
        max_observations_per_session: 64,
        max_viewer_ips_per_session: 32,
        max_identity_conflicts_per_session: 16,
        max_device_ids_per_session: 32,
        max_client_variants_per_session: 16,
        max_media_file_ids_per_session: 32,
        max_play_methods_per_session: 16,
        max_token_issued_at_per_session: 32,
        max_routes_per_session: 32,
    }
}

fn parse_families(value: &str) -> Option<BTreeMap<String, bool>> {
    let mut families = BTreeMap::new();
    for entry in value.split(',') {
        let name = to_lower(trim_space(entry));
        if name.is_empty() {
            continue;
        }
        if !FAMILY_NAMES.contains(&name.as_str()) {
            return None;
        }
        families.insert(name, true);
    }
    Some(families)
}

const MAX_DURATION: i64 = i64::MAX;

/// `streamtelemetry.ConfigFromEnv`: a safe configuration. Invalid core settings disable telemetry;
/// invalid distributed-only settings retain local telemetry.
pub fn config_from_env(env: &Env, node_id: &str) -> Config {
    let mut cfg = default_config(node_id);
    cfg.enabled = bool_default(env, ENABLED_ENV, true);
    let mut core_invalid: Vec<String> = Vec::new();
    let mut distributed_invalid: Vec<String> = Vec::new();
    let mut explicit: HashSet<&str> = HashSet::new();
    cfg.distributed = env_bool(env, DISTRIBUTED_ENV);
    cfg.distributed_explicit = is_set(env, DISTRIBUTED_ENV);

    let duration_var = |name: &'static str,
                        dst: &mut Duration,
                        explicit: &mut HashSet<&'static str>,
                        invalid: &mut Vec<String>| {
        let value = trim_space(env.get(name));
        if value.is_empty() {
            return;
        }
        explicit.insert(name);
        match parse_duration(value) {
            Ok(p) if p.0 > 0 => *dst = p,
            _ => invalid.push(name.to_owned()),
        }
    };
    let positive_int64 = |name: &'static str, dst: &mut i64, invalid: &mut Vec<String>| {
        let value = trim_space(env.get(name));
        if value.is_empty() {
            return;
        }
        match parse_int(value, 10, 64) {
            Ok(p) if p > 0 => *dst = p,
            _ => invalid.push(name.to_owned()),
        }
    };
    let positive_int = |name: &'static str, dst: &mut i64, invalid: &mut Vec<String>| {
        let value = trim_space(env.get(name));
        if value.is_empty() {
            return;
        }
        match atoi(value) {
            Ok(p) if p > 0 => *dst = p,
            _ => invalid.push(name.to_owned()),
        }
    };

    duration_var(
        SWEEP_INTERVAL_ENV,
        &mut cfg.sweep_interval,
        &mut explicit,
        &mut core_invalid,
    );
    duration_var(
        RETENTION_ENV,
        &mut cfg.retention,
        &mut explicit,
        &mut core_invalid,
    );
    positive_int64(MAX_SESSIONS_ENV, &mut cfg.max_sessions, &mut core_invalid);
    positive_int64(MAX_TRANSFERS_ENV, &mut cfg.max_transfers, &mut core_invalid);
    positive_int64(
        MAX_OBSERVATIONS_ENV,
        &mut cfg.max_observations,
        &mut core_invalid,
    );
    duration_var(
        FRESHNESS_ENV,
        &mut cfg.freshness,
        &mut explicit,
        &mut distributed_invalid,
    );
    duration_var(
        MEMBERSHIP_TTL_ENV,
        &mut cfg.membership_ttl,
        &mut explicit,
        &mut distributed_invalid,
    );
    duration_var(
        VIEW_TTL_ENV,
        &mut cfg.view_ttl,
        &mut explicit,
        &mut distributed_invalid,
    );
    positive_int(
        FULL_RESYNC_EVERY_ENV,
        &mut cfg.full_resync_every,
        &mut distributed_invalid,
    );
    positive_int(
        MAX_PUBLISHERS_ENV,
        &mut cfg.max_publishers,
        &mut distributed_invalid,
    );
    positive_int(
        MAX_MERGED_SESSIONS_ENV,
        &mut cfg.max_merged_sessions,
        &mut distributed_invalid,
    );
    positive_int(
        MAX_MERGED_TRANSFERS_ENV,
        &mut cfg.max_merged_transfers,
        &mut distributed_invalid,
    );

    let value = trim_space(env.get(FAMILIES_ENV));
    if !value.is_empty() {
        match parse_families(value) {
            Some(f) => cfg.families = Some(f),
            None => core_invalid.push(FAMILIES_ENV.to_owned()),
        }
    }
    let value = env.get(KEY_PREFIX_ENV);
    if !value.is_empty() {
        if trim_space(value).is_empty()
            || value
                .chars()
                .any(|r| silo_gocompat::unicode::is_space(r as u32))
        {
            distributed_invalid.push(KEY_PREFIX_ENV.to_owned());
        } else {
            cfg.key_prefix = value.to_owned();
        }
    }

    let cross_check_failed =
        |involved: &[&str], explicit: &HashSet<&str>, out: &mut Vec<String>| {
            let mut named: Vec<String> = involved
                .iter()
                .filter(|n| explicit.contains(*n))
                .map(|n| (*n).to_owned())
                .collect();
            if named.is_empty() {
                named = involved.iter().map(|n| (*n).to_owned()).collect();
            }
            out.extend(named);
        };
    let third = Duration(MAX_DURATION / 3);
    if !explicit.contains(FRESHNESS_ENV)
        && cfg.sweep_interval.0 <= third.0
        && cfg.freshness.0 < cfg.sweep_interval.0.wrapping_mul(3)
    {
        cfg.freshness = Duration(cfg.sweep_interval.0.wrapping_mul(3));
    }
    if !explicit.contains(SWEEP_INTERVAL_ENV)
        && cfg.freshness.0 < cfg.sweep_interval.0.wrapping_mul(3)
    {
        cfg.sweep_interval = Duration(cfg.freshness.0 / 3);
    }
    if !explicit.contains(MEMBERSHIP_TTL_ENV) && cfg.membership_ttl.0 <= cfg.freshness.0 {
        cfg.membership_ttl = Duration(cfg.freshness.0.wrapping_mul(2));
    }
    if !explicit.contains(FRESHNESS_ENV) && cfg.membership_ttl.0 <= cfg.freshness.0 {
        cfg.freshness = Duration(cfg.membership_ttl.0 / 2);
        if !explicit.contains(SWEEP_INTERVAL_ENV)
            && cfg.freshness.0 < cfg.sweep_interval.0.wrapping_mul(3)
        {
            cfg.sweep_interval = Duration(cfg.freshness.0 / 3);
        }
    }
    if cfg.sweep_interval.0 <= 0
        || cfg.sweep_interval.0 > third.0
        || cfg.freshness.0 < cfg.sweep_interval.0.wrapping_mul(3)
    {
        cross_check_failed(
            &[SWEEP_INTERVAL_ENV, FRESHNESS_ENV],
            &explicit,
            &mut distributed_invalid,
        );
    }
    if cfg.membership_ttl.0 <= cfg.freshness.0 {
        cross_check_failed(
            &[FRESHNESS_ENV, MEMBERSHIP_TTL_ENV],
            &explicit,
            &mut distributed_invalid,
        );
    }
    if cfg.membership_ttl.0 > MAX_DURATION / 10 {
        cross_check_failed(&[MEMBERSHIP_TTL_ENV], &explicit, &mut distributed_invalid);
    }

    if !core_invalid.is_empty() {
        if cfg.enabled {
            cfg.enabled = false;
            tracing::error!(variables = %core_invalid.join(","), "stream telemetry disabled because configuration is invalid");
        } else {
            tracing::warn!(variables = %core_invalid.join(","), "ignoring invalid disabled stream telemetry configuration");
        }
    }
    if !distributed_invalid.is_empty() {
        if cfg.distributed || !cfg.distributed_explicit {
            cfg.distributed = false;
            tracing::error!(variables = %distributed_invalid.join(","), "stream telemetry distributed mode disabled because configuration is invalid");
        } else {
            tracing::warn!(variables = %distributed_invalid.join(","), "ignoring invalid distributed stream telemetry configuration");
        }
        cfg.distributed_explicit = true;
    }
    cfg
}
