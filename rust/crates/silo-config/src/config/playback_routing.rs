//! Playback routing preferences.

use super::SettingsMap;
use super::db_loader::string_or;
use serde::Serialize;
use silo_gocompat::strconv::quote;

pub const PLAYBACK_ROUTING_DIRECT_PLAY_EGRESS_SETTING_KEY: &str =
    "playback.routing.direct_play_egress";
pub const PLAYBACK_ROUTING_REMUX_EXECUTION_SETTING_KEY: &str = "playback.routing.remux_execution";
pub const PLAYBACK_ROUTING_REMUX_EGRESS_SETTING_KEY: &str = "playback.routing.remux_egress";
pub const PLAYBACK_ROUTING_VIDEO_TRANSCODE_EXECUTION_SETTING_KEY: &str =
    "playback.routing.video_transcode_execution";
pub const PLAYBACK_ROUTING_VIDEO_TRANSCODE_EGRESS_SETTING_KEY: &str =
    "playback.routing.video_transcode_egress";

pub const PLAYBACK_EXECUTION_PREFER_WORKER: &str = "prefer_worker";
pub const PLAYBACK_EXECUTION_PREFER_TRANSCODE: &str = "prefer_transcode";
pub const PLAYBACK_EXECUTION_WORKER_ONLY: &str = "worker_only";
pub const PLAYBACK_EXECUTION_PREFER_API: &str = "prefer_api";
pub const PLAYBACK_EXECUTION_API_ONLY: &str = "api_only";

pub const PLAYBACK_EGRESS_PREFER_PROXY: &str = "prefer_proxy";
pub const PLAYBACK_EGRESS_PROXY_ONLY: &str = "proxy_only";
pub const PLAYBACK_EGRESS_PREFER_API: &str = "prefer_api";
pub const PLAYBACK_EGRESS_API_ONLY: &str = "api_only";

/// The immutable routing snapshot consumed by one playback start or replan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PlaybackRoutingPolicy {
    #[serde(rename = "DirectPlayEgress")]
    pub direct_play_egress: String,
    #[serde(rename = "RemuxExecution")]
    pub remux_execution: String,
    #[serde(rename = "RemuxEgress")]
    pub remux_egress: String,
    #[serde(rename = "VideoTranscodeExecution")]
    pub video_transcode_execution: String,
    #[serde(rename = "VideoTranscodeEgress")]
    pub video_transcode_egress: String,
}

pub fn default_playback_routing_policy() -> PlaybackRoutingPolicy {
    PlaybackRoutingPolicy {
        direct_play_egress: PLAYBACK_EGRESS_PREFER_PROXY.to_owned(),
        remux_execution: PLAYBACK_EXECUTION_PREFER_TRANSCODE.to_owned(),
        remux_egress: PLAYBACK_EGRESS_PREFER_PROXY.to_owned(),
        video_transcode_execution: PLAYBACK_EXECUTION_PREFER_TRANSCODE.to_owned(),
        video_transcode_egress: PLAYBACK_EGRESS_PREFER_PROXY.to_owned(),
    }
}

/// Fills zero-valued fields with the runtime defaults.
pub fn effective_playback_routing_policy(policy: &PlaybackRoutingPolicy) -> PlaybackRoutingPolicy {
    let defaults = default_playback_routing_policy();
    let pick = |v: &str, d: String| if v.is_empty() { d } else { v.to_owned() };
    PlaybackRoutingPolicy {
        direct_play_egress: pick(&policy.direct_play_egress, defaults.direct_play_egress),
        remux_execution: pick(&policy.remux_execution, defaults.remux_execution),
        remux_egress: pick(&policy.remux_egress, defaults.remux_egress),
        video_transcode_execution: pick(
            &policy.video_transcode_execution,
            defaults.video_transcode_execution,
        ),
        video_transcode_egress: pick(
            &policy.video_transcode_egress,
            defaults.video_transcode_egress,
        ),
    }
}

pub(crate) fn playback_routing_policy_from_settings(values: &SettingsMap) -> PlaybackRoutingPolicy {
    let d = default_playback_routing_policy();
    PlaybackRoutingPolicy {
        direct_play_egress: string_or(
            values,
            PLAYBACK_ROUTING_DIRECT_PLAY_EGRESS_SETTING_KEY,
            &d.direct_play_egress,
        ),
        remux_execution: string_or(
            values,
            PLAYBACK_ROUTING_REMUX_EXECUTION_SETTING_KEY,
            &d.remux_execution,
        ),
        remux_egress: string_or(
            values,
            PLAYBACK_ROUTING_REMUX_EGRESS_SETTING_KEY,
            &d.remux_egress,
        ),
        video_transcode_execution: string_or(
            values,
            PLAYBACK_ROUTING_VIDEO_TRANSCODE_EXECUTION_SETTING_KEY,
            &d.video_transcode_execution,
        ),
        video_transcode_egress: string_or(
            values,
            PLAYBACK_ROUTING_VIDEO_TRANSCODE_EGRESS_SETTING_KEY,
            &d.video_transcode_egress,
        ),
    }
}

pub(crate) fn validate_playback_routing_policy(
    policy: &PlaybackRoutingPolicy,
) -> Result<(), String> {
    let policy = effective_playback_routing_policy(policy);
    for (key, value) in [
        (
            PLAYBACK_ROUTING_REMUX_EXECUTION_SETTING_KEY,
            &policy.remux_execution,
        ),
        (
            PLAYBACK_ROUTING_VIDEO_TRANSCODE_EXECUTION_SETTING_KEY,
            &policy.video_transcode_execution,
        ),
    ] {
        if !matches!(
            value.as_str(),
            PLAYBACK_EXECUTION_PREFER_WORKER
                | PLAYBACK_EXECUTION_PREFER_TRANSCODE
                | PLAYBACK_EXECUTION_WORKER_ONLY
                | PLAYBACK_EXECUTION_PREFER_API
                | PLAYBACK_EXECUTION_API_ONLY
        ) {
            return Err(format!(
                "{key} has invalid execution preference {}",
                quote(value)
            ));
        }
    }
    for (key, value) in [
        (
            PLAYBACK_ROUTING_DIRECT_PLAY_EGRESS_SETTING_KEY,
            &policy.direct_play_egress,
        ),
        (
            PLAYBACK_ROUTING_REMUX_EGRESS_SETTING_KEY,
            &policy.remux_egress,
        ),
        (
            PLAYBACK_ROUTING_VIDEO_TRANSCODE_EGRESS_SETTING_KEY,
            &policy.video_transcode_egress,
        ),
    ] {
        if !matches!(
            value.as_str(),
            PLAYBACK_EGRESS_PREFER_PROXY
                | PLAYBACK_EGRESS_PROXY_ONLY
                | PLAYBACK_EGRESS_PREFER_API
                | PLAYBACK_EGRESS_API_ONLY
        ) {
            return Err(format!(
                "{key} has invalid egress preference {}",
                quote(value)
            ));
        }
    }
    if policy.remux_execution == PLAYBACK_EXECUTION_API_ONLY
        && policy.remux_egress == PLAYBACK_EGRESS_PROXY_ONLY
    {
        return Err(format!(
            "{PLAYBACK_ROUTING_REMUX_EXECUTION_SETTING_KEY}=api_only cannot be combined with {PLAYBACK_ROUTING_REMUX_EGRESS_SETTING_KEY}=proxy_only: API-produced remuxes cannot use proxy egress"
        ));
    }
    if policy.video_transcode_execution == PLAYBACK_EXECUTION_API_ONLY
        && policy.video_transcode_egress == PLAYBACK_EGRESS_PROXY_ONLY
    {
        return Err(format!(
            "{PLAYBACK_ROUTING_VIDEO_TRANSCODE_EXECUTION_SETTING_KEY}=api_only cannot be combined with {PLAYBACK_ROUTING_VIDEO_TRANSCODE_EGRESS_SETTING_KEY}=proxy_only: API-produced transcodes cannot use proxy egress"
        ));
    }
    Ok(())
}
