//! Playback, node, and watch-together discovery documents: `internal/apiv2/admin_node_drain.go`,
//! `admin_sessions.go`, `admin_playback_commands.go`, `admin_settings_discovery.go`,
//! `playback_control_socket.go`, and `watch_together_capabilities.go`.
//!
//! Go derives each document from which services its process wired. These documents are the values a
//! server with Postgres and Redis wires (every service present), which is what the front serves in front
//! of. Session, node, transcode, and room operations stay on Go: they read the playback manager, the node
//! pool, and the room hub, which live in Go's process.

use std::sync::Arc;

use serde::Serialize;
use silo_http::chi::Mux;
use silo_http::handler_fn;

use super::chain::{Stack, V2Class, capability_json, write_capability};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/nodes/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/sessions/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/sessions/command-capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/playback-routing/capabilities"),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/playback/sessions/control/capabilities",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/watch-together/capabilities"),
];

/// `AdminNodeCapabilities`.
#[derive(Serialize)]
struct NodeCaps<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    drain: bool,
    summary: bool,
}

/// `AdminPlaybackSessionCapabilitiesOutputBody`.
#[derive(Serialize)]
struct SessionCaps<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    available: bool,
    user_filter: bool,
    summary: bool,
    node_observations: bool,
    effective_play_method: bool,
    effective_play_method_values: &'a [&'a str],
    is_jellyfin_client: bool,
    transcode_hw_accel: bool,
    tone_map_mode: bool,
    tone_map_mode_values: &'a [&'a str],
    client_build: bool,
    client_channel: bool,
    target_audio_channels: bool,
    network_access_route: bool,
    stream_location: bool,
    node_routing: bool,
    output_format: bool,
    source_video_height: bool,
    device_identity: bool,
    lifecycle_events: bool,
}

/// `AdminPlaybackCommandCapabilities`.
#[derive(Serialize)]
struct CommandCaps<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    available: bool,
    actions: &'a [&'a str],
    sequenced_commands: bool,
    terminate_revokes_authority: bool,
}

/// `AdminPlaybackRoutingCapabilities` over `handlers.AdminPlaybackRoutingCapabilities`.
#[derive(Serialize)]
struct RoutingCaps<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    features: &'a [&'a str],
    workloads: &'a [&'a str],
    execution_preferences: &'a [&'a str],
    egress_preferences: &'a [&'a str],
}

/// `PlaybackControlSocketCapabilities`.
#[derive(Serialize)]
struct ControlCaps<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    available: bool,
    protocol: &'a str,
}

/// `WatchTogetherCapabilities`.
#[derive(Serialize)]
struct RoomCaps<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    staged_selection: bool,
    lobby_ready: bool,
    connection_replaced: bool,
    selection_mode_switch: bool,
    member_state: bool,
    picker: bool,
    vote_host_override: bool,
    stop_playback: bool,
    max_member_state_ids: i32,
    socket_protocol: &'a str,
}

fn document<F>(
    stack: &Arc<Stack>,
    v2: &Mux,
    path: &'static str,
    class: V2Class,
    operation: &'static str,
    render: F,
) where
    F: Fn(&str) -> Vec<u8> + Send + Sync + Copy + 'static,
{
    v2.get(
        path,
        stack.v2(
            path,
            class,
            handler_fn(move |w, r| {
                Box::pin(async move { write_capability(w, r, operation, render).await })
            }),
        ),
    );
}

/// Registers the discovery documents.
pub fn mount(stack: &Arc<Stack>, v2: &Mux) {
    document(
        stack,
        v2,
        "/api/v2/admin/nodes/capabilities",
        V2Class::ActingAdmin,
        "getAdminNodeCapabilities",
        |revision| {
            capability_json(&NodeCaps {
                revision,
                state: "available",
                allowed: true,
                drain: true,
                summary: true,
            })
        },
    );
    document(
        stack,
        v2,
        "/api/v2/admin/sessions/capabilities",
        V2Class::ActingAdmin,
        "getAdminPlaybackSessionCapabilities",
        |revision| {
            capability_json(&SessionCaps {
                revision,
                state: "available",
                allowed: true,
                available: true,
                user_filter: true,
                summary: true,
                node_observations: true,
                effective_play_method: true,
                effective_play_method_values: &["direct", "remux", "transcode", "direct_stream"],
                is_jellyfin_client: true,
                transcode_hw_accel: true,
                tone_map_mode: true,
                tone_map_mode_values: &["hardware", "software"],
                client_build: true,
                client_channel: true,
                target_audio_channels: true,
                network_access_route: true,
                stream_location: true,
                node_routing: true,
                output_format: true,
                source_video_height: true,
                device_identity: true,
                lifecycle_events: true,
            })
        },
    );
    document(
        stack,
        v2,
        "/api/v2/admin/sessions/command-capabilities",
        V2Class::ActingAdmin,
        "getAdminPlaybackCommandCapabilities",
        |revision| {
            capability_json(&CommandCaps {
                revision,
                state: "available",
                allowed: true,
                available: true,
                actions: &["pause", "resume", "stop", "message", "terminate"],
                sequenced_commands: true,
                terminate_revokes_authority: true,
            })
        },
    );
    document(
        stack,
        v2,
        "/api/v2/admin/playback-routing/capabilities",
        V2Class::ActingAdmin,
        "getAdminPlaybackRoutingCapabilities",
        |revision| {
            capability_json(&RoutingCaps {
                revision,
                state: "available",
                allowed: true,
                features: &["playback_node_routing_v1"],
                workloads: &["direct_play", "remux", "video_transcode"],
                execution_preferences: &[
                    "prefer_worker",
                    "prefer_transcode",
                    "worker_only",
                    "prefer_api",
                    "api_only",
                ],
                egress_preferences: &["prefer_proxy", "proxy_only", "prefer_api", "api_only"],
            })
        },
    );
    document(
        stack,
        v2,
        "/api/v2/playback/sessions/control/capabilities",
        V2Class::ProfileScoped,
        "getPlaybackControlSocketCapabilities",
        |revision| {
            capability_json(&ControlCaps {
                revision,
                state: "available",
                allowed: true,
                available: true,
                protocol: "silo.playback-control.v2",
            })
        },
    );
    document(
        stack,
        v2,
        "/api/v2/watch-together/capabilities",
        V2Class::Authenticated,
        "getWatchTogetherCapabilities",
        |revision| {
            capability_json(&RoomCaps {
                revision,
                state: "available",
                allowed: true,
                staged_selection: true,
                lobby_ready: true,
                connection_replaced: true,
                selection_mode_switch: true,
                member_state: true,
                picker: true,
                vote_host_override: true,
                stop_playback: true,
                max_member_state_ids: 200,
                socket_protocol: "silo.room.v2",
            })
        },
    );
}
