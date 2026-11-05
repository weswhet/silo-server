//! Static v2 capability documents for watch history: `getAdminPlaybackHistoryCapabilities`
//! (`internal/apiv2/admin_playback_history.go`), `getAdminHistoryImportCapabilities`
//! (`internal/apiv2/admin_history_imports.go`), and `getHistoryImportCapability`
//! (`internal/apiv2/history_imports.go`). Go's server always wires the playback history store and
//! both history import services, so every document answers `available`.

use std::sync::Arc;

use serde::Serialize;
use silo_http::chi::Mux;
use silo_http::handler_fn;

use super::chain::{Stack, V2Class, capability_json, write_capability};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/playback-history/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/history-imports/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/history-imports/capability"),
];

/// `handlers.PlaybackEndReasons`, in order.
const END_REASONS: [&str; 5] = ["stopped", "terminated", "expired", "aborted", "replaced"];
/// `adminHistoryMaxLookbackHours`.
const MAX_LOOKBACK_HOURS: i64 = 8760;
/// `historyimport.MaxPlexConnectionCandidates`.
const MAX_PLEX_CONNECTIONS: i64 = 8;

#[derive(Serialize)]
struct AdminPlaybackHistoryCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    available: bool,
    ended_before: bool,
    watch_measurement: bool,
    client_ip: bool,
    device_identity: bool,
    client_identity: bool,
    stream_decisions: bool,
    end_reason: bool,
    end_reason_values: [&'static str; 5],
    lifecycle_seq: bool,
}

#[derive(Serialize)]
struct AdminHistoryImportCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    available: bool,
    guarded_configuration: bool,
    durable_runs: bool,
    max_bulk_mappings: i64,
    played_lookback: bool,
    max_lookback_hours: i64,
}

#[derive(Serialize)]
struct HistoryImportCapability<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    plex_connection_fallback: bool,
    max_plex_connections: i64,
}

pub fn mount(stack: &Arc<Stack>, v2: &Mux) {
    const PLAYBACK: &str = "/api/v2/admin/playback-history/capabilities";
    v2.get(
        PLAYBACK,
        stack.v2(
            PLAYBACK,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getAdminPlaybackHistoryCapabilities", |revision| {
                        capability_json(&AdminPlaybackHistoryCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                            ended_before: true,
                            watch_measurement: true,
                            client_ip: true,
                            device_identity: true,
                            client_identity: true,
                            stream_decisions: true,
                            end_reason: true,
                            end_reason_values: END_REASONS,
                            lifecycle_seq: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    const ADMIN_IMPORTS: &str = "/api/v2/admin/history-imports/capabilities";
    v2.get(
        ADMIN_IMPORTS,
        stack.v2(
            ADMIN_IMPORTS,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getAdminHistoryImportCapabilities", |revision| {
                        capability_json(&AdminHistoryImportCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                            guarded_configuration: true,
                            durable_runs: true,
                            max_bulk_mappings: 200,
                            played_lookback: true,
                            max_lookback_hours: MAX_LOOKBACK_HOURS,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    const IMPORTS: &str = "/api/v2/history-imports/capability";
    v2.get(
        IMPORTS,
        stack.v2(
            IMPORTS,
            V2Class::Authenticated,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getHistoryImportCapability", |revision| {
                        capability_json(&HistoryImportCapability {
                            revision,
                            state: "available",
                            allowed: true,
                            plex_connection_fallback: true,
                            max_plex_connections: MAX_PLEX_CONNECTIONS,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}
