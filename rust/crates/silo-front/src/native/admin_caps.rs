//! Static v2 capability documents for admin observability: `getAdminDashboardCapabilities`
//! (`internal/apiv2/admin_dashboard_capabilities.go`) and `getAdminResourceCapabilities`
//! (`internal/apiv2/admin_system.go`). Go's server always wires the resource sampler and runs on
//! Linux, so the resource document answers `available`.

use std::sync::Arc;

use serde::Serialize;
use silo_http::chi::Mux;
use silo_http::handler_fn;

use super::chain::{Stack, V2Class, capability_json, write_capability};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/dashboard/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/system/resources/capabilities"),
];

#[derive(Serialize)]
struct AdminDashboardCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    server_layouts: bool,
    timeseries: bool,
    playback_activity: bool,
    top_activity: bool,
    health: bool,
    log_level_list: bool,
    watch_providers: bool,
    downloads_stats: bool,
    egress_totals: bool,
    egress_by_source: bool,
    api_clients: bool,
}

#[derive(Serialize)]
struct AdminResourceCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    instance_attribution: bool,
    process_resources: bool,
    cgroup_resources: bool,
    sample_freshness: bool,
}

pub fn mount(stack: &Arc<Stack>, v2: &Mux) {
    const DASHBOARD: &str = "/api/v2/admin/dashboard/capabilities";
    v2.get(
        DASHBOARD,
        stack.v2(
            DASHBOARD,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getAdminDashboardCapabilities", |revision| {
                        capability_json(&AdminDashboardCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            server_layouts: false,
                            timeseries: true,
                            playback_activity: true,
                            top_activity: true,
                            health: true,
                            log_level_list: true,
                            watch_providers: true,
                            downloads_stats: true,
                            egress_totals: true,
                            egress_by_source: true,
                            api_clients: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    const RESOURCES: &str = "/api/v2/admin/system/resources/capabilities";
    v2.get(
        RESOURCES,
        stack.v2(
            RESOURCES,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getAdminResourceCapabilities", |revision| {
                        capability_json(&AdminResourceCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            instance_attribution: true,
                            process_resources: true,
                            cgroup_resources: true,
                            sample_freshness: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}
