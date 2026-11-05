//! Library administration capability rows: v2 `scan_controls.go` (`getScanCapabilities`),
//! `autoscan_delivery.go` (`getAutoscanDeliveryCapabilities`), `admin_job_artifact_download.go`
//! (`getAdminJobCapabilities`), and `admin_storage_transition.go` (`getAdminStorageTransitionCapabilities`).
//!
//! The six autoscan inspection reads use Postgres; running-poll elapsed time also uses the clock.
//! None requires the plugin host, S3, or in-process scheduler state.
//!
//! Collection-group list/order and unmatched-file reads use the Go repository SQL. Retained-job
//! reads sign local artifact capabilities with Stack's artwork key. Job reads and
//! `getAdminJobCapabilities` stay on Go for S3 deployments, because download URLs need presigning.
//! Trickplay library status and marker contribution history read Postgres only; contribution history
//! applies catalog and file access checks without calling the plugin host or a remote provider.
//! Collection-group writes preserve Go transaction boundaries and have no process-local effects.
//! Job cancellation stays on Go: running image-cache cleanup signals its in-process CancelRegistry;
//! queued cleanup also publishes a realtime event. Mutating scan, autoscan, task, and storage
//! transition actions stay on Go.

mod contributions;
mod groups;
mod trickplay;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::problem::{Problem, internal_error};
use silo_api_v2::wire::{Instant, PageInfo, paginated};
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::strings::trim_space;
use silo_http::Request;
use silo_http::chi::Mux;
use silo_http::handler_fn;
use silo_store::access::Scope as AccessScope;
use silo_store::autoscan as store;
use silo_store::library_admin_reads as reads;

use std::collections::BTreeMap;
use std::time::SystemTime;

use super::chain::{
    Stack, V2Class, capability_json, v2_public, write_capability, write_problem, write_v2_json,
};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/trickplay/libraries"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/files/{fileId}/contributions"),
    NativeRow::new(
        ApiV2,
        "POST",
        "/api/v2/admin/libraries/{library_id}/collection-groups",
    ),
    NativeRow::new(
        ApiV2,
        "PUT",
        "/api/v2/admin/libraries/{library_id}/collection-groups/order",
    ),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/admin/libraries/{library_id}/collection-groups",
    ),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/admin/libraries/{library_id}/collection-groups/order",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/unmatched"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/jobs"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/jobs/{id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/autoscan/settings"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/autoscan/status"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/autoscan/connections"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/autoscan/sources"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/autoscan/events"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/autoscan/scans"),
    NativeRow::new(ApiV2, "GET", "/api/v2/scan/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/autoscan/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/jobs/capabilities"),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/admin/storage-transitions/capabilities",
    ),
];

/// Rows that need no credential.
pub const PUBLIC_ROWS: &[NativeRow] = &[NativeRow::new(
    ApiV2,
    "GET",
    "/api/v2/autoscan/capabilities",
)];

/// Rows whose answer depends on S3 presigning, which is not ported.
pub const S3_ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/jobs/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/jobs"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/jobs/{id}"),
];

/// `Capability`.
#[derive(Serialize)]
struct Capability<'a> {
    revision: &'a str,
    state: &'static str,
    /// Huma fills `allowed` on an acting-administrator document.
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed: Option<bool>,
}

/// `AdminJobArtifactCapabilities`.
#[derive(Serialize)]
struct JobCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    artifact_download: bool,
    public_links: bool,
}

/// `AdminStorageTransitionCapabilities`.
#[derive(Serialize)]
struct StorageTransitionCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    start_fresh: bool,
    preserve_uploads: bool,
    migrate_all: bool,
    local_target: bool,
    s3_target: bool,
    source_health: bool,
    job_cancellation: bool,
    resumable_recovery: bool,
}

fn simple(
    v2: &Mux,
    stack: Option<&Arc<Stack>>,
    path: &'static str,
    class: V2Class,
    op: &'static str,
) {
    let admin = matches!(class, V2Class::ActingAdmin);
    let handler = handler_fn(move |w, r| {
        Box::pin(async move {
            // The library handler (`ScanControlAvailable`) and autoscan delivery are always wired in `NewRouter`.
            write_capability(w, r, op, |revision| {
                capability_json(&Capability {
                    revision,
                    state: "available",
                    allowed: admin.then_some(true),
                })
            })
            .await;
        })
    });
    match stack {
        Some(stack) => v2.get(path, stack.v2(path, class, handler)),
        None => v2.get(path, v2_public(path, handler)),
    }
}

/// The public row, mounted without a stack.
pub fn mount_public(v2: &Mux) {
    simple(
        v2,
        None,
        "/api/v2/autoscan/capabilities",
        V2Class::Public,
        "getAutoscanDeliveryCapabilities",
    );
}

pub fn mount(stack: &Arc<Stack>, v2: &Mux) {
    contributions::mount(stack, v2);
    groups::mount(stack, v2);
    trickplay::mount(stack, v2);
    mount_autoscan(stack, v2);
    mount_admin_reads(stack, v2);
    jobs::mount(stack, v2);
    simple(
        v2,
        Some(stack),
        "/api/v2/scan/capabilities",
        V2Class::ActingAdmin,
        "getScanCapabilities",
    );

    let path = "/api/v2/admin/jobs/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    // A local artifact store: downloads stream from this server, and no public link can be minted.
                    write_capability(w, r, "getAdminJobCapabilities", |revision| {
                        capability_json(&JobCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            artifact_download: true,
                            public_links: false,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    let path = "/api/v2/admin/storage-transitions/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getAdminStorageTransitionCapabilities", |revision| {
                        capability_json(&StorageTransitionCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            start_fresh: true,
                            preserve_uploads: true,
                            migrate_all: true,
                            local_target: true,
                            s3_target: true,
                            source_health: true,
                            job_cancellation: true,
                            resumable_recovery: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}

#[derive(Serialize)]
struct AdminAutoscanSettings {
    enabled: bool,
    default_poll_interval_seconds: i64,
    debounce_seconds: i64,
}

#[derive(Serialize)]
struct AdminAutoscanStatusSource {
    id: String,
    plugin_id: String,
    capability_id: String,
    connection_id: Option<String>,
    enabled: bool,
    label: String,
    path_rewrites: Vec<AdminAutoscanPathRewrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_run_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

#[derive(Serialize)]
struct AdminAutoscanRunningPoll {
    id: String,
    source_id: Option<String>,
    plugin_id: String,
    capability_id: String,
    started_at: Instant,
    elapsed_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    marker_before: Option<String>,
}

#[derive(Serialize)]
struct AdminAutoscanStatus {
    enabled: bool,
    sources: Vec<AdminAutoscanStatusSource>,
    running_polls: Vec<AdminAutoscanRunningPoll>,
    active_scans: i64,
    accepted_scans: i64,
    running_scans: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_event_at: Option<Instant>,
}

#[derive(Serialize)]
struct AdminAutoscanConnection {
    id: String,
    name: String,
    kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    base_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_integration_id: Option<String>,
    has_api_key: bool,
}

#[derive(Serialize)]
struct AdminAutoscanPathRewrite {
    from: String,
    to: String,
}

#[derive(Serialize)]
struct AdminAutoscanSource {
    id: String,
    plugin_id: String,
    capability_id: String,
    connection_id: Option<String>,
    enabled: bool,
    delivery_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_interval_seconds: Option<i64>,
    path_rewrites: Vec<AdminAutoscanPathRewrite>,
    source_config: BTreeMap<String, String>,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_run_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    webhook_configured: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    webhook_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    webhook_secret_suffix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    webhook_last_received_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    webhook_last_error_at: Option<Instant>,
    #[serde(skip_serializing_if = "String::is_empty")]
    webhook_last_error_message: String,
}

#[derive(Serialize)]
struct AdminAutoscanEventRun {
    id: String,
    library_id: String,
    mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    path: String,
    trigger: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<Instant>,
    #[serde(skip_serializing_if = "String::is_empty")]
    error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<AdminAutoscanScanResult>,
}

#[derive(Serialize)]
struct AdminAutoscanEventChange {
    source_path: String,
    rewritten_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope: String,
    outcome: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    reason: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    library_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    target_mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    target_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    scan_run_id: String,
}

#[derive(Serialize)]
struct AdminAutoscanEvent {
    id: String,
    source_id: Option<String>,
    plugin_id: String,
    capability_id: String,
    started_at: Instant,
    completed_at: Instant,
    duration_ms: i64,
    status: String,
    delivery_mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    provider_event_type: String,
    changes_returned: i64,
    changes_resolved: i64,
    targets_claimed: i64,
    scans_created: i64,
    scans_reused: i64,
    scans_suppressed: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    error_message: String,
    scan_runs: Vec<AdminAutoscanEventRun>,
    changes: Vec<AdminAutoscanEventChange>,
    changes_truncated: bool,
}

#[derive(Serialize)]
struct AdminAutoscanScan {
    id: String,
    library_id: String,
    mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    path: String,
    trigger: String,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    autoscan_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_id: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    plugin_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    capability_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    event_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_completed_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<AdminAutoscanScanResult>,
}

#[derive(Serialize)]
struct AdminAutoscanScanResult {
    r#new: i64,
    updated: i64,
    unchanged: i64,
    missing: i64,
    missing_skipped_protected: i64,
    files_deleted: i64,
    items_deleted: i64,
    memberships_removed: i64,
    errors: i64,
    skipped: i64,
}

fn instant(t: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(t))
}
fn instant_opt(t: Option<SystemTime>) -> Option<Instant> {
    t.map(instant)
}
fn internal_problem() -> Problem {
    Problem::new(internal_error(), "An unexpected error occurred.")
}
fn query(r: &Request, name: &str) -> String {
    let (q, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    q.get(name)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}
fn viewer_digest(r: &Request) -> String {
    let scope = r
        .extensions
        .get::<Arc<AccessScope>>()
        .map(|s| silo_core::apiv2::ViewerScope {
            policy_revision: s.policy_revision,
            libraries_restricted: s.libraries_restricted,
            allowed_library_ids: s
                .libraries_restricted
                .then(|| s.allowed_library_ids.clone()),
            disabled_library_ids: (!s.disabled_library_ids.is_empty())
                .then(|| s.disabled_library_ids.clone()),
            max_content_rating: s.maturity_limits.max_content_rating.clone(),
            allow_unrated_content: s.maturity_limits.allow_unrated_content,
            max_advisory_age: i64::from(s.maturity_limits.max_advisory_age),
            require_advisory_age: s.maturity_limits.require_advisory_age,
        });
    silo_core::apiv2::viewer_scope_digest(scope.as_ref())
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct ConnectionPosition {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ID")]
    id: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct SourcePosition {
    #[serde(rename = "Label")]
    label: String,
    #[serde(rename = "ID")]
    id: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct HistoryPosition {
    #[serde(rename = "Offset")]
    offset: i64,
}
#[derive(Serialize)]
struct HistoryPage<T> {
    items: Vec<T>,
    page: Option<PageInfo>,
    total: i64,
}
fn scan_result(v: store::ScanResult) -> AdminAutoscanScanResult {
    AdminAutoscanScanResult {
        r#new: v.new,
        updated: v.updated,
        unchanged: v.unchanged,
        missing: v.missing,
        missing_skipped_protected: v.missing_skipped_protected,
        files_deleted: v.files_deleted,
        items_deleted: v.items_deleted,
        memberships_removed: v.memberships_removed,
        errors: v.errors,
        skipped: v.skipped,
    }
}
fn rewrites(v: Vec<store::PathRewrite>) -> Vec<AdminAutoscanPathRewrite> {
    v.into_iter()
        .map(|p| AdminAutoscanPathRewrite {
            from: p.from,
            to: p.to,
        })
        .collect()
}
fn source(v: store::Source) -> AdminAutoscanSource {
    AdminAutoscanSource {
        id: v.id,
        plugin_id: v.plugin_id,
        capability_id: v.capability_id,
        connection_id: v.connection_id,
        enabled: v.enabled,
        delivery_mode: if v.delivery_mode.is_empty() {
            "poll".into()
        } else {
            v.delivery_mode
        },
        poll_interval_seconds: v.poll_interval_seconds.map(i64::from),
        path_rewrites: rewrites(v.path_rewrites),
        source_config: v
            .source_config
            .into_iter()
            .filter_map(|(k, v)| {
                let k = trim_space(&k);
                (!k.is_empty()).then(|| (k.to_owned(), trim_space(&v).to_owned()))
            })
            .collect(),
        label: v.label,
        last_run_at: instant_opt(v.last_run_at),
        last_error: v.last_error,
        webhook_configured: false,
        webhook_url: String::new(),
        webhook_secret_suffix: String::new(),
        webhook_last_received_at: None,
        webhook_last_error_at: None,
        webhook_last_error_message: String::new(),
    }
}
fn event(v: store::EventWithRuns) -> Result<AdminAutoscanEvent, Problem> {
    let e = v.event;
    if e.id <= 0 {
        return Err(Problem::new(internal_error(), "Invalid event identity."));
    }
    let mut scan_runs = Vec::with_capacity(v.runs.len());
    for r in v.runs {
        if r.id.is_empty() || r.media_folder_id <= 0 {
            return Err(Problem::new(
                internal_error(),
                "Invalid event scan identity.",
            ));
        }
        scan_runs.push(AdminAutoscanEventRun {
            id: r.id,
            library_id: r.media_folder_id.to_string(),
            mode: r.mode,
            path: r.path,
            trigger: r.trigger,
            status: r.status,
            requested_at: instant_opt(r.requested_at),
            started_at: instant_opt(r.started_at),
            completed_at: instant_opt(r.completed_at),
            error_message: r.error_message,
            result: r.result.map(scan_result),
        });
    }
    Ok(AdminAutoscanEvent {
        id: e.id.to_string(),
        source_id: e.source_id,
        plugin_id: e.plugin_id,
        capability_id: e.capability_id,
        started_at: instant(e.started_at),
        completed_at: instant(e.completed_at),
        duration_ms: e.duration_ms,
        status: e.status,
        delivery_mode: e.delivery_mode,
        provider_event_type: e.provider_event_type,
        changes_returned: i64::from(e.changes_returned),
        changes_resolved: i64::from(e.changes_resolved),
        targets_claimed: i64::from(e.targets_claimed),
        scans_created: i64::from(e.scans_created),
        scans_reused: i64::from(e.scans_reused),
        scans_suppressed: i64::from(e.scans_suppressed),
        error_message: e.error_message,
        scan_runs,
        changes: e
            .changes
            .into_iter()
            .map(|c| AdminAutoscanEventChange {
                source_path: c.source_path,
                rewritten_path: c.rewritten_path,
                scope: c.scope,
                outcome: c.outcome,
                reason: c.reason,
                detail: c.detail,
                library_id: if c.library_id > 0 {
                    c.library_id.to_string()
                } else {
                    String::new()
                },
                target_mode: c.target_mode,
                target_path: c.target_path,
                scan_run_id: c.scan_run_id,
            })
            .collect(),
        changes_truncated: e.changes_truncated,
    })
}
fn scan(v: store::ScanWithEvent) -> Result<AdminAutoscanScan, Problem> {
    let r = v.run;
    if r.id.is_empty() || r.media_folder_id <= 0 {
        return Err(Problem::new(
            internal_error(),
            "Invalid scan history identity.",
        ));
    }
    Ok(AdminAutoscanScan {
        id: r.id,
        library_id: r.media_folder_id.to_string(),
        mode: r.mode,
        path: r.path,
        trigger: r.trigger,
        status: r.status,
        error_message: r.error_message,
        requested_at: instant_opt(r.requested_at),
        started_at: instant_opt(r.started_at),
        completed_at: instant_opt(r.completed_at),
        autoscan_event_id: v.autoscan_event_id.map(|n| n.to_string()),
        source_id: v.source_id,
        plugin_id: v.plugin_id,
        capability_id: v.capability_id,
        event_status: v.event_status,
        event_completed_at: instant_opt(v.event_completed_at),
        result: r.result.map(scan_result),
    })
}
macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}
macro_rules! read_db {
    ($w:ident, $r:ident, $call:expr) => {
        match $call.await {
            Ok(v) => v,
            Err(_) => return write_problem($w, $r, internal_problem()).await,
        }
    };
}
fn mount_autoscan(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/admin/autoscan/settings";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let Some(claims) = get_claims(r) else {
                    return;
                };
                let settings = read_db!(w, r, store::get_settings(&s.pool));
                let body = AdminAutoscanSettings {
                    enabled: settings.enabled,
                    default_poll_interval_seconds: i64::from(
                        settings.default_poll_interval_seconds,
                    ),
                    debounce_seconds: i64::from(settings.debounce_seconds),
                };
                let label = format!(
                    "admin-autoscan-settings:{}:{}:{}",
                    claims.user_id,
                    get_profile_id(r),
                    viewer_digest(r)
                );
                let value = format!(
                    "{}:{}:{}",
                    body.enabled, body.default_poll_interval_seconds, body.debounce_seconds
                );
                let tag = silo_core::apiv2::render_etag(label.as_bytes(), value.as_bytes(), 1);
                let joined = |name: &str| {
                    let values = r.header.values(name);
                    if values.is_empty() {
                        return String::new();
                    }
                    let joined = values
                        .iter()
                        .map(|v| String::from_utf8_lossy(v).into_owned())
                        .collect::<Vec<_>>()
                        .join(", ");
                    if trim_space(&joined).is_empty() {
                        ",".to_owned()
                    } else {
                        joined
                    }
                };
                let (unchanged, problem) = silo_api_v2::precondition::evaluate_read_preconditions(
                    &joined("If-Match"),
                    &joined("If-None-Match"),
                    &tag,
                );
                if let Some(p) = problem {
                    return write_problem(w, r, p).await;
                }
                w.header().set("ETag", tag.to_wire());
                if unchanged {
                    w.write_header(304).await;
                    return;
                }
                write_v2_json(w, &body).await;
            }),
        ),
    );
    let path = "/api/v2/admin/autoscan/status";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let settings = read_db!(w, r, store::get_settings(&s.pool));
                let sources = read_db!(w, r, store::list_sources(&s.pool));
                let queue = read_db!(w, r, store::get_queue_summary(&s.pool));
                let running = read_db!(w, r, store::list_running_events(&s.pool));
                let latest = read_db!(w, r, store::latest_event_at(&s.pool));
                let now = SystemTime::now();
                let body = AdminAutoscanStatus {
                    enabled: settings.enabled,
                    sources: sources
                        .into_iter()
                        .map(|v| AdminAutoscanStatusSource {
                            id: v.id,
                            plugin_id: v.plugin_id,
                            capability_id: v.capability_id,
                            connection_id: v.connection_id,
                            enabled: v.enabled,
                            label: v.label,
                            path_rewrites: rewrites(v.path_rewrites),
                            last_run_at: instant_opt(v.last_run_at),
                            last_error: v.last_error,
                        })
                        .collect(),
                    running_polls: running
                        .into_iter()
                        .map(|v| AdminAutoscanRunningPoll {
                            id: v.id.to_string(),
                            source_id: v.source_id,
                            plugin_id: v.plugin_id,
                            capability_id: v.capability_id,
                            started_at: instant(v.started_at),
                            elapsed_ms: now
                                .duration_since(v.started_at)
                                .unwrap_or_default()
                                .min(std::time::Duration::from_nanos(i64::MAX as u64))
                                .as_millis() as i64,
                            marker_before: v.marker_before,
                        })
                        .collect(),
                    active_scans: i64::from(queue.active),
                    accepted_scans: i64::from(queue.accepted),
                    running_scans: i64::from(queue.running),
                    latest_event_at: instant_opt(latest),
                };
                write_v2_json(w, &body).await;
            }),
        ),
    );
    let path = "/api/v2/admin/autoscan/connections";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let Some(claims) = get_claims(r) else {
                    return;
                };
                let limit = query(r, "limit").parse::<usize>().unwrap_or(50);
                let cursor = query(r, "cursor");
                let scope = CursorScope {
                    operation_id: "listAdminAutoscanConnections".into(),
                    security: format!("{}/{}", claims.user_id, get_profile_id(r)),
                    filter: limit.to_string(),
                    sort: "name".into(),
                    tiebreaker: "id".into(),
                };
                let after: ConnectionPosition = if cursor.is_empty() {
                    ConnectionPosition::default()
                } else {
                    match s.cursors.decode(&scope, &cursor) {
                        Ok(v) => v,
                        Err(p) => return write_problem(w, r, p).await,
                    }
                };
                let mut rows = read_db!(w, r, store::list_connections(&s.pool, &s.cipher));
                rows.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
                let mut items = Vec::with_capacity(limit);
                let mut last = ConnectionPosition::default();
                let mut next = String::new();
                for row in rows {
                    if !cursor.is_empty() && (&row.name, &row.id) <= (&after.name, &after.id) {
                        continue;
                    }
                    if items.len() == limit {
                        next = match s.cursors.encode(&scope, &last) {
                            Ok(v) => v,
                            Err(p) => return write_problem(w, r, p).await,
                        };
                        break;
                    }
                    last = ConnectionPosition {
                        name: row.name.clone(),
                        id: row.id.clone(),
                    };
                    items.push(AdminAutoscanConnection {
                        id: row.id,
                        name: row.name,
                        kind: row.kind,
                        base_url: row.base_url,
                        request_integration_id: row.request_integration_id,
                        has_api_key: !trim_space(&row.api_key_ref).is_empty(),
                    });
                }
                write_v2_json(w, &paginated(items, next)).await;
            }),
        ),
    );
    let path = "/api/v2/admin/autoscan/sources";
    v2.get(path, stack.v2(path,V2Class::ActingAdmin,route!(stack,|s,w,r| {
        let Some(claims) = get_claims(r) else { return; };
        let limit = query(r,"limit").parse::<usize>().unwrap_or(50);
        let cursor = query(r,"cursor");
        let scope = CursorScope { operation_id:"listAdminAutoscanSources".into(),security:format!("{}/{}",claims.user_id,get_profile_id(r)),
            filter:limit.to_string(),sort:"label".into(),tiebreaker:"id".into() };
        let after: SourcePosition = if cursor.is_empty() { SourcePosition::default() } else { match s.cursors.decode(&scope,&cursor) {
            Ok(v)=>v,Err(p)=>return write_problem(w,r,p).await,
        }};
        let rows = read_db!(w,r,store::list_sources(&s.pool));
        let endpoints = read_db!(w,r,store::list_webhook_endpoints(&s.pool));
        let public_url = s.settings.get("server.public_url").await.unwrap_or_default();
        let public_url = trim_space(&public_url).trim_end_matches('/');
        let mut rows: Vec<_> = rows.into_iter().map(source).collect();
        // Go decorates the full enumeration before sorting or selecting a page.
        for row in &mut rows {
            if let Some(endpoint) = endpoints.iter().find(|e| e.source_id == row.id) {
                row.webhook_configured = true;
                row.webhook_secret_suffix = endpoint.secret_suffix.clone();
                row.webhook_last_received_at = instant_opt(endpoint.last_received_at);
                row.webhook_last_error_at = instant_opt(endpoint.last_error_at);
                row.webhook_last_error_message = endpoint.last_error_message.clone();
                match store::reveal_webhook_token(&s.pool,&s.cipher,&endpoint.source_id).await {
                    Ok(token) => row.webhook_url = format!("{public_url}/api/v2/autoscan/webhooks/{token}"),
                    Err(error) => tracing::warn!(%error, source_id = %endpoint.source_id, "autoscan: reveal webhook token failed"),
                }
            }
        }
        rows.sort_by(|a,b| (&a.label,&a.id).cmp(&(&b.label,&b.id)));
        let mut items = Vec::with_capacity(limit);
        let mut last = SourcePosition::default();
        let mut next = String::new();
        for row in rows {
            if !cursor.is_empty() && (&row.label,&row.id) <= (&after.label,&after.id) { continue; }
            if items.len() == limit {
                next = match s.cursors.encode(&scope,&last) { Ok(v)=>v,Err(p)=>return write_problem(w,r,p).await }; break;
            }
            last = SourcePosition { label:row.label.clone(),id:row.id.clone() }; items.push(row);
        }
        write_v2_json(w,&paginated(items,next)).await;
    })));
    for (path, events) in [
        ("/api/v2/admin/autoscan/events", true),
        ("/api/v2/admin/autoscan/scans", false),
    ] {
        v2.get(
            path,
            stack.v2(
                path,
                V2Class::ActingAdmin,
                route!(stack, |s, w, r| {
                    let Some(claims) = get_claims(r) else {
                        return;
                    };
                    let limit = query(r, "limit").parse::<i64>().unwrap_or(50);
                    let cursor = query(r, "cursor");
                    let status = query(r, "status");
                    let search = trim_space(&query(r, "q")).to_owned();
                    let source_id = trim_space(&query(r, "source_id")).to_owned();
                    let filter = if events {
                        serde_json::json!([source_id, status, search, limit])
                    } else {
                        serde_json::json!([status, search, limit])
                    };
                    let filter = String::from_utf8(
                        silo_gocompat::json::marshal(&filter).expect("cursor filter serializes"),
                    )
                    .expect("JSON is UTF-8");
                    let scope = CursorScope {
                        operation_id: if events {
                            "listAdminAutoscanEvents"
                        } else {
                            "listAdminAutoscanScans"
                        }
                        .into(),
                        security: format!(
                            "{}/{}/{}",
                            claims.user_id,
                            get_profile_id(r),
                            viewer_digest(r)
                        ),
                        filter,
                        sort: if events {
                            "completed_desc"
                        } else {
                            "lifecycle_desc"
                        }
                        .into(),
                        tiebreaker: "id_desc".into(),
                    };
                    let mut pos: HistoryPosition = if cursor.is_empty() {
                        HistoryPosition::default()
                    } else {
                        match s.cursors.decode(&scope, &cursor) {
                            Ok(v) => v,
                            Err(p) => return write_problem(w, r, p).await,
                        }
                    };
                    if !(0..=1_000_000_000).contains(&pos.offset) {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                silo_api_v2::problem::invalid_cursor(),
                                if events {
                                    "Invalid event history position."
                                } else {
                                    "Invalid scan history position."
                                },
                            ),
                        )
                        .await;
                    }
                    if events {
                        let filter = store::EventListFilter {
                            source_id,
                            status,
                            search,
                            limit,
                            offset: pos.offset,
                        };
                        let rows = read_db!(w, r, store::list_events(&s.pool, &filter));
                        let total = read_db!(w, r, store::count_events(&s.pool, &filter));
                        if total < 0 || rows.len() as i64 > limit {
                            return write_problem(
                                w,
                                r,
                                Problem::new(internal_error(), "Invalid event history page."),
                            )
                            .await;
                        }
                        let mut items = Vec::with_capacity(rows.len());
                        for row in rows {
                            match event(row) {
                                Ok(v) => items.push(v),
                                Err(p) => return write_problem(w, r, p).await,
                            }
                        }
                        let next = if items.len() as i64 == limit {
                            pos.offset += items.len() as i64;
                            match s.cursors.encode(&scope, &pos) {
                                Ok(v) => v,
                                Err(p) => return write_problem(w, r, p).await,
                            }
                        } else {
                            String::new()
                        };
                        let page = paginated(items, next);
                        write_v2_json(
                            w,
                            &HistoryPage {
                                items: page.items,
                                page: page.page,
                                total,
                            },
                        )
                        .await;
                    } else {
                        let filter = store::ScanListFilter {
                            status,
                            search,
                            limit,
                            offset: pos.offset,
                        };
                        let rows = read_db!(w, r, store::list_autoscan_scans(&s.pool, &filter));
                        let total = read_db!(w, r, store::count_autoscan_scans(&s.pool, &filter));
                        if total < 0 || rows.len() as i64 > limit {
                            return write_problem(
                                w,
                                r,
                                Problem::new(internal_error(), "Invalid scan history page."),
                            )
                            .await;
                        }
                        let mut items = Vec::with_capacity(rows.len());
                        for row in rows {
                            match scan(row) {
                                Ok(v) => items.push(v),
                                Err(p) => return write_problem(w, r, p).await,
                            }
                        }
                        let next = if items.len() as i64 == limit {
                            pos.offset += items.len() as i64;
                            match s.cursors.encode(&scope, &pos) {
                                Ok(v) => v,
                                Err(p) => return write_problem(w, r, p).await,
                            }
                        } else {
                            String::new()
                        };
                        let page = paginated(items, next);
                        write_v2_json(
                            w,
                            &HistoryPage {
                                items: page.items,
                                page: page.page,
                                total,
                            },
                        )
                        .await;
                    }
                }),
            ),
        );
    }
}

#[derive(Serialize)]
struct AdminCollectionGroup {
    id: String,
    library_id: String,
    name: String,
    slug: String,
    kind: String,
    default_sort_mode: String,
    sort_order: i32,
}

#[derive(Serialize)]
struct AdminGroups {
    items: Vec<AdminCollectionGroup>,
    ungrouped_sort_order: i32,
}

#[derive(Serialize)]
struct AdminCollectionOrder {
    library_id: String,
    group_id: Option<String>,
    ordered_ids: Vec<String>,
    has_more: bool,
}

#[derive(Serialize)]
struct AdminUnmatchedFile {
    id: String,
    media_folder_id: String,
    file_path: String,
    file_size: i64,
    container: String,
}

fn mount_admin_reads(stack: &Arc<Stack>, v2: &Mux) {
    for (path, canonical) in [
        (
            "/api/v2/admin/libraries/{library_id}/collection-groups",
            false,
        ),
        (
            "/api/v2/admin/libraries/{library_id}/collection-groups/order",
            true,
        ),
    ] {
        v2.get(path, stack.v2(path, V2Class::ActingAdmin, route!(stack, |s, w, r| {
            let Some(id) = silo_api_v2::wire::Id(r.url_param("library_id").to_owned()).to_int() else {
                return write_problem(w, r, Problem::new(silo_api_v2::problem::type_for_status(404), "No library has that identifier.")).await;
            };
            // Go accepts a machine integer, then pgx rejects values outside the int4 key range.
            let Ok(database_id) = i32::try_from(id) else {
                return write_problem(w, r, internal_problem()).await;
            };
            let revision = if canonical {
                let revision = read_db!(w, r, reads::collection_order_revision(&s.pool, database_id));
                let Some(revision) = revision else {
                    return write_problem(w, r, Problem::new(silo_api_v2::problem::type_for_status(404), "Collection or group not found.")).await;
                };
                revision
            } else { 0 };
            let groups = read_db!(w, r, reads::list_collection_groups(&s.pool, database_id));
            let ungrouped = match reads::ungrouped_sort_order(&s.pool, database_id).await {
                Ok(order) => order,
                Err(_) if !canonical => 9999,
                Err(_) => return write_problem(w, r, internal_problem()).await,
            };
            if canonical {
                let after = read_db!(w, r, reads::collection_order_revision(&s.pool, database_id));
                let Some(after) = after else {
                    return write_problem(w, r, Problem::new(silo_api_v2::problem::type_for_status(404), "Collection or group not found.")).await;
                };
                if after != revision {
                    return write_problem(w, r, Problem::new(silo_api_v2::problem::type_for_status(409), "The collection changed during the read; fetch its current editor again.")).await;
                }
                let mut positions: Vec<_> = groups.into_iter().map(|g| (g.sort_order, g.id)).collect();
                positions.push((ungrouped, "ungrouped".to_owned()));
                positions.sort();
                let Some(claims) = get_claims(r) else { return; };
                let scope = format!("collections:admin-groups-order:{}:{}:{}", claims.user_id, get_profile_id(r), viewer_digest(r));
                let tag = silo_core::apiv2::render_etag(scope.as_bytes(), id.to_string().as_bytes(), revision);
                w.header().set("ETag", tag.to_wire());
                write_v2_json(w, &AdminCollectionOrder {
                    library_id: id.to_string(), group_id: None,
                    ordered_ids: positions.into_iter().map(|(_, id)| id).collect(), has_more: false,
                }).await;
            } else {
                write_v2_json(w, &AdminGroups {
                    items: groups.into_iter().map(|g| AdminCollectionGroup {
                        id: g.id, library_id: g.library_id.to_string(), name: g.name, slug: g.slug,
                        kind: g.kind, default_sort_mode: g.default_sort_mode, sort_order: g.sort_order,
                    }).collect(), ungrouped_sort_order: ungrouped,
                }).await;
            }
        })));
    }
    let path = "/api/v2/admin/unmatched";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let Some(claims) = get_claims(r) else {
                    return;
                };
                // The shared v2 chain applies Huma's integer parsing and bounds first.
                let limit = query(r, "limit").parse::<i64>().unwrap_or(50);
                let cursor = query(r, "cursor");
                let scope = CursorScope {
                    operation_id: "listAdminUnmatchedFiles".into(),
                    security: format!("{}/{}", claims.user_id, get_profile_id(r)),
                    filter: limit.to_string(),
                    sort: "id".into(),
                    tiebreaker: "id".into(),
                };
                let after: i64 = if cursor.is_empty() {
                    0
                } else {
                    match s.cursors.decode(&scope, &cursor) {
                        Ok(after) if after > 0 => after,
                        Ok(_) => {
                            return write_problem(
                                w,
                                r,
                                Problem::new(
                                    silo_api_v2::problem::invalid_cursor(),
                                    "Invalid file cursor",
                                ),
                            )
                            .await;
                        }
                        Err(p) => return write_problem(w, r, p).await,
                    }
                };
                let mut rows =
                    read_db!(w, r, reads::list_unmatched_files(&s.pool, limit + 1, after));
                let more = rows.len() as i64 > limit;
                rows.truncate(limit as usize);
                let next = if more && !rows.is_empty() {
                    match s
                        .cursors
                        .encode(&scope, &rows.last().expect("nonempty page").id)
                    {
                        Ok(next) => next,
                        Err(_) => return write_problem(w, r, internal_problem()).await,
                    }
                } else {
                    String::new()
                };
                let items: Vec<_> = rows
                    .into_iter()
                    .map(|f| AdminUnmatchedFile {
                        id: f.id.to_string(),
                        media_folder_id: f.media_folder_id.to_string(),
                        file_path: f.file_path,
                        file_size: f.file_size,
                        container: f.container,
                    })
                    .collect();
                write_v2_json(w, &paginated(items, next)).await;
            }),
        ),
    );
}

mod jobs {
    //! Retained admin jobs and signed local artifact URLs. S3 deployments keep these rows on Go.
    use super::super::chain::client_ip_of;
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use silo_gocompat::json::unmarshal;
    use silo_gocompat::time::GoTime;
    use silo_store::catalog::library_admin as jobs_store;

    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct CatalogResult {
        format_version: i64,
        schema_version: i64,
        libraries_exported: i64,
        items_exported: i64,
        cast_exported: i64,
        crew_exported: i64,
        seasons_exported: i64,
        episodes_exported: i64,
        files_exported: i64,
        library_links_exported: i64,
        items_created: i64,
        files_created: i64,
    }
    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct LibraryResult {
        total_items: i64,
        items_with_ids: i64,
        items_without_ids: i64,
        refreshed_ok: i64,
        refreshed_failed: i64,
        pipeline_ok: i64,
        pipeline_failed: i64,
        deleted_media_files: i64,
        deleted_orphaned_items: i64,
        image_cleanup_queued: bool,
        image_cleanup_dirs: i64,
        deleted_prefixes: i64,
        deleted_s3_objects: i64,
    }

    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct LibraryJobRequest {
        library_id: i64,
        library_name: String,
    }
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct CatalogJobRequest {
        library_ids: Vec<i64>,
        source_label: String,
    }
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct RefreshPayload {
        library_id: i64,
        refreshed_ok: i64,
        pipeline_ok: i64,
        refreshed_failed: i64,
        pipeline_failed: i64,
    }
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct DeletionPayload {
        library_id: i64,
        deleted_media_files: i64,
        deleted_item_links: i64,
        deleted_orphaned_items: i64,
    }
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct ItemPayload {
        requested_content_id: String,
        refresh_content_id: String,
        detail_content_id: String,
        matched_files: i64,
        artwork_cache_warning: String,
        scan_result: Option<ItemScan>,
    }
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct ItemScan {
        new: i64,
    }
    #[derive(Serialize)]
    struct ItemResult {
        new_files: i64,
        artwork_cache_incomplete: bool,
        requested_content_id: String,
        refresh_content_id: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        detail_content_id: String,
        matched_files: i64,
    }
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct TransitionPayload {
        phase: String,
        verified_objects: i64,
        copied_objects: i64,
        claim_generation: i64,
        failure_category: String,
        manual_restart_required: bool,
    }
    #[derive(Default, Serialize)]
    struct TransitionResult {
        phase: String,
        verified_objects: i64,
        #[serde(skip_serializing_if = "String::is_empty")]
        failure_category: String,
        manual_restart_required: bool,
    }
    #[derive(Serialize)]
    struct JobProgress {
        current: i64,
        total: i64,
        unit: &'static str,
    }
    #[derive(Serialize)]
    struct RefreshResult {
        library_id: String,
        refreshed: i64,
        failed: i64,
    }
    #[derive(Serialize)]
    struct DeletionResult {
        library_id: String,
        deleted_media_files: i64,
        deleted_item_links: i64,
        deleted_orphaned_items: i64,
    }
    #[derive(Serialize)]
    struct Failure {
        #[serde(rename = "type")]
        kind: String,
        title: &'static str,
        detail: &'static str,
        retryable: bool,
    }

    #[derive(Serialize)]
    struct TaskJob {
        #[serde(skip_serializing_if = "Option::is_none")]
        library_id: Option<String>,
        #[serde(skip_serializing_if = "String::is_empty")]
        library_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        library_result: Option<LibraryResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        template_result: Option<TemplateResult>,
        id: String,
        kind: String,
        state: String,
        terminal: bool,
        cancelable: bool,
        created_at: Instant,
        #[serde(skip_serializing_if = "Option::is_none")]
        started_at: Option<Instant>,
        #[serde(skip_serializing_if = "Option::is_none")]
        finished_at: Option<Instant>,
        #[serde(skip_serializing_if = "Option::is_none")]
        progress: Option<JobProgress>,
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_result: Option<RefreshResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        deletion_result: Option<DeletionResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        failure: Option<Failure>,
        library_ids: Vec<String>,
        #[serde(skip_serializing_if = "String::is_empty")]
        source_label: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        catalog_result: Option<CatalogResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        item_result: Option<ItemResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        storage_transition_result: Option<TransitionResult>,
        artifact_size_bytes: i64,
        #[serde(skip_serializing_if = "String::is_empty")]
        download_url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        download_expires_at: Option<Instant>,
        #[serde(skip_serializing_if = "String::is_empty")]
        public_url: String,
        public_link_supported: bool,
    }

    fn payload<T: serde::de::DeserializeOwned>(raw: &Option<String>) -> Option<T> {
        unmarshal(raw.as_deref().unwrap_or_default().as_bytes()).ok()
    }
    fn transition(job: &jobs_store::AdminJob) -> TransitionResult {
        let raw: TransitionPayload = payload(&job.result_payload).unwrap_or_default();
        let mut out = TransitionResult {
            verified_objects: raw.verified_objects.max(raw.copied_objects).max(0),
            manual_restart_required: raw.manual_restart_required,
            ..Default::default()
        };
        let checking = |out: &mut TransitionResult| {
            out.phase = "checking_target".into();
            out.verified_objects = 0;
            out.manual_restart_required = false;
        };
        match job.status.as_str() {
            "queued" => {
                out.phase = "queued".into();
                out.verified_objects = 0;
                out.manual_restart_required = false;
            }
            "failed" => {
                out.phase = "failed".into();
                out.manual_restart_required = false;
                out.failure_category = match raw.failure_category.as_str() {
                    "preparation_failed"
                    | "target_check_failed"
                    | "copy_failed"
                    | "verification_failed"
                    | "commit_failed" => raw.failure_category,
                    _ => "unknown".into(),
                };
            }
            "cancelled" => {
                out.phase = "canceled".into();
                out.manual_restart_required = false;
            }
            "completed" => {
                out.phase = if raw.phase == "restart_pending" || raw.manual_restart_required {
                    "restart_pending"
                } else {
                    "completed"
                }
                .into()
            }
            "running" => {
                if raw.claim_generation != job.claim_generation
                    && (raw.claim_generation != 0 || job.claim_generation > 1)
                {
                    checking(&mut out)
                } else {
                    match raw.phase.as_str() {
                        "checking_target" | "copying" | "verifying" | "committing"
                        | "restart_pending" => out.phase = raw.phase,
                        _ => checking(&mut out),
                    }
                }
            }
            _ => checking(&mut out),
        }
        out
    }

    fn task_job(job: &jobs_store::AdminJob, admin: bool, secret: &str, now: SystemTime) -> TaskJob {
        let terminal = matches!(job.status.as_str(), "completed" | "failed" | "cancelled");
        let state = if job.cancel_requested && !terminal {
            "canceling"
        } else {
            match job.status.as_str() {
                "completed" => "succeeded",
                "cancelled" => "canceled",
                v => v,
            }
        }
        .to_owned();
        let done = job.status == "completed";
        let progress_valid = job.progress_total > 0
            && job.progress_current >= 0
            && job.progress_current <= job.progress_total;
        let transition = (job.job_type == "storage_transition").then(|| transition(job));
        let mut out=TaskJob {
            library_id:None, library_name:String::new(), library_result:None, template_result:None,
            id:job.id.clone(),kind:job.job_type.clone(),state,terminal,
            cancelable:matches!(job.job_type.as_str(),"library_refresh"|"storage_transition"|"image_cache_cleanup") && !terminal,
            created_at:instant(job.requested_at),started_at:instant_opt(job.started_at),finished_at:instant_opt(job.completed_at),
            progress:(progress_valid && transition.as_ref().is_none_or(|t|job.status!="queued" && t.phase!="checking_target")).then_some(JobProgress {current:job.progress_current,total:job.progress_total,unit:"items"}),
            refresh_result:None,deletion_result:None,
            failure:(job.status=="failed").then(||Failure {kind:format!("{}job_failed",silo_api_v2::problem::PROBLEM_TYPE_ORIGIN),title:"Job failed",detail:"The operation could not finish. Inspect administrator diagnostics before submitting new work.",retryable:false}),
            library_ids:vec![],source_label:String::new(),catalog_result:None,item_result:None,storage_transition_result:None,artifact_size_bytes:0,download_url:String::new(),download_expires_at:None,public_url:String::new(),public_link_supported:false,
        };
        if done && job.job_type == "library_refresh" {
            out.refresh_result =
                payload::<RefreshPayload>(&job.result_payload).map(|p| RefreshResult {
                    library_id: p.library_id.to_string(),
                    refreshed: p.refreshed_ok + p.pipeline_ok,
                    failed: p.refreshed_failed + p.pipeline_failed,
                });
        }
        if done && job.job_type == "delete_library" {
            out.deletion_result =
                payload::<DeletionPayload>(&job.result_payload).map(|p| DeletionResult {
                    library_id: p.library_id.to_string(),
                    deleted_media_files: p.deleted_media_files,
                    deleted_item_links: p.deleted_item_links,
                    deleted_orphaned_items: p.deleted_orphaned_items,
                });
        }
        if done && job.job_type == "item_refresh" {
            out.item_result = payload::<ItemPayload>(&job.result_payload)
                .filter(|p| !p.requested_content_id.is_empty() && !p.refresh_content_id.is_empty())
                .map(|p| ItemResult {
                    new_files: p.scan_result.map_or(0, |v| v.new),
                    artwork_cache_incomplete: !p.artwork_cache_warning.is_empty(),
                    requested_content_id: p.requested_content_id,
                    refresh_content_id: p.refresh_content_id,
                    detail_content_id: p.detail_content_id,
                    matched_files: p.matched_files,
                });
        }
        if !admin {
            return out;
        }
        out.storage_transition_result = transition;
        if matches!(
            job.job_type.as_str(),
            "library_refresh" | "delete_library" | "image_cache_cleanup"
        ) {
            if let Some(p) = payload::<LibraryJobRequest>(&job.request_payload) {
                out.library_id = (p.library_id > 0).then(|| p.library_id.to_string());
                out.library_name = p.library_name;
            }
            if done || (job.job_type == "image_cache_cleanup" && job.status == "cancelled") {
                out.library_result = payload(&job.result_payload);
            }
        }
        if job.job_type == "template_bundle_apply" {
            out.cancelable = false;
            out.progress = progress_valid.then_some(JobProgress {
                current: job.progress_current,
                total: job.progress_total,
                unit: "templates",
            });
            if done {
                out.template_result =
                    payload::<TemplateResult>(&job.result_payload).map(safe_template);
            }
        }
        if matches!(job.job_type.as_str(), "catalog_export" | "catalog_import") {
            if let Some(p) = payload::<CatalogJobRequest>(&job.request_payload) {
                out.library_ids = p.library_ids.iter().map(i64::to_string).collect();
                out.source_label = p.source_label;
            }
            if done {
                out.catalog_result = payload(&job.result_payload);
            }
            out.artifact_size_bytes = job.artifact_size_bytes;
            out.public_url = job.public_url.clone();
            if done && !job.artifact_bucket.is_empty() && !job.artifact_key.is_empty() {
                let (url, expires) = sign_artifact(secret, &job.id, now);
                out.download_url = url;
                out.download_expires_at = Some(expires);
            }
        }
        out
    }

    fn id_json<S: serde::Serializer>(id: &i64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&id.to_string())
    }
    fn optional_id_json<S: serde::Serializer>(id: &i64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&if *id > 0 {
            id.to_string()
        } else {
            String::new()
        })
    }
    fn no_id(id: &i64) -> bool {
        *id <= 0
    }
    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct TemplateEntry {
        template_id: String,
        template_title: String,
        #[serde(serialize_with = "id_json")]
        library_id: i64,
        library_name: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        collection_id: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        reason: String,
    }
    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct TemplateCollectionEntry {
        #[serde(serialize_with = "id_json")]
        library_id: i64,
        library_name: String,
        collection_id: String,
        collection_title: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        reason: String,
    }
    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct TemplateFeaturedEntry {
        surface: String,
        #[serde(serialize_with = "optional_id_json", skip_serializing_if = "no_id")]
        library_id: i64,
        #[serde(skip_serializing_if = "String::is_empty")]
        library_name: String,
        template_id: String,
        template_title: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        collection_id: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        section_id: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        reason: String,
    }
    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct TemplateResult {
        bundle_id: String,
        dry_run: bool,
        delete_existing: bool,
        deleted: Vec<TemplateCollectionEntry>,
        delete_skipped: Vec<TemplateCollectionEntry>,
        delete_failed: Vec<TemplateCollectionEntry>,
        created: Vec<TemplateEntry>,
        skipped: Vec<TemplateEntry>,
        failed: Vec<TemplateEntry>,
        sync_queued: Vec<TemplateEntry>,
        featured: Vec<TemplateFeaturedEntry>,
        featured_failed: Vec<TemplateFeaturedEntry>,
    }
    fn safe_template(mut p: TemplateResult) -> TemplateResult {
        fn reason(s: &mut String) {
            if !matches!(
                s.as_str(),
                "" | "would_create"
                    | "created"
                    | "created_sync_skipped_unconfigured"
                    | "sync_queued"
                    | "sync_queued_no_schedule"
                    | "would_delete"
                    | "deleted"
                    | "in_use_by_section"
                    | "shared_with_unselected_library"
                    | "ineligible_library"
                    | "already_exists"
                    | "already_exists_delete_failed"
                    | "library_not_selected"
                    | "template_not_found"
                    | "template_not_in_bundle"
                    | "collection_not_available"
                    | "section_repo_not_configured"
            ) {
                *s = "operation_failed".into();
            }
        }
        for v in p
            .deleted
            .iter_mut()
            .chain(&mut p.delete_skipped)
            .chain(&mut p.delete_failed)
        {
            reason(&mut v.reason);
        }
        for v in p
            .created
            .iter_mut()
            .chain(&mut p.skipped)
            .chain(&mut p.failed)
            .chain(&mut p.sync_queued)
        {
            reason(&mut v.reason);
        }
        for v in p.featured.iter_mut().chain(&mut p.featured_failed) {
            reason(&mut v.reason);
        }
        p
    }

    /// Go's job-artifact domain is distinct from artwork, even though both derive from the JWT secret.
    fn sign_artifact(secret: &str, id: &str, now: SystemTime) -> (String, Instant) {
        type H = Hmac<Sha256>;
        let hmac = |key: &[u8], bytes: &[u8]| {
            let mut h = H::new_from_slice(key).expect("HMAC takes any key");
            h.update(bytes);
            h.finalize().into_bytes().to_vec()
        };
        let key = hmac(secret.as_bytes(), b"silo-job-artifact-url-v1");
        let secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let exp = secs - (secs + 62_135_596_800).rem_euclid(900) + 1800;
        let sig = hmac(&key, format!("job-artifact-v1\n{id}\n{exp}").as_bytes());
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut encoded = String::new();
        for c in sig[..16].chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            encoded.push(TABLE[(n >> 18) as usize & 63] as char);
            encoded.push(TABLE[(n >> 12) as usize & 63] as char);
            if c.len() > 1 {
                encoded.push(TABLE[(n >> 6) as usize & 63] as char);
            }
            if c.len() > 2 {
                encoded.push(TABLE[n as usize & 63] as char);
            }
        }
        let path = silo_gocompat::url::Url {
            path: format!(
                "/api/v2/admin/jobs/{}/artifact",
                id.strip_prefix('/').unwrap_or(id)
            ),
            ..Default::default()
        }
        .escaped_path();
        (
            format!("{path}?exp={exp}&sig={encoded}"),
            Instant::new(
                time::OffsetDateTime::from_unix_timestamp(exp)
                    .expect("current expiry fits timestamp"),
            ),
        )
    }

    #[derive(Default, Serialize, Deserialize)]
    #[serde(default)]
    struct JobPosition {
        requested: GoTime,
        id: String,
    }

    pub(super) fn mount(stack: &Arc<Stack>, v2: &Mux) {
        let path = "/api/v2/admin/jobs";
        let s = stack.clone();
        v2.get(
            path,
            stack.v2(
                path,
                V2Class::ActingAdmin,
                handler_fn(move |w, r| {
                    let s = s.clone();
                    Box::pin(async move {
                        let Some(claims) = get_claims(r) else {
                            return;
                        };
                        let limit = query(r, "limit").parse::<i64>().unwrap_or(20);
                        let kind = query(r, "kind");
                        let cursor = query(r, "cursor");
                        let scope = CursorScope {
                            operation_id: "listAdminJobs".into(),
                            security: format!("{}/{}", claims.user_id, get_profile_id(r)),
                            filter: kind.clone(),
                            sort: "-requested_at".into(),
                            tiebreaker: "id".into(),
                        };
                        let pos: JobPosition = if cursor.is_empty() {
                            JobPosition::default()
                        } else {
                            match s.cursors.decode(&scope, &cursor) {
                                Ok(v) => v,
                                Err(p) => return write_problem(w, r, p).await,
                            }
                        };
                        let mut rows = match jobs_store::list_admin_jobs(
                            &s.pool,
                            &kind,
                            pos.requested.to_system_time(),
                            &pos.id,
                            limit + 1,
                        )
                        .await
                        {
                            Ok(v) => v,
                            Err(_) => return write_problem(w, r, internal_problem()).await,
                        };
                        let mut next = String::new();
                        if rows.len() > limit as usize {
                            rows.truncate(limit as usize);
                            let last = rows.last().expect("positive validated limit");
                            next = match s.cursors.encode(
                                &scope,
                                &JobPosition {
                                    requested: GoTime::from_system_time(last.requested_at),
                                    id: last.id.clone(),
                                },
                            ) {
                                Ok(v) => v,
                                Err(p) => return write_problem(w, r, p).await,
                            };
                        }
                        let now = SystemTime::now();
                        let items = rows
                            .iter()
                            .map(|job| task_job(job, true, &s.artwork_secret, now))
                            .collect();
                        write_v2_json(w, &paginated(items, next)).await;
                    })
                }),
            ),
        );
        let path = "/api/v2/admin/jobs/{id}";
        let s = stack.clone();
        v2.get(
            path,
            stack.v2(
                path,
                V2Class::ProfileOptional,
                handler_fn(move |w, r| {
                    let s = s.clone();
                    Box::pin(async move {
                        let hidden = || {
                            Problem::new(
                                silo_api_v2::problem::type_for_status(404),
                                "Job not found",
                            )
                        };
                        let job = match jobs_store::admin_job(&s.pool, r.url_param("id")).await {
                            Ok(Some(v)) => v,
                            Ok(None) => return write_problem(w, r, hidden()).await,
                            Err(_) => return write_problem(w, r, internal_problem()).await,
                        };
                        let admin = match s.gates.acting_admin(r, &client_ip_of(r)).await {
                            Ok(v) => v,
                            Err(_) => return write_problem(w, r, internal_problem()).await,
                        };
                        if !admin
                            && (job.job_type != "item_refresh"
                                || get_claims(r)
                                    .is_none_or(|c| c.user_id != job.created_by_user_id))
                        {
                            return write_problem(w, r, hidden()).await;
                        }
                        let body = task_job(&job, admin, &s.artwork_secret, SystemTime::now());
                        if !body.terminal {
                            w.header().set("Retry-After", "5");
                        }
                        write_v2_json(w, &body).await;
                    })
                }),
            ),
        );
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn job(kind: &str) -> jobs_store::AdminJob {
            jobs_store::AdminJob {
                id: "job-1".into(),
                job_type: kind.into(),
                status: "completed".into(),
                created_by_user_id: 7,
                request_payload: Some(
                    r#"{"library_id":12,"library_name":"private","source_label":"private"}"#.into(),
                ),
                result_payload: Some("{}".into()),
                progress_current: 1,
                progress_total: 1,
                artifact_bucket: "private".into(),
                artifact_key: "private".into(),
                artifact_size_bytes: 99,
                public_url: "https://private.invalid".into(),
                requested_at: SystemTime::UNIX_EPOCH,
                started_at: None,
                completed_at: None,
                cancel_requested: false,
                claim_generation: 1,
            }
        }
        #[test]
        fn artifact_signature_uses_its_domain_and_bucket() {
            let (url, expiry) = sign_artifact(
                "secret",
                "job-1",
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1700000000),
            );
            assert_eq!(
                url,
                "/api/v2/admin/jobs/job-1/artifact?exp=1700001000&sig=GVRM_sv4T2NR6F8UfXfY6w"
            );
            assert_eq!(
                serde_json::to_string(&expiry).unwrap(),
                "\"2023-11-14T22:30:00.000Z\""
            );
        }
        #[test]
        fn item_owner_receives_only_safe_result() {
            let mut job = job("item_refresh");
            job.result_payload=Some(r#"{"requested_content_id":"a","refresh_content_id":"b","scan_path":"private","artwork_cache_warning":"private","scan_result":{"new":3},"matched_files":4}"#.into());
            let out = task_job(&job, false, "secret", SystemTime::UNIX_EPOCH);
            let json = serde_json::to_string(&out).unwrap();
            assert!(!json.contains("private"));
            assert!(!json.contains("download_url"));
            assert!(!json.contains("library_name"));
            let item = out.item_result.unwrap();
            assert_eq!(item.new_files, 3);
            assert!(item.artwork_cache_incomplete);
            assert_eq!(item.matched_files, 4);
        }
        #[test]
        fn null_job_payload_retains_go_zero_value_results() {
            let mut job = job("catalog_export");
            job.result_payload = Some("null".into());
            assert!(
                task_job(&job, true, "secret", SystemTime::UNIX_EPOCH)
                    .catalog_result
                    .is_some()
            );
            let template: TemplateResult = unmarshal(br#"{"created":null}"#).unwrap();
            assert!(template.created.is_empty());
        }
    }
}
