//! Library administration capability rows: v2 `scan_controls.go` (`getScanCapabilities`),
//! `autoscan_delivery.go` (`getAutoscanDeliveryCapabilities`), `admin_job_artifact_download.go`
//! (`getAdminJobCapabilities`), and `admin_storage_transition.go` (`getAdminStorageTransitionCapabilities`).
//!
//! Every scan, autoscan, job, task, and storage transition action stays on Go: each reaches the scanner, the
//! autoscan ingest path, the job runner, or the blob store. `getAdminJobCapabilities` stays on Go while a
//! deployment uses S3, because public links need presigning.

use std::sync::Arc;

use serde::Serialize;
use silo_http::chi::Mux;
use silo_http::handler_fn;

use super::chain::{Stack, V2Class, capability_json, v2_public, write_capability};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", "/api/v2/scan/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/autoscan/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/jobs/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/storage-transitions/capabilities"),
];

/// Rows that need no credential.
pub const PUBLIC_ROWS: &[NativeRow] = &[NativeRow::new(ApiV2, "GET", "/api/v2/autoscan/capabilities")];

/// Rows whose answer depends on S3 presigning, which is not ported.
pub const S3_ROWS: &[NativeRow] = &[NativeRow::new(ApiV2, "GET", "/api/v2/admin/jobs/capabilities")];

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

fn simple(v2: &Mux, stack: Option<&Arc<Stack>>, path: &'static str, class: V2Class, op: &'static str) {
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
