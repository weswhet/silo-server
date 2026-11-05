//! Native `listAdminTrickplayLibraries`, a single Postgres read with no worker dependency.
//!
//! `POST /api/v2/admin/jobs/{id}/cancel` remains on Go: its
//! `RequestAdminTaskJobCancellation` signals `CancelRegistry.Cancel` for running
//! image-cache-cleanup jobs. Cancellation is therefore not a pure Postgres update.

use std::sync::Arc;

use serde::Serialize;
use silo_api_v2::problem::{Problem, internal_error};
use silo_http::{chi::Mux, handler_fn};
use silo_store::library_admin_reads::trickplay as store;

use super::super::chain::{Stack, V2Class, write_problem, write_v2_json};

#[derive(Serialize)]
struct Library {
    library_id: String,
    name: String,
    pending: i64,
    running: i64,
    ready: i64,
    unusable: i64,
    sheet_bytes: i64,
}

#[derive(Serialize)]
struct Libraries {
    items: Vec<Library>,
}

pub(super) fn mount(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/admin/trickplay/libraries";
    let s = stack.clone();
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    let libraries = match store::library_statuses(&s.pool).await {
                        Ok(v) => v,
                        Err(_) => {
                            return write_problem(
                                w,
                                r,
                                Problem::new(internal_error(), "An unexpected error occurred."),
                            )
                            .await;
                        }
                    };
                    let items = libraries
                        .into_iter()
                        .map(|l| Library {
                            library_id: l.library_id.to_string(),
                            name: l.name,
                            pending: l.pending,
                            running: l.running,
                            ready: l.ready,
                            unusable: l.unusable,
                            sheet_bytes: l.sheet_bytes,
                        })
                        .collect();
                    write_v2_json(w, &Libraries { items }).await;
                })
            }),
        ),
    );
}
