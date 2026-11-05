//! The native rows: the Rust handlers, the chain in front of them, and which requests go to them.
//!
//! A native handler runs behind silo-http's port of Go's connection engine, so framing, header order,
//! and refusals are Go's. Each domain keeps its rows and handlers in its own file. See `README.md`,
//! Adding a native row.

// A `Problem` is the refusal itself: every handler returns one or an answer, on the way to the wire.
#![allow(clippy::result_large_err)]

pub mod account;
pub mod admin_settings;
pub mod admin_stats;
pub mod api_keys;
pub mod auth;
pub mod catalog;
pub mod chain;
pub mod collections;
pub mod discovery;
pub mod huma;
pub mod interest;
pub mod libraries;
pub mod library_admin;
pub mod notifications;
pub mod personal;
pub mod playback;
pub mod profiles;
pub mod requests;
pub mod settings;
pub mod system;
pub mod watch_state;

use std::sync::Arc;

use serde::Serialize;
use silo_http::chi::Mux;
use silo_http::compress::{ResponseInfo, compress_with_exclusions};
use silo_http::{BoxHandler, Header, ResponseWriter, ServeMux, handler_fn, not_found_handler};

pub use chain::{Stack, Step, V2Class};

use crate::frontend::{self, BrandingSource, WebDist};
use crate::http1::RequestHead;
use crate::rows::{NativeRow, ROWS, Surface, in_table, is_native};

/// Every domain's rows. A new domain adds one line here and one in [`main_handler`].
pub const DOMAINS: &[&[NativeRow]] = &[
    system::ROWS,
    account::ROWS,
    discovery::ROWS,
    auth::ROWS,
    api_keys::ROWS,
    settings::ROWS,
    profiles::ROWS,
    admin_settings::ROWS,
    libraries::ROWS,
    notifications::ROWS,
    personal::ROWS,
    admin_stats::ROWS,
    catalog::ROWS,
    collections::ROWS,
    requests::ROWS,
    library_admin::ROWS,
    playback::ROWS,
    watch_state::ROWS,
];

const fn all_in_table() -> bool {
    let mut d = 0;
    while d < DOMAINS.len() {
        let mut i = 0;
        while i < DOMAINS[d].len() {
            if !in_table(DOMAINS[d][i]) {
                return false;
            }
            i += 1;
        }
        d += 1;
    }
    true
}
#[allow(long_running_const_eval)]
const _: () = assert!(
    all_in_table(),
    "a native/<domain>.rs ROWS entry is not in rows_table.rs"
);

/// `netaccess.IngressTokenHeader` and `IngressPeerHeader`: the middleware that reads them needs the
/// network access registry.
const INGRESS_HEADERS: [&str; 2] = ["X-Silo-Ingress-Token", "X-Silo-Ingress-Peer"];

/// The identity `/api/v1/health` advertises, read from settings at startup as `deps.Config` is.
#[derive(Clone, Debug)]
pub struct ServerIdentity {
    pub name: String,
    pub id: String,
}

/// What the native rows have available. A row whose input is missing stays on Go.
#[derive(Clone, Default)]
pub struct NativeInputs {
    pub identity: Option<ServerIdentity>,
    pub spa: Option<(WebDist, BrandingSource)>,
    /// The credential chain. Without it every row behind a credential stays on Go.
    pub stack: Option<Arc<Stack>>,
}

/// `apiv2.Problem`, for the two the v2 router itself writes.
#[derive(Serialize)]
struct Problem<'a> {
    #[serde(rename = "type")]
    type_uri: String,
    title: &'a str,
    status: u16,
    detail: &'a str,
    instance: String,
}

/// `writeProblem` for the router's own answers.
async fn write_problem(
    w: &mut dyn ResponseWriter,
    slug: &str,
    title: &str,
    status: u16,
    detail: &str,
    allow: Option<String>,
    id: String,
) {
    let problem = Problem {
        type_uri: format!("{}{slug}", silo_api_v2::problem::PROBLEM_TYPE_ORIGIN),
        title,
        status,
        detail,
        instance: format!("urn:silo:request:{id}"),
    };
    let mut body = silo_gocompat::json::marshal(&problem).expect("a struct of strings marshals");
    body.push(b'\n');
    let h = w.header();
    if let Some(allow) = allow {
        h.add("Allow", allow);
    }
    h.set("Content-Type", "application/problem+json");
    h.set("Cache-Control", "no-store");
    w.write_header(status).await;
    let _ = w.write(&body).await;
}

/// `methodOrder`.
const METHOD_ORDER: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// `Registry.AllowedMethods`: every declared operation the concrete path is an instance of.
fn v2_methods(path: &str) -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = ROWS
        .iter()
        .filter(|r| r.surface == Surface::ApiV2 && matches_template(r.path, path))
        .map(|r| r.method)
        .collect();
    methods.sort_unstable();
    methods.dedup();
    let rank = |m: &str| {
        METHOD_ORDER
            .iter()
            .position(|o| *o == m)
            .unwrap_or(usize::MAX)
    };
    methods.sort_by_key(|m| rank(m));
    methods
}

/// The test half of `apiv2.IdentityEncoded`. Its header edits (`Content-Encoding: identity` and
/// `no-transform`) are on the rows that carry an ETag, because silo-http's `SkipResponse` gets the
/// header read-only.
fn identity_encoded(info: &ResponseInfo, h: &Header) -> bool {
    info.path.starts_with(b"/api/v2/") && !h.get("ETag").is_empty()
}

/// The handler behind the `main` listener's native rows, shaped like `newRootMux`.
pub fn main_handler(inputs: &NativeInputs) -> BoxHandler {
    let api = Mux::new();
    let skip_response: silo_http::compress::SkipResponse = Arc::new(identity_encoded);
    match &inputs.stack {
        Some(stack) => api.use_middleware([
            stack.base_middleware(),
            chain::recoverer(),
            stack.observe_middleware(),
        ]),
        None => api.use_middleware([chain::recoverer()]),
    }
    api.use_middleware([compress_with_exclusions(None, Some(skip_response), &[])]);

    let v2 = Mux::new();
    v2.use_middleware([
        chain::request_id_v2(),
        chain::reject_malformed_device_header(),
    ]);
    v2.not_found(handler_fn(|w, r| {
        let id = chain::request_id_of(r);
        chain::note_problem(r, "not_found");
        Box::pin(write_problem(
            w,
            "not_found",
            "Not found",
            404,
            "No operation is registered at this path.",
            None,
            id,
        ))
    }));
    v2.method_not_allowed(handler_fn(|w, r| {
        let allow = v2_methods(&String::from_utf8_lossy(&r.url.path)).join(", ");
        let id = chain::request_id_of(r);
        chain::note_problem(r, "method_not_allowed");
        Box::pin(write_problem(
            w,
            "method_not_allowed",
            "Method not allowed",
            405,
            "The method is not supported at this path.",
            (!allow.is_empty()).then_some(allow),
            id,
        ))
    }));

    system::mount(&api, &v2, inputs);
    discovery::mount_public(&api, &v2);
    library_admin::mount_public(&v2);
    if let Some(stack) = &inputs.stack {
        account::mount(stack, &api, &v2);
        auth::mount(stack, &api, &v2);
        api_keys::mount(stack, &api, &v2);
        settings::mount(stack, &api, &v2);
        profiles::mount(stack, &api, &v2);
        admin_settings::mount_v2(stack, &v2);
        libraries::mount(stack, &api, &v2);
        notifications::mount(stack, &api, &v2);
        personal::mount(stack, &api, &v2);
        admin_stats::mount_v2(stack, &v2);
        catalog::mount_v2(stack, &v2);
        collections::mount(stack, &api, &v2);
        requests::mount(stack, &api, &v2);
        discovery::mount(stack, &api, &v2);
        library_admin::mount(stack, &v2);
        playback::mount(stack, &v2);
        watch_state::mount(stack, &v2);
    }

    api.handle("/api/v2/*", Arc::new(v2));

    let mux = ServeMux::new();
    mux.handle("/metrics", not_found_handler());
    mux.handle("/api/", Arc::new(api));
    if let Some((dist, branding)) = &inputs.spa {
        mux.handle("/", frontend::handler(dist.clone(), branding.clone()));
    }
    Arc::new(mux)
}

/// Decides whether a request on the `main` listener can be answered natively.
pub struct Gate {
    health: bool,
    spa: bool,
    stack: Option<Arc<Stack>>,
    /// Surfaces sent back to Go, the rollback switch and proxy-all mode.
    force_go: Vec<Surface>,
}

/// Whether a request path is an instance of a row's template. A row spelled with a trailing slash is
/// chi's mounted `/`, which answers both spellings.
fn matches_template(template: &str, path: &str) -> bool {
    let template = template.strip_suffix('/').unwrap_or(template);
    let mut a = template.split('/');
    let mut b = path.split('/');
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(t), Some(p)) => {
                if t.starts_with('{') {
                    if p.is_empty() {
                        return false;
                    }
                } else if t != p {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// The row for a path: an exact spelling wins over a template, so a literal Go row beside a native
/// `{id}` row stays Go's.
fn domain_row(path: &str) -> Option<&'static NativeRow> {
    let rows = || {
        DOMAINS
            .iter()
            .flat_map(|rows| rows.iter())
            .filter(|r| matches!(r.surface, Surface::ApiV1 | Surface::ApiV2))
    };
    if let Some(row) = rows().find(|r| r.path.strip_suffix('/').unwrap_or(r.path) == path) {
        return Some(row);
    }
    let literal_elsewhere = ROWS.iter().any(|r| r.path == path);
    if literal_elsewhere {
        return None;
    }
    // chi takes the template with a literal where another has a parameter, so a path that a Go row spells with
    // more literals is Go's (`PUT /admin/collections/{id}/items/order` beside a native `.../items/{item_id}`).
    let params = |p: &str| p.matches('{').count();
    let native = rows()
        .filter(|r| r.path.contains('{') && matches_template(r.path, path))
        .min_by_key(|r| params(r.path))?;
    let go_more_literal = ROWS.iter().any(|r| {
        r.surface == native.surface
            && params(r.path) < params(native.path)
            && matches_template(r.path, path)
            && !DOMAINS.iter().any(|d| d.iter().any(|n| n.path == r.path))
    });
    (!go_more_literal).then_some(native)
}

/// Rows that need no credential: these work without the chain.
fn is_public(row: &NativeRow) -> bool {
    system::ROWS.contains(row)
        || discovery::PUBLIC_ROWS.contains(row)
        || library_admin::PUBLIC_ROWS.contains(row)
}

/// The raw path is one `ServeMux` keeps as is and routes to the frontend.
fn spa_path(path: &[u8]) -> bool {
    let clean = !path.contains(&b'%')
        && !path.windows(2).any(|w| w == b"//")
        && !path.windows(3).any(|w| w == b"/./")
        && !path.windows(4).any(|w| w == b"/../")
        && !path.ends_with(b"/.")
        && !path.ends_with(b"/..");
    clean
        && path != b"/api"
        && !path.starts_with(b"/api/")
        && path != b"/metrics"
        // Branding: these read the asset store when a custom icon or name is set.
        && path != b"/site.webmanifest"
        && path != b"/favicon.ico"
}

/// Routing conditions read on the request path; `None` uses the last reload's value.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fresh {
    pub personal_needs_go: Option<bool>,
    pub request_server_enabled: Option<bool>,
}

impl Gate {
    pub fn new(inputs: &NativeInputs, force_go: Vec<Surface>) -> Self {
        Self {
            health: inputs.identity.is_some(),
            spa: inputs.spa.is_some(),
            stack: inputs.stack.clone(),
            force_go,
        }
    }

    /// Re-reads, on the request path, the database conditions Go checks on each request before a row's
    /// routing depends on them: a watch provider connection or watchlist title for the personal rows, and
    /// an enabled request server for the request status rows. The admin reload alone would lag them by
    /// up to its poll interval, because no event announces those tables changing.
    /// The values read decide this request, so a concurrent request's older read cannot.
    pub async fn refresh_for(&self, head: &RequestHead) -> Fresh {
        let mut fresh = Fresh::default();
        let Some(stack) = self.stack.as_ref() else {
            return fresh;
        };
        let Some(path) = head.origin_path().and_then(|p| std::str::from_utf8(p).ok()) else {
            return fresh;
        };
        let bare = path.strip_suffix('/').unwrap_or(path);
        if requests::STATUS_PATHS.contains(&bare) {
            fresh.request_server_enabled = Some(stack.refresh_request_server().await);
        }
        if domain_row(bare)
            .is_some_and(|row| personal::ROWS.contains(row) || row.path == "/api/v2/watched/{id}")
        {
            fresh.personal_needs_go = Some(stack.refresh_personal_needs_go().await);
        }
        fresh
    }

    fn enabled(&self, surface: Surface) -> bool {
        !self.force_go.contains(&surface)
    }

    /// Whether this request goes to the native handler. A native path takes its trailing-slash spelling
    /// and every method the table does not list there, because the router's own 404 and 405 answers for
    /// them are ported too. A method the table lists as Go's goes to Go.
    pub fn is_native(&self, head: &RequestHead) -> bool {
        self.is_native_with(head, Fresh::default())
    }

    /// `is_native`, with the conditions `refresh_for` read for this request.
    pub fn is_native_with(&self, head: &RequestHead, fresh: Fresh) -> bool {
        let Some(path) = head.origin_path() else {
            return false;
        };
        let Ok(path_text) = std::str::from_utf8(path) else {
            return false;
        };
        let method = head.method.as_str();
        // See the note on CONNECT at the top of rows_table.rs.
        if method == "CONNECT" {
            return false;
        }
        if self.enabled(Surface::Root) && path == b"/metrics" {
            return is_native(Surface::Root, method, "/metrics");
        }
        let no_ingress = !INGRESS_HEADERS.iter().any(|h| head.has(h));
        let bare = path_text.strip_suffix('/').unwrap_or(path_text);
        if notifications::is_go_subtree(bare) || requests::is_go_literal(bare) {
            return false;
        }
        if let Some(row) = domain_row(bare) {
            if !self.enabled(row.surface) || !no_ingress {
                return false;
            }
            if row.path == "/api/v1/health" && !self.health {
                return false;
            }
            // A policy this process cannot load stays Go's to enforce.
            if !is_public(row) && self.stack.as_ref().is_none_or(|s| s.policy_refused()) {
                return false;
            }
            // Sign-in with a configured external provider needs the plugin host.
            if auth::PROVIDER_PATHS.contains(&bare)
                && self.stack.as_ref().is_some_and(|s| s.external_sign_in())
            {
                return false;
            }
            // Avatars and library posters in S3 need presigned URLs, which are not ported.
            if (profiles::ROWS.contains(row)
                || libraries::ROWS.contains(row)
                || notifications::ROWS.contains(row)
                || library_admin::S3_ROWS.contains(row)
                || playback::S3_ROWS.contains(row))
                && self
                    .stack
                    .as_ref()
                    .is_some_and(|s| !s.local_operational_store)
            {
                return false;
            }
            // Go answers for its Meilisearch provider, its session limits, and its result window.
            if bare == catalog::SEARCH_CAPABILITIES
                && self.stack.as_ref().is_some_and(|s| s.search_meilisearch())
            {
                return false;
            }
            // Watch providers and plugin-backed session posters need the plugin host.
            if (bare == "/api/v1/admin/stats"
                || bare == "/api/v2/admin/stats"
                || bare == "/api/v2/admin/sessions")
                && self.stack.as_ref().is_some_and(|s| s.plugins_installed())
            {
                return false;
            }
            // `missing_seasons_requestable` asks an enabled server's plugin.
            if requests::STATUS_PATHS.contains(&bare)
                && self.stack.as_ref().is_some_and(|s| {
                    fresh
                        .request_server_enabled
                        .unwrap_or(s.request_server_enabled())
                })
            {
                return false;
            }
            // Watch provider fan-out and title promotion need the plugin host and watchlist service.
            if (personal::ROWS.contains(row) || row.path == "/api/v2/watched/{id}")
                && self
                    .stack
                    .as_ref()
                    .is_some_and(|s| fresh.personal_needs_go.unwrap_or(s.personal_needs_go()))
            {
                return false;
            }
            // A method this path does not answer natively stays on Go when Go's answer is not a plain 405 of the
            // native rows: another method at the path is Go's, so its `Allow` names that method, or the method is
            // at a sibling template that takes this path as a parameter (`PUT /libraries/{id}`), whose methods chi also names.
            let spelled_exactly = bare == path_text || row.path.ends_with('/');
            if spelled_exactly && !is_native(row.surface, method, row.path) {
                let same_path_go = ROWS.iter().any(|r| {
                    r.surface == row.surface
                        && r.path == row.path
                        && !is_native(r.surface, r.method, r.path)
                });
                let sibling = ROWS.iter().any(|r| {
                    r.surface == row.surface && r.path != row.path && matches_template(r.path, bare)
                });
                if same_path_go || sibling {
                    return false;
                }
            }
            return true;
        }
        if bare.starts_with("/api/") || path_text == "/api" {
            return false;
        }
        self.spa
            && self.enabled(Surface::Root)
            && spa_path(path)
            && is_native(Surface::Root, method, "/")
    }
}
