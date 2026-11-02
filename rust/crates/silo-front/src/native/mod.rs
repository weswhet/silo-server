//! The native rows: the Rust handlers, the chain in front of them, and which requests go to them.
//!
//! A native handler runs behind silo-http's port of Go's connection engine, so framing, header order,
//! and refusals are Go's. Each domain keeps its rows and handlers in its own file. See `README.md`,
//! Adding a native row.

pub mod account;
pub mod chain;
pub mod discovery;
pub mod system;

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
pub const DOMAINS: &[&[NativeRow]] = &[system::ROWS, account::ROWS, discovery::ROWS];

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

/// The methods the contract declares on a v2 path, sorted as `Registry.AllowedMethods` sorts them.
fn v2_methods(path: &str) -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = ROWS
        .iter()
        .filter(|r| r.surface == Surface::ApiV2 && r.path == path)
        .map(|r| r.method)
        .collect();
    methods.sort_unstable();
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
    if let Some(stack) = &inputs.stack {
        api.use_middleware([stack.base_middleware()]);
    }
    api.use_middleware([compress_with_exclusions(None, Some(skip_response), &[])]);

    let v2 = Mux::new();
    v2.use_middleware([
        chain::request_id_v2(),
        chain::reject_malformed_device_header(),
    ]);
    v2.not_found(handler_fn(|w, r| {
        let id = chain::request_id_of(r);
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
    if let Some(stack) = &inputs.stack {
        account::mount(stack, &api, &v2);
        discovery::mount(stack, &api, &v2);
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
    chain: bool,
    /// Surfaces sent back to Go, the rollback switch and proxy-all mode.
    force_go: Vec<Surface>,
}

fn domain_row(path: &str) -> Option<&'static NativeRow> {
    DOMAINS
        .iter()
        .flat_map(|rows| rows.iter())
        .find(|r| r.path == path && matches!(r.surface, Surface::ApiV1 | Surface::ApiV2))
}

/// Rows that need no credential: these work without the chain.
fn is_public(row: &NativeRow) -> bool {
    system::ROWS.contains(row) || discovery::PUBLIC_ROWS.contains(row)
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

impl Gate {
    pub fn new(inputs: &NativeInputs, force_go: Vec<Surface>) -> Self {
        Self {
            health: inputs.identity.is_some(),
            spa: inputs.spa.is_some(),
            chain: inputs.stack.is_some(),
            force_go,
        }
    }

    fn enabled(&self, surface: Surface) -> bool {
        !self.force_go.contains(&surface)
    }

    /// Whether this request goes to the native handler. A native path takes its trailing-slash spelling
    /// and every method the table does not list there, because the router's own 404 and 405 answers for
    /// them are ported too. A method the table lists as Go's goes to Go.
    pub fn is_native(&self, head: &RequestHead) -> bool {
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
        if let Some(row) = domain_row(bare) {
            if !self.enabled(row.surface) || !no_ingress {
                return false;
            }
            if row.path == "/api/v1/health" && !self.health {
                return false;
            }
            if !is_public(row) && !self.chain {
                return false;
            }
            // A Go-owned method at this path stays on Go.
            let spelled_exactly = bare == path_text;
            if spelled_exactly
                && !is_native(row.surface, method, bare)
                && ROWS
                    .iter()
                    .any(|r| r.surface == row.surface && r.path == bare && r.method == method)
            {
                return false;
            }
            // `queryGuard` and Huma's unknown-parameter refusal are not ported.
            if row.surface == Surface::ApiV2 && !head.query().is_none_or(<[u8]>::is_empty) {
                return false;
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
