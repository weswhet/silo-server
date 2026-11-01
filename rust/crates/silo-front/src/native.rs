//! The native rows: what Rust answers itself, and which requests of those rows it can answer without
//! the domain logic it does not have yet.
//!
//! A native handler runs behind silo-http's port of Go's connection engine, so framing, header order,
//! and refusals are Go's. [`Gate`] sends anything the handler cannot answer faithfully back to Go: the
//! row then shows as not ported rather than as a guess.

use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest, Sha256};
use silo_http::chi::Mux;
use silo_http::compress::{ResponseInfo, compress_with_exclusions};
use silo_http::{BoxHandler, Header, ResponseWriter, ServeMux, handler_fn, not_found_handler};

use crate::frontend::{self, BrandingSource, WebDist};
use crate::http1::{Framing, RequestHead};
use crate::rows::{Disposition, NativeId, ROWS, Surface, native_row};

const DOCS_HTML: &[u8] = include_bytes!("../../../../internal/apiv2/docsui/index.html");
const DOCS_INIT: &[u8] = include_bytes!("../../../../internal/apiv2/docsui/init.js");
const DOCS_SCRIPT: &[u8] = include_bytes!("../../../../internal/apiv2/docsui/swagger-ui-bundle.js");
const DOCS_CSS: &[u8] = include_bytes!("../../../../internal/apiv2/docsui/swagger-ui.css");
const DOCS_SCRIPT_LICENSES: &[u8] =
    include_bytes!("../../../../internal/apiv2/docsui/swagger-ui-bundle.js.LICENSE.txt");
const DOCS_LICENSE: &[u8] = include_bytes!("../../../../internal/apiv2/docsui/LICENSE");
const DOCS_NOTICE: &[u8] = include_bytes!("../../../../internal/apiv2/docsui/NOTICE");

/// `apiv2.DocsOrigin` and the problems path under it.
const PROBLEM_TYPE_BASE: &str = "https://siloserver.org/docs/api/v2/problems/";

const DOCS_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

/// `netaccess.IngressTokenHeader` and `IngressPeerHeader`: the middleware that reads them needs the
/// network access registry.
const INGRESS_HEADERS: [&str; 2] = ["X-Silo-Ingress-Token", "X-Silo-Ingress-Peer"];
/// `rejectMalformedDeviceHeader` answers from the v2 problem writer.
const DEVICE_HEADER: &str = "X-Silo-Device-Id";

/// `handlers.healthStatus`.
#[derive(Serialize)]
struct HealthStatus<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    server_name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    server_id: &'a str,
}

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
}

/// `apimw.NewRequestID`.
fn new_request_id() -> String {
    let id: [u8; 12] = rand::random();
    let mut out = String::with_capacity(24);
    for byte in id {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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

/// `writeProblem`, with `requestID` in front of it.
async fn write_problem(
    w: &mut dyn ResponseWriter,
    slug: &str,
    title: &str,
    status: u16,
    detail: &str,
    allow: Option<String>,
) {
    let id = new_request_id();
    w.header()
        .set_raw("X-Request-ID", vec![id.clone().into_bytes()]);
    let problem = Problem {
        type_uri: format!("{PROBLEM_TYPE_BASE}{slug}"),
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

/// The methods the table declares native on a v2 path, in the order the registry lists them.
fn v2_methods(path: &str) -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = ROWS
        .iter()
        .filter(|r| {
            r.surface == Surface::ApiV2
                && r.path == path
                && matches!(r.disposition, Disposition::Native(_))
        })
        .map(|r| r.method)
        .collect();
    methods.sort_unstable();
    methods
}

/// The test half of `apiv2.IdentityEncoded`. Its header edits (`Content-Encoding: identity` and
/// `no-transform`) are on the one native row that carries an ETag, because silo-http's `SkipResponse`
/// gets the header read-only.
fn identity_encoded(info: &ResponseInfo, h: &Header) -> bool {
    info.path.starts_with(b"/api/v2/") && !h.get("ETag").is_empty()
}

fn docs_asset(mux: &Mux, path: &str, media_type: &'static str, body: Arc<Vec<u8>>) {
    let serve = handler_fn(move |w, r| {
        let body = body.clone();
        Box::pin(async move {
            w.header()
                .set_raw("X-Request-ID", vec![new_request_id().into_bytes()]);
            let h = w.header();
            h.set("Content-Type", format!("{media_type}; charset=utf-8"));
            h.set("Content-Length", body.len().to_string());
            h.set("Cache-Control", "no-cache");
            h.set("Content-Security-Policy", DOCS_CSP);
            h.set("X-Content-Type-Options", "nosniff");
            h.set("Referrer-Policy", "no-referrer");
            w.write_header(200).await;
            if r.method != "HEAD" {
                let _ = w.write(&body).await;
            }
        })
    });
    mux.get(path, serve.clone());
    mux.head(path, serve);
}

/// The handler behind the `main` listener's native rows, shaped like `newRootMux`.
pub fn main_handler(inputs: &NativeInputs) -> BoxHandler {
    let api = Mux::new();
    let skip_response: silo_http::compress::SkipResponse = Arc::new(identity_encoded);
    api.use_middleware([compress_with_exclusions(None, Some(skip_response), &[])]);

    if let Some(identity) = &inputs.identity {
        let mut body = silo_gocompat::json::marshal(&HealthStatus {
            status: "ok",
            server_name: &identity.name,
            server_id: &identity.id,
        })
        .expect("a struct of strings marshals");
        body.push(b'\n');
        let body = Arc::new(body);
        api.get(
            "/api/v1/health",
            handler_fn(move |w, _r| {
                let body = body.clone();
                Box::pin(async move {
                    w.header().set("Content-Type", "application/json");
                    w.write_header(200).await;
                    let _ = w.write(&body).await;
                })
            }),
        );
    }

    let v2 = Mux::new();
    v2.not_found(handler_fn(|w, _r| {
        Box::pin(write_problem(
            w,
            "not_found",
            "Not found",
            404,
            "No operation is registered at this path.",
            None,
        ))
    }));
    v2.method_not_allowed(handler_fn(|w, r| {
        let allow = v2_methods(&String::from_utf8_lossy(&r.url.path)).join(", ");
        Box::pin(write_problem(
            w,
            "method_not_allowed",
            "Method not allowed",
            405,
            "The method is not supported at this path.",
            (!allow.is_empty()).then_some(allow),
        ))
    }));

    let openapi = silo_contracts::embedded::openapi_v2();
    let digest = Sha256::digest(openapi);
    let mut etag = String::with_capacity(66);
    etag.push('"');
    for byte in digest {
        etag.push_str(&format!("{byte:02x}"));
    }
    etag.push('"');
    v2.get(
        "/api/v2/openapi.json",
        handler_fn(move |w, _r| {
            let etag = etag.clone();
            Box::pin(async move {
                w.header()
                    .set_raw("X-Request-ID", vec![new_request_id().into_bytes()]);
                let h = w.header();
                h.set("Cache-Control", "public, max-age=300, no-transform");
                h.set("Content-Encoding", "identity");
                h.set("Content-Type", "application/json");
                h.set("ETag", etag);
                h.set("Content-Length", openapi.len().to_string());
                w.write_header(200).await;
                let _ = w.write(openapi).await;
            })
        }),
    );

    let mut licenses = Vec::new();
    licenses.extend_from_slice(DOCS_LICENSE);
    licenses.push(b'\n');
    licenses.extend_from_slice(DOCS_NOTICE);
    licenses.push(b'\n');
    licenses.extend_from_slice(DOCS_SCRIPT_LICENSES);
    docs_asset(
        &v2,
        "/api/v2/docs",
        "text/html",
        Arc::new(DOCS_HTML.to_vec()),
    );
    docs_asset(
        &v2,
        "/api/v2/docs/init.js",
        "text/javascript",
        Arc::new(DOCS_INIT.to_vec()),
    );
    docs_asset(
        &v2,
        "/api/v2/docs/swagger-ui-bundle.js",
        "text/javascript",
        Arc::new(DOCS_SCRIPT.to_vec()),
    );
    docs_asset(
        &v2,
        "/api/v2/docs/swagger-ui.css",
        "text/css",
        Arc::new(DOCS_CSS.to_vec()),
    );
    docs_asset(
        &v2,
        "/api/v2/docs/swagger-ui-bundle.js.LICENSE.txt",
        "text/plain",
        Arc::new(licenses),
    );

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
    /// Surfaces sent back to Go, the rollback switch and proxy-all mode.
    force_go: Vec<Surface>,
}

/// `Accept` values `acceptsRepresentation` allows for JSON, conservatively: anything else goes to Go,
/// which owns the 406 problem body.
fn accept_is_json(head: &RequestHead) -> bool {
    let mut values = head.values("Accept");
    let Some(first) = values.next() else {
        return true;
    };
    values.next().is_none()
        && matches!(first, b"" | b"*/*" | b"application/*" | b"application/json")
}

/// `identityForbidden` is the v2 problem writer's business. Without `identity` or `*` in the field,
/// identity stays acceptable and the guard passes.
fn accept_encoding_allows_identity(head: &RequestHead) -> bool {
    head.values("Accept-Encoding").all(|v| {
        !v.split(|&b| b == b',').any(|part| {
            let coding = part.split(|&b| b == b';').next().unwrap_or_default();
            let coding = silo_http::header::trim_string(coding);
            coding == b"*" || coding.eq_ignore_ascii_case(b"identity")
        })
    })
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
            force_go,
        }
    }

    fn enabled(&self, surface: Surface) -> bool {
        !self.force_go.contains(&surface)
    }

    /// Whether this request goes to the native handler. A native path takes every method and its
    /// trailing-slash spelling, because the router's own 404 and 405 answers for them are ported too.
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
            return native_row(Surface::Root, method, "/metrics").is_some();
        }
        let no_ingress = !INGRESS_HEADERS.iter().any(|h| head.has(h));
        let bare = path_text.strip_suffix('/').unwrap_or(path_text);
        if self.enabled(Surface::ApiV1) && bare == "/api/v1/health" {
            return self.health && no_ingress && head.framing == Framing::None;
        }
        if bare.starts_with("/api/v2/") {
            let served = self.enabled(Surface::ApiV2) && !v2_methods(bare).is_empty();
            let chain = no_ingress && !head.has(DEVICE_HEADER) && head.framing == Framing::None;
            let operation = native_row(Surface::ApiV2, method, path_text);
            if operation == Some(NativeId::OpenApi) {
                // The guards in front of the operation answer these with problems that are Go's.
                return served
                    && chain
                    && head.query().is_none_or(<[u8]>::is_empty)
                    && accept_is_json(head)
                    && accept_encoding_allows_identity(head);
            }
            return served && chain;
        }
        self.spa
            && self.enabled(Surface::Root)
            && spa_path(path)
            && native_row(Surface::Root, method, "/") == Some(NativeId::Spa)
    }
}
