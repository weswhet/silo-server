//! The rows that need no credential: health, the contract document, its viewer, the SPA.

use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest, Sha256};
use silo_http::chi::Mux;
use silo_http::handler_fn;

use super::NativeInputs;
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2, Root};
use silo_gate::mw::new_request_id;

const DOCS_HTML: &[u8] = include_bytes!("../../../../../internal/apiv2/docsui/index.html");
const DOCS_INIT: &[u8] = include_bytes!("../../../../../internal/apiv2/docsui/init.js");
const DOCS_SCRIPT: &[u8] =
    include_bytes!("../../../../../internal/apiv2/docsui/swagger-ui-bundle.js");
const DOCS_CSS: &[u8] = include_bytes!("../../../../../internal/apiv2/docsui/swagger-ui.css");
const DOCS_SCRIPT_LICENSES: &[u8] =
    include_bytes!("../../../../../internal/apiv2/docsui/swagger-ui-bundle.js.LICENSE.txt");
const DOCS_LICENSE: &[u8] = include_bytes!("../../../../../internal/apiv2/docsui/LICENSE");
const DOCS_NOTICE: &[u8] = include_bytes!("../../../../../internal/apiv2/docsui/NOTICE");

const DOCS_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/health"),
    NativeRow::new(ApiV2, "GET", "/api/v2/openapi.json"),
    NativeRow::new(ApiV2, "GET", "/api/v2/docs"),
    NativeRow::new(ApiV2, "GET", "/api/v2/docs/init.js"),
    NativeRow::new(ApiV2, "GET", "/api/v2/docs/swagger-ui-bundle.js"),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/docs/swagger-ui-bundle.js.LICENSE.txt",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/docs/swagger-ui.css"),
    NativeRow::new(ApiV2, "HEAD", "/api/v2/docs"),
    NativeRow::new(ApiV2, "HEAD", "/api/v2/docs/init.js"),
    NativeRow::new(ApiV2, "HEAD", "/api/v2/docs/swagger-ui-bundle.js"),
    NativeRow::new(
        ApiV2,
        "HEAD",
        "/api/v2/docs/swagger-ui-bundle.js.LICENSE.txt",
    ),
    NativeRow::new(ApiV2, "HEAD", "/api/v2/docs/swagger-ui.css"),
    NativeRow::new(Root, "DELETE", "/"),
    NativeRow::new(Root, "DELETE", "/metrics"),
    NativeRow::new(Root, "GET", "/"),
    NativeRow::new(Root, "GET", "/metrics"),
    NativeRow::new(Root, "HEAD", "/"),
    NativeRow::new(Root, "HEAD", "/metrics"),
    NativeRow::new(Root, "OPTIONS", "/"),
    NativeRow::new(Root, "OPTIONS", "/metrics"),
    NativeRow::new(Root, "PATCH", "/"),
    NativeRow::new(Root, "PATCH", "/metrics"),
    NativeRow::new(Root, "POST", "/"),
    NativeRow::new(Root, "POST", "/metrics"),
    NativeRow::new(Root, "PUT", "/"),
    NativeRow::new(Root, "PUT", "/metrics"),
    NativeRow::new(Root, "QUERY", "/"),
    NativeRow::new(Root, "QUERY", "/metrics"),
    NativeRow::new(Root, "TRACE", "/"),
    NativeRow::new(Root, "TRACE", "/metrics"),
];

/// `handlers.healthStatus`.
#[derive(Serialize)]
struct HealthStatus<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    server_name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    server_id: &'a str,
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

/// Registers health, the contract document and its viewer.
pub fn mount(api: &Mux, v2: &Mux, inputs: &NativeInputs) {
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
        v2,
        "/api/v2/docs",
        "text/html",
        Arc::new(DOCS_HTML.to_vec()),
    );
    docs_asset(
        v2,
        "/api/v2/docs/init.js",
        "text/javascript",
        Arc::new(DOCS_INIT.to_vec()),
    );
    docs_asset(
        v2,
        "/api/v2/docs/swagger-ui-bundle.js",
        "text/javascript",
        Arc::new(DOCS_SCRIPT.to_vec()),
    );
    docs_asset(
        v2,
        "/api/v2/docs/swagger-ui.css",
        "text/css",
        Arc::new(DOCS_CSS.to_vec()),
    );
    docs_asset(
        v2,
        "/api/v2/docs/swagger-ui-bundle.js.LICENSE.txt",
        "text/plain",
        Arc::new(licenses),
    );
}
