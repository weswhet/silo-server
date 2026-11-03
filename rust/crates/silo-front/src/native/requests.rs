//! Media requests: reading and listing them, cancelling them, the queue counts and history, route
//! administration, and reading and deleting servers. `handlers/requests.go` and the `apiv2` request files.
//! The SQL is Go's (`silo_store::requests`).
//!
//! Rows that stay on Go: search, discovery, title detail, and following need TMDB; creating, approving, and
//! retrying submit through the router plugin; decline dispatches through the notification system; saving a server
//! and loading its options call the plugin. `/requests/status` goes to Go while a server is enabled, because
//! `missing_seasons_requestable` then asks its plugin.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::precondition::evaluate_guarded_preconditions;
use silo_api_v2::problem::{Problem, ProblemError};
use silo_api_v2::wire::{Instant, paginated};
use silo_core::apiv2::{EntityTag, render_etag};
use silo_gate::mw::auth::get_profile_id;
use silo_gocompat::json::{Decoder, unmarshal};
use silo_gocompat::strings::trim_space;
use silo_gocompat::time::{GoTime, RFC3339_NANO};
use silo_http::chi::Mux;
use silo_http::{Request, ResponseWriter, handler_fn};
use silo_store::requests::{self as store, Config, Error, ListFilter, MediaRequest, Viewer};
use silo_store::userstore::pgstore::PostgresUserStore;

use super::auth::write_v1_error;
use super::chain::{
    Stack, Step, V2Class, capability_json, client_ip_of, problem_type, write_capability,
    write_problem, write_v1_json, write_v2_json, write_v2_json_status,
};
use super::huma::RawBody;
use super::personal::user_of;
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/requests/mine"),
    NativeRow::new(ApiV1, "GET", "/api/v1/requests/status"),
    NativeRow::new(ApiV1, "GET", "/api/v1/requests/{id}"),
    NativeRow::new(ApiV1, "POST", "/api/v1/requests/{id}/cancel"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/requests"),
    NativeRow::new(ApiV1, "POST", "/api/v1/admin/requests/{id}/cancel"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/request-integrations"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/admin/request-integrations/{id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/requests/mine"),
    NativeRow::new(ApiV2, "GET", "/api/v2/requests/status"),
    NativeRow::new(ApiV2, "GET", "/api/v2/requests/{id}"),
    NativeRow::new(ApiV2, "POST", "/api/v2/requests/{id}/cancel"),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/requests/follows/{media_type}/{tmdb_id}",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/requests"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/requests/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/requests/counts"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/requests/{id}/events"),
    NativeRow::new(ApiV2, "POST", "/api/v2/admin/requests/{id}/cancel"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/request-routes"),
    NativeRow::new(ApiV2, "POST", "/api/v2/admin/request-routes"),
    NativeRow::new(ApiV2, "POST", "/api/v2/admin/request-routes/order"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/request-routes/{id}"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/admin/request-routes/{id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/admin/request-routes/{id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/request-integrations"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/request-integrations/{id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/admin/request-integrations/{id}"),
];

/// `/requests/status`, which goes to Go while a server is enabled.
pub const STATUS_PATHS: [&str; 2] = ["/api/v1/requests/status", "/api/v2/requests/status"];

/// Literal paths on Go that a native `{id}` row would otherwise take.
pub fn is_go_literal(bare: &str) -> bool {
    matches!(
        bare,
        "/api/v1/requests/search"
            | "/api/v1/requests/discover"
            | "/api/v2/requests/search"
            | "/api/v2/requests/discover"
            | "/api/v2/admin/request-routes/titles"
            | "/api/v2/admin/request-routes/preview"
    )
}

const V1_PROFILE: &[Step] = &[
    Step::Auth,
    Step::Demo,
    Step::RateLimit,
    Step::Viewer,
    Step::Profile,
];
const V1_ACTING_ADMIN: &[Step] = &[Step::ActingAdmin];
const V2_PROFILE_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::Profile,
];
const V2_ADMIN_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
];

macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

fn go_time(t: SystemTime) -> String {
    GoTime::from_system_time(t).format(RFC3339_NANO)
}

fn instant(t: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(t))
}

fn raw_body(r: &Request) -> Vec<u8> {
    r.extensions
        .get::<RawBody>()
        .map_or(Vec::new(), |b| b.0.clone())
}

fn query_of(r: &Request) -> std::collections::HashMap<String, Vec<String>> {
    silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query))
        .0
        .into_iter()
        .collect()
}

fn q1(query: &std::collections::HashMap<String, Vec<String>>, name: &str) -> String {
    query
        .get(name)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
}

/// `strconv.Atoi` with its error ignored: out of range saturates, anything else is 0.
fn atoi_lossy(raw: &str) -> i64 {
    match raw.parse::<i128>() {
        Ok(v) => i64::try_from(v).unwrap_or(if v < 0 { i64::MIN } else { i64::MAX }),
        Err(_) => 0,
    }
}

/// The acting viewer. `ActingAdmin` needs a policy decision, so it fails like Go's check does.
async fn viewer(s: &Stack, r: &Request) -> Result<Viewer, String> {
    Ok(Viewer {
        user_id: user_of(r),
        profile_id: trim_space(&get_profile_id(r)).to_owned(),
        is_admin: s.gates.acting_admin(r, &client_ip_of(r)).await?,
    })
}

/// `adminRequestViewer`: the operation's class has already required an acting administrator.
fn admin_viewer(r: &Request) -> Viewer {
    Viewer {
        user_id: user_of(r),
        profile_id: get_profile_id(r).to_owned(),
        is_admin: true,
    }
}

fn problem(id: &str, detail: &str) -> Problem {
    Problem::new(problem_type(id), detail)
}

/// `requestProblem`.
fn request_problem(e: Error) -> Problem {
    match e {
        Error::Validation { fields, form } => {
            let mut p = problem(
                "validation_failed",
                "The request did not pass validation; see errors.",
            );
            if !form.is_empty() {
                p.detail = form;
            }
            p.with_errors(fields.into_iter().map(|(field, detail)| ProblemError {
                location: format!("body.{field}"),
                code: "invalid".to_owned(),
                detail,
            }))
        }
        Error::InvalidMediaType => problem(
            "validation_failed",
            "The request did not pass validation; see errors.",
        )
        .with_errors([ProblemError {
            location: "query.media_type".to_owned(),
            code: "invalid".to_owned(),
            detail: "expected movie or series".to_owned(),
        }]),
        Error::InvalidInput(_) => {
            problem("validation_failed", "The request did not pass validation.")
        }
        Error::RequestsDisabled => problem(
            "capability_disabled",
            "The requests capability is disabled by an administrator.",
        ),
        Error::Forbidden => problem("permission_denied", "Request access denied."),
        Error::NotFound => problem("not_found", "The request was not found."),
        Error::InvalidState => problem(
            "conflict",
            "The request is not in a state that allows this action.",
        ),
        Error::StaleRevision | Error::Internal(_) => {
            if let Error::Internal(message) = &e {
                tracing::error!(component = "requests", error = %message, "request operation failed");
            }
            problem("internal_error", "An unexpected error occurred.")
        }
    }
}

/// `writeRequestServiceError`.
async fn write_v1_service_error(w: &mut dyn ResponseWriter, e: Error) {
    match e {
        Error::Validation { fields, form } => {
            #[derive(Serialize)]
            struct Body {
                error: &'static str,
                field_errors: Option<BTreeMap<String, String>>,
                form_error: String,
            }
            write_v1_json(
                w,
                400,
                &Body {
                    error: "validation_failed",
                    field_errors: (!fields.is_empty()).then_some(fields),
                    form_error: form,
                },
            )
            .await;
        }
        Error::InvalidInput(message) => {
            write_v1_error(
                w,
                400,
                "bad_request",
                &format!("invalid request input: {message}"),
            )
            .await;
        }
        Error::InvalidMediaType => {
            write_v1_error(w, 400, "bad_request", "invalid media type").await
        }
        Error::RequestsDisabled => {
            write_v1_error(w, 403, "requests_disabled", "Requests are disabled").await
        }
        Error::Forbidden => write_v1_error(w, 403, "forbidden", "Request access denied").await,
        Error::NotFound => write_v1_error(w, 404, "not_found", "Request not found").await,
        Error::InvalidState => {
            write_v1_error(
                w,
                409,
                "invalid_state",
                "Request is not in a valid state for this action",
            )
            .await;
        }
        Error::StaleRevision | Error::Internal(_) => {
            if let Error::Internal(message) = &e {
                tracing::error!(component = "requests", error = %message, "request operation failed");
            }
            write_v1_error(w, 500, "internal_error", "Request operation failed").await;
        }
    }
}

fn v1_opt(t: Option<SystemTime>) -> Option<String> {
    t.map(go_time)
}

/// `requests.Target`, as v1 serializes it.
#[derive(Serialize)]
struct V1Target {
    id: i64,
    request_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    integration_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    integration_kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    instance_name: String,
    quality: String,
    is_anime: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    external_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    external_status: String,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    created_at: String,
    updated_at: String,
}

/// `requests.Request`, as v1 serializes it.
#[derive(Serialize)]
struct V1Request {
    id: String,
    provider: String,
    media_type: String,
    tmdb_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tvdb_id: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    imdb_id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    year: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    overview: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    backdrop_path: String,
    status: String,
    outcome: String,
    #[serde(skip_serializing_if = "is_zero_i32")]
    requested_by_user_id: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    requested_by_profile_id: String,
    is_anime: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    targets: Vec<V1Target>,
    #[serde(skip_serializing_if = "String::is_empty")]
    library_content_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn v1_request(r: MediaRequest) -> V1Request {
    V1Request {
        id: r.id,
        provider: r.provider,
        media_type: r.media_type,
        tmdb_id: r.tmdb_id,
        tvdb_id: r.tvdb_id,
        imdb_id: r.imdb_id,
        title: r.title,
        year: r.year,
        overview: r.overview,
        poster_path: r.poster_path,
        backdrop_path: r.backdrop_path,
        status: r.status,
        outcome: r.outcome,
        requested_by_user_id: r.requested_by_user_id,
        requested_by_profile_id: r.requested_by_profile_id,
        is_anime: r.is_anime,
        targets: r
            .targets
            .into_iter()
            .map(|t| V1Target {
                id: t.id,
                request_id: t.request_id,
                integration_id: t.integration_id,
                integration_kind: t.integration_kind,
                instance_name: t.instance_name,
                quality: t.quality,
                is_anime: t.is_anime,
                external_id: t.external_id,
                external_status: t.external_status,
                status: t.status,
                last_error: t.last_error,
                created_at: go_time(t.created_at),
                updated_at: go_time(t.updated_at),
            })
            .collect(),
        library_content_id: r.library_content_id,
        last_error: r.last_error,
        created_at: go_time(r.created_at),
        updated_at: go_time(r.updated_at),
        approved_at: v1_opt(r.approved_at),
        completed_at: v1_opt(r.completed_at),
    }
}

/// `parseRequestListFilter`.
fn v1_filter(r: &Request) -> ListFilter {
    let q = query_of(r);
    ListFilter {
        status: trim_space(&q1(&q, "status")).to_owned(),
        outcome: trim_space(&q1(&q, "outcome")).to_owned(),
        limit: atoi_lossy(&q1(&q, "limit")),
        offset: atoi_lossy(&q1(&q, "offset")),
        ..ListFilter::default()
    }
}

#[derive(Serialize)]
struct V1List {
    requests: Option<Vec<V1Request>>,
}

fn v1_list(rows: Vec<MediaRequest>) -> V1List {
    V1List {
        requests: (!rows.is_empty()).then(|| rows.into_iter().map(v1_request).collect()),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ReasonBody {
    reason: String,
}

async fn v1_cancel(s: &Stack, w: &mut dyn ResponseWriter, r: &mut Request) {
    let viewer = match viewer(s, r).await {
        Ok(v) => v,
        Err(_) => {
            return write_v1_error(w, 500, "internal_error", "Failed to verify active profile")
                .await;
        }
    };
    let (bytes, _) = r.read_all().await;
    let mut body = ReasonBody::default();
    if trim_ws_nonempty(&bytes) {
        let mut stream = Decoder::new().stream(&bytes[..]);
        match stream.decode::<ReasonBody>() {
            Ok(b) => body = b,
            Err(_) => return write_v1_error(w, 400, "bad_request", "Invalid request body").await,
        }
    }
    let id = r.url_param("id").to_owned();
    match store::cancel(&s.pool, &viewer, &id, &body.reason, false).await {
        Ok(req) => write_v1_json(w, 200, &v1_request(req)).await,
        Err(e) => write_v1_service_error(w, e).await,
    }
}

/// A body `Decode` would not answer `io.EOF` for.
fn trim_ws_nonempty(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
}

/// `requests.Integration`, as v1 serializes it.
#[derive(Serialize)]
struct V1Integration {
    id: String,
    name: String,
    capability_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    installation_id: Option<i32>,
    supported_media_types: Vec<String>,
    plugin_config: Config,
    enabled: bool,
    base_url: String,
    has_api_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_check_at: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_check_status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_check_error: String,
    updated_at: String,
}

fn mount_v1(stack: &Arc<Stack>, api: &Mux) {
    let mux = Mux::new();
    mux.use_middleware([stack.v1_group(V1_PROFILE)]);
    mux.get(
        "/status",
        stack.v1(
            "/api/v1/requests/status",
            &[],
            route!(stack, |s, w, _r| {
                let (enabled, _) = match store::settings_flags(&s.pool).await {
                    Ok(v) => v,
                    Err(e) => return write_v1_service_error(w, e).await,
                };
                #[derive(Serialize)]
                struct Status {
                    requests_enabled: bool,
                    rating_restrictions_enforced: bool,
                }
                write_v1_json(
                    w,
                    200,
                    &Status {
                        requests_enabled: enabled,
                        rating_restrictions_enforced: true,
                    },
                )
                .await;
            }),
        ),
    );
    mux.get(
        "/mine",
        stack.v1(
            "/api/v1/requests/mine",
            &[],
            route!(stack, |s, w, r| {
                let viewer = match viewer(&s, r).await {
                    Ok(v) => v,
                    Err(_) => {
                        return write_v1_error(
                            w,
                            500,
                            "internal_error",
                            "Failed to verify active profile",
                        )
                        .await;
                    }
                };
                match store::list_mine(&s.pool, &viewer, v1_filter(r)).await {
                    Ok(rows) => write_v1_json(w, 200, &v1_list(rows)).await,
                    Err(e) => write_v1_service_error(w, e).await,
                }
            }),
        ),
    );
    mux.get(
        "/{id}",
        stack.v1(
            "/api/v1/requests/{id}",
            &[],
            route!(stack, |s, w, r| {
                let viewer = match viewer(&s, r).await {
                    Ok(v) => v,
                    Err(_) => {
                        return write_v1_error(
                            w,
                            500,
                            "internal_error",
                            "Failed to verify active profile",
                        )
                        .await;
                    }
                };
                match store::get(&s.pool, &viewer, r.url_param("id")).await {
                    Ok(req) => write_v1_json(w, 200, &v1_request(req)).await,
                    Err(e) => write_v1_service_error(w, e).await,
                }
            }),
        ),
    );
    mux.post(
        "/{id}/cancel",
        stack.v1(
            "/api/v1/requests/{id}/cancel",
            &[],
            route!(stack, |s, w, r| { v1_cancel(&s, w, r).await }),
        ),
    );
    api.mount("/api/v1/requests", mux);
}

/// The `/api/v1/admin` rows; the caller holds the mux.
pub fn mount_v1_admin(stack: &Arc<Stack>, admin: &Mux) {
    admin.get(
        "/requests",
        stack.v1(
            "/api/v1/admin/requests",
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                match store::list_admin(&s.pool, &admin_viewer(r), v1_filter(r)).await {
                    Ok(rows) => write_v1_json(w, 200, &v1_list(rows)).await,
                    Err(e) => write_v1_service_error(w, e).await,
                }
            }),
        ),
    );
    admin.post(
        "/requests/{id}/cancel",
        stack.v1(
            "/api/v1/admin/requests/{id}/cancel",
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| { v1_cancel(&s, w, r).await }),
        ),
    );
    admin.get(
        "/request-integrations",
        stack.v1(
            "/api/v1/admin/request-integrations",
            V1_ACTING_ADMIN,
            route!(stack, |s, w, _r| {
                let rows = match store::list_integrations(&s.pool, &s.cipher).await {
                    Ok(rows) => rows,
                    Err(e) => return write_v1_service_error(w, e).await,
                };
                #[derive(Serialize)]
                struct Out {
                    integrations: Vec<V1Integration>,
                }
                let integrations = rows
                    .into_iter()
                    .map(|i| V1Integration {
                        id: i.id,
                        name: i.name,
                        capability_id: i.capability_id,
                        installation_id: i.installation_id,
                        supported_media_types: i.supported_media_types,
                        plugin_config: i.plugin_config,
                        enabled: i.enabled,
                        base_url: i.base_url,
                        has_api_key: i.has_api_key,
                        last_check_at: v1_opt(i.last_check_at),
                        last_check_status: i.last_check_status,
                        last_check_error: i.last_check_error,
                        updated_at: go_time(i.updated_at),
                    })
                    .collect();
                write_v1_json(w, 200, &Out { integrations }).await;
            }),
        ),
    );
    admin.delete(
        "/request-integrations/{id}",
        stack.v1(
            "/api/v1/admin/request-integrations/{id}",
            V1_ACTING_ADMIN,
            route!(stack, |s, w, r| {
                match store::delete_integration(&s.pool, r.url_param("id"), None).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_v1_service_error(w, e).await,
                }
            }),
        ),
    );
}

#[derive(Serialize)]
struct V2Download {
    phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_total: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_left: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    percent: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    estimated_completion_at: Option<Instant>,
    downloads: i32,
    updated_at: Instant,
}

/// `requestDownloadOf`.
fn v2_download(d: Option<store::Download>) -> Option<V2Download> {
    let d = d?;
    let (mut total, mut left, mut percent) = (None, None, None);
    if d.bytes_total > 0 {
        let l = d.bytes_left.max(0).min(d.bytes_total);
        let p = i128::from(d.bytes_total - l) * 100 / i128::from(d.bytes_total);
        total = Some(d.bytes_total);
        left = Some(l);
        percent = Some(p as i64);
    }
    Some(V2Download {
        phase: d.phase,
        bytes_total: total,
        bytes_left: left,
        percent,
        estimated_completion_at: d.estimated.map(instant),
        downloads: d.downloads.max(0),
        updated_at: instant(d.updated_at),
    })
}

#[derive(Serialize)]
struct V2Target {
    id: String,
    request_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    integration_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    integration_kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    instance_name: String,
    quality: String,
    is_anime: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    external_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    external_status: String,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    route_name: String,
    created_at: Instant,
    updated_at: Instant,
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<V2Download>,
}

#[derive(Serialize)]
struct V2SeasonProgress {
    season_number: i32,
    episodes_aired: i64,
    episodes_available: i64,
}

#[derive(Serialize)]
struct V2Request {
    id: String,
    provider: String,
    media_type: String,
    tmdb_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tvdb_id: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    imdb_id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    year: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    overview: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    backdrop_path: String,
    status: String,
    outcome: String,
    state: String,
    seasons: Vec<i32>,
    season_progress: Vec<V2SeasonProgress>,
    #[serde(skip_serializing_if = "String::is_empty")]
    outcome_reason: String,
    source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    requested_by_user_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    requested_by_profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    integration_kind: String,
    is_anime: bool,
    targets: Vec<V2Target>,
    #[serde(skip_serializing_if = "String::is_empty")]
    external_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    external_status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    library_content_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    created_at: Instant,
    updated_at: Instant,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<V2Download>,
}

/// `mediaRequestOf`: the download server details go to an administrator only.
fn v2_request(r: MediaRequest, viewer: &Viewer) -> V2Request {
    let state = r.state().to_owned();
    let download = v2_download(r.download());
    let admin = viewer.is_admin;
    V2Request {
        state,
        download,
        id: r.id,
        provider: r.provider,
        media_type: r.media_type,
        tmdb_id: r.tmdb_id,
        tvdb_id: r.tvdb_id,
        imdb_id: r.imdb_id,
        title: r.title,
        year: r.year,
        overview: r.overview,
        poster_path: r.poster_path,
        backdrop_path: r.backdrop_path,
        status: r.status,
        outcome: r.outcome,
        seasons: r.seasons,
        season_progress: r
            .season_progress
            .iter()
            .map(|p| V2SeasonProgress {
                season_number: p.season,
                episodes_aired: p.aired,
                episodes_available: p.have,
            })
            .collect(),
        outcome_reason: r.outcome_reason,
        source: if r.source.is_empty() {
            "direct".to_owned()
        } else {
            r.source
        },
        requested_by_user_id: if r.requested_by_user_id != 0 {
            r.requested_by_user_id.to_string()
        } else {
            String::new()
        },
        requested_by_profile_id: r.requested_by_profile_id,
        integration_kind: String::new(),
        is_anime: r.is_anime,
        external_id: String::new(),
        external_status: String::new(),
        library_content_id: r.library_content_id,
        last_error: if admin { r.last_error } else { String::new() },
        created_at: instant(r.created_at),
        updated_at: instant(r.updated_at),
        approved_at: r.approved_at.map(instant),
        completed_at: r.completed_at.map(instant),
        targets: r
            .targets
            .into_iter()
            .map(|t| {
                let hide = |v: String| if admin { v } else { String::new() };
                V2Target {
                    id: t.id.to_string(),
                    request_id: t.request_id,
                    integration_id: hide(t.integration_id),
                    integration_kind: hide(t.integration_kind),
                    instance_name: hide(t.instance_name),
                    quality: t.quality,
                    is_anime: t.is_anime,
                    external_id: hide(t.external_id),
                    external_status: hide(t.external_status),
                    status: t.status,
                    last_error: hide(t.last_error),
                    route_name: hide(t.route_name),
                    created_at: instant(t.created_at),
                    updated_at: instant(t.updated_at),
                    download: v2_download(t.download),
                }
            })
            .collect(),
    }
}

/// `requests.RequestPageKey`.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct PageKey {
    created_at: String,
    id: String,
}

fn page_time(raw: &str) -> Option<SystemTime> {
    let t =
        time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339).ok()?;
    (t.year() > 1).then(|| t.into())
}

/// The shared half of `listMyRequests` and `listAdminRequests`: `limit` is the page, one more is read.
async fn write_request_page(
    s: &Stack,
    w: &mut dyn ResponseWriter,
    r: &Request,
    scope: CursorScope,
    viewer: &Viewer,
    mut filter: ListFilter,
    admin: bool,
) {
    let q = query_of(r);
    let limit = q1(&q, "limit").parse::<i64>().unwrap_or(50);
    let cursor = q1(&q, "cursor");
    if !cursor.is_empty() {
        let key: PageKey = match s.cursors.decode(&scope, &cursor) {
            Ok(key) => key,
            Err(p) => return write_problem(w, r, p).await,
        };
        match page_time(&key.created_at) {
            Some(at) if !key.id.is_empty() => filter.before = Some((at, key.id)),
            _ => {
                return write_problem(
                    w,
                    r,
                    problem("invalid_cursor", "The cursor position is invalid."),
                )
                .await;
            }
        }
    }
    filter.limit = limit + 1;
    let rows = if admin {
        store::list_admin(&s.pool, viewer, filter).await
    } else {
        store::list_mine(&s.pool, viewer, filter).await
    };
    let mut rows = match rows {
        Ok(rows) => rows,
        Err(e) => return write_problem(w, r, request_problem(e)).await,
    };
    let mut next = String::new();
    if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        let last = &rows[rows.len() - 1];
        let key = PageKey {
            created_at: go_time(last.created_at),
            id: last.id.clone(),
        };
        next = match s.cursors.encode(&scope, &key) {
            Ok(next) => next,
            Err(_) => {
                let detail = if admin {
                    "Unable to encode cursor."
                } else {
                    "Unable to encode request cursor."
                };
                return write_problem(w, r, problem("internal_error", detail)).await;
            }
        };
    }
    let items: Vec<V2Request> = rows
        .into_iter()
        .map(|row| v2_request(row, viewer))
        .collect();
    write_v2_json(w, &paginated(items, next)).await;
}

/// `Service.RequestCapabilityAllowed`, `Service.GetFeatureStatus`, and `WatchlistAutoRequest`.
#[derive(Serialize)]
struct FeatureStatus<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    requests_enabled: bool,
    rating_restrictions_enforced: bool,
    follow_supported: bool,
    season_requests_supported: bool,
    missing_seasons_requestable: bool,
    download_progress_supported: bool,
    watchlist_titles_supported: bool,
    watchlist_requests: bool,
    discover_rows_supported: bool,
}

/// `StoreWatchlistPreference.WatchlistAutoRequest`.
async fn watchlist_auto_request(s: &Stack, user: i64, profile: &str) -> bool {
    if profile.is_empty() {
        return false;
    }
    let store = PostgresUserStore::new(s.pool.clone(), user);
    let context = silo_config::resolve::Context {
        profile_id: profile.to_owned(),
        ..Default::default()
    };
    let keys = ["requests.watchlist_auto_request".to_owned()];
    match super::settings::resolver_for(s)
        .resolve(&store, &context, &keys, &Default::default())
        .await
    {
        Ok(resolved) if resolved.len() == 1 => {
            unmarshal::<bool>(resolved[0].value.as_bytes().unwrap_or_default()).unwrap_or(false)
        }
        Ok(_) => false,
        Err(error) => {
            tracing::warn!(component = "requests", step = "reading setting values failed", profile_id = %profile, %error, "watchlist request preference unavailable");
            false
        }
    }
}

/// `ensureViewerRequestsAllowed` and `userLimitBlocked`.
async fn capability_allowed(s: &Stack, user: i64) -> Result<bool, Error> {
    Ok(store::requests_allowed(&s.pool, user).await?
        && !store::user_limit_blocked(&s.pool, user).await?)
}

// A reference to each `V2Class` keeps the classes readable where the operations register.
fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let p = "/api/v2/requests/mine";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let q = query_of(r);
                let v = match viewer(&s, r).await {
                    Ok(v) => v,
                    Err(_) => {
                        return write_problem(
                            w,
                            r,
                            problem("internal_error", "An unexpected error occurred."),
                        )
                        .await;
                    }
                };
                let (status, outcome) = (q1(&q, "status"), q1(&q, "outcome"));
                let scope = CursorScope {
                    operation_id: "listMyRequests".to_owned(),
                    security: format!("{}/{}", v.user_id, v.profile_id),
                    filter: format!("{status}|{outcome}"),
                    sort: "-created_at".to_owned(),
                    tiebreaker: "id".to_owned(),
                };
                let filter = ListFilter {
                    status,
                    outcome,
                    ..ListFilter::default()
                };
                write_request_page(&s, w, r, scope, &v, filter, false).await;
            }),
        ),
    );
    let p = "/api/v2/requests/status";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let user = user_of(r);
                let profile = get_profile_id(r).to_owned();
                let (enabled, watchlist) = match store::settings_flags(&s.pool).await {
                    Ok(v) => v,
                    Err(e) => return write_problem(w, r, request_problem(e)).await,
                };
                let mut allowed = false;
                let mut watchlist_on = false;
                if enabled {
                    watchlist_on =
                        watchlist && user != 0 && watchlist_auto_request(&s, user, &profile).await;
                    allowed = match capability_allowed(&s, user).await {
                        Ok(v) => v,
                        Err(e) => return write_problem(w, r, request_problem(e)).await,
                    };
                }
                write_capability(w, r, "getRequestStatus", |revision| {
                    capability_json(&FeatureStatus {
                        revision,
                        state: if enabled { "available" } else { "disabled" },
                        allowed,
                        requests_enabled: enabled,
                        rating_restrictions_enforced: true,
                        follow_supported: true,
                        season_requests_supported: true,
                        missing_seasons_requestable: enabled,
                        download_progress_supported: true,
                        watchlist_titles_supported: enabled,
                        watchlist_requests: watchlist_on && allowed,
                        discover_rows_supported: true,
                    })
                })
                .await;
            }),
        ),
    );
    let p = "/api/v2/requests/{id}";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let v = match viewer(&s, r).await {
                    Ok(v) => v,
                    Err(_) => {
                        return write_problem(
                            w,
                            r,
                            problem("internal_error", "An unexpected error occurred."),
                        )
                        .await;
                    }
                };
                match store::get(&s.pool, &v, r.url_param("id")).await {
                    Ok(req) => write_v2_json(w, &v2_request(req, &v)).await,
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    let p = "/api/v2/requests/{id}/cancel";
    v2.post(
        p,
        stack.v2_steps(
            p,
            V2_PROFILE_WRITE,
            route!(stack, |s, w, r| {
                let v = match viewer(&s, r).await {
                    Ok(v) => v,
                    Err(_) => {
                        return write_problem(
                            w,
                            r,
                            problem("internal_error", "An unexpected error occurred."),
                        )
                        .await;
                    }
                };
                let body: ReasonBody = unmarshal(&raw_body(r)).unwrap_or_default();
                match store::cancel(&s.pool, &v, r.url_param("id"), &body.reason, false).await {
                    Ok(req) => write_v2_json(w, &v2_request(req, &v)).await,
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    let p = "/api/v2/requests/follows/{media_type}/{tmdb_id}";
    v2.delete(
        p,
        stack.v2_steps(
            p,
            V2_PROFILE_WRITE,
            route!(stack, |s, w, r| {
                let v = Viewer {
                    user_id: user_of(r),
                    profile_id: trim_space(&get_profile_id(r)).to_owned(),
                    is_admin: false,
                };
                // Huma has validated the integer against its schema; only the width can still refuse.
                let tmdb = r.url_param("tmdb_id").parse::<i64>().unwrap_or(0);
                match store::unfollow(&s.pool, &v, r.url_param("media_type"), tmdb).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    mount_v2_admin(stack, v2);
    mount_v2_routes(stack, v2);
    mount_v2_integrations(stack, v2);
}

fn mount_v2_admin(stack: &Arc<Stack>, v2: &Mux) {
    let p = "/api/v2/admin/requests/capabilities";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    #[derive(Serialize)]
                    struct Out<'a> {
                        revision: &'a str,
                        state: &'static str,
                        allowed: bool,
                        available: bool,
                        guarded_configuration: bool,
                        routing: bool,
                        routing_series_status: bool,
                        discover_layout: bool,
                        discover_list_order: bool,
                    }
                    write_capability(w, r, "getAdminRequestCapabilities", |revision| {
                        capability_json(&Out {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                            guarded_configuration: true,
                            routing: true,
                            routing_series_status: true,
                            discover_layout: true,
                            discover_list_order: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
    let p = "/api/v2/admin/requests/counts";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                #[derive(Serialize)]
                struct Out {
                    needs_approval: i64,
                    in_progress: i64,
                    failed: i64,
                    done: i64,
                }
                match store::count_views(&s.pool).await {
                    Ok([needs_approval, in_progress, failed, done]) => {
                        write_v2_json(
                            w,
                            &Out {
                                needs_approval,
                                in_progress,
                                failed,
                                done,
                            },
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    let p = "/api/v2/admin/requests";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let q = query_of(r);
                let v = admin_viewer(r);
                let (status, outcome, view, query, media_type, by) = (
                    q1(&q, "status"),
                    q1(&q, "outcome"),
                    q1(&q, "view"),
                    q1(&q, "q"),
                    q1(&q, "media_type"),
                    q1(&q, "requested_by_user_id"),
                );
                let scope = CursorScope {
                    operation_id: "listAdminRequests".to_owned(),
                    security: format!("{}/{}", v.user_id, v.profile_id),
                    filter: [&status, &outcome, &view, &query, &media_type, &by]
                        .map(String::as_str)
                        .join("|"),
                    sort: "-created_at".to_owned(),
                    tiebreaker: "id".to_owned(),
                };
                let mut filter = ListFilter {
                    status,
                    outcome,
                    view,
                    query,
                    media_type,
                    ..ListFilter::default()
                };
                if !by.is_empty() {
                    match by.parse::<i32>() {
                        Ok(id) => filter.requested_by_user_id = i64::from(id),
                        Err(_) => {
                            return write_problem(
                                w,
                                r,
                                problem("validation_failed", "Invalid account ID."),
                            )
                            .await;
                        }
                    }
                }
                write_request_page(&s, w, r, scope, &v, filter, true).await;
            }),
        ),
    );
    let p = "/api/v2/admin/requests/{id}/events";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                #[derive(Serialize)]
                struct Item {
                    id: String,
                    #[serde(rename = "type")]
                    kind: String,
                    #[serde(skip_serializing_if = "String::is_empty")]
                    actor_user_id: String,
                    #[serde(skip_serializing_if = "String::is_empty")]
                    actor_username: String,
                    #[serde(skip_serializing_if = "String::is_empty")]
                    message: String,
                    created_at: Instant,
                }
                match store::list_events(&s.pool, r.url_param("id")).await {
                    Ok(events) => {
                        let items: Vec<Item> = events
                            .into_iter()
                            .map(|e| Item {
                                id: e.id.to_string(),
                                kind: e.event_type,
                                actor_user_id: e
                                    .actor_user_id
                                    .map(|u| u.to_string())
                                    .unwrap_or_default(),
                                actor_username: e.actor_username,
                                message: e.message,
                                created_at: instant(e.created_at),
                            })
                            .collect();
                        write_v2_json(w, &paginated(items, "")).await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    let p = "/api/v2/admin/requests/{id}/cancel";
    v2.post(
        p,
        stack.v2_steps(
            p,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let v = admin_viewer(r);
                let body: ReasonBody = unmarshal(&raw_body(r)).unwrap_or_default();
                match store::cancel(&s.pool, &v, r.url_param("id"), &body.reason, true).await {
                    Ok(req) => write_v2_json(w, &v2_request(req, &v)).await,
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
}

/// `adminRequestTag`.
fn admin_tag(r: &Request, kind: &str, id: &str, revision: i64) -> EntityTag {
    let scope = format!("admin-requests/{}/{}/{kind}", user_of(r), get_profile_id(r));
    render_etag(scope.as_bytes(), id.as_bytes(), revision)
}

/// `adminRequestGuard`.
fn admin_guard(r: &Request, tag: &EntityTag, revision: i64) -> Result<i64, Problem> {
    let header = |name: &str| String::from_utf8_lossy(r.header.get(name)).into_owned();
    let if_match = header("If-Match");
    if let Some(p) = evaluate_guarded_preconditions(&if_match, &header("If-None-Match"), tag) {
        return Err(p);
    }
    Ok(if if_match == "*" { -1 } else { revision })
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct V2Destination {
    #[serde(skip_serializing_if = "String::is_empty")]
    integration_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    overrides: Option<Config>,
}

#[derive(Serialize)]
struct V2Route {
    id: String,
    media_type: String,
    position: i64,
    name: String,
    enabled: bool,
    is_fallback: bool,
    conditions: store::Conditions,
    hd: V2Destination,
    uhd: V2Destination,
    skip_uhd: bool,
}

fn v2_destination(d: store::Destination) -> V2Destination {
    V2Destination {
        integration_id: d.integration_id,
        overrides: d.overrides.filter(|o| !o.is_empty()),
    }
}

fn v2_route(r: store::Route) -> V2Route {
    V2Route {
        id: r.id,
        media_type: r.media_type,
        position: r.position,
        name: r.name,
        enabled: r.enabled,
        is_fallback: r.is_fallback,
        conditions: r.conditions,
        hd: v2_destination(r.hd),
        uhd: v2_destination(r.uhd),
        skip_uhd: r.skip_uhd,
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RouteBody {
    media_type: String,
    name: String,
    enabled: bool,
    conditions: store::Conditions,
    hd: V2Destination,
    uhd: V2Destination,
    skip_uhd: bool,
}

impl RouteBody {
    fn domain(self, id: String) -> store::Route {
        let dest = |d: V2Destination| store::Destination {
            integration_id: d.integration_id,
            overrides: d.overrides.map(store::go_any_config),
        };
        store::Route {
            id,
            media_type: self.media_type,
            name: self.name,
            enabled: self.enabled,
            conditions: self.conditions,
            skip_uhd: self.skip_uhd,
            hd: dest(self.hd),
            uhd: dest(self.uhd),
            ..store::Route::default()
        }
    }
}

fn route_tag(r: &Request, route: &store::Route) -> EntityTag {
    admin_tag(r, "route", &route.id, route.revision)
}

#[derive(Serialize)]
struct Items<T> {
    items: Vec<T>,
}

/// `idgen.NextID`, on this process's own machine lease.
async fn next_id(s: &Stack) -> Result<String, Error> {
    let lease = s
        .route_ids
        .get_or_try_init(|| {
            silo_runtime::idgen_lease::Lease::start((*s.pool).clone(), "silo-front")
        })
        .await
        .map_err(|e| Error::Internal(e.to_string()))?;
    lease
        .generator()
        .current()
        .await
        .next_id()
        .map_err(|e| Error::Internal(e.to_string()))
}

fn mount_v2_routes(stack: &Arc<Stack>, v2: &Mux) {
    let p = "/api/v2/admin/request-routes";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                match store::list_routes_admin(&s.pool).await {
                    Ok(routes) => {
                        write_v2_json(
                            w,
                            &Items {
                                items: routes.into_iter().map(v2_route).collect(),
                            },
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    v2.post(
        p,
        stack.v2_steps(
            p,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let body: RouteBody = unmarshal(&raw_body(r)).unwrap_or_default();
                let id = match next_id(&s).await {
                    Ok(id) => id,
                    Err(e) => return write_problem(w, r, request_problem(e)).await,
                };
                match store::create_route(&s.pool, &s.cipher, body.domain(String::new()), id).await
                {
                    Ok(route) => {
                        w.header().set(
                            "Location",
                            format!("/api/v2/admin/request-routes/{}", route.id),
                        );
                        w.header().set("ETag", route_tag(r, &route).to_wire());
                        write_v2_json_status(w, 201, &v2_route(route)).await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    let p = "/api/v2/admin/request-routes/order";
    v2.post(
        p,
        stack.v2_steps(
            p,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct Body {
                    media_type: String,
                    ids: Vec<String>,
                }
                let body: Body = unmarshal(&raw_body(r)).unwrap_or_default();
                match store::reorder_routes(&s.pool, &body.media_type, &body.ids).await {
                    Ok(routes) => {
                        write_v2_json(
                            w,
                            &Items {
                                items: routes.into_iter().map(v2_route).collect(),
                            },
                        )
                        .await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    let p = "/api/v2/admin/request-routes/{id}";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                match store::get_route(&s.pool, r.url_param("id")).await {
                    Ok(route) => {
                        w.header().set("ETag", route_tag(r, &route).to_wire());
                        write_v2_json(w, &v2_route(route)).await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    v2.put(
        p,
        stack.v2_steps(
            p,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let id = r.url_param("id").to_owned();
                let current = match store::get_route(&s.pool, &id).await {
                    Ok(c) => c,
                    Err(e) => return write_problem(w, r, request_problem(e)).await,
                };
                let expected = match admin_guard(r, &route_tag(r, &current), current.revision) {
                    Ok(v) => v,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let body: RouteBody = unmarshal(&raw_body(r)).unwrap_or_default();
                match store::update_route(&s.pool, &s.cipher, body.domain(id.clone()), expected)
                    .await
                {
                    Ok(route) => {
                        w.header().set("ETag", route_tag(r, &route).to_wire());
                        write_v2_json(w, &v2_route(route)).await;
                    }
                    Err(Error::StaleRevision) => {
                        let current = match store::get_route(&s.pool, &id).await {
                            Ok(c) => c,
                            Err(e) => return write_problem(w, r, request_problem(e)).await,
                        };
                        let p = problem(
                            "precondition_failed",
                            "The routing rule changed; reload before saving.",
                        )
                        .with_header("ETag", route_tag(r, &current).to_wire());
                        write_problem(w, r, p).await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    v2.delete(
        p,
        stack.v2_steps(
            p,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let id = r.url_param("id").to_owned();
                let current = match store::get_route(&s.pool, &id).await {
                    Ok(c) => c,
                    Err(e) => return write_problem(w, r, request_problem(e)).await,
                };
                let expected = match admin_guard(r, &route_tag(r, &current), current.revision) {
                    Ok(v) => v,
                    Err(p) => return write_problem(w, r, p).await,
                };
                match store::delete_route(&s.pool, &id, expected).await {
                    Ok(()) => w.write_header(204).await,
                    Err(Error::StaleRevision) => {
                        let p = problem(
                            "precondition_failed",
                            "The routing rule changed; reload before deleting.",
                        );
                        write_problem(w, r, p).await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
}

#[derive(Serialize)]
struct V2Integration {
    id: String,
    name: String,
    capability_id: String,
    installation_id: Option<String>,
    supported_media_types: Vec<String>,
    plugin_config: Config,
    enabled: bool,
    base_url: String,
    has_api_key: bool,
    last_check_at: Option<Instant>,
    last_check_status: String,
    last_check_error: String,
    updated_at: Instant,
}

fn v2_integration(i: store::Integration) -> V2Integration {
    V2Integration {
        id: i.id,
        name: i.name,
        capability_id: i.capability_id,
        installation_id: i.installation_id.map(|v| v.to_string()),
        supported_media_types: i.supported_media_types,
        plugin_config: i.plugin_config,
        enabled: i.enabled,
        base_url: i.base_url,
        has_api_key: i.has_api_key,
        last_check_at: i.last_check_at.map(instant),
        last_check_status: i.last_check_status,
        last_check_error: i.last_check_error,
        updated_at: instant(i.updated_at),
    }
}

fn mount_v2_integrations(stack: &Arc<Stack>, v2: &Mux) {
    let p = "/api/v2/admin/request-integrations";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let q = query_of(r);
                let v = admin_viewer(r);
                let scope = CursorScope {
                    operation_id: "listRequestIntegrations".to_owned(),
                    security: format!("{}/{}", v.user_id, v.profile_id),
                    filter: String::new(),
                    sort: "id".to_owned(),
                    tiebreaker: "id".to_owned(),
                };
                let limit = q1(&q, "limit").parse::<usize>().unwrap_or(50);
                let cursor = q1(&q, "cursor");
                let mut after = String::new();
                if !cursor.is_empty() {
                    after = match s.cursors.decode::<String>(&scope, &cursor) {
                        Ok(a) => a,
                        Err(p) => return write_problem(w, r, p).await,
                    };
                    if after.is_empty() {
                        return write_problem(
                            w,
                            r,
                            problem("invalid_cursor", "Invalid integration cursor."),
                        )
                        .await;
                    }
                }
                let mut rows = match store::list_integrations(&s.pool, &s.cipher).await {
                    Ok(rows) => rows,
                    Err(e) => return write_problem(w, r, request_problem(e)).await,
                };
                rows.sort_by(|a, b| a.id.cmp(&b.id));
                let mut items: Vec<V2Integration> = Vec::new();
                let mut next = String::new();
                for row in rows {
                    if row.id <= after {
                        continue;
                    }
                    if items.len() == limit {
                        next = match s.cursors.encode(&scope, &items[items.len() - 1].id) {
                            Ok(n) => n,
                            Err(_) => {
                                return write_problem(
                                    w,
                                    r,
                                    problem("internal_error", "Unable to encode cursor."),
                                )
                                .await;
                            }
                        };
                        break;
                    }
                    items.push(v2_integration(row));
                }
                write_v2_json(w, &paginated(items, next)).await;
            }),
        ),
    );
    let p = "/api/v2/admin/request-integrations/{id}";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                match store::get_integration(&s.pool, &s.cipher, r.url_param("id")).await {
                    Ok(i) => {
                        w.header().set(
                            "ETag",
                            admin_tag(r, "integration", &i.id, i.revision).to_wire(),
                        );
                        write_v2_json(w, &v2_integration(i)).await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
    v2.delete(
        p,
        stack.v2_steps(
            p,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let i = match store::get_integration(&s.pool, &s.cipher, r.url_param("id")).await {
                    Ok(i) => i,
                    Err(e) => return write_problem(w, r, request_problem(e)).await,
                };
                let tag = admin_tag(r, "integration", &i.id, i.revision);
                let expected = match admin_guard(r, &tag, i.revision) {
                    Ok(v) => v,
                    Err(p) => return write_problem(w, r, p).await,
                };
                match store::delete_integration(&s.pool, &i.id, Some(expected)).await {
                    Ok(()) => w.write_header(204).await,
                    Err(Error::StaleRevision) => {
                        let current = match store::get_integration(&s.pool, &s.cipher, &i.id).await
                        {
                            Ok(c) => c,
                            Err(e) => return write_problem(w, r, request_problem(e)).await,
                        };
                        let p = problem(
                            "precondition_failed",
                            "The integration changed; reload before deleting.",
                        )
                        .with_header(
                            "ETag",
                            admin_tag(r, "integration", &current.id, current.revision).to_wire(),
                        );
                        write_problem(w, r, p).await;
                    }
                    Err(e) => write_problem(w, r, request_problem(e)).await,
                }
            }),
        ),
    );
}

pub fn mount(stack: &Arc<Stack>, api: &Mux, v2: &Mux) {
    mount_v1(stack, api);
    mount_v2(stack, v2);
}
