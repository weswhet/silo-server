//! `internal/apiv2/problem.go`: the RFC 9457 Problem Details envelope every v2 error uses, the
//! shared problem-type catalog, and Huma's validation error mapping (the fixed, safe details and
//! stable `errors[].code` values a framework message never leaks through).
//!
//! Every exported `apiv2.*` identifier that is pure data or pure logic is ported here. What is
//! not ported: the Huma/chi plumbing itself (`installErrorAdapter`, `problemTransformer`,
//! `writeProblem`, `requestIDFrom`) and the multipart/body-limit detection that reads
//! `*http.MaxBytesError` and Huma's live `[]error` chain, because both need a running Huma
//! pipeline this crate does not have. [`from_huma_error`] ports `fromHumaError` itself: the
//! caller supplies the decoded `(status, message, [(location, message)])` shape Huma would have
//! produced, which is exactly what a hand-written Rust validator (or a future Huma-equivalent)
//! must supply too.

use serde::{Deserialize, Serialize};

/// `apiv2.ProblemTypeOrigin`.
pub const PROBLEM_TYPE_ORIGIN: &str = "https://siloserver.org/docs/api/v2/problems/";

/// `apiv2.ProblemType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProblemType {
    pub id: &'static str,
    pub status: u16,
    pub title: &'static str,
}

impl ProblemType {
    /// `ProblemType.URI`.
    pub fn uri(&self) -> String {
        format!("{PROBLEM_TYPE_ORIGIN}{}", self.id)
    }
}

/// The catalog, in the exact declaration order of Go's `catalog` slice literal
/// (`internal/apiv2/problem.go`): [`type_for_status`] returns the first entry in this order
/// whose status matches, so the order is part of the port, not incidental.
pub const CATALOG: &[ProblemType] = &[
    ProblemType {
        id: "range_not_satisfiable",
        status: 416,
        title: "Range not satisfiable",
    },
    ProblemType {
        id: "device_login_expired",
        status: 410,
        title: "Device login expired",
    },
    ProblemType {
        id: "unsupported_source",
        status: 410,
        title: "Unsupported source",
    },
    ProblemType {
        id: "malformed_request",
        status: 400,
        title: "Malformed request",
    },
    ProblemType {
        id: "invalid_cursor",
        status: 400,
        title: "Invalid cursor",
    },
    ProblemType {
        id: "authentication_required",
        status: 401,
        title: "Authentication required",
    },
    ProblemType {
        id: "invalid_token",
        status: 401,
        title: "Invalid token",
    },
    ProblemType {
        id: "session_expired",
        status: 401,
        title: "Session expired",
    },
    ProblemType {
        id: "permission_denied",
        status: 403,
        title: "Permission denied",
    },
    ProblemType {
        id: "profile_verification_required",
        status: 403,
        title: "Profile verification required",
    },
    ProblemType {
        id: "not_found",
        status: 404,
        title: "Not found",
    },
    ProblemType {
        id: "method_not_allowed",
        status: 405,
        title: "Method not allowed",
    },
    ProblemType {
        id: "not_acceptable",
        status: 406,
        title: "Not acceptable",
    },
    ProblemType {
        id: "request_timeout",
        status: 408,
        title: "Request timeout",
    },
    ProblemType {
        id: "conflict",
        status: 409,
        title: "Conflict",
    },
    ProblemType {
        id: "idempotency_conflict",
        status: 409,
        title: "Idempotency conflict",
    },
    ProblemType {
        id: "job_not_cancelable",
        status: 409,
        title: "Job not cancelable",
    },
    ProblemType {
        id: "capability_disabled",
        status: 409,
        title: "Capability disabled",
    },
    ProblemType {
        id: "capability_not_configured",
        status: 409,
        title: "Capability not configured",
    },
    ProblemType {
        id: "precondition_failed",
        status: 412,
        title: "Precondition failed",
    },
    ProblemType {
        id: "payload_too_large",
        status: 413,
        title: "Payload too large",
    },
    ProblemType {
        id: "unsupported_media_type",
        status: 415,
        title: "Unsupported media type",
    },
    ProblemType {
        id: "validation_failed",
        status: 422,
        title: "Validation failed",
    },
    ProblemType {
        id: "precondition_required",
        status: 428,
        title: "Precondition required",
    },
    ProblemType {
        id: "rate_limited",
        status: 429,
        title: "Rate limited",
    },
    ProblemType {
        id: "internal_error",
        status: 500,
        title: "Internal error",
    },
    ProblemType {
        id: "capability_unsupported",
        status: 501,
        title: "Capability unsupported",
    },
    ProblemType {
        id: "dependency_unavailable",
        status: 503,
        title: "Dependency unavailable",
    },
    ProblemType {
        id: "client_upgrade_required",
        status: 410,
        title: "Client upgrade required",
    },
    ProblemType {
        id: "sync_reset_required",
        status: 409,
        title: "Progress reset required",
    },
    ProblemType {
        id: "snapshot_request_conflict",
        status: 409,
        title: "Snapshot request conflict",
    },
    ProblemType {
        id: "progress_snapshot_too_large",
        status: 413,
        title: "Progress snapshot too large",
    },
    ProblemType {
        id: "installation_changed",
        status: 409,
        title: "Playback installation changed",
    },
    ProblemType {
        id: "playback_session_ended",
        status: 410,
        title: "Playback session ended",
    },
    // `handlers.PlaybackCodeProgressConflict`.
    ProblemType {
        id: "progress_conflict",
        status: 409,
        title: "Playback progress conflict",
    },
    ProblemType {
        id: "password_change_required",
        status: 403,
        title: "Password change required",
    },
    ProblemType {
        id: "not_permitted",
        status: 403,
        title: "Not permitted",
    },
    ProblemType {
        id: "account_required",
        status: 403,
        title: "Account required",
    },
    ProblemType {
        id: "local_login_disabled",
        status: 403,
        title: "Local password sign-in disabled",
    },
    ProblemType {
        id: "password_expired",
        status: 403,
        title: "Password expired",
    },
    ProblemType {
        id: "email_in_use",
        status: 409,
        title: "Email in use",
    },
    ProblemType {
        id: "identity_linked_elsewhere",
        status: 409,
        title: "Identity linked elsewhere",
    },
    ProblemType {
        id: "provider_already_enabled",
        status: 409,
        title: "Provider already enabled",
    },
    ProblemType {
        id: "break_glass_required",
        status: 409,
        title: "Break-glass account required",
    },
    ProblemType {
        id: "last_sign_in_method",
        status: 409,
        title: "Last sign-in method",
    },
    ProblemType {
        id: "provider_unavailable",
        status: 503,
        title: "Provider unavailable",
    },
    ProblemType {
        id: "invalid_grant",
        status: 400,
        title: "Invalid grant",
    },
    ProblemType {
        id: "account_disabled",
        status: 403,
        title: "Account disabled",
    },
    ProblemType {
        id: "local_password_required",
        status: 409,
        title: "Local password required",
    },
    ProblemType {
        id: "already_linked",
        status: 409,
        title: "Already linked",
    },
    ProblemType {
        id: "token_refresh_required",
        status: 401,
        title: "Token refresh required",
    },
    ProblemType {
        id: "network_identity_required",
        status: 403,
        title: "Network identity required",
    },
    ProblemType {
        id: "prepared_file_expired",
        status: 409,
        title: "Prepared file expired",
    },
];

/// `apiv2.TypeForStatus`: the first catalog entry declared for `status`, or `internal_error`.
pub fn type_for_status(status: u16) -> ProblemType {
    CATALOG
        .iter()
        .find(|t| t.status == status)
        .copied()
        .unwrap_or(internal_error())
}

fn find(id: &str) -> ProblemType {
    CATALOG
        .iter()
        .find(|t| t.id == id)
        .copied()
        .unwrap_or_else(|| panic!("apiv2: no catalog entry named {id}"))
}

/// `apiv2.TypeInternalError`, used as the fallback [`type_for_status`] and [`huma_status_type`]
/// return when nothing else applies.
pub fn internal_error() -> ProblemType {
    // The literal, not `find`, so this one lookup can never panic.
    ProblemType {
        id: "internal_error",
        status: 500,
        title: "Internal error",
    }
}

macro_rules! problem_type_fn {
    ($name:ident, $id:literal) => {
        #[allow(missing_docs)]
        pub fn $name() -> ProblemType {
            find($id)
        }
    };
}
problem_type_fn!(malformed_request, "malformed_request");
problem_type_fn!(invalid_cursor, "invalid_cursor");
problem_type_fn!(not_acceptable, "not_acceptable");
problem_type_fn!(request_timeout, "request_timeout");
problem_type_fn!(payload_too_large, "payload_too_large");
problem_type_fn!(unsupported_media_type, "unsupported_media_type");
problem_type_fn!(validation_failed, "validation_failed");
problem_type_fn!(precondition_required, "precondition_required");
problem_type_fn!(precondition_failed, "precondition_failed");
problem_type_fn!(method_not_allowed, "method_not_allowed");
problem_type_fn!(dependency_unavailable, "dependency_unavailable");

/// `apiv2.RequestIDHeader`.
pub const REQUEST_ID_HEADER: &str = "X-Request-ID";
/// `apiv2.problemContentType`.
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";
/// The listener default every structured v2 response gets unless the operation overrides it
/// (`apiv2.defaultHeaders`).
pub const DEFAULT_CACHE_CONTROL: &str = "no-store";

/// `apiv2.ProblemError`: one entry of a validation problem's `errors` array. Never carries the
/// rejected value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProblemError {
    pub location: String,
    pub code: String,
    pub detail: String,
}

/// `apiv2.Problem`: the RFC 9457 envelope every v2 error uses. `headers` carries out-of-band
/// response headers (`Retry-After`, `ETag`); it is not part of the JSON body, matching Go's
/// unexported `headers http.Header` field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Problem {
    pub r#type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: String,
    pub errors: Vec<ProblemError>,
    headers: Vec<(String, String)>,
}

impl Problem {
    /// `apiv2.NewProblem`.
    pub fn new(t: ProblemType, detail: impl Into<String>) -> Self {
        Self {
            r#type: t.uri(),
            title: t.title.to_owned(),
            status: t.status,
            detail: detail.into(),
            instance: String::new(),
            errors: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// `Problem.WithErrors`.
    #[must_use]
    pub fn with_errors(mut self, errs: impl IntoIterator<Item = ProblemError>) -> Self {
        self.errors.extend(errs);
        self
    }

    /// `Problem.WithHeader`. Go builds `p.headers` with `http.Header.Add`, which canonicalizes
    /// the field name (`textproto.CanonicalMIMEHeaderKey`) as it is stored; this does the same so
    /// a later exact-match lookup (or a byte-for-byte vector comparison) sees the same key Go
    /// does, e.g. `"ETag"` stored as `"Etag"`.
    #[must_use]
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .push((canonical_header_key(name.as_ref()), value.into()));
        self
    }

    /// `Problem.WithRetryAfter`: `Retry-After` in delta-seconds, floored at 1.
    #[must_use]
    pub fn with_retry_after(self, seconds: i64) -> Self {
        self.with_header("Retry-After", seconds.max(1).to_string())
    }

    /// `Problem.GetHeaders`.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The RFC 9457 JSON body (`encoding/json`'s default HTML-escaping is irrelevant here: none
    /// of these fields can carry `<`, `>` or `&` from a fixed title/type, and `detail`/`errors`
    /// text is rendered the same way `writeProblem`'s encoder does, with HTML escaping off, by
    /// the caller using `silo_gocompat::json::marshal` on this type via [`Problem::to_body`]).
    pub fn to_body(&self) -> ProblemBodyOwned {
        ProblemBodyOwned {
            type_: self.r#type.clone(),
            title: self.title.clone(),
            status: self.status,
            detail: self.detail.clone(),
            instance: self.instance.clone(),
            errors: self.errors.clone(),
        }
    }
}

/// An owned, directly serializable copy of the wire body, for callers that want a `Serialize`
/// value without borrowing from the [`Problem`].
#[derive(Serialize, Deserialize)]
pub struct ProblemBodyOwned {
    #[serde(rename = "type")]
    pub type_: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<ProblemError>,
}

/// `apiv2.requestInstance`.
pub fn request_instance(request_id: &str) -> String {
    format!("urn:silo:request:{request_id}")
}

/// `textproto.CanonicalMIMEHeaderKey`, restricted to the ASCII letters and digits every header
/// name this crate writes uses: uppercase the first letter of each `-`-separated segment,
/// lowercase the rest. `net/http`'s `Header.Add` applies this on every write, so a `Problem`'s
/// stored header keys must match it to agree byte-for-byte with Go's.
pub fn canonical_header_key(name: &str) -> String {
    // Byte-oriented and ASCII-only on purpose: this is what `textproto.CanonicalMIMEHeaderKey`
    // itself does (it is not a Unicode case fold), so `char::to_ascii_{upper,lower}case` is the
    // faithful port here, not `silo_gocompat::unicode`'s general rune case maps.
    let mut out = name.as_bytes().to_vec();
    let mut start_of_word = true;
    for b in &mut out {
        if *b == b'-' {
            start_of_word = true;
        } else if start_of_word {
            b.make_ascii_uppercase();
            start_of_word = false;
        } else {
            b.make_ascii_lowercase();
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| name.to_owned())
}

// --- Huma's validation error mapping (`fromHumaError` and its helpers). ---

/// One `huma.ErrorDetail`-shaped failure: a location (`body`, `query.sort`, `form.name`, ...) and
/// the framework's own message text, exactly as Huma would report it. [`from_huma_error`] takes
/// these instead of a live Huma error chain because this crate has no Huma pipeline; whatever
/// validates a v2 request in Rust must produce this same shape to reuse the mapping.
#[derive(Debug, Clone)]
pub struct ErrorDetail {
    pub location: String,
    pub message: String,
}

/// One `errs` entry `from_huma_error` folds: either a decoded `ErrorDetail` (the common case) or
/// an opaque application error, whose text becomes one `errors[]` entry verbatim (`fromHumaError`
/// falls back to `err.Error()` when `errors.As` does not find a `*huma.ErrorDetail`).
#[derive(Debug, Clone)]
pub enum HumaErr {
    Detail(ErrorDetail),
    Other(String),
}

/// `(*http.MaxBytesError).Error()`'s exact text on the Go toolchain this port targets
/// (go1.26.10, `net/http/request.go`), the default [`from_huma_error`] body-size needle.
pub const HTTP_MAX_BYTES_MESSAGE: &str = "http: request body too large";

const LOCATION_BODY: &str = "body";
const CODE_INVALID: &str = "invalid";
const CODE_INVALID_TYPE: &str = "invalid_type";
const CODE_INVALID_ENUM: &str = "invalid_enum";
const CODE_REQUIRED: &str = "required";
const CODE_OUT_OF_RANGE: &str = "out_of_range";
const CODE_UNKNOWN_FIELD: &str = "unknown_field";
const CODE_UNKNOWN_PARAMETER: &str = "unknown_parameter";
const CODE_MALFORMED_JSON: &str = "malformed_json";
const CODE_MALFORMED_FORM: &str = "malformed_form";

/// `apiv2.validationCode`: maps a Huma validation message onto a stable code. A message the
/// table does not name is reported as `invalid` rather than as text a client would be tempted to
/// parse.
pub fn validation_code(msg: &str) -> &'static str {
    if msg.starts_with("unknown query parameter") {
        CODE_UNKNOWN_PARAMETER
    } else if msg.starts_with("unexpected property") {
        CODE_UNKNOWN_FIELD
    } else if msg.starts_with("expected required property")
        || msg.ends_with("parameter is missing")
        || msg == "request body is required"
    {
        CODE_REQUIRED
    } else if msg.starts_with("expected value to be one of") {
        CODE_INVALID_ENUM
    } else if msg.starts_with("expected number >")
        || msg.starts_with("expected number <")
        || msg.starts_with("expected length")
        || msg.starts_with("expected array length")
    {
        CODE_OUT_OF_RANGE
    } else if msg.starts_with("expected ") || msg.starts_with("invalid ") {
        CODE_INVALID_TYPE
    } else {
        CODE_INVALID
    }
}

const MSG_EXPECTED_URI: &str = "expected string to be RFC 3986 uri: ";

/// `apiv2.validationDetail`: keeps Huma's message except where it echoes the rejected value.
pub fn validation_detail(msg: &str) -> String {
    if let Some(_rest) = msg.strip_prefix(MSG_EXPECTED_URI) {
        return MSG_EXPECTED_URI.trim_end_matches(": ").to_owned();
    }
    if let Some(rest) = msg.strip_prefix("Invalid mime type: ")
        && let Some((_, want)) = rest.split_once(", expected ")
    {
        return format!("expected a part of media type {}", want.replace(',', ", "));
    }
    msg.to_owned()
}

/// `apiv2.validationLocation`: lifts the property a "required" message names into the location,
/// and maps a multipart `form`/`form.<name>` location onto the contract's `body`/`body.<name>`
/// grammar.
pub fn validation_location(detail: &ErrorDetail) -> String {
    let mut location = detail.location.clone();
    if location == "form" || location.starts_with("form.") {
        location = format!("{LOCATION_BODY}{}", location.trim_start_matches("form"));
    }
    const PREFIX: &str = "expected required property ";
    if let Some(rest) = detail.message.strip_prefix(PREFIX)
        && let Some(name) = rest.strip_suffix(" to be present")
        && !name.is_empty()
        && !name.contains([' ', '.', '['])
    {
        return format!("{location}.{name}");
    }
    if location != detail.location {
        return location;
    }
    if !detail.location.is_empty()
        && detail.location != LOCATION_BODY
        && !detail.location.contains(['.', '['])
    {
        return format!("{LOCATION_BODY}.{}", detail.location);
    }
    detail.location.clone()
}

/// `apiv2.humaStatusType`.
pub fn huma_status_type(status: u16, _msg: &str) -> ProblemType {
    match status {
        400 => malformed_request(),
        422 => validation_failed(),
        406 => not_acceptable(),
        408 => request_timeout(),
        413 => payload_too_large(),
        415 => unsupported_media_type(),
        405 => method_not_allowed(),
        _ => type_for_status(status),
    }
}

/// `apiv2.humaDetail`: replaces Huma's message with a fixed safe detail per type so a framework
/// message (which can embed limits or parser positions) never leaks.
pub fn huma_detail(t: ProblemType, msg: &str, body_limit: i64) -> String {
    match t.id {
        "validation_failed" => "The request did not pass validation; see errors.".to_owned(),
        "malformed_request" => "The request could not be parsed.".to_owned(),
        "not_acceptable" => {
            "No acceptable representation is available for this operation.".to_owned()
        }
        "request_timeout" => {
            "The request body was not received before the read deadline.".to_owned()
        }
        "payload_too_large" => format!("The request body exceeds the {body_limit}-byte limit."),
        "unsupported_media_type" => {
            "The request media type is not supported; send application/json.".to_owned()
        }
        "internal_error" => "An unexpected error occurred.".to_owned(),
        _ => {
            if msg.is_empty() {
                t.title.to_owned()
            } else {
                msg.to_owned()
            }
        }
    }
}

/// `apiv2.formParseFailure` / `apiv2.formSizeFailure`: whether `errs` is the multipart parser's
/// single "cannot read multipart form" detail at `body`, and whether its text names the body-size
/// guard specifically. `max_bytes_message` is the exact text `(*http.MaxBytesError).Error()`
/// produces ("http: request body too large"); callers on a non-net/http transport pass whatever
/// text their own body-size guard uses, if any.
fn form_parse_detail(status: u16, errs: &[HumaErr]) -> Option<&ErrorDetail> {
    if status != 422 || errs.len() != 1 {
        return None;
    }
    match &errs[0] {
        HumaErr::Detail(d)
            if d.location == LOCATION_BODY
                && d.message.starts_with("cannot read multipart form") =>
        {
            Some(d)
        }
        _ => None,
    }
}

/// `apiv2.fromHumaError`: the error adapter mapping a Huma-generated failure onto the Silo
/// envelope with a catalog type, stable codes, and no echoed values.
pub fn from_huma_error(
    request_id: &str,
    status: u16,
    msg: &str,
    errs: &[HumaErr],
    body_limit: i64,
    max_bytes_message: &str,
) -> Problem {
    if let Some(d) = form_parse_detail(status, errs) {
        if !max_bytes_message.is_empty() && d.message.contains(max_bytes_message) {
            let t = payload_too_large();
            let detail = huma_detail(t, msg, body_limit);
            let mut p = Problem::new(t, detail);
            p.instance = request_instance(request_id);
            return p;
        }
        let t = malformed_request();
        let detail = huma_detail(t, msg, body_limit);
        let mut p = Problem::new(t, detail).with_errors([ProblemError {
            location: LOCATION_BODY.to_owned(),
            code: CODE_MALFORMED_FORM.to_owned(),
            detail: "The request body is not a valid multipart form.".to_owned(),
        }]);
        p.instance = request_instance(request_id);
        return p;
    }
    let t = huma_status_type(status, msg);
    let detail = huma_detail(t, msg, body_limit);
    let mut p = Problem::new(t, detail);
    p.instance = request_instance(request_id);
    if status != 422 && status != 400 {
        return p;
    }
    for err in errs {
        match err {
            HumaErr::Other(text) => {
                p.errors.push(ProblemError {
                    location: LOCATION_BODY.to_owned(),
                    code: CODE_INVALID.to_owned(),
                    detail: text.clone(),
                });
            }
            HumaErr::Detail(d) => {
                if status == 400 && d.location == LOCATION_BODY {
                    p.errors.push(ProblemError {
                        location: LOCATION_BODY.to_owned(),
                        code: CODE_MALFORMED_JSON.to_owned(),
                        detail: "The request body is not valid JSON.".to_owned(),
                    });
                    continue;
                }
                p.errors.push(ProblemError {
                    location: validation_location(d),
                    code: validation_code(&d.message).to_owned(),
                    detail: validation_detail(&d.message),
                });
            }
        }
    }
    p
}
