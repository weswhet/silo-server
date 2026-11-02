//! The refusals of `auth.go`, `profile.go`, `viewer_access.go`, `demo_guard.go`, `permissions.go`, and
//! `ratelimit/middleware.go`, and their v1 bodies.

use serde::Serialize;

/// `Reason*`. These refine a code that covers denials v2 tells apart.
pub mod reason {
    pub const AUTHENTICATION_REQUIRED: &str = "authentication_required";
    pub const INVALID_CREDENTIAL: &str = "invalid_credential";
    pub const ACCOUNT_DISABLED: &str = "account_disabled";
    pub const SESSION_INVALID: &str = "session_invalid";
    pub const TOKEN_REFRESH_REQUIRED: &str = "token_refresh_required";
    pub const PROFILE_HEADER_REQUIRED: &str = "profile_header_required";
    pub const ITEM_ID_REQUIRED: &str = "item_id_required";
    pub const VIEWER_ACCESS_UNAVAILABLE: &str = "viewer_access_unavailable";
}

/// `CodePasswordChangeRequired`.
pub const CODE_PASSWORD_CHANGE_REQUIRED: &str = "password_change_required";
/// `CodeServiceUnavailable`.
pub const CODE_SERVICE_UNAVAILABLE: &str = "service_unavailable";
/// `auth.SessionCheckRetryAfterSeconds`.
pub const CREDENTIAL_CHECK_RETRY_AFTER_SECONDS: i64 = 5;
/// `ViewerAccessRetryAfterSeconds`.
pub const VIEWER_ACCESS_RETRY_AFTER_SECONDS: i64 = 1;

/// One gate's refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    /// `recordDenialReason`, never written to a v1 body.
    pub reason: &'static str,
    /// `Retry-After`, set by the gate before the status.
    pub retry_after: Option<i64>,
    /// `rateLimitError.RetryAfter`.
    pub retry_after_field: Option<i64>,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct RateLimitError<'a> {
    error: &'a str,
    message: &'a str,
    retry_after: i64,
}

impl Denial {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            reason: "",
            retry_after: None,
            retry_after_field: None,
        }
    }

    /// `writeUnauthorized`.
    pub fn unauthorized(message: &str, reason: &'static str) -> Self {
        Self {
            reason,
            ..Self::new(401, "unauthorized", message)
        }
    }

    /// `writeForbidden`.
    pub fn forbidden(message: &str) -> Self {
        Self::new(403, "forbidden", message)
    }

    /// `writeInternalError`.
    pub fn internal(message: &str) -> Self {
        Self::new(500, "internal_error", message)
    }

    /// `writePasswordChangeRequired`.
    pub fn password_change_required() -> Self {
        Self::new(
            403,
            CODE_PASSWORD_CHANGE_REQUIRED,
            "Choose a new password to continue",
        )
    }

    /// `writeCredentialCheckUnavailable`.
    pub fn credential_check_unavailable() -> Self {
        Self {
            retry_after: Some(CREDENTIAL_CHECK_RETRY_AFTER_SECONDS),
            ..Self::new(
                503,
                CODE_SERVICE_UNAVAILABLE,
                "Sign-in could not be checked right now; try again shortly",
            )
        }
    }

    /// `writeProfileHeaderRequired`.
    pub fn profile_header_required() -> Self {
        Self {
            reason: reason::PROFILE_HEADER_REQUIRED,
            ..Self::new(400, "bad_request", "X-Profile-Id header is required")
        }
    }

    /// `writeDemoBlocked`.
    pub fn demo_blocked() -> Self {
        Self::new(
            403,
            "demo_restricted",
            "This action is not available in demo mode.",
        )
    }

    /// `writeRateLimitBody`, with `writeRateLimitResponse`'s `Retry-After`.
    pub fn rate_limited(retry_seconds: i64) -> Self {
        Self {
            retry_after: Some(retry_seconds),
            retry_after_field: Some(retry_seconds),
            ..Self::new(
                429,
                "rate_limit_exceeded",
                format!("Too many requests. Please retry after {retry_seconds} seconds."),
            )
        }
    }

    /// The v1 body, `json.NewEncoder(w).Encode`. The demo refusal is Go's fixed string, with no newline.
    pub fn v1_body(&self) -> Vec<u8> {
        if self.code == "demo_restricted" {
            return br#"{"error":"demo_restricted","message":"This action is not available in demo mode."}"#.to_vec();
        }
        let mut body = match self.retry_after_field {
            Some(retry_after) => silo_gocompat::json::marshal(&RateLimitError {
                error: self.code,
                message: &self.message,
                retry_after,
            }),
            None => silo_gocompat::json::marshal(&ErrorResponse {
                error: self.code,
                message: &self.message,
            }),
        }
        .expect("a struct of strings marshals");
        body.push(b'\n');
        body
    }
}
