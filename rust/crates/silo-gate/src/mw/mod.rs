//! `internal/api/middleware`, one module per concern.
//!
//! A Go middleware that refuses writes the v1 JSON error, and on v2 a `denialWriter` translates it. Here
//! a gate returns a [`Denial`] and the surface's writer renders it, which is the same decision reused
//! with the wire form chosen once. Headers a gate sets go into the `sink` it is given: the response on
//! v1, a throwaway on v2, so `X-RateLimit-*` reach v1 clients only, exactly as Go's writers do.

pub mod activity;
pub mod auth;
pub mod denial;
pub mod logging;
pub mod policy_gates;
pub mod route_tables;
pub mod scopes;
pub mod viewer;

pub use auth::{AuthGate, DIRECT_DOWNLOAD_LINK_PARAM};
pub use denial::Denial;

/// `chimw.RequestIDKey`.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// `apimw.NewRequestID`: 96 random bits as 24 hex characters.
pub fn new_request_id() -> String {
    let id: [u8; 12] = rand::random();
    let mut out = String::with_capacity(24);
    for byte in id {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `apimw.APIv2Prefix`.
pub const API_V2_PREFIX: &str = "/api/v2/";
