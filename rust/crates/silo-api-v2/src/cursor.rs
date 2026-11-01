//! `internal/apiv2/cursor.go`: opaque, HMAC-signed pagination cursors, scoped to an operation,
//! security context, filter and sort so a cursor presented against a different query is
//! rejected.
//!
//! The signing primitives (`CursorScope`, `encode_cursor`, `decode_cursor`) already live in
//! `silo_core::apiv2`; this module is the thin `Cursors.Encode` / `Cursors.Decode` wrapper that
//! maps their outcomes onto [`crate::problem::Problem`], matching what Go's methods return.

use serde::{Serialize, de::DeserializeOwned};
use silo_core::apiv2::{CursorError, decode_cursor, encode_cursor};

use crate::problem::{self, Problem};

/// Re-exported so callers mint a scope without depending on `silo-core` directly.
pub use silo_core::apiv2::CursorScope;

/// `apiv2.Cursors`: mints and verifies cursors with one HMAC secret.
#[derive(Debug, Clone)]
pub struct Cursors {
    secret: Vec<u8>,
}

impl Cursors {
    /// `apiv2.NewCursors`.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    /// `Cursors.Encode`.
    // `Problem` is the one error type the whole wire kit returns; every other fallible function
    // here returns `Option<Problem>`, so boxing just this `Err` would be an inconsistent one-off.
    #[allow(clippy::result_large_err)]
    pub fn encode<P: Serialize + ?Sized>(
        &self,
        scope: &CursorScope,
        position: &P,
    ) -> Result<String, Problem> {
        encode_cursor(&self.secret, scope, position).map_err(cursor_problem)
    }

    /// `Cursors.Decode`. The position is decoded with plain `serde_json`, matching
    /// `cursor.go`'s own use of the stdlib `encoding/json.Unmarshal` (not the Go-request-decode
    /// fork `silo_gocompat::json` ports elsewhere): a cursor's position is server-authored and
    /// HMAC-authenticated, never adversarial client JSON, so the two decoders' behavior on
    /// malformed input never has to agree.
    #[allow(clippy::result_large_err)]
    #[allow(
        clippy::disallowed_methods,
        reason = "cursor.go decodes the position with plain encoding/json, not gojson; see the doc comment above"
    )]
    pub fn decode<P: DeserializeOwned>(
        &self,
        scope: &CursorScope,
        cursor: &str,
    ) -> Result<P, Problem> {
        let raw = decode_cursor(&self.secret, scope, cursor).map_err(cursor_problem)?;
        serde_json::from_slice(&raw).map_err(|_| invalid_cursor_problem())
    }
}

fn invalid_cursor_problem() -> Problem {
    Problem::new(
        problem::invalid_cursor(),
        "The cursor is malformed, tampered with, or belongs to a different query.",
    )
}

fn cursor_problem(e: CursorError) -> Problem {
    match e {
        CursorError::Invalid => invalid_cursor_problem(),
        CursorError::NotConfigured => Problem::new(
            problem::dependency_unavailable(),
            "Pagination signing is not configured.",
        ),
    }
}
