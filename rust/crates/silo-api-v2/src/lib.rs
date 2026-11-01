//! The `/api/v2` wire kit: the shared machinery every v2 operation's request and response types
//! build on (`internal/apiv2`'s non-handler files), ported ahead of any individual operation so
//! handlers that come later share one envelope, one precondition evaluator, and one cursor
//! signer instead of each re-deriving them.
//!
//! What is here: [`problem`] (RFC 9457 `problem+json`, the shared type catalog, and Huma's
//! validation error mapping), [`precondition`] (RFC 9110 entity tags and the `Evaluate*`
//! outcome functions), [`cursor`] (HMAC-signed pagination cursors), and [`wire`] (`Instant`,
//! `Patch`, the collection envelope, and the sort-query grammar). No HTTP transport, router, or
//! handler lives in this crate yet: `Dependencies`, `Registry`, and the ~230 operation files of
//! `internal/apiv2` are future work, listed in this port's own notes rather than attempted here.

pub mod cursor;
pub mod precondition;
pub mod problem;
pub mod wire;
