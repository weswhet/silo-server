//! `internal/clientip`, `internal/ratelimit`, and `internal/policy`: the three layers that gate a
//! request after `silo-auth` names who is asking. See each module's doc for exact scope and the
//! parts deferred to a later session (recorded in the port report's `stubbed_or_skipped`).
//!
//! `internal/api/middleware`, `internal/invitations`, and `internal/passwordreset` — named in the
//! plan's crate-10 row — are NOT ported in this session; see the crate-level doc comment this
//! session's report carries for why.

pub mod clientip;
pub mod limiter;
pub mod mw;
pub mod policy;
pub mod ratelimit;
mod rego_check;
