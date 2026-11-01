//! Port of `github.com/go-chi/chi/v5` v5.4.0: the routing tree, `Mux`, and routing `Context`.
//!
//! `axum::Router` cannot be used here: matchit rejects mid-segment and regex parameters, and axum's
//! `get` also serves HEAD where chi answers 405. The code follows chi line by line, including its
//! quirks, because they are the wire behavior.

mod context;
mod middleware;
mod mux;
mod tree;

pub use context::{Context, RouteParams, url_param, url_param_bytes};
pub use middleware::{redirect_slashes, strip_slashes};
pub use mux::{ChainHandler, Middleware, Mounted, Mux, WalkFn, chain, middleware_fn, walk};
pub use tree::{Route, register_method};
