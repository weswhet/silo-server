//! Ports of the Go HTTP server stack Silo's wire behavior comes from.
//!
//! Clients and the conformance harness see this crate's bytes, so it owns the HTTP/1.1 connection
//! rather than sitting on hyper: Go's header order and casing, lowercase chunk sizes, Date placement,
//! bad-request bodies, and acceptance of raw request targets are not things hyper exposes. Each module
//! names the Go it ports. Go 1.26.7 and chi v5.4.0 are the references, and the `differential` test runs
//! them against this crate over TCP.

pub mod bufio;
pub mod chi;
pub mod compress;
pub mod fs;
pub mod header;
pub mod mime;
pub mod request;
pub mod response;
pub mod servemux;
pub mod server;
pub mod sniff;
pub mod status;
pub mod tower_bridge;
pub mod url;
mod url_table;

pub use crate::bufio::{BoxedIo, Io};
pub use crate::header::{Header, TIME_FORMAT, canonical_header_key, format_time, parse_time};
pub use crate::request::{Body, ReadCloser, Request, max_bytes_reader};
pub use crate::response::{
    AbortHandler, BoxFuture, BoxHandler, Handler, Hijacked, ResponseWriter, WriteError,
    abort_handler, error, handler_fn, not_found, not_found_handler, redirect, redirect_handler,
    strip_prefix,
};
pub use crate::servemux::ServeMux;
pub use crate::server::{Server, ServerConfig};
pub use crate::sniff::detect_content_type;
pub use crate::status::status_text;
pub use crate::url::Url;
