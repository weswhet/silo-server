//! Go-compatible primitives for the Silo port.
//!
//! Go is the behavioral reference while the port runs next to it, and many Go standard library
//! functions look like Rust counterparts that behave differently on the inputs that matter here:
//! `strings.ToLower` versus `str::to_lowercase`, `regexp` versus `regex`, `json.Marshal` versus
//! `serde_json::to_vec`, `filepath.Clean` versus `Path` methods. Domain crates call this crate
//! instead, and `rust/clippy.toml` bans the lookalikes outside it.
//!
//! The ported behavior is checked against differential vectors from the real Go standard library, under
//! `rust/conformance/vectors/gocompat`. Unicode tables are generated from the Go toolchain the server
//! builds with, not from the Unicode version Rust or the `regex` crate ships. Regenerate both with the
//! command at the top of the generator's `main.go`.

#![allow(clippy::disallowed_methods)]

pub mod filepath;
pub mod json;
pub mod path;
pub mod regexp;
pub mod strconv;
pub mod strings;
pub mod time;
pub mod unicode;
#[rustfmt::skip]
mod unicode_tables;
pub mod url;
