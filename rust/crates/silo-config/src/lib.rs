//! Silo's configuration: bootstrap env and flags, the `server_settings` model and its admin
//! defaults, the settings contract and resolver, and the robfig cron parser.
//!
//! This is a port of `internal/config`, `contracts/settings/v1`, `internal/settingscontract`,
//! `internal/settingsresolve`, and the environment parsing `cmd/silo` runs at startup. Go is the
//! behavioral reference, and differential vectors from the real Go packages live under
//! `rust/conformance/vectors/config`.

pub mod config;
pub mod cron;
pub mod env;
pub mod gojson;
pub mod gonet;
pub mod goparse;
pub mod lang;
#[rustfmt::skip]
mod lang_tables;
pub mod resolve;
pub mod settings;
