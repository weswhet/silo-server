//! API conformance harness: replays one request plan against a reference and a
//! candidate server and reports parity per surface. See ../README.md.

pub mod auth_flows;
pub mod baseline;
pub mod collection_flows;
pub mod diff;
pub mod effects;
pub mod http;
pub mod model;
pub mod mutate;
pub mod normalize;
pub mod notification_flows;
pub mod origin;
pub mod params;
pub mod personal_flows;
pub mod plan;
pub mod report;
pub mod request_flows;
pub mod runner;
pub mod schema;
pub mod settings_flows;
pub mod sources;
