//! API conformance harness: replays one request plan against a reference and a
//! candidate server and reports parity per surface. See ../README.md.

pub mod baseline;
pub mod diff;
pub mod http;
pub mod model;
pub mod mutate;
pub mod normalize;
pub mod params;
pub mod plan;
pub mod report;
pub mod runner;
pub mod schema;
pub mod sources;
