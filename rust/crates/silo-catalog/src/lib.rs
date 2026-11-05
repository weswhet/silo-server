//! The catalog read stack, ported from `internal/catalog`. This crate holds the query engine
//! ([`query`]): `QueryDefinition` validation, `QueryBuilder`'s SQL, the preview page plan the
//! `QueryExecutor` runs, cursor seeks, and grouping by work. [`model`] holds the media item columns
//! and the row type the plans select.
//!
//! The SQL text and argument lists match Go's byte for byte; the `catalogquery` vectors under
//! `rust/conformance/vectors/catalog/` prove it.

pub mod model;
pub mod query;
pub mod search;
