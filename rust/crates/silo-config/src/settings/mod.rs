//! `contracts/settings/v1` and `internal/settingscontract`.

pub mod canonical;
pub mod contract;
pub mod jsonschema;
pub mod keys;
pub mod load;
pub mod mirror;
pub mod strictjson;
pub mod validate;

pub use canonical::{canonical_bytes, etag, public_bytes, public_etag};
pub use contract::*;
pub use load::{
    MANIFEST_JSON, MANIFEST_SCHEMA_JSON, ObjectSchemas, SCHEMA_FILES, load, must_load,
    object_schema, object_schemas,
};
pub use validate::{normalize_language_tag, step_aligned};
