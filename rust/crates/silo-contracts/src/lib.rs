//! The artifacts the server embeds, and the conversion code its migrations need.
//!
//! - [`embedded`]: `contracts/` and `migrations/sql/`, byte for byte.
//! - [`migrate`]: the goose-compatible runner over those files and the six Go migrations.
//! - [`settingscontract`], [`settingsmigrate`], [`settingskeys`]: the settings contract and the
//!   legacy conversion the settings backfill applies.
//! - [`lang`], [`naming`], [`displayprefs`]: the rules the other Go migrations apply.
//!
//! The conversion code sits here, not in a higher crate, because the migrator is the lowest thing
//! that needs it.

pub mod displayprefs;
pub mod embedded;
pub mod gojson;
pub mod jsonschema;
pub mod lang;
pub mod migrate;
pub mod naming;
pub mod settingscontract;
pub mod settingskeys;
pub mod settingsmigrate;
