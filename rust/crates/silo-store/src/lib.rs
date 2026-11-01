//! Silo's settings store (`enc:v1`), the canonical `userstore` setting-values engine, and a
//! bounded slice of `access`. Ported from `internal/catalog/{server_settings_repo,
//! encrypted_settings_repo}.go`, `internal/userstore` (+ `pgstore`), and `internal/access/types.go`.
//!
//! # What this crate is, versus the plan's crate table
//!
//! The plan's crate-5 row lists "Settings, userstore, userdb, access, blobstore, s3client,
//! naming". By the time this crate was built:
//! - The settings *contract* (`settingscontract`, `settingskeys`, `settingsmigrate`) and the
//!   settings *resolver* (`settingsresolve`) had already moved into `silo-contracts` and
//!   `silo-config` respectively, out of necessity (the migrator and `silo-config` needed them
//!   before this crate existed). What "Settings" means here instead is the runtime CRUD against
//!   the `server_settings` table — Go keeps that in `internal/catalog`, not a `settings` package,
//!   but no crate had ported it yet. See [`settings`].
//! - `userstore`'s row types ([`silo_config::resolve::SettingIdentity`] etc.) are likewise already
//!   defined in `silo_config::resolve`. This crate re-exports them and adds the identity
//!   validation and the Postgres backend. See [`userstore`].
//! - `naming` is almost entirely NOT ported here. `silo_contracts::naming` already carries the
//!   three functions `silo-contracts`' settings migrator needed
//!   (`sidecar_subtitle_tags`/`subtitle_suffix`/`parse_subtitle_suffix`). The remaining ~7,300 Go
//!   lines (episode/movie/series identity, folder IDs, acronym and provider-tag parity, …) are
//!   each their own multi-day port with their own parity test corpus and are not attempted here.
//! - `access` is ported only as far as [`access::types`]: the pure data types and the few pure
//!   methods/constants on them (`Scope`, `MaturityLimits`, `ResolveInput`,
//!   `ProfileTokenClaims`, `ValidAdvisoryAgeLimit`). `resolver.go` (the actual
//!   `ResolveScope`) and the Postgres-backed `groups`/`household`/`rating`/`quality`/
//!   `metadata_curation`/`metadata_language`/`viewer_preferences`/`profile_token` files are not
//!   ported: they depend on the catalog, policy and JWT wiring that does not exist as a crate yet.
//! - `blobstore`/`s3client` are not ported here beyond what already lives in `silo_core::blobstore`
//!   (`validate_key`, the identity strings, presigning). [`blobstore::media_type`] is the one
//!   addition. The `Store` trait, the filesystem and S3 backends, and all of `s3client` (retry,
//!   paging, transport, presign-window edge cases) are not ported.
//! - `userdb` (the SQLite backend, `internal/userdb`) is not ported at all; see the crate's own
//!   module doc on [`userstore::pgstore`]. Go's Postgres backend (`userstore`) is primary and is
//!   what this crate covers.
//!
//! See the port report's `stubbed_or_skipped` and `divergences` for the exact list and the reasons.

pub mod access;
pub mod blobstore;
pub mod settings;
pub mod userstore;
