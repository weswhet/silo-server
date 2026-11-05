//! Formats that must stay byte-compatible with the Go server while the two run side by side, and with
//! everything Go already wrote once it is gone: at-rest ciphertext, content IDs, signed tokens and URLs,
//! validators, and the hashes stored next to credentials.
//!
//! Each module names the Go package it ports. Inputs are bytes where Go's are arbitrary `string`s,
//! because file paths and row values are not always UTF-8. Every family has vectors from the real Go
//! packages under `rust/conformance/vectors/core`, checked in both directions; the list of families is
//! `rust/parity/formats.json`.

#[rustfmt::skip]
pub mod advisory_locks;
pub mod apikey;
pub mod apiv2;
pub mod artworkkey;
pub mod artworkurl;
pub mod blobstore;
pub mod contentid;
pub mod digest;
pub mod downloads;
pub mod embeddings;
pub mod fspath;
pub mod goid;
pub mod gourl;
pub mod hexgo;
pub mod idgen;
pub mod imagesize;
pub mod jcs;
pub mod jellycompat;
pub mod keyframes;
pub mod lantls;
pub mod models;
pub mod naming;
pub mod nodeauth;
pub mod oauth;
pub mod passwordhash;
pub mod playback;
pub mod redis;
#[rustfmt::skip]
pub mod redis_lua;
pub mod searchfold;
pub mod secret;
pub mod streamtoken;
pub mod thumbhash;
pub mod tokens;
pub mod utf8go;
