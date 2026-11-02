//! `internal/auth`: JWT claims and `JWTService`, login session CRUD, permissions, device login
//! codes, and the auth-provider trait bridge to plugins. See each module's doc for exact scope.

pub mod api_key;
pub mod api_key_store;
pub mod attempts;
pub mod audit;
pub mod claims;
pub mod device;
pub mod device_login;
pub mod passwordhash;
pub mod permissions;
pub mod provider;
pub mod service;
pub mod session;
pub mod user;
