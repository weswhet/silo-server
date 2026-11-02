//! `internal/auth`: JWT claims and `JWTService`, login session CRUD, permissions, device login
//! codes, and the auth-provider trait bridge to plugins. See each module's doc for exact scope.

pub mod api_key;
pub mod api_key_store;
pub mod claims;
pub mod device_login;
pub mod permissions;
pub mod provider;
pub mod session;
pub mod user;
