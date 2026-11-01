//! Process-bootstrap infrastructure shared by every Silo API replica: Postgres wiring and
//! migrations, the Redis cache and pub/sub event bus (`internal/cache`), session-level advisory
//! locks and the storage admission lock (`internal/database/pglock`), and outbound mail
//! (`internal/mail`) with a hand-written SASL layer.
//!
//! Lower crates already hold the formats that must stay byte-identical with Go: advisory lock
//! integers and the Lua script texts live in [`silo_core::advisory_locks`] and
//! [`silo_core::redis_lua`], the Redis channel and key-prefix layout lives in [`silo_core::redis`],
//! and Redis URL parsing (including Sentinel) lives in `silo_config::config`. This crate wires
//! those into live Postgres and Redis connections; it does not redefine them.

pub mod admission;
pub mod cache;
pub mod database;
pub mod idgen_lease;
pub mod locks;
pub mod mail;
