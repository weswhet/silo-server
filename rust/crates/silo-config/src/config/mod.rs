//! `internal/config`.

mod admin_defaults;
mod admin_settings;
mod ai_providers;
mod bootstrap;
mod cached_setting;
mod db_loader;
mod dotenv;
mod playback_routing;
mod redis_url;
mod restart_keys;
mod theme_url;
mod types;
mod unrated_content;
mod yaml_import;

pub use admin_defaults::*;
pub use admin_settings::*;
pub use ai_providers::*;
pub use bootstrap::*;
pub use cached_setting::*;
pub use db_loader::load_from_db;
pub use dotenv::{DotenvError, parse_dotenv};
pub use playback_routing::*;
pub use redis_url::*;
pub use restart_keys::*;
pub use theme_url::*;
pub(crate) use types::ser_duration as types_ser_duration;
pub use types::*;
pub use unrated_content::*;
pub use yaml_import::{yaml_to_settings_map, yaml_to_settings_map_bytes};

use std::future::Future;
use std::pin::Pin;

/// A boxed future, the shape of an object-safe async trait method.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Settings as `map[string]string`.
pub type SettingsMap = std::collections::HashMap<String, String>;

pub(crate) fn m_get<'a>(m: &'a SettingsMap, key: &str) -> &'a str {
    m.get(key).map_or("", String::as_str)
}
