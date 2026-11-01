//! Every environment variable and flag `cmd/silo` reads at startup, with Go's defaults and spellings.
//!
//! Each parser takes the [`Env`] the bootstrap loader produced, so a value from `.env` reaches it
//! just as `godotenv.Load` makes it reach `os.Getenv`.

pub mod flags;
pub mod misc;
pub mod postgres_tune;
pub mod stream_telemetry;
pub mod telemetry;
pub mod tuning;

pub use crate::config::Env;

/// `envutil.Truthy`: whether a raw value means "on". Case and surrounding whitespace are ignored.
pub fn truthy(value: &str) -> bool {
    matches!(
        silo_gocompat::strings::to_lower(silo_gocompat::strings::trim_space(value)).as_str(),
        "1" | "true" | "yes" | "on" | "enabled"
    )
}

/// `envutil.Bool`.
pub fn env_bool(env: &Env, name: &str) -> bool {
    truthy(env.get(name))
}

/// `envutil.IsSet`: whitespace-only counts as empty.
pub fn is_set(env: &Env, name: &str) -> bool {
    !silo_gocompat::strings::trim_space(env.get(name)).is_empty()
}

/// `envutil.BoolDefault`: `def` when unset or empty, and a present but unrecognized value is false,
/// so a typo in a default-on kill switch turns the flag off.
pub fn bool_default(env: &Env, name: &str, def: bool) -> bool {
    if !is_set(env, name) {
        return def;
    }
    truthy(env.get(name))
}
