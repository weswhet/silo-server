//! Key relationships: settings that are two spellings of one preference.

use crate::gojson::{self, Value};
use crate::settings::keys;
use silo_gocompat::strconv::quote;

pub const INTRO_SKIP_MODE_NEVER: &str = "never";
pub const INTRO_SKIP_MODE_ASK: &str = "ask";
pub const INTRO_SKIP_MODE_ALWAYS: &str = "always";

/// The companion row implied by writing another key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredWrite {
    pub key: String,
    pub value: Vec<u8>,
}

/// `MirrorKey`: the key whose row travels with this one.
pub fn mirror_key(key: &str) -> Option<&'static str> {
    match key {
        keys::PLAYBACK_AUTO_SKIP_INTRO => Some(keys::PLAYBACK_INTRO_SKIP_MODE),
        keys::PLAYBACK_INTRO_SKIP_MODE => Some(keys::PLAYBACK_AUTO_SKIP_INTRO),
        _ => None,
    }
}

/// `LogicalKey`: collapses a mirrored pair onto one name.
pub fn logical_key(key: &str) -> &str {
    match mirror_key(key) {
        Some(mirror) if key >= mirror => mirror,
        _ => key,
    }
}

/// `MirrorWrite`: the companion row for a value written at `key`, or `None` when it has no mirror.
pub fn mirror_write(key: &str, value: &[u8]) -> Result<Option<MirroredWrite>, String> {
    let Some(mirror) = mirror_key(key) else {
        return Ok(None);
    };
    let shown = String::from_utf8_lossy(value);
    let parsed = gojson::parse(value).ok().map(|n| n.value);
    if key == keys::PLAYBACK_AUTO_SKIP_INTRO {
        let Some(Value::Bool(enabled)) = parsed else {
            return Err(format!(
                "{key}: mirroring to {mirror} needs a boolean, got {shown}"
            ));
        };
        let mode = if enabled {
            INTRO_SKIP_MODE_ALWAYS
        } else {
            INTRO_SKIP_MODE_ASK
        };
        return Ok(Some(MirroredWrite {
            key: mirror.to_owned(),
            value: format!("\"{mode}\"").into_bytes(),
        }));
    }
    let Some(Value::String(mode)) = parsed else {
        return Err(format!(
            "{key}: mirroring to {mirror} needs a string, got {shown}"
        ));
    };
    if mode != INTRO_SKIP_MODE_NEVER
        && mode != INTRO_SKIP_MODE_ASK
        && mode != INTRO_SKIP_MODE_ALWAYS
    {
        return Err(format!("{key}: {} is not an intro skip mode", quote(&mode)));
    }
    let encoded: &[u8] = if mode == INTRO_SKIP_MODE_ALWAYS {
        b"true"
    } else {
        b"false"
    };
    Ok(Some(MirroredWrite {
        key: mirror.to_owned(),
        value: encoded.to_vec(),
    }))
}
