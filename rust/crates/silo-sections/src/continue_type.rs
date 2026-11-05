//! Port of `internal/sections/continue_type.go`.

use serde::Deserialize;
use silo_gocompat::strings::to_lower;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinueType(pub String);

impl ContinueType {
    pub const WATCHING: &'static str = "watching";
    pub const LISTENING: &'static str = "listening";
    pub const READING: &'static str = "reading";

    pub fn new(s: &str) -> Self {
        Self(s.to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_valid(&self) -> bool {
        matches!(
            self.0.as_str(),
            Self::WATCHING | Self::LISTENING | Self::READING
        )
    }
    pub fn matches_item(&self, item_type: &str) -> bool {
        match self.0.as_str() {
            Self::WATCHING => item_type == "movie" || item_type == "episode",
            Self::LISTENING => item_type == "audiobook",
            Self::READING => item_type == "ebook",
            _ => false,
        }
    }
    pub fn allows_next_up(&self) -> bool {
        self.0 == Self::WATCHING
    }
}

/// `ContinueTypeConfig`: compact JSON `{"continue_type":...}`; an invalid type becomes watching.
pub fn continue_type_config(typ: &ContinueType) -> String {
    let t = if typ.is_valid() {
        typ.as_str()
    } else {
        ContinueType::WATCHING
    };
    format!(r#"{{"continue_type":"{t}"}}"#)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawConfig {
    continue_type: String,
    filter_type: String,
    media_scope: String,
}

/// `ParseContinueType`. Err carries Go's message; the type on error is always watching.
pub fn parse_continue_type(config: &[u8]) -> Result<ContinueType, String> {
    let mut raw = RawConfig::default();
    if !config.is_empty() {
        // Go's json.Unmarshal into a struct accepts `null` as a no-op.
        match serde_json::from_slice::<Option<RawConfig>>(config) {
            Ok(Some(r)) => raw = r,
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    let ct = raw.continue_type.trim();
    if !ct.is_empty() {
        let typ = ContinueType(to_lower(ct));
        if !typ.is_valid() {
            return Err("continue_type must be 'watching', 'listening', or 'reading'".into());
        }
        return Ok(typ);
    }
    for v in [&raw.filter_type, &raw.media_scope] {
        match to_lower(v.trim()).as_str() {
            "audiobook" => return Ok(ContinueType::new(ContinueType::LISTENING)),
            "ebook" => return Ok(ContinueType::new(ContinueType::READING)),
            _ => {}
        }
    }
    Ok(ContinueType::new(ContinueType::WATCHING))
}

/// `ContinueTypeFromConfig`: parse errors degrade to watching.
pub fn continue_type_from_config(config: &[u8]) -> ContinueType {
    parse_continue_type(config).unwrap_or_else(|_| ContinueType::new(ContinueType::WATCHING))
}

pub fn is_audiobook_library_type(library_type: &str) -> bool {
    matches!(
        to_lower(library_type.trim()).as_str(),
        "audiobook" | "audiobooks"
    )
}
