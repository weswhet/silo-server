//! The theme catalog URL allowlist.

use crate::gonet::Url;

/// The catalog fetched when no override is stored.
pub const DEFAULT_THEME_CATALOG_URL: &str =
    "https://raw.githubusercontent.com/Silo-Server/silo-themes/main/catalog.json";

const ALLOWED_THEME_REMOTE_HOSTS: [&str; 3] = [
    "raw.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
];

/// `ValidateThemeRemoteURL`.
pub fn validate_theme_remote_url(parsed: &Url) -> Result<(), String> {
    const MESSAGE: &str =
        "invalid character \"theme URL must use HTTPS on an approved GitHub host\" in host name";
    if parsed.scheme != "https"
        || parsed.host.is_empty()
        || !ALLOWED_THEME_REMOTE_HOSTS.contains(&parsed.hostname())
    {
        return Err(MESSAGE.to_owned());
    }
    Ok(())
}

pub(crate) fn normalize_admin_theme_url(key: &str, value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    match Url::parse(value) {
        Ok(parsed) if validate_theme_remote_url(&parsed).is_ok() => {
            Ok(value.trim_end_matches('/').to_owned())
        }
        _ => Err(format!("{key} must use HTTPS on an approved GitHub host")),
    }
}
