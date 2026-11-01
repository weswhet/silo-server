//! The `access.unrated_content` policy.

use super::{
    ACCESS_UNRATED_CONTENT_ALLOW, ACCESS_UNRATED_CONTENT_SETTING_KEY, CachedSetting, SettingReader,
};
use std::sync::Arc;
use std::time::Duration;

/// How long a node serves a cached `access.unrated_content` value.
pub const UNRATED_CONTENT_CACHE_TTL: Duration = Duration::from_secs(10);

/// Resolves the setting for the viewer scope resolvers.
pub struct UnratedContentPolicy {
    setting: CachedSetting<bool>,
}

impl UnratedContentPolicy {
    /// Binds the policy to a server settings reader. No reader keeps the default.
    pub fn new(settings: Option<Arc<dyn SettingReader>>) -> Self {
        UnratedContentPolicy {
            setting: CachedSetting::new(
                settings,
                ACCESS_UNRATED_CONTENT_SETTING_KEY,
                UNRATED_CONTENT_CACHE_TTL,
                |value| {
                    silo_gocompat::strings::equal_fold(
                        silo_gocompat::strings::trim_space(value),
                        ACCESS_UNRATED_CONTENT_ALLOW,
                    )
                },
            ),
        }
    }

    /// Whether a title with no rating stays visible to a viewer with a content-rating ceiling.
    pub async fn allow_unrated_content(&self) -> bool {
        self.setting.get().await
    }
}
