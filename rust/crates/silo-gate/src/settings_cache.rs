//! The server settings repository as the readers `silo_config`'s setting caches take.

use std::sync::Arc;

use silo_config::config::{
    AdminDefaults, BoxFuture, ManySettingReader, SettingError, SettingReader, SettingsMap,
    UnratedContentPolicy,
};
use silo_store::settings::ServerSettingsRepo;

struct Reader(ServerSettingsRepo);

impl SettingReader for Reader {
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<String, SettingError>> {
        Box::pin(async move { self.0.get(key).await.map_err(Into::into) })
    }
}

impl ManySettingReader for Reader {
    fn get_many<'a>(
        &'a self,
        keys: &'a [String],
    ) -> BoxFuture<'a, Result<SettingsMap, SettingError>> {
        Box::pin(async move {
            let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
            let values = self.0.get_many(&keys).await?;
            Ok(values.into_iter().collect())
        })
    }
}

/// `config.NewAdminDefaults(settingsRepo)`.
pub fn admin_defaults(settings: ServerSettingsRepo) -> AdminDefaults {
    AdminDefaults::new(Some(Arc::new(Reader(settings))))
}

/// `config.NewUnratedContentPolicy(settingsRepo)`.
pub fn unrated_content(settings: ServerSettingsRepo) -> UnratedContentPolicy {
    UnratedContentPolicy::new(Some(Arc::new(Reader(settings))))
}
