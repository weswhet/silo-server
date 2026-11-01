//! The configuration needed before a database connection.

use std::collections::HashMap;

const MIN_SECRET_KEY_LEN: usize = 32;

/// `BootstrapConfig`.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct BootstrapConfig {
    #[serde(rename = "DatabaseURL")]
    pub database_url: String,
    /// Optional override; empty means use the DB setting.
    #[serde(rename = "RedisURL")]
    pub redis_url: String,
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "JFListen")]
    pub jf_listen: String,
    #[serde(rename = "ABSListen")]
    pub abs_listen: String,
    #[serde(rename = "Mode")]
    pub mode: String,
    /// The raw `SECRET_KEY` bytes the at-rest credential cipher derives its data key from.
    #[serde(rename = "SecretKey", with = "silo_gocompat::json::bytes")]
    pub secret_key: Vec<u8>,
}

impl std::fmt::Debug for BootstrapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapConfig")
            .field("listen", &self.listen)
            .field("jf_listen", &self.jf_listen)
            .field("abs_listen", &self.abs_listen)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// The process environment as `os.Getenv` sees it after `godotenv.Load`: a value already set in the
/// environment, even to "", wins over the file.
///
/// Rust cannot call `setenv` safely once threads exist, so `.env` values live here rather than in the
/// process environment. Everything that reads config takes this, and [`Env::apply_to_process`] exists
/// for a process that must also pass them to a child.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    vars: HashMap<String, String>,
}

impl Env {
    /// A snapshot of the process environment.
    pub fn from_process() -> Self {
        let mut vars = HashMap::new();
        for (k, v) in std::env::vars_os() {
            vars.insert(
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            );
        }
        Env { vars }
    }

    /// An environment holding exactly these variables.
    pub fn from_pairs<K: Into<String>, V: Into<String>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Env {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// `os.Getenv`: an unset variable reads as "".
    pub fn get(&self, key: &str) -> &str {
        self.vars.get(key).map_or("", String::as_str)
    }

    /// `os.LookupEnv`.
    pub fn lookup(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.vars.insert(key.into(), value.into());
    }

    /// `godotenv.Load(path)`, ignoring its error like the callers do. A file that is missing or does
    /// not parse changes nothing.
    pub fn load_dotenv(&mut self, path: &str) {
        let Ok(data) = std::fs::read(path) else {
            return;
        };
        self.load_dotenv_bytes(&data);
    }

    /// `godotenv.Load` on file contents.
    pub fn load_dotenv_bytes(&mut self, data: &[u8]) {
        let Ok(parsed) = super::parse_dotenv(data) else {
            return;
        };
        for (key, value) in parsed {
            // os.Setenv refuses an empty key, or one with = or NUL in it.
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                continue;
            }
            self.vars.entry(key).or_insert(value);
        }
    }

    /// Writes every variable to the process environment.
    ///
    /// # Safety
    /// Call it before any other thread exists, as with [`std::env::set_var`].
    pub unsafe fn apply_to_process(&self) {
        for (k, v) in &self.vars {
            // SAFETY: the caller guarantees no other thread reads the environment.
            unsafe { std::env::set_var(k, v) };
        }
    }
}

/// `applyBootstrapOverrides`: replaces the settings the process environment owns in a config built
/// from the database.
pub fn apply_bootstrap_overrides(cfg: &mut super::Config, bc: &BootstrapConfig) {
    cfg.server.listen.clone_from(&bc.listen);
    cfg.server.mode.clone_from(&bc.mode);
    cfg.database.url.clone_from(&bc.database_url);
    cfg.jellyfin_compat.listen.clone_from(&bc.jf_listen);
    cfg.audiobookshelf_compat = cfg
        .audiobookshelf_compat
        .with_bootstrap_listen(&bc.abs_listen);
    cfg.redis = cfg.redis.with_bootstrap_url(&bc.redis_url);
}

/// `addRedisBootstrapSettings`: records what `REDIS_URL` supplies in the maps the admin settings
/// handlers read. `REDIS_URL` names the database number too, so `redis.db` reports the number in use.
pub fn add_redis_bootstrap_settings(
    redis_url: &str,
    configured: &mut HashMap<String, bool>,
    values: &mut HashMap<String, String>,
) {
    if redis_url.is_empty() {
        return;
    }
    configured.insert("redis.url".to_owned(), true);
    values.insert("redis.url".to_owned(), redis_url.to_owned());
    configured.insert(super::REDIS_DB_SETTING_KEY.to_owned(), true);
    let cfg = super::RedisConfig {
        url: redis_url.to_owned(),
        db: String::new(),
    };
    values.insert(
        super::REDIS_DB_SETTING_KEY.to_owned(),
        cfg.database().unwrap_or(0).to_string(),
    );
}

/// `LoadDatabaseURL`: for maintenance commands that only reach the database.
pub fn load_database_url(env: &mut Env, env_file: &str) -> Result<String, String> {
    if !env_file.is_empty() {
        env.load_dotenv(env_file);
    }
    let db_url = env.get("DATABASE_URL");
    if db_url.is_empty() {
        return Err("DATABASE_URL is required (set in .env or environment)".to_owned());
    }
    Ok(db_url.to_owned())
}

/// `LoadBootstrap`: bootstrap configuration from a `.env` file, if it exists, and the environment.
pub fn load_bootstrap(env: &mut Env, env_file: &str) -> Result<BootstrapConfig, String> {
    let database_url = load_database_url(env, env_file)?;
    let secret_key = env.get("SECRET_KEY");
    if secret_key.len() < MIN_SECRET_KEY_LEN {
        return Err(format!(
            "SECRET_KEY is required (>={MIN_SECRET_KEY_LEN} chars); generate one with: openssl rand -base64 48"
        ));
    }
    let or_default = |key: &str, default: &'static str| -> String {
        let v = env.get(key);
        if v.is_empty() {
            default.to_owned()
        } else {
            v.to_owned()
        }
    };
    let port = or_default("PORT", "8080");
    let jf_port = or_default("JF_PORT", "8096");
    let abs_port = or_default("ABS_PORT", "13378");
    let mode = or_default("MODE", "integrated");
    if (mode == "proxy" || mode == "transcode") && env.get("NODE_URL").is_empty() {
        return Err(format!(
            "MODE={mode} needs NODE_URL, this node's own URL, which matches it to its entry on the main server"
        ));
    }
    Ok(BootstrapConfig {
        database_url,
        redis_url: env.get("REDIS_URL").to_owned(),
        listen: format!(":{port}"),
        jf_listen: format!(":{jf_port}"),
        abs_listen: format!(":{abs_port}"),
        mode,
        secret_key: secret_key.as_bytes().to_vec(),
    })
}
