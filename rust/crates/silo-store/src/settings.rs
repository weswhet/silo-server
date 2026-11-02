//! `internal/catalog/server_settings_repo.go` and `internal/catalog/encrypted_settings_repo.go`:
//! CRUD over the `server_settings` table, and the at-rest encryption decorator.
//!
//! Go keeps this code in the `catalog` package; the plan's crate table puts "Settings" in the
//! store crate, and the actual settings-contract and resolver code it named has since moved to
//! `silo-contracts`/`silo-config` (see those crates' public APIs). What is left unported anywhere
//! is this runtime CRUD, so it lives here.
//!
//! A deliberate simplification from Go: `acquireSettingsValueSlot` (a local in-process semaphore
//! that serializes same-key waiters before they each take a connection to queue on the Postgres
//! advisory lock) is not ported. The advisory lock alone still serializes writers correctly across
//! processes; the slot only reduces local connection pressure under contention. See
//! `go_defects`/`divergences` in the port report for this session.

use std::collections::HashMap;
use std::sync::Arc;

use silo_core::secret::{self, Cipher};
use silo_pg::{Error as PgError, Pool, Session};

/// The advisory lock name general `server_settings` mutations serialize on.
/// `config.ServerSettingsMutationLock`.
pub const SERVER_SETTINGS_MUTATION_LOCK: &str = "silo:server_settings:mutation";

/// `config.StorageTransitionTargetKey`.
pub const STORAGE_TRANSITION_TARGET_KEY: &str = "storage.transition.target";

/// An error from a settings operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("server_settings {op} {key:?}: {source}")]
    Query {
        op: &'static str,
        key: String,
        #[source]
        source: PgError,
    },
    #[error("server_settings {op}: {source}")]
    Batch {
        op: &'static str,
        #[source]
        source: PgError,
    },
    #[error("decrypt setting {key:?}: {source}")]
    Decrypt {
        key: String,
        #[source]
        source: secret::Error,
    },
    #[error("encrypt setting {key:?}: {source}")]
    Encrypt {
        key: String,
        #[source]
        source: secret::Error,
    },
    #[error("decrypt setting {key:?}: not valid UTF-8")]
    NotUtf8 { key: String },
}

type Result<T> = std::result::Result<T, Error>;

/// `catalog.ServerSettingsRepo`: raw CRUD access to the `server_settings` table. No encryption; see
/// [`EncryptedSettingsRepo`] for the decorator Go always wires in front of this in production.
#[derive(Clone)]
pub struct ServerSettingsRepo {
    pool: Arc<Pool>,
}

impl ServerSettingsRepo {
    /// `catalog.NewServerSettingsRepo`.
    pub fn new(pool: Arc<Pool>) -> Self {
        Self { pool }
    }

    /// `ServerSettingsRepo.Get`: empty string, not an error, when the key has no row.
    pub async fn get(&self, key: &str) -> Result<String> {
        let mut session = self.acquire("get", key).await?;
        get_value(&mut session, key).await
    }

    /// `ServerSettingsRepo.GetMany`: a batch read in one round trip, so a group `SetMany` wrote is
    /// seen whole or not at all. Keys without a row are absent from the map.
    pub async fn get_many(&self, keys: &[&str]) -> Result<HashMap<String, String>> {
        let mut session = self.acquire("get_many", "").await?;
        let rows = session
            .query(
                "SELECT key, value FROM server_settings WHERE key = ANY($1)",
                &[&keys],
            )
            .await
            .map_err(|source| Error::Batch {
                op: "get many",
                source,
            })?;
        let mut values = HashMap::with_capacity(rows.len());
        for row in rows {
            values.insert(row.get::<_, String>(0), row.get::<_, String>(1));
        }
        Ok(values)
    }

    /// `ServerSettingsRepo.Set`: upserts one setting inside a mutation transaction.
    pub async fn set(&self, key: &str, value: &str) -> Result<()> {
        self.set_many(&[(key, value)]).await
    }

    /// `ServerSettingsRepo.SetMany`: atomically upserts a related group of settings.
    pub async fn set_many(&self, values: &[(&str, &str)]) -> Result<()> {
        let mut session = self.acquire("set_many", "").await?;
        let mut tx = begin_mutation(&mut session).await?;
        upsert_values(&mut tx, values).await?;
        tx.commit().await.map_err(|source| Error::Batch {
            op: "commit mutation",
            source,
        })?;
        Ok(())
    }

    /// `ServerSettingsRepo.UpdateAtomic`: a read/validate/write mutation serialized across every
    /// process sharing the database. `update` sees the full current snapshot and returns the
    /// subset of values to write.
    pub async fn update_atomic<E>(
        &self,
        update: impl FnOnce(&HashMap<String, String>) -> std::result::Result<HashMap<String, String>, E>,
    ) -> std::result::Result<(), UpdateError<E>> {
        let mut session = self
            .acquire("update_atomic", "")
            .await
            .map_err(UpdateError::Store)?;
        let mut tx = begin_mutation(&mut session)
            .await
            .map_err(UpdateError::Store)?;
        let current = get_all(&mut tx).await.map_err(UpdateError::Store)?;
        let writes = update(&current).map_err(UpdateError::Update)?;
        let pairs: Vec<(&str, &str)> = writes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        upsert_values(&mut tx, &pairs)
            .await
            .map_err(UpdateError::Store)?;
        tx.commit().await.map_err(|source| {
            UpdateError::Store(Error::Batch {
                op: "commit mutation",
                source,
            })
        })?;
        Ok(())
    }

    /// `ServerSettingsRepo.SetIfAbsent`: inserts only when the key is absent or empty, reporting
    /// whether this call won the write. Used for single-writer generated credentials.
    pub async fn set_if_absent(&self, key: &str, value: &str) -> Result<bool> {
        let mut session = self.acquire("set_if_absent", key).await?;
        let mut tx = begin_mutation(&mut session).await?;
        let rows = tx
            .execute(
                "INSERT INTO server_settings (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                 WHERE server_settings.value = ''",
                &[&key, &value],
            )
            .await
            .map_err(|source| Error::Query {
                op: "set-if-absent",
                key: key.to_owned(),
                source,
            })?;
        tx.commit().await.map_err(|source| Error::Batch {
            op: "commit mutation",
            source,
        })?;
        Ok(rows > 0)
    }

    /// `ServerSettingsRepo.GetAll`.
    pub async fn get_all(&self) -> Result<HashMap<String, String>> {
        let mut session = self.acquire("get_all", "").await?;
        get_all(&mut session).await
    }

    async fn acquire(&self, op: &'static str, key: &str) -> Result<Session> {
        self.pool.acquire().await.map_err(|source| Error::Query {
            op,
            key: key.to_owned(),
            source,
        })
    }
}

async fn get_value(session: &mut Session, key: &str) -> Result<String> {
    match session
        .query_one("SELECT value FROM server_settings WHERE key = $1", &[&key])
        .await
    {
        Ok(row) => Ok(row.get::<_, String>(0)),
        Err(PgError::NoRows) => Ok(String::new()),
        Err(source) => Err(Error::Query {
            op: "get",
            key: key.to_owned(),
            source,
        }),
    }
}

async fn get_all(session: &mut Session) -> Result<HashMap<String, String>> {
    let rows = session
        .query("SELECT key, value FROM server_settings", &[])
        .await
        .map_err(|source| Error::Batch {
            op: "get all",
            source,
        })?;
    let mut settings = HashMap::with_capacity(rows.len());
    for row in rows {
        settings.insert(row.get::<_, String>(0), row.get::<_, String>(1));
    }
    Ok(settings)
}

async fn begin_mutation(session: &mut Session) -> Result<silo_pg::Tx<'_>> {
    let mut tx = session.begin().await.map_err(|source| Error::Batch {
        op: "begin mutation",
        source,
    })?;
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        &[&SERVER_SETTINGS_MUTATION_LOCK],
    )
    .await
    .map_err(|source| Error::Batch {
        op: "acquire mutation lock",
        source,
    })?;
    Ok(tx)
}

// upsertServerSettings: sorted key order, so two writers of the same batch always apply their
// per-key statements in the same order (matters only for lock-ordering and log reading, not for
// the result, since each is its own statement inside one transaction).
async fn upsert_values(tx: &mut silo_pg::Tx<'_>, values: &[(&str, &str)]) -> Result<()> {
    let mut sorted = values.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    for (key, value) in sorted {
        tx.execute(
            "INSERT INTO server_settings (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &[&key, &value],
        )
        .await
        .map_err(|source| Error::Query {
            op: "set",
            key: key.to_owned(),
            source,
        })?;
    }
    Ok(())
}

/// The error [`ServerSettingsRepo::update_atomic`] returns: either the store failed, or the
/// caller's validator did.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError<E> {
    #[error(transparent)]
    Store(#[from] Error),
    #[error(transparent)]
    Update(E),
}

/// `catalog.SensitiveSettingKeys`: the single source of truth for which `server_settings` keys
/// hold secrets. Copied verbatim from Go; see that file's comment for the audit trail. Adding a
/// key here is only safe when every reader goes through a cipher-aware path.
pub const SENSITIVE_SETTING_KEYS: &[&str] = &[
    "auth.jwt_secret",
    "audiobooks.abs.jwt_secret",
    "s3.public_access_key",
    "s3.public_secret_key",
    "s3.public_token_secret",
    "s3.private_access_key",
    "s3.private_secret_key",
    "s3.user_db_access_key",
    "s3.user_db_secret_key",
    "s3.operational_access_key",
    "s3.operational_secret_key",
    "s3.operational_token_secret",
    STORAGE_TRANSITION_TARGET_KEY,
    "redis.url",
    "redis.sentinel_password",
    "tmdb.api_key",
    "mdblist.api_key",
    "introdb.api_key",
    "ai.providers",
    "ai.chatgpt.credentials",
    "ai.api_key",
    "ai.asr_api_key",
    "subtitle_ai.api_key",
    "recommendations.embedding_auth_token",
    "recommendations.openai_api_key",
    "catalog.search.meilisearch.api_key",
    "watchsync.simkl.client_id",
    "watchsync.simkl.client_secret",
    "requests.radarr.api_key",
    "requests.sonarr.api_key",
    "email.smtp_password",
    "discord.client_secret",
    "discord.bot_token",
    "notifications.web_push.vapid_keypair",
    "notifications.push_relay_api_key",
];

fn is_sensitive(key: &str) -> bool {
    SENSITIVE_SETTING_KEYS.contains(&key)
}

/// `catalog.EncryptedSettingsRepo`: decorates a raw [`ServerSettingsRepo`], transparently
/// encrypting [`SENSITIVE_SETTING_KEYS`] on write and decrypting them on read. Every other
/// consumer keeps seeing plaintext while the values rest as ciphertext, GCM-bound to their key.
pub struct EncryptedSettingsRepo {
    inner: ServerSettingsRepo,
    cipher: Cipher,
}

impl EncryptedSettingsRepo {
    /// `catalog.NewEncryptedSettingsRepo`. `inner` must be the raw store, never another encrypted
    /// decorator, or writes would double-encrypt.
    pub fn new(inner: ServerSettingsRepo, cipher: Cipher) -> Self {
        Self { inner, cipher }
    }

    fn encrypt_if_sensitive(&self, key: &str, value: String) -> Result<String> {
        if is_sensitive(key) && !value.is_empty() {
            self.cipher
                .encrypt(&value, secret::aad::settings(key))
                .map_err(|source| Error::Encrypt {
                    key: key.to_owned(),
                    source,
                })
        } else {
            Ok(value)
        }
    }

    fn decrypt(&self, key: &str, value: String) -> Result<String> {
        let plain = self
            .cipher
            .decrypt_if_encrypted(&value, secret::aad::settings(key))
            .map_err(|source| Error::Decrypt {
                key: key.to_owned(),
                source,
            })?;
        String::from_utf8(plain).map_err(|_| Error::NotUtf8 {
            key: key.to_owned(),
        })
    }

    /// `EncryptedSettingsRepo.Set`.
    pub async fn set(&self, key: &str, value: &str) -> Result<()> {
        let stored = self.encrypt_if_sensitive(key, value.to_owned())?;
        self.inner.set(key, &stored).await
    }

    /// `EncryptedSettingsRepo.SetMany`.
    pub async fn set_many(&self, values: &[(&str, &str)]) -> Result<()> {
        let mut encrypted = Vec::with_capacity(values.len());
        for (key, value) in values {
            encrypted.push((*key, self.encrypt_if_sensitive(key, (*value).to_owned())?));
        }
        let pairs: Vec<(&str, &str)> = encrypted.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.inner.set_many(&pairs).await
    }

    /// `EncryptedSettingsRepo.UpdateAtomic`: the validator sees plaintext; only the returned
    /// writes are encrypted before they reach `server_settings`.
    pub async fn update_atomic<E>(
        &self,
        update: impl FnOnce(&HashMap<String, String>) -> std::result::Result<HashMap<String, String>, E>,
    ) -> std::result::Result<(), UpdateError<E>> {
        self.inner
            .update_atomic(|raw_current| {
                let mut current = HashMap::with_capacity(raw_current.len());
                for (key, value) in raw_current {
                    match self.decrypt(key, value.clone()) {
                        Ok(plain) => {
                            current.insert(key.clone(), plain);
                        }
                        Err(e) => return Err(DecryptOrUpdate::Decrypt(e)),
                    }
                }
                let writes = update(&current).map_err(DecryptOrUpdate::Update)?;
                let mut encrypted = HashMap::with_capacity(writes.len());
                for (key, value) in writes {
                    let stored = self
                        .encrypt_if_sensitive(&key, value)
                        .map_err(DecryptOrUpdate::Decrypt)?;
                    encrypted.insert(key, stored);
                }
                Ok(encrypted)
            })
            .await
            .map_err(|e| match e {
                UpdateError::Store(store) => UpdateError::Store(store),
                UpdateError::Update(DecryptOrUpdate::Decrypt(err)) => UpdateError::Store(err),
                UpdateError::Update(DecryptOrUpdate::Update(err)) => UpdateError::Update(err),
            })
    }

    /// `EncryptedSettingsRepo.SetIfAbsent`.
    pub async fn set_if_absent(&self, key: &str, value: &str) -> Result<bool> {
        let stored = self.encrypt_if_sensitive(key, value.to_owned())?;
        self.inner.set_if_absent(key, &stored).await
    }

    /// `EncryptedSettingsRepo.Get`: legacy plaintext passes through; an `enc:v1:` value is
    /// decrypted; a corrupt ciphertext errors.
    pub async fn get(&self, key: &str) -> Result<String> {
        let raw = self.inner.get(key).await?;
        self.decrypt(key, raw)
    }

    /// `EncryptedSettingsRepo.GetMany`.
    pub async fn get_many(&self, keys: &[&str]) -> Result<HashMap<String, String>> {
        let raw = self.inner.get_many(keys).await?;
        let mut out = HashMap::with_capacity(raw.len());
        for (key, value) in raw {
            out.insert(key.clone(), self.decrypt(&key, value)?);
        }
        Ok(out)
    }

    /// `EncryptedSettingsRepo.GetAll`: an unreadable storage-transition receipt is omitted rather
    /// than failing the whole read; any other unreadable value is still fatal.
    pub async fn get_all(&self) -> Result<HashMap<String, String>> {
        let raw = self.inner.get_all().await?;
        let mut out = HashMap::with_capacity(raw.len());
        for (key, value) in raw {
            match self.decrypt(&key, value) {
                Ok(plain) => {
                    out.insert(key, plain);
                }
                Err(err) if key == STORAGE_TRANSITION_TARGET_KEY => {
                    tracing::warn!(
                        component = "silo_store::settings",
                        error = %err,
                        "omitting an unreadable storage transition target from the snapshot"
                    );
                }
                Err(err) => return Err(err),
            }
        }
        Ok(out)
    }

    /// `EncryptedSettingsRepo.BackfillSensitiveSettings`: encrypts any plaintext value currently
    /// stored under a sensitive key. Idempotent and best-effort: a per-key failure is collected
    /// but does not abort the sweep. Returns the number of keys newly encrypted.
    pub async fn backfill_sensitive_settings(&self) -> (usize, Vec<Error>) {
        let mut keys: Vec<&str> = SENSITIVE_SETTING_KEYS.to_vec();
        keys.sort_unstable();
        let mut encrypted = 0usize;
        let mut errors = Vec::new();
        for key in keys {
            let raw = match self.inner.get(key).await {
                Ok(v) => v,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };
            if raw.is_empty() || secret::is_encrypted(&raw) {
                continue;
            }
            let ct = match self.cipher.encrypt(&raw, secret::aad::settings(key)) {
                Ok(v) => v,
                Err(source) => {
                    errors.push(Error::Encrypt {
                        key: key.to_owned(),
                        source,
                    });
                    continue;
                }
            };
            if let Err(e) = self.inner.set(key, &ct).await {
                errors.push(e);
                continue;
            }
            encrypted += 1;
        }
        (encrypted, errors)
    }
}

enum DecryptOrUpdate<E> {
    Decrypt(Error),
    Update(E),
}
