//! `internal/secret`: AES-256-GCM at rest, in the `enc:v1:` envelope.
//!
//! The data key is HKDF-SHA256 of the raw `SECRET_KEY` with no salt. Every ciphertext is GCM-bound to
//! its logical row through additional authenticated data, so renaming a settings row or moving a
//! credential to another row makes it undecryptable. The AAD builders below are the same strings
//! the Go repositories use.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use silo_jwt::base64go::{raw_url_decode, raw_url_encode};

use crate::hexgo::hkdf_sha256;

const ENVELOPE_PREFIX: &str = "enc:v1:";
const HKDF_INFO: &[u8] = b"silo/data-encryption/v1";
const NONCE_SIZE: usize = 12;

/// The minimum `SECRET_KEY` length in bytes.
pub const MIN_MASTER_KEY_LEN: usize = 32;

/// A secret operation that failed. No variant carries key or plaintext material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MasterKeyTooShort(usize),
    NotAnEnvelope,
    /// `ErrUnknownVersion`: an `enc:vN:` this build does not understand.
    UnknownVersion(String),
    Decode,
    TooShort,
    /// Wrong key, tampering, or an AAD mismatch.
    Authenticate,
    Random,
    /// A plugin state or config wrapper that does not have the expected shape.
    InvalidWrapper(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MasterKeyTooShort(n) => write!(
                f,
                "secret: master key must be at least {MIN_MASTER_KEY_LEN} bytes, got {n}"
            ),
            Self::NotAnEnvelope => f.write_str("secret: not an enc envelope"),
            Self::UnknownVersion(v) => write!(f, "secret: unknown ciphertext version: {v:?}"),
            Self::Decode => f.write_str("secret: decode ciphertext"),
            Self::TooShort => f.write_str("secret: ciphertext too short"),
            Self::Authenticate => f.write_str("secret: authenticate ciphertext"),
            Self::Random => f.write_str("secret: read nonce"),
            Self::InvalidWrapper(m) => write!(f, "secret: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// `secret.Cipher`. Plaintext and AAD are bytes because Go's are arbitrary `string`s.
#[derive(Clone)]
pub struct Cipher {
    gcm: Aes256Gcm,
}

impl Cipher {
    /// `secret.New`.
    pub fn new(master_key: &[u8]) -> Result<Self, Error> {
        if master_key.len() < MIN_MASTER_KEY_LEN {
            return Err(Error::MasterKeyTooShort(master_key.len()));
        }
        let mut data_key = [0u8; 32];
        hkdf_sha256(master_key, HKDF_INFO, &mut data_key);
        let gcm = Aes256Gcm::new_from_slice(&data_key).expect("32 bytes is an AES-256 key");
        Ok(Self { gcm })
    }

    /// `Cipher.Encrypt`. Empty plaintext stays an empty column value and is never wrapped.
    pub fn encrypt(
        &self,
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<String, Error> {
        let plaintext = plaintext.as_ref();
        if plaintext.is_empty() {
            return Ok(String::new());
        }
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Random)?;
        self.seal(&nonce, plaintext, aad.as_ref())
    }

    /// The seal step of `encrypt` with a chosen nonce. Only a differential test has a reason to
    /// choose one: reusing a nonce under this key breaks GCM.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<String, Error> {
        let sealed = self
            .gcm
            .encrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Authenticate)?;
        let mut body = Vec::with_capacity(NONCE_SIZE + sealed.len());
        body.extend_from_slice(nonce);
        body.extend_from_slice(&sealed);
        Ok(format!("{ENVELOPE_PREFIX}{}", raw_url_encode(body)))
    }

    /// `Cipher.Decrypt`. It never returns the ciphertext or an empty string on failure; passing legacy
    /// plaintext through is what [`Self::decrypt_if_encrypted`] is for.
    pub fn decrypt(
        &self,
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut parts = ciphertext.as_ref().splitn(3, |b| *b == b':');
        let (Some(scheme), Some(version), Some(body)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::NotAnEnvelope);
        };
        if scheme != b"enc" {
            return Err(Error::NotAnEnvelope);
        }
        if version != b"v1" {
            return Err(Error::UnknownVersion(
                String::from_utf8_lossy(version).into_owned(),
            ));
        }
        let sealed = raw_url_decode(body).map_err(|_| Error::Decode)?;
        if sealed.len() < NONCE_SIZE {
            return Err(Error::TooShort);
        }
        let (nonce, body) = sealed.split_at(NONCE_SIZE);
        let nonce: [u8; NONCE_SIZE] = nonce.try_into().map_err(|_| Error::TooShort)?;
        self.gcm
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: body,
                    aad: aad.as_ref(),
                },
            )
            .map_err(|_| Error::Authenticate)
    }

    /// `Cipher.DecryptIfEncrypted`, the read-path contract: empty stays empty, a value without the
    /// envelope is legacy plaintext, and a failed `enc:v1:` value is an error, never a credential.
    pub fn decrypt_if_encrypted(
        &self,
        value: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let value = value.as_ref();
        if value.is_empty() || !is_encrypted(value) {
            return Ok(value.to_vec());
        }
        self.decrypt(value, aad)
    }

    /// `Cipher.EncryptIfPlaintext`: `(value, changed)`, never double-encrypting.
    pub fn encrypt_if_plaintext(
        &self,
        value: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<(Vec<u8>, bool), Error> {
        let value = value.as_ref();
        if value.is_empty() || is_encrypted(value) {
            return Ok((value.to_vec(), false));
        }
        Ok((self.encrypt(value, aad)?.into_bytes(), true))
    }
}

/// `secret.IsEncrypted`: a prefix check, not a validity check.
pub fn is_encrypted(value: impl AsRef<[u8]>) -> bool {
    value.as_ref().starts_with(ENVELOPE_PREFIX.as_bytes())
}

/// `secret.BackfillTarget`: one literal-credential column the startup backfill sweeps in place. The SQL
/// expressions are compile-time constants and must match the read path's AAD exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackfillTarget {
    pub table: &'static str,
    pub column: &'static str,
    /// The row's stable update key, rendered to text.
    pub key_expr: &'static str,
    /// The AAD's primary-key part.
    pub aad_expr: &'static str,
}

/// `secret.ColumnBackfillTargets`.
pub const COLUMN_BACKFILL_TARGETS: [BackfillTarget; 10] = {
    const WATCH_TUPLE: &str = "provider || ':' || user_id::text || ':' || profile_id";
    const fn target(
        table: &'static str,
        column: &'static str,
        key_expr: &'static str,
        aad_expr: &'static str,
    ) -> BackfillTarget {
        BackfillTarget {
            table,
            column,
            key_expr,
            aad_expr,
        }
    }
    [
        target(
            "subtitle_provider_config",
            "api_key",
            "provider_name",
            "provider_name",
        ),
        target(
            "subtitle_provider_config",
            "password",
            "provider_name",
            "provider_name",
        ),
        target(
            "watch_provider_connections",
            "access_token",
            "id::text",
            WATCH_TUPLE,
        ),
        target(
            "watch_provider_connections",
            "refresh_token",
            "id::text",
            WATCH_TUPLE,
        ),
        target(
            "webhook_sync_connections",
            "access_token",
            "id::text",
            "id::text",
        ),
        target(
            "history_import_sources",
            "admin_token",
            "id::text",
            "id::text",
        ),
        target(
            "history_import_connect_sessions",
            "connect_access_token",
            "id::text",
            "id::text",
        ),
        target(
            "history_import_plex_sessions",
            "auth_token",
            "id::text",
            "id::text",
        ),
        target(
            "jellycompat_sessions",
            "streamapp_access_token",
            "token",
            "token",
        ),
        target(
            "jellycompat_sessions",
            "streamapp_refresh_token",
            "token",
            "token",
        ),
    ]
};

const INSTANCE_STATE_EMPTY_MARKER: &str = "empty:v1:";
const ENCRYPTED_RUNTIME_CONFIG_FIELD: &str = "__silo_encrypted_runtime_config_v1";

/// `InstanceStateStore.seal`: an empty value is an authenticated marker, because `encrypt` leaves
/// empty plaintext unwrapped.
pub fn seal_instance_state(
    cipher: &Cipher,
    installation_id: i64,
    scope: &str,
    key: &str,
    value: &[u8],
) -> Result<Vec<u8>, Error> {
    let aad = aad::plugin_instance_state(installation_id, scope, key);
    if value.is_empty() {
        let ciphertext = cipher.encrypt(b"empty", format!("{INSTANCE_STATE_EMPTY_MARKER}{aad}"))?;
        return Ok(format!("{INSTANCE_STATE_EMPTY_MARKER}{ciphertext}").into_bytes());
    }
    Ok(cipher.encrypt(value, aad)?.into_bytes())
}

/// `InstanceStateStore.open`.
pub fn open_instance_state(
    cipher: &Cipher,
    installation_id: i64,
    scope: &str,
    key: &str,
    stored: &[u8],
) -> Result<Vec<u8>, Error> {
    let aad = aad::plugin_instance_state(installation_id, scope, key);
    if let Some(ciphertext) = stored.strip_prefix(INSTANCE_STATE_EMPTY_MARKER.as_bytes()) {
        let plaintext =
            cipher.decrypt(ciphertext, format!("{INSTANCE_STATE_EMPTY_MARKER}{aad}"))?;
        if plaintext != b"empty" {
            return Err(Error::InvalidWrapper(
                "invalid empty plugin instance state marker",
            ));
        }
        return Ok(Vec::new());
    }
    if !is_encrypted(stored) {
        return Err(Error::InvalidWrapper(
            "plugin instance state row is not an encrypted envelope",
        ));
    }
    cipher.decrypt(stored, aad)
}

/// `encodeRuntimeConfigJSON` with a cipher: `{"__silo_encrypted_runtime_config_v1":"enc:v1:..."}`.
pub fn seal_runtime_config(
    cipher: &Cipher,
    installation_id: i64,
    key: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if !silo_gocompat::json::valid(plaintext) {
        return Err(Error::InvalidWrapper(
            "plugin runtime config is not valid JSON",
        ));
    }
    let ciphertext = cipher.encrypt(plaintext, aad::plugin_runtime_config(installation_id, key))?;
    let mut wrapped = std::collections::BTreeMap::new();
    wrapped.insert(ENCRYPTED_RUNTIME_CONFIG_FIELD, ciphertext);
    silo_gocompat::json::marshal(&wrapped)
        .map_err(|_| Error::InvalidWrapper("marshaling encrypted plugin runtime config"))
}

/// The unwrap step of `decodeRuntimeConfigValue`. A stored object with exactly the one wrapper key is
/// decrypted; any other JSON object is legacy plaintext and comes back unchanged. The caller decodes
/// the returned JSON and must keep number text intact.
pub fn open_runtime_config(
    cipher: &Cipher,
    installation_id: i64,
    key: &str,
    stored: &[u8],
) -> Result<Vec<u8>, Error> {
    if stored.is_empty() {
        return Ok(b"{}".to_vec());
    }
    let parsed = silo_jwt::gojson::parse_value(stored)
        .map_err(|_| Error::InvalidWrapper("unmarshaling plugin runtime config"))?;
    match &parsed {
        serde_json::Value::Object(map) => {
            if map.len() == 1
                && let Some(raw) = map.get(ENCRYPTED_RUNTIME_CONFIG_FIELD)
            {
                let Some(ciphertext) = raw.as_str().filter(|c| is_encrypted(c)) else {
                    return Err(Error::InvalidWrapper(
                        "invalid encrypted plugin runtime config envelope",
                    ));
                };
                return cipher
                    .decrypt(ciphertext, aad::plugin_runtime_config(installation_id, key));
            }
            Ok(stored.to_vec())
        }
        serde_json::Value::Null => Ok(stored.to_vec()),
        _ => Err(Error::InvalidWrapper("unmarshaling plugin runtime config")),
    }
}

/// The AAD strings. Read and write sites must agree byte for byte.
pub mod aad {
    /// `secret.SettingsAAD`.
    pub fn settings(key: &str) -> String {
        format!("server_settings:{key}")
    }

    /// `secret.RowAAD`.
    pub fn row(table: &str, column: &str, pk: &str) -> String {
        format!("{table}:{column}:{pk}")
    }

    /// `jellycompatTokenAAD`, with column `streamapp_access_token` or `streamapp_refresh_token`.
    pub fn jellycompat_token(column: &str, token: &str) -> String {
        row("jellycompat_sessions", column, token)
    }

    /// `webhookTokenAAD`.
    pub fn webhook_sync_token(id: &str) -> String {
        row("webhook_sync_connections", "access_token", id)
    }

    /// `autoscan.webhookSecretAAD`.
    pub fn autoscan_webhook_secret(source_id: &str) -> String {
        row("autoscan_webhook_endpoints", "secret_ref", source_id)
    }

    /// `connectionAPIKeyAAD`.
    pub fn autoscan_connection_api_key(id: &str) -> String {
        row("autoscan_connections", "api_key_ref", id)
    }

    /// `requests.apiKeyAAD`.
    pub fn request_integration_api_key(id: &str) -> String {
        row("request_integrations", "api_key_ref", id)
    }

    /// `refreshStateAAD`.
    pub fn plugin_auth_refresh_state(identity_id: i64) -> String {
        row(
            "plugin_auth_identities",
            "refresh_state",
            &identity_id.to_string(),
        )
    }

    /// `sourceAdminTokenAAD`.
    pub fn history_import_source_admin_token(source_id: i64) -> String {
        row(
            "history_import_sources",
            "admin_token",
            &source_id.to_string(),
        )
    }

    /// `connectSessionTokenAAD`.
    pub fn history_import_connect_session(session_id: &str) -> String {
        row(
            "history_import_connect_sessions",
            "connect_access_token",
            session_id,
        )
    }

    /// `connectServerAccessKeyAAD`.
    pub fn history_import_connect_server(session_id: &str, index: i64, server_id: &str) -> String {
        row(
            "history_import_connect_sessions",
            "servers_json.access_key",
            &format!("{session_id}:{index}:{server_id}"),
        )
    }

    /// `plexSessionTokenAAD`.
    pub fn history_import_plex_session(session_id: &str) -> String {
        row("history_import_plex_sessions", "auth_token", session_id)
    }

    /// `plexServerAccessTokenAAD`.
    pub fn history_import_plex_server(
        session_id: &str,
        index: i64,
        client_identifier: &str,
    ) -> String {
        row(
            "history_import_plex_sessions",
            "servers_json.access_token",
            &format!("{session_id}:{index}:{client_identifier}"),
        )
    }

    /// `personalCredentialAAD`.
    pub fn history_import_run_credential(run_id: &str) -> String {
        row("history_import_run_credentials", "payload", run_id)
    }

    /// `watchsync.TokenAAD`, with column `access_token`, `refresh_token`, or `plugin_credentials`.
    pub fn watch_provider_token(
        column: &str,
        provider: &str,
        user_id: i64,
        profile_id: &str,
    ) -> String {
        row(
            "watch_provider_connections",
            column,
            &format!("{provider}:{user_id}:{profile_id}"),
        )
    }

    /// `authStateAAD`.
    pub fn watch_provider_auth_state(provider: &str, user_id: i64, profile_id: &str) -> String {
        row(
            "watch_provider_auth_sessions",
            "device_code",
            &format!("{provider}:{user_id}:{profile_id}"),
        )
    }

    /// `providerSecretAAD`, with column `api_key` or `password`.
    pub fn subtitle_provider_secret(column: &str, provider_name: &str) -> String {
        row("subtitle_provider_config", column, provider_name)
    }

    /// `pushDeviceAPNsTokenAAD`.
    pub fn push_device_apns(id: &str) -> String {
        row("push_devices", "apns_token", id)
    }

    /// `pushDeviceFCMTokenAAD`.
    pub fn push_device_fcm(id: &str) -> String {
        row("push_devices", "fcm_token", id)
    }

    /// `runtimeConfigAAD`.
    pub fn plugin_runtime_config(installation_id: i64, key: &str) -> String {
        row(
            "plugin_runtime_configs",
            "config_value",
            &format!("{installation_id}:{key}"),
        )
    }

    /// `instanceStateAAD`.
    pub fn plugin_instance_state(installation_id: i64, scope: &str, key: &str) -> String {
        row(
            "plugin_instance_state",
            "state_value",
            &format!("{installation_id}:{scope}:{key}"),
        )
    }

    /// `notifications.webhookURLAAD`.
    pub fn notification_webhook_url(id: &str) -> String {
        format!("notification_webhook:{id}:url")
    }

    /// `notifications.webhookSecretAAD`.
    pub fn notification_webhook_secret(id: &str) -> String {
        format!("notification_webhook:{id}:signing_secret")
    }

    /// `serverChannelURLAAD`.
    pub fn server_channel_url(id: &str) -> String {
        format!("server_channel:{id}:url")
    }

    /// `serverChannelSecretAAD`.
    pub fn server_channel_secret(id: &str) -> String {
        format!("server_channel:{id}:signing_secret")
    }

    /// `emailVerificationAAD`.
    pub fn email_verification(id: &str) -> String {
        format!("notification-email-verification:{id}")
    }

    /// `pendingLinkAAD`, under the OAuth completion cipher rather than `enc:v1`.
    pub fn oauth_pending_link(code_hash: &str) -> String {
        format!("oauth_pending_links:{code_hash}")
    }
}
