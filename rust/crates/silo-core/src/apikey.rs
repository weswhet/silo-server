//! Hashes stored next to credentials in `internal/auth`, `internal/notifications`,
//! `internal/autoscan`, and `internal/audiobooks`: the database holds the digest, never the secret.

use silo_gocompat::strings::{to_lower, to_upper, trim_space};

use crate::hexgo::{sha256, sha256_hex};
use crate::passwordhash::normalize_username;

/// How many leading characters of a minted key `api_keys.key_prefix` keeps.
pub const KEY_PREFIX_LEN: usize = 11;

/// `api_keys.key_hash`: `HashLinkToken` of the whole bearer.
pub fn api_key_hash(key: &[u8]) -> String {
    sha256_hex(key)
}

/// `api_keys.key_prefix` of a freshly minted key. Legacy keys of other shapes keep an empty prefix.
pub fn api_key_prefix(key: &str) -> &str {
    &key[..KEY_PREFIX_LEN]
}

/// `generateAPIKey`'s shape from 32 random bytes: `sa_` and 64 lowercase hex digits.
pub fn format_api_key(random: &[u8; 32]) -> String {
    format!("sa_{}", crate::hexgo::encode(random))
}

/// `auth.ValidTextKey`: a key Postgres can compare at all. Invalid UTF-8 or a NUL means not found, not
/// an outage.
pub fn valid_text_key(key: &[u8]) -> bool {
    std::str::from_utf8(key).is_ok() && !key.contains(&0)
}

/// `HashLinkToken`: invite, password reset, and every other link token.
pub fn hash_link_token(token: &[u8]) -> String {
    sha256_hex(token)
}

/// `hashDeviceLoginSecret`.
pub fn hash_device_login_secret(value: &[u8]) -> String {
    sha256_hex(value)
}

/// `normalizeUserCode`.
pub fn normalize_user_code(value: &str) -> String {
    to_upper(trim_space(value)).replace(['-', ' '], "")
}

/// `formatUserCode`: `NNNN-NNNN` for an eight-byte code. Like Go it cuts bytes, so eight bytes of
/// multi-byte text come back split mid-character.
pub fn format_user_code(value: &str) -> Vec<u8> {
    let value = normalize_user_code(value).into_bytes();
    if value.len() != 8 {
        return value;
    }
    let mut out = Vec::with_capacity(9);
    out.extend_from_slice(&value[..4]);
    out.push(b'-');
    out.extend_from_slice(&value[4..]);
    out
}

/// `auth.QuickConnectCode`: six digits derived one way from the secret, with no leading zero.
pub fn quick_connect_code(secret: &str) -> String {
    let sum = sha256(format!("silo-quick-connect-code:{}", trim_space(secret)));
    let n = u64::from_be_bytes(sum[..8].try_into().expect("8 bytes")) % 900_000;
    (100_000 + n).to_string()
}

/// `jellycompat.quickConnectSessionToken`.
pub fn quick_connect_session_token(secret: &str) -> String {
    let sum = sha256(format!("silo-quick-connect-session:{}", trim_space(secret)));
    crate::hexgo::encode(&sum[..16])
}

/// `signInAttemptKey`: the attempt-budget key of a sign-in name.
pub fn sign_in_attempt_key(name: &str) -> String {
    format!(
        "signin_name:{}",
        sha256_hex(to_lower(normalize_username(name)))
    )
}

/// `apnsTokenHash`: Apple tokens are lowercased and trimmed first.
pub fn apns_token_hash(token: &str) -> String {
    sha256_hex(to_lower(trim_space(token)))
}

/// `fcmTokenHash`: trimmed only.
pub fn fcm_token_hash(token: &str) -> String {
    sha256_hex(trim_space(token))
}

/// `hashEmailToken`.
pub fn hash_email_token(token: &[u8]) -> String {
    sha256_hex(token)
}

/// `hashWebhookToken`, the `secret_hash` lookup value of an autoscan webhook.
pub fn hash_webhook_token(token: &[u8]) -> String {
    sha256_hex(token)
}

/// `autoscan.webhookSecretSuffixLen`: how many trailing token characters are stored for display.
pub const WEBHOOK_SECRET_SUFFIX_LEN: usize = 6;

/// `absTokenHash`, over the token's JTI.
pub fn abs_token_hash(jti: &[u8]) -> String {
    sha256_hex(jti)
}

/// `deviceProfileTokenHash`.
pub fn device_profile_token_hash(token: &[u8]) -> String {
    sha256_hex(token)
}

/// `pushDigest`, used for `installation_key_hash` as well.
pub fn push_digest(value: &[u8]) -> String {
    sha256_hex(value)
}

/// The Apple push `intent_hash`, over Go's untagged struct field names. Only an exact replay of the
/// newest command matches the stored value.
pub fn apple_push_intent(
    user: i64,
    profile: &str,
    apns_token: &str,
    environment: &str,
    topic: &str,
    mode: &str,
) -> String {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Intent<'a> {
        user: i64,
        profile: &'a str,
        token_hash: String,
        environment: &'a str,
        topic: &'a str,
        mode: &'a str,
    }
    let payload = silo_gocompat::json::marshal(&Intent {
        user,
        profile,
        token_hash: apns_token_hash(apns_token),
        environment,
        topic,
        mode,
    })
    .unwrap_or_default();
    push_digest(&payload)
}

/// `androidPushIntent`.
pub fn android_push_intent(
    user: i64,
    profile: &str,
    fcm_token: &str,
    mode: &str,
    remove: bool,
) -> String {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Intent<'a> {
        user: i64,
        profile: &'a str,
        token_hash: String,
        mode: &'a str,
        remove: bool,
    }
    let payload = silo_gocompat::json::marshal(&Intent {
        user,
        profile,
        token_hash: fcm_token_hash(fcm_token),
        mode,
        remove,
    })
    .unwrap_or_default();
    push_digest(&payload)
}

/// `randomToken`: a base64url token of `size` random bytes.
pub fn mint_token(size: usize) -> Option<String> {
    let mut raw = vec![0u8; size];
    getrandom::getrandom(&mut raw).ok()?;
    Some(silo_jwt::base64go::raw_url_encode(raw))
}

/// `NewLinkToken`: the token and its stored digest.
pub fn mint_link_token() -> Option<(String, String)> {
    let token = mint_token(32)?;
    let hash = hash_link_token(token.as_bytes());
    Some((token, hash))
}

/// `generateAPIKey`.
pub fn mint_api_key() -> Option<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).ok()?;
    Some(format_api_key(&raw))
}

/// `randomUserCode`. Rejection sampling keeps every digit equally likely.
pub fn mint_user_code() -> Option<String> {
    let mut code = String::with_capacity(8);
    let mut buf = [0u8; 8];
    while code.len() < 8 {
        getrandom::getrandom(&mut buf).ok()?;
        for &b in &buf {
            if b >= 250 {
                continue;
            }
            code.push(char::from(b'0' + b % 10));
            if code.len() == 8 {
                break;
            }
        }
    }
    String::from_utf8(format_user_code(&code)).ok()
}

/// `randomQuickConnectSecret`: 32 random bytes as uppercase hex.
pub fn mint_quick_connect_secret() -> Option<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).ok()?;
    Some(to_upper(&crate::hexgo::encode(raw)))
}

/// The generated `auth.jwt_secret`: 32 random bytes in standard base64. Signing uses this text as its
/// key, never the decoded bytes.
pub fn mint_jwt_secret() -> Option<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).ok()?;
    Some(silo_jwt::base64go::std_encode(raw))
}
