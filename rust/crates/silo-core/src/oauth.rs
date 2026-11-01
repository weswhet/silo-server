//! `internal/auth`'s OAuth formats: the signed `state`, binder cookies, PKCE, and the completion AEAD,
//! which is not the `enc:v1` cipher.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use silo_gocompat::time::GoTime;
use silo_jwt::base64go::{raw_url_decode, raw_url_encode};
use silo_jwt::gojson::{self, value};

use crate::hexgo::{ct_eq, encode as hex_encode, hmac_sha256, sha256, sha256_hex};

const BINDER_COOKIE_PREFIX: &str = "silo_oauth_";
const COMPLETION_DEFAULT_MATERIAL: &[u8] = b"silo-oauth-completion-default";

/// `auth.DeriveOAuthStateSecret`.
pub fn derive_state_secret(jwt_secret: &[u8]) -> [u8; 32] {
    hmac_sha256(jwt_secret, &[b"silo/oauth-state-v1"])
}

/// `auth.StatePayload`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatePayload {
    #[serde(rename = "n", default)]
    pub nonce: String,
    #[serde(rename = "i", default)]
    pub install_id: String,
    #[serde(rename = "e", default = "zero_time")]
    pub expires_at: GoTime,
}

fn zero_time() -> GoTime {
    GoTime::ZERO
}

/// `VerifyState` failures. [`StateError::Expired`] carries the authentic payload, so the callback can
/// still answer the flow's own client.
#[derive(Debug, Clone, PartialEq)]
pub enum StateError {
    Malformed,
    SignatureMismatch,
    Decode,
    Expired(StatePayload),
}

/// `auth.SignState`.
pub fn sign_state(secret: &[u8], payload: &StatePayload) -> String {
    let body = silo_gocompat::json::marshal(payload).unwrap_or_default();
    let body_b64 = raw_url_encode(body);
    let sig = raw_url_encode(hmac_sha256(secret, &[body_b64.as_bytes()]));
    format!("{body_b64}.{sig}")
}

/// `auth.VerifyState` at a given time.
pub fn verify_state(secret: &[u8], signed: &str, now: GoTime) -> Result<StatePayload, StateError> {
    let (body_b64, sig_b64) = signed.split_once('.').ok_or(StateError::Malformed)?;
    let expected = raw_url_encode(hmac_sha256(secret, &[body_b64.as_bytes()]));
    if !ct_eq(sig_b64.as_bytes(), expected.as_bytes()) {
        return Err(StateError::SignatureMismatch);
    }
    let body = raw_url_decode(body_b64).map_err(|_| StateError::Decode)?;
    static FIELDS: [gojson::Field; 3] = [value("n"), value("i"), value("e")];
    let payload: StatePayload = gojson::unmarshal::<PayloadOrZero>(&body, &FIELDS)
        .map_err(|_| StateError::Decode)?
        .0;
    let expires = payload.expires_at;
    let after = (now.unix(), now.nanosecond()) > (expires.unix(), expires.nanosecond());
    if after {
        return Err(StateError::Expired(payload));
    }
    Ok(payload)
}

/// A `StatePayload` that decodes to Go's zero value for `null`.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct PayloadOrZero(StatePayload);

impl Default for PayloadOrZero {
    fn default() -> Self {
        Self(StatePayload {
            nonce: String::new(),
            install_id: String::new(),
            expires_at: GoTime::ZERO,
        })
    }
}

/// `oauthBinderHash`.
pub fn binder_hash(value: &[u8]) -> String {
    sha256_hex(value)
}

/// `OAuthBinderCookieName`.
pub fn binder_cookie_name(state: &[u8]) -> String {
    format!("{BINDER_COOKIE_PREFIX}{}", hex_encode(&sha256(state)[..8]))
}

/// `PKCEChallengeS256`.
pub fn pkce_challenge_s256(verifier: &[u8]) -> String {
    raw_url_encode(sha256(verifier))
}

/// `oauthCompletionCodeHash`.
pub fn completion_code_hash(code: &[u8]) -> String {
    sha256_hex(code)
}

/// The completion cipher of `PGOAuthStore`. It stores `base64url(nonce || sealed)` with no prefix.
pub struct CompletionCipher {
    gcm: Aes256Gcm,
}

impl CompletionCipher {
    /// `NewPGOAuthStore`. `material` is the derived OAuth state secret; empty material falls back to a
    /// fixed value, which `cmd/silo/main.go` uses only for cleanup.
    pub fn new(material: &[u8]) -> Self {
        let material = if material.is_empty() {
            COMPLETION_DEFAULT_MATERIAL
        } else {
            material
        };
        let mut preimage = b"silo/oauth-completion/v1:".to_vec();
        preimage.extend_from_slice(material);
        let key = sha256(preimage);
        Self {
            gcm: Aes256Gcm::new_from_slice(&key).expect("32 bytes"),
        }
    }

    /// `PGOAuthStore.seal`.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Option<String> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).ok()?;
        self.seal_with_nonce(&nonce, plaintext, aad)
    }

    /// `seal` with a chosen nonce, for differential tests. Never reuse a nonce under this key.
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Option<String> {
        let sealed = self
            .gcm
            .encrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .ok()?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        Some(raw_url_encode(out))
    }

    /// `PGOAuthStore.open`.
    pub fn open(&self, ciphertext: &str, aad: &[u8]) -> Option<Vec<u8>> {
        let sealed = raw_url_decode(ciphertext).ok()?;
        if sealed.len() < 12 {
            return None;
        }
        let (nonce, body) = sealed.split_at(12);
        let nonce: [u8; 12] = nonce.try_into().ok()?;
        self.gcm
            .decrypt(&Nonce::from(nonce), Payload { msg: body, aad })
            .ok()
    }
}
