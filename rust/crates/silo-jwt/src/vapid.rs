//! VAPID authorization headers, as `webpush-go`'s `getVAPIDAuthorizationHeader` builds them.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde::Serialize;

use crate::base64go::{raw_url_decode, raw_url_encode, url_decode};
use crate::{Error, signing_string};

/// The claims webpush-go signs. Go encodes them from a map, so the keys are sorted.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VapidClaims {
    pub aud: String,
    pub exp: i64,
    pub sub: String,
}

/// A malformed key or endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VapidError {
    InvalidKey,
    InvalidEndpoint,
    Sign(String),
}

impl std::fmt::Display for VapidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("invalid VAPID key"),
            Self::InvalidEndpoint => f.write_str("invalid push endpoint"),
            Self::Sign(m) => write!(f, "signing VAPID token: {m}"),
        }
    }
}

impl std::error::Error for VapidError {}

impl From<Error> for VapidError {
    fn from(e: Error) -> Self {
        Self::Sign(e.to_string())
    }
}

/// The stored `{public, private}` pair, as the two base64 strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VapidKeys {
    pub public: String,
    pub private: String,
}

/// `decodeVapidKey`: padded base64url first, then raw.
pub fn decode_vapid_key(key: &str) -> Result<Vec<u8>, VapidError> {
    url_decode(key)
        .or_else(|_| raw_url_decode(key))
        .map_err(|_| VapidError::InvalidKey)
}

/// webpush-go treats a subscriber that is not an `https:` URL as an email address.
pub fn vapid_subscriber(subscriber: &str) -> String {
    if subscriber.starts_with("https:") {
        subscriber.to_owned()
    } else {
        format!("mailto:{subscriber}")
    }
}

/// `subURL.Scheme + "://" + subURL.Host` for a push service endpoint, which is always an absolute
/// `https` URL. Anything else is refused here rather than given `url.Parse`'s reading of it.
pub fn scheme_host(endpoint: &str) -> Result<String, VapidError> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or(VapidError::InvalidEndpoint)?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return Err(VapidError::InvalidEndpoint);
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    if host.is_empty() {
        return Err(VapidError::InvalidEndpoint);
    }
    Ok(format!(
        "{}://{}",
        silo_gocompat::strings::to_lower(scheme),
        host
    ))
}

/// `vapid t=<jwt>, k=<public key>` for one push request. `exp_unix` is the token's expiry, which
/// webpush-go sets twelve hours ahead.
pub fn vapid_authorization_header(
    endpoint: &str,
    subscriber: &str,
    keys: &VapidKeys,
    exp_unix: i64,
) -> Result<String, VapidError> {
    let claims = VapidClaims {
        aud: scheme_host(endpoint)?,
        exp: exp_unix,
        sub: vapid_subscriber(subscriber),
    };
    let private = decode_vapid_key(&keys.private)?;
    let signing = SigningKey::from_slice(&private).map_err(|_| VapidError::InvalidKey)?;
    let text = signing_string("ES256", &claims)?;
    let signature: Signature = signing.sign(text.as_bytes());
    let public = decode_vapid_key(&keys.public)?;
    Ok(format!(
        "vapid t={text}.{}, k={}",
        raw_url_encode(signature.to_bytes()),
        raw_url_encode(public)
    ))
}
