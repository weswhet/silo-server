//! JWTs with the semantics of `github.com/golang-jwt/jwt/v5`, which every Silo token passes through.
//!
//! The rules a generic JWT crate gets wrong for Silo:
//!
//! - `exp` is optional unless a verifier requires it, there is no leeway, and a token is valid only
//!   while `now < exp`. `nbf` is checked when present, `iat` never.
//! - A verifier chooses its own algorithm set. Most of Silo's accept any HMAC algorithm; the
//!   newer ones accept exactly HS256.
//! - Claims decode through `encoding/json`, so keys match case-insensitively, unknown keys are ignored,
//!   and invalid UTF-8 becomes U+FFFD. See [`gojson`].
//! - Claims encode through `encoding/json`, so the signed bytes match Go's for the same claims.
//!
//! RS256 verifies the ChatGPT identity token (`internal/ai/chatgpt`). ES256 signs VAPID headers for web
//! push, matching `webpush-go`.

pub mod base64go;
pub mod gojson;
mod vapid;

use hmac::{Hmac, Mac};
use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
use rsa::signature::Verifier as _;
use serde::de::{self, DeserializeOwned, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Sha256, Sha384, Sha512};
use silo_gocompat::json;

use base64go::{raw_url_decode, raw_url_encode};
use gojson::{Field, Normalized, pointer, value};

pub use rsa::{BigUint, RsaPublicKey};
pub use vapid::{
    VapidClaims, VapidError, VapidKeys, decode_vapid_key, scheme_host, vapid_authorization_header,
    vapid_subscriber,
};

/// The current time in Unix nanoseconds, which is what `time.Now()` compares in Go.
pub fn now_unix_nanos() -> i128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

/// A whole-second `NumericDate`.
///
/// Decoding follows `newNumericDateFromSeconds`: the JSON number goes through `float64` and the result
/// is truncated toward the start of time. A numeric string is accepted too, because Go decodes this
/// field through `json.Number`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NumericDate(pub i64);

impl NumericDate {
    fn from_f64(f: f64) -> Self {
        let round = f.trunc();
        let frac = f - round;
        let nanos = (frac * 1e9) as i64;
        let secs = round as i64;
        Self(if nanos < 0 {
            secs.saturating_sub(1)
        } else {
            secs
        })
    }
}

impl Serialize for NumericDate {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for NumericDate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct DateVisitor;
        impl Visitor<'_> for DateVisitor {
            type Value = NumericDate;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON number")
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<NumericDate, E> {
                Ok(NumericDate::from_f64(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<NumericDate, E> {
                Ok(NumericDate::from_f64(v as f64))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<NumericDate, E> {
                Ok(NumericDate::from_f64(v as f64))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<NumericDate, E> {
                if !silo_gocompat::json::valid(v.as_bytes())
                    || !v
                        .bytes()
                        .next()
                        .is_some_and(|b| b == b'-' || b.is_ascii_digit())
                {
                    return Err(E::custom("invalid number literal"));
                }
                let parsed: f64 = v.parse().map_err(|_| E::custom("number out of range"))?;
                if parsed.is_infinite() {
                    return Err(E::custom("number out of range"));
                }
                Ok(NumericDate::from_f64(parsed))
            }
        }
        d.deserialize_any(DateVisitor)
    }
}

/// `jwt.ClaimStrings`: decodes from one string or an array of strings, always encodes as an array.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Audience(pub Vec<String>);

impl Audience {
    /// Whether the claim is empty, which `omitempty` drops.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for Audience {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct AudVisitor;
        impl<'de> Visitor<'de> for AudVisitor {
            type Value = Audience;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string or an array of strings")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Audience, E> {
                Ok(Audience(vec![v.to_owned()]))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Audience, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element::<String>()? {
                    out.push(item);
                }
                Ok(Audience(out))
            }
        }
        d.deserialize_any(AudVisitor)
    }
}

/// `jwt.RegisteredClaims`, in Go's field order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegisteredClaims {
    #[serde(rename = "iss", skip_serializing_if = "String::is_empty")]
    pub issuer: String,
    #[serde(rename = "sub", skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(rename = "aud", skip_serializing_if = "Audience::is_empty")]
    pub audience: Audience,
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NumericDate>,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<NumericDate>,
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<NumericDate>,
    #[serde(rename = "jti", skip_serializing_if = "String::is_empty")]
    pub id: String,
}

/// The field table of [`RegisteredClaims`], for a claims type that embeds it.
pub const REGISTERED_FIELDS: [Field; 7] = [
    value("iss"),
    value("sub"),
    value("aud"),
    pointer("exp"),
    pointer("nbf"),
    pointer("iat"),
    value("jti"),
];

/// A claims struct: what `jwt.Claims` asks for, plus its field table for decoding.
pub trait Claims: Serialize + DeserializeOwned + Default {
    /// Every JSON-visible field, embedded ones included.
    fn fields() -> &'static [Field];
    fn exp(&self) -> Option<NumericDate>;
    fn nbf(&self) -> Option<NumericDate>;
    fn iss(&self) -> &str {
        ""
    }
    fn aud(&self) -> &[String] {
        &[]
    }
}

impl Claims for RegisteredClaims {
    fn fields() -> &'static [Field] {
        &REGISTERED_FIELDS
    }
    fn exp(&self) -> Option<NumericDate> {
        self.expires_at
    }
    fn nbf(&self) -> Option<NumericDate> {
        self.not_before
    }
    fn iss(&self) -> &str {
        &self.issuer
    }
    fn aud(&self) -> &[String] {
        &self.audience.0
    }
}

/// Implements [`Claims`] for a struct with a `registered: RegisteredClaims` field.
#[macro_export]
macro_rules! impl_claims {
    ($ty:ty, [$($field:expr),* $(,)?]) => {
        impl $crate::Claims for $ty {
            fn fields() -> &'static [$crate::gojson::Field] {
                static FIELDS: ::std::sync::LazyLock<::std::vec::Vec<$crate::gojson::Field>> =
                    ::std::sync::LazyLock::new(|| {
                        let mut all = ::std::vec![$($field),*];
                        all.extend_from_slice(&$crate::REGISTERED_FIELDS);
                        all
                    });
                FIELDS.as_slice()
            }
            fn exp(&self) -> Option<$crate::NumericDate> {
                self.registered.expires_at
            }
            fn nbf(&self) -> Option<$crate::NumericDate> {
                self.registered.not_before
            }
            fn iss(&self) -> &str {
                &self.registered.issuer
            }
            fn aud(&self) -> &[String] {
                &self.registered.audience.0
            }
        }
    };
}

/// One failed claim check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    Expired,
    NotValidYet,
    Required(&'static str),
    InvalidAudience,
    InvalidIssuer,
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired => f.write_str("token is expired"),
            Self::NotValidYet => f.write_str("token is not valid yet"),
            Self::Required(name) => write!(
                f,
                "token is missing required claim: {name} claim is required"
            ),
            Self::InvalidAudience => f.write_str("token has invalid audience"),
            Self::InvalidIssuer => f.write_str("token has invalid issuer"),
        }
    }
}

/// Why a token was refused, in the error classes of golang-jwt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `ErrTokenMalformed`.
    Malformed(String),
    /// `ErrTokenUnverifiable`: no key could be chosen.
    Unverifiable(String),
    /// `ErrTokenSignatureInvalid`.
    SignatureInvalid(String),
    /// `ErrTokenInvalidClaims`, with every failed check.
    InvalidClaims(Vec<ClaimError>),
    /// Signing failed.
    Sign(String),
}

impl Error {
    /// `errors.Is(err, jwt.ErrTokenExpired)`.
    pub fn is_expired(&self) -> bool {
        matches!(self, Self::InvalidClaims(list) if list.contains(&ClaimError::Expired))
    }

    /// A stable class name.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::Unverifiable(_) => "unverifiable",
            Self::SignatureInvalid(_) => "signature_invalid",
            Self::InvalidClaims(_) => "invalid_claims",
            Self::Sign(_) => "sign",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "token is malformed: {m}"),
            Self::Unverifiable(m) => write!(f, "token is unverifiable: {m}"),
            Self::SignatureInvalid(m) if m.is_empty() => f.write_str("token signature is invalid"),
            Self::SignatureInvalid(m) => write!(f, "token signature is invalid: {m}"),
            Self::InvalidClaims(list) => {
                f.write_str("token has invalid claims: ")?;
                for (i, e) in list.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
            Self::Sign(m) => write!(f, "signing token: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// The signing methods golang-jwt registers. Only the first five can verify here, which covers every
/// key Silo's verifiers supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Es256,
    /// RS384, RS512, ES384, ES512, PS256, PS384, PS512, EdDSA, or none: registered in Go, so the
    /// token gets as far as the key lookup, but no Silo verifier has a key for one.
    Other,
}

impl Method {
    fn from_alg(alg: &str) -> Option<Self> {
        Some(match alg {
            "HS256" => Self::Hs256,
            "HS384" => Self::Hs384,
            "HS512" => Self::Hs512,
            "RS256" => Self::Rs256,
            "ES256" => Self::Es256,
            "RS384" | "RS512" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512" | "EdDSA"
            | "none" => Self::Other,
            _ => return None,
        })
    }

    /// `token.Method.(*jwt.SigningMethodHMAC)`.
    pub fn is_hmac(self) -> bool {
        matches!(self, Self::Hs256 | Self::Hs384 | Self::Hs512)
    }
}

/// The verification key a verifier's key function returns.
pub enum Key<'a> {
    Hmac(&'a [u8]),
    Rsa(RsaPublicKey),
    Es256(p256::ecdsa::VerifyingKey),
}

/// The token's header, for choosing a key.
pub struct Header {
    pub alg: String,
    pub kid: Option<String>,
    pub method: Method,
}

/// A parsed token that passed every check.
#[derive(Debug, Clone, PartialEq)]
pub struct Token<C> {
    pub claims: C,
}

/// `jwt.NewParser` and its options.
#[derive(Debug, Clone, Default)]
pub struct Parser<'a> {
    valid_methods: Option<&'a [&'a str]>,
    require_exp: bool,
    issuer: Option<&'a str>,
    audience: Option<&'a str>,
    now: Option<i128>,
}

impl<'a> Parser<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// `jwt.WithValidMethods`.
    pub fn valid_methods(mut self, methods: &'a [&'a str]) -> Self {
        self.valid_methods = Some(methods);
        self
    }

    /// `jwt.WithExpirationRequired`.
    pub fn expiration_required(mut self) -> Self {
        self.require_exp = true;
        self
    }

    /// `jwt.WithIssuer`.
    pub fn issuer(mut self, issuer: &'a str) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// `jwt.WithAudience`.
    pub fn audience(mut self, audience: &'a str) -> Self {
        self.audience = Some(audience);
        self
    }

    /// `jwt.WithTimeFunc`, as Unix nanoseconds.
    pub fn at(mut self, unix_nanos: i128) -> Self {
        self.now = Some(unix_nanos);
        self
    }

    /// `ParseWithClaims` with a key function.
    pub fn parse<C, F>(&self, token: &str, keyfunc: F) -> Result<Token<C>, Error>
    where
        C: Claims,
        F: FnOnce(&Header) -> Result<Key<'a>, String>,
    {
        let unverified = parse_unverified::<C>(token)?;
        if let Some(methods) = self.valid_methods
            && !methods.contains(&unverified.header.alg.as_str())
        {
            return Err(Error::SignatureInvalid(format!(
                "signing method {} is invalid",
                unverified.header.alg
            )));
        }
        let key = keyfunc(&unverified.header)
            .map_err(|e| Error::Unverifiable(format!("error while executing keyfunc: {e}")))?;
        verify_signature(
            unverified.header.method,
            unverified.signing_string.as_bytes(),
            &unverified.signature,
            &key,
        )?;
        self.validate(&unverified.claims)?;
        Ok(Token {
            claims: unverified.claims,
        })
    }

    /// The common Silo verifier: reject anything but HMAC, then use `secret`.
    pub fn parse_hmac<C: Claims>(&self, token: &str, secret: &'a [u8]) -> Result<Token<C>, Error> {
        self.parse(token, |header| {
            if header.method.is_hmac() {
                Ok(Key::Hmac(secret))
            } else {
                Err(format!("unexpected signing method: {}", header.alg))
            }
        })
    }

    /// The verifier that checks `t.Method.Alg() != HS256` in its key function.
    pub fn parse_hs256_keyfunc<C: Claims>(
        &self,
        token: &str,
        secret: &'a [u8],
    ) -> Result<Token<C>, Error> {
        self.parse(token, |header| {
            if header.alg == "HS256" {
                Ok(Key::Hmac(secret))
            } else {
                Err(format!("unexpected signing method {}", header.alg))
            }
        })
    }

    fn validate<C: Claims>(&self, claims: &C) -> Result<(), Error> {
        let now = self.now.unwrap_or_else(now_unix_nanos);
        let mut errors = Vec::new();
        match claims.exp() {
            None => {
                if self.require_exp {
                    errors.push(ClaimError::Required("exp"));
                }
            }
            Some(exp) => {
                if now >= i128::from(exp.0) * 1_000_000_000 {
                    errors.push(ClaimError::Expired);
                }
            }
        }
        if let Some(nbf) = claims.nbf()
            && now < i128::from(nbf.0) * 1_000_000_000
        {
            errors.push(ClaimError::NotValidYet);
        }
        if let Some(expected) = self.audience {
            let aud = claims.aud();
            if aud.is_empty() || (aud.len() == 1 && aud[0].is_empty()) {
                errors.push(ClaimError::Required("aud"));
            } else if !aud.iter().any(|a| a == expected) {
                errors.push(ClaimError::InvalidAudience);
            }
        }
        if let Some(expected) = self.issuer.filter(|i| !i.is_empty()) {
            let iss = claims.iss();
            if iss.is_empty() {
                errors.push(ClaimError::Required("iss"));
            } else if iss != expected {
                errors.push(ClaimError::InvalidIssuer);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidClaims(errors))
        }
    }
}

/// `ParseUnverified`: everything but the signature and the claim checks.
pub struct Unverified<C> {
    pub header: Header,
    /// The literal `null` leaves Go's struct at its zero value, so it decodes to `C::default()`.
    pub claims: C,
    pub signature: Vec<u8>,
    pub signing_string: String,
}

/// `ParseUnverified`. Never use the result of this on a token a client presented.
pub fn parse_unverified<C: Claims>(token: &str) -> Result<Unverified<C>, Error> {
    let mut parts = token.splitn(3, '.');
    let (Some(head), Some(body), Some(sig)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Malformed(
            "token contains an invalid number of segments".to_owned(),
        ));
    };
    if sig.contains('.') {
        return Err(Error::Malformed(
            "token contains an invalid number of segments".to_owned(),
        ));
    }

    let header_bytes = raw_url_decode(head)
        .map_err(|e| Error::Malformed(format!("could not base64 decode header: {e}")))?;
    let header_value = gojson::parse_value(&header_bytes)
        .map_err(|e| Error::Malformed(format!("could not JSON decode header: {e}")))?;
    let header_map = match header_value {
        serde_json::Value::Object(map) => Some(map),
        serde_json::Value::Null => None,
        _ => {
            return Err(Error::Malformed(
                "could not JSON decode header: not an object".to_owned(),
            ));
        }
    };

    let claim_bytes = raw_url_decode(body)
        .map_err(|e| Error::Malformed(format!("could not base64 decode claim: {e}")))?;
    let claims = match gojson::normalize_object(&claim_bytes, C::fields())
        .map_err(|e| Error::Malformed(format!("could not JSON decode claim: {e}")))?
    {
        Normalized::Null => C::default(),
        Normalized::Object(map) => serde_json::from_value::<C>(serde_json::Value::Object(map))
            .map_err(|e| Error::Malformed(format!("could not JSON decode claim: {e}")))?,
    };

    let alg = header_map
        .as_ref()
        .and_then(|m| m.get("alg"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Unverifiable("signing method (alg) is unspecified".to_owned()))?
        .to_owned();
    let method = Method::from_alg(&alg)
        .ok_or_else(|| Error::Unverifiable("signing method (alg) is unavailable".to_owned()))?;
    let kid = header_map
        .as_ref()
        .and_then(|m| m.get("kid"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let signature = raw_url_decode(sig)
        .map_err(|e| Error::Malformed(format!("could not base64 decode signature: {e}")))?;

    Ok(Unverified {
        header: Header { alg, kid, method },
        claims,
        signature,
        signing_string: format!("{head}.{body}"),
    })
}

macro_rules! hmac_verify {
    ($digest:ty, $key:expr, $text:expr, $sig:expr) => {{
        let mut mac =
            <Hmac<$digest> as Mac>::new_from_slice($key).expect("HMAC accepts a key of any length");
        Mac::update(&mut mac, $text);
        mac.verify_slice($sig).ok()
    }};
}

fn verify_signature(method: Method, text: &[u8], sig: &[u8], key: &Key<'_>) -> Result<(), Error> {
    let invalid = || Error::SignatureInvalid("signature is invalid".to_owned());
    match (method, key) {
        (Method::Hs256, Key::Hmac(k)) => hmac_verify!(Sha256, k, text, sig),
        (Method::Hs384, Key::Hmac(k)) => hmac_verify!(Sha384, k, text, sig),
        (Method::Hs512, Key::Hmac(k)) => hmac_verify!(Sha512, k, text, sig),
        (Method::Rs256, Key::Rsa(k)) => {
            let verifying = RsaVerifyingKey::<Sha256>::new(k.clone());
            rsa::pkcs1v15::Signature::try_from(sig)
                .ok()
                .and_then(|s| verifying.verify(text, &s).ok())
        }
        (Method::Es256, Key::Es256(k)) => {
            if sig.len() != 64 {
                None
            } else {
                p256::ecdsa::Signature::from_slice(sig)
                    .ok()
                    .and_then(|s| k.verify(text, &s).ok())
            }
        }
        _ => None,
    }
    .ok_or_else(invalid)
}

/// `jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)`.
pub fn sign_hs256<C: Serialize>(claims: &C, key: &[u8]) -> Result<String, Error> {
    let signing_string = signing_string("HS256", claims)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    Mac::update(&mut mac, signing_string.as_bytes());
    let sig = mac.finalize().into_bytes();
    Ok(format!("{signing_string}.{}", raw_url_encode(sig)))
}

/// `token.SigningString()`. `SignedString` appends the base64url signature.
pub fn signing_string<C: Serialize>(alg: &str, claims: &C) -> Result<String, Error> {
    #[derive(Serialize)]
    struct JwtHeader<'a> {
        alg: &'a str,
        typ: &'a str,
    }
    let head =
        json::marshal(&JwtHeader { alg, typ: "JWT" }).map_err(|e| Error::Sign(e.to_string()))?;
    let body = json::marshal(claims).map_err(|e| Error::Sign(e.to_string()))?;
    Ok(format!("{}.{}", raw_url_encode(head), raw_url_encode(body)))
}

/// `base64url(n)`-style JWK components into an RSA key, under the checks the ChatGPT verifier applies
/// before it trusts a key: an exponent of at most 4 bytes and a modulus of at least 256 bytes.
pub fn rsa_key_from_jwk(n: &str, e: &str) -> Option<RsaPublicKey> {
    let n = raw_url_decode(n).ok()?;
    let e = raw_url_decode(e).ok()?;
    if e.len() > 4 || n.len() < 256 {
        return None;
    }
    RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(&n),
        BigUint::from_bytes_be(&e),
        16384,
    )
    .ok()
}
