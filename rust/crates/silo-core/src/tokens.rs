//! The HS256 JWTs other than the stream token: `internal/auth`, `internal/access`,
//! `internal/watchtogether`, `internal/themesongs`, and `internal/audiobooks/abs`.
//!
//! Tokens minted by either implementation must validate in the other for their whole lifetime. The
//! struct field order below is Go's, because it decides the signed bytes.

use serde::{Deserialize, Serialize};
use silo_gocompat::json::omit_empty;
use silo_jwt::gojson::{Field, pointer, value};
use silo_jwt::{
    Audience, Claims, Error as JwtError, NumericDate, Parser, RegisteredClaims, impl_claims,
    parse_unverified, sign_hs256,
};

use crate::hexgo::sha256;

fn floor_secs(unix_nanos: i128) -> i64 {
    unix_nanos.div_euclid(1_000_000_000) as i64
}

/// The token types of [`AccessClaims`].
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";
pub const TOKEN_TYPE_API_KEY: &str = "api_key";
pub const TOKEN_TYPE_PLUGIN_ACCESS: &str = "plugin_access";
pub const TOKEN_TYPE_APPLE_PUSH_DISPLAY: &str = "apple_push_display";
pub const TOKEN_TYPE_DIRECT_DOWNLOAD_LINK: &str = "direct_download_link";

/// `auth.DirectDownloadLinkTTL`, in seconds.
pub const DIRECT_DOWNLOAD_LINK_TTL_SECS: i64 = 300;

/// `auth.Claims`. `APIKeyScopes` and `SessionEndsAt` never reach a token, so they live on the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessClaims {
    pub user_id: i64,
    pub role: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub profile_id: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonator_user_id: Option<i64>,
    #[serde(skip_serializing_if = "omit_empty")]
    pub password_change_required: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    pub api_key_id: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub rate_tier: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub file_id: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub session_purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_pin_revision: Option<i64>,
    #[serde(flatten)]
    pub registered: RegisteredClaims,
}

impl_claims!(
    AccessClaims,
    [
        value("user_id"),
        value("role"),
        value("session_id"),
        value("profile_id"),
        value("token_type"),
        pointer("impersonator_user_id"),
        value("password_change_required"),
        value("api_key_id"),
        value("rate_tier"),
        value("file_id"),
        value("session_purpose"),
        pointer("profile_pin_revision"),
    ]
);

/// `generateToken` at a given time: `exp` is the earlier of `now + expiry` and the session's absolute
/// end. `iat` and `exp` truncate to whole seconds.
pub fn sign_access(
    mut claims: AccessClaims,
    token_type: &str,
    expiry_nanos: i64,
    session_ends_at_nanos: Option<i128>,
    now_unix_nanos: i128,
    secret: &[u8],
) -> Result<String, JwtError> {
    let mut expires = now_unix_nanos + i128::from(expiry_nanos);
    if let Some(ends) = session_ends_at_nanos
        && ends < expires
    {
        expires = ends;
    }
    claims.token_type = token_type.to_owned();
    claims.registered = RegisteredClaims {
        expires_at: Some(NumericDate(floor_secs(expires))),
        issued_at: Some(NumericDate(floor_secs(now_unix_nanos))),
        ..RegisteredClaims::default()
    };
    sign_hs256(&claims, secret)
}

/// `JWTService.ValidateToken`'s two sentinel errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessError {
    Invalid(String),
    Expired,
}

/// `JWTService.ValidateToken`.
pub fn validate_access<'a>(
    token: &str,
    secret: &'a [u8],
    parser: Parser<'a>,
) -> Result<AccessClaims, AccessError> {
    if token.is_empty() {
        return Err(AccessError::Invalid(String::new()));
    }
    parser
        .parse_hmac::<AccessClaims>(token, secret)
        .map(|t| t.claims)
        .map_err(|e| {
            if e.is_expired() {
                AccessError::Expired
            } else {
                AccessError::Invalid(e.to_string())
            }
        })
}

/// `StoredRefreshTokenSessionID`: reads Silo's own stored refresh token without checking it. Never use
/// it on a token a request presented.
pub fn stored_refresh_token_session_id(token: &str) -> Option<String> {
    let claims = parse_unverified::<AccessClaims>(token).ok()?.claims;
    (claims.token_type == TOKEN_TYPE_REFRESH && !claims.session_id.is_empty())
        .then_some(claims.session_id)
}

/// `access.profileJWTClaims`, the durable `X-Profile-Token`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileClaims {
    pub user_id: i64,
    pub session_id: String,
    pub profile_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_revision: Option<i64>,
    pub policy_revision: i64,
    #[serde(flatten)]
    pub registered: RegisteredClaims,
}

impl_claims!(
    ProfileClaims,
    [
        value("user_id"),
        value("session_id"),
        value("profile_id"),
        pointer("pin_revision"),
        value("policy_revision"),
    ]
);

/// `ProfileTokenService.Mint` at a given time. With a non-positive `ttl_nanos` the token is durable and
/// has no `exp`, which is what production uses.
pub fn mint_profile(
    mut claims: ProfileClaims,
    ttl_nanos: i64,
    now_unix_nanos: i128,
    secret: &[u8],
) -> Result<String, JwtError> {
    claims.registered = RegisteredClaims {
        issued_at: Some(NumericDate(floor_secs(now_unix_nanos))),
        expires_at: (ttl_nanos > 0)
            .then(|| NumericDate(floor_secs(now_unix_nanos + i128::from(ttl_nanos)))),
        ..RegisteredClaims::default()
    };
    sign_hs256(&claims, secret)
}

/// `ProfileTokenService.Validate`. A token without `pin_revision` is refused.
pub fn validate_profile<'a>(
    token: &str,
    secret: &'a [u8],
    parser: Parser<'a>,
) -> Result<ProfileClaims, String> {
    if token.is_empty() {
        return Err("profile unverified".to_owned());
    }
    let claims = parser
        .parse_hmac::<ProfileClaims>(token, secret)
        .map_err(|e| e.to_string())?
        .claims;
    if claims.pin_revision.is_none() {
        return Err("token predates pin_revision".to_owned());
    }
    Ok(claims)
}

/// `watchtogether.roomJWTClaims`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RoomClaims {
    pub room_id: String,
    pub user_id: i64,
    pub profile_id: String,
    #[serde(flatten)]
    pub registered: RegisteredClaims,
}

impl_claims!(
    RoomClaims,
    [value("room_id"), value("user_id"), value("profile_id")]
);

/// `RoomTokenService.Mint` at a given time.
pub fn mint_room(
    mut claims: RoomClaims,
    ttl_nanos: i64,
    now_unix_nanos: i128,
    secret: &[u8],
) -> Result<String, JwtError> {
    claims.registered = RegisteredClaims {
        issued_at: Some(NumericDate(floor_secs(now_unix_nanos))),
        expires_at: Some(NumericDate(floor_secs(
            now_unix_nanos + i128::from(ttl_nanos),
        ))),
        ..RegisteredClaims::default()
    };
    sign_hs256(&claims, secret)
}

/// `RoomTokenService.Validate`, the frozen v1 validator: any HMAC algorithm, `exp` optional.
pub fn validate_room<'a>(
    token: &str,
    secret: &'a [u8],
    parser: Parser<'a>,
) -> Result<RoomClaims, JwtError> {
    parser
        .parse_hmac::<RoomClaims>(token, secret)
        .map(|t| t.claims)
}

/// `RoomTokenService.ValidateSocketProof`: exact HS256 and a signed expiry.
pub fn validate_room_socket_proof<'a>(
    token: &str,
    secret: &'a [u8],
    parser: Parser<'a>,
) -> Result<RoomClaims, JwtError> {
    parser
        .valid_methods(&["HS256"])
        .expiration_required()
        .parse::<RoomClaims, _>(token, |_| Ok(silo_jwt::Key::Hmac(secret)))
        .map(|t| t.claims)
}

/// `themesongs.grantAudienceOriginal`.
pub const THEME_AUDIENCE_ORIGINAL: &str = "theme-audio";
/// `themesongs.grantAudienceConverted`.
pub const THEME_AUDIENCE_CONVERTED: &str = "theme-audio-aac";

/// `themesongs.NewService`'s grant key.
pub fn theme_grant_key(secret: &str) -> [u8; 32] {
    sha256(format!("silo.theme-audio.v2\0{secret}"))
}

/// `themesongs.Grant`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ThemeGrant {
    pub user_id: i64,
    pub profile_id: String,
    pub session_id: String,
    pub policy_revision: i64,
    pub owner_id: String,
    pub theme_id: String,
    pub size: i64,
    pub modified: i64,
    #[serde(flatten)]
    pub registered: RegisteredClaims,
}

impl_claims!(
    ThemeGrant,
    [
        value("user_id"),
        value("profile_id"),
        value("session_id"),
        value("policy_revision"),
        value("owner_id"),
        value("theme_id"),
        value("size"),
        value("modified"),
    ]
);

/// `Service.Mint`'s claim layout. `audience` is one of the two constants above.
pub fn mint_theme_grant(
    mut grant: ThemeGrant,
    audience: &str,
    expires_unix_nanos: i128,
    now_unix_nanos: i128,
    key: &[u8],
) -> Result<String, JwtError> {
    grant.registered = RegisteredClaims {
        audience: Audience(vec![audience.to_owned()]),
        expires_at: Some(NumericDate(floor_secs(expires_unix_nanos))),
        issued_at: Some(NumericDate(floor_secs(now_unix_nanos))),
        ..RegisteredClaims::default()
    };
    sign_hs256(&grant, key)
}

/// `Service.Validate`, without the caller's owner and id comparison: exact HS256 and a signed expiry,
/// with the identity fields present and exactly one audience. Returns the grant and whether its audience
/// is the converted delivery.
pub fn validate_theme_grant<'a>(
    token: &str,
    owner: &str,
    id: &str,
    key: &'a [u8],
    parser: Parser<'a>,
) -> Option<(ThemeGrant, bool)> {
    if key.is_empty() || token.is_empty() {
        return None;
    }
    let grant = parser
        .valid_methods(&["HS256"])
        .expiration_required()
        .parse::<ThemeGrant, _>(token, |_| Ok(silo_jwt::Key::Hmac(key)))
        .ok()?
        .claims;
    if grant.owner_id != owner
        || grant.theme_id != id
        || grant.user_id <= 0
        || grant.profile_id.is_empty()
        || grant.session_id.is_empty()
        || grant.registered.audience.0.len() != 1
    {
        return None;
    }
    let converted = match grant.registered.audience.0[0].as_str() {
        THEME_AUDIENCE_ORIGINAL => false,
        THEME_AUDIENCE_CONVERTED => true,
        _ => return None,
    };
    Some((grant, converted))
}

/// `abs.Claims`. `sub` and `jti` shadow the embedded registered fields, so they are always present.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AbsClaims {
    #[serde(rename = "type")]
    pub token_type: String,
    #[serde(rename = "sub")]
    pub user_id: String,
    #[serde(rename = "pid", skip_serializing_if = "omit_empty")]
    pub profile_id: String,
    #[serde(rename = "pin_rev", skip_serializing_if = "Option::is_none")]
    pub pin_revision: Option<i64>,
    pub jti: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub device_id: String,
    #[serde(rename = "sid", skip_serializing_if = "omit_empty")]
    pub session_id: String,
    #[serde(rename = "bid", skip_serializing_if = "omit_empty")]
    pub book_id: String,
    #[serde(rename = "fidx", skip_serializing_if = "omit_empty")]
    pub file_idx: i64,
    #[serde(rename = "iss", skip_serializing_if = "omit_empty")]
    pub issuer: String,
    #[serde(rename = "aud", skip_serializing_if = "Audience::is_empty")]
    pub audience: Audience,
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NumericDate>,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<NumericDate>,
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<NumericDate>,
}

impl Claims for AbsClaims {
    fn fields() -> &'static [Field] {
        static FIELDS: [Field; 14] = [
            value("type"),
            value("sub"),
            value("pid"),
            pointer("pin_rev"),
            value("jti"),
            value("device_id"),
            value("sid"),
            value("bid"),
            value("fidx"),
            value("iss"),
            value("aud"),
            pointer("exp"),
            pointer("nbf"),
            pointer("iat"),
        ];
        &FIELDS
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

/// `abs.issueJWT`.
pub fn sign_abs(claims: &AbsClaims, secret: &[u8]) -> Result<String, JwtError> {
    sign_hs256(claims, secret)
}

/// `abs.ParseToken`.
pub fn parse_abs<'a>(
    token: &str,
    secret: &'a [u8],
    parser: Parser<'a>,
) -> Result<AbsClaims, JwtError> {
    parser
        .parse_hs256_keyfunc::<AbsClaims>(token, secret)
        .map(|t| t.claims)
}

/// `identityClaims` of the ChatGPT identity token.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChatGptIdentityClaims {
    #[serde(flatten)]
    pub registered: RegisteredClaims,
    pub nonce: String,
    pub email: String,
}

impl_claims!(ChatGptIdentityClaims, [value("nonce"), value("email")]);

/// The JSON Web Key set entry `verifyIDTokenOnce` picks a key from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub kty: String,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub n: String,
    #[serde(default)]
    pub e: String,
}

/// `verifyIDTokenOnce`, once the key set is fetched: RS256 only, issuer and audience checked, `exp`
/// required, a non-empty subject, and the nonce when one is expected.
pub fn verify_chatgpt_id_token<'a>(
    raw: &str,
    keys: &[Jwk],
    issuer: &'a str,
    client_id: &'a str,
    nonce: &str,
    parser: Parser<'a>,
) -> Option<ChatGptIdentityClaims> {
    let parsed = parser
        .valid_methods(&["RS256"])
        .issuer(issuer)
        .audience(client_id)
        .expiration_required()
        .parse::<ChatGptIdentityClaims, _>(raw, |header| {
            let kid = header.kid.clone().unwrap_or_default();
            for key in keys {
                if key.kty != "RSA" || key.kid != kid || kid.is_empty() {
                    continue;
                }
                return silo_jwt::rsa_key_from_jwk(&key.n, &key.e)
                    .map(silo_jwt::Key::Rsa)
                    .ok_or_else(|| "identity".to_owned());
            }
            Err("identity".to_owned())
        })
        .ok()?;
    let claims = parsed.claims;
    if claims.registered.subject.is_empty()
        || (!nonce.is_empty() && !crate::hexgo::ct_eq(nonce.as_bytes(), claims.nonce.as_bytes()))
    {
        return None;
    }
    Some(claims)
}
