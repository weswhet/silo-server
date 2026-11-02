//! `internal/auth/jwt.go`: the `Claims` struct and `JWTService` (HMAC-SHA256 access/refresh/
//! plugin-access/Apple-push-display/direct-download-link tokens). Built on `silo_jwt`'s golang-jwt
//! semantics rather than redefining them.

use std::sync::atomic::{AtomicI64, Ordering};

use serde::{Deserialize, Serialize};
use silo_jwt::{Audience, Error as JwtError, NumericDate, Parser, RegisteredClaims};

/// `auth.TokenTypeAccess` and friends.
pub mod token_type {
    pub const ACCESS: &str = "access";
    pub const REFRESH: &str = "refresh";
    pub const API_KEY: &str = "api_key";
    pub const PLUGIN_ACCESS: &str = "plugin_access";
    pub const APPLE_PUSH_DISPLAY: &str = "apple_push_display";
    pub const DIRECT_DOWNLOAD_LINK: &str = "direct_download_link";
}

/// `auth.DirectDownloadLinkTTL`.
pub const DIRECT_DOWNLOAD_LINK_TTL_SECS: i64 = 5 * 60;

/// `auth.PluginAccessCookieName`.
pub const PLUGIN_ACCESS_COOKIE_NAME: &str = "silo_plugin_access";

/// `auth.Claims`. Field order and JSON tags match the Go struct exactly, which matters because the
/// signed bytes are `encoding/json`'s field-declaration order, not alphabetical — a reordering here
/// would still decode correctly (JSON objects are unordered) but would make a byte-for-byte minted
/// token differ from Go's for identical semantic claims, which the differential vectors check.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Claims {
    pub user_id: i64,
    pub role: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile_id: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonator_user_id: Option<i64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub password_change_required: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub api_key_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rate_tier: String,
    /// Never serialized (`json:"-"` in Go): only exists on claims built in-process for an
    /// API-key request, never on a minted token.
    #[serde(skip)]
    pub api_key_scopes: Vec<String>,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub file_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session_purpose: String,
    /// Never serialized: caps a freshly minted token's expiry at the session's absolute end.
    #[serde(skip)]
    pub session_ends_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_pin_revision: Option<i64>,
    #[serde(flatten)]
    pub registered: RegisteredClaims,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// `models.SessionPurposeRemotePlayback`, copied here to avoid a dependency on a models crate this
/// session's scope does not include; keep in sync if that type moves.
pub const SESSION_PURPOSE_REMOTE_PLAYBACK: &str = "remote_playback";
/// `models.RoleUser`.
pub const ROLE_USER: &str = "user";

silo_jwt::impl_claims!(
    Claims,
    [
        silo_jwt::gojson::value("user_id"),
        silo_jwt::gojson::value("role"),
        silo_jwt::gojson::value("session_id"),
        silo_jwt::gojson::value("profile_id"),
        silo_jwt::gojson::value("token_type"),
        silo_jwt::gojson::pointer("impersonator_user_id"),
        silo_jwt::gojson::value("password_change_required"),
        silo_jwt::gojson::value("api_key_id"),
        silo_jwt::gojson::value("rate_tier"),
        silo_jwt::gojson::value("file_id"),
        silo_jwt::gojson::value("session_purpose"),
        silo_jwt::gojson::pointer("profile_pin_revision"),
    ]
);

impl Claims {
    /// `Claims.IsOwnLoginSession`.
    pub fn is_own_login_session(&self) -> bool {
        self.token_type != token_type::API_KEY
            && !self.session_id.is_empty()
            && self.impersonator_user_id.is_none()
            && !self.is_remote_playback()
    }

    /// `Claims.IsRemotePlayback`.
    pub fn is_remote_playback(&self) -> bool {
        self.session_purpose == SESSION_PURPOSE_REMOTE_PLAYBACK
    }
}

/// `auth.ErrInvalidToken`/`ErrExpiredToken`, as a classification over [`silo_jwt::Error`] rather
/// than a new sentinel type: every failure a `JWTService` method can return is a `silo_jwt::Error`,
/// and `is_expired()`/`is_invalid()` below are `errors.Is(err, auth.ErrExpiredToken)` and its
/// negation.
pub trait TokenErrorExt {
    fn is_expired_token(&self) -> bool;
}

impl TokenErrorExt for JwtError {
    fn is_expired_token(&self) -> bool {
        self.is_expired()
    }
}

/// `auth.JWTService`. `access_expiry`/`refresh_expiry` are nanosecond `time.Duration`s, hot-
/// reloadable like the Go atomics.
pub struct JwtService {
    secret: Vec<u8>,
    access_expiry_ns: AtomicI64,
    refresh_expiry_ns: AtomicI64,
}

impl JwtService {
    /// `auth.NewJWTService`.
    pub fn new(secret: impl Into<Vec<u8>>, access_expiry_ns: i64, refresh_expiry_ns: i64) -> Self {
        Self {
            secret: secret.into(),
            access_expiry_ns: AtomicI64::new(access_expiry_ns),
            refresh_expiry_ns: AtomicI64::new(refresh_expiry_ns),
        }
    }

    /// `JWTService.SetExpiries`.
    pub fn set_expiries(&self, access_ns: i64, refresh_ns: i64) {
        self.access_expiry_ns.store(access_ns, Ordering::SeqCst);
        self.refresh_expiry_ns.store(refresh_ns, Ordering::SeqCst);
    }

    pub fn access_expiry_ns(&self) -> i64 {
        self.access_expiry_ns.load(Ordering::SeqCst)
    }

    pub fn refresh_expiry_ns(&self) -> i64 {
        self.refresh_expiry_ns.load(Ordering::SeqCst)
    }

    /// `generateAccessToken`, with every claim the caller set.
    pub fn access_token_for(&self, claims: Claims) -> Result<String, JwtError> {
        self.generate_token(
            claims,
            token_type::ACCESS,
            self.access_expiry_ns(),
            now_unix_nanos(),
        )
    }

    /// `generateRefreshToken`, with every claim the caller set.
    pub fn refresh_token_for(&self, claims: Claims) -> Result<String, JwtError> {
        self.generate_token(
            claims,
            token_type::REFRESH,
            self.refresh_expiry_ns(),
            now_unix_nanos(),
        )
    }

    /// `accessExpiresIn`: the access token's lifetime, or the time left before the session ends.
    pub fn access_expires_in(&self, claims: &Claims) -> i64 {
        let mut expiry = self.access_expiry_ns();
        if let Some(ends_at) = claims.session_ends_at {
            let now = now_unix_nanos();
            let left = (i128::from(ends_at) * 1_000_000_000 - now).max(0);
            expiry = expiry.min(i64::try_from(left).unwrap_or(i64::MAX));
        }
        expiry / 1_000_000_000
    }

    /// `JWTService.GenerateAccessToken`.
    pub fn generate_access_token(
        &self,
        user_id: i64,
        role: &str,
        session_id: &str,
    ) -> Result<String, JwtError> {
        self.generate_token(
            Claims {
                user_id,
                role: role.to_owned(),
                session_id: session_id.to_owned(),
                ..Default::default()
            },
            token_type::ACCESS,
            self.access_expiry_ns(),
            now_unix_nanos(),
        )
    }

    /// `JWTService.GenerateRefreshToken`.
    pub fn generate_refresh_token(
        &self,
        user_id: i64,
        role: &str,
        session_id: &str,
    ) -> Result<String, JwtError> {
        self.generate_token(
            Claims {
                user_id,
                role: role.to_owned(),
                session_id: session_id.to_owned(),
                ..Default::default()
            },
            token_type::REFRESH,
            self.refresh_expiry_ns(),
            now_unix_nanos(),
        )
    }

    /// `JWTService.GeneratePluginAccessToken`.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_plugin_access_token(
        &self,
        user_id: i64,
        role: &str,
        session_id: &str,
        profile_id: &str,
        profile_pin_revision: Option<i64>,
        ttl_ns: i64,
    ) -> Result<String, JwtError> {
        let ttl_ns = if ttl_ns <= 0 {
            5 * 60 * 1_000_000_000
        } else {
            ttl_ns
        };
        self.generate_token(
            Claims {
                user_id,
                role: role.to_owned(),
                session_id: session_id.to_owned(),
                profile_id: profile_id.to_owned(),
                profile_pin_revision,
                ..Default::default()
            },
            token_type::PLUGIN_ACCESS,
            ttl_ns,
            now_unix_nanos(),
        )
    }

    fn generate_token(
        &self,
        mut claims: Claims,
        kind: &str,
        expiry_ns: i64,
        now_ns: i128,
    ) -> Result<String, JwtError> {
        let now_secs = (now_ns / 1_000_000_000) as i64;
        let mut expires_at_secs = now_secs + expiry_ns / 1_000_000_000;
        if let Some(ends_at) = claims.session_ends_at
            && ends_at < expires_at_secs
        {
            expires_at_secs = ends_at;
        }
        claims.token_type = kind.to_owned();
        claims.registered = RegisteredClaims {
            expires_at: Some(NumericDate(expires_at_secs)),
            issued_at: Some(NumericDate(now_secs)),
            ..Default::default()
        };
        silo_jwt::sign_hs256(&claims, &self.secret)
    }

    /// `JWTService.ValidateToken`.
    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        if token.is_empty() {
            return Err(JwtError::Malformed("empty token".to_owned()));
        }
        Parser::new()
            .parse_hmac::<Claims>(token, &self.secret)
            .map(|t| t.claims)
    }

    /// `auth.StoredRefreshTokenSessionID`: reads an unverified, Silo-minted refresh token's session
    /// ID without checking its signature or expiry. Never call this on a client-presented token.
    pub fn stored_refresh_token_session_id(token: &str) -> Result<String, JwtError> {
        let unverified = silo_jwt::parse_unverified::<Claims>(token)?;
        if unverified.claims.token_type != token_type::REFRESH
            || unverified.claims.session_id.is_empty()
        {
            return Err(JwtError::Malformed(
                "not a refresh token of a login session".to_owned(),
            ));
        }
        Ok(unverified.claims.session_id)
    }
}

fn now_unix_nanos() -> i128 {
    silo_jwt::now_unix_nanos()
}

/// Something, read from an account's `Audience` claim, that the audience helper treats as empty.
/// Kept for symmetry with the `silo_jwt::Audience` type re-exported through [`Claims`].
pub type AudienceList = Audience;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_round_trips() {
        let svc = JwtService::new(
            b"secret".to_vec(),
            15 * 60 * 1_000_000_000,
            30 * 24 * 3600 * 1_000_000_000,
        );
        let token = svc.generate_access_token(7, "admin", "sess-1").unwrap();
        let claims = svc.validate_token(&token).unwrap();
        assert_eq!(claims.user_id, 7);
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.session_id, "sess-1");
        assert_eq!(claims.token_type, token_type::ACCESS);
        assert!(claims.is_own_login_session());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let svc = JwtService::new(b"secret".to_vec(), 1_000_000_000, 1_000_000_000);
        let token = svc.generate_access_token(1, "user", "s").unwrap();
        let other = JwtService::new(b"different".to_vec(), 1_000_000_000, 1_000_000_000);
        assert!(other.validate_token(&token).is_err());
    }

    #[test]
    fn stored_refresh_token_session_id_ignores_signature() {
        let svc = JwtService::new(b"secret".to_vec(), 1_000_000_000, 1_000_000_000);
        let token = svc.generate_refresh_token(1, "user", "sess-xyz").unwrap();
        assert_eq!(
            JwtService::stored_refresh_token_session_id(&token).unwrap(),
            "sess-xyz"
        );
    }
}
