//! `internal/auth/provider.go` and `plugin_provider.go`: the `AuthProvider` trait bridge.
//!
//! # The problem (critique finding 5)
//!
//! `internal/auth` imports `internal/plugins`/`internal/pluginhost` (`PluginProvider` calls a
//! plugin's auth RPCs through the plugin host), but the plan's milestone order puts the plugin
//! host crate work after `silo-auth`. The plan's own fix for this class of problem is a Rust
//! trait at the seam instead of porting the callee first (see `plan.md`'s "Implement the 14 cuts
//! by moving symbols down into lower crates. The exceptions are `auth -> plugins` and
//! `pluginhost -> events`, which use traits."). [`AuthProvider`] is that trait for this one: it
//! has the exact two-method shape of Go's `auth.AuthProvider` interface, so a provider on either
//! side of the Go/Rust boundary is interchangeable to a caller that only knows the trait.
//!
//! # What is and is not ported here
//!
//! Only the trait and its error/result types are ported — no implementation of it. Specifically:
//!
//! - **`LocalProvider`** (password sign-in against the local Postgres `users` table, with bcrypt
//!   via `internal/auth/passwordhash`, break-glass admin bypass, the server-wide local-login
//!   switch, and the constant-time-against-enumeration placeholder-hash comparison) is **not**
//!   ported. It needs a `UserRepository` (`internal/auth/repository.go`, 829 Go lines — account
//!   CRUD, not attempted this session) and the password-hash/placeholder machinery
//!   (`internal/auth/password_hash.go`, `internal/auth/local_login_policy.go`), neither of which
//!   exists in this crate yet. **Every local password sign-in stays served by Go** behind the
//!   strangler proxy until that work lands.
//! - **`PluginProvider`** (sign-in through an LDAP/SSO/etc. plugin, over the plugin host's gRPC
//!   client) is **not** ported, and structurally cannot be until `silo-plugins`/`pluginhost`
//!   exist as crates (milestone order, same as the critique's finding). **Every plugin-backed
//!   sign-in stays served by Go** for the same reason — not merely "not yet ported" but blocked
//!   on a dependency that does not exist in this workspace.
//! - [`crate::session::SessionRepository::is_valid`] is already a complete, independent port of
//!   the one piece both providers' `ValidateSession` delegates to (`LocalProvider.ValidateSession`
//!   and `PluginProvider`'s equivalent both just call `sessions.IsValid`), so a caller that only
//!   needs session validation — not authentication — already has a working Rust path.
//!
//! A Rust implementation of [`AuthProvider`] added in a later session, for either kind of
//! provider, slots in without changing this trait or any caller already written against it.

use std::future::Future;

/// `auth.Credentials`.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// `auth.ErrInvalidCredentials`/`ErrUserDisabled`, plus the two further refusals
/// `LocalProvider.Authenticate` can return (`ErrLocalLoginDisabled`, `ErrNotPermitted`) so a trait
/// implementation on either side of the Go/Rust boundary can report the same refusal classes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user account is disabled")]
    UserDisabled,
    #[error("local password sign-in is disabled")]
    LocalLoginDisabled,
    #[error("not permitted")]
    NotPermitted,
    /// A provider-specific failure (a plugin RPC error, a database error, …) that is not one of
    /// the above classified refusals.
    #[error("{0}")]
    Other(String),
}

/// The account an [`AuthProvider`] authenticated. This is deliberately not `models::User` (no
/// models crate exists in this session's dependency graph) — a caller adapts a provider's result
/// into its own user type. Every field here is one both `LocalProvider` and `PluginProvider`
/// resolve before returning, per `provider.go`/`plugin_provider.go`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub role: String,
    pub enabled: bool,
    /// The external sign-in identity this authentication went through
    /// (`plugin_auth_identities.id`), for the login session it opens; `None` for a local
    /// password sign-in, which has no identity row.
    pub identity_id: Option<i64>,
}

/// `auth.AuthProvider`. Implemented by this crate's own code for a provider ported to Rust, and
/// by a bridge type (not provided here; see the module doc) that calls back into the Go process
/// over its existing RPC/HTTP surface for a provider that still lives there.
pub trait AuthProvider: Send + Sync {
    /// `AuthProvider.Authenticate`.
    fn authenticate(
        &self,
        credentials: Credentials,
    ) -> impl Future<Output = Result<AuthenticatedUser, AuthError>> + Send;

    /// `AuthProvider.ValidateSession`.
    fn validate_session(
        &self,
        session_id: &str,
    ) -> impl Future<Output = Result<bool, AuthError>> + Send;
}

/// `auth.LookupLogin`'s gate: whether `identifier` is a plausible bare email address, for a
/// `LoginDirectory`-style implementation's username/email fallback. This one pure helper is
/// ported on its own — `LookupLogin` itself and `LoginDirectory` need the (unported)
/// `UserRepository` to mean anything.
///
/// Go parses with `net/mail.ParseAddress` and requires the parsed address to equal the input
/// exactly (rejecting a display-name form like `"Name <a@b.com>"` even though `net/mail` itself
/// accepts it as an address). `silo_gocompat` has no `net/mail` port, and a full RFC 5322 address
/// parser is its own undertaking, so this is a narrower check: it requires exactly one `@`, a
/// non-empty local part and domain, and no whitespace or angle brackets anywhere in the string.
/// This is strictly narrower than Go's parser in the direction that matters for a login-identifier
/// gate (it rejects some strings Go would accept as "looks like an email", never the reverse for
/// a plain `local@domain` address), so at worst it sends a few more identifiers through the
/// username-only lookup path, which only changes whether the email-column fallback is tried, not
/// whether a legitimate login succeeds for an account whose username equals its email.
pub fn looks_like_email(identifier: &str) -> bool {
    let identifier = identifier.trim();
    if identifier.contains(char::is_whitespace) || identifier.contains(['<', '>']) {
        return false;
    }
    match identifier.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@') && domain.contains('.')
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_email_accepts_plain_addresses() {
        assert!(looks_like_email("person@example.com"));
        assert!(!looks_like_email("not-an-email"));
        assert!(!looks_like_email("person@example.com, other@example.com"));
        assert!(!looks_like_email("Name <person@example.com>"));
    }
}
