//! `internal/access/types.go`: the viewer access scope's pure data types.
//!
//! This is the whole of what this session ported from `internal/access` (4,672 Go LOC across the
//! package). `resolver.go` (the real `ResolveScope`, which reads profiles, policy and server
//! settings) and the Postgres-backed `groups`/`household`/`rating`/`quality`/
//! `metadata_curation`/`metadata_language`/`viewer_preferences`/`profile_token` files are not
//! ported: they need the catalog crate (not built yet), the policy engine, and JWT verification
//! wiring together, which is its own multi-crate task.

/// `access.MaturityLimits`: the per-viewer maturity restrictions every catalog read enforces.
/// They travel as one value so a filter narrowed to its maturity limits cannot keep one and drop
/// another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaturityLimits {
    /// "" means no ceiling; see [`has_ceiling`].
    pub max_content_rating: String,
    /// The server-wide decision for titles with no rating. Has no effect without a ceiling.
    pub allow_unrated_content: bool,
    /// 0 means no limit.
    pub max_advisory_age: i32,
    /// Makes the advisory-age limit fail closed. Has no effect without a limit.
    pub require_advisory_age: bool,
}

/// `access.HasCeiling`-shaped check reused by [`MaturityLimits::active`]: Go defines `HasCeiling`
/// as a free function (not shown in `types.go`, used from it) that is simply "non-empty".
fn has_ceiling(max_content_rating: &str) -> bool {
    !max_content_rating.is_empty()
}

impl MaturityLimits {
    /// `MaturityLimits.HidesUnadvised`: a limit is set and the profile requires an advisory age.
    pub fn hides_unadvised(&self) -> bool {
        self.max_advisory_age > 0 && self.require_advisory_age
    }

    /// `MaturityLimits.Active`: whether the limits restrict anything at all.
    pub fn active(&self) -> bool {
        has_ceiling(&self.max_content_rating) || self.max_advisory_age > 0
    }
}

/// `access.MinAdvisoryAgeLimit`.
pub const MIN_ADVISORY_AGE_LIMIT: i32 = 1;
/// `access.MaxAdvisoryAgeLimit`.
pub const MAX_ADVISORY_AGE_LIMIT: i32 = 21;

/// `access.ValidAdvisoryAgeLimit`: whether `age` is a storable advisory-age limit. 0 ("no limit")
/// is not a stored value; callers represent it as absent/null.
pub fn valid_advisory_age_limit(age: i32) -> bool {
    (MIN_ADVISORY_AGE_LIMIT..=MAX_ADVISORY_AGE_LIMIT).contains(&age)
}

/// `access.Scope`: the resolved effective access policy for a viewer request.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scope {
    pub user_id: i32,
    pub profile_id: String,
    /// The selected profile's PIN revision, 0 without a profile.
    pub profile_pin_revision: i64,
    pub allowed_library_ids: Vec<i64>,
    /// Libraries whose membership globally hides an item.
    pub disabled_library_ids: Vec<i64>,
    pub libraries_restricted: bool,
    /// Libraries hidden only by `ui.disabled_library_ids`; nil (`None`) when unrestricted.
    pub hidden_library_ids: Option<Vec<i64>>,
    pub maturity_limits: MaturityLimits,
    pub max_playback_quality: String,
    pub max_remote_stream_bitrate_kbps: i64,
    pub max_local_stream_bitrate_kbps: i64,
    /// "" inherits the library's metadata language.
    pub preferred_metadata_language: String,
    /// Maps a media item's canonical original-language code to the profile's target language.
    pub metadata_language_overrides: std::collections::HashMap<String, String>,
    pub policy_revision: i64,
    pub profile_verified: bool,
    /// Set when `profile_verified` holds only because the request was PIN-exempt, not because a
    /// profile token proved the PIN.
    pub pin_verification_skipped: bool,
    pub next_up_mode: String,
    pub next_up_new_releases_first: bool,
    /// Set when the profile's viewer preferences could not be read and the scope carries defaults.
    pub preferences_degraded: bool,
}

/// `access.ResolveInput`: the request input for resolving a viewer access scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveInput {
    pub user_id: i32,
    pub session_id: String,
    pub profile_id: String,
    pub profile_token: String,
    pub skip_pin_verification: bool,
    /// Resolves what the profile may access, leaving out libraries it hides from its own browsing.
    pub content_access_only: bool,
}

/// `access.ProfileTokenClaims`: the claims embedded in a verified profile token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileTokenClaims {
    pub user_id: i32,
    pub session_id: String,
    pub profile_id: String,
    /// The profile's PIN revision when its PIN was verified.
    pub pin_revision: i64,
    /// The account's `access_policy_revision` at mint time. Ignored by validation.
    pub policy_revision: i64,
}
