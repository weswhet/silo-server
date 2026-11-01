//! `internal/artworkurl`: signed capability URLs for artwork and job artifacts.
//!
//! Multi-node deployments verify each other's URLs, and clients cache images by full URL, so the
//! issuance windows and the signature bytes are both part of the format.

use silo_jwt::base64go::raw_url_encode;

use crate::artworkkey;
use crate::gourl::escaped_path_of;
use crate::hexgo::{ct_eq, hmac_sha256};

const ARTWORK_DOMAIN: &str = "silo-artwork-url-v1";
const ARTWORK_LABEL: &str = "artwork-v1";
const ARTWORK_ROUTE: &str = "/api/v2/artwork/";
const JOB_ARTIFACT_DOMAIN: &str = "silo-job-artifact-url-v1";
const JOB_ARTIFACT_LABEL: &str = "job-artifact-v1";
const JOB_ARTIFACT_ROUTE: &str = "/api/v2/admin/jobs/";

const SECOND: i128 = 1_000_000_000;
const MINUTE: i128 = 60 * SECOND;
const HOUR: i128 = 60 * MINUTE;
const REVISIONED_URL_WINDOW: i128 = 24 * HOUR;
const SHORT_URL_BUCKET: i128 = 15 * MINUTE;
/// Unix seconds of Go's zero time, which `Time.Truncate` measures from.
const GO_ZERO_TIME_UNIX: i128 = -62_135_596_800;

/// `ErrExpired` and `ErrBadSignature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Expired,
    BadSignature,
}

fn clamp_ttl(ttl: i128, fallback: i128) -> i128 {
    let ttl = if ttl <= 0 { fallback } else { ttl };
    ttl.clamp(MINUTE, 24 * HOUR)
}

/// `artworkurl.Signer`.
pub struct Signer {
    key: [u8; 32],
    label: &'static str,
    route: &'static str,
    ttl: i128,
    day_windows: bool,
}

impl Signer {
    /// `NewSigner`. Durations are nanoseconds.
    pub fn new(jwt_secret: &str, ttl_nanos: i64) -> Self {
        Self {
            key: hmac_sha256(jwt_secret.as_bytes(), &[ARTWORK_DOMAIN.as_bytes()]),
            label: ARTWORK_LABEL,
            route: ARTWORK_ROUTE,
            ttl: clamp_ttl(i128::from(ttl_nanos), 4 * HOUR),
            day_windows: true,
        }
    }

    /// `NewJobArtifactSigner`.
    pub fn new_job_artifact(jwt_secret: &str, ttl_nanos: i64) -> Self {
        Self {
            key: hmac_sha256(jwt_secret.as_bytes(), &[JOB_ARTIFACT_DOMAIN.as_bytes()]),
            label: JOB_ARTIFACT_LABEL,
            route: JOB_ARTIFACT_ROUTE,
            ttl: clamp_ttl(i128::from(ttl_nanos), 4 * HOUR),
            day_windows: false,
        }
    }

    /// `signature`.
    pub fn signature(&self, key: &str, exp: i64) -> String {
        let text = format!("{}\n{key}\n{exp}", self.label);
        raw_url_encode(&hmac_sha256(&self.key, &[text.as_bytes()])[..16])
    }

    /// `SignFor`: the root-relative URL and its expiry in Unix nanoseconds. A non-positive TTL means the
    /// default.
    pub fn sign_for(&self, key: &str, now_unix_nanos: i128, ttl_nanos: i64) -> (String, i128) {
        let ttl = clamp_ttl(i128::from(ttl_nanos), self.ttl);
        let mut bucket = SHORT_URL_BUCKET.min(ttl);
        if self.day_windows && ttl >= self.ttl && !artworkkey::revision(key).is_empty() {
            bucket = bucket.max(REVISIONED_URL_WINDOW);
        }
        let since_zero = now_unix_nanos - GO_ZERO_TIME_UNIX * SECOND;
        let truncated = since_zero - since_zero.rem_euclid(bucket) + GO_ZERO_TIME_UNIX * SECOND;
        let expires = truncated + bucket + ttl;
        let exp = expires.div_euclid(SECOND) as i64;
        let suffix = if self.label == JOB_ARTIFACT_LABEL {
            "/artifact"
        } else {
            ""
        };
        let path = format!(
            "{}{}{suffix}",
            self.route,
            key.strip_prefix('/').unwrap_or(key)
        );
        (
            format!(
                "{}?exp={exp}&sig={}",
                escaped_path_of(path),
                self.signature(key, exp)
            ),
            expires,
        )
    }

    /// `Sign`.
    pub fn sign(&self, key: &str, now_unix_nanos: i128) -> (String, i128) {
        self.sign_for(key, now_unix_nanos, self.ttl as i64)
    }

    /// `Verify`: valid while `now < exp`.
    pub fn verify(&self, key: &str, exp: i64, sig: &str, now_unix: i64) -> Result<(), Error> {
        if now_unix >= exp {
            return Err(Error::Expired);
        }
        if !ct_eq(self.signature(key, exp).as_bytes(), sig.as_bytes()) {
            return Err(Error::BadSignature);
        }
        Ok(())
    }
}
