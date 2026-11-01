//! `internal/blobstore` and `internal/s3client`: the identity strings recorded in
//! `artwork.storage_identity` and `storage.operational_identity`, key rules, and read URLs. A store
//! whose identity differs from the record refuses to open, and replicas must issue the same URL within a
//! window so clients and CDNs keep hitting.

use silo_gocompat::strings::{to_lower, trim_space};
use silo_gocompat::unicode::is_control;

use crate::gourl::{ParseError, parse_escaped_path};
use crate::hexgo::{encode as hex_encode, hmac_sha256, sha256_hex};

/// `BackendLocal`.
pub const BACKEND_LOCAL: &str = "local";
/// `BackendS3`.
pub const BACKEND_S3: &str = "s3";

/// `ValidateKey`.
pub fn validate_key(key: &str) -> bool {
    if key.len() > 1024 || key.chars().any(|c| is_control(c as u32)) {
        return false;
    }
    if key.is_empty() || key.starts_with('/') || key.contains('\\') {
        return false;
    }
    key.split('/').all(|part| {
        !(part.is_empty()
            || part == "."
            || part == ".."
            || part.starts_with(".tmp-")
            || part.starts_with(".probe-"))
    })
}

/// `Filesystem.Identity` without a recorded identity.
pub fn local_identity(root: &str) -> String {
    format!("{BACKEND_LOCAL}|{root}")
}

/// `normalizeEndpoint`: lowercases only the scheme and host. An endpoint without a host is lowercased
/// whole.
pub fn normalize_endpoint(raw: &str) -> String {
    let raw = trim_space(raw);
    let Ok(path) = parse_escaped_path(raw) else {
        return to_lower(raw);
    };
    let Some((scheme, rest)) = raw.split_once("://") else {
        return to_lower(raw);
    };
    let rest_no_frag = rest.split('#').next().unwrap_or("");
    let authority_end = rest_no_frag.find(['/', '?']).unwrap_or(rest_no_frag.len());
    let authority = &rest_no_frag[..authority_end];
    let (user, host) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };
    if host.is_empty() {
        return to_lower(raw);
    }
    let query = rest_no_frag[authority_end..]
        .split_once('?')
        .map(|(_, q)| q);
    let mut out = format!("{}://", to_lower(scheme));
    if let Some(user) = user {
        out.push_str(user);
        out.push('@');
    }
    out.push_str(&to_lower(host));
    out.push_str(&path);
    if let Some(query) = query
        && !query.is_empty()
    {
        out.push('?');
        out.push_str(query);
    }
    if let Some((_, fragment)) = rest.split_once('#') {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// `S3.Identity`.
pub fn s3_identity(endpoint: &str, bucket: &str, key_prefix: &str) -> String {
    format!(
        "{BACKEND_S3}|{}|{}|{key_prefix}",
        normalize_endpoint(endpoint),
        to_lower(trim_space(bucket))
    )
}

/// `NormalizeKeyPrefix`.
pub fn normalize_key_prefix(prefix: &str) -> &str {
    trim_space(prefix).trim_matches('/')
}

/// `Client.prefixedKey`.
pub fn prefixed_key(key_prefix: &str, key: &str) -> String {
    let trimmed = key.trim_start_matches('/');
    if key_prefix.is_empty() {
        return trimmed.to_owned();
    }
    if trimmed.is_empty() {
        return key_prefix.to_owned();
    }
    format!("{key_prefix}/{trimmed}")
}

/// `Client.PresignGetURLAt` for the presigned case: `(url, expires_unix)`. Every call in the same
/// window signs at the window start, so replicas issue the same URL. `now_unix_nanos` truncates like
/// `time.Truncate`, from Go's zero time.
pub fn presign_get_url_at(
    req: &mut PresignRequest<'_>,
    now_unix_nanos: i128,
    expiry_seconds: i64,
    window_seconds: i64,
) -> Result<(String, i64), ParseError> {
    const MAX_LIFETIME: i64 = 7 * 24 * 3600;
    const GO_ZERO_TIME_UNIX: i128 = -62_135_596_800;
    let window = window_seconds.min(MAX_LIFETIME - expiry_seconds).max(0);
    let now_secs = now_unix_nanos.div_euclid(1_000_000_000);
    let issued = if window == 0 {
        now_secs as i64
    } else {
        let since_zero = now_secs - GO_ZERO_TIME_UNIX;
        (since_zero - since_zero.rem_euclid(i128::from(window)) + GO_ZERO_TIME_UNIX) as i64
    };
    let lifetime = window + expiry_seconds;
    req.issued_unix = issued;
    req.lifetime_seconds = lifetime;
    Ok((presign_get_url(req)?, issued + lifetime))
}

/// What a SigV4 presigned read URL needs.
#[derive(Debug, Clone, Default)]
pub struct PresignRequest<'a> {
    pub endpoint: &'a str,
    pub region: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub path_style: bool,
    pub bucket: &'a str,
    pub key: &'a str,
    pub issued_unix: i64,
    pub lifetime_seconds: i64,
}

/// `aws-sdk-go-v2`'s `EscapePath`, keeping slashes: only unreserved bytes pass.
fn escape_key(key: &str) -> String {
    key.split('/')
        .map(path_escape_strict)
        .collect::<Vec<_>>()
        .join("/")
}

fn path_escape_strict(segment: &str) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(segment.len());
    for &b in segment.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(UPPER[usize::from(b >> 4)]));
            out.push(char::from(UPPER[usize::from(b & 15)]));
        }
    }
    out
}

fn sigv4_date(unix: i64) -> (String, String) {
    let t = silo_gocompat::time::GoTime::from_unix(unix, 0);
    (t.format("20060102"), t.format("20060102T150405Z"))
}

/// `PresignGetObject` with a fixed signing time: the query-string SigV4 URL the AWS SDK produces.
pub fn presign_get_url(req: &PresignRequest<'_>) -> Result<String, ParseError> {
    let endpoint = req.endpoint.trim_end_matches('/');
    let (scheme, host_part) = endpoint.split_once("://").ok_or(ParseError)?;
    let (host_only, base_path) = match host_part.find('/') {
        Some(i) => (&host_part[..i], &host_part[i..]),
        None => (host_part, ""),
    };
    let (host, path) = if req.path_style {
        (
            host_only.to_owned(),
            format!("{base_path}/{}/{}", req.bucket, escape_key(req.key)),
        )
    } else {
        (
            format!("{}.{host_only}", req.bucket),
            format!("{base_path}/{}", escape_key(req.key)),
        )
    };
    let (date, stamp) = sigv4_date(req.issued_unix);
    let scope = format!("{date}/{}/s3/aws4_request", req.region);
    let credential = format!("{}/{scope}", req.access_key);
    let mut query = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_owned()),
        ("X-Amz-Credential", credential),
        ("X-Amz-Date", stamp.clone()),
        ("X-Amz-Expires", req.lifetime_seconds.to_string()),
        ("X-Amz-SignedHeaders", "host".to_owned()),
        ("x-id", "GetObject".to_owned()),
    ];
    query.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{k}={}", path_escape_strict(v)))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_request =
        format!("GET\n{path}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(
        format!("AWS4{}", req.secret_key).as_bytes(),
        &[date.as_bytes()],
    );
    let k_region = hmac_sha256(&k_date, &[req.region.as_bytes()]);
    let k_service = hmac_sha256(&k_region, &[b"s3"]);
    let k_signing = hmac_sha256(&k_service, &[b"aws4_request"]);
    let signature = hex_encode(hmac_sha256(&k_signing, &[string_to_sign.as_bytes()]));
    Ok(format!(
        "{scheme}://{host}{path}?{canonical_query}&X-Amz-Signature={signature}"
    ))
}
