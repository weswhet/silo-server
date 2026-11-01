//! `internal/apiv2`: entity tags and pagination cursors, which replicas must agree on while a client
//! holds them.

use serde::Serialize;
use silo_gocompat::json::{self, RawMessage};
use silo_jwt::base64go::{raw_url_decode, raw_url_encode};

use crate::hexgo::{ct_eq, encode as hex_encode, hmac_sha256, sha256};

/// `EntityTag`: the opaque text and whether the `W/` prefix was present.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntityTag {
    pub opaque: String,
    pub weak: bool,
}

impl EntityTag {
    /// `EntityTag.String`.
    pub fn to_wire(&self) -> String {
        if self.weak {
            format!("W/\"{}\"", self.opaque)
        } else {
            format!("\"{}\"", self.opaque)
        }
    }
}

fn base36(mut v: u64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if v == 0 {
        return "0".to_owned();
    }
    let mut out = Vec::new();
    while v > 0 {
        out.push(DIGITS[(v % 36) as usize]);
        v /= 36;
    }
    out.reverse();
    String::from_utf8(out).expect("ASCII")
}

/// `RenderETag`: SHA-256 over the length-prefixed scope and ID names the resource, and the XOR with the
/// version keeps two versions of one resource apart.
pub fn render_etag(scope: &[u8], id: &[u8], version: i64) -> EntityTag {
    let mut preimage = Vec::with_capacity(16 + scope.len() + id.len());
    preimage.extend_from_slice(&(scope.len() as u64).to_be_bytes());
    preimage.extend_from_slice(scope);
    preimage.extend_from_slice(&(id.len() as u64).to_be_bytes());
    preimage.extend_from_slice(id);
    let digest = sha256(&preimage);
    let binding = hex_encode(&digest[..12]);
    let mask = u64::from_be_bytes(digest[12..20].try_into().expect("8 bytes"));
    EntityTag {
        opaque: format!("{binding}.{}", base36(version as u64 ^ mask)),
        weak: false,
    }
}

/// `ErrMalformedEntityTag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedEntityTag;

fn is_etag_char(b: u8) -> bool {
    b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80
}

/// `ParseEntityTag`.
pub fn parse_entity_tag(s: &[u8]) -> Result<(Vec<u8>, bool), MalformedEntityTag> {
    let (weak, s) = match s.strip_prefix(b"W/") {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    if s.len() < 2 || s[0] != b'"' || s[s.len() - 1] != b'"' {
        return Err(MalformedEntityTag);
    }
    let inner = &s[1..s.len() - 1];
    if !inner.iter().all(|b| is_etag_char(*b)) {
        return Err(MalformedEntityTag);
    }
    Ok((inner.to_vec(), weak))
}

/// `ParseETagList`: the tags as `(opaque, weak)`, or the wildcard.
pub fn parse_etag_list(field: &[u8]) -> Result<ETagList, MalformedEntityTag> {
    let trimmed: &[u8] = {
        let is_ows = |b: &u8| *b == b' ' || *b == b'\t';
        let start = field.iter().position(|b| !is_ows(b)).unwrap_or(field.len());
        let end = field
            .iter()
            .rposition(|b| !is_ows(b))
            .map_or(start, |p| p + 1);
        &field[start..end]
    };
    if trimmed == b"*" {
        return Ok(ETagList::Star);
    }
    let mut tags = Vec::new();
    let mut i = 0;
    while i < field.len() {
        while i < field.len() && (field[i] == b' ' || field[i] == b'\t') {
            i += 1;
        }
        if i == field.len() {
            break;
        }
        if field[i] == b',' {
            i += 1;
            continue;
        }
        let start = i;
        if field[i..].starts_with(b"W/") {
            i += 2;
        }
        if i == field.len() || field[i] != b'"' {
            return Err(MalformedEntityTag);
        }
        i += 1;
        while i < field.len() && field[i] != b'"' {
            i += 1;
        }
        if i == field.len() {
            return Err(MalformedEntityTag);
        }
        i += 1;
        tags.push(parse_entity_tag(&field[start..i])?);
        while i < field.len() && (field[i] == b' ' || field[i] == b'\t') {
            i += 1;
        }
        if i < field.len() {
            if field[i] != b',' {
                return Err(MalformedEntityTag);
            }
            i += 1;
        }
    }
    Ok(ETagList::Tags(tags))
}

/// The value of an `If-Match` or `If-None-Match` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ETagList {
    Star,
    Tags(Vec<(Vec<u8>, bool)>),
}

/// `CursorScope`: a cursor presented against a different scope is invalid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CursorScope {
    pub operation_id: String,
    pub security: String,
    pub filter: String,
    pub sort: String,
    pub tiebreaker: String,
}

impl CursorScope {
    fn key(&self) -> String {
        [
            self.operation_id.as_str(),
            &self.security,
            &self.filter,
            &self.sort,
            &self.tiebreaker,
        ]
        .join("\0")
    }
}

/// `Cursors.Decode` failures, which map to `invalid_cursor` and `dependency_unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorError {
    Invalid,
    NotConfigured,
}

fn cursor_mac(secret: &[u8], scope: &CursorScope, body: &[u8]) -> [u8; 32] {
    hmac_sha256(secret, &[scope.key().as_bytes(), &[0], body])
}

/// `Cursors.Encode`: `base64url(json{v:1,p}).base64url(hmac)`. The position is authenticated, not
/// encrypted, so it must not hold credentials.
pub fn encode_cursor<P: Serialize + ?Sized>(
    secret: &[u8],
    scope: &CursorScope,
    position: &P,
) -> Result<String, CursorError> {
    #[derive(Serialize)]
    struct Body {
        v: i64,
        p: RawMessage,
    }
    if secret.is_empty() {
        return Err(CursorError::NotConfigured);
    }
    let pos = json::marshal(position).map_err(|_| CursorError::Invalid)?;
    let body = json::marshal(&Body {
        v: 1,
        p: RawMessage::from(pos),
    })
    .map_err(|_| CursorError::Invalid)?;
    let mac = cursor_mac(secret, scope, &body);
    Ok(format!("{}.{}", raw_url_encode(&body), raw_url_encode(mac)))
}

/// `Cursors.Decode` up to the position: the authenticated raw JSON of `p`, which the caller decodes
/// with `silo_jwt::gojson` into its own position type.
pub fn decode_cursor(
    secret: &[u8],
    scope: &CursorScope,
    cursor: &str,
) -> Result<Vec<u8>, CursorError> {
    if secret.is_empty() {
        return Err(CursorError::NotConfigured);
    }
    let (body64, mac64) = cursor.split_once('.').ok_or(CursorError::Invalid)?;
    let body = raw_url_decode(body64).map_err(|_| CursorError::Invalid)?;
    let mac = raw_url_decode(mac64).map_err(|_| CursorError::Invalid)?;
    if !ct_eq(&mac, &cursor_mac(secret, scope, &body)) {
        return Err(CursorError::Invalid);
    }
    let fields = raw_object_fields(&body).ok_or(CursorError::Invalid)?;
    let mut version: i64 = 0;
    let mut pos: Option<Vec<u8>> = None;
    for (key, raw) in fields {
        if silo_gocompat::strings::equal_fold(&key, "v") {
            if raw == b"null" {
                continue;
            }
            version = std::str::from_utf8(&raw)
                .ok()
                .and_then(|t| t.parse().ok())
                .ok_or(CursorError::Invalid)?;
        } else if silo_gocompat::strings::equal_fold(&key, "p") {
            pos = Some(raw);
        }
    }
    if version != 1 {
        return Err(CursorError::Invalid);
    }
    pos.ok_or(CursorError::Invalid)
}

/// Splits a JSON object into key and raw-value spans, in source order.
fn raw_object_fields(body: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    if !json::valid(body) {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 0;
    let skip_ws = |i: &mut usize| {
        while *i < body.len() && matches!(body[*i], b' ' | b'\t' | b'\r' | b'\n') {
            *i += 1;
        }
    };
    skip_ws(&mut i);
    if body.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    loop {
        skip_ws(&mut i);
        match body.get(i)? {
            b'}' => return Some(out),
            b',' => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let key_start = i;
        i = skip_string(body, i);
        let key: String = silo_jwt::gojson::parse_value(&body[key_start..i])
            .ok()?
            .as_str()?
            .to_owned();
        skip_ws(&mut i);
        i += 1; // ':'
        skip_ws(&mut i);
        let start = i;
        let mut depth = 0usize;
        loop {
            match *body.get(i)? {
                b'"' => i = skip_string(body, i),
                b'{' | b'[' => {
                    depth += 1;
                    i += 1;
                }
                b'}' | b']' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                    i += 1;
                }
                b',' if depth == 0 => break,
                b' ' | b'\t' | b'\r' | b'\n' if depth == 0 => break,
                _ => i += 1,
            }
        }
        out.push((key, body[start..i].to_vec()));
    }
}

fn skip_string(body: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < body.len() {
        match body[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    i
}

/// The visibility fields of `access.Scope` that `viewerScopeDigest` reads. A `None` ID list and an empty
/// one are different policies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewerScope {
    pub policy_revision: i64,
    pub libraries_restricted: bool,
    pub allowed_library_ids: Option<Vec<i64>>,
    pub disabled_library_ids: Option<Vec<i64>>,
    pub max_content_rating: String,
    pub allow_unrated_content: bool,
    pub max_advisory_age: i64,
    pub require_advisory_age: bool,
}

/// `viewerScopeDigest`. A request that resolved no scope is the literal `none`.
pub fn viewer_scope_digest(scope: Option<&ViewerScope>) -> String {
    let Some(scope) = scope else {
        return "none".to_owned();
    };
    fn ids(list: &Option<Vec<i64>>) -> String {
        match list {
            None => "-".to_owned(),
            Some(list) => {
                let mut sorted = list.clone();
                sorted.sort_unstable();
                sorted
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            }
        }
    }
    let mut parts = vec![
        scope.policy_revision.to_string(),
        if scope.libraries_restricted { "1" } else { "0" }.to_owned(),
        ids(&scope.allowed_library_ids),
        ids(&scope.disabled_library_ids),
        scope.max_content_rating.clone(),
        scope.allow_unrated_content.to_string(),
    ];
    if scope.max_advisory_age > 0 {
        parts.push(format!("advisory={}", scope.max_advisory_age));
    }
    if scope.max_advisory_age > 0 && scope.require_advisory_age {
        parts.push("requireadvisory".to_owned());
    }
    hex_encode(&sha256(parts.join("\0"))[..8])
}
