//! `internal/apiv2/precondition.go`: RFC 9110 entity tags, the `If-Match` / `If-None-Match`
//! list grammar, strong and weak comparison, and the mapping of each precondition outcome onto
//! the [`crate::problem`] catalog.
//!
//! Entity-tag rendering and parsing (`RenderETag`, `ParseEntityTag`, `ParseETagList`) already
//! live in `silo_core::apiv2`, ported there for the cursor and settings work that needed them
//! first; this module depends on that port rather than re-implementing it (the repository's
//! dedup rule). Everything here — strong/weak matching and the seven `Evaluate*` outcome
//! functions, which are specific to the v2 wire kit and were not ported elsewhere — is new.

use silo_core::apiv2::{
    self as core_apiv2, ETagList, EntityTag as RenderedTag, MalformedEntityTag,
};

use crate::problem::{self, Problem, ProblemError};

/// A parsed or rendered entity-tag, in the uniform shape `StrongMatch`/`WeakMatch` compare: the
/// opaque text as bytes (RFC 9110 `etagc` allows `obs-text`, so it is not always valid UTF-8) and
/// whether the `W/` weakness prefix was present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub opaque: Vec<u8>,
    pub weak: bool,
}

impl Tag {
    /// Whether the tag is the zero value (no tag at all), matching `EntityTag.IsZero`. An empty
    /// opaque-tag parsed from the wire is a different, non-zero value; only the Rust default /
    /// Go zero value is zero.
    pub fn is_zero(&self) -> bool {
        self.opaque.is_empty() && !self.weak
    }

    /// The wire form: `"opaque"` or `W/"opaque"`, rendered as Go's `%q`-free direct concatenation
    /// does (the opaque text is never re-escaped; a resource's own rendered tag is always
    /// ASCII-safe, and a tag copied back from a client is only ever compared, never echoed).
    pub fn to_wire(&self) -> String {
        let text = String::from_utf8_lossy(&self.opaque);
        if self.weak {
            format!("W/\"{text}\"")
        } else {
            format!("\"{text}\"")
        }
    }
}

impl From<&RenderedTag> for Tag {
    fn from(t: &RenderedTag) -> Self {
        Tag {
            opaque: t.opaque.as_bytes().to_vec(),
            weak: t.weak,
        }
    }
}

impl From<(Vec<u8>, bool)> for Tag {
    fn from((opaque, weak): (Vec<u8>, bool)) -> Self {
        Tag { opaque, weak }
    }
}

/// `apiv2.StrongMatch`.
pub fn strong_match(a: &Tag, b: &Tag) -> bool {
    !a.weak && !b.weak && a.opaque == b.opaque
}

/// `apiv2.WeakMatch`.
pub fn weak_match(a: &Tag, b: &Tag) -> bool {
    a.opaque == b.opaque
}

const IF_MATCH_FIELD: &str = "If-Match";
const IF_NONE_MATCH_FIELD: &str = "If-None-Match";
const ETAG_FIELD: &str = "ETag";

fn malformed_etag_list(field: &str) -> Problem {
    Problem::new(
        problem::malformed_request(),
        format!("The {field} header field is not a valid entity-tag list."),
    )
    .with_errors([ProblemError {
        location: format!("header.{field}"),
        code: "invalid_entity_tag".to_owned(),
        detail: "expected \"*\" or a comma-separated list of quoted entity-tags".to_owned(),
    }])
}

/// The parsed state of an `If-Match` / `If-None-Match` field: unparsed list elements folded into
/// [`Tag`]s so [`strong_match`] / [`weak_match`] can compare them uniformly.
enum Parsed {
    Star,
    Tags(Vec<Tag>),
}

fn parse(field: &str) -> Result<Parsed, MalformedEntityTag> {
    match core_apiv2::parse_etag_list(field.as_bytes())? {
        ETagList::Star => Ok(Parsed::Star),
        ETagList::Tags(tags) => Ok(Parsed::Tags(tags.into_iter().map(Tag::from).collect())),
    }
}

/// `apiv2.EvaluateIfMatch`.
pub fn evaluate_if_match(if_match: &str, current: &RenderedTag) -> Option<Problem> {
    if if_match.is_empty() {
        return Some(Problem::new(
            problem::precondition_required(),
            "This operation requires the If-Match header field carrying the resource's current ETag.",
        ));
    }
    let current = Tag::from(current);
    match parse(if_match) {
        Err(_) => Some(malformed_etag_list(IF_MATCH_FIELD)),
        Ok(Parsed::Star) => None,
        Ok(Parsed::Tags(tags)) => {
            if tags.iter().any(|t| strong_match(t, &current)) {
                None
            } else {
                Some(stale_version_problem(Some(&current)))
            }
        }
    }
}

/// `apiv2.EvaluateIfNoneMatch`.
pub fn evaluate_if_none_match(
    if_none_match: &str,
    current: &RenderedTag,
) -> (bool, Option<Problem>) {
    if if_none_match.is_empty() {
        return (false, None);
    }
    let current = Tag::from(current);
    match parse(if_none_match) {
        Err(_) => (false, Some(malformed_etag_list(IF_NONE_MATCH_FIELD))),
        Ok(Parsed::Star) => (true, None),
        Ok(Parsed::Tags(tags)) => (tags.iter().any(|t| weak_match(t, &current)), None),
    }
}

/// `apiv2.EvaluateCreateOnly`.
pub fn evaluate_create_only(
    if_none_match: &str,
    existing: Option<&RenderedTag>,
) -> Option<Problem> {
    if if_none_match.is_empty() {
        return None;
    }
    let parsed = match parse(if_none_match) {
        Err(_) => return Some(malformed_etag_list(IF_NONE_MATCH_FIELD)),
        Ok(p) => p,
    };
    let existing = existing?;
    let existing_tag = Tag::from(existing);
    let matched = match &parsed {
        Parsed::Star => true,
        Parsed::Tags(tags) => tags.iter().any(|t| weak_match(t, &existing_tag)),
    };
    if matched {
        Some(
            Problem::new(
                problem::precondition_failed(),
                "A resource already exists at this identifier.",
            )
            .with_header(ETAG_FIELD, existing.to_wire()),
        )
    } else {
        None
    }
}

/// `apiv2.EvaluateGuardedPreconditions`.
pub fn evaluate_guarded_preconditions(
    if_match: &str,
    if_none_match: &str,
    current: &RenderedTag,
) -> Option<Problem> {
    if let Some(p) = evaluate_if_match(if_match, current) {
        return Some(p);
    }
    if if_none_match.is_empty() {
        return None;
    }
    let current_tag = Tag::from(current);
    match parse(if_none_match) {
        Err(_) => Some(malformed_etag_list(IF_NONE_MATCH_FIELD)),
        Ok(Parsed::Star) => Some(
            Problem::new(
                problem::precondition_failed(),
                "If-None-Match: * refuses the mutation because the resource exists.",
            )
            .with_header(ETAG_FIELD, current.to_wire()),
        ),
        Ok(Parsed::Tags(tags)) => {
            if tags.iter().any(|t| weak_match(t, &current_tag)) {
                Some(
                    Problem::new(
                        problem::precondition_failed(),
                        "A tag named by If-None-Match matches the current representation; the mutation was not applied.",
                    )
                    .with_header(ETAG_FIELD, current.to_wire()),
                )
            } else {
                None
            }
        }
    }
}

/// `apiv2.EvaluateReadPreconditions`.
pub fn evaluate_read_preconditions(
    if_match: &str,
    if_none_match: &str,
    current: &RenderedTag,
) -> (bool, Option<Problem>) {
    if !if_match.is_empty()
        && let Some(p) = evaluate_if_match(if_match, current)
    {
        return (false, Some(p));
    }
    evaluate_if_none_match(if_none_match, current)
}

/// `apiv2.EvaluateCreateOnlyPreconditions`.
pub fn evaluate_create_only_preconditions(
    if_match: &str,
    if_none_match: &str,
    existing: Option<&RenderedTag>,
) -> Option<Problem> {
    if !if_match.is_empty() {
        match existing {
            None => {
                return Some(match parse(if_match) {
                    Err(_) => malformed_etag_list(IF_MATCH_FIELD),
                    Ok(_) => Problem::new(
                        problem::precondition_failed(),
                        "If-Match names a resource, but none exists at this identifier.",
                    ),
                });
            }
            Some(existing) => {
                if let Some(p) = evaluate_if_match(if_match, existing) {
                    return Some(p);
                }
            }
        }
    }
    evaluate_create_only(if_none_match, existing)
}

/// `apiv2.IsOverwrite`.
pub fn is_overwrite(if_match: &str) -> bool {
    matches!(parse(if_match), Ok(Parsed::Star))
}

/// `apiv2.StaleVersionProblem`. `current: None` omits the `ETag` header, matching a call with the
/// zero `EntityTag` value in Go.
pub fn stale_version_problem(current: Option<&Tag>) -> Problem {
    let p = Problem::new(
        problem::precondition_failed(),
        "The resource changed while the request was being applied; fetch it again and retry against the current ETag.",
    );
    match current {
        Some(t) if !t.is_zero() => p.with_header(ETAG_FIELD, t.to_wire()),
        _ => p,
    }
}
