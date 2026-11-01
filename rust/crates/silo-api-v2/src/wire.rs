//! `internal/apiv2/wire.go`: the v2 wire vocabulary shared by every operation's request and
//! response types — timestamps, opaque IDs, the presence-aware PATCH transport, the collection
//! envelope, and the shared sort-query grammar.

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _SerError,
};
use time::{Month, OffsetDateTime};

use crate::problem::{self, Problem, ProblemError};

fn go_zero_instant() -> OffsetDateTime {
    OffsetDateTime::new_utc(
        time::Date::from_calendar_date(1, Month::January, 1).expect("valid date"),
        time::Time::MIDNIGHT,
    )
}

/// `apiv2.Instant`: RFC 3339, UTC, exactly millisecond precision, `Z` suffix. The zero instant is
/// not a value: it is rejected on input and refused on output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(OffsetDateTime);

/// The decode failure both `Instant` and `NullableInstant` report: `expected an RFC 3339
/// instant`, matching Go's fixed message (the parser's own text is never echoed).
pub struct NotAnInstant;

fn truncate_to_millis(t: OffsetDateTime) -> OffsetDateTime {
    let nanos = t.unix_timestamp_nanos();
    let ms = nanos.div_euclid(1_000_000);
    OffsetDateTime::from_unix_timestamp_nanos(ms * 1_000_000).expect("in range")
}

impl Instant {
    /// `apiv2.NewInstant`.
    pub fn new(t: OffsetDateTime) -> Self {
        Instant(truncate_to_millis(t.to_offset(time::UtcOffset::UTC)))
    }

    /// `Instant.Time.IsZero`, checked against Go's `time.Time` zero value (year 1), not the Unix
    /// epoch.
    pub fn is_zero(&self) -> bool {
        self.0 == go_zero_instant()
    }

    /// Parses an RFC 3339 instant with any fractional-second precision and truncates it to
    /// milliseconds; rejects a zero instant. `apiv2.Instant.UnmarshalJSON`'s string half.
    pub fn parse(s: &str) -> Result<Self, NotAnInstant> {
        let parsed = OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map_err(|_| NotAnInstant)?;
        let i = Instant::new(parsed);
        if i.is_zero() {
            Err(NotAnInstant)
        } else {
            Ok(i)
        }
    }

    /// `Instant.String`.
    pub fn to_wire(&self) -> String {
        let d = self.0.date();
        let t = self.0.time();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            d.year(),
            u8::from(d.month()),
            d.day(),
            t.hour(),
            t.minute(),
            t.second(),
            t.millisecond()
        )
    }
}

impl Serialize for Instant {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.is_zero() {
            return Err(S::Error::custom("instant is zero"));
        }
        s.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for Instant {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        let s: &str = match &v {
            serde_json::Value::Null => "",
            serde_json::Value::String(s) => s.as_str(),
            _ => return Err(D::Error::custom("expected an RFC 3339 instant string")),
        };
        Instant::parse(s).map_err(|_| D::Error::custom("expected an RFC 3339 instant"))
    }
}

/// `apiv2.NullableInstant`: the explicit-null form, a documented "known to have no value",
/// distinct from field omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NullableInstant {
    pub valid: bool,
    pub time: Option<Instant>,
}

impl Serialize for NullableInstant {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match (self.valid, self.time) {
            (true, Some(t)) => t.serialize(s),
            _ => s.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for NullableInstant {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        if v.is_null() {
            return Ok(NullableInstant {
                valid: false,
                time: None,
            });
        }
        let s: &str = match &v {
            serde_json::Value::String(s) => s.as_str(),
            _ => return Err(D::Error::custom("expected an RFC 3339 instant string")),
        };
        let t = Instant::parse(s).map_err(|_| D::Error::custom("expected an RFC 3339 instant"))?;
        Ok(NullableInstant {
            valid: true,
            time: Some(t),
        })
    }
}

/// `apiv2.ID`: an opaque string identifier. Numeric database keys cross the wire as strings;
/// clients never parse or order them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id(pub String);

impl Id {
    /// `apiv2.IDFromInt`.
    pub fn from_int(v: i64) -> Self {
        Id(v.to_string())
    }

    /// `apiv2.intOfID`: recovers an internal integer key, rejecting anything but a canonical
    /// positive decimal (no leading zeros, sign, or whitespace).
    pub fn to_int(&self) -> Option<i64> {
        let n: i64 = self.0.parse().ok()?;
        if n <= 0 || n.to_string() != self.0 {
            return None;
        }
        Some(n)
    }
}

/// `apiv2.Patch[T]`: the presence-aware PATCH transport for one field — omitted (unchanged),
/// explicit null (clear), or a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch<T> {
    pub present: bool,
    pub null: bool,
    pub value: T,
}

impl<T: Default> Default for Patch<T> {
    fn default() -> Self {
        Patch {
            present: false,
            null: false,
            value: T::default(),
        }
    }
}

impl<T> Patch<T> {
    /// `Patch.IsZero`: true for an absent field, so `skip_serializing_if = "Patch::is_absent"`
    /// on the container field reproduces Go's `json:",omitzero"`.
    pub fn is_absent(&self) -> bool {
        !self.present
    }
}

impl<T: Serialize> Serialize for Patch<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if !self.present || self.null {
            s.serialize_none()
        } else {
            self.value.serialize(s)
        }
    }
}

impl<'de, T: Deserialize<'de> + Default> Deserialize<'de> for Patch<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        if v.is_null() {
            return Ok(Patch {
                present: true,
                null: true,
                value: T::default(),
            });
        }
        let value = T::deserialize(v).map_err(D::Error::custom)?;
        Ok(Patch {
            present: true,
            null: false,
            value,
        })
    }
}

/// `apiv2.PageInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PageInfo {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_cursor: String,
    pub has_more: bool,
}

/// `apiv2.Collection[T]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Collection<T> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<PageInfo>,
}

/// `apiv2.NewCollection`.
pub fn new_collection<T>(items: Vec<T>) -> Collection<T> {
    Collection { items, page: None }
}

/// `apiv2.Paginated`.
pub fn paginated<T>(items: Vec<T>, next: impl Into<String>) -> Collection<T> {
    let next = next.into();
    let has_more = !next.is_empty();
    Collection {
        items,
        page: Some(PageInfo {
            next_cursor: next,
            has_more,
        }),
    }
}

/// `apiv2.DefaultLimit`.
pub const DEFAULT_LIMIT: u32 = 50;

/// `apiv2.SortField`: one parsed `sort=field,-other` term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortField {
    pub field: String,
    pub desc: bool,
}

/// `apiv2.ParseSort`: parses the `sort=field,-other` grammar against an operation's allowlist.
/// An unknown or duplicated field is a validation failure (422).
// `Problem` is the one error type this whole wire kit returns; every other fallible function
// here returns `Option<Problem>` instead of `Result<_, Problem>`, so boxing just this one `Err`
// would be an inconsistent one-off rather than a real size fix.
#[allow(clippy::result_large_err)]
pub fn parse_sort(raw: &str, allowed: &[&str]) -> Result<Vec<SortField>, Problem> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for term in raw.split(',') {
        let field = term.trim();
        let (desc, field) = match field.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, field),
        };
        if field.is_empty() || !allowed.contains(&field) || !seen.insert(field.to_owned()) {
            return Err(invalid_sort_field());
        }
        out.push(SortField {
            field: field.to_owned(),
            desc,
        });
    }
    Ok(out)
}

fn invalid_sort_field() -> Problem {
    Problem::new(
        problem::validation_failed(),
        "The request did not pass validation; see errors.",
    )
    .with_errors([ProblemError {
        location: "query.sort".to_owned(),
        code: "invalid_sort_field".to_owned(),
        detail: "sort names a field this operation does not sort by, or names one twice".to_owned(),
    }])
}
