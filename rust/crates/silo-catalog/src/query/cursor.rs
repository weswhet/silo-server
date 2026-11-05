//! `query_cursor.go`: the cursor tuple, its term kinds, and the keyset seek.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Arg;
use super::definition::{
    DEFAULT_SORT_FIELD, QUERY_SORT_BITRATE, QUERY_SORT_CONTENT_RATING, QUERY_SORT_DATE_VIEWED,
    QUERY_SORT_LAST_AIR_DATE, QUERY_SORT_LATEST_EPISODE_ADDED, QUERY_SORT_PLAYS,
    QUERY_SORT_PROGRESS, QUERY_SORT_RATING_IMDB, QUERY_SORT_RATING_RT_AUDIENCE,
    QUERY_SORT_RATING_RT_CRITIC, QUERY_SORT_RATING_TMDB, QUERY_SORT_RELEASE_DATE,
    QUERY_SORT_RESOLUTION, QUERY_SORT_RUNTIME, QUERY_SORT_YEAR,
};

pub const CURSOR_KIND_TEXT: &str = "text";
pub const CURSOR_KIND_NUMBER: &str = "number";
pub const CURSOR_KIND_TIMESTAMP: &str = "timestamp";
pub const CURSOR_KIND_DATE: &str = "date";

/// `ErrCatalogCursorChanged`'s text.
pub const ERR_CATALOG_CURSOR_CHANGED: &str = "catalog source changed during pagination";

/// `QueryCursor`. `search` and `collection` belong to the resolver and are carried as raw JSON.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct QueryCursor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<Value>,
    /// Go writes a nil slice as `null`; the engine never builds an empty non-nil one.
    #[serde(serialize_with = "keys_out", deserialize_with = "keys_in")]
    pub keys: Vec<QueryCursorValue>,
    pub consumed: i64,
}

fn keys_out<S: serde::Serializer>(keys: &[QueryCursorValue], s: S) -> Result<S::Ok, S::Error> {
    if keys.is_empty() {
        s.serialize_none()
    } else {
        s.collect_seq(keys)
    }
}

fn keys_in<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<QueryCursorValue>, D::Error> {
    Ok(Option::<Vec<QueryCursorValue>>::deserialize(d)?.unwrap_or_default())
}

/// `QueryCursorValue`. A `None` value is SQL NULL.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct QueryCursorValue {
    pub kind: String,
    pub value: Option<String>,
}

/// `queryCursorTerm`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CursorTerm {
    pub expression: String,
    pub kind: String,
    pub descending: bool,
    pub nulls_last: bool,
    pub not_null: bool,
    pub sql_type: String,
}

impl CursorTerm {
    pub(crate) fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            ..Self::default()
        }
    }

    /// `cast`.
    pub fn cast(&self) -> &str {
        if !self.sql_type.is_empty() {
            return &self.sql_type;
        }
        match self.kind.as_str() {
            CURSOR_KIND_DATE => CURSOR_KIND_DATE,
            CURSOR_KIND_NUMBER => "numeric",
            CURSOR_KIND_TIMESTAMP => "timestamptz",
            _ => CURSOR_KIND_TEXT,
        }
    }
}

/// `setCursorTermKinds`.
pub fn set_cursor_term_kinds(terms: &mut [CursorTerm], field: &str) {
    for term in terms.iter_mut() {
        if term.kind.is_empty() {
            term.kind = CURSOR_KIND_TEXT.into();
        }
        if !term.descending {
            term.nulls_last = true;
        }
    }
    if terms.is_empty() {
        return;
    }
    match field {
        QUERY_SORT_LAST_AIR_DATE => terms[0].kind = CURSOR_KIND_DATE.into(),
        QUERY_SORT_RELEASE_DATE => {
            if terms[0].expression.ends_with(".episode_air_date") {
                terms[0].kind = CURSOR_KIND_DATE.into();
            }
        }
        DEFAULT_SORT_FIELD | QUERY_SORT_DATE_VIEWED | QUERY_SORT_LATEST_EPISODE_ADDED => {
            terms[0].kind = CURSOR_KIND_TIMESTAMP.into();
        }
        QUERY_SORT_YEAR
        | QUERY_SORT_RUNTIME
        | QUERY_SORT_RATING_IMDB
        | QUERY_SORT_RATING_TMDB
        | QUERY_SORT_RATING_RT_CRITIC
        | QUERY_SORT_RATING_RT_AUDIENCE
        | QUERY_SORT_RESOLUTION
        | QUERY_SORT_BITRATE
        | QUERY_SORT_PROGRESS
        | QUERY_SORT_PLAYS
        | QUERY_SORT_CONTENT_RATING => terms[0].kind = CURSOR_KIND_NUMBER.into(),
        // playableTypeSeries.
        "series" => terms[1].kind = CURSOR_KIND_NUMBER.into(),
        _ => {}
    }
}

/// `cursorSeekSQL`: the mixed-direction, nullable tuple comparison after `after`, numbering its
/// arguments from `start`. `None` yields no seek.
pub fn cursor_seek_sql(
    terms: &[CursorTerm],
    after: Option<&QueryCursor>,
    start: usize,
) -> Result<(String, Vec<Arg>), String> {
    let Some(after) = after else {
        return Ok((String::new(), Vec::new()));
    };
    if after.keys.len() != terms.len() {
        return Err(format!(
            "{ERR_CATALOG_CURSOR_CHANGED}: cursor key count does not match sort"
        ));
    }
    let mut arms: Vec<String> = Vec::new();
    let mut equal: Vec<String> = Vec::new();
    let mut args: Vec<Arg> = Vec::new();
    let mut bound = String::new();
    for (i, term) in terms.iter().enumerate() {
        let key = &after.keys[i];
        if key.kind != term.kind {
            return Err(format!(
                "{ERR_CATALOG_CURSOR_CHANGED}: cursor key {i} has invalid kind"
            ));
        }
        let expr = &term.expression;
        let mut comparison = "FALSE".to_owned();
        let mut equality = format!("{expr} IS NULL");
        match &key.value {
            None => {
                if !term.nulls_last {
                    comparison = format!("{expr} IS NOT NULL");
                }
            }
            Some(value) => {
                let param = format!("${}::{}", start + args.len(), term.cast());
                args.push(Arg::Str(value.clone()));
                let operator = if term.descending { "<" } else { ">" };
                comparison = format!("{expr} {operator} {param}");
                if term.nulls_last && !term.not_null {
                    comparison = format!("({comparison} OR {expr} IS NULL)");
                }
                equality = format!("{expr} = {param}");
                if i == 0 && term.not_null {
                    bound = format!("{expr} {operator}= {param}");
                }
            }
        }
        let mut prefix = equal.clone();
        prefix.push(comparison);
        arms.push(format!("({})", prefix.join(" AND ")));
        equal.push(equality);
    }
    let mut seek = format!("({})", arms.join(" OR "));
    if !bound.is_empty() {
        seek = format!("({bound} AND {seek})");
    }
    Ok((seek, args))
}
