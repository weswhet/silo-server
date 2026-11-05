//! `query_definition.go`: the query definition, its field and sort vocabularies, and validation.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{lower_trim, q, sprintf, trim};

pub const DEFAULT_SORT_FIELD: &str = "added_at";

pub const QUERY_SORT_YEAR: &str = "year";
pub const QUERY_SORT_RUNTIME: &str = "runtime";
pub const QUERY_SORT_RATING_IMDB: &str = "rating_imdb";
pub const QUERY_SORT_RATING_TMDB: &str = "rating_tmdb";
pub const QUERY_SORT_RATING_RT_CRITIC: &str = "rating_rt_critic";
pub const QUERY_SORT_RATING_RT_AUDIENCE: &str = "rating_rt_audience";
pub const QUERY_SORT_RESOLUTION: &str = "resolution";
pub const QUERY_SORT_PROGRESS: &str = "progress";
pub const QUERY_SORT_LATEST_EPISODE_ADDED: &str = "latest_episode_added";
pub const QUERY_SORT_PLAYS: &str = "plays";
pub const QUERY_SORT_TITLE: &str = "title";
pub const QUERY_SORT_DATE_VIEWED: &str = "date_viewed";
pub const QUERY_SORT_CONTENT_RATING: &str = "content_rating";
pub const QUERY_SORT_RELEASE_DATE: &str = "release_date";
pub const QUERY_SORT_LAST_AIR_DATE: &str = "last_air_date";
pub const QUERY_SORT_BITRATE: &str = "bitrate";

pub const RULE_OP_IN_LAST: &str = "in_last";
pub const RULE_OP_NOT_IN_LAST: &str = "not_in_last";
pub const RULE_OP_NOT_CONTAINS: &str = "not_contains";
pub const RULE_OP_BEGINS_WITH: &str = "begins_with";
pub const RULE_OP_ENDS_WITH: &str = "ends_with";
pub const RULE_FIELD_DECADE: &str = "decade";
pub const RULE_FIELD_SHOW_TITLE: &str = "show_title";
pub const LATEST_EPISODE_ADDED_COLUMN: &str = "latest_episode_added_at";
pub const LATEST_AVAILABLE_AIR_DATE_COLUMN: &str = "latest_available_episode_air_date_at";

pub const MEDIA_SCOPE_VIDEO: &str = "video";
pub const MEDIA_SCOPE_VIDEO_WITH_EPISODES: &str = "video_with_episodes";
pub const DEFAULT_SMART_COLLECTION_ITEM_LIMIT: i64 = 10_000_000;

const RELEASE_DATE_COLUMN: &str =
    "COALESCE(%s.release_date::text, NULLIF(BTRIM(%s.first_air_date), ''))";

/// `queryFieldDef`.
#[derive(Clone, Copy, Debug)]
pub struct FieldDef {
    pub column_sql: &'static str,
    pub is_array: bool,
    pub executable: bool,
    pub personalized: bool,
    pub valid_ops: &'static [&'static str],
}

impl FieldDef {
    /// `allows`: not_in_last rides on in_last.
    pub fn allows(&self, op: &str) -> bool {
        self.valid_ops.contains(&op)
            || (op == RULE_OP_NOT_IN_LAST && self.valid_ops.contains(&RULE_OP_IN_LAST))
    }
}

const EQ: &[&str] = &["is", "is_not"];
const IS: &[&str] = &["is"];
const TEXT_OPS: &[&str] = &[
    "is",
    "is_not",
    "contains",
    RULE_OP_NOT_CONTAINS,
    RULE_OP_BEGINS_WITH,
    RULE_OP_ENDS_WITH,
];
const NUMBER_OPS: &[&str] = &["gt", "gte", "lt", "lte", "between"];
const DATE_OPS: &[&str] = &["gt", "lt", "between", RULE_OP_IN_LAST];

/// `queryFieldDefs`, after `queryFieldAliases`.
pub fn field_def(field: &str) -> Option<FieldDef> {
    let d = |column_sql, is_array, personalized, valid_ops| FieldDef {
        column_sql,
        is_array,
        executable: true,
        personalized,
        valid_ops,
    };
    Some(match field {
        "type" => d("type", false, false, EQ),
        "genre" => d("genres", true, false, &["is", "is_not", "contains"]),
        "year" => d(
            "year",
            false,
            false,
            &["is", "is_not", "gt", "gte", "lt", "lte", "between"],
        ),
        "rating_imdb" => d("rating_imdb", false, false, NUMBER_OPS),
        "studio" => d("studios", true, false, EQ),
        "network" => d("networks", true, false, EQ),
        "country" => d("countries", true, false, EQ),
        "original_language" => d("original_language", false, false, EQ),
        "content_rating" => d("content_rating", false, false, EQ),
        "added_at" => d(
            "created_at",
            false,
            false,
            &["gt", "lt", "between", "in_last"],
        ),
        "release_date" => d(
            RELEASE_DATE_COLUMN,
            false,
            false,
            &["gt", "lt", "between", "in_last"],
        ),
        "status" => d("status", false, false, EQ),
        "actor" | "director" | "writer" | "producer" | "author" | "narrator" | "series" => {
            d("", false, false, EQ)
        }
        "watched" | "favorited" | "in_watchlist" | "in_progress" => d("", false, true, IS),
        "last_watched" => d(
            "",
            false,
            true,
            &["gt", "gte", "lt", "lte", "between", "in_last"],
        ),
        "resolution" => d("", false, false, EQ),
        "hdr" | "dolby_vision" => d("", false, false, IS),
        "bitrate" => d("", false, false, NUMBER_OPS),
        "audio_language" | "subtitle_language" => d("", false, false, EQ),
        RULE_FIELD_SHOW_TITLE => d("", false, false, TEXT_OPS),
        QUERY_SORT_TITLE => d(QUERY_SORT_TITLE, false, false, TEXT_OPS),
        RULE_FIELD_DECADE => d("", false, false, EQ),
        QUERY_SORT_RUNTIME => d("NULLIF(%s.runtime, 0)", false, false, NUMBER_OPS),
        QUERY_SORT_RATING_TMDB => d(QUERY_SORT_RATING_TMDB, false, false, NUMBER_OPS),
        QUERY_SORT_RATING_RT_CRITIC => d(QUERY_SORT_RATING_RT_CRITIC, false, false, NUMBER_OPS),
        QUERY_SORT_RATING_RT_AUDIENCE => d(QUERY_SORT_RATING_RT_AUDIENCE, false, false, NUMBER_OPS),
        QUERY_SORT_LATEST_EPISODE_ADDED => d(LATEST_EPISODE_ADDED_COLUMN, false, false, DATE_OPS),
        QUERY_SORT_LAST_AIR_DATE => d(LATEST_AVAILABLE_AIR_DATE_COLUMN, false, false, DATE_OPS),
        _ => return None,
    })
}

/// `v2RuleFields`.
fn is_v2_rule_field(field: &str) -> bool {
    matches!(
        field,
        RULE_FIELD_SHOW_TITLE
            | QUERY_SORT_TITLE
            | RULE_FIELD_DECADE
            | QUERY_SORT_RUNTIME
            | QUERY_SORT_RATING_TMDB
            | QUERY_SORT_RATING_RT_CRITIC
            | QUERY_SORT_RATING_RT_AUDIENCE
            | QUERY_SORT_LATEST_EPISODE_ADDED
            | QUERY_SORT_LAST_AIR_DATE
    )
}

/// `booleanRuleFields`.
pub fn is_boolean_rule_field(field: &str) -> bool {
    matches!(
        field,
        "watched" | "in_progress" | "favorited" | "in_watchlist" | "hdr" | "dolby_vision"
    )
}

/// `querySortDef`.
#[derive(Clone, Copy, Debug)]
pub struct SortDef {
    pub column_sql: &'static str,
    pub default_order: &'static str,
    pub nulls_last: bool,
    pub personalized: bool,
    pub title_sort_only: bool,
}

/// Every key of `querySortDefs`.
pub const SORT_FIELDS: &[&str] = &[
    "title",
    "added_at",
    "release_date",
    "last_air_date",
    "latest_episode_added",
    "year",
    "content_rating",
    "runtime",
    "rating_imdb",
    "rating_tmdb",
    "rating_rt_critic",
    "rating_rt_audience",
    "resolution",
    "bitrate",
    "progress",
    "date_viewed",
    "plays",
    "author",
    "narrator",
    "series",
];

/// `querySortDefs`.
pub fn sort_def(field: &str) -> Option<SortDef> {
    let d = |column_sql, default_order, nulls_last| SortDef {
        column_sql,
        default_order,
        nulls_last,
        personalized: false,
        title_sort_only: false,
    };
    Some(match field {
        "title" => SortDef {
            title_sort_only: true,
            ..d(
                "LOWER(COALESCE(NULLIF(BTRIM(%s.sort_title), ''), %s.title))",
                "asc",
                false,
            )
        },
        "added_at" => d("", "desc", false),
        "release_date" => d(RELEASE_DATE_COLUMN, "desc", true),
        "last_air_date" => d("last_air_date", "desc", true),
        "latest_episode_added" => d("latest_episode_added_at", "desc", true),
        "year" => d("year", "desc", false),
        "content_rating" => d("", "asc", false),
        "runtime" => d("runtime", "desc", true),
        "rating_imdb" => d("rating_imdb", "desc", true),
        "rating_tmdb" => d("rating_tmdb", "desc", true),
        "rating_rt_critic" => d("rating_rt_critic", "desc", true),
        "rating_rt_audience" => d("rating_rt_audience", "desc", true),
        "resolution" | "bitrate" => d("", "desc", true),
        "progress" | "date_viewed" | "plays" => SortDef {
            personalized: true,
            ..d("", "desc", true)
        },
        "author" | "narrator" | "series" => d("", "asc", true),
        _ => return None,
    })
}

/// `QueryDefinition`. A nil and an empty library list behave the same everywhere, so `library_ids`
/// is a plain vector.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, rename = "catalog.QueryDefinition")]
pub struct QueryDefinition {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub library_ids: Vec<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub media_scope: String,
    #[serde(rename = "match")]
    pub match_: String,
    pub groups: Vec<QueryGroup>,
    pub sort: QuerySort,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct QueryGroup {
    #[serde(rename = "match")]
    pub match_: String,
    pub rules: Vec<QueryRule>,
}

/// `QueryRule`. `value` is Go's `any`: a JSON number decodes as a Go `float64`, held as an `f64`
/// number; an integer number is a Go `int`, which only the URL parser produces.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct QueryRule {
    pub field: String,
    pub op: String,
    #[serde(deserialize_with = "go_any")]
    pub value: Value,
}

/// Decodes a JSON value the way `encoding/json` fills an `any`: every number is a `float64`.
fn go_any<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
    Ok(as_go_floats(Value::deserialize(d)?))
}

/// Turns every number in v into an `f64` number.
pub fn as_go_floats(v: Value) -> Value {
    match v {
        Value::Number(n) => serde_json::Number::from_f64(n.as_f64().unwrap_or(0.0))
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Value::Array(items) => Value::Array(items.into_iter().map(as_go_floats).collect()),
        Value::Object(map) => {
            Value::Object(map.into_iter().map(|(k, v)| (k, as_go_floats(v))).collect())
        }
        other => other,
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct QuerySort {
    pub field: String,
    pub order: String,
}

/// `IsValidMediaScope`.
pub fn is_valid_media_scope(scope: &str) -> bool {
    matches!(
        scope,
        "" | "movie" | "series" | "episode" | "audiobook" | "ebook" | "manga" | MEDIA_SCOPE_VIDEO
    )
}

/// `MediaScopeItemTypes`.
pub fn media_scope_item_types(scope: &str) -> Vec<String> {
    let scope = lower_trim(scope);
    match scope.as_str() {
        "" => Vec::new(),
        MEDIA_SCOPE_VIDEO => vec!["movie".into(), "series".into()],
        MEDIA_SCOPE_VIDEO_WITH_EPISODES => vec!["movie".into(), "series".into(), "episode".into()],
        _ => vec![scope],
    }
}

/// `MediaScopeMatchesItemType`.
pub fn media_scope_matches_item_type(scope: &str, item_type: &str) -> bool {
    let types = media_scope_item_types(scope);
    if types.is_empty() {
        return true;
    }
    let item_type = lower_trim(item_type);
    types.contains(&item_type)
}

/// `ApplySmartCollectionItemLimit`.
pub fn apply_smart_collection_item_limit(mut def: QueryDefinition) -> QueryDefinition {
    let limit = match def.limit {
        Some(l) if l > 0 => l,
        _ => DEFAULT_SMART_COLLECTION_ITEM_LIMIT,
    };
    def.limit = Some(limit);
    def
}

/// `ruleBool`: a bool, or exactly the strings "true" and "false".
pub fn rule_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s == "true" => Some(true),
        Value::String(s) if s == "false" => Some(false),
        _ => None,
    }
}

/// `catalogFloat` for values decoded from JSON: a number, or a string `strconv.ParseFloat` reads.
pub fn catalog_float(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => parse_go_float(super::trim(s)),
        _ => None,
    }
}

/// `strconv.ParseFloat(s, 64)` for decimal input, infinities, and NaN.
fn parse_go_float(s: &str) -> Option<f64> {
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    let lowered = body.to_ascii_lowercase();
    if matches!(lowered.as_str(), "inf" | "infinity" | "nan") {
        return s.parse::<f64>().ok();
    }
    // Go accepts underscores only between digits of a prefixed literal, and rejects them here;
    // Rust's parser also rejects them. Hex floats are not accepted by either path below.
    if body.is_empty()
        || !body
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        return None;
    }
    let parsed = s.parse::<f64>().ok()?;
    // ParseFloat returns ±Inf with a range error when the value overflows.
    if parsed.is_infinite() {
        return None;
    }
    Some(parsed)
}

/// `catalogFloatRange`.
pub fn catalog_float_range(value: &Value) -> Option<[f64; 2]> {
    match value {
        Value::Array(v) if v.len() == 2 => Some([catalog_float(&v[0])?, catalog_float(&v[1])?]),
        _ => None,
    }
}

/// `fmt.Sprint` of a JSON-decoded value.
pub fn go_sprint(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            silo_gocompat::strconv::format_float(n.as_f64().unwrap_or(0.0), b'g', -1, 64)
                .replace("e+0", "e+")
                .replace("e-0", "e-")
        }
        Value::String(s) => s.clone(),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(go_sprint).collect::<Vec<_>>().join(" ")
        ),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            format!(
                "map[{}]",
                keys.iter()
                    .map(|k| format!("{k}:{}", go_sprint(&map[*k])))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }
}

/// `catalogStringRange`.
pub fn catalog_string_range(value: &Value) -> Option<[String; 2]> {
    match value {
        Value::Array(v) if v.len() == 2 => Some([go_sprint(&v[0]), go_sprint(&v[1])]),
        _ => None,
    }
}

/// `isRuleDate`: a calendar date or an RFC 3339 time, year 1 or later.
pub fn is_rule_date(value: &str) -> bool {
    let value = trim(value);
    let parsed = silo_gocompat::time::parse("2006-01-02", value)
        .or_else(|_| silo_gocompat::time::parse("2006-01-02T15:04:05Z07:00", value));
    matches!(parsed, Ok(t) if t.date().0 >= 1)
}

/// `decadeStart`.
pub fn decade_start(value: &Value) -> Option<i64> {
    let year = catalog_float(value)?;
    if year.is_nan() || !(10.0..=9999.0).contains(&year) {
        return None;
    }
    let start = year as i64;
    Some(start - start % 10)
}

/// `validateRuleValue`.
fn validate_rule_value(rule: &QueryRule) -> Result<(), String> {
    if rule.op == RULE_OP_IN_LAST || rule.op == RULE_OP_NOT_IN_LAST {
        return super::builder::rule_interval(rule).map(|_| ());
    }
    if is_boolean_rule_field(&rule.field) {
        if rule_bool(&rule.value).is_none() {
            return Err(format!("{} requires true or false", rule.field));
        }
        return Ok(());
    }
    match rule.field.as_str() {
        QUERY_SORT_TITLE | RULE_FIELD_SHOW_TITLE => match &rule.value {
            Value::String(s) if !trim(s).is_empty() => {}
            _ => return Err(format!("{} requires a non-empty string", rule.field)),
        },
        RULE_FIELD_DECADE => {
            if decade_start(&rule.value).is_none() {
                return Err("decade requires a year such as 1990".into());
            }
        }
        "rating_imdb"
        | QUERY_SORT_RUNTIME
        | QUERY_SORT_RATING_TMDB
        | QUERY_SORT_RATING_RT_CRITIC
        | QUERY_SORT_RATING_RT_AUDIENCE => {
            if rule.op == "between" {
                if catalog_float_range(&rule.value).is_none() {
                    return Err(format!(
                        "{} between requires [min, max] numbers",
                        rule.field
                    ));
                }
            } else if catalog_float(&rule.value).is_none() {
                return Err(format!("{} requires a number", rule.field));
            }
        }
        QUERY_SORT_LATEST_EPISODE_ADDED | QUERY_SORT_LAST_AIR_DATE => {
            if rule.op == "between" {
                let ok = catalog_string_range(&rule.value)
                    .is_some_and(|b| is_rule_date(&b[0]) && is_rule_date(&b[1]));
                if !ok {
                    return Err(format!(
                        "{} between requires [from, to] dates such as 2024-01-31",
                        rule.field
                    ));
                }
            } else {
                let ok = matches!(&rule.value, Value::String(s) if is_rule_date(s));
                if !ok {
                    return Err(format!("{} requires a date such as 2024-01-31", rule.field));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// `ValidateV1Rules`.
pub fn validate_v1_rules(def: &QueryDefinition) -> Result<(), String> {
    let def = def.normalize();
    for (i, group) in def.groups.iter().enumerate() {
        for (j, rule) in group.rules.iter().enumerate() {
            if is_v2_rule_field(&rule.field) {
                return Err(format!(
                    "groups[{i}].rules[{j}].field {} is not supported",
                    q(&rule.field)
                ));
            }
            if rule.op == RULE_OP_NOT_IN_LAST {
                return Err(format!(
                    "groups[{i}].rules[{j}].op {} is not supported for field {}",
                    q(&rule.op),
                    q(&rule.field)
                ));
            }
        }
    }
    Ok(())
}

/// `normalizeMatch`.
pub fn normalize_match(m: &str) -> String {
    let n = lower_trim(m);
    if n.is_empty() { "all".into() } else { n }
}

/// `normalizeLibraryIDs`: positive IDs deduplicated, non-positive ones kept, all sorted.
pub fn normalize_library_ids(ids: &[i64]) -> Vec<i64> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<i64> = Vec::with_capacity(ids.len());
    for &id in ids {
        if id <= 0 {
            out.push(id);
            continue;
        }
        if seen.insert(id) {
            out.push(id);
        }
    }
    out.sort_unstable();
    out
}

/// `NormalizeQuerySort`.
pub fn normalize_query_sort(sort: &QuerySort) -> QuerySort {
    let mut field = lower_trim(&sort.field);
    let mut order = lower_trim(&sort.order);
    field = match field.as_str() {
        "sort_title" => "title".into(),
        "recently_added" => "added_at".into(),
        "rating" => "rating_imdb".into(),
        _ => field,
    };
    if field.is_empty() {
        field = DEFAULT_SORT_FIELD.into();
    }
    if order.is_empty()
        && let Some(def) = sort_def(&field)
    {
        order = def.default_order.into();
    }
    QuerySort { field, order }
}

/// `QuerySortFieldSet`.
pub fn query_sort_field_set(allow_personalized: bool) -> Vec<&'static str> {
    SORT_FIELDS
        .iter()
        .copied()
        .filter(|f| allow_personalized || !sort_def(f).is_some_and(|d| d.personalized))
        .collect()
}

/// `QuerySortRequiresProfile`.
pub fn query_sort_requires_profile(field: &str) -> bool {
    sort_def(&lower_trim(field)).is_some_and(|d| d.personalized)
}

/// `QueryFieldRequiresProfile`.
pub fn query_field_requires_profile(field: &str) -> bool {
    field_def(&lower_trim(field)).is_some_and(|d| d.personalized)
}

/// `NormalizePersonalListSort`.
pub fn normalize_personal_list_sort(field: &str, order: &str) -> Option<QuerySort> {
    let field = lower_trim(field);
    if !matches!(
        field.as_str(),
        "title" | "release_date" | "year" | "rating_imdb" | "added_at"
    ) {
        return None;
    }
    let mut order = lower_trim(order);
    if order != "asc" && order != "desc" {
        order = sort_def(&field)
            .map(|d| d.default_order)
            .unwrap_or("")
            .into();
    }
    Some(QuerySort { field, order })
}

/// `NormalizePersonalSourceSort`.
pub fn normalize_personal_source_sort(field: &str, order: &str) -> Option<QuerySort> {
    let field = lower_trim(field);
    if field == "relevance"
        || field == "random"
        || !query_sort_field_set(false).contains(&field.as_str())
    {
        return None;
    }
    let mut order = lower_trim(order);
    if order.is_empty() {
        order = sort_def(&field)
            .map(|d| d.default_order)
            .unwrap_or("")
            .into();
    } else if order != "asc" && order != "desc" {
        return None;
    }
    Some(QuerySort { field, order })
}

/// `NormalizeCollectionSort`.
pub fn normalize_collection_sort(
    field: &str,
    order: &str,
    allow_personalized: bool,
) -> Option<QuerySort> {
    let field = lower_trim(field);
    let def = sort_def(&field)?;
    if def.personalized && !allow_personalized {
        return None;
    }
    let mut order = lower_trim(order);
    if order.is_empty() {
        order = def.default_order.into();
    } else if order != "asc" && order != "desc" {
        return None;
    }
    Some(QuerySort { field, order })
}

impl QueryDefinition {
    /// `Normalize`.
    pub fn normalize(&self) -> QueryDefinition {
        let mut n = self.clone();
        n.media_scope = lower_trim(&n.media_scope);
        n.match_ = normalize_match(&n.match_);
        n.library_ids = normalize_library_ids(&n.library_ids);
        n.sort = normalize_query_sort(&n.sort);
        for group in &mut n.groups {
            group.match_ = normalize_match(&group.match_);
            for rule in &mut group.rules {
                let mut field = lower_trim(&rule.field);
                if field == "rating" {
                    field = "rating_imdb".into();
                }
                rule.field = field;
                rule.op = lower_trim(&rule.op);
                if is_boolean_rule_field(&rule.field)
                    && let Some(b) = rule_bool(&rule.value)
                {
                    rule.value = Value::Bool(b);
                }
            }
        }
        n
    }

    /// `Validate`.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_with_options(true, true)
    }

    /// `ValidateWithOptions`.
    pub fn validate_with_options(
        &self,
        allow_personalized_sorts: bool,
        allow_personalized_fields: bool,
    ) -> Result<(), String> {
        let n = self.normalize();
        if n.library_ids.iter().any(|id| *id <= 0) {
            return Err("library_ids must contain positive library IDs".into());
        }
        if !is_valid_media_scope(&n.media_scope) {
            return Err("media_scope must be 'movie', 'series', 'episode', 'audiobook', 'ebook', 'manga', or 'video'".into());
        }
        if n.match_ != "all" && n.match_ != "any" {
            return Err("match must be 'all' or 'any'".into());
        }
        for (i, group) in n.groups.iter().enumerate() {
            if group.match_ != "all" && group.match_ != "any" {
                return Err(format!("groups[{i}].match must be 'all' or 'any'"));
            }
            for (j, rule) in group.rules.iter().enumerate() {
                let Some(def) = field_def(&rule.field) else {
                    return Err(format!(
                        "groups[{i}].rules[{j}].field {} is not supported",
                        q(&rule.field)
                    ));
                };
                if def.personalized && !allow_personalized_fields {
                    return Err(format!(
                        "groups[{i}].rules[{j}].field {} requires profile scope",
                        q(&rule.field)
                    ));
                }
                if n.media_scope == "ebook" && rule.field == "narrator" {
                    return Err(format!(
                        "groups[{i}].rules[{j}].field {} is not supported for ebook media_scope",
                        q(&rule.field)
                    ));
                }
                if !def.allows(&rule.op) {
                    return Err(format!(
                        "groups[{i}].rules[{j}].op {} is not supported for field {}",
                        q(&rule.op),
                        q(&rule.field)
                    ));
                }
                if let Err(e) = validate_rule_value(rule) {
                    return Err(format!("groups[{i}].rules[{j}]: {e}"));
                }
            }
        }
        if !n.sort.field.is_empty() {
            let Some(def) = sort_def(&n.sort.field) else {
                return Err(format!("sort.field {} is not supported", q(&n.sort.field)));
            };
            if def.personalized && !allow_personalized_sorts {
                return Err(format!(
                    "sort.field {} requires profile scope",
                    q(&n.sort.field)
                ));
            }
            if n.media_scope == "ebook" && n.sort.field == "narrator" {
                return Err(format!(
                    "sort.field {} is not supported for ebook media_scope",
                    q(&n.sort.field)
                ));
            }
        }
        if !n.sort.order.is_empty() && n.sort.order != "asc" && n.sort.order != "desc" {
            return Err("sort.order must be 'asc' or 'desc'".into());
        }
        if n.limit.is_some_and(|l| l <= 0) {
            return Err("limit must be positive".into());
        }
        Ok(())
    }

    /// `IsPersonalized`.
    pub fn is_personalized(&self) -> bool {
        self.groups
            .iter()
            .flat_map(|g| &g.rules)
            .any(|r| query_field_requires_profile(&r.field))
            || query_sort_requires_profile(&self.sort.field)
    }
}

/// `queryColumnSQL`.
pub fn query_column_sql(alias: &str, raw: &str) -> String {
    match raw.matches("%s").count() {
        0 => format!("{alias}.{raw}"),
        1 => sprintf(raw, &[&alias]),
        _ => sprintf(raw, &[&alias, &alias]),
    }
}

/// `collectionSortConfig`.
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct CollectionSortConfig {
    field: String,
    order: String,
}

/// `ParseCollectionDefaultSort`: `None` means source order.
pub fn parse_collection_default_sort(raw: &[u8], allow_personalized: bool) -> Option<QuerySort> {
    if raw.trim_ascii().is_empty() {
        return None;
    }
    let cfg: Option<CollectionSortConfig> = silo_gocompat::json::unmarshal(raw).ok()?;
    let cfg = cfg.unwrap_or_default();
    normalize_collection_sort(&cfg.field, &cfg.order, allow_personalized)
}

/// `EncodeCollectionDefaultSort`.
pub fn encode_collection_default_sort(sort: Option<&QuerySort>) -> String {
    match sort {
        Some(s) if !trim(&s.field).is_empty() => {
            silo_gocompat::json::marshal_to_string(&CollectionSortConfig {
                field: s.field.clone(),
                order: s.order.clone(),
            })
            .unwrap_or_default()
        }
        _ => "{}".into(),
    }
}

/// `NormalizeLegacySectionFilter`.
pub fn normalize_legacy_section_filter(config: &[u8]) -> Result<QueryDefinition, String> {
    // Go names the anonymous struct by its full type in decode errors.
    #[derive(Default, Deserialize)]
    #[serde(
        default,
        rename = r#"struct { FilterType string "json:\"filter_type\""; FilterLibraryID *int "json:\"filter_library_id\""; FilterLibraryIDs []int "json:\"filter_library_ids\""; Match string "json:\"match\""; Groups []catalog.QueryGroup "json:\"groups\""; Sort string "json:\"sort\""; Order string "json:\"order\""; Limit *int "json:\"limit\"" }"#
    )]
    struct Legacy {
        filter_type: String,
        filter_library_id: Option<i64>,
        filter_library_ids: Option<Vec<i64>>,
        #[serde(rename = "match")]
        match_: String,
        groups: Option<Vec<QueryGroup>>,
        sort: String,
        order: String,
        limit: Option<i64>,
    }
    let mut legacy = Legacy::default();
    if !config.is_empty() {
        let parsed: Option<Legacy> =
            silo_gocompat::json::unmarshal(config).map_err(|e| e.to_string())?;
        legacy = parsed.unwrap_or_default();
    }
    let mut library_ids = legacy.filter_library_ids.unwrap_or_default();
    if let Some(id) = legacy.filter_library_id {
        library_ids.push(id);
    }
    let def = QueryDefinition {
        library_ids,
        media_scope: legacy.filter_type,
        match_: legacy.match_,
        groups: legacy.groups.unwrap_or_default(),
        sort: QuerySort {
            field: legacy.sort,
            order: legacy.order,
        },
        limit: legacy.limit,
    }
    .normalize();
    def.validate()?;
    Ok(def)
}
