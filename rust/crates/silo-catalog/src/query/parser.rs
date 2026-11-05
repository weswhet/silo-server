//! `catalog_parser.go` and the `CatalogRequest` fields it fills (`catalog_request.go`), with the
//! `browse.go` parameter helpers it calls.

use std::collections::BTreeMap;

use serde_json::Value;
use silo_gocompat::url::Values;

use super::builder::go_atoi;
use super::definition::{
    MEDIA_SCOPE_VIDEO, MEDIA_SCOPE_VIDEO_WITH_EPISODES, QUERY_SORT_TITLE, QueryDefinition,
    QueryGroup, QueryRule, QuerySort, RULE_FIELD_SHOW_TITLE, is_valid_media_scope,
    normalize_query_sort,
};
use super::{lower_trim, q, trim};

pub const SOURCE_QUERY: &str = "query";
pub const SOURCE_SECTION: &str = "section";
pub const SOURCE_LIBRARY_COLLECTION: &str = "library_collection";
pub const SOURCE_USER_COLLECTION: &str = "user_collection";
pub const SOURCE_FAVORITES: &str = "favorites";
pub const SOURCE_WATCHLIST: &str = "watchlist";
pub const SOURCE_HISTORY: &str = "history";
pub const SOURCE_PERSON: &str = "person";

/// `ErrSearchMediaScopeSource`'s text.
pub const ERR_SEARCH_MEDIA_SCOPE_SOURCE: &str =
    r#"type "video_with_episodes" is only supported with source "query""#;

/// `CatalogRequestOptions`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CatalogRequestOptions {
    pub search_media_scopes: bool,
    pub extended_rules: bool,
}

/// The `CatalogRequest` fields the parser fills. `snapshot_at` keeps Go's `RFC3339Nano` rendering
/// of the parsed time.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CatalogRequest {
    pub source: String,
    pub scope: String,
    pub section_id: String,
    pub library_id: i64,
    pub collection_id: String,
    pub person_id: i64,
    pub name_prefix: String,
    pub search_query: String,
    pub query: QueryDefinition,
    pub limit: i64,
    pub offset: i64,
    pub use_source_order: bool,
    pub skip_total: bool,
    pub snapshot_at: Option<silo_gocompat::time::GoTime>,
    pub search_media_scope: String,
    pub v1_rules: bool,
}

fn get<'a>(values: &'a Values, key: &str) -> &'a str {
    values
        .get(key)
        .and_then(|v| v.first())
        .map(String::as_str)
        .unwrap_or("")
}

/// `ParseIntParam`.
pub fn parse_int_param(s: &str) -> i64 {
    go_atoi(s).unwrap_or(0)
}

/// `ParseInt64Param`.
pub fn parse_int64_param(s: &str) -> i64 {
    go_atoi(s).unwrap_or(0)
}

/// `ParseContentRatings`.
pub fn parse_content_ratings(s: &str) -> Vec<String> {
    s.split(',')
        .map(trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `strconv.ParseBool`.
fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn is_known_source(source: &str) -> bool {
    matches!(
        source,
        SOURCE_QUERY
            | SOURCE_SECTION
            | SOURCE_LIBRARY_COLLECTION
            | SOURCE_USER_COLLECTION
            | SOURCE_FAVORITES
            | SOURCE_WATCHLIST
            | SOURCE_HISTORY
            | SOURCE_PERSON
    )
}

/// `ParseCatalogRequestWithOptions`.
pub fn parse_catalog_request(
    values: &Values,
    options: CatalogRequestOptions,
) -> Result<CatalogRequest, String> {
    let mut req = CatalogRequest {
        source: lower_trim(get(values, "source")),
        limit: 20,
        v1_rules: !options.extended_rules,
        ..CatalogRequest::default()
    };
    if req.source.is_empty() {
        req.source = SOURCE_QUERY.into();
    }
    let search_scope = options.search_media_scopes
        && lower_trim(get(values, "type")) == MEDIA_SCOPE_VIDEO_WITH_EPISODES;
    if search_scope && req.source != SOURCE_QUERY && is_known_source(&req.source) {
        return Err(ERR_SEARCH_MEDIA_SCOPE_SOURCE.into());
    }
    let limit = parse_int_param(get(values, "limit"));
    if limit > 0 {
        req.limit = limit;
    }
    if req.limit > 100 {
        req.limit = 100;
    }
    req.offset = parse_int_param(get(values, "offset")).max(0);
    let include_total = trim(get(values, "include_total"));
    req.skip_total = !include_total.is_empty() && parse_bool(include_total) == Some(false);

    let raw = trim(get(values, "snapshot"));
    if !raw.is_empty() {
        let t = silo_gocompat::time::parse(silo_gocompat::time::RFC3339_NANO, raw)
            .map_err(|e| format!("invalid snapshot timestamp: {e}"))?;
        req.snapshot_at = Some(t);
    }

    match req.source.as_str() {
        SOURCE_QUERY => {
            let overlay = parse_catalog_overlay(values)?;
            req.name_prefix = overlay.name_prefix;
            req.search_query = overlay.search_query;
            req.query = overlay.query;
            req.use_source_order = false;
            if !overlay.has_explicit_sort {
                req.query.sort = default_catalog_query_sort(&req.search_query);
            }
        }
        SOURCE_FAVORITES | SOURCE_WATCHLIST | SOURCE_HISTORY => {
            let overlay = parse_catalog_overlay(values)?;
            req.name_prefix = overlay.name_prefix;
            req.search_query = overlay.search_query;
            req.query = overlay.query;
            req.use_source_order = !overlay.has_explicit_sort
                || (req.source != SOURCE_HISTORY && req.query.sort.field == "added_at");
        }
        SOURCE_PERSON => {
            req.person_id = parse_int64_param(get(values, "person_id"));
            if req.person_id <= 0 {
                return Err("person_id is required".into());
            }
            let overlay = parse_catalog_overlay(values)?;
            req.name_prefix = overlay.name_prefix;
            req.search_query = overlay.search_query;
            req.query = overlay.query;
            req.use_source_order = !overlay.has_explicit_sort;
        }
        SOURCE_SECTION => {
            let mut scope = lower_trim(get(values, "scope"));
            if scope.is_empty() {
                scope = "library".into();
            }
            if scope != "home" && scope != "library" {
                return Err("scope must be 'home' or 'library'".into());
            }
            req.section_id = trim(get(values, "section_id")).to_owned();
            if req.section_id.is_empty() {
                return Err("section_id is required".into());
            }
            if scope == "library" {
                let id = parse_int_param(get(values, "library_id"));
                if id <= 0 {
                    return Err("library_id is required for library sections".into());
                }
                req.library_id = id;
            }
            if has_catalog_overlay_params(values, scope == "library") {
                return Err(format!(
                    "source {} does not allow overlay params",
                    q(&req.source)
                ));
            }
            req.scope = scope;
            req.use_source_order = true;
        }
        SOURCE_LIBRARY_COLLECTION | SOURCE_USER_COLLECTION => {
            req.collection_id = trim(get(values, "collection_id")).to_owned();
            if req.collection_id.is_empty() {
                return Err("collection_id is required".into());
            }
            let overlay = parse_catalog_overlay(values)?;
            req.name_prefix = overlay.name_prefix;
            req.search_query = overlay.search_query;
            req.query = overlay.query;
            req.use_source_order = !overlay.has_explicit_sort;
        }
        _ => return Err(format!("unsupported catalog source {}", q(&req.source))),
    }
    if search_scope {
        req.query.media_scope = MEDIA_SCOPE_VIDEO.into();
        req.search_media_scope = MEDIA_SCOPE_VIDEO_WITH_EPISODES.into();
    }
    Ok(req)
}

struct Overlay {
    search_query: String,
    name_prefix: String,
    query: QueryDefinition,
    has_explicit_sort: bool,
}

fn rule(field: &str, op: &str, value: Value) -> QueryRule {
    QueryRule {
        field: field.into(),
        op: op.into(),
        value,
    }
}

fn parse_catalog_overlay(values: &Values) -> Result<Overlay, String> {
    let mut def = QueryDefinition {
        match_: normalize_catalog_match(get(values, "match")),
        ..QueryDefinition::default()
    };
    let search_query = trim(get(values, "q")).to_owned();
    let library_id = parse_int_param(get(values, "library_id"));
    if library_id > 0 {
        def.library_ids = vec![library_id];
    }
    let scope = parse_catalog_media_scope(get(values, "type"));
    if !scope.is_empty() {
        def.media_scope = scope;
    }
    let query_limit = parse_int_param(get(values, "query_limit"));
    if query_limit > 0 {
        def.limit = Some(query_limit);
    }
    let mut implicit = Vec::new();
    let genre = trim(get(values, "genre"));
    if !genre.is_empty() {
        implicit.push(rule("genre", "contains", Value::from(genre)));
    }
    let status = trim(get(values, "status"));
    if !status.is_empty() {
        implicit.push(rule("status", "is", Value::from(status)));
    }
    let year_min = parse_int_param(get(values, "year_min"));
    let year_max = parse_int_param(get(values, "year_max"));
    if year_min > 0 && year_max > 0 {
        implicit.push(rule(
            "year",
            "between",
            Value::Array(vec![Value::from(year_min), Value::from(year_max)]),
        ));
    } else if year_min > 0 {
        implicit.push(rule("year", "gte", Value::from(year_min)));
    } else if year_max > 0 {
        implicit.push(rule("year", "lte", Value::from(year_max)));
    }
    if !implicit.is_empty() {
        def.groups.push(QueryGroup {
            match_: "all".into(),
            rules: implicit,
        });
    }
    let ratings = parse_content_ratings(get(values, "content_rating"));
    if ratings.len() == 1 {
        def.groups.push(QueryGroup {
            match_: "all".into(),
            rules: vec![rule(
                "content_rating",
                "is",
                Value::from(ratings[0].clone()),
            )],
        });
    } else if ratings.len() > 1 {
        def.groups.push(QueryGroup {
            match_: "any".into(),
            rules: ratings
                .into_iter()
                .map(|r| rule("content_rating", "is", Value::from(r)))
                .collect(),
        });
    }
    def.groups.extend(parse_catalog_groups(values));
    let has_explicit_sort = !get(values, "sort").is_empty() || !get(values, "order").is_empty();
    if has_explicit_sort {
        def.sort = normalize_explicit_catalog_sort(get(values, "sort"), get(values, "order"));
    }
    Ok(Overlay {
        search_query,
        name_prefix: trim(get(values, "name_prefix")).to_owned(),
        query: def,
        has_explicit_sort,
    })
}

#[derive(Default)]
struct RuleBuilder {
    field: String,
    op: String,
    values: Vec<String>,
    indexed: Option<BTreeMap<i64, String>>,
}

#[derive(Default)]
struct GroupBuilder {
    match_: String,
    rules: BTreeMap<i64, RuleBuilder>,
}

/// One `[n]` index: ASCII digits, read with `strconv.Atoi` (0 when it overflows).
fn index(s: &str) -> Option<(i64, &str)> {
    let rest = s.strip_prefix('[')?;
    let end = rest.find(']')?;
    let digits = &rest[..end];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((go_atoi(digits).unwrap_or(0), &rest[end + 1..]))
}

enum Key {
    Match(i64),
    Rule(i64, i64, String),
    Value(i64, i64, i64),
}

/// The three `groups[...]` key patterns.
fn parse_key(key: &str) -> Option<Key> {
    let (g, rest) = index(key.strip_prefix("groups")?)?;
    if rest == "[match]" {
        return Some(Key::Match(g));
    }
    let (r, rest) = index(rest.strip_prefix("[rules]")?)?;
    match rest {
        "[field]" | "[op]" | "[value]" => Some(Key::Rule(g, r, rest[1..rest.len() - 1].to_owned())),
        _ => {
            let (v, rest) = index(rest.strip_prefix("[value]")?)?;
            rest.is_empty().then_some(Key::Value(g, r, v))
        }
    }
}

fn parse_catalog_groups(values: &Values) -> Vec<QueryGroup> {
    let mut groups: BTreeMap<i64, GroupBuilder> = BTreeMap::new();
    for (key, raw) in values {
        match parse_key(key) {
            Some(Key::Match(g)) => {
                let b = groups.entry(g).or_default();
                if let Some(first) = raw.first() {
                    b.match_ = first.clone();
                }
            }
            Some(Key::Rule(g, r, name)) => {
                let rule = groups.entry(g).or_default().rules.entry(r).or_default();
                match name.as_str() {
                    "field" => {
                        if let Some(first) = raw.first() {
                            rule.field = first.clone();
                        }
                    }
                    "op" => {
                        if let Some(first) = raw.first() {
                            rule.op = first.clone();
                        }
                    }
                    _ => rule.values = raw.clone(),
                }
            }
            Some(Key::Value(g, r, v)) => {
                let rule = groups.entry(g).or_default().rules.entry(r).or_default();
                if let Some(first) = raw.first() {
                    rule.indexed
                        .get_or_insert_with(BTreeMap::new)
                        .insert(v, first.clone());
                }
            }
            None => {}
        }
    }
    groups
        .into_values()
        .map(|b| QueryGroup {
            match_: normalize_catalog_match(&b.match_),
            rules: b
                .rules
                .into_values()
                .map(|r| QueryRule {
                    value: r.value(),
                    field: r.field,
                    op: r.op,
                })
                .collect(),
        })
        .collect()
}

impl RuleBuilder {
    fn value(&self) -> Value {
        if let Some(indexed) = self.indexed.as_ref().filter(|m| !m.is_empty()) {
            return Value::Array(indexed.values().map(|v| self.scalar(v)).collect());
        }
        match self.values.len() {
            0 => Value::Null,
            1 => self.scalar(&self.values[0]),
            _ => Value::Array(self.values.iter().map(|v| self.scalar(v)).collect()),
        }
    }

    fn scalar(&self, raw: &str) -> Value {
        let field = lower_trim(&self.field);
        if field == QUERY_SORT_TITLE || field == RULE_FIELD_SHOW_TITLE {
            return Value::from(trim(raw));
        }
        parse_catalog_scalar(raw)
    }
}

/// `parseCatalogScalar`: a bool, a Go `int`, a `float64`, or the trimmed string.
pub fn parse_catalog_scalar(raw: &str) -> Value {
    let trimmed = trim(raw);
    match super::lower(trimmed).as_str() {
        "true" => return Value::Bool(true),
        "false" => return Value::Bool(false),
        _ => {}
    }
    if let Some(i) = go_atoi(trimmed) {
        return Value::from(i);
    }
    if let Some(f) = super::definition::catalog_float(&Value::from(trimmed))
        && let Some(n) = serde_json::Number::from_f64(f)
    {
        return Value::Number(n);
    }
    Value::from(trimmed)
}

fn has_catalog_overlay_params(values: &Values, ignore_library_id: bool) -> bool {
    values.iter().any(|(key, raw)| {
        if raw.is_empty() {
            return false;
        }
        if key.starts_with("groups[") {
            return true;
        }
        match key.as_str() {
            "library_id" => !ignore_library_id,
            "q" | "name_prefix" | "match" | "type" | "genre" | "year_min" | "year_max"
            | "content_rating" | "status" | "sort" | "order" | "query_limit" => true,
            _ => false,
        }
    })
}

fn normalize_catalog_match(raw: &str) -> String {
    if silo_gocompat::strings::equal_fold(trim(raw), "any") {
        "any".into()
    } else {
        "all".into()
    }
}

fn parse_catalog_media_scope(raw: &str) -> String {
    let scope = lower_trim(raw);
    if !scope.is_empty() && is_valid_media_scope(&scope) {
        scope
    } else {
        String::new()
    }
}

fn default_catalog_query_sort(search_query: &str) -> QuerySort {
    if !trim(search_query).is_empty() {
        QuerySort {
            field: "relevance".into(),
            order: "desc".into(),
        }
    } else {
        QuerySort {
            field: "title".into(),
            order: "asc".into(),
        }
    }
}

fn normalize_explicit_catalog_sort(field: &str, order: &str) -> QuerySort {
    let field = lower_trim(field);
    let mut order = lower_trim(order);
    if field == "relevance" {
        if order.is_empty() {
            order = "desc".into();
        }
        return QuerySort { field, order };
    }
    let mut normalized = normalize_query_sort(&QuerySort {
        field: field.clone(),
        order,
    });
    if field.is_empty() {
        normalized.field = String::new();
    }
    normalized
}

impl CatalogRequest {
    /// `ValidateQueryDefinition`.
    pub fn validate_query_definition(&self) -> Result<(), String> {
        let mut def = self.query.clone();
        if normalize_query_sort(&def.sort).field == "relevance" {
            if self.source != SOURCE_QUERY || trim(&self.search_query).is_empty() {
                return Err("relevance sort requires query source and q".into());
            }
            def.sort.field = String::new();
        }
        def.validate()
    }
}
