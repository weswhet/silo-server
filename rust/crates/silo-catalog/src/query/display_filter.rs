//! `display_query_filter.go`: a personal collection's filter-only display fragment.

use serde::Serialize;
use serde_json::Value;
use silo_pg::Pool;

use super::access::AccessFilter;
use super::definition::{QueryDefinition, QueryGroup, QueryRule, QuerySort, normalize_match};
use super::executor::QueryExecutor;
use super::{lower_trim, q, trim};
use crate::model::MediaItem;

/// `NormalizeDisplayQueryFragment`: the canonical JSON of a display filter, or `""` when it is
/// absent or carries no rules.
pub fn normalize_display_query_fragment(raw: &[u8]) -> Result<String, String> {
    let trimmed = raw.trim_ascii();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let def: Option<QueryDefinition> = silo_gocompat::json::unmarshal(trimmed)
        .map_err(|e| format!("display_query_definition must be a query definition: {e}"))?;
    let def = def.unwrap_or_default();
    if !def.library_ids.is_empty()
        || !trim(&def.media_scope).is_empty()
        || def.limit.is_some()
        || def.sort != QuerySort::default()
    {
        return Err("display_query_definition is filter-only and must not set library_ids, media_scope, sort, or limit".into());
    }
    let mut groups = Vec::new();
    for group in &def.groups {
        let mut rules = Vec::new();
        for rule in &group.rules {
            let field = lower_trim(&rule.field);
            if field != "type" && field != "watched" {
                return Err(format!(
                    "display_query_definition does not support field {}",
                    q(&rule.field)
                ));
            }
            let mut rule = QueryRule {
                field: field.clone(),
                ..rule.clone()
            };
            if field == "type"
                && let Value::String(v) = &rule.value
            {
                rule.value = Value::String(lower_trim(v));
            }
            validate_display_filter_value(&field, &rule)?;
            if field == "type" && rule.value == Value::String("all".into()) {
                continue;
            }
            rules.push(rule);
        }
        if rules.is_empty() {
            continue;
        }
        groups.push(QueryGroup {
            match_: normalize_match(&group.match_),
            rules,
        });
    }
    if groups.is_empty() {
        return Ok(String::new());
    }
    let canonical = QueryDefinition {
        match_: normalize_match(&def.match_),
        groups: groups.clone(),
        ..QueryDefinition::default()
    };
    canonical
        .validate()
        .map_err(|e| format!("invalid display_query_definition: {e}"))?;
    #[derive(Serialize)]
    struct Out<'a> {
        #[serde(rename = "match")]
        match_: &'a str,
        groups: &'a [QueryGroup],
    }
    silo_gocompat::json::marshal_to_string(&Out {
        match_: &canonical.match_,
        groups: &groups,
    })
    .map_err(|e| format!("encoding display_query_definition: {e}"))
}

fn validate_display_filter_value(field: &str, rule: &QueryRule) -> Result<(), String> {
    match field {
        "watched" => {
            if !rule.value.is_boolean() {
                return Err("display_query_definition watched value must be a boolean".into());
            }
        }
        "type" => {
            let value = match &rule.value {
                Value::String(v) if !v.is_empty() => v.as_str(),
                _ => {
                    return Err(
                        "display_query_definition type value must be a non-empty string".into(),
                    );
                }
            };
            if !matches!(value, "all" | "movie" | "series") {
                return Err(format!(
                    "display_query_definition type value must be one of {}, {}, or {}",
                    q("all"),
                    q("movie"),
                    q("series")
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

/// `FilterCollectionItemsByDisplayQuery`: the items, in their order, that the stored fragment
/// matches.
pub async fn filter_collection_items_by_display_query(
    pool: &Pool,
    items: Vec<MediaItem>,
    display_query_definition: &str,
    access: &AccessFilter,
) -> Result<Vec<MediaItem>, String> {
    let trimmed = trim(display_query_definition);
    if trimmed.is_empty() || items.is_empty() {
        return Ok(items);
    }
    let def: Option<QueryDefinition> = silo_gocompat::json::unmarshal(trimmed.as_bytes())
        .map_err(|e| format!("parsing collection display_query_definition: {e}"))?;
    let mut def = def.unwrap_or_default();
    def.media_scope = String::new();
    def.library_ids = Vec::new();
    def.sort = QuerySort::default();
    def.limit = None;
    if def.groups.is_empty() {
        return Ok(items);
    }
    let ids: Vec<String> = items
        .iter()
        .filter(|i| !trim(&i.content_id).is_empty())
        .map(|i| i.content_id.clone())
        .collect();
    if ids.is_empty() {
        return Ok(items);
    }
    let mut query_access = access.clone();
    let limit = ids.len() as i64;
    query_access.allowed_content_ids = Some(ids);
    let (matched, _, _) = QueryExecutor::default()
        .preview_page(pool, &def, &query_access, limit, 0, true)
        .await
        .map_err(|e| format!("evaluating collection display_query_definition: {e}"))?;
    let matched: std::collections::HashSet<String> =
        matched.into_iter().map(|i| i.content_id).collect();
    Ok(items
        .into_iter()
        .filter(|i| matched.contains(&i.content_id))
        .collect())
}
