//! Byte-for-byte SQL and pure reranking parity with the Go catalogsearchsql corpus.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;
use silo_catalog::query::{AccessFilter, Arg};
use silo_catalog::search::{fuzzy, query::parse_search_query, sql};

#[derive(Default, Deserialize)]
#[serde(default)]
struct Corpus {
    sql: Vec<SqlCase>,
    rerank: Vec<RerankCase>,
    text: Vec<TextCase>,
    levenshtein: Vec<LevenshteinCase>,
}

fn corpus() -> Corpus {
    serde_json::from_str(include_str!(
        "../../../conformance/vectors/catalog/search_sql.json"
    ))
    .unwrap()
}

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
struct GoArg {
    #[serde(rename = "type")]
    ty: String,
    value: Value,
}

fn normalize(value: &Value) -> Value {
    match value {
        Value::Number(number) => serde_json::json!(number.as_f64()),
        Value::Array(values) => Value::Array(values.iter().map(normalize).collect()),
        other => other.clone(),
    }
}

fn check_args(context: &str, got: &[Arg], want: &[GoArg]) {
    let got: Vec<_> = got
        .iter()
        .map(|arg| (arg.go_type().to_owned(), normalize(&arg.json())))
        .collect();
    let want: Vec<_> = want
        .iter()
        .map(|arg| {
            let value = if arg.value.is_null() && arg.ty.starts_with("[]") {
                Value::Array(vec![])
            } else {
                normalize(&arg.value)
            };
            (arg.ty.clone(), value)
        })
        .collect();
    assert_eq!(got, want, "args: {context}");
}

fn check_sql(context: &str, got: &str, want: &str) {
    if got == want {
        return;
    }
    let offset = got
        .bytes()
        .zip(want.bytes())
        .position(|(a, b)| a != b)
        .unwrap_or(got.len().min(want.len()));
    let excerpt = |sql: &str| {
        let start = sql.floor_char_boundary(offset.saturating_sub(100));
        let end = sql.floor_char_boundary((offset + 200).min(sql.len()));
        sql[start..end].to_owned()
    };
    panic!(
        "{context}: SQL differs at byte {offset} (lengths {} / {}):\ngot: {:?}\nwant: {:?}",
        got.len(),
        want.len(),
        excerpt(got),
        excerpt(want)
    );
}

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
struct GoAccess {
    name: String,
    allowed: Option<Vec<i32>>,
    disabled: Option<Vec<i32>>,
    max_content_rating: String,
    allow_unrated_content: bool,
    max_advisory_age: i32,
    require_advisory_age: bool,
    excluded_media_types: Option<Vec<String>>,
}

impl GoAccess {
    fn filter(&self) -> AccessFilter {
        AccessFilter {
            allowed: self.allowed.clone(),
            disabled: self.disabled.clone().unwrap_or_default(),
            max_content_rating: self.max_content_rating.clone(),
            allow_unrated_content: self.allow_unrated_content,
            max_advisory_age: self.max_advisory_age,
            require_advisory_age: self.require_advisory_age,
            excluded_media_types: self.excluded_media_types.clone().unwrap_or_default(),
            ..AccessFilter::default()
        }
    }
}

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
struct SqlCase {
    kind: String,
    query: String,
    types: Option<Vec<String>>,
    limit: i64,
    offset: i64,
    total: bool,
    exclude: Option<Vec<String>>,
    min_sim: f64,
    user_id: i64,
    ids: Option<Vec<String>>,
    access: GoAccess,
    data_sql: String,
    count_sql: String,
    args: Vec<GoArg>,
}

#[test]
fn sql_matches_go() {
    let cases = corpus().sql;
    assert_eq!(cases.len(), 1606, "the complete SQL corpus must be checked");
    let mut kinds = HashMap::new();
    for (index, case) in cases.iter().enumerate() {
        let context = format!(
            "case {index}: {} {:?}, types {:?}, access {}, limit {}, offset {}, total {}",
            case.kind,
            case.query,
            case.types,
            case.access.name,
            case.limit,
            case.offset,
            case.total
        );
        *kinds.entry(case.kind.as_str()).or_insert(0) += 1;
        let access = case.access.filter();
        let parsed = parse_search_query(&case.query);
        let types = case.types.as_deref().unwrap_or_default();
        let ids = case.ids.as_deref().unwrap_or_default();
        let (data, count, args) = match case.kind.as_str() {
            "get_by_ids" => {
                let (data, args) = sql::build_get_by_ids_with_access_sql(ids, &access);
                (data, String::new(), args)
            }
            "count_personal" => {
                let (data, args) = sql::build_count_visible_personal_collection_members_sql(
                    case.user_id,
                    ids,
                    &access,
                );
                (data, String::new(), args)
            }
            "mixed" => sql::build_mixed_search_sql_from_parsed(
                &parsed,
                types,
                case.limit,
                case.offset,
                &access,
                case.total,
            ),
            "fuzzy" => sql::build_fuzzy_search_from_parsed(
                &parsed,
                types,
                case.limit,
                case.offset,
                &access,
                case.total,
                case.exclude.as_deref().unwrap_or_default(),
                case.min_sim,
            ),
            other => panic!("unhandled SQL kind {other}: {context}"),
        };
        check_sql(&format!("data SQL: {context}"), &data, &case.data_sql);
        check_sql(&format!("count SQL: {context}"), &count, &case.count_sql);
        check_args(&context, &args, &case.args);
    }
    assert_eq!(kinds.len(), 4);
    assert_eq!(kinds["get_by_ids"], 20);
    assert_eq!(kinds["count_personal"], 20);
    assert_eq!(kinds["mixed"], 1044);
    assert_eq!(kinds["fuzzy"], 522);
}

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
struct RerankCase {
    search: String,
    titles: Vec<String>,
    aliases: Vec<Option<Vec<String>>>,
    exact_hits: bool,
    admitted: Vec<String>,
    required: usize,
    candidate_text: String,
}

#[test]
fn fuzzy_rerank_matches_go() {
    let cases = corpus().rerank;
    assert_eq!(cases.len(), 34);
    for (index, case) in cases.iter().enumerate() {
        let context = format!("case {index}: {:?}, exact {}", case.search, case.exact_hits);
        let items: Vec<_> = case
            .titles
            .iter()
            .enumerate()
            .map(|(index, title)| fuzzy::FuzzyItem {
                content_id: index.to_string(),
                title: title.clone(),
            })
            .collect();
        let aliases: HashMap<_, _> = case
            .aliases
            .iter()
            .enumerate()
            .filter_map(|(index, aliases)| {
                aliases
                    .as_ref()
                    .map(|aliases| (index.to_string(), aliases.clone()))
            })
            .collect();
        let (ranks, required) = fuzzy::rank_fuzzy_items(&case.search, &items, &aliases);
        assert_eq!(required, case.required, "required: {context}");
        let admitted = fuzzy::admit_fuzzy_ranks(ranks, required, case.exact_hits);
        let ids: Vec<_> = admitted
            .iter()
            .map(|rank| rank.item.content_id.clone())
            .collect();
        assert_eq!(ids, case.admitted, "admitted IDs: {context}");
        assert_eq!(
            fuzzy::fuzzy_candidate_text(&case.search),
            case.candidate_text,
            "candidate text: {context}"
        );
    }
}

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
struct TextCase {
    query: String,
    search_text: String,
    types: Option<Vec<String>>,
    media_types: Option<Vec<String>>,
    episodes: bool,
}

#[test]
fn search_text_and_types_match_go() {
    let cases = corpus().text;
    assert_eq!(cases.len(), 207);
    for (index, case) in cases.iter().enumerate() {
        let context = format!("case {index}: {:?}, {:?}", case.query, case.types);
        assert_eq!(
            sql::search_text_from_parsed(&parse_search_query(&case.query)),
            case.search_text,
            "search text: {context}"
        );
        let (media_types, episodes) =
            sql::split_search_item_types(case.types.as_deref().unwrap_or_default());
        assert_eq!(
            media_types,
            case.media_types.clone().unwrap_or_default(),
            "media types: {context}"
        );
        assert_eq!(episodes, case.episodes, "episodes: {context}");
    }
}

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
struct LevenshteinCase {
    a: String,
    b: String,
    max: usize,
    d: usize,
}

#[test]
fn bounded_levenshtein_matches_go() {
    let cases = corpus().levenshtein;
    assert_eq!(cases.len(), 507);
    for (index, case) in cases.iter().enumerate() {
        let a: Vec<_> = case.a.chars().collect();
        let b: Vec<_> = case.b.chars().collect();
        assert_eq!(
            fuzzy::bounded_levenshtein_runes(&a, &b, case.max),
            case.d,
            "case {index}: {case:?}"
        );
    }
}
