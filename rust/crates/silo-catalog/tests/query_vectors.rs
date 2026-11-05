//! The query engine against the `catalogquery` vectors Go wrote
//! (`rust/conformance/vectors/generators/catalogquery`). SQL must match byte for byte, and every
//! argument must match in value and Go type.

use serde::Deserialize;
use serde_json::Value;
use silo_catalog::query::builder::{QueryBuilder, parse_duration};
use silo_catalog::query::cursor::{CursorTerm, QueryCursor, cursor_seek_sql};
use silo_catalog::query::executor::{PreviewPagePlan, QueryExecutor};
use silo_catalog::query::{AccessFilter, Arg, QueryDefinition, QuerySort, access, definition};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/vectors/catalog/"
);

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let raw = std::fs::read(format!("{DIR}{name}.json")).unwrap();
    serde_json::from_slice(&raw).unwrap()
}

fn def(raw: &str) -> QueryDefinition {
    silo_gocompat::json::unmarshal(raw.as_bytes()).unwrap()
}

#[derive(Deserialize, Clone, Debug)]
struct GoArg {
    #[serde(rename = "type")]
    ty: String,
    value: Value,
}

fn norm(v: &Value) -> Value {
    match v {
        Value::Number(n) => serde_json::json!(n.as_f64()),
        Value::Array(items) => Value::Array(items.iter().map(norm).collect()),
        other => other.clone(),
    }
}

fn check_args(ctx: &str, got: &[Arg], want: &Option<Vec<GoArg>>) {
    let want = want.clone().unwrap_or_default();
    let got: Vec<(String, Value)> = got
        .iter()
        .map(|a| (a.go_type().to_owned(), norm(&a.json())))
        .collect();
    let want: Vec<(String, Value)> = want
        .iter()
        .map(|a| {
            // A nil []int marshals as null; the Rust side carries an empty list.
            let v = if a.value.is_null() && a.ty.starts_with("[]") {
                Value::Array(vec![])
            } else {
                norm(&a.value)
            };
            (a.ty.clone(), v)
        })
        .collect();
    assert_eq!(got, want, "args differ: {ctx}");
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
struct Builder {
    alias: String,
    user_id: i64,
    profile_id: String,
    library_ids: Option<Vec<i64>>,
    media_scope: String,
    media_items: bool,
    arg_idx: usize,
}

impl Builder {
    fn make(&self) -> QueryBuilder {
        let mut b = QueryBuilder::new(&self.alias);
        b.with_user_scope(self.user_id, &self.profile_id)
            .with_library_scope(self.library_ids.as_deref().unwrap_or_default())
            .with_media_scope(&self.media_scope)
            .with_arg_idx(self.arg_idx);
        if self.media_items {
            b.with_media_items_relation();
        }
        b
    }
}

#[derive(Deserialize)]
struct BuildCase {
    builder: Builder,
    def: String,
    sql: String,
    args: Option<Vec<GoArg>>,
    history_cte: bool,
    arg_idx: usize,
    v1_error: String,
    error: String,
}

#[test]
fn build_matches_go() {
    let cases: Vec<BuildCase> = load("query_build");
    assert!(cases.len() > 1000);
    for c in &cases {
        let ctx = format!("{:?} {}", c.builder, c.def);
        let d = def(&c.def);
        let mut b = c.builder.make();
        match b.build(&d) {
            Ok((sql, args)) => {
                assert_eq!(c.error, "", "{ctx}");
                assert_eq!(sql, c.sql, "{ctx}");
                check_args(&ctx, &args, &c.args);
            }
            Err(e) => assert_eq!(e, c.error, "{ctx}"),
        }
        assert_eq!(b.requires_user_history_cte(), c.history_cte, "{ctx}");
        assert_eq!(b.arg_idx(), c.arg_idx, "{ctx}");
        let v1 = definition::validate_v1_rules(&d).err().unwrap_or_default();
        assert_eq!(v1, c.v1_error, "{ctx}");
    }
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
struct GoTerm {
    expression: String,
    kind: String,
    descending: bool,
    nulls_last: bool,
    not_null: bool,
    sql_type: String,
}

impl GoTerm {
    fn term(&self) -> CursorTerm {
        CursorTerm {
            expression: self.expression.clone(),
            kind: self.kind.clone(),
            descending: self.descending,
            nulls_last: self.nulls_last,
            not_null: self.not_null,
            sql_type: self.sql_type.clone(),
        }
    }
}

fn terms(ts: &Option<Vec<GoTerm>>) -> Vec<CursorTerm> {
    ts.iter().flatten().map(GoTerm::term).collect()
}

#[derive(Deserialize)]
struct SortPlan {
    terms: Option<Vec<GoTerm>>,
    joins: Option<Vec<String>>,
    order_by: String,
    args: Option<Vec<GoArg>>,
}

#[derive(Deserialize)]
struct SortCase {
    builder: Builder,
    sort: QuerySort,
    plan: Option<SortPlan>,
    error: String,
}

#[test]
fn sort_plans_match_go() {
    let cases: Vec<SortCase> = load("query_sort");
    for c in &cases {
        let ctx = format!("{:?} {:?}", c.builder, c.sort);
        let mut b = c.builder.make();
        match b.build_sort_plan(&c.sort) {
            Ok(plan) => {
                let want = c
                    .plan
                    .as_ref()
                    .unwrap_or_else(|| panic!("{ctx}: {}", c.error));
                assert_eq!(plan.order_by, want.order_by, "{ctx}");
                assert_eq!(plan.joins, want.joins.clone().unwrap_or_default(), "{ctx}");
                assert_eq!(plan.terms, terms(&want.terms), "{ctx}");
                check_args(&ctx, &plan.args, &want.args);
            }
            Err(e) => assert_eq!(e, c.error, "{ctx}"),
        }
    }
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
struct GoAccess {
    allowed: Option<Vec<i32>>,
    disabled: Option<Vec<i32>>,
    max_content_rating: String,
    allow_unrated_content: bool,
    max_advisory_age: i32,
    require_advisory_age: bool,
    allowed_content_ids: Option<Vec<String>>,
    user_id: i64,
    profile_id: String,
    name_prefix: String,
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
            allowed_content_ids: self.allowed_content_ids.clone(),
            user_id: self.user_id,
            profile_id: self.profile_id.clone(),
            name_prefix: self.name_prefix.clone(),
            excluded_media_types: self.excluded_media_types.clone().unwrap_or_default(),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct GoExecutor {
    group_by_work: bool,
    source_where: String,
    source_args: Option<Vec<Value>>,
    source_order: Option<Vec<GoTerm>>,
    source_cte: String,
    source_join: String,
    scope: String,
    base_relation_sql: String,
    snapshot_at: Option<silo_gocompat::time::GoTime>,
}

impl GoExecutor {
    fn make(&self) -> QueryExecutor {
        QueryExecutor {
            group_by_work: self.group_by_work,
            source_where: self.source_where.clone(),
            // The corpus's source arguments are Go ints.
            source_args: self
                .source_args
                .iter()
                .flatten()
                .map(|v| Arg::Int(v.as_i64().unwrap()))
                .collect(),
            source_order: terms(&self.source_order),
            source_cte: self.source_cte.clone(),
            source_join: self.source_join.clone(),
            scope: self.scope.clone(),
            base_relation_sql: self.base_relation_sql.clone(),
            snapshot_at: self.snapshot_at,
        }
    }
}

#[derive(Deserialize)]
struct PlanOut {
    terms: Option<Vec<GoTerm>>,
    paged_sql: String,
    paged_args: Option<Vec<GoArg>>,
    paged_total_sql: String,
    count_sql: String,
    count_args: Option<Vec<GoArg>>,
    cursor_sql: String,
    cursor_args: Option<Vec<GoArg>>,
    after_sql: String,
    after_args: Option<Vec<GoArg>>,
    after_error: String,
    tuple_sql: String,
    tuple_args: Option<Vec<GoArg>>,
    title_key: String,
    anchor_sql: String,
    anchor_args: Option<Vec<GoArg>>,
}

#[derive(Deserialize)]
struct PlanCase {
    executor: GoExecutor,
    def: String,
    access: GoAccess,
    limit: i64,
    offset: i64,
    after: Option<String>,
    plan: Option<PlanOut>,
    error: String,
    count_sql: String,
    count_args: Option<Vec<GoArg>>,
    count_error: String,
}

#[derive(Deserialize)]
struct Columns {
    list_columns: String,
    episode_base_relation: String,
    item_columns: Vec<String>,
    episode_hydrate: String,
}

#[test]
fn columns_match_go() {
    let c: Columns = load("query_columns");
    assert_eq!(
        format!(
            "{}, {}",
            silo_catalog::model::qualified_list_item_columns("mi"),
            access::manga_count_columns("mi")
        ),
        c.list_columns
    );
    assert_eq!(
        silo_catalog::query::episode_source::episode_catalog_base_relation(),
        c.episode_base_relation
    );
    assert_eq!(
        vec![
            silo_catalog::model::join_item_columns(""),
            silo_catalog::model::join_item_columns("mi"),
            silo_catalog::model::qualified_item_column_refs("mi"),
            silo_catalog::model::qualified_list_item_columns("x"),
        ],
        c.item_columns
    );
    assert_eq!(
        silo_catalog::query::episode_entries::hydrate_sql(),
        c.episode_hydrate
    );
}

fn squeeze(sql: &str, c: &Columns) -> String {
    sql.replace(&c.list_columns, "<list_columns>")
        .replace(&c.episode_base_relation, "<episode_base_relation>")
}

fn after_cursor(plan: &PreviewPagePlan, value: &Option<String>) -> QueryCursor {
    QueryCursor {
        keys: plan
            .cursor_terms
            .iter()
            .enumerate()
            .map(|(i, t)| silo_catalog::query::QueryCursorValue {
                kind: t.kind.clone(),
                value: if i % 2 == 0 || value.is_none() {
                    value.clone()
                } else {
                    None
                },
            })
            .collect(),
        consumed: 3,
        ..QueryCursor::default()
    }
}

#[test]
fn preview_plans_match_go() {
    let cols: Columns = load("query_columns");
    let cases: Vec<PlanCase> = load("query_plan");
    assert!(cases.len() > 500);
    for c in &cases {
        let ctx = format!(
            "{:?} {} {:?} {}/{}",
            c.executor, c.def, c.access, c.limit, c.offset
        );
        let ex = c.executor.make();
        let d = def(&c.def);
        let filter = c.access.filter();
        match ex.build_preview_page_plan(&d, &filter, c.limit, c.offset) {
            Ok(plan) => {
                let want = c
                    .plan
                    .as_ref()
                    .unwrap_or_else(|| panic!("{ctx}: {}", c.error));
                assert_eq!(plan.cursor_terms, terms(&want.terms), "{ctx}");
                assert_eq!(plan.title_key, want.title_key, "{ctx}");
                let (sql, args) = plan.paged_sql(false);
                assert_eq!(squeeze(&sql, &cols), want.paged_sql, "{ctx}");
                check_args(&ctx, &args, &want.paged_args);
                assert_eq!(
                    squeeze(&plan.paged_sql(true).0, &cols),
                    want.paged_total_sql,
                    "{ctx}"
                );
                let (sql, args) = plan.count_sql();
                assert_eq!(squeeze(&sql, &cols), want.count_sql, "{ctx}");
                check_args(&ctx, &args, &want.count_args);
                let (sql, args) = plan.cursor_sql(None).unwrap();
                assert_eq!(squeeze(&sql, &cols), want.cursor_sql, "{ctx}");
                check_args(&ctx, &args, &want.cursor_args);
                let after = after_cursor(&plan, &c.after);
                match plan.cursor_sql(Some(&after)) {
                    Ok((sql, args)) => {
                        assert_eq!(squeeze(&sql, &cols), want.after_sql, "{ctx}");
                        check_args(&ctx, &args, &want.after_args);
                    }
                    Err(e) => assert_eq!(e, want.after_error, "{ctx}"),
                }
                let (sql, args) = plan.seek_anchor_sql();
                assert_eq!(squeeze(&sql, &cols), want.anchor_sql, "{ctx}");
                check_args(&ctx, &args, &want.anchor_args);
                let (sql, args) = plan.tuple_sql(None, 4).unwrap();
                assert_eq!(squeeze(&sql, &cols), want.tuple_sql, "{ctx}");
                check_args(&ctx, &args, &want.tuple_args);
            }
            Err(e) => assert_eq!(e, c.error, "{ctx}"),
        }
        match ex.build_count_query(&d, &filter) {
            Ok((sql, args)) => {
                assert_eq!(c.count_error, "", "{ctx}");
                assert_eq!(squeeze(&sql, &cols), c.count_sql, "{ctx}");
                check_args(&ctx, &args, &c.count_args);
            }
            Err(e) => assert_eq!(e, c.count_error, "{ctx}"),
        }
    }
}

#[derive(Deserialize)]
struct SeekCase {
    terms: Vec<GoTerm>,
    after: Option<QueryCursor>,
    start: usize,
    sql: String,
    args: Option<Vec<GoArg>>,
    error: String,
}

#[test]
fn seeks_match_go() {
    let cases: Vec<SeekCase> = load("query_seek");
    for c in &cases {
        let terms: Vec<CursorTerm> = c.terms.iter().map(GoTerm::term).collect();
        let ctx = format!("{terms:?} {:?}", c.after);
        match cursor_seek_sql(&terms, c.after.as_ref(), c.start) {
            Ok((sql, args)) => {
                assert_eq!(sql, c.sql, "{ctx}");
                check_args(&ctx, &args, &c.args);
            }
            Err(e) => assert_eq!(e, c.error, "{ctx}"),
        }
    }
}

#[derive(Deserialize)]
struct DurationCase {
    input: String,
    output: String,
    error: String,
}

#[test]
fn durations_match_go() {
    let cases: Vec<DurationCase> = load("query_duration");
    for c in &cases {
        match parse_duration(&c.input) {
            Ok(o) => assert_eq!(
                (o.as_str(), ""),
                (c.output.as_str(), c.error.as_str()),
                "{}",
                c.input
            ),
            Err(e) => assert_eq!(e, c.error, "{}", c.input),
        }
    }
}

#[derive(Deserialize)]
struct CursorJson {
    cursor: QueryCursor,
    json: String,
}

#[test]
fn cursor_json_matches_go() {
    let cases: Vec<CursorJson> = load("query_cursor_json");
    for c in &cases {
        assert_eq!(
            silo_gocompat::json::marshal_to_string(&c.cursor).unwrap(),
            c.json
        );
        let back: QueryCursor = silo_gocompat::json::unmarshal(c.json.as_bytes()).unwrap();
        assert_eq!(back, c.cursor);
    }
}

#[derive(Deserialize)]
struct LibraryScopeCase {
    access: GoAccess,
    requested: Option<Vec<i64>>,
    ids: Option<Vec<i64>>,
    none: bool,
}

#[test]
fn library_scope_matches_go() {
    let cases: Vec<LibraryScopeCase> = load("query_library_scope");
    for c in &cases {
        let (ids, none) = access::library_scope(
            &c.access.filter(),
            c.requested.as_deref().unwrap_or_default(),
        );
        assert_eq!(
            (ids, none),
            (c.ids.clone(), c.none),
            "{:?} {:?}",
            c.access,
            c.requested
        );
    }
}

#[derive(Deserialize, Debug)]
struct RuleOut {
    field: String,
    op: String,
    #[serde(rename = "type")]
    ty: String,
    elem_types: Option<Vec<String>>,
    value: Value,
}

#[derive(Deserialize, Debug)]
struct GroupOut {
    #[serde(rename = "match")]
    match_: String,
    rules: Vec<RuleOut>,
}

#[derive(Deserialize, Debug)]
struct RequestOut {
    source: String,
    scope: String,
    section_id: String,
    library_id: i64,
    collection_id: String,
    person_id: i64,
    name_prefix: String,
    search_query: String,
    library_ids: Option<Vec<i64>>,
    media_scope: String,
    #[serde(rename = "match")]
    match_: String,
    groups: Vec<GroupOut>,
    sort: QuerySort,
    query_limit: Option<i64>,
    limit: i64,
    offset: i64,
    use_source_order: bool,
    skip_total: bool,
    snapshot_at: String,
    search_media_scope: String,
    v1_rules: bool,
    validate_error: String,
}

#[derive(Deserialize)]
struct ParseCase {
    query: String,
    search_media_scopes: bool,
    extended_rules: bool,
    request: Option<RequestOut>,
    error: String,
}

#[test]
fn parse_matches_go() {
    use silo_catalog::query::parser::{CatalogRequestOptions, parse_catalog_request};
    let cases: Vec<ParseCase> = load("query_parse");
    for c in &cases {
        let ctx = format!("{} {} {}", c.query, c.search_media_scopes, c.extended_rules);
        let (values, err) = silo_gocompat::url::parse_query(&c.query);
        assert!(err.is_none(), "{ctx}");
        let opts = CatalogRequestOptions {
            search_media_scopes: c.search_media_scopes,
            extended_rules: c.extended_rules,
        };
        let req = match parse_catalog_request(&values, opts) {
            Ok(req) => req,
            Err(e) => {
                assert_eq!(e, c.error, "{ctx}");
                continue;
            }
        };
        let want = c
            .request
            .as_ref()
            .unwrap_or_else(|| panic!("{ctx}: {}", c.error));
        let got = (
            req.source.as_str(),
            req.scope.as_str(),
            req.section_id.as_str(),
            req.library_id,
            req.collection_id.as_str(),
            req.person_id,
            req.name_prefix.as_str(),
            req.search_query.as_str(),
        );
        assert_eq!(
            got,
            (
                want.source.as_str(),
                want.scope.as_str(),
                want.section_id.as_str(),
                want.library_id,
                want.collection_id.as_str(),
                want.person_id,
                want.name_prefix.as_str(),
                want.search_query.as_str()
            ),
            "{ctx}"
        );
        assert_eq!(
            req.query.library_ids,
            want.library_ids.clone().unwrap_or_default(),
            "{ctx}"
        );
        assert_eq!(
            (
                req.query.media_scope.as_str(),
                req.query.match_.as_str(),
                &req.query.sort,
                req.query.limit
            ),
            (
                want.media_scope.as_str(),
                want.match_.as_str(),
                &want.sort,
                want.query_limit
            ),
            "{ctx}"
        );
        assert_eq!(
            (
                req.limit,
                req.offset,
                req.use_source_order,
                req.skip_total,
                req.v1_rules
            ),
            (
                want.limit,
                want.offset,
                want.use_source_order,
                want.skip_total,
                want.v1_rules
            ),
            "{ctx}"
        );
        assert_eq!(req.search_media_scope, want.search_media_scope, "{ctx}");
        assert_eq!(
            req.snapshot_at
                .map(|t| t.rfc3339_nano())
                .unwrap_or_default(),
            want.snapshot_at,
            "{ctx}"
        );
        assert_eq!(req.query.groups.len(), want.groups.len(), "{ctx}");
        for (g, w) in req.query.groups.iter().zip(&want.groups) {
            assert_eq!(g.match_, w.match_, "{ctx}");
            assert_eq!(g.rules.len(), w.rules.len(), "{ctx}");
            for (r, w) in g.rules.iter().zip(&w.rules) {
                let arg = Arg::Value(r.value.clone());
                assert_eq!(
                    (r.field.as_str(), r.op.as_str(), arg.go_type()),
                    (w.field.as_str(), w.op.as_str(), w.ty.as_str()),
                    "{ctx}"
                );
                let elems: Vec<String> = match &r.value {
                    Value::Array(items) => items
                        .iter()
                        .map(|i| Arg::Value(i.clone()).go_type().to_owned())
                        .collect(),
                    _ => Vec::new(),
                };
                assert_eq!(elems, w.elem_types.clone().unwrap_or_default(), "{ctx}");
                assert_eq!(norm(&r.value), norm(&w.value), "{ctx}");
            }
        }
        let validate = req.validate_query_definition().err().unwrap_or_default();
        assert_eq!(validate, want.validate_error, "{ctx}");
    }
}

#[derive(Deserialize)]
struct FragmentCase {
    input: String,
    output: String,
    error: String,
}

#[test]
fn display_fragments_match_go() {
    use silo_catalog::query::display_filter::normalize_display_query_fragment;
    let cases: Vec<FragmentCase> = load("query_display_fragment");
    for c in &cases {
        match normalize_display_query_fragment(c.input.as_bytes()) {
            Ok(o) => assert_eq!(
                (o.as_str(), ""),
                (c.output.as_str(), c.error.as_str()),
                "{}",
                c.input
            ),
            Err(e) => assert_eq!(e, c.error, "{}", c.input),
        }
    }
}

#[derive(Deserialize, Debug)]
struct EpisodeQueryOut {
    empty: bool,
    with_ctes: String,
    from: String,
    sort_join: String,
    #[serde(rename = "where")]
    where_: String,
    order_by: String,
    args: Option<Vec<GoArg>>,
    requires_full_page_gate: bool,
    page_sql: String,
    page_args: Option<Vec<GoArg>>,
    seek_sql: String,
    seek_args: Option<Vec<GoArg>>,
}

#[derive(Deserialize)]
struct EpisodeCase {
    executor: GoExecutor,
    def: String,
    access: GoAccess,
    limit: i64,
    offset: i64,
    user_state: Option<EpisodeQueryOut>,
    user_ok: bool,
    user_error: String,
    entries: Option<EpisodeQueryOut>,
    entries_ok: bool,
    entries_error: String,
}

fn check_episode(
    ctx: &str,
    got: Result<Option<silo_catalog::query::episode_entries::EpisodeCatalogQuery>, String>,
    (want, ok, err): (&Option<EpisodeQueryOut>, bool, &str),
    def: &QueryDefinition,
    limit: i64,
    offset: i64,
) {
    match got {
        Err(e) => assert_eq!((e.as_str(), ok), (err, true), "{ctx}"),
        Ok(None) => assert!(!ok && err.is_empty(), "{ctx}: Go answered ({err})"),
        Ok(Some(q)) => {
            let w = want
                .as_ref()
                .unwrap_or_else(|| panic!("{ctx}: Go refused: {err}"));
            assert_eq!(q.empty, w.empty, "{ctx}");
            assert_eq!(
                (
                    &q.with_ctes,
                    &q.from,
                    &q.sort_join,
                    &q.where_,
                    &q.order_by,
                    q.requires_full_page_gate
                ),
                (
                    &w.with_ctes,
                    &w.from,
                    &w.sort_join,
                    &w.where_,
                    &w.order_by,
                    w.requires_full_page_gate
                ),
                "{ctx}"
            );
            check_args(ctx, &q.args, &w.args);
            if !q.empty {
                let (sql, args, _) = q.page_sql(def, limit, offset);
                assert_eq!(sql, w.page_sql, "{ctx}");
                check_args(ctx, &args, &w.page_args);
                let (sql, args) = q.seek_sql(9);
                assert_eq!(sql, w.seek_sql, "{ctx}");
                check_args(ctx, &args, &w.seek_args);
            }
        }
    }
}

#[test]
fn episode_catalog_queries_match_go() {
    let cases: Vec<EpisodeCase> = load("query_episode");
    assert!(cases.len() > 1000);
    for c in &cases {
        let ctx = format!(
            "{:?} {} {:?} {}/{}",
            c.executor, c.def, c.access, c.limit, c.offset
        );
        let ex = c.executor.make();
        let d = def(&c.def);
        let filter = c.access.filter();
        check_episode(
            &format!("user state {ctx}"),
            ex.episode_catalog_user_state_query(&d, &filter, false),
            (&c.user_state, c.user_ok, &c.user_error),
            &d,
            c.limit,
            c.offset,
        );
        check_episode(
            &format!("entries {ctx}"),
            ex.episode_catalog_entries_query(&d, &filter),
            (&c.entries, c.entries_ok, &c.entries_error),
            &d,
            c.limit,
            c.offset,
        );
    }
}

#[derive(Deserialize)]
struct SortHelperCase {
    #[serde(rename = "fn")]
    func: String,
    field: String,
    order: String,
    flag: bool,
    sort: QuerySort,
    ok: bool,
    output: String,
}

#[test]
fn sort_helpers_match_go() {
    let cases: Vec<SortHelperCase> = load("query_sort_helpers");
    for c in &cases {
        let ctx = format!("{} {:?} {:?} {}", c.func, c.field, c.order, c.flag);
        let got = match c.func.as_str() {
            "personal_list" => definition::normalize_personal_list_sort(&c.field, &c.order),
            "personal_source" => definition::normalize_personal_source_sort(&c.field, &c.order),
            "collection" => definition::normalize_collection_sort(&c.field, &c.order, c.flag),
            "parse_default" => {
                definition::parse_collection_default_sort(c.field.as_bytes(), c.flag)
            }
            _ => {
                let sort = QuerySort {
                    field: c.field.clone(),
                    order: c.order.clone(),
                };
                let out = definition::encode_collection_default_sort(c.flag.then_some(&sort));
                assert_eq!(out, c.output, "{ctx}");
                continue;
            }
        };
        assert_eq!(got.is_some(), c.ok, "{ctx}");
        assert_eq!(got.unwrap_or_default(), c.sort, "{ctx}");
    }
}

#[derive(Deserialize)]
struct LegacyCase {
    input: String,
    def: String,
    error: String,
}

#[test]
fn legacy_section_filters_match_go() {
    let cases: Vec<LegacyCase> = load("query_legacy_section");
    for c in &cases {
        // silo_gocompat::json names a mismatched Go `int` "int64" (its documented limit), and it
        // cannot name the anonymous struct inside a field path, so this one error text differs.
        if c.input == r#"{"filter_library_id":"x"}"# {
            let e = definition::normalize_legacy_section_filter(c.input.as_bytes()).unwrap_err();
            assert!(
                e.starts_with("json: cannot unmarshal string into Go struct field "),
                "{e}"
            );
            continue;
        }
        match definition::normalize_legacy_section_filter(c.input.as_bytes()) {
            Ok(d) => {
                assert_eq!(c.error, "", "{}", c.input);
                assert_eq!(
                    silo_gocompat::json::marshal_to_string(&d).unwrap(),
                    c.def,
                    "{}",
                    c.input
                );
            }
            Err(e) => assert_eq!(e, c.error, "{}", c.input),
        }
    }
}
