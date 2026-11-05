//! `episode_catalog_entries_executor.go`: answering an "episode" definition from the
//! `episode_catalog_entries` read model when its library scope is one library.

use serde_json::Value;

use super::access::{
    AccessFilter, append_library_access_conditions, apply_section_access_filter, library_scope,
};
use super::builder::{normalize_resolution_value, parse_duration, rule_interval};
use super::definition::{
    DEFAULT_SORT_FIELD, QUERY_SORT_LAST_AIR_DATE, QUERY_SORT_RELEASE_DATE, QUERY_SORT_TITLE,
    QueryDefinition, QueryGroup, QueryRule, QuerySort, RULE_OP_IN_LAST, RULE_OP_NOT_IN_LAST,
    normalize_query_sort, query_column_sql, sort_def,
};
use super::episode_source::EPISODE_CATALOG_SERIES_PARENT_GUARD;
use super::executor::{QueryExecutor, escape_prefix_for_like, normalize_preview_page_bounds};
use super::templates as t;
use super::{Arg, lower, q, sprintf, trim};

/// `episodeCatalogQuery`.
#[derive(Clone, Debug, Default)]
pub struct EpisodeCatalogQuery {
    pub empty: bool,
    pub with_ctes: String,
    pub from: String,
    pub sort_join: String,
    pub where_: String,
    pub order_by: String,
    pub args: Vec<Arg>,
    pub requires_full_page_gate: bool,
}

#[derive(Clone, Debug, Default)]
struct UserStatePlan {
    entry_def: QueryDefinition,
    source: String,
    alias: String,
    positive_source: bool,
    user_clauses: Vec<String>,
    user_args: Vec<Arg>,
    sort_field: String,
    sort_order: String,
    sort_only: bool,
    requires_full_page_gate: bool,
    require_progress_ratio: bool,
}

/// `episodeCatalogSeekSorts`.
pub const EPISODE_CATALOG_SEEK_SORTS: &[&str] = &[
    QUERY_SORT_TITLE,
    DEFAULT_SORT_FIELD,
    QUERY_SORT_RELEASE_DATE,
    QUERY_SORT_LAST_AIR_DATE,
];

type Built = Result<(String, Vec<Arg>, usize, bool), String>;

/// `applyEpisodeCatalogAccessFilter`.
fn apply_episode_catalog_access_filter(
    library_id: i64,
    access: &AccessFilter,
    where_parts: &mut Vec<String>,
    args: &mut Vec<Arg>,
    arg_idx: &mut usize,
) {
    if !access.disabled.is_empty() {
        where_parts.push("EXISTS (SELECT 1 FROM episode_libraries el_scope_any WHERE el_scope_any.episode_id = ece.episode_id)".into());
        where_parts.push(format!("NOT EXISTS (SELECT 1 FROM episode_libraries el_scope_out WHERE el_scope_out.episode_id = ece.episode_id AND el_scope_out.media_folder_id = ANY(${}))", *arg_idx));
        args.push(Arg::Ints(
            access.disabled.iter().map(|d| i64::from(*d)).collect(),
        ));
        *arg_idx += 1;
    }
    let parent = AccessFilter {
        allowed: Some(vec![library_id as i32]),
        disabled: access.disabled.clone(),
        ..AccessFilter::default()
    };
    append_library_access_conditions("ece.series_id", &parent, where_parts, args, arg_idx);
    if access.excluded_media_types.iter().any(|t| t == "episode") {
        where_parts.push("1 = 0".into());
    }
    let mut access = access.clone();
    access.excluded_media_types = Vec::new();
    apply_section_access_filter("ece", &access, where_parts, args, arg_idx);
    where_parts.push(EPISODE_CATALOG_SERIES_PARENT_GUARD.into());
}

/// `singleEpisodeCatalogLibraryID`: `(library, empty, ok)`.
fn single_episode_catalog_library_id(
    def: &QueryDefinition,
    access: &AccessFilter,
) -> (i64, bool, bool) {
    let (ids, empty) = library_scope(access, &def.library_ids);
    if empty {
        return (0, true, true);
    }
    let ids = ids.unwrap_or_default();
    if ids.len() != 1 {
        return (0, false, false);
    }
    if ids[0] <= 0 {
        return (0, true, true);
    }
    (ids[0], false, true)
}

impl QueryExecutor {
    fn effective_scope(&self, def: &QueryDefinition) -> String {
        if self.scope.is_empty() {
            def.media_scope.clone()
        } else {
            self.scope.clone()
        }
    }

    /// `appendEpisodeCatalogViewerFilters`.
    fn append_episode_catalog_viewer_filters(
        &self,
        access: &AccessFilter,
        where_parts: &mut Vec<String>,
        args: &mut Vec<Arg>,
        arg_idx: &mut usize,
    ) {
        if let Some(at) = self.snapshot_at {
            where_parts.push(format!("ece.episode_created_at <= ${}", *arg_idx));
            args.push(Arg::Time(at));
            *arg_idx += 1;
        }
        let prefix = trim(&access.name_prefix);
        if !prefix.is_empty() {
            where_parts.push(format!("ece.sort_key LIKE ${} ESCAPE '\\'", *arg_idx));
            args.push(Arg::Str(format!("{}%", escape_prefix_for_like(prefix))));
            *arg_idx += 1;
        }
    }

    /// `episodeCatalogTotalQuery`. `Ok(None)` means the general query must answer.
    pub fn episode_catalog_total_query(
        &self,
        def: &QueryDefinition,
        access: &AccessFilter,
    ) -> Result<Option<EpisodeCatalogQuery>, String> {
        if !self.uses_episode_catalog_queries() {
            return Ok(None);
        }
        match self.episode_catalog_user_state_query(def, access, true)? {
            Some(q) => Ok(Some(q)),
            None => self.episode_catalog_entries_query(def, access),
        }
    }

    /// `episodeCatalogCountQuery`.
    pub fn episode_catalog_count_query(
        &self,
        def: &QueryDefinition,
        access: &AccessFilter,
    ) -> Result<Option<(String, Vec<Arg>)>, String> {
        let Some(q) = self.episode_catalog_total_query(def, access)? else {
            return Ok(None);
        };
        if q.empty {
            return Ok(Some(("SELECT 0".into(), Vec::new())));
        }
        let (_, _, max) = normalize_preview_page_bounds(def, 1, 0);
        Ok(Some(episode_catalog_count_sql(
            &q.with_ctes,
            &q.from,
            &q.where_,
            &q.args,
            max,
        )))
    }

    /// `episodeCatalogUserStateQuery`.
    pub fn episode_catalog_user_state_query(
        &self,
        def: &QueryDefinition,
        access: &AccessFilter,
        include_total: bool,
    ) -> Result<Option<EpisodeCatalogQuery>, String> {
        let def = def.normalize();
        if self.effective_scope(&def) != "episode" {
            return Ok(None);
        }
        if access.user_id == 0 || trim(&access.profile_id).is_empty() {
            return Ok(None);
        }
        let Some(plan) = extract_user_state_plan(&def)? else {
            return Ok(None);
        };
        if include_total && plan.sort_only {
            return Ok(None);
        }
        let (library_id, empty, ok) = single_episode_catalog_library_id(&def, access);
        if !ok {
            return Ok(None);
        }
        if empty {
            return Ok(Some(EpisodeCatalogQuery {
                empty: true,
                ..Default::default()
            }));
        }
        let mut args = vec![
            Arg::Int(access.user_id),
            Arg::Str(access.profile_id.clone()),
            Arg::Int(library_id),
        ];
        let mut arg_idx = 4;
        let mut where_parts = vec!["ece.media_folder_id = $3".to_owned()];
        if let Some(ids) = &access.allowed_content_ids {
            if ids.is_empty() {
                return Ok(Some(EpisodeCatalogQuery {
                    empty: true,
                    ..Default::default()
                }));
            }
            where_parts.push(format!("ece.episode_id = ANY(${arg_idx})"));
            args.push(Arg::Strs(ids.clone()));
            arg_idx += 1;
        }
        apply_episode_catalog_access_filter(
            library_id,
            access,
            &mut where_parts,
            &mut args,
            &mut arg_idx,
        );
        self.append_episode_catalog_viewer_filters(
            access,
            &mut where_parts,
            &mut args,
            &mut arg_idx,
        );
        let (query_where, query_args, next, ok) = entry_query_where(&plan.entry_def, arg_idx)?;
        if !ok {
            return Ok(None);
        }
        if !query_where.is_empty() {
            where_parts.push(query_where);
            args.extend(query_args);
            arg_idx = next;
        }
        where_parts.extend(rebind_user_state_clauses(&plan.user_clauses, arg_idx));
        args.extend(plan.user_args.iter().cloned());
        let Some(order_by) = user_state_order_by(&plan) else {
            return Ok(None);
        };
        Ok(Some(EpisodeCatalogQuery {
            with_ctes: user_state_cte(&plan),
            from: user_state_from_clause(&plan),
            sort_join: entry_sort_join(&plan.sort_field),
            where_: format!("WHERE {}", where_parts.join(" AND ")),
            order_by,
            args,
            requires_full_page_gate: plan.requires_full_page_gate,
            empty: false,
        }))
    }

    /// `episodeCatalogEntriesQuery`.
    pub fn episode_catalog_entries_query(
        &self,
        def: &QueryDefinition,
        access: &AccessFilter,
    ) -> Result<Option<EpisodeCatalogQuery>, String> {
        let def = def.normalize();
        if self.effective_scope(&def) != "episode" {
            return Ok(None);
        }
        let allow = !trim(&access.profile_id).is_empty();
        def.validate_with_options(allow, allow)?;
        let (library_id, empty, ok) = single_episode_catalog_library_id(&def, access);
        if !ok {
            return Ok(None);
        }
        if empty {
            return Ok(Some(EpisodeCatalogQuery {
                empty: true,
                ..Default::default()
            }));
        }
        let mut where_parts = vec!["ece.media_folder_id = $1".to_owned()];
        let mut args = vec![Arg::Int(library_id)];
        let mut arg_idx = 2;
        if let Some(ids) = &access.allowed_content_ids {
            if ids.is_empty() {
                return Ok(Some(EpisodeCatalogQuery {
                    empty: true,
                    ..Default::default()
                }));
            }
            where_parts.push(format!("ece.episode_id = ANY(${arg_idx})"));
            args.push(Arg::Strs(ids.clone()));
            arg_idx += 1;
        }
        apply_episode_catalog_access_filter(
            library_id,
            access,
            &mut where_parts,
            &mut args,
            &mut arg_idx,
        );
        self.append_episode_catalog_viewer_filters(
            access,
            &mut where_parts,
            &mut args,
            &mut arg_idx,
        );
        let (query_where, query_args, _, ok) = entry_query_where(&def, arg_idx)?;
        if !ok {
            return Ok(None);
        }
        if !query_where.is_empty() {
            where_parts.push(query_where);
            args.extend(query_args);
        }
        let Some(order_by) = entry_order_by(&def.sort) else {
            return Ok(None);
        };
        Ok(Some(EpisodeCatalogQuery {
            from: "FROM episode_catalog_entries ece".into(),
            sort_join: entry_sort_join(&def.sort.field),
            where_: format!("WHERE {}", where_parts.join(" AND ")),
            order_by,
            args,
            ..Default::default()
        }))
    }
}

impl EpisodeCatalogQuery {
    fn with_clause(&self) -> String {
        if self.with_ctes.is_empty() {
            String::new()
        } else {
            format!("WITH {}\n", self.with_ctes)
        }
    }

    /// `episodeCatalogPreviewPage`'s page statement, with the page limit it asks for.
    pub fn page_sql(
        &self,
        def: &QueryDefinition,
        limit: i64,
        offset: i64,
    ) -> (String, Vec<Arg>, i64) {
        let (limit, offset, max) = normalize_preview_page_bounds(&def.normalize(), limit, offset);
        let mut page_limit = limit;
        if max <= 0 || offset + limit < max {
            page_limit += 1;
        }
        let mut args = self.args.clone();
        let limit_at = args.len() + 1;
        args.push(Arg::Int(page_limit));
        let mut offset_clause = String::new();
        if offset > 0 {
            offset_clause = format!(" OFFSET ${}", limit_at + 1);
            args.push(Arg::Int(offset));
        }
        let sql = sprintf(
            t::ECE_PAGE,
            &[
                &self.with_clause(),
                &self.from,
                &self.sort_join,
                &self.where_,
                &self.order_by,
                &limit_at,
                &offset_clause,
            ],
        );
        (sql, args, page_limit)
    }

    /// `episodeCatalogSeek`'s statement: the episode `offset` rows in.
    pub fn seek_sql(&self, offset: i64) -> (String, Vec<Arg>) {
        let mut args = self.args.clone();
        args.push(Arg::Int(offset));
        (
            format!(
                "{}SELECT ece.episode_id {}{} {} {} LIMIT 1 OFFSET ${}",
                self.with_clause(),
                self.from,
                self.sort_join,
                self.where_,
                self.order_by,
                args.len()
            ),
            args,
        )
    }
}

/// `hydrateEpisodeCatalogEntryPage`'s statement.
pub fn hydrate_sql() -> String {
    format!(
        "SELECT {} FROM {}",
        crate::model::qualified_list_item_columns("mi"),
        sprintf(t::EPISODE_CATALOG_SELECT_BODY, &[&"e.content_id = ANY($1)"])
    )
}

/// `episodeCatalogCountSQL`.
pub fn episode_catalog_count_sql(
    with_ctes: &str,
    from: &str,
    where_: &str,
    args: &[Arg],
    max_results: i64,
) -> (String, Vec<Arg>) {
    let mut args = args.to_vec();
    let with = if trim(with_ctes).is_empty() {
        String::new()
    } else {
        format!("WITH {with_ctes}\n")
    };
    if max_results > 0 {
        let at = args.len() + 1;
        args.push(Arg::Int(max_results));
        return (
            sprintf(t::ECE_COUNT_LIMIT, &[&with, &from, &where_, &at]),
            args,
        );
    }
    (sprintf(t::ECE_COUNT, &[&with, &from, &where_]), args)
}

fn extract_user_state_plan(def: &QueryDefinition) -> Result<Option<UserStatePlan>, String> {
    let sort = normalize_query_sort(&def.sort);
    let mut plan = UserStatePlan {
        entry_def: def.clone(),
        sort_field: sort.field.clone(),
        sort_order: sort.order,
        ..Default::default()
    };
    match plan.sort_field.as_str() {
        "date_viewed" | "plays" => {
            plan.source = "viewed".into();
            plan.alias = "uv".into();
            plan.positive_source = true;
            plan.sort_only = true;
            plan.requires_full_page_gate = true;
        }
        "progress" => {
            plan.source = "progress".into();
            plan.alias = "up".into();
            plan.positive_source = true;
            plan.sort_only = true;
            plan.requires_full_page_gate = true;
        }
        _ => {}
    }
    if def.groups.is_empty() {
        if plan.source.is_empty() {
            return Ok(None);
        }
        plan.require_progress_ratio = plan.source == "progress" && plan.sort_only;
        return Ok(Some(plan));
    }
    if def.match_ != "all" {
        return Ok(None);
    }
    let mut filtered = Vec::new();
    for group in &def.groups {
        if group.match_ != "all" {
            if group
                .rules
                .iter()
                .any(|r| matches!(r.field.as_str(), "watched" | "in_progress" | "last_watched"))
            {
                return Ok(None);
            }
            filtered.push(group.clone());
            continue;
        }
        let mut rules = Vec::new();
        for rule in &group.rules {
            let Some((source, alias, positive, clause, args)) = user_state_rule(rule)? else {
                rules.push(rule.clone());
                continue;
            };
            if !plan.source.is_empty() && plan.source != source {
                return Ok(None);
            }
            plan.source = source.into();
            plan.alias = alias.into();
            plan.positive_source = positive;
            plan.user_clauses.push(clause);
            plan.user_args.extend(args);
            plan.sort_only = false;
            plan.requires_full_page_gate = false;
        }
        if !rules.is_empty() {
            filtered.push(QueryGroup {
                rules,
                ..group.clone()
            });
        }
    }
    if plan.source.is_empty() {
        return Ok(None);
    }
    plan.entry_def.groups = filtered;
    plan.require_progress_ratio = plan.source == "progress" && plan.sort_only;
    Ok(Some(plan))
}

type UserRule = (&'static str, &'static str, bool, String, Vec<Arg>);

/// `buildEpisodeCatalogUserStateRule`. `Ok(None)` leaves the rule to the entry query.
fn user_state_rule(rule: &QueryRule) -> Result<Option<UserRule>, String> {
    match rule.field.as_str() {
        "watched" => {
            let Value::Bool(v) = rule.value else {
                return Err("watched requires a boolean value".into());
            };
            let clause = if v {
                "uv.episode_id IS NOT NULL"
            } else {
                "uv.episode_id IS NULL"
            };
            Ok(Some(("viewed", "uv", v, clause.into(), Vec::new())))
        }
        "in_progress" => {
            let Value::Bool(v) = rule.value else {
                return Err("in_progress requires a boolean value".into());
            };
            let clause = if v {
                "up.episode_id IS NOT NULL"
            } else {
                "up.episode_id IS NULL"
            };
            Ok(Some(("progress", "up", v, clause.into(), Vec::new())))
        }
        "last_watched" => {
            if !matches!(rule.op.as_str(), "gt" | "gte" | "between" | "in_last") {
                return Ok(None);
            }
            let (clause, args) = match rule.op.as_str() {
                "gt" | "gte" => {
                    let op = if rule.op == "gt" { ">" } else { ">=" };
                    (
                        format!("uv.last_watched {op} $%d::timestamptz"),
                        vec![Arg::Value(rule.value.clone())],
                    )
                }
                "between" => {
                    let Value::Array(items) = &rule.value else {
                        return Err(format!(
                            "between requires [min, max] array: unsupported between value type: {}",
                            Arg::Value(rule.value.clone()).go_type()
                        ));
                    };
                    if items.len() != 2 {
                        return Err(format!(
                            "between requires [min, max] array: expected 2 elements, got {}",
                            items.len()
                        ));
                    }
                    (
                        "uv.last_watched >= $%d::timestamptz AND uv.last_watched <= $%d::timestamptz".into(),
                        vec![Arg::Value(items[0].clone()), Arg::Value(items[1].clone())],
                    )
                }
                _ => {
                    let Value::String(d) = &rule.value else {
                        return Err("in_last requires a duration string like '30d'".into());
                    };
                    (
                        format!(
                            "uv.last_watched >= NOW() - INTERVAL '{}'",
                            parse_duration(d)?
                        ),
                        Vec::new(),
                    )
                }
            };
            Ok(Some(("viewed", "uv", true, clause, args)))
        }
        _ => Ok(None),
    }
}

fn rebind_user_state_clauses(clauses: &[String], arg_idx: usize) -> Vec<String> {
    let mut next = arg_idx;
    clauses
        .iter()
        .map(|c| {
            let mut c = c.clone();
            while let Some(pos) = c.find("$%d") {
                c.replace_range(pos..pos + 3, &format!("${next}"));
                next += 1;
            }
            c
        })
        .collect()
}

fn user_state_cte(plan: &UserStatePlan) -> String {
    if plan.source == "progress" {
        let gate = if plan.require_progress_ratio {
            t::ECE_PROGRESS_RATIO_GATE
        } else {
            ""
        };
        return sprintf(t::ECE_PROGRESS_CTE, &[&gate]);
    }
    t::ECE_VIEWED_CTE.into()
}

fn user_state_from_clause(plan: &UserStatePlan) -> String {
    let table = if plan.source == "progress" {
        "user_progress"
    } else {
        "user_viewed"
    };
    let a = &plan.alias;
    if plan.positive_source {
        format!(
            "FROM {table} {a} JOIN episode_catalog_entries ece ON ece.episode_id = {a}.episode_id"
        )
    } else {
        format!(
            "FROM episode_catalog_entries ece LEFT JOIN {table} {a} ON {a}.episode_id = ece.episode_id"
        )
    }
}

fn user_state_order_by(plan: &UserStatePlan) -> Option<String> {
    let dir = if plan.sort_order == "asc" {
        "ASC"
    } else {
        "DESC"
    };
    let col = match plan.sort_field.as_str() {
        "date_viewed" => "uv.last_watched",
        "plays" => "uv.play_count",
        "progress" => "up.progress_ratio",
        _ => {
            return entry_order_by(&QuerySort {
                field: plan.sort_field.clone(),
                order: plan.sort_order.clone(),
            });
        }
    };
    Some(format!(
        "ORDER BY {col} {dir} NULLS LAST, ece.sort_key ASC, ece.episode_id ASC"
    ))
}

/// `buildEpisodeCatalogEntryQueryWhere`: `(where, args, next arg, ok)`.
fn entry_query_where(def: &QueryDefinition, mut arg_idx: usize) -> Built {
    if def.groups.is_empty() {
        return Ok((String::new(), Vec::new(), arg_idx, true));
    }
    let joiner = if def.match_ == "any" { " OR " } else { " AND " };
    let mut args = Vec::new();
    let mut clauses = Vec::new();
    for group in &def.groups {
        let (clause, group_args, next, ok) = entry_group_where(group, arg_idx)?;
        if !ok {
            return Ok((String::new(), Vec::new(), arg_idx, false));
        }
        arg_idx = next;
        args.extend(group_args);
        if !clause.is_empty() {
            clauses.push(clause);
        }
    }
    let clause = match clauses.len() {
        0 => String::new(),
        1 => format!("({})", clauses[0]),
        _ => format!(
            "({})",
            clauses
                .iter()
                .map(|c| format!("({c})"))
                .collect::<Vec<_>>()
                .join(joiner)
        ),
    };
    Ok((clause, args, arg_idx, true))
}

fn is_same_file_technical_rule(rule: &QueryRule) -> bool {
    rule.op != "is_not"
        && matches!(
            rule.field.as_str(),
            "resolution"
                | "hdr"
                | "dolby_vision"
                | "bitrate"
                | "audio_language"
                | "subtitle_language"
        )
}

fn entry_group_where(group: &QueryGroup, mut arg_idx: usize) -> Built {
    if group.rules.is_empty() {
        return Ok((String::new(), Vec::new(), arg_idx, true));
    }
    if group.match_ == "all"
        && group
            .rules
            .iter()
            .filter(|r| is_same_file_technical_rule(r))
            .count()
            > 1
    {
        return Ok((String::new(), Vec::new(), arg_idx, false));
    }
    let joiner = if group.match_ == "any" {
        " OR "
    } else {
        " AND "
    };
    let mut args = Vec::new();
    let mut clauses = Vec::new();
    for rule in &group.rules {
        let (clause, rule_args, next, ok) = entry_rule_where(rule, arg_idx)?;
        if !ok {
            return Ok((String::new(), Vec::new(), arg_idx, false));
        }
        arg_idx = next;
        args.extend(rule_args);
        if !clause.is_empty() {
            clauses.push(clause);
        }
    }
    Ok((clauses.join(joiner), args, arg_idx, true))
}

fn entry_rule_where(rule: &QueryRule, arg_idx: usize) -> Built {
    match rule.field.as_str() {
        "type" => {
            let Value::String(v) = &rule.value else {
                return Err("type requires a string value".into());
            };
            let episode = v == "episode";
            let clause = match rule.op.as_str() {
                "is" => {
                    if episode {
                        "1 = 1"
                    } else {
                        "1 = 0"
                    }
                }
                "is_not" => {
                    if episode {
                        "1 = 0"
                    } else {
                        "1 = 1"
                    }
                }
                _ => return Err(format!("unsupported type operator {}", q(&rule.op))),
            };
            Ok((clause.into(), Vec::new(), arg_idx, true))
        }
        "genre" => array_clause("ece.genres", rule, rule.value.clone(), arg_idx),
        "studio" => array_clause("ece.studios", rule, rule.value.clone(), arg_idx),
        "network" => array_clause("ece.networks", rule, rule.value.clone(), arg_idx),
        "country" => array_clause("ece.countries", rule, rule.value.clone(), arg_idx),
        "year" => comparison_clause("ece.year", rule, arg_idx, ""),
        "rating_imdb" => comparison_clause("ece.rating_imdb", rule, arg_idx, ""),
        "original_language" => equality_clause("ece.original_language", rule, arg_idx),
        "content_rating" => equality_clause("ece.content_rating", rule, arg_idx),
        "added_at" => comparison_clause("ece.episode_created_at", rule, arg_idx, "timestamptz"),
        "release_date" => comparison_clause("ece.episode_air_date", rule, arg_idx, "date"),
        "status" => equality_clause("ece.status", rule, arg_idx),
        "resolution" => {
            let Value::String(v) = &rule.value else {
                return Err("resolution requires a string value".into());
            };
            array_clause(
                "ece.resolution_codes",
                rule,
                Value::String(normalize_resolution_value(v)),
                arg_idx,
            )
        }
        "hdr" => presence_clause("ece.has_hdr", "ece.has_non_hdr", rule, arg_idx),
        "dolby_vision" => presence_clause(
            "ece.has_dolby_vision",
            "ece.has_non_dolby_vision",
            rule,
            arg_idx,
        ),
        "bitrate" => match rule.op.as_str() {
            "gt" | "gte" => Ok((
                format!(
                    "ece.max_bitrate {} ${arg_idx}",
                    if rule.op == "gt" { ">" } else { ">=" }
                ),
                vec![Arg::Value(rule.value.clone())],
                arg_idx + 1,
                true,
            )),
            "lt" | "lte" => Ok((
                format!(
                    "ece.min_bitrate {} ${arg_idx}",
                    if rule.op == "lt" { "<" } else { "<=" }
                ),
                vec![Arg::Value(rule.value.clone())],
                arg_idx + 1,
                true,
            )),
            "between" => Ok((String::new(), Vec::new(), arg_idx, false)),
            _ => Err(format!("unsupported bitrate operator {}", q(&rule.op))),
        },
        "audio_language" | "subtitle_language" => {
            let Value::String(v) = &rule.value else {
                return Err(format!("{} requires a string value", rule.field));
            };
            let column = if rule.field == "audio_language" {
                "ece.audio_language_codes"
            } else {
                "ece.subtitle_language_codes"
            };
            array_clause(column, rule, Value::String(lower(v)), arg_idx)
        }
        _ => Ok((String::new(), Vec::new(), arg_idx, false)),
    }
}

fn array_clause(column: &str, rule: &QueryRule, value: Value, arg_idx: usize) -> Built {
    if !matches!(rule.op.as_str(), "is" | "is_not" | "contains") {
        return Err(format!("unsupported array operator {}", q(&rule.op)));
    }
    let mut clause = format!("{column} @> ARRAY[${arg_idx}]::text[]");
    if rule.op == "is_not" {
        clause = format!("NOT ({clause})");
    }
    Ok((clause, vec![Arg::Value(value)], arg_idx + 1, true))
}

fn equality_clause(column: &str, rule: &QueryRule, arg_idx: usize) -> Built {
    if rule.op != "is" && rule.op != "is_not" {
        return Err(format!("unsupported equality operator {}", q(&rule.op)));
    }
    let mut clause = format!("{column} = ${arg_idx}");
    if rule.op == "is_not" {
        clause = format!("NOT ({clause})");
    }
    Ok((
        clause,
        vec![Arg::Value(rule.value.clone())],
        arg_idx + 1,
        true,
    ))
}

fn comparison_clause(column: &str, rule: &QueryRule, arg_idx: usize, cast: &str) -> Built {
    let p = |i: usize| {
        if cast.is_empty() {
            format!("${i}")
        } else {
            format!("${i}::{cast}")
        }
    };
    let v = || vec![Arg::Value(rule.value.clone())];
    match rule.op.as_str() {
        "gt" | "gte" | "lt" | "lte" => {
            let op = match rule.op.as_str() {
                "gt" => ">",
                "gte" => ">=",
                "lt" => "<",
                _ => "<=",
            };
            Ok((
                format!("{column} {op} {}", p(arg_idx)),
                v(),
                arg_idx + 1,
                true,
            ))
        }
        "between" => {
            let items = match &rule.value {
                Value::Array(items) if items.len() == 2 => items,
                Value::Array(items) => {
                    return Err(format!(
                        "between requires [min, max] array: expected 2 elements, got {}",
                        items.len()
                    ));
                }
                other => {
                    return Err(format!(
                        "between requires [min, max] array: unsupported between value type: {}",
                        Arg::Value(other.clone()).go_type()
                    ));
                }
            };
            Ok((
                format!(
                    "{column} >= {} AND {column} <= {}",
                    p(arg_idx),
                    p(arg_idx + 1)
                ),
                vec![Arg::Value(items[0].clone()), Arg::Value(items[1].clone())],
                arg_idx + 2,
                true,
            ))
        }
        "is" => Ok((format!("{column} = {}", p(arg_idx)), v(), arg_idx + 1, true)),
        "is_not" => Ok((
            format!("NOT ({column} = {})", p(arg_idx)),
            v(),
            arg_idx + 1,
            true,
        )),
        RULE_OP_IN_LAST | RULE_OP_NOT_IN_LAST => {
            let interval = rule_interval(rule)?;
            let cutoff = if cast == "date" {
                format!("(CURRENT_DATE - INTERVAL '{interval}')::date")
            } else {
                format!("NOW() - INTERVAL '{interval}'")
            };
            let clause = if rule.op == RULE_OP_NOT_IN_LAST {
                format!("{column} < {cutoff}")
            } else {
                format!("{column} >= {cutoff}")
            };
            Ok((clause, Vec::new(), arg_idx, true))
        }
        _ => Err(format!("unsupported comparison operator {}", q(&rule.op))),
    }
}

fn presence_clause(true_col: &str, false_col: &str, rule: &QueryRule, arg_idx: usize) -> Built {
    if rule.op != "is" {
        return Err(format!("unsupported boolean operator {}", q(&rule.op)));
    }
    let Value::Bool(v) = rule.value else {
        return Err(format!("{} requires a boolean value", rule.field));
    };
    Ok((
        (if v { true_col } else { false_col }).into(),
        Vec::new(),
        arg_idx,
        true,
    ))
}

/// `episodeCatalogEntrySortJoin`.
fn entry_sort_join(field: &str) -> String {
    if field == QUERY_SORT_RELEASE_DATE || field == QUERY_SORT_LAST_AIR_DATE {
        return " JOIN episodes sort_episode ON sort_episode.content_id = ece.episode_id JOIN media_items sort_series ON sort_series.content_id = ece.series_id".into();
    }
    String::new()
}

/// `episodeCatalogEntryOrderBy`.
fn entry_order_by(sort: &QuerySort) -> Option<String> {
    let sort = normalize_query_sort(sort);
    let dir = if sort.order == "asc" { "ASC" } else { "DESC" };
    let tail = "ece.sort_key ASC, ece.episode_id ASC";
    Some(match sort.field.as_str() {
        "title" => format!("ORDER BY ece.sort_key {dir}, ece.episode_id ASC"),
        "added_at" => format!("ORDER BY ece.added_at {dir}, {tail}"),
        "release_date" | "last_air_date" => format!(
            "ORDER BY ece.episode_air_date {dir} NULLS LAST, {} ASC, ece.series_id ASC, sort_episode.season_number {dir}, sort_episode.episode_number {dir}, ece.episode_id ASC",
            query_column_sql("sort_series", sort_def("title").unwrap().column_sql)
        ),
        "year" => format!("ORDER BY ece.year {dir}, {tail}"),
        "content_rating" => {
            format!("ORDER BY ece.content_rating_age {dir}, ece.content_rating_label {dir}, {tail}")
        }
        "runtime" => format!("ORDER BY ece.runtime {dir} NULLS LAST, {tail}"),
        "rating_imdb" => format!("ORDER BY ece.rating_imdb {dir} NULLS LAST, {tail}"),
        "rating_tmdb" => format!("ORDER BY ece.rating_tmdb {dir} NULLS LAST, {tail}"),
        "rating_rt_critic" | "rating_rt_audience" => format!("ORDER BY {tail}"),
        "resolution" => format!("ORDER BY ece.max_resolution_rank {dir} NULLS LAST, {tail}"),
        "bitrate" => format!("ORDER BY ece.max_bitrate {dir} NULLS LAST, {tail}"),
        _ => return None,
    })
}
