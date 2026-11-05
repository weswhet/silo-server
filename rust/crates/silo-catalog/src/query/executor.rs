//! `query_executor.go`'s plan (`buildPreviewPagePlan` and its renderers), `query_cursor.go`'s
//! cursor renderer, and `query_work_groups.go`.

use super::access::{
    AccessFilter, append_episode_parent_library_access_by_episode_id, apply_section_access_filter,
    filter_ids, in_some_library_where, library_scope, manga_chapter_exclusion_where,
    manga_count_columns,
};
use super::builder::{QueryBuilder, QuerySortPlan, escape_like_literal, user_history_cte_sql};
use super::cursor::{CursorTerm, QueryCursor, cursor_seek_sql};
use super::definition::{
    QUERY_SORT_TITLE, QueryDefinition, media_scope_item_types, normalize_query_sort,
};
use super::episode_source::{
    MEDIA_ITEMS_BASE_RELATION, catalog_library_content_expr_for_scope,
    catalog_library_membership_table_and_key_for_scope,
    episode_catalog_base_relation_for_libraries, is_episode_catalog_scope,
};
use super::templates as t;
use super::{Arg, lower_trim, rebind_sql_placeholders, sprintf, trim};
use crate::model::qualified_list_item_columns;

const CURSOR_SQL_ASCENDING: &str = "ASC";
const CURSOR_SQL_DESCENDING: &str = "DESC";

/// `QueryExecutor`, without the pool and caches: the plan it builds is pure.
#[derive(Clone, Debug, Default)]
pub struct QueryExecutor {
    pub group_by_work: bool,
    pub source_where: String,
    pub source_args: Vec<Arg>,
    pub source_order: Vec<CursorTerm>,
    pub source_cte: String,
    pub source_join: String,
    pub scope: String,
    pub base_relation_sql: String,
    /// `SnapshotAt`: limits results to items created at or before it.
    pub snapshot_at: Option<silo_gocompat::time::GoTime>,
}

/// `previewPagePlan`.
#[derive(Clone, Debug, Default)]
pub struct PreviewPagePlan {
    pub cursor_terms: Vec<CursorTerm>,
    pub ctes: Vec<String>,
    pub cte_args: Vec<Arg>,
    pub from_clause_paged: String,
    pub from_clause_count: String,
    pub where_clause: String,
    pub args: Vec<Arg>,
    pub order_by: String,
    pub sort_args: Vec<Arg>,
    pub limit: i64,
    pub offset: i64,
    pub max_results: i64,
    pub limit_arg_idx: usize,
    pub defer_episode_hydration: bool,
    pub title_key: String,
}

impl PreviewPagePlan {
    pub(crate) fn with_clause(&self) -> String {
        if self.ctes.is_empty() {
            return String::new();
        }
        format!("WITH {}\n", self.ctes.join(",\n"))
    }

    /// `countSQL`.
    pub fn count_sql(&self) -> (String, Vec<Arg>) {
        let mut args = self.cte_args.clone();
        args.extend(self.args.iter().cloned());
        let with = self.with_clause();
        if self.max_results > 0 {
            let at = args.len() + 1;
            args.push(Arg::Int(self.max_results));
            return (
                format!(
                    "{with}SELECT COUNT(*) FROM (SELECT 1 {} {} LIMIT ${at}) sub",
                    self.from_clause_count, self.where_clause
                ),
                args,
            );
        }
        (
            format!(
                "{with}SELECT COUNT(*) FROM (SELECT 1 {} {}) sub",
                self.from_clause_count, self.where_clause
            ),
            args,
        )
    }

    /// `pagedSQL`.
    pub fn paged_sql(&self, include_total: bool) -> (String, Vec<Arg>) {
        let mut query_limit = self.limit;
        if !include_total && (self.max_results <= 0 || self.offset + self.limit < self.max_results)
        {
            query_limit += 1;
        }
        let mut args = self.cte_args.clone();
        args.extend(self.args.iter().cloned());
        args.extend(self.sort_args.iter().cloned());
        args.push(Arg::Int(query_limit));
        let mut offset_clause = String::new();
        if self.offset > 0 {
            offset_clause = format!(" OFFSET ${}", self.limit_arg_idx + 1);
            args.push(Arg::Int(self.offset));
        }
        let select = format!(
            "{}, {}",
            qualified_list_item_columns("mi"),
            manga_count_columns("mi")
        );
        if self.defer_episode_hydration && self.ctes.is_empty() {
            let limit = self.limit_arg_idx;
            let sql = sprintf(
                t::DEFERRED_EPISODE_PAGE,
                &[
                    &self.from_clause_paged,
                    &self.where_clause,
                    &self.order_by,
                    &limit,
                    &offset_clause,
                    &select,
                    &self.from_clause_paged,
                    &self.order_by,
                ],
            );
            return (sql, args);
        }
        (
            format!(
                "{}SELECT {select} {} {} {} LIMIT ${}{offset_clause}",
                self.with_clause(),
                self.from_clause_paged,
                self.where_clause,
                self.order_by,
                self.limit_arg_idx
            ),
            args,
        )
    }

    /// `cursorSQL`.
    pub fn cursor_sql(&self, after: Option<&QueryCursor>) -> Result<(String, Vec<Arg>), String> {
        let (where_, mut args) = self.where_after(after)?;
        let mut columns = format!(
            "{}, {}",
            qualified_list_item_columns("mi"),
            manga_count_columns("mi")
        );
        for term in &self.cursor_terms {
            columns.push_str(&format!(", ({})::text", term.expression));
        }
        let mut query_limit = self.limit + 1;
        if self.max_results > 0 {
            query_limit = query_limit.min(self.max_results);
        }
        args.push(Arg::Int(query_limit));
        Ok((
            format!(
                "{}SELECT {columns} {} {where_} {} LIMIT ${}",
                self.with_clause(),
                self.from_clause_paged,
                self.order_by,
                args.len()
            ),
            args,
        ))
    }

    /// `whereAfter`.
    pub fn where_after(&self, after: Option<&QueryCursor>) -> Result<(String, Vec<Arg>), String> {
        let mut args = self.cte_args.clone();
        args.extend(self.args.iter().cloned());
        args.extend(self.sort_args.iter().cloned());
        let (seek, seek_args) = cursor_seek_sql(&self.cursor_terms, after, args.len() + 1)?;
        args.extend(seek_args);
        let mut where_ = self.where_clause.clone();
        if !seek.is_empty() {
            if where_.is_empty() {
                where_ = format!("WHERE {seek}");
            } else {
                where_ = format!("{where_} AND {seek}");
            }
        }
        Ok((where_, args))
    }

    /// `queryTuple`'s statement: the sort tuple `offset` rows past `after`.
    pub fn tuple_sql(
        &self,
        after: Option<&QueryCursor>,
        offset: i64,
    ) -> Result<(String, Vec<Arg>), String> {
        let (where_, mut args) = self.where_after(after)?;
        args.push(Arg::Int(offset));
        let tail = format!("{where_} {} LIMIT 1 OFFSET ${}", self.order_by, args.len());
        Ok((self.scan_tuple_sql(&tail), args))
    }

    /// `queryTupleFor`'s statement: the sort tuple of one row.
    pub fn tuple_for_sql(&self, content_id: &str) -> Result<(String, Vec<Arg>), String> {
        let (mut where_, mut args) = self.where_after(None)?;
        args.push(Arg::Str(content_id.to_owned()));
        let m = format!("mi.content_id = ${}", args.len());
        if where_.is_empty() {
            where_ = format!("WHERE {m}");
        } else {
            where_ = format!("{where_} AND {m}");
        }
        Ok((self.scan_tuple_sql(&format!("{where_} LIMIT 1")), args))
    }

    fn scan_tuple_sql(&self, tail: &str) -> String {
        let columns: Vec<String> = self
            .cursor_terms
            .iter()
            .map(|t| format!("({})::text", t.expression))
            .collect();
        format!(
            "{}SELECT {} {} {tail}",
            self.with_clause(),
            columns.join(", "),
            self.from_clause_paged
        )
    }

    /// `groupedByWork`.
    pub fn grouped_by_work(mut self) -> PreviewPagePlan {
        let mut columns = vec![
            "mi.*".to_owned(),
            "CASE WHEN mi.type IN ('ebook','audiobook') AND work_link.work_id IS NOT NULL THEN 'work:' || work_link.work_id ELSE 'item:' || mi.content_id END AS catalog_work_key".to_owned(),
        ];
        let mut terms = self.cursor_terms.clone();
        let mut inner = Vec::new();
        let mut outer = Vec::new();
        for (i, term) in terms.iter_mut().enumerate() {
            let alias = format!("catalog_work_sort_{i}");
            columns.push(format!("{} AS {alias}", term.expression));
            let mut suffix = if term.descending {
                " DESC NULLS LAST".to_owned()
            } else {
                " ASC NULLS LAST".to_owned()
            };
            if !term.nulls_last {
                suffix = suffix.replace("LAST", "FIRST");
            }
            inner.push(format!("{alias}{suffix}"));
            term.expression = format!("mi.{alias}");
            outer.push(format!("{}{suffix}", term.expression));
        }
        let sort_args = std::mem::take(&mut self.sort_args);
        self.args.extend(sort_args);
        let mut source_limit = String::new();
        let mut source_order = String::new();
        if self.max_results > 0 {
            source_order = self.order_by.clone();
            self.args.push(Arg::Int(self.max_results));
            source_limit = format!(" LIMIT ${}", self.cte_args.len() + self.args.len());
        }
        let candidates = format!(
            "catalog_work_candidates AS (SELECT {} {} LEFT JOIN literary_work_items work_link ON work_link.content_id=mi.content_id {} {source_order}{source_limit})",
            columns.join(", "),
            self.from_clause_paged,
            self.where_clause
        );
        let ranked = format!(
            "catalog_work_ranked AS (SELECT catalog_work_candidates.*, ROW_NUMBER() OVER (PARTITION BY catalog_work_key ORDER BY {}) AS catalog_work_rank FROM catalog_work_candidates)",
            inner.join(", ")
        );
        self.ctes.push(candidates);
        self.ctes.push(ranked);
        self.from_clause_paged = "FROM catalog_work_ranked mi".into();
        self.from_clause_count = self.from_clause_paged.clone();
        self.where_clause = "WHERE mi.catalog_work_rank = 1".into();
        self.order_by = format!("ORDER BY {}", outer.join(", "));
        self.cursor_terms = terms;
        self.max_results = 0;
        self.limit_arg_idx = self.cte_args.len() + self.args.len() + 1;
        self
    }
}

/// `normalizePreviewPageBounds`.
pub fn normalize_preview_page_bounds(
    def: &QueryDefinition,
    mut limit: i64,
    mut offset: i64,
) -> (i64, i64, i64) {
    if limit <= 0 {
        limit = 20;
    }
    if offset < 0 {
        offset = 0;
    }
    let Some(max) = def.limit.filter(|l| *l > 0) else {
        return (limit, offset, 0);
    };
    let remaining = max - offset;
    if remaining <= 0 {
        return (0, offset, max);
    }
    (limit.min(remaining), offset, max)
}

/// `escapePrefixForLike`.
pub fn escape_prefix_for_like(s: &str) -> String {
    escape_like_literal(&lower_trim(s))
}

/// `buildLibraryScopeJoin`.
pub fn build_library_scope_join(
    allowed: &[i64],
    disabled: &[i64],
    mut arg_idx: usize,
    media_scope: &str,
    item_content_expr: &str,
) -> (String, Vec<Arg>, bool) {
    if allowed.is_empty() && disabled.is_empty() {
        return (String::new(), Vec::new(), false);
    }
    let content = if trim(item_content_expr).is_empty() {
        "mi.content_id"
    } else {
        item_content_expr
    };
    let (table, key) = catalog_library_membership_table_and_key_for_scope(media_scope);
    let mut clauses = Vec::new();
    let mut args = Vec::new();
    if !allowed.is_empty() {
        clauses.push(format!("EXISTS (SELECT 1 FROM {table} mil_scope_in WHERE mil_scope_in.{key} = {content} AND mil_scope_in.media_folder_id = ANY(${arg_idx}))"));
        args.push(Arg::Ints(allowed.to_vec()));
        arg_idx += 1;
    }
    if !disabled.is_empty() {
        if allowed.is_empty() {
            clauses.push(format!(
                "EXISTS (SELECT 1 FROM {table} mil_scope_in WHERE mil_scope_in.{key} = {content})"
            ));
        }
        clauses.push(format!("NOT EXISTS (SELECT 1 FROM {table} mil_scope_out WHERE mil_scope_out.{key} = {content} AND mil_scope_out.media_folder_id = ANY(${arg_idx}))"));
        args.push(Arg::Ints(disabled.to_vec()));
        arg_idx += 1;
    }
    if is_episode_catalog_scope(media_scope) {
        let parent = AccessFilter {
            allowed: (!allowed.is_empty()).then(|| filter_ids(allowed)),
            disabled: filter_ids(disabled),
            ..AccessFilter::default()
        };
        let mut parent_clauses = Vec::new();
        append_episode_parent_library_access_by_episode_id(
            content,
            &parent,
            &mut parent_clauses,
            &mut args,
            &mut arg_idx,
        );
        clauses.extend(parent_clauses);
    }
    (clauses.join(" AND "), args, true)
}

impl QueryExecutor {
    /// `usesEpisodeCatalogQueries`.
    pub fn uses_episode_catalog_queries(&self) -> bool {
        !self.group_by_work
            && self.source_where.is_empty()
            && self.source_join.is_empty()
            && self.source_order.is_empty()
    }

    /// `buildCountQuery`.
    pub fn build_count_query(
        &self,
        def: &QueryDefinition,
        access: &AccessFilter,
    ) -> Result<(String, Vec<Arg>), String> {
        if let Some(count) = self.episode_catalog_count_query(def, access)? {
            return Ok(count);
        }
        let mut plan = self.build_preview_page_plan(def, access, 1, 0)?;
        if let Some(limit) = def.limit
            && !self.group_by_work
        {
            plan.max_results = limit;
        }
        Ok(plan.count_sql())
    }

    /// `buildPreviewPagePlan`.
    pub fn build_preview_page_plan(
        &self,
        def: &QueryDefinition,
        access: &AccessFilter,
        limit: i64,
        offset: i64,
    ) -> Result<PreviewPagePlan, String> {
        let def = def.normalize();
        let allow_personalized = !trim(&access.profile_id).is_empty();
        def.validate_with_options(allow_personalized, allow_personalized)?;

        let (library_ids, library_scope_empty) = library_scope(access, &def.library_ids);
        let library_ids = library_ids.unwrap_or_default();
        let disabled: Vec<i64> = access.disabled.iter().map(|d| i64::from(*d)).collect();

        let effective_scope = if self.scope.is_empty() {
            def.media_scope.clone()
        } else {
            self.scope.clone()
        };
        let mut base_relation = self.base_relation_sql.clone();
        let mut base_args = Vec::new();
        let mut library_handled = false;
        if is_episode_catalog_scope(&effective_scope) {
            let (relation, args, handled) =
                episode_catalog_base_relation_for_libraries(&library_ids, &disabled, 1);
            base_relation = relation;
            base_args = args;
            library_handled = handled;
        }
        if trim(&base_relation).is_empty() {
            base_relation = MEDIA_ITEMS_BASE_RELATION.into();
        }

        let mut builder = QueryBuilder::new("mi");
        builder
            .with_arg_idx(base_args.len() + 1)
            .with_user_scope(access.user_id, &access.profile_id)
            .with_media_scope(&effective_scope)
            .with_library_scope(&library_ids);
        if base_relation == MEDIA_ITEMS_BASE_RELATION {
            builder.with_media_items_relation();
        }
        let (filter_where, filter_args) = builder.build(&def)?;
        let filter_offset = base_args.len();
        let filter_where = rebind_sql_placeholders(&filter_where, filter_offset);

        let mut conditions: Vec<String> = Vec::new();
        let mut args = base_args;
        args.extend(filter_args);
        let mut arg_idx = builder.arg_idx() + filter_offset;

        let source_shift = arg_idx - 1;
        let source_cte = if self.source_cte.is_empty() {
            String::new()
        } else {
            rebind_sql_placeholders(&self.source_cte, source_shift)
        };
        let source_join = if self.source_join.is_empty() {
            String::new()
        } else {
            rebind_sql_placeholders(&self.source_join, source_shift)
        };
        if !self.source_where.is_empty() {
            conditions.push(format!(
                "({})",
                rebind_sql_placeholders(&self.source_where, source_shift)
            ));
        }
        if !self.source_where.is_empty() || !source_join.is_empty() || !source_cte.is_empty() {
            args.extend(self.source_args.iter().cloned());
            arg_idx += self.source_args.len();
        }
        if !filter_where.is_empty() {
            conditions.push(filter_where);
        }
        if !def.media_scope.is_empty() && !is_episode_catalog_scope(&def.media_scope) {
            let types = media_scope_item_types(&def.media_scope);
            if types.len() == 1 {
                conditions.push(format!("mi.type = ${arg_idx}"));
                args.push(Arg::Str(types[0].clone()));
            } else {
                conditions.push(format!("mi.type = ANY(${arg_idx})"));
                args.push(Arg::Strs(types));
            }
            arg_idx += 1;
        }
        let (lib_where, lib_args, has_lib) = if library_handled {
            (String::new(), Vec::new(), false)
        } else {
            build_library_scope_join(
                &library_ids,
                &disabled,
                arg_idx,
                &def.media_scope,
                &catalog_library_content_expr_for_scope(&def.media_scope, "mi"),
            )
        };
        if has_lib {
            conditions.push(lib_where);
            arg_idx += lib_args.len();
            args.extend(lib_args);
        } else if base_relation == MEDIA_ITEMS_BASE_RELATION {
            conditions.push(in_some_library_where("mi.content_id"));
        }
        if library_scope_empty {
            conditions.push("1 = 0".into());
        }
        if let Some(ids) = &access.allowed_content_ids {
            if ids.is_empty() {
                conditions.push("1 = 0".into());
            } else {
                conditions.push(format!("mi.content_id = ANY(${arg_idx})"));
                args.push(Arg::Strs(ids.clone()));
                arg_idx += 1;
            }
        }
        apply_section_access_filter("mi", access, &mut conditions, &mut args, &mut arg_idx);
        if let Some(at) = self.snapshot_at {
            conditions.push(format!("mi.created_at <= ${arg_idx}"));
            args.push(Arg::Time(at));
            arg_idx += 1;
        }
        conditions.push(manga_chapter_exclusion_where("mi"));
        let prefix = trim(&access.name_prefix);
        if !prefix.is_empty() {
            conditions.push(format!(
                "{} LIKE ${arg_idx} ESCAPE '\\'",
                builder.normalized_title_expr()
            ));
            args.push(Arg::Str(format!("{}%", escape_prefix_for_like(prefix))));
            arg_idx += 1;
        }

        let mut where_clause = String::new();
        if !conditions.is_empty() {
            where_clause = format!("WHERE {}", conditions.join(" AND "));
        }
        let mut from_base = format!("FROM {base_relation}");
        if !source_join.is_empty() {
            from_base = format!("{from_base} {source_join}");
        }
        let mut from_count = from_base.clone();

        let (limit, offset, max_results) = normalize_preview_page_bounds(&def, limit, offset);
        let mut sort_plan = builder.with_arg_idx(arg_idx).build_sort_plan(&def.sort)?;
        if !self.source_order.is_empty() {
            let mut terms = self.source_order.clone();
            let mut clauses = Vec::new();
            for term in &mut terms {
                term.expression = rebind_sql_placeholders(&term.expression, source_shift);
                let direction = if term.descending {
                    CURSOR_SQL_DESCENDING
                } else {
                    CURSOR_SQL_ASCENDING
                };
                let nulls = if term.nulls_last {
                    "NULLS LAST"
                } else {
                    "NULLS FIRST"
                };
                clauses.push(format!("{} {direction} {nulls}", term.expression));
            }
            sort_plan = QuerySortPlan {
                order_by: format!("ORDER BY {}", clauses.join(", ")),
                terms,
                ..QuerySortPlan::default()
            };
        }
        let mut from_paged = from_base;
        if !sort_plan.joins.is_empty() {
            from_paged = format!("{from_paged} {}", sort_plan.joins.join(" "));
        }
        let mut limit_arg_idx = arg_idx + sort_plan.args.len();

        let mut ctes = Vec::new();
        let mut cte_args = Vec::new();
        if !source_cte.is_empty() {
            ctes.push(source_cte);
        }
        if builder.requires_user_history_cte() {
            const SHIFT: usize = 2;
            cte_args = builder.user_history_cte_args();
            for cte in &mut ctes {
                *cte = rebind_sql_placeholders(cte, SHIFT);
            }
            ctes.insert(0, user_history_cte_sql(1));
            from_paged = rebind_sql_placeholders(&from_paged, SHIFT);
            from_count = rebind_sql_placeholders(&from_count, SHIFT);
            where_clause = rebind_sql_placeholders(&where_clause, SHIFT);
            sort_plan.order_by = rebind_sql_placeholders(&sort_plan.order_by, SHIFT);
            for term in &mut sort_plan.terms {
                term.expression = rebind_sql_placeholders(&term.expression, SHIFT);
            }
            let join = " LEFT JOIN user_last_watched uhist ON uhist.media_item_id = mi.content_id";
            from_paged.push_str(join);
            from_count.push_str(join);
            limit_arg_idx += SHIFT;
        }

        let defer = is_episode_catalog_scope(&effective_scope)
            && offset > 0
            && normalize_query_sort(&def.sort).field == QUERY_SORT_TITLE
            && sort_plan.joins.is_empty()
            && ctes.is_empty()
            && self.source_order.is_empty()
            && self.source_join.is_empty();
        let plan = PreviewPagePlan {
            cursor_terms: sort_plan.terms,
            ctes,
            cte_args,
            from_clause_paged: from_paged,
            from_clause_count: from_count,
            where_clause,
            args,
            order_by: sort_plan.order_by,
            sort_args: sort_plan.args,
            limit,
            offset,
            max_results,
            limit_arg_idx,
            defer_episode_hydration: defer,
            title_key: builder.normalized_title_expr(),
        };
        if self.group_by_work {
            return Ok(plan.grouped_by_work());
        }
        Ok(plan)
    }
}
