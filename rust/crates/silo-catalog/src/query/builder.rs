//! `query_builder.go`: a query definition's filter clause and sort plan as SQL over one alias.

use serde_json::Value;

use super::cursor::{CURSOR_KIND_DATE, CURSOR_KIND_NUMBER, CursorTerm, set_cursor_term_kinds};
use super::definition::*;
use super::episode_source::{
    catalog_library_content_expr_for_scope, catalog_media_file_group_expr_for_scope,
    catalog_media_file_join_condition_for_scope, is_episode_catalog_scope,
};
use super::templates as t;
use super::{Arg, lower, lower_trim, q, sprintf, trim};

/// `EbookFinishedProgressThresholdSQL`: `models.EbookFinishedProgressThreshold` (0.9).
pub const EBOOK_FINISHED_PROGRESS_THRESHOLD_SQL: &str = "0.9";

/// `models.PersonKind` values the rules name.
pub const PERSON_KIND_ACTOR: i64 = 1;
pub const PERSON_KIND_DIRECTOR: i64 = 2;
pub const PERSON_KIND_WRITER: i64 = 3;
pub const PERSON_KIND_PRODUCER: i64 = 4;
pub const PERSON_KIND_AUTHOR: i64 = 7;
pub const PERSON_KIND_NARRATOR: i64 = 8;

/// `QuerySortPlan`.
#[derive(Clone, Debug, Default)]
pub struct QuerySortPlan {
    pub terms: Vec<CursorTerm>,
    pub joins: Vec<String>,
    pub order_by: String,
    pub args: Vec<Arg>,
}

/// `QueryBuilder`.
#[derive(Clone, Debug)]
pub struct QueryBuilder {
    cursor_terms: Vec<CursorTerm>,
    alias: String,
    arg_idx: usize,
    args: Vec<Arg>,
    user_id: i64,
    profile_id: String,
    library_ids: Vec<i64>,
    media_scope: String,
    title_not_null: bool,
    require_user_history_cte: bool,
}

type R<T> = Result<T, String>;

impl QueryBuilder {
    /// `NewQueryBuilder`.
    pub fn new(alias: &str) -> Self {
        Self {
            cursor_terms: Vec::new(),
            alias: alias.to_owned(),
            arg_idx: 1,
            args: Vec::new(),
            user_id: 0,
            profile_id: String::new(),
            library_ids: Vec::new(),
            media_scope: String::new(),
            title_not_null: false,
            require_user_history_cte: false,
        }
    }

    pub fn with_user_scope(&mut self, user_id: i64, profile_id: &str) -> &mut Self {
        self.user_id = user_id;
        self.profile_id = profile_id.to_owned();
        self
    }

    pub fn with_library_scope(&mut self, library_ids: &[i64]) -> &mut Self {
        self.library_ids = library_ids.to_vec();
        self
    }

    pub fn with_media_items_relation(&mut self) -> &mut Self {
        self.title_not_null = true;
        self
    }

    pub fn with_media_scope(&mut self, scope: &str) -> &mut Self {
        self.media_scope = trim(scope).to_owned();
        self
    }

    pub fn with_arg_idx(&mut self, arg_idx: usize) -> &mut Self {
        if arg_idx > 0 {
            self.arg_idx = arg_idx;
        }
        self
    }

    pub fn arg_idx(&self) -> usize {
        self.arg_idx
    }

    pub fn requires_user_history_cte(&self) -> bool {
        self.require_user_history_cte
    }

    /// `UserHistoryCTEArgs`.
    pub fn user_history_cte_args(&self) -> Vec<Arg> {
        if !self.require_user_history_cte {
            return Vec::new();
        }
        vec![Arg::Int(self.user_id), Arg::Str(self.profile_id.clone())]
    }

    /// `Build`: the parenthesized filter expression and its arguments, numbered from `$1`.
    pub fn build(&mut self, def: &QueryDefinition) -> R<(String, Vec<Arg>)> {
        let normalized = def.normalize();
        normalized.validate()?;
        self.arg_idx = 1;
        self.args = Vec::new();
        if normalized.groups.is_empty() {
            return Ok((String::new(), Vec::new()));
        }
        let top_joiner = if normalized.match_ == "any" {
            " OR "
        } else {
            " AND "
        };
        let mut clauses = Vec::new();
        for group in &normalized.groups {
            let clause = self.build_group(group)?;
            if !clause.is_empty() {
                clauses.push(clause);
            }
        }
        if clauses.is_empty() {
            return Ok((String::new(), Vec::new()));
        }
        let args = std::mem::take(&mut self.args);
        self.args = args.clone();
        if clauses.len() == 1 {
            return Ok((format!("({})", clauses[0]), args));
        }
        let wrapped: Vec<String> = clauses.iter().map(|c| format!("({c})")).collect();
        Ok((format!("({})", wrapped.join(top_joiner)), args))
    }

    /// `BuildSortClause`.
    pub fn build_sort_clause(&mut self, sort: &QuerySort) -> R<(String, Vec<Arg>)> {
        let plan = self.build_sort_plan(sort)?;
        Ok((plan.order_by, plan.args))
    }

    /// `BuildSortPlan`.
    pub fn build_sort_plan(&mut self, sort: &QuerySort) -> R<QuerySortPlan> {
        self.cursor_terms = Vec::new();
        let field = normalize_query_sort(sort).field;
        let mut result = self.sort_plan_inner(sort);
        // Go's deferred function fills the terms on every return, the error path included.
        if let Ok(plan) = &mut result {
            plan.terms = self.cursor_terms.clone();
            set_cursor_term_kinds(&mut plan.terms, &field);
        }
        result
    }

    fn sort_plan_inner(&mut self, sort: &QuerySort) -> R<QuerySortPlan> {
        let sort = normalize_query_sort(sort);
        let sort_def =
            sort_def(&sort.field).unwrap_or_else(|| sort_def(DEFAULT_SORT_FIELD).unwrap());
        let dir = if sort.order == "asc" { "ASC" } else { "DESC" };
        if sort_def.personalized {
            self.ensure_user_scope(&sort.field)?;
        }
        let mut plan = QuerySortPlan::default();
        if is_episode_catalog_scope(&self.media_scope)
            && (sort.field == QUERY_SORT_RELEASE_DATE || sort.field == QUERY_SORT_LAST_AIR_DATE)
        {
            plan.order_by = self.episode_air_date_order_by(dir);
            return Ok(plan);
        }
        let title_expr = self.normalized_title_expr();
        let a = self.alias.clone();
        match sort.field.as_str() {
            "title" => {
                self.cursor_terms = vec![
                    CursorTerm {
                        descending: dir == "DESC",
                        not_null: self.title_not_null,
                        ..CursorTerm::new(&title_expr)
                    },
                    CursorTerm {
                        not_null: true,
                        ..CursorTerm::new(format!("{a}.content_id"))
                    },
                ];
                plan.order_by = format!("ORDER BY {title_expr} {dir}, {a}.content_id ASC");
                return Ok(plan);
            }
            "release_date" => {
                let expr = self.release_date_sort_expr();
                plan.order_by = self.order_by_expr(&expr, dir, true, &title_expr);
                return Ok(plan);
            }
            "added_at" => {
                let (expr, joins, args, nulls_last) = self.added_at_sort_plan();
                plan.joins = joins;
                plan.args = args;
                plan.order_by = self.order_by_expr(&expr, dir, nulls_last, &title_expr);
                return Ok(plan);
            }
            "content_rating" => {
                let rank = format!("COALESCE({a}.content_rating_age, 2147483647)");
                let label =
                    format!("LOWER(COALESCE(NULLIF(BTRIM({a}.content_rating), ''), '~~~~'))");
                self.cursor_terms = vec![
                    CursorTerm {
                        descending: dir == "DESC",
                        ..CursorTerm::new(&rank)
                    },
                    CursorTerm {
                        descending: dir == "DESC",
                        ..CursorTerm::new(&label)
                    },
                    CursorTerm::new(&title_expr),
                    CursorTerm::new(format!("{a}.content_id")),
                ];
                plan.order_by = format!(
                    "ORDER BY {rank} {dir}, {label} {dir}, {title_expr} ASC, {a}.content_id ASC"
                );
                return Ok(plan);
            }
            "resolution" => {
                let (join, args) =
                    self.media_file_sort_join("max_resolution_rank", t::RESOLUTION_RANK);
                plan.joins = vec![join];
                plan.args = args;
                plan.order_by =
                    self.order_by_expr("sort_files.max_resolution_rank", dir, true, &title_expr);
                return Ok(plan);
            }
            "bitrate" => {
                let (join, args) = self.media_file_sort_join("max_bitrate", "MAX(mf.bitrate)");
                plan.joins = vec![join];
                plan.args = args;
                plan.order_by =
                    self.order_by_expr("sort_files.max_bitrate", dir, true, &title_expr);
                return Ok(plan);
            }
            "progress" | "date_viewed" | "plays" => {
                let (expr, joins, args) = match sort.field.as_str() {
                    "progress" => self.progress_sort_plan(),
                    "date_viewed" => self.date_viewed_sort_plan(),
                    _ => self.plays_sort_plan(),
                };
                plan.joins = joins;
                plan.args = args;
                plan.order_by = self.order_by_expr(&expr, dir, true, &title_expr);
                return Ok(plan);
            }
            "last_air_date" => {
                let expr = query_column_sql(&a, LATEST_AVAILABLE_AIR_DATE_COLUMN);
                plan.order_by = self.order_by_expr(&expr, dir, true, &title_expr);
                return Ok(plan);
            }
            "author" => {
                plan.joins = vec![self.person_kind_sort_join(PERSON_KIND_AUTHOR, "sort_author")];
                plan.order_by = self.order_by_expr("sort_author.name", dir, true, &title_expr);
                return Ok(plan);
            }
            "narrator" => {
                plan.joins =
                    vec![self.person_kind_sort_join(PERSON_KIND_NARRATOR, "sort_narrator")];
                plan.order_by = self.order_by_expr("sort_narrator.name", dir, true, &title_expr);
                return Ok(plan);
            }
            "series" => {
                plan.joins = vec![format!(
                    "LEFT JOIN {} sort_series ON sort_series.content_id = {a}.content_id",
                    self.book_series_table()
                )];
                self.cursor_terms = vec![
                    CursorTerm {
                        descending: dir == "DESC",
                        nulls_last: true,
                        ..CursorTerm::new("sort_series.series_name")
                    },
                    CursorTerm {
                        nulls_last: true,
                        ..CursorTerm::new("sort_series.series_index")
                    },
                    CursorTerm::new(&title_expr),
                    CursorTerm::new(format!("{a}.content_id")),
                ];
                plan.order_by = format!(
                    "ORDER BY sort_series.series_name {dir} NULLS LAST, sort_series.series_index ASC NULLS LAST, {title_expr} ASC, {a}.content_id ASC"
                );
                return Ok(plan);
            }
            _ => {}
        }
        let column = query_column_sql(&a, sort_def.column_sql);
        plan.order_by = self.order_by_expr(&column, dir, sort_def.nulls_last, &title_expr);
        if sort_def.title_sort_only {
            plan.order_by = format!("ORDER BY {column} {dir}, {a}.content_id ASC");
        }
        Ok(plan)
    }

    fn build_group(&mut self, group: &QueryGroup) -> R<String> {
        if group.rules.is_empty() {
            return Ok(String::new());
        }
        let joiner = if group.match_ == "any" {
            " OR "
        } else {
            " AND "
        };
        let (combined, consumed) = self.build_same_file_technical_clause(group)?;
        let mut clauses = Vec::new();
        if !combined.is_empty() {
            clauses.push(combined);
        }
        for (index, rule) in group.rules.iter().enumerate() {
            if consumed.contains(&index) {
                continue;
            }
            let clause = self.build_rule(rule)?;
            if !clause.is_empty() {
                clauses.push(clause);
            }
        }
        Ok(clauses.join(joiner))
    }

    fn push(&mut self, arg: Arg) -> usize {
        self.args.push(arg);
        let at = self.arg_idx;
        self.arg_idx += 1;
        at
    }

    fn build_rule(&mut self, rule: &QueryRule) -> R<String> {
        let Some(def) = field_def(&rule.field) else {
            return Err(format!("unknown filter field: {}", q(&rule.field)));
        };
        if !def.allows(&rule.op) {
            return Err(format!(
                "invalid operator {} for field {}",
                q(&rule.op),
                q(&rule.field)
            ));
        }
        let a = self.alias.clone();
        match rule.field.as_str() {
            "actor" => return Ok(self.build_person_clause(PERSON_KIND_ACTOR, rule)),
            "director" => return Ok(self.build_person_clause(PERSON_KIND_DIRECTOR, rule)),
            "writer" => return Ok(self.build_person_clause(PERSON_KIND_WRITER, rule)),
            "producer" => return Ok(self.build_person_clause(PERSON_KIND_PRODUCER, rule)),
            "author" => return Ok(self.build_person_clause(PERSON_KIND_AUTHOR, rule)),
            "narrator" => return Ok(self.build_person_clause(PERSON_KIND_NARRATOR, rule)),
            "series" => return Ok(self.build_book_series_clause(rule)),
            "watched" => return self.build_watched_clause(rule),
            "favorited" => {
                return self.build_list_clause(rule, t::FAVORITE_CLAUSE, "favorited");
            }
            "in_watchlist" => {
                return self.build_list_clause(rule, t::WATCHLIST_CLAUSE, "in_watchlist");
            }
            "in_progress" => return self.build_in_progress_clause(rule),
            "last_watched" => {
                self.ensure_user_scope(&rule.field)?;
                self.require_user_history_cte = true;
                return self.build_timestamp_rule_clause(
                    "COALESCE(uhist.last_watched, '-infinity'::timestamptz)",
                    rule,
                );
            }
            "added_at" => {
                let expr = self.added_at_filter_expr();
                return self.build_timestamp_rule_clause(&expr, rule);
            }
            "release_date" => return self.build_release_date_clause(rule),
            QUERY_SORT_LATEST_EPISODE_ADDED => {
                if is_episode_catalog_scope(&self.media_scope) {
                    return self.build_timestamp_rule_clause("NULL::timestamptz", rule);
                }
                return self
                    .build_timestamp_rule_clause(&query_column_sql(&a, def.column_sql), rule);
            }
            QUERY_SORT_LAST_AIR_DATE => {
                return self.build_date_rule_clause(&query_column_sql(&a, def.column_sql), rule);
            }
            QUERY_SORT_TITLE => return self.build_text_rule_clause(&format!("{a}.title"), rule),
            RULE_FIELD_SHOW_TITLE => {
                if !is_episode_catalog_scope(&self.media_scope) {
                    return Ok("FALSE".into());
                }
                let m = self.build_text_rule_clause("show_title.title", rule)?;
                return Ok(format!(
                    "EXISTS (SELECT 1 FROM media_items show_title WHERE show_title.content_id = {a}.episode_series_id AND {m})"
                ));
            }
            RULE_FIELD_DECADE => return self.build_decade_clause(rule),
            QUERY_SORT_RUNTIME
            | QUERY_SORT_RATING_TMDB
            | QUERY_SORT_RATING_RT_CRITIC
            | QUERY_SORT_RATING_RT_AUDIENCE => {
                return self.build_numeric_rule_clause(&query_column_sql(&a, def.column_sql), rule);
            }
            "resolution" => return self.build_resolution_clause(rule),
            "hdr" => return Ok(self.build_media_file_equality_clause("mf.hdr", rule)),
            "dolby_vision" => return self.build_dolby_vision_clause(rule),
            "bitrate" => return self.build_media_file_comparison_clause("mf.bitrate", rule),
            "audio_language" => {
                return self.build_language_clause(
                    rule,
                    t::AUDIO_LANGUAGE_CLAUSE,
                    "audio_language",
                );
            }
            "subtitle_language" => {
                return self.build_language_clause(
                    rule,
                    t::SUBTITLE_LANGUAGE_CLAUSE,
                    "subtitle_language",
                );
            }
            _ => {}
        }
        let column = query_column_sql(&a, def.column_sql);
        match rule.op.as_str() {
            "is" => Ok(self.build_equality_clause(&column, def.is_array, &rule.value, false)),
            "is_not" => Ok(self.build_equality_clause(&column, def.is_array, &rule.value, true)),
            "contains" => {
                if !def.is_array {
                    return Err("contains operator only valid for array fields".into());
                }
                let at = self.push(Arg::Value(rule.value.clone()));
                Ok(format!("{column} @> ARRAY[${at}]::text[]"))
            }
            "gt" => Ok(self.build_comparison_clause(&column, ">", &rule.value)),
            "gte" => Ok(self.build_comparison_clause(&column, ">=", &rule.value)),
            "lt" => Ok(self.build_comparison_clause(&column, "<", &rule.value)),
            "lte" => Ok(self.build_comparison_clause(&column, "<=", &rule.value)),
            "between" => {
                let values = to_between_values(&rule.value)
                    .map_err(|e| format!("between requires [min, max] array: {e}"))?;
                let lo = self.push(Arg::Value(values[0].clone()));
                let hi = self.push(Arg::Value(values[1].clone()));
                Ok(format!("{column} >= ${lo} AND {column} <= ${hi}"))
            }
            "in_last" => {
                let Value::String(duration) = &rule.value else {
                    return Err("in_last requires a duration string like '30d'".into());
                };
                let interval = parse_duration(duration)?;
                Ok(format!("{column} >= NOW() - INTERVAL '{interval}'"))
            }
            _ => Err(format!("unhandled operator: {}", q(&rule.op))),
        }
    }

    fn negate(rule: &QueryRule, clause: String) -> String {
        if rule.op == "is_not" {
            format!("NOT ({clause})")
        } else {
            clause
        }
    }

    fn build_person_clause(&mut self, kind: i64, rule: &QueryRule) -> String {
        let at = self.push(Arg::Value(rule.value.clone()));
        let clause = sprintf(t::PERSON_CLAUSE, &[&self.alias, &kind, &at]);
        Self::negate(rule, clause)
    }

    fn person_kind_sort_join(&self, kind: i64, alias: &str) -> String {
        sprintf(t::PERSON_KIND_SORT_JOIN, &[&self.alias, &kind, &alias])
    }

    fn book_series_table(&self) -> &'static str {
        if self.media_scope == "ebook" {
            "ebook_series"
        } else {
            "audiobook_series"
        }
    }

    fn build_book_series_clause(&mut self, rule: &QueryRule) -> String {
        let at = self.push(Arg::Value(rule.value.clone()));
        let table = self.book_series_table();
        let clause = sprintf(t::BOOK_SERIES_CLAUSE, &[&table, &self.alias, &at]);
        Self::negate(rule, clause)
    }

    fn build_resolution_clause(&mut self, rule: &QueryRule) -> R<String> {
        let Value::String(value) = &rule.value else {
            return Err("resolution requires a string value".into());
        };
        let scope = self.media_file_library_scope_clause("mf");
        let at = self.push(Arg::Str(normalize_resolution_value(value)));
        let clause = sprintf(
            t::RESOLUTION_CLAUSE,
            &[
                &self.media_file_join_condition("mf"),
                &scope,
                &normalized_resolution_expr("mf.resolution"),
                &at,
            ],
        );
        Ok(Self::negate(rule, clause))
    }

    fn build_media_file_equality_clause(&mut self, column: &str, rule: &QueryRule) -> String {
        let scope = self.media_file_library_scope_clause("mf");
        let at = self.push(Arg::Value(rule.value.clone()));
        let clause = sprintf(
            t::MEDIA_FILE_EQUALITY_CLAUSE,
            &[&self.media_file_join_condition("mf"), &scope, &column, &at],
        );
        Self::negate(rule, clause)
    }

    fn build_media_file_comparison_clause(&mut self, column: &str, rule: &QueryRule) -> R<String> {
        let scope = self.media_file_library_scope_clause("mf");
        match rule.op.as_str() {
            "gt" | "gte" | "lt" | "lte" => {
                let operator = comparison_sql(&rule.op);
                let at = self.push(Arg::Value(rule.value.clone()));
                Ok(sprintf(
                    t::MEDIA_FILE_COMPARISON_CLAUSE,
                    &[
                        &self.media_file_join_condition("mf"),
                        &scope,
                        &column,
                        &operator,
                        &at,
                    ],
                ))
            }
            "between" => {
                let values = to_between_values(&rule.value)
                    .map_err(|e| format!("between requires [min, max] array: {e}"))?;
                let lo = self.push(Arg::Value(values[0].clone()));
                let hi = self.push(Arg::Value(values[1].clone()));
                Ok(sprintf(
                    t::MEDIA_FILE_BETWEEN_CLAUSE,
                    &[
                        &self.media_file_join_condition("mf"),
                        &scope,
                        &column,
                        &lo,
                        &column,
                        &hi,
                    ],
                ))
            }
            _ => Err(format!(
                "unsupported operator {} for media file comparison",
                q(&rule.op)
            )),
        }
    }

    fn build_dolby_vision_clause(&mut self, rule: &QueryRule) -> R<String> {
        let Value::Bool(value) = rule.value else {
            return Err("dolby_vision requires a boolean value".into());
        };
        let scope = self.media_file_library_scope_clause("mf");
        let mut inner = t::DOLBY_VISION_INNER.to_owned();
        if !value {
            inner = format!("NOT {inner}");
        }
        Ok(sprintf(
            t::DOLBY_VISION_CLAUSE,
            &[&self.media_file_join_condition("mf"), &scope, &inner],
        ))
    }

    fn build_language_clause(
        &mut self,
        rule: &QueryRule,
        template: &str,
        field: &str,
    ) -> R<String> {
        let Value::String(value) = &rule.value else {
            return Err(format!("{field} requires a string value"));
        };
        let scope = self.media_file_library_scope_clause("mf");
        let at = self.push(Arg::Str(lower(value)));
        let join = self.media_file_join_condition("mf");
        let clause = if field == "audio_language" {
            sprintf(template, &[&join, &scope, &at])
        } else {
            sprintf(template, &[&join, &scope, &at, &at])
        };
        Ok(Self::negate(rule, clause))
    }

    fn build_same_file_technical_clause(&mut self, group: &QueryGroup) -> R<(String, Vec<usize>)> {
        if group.match_ == "any" {
            return Ok((String::new(), Vec::new()));
        }
        let start_idx = self.arg_idx;
        let start_len = self.args.len();
        let mut consumed = Vec::new();
        let mut predicates = Vec::new();
        for (index, rule) in group.rules.iter().enumerate() {
            if !is_same_file_technical_rule(rule) {
                continue;
            }
            let predicate = self.build_technical_media_file_predicate(rule, "mf")?;
            if predicate.is_empty() {
                continue;
            }
            consumed.push(index);
            predicates.push(predicate);
        }
        if predicates.len() < 2 {
            self.arg_idx = start_idx;
            self.args.truncate(start_len);
            return Ok((String::new(), Vec::new()));
        }
        let mut parts = vec![
            self.media_file_join_condition("mf"),
            "mf.missing_since IS NULL".to_owned(),
        ];
        if !self.library_ids.is_empty() {
            let ids = self.library_ids.clone();
            let placeholders = self.consume_int_args(&ids);
            parts.push(format!(
                "mf.media_folder_id IN ({})",
                placeholders.join(", ")
            ));
        }
        parts.extend(predicates);
        Ok((
            sprintf(t::SAME_FILE_CLAUSE, &[&parts.join("\n\t\t  AND ")]),
            consumed,
        ))
    }

    fn build_technical_media_file_predicate(&mut self, rule: &QueryRule, alias: &str) -> R<String> {
        match rule.field.as_str() {
            "resolution" => {
                let Value::String(value) = &rule.value else {
                    return Err("resolution requires a string value".into());
                };
                let at = self.push(Arg::Str(normalize_resolution_value(value)));
                Ok(format!(
                    "{} = ${at}",
                    normalized_resolution_expr(&format!("{alias}.resolution"))
                ))
            }
            "hdr" => {
                let Value::Bool(value) = rule.value else {
                    return Err("hdr requires a boolean value".into());
                };
                let at = self.push(Arg::Bool(value));
                Ok(format!("{alias}.hdr = ${at}"))
            }
            "dolby_vision" => {
                let Value::Bool(value) = rule.value else {
                    return Err("dolby_vision requires a boolean value".into());
                };
                let predicate = sprintf(t::SAME_FILE_DOLBY_VISION, &[&alias]);
                Ok(if value {
                    predicate
                } else {
                    format!("NOT ({predicate})")
                })
            }
            "bitrate" => {
                let column = format!("{alias}.bitrate");
                match rule.op.as_str() {
                    "gt" | "gte" | "lt" | "lte" => {
                        let at = self.push(Arg::Value(rule.value.clone()));
                        Ok(format!("{column} {} ${at}", comparison_sql(&rule.op)))
                    }
                    "between" => {
                        let values = to_between_values(&rule.value)
                            .map_err(|e| format!("between requires [min, max] array: {e}"))?;
                        let lo = self.push(Arg::Value(values[0].clone()));
                        let hi = self.push(Arg::Value(values[1].clone()));
                        Ok(format!("{column} >= ${lo} AND {column} <= ${hi}"))
                    }
                    _ => Err(format!(
                        "unsupported operator {} for media file comparison",
                        q(&rule.op)
                    )),
                }
            }
            "audio_language" => {
                let Value::String(value) = &rule.value else {
                    return Err("audio_language requires a string value".into());
                };
                let at = self.push(Arg::Str(lower(value)));
                Ok(format!(
                    "{alias}.audio_language_codes @> ARRAY[${at}]::text[]"
                ))
            }
            "subtitle_language" => {
                let Value::String(value) = &rule.value else {
                    return Err("subtitle_language requires a string value".into());
                };
                let at = self.push(Arg::Str(lower(value)));
                Ok(sprintf(t::SAME_FILE_SUBTITLE, &[&alias, &at, &alias, &at]))
            }
            _ => Err(format!(
                "field {} does not support same-file filtering",
                q(&rule.field)
            )),
        }
    }

    fn media_file_library_scope_clause(&mut self, alias: &str) -> String {
        if self.library_ids.is_empty() {
            return "TRUE".into();
        }
        let ids = self.library_ids.clone();
        let placeholders = self.consume_int_args(&ids);
        format!("{alias}.media_folder_id IN ({})", placeholders.join(", "))
    }

    fn media_file_join_condition(&self, mf: &str) -> String {
        catalog_media_file_join_condition_for_scope(&self.media_scope, mf, &self.alias)
    }

    fn ensure_user_scope(&self, field: &str) -> R<()> {
        if self.user_id == 0 || trim(&self.profile_id).is_empty() {
            return Err(format!("field {} requires user scope", q(field)));
        }
        Ok(())
    }

    fn build_watched_clause(&mut self, rule: &QueryRule) -> R<String> {
        self.ensure_user_scope(&rule.field)?;
        let Value::Bool(value) = rule.value else {
            return Err("watched requires a boolean value".into());
        };
        let clause = self.user_state_completion_clause();
        Ok(if value {
            clause
        } else {
            format!("NOT ({clause})")
        })
    }

    fn build_list_clause(&mut self, rule: &QueryRule, template: &str, field: &str) -> R<String> {
        self.ensure_user_scope(&rule.field)?;
        let Value::Bool(value) = rule.value else {
            return Err(format!("{field} requires a boolean value"));
        };
        let base = self.push_user();
        let clause = sprintf(template, &[&base, &(base + 1), &self.alias]);
        Ok(if value {
            clause
        } else {
            format!("NOT ({clause})")
        })
    }

    fn push_user(&mut self) -> usize {
        self.args.push(Arg::Int(self.user_id));
        self.args.push(Arg::Str(self.profile_id.clone()));
        let base = self.arg_idx;
        self.arg_idx += 2;
        base
    }

    fn build_in_progress_clause(&mut self, rule: &QueryRule) -> R<String> {
        self.ensure_user_scope(&rule.field)?;
        let Value::Bool(value) = rule.value else {
            return Err("in_progress requires a boolean value".into());
        };
        let base = self.push_user();
        let clause = if self.media_scope == "ebook" {
            sprintf(
                t::EBOOK_IN_PROGRESS_CLAUSE,
                &[
                    &base,
                    &(base + 1),
                    &self.alias,
                    &EBOOK_FINISHED_PROGRESS_THRESHOLD_SQL,
                    &base,
                    &(base + 1),
                ],
            )
        } else {
            sprintf(
                t::IN_PROGRESS_CLAUSE,
                &[&base, &(base + 1), &self.alias, &base, &(base + 1)],
            )
        };
        Ok(if value {
            clause
        } else {
            format!("NOT ({clause})")
        })
    }

    fn build_release_date_clause(&mut self, rule: &QueryRule) -> R<String> {
        const MARKER: &str = "\u{0}release_date\u{0}";
        let clause = self.build_date_rule_clause(MARKER, rule)?;
        let a = &self.alias;
        if is_episode_catalog_scope(&self.media_scope) {
            return Ok(clause.replace(MARKER, &format!("{a}.episode_air_date")));
        }
        let release_date = format!("{a}.release_date");
        let trimmed = format!("NULLIF(BTRIM({a}.first_air_date), '')");
        let first_air = format!(
            "(CASE WHEN {trimmed} ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$' THEN {trimmed}::date ELSE NULL END)"
        );
        Ok(format!(
            "(({release_date} IS NOT NULL AND {}) OR ({release_date} IS NULL AND {}))",
            clause.replace(MARKER, &release_date),
            clause.replace(MARKER, &first_air)
        ))
    }

    fn build_timestamp_rule_clause(&mut self, column: &str, rule: &QueryRule) -> R<String> {
        self.build_relative_rule_clause(column, rule, "timestamptz", |i| {
            format!("NOW() - INTERVAL '{i}'")
        })
    }

    fn build_date_rule_clause(&mut self, column: &str, rule: &QueryRule) -> R<String> {
        self.build_relative_rule_clause(column, rule, "date", |i| {
            format!("(CURRENT_DATE - INTERVAL '{i}')::date")
        })
    }

    fn build_relative_rule_clause(
        &mut self,
        column: &str,
        rule: &QueryRule,
        cast: &str,
        cutoff: impl Fn(&str) -> String,
    ) -> R<String> {
        match rule.op.as_str() {
            "gt" | "gte" | "lt" | "lte" => Ok(self.build_typed_comparison_clause(
                column,
                comparison_sql(&rule.op),
                &rule.value,
                cast,
            )),
            "between" => self.build_typed_between_clause(column, &rule.value, cast),
            RULE_OP_IN_LAST | RULE_OP_NOT_IN_LAST => {
                let interval = rule_interval(rule)?;
                let cutoff = cutoff(&interval);
                Ok(if rule.op == RULE_OP_NOT_IN_LAST {
                    format!("{column} < {cutoff}")
                } else {
                    format!("{column} >= {cutoff}")
                })
            }
            _ => Err(format!(
                "unsupported operator {} for {}",
                q(&rule.op),
                rule.field
            )),
        }
    }

    fn build_numeric_rule_clause(&mut self, column: &str, rule: &QueryRule) -> R<String> {
        match rule.op.as_str() {
            "gt" | "gte" | "lt" | "lte" => {
                if catalog_float(&rule.value).is_none() {
                    return Err(format!("{} requires a number", rule.field));
                }
                Ok(self.build_typed_comparison_clause(
                    column,
                    comparison_sql(&rule.op),
                    &rule.value,
                    "numeric",
                ))
            }
            "between" => {
                if catalog_float_range(&rule.value).is_none() {
                    return Err(format!(
                        "{} between requires [min, max] numbers",
                        rule.field
                    ));
                }
                self.build_typed_between_clause(column, &rule.value, "numeric")
            }
            _ => Err(format!(
                "unsupported operator {} for {}",
                q(&rule.op),
                rule.field
            )),
        }
    }

    fn build_text_rule_clause(&mut self, column: &str, rule: &QueryRule) -> R<String> {
        let Value::String(value) = &rule.value else {
            return Err(format!("{} requires a string value", rule.field));
        };
        let value = trim(value).to_owned();
        let escaped = escape_like_literal(&value);
        let at = self.arg_idx;
        let clause = match rule.op.as_str() {
            "is" | "is_not" => {
                self.args.push(Arg::Str(value));
                format!("LOWER(BTRIM({column})) = LOWER(${at})")
            }
            "contains" | RULE_OP_NOT_CONTAINS => {
                self.args.push(Arg::Str(format!("%{escaped}%")));
                format!("{column} ILIKE ${at} ESCAPE '\\'")
            }
            RULE_OP_BEGINS_WITH => {
                self.args.push(Arg::Str(format!("{escaped}%")));
                format!("BTRIM({column}) ILIKE ${at} ESCAPE '\\'")
            }
            RULE_OP_ENDS_WITH => {
                self.args.push(Arg::Str(format!("%{escaped}")));
                format!("BTRIM({column}) ILIKE ${at} ESCAPE '\\'")
            }
            _ => {
                return Err(format!(
                    "unsupported operator {} for {}",
                    q(&rule.op),
                    rule.field
                ));
            }
        };
        self.arg_idx += 1;
        Ok(if rule.op == "is_not" || rule.op == RULE_OP_NOT_CONTAINS {
            format!("NOT ({clause})")
        } else {
            clause
        })
    }

    fn build_decade_clause(&mut self, rule: &QueryRule) -> R<String> {
        let Some(start) = decade_start(&rule.value) else {
            return Err("decade requires a year such as 1990".into());
        };
        let lo = self.push(Arg::Int(start));
        let hi = self.push(Arg::Int(start + 9));
        let column = format!("{}.year", self.alias);
        let clause = format!("{column} >= ${lo} AND {column} <= ${hi}");
        Ok(Self::negate(rule, clause))
    }

    /// `userStateCompletionClause`.
    fn user_state_completion_clause(&mut self) -> String {
        let base = self.push_user();
        let row_id = format!("{}.content_id", self.alias);
        let a = self.alias.clone();
        match self.media_scope.as_str() {
            "ebook" => ebook_leaf_completion_sql(&row_id, base),
            "series" => episode_rollup_completion_sql("series_id", &a, base),
            "movie" | "episode" | "audiobook" | "manga" => video_leaf_completion_sql(&row_id, base),
            _ => sprintf(
                t::COMPLETION_CASE,
                &[
                    &a,
                    &episode_rollup_completion_sql("series_id", &a, base),
                    &episode_rollup_completion_sql("season_id", &a, base),
                    &ebook_leaf_completion_sql(&row_id, base),
                    &video_leaf_completion_sql(&row_id, base),
                ],
            ),
        }
    }

    fn build_typed_comparison_clause(
        &mut self,
        column: &str,
        op: &str,
        value: &Value,
        cast: &str,
    ) -> String {
        let at = self.push(Arg::Value(value.clone()));
        let mut placeholder = format!("${at}");
        if !cast.is_empty() {
            placeholder = format!("{placeholder}::{cast}");
        }
        format!("{column} {op} {placeholder}")
    }

    fn build_typed_between_clause(&mut self, column: &str, value: &Value, cast: &str) -> R<String> {
        let values = to_between_values(value)
            .map_err(|e| format!("between requires [min, max] array: {e}"))?;
        let lo = self.push(Arg::Value(values[0].clone()));
        let hi = self.push(Arg::Value(values[1].clone()));
        let (mut left, mut right) = (format!("${lo}"), format!("${hi}"));
        if !cast.is_empty() {
            left = format!("{left}::{cast}");
            right = format!("{right}::{cast}");
        }
        Ok(format!("{column} >= {left} AND {column} <= {right}"))
    }

    /// `normalizedTitleExpr`.
    pub fn normalized_title_expr(&self) -> String {
        let a = &self.alias;
        if is_episode_catalog_scope(&self.media_scope) {
            return format!("{a}.sort_key");
        }
        format!("LOWER(COALESCE(NULLIF(BTRIM({a}.sort_title), ''), {a}.title))")
    }

    fn episode_air_date_order_by(&mut self, dir: &str) -> String {
        let descending = dir == "DESC";
        let a = self.alias.clone();
        self.cursor_terms = vec![
            CursorTerm {
                kind: CURSOR_KIND_DATE.into(),
                descending,
                nulls_last: true,
                ..CursorTerm::new(format!("{a}.episode_air_date"))
            },
            CursorTerm::new(format!("{a}.episode_series_sort_key")),
            CursorTerm::new(format!("{a}.episode_series_id")),
            CursorTerm {
                kind: CURSOR_KIND_NUMBER.into(),
                descending,
                ..CursorTerm::new(format!("{a}.episode_season_number"))
            },
            CursorTerm {
                kind: CURSOR_KIND_NUMBER.into(),
                descending,
                ..CursorTerm::new(format!("{a}.episode_number"))
            },
            CursorTerm::new(format!("{a}.content_id")),
        ];
        format!(
            "ORDER BY {a}.episode_air_date {dir} NULLS LAST, {a}.episode_series_sort_key ASC, {a}.episode_series_id ASC, {a}.episode_season_number {dir}, {a}.episode_number {dir}, {a}.content_id ASC"
        )
    }

    fn release_date_sort_expr(&self) -> String {
        if is_episode_catalog_scope(&self.media_scope) {
            return format!("{}.episode_air_date", self.alias);
        }
        query_column_sql(&self.alias, sort_def("release_date").unwrap().column_sql)
    }

    fn added_at_filter_expr(&self) -> String {
        if is_episode_catalog_scope(&self.media_scope) {
            return format!("{}.episode_created_at", self.alias);
        }
        format!("{}.created_at", self.alias)
    }

    fn order_by_expr(
        &mut self,
        expr: &str,
        dir: &str,
        nulls_last: bool,
        title_expr: &str,
    ) -> String {
        let a = &self.alias;
        self.cursor_terms = vec![
            CursorTerm {
                descending: dir == "DESC",
                nulls_last: nulls_last || dir != "DESC",
                ..CursorTerm::new(expr)
            },
            CursorTerm {
                nulls_last: true,
                ..CursorTerm::new(title_expr)
            },
            CursorTerm {
                nulls_last: true,
                ..CursorTerm::new(format!("{a}.content_id"))
            },
        ];
        let mut clause = format!("ORDER BY {expr} {dir}");
        if nulls_last {
            clause.push_str(" NULLS LAST");
        }
        clause.push_str(&format!(", {title_expr} ASC, {a}.content_id ASC"));
        clause
    }

    fn added_at_sort_plan(&mut self) -> (String, Vec<String>, Vec<Arg>, bool) {
        let a = self.alias.clone();
        if self.library_ids.is_empty() {
            return (format!("{a}.created_at"), Vec::new(), Vec::new(), false);
        }
        let ids = self.library_ids.clone();
        let start = self.args.len();
        let placeholders = self.consume_int_args(&ids);
        let args: Vec<Arg> = self.args.drain(start..).collect();
        if is_episode_catalog_scope(&self.media_scope) {
            if ids.len() == 1 {
                let join = sprintf(t::ADDED_EPISODE_SINGLE_JOIN, &[&a, &placeholders[0]]);
                return ("sort_added.first_seen_at".into(), vec![join], args, false);
            }
            let join = sprintf(t::ADDED_EPISODE_MULTI_JOIN, &[&placeholders.join(", "), &a]);
            return ("sort_added.added_at".into(), vec![join], args, true);
        }
        let content = catalog_library_content_expr_for_scope(&self.media_scope, &a);
        if ids.len() == 1 {
            let join = sprintf(t::ADDED_SINGLE_JOIN, &[&content, &placeholders[0]]);
            return ("sort_added.first_seen_at".into(), vec![join], args, false);
        }
        let join = sprintf(t::ADDED_MULTI_JOIN, &[&placeholders.join(", "), &content]);
        ("sort_added.added_at".into(), vec![join], args, true)
    }

    fn media_file_sort_join(&mut self, column_alias: &str, aggregate: &str) -> (String, Vec<Arg>) {
        let mut parts = vec!["mf.missing_since IS NULL".to_owned()];
        let mut args = Vec::new();
        if !self.library_ids.is_empty() {
            let ids = self.library_ids.clone();
            let start = self.args.len();
            let placeholders = self.consume_int_args(&ids);
            args = self.args.drain(start..).collect();
            parts.push(format!(
                "mf.media_folder_id IN ({})",
                placeholders.join(", ")
            ));
        }
        let group = catalog_media_file_group_expr_for_scope(&self.media_scope, "mf");
        let join = sprintf(
            t::MEDIA_FILE_SORT_JOIN,
            &[
                &group,
                &aggregate,
                &column_alias,
                &parts.join(" AND "),
                &group,
                &self.alias,
            ],
        );
        (join, args)
    }

    /// `consumeIntArgs`, which here also appends the arguments; callers that keep them apart drain
    /// them back off.
    fn consume_int_args(&mut self, values: &[i64]) -> Vec<String> {
        let placeholders = (0..values.len())
            .map(|i| format!("${}", self.arg_idx + i))
            .collect();
        self.args.extend(values.iter().map(|v| Arg::Int(*v)));
        self.arg_idx += values.len();
        placeholders
    }

    fn user_join(&self, template: &str, ebook: bool) -> String {
        let i = self.arg_idx;
        if ebook {
            sprintf(
                template,
                &[
                    &EBOOK_FINISHED_PROGRESS_THRESHOLD_SQL,
                    &i,
                    &(i + 1),
                    &i,
                    &(i + 1),
                    &self.alias,
                ],
            )
        } else {
            sprintf(template, &[&i, &(i + 1), &i, &(i + 1), &self.alias])
        }
    }

    fn user_args(&self) -> Vec<Arg> {
        vec![Arg::Int(self.user_id), Arg::Str(self.profile_id.clone())]
    }

    fn progress_sort_plan(&self) -> (String, Vec<String>, Vec<Arg>) {
        if self.media_scope == "ebook" {
            return (
                "sort_progress.progress_ratio".into(),
                vec![self.user_join(t::EBOOK_PROGRESS_SORT_JOIN, true)],
                self.user_args(),
            );
        }
        (
            "sort_progress.progress_ratio".into(),
            vec![self.user_join(t::PROGRESS_SORT_JOIN, false)],
            self.user_args(),
        )
    }

    fn date_viewed_sort_plan(&self) -> (String, Vec<String>, Vec<Arg>) {
        if self.media_scope == "ebook" {
            return (
                "sort_ebook_viewed.viewed_at".into(),
                vec![self.user_join(t::EBOOK_DATE_VIEWED_JOIN, true)],
                self.user_args(),
            );
        }
        (
            t::DATE_VIEWED_EXPR.into(),
            vec![
                self.user_join(t::DATE_VIEWED_HISTORY_JOIN, false),
                self.user_join(t::DATE_VIEWED_PROGRESS_JOIN, false),
            ],
            self.user_args(),
        )
    }

    fn plays_sort_plan(&self) -> (String, Vec<String>, Vec<Arg>) {
        if self.media_scope == "ebook" {
            return (
                "NULLIF(sort_ebook_plays.completed_play_count, 0)".into(),
                vec![self.user_join(t::EBOOK_PLAYS_JOIN, true)],
                self.user_args(),
            );
        }
        (
            t::PLAYS_EXPR.into(),
            vec![
                self.user_join(t::PLAYS_HISTORY_JOIN, false),
                self.user_join(t::PLAYS_PROGRESS_JOIN, false),
            ],
            self.user_args(),
        )
    }

    fn build_equality_clause(
        &mut self,
        column: &str,
        is_array: bool,
        value: &Value,
        negate: bool,
    ) -> String {
        let at = self.push(Arg::Value(value.clone()));
        if is_array {
            let clause = format!("{column} @> ARRAY[${at}]::text[]");
            return if negate {
                format!("NOT ({clause})")
            } else {
                clause
            };
        }
        let op = if negate { "!=" } else { "=" };
        format!("{column} {op} ${at}")
    }

    fn build_comparison_clause(&mut self, column: &str, op: &str, value: &Value) -> String {
        let at = self.push(Arg::Value(value.clone()));
        format!("{column} {op} ${at}")
    }
}

/// `UserHistoryCTESQL`.
pub fn user_history_cte_sql(arg_idx: usize) -> String {
    let (a, b) = (arg_idx, arg_idx + 1);
    sprintf(
        t::USER_HISTORY_CTE,
        &[
            &a,
            &b,
            &a,
            &b,
            &a,
            &b,
            &EBOOK_FINISHED_PROGRESS_THRESHOLD_SQL,
            &a,
            &b,
        ],
    )
}

fn video_leaf_completion_sql(content: &str, base: usize) -> String {
    sprintf(t::VIDEO_LEAF_COMPLETION, &[&base, &(base + 1), &content])
}

fn ebook_leaf_completion_sql(content: &str, base: usize) -> String {
    sprintf(
        t::EBOOK_LEAF_COMPLETION,
        &[
            &base,
            &(base + 1),
            &content,
            &EBOOK_FINISHED_PROGRESS_THRESHOLD_SQL,
        ],
    )
}

fn episode_rollup_completion_sql(link: &str, alias: &str, base: usize) -> String {
    let leaf = video_leaf_completion_sql("episodes.content_id", base);
    sprintf(
        t::EPISODE_ROLLUP_COMPLETION,
        &[&link, &alias, &t::EPISODE_AVAILABILITY_PREDICATE, &leaf],
    )
}

fn comparison_sql(op: &str) -> &'static str {
    match op {
        "gt" => ">",
        "gte" => ">=",
        "lt" => "<",
        _ => "<=",
    }
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

/// `normalizedResolutionExpr`.
pub fn normalized_resolution_expr(column: &str) -> String {
    sprintf(t::NORMALIZED_RESOLUTION, &[&column, &column])
}

/// `normalizeResolutionValue`.
pub fn normalize_resolution_value(value: &str) -> String {
    let v = lower_trim(value);
    if v == "4k" || v == "uhd" {
        "2160p".into()
    } else {
        v
    }
}

/// `pathscope.EscapeLike` and `escapeLikeLiteral`: escapes `\`, `%`, and `_`.
pub fn escape_like_literal(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// `toBetweenValues`, for a value decoded from JSON.
fn to_between_values(v: &Value) -> Result<[Value; 2], String> {
    match v {
        Value::Array(items) if items.len() == 2 => Ok([items[0].clone(), items[1].clone()]),
        Value::Array(items) => Err(format!("expected 2 elements, got {}", items.len())),
        other => Err(format!(
            "unsupported between value type: {}",
            Arg::Value(other.clone()).go_type()
        )),
    }
}

/// `ruleInterval`.
pub fn rule_interval(rule: &QueryRule) -> R<String> {
    let Value::String(duration) = &rule.value else {
        return Err(format!("{} requires a duration string like '30d'", rule.op));
    };
    parse_duration(duration)
}

/// `parseDuration`.
pub fn parse_duration(s: &str) -> R<String> {
    let (amount, unit) = parse_duration_spec(s, now_unix())?;
    let word = match unit {
        b'h' => "hours",
        b'd' => "days",
        b'w' => "weeks",
        b'm' => "months",
        _ => "years",
    };
    Ok(format!("{amount} {word}"))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `strconv.Atoi`.
pub fn go_atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

/// `parseDurationSpec`, with `now` in Unix seconds (UTC).
pub fn parse_duration_spec(s: &str, now: i64) -> R<(i64, u8)> {
    let normalized = lower_trim(s);
    let invalid = || format!("invalid duration: {}", q(s));
    if normalized.len() < 2 {
        return Err(invalid());
    }
    let bytes = normalized.as_bytes();
    let unit = bytes[bytes.len() - 1];
    let value = silo_gocompat::strings::trim_space(
        std::str::from_utf8(&bytes[..bytes.len() - 1]).unwrap_or("\u{fffd}"),
    );
    let amount = match go_atoi(value) {
        Some(a) if a > 0 => a,
        _ => return Err(invalid()),
    };
    if !matches!(unit, b'h' | b'd' | b'w' | b'm' | b'y') {
        // %q of a byte formats it as a quoted rune.
        let rune = char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}');
        return Err(format!("unsupported duration unit {}", go_quote_rune(rune)));
    }
    if amount > 100_000_000 || cutoff_before_postgres_min(amount, unit, now) {
        return Err(invalid());
    }
    Ok((amount, unit))
}

/// Go's `%q` of a rune.
fn go_quote_rune(r: char) -> String {
    let quoted = q(&r.to_string());
    let inner = &quoted[1..quoted.len() - 1];
    let inner = inner.replace("\\\"", "\"");
    let inner = if r == '\'' { "\\'".to_owned() } else { inner };
    format!("'{inner}'")
}

/// Days from 1970-01-01 to the proleptic Gregorian date (y, m, d), with month overflow allowed.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let total = y * 12 + (m - 1);
    let (y, m) = (total.div_euclid(12), total.rem_euclid(12) + 1);
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468 + (d - 1)
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `cutoffTime(now).Before(postgresMinTimestamp)`: 4714-11-24 BC is Go year -4713.
fn cutoff_before_postgres_min(amount: i64, unit: u8, now: i64) -> bool {
    let min = days_from_civil(-4713, 11, 24) * 86400;
    let day = now.div_euclid(86400);
    let secs = now.rem_euclid(86400);
    let (y, m, d) = civil_from_days(day);
    let cutoff = match unit {
        b'h' => now - amount * 3600,
        b'd' => (day - amount) * 86400 + secs,
        b'w' => (day - 7 * amount) * 86400 + secs,
        b'm' => days_from_civil(y, m - amount, d) * 86400 + secs,
        _ => days_from_civil(y - amount, m, d) * 86400 + secs,
    };
    cutoff < min
}
