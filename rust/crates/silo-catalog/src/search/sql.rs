//! Pure PostgreSQL search builders, preserving the Go query text and argument order.
use super::fuzzy::fuzzy_candidate_text;
use super::query::{
    ParsedSearchQuery, build_title_prefix_ts_query, collapse_search_whitespace,
    use_exact_short_title_search, use_leading_short_title_search,
};
use crate::model::join_item_columns;
use crate::query::access::{
    append_library_access_conditions, apply_maturity_limits, apply_section_access_filter,
    in_some_library_where, manga_chapter_exclusion_where,
};
use crate::query::episode_source::episode_catalog_base_relation;
use crate::query::{AccessFilter, Arg, lower_trim, sprintf};
use silo_gocompat::strings::trim_space;
pub const OVERVIEW_MATCH_FLOOR: f64 = 0.15;
pub const TITLE_RANK_NORMALIZATION: usize = 2;
const TITLE_PREFIX_QUERY: &str = "to_tsquery('simple', $2)";
const ORDER: &str = r#"%[1]sexact_title_match DESC, %[1]scontiguous_title_match DESC, %[1]syear_match DESC,
	%[1]sphrase_rank DESC, %[1]stitle_prefix_rank DESC, %[1]soverview_rank DESC,
	LOWER(%[1]stitle) ASC, %[1]scontent_id ASC"#;
const ALIAS_CTE: &str = r#"alias_scores AS MATERIALIZED (
		SELECT
			mia.content_id,
			MAX(CASE WHEN mia.normalized_title = $%[1]d THEN 1 ELSE 0 END) AS exact_title_match,
			MAX(%[2]s) AS contiguous_title_match,
			MAX(CASE WHEN $2 <> '' THEN %[3]s ELSE 0 END) AS title_prefix_rank,
			MIN(%[4]s) AS contiguous_title_words
		FROM media_item_aliases mia
		WHERE %[5]s
		GROUP BY mia.content_id
	)"#;
const BRANCH: &str = r#"
		SELECT %s
			%s AS content_id,
			%s AS type,
			%s AS title,
			CASE WHEN $%d <> '' AND (%s) THEN 1 ELSE 0 END AS exact_title_match,
			CASE WHEN $%d <> '' THEN %s ELSE 0 END AS contiguous_title_match,
			CASE WHEN $%d::int IS NOT NULL AND (%s) = $%d::int THEN 1 ELSE 0 END AS year_match,
			%s AS title_prefix_rank,
			(%s)::float8 AS overview_rank,
			(CASE WHEN $%d <> '' THEN %s ELSE 0 END)::float8 AS phrase_rank
		FROM %s
		WHERE %s"#;
const PAGE: &str = r#", page AS (
		SELECT scored.*%s
		%s
		ORDER BY %s
		LIMIT $%d%s
	)"#;
const HYDRATED: &str = r#"LATERAL (
		SELECT %s
		FROM media_items hydrated_mi
		WHERE page.type <> 'episode'
		  AND hydrated_mi.content_id = page.content_id
		UNION ALL
		SELECT %s
		FROM %s
		WHERE page.type = 'episode'
		  AND mi.content_id = page.content_id
	) hydrated"#;
const DATA: &str = r#"
		SELECT %s%s
		FROM page
		JOIN %s ON true
		ORDER BY %s"#;
const OVERVIEW: &str = r#"SELECT * FROM title_scored
		UNION ALL
		SELECT *
		FROM (
			%s
		) overview_scored
		WHERE NOT EXISTS (SELECT 1 FROM title_scored)
		  AND overview_scored.overview_rank >= %g"#;
const FUZZY_CTE: &str = r#"
		WITH alias_candidates AS MATERIALIZED (
			SELECT
				mia.content_id,
				MAX(
					0.65 * similarity($2, mia.normalized_title)
						+ 0.35 * strict_word_similarity($2, mia.normalized_title)
				) AS fuzzy_rank,
				MAX(similarity(public.normalize_search_text($1), mia.normalized_title)) AS fuzzy_full_rank
			FROM media_item_aliases mia
			WHERE $2 <<%% mia.normalized_title
			GROUP BY mia.content_id
		), candidates AS (
			SELECT
				mi.content_id,
				0.65 * similarity($2, mi.title_normalized)
					+ 0.35 * strict_word_similarity($2, mi.title_normalized) AS fuzzy_rank,
				similarity(public.normalize_search_text($1), mi.title_normalized) AS fuzzy_full_rank
			FROM media_items mi
			WHERE $2 <<%% mi.title_normalized
			UNION ALL
			SELECT content_id, fuzzy_rank, fuzzy_full_rank
			FROM alias_candidates
		), candidate_scores AS (
			SELECT content_id, MAX(fuzzy_rank) AS fuzzy_rank, MAX(fuzzy_full_rank) AS fuzzy_full_rank
			FROM candidates
			GROUP BY content_id
		), scored AS (
			SELECT
				%s,
				cs.fuzzy_rank,
				cs.fuzzy_full_rank
			FROM %s
			JOIN candidate_scores cs ON cs.content_id = mi.content_id
			%s
		)
	"#;
const FUZZY_DATA: &str = r#"
		SELECT %s%s
		FROM scored
		ORDER BY fuzzy_rank DESC, fuzzy_full_rank DESC, LOWER(title) ASC, content_id ASC
		LIMIT $%d OFFSET $%d"#;

pub fn append_listed_library_access_conditions(
    key: &str,
    filter: &AccessFilter,
    conditions: &mut Vec<String>,
    args: &mut Vec<Arg>,
    idx: &mut usize,
) {
    if filter.allowed.is_none() && filter.disabled.is_empty() {
        conditions.push(in_some_library_where(key));
        return;
    }
    append_library_access_conditions(key, filter, conditions, args, idx);
}
pub fn item_access_conditions(
    filter: &AccessFilter,
    args: &mut Vec<Arg>,
    idx: &mut usize,
) -> Vec<String> {
    let mut conditions = Vec::new();
    append_library_access_conditions("mi.content_id", filter, &mut conditions, args, idx);
    apply_section_access_filter("mi", filter, &mut conditions, args, idx);
    conditions
}
pub fn build_get_by_ids_with_access_sql(
    ids: &[String],
    filter: &AccessFilter,
) -> (String, Vec<Arg>) {
    let mut sql = format!(
        "SELECT {}\n            FROM media_items mi\n            WHERE mi.content_id = ANY($1)",
        join_item_columns("")
    );
    let mut args = vec![Arg::Strs(ids.to_vec())];
    let mut idx = 2;
    for condition in item_access_conditions(filter, &mut args, &mut idx) {
        sql.push_str(&format!("\n            AND {condition}"));
    }
    sql.push_str(" ORDER BY mi.content_id ASC");
    (sql, args)
}
pub fn build_count_visible_personal_collection_members_sql(
    user_id: i64,
    ids: &[String],
    filter: &AccessFilter,
) -> (String, Vec<Arg>) {
    let mut sql = "SELECT upci.collection_id, COUNT(*)\n            FROM user_personal_collection_items upci\n            JOIN media_items mi ON mi.content_id = upci.media_item_id\n            WHERE upci.user_id = $1 AND upci.collection_id = ANY($2) AND upci.sub_item_id = ''".to_owned();
    let mut args = vec![Arg::Int(user_id), Arg::Strs(ids.to_vec())];
    let mut idx = 3;
    for c in item_access_conditions(filter, &mut args, &mut idx) {
        sql.push_str(&format!("\n            AND {c}"));
    }
    sql.push_str(&format!(
        "\n            AND {}\n            GROUP BY upci.collection_id",
        manga_chapter_exclusion_where("mi")
    ));
    (sql, args)
}
pub fn search_text_from_parsed(parsed: &ParsedSearchQuery) -> String {
    if !parsed.text.is_empty() {
        return parsed.text.clone();
    }
    collapse_search_whitespace(&trim_space(&parsed.raw).replace('"', " "))
}
pub fn split_search_item_types(types: &[String]) -> (Vec<String>, bool) {
    if types.is_empty() {
        return (vec![], true);
    }
    let mut media = Vec::new();
    let mut episodes = false;
    for t in types {
        let t = lower_trim(t);
        if t.is_empty() {
            continue;
        }
        if t == "episode" {
            episodes = true;
            continue;
        }
        if !media.contains(&t) {
            media.push(t);
        }
    }
    (media, episodes)
}
pub fn append_search_scope_filters(
    types: &[String],
    filter: &AccessFilter,
    conditions: &mut Vec<String>,
    args: &mut Vec<Arg>,
    idx: &mut usize,
) -> String {
    let mut placeholders = vec![];
    for t in types {
        if trim_space(t).is_empty() {
            continue;
        }
        placeholders.push(format!("${idx}"));
        args.push(Arg::Str(lower_trim(t)));
        *idx += 1;
    }
    if !placeholders.is_empty() {
        conditions.push(format!("mi.type IN ({})", placeholders.join(", ")));
    }
    append_listed_library_access_conditions("mi.content_id", filter, conditions, args, idx);
    apply_section_access_filter("mi", filter, conditions, args, idx);
    conditions.push(manga_chapter_exclusion_where("mi"));
    "media_items mi".into()
}
#[allow(clippy::too_many_arguments)]
pub fn build_fuzzy_search_from_parsed(
    parsed: &ParsedSearchQuery,
    types: &[String],
    limit: i64,
    offset: i64,
    filter: &AccessFilter,
    total: bool,
    exclude: &[String],
    min_similarity: f64,
) -> (String, String, Vec<Arg>) {
    // Cursor definitions, seek predicates, and cursor key columns are intentionally unsupported.
    let text = search_text_from_parsed(parsed);
    if text.is_empty() {
        return (String::new(), String::new(), vec![]);
    }
    let mut args = vec![
        Arg::Str(text.clone()),
        Arg::Str(fuzzy_candidate_text(&text)),
    ];
    let mut idx = 3;
    let mut conditions = vec![];
    if min_similarity > 0.0 {
        conditions.push(format!("cs.fuzzy_full_rank >= ${idx}"));
        args.push(Arg::Value(serde_json::json!(min_similarity)));
        idx += 1;
    }
    let from = append_search_scope_filters(types, filter, &mut conditions, &mut args, &mut idx);
    if !exclude.is_empty() {
        conditions.push(format!("NOT (mi.content_id = ANY(${idx}))"));
        args.push(Arg::Strs(exclude.to_vec()));
        idx += 1;
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    let scored = sprintf(FUZZY_CTE, &[&join_item_columns("mi"), &from, &where_clause]);
    let total = if total {
        ", COUNT(*) OVER () AS total_count"
    } else {
        ""
    };
    let data = scored.clone()
        + &sprintf(
            FUZZY_DATA,
            &[&join_item_columns(""), &total, &idx, &(idx + 1)],
        );
    args.extend([Arg::Int(limit), Arg::Int(offset)]);
    (data, scored + "SELECT COUNT(*) FROM scored", args)
}
pub fn mixed_search_order(prefix: &str) -> String {
    sprintf(ORDER, &[&prefix])
}
pub fn title_rank_sql(vector: &str, query: &str) -> String {
    format!("ts_rank_cd({vector}, {query}, {TITLE_RANK_NORMALIZATION})")
}
pub fn year_suffixed_title_sql(title: &str, year: &str, idx: usize) -> String {
    format!("({year} > 0 AND {title} = ${idx} || ' ' || {year}::text)")
}
pub fn search_title_match_condition(vector: &str, extra: &[String]) -> String {
    let mut arms = vec![format!("($2 <> '' AND ({vector}) @@ {TITLE_PREFIX_QUERY})")];
    arms.extend_from_slice(extra);
    format!("({})", arms.join(" OR "))
}
pub fn search_overview_match_condition(vector: &str) -> String {
    format!("({vector}) @@ websearch_to_tsquery('english', $1)")
}
#[derive(Clone, Copy, Debug)]
pub struct SearchTitleLookup {
    pub exact_short: bool,
    pub leading_short: bool,
    pub exact_idx: usize,
    pub title_lookup_idx: usize,
}
impl SearchTitleLookup {
    pub fn condition(&self, title: &str, vector: &str) -> String {
        if self.exact_short {
            format!("{title} = ${}", self.exact_idx)
        } else if self.leading_short {
            format!("{title} LIKE ${} || '%'", self.title_lookup_idx)
        } else {
            search_title_match_condition(vector, &[])
        }
    }
}
pub fn mixed_search_alias_match_condition(lookup: SearchTitleLookup) -> String {
    lookup.condition(
        "mia.normalized_title",
        "to_tsvector('simple', mia.normalized_title)",
    )
}
pub fn title_position_sql(titles: &[&str], idx: usize) -> String {
    let leading = titles
        .iter()
        .map(|s| format!("{s} LIKE ${idx} || '%'"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let contiguous = titles
        .iter()
        .map(|s| format!("{s} LIKE '%' || ${idx} || '%'"))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!("CASE WHEN {leading} THEN 2 WHEN {contiguous} THEN 1 ELSE 0 END")
}
pub fn title_words_sql(titles: &[&str], idx: usize) -> String {
    let counts=titles.iter().map(|s|format!("CASE WHEN {s} LIKE '%' || ${idx} || '%' THEN array_length(string_to_array({s}, ' '), 1) END")).collect::<Vec<_>>().join(", ");
    format!("CASE WHEN ${idx} <> '' THEN LEAST({counts}) END")
}
pub fn title_prefix_rank_sql(words: &str, rank: &str) -> String {
    format!(
        "(CASE WHEN $2 <> '' THEN COALESCE((1.0 / (1 + {words}))::float8, {rank}) ELSE 0 END)::float8"
    )
}
pub fn build_mixed_search_alias_scores_cte(lookup: SearchTitleLookup) -> String {
    sprintf(
        ALIAS_CTE,
        &[
            &lookup.exact_idx,
            &title_position_sql(&["mia.normalized_title"], lookup.exact_idx),
            &title_rank_sql(
                "setweight(to_tsvector('simple', mia.normalized_title), 'A')",
                TITLE_PREFIX_QUERY,
            ),
            &title_words_sql(&["mia.normalized_title"], lookup.exact_idx),
            &mixed_search_alias_match_condition(lookup),
        ],
    )
}
pub struct MixedSearchAliasArms<'a> {
    pub exact_arm: &'a str,
    pub contiguous_rank: &'a str,
    pub prefix_rank: &'a str,
    pub contiguous_words: &'a str,
}
#[allow(clippy::too_many_arguments)]
pub fn build_mixed_search_candidate_branch(
    id: &str,
    kind: &str,
    title: &str,
    year: &str,
    title_vector: &str,
    overview_vector: &str,
    exact_titles: &[&str],
    year_title: &str,
    from: &str,
    conditions: &[String],
    exact_idx: usize,
    year_idx: usize,
    phrase_idx: usize,
    aliases: Option<&MixedSearchAliasArms<'_>>,
    overview: bool,
    distinct: bool,
) -> String {
    let mut exact = exact_titles
        .iter()
        .map(|s| format!("{s} = ${exact_idx}"))
        .collect::<Vec<_>>();
    if !year_title.is_empty() {
        exact.push(year_suffixed_title_sql(year_title, year, exact_idx));
    }
    let mut position = title_position_sql(exact_titles, exact_idx);
    let mut words = title_words_sql(exact_titles, exact_idx);
    let mut rank = title_rank_sql(title_vector, TITLE_PREFIX_QUERY);
    if let Some(a) = aliases {
        exact.push(a.exact_arm.into());
        position = format!("GREATEST({position}, {})", a.contiguous_rank);
        words = format!("LEAST({words}, {})", a.contiguous_words);
        rank = format!("GREATEST({rank}, {})", a.prefix_rank);
    }
    let overview_rank = if overview {
        format!("ts_rank_cd({overview_vector}, websearch_to_tsquery('english', $1))")
    } else {
        "0::real".into()
    };
    sprintf(
        BRANCH,
        &[
            &if distinct { "DISTINCT " } else { "" },
            &id,
            &kind,
            &title,
            &exact_idx,
            &exact.join(" OR "),
            &exact_idx,
            &position,
            &year_idx,
            &year,
            &year_idx,
            &title_prefix_rank_sql(&words, &rank),
            &overview_rank,
            &phrase_idx,
            &title_rank_sql(
                title_vector,
                &format!("phraseto_tsquery('simple', public.normalize_search_text(${phrase_idx}))"),
            ),
            &from,
            &conditions.join(" AND "),
        ],
    )
}
#[derive(Clone, Debug)]
pub struct EpisodeSearchSource {
    pub match_condition: String,
    pub overview: bool,
    pub libraries: Vec<String>,
    pub policy: Vec<String>,
    pub fenced: bool,
    pub distinct: bool,
}
impl EpisodeSearchSource {
    pub fn relation(&self) -> String {
        if !self.fenced {
            return "episode_catalog_entries ece JOIN media_items si ON si.content_id = ece.series_id".into();
        }
        let mut columns="ece.episode_id, ece.series_id, ece.media_folder_id, ece.title, ece.year,\n\t\t       ece.search_title_normalized, ece.search_title_vector".to_owned();
        if self.overview {
            columns.push_str(", ece.search_overview_vector");
        }
        columns.push_str(", ece.content_rating_age, ece.advisory_age");
        let mut admission = vec![self.match_condition.clone()];
        admission.extend_from_slice(&self.libraries);
        format!(
            "(\n\t\tSELECT {columns}, si.content_id AS search_series_parent_id\n\t\tFROM (\n\t\tSELECT {columns}\n\t\tFROM episode_catalog_entries ece WHERE {} OFFSET 0\n\t\t) ece LEFT JOIN media_items si ON si.content_id = ece.series_id AND si.type = 'series'\n\t\tOFFSET 0\n\t) ece",
            admission.join(" AND ")
        )
    }
    pub fn conditions(&self) -> Vec<String> {
        let mut c = if self.fenced {
            vec!["ece.search_series_parent_id IS NOT NULL".into()]
        } else {
            let mut c = vec![self.match_condition.clone(), "si.type = 'series'".into()];
            c.extend_from_slice(&self.libraries);
            c
        };
        c.extend_from_slice(&self.policy);
        c
    }
    pub fn branch(&self, exact: usize, year: usize, phrase: usize) -> String {
        build_mixed_search_candidate_branch(
            "ece.episode_id",
            "'episode'::text",
            "ece.title",
            "ece.year",
            "ece.search_title_vector",
            "ece.search_overview_vector",
            &["ece.search_title_normalized"],
            "",
            &self.relation(),
            &self.conditions(),
            exact,
            year,
            phrase,
            None,
            self.overview,
            self.distinct,
        )
    }
    fn candidates(&self) -> String {
        format!(
            "SELECT {}ece.episode_id AS content_id FROM {} WHERE {}",
            if self.distinct { "DISTINCT " } else { "" },
            self.relation(),
            self.conditions().join(" AND ")
        )
    }
}
pub fn append_episode_catalog_search_access(
    alias: &str,
    filter: &AccessFilter,
    libraries: &mut Vec<String>,
    policy: &mut Vec<String>,
    args: &mut Vec<Arg>,
    idx: &mut usize,
) {
    if let Some(ids) = &filter.allowed {
        libraries.push(format!("{alias}.media_folder_id = ANY(${idx})"));
        args.push(Arg::Ints(ids.iter().map(|v| i64::from(*v)).collect()));
        *idx += 1;
    }
    if !filter.disabled.is_empty() {
        policy.push(format!("NOT EXISTS (SELECT 1 FROM episode_catalog_entries disabled_ece WHERE disabled_ece.episode_id = {alias}.episode_id AND disabled_ece.media_folder_id = ANY(${idx}))"));
        args.push(Arg::Ints(
            filter.disabled.iter().map(|v| i64::from(*v)).collect(),
        ));
        *idx += 1;
    }
    append_library_access_conditions(&format!("{alias}.series_id"), filter, policy, args, idx);
}
pub fn append_episode_library_search_access(
    episode: &str,
    series: &str,
    filter: &AccessFilter,
    conditions: &mut Vec<String>,
    args: &mut Vec<Arg>,
    idx: &mut usize,
) {
    if let Some(ids) = &filter.allowed {
        conditions.push(format!("EXISTS (SELECT 1 FROM episode_libraries allowed_el WHERE allowed_el.episode_id = {episode} AND allowed_el.media_folder_id = ANY(${idx}))"));
        args.push(Arg::Ints(ids.iter().map(|v| i64::from(*v)).collect()));
        *idx += 1;
    }
    if !filter.disabled.is_empty() {
        conditions.push(format!("NOT EXISTS (SELECT 1 FROM episode_libraries disabled_el WHERE disabled_el.episode_id = {episode} AND disabled_el.media_folder_id = ANY(${idx}))"));
        args.push(Arg::Ints(
            filter.disabled.iter().map(|v| i64::from(*v)).collect(),
        ));
        *idx += 1;
    }
    append_library_access_conditions(series, filter, conditions, args, idx);
}
#[allow(clippy::too_many_arguments)]
pub fn build_mixed_search_count_sql(
    media_title: &[String],
    media_overview: &[String],
    include_media: bool,
    episode_title: Option<&EpisodeSearchSource>,
    episode_overview: Option<&EpisodeSearchSource>,
    lookup: SearchTitleLookup,
    year: usize,
    phrase: usize,
) -> String {
    let mut ctes = vec![format!(
        "search_parameters AS (SELECT $1::text, $2::text, ${}::text, ${year}::int, ${phrase}::text)",
        lookup.exact_idx
    )];
    if include_media {
        ctes.push(format!("alias_scores AS MATERIALIZED (\n\t\t\tSELECT DISTINCT mia.content_id FROM media_item_aliases mia\n\t\t\tWHERE {})",mixed_search_alias_match_condition(lookup)));
    }
    let mut titles = vec![];
    let mut overviews = vec![];
    if include_media {
        titles.push(format!(
            "SELECT mi.content_id FROM media_items mi WHERE {}",
            media_title.join(" AND ")
        ));
        if !media_overview.is_empty() {
            overviews.push(format!("SELECT mi.content_id FROM media_items mi WHERE {} AND ts_rank_cd(mi.search_overview_vector, websearch_to_tsquery('english', $1)) >= {OVERVIEW_MATCH_FLOOR}",media_overview.join(" AND ")));
        }
    }
    if let Some(s) = episode_title {
        titles.push(s.candidates());
    }
    if let Some(s) = episode_overview {
        overviews.push(s.candidates()+&format!(" AND ts_rank_cd(ece.search_overview_vector, websearch_to_tsquery('english', $1)) >= {OVERVIEW_MATCH_FLOOR}"));
    }
    ctes.push(format!(
        "title_candidates AS MATERIALIZED ({})",
        titles.join(" UNION ALL ")
    ));
    if overviews.is_empty() {
        return format!(
            "WITH {} SELECT COUNT(*) FROM title_candidates",
            ctes.join(",\n")
        );
    }
    ctes.push(format!("candidates AS (\n\t\tSELECT content_id FROM title_candidates\n\t\tUNION ALL\n\t\tSELECT content_id FROM ({}) overview_candidates\n\t\tWHERE NOT EXISTS (SELECT 1 FROM title_candidates)\n\t)",overviews.join(" UNION ALL ")));
    format!("WITH {} SELECT COUNT(*) FROM candidates", ctes.join(",\n"))
}
pub fn build_mixed_search_sql_from_parsed(
    parsed: &ParsedSearchQuery,
    types: &[String],
    limit: i64,
    offset: i64,
    filter: &AccessFilter,
    total: bool,
) -> (String, String, Vec<Arg>) {
    // Cursor definitions, seek predicates, grouping, and cursor keys are intentionally omitted.
    let text = search_text_from_parsed(parsed);
    if text.is_empty() {
        return (String::new(), String::new(), vec![]);
    }
    let (media_types, episodes) = split_search_item_types(types);
    let media = types.is_empty() || !media_types.is_empty();
    if !media && !episodes {
        return (String::new(), String::new(), vec![]);
    }
    let mut args = vec![
        Arg::Str(text.clone()),
        Arg::Str(build_title_prefix_ts_query(&text)),
    ];
    let mut idx = 3;
    let mut lookup = SearchTitleLookup {
        exact_short: use_exact_short_title_search(parsed),
        leading_short: use_leading_short_title_search(parsed),
        exact_idx: 0,
        title_lookup_idx: 0,
    };
    let narrow = lookup.exact_short || lookup.leading_short;
    let mut media_conditions = vec![];
    if media {
        if !types.is_empty() {
            media_conditions.push(format!("mi.type = ANY(${idx})"));
            args.push(Arg::Strs(media_types));
            idx += 1;
        }
        let mut libraries = vec![];
        append_listed_library_access_conditions(
            "mi.content_id",
            filter,
            &mut libraries,
            &mut args,
            &mut idx,
        );
        if !libraries.is_empty() {
            media_conditions.push(format!(
                "COALESCE((SELECT {} OFFSET 0), FALSE)",
                libraries.join(" AND ")
            ));
        }
        apply_section_access_filter("mi", filter, &mut media_conditions, &mut args, &mut idx);
        media_conditions.push(manga_chapter_exclusion_where("mi"));
    }
    let mut episode_libraries = vec![];
    let mut episode_policy = vec![];
    if episodes {
        append_episode_catalog_search_access(
            "ece",
            filter,
            &mut episode_libraries,
            &mut episode_policy,
            &mut args,
            &mut idx,
        );
        apply_maturity_limits("ece", filter, &mut episode_policy, &mut args, &mut idx);
        if !filter.excluded_media_types.is_empty() {
            episode_policy.push(format!("NOT ('episode' = ANY(${idx}))"));
            args.push(Arg::Strs(filter.excluded_media_types.clone()));
            idx += 1;
        }
    }
    let exact = idx;
    args.push(Arg::Str(parsed.exact_title_hint.clone()));
    idx += 1;
    lookup.exact_idx = exact;
    lookup.title_lookup_idx = exact;
    if lookup.leading_short {
        lookup.title_lookup_idx = idx;
        args.push(Arg::Str(parsed.normalized_text.clone()));
        idx += 1;
    }
    let year = idx;
    args.push(
        parsed
            .year
            .map(Arg::Int)
            .unwrap_or(Arg::Value(serde_json::Value::Null)),
    );
    idx += 1;
    let phrase = idx;
    args.push(Arg::Str(parsed.phrase.clone()));
    idx += 1;
    let mut media_title = vec![];
    let mut media_overview = vec![];
    if media {
        let mut title_match =
            lookup.condition("title_mi.title_normalized", "title_mi.search_title_vector");
        if lookup.exact_short {
            title_match = format!(
                "({title_match} OR (title_mi.title_normalized LIKE ${exact} || ' %' AND {}))",
                year_suffixed_title_sql("title_mi.title_normalized", "title_mi.year", exact)
            );
        }
        media_title.push(format!("mi.content_id IN (SELECT title_mi.content_id FROM media_items title_mi WHERE {title_match} UNION SELECT alias_scores.content_id FROM alias_scores)"));
        media_title.extend_from_slice(&media_conditions);
        if !narrow {
            media_overview.push(search_overview_match_condition("mi.search_overview_vector"));
            media_overview.extend_from_slice(&media_conditions);
        }
    }
    let episode_title = episodes.then(|| EpisodeSearchSource {
        match_condition: lookup.condition("ece.search_title_normalized", "ece.search_title_vector"),
        libraries: episode_libraries,
        policy: episode_policy,
        fenced: filter.allowed.is_some() || !filter.disabled.is_empty(),
        distinct: filter.allowed.as_ref().map_or(0, Vec::len) != 1,
        overview: false,
    });
    let episode_overview = episode_title.as_ref().filter(|_| !narrow).map(|s| {
        let mut s = s.clone();
        s.match_condition = search_overview_match_condition("ece.search_overview_vector");
        s.overview = true;
        s
    });
    let mut titles = vec![];
    let mut overviews = vec![];
    if media {
        let alias = MixedSearchAliasArms {
            exact_arm: "COALESCE(search_alias.exact_title_match, 0) > 0",
            contiguous_rank: "COALESCE(search_alias.contiguous_title_match, 0)",
            prefix_rank: "COALESCE(search_alias.title_prefix_rank, 0)",
            contiguous_words: "search_alias.contiguous_title_words",
        };
        let exact_titles = [
            "mi.title_normalized",
            "mi.original_title_normalized",
            "mi.sort_title_normalized",
        ];
        titles.push(build_mixed_search_candidate_branch("mi.content_id","mi.type","mi.title","mi.year","mi.search_title_vector","mi.search_overview_vector",&exact_titles,"mi.title_normalized","media_items mi LEFT JOIN alias_scores search_alias ON search_alias.content_id = mi.content_id",&media_title,exact,year,phrase,Some(&alias),false,false));
        if !narrow {
            overviews.push(build_mixed_search_candidate_branch(
                "mi.content_id",
                "mi.type",
                "mi.title",
                "mi.year",
                "mi.search_title_vector",
                "mi.search_overview_vector",
                &exact_titles,
                "mi.title_normalized",
                "media_items mi",
                &media_overview,
                exact,
                year,
                phrase,
                None,
                true,
                false,
            ));
        }
    }
    if let Some(s) = &episode_title {
        titles.push(s.branch(exact, year, phrase));
    }
    if let Some(s) = &episode_overview {
        overviews.push(s.branch(exact, year, phrase));
    }
    let mut inner = vec![];
    if media {
        inner.push(build_mixed_search_alias_scores_cte(lookup));
    }
    let title_body = titles.join("\nUNION ALL\n");
    let mut body = if !overviews.is_empty() {
        inner.push(format!("title_scored AS MATERIALIZED (\n{title_body}\n)"));
        sprintf(
            OVERVIEW,
            &[&overviews.join("\nUNION ALL\n"), &OVERVIEW_MATCH_FLOOR],
        )
    } else {
        title_body
    };
    if !inner.is_empty() {
        body = format!("WITH {}\n{body}", inner.join(",\n"));
    }
    let scored = format!("WITH scored AS (\n{body}\n)");
    let post = if narrow {
        "FROM scored WHERE $1::text IS NOT NULL"
    } else {
        "FROM scored"
    };
    let page_total = if total {
        ", COUNT(*) OVER () AS total_count"
    } else {
        ""
    };
    let final_total = if total { ", page.total_count" } else { "" };
    let page = sprintf(
        PAGE,
        &[
            &page_total,
            &post,
            &mixed_search_order(""),
            &idx,
            &format!(" OFFSET ${}", idx + 1),
        ],
    );
    args.extend([Arg::Int(limit), Arg::Int(offset)]);
    let hydrated = sprintf(
        HYDRATED,
        &[
            &join_item_columns("hydrated_mi"),
            &join_item_columns("mi"),
            &episode_catalog_base_relation(),
        ],
    );
    let data = scored
        + &page
        + &sprintf(
            DATA,
            &[
                &join_item_columns("hydrated"),
                &final_total,
                &hydrated,
                &mixed_search_order("page."),
            ],
        );
    let count = build_mixed_search_count_sql(
        &media_title,
        &media_overview,
        media,
        episode_title.as_ref(),
        episode_overview.as_ref(),
        lookup,
        year,
        phrase,
    );
    (data, count, args)
}

/// Build `GetSearchItemsByIDsWithAccess` without executing it. Empty IDs or an
/// explicitly empty library allowlist need no query, matching the Go early return.
pub fn build_get_search_items_by_ids_with_access_sql(
    content_ids: &[String],
    filter: &AccessFilter,
) -> (String, Vec<Arg>) {
    if content_ids.is_empty() || filter.allowed.as_ref().is_some_and(Vec::is_empty) {
        return (String::new(), Vec::new());
    }

    let mut args = vec![Arg::Strs(content_ids.to_vec())];
    let mut arg_idx = 2;
    let mut media_conditions = vec!["hydrated_mi.content_id = ANY($1)".to_owned()];
    append_listed_library_access_conditions(
        "hydrated_mi.content_id",
        filter,
        &mut media_conditions,
        &mut args,
        &mut arg_idx,
    );
    crate::query::access::apply_section_access_filter(
        "hydrated_mi",
        filter,
        &mut media_conditions,
        &mut args,
        &mut arg_idx,
    );

    let mut episode_conditions = vec!["mi.content_id = ANY($1)".to_owned()];
    append_episode_library_search_access(
        "mi.content_id",
        &crate::query::access::episode_parent_series_id_expr("mi.content_id"),
        filter,
        &mut episode_conditions,
        &mut args,
        &mut arg_idx,
    );
    crate::query::access::apply_section_access_filter(
        "mi",
        filter,
        &mut episode_conditions,
        &mut args,
        &mut arg_idx,
    );

    let query = format!(
        "\n\t\tSELECT {}\n\t\tFROM media_items hydrated_mi\n\t\tWHERE {}\n\t\tUNION ALL\n\t\tSELECT {}\n\t\tFROM {}\n\t\tWHERE {}",
        crate::model::qualified_item_columns("hydrated_mi"),
        media_conditions.join(" AND "),
        crate::model::qualified_item_columns("mi"),
        crate::query::episode_source::episode_catalog_base_relation(),
        episode_conditions.join(" AND "),
    );
    (query, args)
}
