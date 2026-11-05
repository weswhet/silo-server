//! The SQL half of `access_filter.go` the query engine uses, over `silo_store`'s `AccessFilter`.

pub use silo_store::catalog::access::AccessFilter;
use silo_store::rating::{age_for_ceiling, has_ceiling};

use super::Arg;

fn ints(ids: &[i32]) -> Vec<i64> {
    ids.iter().map(|id| i64::from(*id)).collect()
}

/// `AccessFilter.LibraryScope`: the libraries a read may touch, and whether none survived.
pub fn library_scope(filter: &AccessFilter, requested: &[i64]) -> (Option<Vec<i64>>, bool) {
    let requested: Vec<i64> = if requested.is_empty() {
        match &filter.allowed {
            None => return (None, false),
            Some(allowed) => ints(allowed),
        }
    } else if let Some(allowed) = &filter.allowed {
        intersect_ints(requested, &ints(allowed))
    } else {
        requested.to_vec()
    };
    let disabled = ints(&filter.disabled);
    let ids: Vec<i64> = requested
        .into_iter()
        .filter(|id| !disabled.contains(id))
        .collect();
    if ids.is_empty() {
        return (None, true);
    }
    (Some(ids), false)
}

/// `intersectInts`: a's values that b holds, deduplicated, in a's order.
pub fn intersect_ints(a: &[i64], b: &[i64]) -> Vec<i64> {
    let mut out: Vec<i64> = Vec::new();
    if a.is_empty() || b.is_empty() {
        return out;
    }
    for v in a {
        if b.contains(v) && !out.contains(v) {
            out.push(*v);
        }
    }
    out
}

/// `ApplySectionAccessFilter` (`applyAccessFilter`): the maturity limits, then the excluded types.
pub fn apply_section_access_filter(
    alias: &str,
    filter: &AccessFilter,
    conditions: &mut Vec<String>,
    args: &mut Vec<Arg>,
    arg_idx: &mut usize,
) {
    apply_maturity_limits(alias, filter, conditions, args, arg_idx);
    if !filter.excluded_media_types.is_empty() {
        conditions.push(format!("NOT ({alias}.type = ANY(${}))", *arg_idx));
        args.push(Arg::Strs(filter.excluded_media_types.clone()));
        *arg_idx += 1;
    }
}

/// `ApplyMaturityLimits`. Both ages bind as a Go `int`; `Arg::Int` encodes into `smallint`.
pub fn apply_maturity_limits(
    alias: &str,
    filter: &AccessFilter,
    conditions: &mut Vec<String>,
    args: &mut Vec<Arg>,
    arg_idx: &mut usize,
) {
    if has_ceiling(&filter.max_content_rating) {
        let Some(age) = age_for_ceiling(&filter.max_content_rating) else {
            conditions.push("1 = 0".into());
            return;
        };
        let column = format!("{alias}.content_rating_age");
        let at = *arg_idx;
        conditions.push(if filter.allow_unrated_content {
            format!("({column} IS NULL OR {column} <= ${at})")
        } else {
            format!("({column} IS NOT NULL AND {column} <= ${at})")
        });
        args.push(Arg::Int(i64::from(age)));
        *arg_idx += 1;
    }
    if filter.max_advisory_age > 0 {
        let column = format!("{alias}.advisory_age");
        let at = *arg_idx;
        conditions.push(if filter.require_advisory_age {
            format!("({column} IS NOT NULL AND {column} <= ${at})")
        } else {
            format!("({column} IS NULL OR {column} <= ${at})")
        });
        args.push(Arg::Int(i64::from(filter.max_advisory_age)));
        *arg_idx += 1;
    }
}

/// `libraryAccessConditions`.
pub fn library_access_conditions(key: &str, allowed: usize, disabled: usize) -> Vec<String> {
    let mut out = Vec::new();
    if allowed > 0 {
        out.push(format!("EXISTS (SELECT 1 FROM media_item_libraries mil WHERE mil.content_id = {key} AND mil.media_folder_id = ANY(${allowed}))"));
    }
    if disabled > 0 {
        if allowed == 0 {
            out.push(format!(
                "EXISTS (SELECT 1 FROM media_item_libraries mil WHERE mil.content_id = {key})"
            ));
        }
        out.push(format!("NOT EXISTS (SELECT 1 FROM media_item_libraries mil WHERE mil.content_id = {key} AND mil.media_folder_id = ANY(${disabled}))"));
    }
    out
}

/// A library allowlist in the episode relation's `AccessFilter`: the resolved scope as `i32`s.
pub(crate) fn filter_ids(ids: &[i64]) -> Vec<i32> {
    ids.iter().map(|id| *id as i32).collect()
}

/// `appendLibraryAccessConditions`. The ID lists bind as a Go `[]int`.
pub fn append_library_access_conditions(
    key: &str,
    filter: &AccessFilter,
    conditions: &mut Vec<String>,
    args: &mut Vec<Arg>,
    arg_idx: &mut usize,
) {
    let (mut allowed_at, mut disabled_at) = (0, 0);
    if let Some(allowed) = &filter.allowed {
        args.push(Arg::Ints(ints(allowed)));
        allowed_at = *arg_idx;
        *arg_idx += 1;
    }
    if !filter.disabled.is_empty() {
        args.push(Arg::Ints(ints(&filter.disabled)));
        disabled_at = *arg_idx;
        *arg_idx += 1;
    }
    conditions.extend(library_access_conditions(key, allowed_at, disabled_at));
}

/// `InSomeLibraryWhere`.
pub fn in_some_library_where(content_id_expr: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM media_item_libraries in_library WHERE in_library.content_id = {content_id_expr})"
    )
}

/// `episodeParentSeriesIDExpr`.
pub fn episode_parent_series_id_expr(episode_id_expr: &str) -> String {
    format!(
        "(SELECT e_parent.series_id FROM episodes e_parent WHERE e_parent.content_id = {episode_id_expr})"
    )
}

/// `appendEpisodeParentLibraryAccessByEpisodeID`.
pub fn append_episode_parent_library_access_by_episode_id(
    episode_id_expr: &str,
    filter: &AccessFilter,
    conditions: &mut Vec<String>,
    args: &mut Vec<Arg>,
    arg_idx: &mut usize,
) {
    append_library_access_conditions(
        &episode_parent_series_id_expr(episode_id_expr),
        filter,
        conditions,
        args,
        arg_idx,
    );
}

/// `MangaChapterExclusionWhere`.
pub fn manga_chapter_exclusion_where(alias: &str) -> String {
    format!(
        "NOT EXISTS (SELECT 1 FROM manga_chapters mc WHERE mc.chapter_content_id = {alias}.content_id)"
    )
}

/// `mangaCountColumns`.
pub fn manga_count_columns(a: &str) -> String {
    format!(
        "CASE WHEN {a}.type = 'manga' THEN (SELECT count(*) FROM manga_chapters mc WHERE mc.series_content_id = {a}.content_id AND (mc.volume IS NULL OR mc.volume = '')) END AS manga_chapter_count, CASE WHEN {a}.type = 'manga' THEN (SELECT count(DISTINCT mc.volume) FROM manga_chapters mc WHERE mc.series_content_id = {a}.content_id AND mc.volume IS NOT NULL AND mc.volume <> '') END AS manga_volume_count"
    )
}
