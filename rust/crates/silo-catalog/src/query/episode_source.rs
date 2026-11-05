//! `episode_catalog_source.go` and `air_date_sql.go`: the episode relation the "episode" media scope
//! reads, and the scope-dependent column expressions.

use super::access::{AccessFilter, append_library_access_conditions, filter_ids};
use super::definition::LATEST_AVAILABLE_AIR_DATE_COLUMN;
use super::templates as t;
use super::{Arg, sprintf};

/// `isEpisodeCatalogScope`.
pub fn is_episode_catalog_scope(scope: &str) -> bool {
    scope == "episode"
}

/// `mediaItemsBaseRelation`.
pub const MEDIA_ITEMS_BASE_RELATION: &str = "media_items mi";

/// `episodeCatalogSeriesParentGuard`.
pub const EPISODE_CATALOG_SERIES_PARENT_GUARD: &str = t::EPISODE_CATALOG_SERIES_PARENT_GUARD;

/// `episodeCatalogBaseRelation`.
pub fn episode_catalog_base_relation() -> String {
    sprintf(
        t::EPISODE_CATALOG_SELECT_BODY,
        &[&t::EPISODE_CATALOG_ACTIVE_LIBRARY_EXISTS],
    )
}

/// `catalogBaseRelationForScope`.
pub fn catalog_base_relation_for_scope(scope: &str) -> String {
    if is_episode_catalog_scope(scope) {
        return episode_catalog_base_relation();
    }
    MEDIA_ITEMS_BASE_RELATION.into()
}

/// `episodeCatalogBaseRelationForLibraries`. `allowed` is the resolved library scope.
pub fn episode_catalog_base_relation_for_libraries(
    allowed: &[i64],
    disabled: &[i64],
    mut arg_idx: usize,
) -> (String, Vec<Arg>, bool) {
    if allowed.is_empty() && disabled.is_empty() {
        return (episode_catalog_base_relation(), Vec::new(), false);
    }
    let mut predicates = Vec::new();
    let mut args = Vec::new();
    if !allowed.is_empty() {
        predicates.push(sprintf(t::EPISODE_SCOPE_IN, &[&arg_idx]));
        args.push(Arg::Ints(allowed.to_vec()));
        arg_idx += 1;
    } else if !disabled.is_empty() {
        predicates.push(t::EPISODE_CATALOG_ACTIVE_LIBRARY_EXISTS.to_owned());
    }
    if !disabled.is_empty() {
        predicates.push(sprintf(t::EPISODE_SCOPE_OUT, &[&arg_idx]));
        args.push(Arg::Ints(disabled.to_vec()));
        arg_idx += 1;
    }
    let parent = AccessFilter {
        allowed: (!allowed.is_empty()).then(|| filter_ids(allowed)),
        disabled: filter_ids(disabled),
        ..AccessFilter::default()
    };
    append_library_access_conditions(
        "e.series_id",
        &parent,
        &mut predicates,
        &mut args,
        &mut arg_idx,
    );
    let relation = sprintf(
        t::EPISODE_CATALOG_SELECT_BODY,
        &[&predicates.join("\n\tAND ")],
    );
    (relation, args, true)
}

/// `catalogLibraryContentExprForScope`.
pub fn catalog_library_content_expr_for_scope(_scope: &str, alias: &str) -> String {
    format!("{alias}.content_id")
}

/// `catalogLibraryMembershipTableAndKeyForScope`.
pub fn catalog_library_membership_table_and_key_for_scope(
    scope: &str,
) -> (&'static str, &'static str) {
    if is_episode_catalog_scope(scope) {
        ("episode_libraries", "episode_id")
    } else {
        ("media_item_libraries", "content_id")
    }
}

/// `catalogMediaFileJoinConditionForScope`.
pub fn catalog_media_file_join_condition_for_scope(scope: &str, mf: &str, item: &str) -> String {
    if is_episode_catalog_scope(scope) {
        format!("{mf}.episode_id = {item}.content_id")
    } else {
        format!("{mf}.content_id = {item}.content_id")
    }
}

/// `catalogMediaFileGroupExprForScope`.
pub fn catalog_media_file_group_expr_for_scope(scope: &str, mf: &str) -> String {
    if is_episode_catalog_scope(scope) {
        format!("{mf}.episode_id")
    } else {
        format!("{mf}.content_id")
    }
}

/// `effectiveLastAirDateExpr`.
pub fn effective_last_air_date_expr(a: &str) -> String {
    format!(
        "(CASE WHEN {a}.type = 'series' THEN COALESCE({a}.last_air_date_at::text, NULLIF(BTRIM({a}.first_air_date), '')) ELSE NULLIF(BTRIM({a}.first_air_date), '') END)"
    )
}

/// `latestAvailableAirDateSortExpr`.
pub fn latest_available_air_date_sort_expr(a: &str) -> String {
    format!(
        "(CASE WHEN {a}.type = 'series' THEN {a}.{LATEST_AVAILABLE_AIR_DATE_COLUMN}::text ELSE NULLIF(BTRIM({a}.first_air_date), '') END)"
    )
}
