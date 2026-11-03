//! `internal/catalog/access_filter.go`, with `EnsureAccessible` and `FilterAccessibleContentIDs`: the
//! per-viewer library and maturity predicates, as Go writes them.

use std::collections::{HashMap, HashSet};

use silo_pg::Pool;
use silo_pg::ToSql;

use crate::access::Scope;
use crate::rating::{age_for_ceiling, has_ceiling};

/// `catalog.AccessFilter`, the fields these reads use. `allowed` is nil when unrestricted.
#[derive(Clone, Debug, Default)]
pub struct AccessFilter {
    pub allowed: Option<Vec<i32>>,
    pub disabled: Vec<i32>,
    pub max_content_rating: String,
    pub allow_unrated_content: bool,
    pub max_advisory_age: i32,
    pub require_advisory_age: bool,
}

/// The positional arguments and SQL conditions the filter adds, numbered after `first`.
struct Bound<'a> {
    args: Vec<&'a (dyn ToSql + Sync)>,
    allowed_at: usize,
    disabled_at: usize,
    maturity: Vec<String>,
}

impl AccessFilter {
    /// `accessFilterFromScope`. Without a scope nothing is restricted.
    pub fn of(scope: Option<&Scope>) -> Self {
        let Some(scope) = scope else {
            return Self::default();
        };
        let ints = |ids: &[i64]| ids.iter().map(|id| *id as i32).collect::<Vec<i32>>();
        Self {
            allowed: scope
                .libraries_restricted
                .then(|| ints(&scope.allowed_library_ids)),
            disabled: ints(&scope.disabled_library_ids),
            max_content_rating: scope.maturity_limits.max_content_rating.clone(),
            allow_unrated_content: scope.maturity_limits.allow_unrated_content,
            max_advisory_age: scope.maturity_limits.max_advisory_age,
            require_advisory_age: scope.maturity_limits.require_advisory_age,
        }
    }

    /// `filterProgress`'s condition for running the access filter at all.
    pub fn restricted(&self) -> bool {
        self.allowed.is_some()
            || !self.disabled.is_empty()
            || has_ceiling(&self.max_content_rating)
            || self.max_advisory_age > 0
    }

    fn nothing_allowed(&self) -> bool {
        self.allowed.as_ref().is_some_and(Vec::is_empty)
    }

    /// `appendLibraryAccessConditions` and `ApplyMaturityLimits` for alias `mi`. `ceiling` holds the
    /// resolved age the arguments borrow.
    fn bind<'a>(&'a self, first: usize, ceiling: &'a mut Option<i32>) -> Bound<'a> {
        let mut args: Vec<&'a (dyn ToSql + Sync)> = Vec::new();
        let mut next = first;
        let mut allowed_at = 0;
        let mut disabled_at = 0;
        if let Some(ids) = &self.allowed {
            args.push(ids);
            allowed_at = next;
            next += 1;
        }
        if !self.disabled.is_empty() {
            args.push(&self.disabled);
            disabled_at = next;
            next += 1;
        }
        let mut maturity = Vec::new();
        if has_ceiling(&self.max_content_rating) {
            *ceiling = age_for_ceiling(&self.max_content_rating);
            if ceiling.is_none() {
                maturity.push("1 = 0".to_owned());
                return Bound {
                    args,
                    allowed_at,
                    disabled_at,
                    maturity,
                };
            }
            maturity.push(if self.allow_unrated_content {
                format!("(mi.content_rating_age IS NULL OR mi.content_rating_age <= ${next})")
            } else {
                format!("(mi.content_rating_age IS NOT NULL AND mi.content_rating_age <= ${next})")
            });
            next += 1;
        }
        let ceiling: &'a Option<i32> = ceiling;
        if let Some(age) = ceiling {
            args.push(age);
        }
        if self.max_advisory_age > 0 {
            maturity.push(if self.require_advisory_age {
                format!("(mi.advisory_age IS NOT NULL AND mi.advisory_age <= ${next})")
            } else {
                format!("(mi.advisory_age IS NULL OR mi.advisory_age <= ${next})")
            });
            args.push(&self.max_advisory_age);
        }
        Bound {
            args,
            allowed_at,
            disabled_at,
            maturity,
        }
    }
}

/// `libraryAccessConditions`. A position of 0 means that restriction is not active.
fn library_conditions(key: &str, allowed: usize, disabled: usize) -> Vec<String> {
    let mut conditions = Vec::new();
    if allowed > 0 {
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM media_item_libraries mil WHERE mil.content_id = {key} AND mil.media_folder_id = ANY(${allowed}))"
        ));
    }
    if disabled > 0 {
        if allowed == 0 {
            conditions.push(format!(
                "EXISTS (SELECT 1 FROM media_item_libraries mil WHERE mil.content_id = {key})"
            ));
        }
        conditions.push(format!(
            "NOT EXISTS (SELECT 1 FROM media_item_libraries mil WHERE mil.content_id = {key} AND mil.media_folder_id = ANY(${disabled}))"
        ));
    }
    conditions
}

/// `ItemRepository.EnsureAccessible`: `Ok(false)` is `ErrItemNotFound`.
pub async fn ensure_accessible(
    pool: &Pool,
    content_id: &str,
    filter: &AccessFilter,
) -> Result<bool, String> {
    if filter.nothing_allowed() {
        return Ok(false);
    }
    let mut ceiling = None;
    let bound = filter.bind(2, &mut ceiling);
    let mut conditions = vec!["mi.content_id = $1".to_owned()];
    conditions.extend(library_conditions(
        "mi.content_id",
        bound.allowed_at,
        bound.disabled_at,
    ));
    conditions.extend(bound.maturity);
    let mut args: Vec<&(dyn ToSql + Sync)> = vec![&content_id];
    args.extend(bound.args);
    let sql = format!(
        "SELECT 1 FROM media_items mi WHERE {} LIMIT 1",
        conditions.join(" AND ")
    );
    let rows = pool.query(&sql, &args).await.map_err(|e| e.to_string())?;
    Ok(!rows.is_empty())
}

/// `filterAccessibleContentIDs`: the requested IDs the viewer may see, an episode through its series.
pub async fn filter_accessible(
    pool: &Pool,
    content_ids: &[String],
    filter: &AccessFilter,
) -> Result<HashSet<String>, String> {
    let mut result = HashSet::new();
    if content_ids.is_empty() || filter.nothing_allowed() {
        return Ok(result);
    }
    if has_ceiling(&filter.max_content_rating)
        && age_for_ceiling(&filter.max_content_rating).is_none()
    {
        return Ok(result);
    }
    let ids = content_ids.to_vec();
    let mut ceiling = None;
    let bound = filter.bind(2, &mut ceiling);
    let mut item = vec!["mi.content_id = req.content_id".to_owned()];
    let mut episode = vec!["e.content_id = req.content_id".to_owned()];
    item.extend(library_conditions(
        "mi.content_id",
        bound.allowed_at,
        bound.disabled_at,
    ));
    episode.extend(library_conditions(
        "e.series_id",
        bound.allowed_at,
        bound.disabled_at,
    ));
    item.extend(bound.maturity.iter().cloned());
    episode.extend(bound.maturity);
    let mut args: Vec<&(dyn ToSql + Sync)> = vec![&ids];
    args.extend(bound.args);
    let sql = format!(
        "
		SELECT req.content_id
		FROM unnest($1::text[]) AS req(content_id)
		WHERE EXISTS (
			SELECT 1
			FROM media_items mi
			WHERE {}
		)
		OR EXISTS (
			SELECT 1
			FROM episodes e JOIN media_items mi ON mi.content_id = e.series_id
			WHERE {}
		)",
        item.join(" AND "),
        episode.join(" AND "),
    );
    for row in pool.query(&sql, &args).await.map_err(|e| e.to_string())? {
        result.insert(row.try_get::<_, String>(0).map_err(|e| e.to_string())?);
    }
    Ok(result)
}

/// `LibraryItemRepository.GetItemsInFolder`.
pub async fn items_in_folder(
    pool: &Pool,
    content_ids: &[String],
    folder: i32,
) -> Result<HashSet<String>, String> {
    let mut result = HashSet::new();
    if content_ids.is_empty() {
        return Ok(result);
    }
    let ids = content_ids.to_vec();
    let rows = pool
        .query(
            "SELECT req.content_id
		FROM unnest($2::text[]) AS req(content_id)
		WHERE EXISTS (
			SELECT 1
			FROM media_item_libraries mil
			WHERE mil.media_folder_id = $1
			  AND mil.content_id = req.content_id
		)
		OR EXISTS (
			SELECT 1
			FROM episode_libraries el
			WHERE el.media_folder_id = $1
			  AND el.episode_id = req.content_id
		)",
            &[&folder, &ids],
        )
        .await
        .map_err(|e| e.to_string())?;
    for row in rows {
        result.insert(row.try_get::<_, String>(0).map_err(|e| e.to_string())?);
    }
    Ok(result)
}

/// `ItemRepository.GetByIDsWithAccess`, the IDs it returns with their titles.
pub async fn visible_items(
    pool: &Pool,
    content_ids: &[String],
    filter: &AccessFilter,
) -> Result<HashMap<String, String>, String> {
    let mut result = HashMap::new();
    if content_ids.is_empty() || filter.nothing_allowed() {
        return Ok(result);
    }
    let ids = content_ids.to_vec();
    let mut ceiling = None;
    let bound = filter.bind(2, &mut ceiling);
    let mut sql =
        "SELECT mi.content_id, mi.title FROM media_items mi WHERE mi.content_id = ANY($1)"
            .to_owned();
    for condition in library_conditions("mi.content_id", bound.allowed_at, bound.disabled_at)
        .into_iter()
        .chain(bound.maturity)
    {
        sql.push_str(" AND ");
        sql.push_str(&condition);
    }
    let mut args: Vec<&(dyn ToSql + Sync)> = vec![&ids];
    args.extend(bound.args);
    for row in pool.query(&sql, &args).await.map_err(|e| e.to_string())? {
        result.insert(
            row.try_get::<_, String>(0).map_err(|e| e.to_string())?,
            row.try_get::<_, String>(1).map_err(|e| e.to_string())?,
        );
    }
    Ok(result)
}

impl AccessFilter {
    /// `catalog.IntersectAccess`.
    pub fn intersect_owner(&self, owner: &Scope) -> AccessFilter {
        let owner = AccessFilter::of_content(owner);
        let mut out = self.clone();
        match (&self.allowed, &owner.allowed) {
            (_, None) => {}
            (None, Some(theirs)) => out.allowed = Some(theirs.clone()),
            (Some(mine), Some(theirs)) => {
                out.allowed = Some(
                    mine.iter()
                        .filter(|id| theirs.contains(id))
                        .copied()
                        .collect(),
                )
            }
        }
        out.max_content_rating =
            crate::rating::stricter_ceiling(&self.max_content_rating, &owner.max_content_rating)
                .to_owned();
        if owner.max_advisory_age > 0
            && (out.max_advisory_age == 0 || owner.max_advisory_age < out.max_advisory_age)
        {
            out.max_advisory_age = owner.max_advisory_age;
        }
        let hides = |f: &AccessFilter| f.max_advisory_age > 0 && f.require_advisory_age;
        out.require_advisory_age = hides(self) || hides(&owner);
        out
    }

    /// `OwnerAccess.OwnerFilter`: allowed libraries and maturity limits only.
    fn of_content(scope: &Scope) -> Self {
        let mut filter = Self::of(Some(scope));
        filter.disabled.clear();
        filter
    }

    /// `AccessFilter.LibraryScope`'s `none` result for a non-empty request, and
    /// `CanAccessLibraryCollection` for an empty one.
    pub fn can_reach_libraries(&self, libraries: &[i32]) -> bool {
        if libraries.is_empty() {
            return self.allowed.is_none() && self.disabled.is_empty();
        }
        libraries.iter().any(|id| {
            self.allowed.as_ref().is_none_or(|a| a.contains(id)) && !self.disabled.contains(id)
        })
    }
}
