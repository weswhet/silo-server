//! Ratings, favorites and watchlist membership, watch progress, home dismissals, and the device
//! registry: `handlers/{ratings,favorites,progress,home_dismissals,devices,devices_service}.go` and
//! their `apiv2` operations. The SQL is Go's.
//!
//! Go's `InterestUpdater` runs here too (`interest.rs`), for the writes these rows make. Requests reach these rows only while no watch provider connection and no watchlist title entry
//! exists (`Stack::personal_needs_go`), because Go's fan-out to providers needs the plugin host.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::problem::{Problem, ProblemError};
use silo_api_v2::wire::{Instant, paginated};
use silo_config::settings::mirror::logical_key;
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::json::Decoder;
use silo_gocompat::strings::trim_space;
use silo_gocompat::time::{GoTime, RFC3339, RFC3339_NANO, parse};
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_pg::{AnyInt, Pool, Row};
use silo_store::access::Scope as AccessScope;
use silo_store::catalog::access::{
    AccessFilter, ensure_accessible, filter_accessible, items_in_folder,
};

use super::auth::{ApiError, service_problem, write_v1_error};
use super::chain::{
    Stack, Step, V2Class, capability_json, problem_type, write_capability, write_problem,
    write_v1_json, write_v2_json,
};
use super::huma::RawBody;
use super::interest;
use super::settings::{
    HouseholdError, Verifier, api, device_of, household_manager, int_of_id, mark_profile_stale,
    publish_envelope, publish_user_settings, write_api,
};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/ratings/"),
    NativeRow::new(ApiV1, "GET", "/api/v1/ratings/{item_id}"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/ratings/{item_id}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/ratings/{item_id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/ratings"),
    NativeRow::new(ApiV2, "GET", "/api/v2/ratings/{item_id}"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/ratings/{item_id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/ratings/{item_id}"),
    NativeRow::new(ApiV1, "GET", "/api/v1/favorites/{item_id}"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/favorites/{item_id}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/favorites/{item_id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/favorites/{item_id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/favorites/{item_id}/membership"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/favorites/{item_id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/favorites/{item_id}"),
    NativeRow::new(ApiV1, "GET", "/api/v1/watchlist/{item_id}"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/watchlist/{item_id}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/watchlist/{item_id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/watchlist/{item_id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/watchlist/{item_id}/membership"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/watchlist/{item_id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/watchlist/{item_id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/capabilities/personal-lists"),
    NativeRow::new(ApiV2, "GET", "/api/v2/capabilities/not-interested"),
    NativeRow::new(ApiV2, "GET", "/api/v2/progress/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/home/capabilities"),
    NativeRow::new(ApiV1, "GET", "/api/v1/progress/"),
    NativeRow::new(ApiV2, "GET", "/api/v2/progress"),
    NativeRow::new(ApiV1, "POST", "/api/v1/sync/progress"),
    NativeRow::new(ApiV2, "POST", "/api/v2/sync/progress"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/home/dismissals/{surface}/{item_id}"),
    NativeRow::new(
        ApiV1,
        "DELETE",
        "/api/v1/home/dismissals/{surface}/{item_id}",
    ),
    NativeRow::new(ApiV2, "PUT", "/api/v2/home/dismissals/{surface}/{item_id}"),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/home/dismissals/{surface}/{item_id}",
    ),
    NativeRow::new(ApiV1, "GET", "/api/v1/devices/"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/devices/{device_id}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/devices/{device_id}/settings"),
    NativeRow::new(ApiV2, "GET", "/api/v2/devices"),
    NativeRow::new(ApiV2, "PATCH", "/api/v2/devices/{device_id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/devices/{device_id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/devices/{device_id}/settings"),
];

/// The v1 chi group these rows share, `RequireProfile` included.
const V1_PROFILE: &[Step] = &[
    Step::Auth,
    Step::Demo,
    Step::RateLimit,
    Step::Viewer,
    Step::Profile,
];
const V2_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::Profile,
];

macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

/// A v1 row's path under its `r.Route` mount: the last segments after `/api/v1/<mount>`.
fn below(path: &'static str) -> &'static str {
    for mount in MOUNTS {
        if let Some(rest) = path.strip_prefix(mount)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            return if rest.is_empty() { "/" } else { rest };
        }
    }
    path
}

const MOUNTS: &[&str] = &[
    "/api/v1/ratings",
    "/api/v1/favorites",
    "/api/v1/watchlist",
    "/api/v1/progress",
    "/api/v1/sync",
    "/api/v1/home/dismissals",
    "/api/v1/devices",
];

/// The chi group's gates on a `r.Route` subrouter, which run before its own 404 and 405.
fn group(stack: &Arc<Stack>) -> Mux {
    let mux = Mux::new();
    mux.use_middleware([stack.v1_group(V1_PROFILE)]);
    mux
}

const INTERNAL: &str = "internal_error";

pub(super) fn user_of(r: &Request) -> i64 {
    get_claims(r).map_or(0, |c| c.user_id)
}

fn scope_of(r: &Request) -> Option<Arc<AccessScope>> {
    r.extensions.get::<Arc<AccessScope>>().cloned()
}

pub(super) fn access_of(r: &Request) -> AccessFilter {
    AccessFilter::of(scope_of(r).as_deref())
}

fn query_param(r: &Request, name: &str) -> String {
    let (query, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    query
        .get(name)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
}

/// `parsePagination`.
fn pagination(r: &Request) -> (i64, i64) {
    let limit = query_param(r, "limit")
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .unwrap_or(50);
    let offset = query_param(r, "offset")
        .parse::<i64>()
        .ok()
        .filter(|n| *n >= 0)
        .unwrap_or(0);
    (limit, offset)
}

fn v2_limit(r: &Request) -> i64 {
    query_param(r, "limit").parse().unwrap_or(50)
}

/// `timeToString`.
fn store_time(t: SystemTime) -> String {
    GoTime::from_system_time(t).to_utc().format(RFC3339)
}

fn instant(t: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(t))
}

pub(super) fn internal() -> Problem {
    Problem::new(problem_type(INTERNAL), "An unexpected error occurred.")
}

pub(super) fn validation(location: &str, detail: &str) -> Problem {
    Problem::new(
        problem_type("validation_failed"),
        "The request did not pass validation; see errors.",
    )
    .with_errors([ProblemError {
        location: location.to_owned(),
        code: "invalid".to_owned(),
        detail: detail.to_owned(),
    }])
}

/// `fieldProblem`.
fn field_problem(e: &ApiError) -> Problem {
    if e.field.is_empty() {
        service_problem(e)
    } else {
        validation(&format!("body.{}", e.field), &e.message)
    }
}

pub(super) fn raw_body(r: &Request) -> Vec<u8> {
    r.extensions
        .get::<RawBody>()
        .map_or(Vec::new(), |b| b.0.clone())
}

/// `v2` cursor security label with the viewer scope digest.
pub(super) fn viewer_digest(r: &Request) -> String {
    let scope = scope_of(r).map(|scope| silo_core::apiv2::ViewerScope {
        policy_revision: scope.policy_revision,
        libraries_restricted: scope.libraries_restricted,
        allowed_library_ids: scope
            .libraries_restricted
            .then(|| scope.allowed_library_ids.clone()),
        disabled_library_ids: (!scope.disabled_library_ids.is_empty())
            .then(|| scope.disabled_library_ids.clone()),
        max_content_rating: scope.maturity_limits.max_content_rating.clone(),
        allow_unrated_content: scope.maturity_limits.allow_unrated_content,
        max_advisory_age: i64::from(scope.maturity_limits.max_advisory_age),
        require_advisory_age: scope.maturity_limits.require_advisory_age,
    });
    silo_core::apiv2::viewer_scope_digest(scope.as_ref())
}

// --- Events ---

#[derive(Serialize)]
struct StatePayload<'a> {
    profile_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    content_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    series_id: &'a str,
    change: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_favorite: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    in_watchlist: Option<bool>,
}

/// `publishUserStateEvent`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_state(
    s: &Stack,
    user: i64,
    profile: &str,
    content: &str,
    series: &str,
    change: &str,
    is_favorite: Option<bool>,
    in_watchlist: Option<bool>,
) {
    if user == 0 || profile.is_empty() || change.is_empty() {
        return;
    }
    let data = silo_gocompat::json::marshal(&StatePayload {
        profile_id: profile,
        content_id: content,
        series_id: series,
        change,
        is_favorite,
        in_watchlist,
    })
    .unwrap_or_default();
    publish_envelope(
        s,
        "user_state",
        "user_state.changed",
        data,
        user,
        profile,
        false,
        false,
    )
    .await;
}

// --- Ratings ---

struct Rating {
    item: String,
    rating: i32,
    rated_at: SystemTime,
}

fn scan_rating(row: &Row) -> Result<Rating, silo_pg::DriverError> {
    Ok(Rating {
        item: row.try_get(0)?,
        rating: i32::from(row.try_get::<_, i16>(1)?),
        rated_at: row.try_get(2)?,
    })
}

async fn get_rating(
    pool: &Pool,
    user: i64,
    profile: &str,
    item: &str,
) -> Result<Option<Rating>, ApiError> {
    let failed = |_| api(500, INTERNAL, "Failed to get rating");
    let rows = pool
        .query(
            "
		SELECT media_item_id, rating, rated_at
		FROM user_ratings
		WHERE user_id = $1 AND profile_id = $2 AND media_item_id = $3",
            &[&AnyInt(user), &profile, &item],
        )
        .await
        .map_err(|e| failed(e.to_string()))?;
    rows.first()
        .map(scan_rating)
        .transpose()
        .map_err(|e| failed(e.to_string()))
}

async fn set_rating(
    s: &Stack,
    r: &Request,
    user: i64,
    profile: &str,
    item: &str,
    rating: i32,
) -> Result<(), ApiError> {
    if !ensure_accessible(&s.pool, item, &access_of(r))
        .await
        .unwrap_or(false)
    {
        return Err(api(404, "not_found", "Item not found"));
    }
    s.pool
        .execute(
            "
		INSERT INTO user_ratings (user_id, profile_id, media_item_id, rating, rated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (user_id, profile_id, media_item_id)
		DO UPDATE SET rating = EXCLUDED.rating, rated_at = EXCLUDED.rated_at",
            &[&AnyInt(user), &profile, &item, &(rating as i16)],
        )
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to set rating"))?;
    mark_profile_stale(s, user, profile).await;
    Ok(())
}

async fn delete_rating(s: &Stack, user: i64, profile: &str, item: &str) -> Result<(), ApiError> {
    s.pool
        .execute(
            "
		DELETE FROM user_ratings
		WHERE user_id = $1 AND profile_id = $2 AND media_item_id = $3",
            &[&AnyInt(user), &profile, &item],
        )
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to delete rating"))?;
    mark_profile_stale(s, user, profile).await;
    Ok(())
}

#[derive(Deserialize, Default)]
struct SetRating {
    #[serde(default)]
    rating: i64,
}

#[derive(Serialize)]
struct V1Rating {
    rating: i32,
    rated_at: String,
}
#[derive(Serialize)]
struct V1RatingItem {
    media_item_id: String,
    rating: i32,
    rated_at: String,
}
#[derive(Serialize)]
struct V1Ratings {
    ratings: Vec<V1RatingItem>,
}
#[derive(Serialize)]
struct V2Rating {
    item_id: String,
    rating: i32,
    rated_at: Instant,
}
#[derive(Serialize, Deserialize, Default)]
struct RatingPosition {
    #[serde(rename = "r", default)]
    rated_at: String,
    #[serde(rename = "m", default)]
    item: String,
}

fn v2_rating(r: Rating) -> V2Rating {
    V2Rating {
        item_id: r.item,
        rating: r.rating,
        rated_at: instant(r.rated_at),
    }
}

fn mount_ratings(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    let sub = group(stack);
    let path = "/api/v1/ratings/";
    sub.get(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                let (limit, offset) = pagination(r);
                let rows = s
                    .pool
                    .query(
                        "
		SELECT media_item_id, rating, rated_at
		FROM user_ratings
		WHERE user_id = $1 AND profile_id = $2
		ORDER BY rated_at DESC
		LIMIT $3 OFFSET $4",
                        &[
                            &AnyInt(user_of(r)),
                            &get_profile_id(r),
                            &AnyInt(limit),
                            &AnyInt(offset),
                        ],
                    )
                    .await;
                let Ok(rows) = rows else {
                    return write_api(w, &api(500, INTERNAL, "Failed to list ratings")).await;
                };
                let ratings = rows
                    .iter()
                    .filter_map(|row| scan_rating(row).ok())
                    .map(|x| V1RatingItem {
                        media_item_id: x.item,
                        rating: x.rating,
                        rated_at: store_time(x.rated_at),
                    })
                    .collect();
                write_v1_json(w, 200, &V1Ratings { ratings }).await
            }),
        ),
    );
    let path = "/api/v1/ratings/{item_id}";
    sub.get(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                match get_rating(
                    &s.pool,
                    user_of(r),
                    &get_profile_id(r),
                    r.url_param("item_id"),
                )
                .await
                {
                    Ok(Some(x)) => {
                        write_v1_json(
                            w,
                            200,
                            &V1Rating {
                                rating: x.rating,
                                rated_at: store_time(x.rated_at),
                            },
                        )
                        .await
                    }
                    Ok(None) => write_v1_error(w, 404, "not_found", "Rating not found").await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    sub.put(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                let (bytes, _) = r.read_all().await;
                let mut stream = Decoder::new().stream(&bytes[..]);
                let Ok(req) = stream.decode::<SetRating>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                if req.rating < 1 || req.rating > 5 {
                    return write_v1_error(w, 400, "bad_request", "Rating must be between 1 and 5")
                        .await;
                }
                let item = r.url_param("item_id").to_owned();
                match set_rating(
                    &s,
                    r,
                    user_of(r),
                    &get_profile_id(r),
                    &item,
                    req.rating as i32,
                )
                .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    sub.delete(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                match delete_rating(&s, user_of(r), &get_profile_id(r), r.url_param("item_id"))
                    .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    api_mux.mount("/api/v1/ratings", sub);

    let path = "/api/v2/ratings";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let limit = v2_limit(r);
                let scope = CursorScope {
                    operation_id: "listRatings".to_owned(),
                    security: format!("{user}/{profile}"),
                    filter: String::new(),
                    sort: "-rated_at,-item_id".to_owned(),
                    tiebreaker: "item_id".to_owned(),
                };
                let raw = query_param(r, "cursor");
                let mut after = None;
                if !raw.is_empty() {
                    let pos: RatingPosition = match s.cursors.decode(&scope, &raw) {
                        Ok(p) => p,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                    let Ok(at) = parse(RFC3339, &pos.rated_at) else {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                problem_type("invalid_cursor"),
                                "The cursor is malformed, tampered with, or belongs to a different query.",
                            ),
                        )
                        .await;
                    };
                    after = Some((at.to_system_time(), pos.item));
                }
                let probe = limit + 1;
                let rows = match &after {
                    None => {
                        s.pool
                            .query(
                                "
			SELECT media_item_id, rating, rated_at
			FROM user_ratings
			WHERE user_id = $1 AND profile_id = $2
			ORDER BY rated_at DESC, media_item_id DESC
			LIMIT $3",
                                &[&AnyInt(user), &profile, &AnyInt(probe)],
                            )
                            .await
                    }
                    Some((at, item)) => {
                        s.pool
                            .query(
                                "
			SELECT media_item_id, rating, rated_at
			FROM user_ratings
			WHERE user_id = $1 AND profile_id = $2
			  AND (rated_at, media_item_id) < ($3::timestamptz, $4)
			ORDER BY rated_at DESC, media_item_id DESC
			LIMIT $5",
                                &[&AnyInt(user), &profile, at, item, &AnyInt(probe)],
                            )
                            .await
                    }
                };
                let Ok(rows) = rows else {
                    return write_problem(w, r, internal()).await;
                };
                let mut ratings: Vec<Rating> =
                    rows.iter().filter_map(|x| scan_rating(x).ok()).collect();
                let mut next = String::new();
                if ratings.len() as i64 > limit {
                    ratings.truncate(limit as usize);
                    if let Some(last) = ratings.last() {
                        let position = RatingPosition {
                            rated_at: GoTime::from_system_time(last.rated_at)
                                .to_utc()
                                .format(RFC3339_NANO),
                            item: last.item.clone(),
                        };
                        next = match s.cursors.encode(&scope, &position) {
                            Ok(c) => c,
                            Err(_) => return write_problem(w, r, internal()).await,
                        };
                    }
                }
                let items: Vec<V2Rating> = ratings.into_iter().map(v2_rating).collect();
                write_v2_json(w, &paginated(items, next)).await
            }),
        ),
    );
    let path = "/api/v2/ratings/{item_id}";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                match get_rating(
                    &s.pool,
                    user_of(r),
                    &get_profile_id(r),
                    r.url_param("item_id"),
                )
                .await
                {
                    Ok(Some(x)) => write_v2_json(w, &v2_rating(x)).await,
                    Ok(None) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(
                                problem_type("not_found"),
                                "The profile has not rated the item.",
                            ),
                        )
                        .await
                    }
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let Ok(body) = silo_gocompat::json::unmarshal::<SetRating>(&raw_body(r)) else {
                    return write_problem(w, r, internal()).await;
                };
                let item = r.url_param("item_id").to_owned();
                match set_rating(
                    &s,
                    r,
                    user_of(r),
                    &get_profile_id(r),
                    &item,
                    body.rating as i32,
                )
                .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                match delete_rating(&s, user_of(r), &get_profile_id(r), r.url_param("item_id"))
                    .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
}

// --- Favorites and watchlist membership ---

#[derive(Clone, Copy)]
struct List {
    table: &'static str,
    /// `user_state.changed`'s change.
    change: &'static str,
    label: &'static str,
    check: &'static str,
    add: &'static str,
    remove: &'static str,
    absent: &'static str,
}

const FAVORITES: List = List {
    table: "user_favorites",
    change: "favorite",
    label: "favorites",
    check: "Failed to check favorite",
    add: "Failed to add favorite",
    remove: "Failed to remove favorite",
    absent: "The item is not one of the profile's favorites.",
};
const WATCHLIST: List = List {
    table: "user_watchlist",
    change: "watchlist",
    label: "watchlist",
    check: "Failed to check watchlist",
    add: "Failed to add to watchlist",
    remove: "Failed to remove from watchlist",
    absent: "The item is not on the profile's watchlist.",
};

/// `ensureAccessibleItem` with `itemLookupError`.
async fn ensure_item(s: &Stack, item: &str, filter: &AccessFilter) -> Result<(), ApiError> {
    let not_found = || api(404, "not_found", "Item not found");
    let failed = |e: String| {
        tracing::error!(component = "api", content_id = item, error = %e, "personal list: item lookup failed");
        api(500, INTERNAL, "Failed to check item access")
    };
    if item.contains('\0') {
        return Err(not_found());
    }
    if ensure_accessible(&s.pool, item, filter)
        .await
        .map_err(failed)?
    {
        return Ok(());
    }
    let rows = s
        .pool
        .query(
            "SELECT series_id FROM episodes WHERE content_id = $1",
            &[&item],
        )
        .await
        .map_err(|e| failed(e.to_string()))?;
    let Some(row) = rows.first() else {
        return Err(not_found());
    };
    let series: Option<String> = row.try_get(0).map_err(|e| failed(e.to_string()))?;
    if ensure_accessible(&s.pool, &series.unwrap_or_default(), filter)
        .await
        .map_err(failed)?
    {
        Ok(())
    } else {
        Err(not_found())
    }
}

/// `GetFavorite` and `GetWatchlistEntry`, with the entry's `added_at`.
async fn get_entry(
    s: &Stack,
    r: &Request,
    list: List,
    item: &str,
) -> Result<Option<SystemTime>, ApiError> {
    ensure_item(s, item, &access_of(r)).await?;
    let sql = format!(
        "SELECT added_at FROM {}
		 WHERE user_id = $1 AND profile_id = $2 AND media_item_id = $3",
        list.table
    );
    let rows = s
        .pool
        .query(&sql, &[&AnyInt(user_of(r)), &get_profile_id(r), &item])
        .await
        .map_err(|_| api(500, INTERNAL, list.check))?;
    rows.first()
        .map(|row| row.try_get(0))
        .transpose()
        .map_err(|_: silo_pg::DriverError| api(500, INTERNAL, list.check))
}

/// `notifyListChange`, without the watch provider fan-out the gate rules out.
async fn notify_list(s: &Stack, list: List, added: bool, user: i64, profile: &str, item: &str) {
    mark_profile_stale(s, user, profile).await;
    let (favorite, watchlist) = if list.change == "favorite" {
        (Some(added), None)
    } else {
        (None, Some(added))
    };
    publish_state(s, user, profile, item, "", list.change, favorite, watchlist).await;
}

async fn add_entry(s: &Stack, r: &Request, list: List, item: &str) -> Result<(), ApiError> {
    ensure_item(s, item, &access_of(r)).await?;
    let (user, profile) = (user_of(r), get_profile_id(r));
    let sql = format!(
        "INSERT INTO {} (user_id, profile_id, media_item_id, added_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING",
        list.table
    );
    let added = s
        .pool
        .execute(&sql, &[&AnyInt(user), &profile, &item, &SystemTime::now()])
        .await
        .map_err(|_| api(500, INTERNAL, list.add))?;
    if added > 0 {
        interest::queue_item(user, &profile, item);
        notify_list(s, list, true, user, &profile, item).await;
    }
    Ok(())
}

async fn remove_entry(s: &Stack, r: &Request, list: List, item: &str) -> Result<(), ApiError> {
    let (user, profile) = (user_of(r), get_profile_id(r));
    let sql = format!(
        "DELETE FROM {} WHERE user_id = $1 AND profile_id = $2 AND media_item_id = $3",
        list.table
    );
    let removed = s
        .pool
        .execute(&sql, &[&AnyInt(user), &profile, &item])
        .await
        .map_err(|_| api(500, INTERNAL, list.remove))?;
    if removed > 0 {
        interest::queue_item(user, &profile, item);
        notify_list(s, list, false, user, &profile, item).await;
    }
    Ok(())
}

#[derive(Serialize)]
struct Entry {
    item_id: String,
    added_at: Instant,
}
#[derive(Serialize)]
struct Membership {
    item_id: String,
    is_member: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    added_at: Option<Instant>,
}

/// `storeInstant`'s view of a stored time: whole seconds, as `timeToString` left it.
fn whole_second(t: SystemTime) -> Instant {
    let seconds = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    instant(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
}

fn mount_list(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux, list: List) {
    let sub = group(stack);
    let path: &'static str =
        Box::leak(format!("/api/v1/{}/{{item_id}}", list.label).into_boxed_str());
    sub.get(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                match get_entry(&s, r, list, r.url_param("item_id")).await {
                    Ok(Some(_)) => w.write_header(204).await,
                    Ok(None) => w.write_header(404).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    sub.put(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                match add_entry(&s, r, list, r.url_param("item_id")).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    sub.delete(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                match remove_entry(&s, r, list, r.url_param("item_id")).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    api_mux.mount(
        Box::leak(format!("/api/v1/{}", list.label).into_boxed_str()),
        sub,
    );

    let path: &'static str =
        Box::leak(format!("/api/v2/{}/{{item_id}}", list.label).into_boxed_str());
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let item = r.url_param("item_id").to_owned();
                match get_entry(&s, r, list, &item).await {
                    Ok(Some(at)) => {
                        write_v2_json(
                            w,
                            &Entry {
                                item_id: item,
                                added_at: whole_second(at),
                            },
                        )
                        .await
                    }
                    Ok(None) => {
                        write_problem(w, r, Problem::new(problem_type("not_found"), list.absent))
                            .await
                    }
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                match add_entry(&s, r, list, r.url_param("item_id")).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                match remove_entry(&s, r, list, r.url_param("item_id")).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
    let path: &'static str =
        Box::leak(format!("/api/v2/{}/{{item_id}}/membership", list.label).into_boxed_str());
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let item = r.url_param("item_id").to_owned();
                match get_entry(&s, r, list, &item).await {
                    Ok(at) => {
                        write_v2_json(
                            w,
                            &Membership {
                                item_id: item,
                                is_member: at.is_some(),
                                added_at: at.map(whole_second),
                            },
                        )
                        .await
                    }
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
}

// --- Capabilities ---

fn mount_capabilities(stack: &Arc<Stack>, v2: &Mux) {
    #[derive(Serialize)]
    struct Lists<'a> {
        revision: &'a str,
        state: &'a str,
        allowed: bool,
        membership_supported: bool,
    }
    #[derive(Serialize)]
    struct Plain<'a> {
        revision: &'a str,
        state: &'a str,
        allowed: bool,
    }
    #[derive(Serialize)]
    struct Progress<'a> {
        revision: &'a str,
        state: &'a str,
        allowed: bool,
        clear_resume_position: bool,
        mark_watched_records_rewatch: bool,
    }
    let path = "/api/v2/capabilities/personal-lists";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |_s, w, r| {
                write_capability(w, r, "getPersonalListCapability", |revision| {
                    capability_json(&Lists {
                        revision,
                        state: "available",
                        allowed: true,
                        membership_supported: true,
                    })
                })
                .await
            }),
        ),
    );
    let path = "/api/v2/capabilities/not-interested";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |_s, w, r| {
                write_capability(w, r, "getNotInterestedCapability", |revision| {
                    capability_json(&Plain {
                        revision,
                        state: "available",
                        allowed: true,
                    })
                })
                .await
            }),
        ),
    );
    #[derive(Serialize)]
    struct Home<'a> {
        revision: &'a str,
        state: &'a str,
        allowed: bool,
        include_items_max: i32,
        section_item_limit_max: i32,
        row_item_limit_max: i32,
    }
    let path = "/api/v2/home/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |_s, w, r| {
                write_capability(w, r, "getHomeCapabilities", |revision| {
                    capability_json(&Home {
                        revision,
                        state: "available",
                        allowed: true,
                        include_items_max: 4,
                        section_item_limit_max: 100,
                        row_item_limit_max: 100,
                    })
                })
                .await
            }),
        ),
    );
    let path = "/api/v2/progress/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |_s, w, r| {
                write_capability(w, r, "getProgressCapabilities", |revision| {
                    capability_json(&Progress {
                        revision,
                        state: "available",
                        allowed: true,
                        clear_resume_position: true,
                        mark_watched_records_rewatch: true,
                    })
                })
                .await
            }),
        ),
    );
}

// --- Progress ---

/// `progressListSelect`.
const PROGRESS_SELECT: &str = "
		SELECT media_item_id, position_seconds, duration_seconds, completed, updated_at
		FROM user_watch_progress
		WHERE user_id = $1 AND profile_id = $2
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = user_watch_progress.user_id
			  AND hhi.profile_id = user_watch_progress.profile_id
			  AND hhi.media_item_id = user_watch_progress.media_item_id
			  AND user_watch_progress.updated_at <= hhi.hidden_before
		  )";

/// `progressStatusPredicate`.
fn status_predicate(status: &str) -> &'static str {
    match status {
        "in_progress" => " AND position_seconds > 0",
        "completed" => " AND completed = TRUE",
        _ => "",
    }
}

#[derive(Clone)]
struct ProgressRow {
    item: String,
    position: f64,
    duration: f64,
    completed: bool,
    updated_at: SystemTime,
}

fn scan_progress(rows: &[Row]) -> Result<Vec<ProgressRow>, ApiError> {
    let failed = |_: silo_pg::DriverError| api(500, INTERNAL, "Failed to list progress");
    rows.iter()
        .map(|row| {
            Ok(ProgressRow {
                item: row.try_get(0).map_err(failed)?,
                position: row.try_get(1).map_err(failed)?,
                duration: row.try_get(2).map_err(failed)?,
                completed: row.try_get(3).map_err(failed)?,
                updated_at: row.try_get(4).map_err(failed)?,
            })
        })
        .collect()
}

/// `filterProgress`.
async fn filter_progress(
    s: &Stack,
    r: &Request,
    entries: Vec<ProgressRow>,
    library: i32,
) -> Result<Vec<ProgressRow>, ApiError> {
    let mut entries = entries;
    let filter = access_of(r);
    if filter.restricted() && !entries.is_empty() {
        let ids: Vec<String> = entries.iter().map(|e| e.item.clone()).collect();
        let keep = filter_accessible(&s.pool, &ids, &filter)
            .await
            .map_err(|_| api(500, INTERNAL, "Failed to apply access filter"))?;
        entries.retain(|e| keep.contains(&e.item));
    }
    if library > 0 && !entries.is_empty() {
        let ids: Vec<String> = entries.iter().map(|e| e.item.clone()).collect();
        let keep = items_in_folder(&s.pool, &ids, library)
            .await
            .map_err(|_| api(500, INTERNAL, "Failed to apply library filter"))?;
        entries.retain(|e| keep.contains(&e.item));
    }
    Ok(entries)
}

#[derive(Serialize)]
struct V1Progress {
    media_item_id: String,
    position_seconds: f64,
    duration_seconds: f64,
    completed: bool,
    updated_at: String,
}
#[derive(Serialize)]
struct V1ProgressList {
    progress: Vec<V1Progress>,
    #[serde(skip_serializing_if = "String::is_empty")]
    next_cursor: String,
}
#[derive(Serialize)]
struct V2Progress {
    media_item_id: String,
    position_seconds: f64,
    duration_seconds: f64,
    completed: bool,
    updated_at: Instant,
}
#[derive(Serialize, Deserialize, Default)]
struct ProgressPosition {
    #[serde(rename = "u", default)]
    updated_at: String,
    #[serde(rename = "m", default)]
    item: String,
}

async fn list_progress_v1(s: &Stack, r: &Request) -> Result<V1ProgressList, ApiError> {
    let (user, profile) = (user_of(r), get_profile_id(r));
    let raw_library = query_param(r, "library_id");
    let library = if raw_library.is_empty() {
        0
    } else {
        match raw_library.parse::<i64>() {
            Ok(n) if n > 0 && n <= i64::from(i32::MAX) => n as i32,
            Ok(n) if n > 0 => {
                return Err(api(500, INTERNAL, "Failed to apply library filter"));
            }
            _ => return Err(api(400, "bad_request", "Invalid library_id")),
        }
    };
    let since = query_param(r, "since");
    let failed = |_| api(500, INTERNAL, "Failed to list progress");
    let (rows, next_cursor) = if since.is_empty() {
        let (limit, offset) = pagination(r);
        let sql = format!(
            "{PROGRESS_SELECT}{}
		ORDER BY updated_at DESC
		LIMIT $3 OFFSET $4",
            status_predicate(&query_param(r, "status"))
        );
        let rows = s
            .pool
            .query(
                &sql,
                &[&AnyInt(user), &profile, &AnyInt(limit), &AnyInt(offset)],
            )
            .await
            .map_err(|e| failed(e.to_string()))?;
        (rows, String::new())
    } else {
        let cursor = since.parse::<i64>().unwrap_or(0);
        let rows = s
            .pool
            .query(
                "
		SELECT media_item_id, position_seconds, duration_seconds, completed, updated_at, synced_seq
		FROM user_watch_progress
		WHERE user_id = $1 AND profile_id = $2 AND synced_seq IS NOT NULL AND synced_seq > $3
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = user_watch_progress.user_id
			  AND hhi.profile_id = user_watch_progress.profile_id
			  AND hhi.media_item_id = user_watch_progress.media_item_id
			  AND user_watch_progress.updated_at <= hhi.hidden_before
		  )
		ORDER BY synced_seq ASC
		LIMIT $4",
                &[&AnyInt(user), &profile, &AnyInt(cursor), &AnyInt(500)],
            )
            .await
            .map_err(|e| failed(e.to_string()))?;
        let mut next = cursor;
        for row in &rows {
            let seq: i64 = row.try_get(5).map_err(|e| failed(e.to_string()))?;
            next = next.max(seq);
        }
        (rows, next.to_string())
    };
    let entries = filter_progress(s, r, scan_progress(&rows)?, library).await?;
    Ok(V1ProgressList {
        progress: entries
            .into_iter()
            .map(|e| V1Progress {
                media_item_id: e.item,
                position_seconds: e.position,
                duration_seconds: e.duration,
                completed: e.completed,
                updated_at: store_time(e.updated_at),
            })
            .collect(),
        next_cursor,
    })
}

/// `ListProgressPage`, the seam and the store's keyset query.
async fn progress_page(
    s: &Stack,
    r: &Request,
    status: &str,
    library: i32,
    mut after: Option<(SystemTime, String)>,
    limit: i64,
) -> Result<(Vec<ProgressRow>, bool), ApiError> {
    let (user, profile) = (user_of(r), get_profile_id(r));
    let want = limit + 1;
    let predicate = status_predicate(status);
    let mut matches = Vec::new();
    while (matches.len() as i64) < want {
        let failed = |_| api(500, INTERNAL, "Failed to list progress");
        let rows = match &after {
            None => {
                let sql = format!(
                    "{PROGRESS_SELECT}{predicate}
		ORDER BY date_trunc('second', updated_at) DESC, media_item_id DESC
		LIMIT $3"
                );
                s.pool
                    .query(&sql, &[&AnyInt(user), &profile, &AnyInt(want)])
                    .await
            }
            Some((at, item)) => {
                let sql = format!(
                    "{PROGRESS_SELECT}{predicate}
		  AND (date_trunc('second', updated_at), media_item_id) < ($3::timestamptz, $4)
		ORDER BY date_trunc('second', updated_at) DESC, media_item_id DESC
		LIMIT $5"
                );
                s.pool
                    .query(&sql, &[&AnyInt(user), &profile, at, item, &AnyInt(want)])
                    .await
            }
        }
        .map_err(|e| failed(e.to_string()))?;
        let batch = scan_progress(&rows)?;
        let last = batch.last().cloned();
        let size = batch.len() as i64;
        matches.extend(filter_progress(s, r, batch, library).await?);
        if size < want {
            break;
        }
        if let Some(last) = last {
            let seconds = last
                .updated_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            after = Some((
                SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
                last.item,
            ));
        }
    }
    let more = matches.len() as i64 > limit;
    matches.truncate(limit as usize);
    Ok((matches, more))
}

/// `ProgressSyncUpdate`.
struct Update {
    check_access: bool,
    item: String,
    position: f64,
    duration: f64,
    force: bool,
    updated_at: Option<SystemTime>,
    invalid_updated_at: bool,
}

struct SyncResult {
    item: String,
    ok: bool,
    error: &'static str,
    not_found: bool,
}

/// `ResolveProgressState`: position, completed, skip.
fn resolve_state(position: f64, duration: f64, watched: i64, resume: i64) -> (f64, bool, bool) {
    let fraction = |pct: i64, default: i64| (if pct <= 0 { default } else { pct }) as f64 / 100.0;
    let position = position.max(0.0);
    let duration = duration.max(0.0);
    if duration > 0.0 && position > 0.0 && position / duration < fraction(resume, 5) {
        return (position, false, true);
    }
    let completed = duration > 0.0 && position / duration > fraction(watched, 90);
    (if completed { 0.0 } else { position }, completed, false)
}

const UPDATE_PROGRESS: &str = "
		WITH visible AS (
			SELECT
				CASE
					WHEN hhi.hidden_before IS NOT NULL AND $7::timestamptz <= hhi.hidden_before
					THEN hhi.hidden_before + interval '1 second'
					ELSE $7::timestamptz
				END AS updated_at
			FROM (SELECT 1) seed
			LEFT JOIN user_history_hidden_items hhi
			  ON hhi.user_id = $1
			 AND hhi.profile_id = $2
			 AND hhi.media_item_id = $3
		)
		INSERT INTO user_watch_progress (user_id, profile_id, media_item_id, position_seconds, duration_seconds, completed, updated_at)
		SELECT $1, $2, $3, $4, $5, $6, updated_at
		FROM visible
		ON CONFLICT(user_id, profile_id, media_item_id) DO UPDATE SET
			position_seconds = CASE WHEN excluded.completed THEN 0
				ELSE excluded.position_seconds END,
			duration_seconds = excluded.duration_seconds,
			completed = CASE WHEN excluded.completed
				THEN TRUE ELSE user_watch_progress.completed END,
			updated_at = excluded.updated_at,
			event_at = excluded.updated_at";

const SET_PROGRESS: &str = "
		WITH visible AS (
			SELECT
				CASE
					WHEN hhi.hidden_before IS NOT NULL AND $7::timestamptz <= hhi.hidden_before
					THEN hhi.hidden_before + interval '1 second'
					ELSE $7::timestamptz
				END AS updated_at
			FROM (SELECT 1) seed
			LEFT JOIN user_history_hidden_items hhi
			  ON hhi.user_id = $1
			 AND hhi.profile_id = $2
			 AND hhi.media_item_id = $3
		)
		INSERT INTO user_watch_progress (user_id, profile_id, media_item_id, position_seconds, duration_seconds, completed, updated_at)
		SELECT $1, $2, $3, $4, $5, $6, updated_at
		FROM visible
		ON CONFLICT(user_id, profile_id, media_item_id) DO UPDATE SET
			position_seconds = excluded.position_seconds,
			duration_seconds = excluded.duration_seconds,
			completed = user_watch_progress.completed OR excluded.completed,
			updated_at = excluded.updated_at,
			event_at = excluded.updated_at";

async fn apply_update(
    s: &Stack,
    user: i64,
    profile: &str,
    u: &Update,
    watched: i64,
    resume: i64,
) -> Result<(), String> {
    let (position, completed, skip) = resolve_state(u.position, u.duration, watched, resume);
    if skip {
        return Ok(());
    }
    let item = u.item.as_str();
    let user_id = user;
    let user = AnyInt(user);
    let duration = u.duration.max(0.0);
    let (before, before_at) = interest::current_state(&s.pool, user_id, profile, item).await;
    let e = |e: silo_pg::Error| e.to_string();
    if let Some(client) = u.updated_at {
        // clientclock.Clamp.
        let now = SystemTime::now();
        let event = if client > now + Duration::from_secs(120) {
            tracing::warn!(
                component = "api",
                profile_id = profile,
                media_item_id = item,
                "clamped future-dated progress event time"
            );
            now
        } else {
            client
        };
        let hidden = s
            .pool
            .query(
                "
		SELECT EXISTS(
			SELECT 1
			FROM user_history_hidden_items
			WHERE user_id = $1
			  AND profile_id = $2
			  AND media_item_id = $3
			  AND hidden_before >= $4::timestamptz
		)",
                &[&user, &profile, &item, &event],
            )
            .await
            .map_err(e)?;
        if hidden.first().is_some_and(|r| r.get::<_, bool>(0)) {
            return Ok(());
        }
        let applied = s.pool
            .execute(
                "
		INSERT INTO user_watch_progress (user_id, profile_id, media_item_id, position_seconds, duration_seconds, completed, updated_at, event_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
		ON CONFLICT(user_id, profile_id, media_item_id) DO UPDATE SET
				position_seconds = EXCLUDED.position_seconds,
				duration_seconds = EXCLUDED.duration_seconds,
				completed = user_watch_progress.completed OR EXCLUDED.completed,
				updated_at = EXCLUDED.updated_at,
				event_at = EXCLUDED.event_at
			WHERE EXCLUDED.event_at > user_watch_progress.event_at",
                &[&user, &profile, &item, &position, &duration, &completed, &event],
            )
            .await
            .map_err(e)?;
        if applied > 0 {
            // timestampedAfter.
            let done = completed || before.completed;
            let after = interest::ProgressState {
                exists: true,
                in_progress: !done && position > 0.0,
                completed: done,
            };
            interest::queue_on_transition(user_id, profile, item, before, before_at, after, event);
        }
        return Ok(());
    }
    let sql = if u.force {
        SET_PROGRESS
    } else {
        UPDATE_PROGRESS
    };
    s.pool
        .execute(
            sql,
            &[
                &user,
                &profile,
                &item,
                &position,
                &duration,
                &completed,
                &SystemTime::now(),
            ],
        )
        .await
        .map_err(e)?;
    // progressStateFromValues reads the request's own position and duration.
    let done = u.duration > 0.0
        && u.position / u.duration > (if watched <= 0 { 90 } else { watched }) as f64 / 100.0;
    let after = interest::ProgressState {
        exists: true,
        in_progress: !done && u.position > 0.0,
        completed: done,
    };
    interest::queue_on_transition(
        user_id,
        profile,
        item,
        before,
        before_at,
        after,
        SystemTime::now(),
    );
    Ok(())
}

/// `SyncProgress`.
async fn sync_progress(
    s: &Stack,
    r: &Request,
    updates: Vec<Update>,
) -> Result<Vec<SyncResult>, ApiError> {
    let (user, profile) = (user_of(r), get_profile_id(r));
    let filter = access_of(r);
    let checked_ids: Vec<String> = updates
        .iter()
        .filter(|u| u.check_access)
        .map(|u| u.item.clone())
        .collect();
    let accessible = if checked_ids.is_empty() {
        HashSet::new()
    } else {
        filter_accessible(&s.pool, &checked_ids, &filter)
            .await
            .map_err(|_| api(503, "unavailable", "Catalog access is unavailable"))?
    };
    let pct = |raw: String| raw.parse::<i64>().ok().filter(|n| *n > 0).unwrap_or(0);
    let watched = pct(s
        .settings
        .get("playback.watched_threshold")
        .await
        .unwrap_or_default());
    let resume = pct(s
        .settings
        .get("playback.min_resume_threshold")
        .await
        .unwrap_or_default());

    let mut results = Vec::with_capacity(updates.len());
    let mut any = false;
    for u in &updates {
        let mut result = SyncResult {
            item: u.item.clone(),
            ok: false,
            error: "",
            not_found: false,
        };
        if u.check_access && !accessible.contains(&u.item) {
            result.error = "catalog item not found";
            result.not_found = true;
        } else if u.item.is_empty() {
            result.error = "media_item_id is required";
        } else if u.invalid_updated_at {
            result.error = "updated_at must be RFC3339";
        } else if apply_update(s, user, &profile, u, watched, resume)
            .await
            .is_err()
        {
            result.error = "failed to update progress";
        } else {
            result.ok = true;
            any = true;
        }
        results.push(result);
    }
    if any {
        mark_profile_stale(s, user, &profile).await;
        let mut published: Vec<String> = Vec::new();
        let mut visible: HashSet<String> = HashSet::new();
        for (u, result) in updates.iter().zip(&results) {
            if (u.check_access && !result.ok) || u.item.is_empty() {
                continue;
            }
            published.push(u.item.clone());
            if u.check_access {
                visible.insert(u.item.clone());
            }
        }
        // `episodeSeries`: a series is named only for an episode the viewer may see.
        let unchecked: Vec<String> = published
            .iter()
            .filter(|id| !visible.contains(*id))
            .cloned()
            .collect();
        if s.bus.is_some() {
            if !unchecked.is_empty()
                && let Ok(allowed) = filter_accessible(&s.pool, &unchecked, &filter).await
            {
                visible.extend(allowed);
            }
            let ids: Vec<String> = published
                .iter()
                .filter(|id| visible.contains(*id))
                .cloned()
                .collect();
            let mut series: HashMap<String, String> = HashMap::new();
            if !ids.is_empty()
                && let Ok(rows) = s
                    .pool
                    .query(
                        "SELECT content_id, series_id FROM episodes WHERE content_id = ANY($1) AND series_id IS NOT NULL AND series_id <> ''",
                        &[&ids],
                    )
                    .await
            {
                for row in rows {
                    series.insert(row.get(0), row.get(1));
                }
            }
            for id in &published {
                let of = series.get(id).map_or("", String::as_str);
                publish_state(s, user, &profile, id, of, "progress", None, None).await;
            }
        }
    }
    Ok(results)
}

#[derive(Deserialize, Default)]
struct V1SyncItem {
    #[serde(default)]
    media_item_id: String,
    #[serde(default)]
    position: f64,
    #[serde(default)]
    duration: f64,
    #[serde(default)]
    force_overwrite: bool,
    #[serde(default)]
    updated_at: Option<String>,
}
#[derive(Deserialize, Default)]
struct V1SyncRequest {
    #[serde(default)]
    items: Vec<V1SyncItem>,
}
#[derive(Serialize)]
struct V1SyncResult {
    media_item_id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    error: &'static str,
}
#[derive(Serialize)]
struct V1SyncResponse {
    results: Vec<V1SyncResult>,
}

#[derive(Deserialize, Default)]
struct V2SyncItem {
    #[serde(default)]
    client_ref: Option<String>,
    #[serde(default)]
    media_item_id: String,
    #[serde(default)]
    position_ms: i64,
    #[serde(default)]
    duration_ms: i64,
    #[serde(default)]
    force_overwrite: bool,
    #[serde(default)]
    updated_at: Option<String>,
}
#[derive(Deserialize, Default)]
struct V2SyncRequest {
    #[serde(default)]
    items: Vec<V2SyncItem>,
}
#[derive(Serialize)]
struct BulkFailure {
    #[serde(rename = "type")]
    kind: String,
    title: String,
    status: u16,
    detail: &'static str,
}
#[derive(Serialize)]
struct V2SyncResult {
    index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ref: Option<String>,
    media_item_id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<BulkFailure>,
}
#[derive(Serialize)]
struct Summary {
    total: usize,
    succeeded: usize,
    failed: usize,
}
#[derive(Serialize)]
struct V2SyncResponse {
    items: Vec<V2SyncResult>,
    summary: Summary,
}

/// `validateBulkIdentity`.
fn bulk_identity(items: &[V2SyncItem]) -> Option<Problem> {
    let mut targets = HashSet::new();
    let mut refs = HashSet::new();
    for (i, item) in items.iter().enumerate() {
        let mut field = "";
        if trim_space(&item.media_item_id).is_empty() || targets.contains(&item.media_item_id) {
            field = "media_item_id";
        }
        if let Some(reference) = &item.client_ref
            && (trim_space(reference).is_empty() || refs.contains(reference))
        {
            field = "client_ref";
        }
        if !field.is_empty() {
            return Some(
                Problem::new(
                    problem_type("validation_failed"),
                    "Bulk targets and client references must be nonblank and unique.",
                )
                .with_errors([ProblemError {
                    location: format!("body.items[{i}].{field}"),
                    code: "invalid".to_owned(),
                    detail: "Expected a unique nonblank value.".to_owned(),
                }]),
            );
        }
        targets.insert(item.media_item_id.clone());
        if let Some(reference) = &item.client_ref {
            refs.insert(reference.clone());
        }
    }
    None
}

fn mount_progress(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    let sub = group(stack);
    let path = "/api/v1/progress/";
    sub.get(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                match list_progress_v1(&s, r).await {
                    Ok(body) => write_v1_json(w, 200, &body).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    api_mux.mount("/api/v1/progress", sub);
    let sub = group(stack);
    let path = "/api/v1/sync/progress";
    sub.post(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                let (bytes, _) = r.read_all().await;
                let mut stream = Decoder::new().stream(&bytes[..]);
                let Ok(req) = stream.decode::<V1SyncRequest>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                if req.items.is_empty() {
                    return write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "At least one progress item is required",
                    )
                    .await;
                }
                let updates = req
                    .items
                    .into_iter()
                    .map(|item| {
                        let parsed = item.updated_at.as_deref().map(|raw| parse(RFC3339, raw));
                        Update {
                            check_access: false,
                            item: item.media_item_id,
                            position: item.position,
                            duration: item.duration,
                            force: item.force_overwrite,
                            invalid_updated_at: matches!(parsed, Some(Err(_))),
                            updated_at: parsed.and_then(Result::ok).map(GoTime::to_system_time),
                        }
                    })
                    .collect();
                match sync_progress(&s, r, updates).await {
                    Ok(results) => {
                        let results = results
                            .into_iter()
                            .map(|x| V1SyncResult {
                                media_item_id: x.item,
                                status: if x.ok { "ok" } else { "error" },
                                error: x.error,
                            })
                            .collect();
                        write_v1_json(w, 200, &V1SyncResponse { results }).await
                    }
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    api_mux.mount("/api/v1/sync", sub);

    let path = "/api/v2/progress";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let raw_library = query_param(r, "library_id");
                let mut library = 0;
                if !raw_library.is_empty() {
                    match int_of_id(&raw_library).filter(|n| *n <= i64::from(i32::MAX)) {
                        Some(n) => library = n as i32,
                        None => {
                            return write_problem(
                                w,
                                r,
                                validation("query.library_id", "expected a library identifier"),
                            )
                            .await;
                        }
                    }
                }
                let status = query_param(r, "status");
                let scope = CursorScope {
                    operation_id: "listProgress".to_owned(),
                    security: format!("{}/{}/{}", user_of(r), get_profile_id(r), viewer_digest(r)),
                    filter: format!("{status}|{raw_library}"),
                    sort: "-updated_at,-media_item_id".to_owned(),
                    tiebreaker: "media_item_id".to_owned(),
                };
                let raw = query_param(r, "cursor");
                let mut after = None;
                if !raw.is_empty() {
                    let pos: ProgressPosition = match s.cursors.decode(&scope, &raw) {
                        Ok(p) => p,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                    let Ok(at) = parse(RFC3339_NANO, &pos.updated_at) else {
                        return write_problem(w, r, internal()).await;
                    };
                    after = Some((at.to_system_time(), pos.item));
                }
                let limit = v2_limit(r);
                let (entries, more) =
                    match progress_page(&s, r, &status, library, after, limit).await {
                        Ok(page) => page,
                        Err(e) => return write_problem(w, r, service_problem(&e)).await,
                    };
                let mut next = String::new();
                if more && let Some(last) = entries.last() {
                    let position = ProgressPosition {
                        updated_at: store_time(last.updated_at),
                        item: last.item.clone(),
                    };
                    next = match s.cursors.encode(&scope, &position) {
                        Ok(c) => c,
                        Err(_) => return write_problem(w, r, internal()).await,
                    };
                }
                let items: Vec<V2Progress> = entries
                    .into_iter()
                    .map(|e| V2Progress {
                        media_item_id: e.item,
                        position_seconds: e.position,
                        duration_seconds: e.duration,
                        completed: e.completed,
                        updated_at: whole_second(e.updated_at),
                    })
                    .collect();
                write_v2_json(w, &paginated(items, next)).await
            }),
        ),
    );
    let path = "/api/v2/sync/progress";
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let Ok(req) = silo_gocompat::json::unmarshal::<V2SyncRequest>(&raw_body(r)) else {
                    return write_problem(w, r, internal()).await;
                };
                if let Some(problem) = bulk_identity(&req.items) {
                    return write_problem(w, r, problem).await;
                }
                let refs: Vec<Option<String>> =
                    req.items.iter().map(|i| i.client_ref.clone()).collect();
                let updates = req
                    .items
                    .into_iter()
                    .map(|item| Update {
                        check_access: true,
                        item: item.media_item_id,
                        position: item.position_ms as f64 / 1000.0,
                        duration: item.duration_ms as f64 / 1000.0,
                        force: item.force_overwrite,
                        invalid_updated_at: false,
                        updated_at: item
                            .updated_at
                            .as_deref()
                            .and_then(|raw| parse(RFC3339, raw).ok())
                            .map(GoTime::to_system_time),
                    })
                    .collect();
                let results = match sync_progress(&s, r, updates).await {
                    Ok(results) => results,
                    Err(e) => return write_problem(w, r, service_problem(&e)).await,
                };
                let total = results.len();
                let mut succeeded = 0;
                let mut items = Vec::with_capacity(total);
                for (index, (x, client_ref)) in results.into_iter().zip(refs).enumerate() {
                    let failure = if x.ok {
                        succeeded += 1;
                        None
                    } else {
                        let (slug, detail) = if x.not_found {
                            ("not_found", "Catalog item not found.")
                        } else {
                            (INTERNAL, "Progress could not be updated.")
                        };
                        let kind = problem_type(slug);
                        Some(BulkFailure {
                            kind: kind.uri(),
                            title: kind.title.to_string(),
                            status: kind.status,
                            detail,
                        })
                    };
                    items.push(V2SyncResult {
                        index,
                        client_ref,
                        media_item_id: x.item,
                        status: if failure.is_none() {
                            "success"
                        } else {
                            "failure"
                        },
                        failure,
                    });
                }
                let summary = Summary {
                    total,
                    succeeded,
                    failed: total - succeeded,
                };
                write_v2_json(w, &V2SyncResponse { items, summary }).await
            }),
        ),
    );
}

// --- Home dismissals ---

#[derive(Deserialize, Default)]
struct Dismissal {
    #[serde(default)]
    series_id: String,
    #[serde(default)]
    progress_updated_at: Option<String>,
}

const CONTINUE_WATCHING: &str = "continue_watching";
const NEXT_UP: &str = "next_up";

fn field_error(field: &'static str, message: &str) -> ApiError {
    ApiError {
        field,
        ..api(400, "bad_request", message)
    }
}

/// `ResolveDropSeries`.
async fn drop_series(s: &Stack, item: &str) -> Result<Option<String>, ApiError> {
    let rows = s
        .pool
        .query(
            "
		SELECT COALESCE(
			(SELECT series_id FROM episodes WHERE content_id = $1),
			(SELECT content_id FROM media_items WHERE content_id = $1 AND type = 'series'))",
            &[&item],
        )
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to resolve dismissed item"))?;
    let series: Option<String> = rows.first().and_then(|r| r.get(0));
    Ok(series.filter(|x| !x.is_empty()))
}

/// `dismissHomeItem`. `drop` is false on the frozen v1 routes, which keep per-card dismissals.
async fn dismiss(
    s: &Stack,
    r: &Request,
    drop: bool,
    surface: &str,
    item: &str,
    series: &str,
    stamp: &str,
) -> Result<(), ApiError> {
    if surface == CONTINUE_WATCHING && stamp.is_empty() {
        return Err(field_error(
            "progress_updated_at",
            "progress_updated_at is required",
        ));
    }
    if surface == NEXT_UP && series.is_empty() {
        return Err(field_error("series_id", "series_id is required"));
    }
    let (user, profile) = (user_of(r), get_profile_id(r));
    let failed = || api(500, INTERNAL, "Failed to save dismissal");
    if drop && let Some(of) = drop_series(s, item).await? {
        if !ensure_accessible(&s.pool, &of, &access_of(r))
            .await
            .map_err(|_| api(500, INTERNAL, "Failed to check item access"))?
        {
            return Err(api(404, "not_found", "Item not found"));
        }
        prune_ended(s, user, &profile, &of)
            .await
            .map_err(|_| failed())?;
        s.pool
            .execute(
                "
		INSERT INTO user_dropped_series (user_id, profile_id, series_id, dropped_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (user_id, profile_id, series_id) DO UPDATE SET dropped_at = EXCLUDED.dropped_at",
                &[&AnyInt(user), &profile, &of],
            )
            .await
            .map_err(|_| failed())?;
        interest::queue_home_change(user, &profile, &of);
        publish_state(s, user, &profile, item, &of, "home_dismissal", None, None).await;
        return Ok(());
    }
    let (series_arg, stamp_arg) = match surface {
        CONTINUE_WATCHING => (None, Some(stamp.to_owned())),
        NEXT_UP => (Some(series.to_owned()), None),
        _ => (None, None),
    };
    s.pool
        .execute(
            "INSERT INTO user_home_item_dismissals (
			user_id, profile_id, surface, media_item_id, series_id, progress_updated_at, dismissed_at
		) VALUES ($1, $2, $3, $4, $5, $6::text::timestamptz, $7)
		ON CONFLICT(user_id, profile_id, surface, media_item_id) DO UPDATE SET
			series_id = excluded.series_id,
			progress_updated_at = excluded.progress_updated_at,
			dismissed_at = excluded.dismissed_at",
            &[
                &AnyInt(user),
                &profile,
                &surface,
                &item,
                &series_arg,
                &stamp_arg,
                &whole_second_time(SystemTime::now()),
            ],
        )
        .await
        .map_err(|_| failed())?;
    interest::queue_home_change(user, &profile, item);
    publish_state(
        s,
        user,
        &profile,
        item,
        series,
        "home_dismissal",
        None,
        None,
    )
    .await;
    Ok(())
}

/// `pruneEnded`.
async fn prune_ended(
    s: &Stack,
    user: i64,
    profile: &str,
    keep: &str,
) -> Result<u64, silo_pg::Error> {
    s.pool
        .execute(
            "
		DELETE FROM user_dropped_series t
		USING (
		WITH d AS MATERIALIZED (
			SELECT series_id, dropped_at FROM user_dropped_series
			WHERE user_id = $1 AND profile_id = $2 
		), recent AS (
			SELECT media_item_id, updated_at FROM user_watch_progress
			WHERE user_id = $1 AND profile_id = $2 AND updated_at > (SELECT min(dropped_at) FROM d)
			UNION ALL
			SELECT media_item_id, updated_at FROM user_history_hidden_items
			WHERE user_id = $1 AND profile_id = $2 AND updated_at > (SELECT min(dropped_at) FROM d)
		), activity AS (
			SELECT e.series_id, max(r.updated_at) AS at
			FROM recent r JOIN episodes e ON e.content_id = r.media_item_id
			WHERE e.series_id = ANY(ARRAY(SELECT series_id FROM d))
			GROUP BY e.series_id
		)
		SELECT d.series_id, d.dropped_at, (a.at IS NULL OR a.at <= d.dropped_at) AS active
		FROM d LEFT JOIN activity a ON a.series_id = d.series_id) s
		WHERE t.user_id = $1 AND t.profile_id = $2 AND t.series_id = s.series_id
		  AND t.dropped_at = s.dropped_at AND NOT s.active AND t.series_id <> $3
		  AND NOT EXISTS (
			SELECT 1 FROM watch_provider_dropped_items w
			JOIN watch_provider_connections c ON c.id = w.connection_id
			WHERE c.user_id = $1 AND c.profile_id = $2 AND w.series_id = t.series_id
		  )",
            &[&AnyInt(user), &profile, &keep],
        )
        .await
}

fn whole_second_time(t: SystemTime) -> SystemTime {
    let seconds = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

async fn undismiss(
    s: &Stack,
    r: &Request,
    drop: bool,
    surface: &str,
    item: &str,
) -> Result<(), ApiError> {
    let (user, profile) = (user_of(r), get_profile_id(r));
    let failed = || api(500, INTERNAL, "Failed to delete dismissal");
    let series = if drop {
        drop_series(s, item).await?
    } else {
        None
    };
    if let Some(of) = &series {
        prune_ended(s, user, &profile, of)
            .await
            .map_err(|_| failed())?;
        s.pool
            .execute(
                "
		DELETE FROM user_dropped_series
		WHERE user_id = $1 AND profile_id = $2 AND series_id = $3",
                &[&AnyInt(user), &profile, of],
            )
            .await
            .map_err(|_| failed())?;
        interest::queue_home_change(user, &profile, of);
    }
    s.pool
        .execute(
            "DELETE FROM user_home_item_dismissals
		 WHERE user_id = $1 AND profile_id = $2 AND surface = $3 AND media_item_id = $4",
            &[&AnyInt(user), &profile, &surface, &item],
        )
        .await
        .map_err(|_| failed())?;
    interest::queue_home_change(user, &profile, item);
    publish_state(
        s,
        user,
        &profile,
        item,
        series.as_deref().unwrap_or(""),
        "home_dismissal",
        None,
        None,
    )
    .await;
    Ok(())
}

fn mount_dismissals(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    let sub = group(stack);
    let path = "/api/v1/home/dismissals/{surface}/{item_id}";
    let valid = |surface: &str| surface == CONTINUE_WATCHING || surface == NEXT_UP;
    sub.put(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                let surface = r.url_param("surface").to_owned();
                if !valid(&surface) {
                    return write_v1_error(w, 400, "bad_request", "Surface is invalid").await;
                }
                let (bytes, _) = r.read_all().await;
                let mut stream = Decoder::new().stream(&bytes[..]);
                let Ok(req) = stream.decode::<V1Dismissal>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                let item = r.url_param("item_id").to_owned();
                match dismiss(
                    &s,
                    r,
                    false,
                    &surface,
                    &item,
                    &req.series_id,
                    &req.progress_updated_at,
                )
                .await
                {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    sub.delete(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                let surface = r.url_param("surface").to_owned();
                if !valid(&surface) {
                    return write_v1_error(w, 400, "bad_request", "Surface is invalid").await;
                }
                let item = r.url_param("item_id").to_owned();
                match undismiss(&s, r, false, &surface, &item).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    api_mux.mount("/api/v1/home/dismissals", sub);
    let path = "/api/v2/home/dismissals/{surface}/{item_id}";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let Ok(req) = silo_gocompat::json::unmarshal::<Dismissal>(&raw_body(r)) else {
                    return write_problem(w, r, internal()).await;
                };
                let stamp = req
                    .progress_updated_at
                    .as_deref()
                    .and_then(|raw| parse(RFC3339, raw).ok())
                    .map_or(String::new(), |t| t.to_utc().format(RFC3339));
                let (surface, item) = (
                    r.url_param("surface").to_owned(),
                    r.url_param("item_id").to_owned(),
                );
                match dismiss(&s, r, true, &surface, &item, &req.series_id, &stamp).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, field_problem(&e)).await,
                }
            }),
        ),
    );
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (surface, item) = (
                    r.url_param("surface").to_owned(),
                    r.url_param("item_id").to_owned(),
                );
                match undismiss(&s, r, true, &surface, &item).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, service_problem(&e)).await,
                }
            }),
        ),
    );
}

#[derive(Deserialize, Default)]
struct V1Dismissal {
    #[serde(default)]
    series_id: String,
    #[serde(default)]
    progress_updated_at: String,
}

// --- Devices ---

#[derive(Serialize, Deserialize, Default, Clone)]
struct DevicePosition {
    #[serde(rename = "LastSeenAt", default)]
    last_seen_at: String,
    #[serde(rename = "ProfileID", default)]
    profile_id: String,
    #[serde(rename = "DeviceID", default)]
    device_id: String,
}

struct DeviceRow {
    profile_id: String,
    device_id: String,
    name: String,
    custom_name: String,
    platform: String,
    last_seen: SystemTime,
    profile_name: String,
    changed: usize,
}

/// `ListDeviceSettingsPage`.
async fn device_page(
    pool: &Pool,
    user: i64,
    profile: &str,
    device: &str,
    after: Option<&DevicePosition>,
    limit: i64,
) -> Result<Vec<DeviceRow>, String> {
    let mut sql = "SELECT d.profile_id,d.device_id,d.device_name,COALESCE(d.custom_name,''),d.device_platform,d.last_seen_at,COALESCE(p.name,''),(COALESCE((SELECT json_agg(k.key) FROM user_setting_values k WHERE k.user_id=d.user_id AND k.scope='profile_device' AND k.profile_id=d.profile_id AND k.device_id=d.device_id), '[]'))::text
 FROM user_devices d LEFT JOIN user_profiles p ON p.user_id=d.user_id AND p.id=d.profile_id
 WHERE d.user_id = $1 AND ($2='' OR d.profile_id=$2) AND ($3='' OR d.device_id=$3)".to_owned();
    let user = AnyInt(user);
    let limit = AnyInt(limit);
    let rows = if let Some(a) = after {
        sql += " AND (d.last_seen_at < $4::text::timestamptz OR (d.last_seen_at = $4::text::timestamptz AND (d.profile_id,d.device_id) > ($5,$6))) ORDER BY d.last_seen_at DESC,d.profile_id,d.device_id LIMIT $7";
        pool.query(
            &sql,
            &[&user, &profile, &device, &a.last_seen_at, &a.profile_id, &a.device_id, &limit],
        )
        .await
    } else {
        sql += " ORDER BY d.last_seen_at DESC,d.profile_id,d.device_id LIMIT $4";
        pool.query(&sql, &[&user, &profile, &device, &limit]).await
    }
    .map_err(|e| e.to_string())?;
    rows.iter()
        .map(|row| {
            let e = |x: silo_pg::DriverError| x.to_string();
            let keys: String = row.try_get(7).map_err(e)?;
            let keys: Vec<String> = serde_json::from_str(&keys).map_err(|x| x.to_string())?;
            let logical: HashSet<&str> = keys.iter().map(|k| logical_key(k)).collect();
            Ok(DeviceRow {
                profile_id: row.try_get(0).map_err(e)?,
                device_id: row.try_get(1).map_err(e)?,
                name: row.try_get(2).map_err(e)?,
                custom_name: row.try_get(3).map_err(e)?,
                platform: row.try_get(4).map_err(e)?,
                last_seen: row.try_get(5).map_err(e)?,
                profile_name: row.try_get(6).map_err(e)?,
                changed: logical.len(),
            })
        })
        .collect()
}

/// `forgetPlaybackConnections`.
async fn forget_connections(pool: &Pool, user: i64, device: &str) {
    let result = pool
        .execute(
            "DELETE FROM playback_connections WHERE user_id = $1 AND device_id = ANY($2)
             AND NOT EXISTS (SELECT 1 FROM user_devices WHERE user_id = $1 AND device_id = ANY($2))",
            &[&AnyInt(user), &vec![device.to_owned()]],
        )
        .await;
    if let Err(e) = result {
        tracing::warn!(component = "api", user_id = user, error = %e, "playback connection cleanup failed after device removal");
    }
}

/// The audit line of `auditSettingsForOther` for a device action.
fn audit_device(r: &Request, action: &str, target: &str, device: &str, scope: Option<&str>) {
    let acting = get_profile_id(r);
    if target.is_empty() || target == acting {
        return;
    }
    let user = user_of(r);
    tracing::info!(
        component = "api",
        action,
        actor_user_id = user,
        actor_profile_id = acting,
        target_user_id = user,
        target_profile_id = target,
        acting_as_admin = get_claims(r).is_some_and(|c| c.role == "admin"),
        scope = scope.unwrap_or(""),
        device_id = device,
        "settings changed for another profile"
    );
}

/// `deviceSettingsStore`'s authorization, shared by both versions' messages.
async fn authorize_target(
    s: &Stack,
    r: &Request,
    target: &str,
    household: bool,
    verify: &Verifier,
    forbidden: &str,
    unverified: &str,
) -> Result<(), ApiError> {
    let acting = get_profile_id(r);
    let Some(claims) = get_claims(r) else {
        return Err(api(401, "unauthorized", "Authentication required"));
    };
    let user = claims.user_id;
    if household || (!target.is_empty() && target != acting) {
        match household_manager(s, &claims, user, &acting, verify).await {
            Ok((true, _)) => {}
            Ok((false, _)) => return Err(api(403, "forbidden", forbidden)),
            Err(HouseholdError::Unverified) => return Err(api(403, "forbidden", unverified)),
            Err(HouseholdError::Other) => {
                return Err(api(500, INTERNAL, "Failed to check profile permissions"));
            }
        }
        if !target.is_empty() && target != acting {
            let found = s
                .viewer
                .get_profile(user, target)
                .await
                .map_err(|_| api(500, INTERNAL, "Failed to load profile"))?;
            if found.is_none() {
                return Err(api(404, "not_found", "Profile not found"));
            }
        }
    }
    Ok(())
}

/// `RemoveDeviceSettings`: the keys removed, or `None` for `ErrDeviceNotFound`.
async fn remove_device_settings(
    s: &Stack,
    user: i64,
    profile: &str,
    device: &str,
    forget: bool,
) -> Result<Option<Vec<String>>, String> {
    const PREFERENCE_SETTINGS_ADVISORY_CLASS: i32 = 0x5349_4c4f;
    let e = |x: silo_pg::Error| x.to_string();
    let mut conn = s.pool.acquire().await.map_err(e)?;
    let mut tx = conn.begin().await.map_err(e)?;
    let user_arg = AnyInt(user);
    tx.query(
        "SELECT pg_advisory_xact_lock($1,$2)::text",
        &[&PREFERENCE_SETTINGS_ADVISORY_CLASS, &(user as i32)],
    )
    .await
    .map_err(e)?;
    let owned = !tx
        .query(
            "SELECT true FROM user_devices WHERE user_id=$1 AND profile_id=$2 AND device_id=$3",
            &[&user_arg, &profile, &device],
        )
        .await
        .map_err(e)?
        .is_empty();
    let rows = tx
        .query(
            "DELETE FROM user_setting_values WHERE user_id=$1 AND profile_id=$2 AND device_id=$3 AND scope='profile_device' RETURNING key",
            &[&user_arg, &profile, &device],
        )
        .await
        .map_err(e)?;
    let keys: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
    if !owned && keys.is_empty() {
        return Ok(None);
    }
    tx.execute(
        "DELETE FROM user_device_settings WHERE user_id=$1 AND profile_id=$2 AND device_id=$3",
        &[&user_arg, &profile, &device],
    )
    .await
    .map_err(e)?;
    if forget {
        tx.execute(
            "DELETE FROM user_devices WHERE user_id=$1 AND profile_id=$2 AND device_id=$3",
            &[&user_arg, &profile, &device],
        )
        .await
        .map_err(e)?;
    }
    tx.commit().await.map_err(e)?;
    Ok(Some(keys))
}

/// `removeDevice` and `RemoveDeviceSettings` after authorization.
async fn remove_device(
    s: &Stack,
    r: &Request,
    profile: &str,
    device: &str,
    forget: bool,
) -> Result<(), ApiError> {
    let user = user_of(r);
    let keys = remove_device_settings(s, user, profile, device, forget)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to clear device settings"))?
        .ok_or_else(|| api(404, "not_found", "Device not found"))?;
    if forget {
        forget_connections(&s.pool, user, device).await;
    }
    for key in &keys {
        publish_user_settings(s, user, profile, key, "profile_device").await;
    }
    audit_device(
        r,
        if forget {
            "forget_device"
        } else {
            "clear_device"
        },
        profile,
        device,
        Some("profile_device"),
    );
    Ok(())
}

#[derive(Serialize)]
struct V1Device {
    device_id: String,
    device_name: String,
    device_platform: String,
    last_seen_at: String,
    profile_id: String,
    profile_name: String,
    is_current_device: bool,
    changed_count: usize,
}
#[derive(Serialize)]
struct V1Devices {
    devices: Vec<V1Device>,
}
#[derive(Serialize)]
struct V2Device {
    device_id: String,
    device_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    custom_name: String,
    device_platform: String,
    last_seen_at: Instant,
    profile_id: String,
    profile_name: String,
    is_current_device: bool,
    changed_count: usize,
}

fn v2_device(row: DeviceRow, current: &str) -> V2Device {
    V2Device {
        is_current_device: row.device_id == current,
        device_id: row.device_id,
        device_name: row.name,
        custom_name: row.custom_name,
        device_platform: row.platform,
        last_seen_at: instant(row.last_seen),
        profile_id: row.profile_id,
        profile_name: row.profile_name,
        changed_count: row.changed,
    }
}

/// `deviceCustomName`.
fn device_custom_name(name: &str) -> String {
    // unicode.Bidi_Control.
    let bidi = |c: char| matches!(c, '\u{61C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
    let mapped: String = name
        .chars()
        .filter_map(|c| {
            if c.is_control() && c.is_whitespace() {
                Some(' ')
            } else if c.is_control() || bidi(c) {
                None
            } else {
                Some(c)
            }
        })
        .collect();
    let joined = mapped.split_whitespace().collect::<Vec<_>>().join(" ");
    let clamped: String = trim_space(&joined).chars().take(120).collect();
    // visibleRune: not a space, format character, variation selector, or other default-ignorable.
    let invisible = |c: char| {
        c.is_whitespace()
            || matches!(c,
                '\u{AD}' | '\u{600}'..='\u{605}' | '\u{61C}' | '\u{6DD}' | '\u{70F}' | '\u{890}'..='\u{891}'
                | '\u{8E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}'
                | '\u{180B}'..='\u{180D}' | '\u{180F}' | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
                | '\u{34F}' | '\u{115F}'..='\u{1160}' | '\u{17B4}'..='\u{17B5}' | '\u{2065}'
                | '\u{3164}' | '\u{FFA0}' | '\u{FFF0}'..='\u{FFF8}' | '\u{E0000}' | '\u{E0002}'..='\u{E001F}'
                | '\u{E0080}'..='\u{E00FF}' | '\u{E01F0}'..='\u{E0FFF}')
    };
    if clamped.chars().all(invisible) {
        String::new()
    } else {
        clamped
    }
}

fn mount_devices(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    let sub = group(stack);
    const V1_FORBID_LIST: &str =
        "Viewing the household's devices requires the primary profile or admin access";
    const V1_FORBID_MANAGE: &str =
        "Managing another profile's devices requires the primary profile or admin access";
    const V1_UNVERIFIED: &str = "Profile management requires verifying the primary profile PIN";
    const V2_FORBID: &str =
        "Household device management requires the primary profile or admin access";
    const V2_UNVERIFIED: &str = "Verify the primary profile PIN";

    let path = "/api/v1/devices/";
    sub.get(
        below(path),
        stack.v1(
            path,
            &[],
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let household = silo_gocompat::strings::equal_fold(
                    trim_space(&query_param(r, "scope")),
                    "household",
                );
                if household
                    && let Some(claims) = get_claims(r)
                {
                    let verify = Verifier::v1(&s, r, &claims);
                    if let Err(e) = authorize_target(
                        &s, r, "", true, &verify, V1_FORBID_LIST, V1_UNVERIFIED,
                    )
                    .await
                    {
                        return write_api(w, &e).await;
                    }
                }
                let rows = s
                    .pool
                    .query(
                        "SELECT profile_id, device_id, device_name, device_platform, last_seen_at
		 FROM user_devices
		 WHERE user_id = $1
		 ORDER BY last_seen_at DESC, profile_id ASC, device_name ASC, device_id ASC",
                        &[&AnyInt(user)],
                    )
                    .await;
                let Ok(rows) = rows else {
                    return write_api(w, &api(500, INTERNAL, "Failed to list devices")).await;
                };
                let values = s
                    .pool
                    .query(
                        "SELECT profile_id, device_id, key FROM user_setting_values WHERE user_id = $1 AND scope = 'profile_device'",
                        &[&AnyInt(user)],
                    )
                    .await;
                let Ok(values) = values else {
                    return write_api(w, &api(500, INTERNAL, "Failed to read device settings")).await;
                };
                let mut logical: HashMap<(String, String), HashSet<String>> = HashMap::new();
                for v in &values {
                    let key: String = v.get(2);
                    logical
                        .entry((v.get(0), v.get(1)))
                        .or_default()
                        .insert(logical_key(&key).to_owned());
                }
                let names: HashMap<String, String> =
                    silo_store::userstore::profiles::list_profiles(&s.pool, user)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|p| (p.id, trim_space(&p.name).to_owned()))
                        .collect();
                let current = device_of(r).id;
                let mut devices: Vec<V1Device> = Vec::new();
                for row in &rows {
                    let profile_id: String = row.get(0);
                    if !household && profile_id != profile {
                        continue;
                    }
                    let device_id: String = row.get(1);
                    let seen: SystemTime = row.get(4);
                    devices.push(V1Device {
                        changed_count: logical
                            .get(&(profile_id.clone(), device_id.clone()))
                            .map_or(0, HashSet::len),
                        is_current_device: device_id == current,
                        device_name: row.get(2),
                        device_platform: row.get(3),
                        last_seen_at: GoTime::from_system_time(seen).to_utc().format(RFC3339_NANO),
                        profile_name: names.get(&profile_id).cloned().unwrap_or_default(),
                        profile_id,
                        device_id,
                    });
                }
                devices.sort_by(|a, b| {
                    b.last_seen_at
                        .cmp(&a.last_seen_at)
                        .then_with(|| a.device_id.cmp(&b.device_id))
                });
                write_v1_json(w, 200, &V1Devices { devices }).await
            }),
        ),
    );
    for (path, forget) in [
        ("/api/v1/devices/{device_id}", true),
        ("/api/v1/devices/{device_id}/settings", false),
    ] {
        sub.delete(
            below(path),
            stack.v1(
                path,
                &[],
                route!(stack, |s, w, r| {
                    let mut profile = trim_space(&get_profile_id(r)).to_owned();
                    let device = trim_space(r.url_param("device_id")).to_owned();
                    if device.is_empty() {
                        return write_v1_error(w, 400, "bad_request", "A device id is required")
                            .await;
                    }
                    let named = query_param(r, "profile_id");
                    let named = trim_space(&named);
                    if !named.is_empty()
                        && named != profile
                        && let Some(claims) = get_claims(r)
                    {
                        let verify = Verifier::v1(&s, r, &claims);
                        if let Err(e) = authorize_target(
                            &s,
                            r,
                            named,
                            false,
                            &verify,
                            V1_FORBID_MANAGE,
                            V1_UNVERIFIED,
                        )
                        .await
                        {
                            return write_api(w, &e).await;
                        }
                        profile = named.to_owned();
                    }
                    match remove_device(&s, r, &profile, &device, forget).await {
                        Ok(()) => w.write_header(204).await,
                        Err(e) => write_api(w, &e).await,
                    }
                }),
            ),
        );
    }

    api_mux.mount("/api/v1/devices", sub);

    let path = "/api/v2/devices";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let filter = query_param(r, "scope");
                let household = filter == "household";
                if household {
                    let verify = Verifier::v2(r);
                    if let Err(e) =
                        authorize_target(&s, r, "", true, &verify, V2_FORBID, V2_UNVERIFIED).await
                    {
                        return write_problem(w, r, field_problem(&e)).await;
                    }
                }
                let scope = CursorScope {
                    operation_id: "listDevices".to_owned(),
                    security: format!("{user}/{profile}/{}", viewer_digest(r)),
                    filter: if filter.is_empty() {
                        "profile".to_owned()
                    } else {
                        filter
                    },
                    sort: "-last_seen_at,profile_id,device_id".to_owned(),
                    tiebreaker: "profile_id,device_id".to_owned(),
                };
                let raw = query_param(r, "cursor");
                let mut after = None;
                if !raw.is_empty() {
                    let pos: DevicePosition = match s.cursors.decode(&scope, &raw) {
                        Ok(p) => p,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                    after = Some(pos);
                }
                let limit = v2_limit(r);
                let owner = if household { "" } else { profile.as_str() };
                let Ok(mut rows) =
                    device_page(&s.pool, user, owner, "", after.as_ref(), limit + 1).await
                else {
                    return write_problem(w, r, internal()).await;
                };
                let mut next = String::new();
                if rows.len() as i64 > limit {
                    rows.truncate(limit as usize);
                    if let Some(last) = rows.last() {
                        let position = DevicePosition {
                            last_seen_at: GoTime::from_system_time(last.last_seen)
                                .to_utc()
                                .format(RFC3339_NANO),
                            profile_id: last.profile_id.clone(),
                            device_id: last.device_id.clone(),
                        };
                        next = match s.cursors.encode(&scope, &position) {
                            Ok(c) => c,
                            Err(_) => return write_problem(w, r, internal()).await,
                        };
                    }
                }
                let current = device_of(r).id;
                let items: Vec<V2Device> = rows
                    .into_iter()
                    .map(|row| v2_device(row, &current))
                    .collect();
                write_v2_json(w, &paginated(items, next)).await
            }),
        ),
    );
    for (path, forget) in [
        ("/api/v2/devices/{device_id}", true),
        ("/api/v2/devices/{device_id}/settings", false),
    ] {
        v2.delete(
            path,
            stack.v2_steps(
                path,
                V2_WRITE,
                route!(stack, |s, w, r| {
                    let named = query_param(r, "profile_id");
                    let named = trim_space(&named).to_owned();
                    let device = trim_space(r.url_param("device_id")).to_owned();
                    if device.is_empty() {
                        let e = api(400, "bad_request", "A device id is required");
                        return write_problem(w, r, field_problem(&e)).await;
                    }
                    let verify = Verifier::v2(r);
                    if let Err(e) =
                        authorize_target(&s, r, &named, false, &verify, V2_FORBID, V2_UNVERIFIED)
                            .await
                    {
                        return write_problem(w, r, field_problem(&e)).await;
                    }
                    let profile = if named.is_empty() {
                        get_profile_id(r)
                    } else {
                        named
                    };
                    match remove_device(&s, r, &profile, &device, forget).await {
                        Ok(()) => w.write_header(204).await,
                        Err(e) => write_problem(w, r, field_problem(&e)).await,
                    }
                }),
            ),
        );
    }
    let path = "/api/v2/devices/{device_id}";
    v2.patch(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let user = user_of(r);
                let named = query_param(r, "profile_id");
                let named = trim_space(&named).to_owned();
                let device = trim_space(r.url_param("device_id")).to_owned();
                if device.is_empty() {
                    let e = api(400, "bad_request", "A device id is required");
                    return write_problem(w, r, field_problem(&e)).await;
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&raw_body(r)).unwrap_or_default();
                let rename = body.get("custom_name");
                let mut name = String::new();
                if let Some(value) = rename.and_then(|v| v.as_str()) {
                    name = device_custom_name(value);
                    if name.is_empty() {
                        let e = field_error(
                            "custom_name",
                            "A device name needs at least one visible character",
                        );
                        return write_problem(w, r, field_problem(&e)).await;
                    }
                }
                let verify = Verifier::v2(r);
                if let Err(e) =
                    authorize_target(&s, r, &named, false, &verify, V2_FORBID, V2_UNVERIFIED).await
                {
                    return write_problem(w, r, field_problem(&e)).await;
                }
                let profile = if named.is_empty() { get_profile_id(r) } else { named };
                let not_found = api(404, "not_found", "Device not found");
                if rename.is_some() {
                    let changed = s
                        .pool
                        .execute(
                            "UPDATE user_devices SET custom_name=NULLIF($4,'') WHERE user_id=$1 AND profile_id=$2 AND device_id=$3",
                            &[&AnyInt(user), &profile, &device, &name],
                        )
                        .await;
                    match changed {
                        Ok(0) => return write_problem(w, r, field_problem(&not_found)).await,
                        Ok(_) => audit_device(r, "rename_device", &profile, &device, None),
                        Err(_) => return write_problem(w, r, internal()).await,
                    }
                }
                let Ok(mut rows) = device_page(&s.pool, user, &profile, &device, None, 1).await
                else {
                    return write_problem(w, r, internal()).await;
                };
                let Some(row) = rows.pop() else {
                    return write_problem(w, r, field_problem(&not_found)).await;
                };
                write_v2_json(w, &v2_device(row, &device_of(r).id)).await
            }),
        ),
    );
}

pub fn mount(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    interest::start(stack.clone());
    mount_ratings(stack, api_mux, v2);
    mount_list(stack, api_mux, v2, FAVORITES);
    mount_list(stack, api_mux, v2, WATCHLIST);
    mount_capabilities(stack, v2);
    mount_progress(stack, api_mux, v2);
    mount_dismissals(stack, api_mux, v2);
    mount_devices(stack, api_mux, v2);
}
