//! Personal collection membership, orders, groups, sort preferences, capabilities, and the bundled templates:
//! `handlers/collections*.go`, `collection_sort_prefs.go`, and the `apiv2` personal collection operations. The
//! SQL is Go's (`silo_store::userstore::collections`).
//!
//! The rows that render a collection (list, create, read, update) need the smart query executor to count, and
//! imports, sync, and artwork need outbound fetches and the blob store. Personal membership writes ask Go's process
//! for a collage build (`refreshCollage`), which only Go composes. They all stay on Go. An administrator
//! collection's membership writes start no build, so they are here.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use silo_api_v2::precondition::{evaluate_guarded_preconditions, stale_version_problem};
use silo_api_v2::problem::Problem;
use silo_core::apiv2::{EntityTag, render_etag};
use silo_gate::mw::auth::get_profile_id;
use silo_gocompat::json::Decoder;
use silo_gocompat::strings::trim_space;
use silo_http::chi::Mux;
use silo_http::{Request, ResponseWriter, handler_fn};
use silo_pg::AnyInt;
use silo_store::access::ResolveInput;
use silo_store::catalog::access::{AccessFilter, visible_items};
use silo_store::userstore::collections as store;
use silo_store::userstore::collections::MutationError;

use super::auth::{ApiError, service_problem};
use super::chain::{
    Stack, Step, V2Class, capability_json, problem_type, request_id_of, write_capability,
    write_problem, write_v1_json, write_v2_json_status,
};
use super::personal::{access_of, internal, raw_body, user_of, validation, viewer_digest};
use super::settings::{api, field_error, write_api};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/collections/capabilities"),
    NativeRow::new(ApiV1, "GET", "/api/v1/collections/templates"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/collections/sort-preference"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/collections/sort-preference"),
    NativeRow::new(ApiV1, "POST", "/api/v1/collections/groups"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/collections/groups/order"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/collections/groups/{id}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/collections/groups/{id}"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/collections/order"),
    NativeRow::new(ApiV1, "GET", "/api/v1/collections/{id}/items"),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/collections/templates"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/admin/collections/{id}/items/order"),
    NativeRow::new(
        ApiV1,
        "PUT",
        "/api/v1/admin/collections/{id}/items/{item_id}",
    ),
    NativeRow::new(
        ApiV1,
        "DELETE",
        "/api/v1/admin/collections/{id}/items/{item_id}",
    ),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/collections/template-bundles"),
    NativeRow::new(ApiV2, "GET", "/api/v2/collections/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/collections/templates"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/collections/sort-preference"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/collections/sort-preference"),
    NativeRow::new(ApiV2, "POST", "/api/v2/collections/groups"),
    NativeRow::new(ApiV2, "GET", "/api/v2/collections/groups/order"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/collections/groups/order"),
    NativeRow::new(ApiV2, "GET", "/api/v2/collections/groups/{id}"),
    NativeRow::new(ApiV2, "PATCH", "/api/v2/collections/groups/{id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/collections/groups/{id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/collections/order"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/collections/order"),
    NativeRow::new(ApiV2, "GET", "/api/v2/collections/{id}/items/order"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/collections/templates"),
    NativeRow::new(
        ApiV2,
        "PUT",
        "/api/v2/admin/collections/{id}/items/{item_id}",
    ),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/admin/collections/{id}/items/{item_id}",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/collections/template-bundles"),
    NativeRow::new(
        ApiV1,
        "GET",
        "/api/v1/admin/libraries/{libraryID}/collection-groups/",
    ),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/admin/libraries/{library_id}/collection-groups",
    ),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/admin/libraries/{library_id}/collection-groups/order",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/collection-groups/{id}"),
];

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
const V1_ACTING_ADMIN: &[Step] = &[Step::ActingAdmin];
const V2_ADMIN_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
];

const V1_CATALOG: &[u8] = include_bytes!("collection_templates/v1_catalog.json");
const V1_BUNDLES: &[u8] = include_bytes!("collection_templates/v1_bundles.json");
const V2_CATALOG: &[u8] = include_bytes!("collection_templates/v2_catalog.json");
const V2_BUNDLES: &[u8] = include_bytes!("collection_templates/v2_bundles.json");

/// `collectionManagementModeManual`.
const MANUAL: &str = "manual";
/// `sortPreferenceKinds`.
const SORT_KINDS: [&str; 4] = ["library", "user", "watchlist", "favorites"];
/// `querySortDefs`: the field, its default order, and whether it is per profile.
const SORT_FIELDS: &[(&str, &str, bool)] = &[
    ("title", "asc", false),
    ("added_at", "desc", false),
    ("release_date", "desc", false),
    ("last_air_date", "desc", false),
    ("latest_episode_added", "desc", false),
    ("year", "desc", false),
    ("content_rating", "asc", false),
    ("runtime", "desc", false),
    ("rating_imdb", "desc", false),
    ("rating_tmdb", "desc", false),
    ("rating_rt_critic", "desc", false),
    ("rating_rt_audience", "desc", false),
    ("resolution", "desc", false),
    ("bitrate", "desc", false),
    ("progress", "desc", true),
    ("date_viewed", "desc", true),
    ("plays", "desc", true),
    ("author", "asc", false),
    ("narrator", "asc", false),
    ("series", "asc", false),
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

fn user(r: &Request) -> AnyInt {
    AnyInt(user_of(r))
}

fn profile(r: &Request) -> String {
    get_profile_id(r).to_owned()
}

/// A body written exactly as Go encoded it.
async fn write_raw(w: &mut dyn ResponseWriter, body: &[u8]) {
    w.header().set("Content-Type", "application/json");
    w.write_header(200).await;
    let _ = w.write(body).await;
}

fn lower_trim(raw: &str) -> String {
    silo_gocompat::strings::to_lower(trim_space(raw))
}

/// `NormalizeCollectionSort` with `allowPersonalized`.
fn normalize_collection_sort(field: &str, order: &str) -> Option<(String, String)> {
    let field = lower_trim(field);
    let (_, default, _) = SORT_FIELDS.iter().find(|(f, _, _)| *f == field)?;
    let order = lower_trim(order);
    let order = match order.as_str() {
        "" => (*default).to_owned(),
        "asc" | "desc" => order,
        _ => return None,
    };
    Some((field, order))
}

/// `NormalizePersonalSourceSort`.
fn normalize_personal_sort(field: &str, order: &str) -> Option<(String, String)> {
    let field = lower_trim(field);
    let (_, default, personalized) = SORT_FIELDS.iter().find(|(f, _, _)| *f == field)?;
    if *personalized {
        return None;
    }
    let order = lower_trim(order);
    let order = match order.as_str() {
        "" => (*default).to_owned(),
        "asc" | "desc" => order,
        _ => return None,
    };
    Some((field, order))
}

fn is_personal_kind(kind: &str) -> bool {
    kind == "watchlist" || kind == "favorites"
}

/// `normalizeCollectionRef`.
fn collection_ref(kind: &str, id: &str) -> Option<(String, String)> {
    let kind = lower_trim(kind);
    if is_personal_kind(&kind) {
        return Some((kind, "personal".to_owned()));
    }
    if kind != "library" && kind != "user" {
        return None;
    }
    let id = trim_space(id);
    (!id.is_empty()).then(|| (kind, id.to_owned()))
}

const BAD_REF: &str = "collection_kind must be 'library', 'user', 'watchlist', or 'favorites'; collection_id is required for collection kinds";

#[derive(Deserialize, Default)]
#[serde(default)]
struct SortRequest {
    collection_kind: String,
    collection_id: String,
    field: String,
    order: String,
}

#[derive(Serialize)]
struct V1SortView {
    collection_kind: String,
    collection_id: String,
    field: String,
    order: String,
}

/// `SetPersonalCollectionSortPreference`.
async fn set_sort(s: &Stack, r: &Request, req: &SortRequest) -> Result<V1SortView, ApiError> {
    let Some((kind, id)) = collection_ref(&req.collection_kind, &req.collection_id) else {
        return Err(api(400, "bad_request", BAD_REF));
    };
    let field = lower_trim(&req.field);
    let normalized = if field.is_empty() {
        Some((String::new(), String::new()))
    } else if is_personal_kind(&kind) {
        normalize_personal_sort(&field, &req.order)
    } else {
        normalize_collection_sort(&field, &req.order)
    };
    let Some((field, order)) = normalized else {
        return Err(api(
            400,
            "bad_request",
            "Unsupported sort field or order for this collection",
        ));
    };
    let viewer = profile(r);
    let allowed = match kind.as_str() {
        "library" => match store::library_collection_scope(&s.pool, &id).await {
            Ok(Some((visibility, libraries))) => {
                visibility == "visible" && access_of(r).can_reach_libraries(&libraries)
            }
            _ => false,
        },
        "user" => matches!(
            store::get_head(&s.pool, user(r), &id).await,
            Ok(Some(head)) if head.visible_to(trim_space(&viewer))
        ),
        _ => true,
    };
    if !allowed {
        return Err(api(404, "not_found", "Collection not found"));
    }
    store::set_sort_preference(&s.pool, user(r), &viewer, &kind, &id, &field, &order)
        .await
        .map_err(|_| api(500, "internal_error", "Failed to save sort preference"))?;
    Ok(V1SortView {
        collection_kind: kind,
        collection_id: id,
        field,
        order,
    })
}

/// `ClearPersonalCollectionSortPreference`.
async fn clear_sort(s: &Stack, r: &Request, kind: &str, id: &str) -> Result<(), ApiError> {
    let Some((kind, id)) = collection_ref(kind, id) else {
        return Err(api(400, "bad_request", BAD_REF));
    };
    store::clear_sort_preference(&s.pool, user(r), &profile(r), &kind, &id)
        .await
        .map_err(|_| api(500, "internal_error", "Failed to clear sort preference"))
}

fn not_found() -> ApiError {
    api(404, "not_found", "Collection not found")
}

/// `personalCollectionStore`.
async fn head_of(
    s: &Stack,
    r: &Request,
    id: &str,
    mutate: bool,
) -> Result<store::CollectionHead, ApiError> {
    let head = store::get_head(&s.pool, user(r), id)
        .await
        .map_err(|_| api(500, "internal_error", "Failed to load collection"))?
        .ok_or_else(not_found)?;
    let viewer = profile(r);
    if viewer.is_empty() || !head.visible_to(trim_space(&viewer)) {
        return Err(not_found());
    }
    if mutate && head.creator_profile_id != viewer {
        return Err(api(
            403,
            "forbidden",
            "Only the creator can edit this collection",
        ));
    }
    Ok(head)
}

/// `catalog.PersonalCollectionFilter` for a member list.
async fn owner_scoped(s: &Stack, r: &Request, owner: &str) -> Result<AccessFilter, ()> {
    let viewer = profile(r);
    let access = access_of(r);
    if trim_space(owner).is_empty() {
        return Err(());
    }
    if owner == viewer {
        return Ok(access);
    }
    let id = user_of(r);
    if id <= 0 {
        return Err(());
    }
    let input = ResolveInput {
        user_id: i32::try_from(id).map_err(|_| ())?,
        profile_id: owner.to_owned(),
        skip_pin_verification: true,
        content_access_only: true,
        ..Default::default()
    };
    let scope = s
        .viewer
        .resolve(&input, &request_id_of(r))
        .await
        .map_err(|_| ())?;
    Ok(access.intersect_owner(&scope))
}

#[derive(Serialize)]
struct V1Member {
    collection_id: String,
    media_item_id: String,
    position: i32,
    added_at: String,
}

#[derive(Serialize)]
struct V1Members {
    items: Vec<V1Member>,
}

/// `ListPersonalCollectionItems`.
async fn list_members(s: &Stack, r: &Request) -> Result<V1Members, ApiError> {
    let id = r.url_param("id").to_owned();
    if id.is_empty() {
        return Err(api(400, "bad_request", "Collection ID is required"));
    }
    let failed = || api(500, "internal_error", "Failed to list collection items");
    let head = head_of(s, r, &id, false).await?;
    let mut items = store::list_items(&s.pool, user(r), &id)
        .await
        .map_err(|_| failed())?;
    if !items.is_empty() {
        let filter = owner_scoped(s, r, &head.creator_profile_id)
            .await
            .map_err(|()| failed())?;
        let ids: Vec<String> = items.iter().map(|i| i.media_item_id.clone()).collect();
        let visible = visible_items(&s.pool, &ids, &filter)
            .await
            .map_err(|_| failed())?;
        items.retain(|i| visible.contains_key(&i.media_item_id));
    }
    Ok(V1Members {
        items: items
            .into_iter()
            .map(|i| V1Member {
                collection_id: i.collection_id,
                media_item_id: i.media_item_id,
                position: i.position,
                added_at: i.added_at,
            })
            .collect(),
    })
}

/// A store failure on an order write, as the seams report it.
enum OrderFailure {
    Stale,
    Api(ApiError),
}

/// `ReorderPersonalCollections`.
async fn reorder_own(
    s: &Stack,
    r: &Request,
    ids: &[String],
    expected: Option<i64>,
) -> Result<(), OrderFailure> {
    store::reorder_collections(&s.pool, user(r), &profile(r), ids, expected)
        .await
        .map_err(|e| match e {
            MutationError::RevisionMismatch => OrderFailure::Stale,
            MutationError::OrderedMismatch => OrderFailure::Api(field_error(
                "ordered_ids",
                "ordered_ids must name each of your own collections exactly once",
            )),
            MutationError::Duplicates => OrderFailure::Api(field_error(
                "ordered_ids",
                "ordered_ids contains duplicates",
            )),
            MutationError::Db(_) => {
                OrderFailure::Api(api(500, "internal_error", "Failed to reorder collections"))
            }
        })
}

/// `requireManualCollection`.
async fn require_manual(s: &Stack, r: &Request) -> Result<String, ApiError> {
    let id = r.url_param("id").to_owned();
    if id.is_empty() {
        return Err(api(400, "bad_request", "Collection ID is required"));
    }
    match store::library_collection_kind(&s.pool, &id).await {
        Ok(Some((kind, _))) if kind == MANUAL => Ok(id),
        Ok(Some(_)) => Err(admin_not_manual()),
        Ok(None) => Err(not_found()),
        Err(_) => Err(api(500, "internal_error", "Failed to load collection")),
    }
}

fn admin_not_manual() -> ApiError {
    api(
        409,
        "collection_not_manual",
        "Only manual collections support manual items",
    )
}

/// `adminManualCollection`: the collection's libraries.
async fn admin_manual(s: &Stack, id: &str) -> Result<Vec<i32>, Problem> {
    match store::library_collection_kind(&s.pool, id).await {
        Ok(Some((kind, libraries))) if kind == MANUAL => Ok(libraries),
        Ok(Some(_)) => Err(problem_of(&admin_not_manual())),
        Ok(None) => Err(admin_gone()),
        Err(_) => Err(internal()),
    }
}

fn admin_gone() -> Problem {
    Problem::new(problem_type("not_found"), "Collection or group not found.")
}

/// `adminCollectionError` for a membership write.
fn admin_member_problem(e: &store::LibraryMemberError) -> Problem {
    use store::LibraryMemberError as E;
    match e {
        E::NotManual => Problem::new(
            problem_type("conflict"),
            "Only manual collections support manual items.",
        ),
        E::ItemNotFound => Problem::new(
            problem_type("not_found"),
            "Item not found in collection libraries.",
        ),
        E::OrderedMismatch => Problem::new(
            problem_type("validation_failed"),
            "ordered_ids must include every current entry exactly once.",
        ),
        E::NotFound => admin_gone(),
        E::Duplicates | E::Db(_) => internal(),
    }
}

/// `AddAdminCollectionItem`.
async fn admin_add_member(s: &Stack, r: &Request, position: i64) -> Result<(), Problem> {
    let (id, item) = (
        r.url_param("id").to_owned(),
        r.url_param("item_id").to_owned(),
    );
    let libraries = admin_manual(s, &id).await?;
    let filter = AccessFilter {
        allowed: Some(libraries),
        ..Default::default()
    };
    let visible = visible_items(&s.pool, std::slice::from_ref(&item), &filter)
        .await
        .map_err(|_| internal())?;
    if visible.is_empty() {
        return Err(problem_of(&api(
            404,
            "not_found",
            "Item not found in collection libraries",
        )));
    }
    store::library_add_item_if_absent(&s.pool, &id, &item, AnyInt(position))
        .await
        .map_err(|e| admin_member_problem(&e))
}

/// `RemoveAdminCollectionItem`.
async fn admin_remove_member(s: &Stack, r: &Request) -> Result<(), Problem> {
    let (id, item) = (
        r.url_param("id").to_owned(),
        r.url_param("item_id").to_owned(),
    );
    admin_manual(s, &id).await?;
    store::library_remove_manual_item(&s.pool, &id, &item)
        .await
        .map_err(|e| admin_member_problem(&e))
}

/// `collectionFeatureError(store, "groups")`.
fn groups_unsupported() -> ApiError {
    api(
        501,
        "unsupported",
        "The acting account does not support collection groups",
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Order {
    ordered_ids: Option<Vec<String>>,
    group_id: Option<String>,
}

/// `collectionItemRequest`, and the v2 add body.
#[derive(Deserialize, Default)]
#[serde(default)]
struct ItemPosition {
    position: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct GroupCreate {
    name: String,
    slug: String,
    default_sort_mode: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct GroupUpdate {
    name: Option<String>,
    slug: Option<String>,
    default_sort_mode: Option<String>,
}

/// `json.NewDecoder(r.Body).Decode`.
async fn decode_v1<T: serde::de::DeserializeOwned>(r: &mut Request) -> Option<T> {
    let (bytes, _) = r.read_all().await;
    let mut stream = Decoder::new().stream(&bytes[..]);
    stream.decode::<T>().ok()
}

/// `collectionProblem`.
fn problem_of(e: &ApiError) -> Problem {
    if !e.field.is_empty() {
        return validation(&format!("body.{}", e.field), &e.message);
    }
    match e.status {
        400 => validation("body", &e.message),
        501 => Problem::new(problem_type("capability_unsupported"), &e.message),
        503 => Problem::new(problem_type("dependency_unavailable"), &e.message),
        _ => service_problem(e),
    }
}

fn editor_tag(r: &Request, kind: &str, id: &str, revision: i64) -> EntityTag {
    let scope = format!(
        "collections:{kind}:{}:{}:{}",
        user_of(r),
        profile(r),
        viewer_digest(r)
    );
    render_etag(scope.as_bytes(), id.as_bytes(), revision)
}

/// `PersonalCollectionItemsOrderEditor`.
async fn items_order(
    s: &Stack,
    r: &Request,
    id: &str,
) -> Result<(Vec<String>, bool, i64), ApiError> {
    let changed = || {
        api(
            409,
            "collection_changed",
            "The collection changed; restart from the first page",
        )
    };
    let failed = || api(500, "internal_error", "Failed to load collection items");
    let head = head_of(s, r, id, true).await?;
    if head.collection_type != MANUAL {
        return Err(api(
            400,
            "bad_request",
            "Only manual collections have an editable item order",
        ));
    }
    let page = store::first_page(&s.pool, user(r), id, 200)
        .await
        .map_err(|_| failed())?
        .ok_or_else(not_found)?;
    head_of(s, r, id, true).await?;
    let revision = store::revision(&s.pool, user(r), id)
        .await
        .map_err(|_| failed())?
        .ok_or_else(not_found)?;
    if revision != page.revision {
        return Err(changed());
    }
    let ids: Vec<String> = page.items.iter().map(|i| i.media_item_id.clone()).collect();
    if !ids.is_empty() {
        let visible = visible_items(&s.pool, &ids, &access_of(r))
            .await
            .map_err(|_| api(500, "internal_error", "Failed to validate collection items"))?;
        if visible.len() != ids.len() {
            return Err(api(
                404,
                "not_found",
                "The complete collection order is not accessible",
            ));
        }
    }
    let after = store::revision(&s.pool, user(r), id)
        .await
        .map_err(|_| failed())?
        .ok_or_else(not_found)?;
    if after != page.revision {
        return Err(changed());
    }
    Ok((ids, page.has_more, revision))
}

/// `PersonalCollectionOrderEditor`.
async fn own_order(s: &Stack, r: &Request) -> Result<(Vec<String>, i64), ApiError> {
    let failed = || api(500, "internal_error", "Failed to list collections");
    let revision = store::order_revision(&s.pool, user(r))
        .await
        .map_err(|_| failed())?;
    let ids = store::own_order(&s.pool, user(r), &profile(r))
        .await
        .map_err(|_| failed())?;
    let after = store::order_revision(&s.pool, user(r))
        .await
        .map_err(|_| failed())?;
    if after != revision {
        return Err(api(
            409,
            "collection_changed",
            "The collection changed; restart from the first page",
        ));
    }
    Ok((ids, revision))
}

fn header_text(r: &Request, name: &str) -> String {
    String::from_utf8_lossy(r.header.get(name)).into_owned()
}

/// `collectionGuard`.
fn guard(r: &Request, tag: &EntityTag, revision: i64) -> Result<i64, Problem> {
    let if_match = header_text(r, "If-Match");
    if let Some(p) =
        evaluate_guarded_preconditions(&if_match, &header_text(r, "If-None-Match"), tag)
    {
        return Err(p);
    }
    Ok(if if_match == "*" { -1 } else { revision })
}

#[derive(Serialize)]
struct OrderBody {
    ordered_ids: Vec<String>,
}

#[derive(Serialize)]
struct ItemsOrderBody {
    ordered_ids: Vec<String>,
    has_more: bool,
}

async fn write_own_order(s: &Stack, w: &mut dyn ResponseWriter, r: &Request) {
    match own_order(s, r).await {
        Ok((ordered_ids, revision)) => {
            w.header()
                .set("ETag", editor_tag(r, "order", "", revision).to_wire());
            write_v2_json_status(w, 200, &OrderBody { ordered_ids }).await;
        }
        Err(e) => write_problem(w, r, problem_of(&e)).await,
    }
}

async fn write_items_order(s: &Stack, w: &mut dyn ResponseWriter, r: &Request) {
    let id = r.url_param("id").to_owned();
    match items_order(s, r, &id).await {
        Ok((ordered_ids, has_more, revision)) => {
            w.header().set(
                "ETag",
                editor_tag(r, "items-order", &id, revision).to_wire(),
            );
            write_v2_json_status(
                w,
                200,
                &ItemsOrderBody {
                    ordered_ids,
                    has_more,
                },
            )
            .await;
        }
        Err(e) => write_problem(w, r, problem_of(&e)).await,
    }
}

fn group_scope_problem(location: &str) -> Problem {
    validation(
        location,
        "Personal collection groups are not supported; omit group_id.",
    )
}

#[derive(Serialize)]
struct V1Capabilities {
    display_filter_fields: [&'static str; 2],
    display_filter_presets: Presets,
    collection_default_sort: bool,
    collection_sort_preferences: bool,
    effective_collection_sort: bool,
    sort_preference_kinds: [&'static str; 4],
}

#[derive(Serialize, Clone)]
struct Presets {
    watched: [&'static str; 3],
    media: [&'static str; 3],
}

const PRESETS: Presets = Presets {
    watched: ["all", "watched", "unwatched"],
    media: ["all", "movie", "series"],
};

#[derive(Serialize)]
struct ScheduleZone {
    utc_offset: String,
    abbreviation: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
}

/// `scheduleTimeZone`: the zone this node evaluates cron schedules in.
fn schedule_zone() -> ScheduleZone {
    // SAFETY: localtime_r only writes the struct it is handed.
    let (offset, abbreviation) = unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        let abbreviation = if tm.tm_zone.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(tm.tm_zone)
                .to_string_lossy()
                .into_owned()
        };
        (tm.tm_gmtoff, abbreviation)
    };
    let (sign, minutes) = if offset < 0 {
        ('-', -offset / 60)
    } else {
        ('+', offset / 60)
    };
    let name = std::env::var("TZ").unwrap_or_default();
    ScheduleZone {
        utc_offset: format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60),
        abbreviation,
        name: if name.starts_with('/') {
            String::new()
        } else {
            name
        },
    }
}

#[derive(Serialize)]
struct V2Capabilities<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    groups: bool,
    login_sharing: bool,
    imports: bool,
    import_sources: [&'a str; 3],
    artwork: bool,
    item_reorder: bool,
    display_filter_fields: [&'a str; 2],
    display_filter_presets: Presets,
    collection_default_sort: bool,
    collection_sort_preferences: bool,
    effective_collection_sort: bool,
    sort_preference_kinds: [&'a str; 4],
    create_description: bool,
    mdblist_search: bool,
    schedule_time_zone: ScheduleZone,
    sync_schedule_editable: bool,
    contains_item: bool,
    preview_posters: bool,
    poster_collages: bool,
}

async fn mdblist_configured(s: &Stack) -> bool {
    s.pool
        .query(
            "SELECT 1 FROM server_settings WHERE key = 'mdblist.api_key' AND value <> ''",
            &[],
        )
        .await
        .is_ok_and(|rows| !rows.is_empty())
}

fn mount_v1(stack: &Arc<Stack>, api_mux: &Mux) {
    let sub = Mux::new();
    sub.use_middleware([stack.v1_group(V1_PROFILE)]);
    let p = "/api/v1/collections/capabilities";
    sub.get(
        "/capabilities",
        stack.v1(
            p,
            &[],
            route!(stack, |_s, w, _r| {
                write_v1_json(
                    w,
                    200,
                    &V1Capabilities {
                        display_filter_fields: ["type", "watched"],
                        display_filter_presets: PRESETS,
                        collection_default_sort: true,
                        collection_sort_preferences: true,
                        effective_collection_sort: true,
                        sort_preference_kinds: SORT_KINDS,
                    },
                )
                .await
            }),
        ),
    );
    sub.get(
        "/templates",
        stack.v1(
            "/api/v1/collections/templates",
            &[],
            route!(stack, |_s, w, _r| { write_raw(w, V1_CATALOG).await }),
        ),
    );
    let p = "/api/v1/collections/sort-preference";
    sub.put(
        "/sort-preference",
        stack.v1(
            p,
            &[],
            route!(stack, |s, w, r| {
                let Some(req) = decode_v1::<SortRequest>(r).await else {
                    return super::auth::write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Invalid request body",
                    )
                    .await;
                };
                match set_sort(&s, r, &req).await {
                    Ok(view) => write_v1_json(w, 200, &view).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    sub.delete(
        "/sort-preference",
        stack.v1(
            p,
            &[],
            route!(stack, |s, w, r| {
                let (query, _) =
                    silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
                let first = |k: &str| {
                    query
                        .get(k)
                        .and_then(|v| v.first().cloned())
                        .unwrap_or_default()
                };
                match clear_sort(&s, r, &first("collection_kind"), &first("collection_id")).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    sub.post(
        "/groups",
        stack.v1(
            "/api/v1/collections/groups",
            &[],
            route!(stack, |_s, w, r| {
                let Some(req) = decode_v1::<GroupCreate>(r).await else {
                    return super::auth::write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Invalid request body",
                    )
                    .await;
                };
                if trim_space(&req.name).is_empty() {
                    return write_api(w, &field_error("name", "name is required")).await;
                }
                write_api(w, &groups_unsupported()).await
            }),
        ),
    );
    sub.put(
        "/groups/order",
        stack.v1(
            "/api/v1/collections/groups/order",
            &[],
            route!(stack, |_s, w, r| {
                if decode_v1::<Order>(r).await.is_none() {
                    return super::auth::write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Invalid request body",
                    )
                    .await;
                }
                write_api(w, &groups_unsupported()).await
            }),
        ),
    );
    let p = "/api/v1/collections/groups/{id}";
    sub.put(
        "/groups/{id}",
        stack.v1(
            p,
            &[],
            route!(stack, |_s, w, r| {
                let Some(req) = decode_v1::<GroupUpdate>(r).await else {
                    return super::auth::write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Invalid request body",
                    )
                    .await;
                };
                if req.name.is_some_and(|n| trim_space(&n).is_empty()) {
                    return write_api(w, &field_error("name", "name cannot be empty")).await;
                }
                write_api(w, &groups_unsupported()).await
            }),
        ),
    );
    sub.delete(
        "/groups/{id}",
        stack.v1(
            p,
            &[],
            route!(stack, |_s, w, _r| {
                write_api(w, &groups_unsupported()).await
            }),
        ),
    );
    sub.put(
        "/order",
        stack.v1(
            "/api/v1/collections/order",
            &[],
            route!(stack, |s, w, r| {
                let Some(req) = decode_v1::<Order>(r).await else {
                    return super::auth::write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Invalid request body",
                    )
                    .await;
                };
                if req.group_id.is_some() {
                    return write_api(
                        w,
                        &field_error(
                            "group_id",
                            "Personal collection groups are not supported; omit group_id",
                        ),
                    )
                    .await;
                }
                match reorder_own(&s, r, &req.ordered_ids.unwrap_or_default(), None).await {
                    Ok(()) => w.write_header(204).await,
                    Err(OrderFailure::Api(e)) => write_api(w, &e).await,
                    Err(OrderFailure::Stale) => w.write_header(500).await,
                }
            }),
        ),
    );
    sub.get(
        "/{id}/items",
        stack.v1(
            "/api/v1/collections/{id}/items",
            &[],
            route!(stack, |s, w, r| {
                match list_members(&s, r).await {
                    Ok(view) => write_v1_json(w, 200, &view).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    api_mux.mount("/api/v1/collections", sub);
}

/// The admin subrouter rows, registered from `api_keys::mount`'s admin mux.
pub fn mount_v1_admin(stack: &Arc<Stack>, admin: &Mux) {
    let sub = Mux::new();
    sub.use_middleware([stack.v1_group(V1_ACTING_ADMIN)]);
    sub.get(
        "/templates",
        stack.v1(
            "/api/v1/admin/collections/templates",
            &[],
            route!(stack, |_s, w, _r| { write_raw(w, V1_CATALOG).await }),
        ),
    );
    sub.get(
        "/template-bundles",
        stack.v1(
            "/api/v1/admin/collections/template-bundles",
            &[],
            route!(stack, |_s, w, _r| { write_raw(w, V1_BUNDLES).await }),
        ),
    );
    sub.put(
        "/{id}/items/order",
        stack.v1(
            "/api/v1/admin/collections/{id}/items/order",
            &[],
            route!(stack, |s, w, r| {
                let id = match require_manual(&s, r).await {
                    Ok(id) => id,
                    Err(e) => return write_api(w, &e).await,
                };
                let Some(req) = decode_v1::<Order>(r).await else {
                    return write_api(w, &api(400, "bad_request", "Invalid request body")).await;
                };
                let ids = req.ordered_ids.unwrap_or_default();
                match store::library_reorder_items(&s.pool, &id, &ids).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_api(w, &api(400, "bad_request", e.message())).await,
                }
            }),
        ),
    );
    let p = "/api/v1/admin/collections/{id}/items/{item_id}";
    sub.put(
        "/{id}/items/{item_id}",
        stack.v1(
            p,
            &[],
            route!(stack, |s, w, r| {
                let id = match require_manual(&s, r).await {
                    Ok(id) => id,
                    Err(e) => return write_api(w, &e).await,
                };
                let item = r.url_param("item_id").to_owned();
                if item.is_empty() {
                    return write_api(w, &api(400, "bad_request", "item ID is required")).await;
                }
                let (bytes, _) = r.read_all().await;
                let mut stream = Decoder::new().stream(&bytes[..]);
                let position = match stream.decode::<ItemPosition>() {
                    Ok(b) => b.position,
                    Err(e) if e.is_eof() => 0,
                    Err(_) => {
                        return write_api(w, &api(400, "bad_request", "Invalid request body"))
                            .await;
                    }
                };
                match store::library_add_item(&s.pool, &id, &item, AnyInt(position)).await {
                    Ok(()) => w.write_header(204).await,
                    Err(_) => {
                        write_api(
                            w,
                            &api(500, "internal_error", "Failed to add collection item"),
                        )
                        .await
                    }
                }
            }),
        ),
    );
    sub.delete(
        "/{id}/items/{item_id}",
        stack.v1(
            p,
            &[],
            route!(stack, |s, w, r| {
                let id = match require_manual(&s, r).await {
                    Ok(id) => id,
                    Err(e) => return write_api(w, &e).await,
                };
                let item = r.url_param("item_id").to_owned();
                if item.is_empty() {
                    return write_api(w, &api(400, "bad_request", "item ID is required")).await;
                }
                match store::library_remove_item(&s.pool, &id, &item).await {
                    Ok(()) => w.write_header(204).await,
                    Err(_) => {
                        write_api(
                            w,
                            &api(500, "internal_error", "Failed to remove collection item"),
                        )
                        .await
                    }
                }
            }),
        ),
    );
    admin.mount("/collections", sub);
    let groups = Mux::new();
    groups.use_middleware([stack.v1_group(V1_ACTING_ADMIN)]);
    groups.get(
        "/",
        stack.v1(
            "/api/v1/admin/libraries/{libraryID}/collection-groups/",
            &[],
            route!(stack, |s, w, r| {
                let Some(id) = super::settings::atoi(r.url_param("libraryID")).filter(|n| *n > 0)
                else {
                    return super::auth::write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "invalid library id",
                    )
                    .await;
                };
                match list_admin_groups(&s, id).await {
                    Ok((groups, ungrouped_sort_order)) => {
                        write_v1_json(
                            w,
                            200,
                            &V1Groups {
                                groups,
                                ungrouped_sort_order,
                            },
                        )
                        .await
                    }
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
    admin.mount("/libraries/{libraryID}/collection-groups", groups);
}

#[derive(Serialize)]
struct V1Group {
    id: String,
    library_id: i32,
    name: String,
    slug: String,
    kind: String,
    default_sort_mode: String,
    sort_order: i32,
}

impl From<store::AdminGroup> for V1Group {
    fn from(g: store::AdminGroup) -> Self {
        Self {
            id: g.id,
            library_id: g.library_id,
            name: g.name,
            slug: g.slug,
            kind: g.kind,
            default_sort_mode: g.default_sort_mode,
            sort_order: g.sort_order,
        }
    }
}

#[derive(Serialize)]
struct V1Groups {
    groups: Vec<V1Group>,
    ungrouped_sort_order: i32,
}

#[derive(Serialize)]
struct V2Group {
    id: String,
    library_id: String,
    name: String,
    slug: String,
    kind: String,
    default_sort_mode: String,
    sort_order: i32,
}

impl From<V1Group> for V2Group {
    fn from(g: V1Group) -> Self {
        Self {
            id: g.id,
            library_id: g.library_id.to_string(),
            name: g.name,
            slug: g.slug,
            kind: g.kind,
            default_sort_mode: g.default_sort_mode,
            sort_order: g.sort_order,
        }
    }
}

#[derive(Serialize)]
struct V2Groups {
    items: Vec<V2Group>,
    ungrouped_sort_order: i32,
}

#[derive(Serialize)]
struct V2AdminOrder {
    library_id: String,
    group_id: Option<String>,
    ordered_ids: Vec<String>,
    has_more: bool,
}

/// `ListAdminCollectionGroups`.
async fn list_admin_groups(s: &Stack, library: i64) -> Result<(Vec<V1Group>, i32), ApiError> {
    let groups = store::admin_groups(&s.pool, AnyInt(library))
        .await
        .map_err(|_| api(500, "internal_error", "Failed to load groups"))?;
    let order = store::ungrouped_sort_order(&s.pool, AnyInt(library))
        .await
        .ok()
        .flatten()
        .unwrap_or(9999);
    Ok((groups.into_iter().map(V1Group::from).collect(), order))
}

/// `libraryID`.
fn v2_library(r: &Request) -> Result<i64, Problem> {
    super::settings::int_of_id(r.url_param("library_id"))
        .ok_or_else(|| Problem::new(problem_type("not_found"), "No library has that identifier."))
}

fn group_gone() -> Problem {
    Problem::new(problem_type("not_found"), "Collection or group not found.")
}

fn admin_tag(r: &Request, kind: &str, id: &str, revision: i64) -> EntityTag {
    editor_tag(r, &format!("admin-{kind}"), id, revision)
}

/// `AdminCollectionGroupOrder`.
async fn admin_group_order(s: &Stack, library: i64) -> Result<(Vec<String>, i64), Problem> {
    let lib = AnyInt(library);
    let revision = store::library_order_revision(&s.pool, lib)
        .await
        .map_err(|_| internal())?
        .ok_or_else(group_gone)?;
    let groups = store::admin_groups(&s.pool, lib)
        .await
        .map_err(|_| internal())?;
    let ungrouped = store::ungrouped_sort_order(&s.pool, lib)
        .await
        .map_err(|_| internal())?
        .ok_or_else(internal)?;
    let mut entries: Vec<(i32, String)> =
        groups.into_iter().map(|g| (g.sort_order, g.id)).collect();
    entries.push((ungrouped, "ungrouped".to_owned()));
    entries.sort();
    let after = store::library_order_revision(&s.pool, lib)
        .await
        .map_err(|_| internal())?
        .ok_or_else(group_gone)?;
    if after != revision {
        return Err(Problem::new(
            problem_type("conflict"),
            "The collection changed during the read; fetch its current state and retry.",
        ));
    }
    Ok((entries.into_iter().map(|(_, id)| id).collect(), revision))
}

fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let p = "/api/v2/collections/capabilities";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let mdblist_search = mdblist_configured(&s).await;
                write_capability(w, r, "getCollectionCapabilities", |revision| {
                    capability_json(&V2Capabilities {
                        revision,
                        state: "available",
                        allowed: true,
                        groups: false,
                        login_sharing: true,
                        imports: true,
                        import_sources: ["mdblist", "tmdb", "tmdb_list"],
                        artwork: true,
                        item_reorder: true,
                        display_filter_fields: ["type", "watched"],
                        display_filter_presets: PRESETS,
                        collection_default_sort: true,
                        collection_sort_preferences: true,
                        effective_collection_sort: true,
                        sort_preference_kinds: SORT_KINDS,
                        create_description: true,
                        mdblist_search,
                        schedule_time_zone: schedule_zone(),
                        sync_schedule_editable: true,
                        contains_item: true,
                        preview_posters: true,
                        poster_collages: true,
                    })
                })
                .await
            }),
        ),
    );
    let p = "/api/v2/collections/templates";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |_s, w, _r| { write_raw(w, V2_CATALOG).await }),
        ),
    );
    let p = "/api/v2/admin/collections/templates";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |_s, w, _r| { write_raw(w, V2_CATALOG).await }),
        ),
    );
    let p = "/api/v2/admin/collections/template-bundles";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |_s, w, _r| { write_raw(w, V2_BUNDLES).await }),
        ),
    );
    let p = "/api/v2/admin/libraries/{library_id}/collection-groups";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let library = match v2_library(r) {
                    Ok(v) => v,
                    Err(p) => return write_problem(w, r, p).await,
                };
                match list_admin_groups(&s, library).await {
                    Ok((groups, ungrouped_sort_order)) => {
                        write_v2_json_status(
                            w,
                            200,
                            &V2Groups {
                                items: groups.into_iter().map(V2Group::from).collect(),
                                ungrouped_sort_order,
                            },
                        )
                        .await
                    }
                    Err(e) => write_problem(w, r, problem_of(&e)).await,
                }
            }),
        ),
    );
    let p = "/api/v2/admin/libraries/{library_id}/collection-groups/order";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let library = match v2_library(r) {
                    Ok(v) => v,
                    Err(p) => return write_problem(w, r, p).await,
                };
                match admin_group_order(&s, library).await {
                    Ok((ordered_ids, revision)) => {
                        let tag = admin_tag(r, "groups-order", &library.to_string(), revision);
                        w.header().set("ETag", tag.to_wire());
                        write_v2_json_status(
                            w,
                            200,
                            &V2AdminOrder {
                                library_id: library.to_string(),
                                group_id: None,
                                ordered_ids,
                                has_more: false,
                            },
                        )
                        .await
                    }
                    Err(p) => write_problem(w, r, p).await,
                }
            }),
        ),
    );
    let p = "/api/v2/admin/collection-groups/{id}";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let id = r.url_param("id").to_owned();
                let group = match store::admin_group_by_id(&s.pool, &id).await {
                    Ok(Some(g)) => g,
                    Ok(None) => return write_problem(w, r, group_gone()).await,
                    Err(_) => return write_problem(w, r, internal()).await,
                };
                let lib = AnyInt(i64::from(group.library_id));
                let revision = match store::library_order_revision(&s.pool, lib).await {
                    Ok(Some(v)) => v,
                    Ok(None) => return write_problem(w, r, group_gone()).await,
                    Err(_) => return write_problem(w, r, internal()).await,
                };
                w.header()
                    .set("ETag", admin_tag(r, "group", &id, revision).to_wire());
                write_v2_json_status(w, 200, &V2Group::from(V1Group::from(group))).await
            }),
        ),
    );
    let p = "/api/v2/collections/sort-preference";
    v2.put(
        p,
        stack.v2_steps(
            p,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let Ok(req) = silo_gocompat::json::unmarshal::<SortRequest>(&raw_body(r)) else {
                    return write_problem(w, r, internal()).await;
                };
                match set_sort(&s, r, &req).await {
                    Ok(view) => write_v2_json_status(w, 200, &V2SortView::of(view)).await,
                    Err(e) => write_problem(w, r, problem_of(&e)).await,
                }
            }),
        ),
    );
    v2.delete(
        p,
        stack.v2_steps(
            p,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (query, _) =
                    silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
                let first = |k: &str| {
                    query
                        .get(k)
                        .and_then(|v| v.first().cloned())
                        .unwrap_or_default()
                };
                match clear_sort(&s, r, &first("collection_kind"), &first("collection_id")).await {
                    Ok(()) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, problem_of(&e)).await,
                }
            }),
        ),
    );
    // Every group operation answers `capability_unsupported` once its input passes.
    let p = "/api/v2/collections/groups";
    v2.post(
        p,
        stack.v2_steps(
            p,
            V2_WRITE,
            route!(stack, |_s, w, r| {
                let req =
                    silo_gocompat::json::unmarshal::<GroupCreate>(&raw_body(r)).unwrap_or_default();
                let e = if trim_space(&req.name).is_empty() {
                    field_error("name", "name is required")
                } else {
                    groups_unsupported()
                };
                write_problem(w, r, problem_of(&e)).await
            }),
        ),
    );
    let p = "/api/v2/collections/groups/order";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |_s, w, r| {
                write_problem(w, r, problem_of(&groups_unsupported())).await
            }),
        ),
    );
    v2.put(
        p,
        stack.v2_steps(
            p,
            V2_WRITE,
            route!(stack, |_s, w, r| {
                write_problem(w, r, problem_of(&groups_unsupported())).await
            }),
        ),
    );
    let p = "/api/v2/collections/groups/{id}";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |_s, w, r| {
                write_problem(w, r, problem_of(&groups_unsupported())).await
            }),
        ),
    );
    v2.patch(
        p,
        stack.v2_steps(
            p,
            V2_WRITE,
            route!(stack, |_s, w, r| {
                if let Some(p) = super::huma::reject_nulls(&raw_body(r)) {
                    return write_problem(w, r, p).await;
                }
                write_problem(w, r, problem_of(&groups_unsupported())).await
            }),
        ),
    );
    v2.delete(
        p,
        stack.v2_steps(
            p,
            V2_WRITE,
            route!(stack, |_s, w, r| {
                write_problem(w, r, problem_of(&groups_unsupported())).await
            }),
        ),
    );
    let p = "/api/v2/collections/order";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let (query, _) =
                    silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
                if query
                    .get("group_id")
                    .and_then(|v| v.first())
                    .is_some_and(|g| !g.is_empty())
                {
                    return write_problem(w, r, group_scope_problem("query.group_id")).await;
                }
                write_own_order(&s, w, r).await
            }),
        ),
    );
    v2.put(
        p,
        stack.v2_steps(
            p,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let req = silo_gocompat::json::unmarshal::<Order>(&raw_body(r)).unwrap_or_default();
                if req.group_id.is_some() {
                    return write_problem(w, r, group_scope_problem("body.group_id")).await;
                }
                let (_, revision) = match own_order(&s, r).await {
                    Ok(v) => v,
                    Err(e) => return write_problem(w, r, problem_of(&e)).await,
                };
                let tag = editor_tag(r, "order", "", revision);
                let expected = match guard(r, &tag, revision) {
                    Ok(v) => v,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let ids = req.ordered_ids.unwrap_or_default();
                match reorder_own(&s, r, &ids, Some(expected)).await {
                    Ok(()) => write_own_order(&s, w, r).await,
                    Err(OrderFailure::Api(e)) => write_problem(w, r, problem_of(&e)).await,
                    Err(OrderFailure::Stale) => {
                        let current = own_order(&s, r)
                            .await
                            .map(|(_, rev)| editor_tag(r, "order", "", rev));
                        write_stale(w, r, current).await
                    }
                }
            }),
        ),
    );
    let p = "/api/v2/collections/{id}/items/order";
    v2.get(
        p,
        stack.v2(
            p,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| { write_items_order(&s, w, r).await }),
        ),
    );
    let p = "/api/v2/admin/collections/{id}/items/{item_id}";
    v2.put(
        p,
        stack.v2_steps(
            p,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let position = silo_gocompat::json::unmarshal::<ItemPosition>(&raw_body(r))
                    .map_or(0, |b| b.position);
                match admin_add_member(&s, r, position).await {
                    Ok(()) => w.write_header(204).await,
                    Err(p) => write_problem(w, r, p).await,
                }
            }),
        ),
    );
    v2.delete(
        p,
        stack.v2_steps(
            p,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                match admin_remove_member(&s, r).await {
                    Ok(()) => w.write_header(204).await,
                    Err(p) => write_problem(w, r, p).await,
                }
            }),
        ),
    );
}

/// `guardedCollectionError` on a revision mismatch.
async fn write_stale(
    w: &mut dyn ResponseWriter,
    r: &Request,
    current: Result<EntityTag, ApiError>,
) {
    match current {
        Ok(tag) => {
            let current = silo_api_v2::precondition::Tag {
                opaque: tag.opaque.into_bytes(),
                weak: tag.weak,
            };
            write_problem(w, r, stale_version_problem(Some(&current))).await
        }
        Err(e) => write_problem(w, r, problem_of(&e)).await,
    }
}

#[derive(Serialize)]
struct V2SortView {
    collection_kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    collection_id: String,
    field: String,
    order: String,
}

impl V2SortView {
    fn of(v: V1SortView) -> Self {
        Self {
            collection_kind: v.collection_kind,
            collection_id: v.collection_id,
            field: v.field,
            order: v.order,
        }
    }
}

pub fn mount(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    mount_v1(stack, api_mux);
    mount_v2(stack, v2);
}
