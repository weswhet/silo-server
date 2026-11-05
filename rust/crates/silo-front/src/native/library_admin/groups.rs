//! Native database-only group writes. The Go services publish no event and touch no sections cache.
use super::*;
use crate::native::chain::{Step, write_v2_json_status};
use silo_api_v2::precondition::{Tag, evaluate_guarded_preconditions, stale_version_problem};
use silo_core::apiv2::EntityTag;
use silo_store::library_admin_reads::groups as store;

const ADMIN_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
];
use crate::native::personal::raw_body;

#[derive(Default, Deserialize)]
#[serde(default)]
struct Create {
    name: String,
    slug: Option<String>,
    default_sort_mode: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Order {
    ordered_ids: Option<Vec<String>>,
}

fn library(r: &Request) -> Result<i32, Problem> {
    let id = silo_api_v2::wire::Id(r.url_param("library_id").into())
        .to_int()
        .ok_or_else(|| {
            Problem::new(
                silo_api_v2::problem::type_for_status(404),
                "No library has that identifier.",
            )
        })?;
    i32::try_from(id).map_err(|_| internal_problem())
}
fn not_found() -> Problem {
    Problem::new(
        silo_api_v2::problem::type_for_status(404),
        "Collection or group not found.",
    )
}
fn tag(r: &Request, library: i32, revision: i64) -> EntityTag {
    let user = get_claims(r).expect("authenticated route").user_id;
    let scope = format!(
        "collections:admin-groups-order:{}:{}:{}",
        user,
        get_profile_id(r),
        viewer_digest(r)
    );
    silo_core::apiv2::render_etag(scope.as_bytes(), library.to_string().as_bytes(), revision)
}
async fn order(
    s: &Stack,
    r: &Request,
    library: i32,
) -> Result<(AdminCollectionOrder, EntityTag, i64), Problem> {
    let revision = reads::collection_order_revision(&s.pool, library)
        .await
        .map_err(|_| internal_problem())?
        .ok_or_else(not_found)?;
    let groups = reads::list_collection_groups(&s.pool, library)
        .await
        .map_err(|_| internal_problem())?;
    let ungrouped = reads::ungrouped_sort_order(&s.pool, library)
        .await
        .map_err(|_| internal_problem())?;
    let after = reads::collection_order_revision(&s.pool, library)
        .await
        .map_err(|_| internal_problem())?
        .ok_or_else(not_found)?;
    if revision != after {
        return Err(Problem::new(
            silo_api_v2::problem::type_for_status(409),
            "The collection changed during the read; fetch its current editor again.",
        ));
    }
    let mut positions: Vec<_> = groups.into_iter().map(|g| (g.sort_order, g.id)).collect();
    positions.push((ungrouped, "ungrouped".into()));
    positions.sort();
    Ok((
        AdminCollectionOrder {
            library_id: library.to_string(),
            group_id: None,
            ordered_ids: positions.into_iter().map(|(_, id)| id).collect(),
            has_more: false,
        },
        tag(r, library, revision),
        revision,
    ))
}
fn slugify(value: &str) -> String {
    let value = silo_gocompat::strings::to_lower(trim_space(value));
    let mut out = String::new();
    let mut dash = false;
    for c in value.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            dash = false;
        } else if matches!(c, ' ' | '-' | '_') && !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    let out = out.trim_matches('-');
    if out.is_empty() {
        "group".into()
    } else {
        out.into()
    }
}
async fn create(s: &Stack, r: &Request) -> Result<AdminCollectionGroup, Problem> {
    if let Some(p) = crate::native::huma::reject_nulls(&raw_body(r)) {
        return Err(p);
    }
    let library = library(r)?;
    // Huma has already checked unknown/required fields, length, enum, and nullability.
    let request = silo_gocompat::json::unmarshal::<Create>(&raw_body(r)).unwrap_or_default();
    if request.name.is_empty() {
        return Err(crate::native::personal::validation("body", "name required"));
    }
    let slug = request
        .slug
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| slugify(&request.name));
    let sort = request
        .default_sort_mode
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "manual".into());
    let lease = s
        .route_ids
        .get_or_try_init(|| {
            silo_runtime::idgen_lease::Lease::start((*s.pool).clone(), "silo-front")
        })
        .await
        .map_err(|_| internal_problem())?;
    let id = lease
        .generator()
        .current()
        .await
        .next_id()
        .map_err(|_| internal_problem())?;
    let group = store::create(&s.pool, &id, library, &request.name, &slug, &sort)
        .await
        .map_err(|_| internal_problem())?;
    Ok(AdminCollectionGroup {
        id: group.id,
        library_id: group.library_id.to_string(),
        name: group.name,
        slug: group.slug,
        kind: group.kind,
        default_sort_mode: group.default_sort_mode,
        sort_order: group.sort_order,
    })
}
async fn reorder(s: &Stack, r: &Request) -> Result<(AdminCollectionOrder, EntityTag), Problem> {
    let library = library(r)?;
    let (_, current, revision) = order(s, r, library).await?;
    let if_match = String::from_utf8_lossy(r.header.get("If-Match"));
    let none = String::from_utf8_lossy(r.header.get("If-None-Match"));
    if let Some(p) = evaluate_guarded_preconditions(&if_match, &none, &current) {
        return Err(p);
    }
    let request = silo_gocompat::json::unmarshal::<Order>(&raw_body(r)).unwrap_or_default();
    let expected = if if_match == "*" { -1 } else { revision };
    match store::reorder(
        &s.pool,
        library,
        &request.ordered_ids.unwrap_or_default(),
        expected,
    )
    .await
    {
        Ok(()) => {}
        Err(store::MutationError::Stale) => {
            let (_, current, _) = order(s, r, library).await?;
            return Err(stale_version_problem(Some(&Tag::from(&current))));
        }
        Err(store::MutationError::NotFound) => return Err(not_found()),
        Err(store::MutationError::OrderedMismatch) => {
            return Err(Problem::new(
                silo_api_v2::problem::validation_failed(),
                "ordered_ids must include every current entry exactly once.",
            ));
        }
        Err(_) => return Err(internal_problem()),
    }
    let (body, tag, _) = order(s, r, library).await?;
    Ok((body, tag))
}
pub(super) fn mount(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/admin/libraries/{library_id}/collection-groups";
    let s = stack.clone();
    v2.post(
        path,
        stack.v2_steps(
            path,
            ADMIN_WRITE,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    match create(&s, r).await {
                        Ok(body) => {
                            w.header().set(
                                "Location",
                                format!("/api/v2/admin/collection-groups/{}", body.id),
                            );
                            write_v2_json_status(w, 201, &body).await;
                        }
                        Err(p) => write_problem(w, r, p).await,
                    }
                })
            }),
        ),
    );
    let path = "/api/v2/admin/libraries/{library_id}/collection-groups/order";
    let s = stack.clone();
    v2.put(
        path,
        stack.v2_steps(
            path,
            ADMIN_WRITE,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    match reorder(&s, r).await {
                        Ok((body, tag)) => {
                            w.header().set("ETag", tag.to_wire());
                            write_v2_json(w, &body).await;
                        }
                        Err(p) => write_problem(w, r, p).await,
                    }
                })
            }),
        ),
    );
}
