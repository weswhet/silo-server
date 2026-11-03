//! Catalog reads that do not render cards: the administrator's item files (`admin_split.go`,
//! `admin_item_files_service.go`, v2 `admin_catalog_split.go`) and the catalog capabilities.
//!
//! Browse, query, facets, item detail, seasons, episodes, versions, people, and search status stay on Go.

use std::sync::Arc;

use serde::Serialize;
use silo_api_v2::problem::{Problem, internal_error};
use silo_api_v2::wire::{Id, paginated};
use silo_core::apiv2::CursorScope;
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::json::omit_empty;
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_pg::{AnyInt, Pool};

use super::auth::write_v1_error;
use super::chain::{
    Stack, Step, V2Class, capability_json, problem_type, write_capability, write_problem,
    write_v1_json, write_v2_json,
};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/items/{id}/files"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/catalog/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/items/{id}/files"),
    NativeRow::new(ApiV2, "GET", "/api/v2/catalog/search/capabilities"),
];

/// Go serves search capabilities from its own provider, which Meilisearch replaces.
pub const SEARCH_CAPABILITIES: &str = "/api/v2/catalog/search/capabilities";

const V1_METADATA_ITEM: &[Step] = &[Step::MetadataCuration];
/// `adminCatalogItemsMaxContentIDs`.
const ITEM_LISTING_MAX_CONTENT_IDS: i64 = 200;

const LIST_V1_SQL: &str = r#"
		SELECT id, COALESCE(content_id, ''), media_folder_id, file_path,
		       COALESCE(canonical_root_path, ''),
		       COALESCE(observed_root_path, ''),
		       COALESCE(group_key_version, 1),
		       COALESCE(content_group_key, ''),
		       COALESCE(base_type, ''),
		       COALESCE(season_number, 0),
		       COALESCE(episode_number, 0),
		       COALESCE(episode_id, '')
		FROM media_files
		WHERE content_id = $1
		ORDER BY file_path ASC
	"#;
const LIST_V2_SQL: &str = "SELECT id,media_folder_id,file_path,COALESCE(observed_root_path,''),COALESCE(season_number,0),COALESCE(episode_number,0) FROM media_files WHERE content_id=$1 AND id>$2 ORDER BY id LIMIT $3";

/// `ItemRepository.GetByID`: every failure reads as not found.
async fn item_exists(pool: &Pool, id: &str) -> bool {
    pool.query("SELECT 1 FROM media_items WHERE content_id = $1", &[&id])
        .await
        .is_ok_and(|rows| !rows.is_empty())
}

#[derive(Serialize)]
struct V1File {
    id: i64,
    library_id: i64,
    file_path: String,
    observed_root_path: String,
    #[serde(skip_serializing_if = "omit_empty")]
    season_number: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    episode_number: i64,
}

#[derive(Serialize)]
struct V1Files {
    files: Vec<V1File>,
}

async fn v1_files(pool: &Pool, id: &str) -> Result<Vec<V1File>, silo_pg::Error> {
    let rows = pool.query(LIST_V1_SQL, &[&id]).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        out.push(V1File {
            id: row.try_get::<_, AnyInt>(0)?.0,
            library_id: row.try_get::<_, AnyInt>(2)?.0,
            file_path: row.try_get(3)?,
            observed_root_path: row.try_get(5)?,
            season_number: row.try_get::<_, AnyInt>(9)?.0,
            episode_number: row.try_get::<_, AnyInt>(10)?.0,
        });
    }
    Ok(out)
}

#[derive(Serialize)]
struct V2File {
    id: Id,
    library_id: Id,
    file_path: String,
    observed_root_path: String,
    #[serde(skip_serializing_if = "omit_empty")]
    season_number: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    episode_number: i64,
}

fn v2_int(r: &Request, name: &str, fallback: i64) -> i64 {
    let (values, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    values
        .get(name)
        .and_then(|v| v.first())
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn cursor_of(r: &Request) -> String {
    let (values, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    values
        .get("cursor")
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
}

fn internal(detail: &str) -> Problem {
    Problem::new(internal_error(), detail)
}

async fn v2_files(
    s: &Stack,
    r: &Request,
) -> Result<silo_api_v2::wire::Collection<V2File>, Problem> {
    let id = r.url_param("id").to_owned();
    let limit = v2_int(r, "limit", 50);
    let user = get_claims(r).map_or(0, |c| c.user_id);
    let scope = CursorScope {
        operation_id: "listAdminItemFiles".to_owned(),
        security: format!("{user}/{}", get_profile_id(r)),
        filter: format!("{id}/{limit}"),
        sort: "id".to_owned(),
        tiebreaker: "id".to_owned(),
    };
    let cursor = cursor_of(r);
    let mut after = 0i64;
    if !cursor.is_empty() {
        after = s.cursors.decode::<i64>(&scope, &cursor)?;
        if after <= 0 {
            return Err(Problem::new(
                silo_api_v2::problem::invalid_cursor(),
                "Invalid file cursor.",
            ));
        }
    }
    if !item_exists(&s.pool, &id).await {
        return Err(Problem::new(problem_type("not_found"), "Item not found"));
    }
    let failed = || internal("Failed to load item files");
    let rows = s
        .pool
        .query(LIST_V2_SQL, &[&id, &AnyInt(after), &AnyInt(limit + 1)])
        .await
        .map_err(|_| failed())?;
    let more = rows.len() as i64 > limit;
    let mut items = Vec::new();
    let mut last = 0;
    for row in rows.iter().take(limit as usize) {
        let get = |i: usize| {
            row.try_get::<_, AnyInt>(i)
                .map(|v| v.0)
                .map_err(|_| failed())
        };
        let file_path: String = row.try_get(2).map_err(|_| failed())?;
        let mut observed: String = row.try_get(3).map_err(|_| failed())?;
        if observed.is_empty() {
            observed = silo_gocompat::path::dir(&file_path);
        }
        last = get(0)?;
        items.push(V2File {
            id: Id::from_int(last),
            library_id: Id::from_int(get(1)?),
            file_path,
            observed_root_path: observed,
            season_number: get(4)?,
            episode_number: get(5)?,
        });
    }
    let next = if more && !items.is_empty() {
        s.cursors.encode(&scope, &last)?
    } else {
        String::new()
    };
    Ok(paginated(items, next))
}

#[derive(Serialize)]
struct AdminCatalogCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    item_listing: bool,
    item_listing_max_content_ids: i64,
    item_change_events: bool,
}

#[derive(Serialize)]
struct SearchCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    people_media_scope: bool,
    facet_value_search: bool,
    person_prefetch: bool,
    video_with_episodes_scope: bool,
    extended_query_rules: bool,
    show_title_rules: bool,
    letter_index: bool,
    provider: &'static str,
}

/// Mounts on the `/api/v1/admin` subrouter.
pub fn mount_v1(stack: &Arc<Stack>, admin: &Mux) {
    let held = stack.clone();
    admin.get(
        "/items/{id}/files",
        stack.v1(
            "/api/v1/admin/items/{id}/files",
            V1_METADATA_ITEM,
            handler_fn(move |w, r| {
                let s = held.clone();
                Box::pin(async move {
                    let id = r.url_param("id").to_owned();
                    if !item_exists(&s.pool, &id).await {
                        return write_v1_error(w, 404, "not_found", "Item not found").await;
                    }
                    match v1_files(&s.pool, &id).await {
                        Ok(files) => write_v1_json(w, 200, &V1Files { files }).await,
                        Err(e) => {
                            tracing::error!(component = "api", content_id = %id, error = %e, "admin split: listing item files");
                            write_v1_error(w, 500, "internal_error", "Failed to load item files")
                                .await;
                        }
                    }
                })
            }),
        ),
    );
}

pub fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/admin/items/{id}/files";
    let held = stack.clone();
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(move |w, r| {
                let s = held.clone();
                Box::pin(async move {
                    match v2_files(&s, r).await {
                        Ok(body) => write_v2_json(w, &body).await,
                        Err(p) => write_problem(w, r, p).await,
                    }
                })
            }),
        ),
    );
    let path = "/api/v2/admin/catalog/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getAdminCatalogCapabilities", |revision| {
                        capability_json(&AdminCatalogCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            item_listing: true,
                            item_listing_max_content_ids: ITEM_LISTING_MAX_CONTENT_IDS,
                            item_change_events: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
    v2.get(
        SEARCH_CAPABILITIES,
        stack.v2(
            SEARCH_CAPABILITIES,
            V2Class::ProfileScoped,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getCatalogSearchCapabilities", |revision| {
                        capability_json(&SearchCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            people_media_scope: true,
                            facet_value_search: true,
                            person_prefetch: true,
                            video_with_episodes_scope: true,
                            extended_query_rules: true,
                            show_title_rules: true,
                            letter_index: true,
                            provider: "postgres",
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}
