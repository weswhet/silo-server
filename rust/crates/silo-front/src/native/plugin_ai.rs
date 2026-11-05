//! Static capabilities and database-only plugin catalog configuration.
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::precondition::{
    evaluate_guarded_preconditions, evaluate_read_preconditions, stale_version_problem,
};
use silo_api_v2::problem::Problem;
use silo_api_v2::wire::{Collection, Instant, paginated};
use silo_core::apiv2::{EntityTag, render_etag};
use silo_gate::mw::auth::get_profile_id;
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_store::plugin_catalog as store;

use super::chain::{
    Stack, Step, V2Class, capability_json, write_capability, write_problem, write_v2_json,
};
use super::huma::{RawBody, decode_body, reject_nulls};
use super::personal::{internal, user_of, viewer_digest};
use crate::rows::{NativeRow, Surface::ApiV2};

const CONTENT: &str = "/api/v2/plugin-content/capabilities";
const AI: &str = "/api/v2/admin/ai/capabilities";
const SETTINGS: &str = "/api/v2/admin/plugins/catalog-settings";
const REPOSITORIES: &str = "/api/v2/admin/plugins/repositories";
pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", CONTENT),
    NativeRow::new(ApiV2, "GET", AI),
    NativeRow::new(ApiV2, "GET", SETTINGS),
    NativeRow::new(ApiV2, "PUT", SETTINGS),
    NativeRow::new(ApiV2, "GET", REPOSITORIES),
];
const ADMIN_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
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

#[derive(Serialize)]
struct Capability<'a> {
    revision: &'a str,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed: Option<bool>,
}
#[derive(Serialize)]
struct AICapability<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    reasoning_levels: Vec<&'static str>,
    openai_service_tiers: [&'static str; 3],
    chatgpt_sign_in: bool,
}

/// `reasoning.ForModel`; matching order is significant for the pro and chat variants.
fn reasoning_levels(model: &str) -> Vec<&'static str> {
    let lower = silo_gocompat::strings::to_lower(model);
    let model = lower.strip_prefix("openai/").unwrap_or(&lower);
    let prefixes = |values: &[&str]| values.iter().any(|prefix| model.starts_with(prefix));
    if model == "chat-latest"
        || (model.starts_with("gpt-") && model.ends_with("-chat-latest"))
        || prefixes(&["gpt-4", "gpt-3"])
    {
        vec![]
    } else if prefixes(&["gpt-6.1-sol", "gpt-6-astra"]) {
        vec!["low", "medium", "high", "xhigh", "max"]
    } else if prefixes(&["gpt-6-sol", "gpt-6-luna", "gpt-5.6"]) {
        vec!["none", "low", "medium", "high", "xhigh", "max"]
    } else if model.starts_with("gpt-5-pro") {
        vec!["high"]
    } else if prefixes(&["gpt-5.2-pro", "gpt-5.4-pro", "gpt-5.5-pro"]) {
        vec!["medium", "high", "xhigh"]
    } else if prefixes(&["gpt-5.2", "gpt-5.4", "gpt-5.5"]) {
        vec!["none", "low", "medium", "high", "xhigh"]
    } else if model.starts_with("gpt-5.1") {
        vec!["none", "low", "medium", "high"]
    } else if model == "gpt-5" || prefixes(&["gpt-5-mini", "gpt-5-nano", "gpt-5-20"]) {
        vec!["minimal", "low", "medium", "high"]
    } else if prefixes(&["o1", "o3", "o4"]) {
        vec!["low", "medium", "high"]
    } else {
        vec!["none", "minimal", "low", "medium", "high", "xhigh", "max"]
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename = "AdminPluginCatalogSettings")]
struct CatalogSettings {
    include_approved_community_plugins: bool,
}

fn settings_tag(r: &Request, include: bool) -> EntityTag {
    render_etag(
        format!(
            "admin-plugin-catalog:{}:{}:{}",
            user_of(r),
            get_profile_id(r),
            viewer_digest(r)
        )
        .as_bytes(),
        include.to_string().as_bytes(),
        1,
    )
}
fn header(r: &Request, name: &str) -> String {
    String::from_utf8_lossy(r.header.get(name)).into_owned()
}

#[derive(Serialize)]
struct Repository {
    id: String,
    url: String,
    display_name: String,
    enabled: bool,
    source_kind: String,
    managed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_fetched_at: Option<Instant>,
    created_at: Instant,
    updated_at: Instant,
}
fn instant(at: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(at))
}
fn repository(row: store::Repository) -> Repository {
    Repository {
        id: row.id.to_string(),
        url: row.url,
        display_name: row.display_name,
        enabled: row.enabled,
        source_kind: row.source_kind,
        managed: row.managed_key.is_some(),
        last_fetched_at: row.last_fetched_at.map(instant),
        created_at: instant(row.created_at),
        updated_at: instant(row.updated_at),
    }
}

async fn repositories(s: &Stack, r: &Request) -> Result<Collection<Repository>, Problem> {
    let (query, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    let param = |key: &str| {
        query
            .get(key)
            .and_then(|v| v.first())
            .map(String::as_str)
            .unwrap_or("")
    };
    let limit = param("limit").parse::<usize>().unwrap_or(50);
    let scope = CursorScope {
        operation_id: "listAdminPluginRepositories".to_owned(),
        security: format!("{}/{}/{}", user_of(r), get_profile_id(r), viewer_digest(r)),
        filter: limit.to_string(),
        sort: "id".to_owned(),
        tiebreaker: "id".to_owned(),
    };
    let after: i64 = if param("cursor").is_empty() {
        0
    } else {
        s.cursors.decode(&scope, param("cursor"))?
    };
    let rows = store::list_repositories(&s.pool)
        .await
        .map_err(|_| internal())?;
    let mut seen = std::collections::HashSet::new();
    if rows.iter().any(|row| row.id <= 0 || !seen.insert(row.id)) {
        return Err(internal());
    }
    let mut items = Vec::with_capacity(limit);
    let mut next = String::new();
    let mut last = 0;
    for row in rows {
        if row.id <= after {
            continue;
        }
        if items.len() == limit {
            next = s.cursors.encode(&scope, &last).map_err(|_| internal())?;
            break;
        }
        last = row.id;
        items.push(repository(row));
    }
    Ok(paginated(items, next))
}

pub fn mount(stack: &Arc<Stack>, _api: &Mux, v2: &Mux) {
    // Go's production startup always creates the proxy with a database, and creates ChatGPT with
    // the PostgreSQL settings store and secret cipher. Native Stack requires both dependencies.
    // Neither capability consults a plugin process or makes an upstream request.
    v2.get(
        CONTENT,
        stack.v2(
            CONTENT,
            V2Class::Public,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getPluginContentCapabilities", |revision| {
                        capability_json(&Capability {
                            revision,
                            state: "available",
                            allowed: None,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
    v2.get(
        AI,
        stack.v2(
            AI,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    let (query, _) =
                        silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
                    let model = query
                        .get("model")
                        .and_then(|values| values.first())
                        .map(String::as_str)
                        .unwrap_or("");
                    write_capability(w, r, "getAdminAICapabilities", |revision| {
                        capability_json(&AICapability {
                            revision,
                            state: "available",
                            allowed: true,
                            reasoning_levels: reasoning_levels(model),
                            openai_service_tiers: ["default", "priority", "ultrafast"],
                            chatgpt_sign_in: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
    v2.get(
        SETTINGS,
        stack.v2(
            SETTINGS,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let include = match store::get_settings(&s.pool).await {
                    Ok(include) => include,
                    Err(_) => return write_problem(w, r, internal()).await,
                };
                let tag = settings_tag(r, include);
                let (matched, problem) = evaluate_read_preconditions(
                    &header(r, "If-Match"),
                    &header(r, "If-None-Match"),
                    &tag,
                );
                if let Some(p) = problem {
                    return write_problem(w, r, p).await;
                }
                w.header().set("ETag", tag.to_wire());
                if matched {
                    w.write_header(304).await;
                } else {
                    write_v2_json(
                        w,
                        &CatalogSettings {
                            include_approved_community_plugins: include,
                        },
                    )
                    .await;
                }
            }),
        ),
    );
    v2.put(
        SETTINGS,
        stack.v2_steps(
            SETTINGS,
            ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let body: CatalogSettings = match decode_body(r) {
                    Ok(body) => body,
                    Err(p) => return write_problem(w, r, p).await,
                };
                if let Some(raw) = r.extensions.get::<RawBody>()
                    && let Some(p) = reject_nulls(&raw.0)
                {
                    return write_problem(w, r, p).await;
                }
                let include = match store::get_settings(&s.pool).await {
                    Ok(include) => include,
                    Err(_) => return write_problem(w, r, internal()).await,
                };
                let if_match = header(r, "If-Match");
                let if_none_match = header(r, "If-None-Match");
                if let Some(p) = evaluate_guarded_preconditions(
                    &if_match,
                    &if_none_match,
                    &settings_tag(r, include),
                ) {
                    return write_problem(w, r, p).await;
                }
                let expected = if silo_gocompat::strings::trim_space(&if_match) == "*"
                    && evaluate_guarded_preconditions(
                        &if_match,
                        &if_none_match,
                        &settings_tag(r, !include),
                    )
                    .is_none()
                {
                    None
                } else {
                    Some(include)
                };
                match store::set_include_conditional(
                    &s.pool,
                    body.include_approved_community_plugins,
                    expected,
                )
                .await
                {
                    Ok(include) => {
                        w.header().set("ETag", settings_tag(r, include).to_wire());
                        write_v2_json(
                            w,
                            &CatalogSettings {
                                include_approved_community_plugins: include,
                            },
                        )
                        .await;
                    }
                    Err(store::Error::Changed(actual)) => {
                        write_problem(
                            w,
                            r,
                            stale_version_problem(Some(&(&settings_tag(r, actual)).into())),
                        )
                        .await
                    }
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );
    v2.get(
        REPOSITORIES,
        stack.v2(
            REPOSITORIES,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                match repositories(&s, r).await {
                    Ok(out) => write_v2_json(w, &out).await,
                    Err(p) => write_problem(w, r, p).await,
                }
            }),
        ),
    );
}
