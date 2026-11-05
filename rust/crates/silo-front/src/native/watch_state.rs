//! Watched-state commands: `internal/apiv2/progress.go` `clearResumePosition` over
//! `handlers.ItemsHandler.ClearResumePosition` (`watch_state_service.go`), `lookupWatchedTarget`
//! (`items.go`), and `PostgresUserStore.ClearResumePosition` (`userstore/pgstore/progress.go`).

use std::sync::Arc;
use std::time::SystemTime;

use silo_gate::mw::auth::get_profile_id;
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_pg::AnyInt;
use silo_store::catalog::access::{AccessFilter, ensure_accessible};

use super::auth::{ApiError, service_problem};
use super::chain::{Stack, V2Class, write_problem};
use super::interest;
use super::personal::{access_of, publish_state, user_of, validation};
use super::settings::{api, mark_profile_stale};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[NativeRow::new(
    ApiV2,
    "DELETE",
    "/api/v2/progress/{media_item_id}/position",
)];

const INTERNAL: &str = "internal_error";

/// `watchedTarget`: the target's type and, for a season or episode, its series.
struct Target {
    kind: String,
    series: String,
}

enum Lookup {
    Found(Target),
    NotFound,
}

/// `lookupWatchedTarget`. Any other item type is not found.
async fn lookup_target(s: &Stack, content: &str, filter: &AccessFilter) -> Result<Lookup, String> {
    let rows = s
        .pool
        .query(
            "SELECT type FROM media_items WHERE content_id = $1",
            &[&content],
        )
        .await
        .map_err(|e| e.to_string())?;
    if let Some(row) = rows.first() {
        let kind: String = row.try_get(0).map_err(|e| e.to_string())?;
        if !ensure_accessible(&s.pool, content, filter).await? {
            return Ok(Lookup::NotFound);
        }
        return Ok(match kind.as_str() {
            "movie" | "audiobook" | "ebook" | "series" => Lookup::Found(Target {
                kind,
                series: String::new(),
            }),
            _ => Lookup::NotFound,
        });
    }
    for (table, kind) in [("seasons", "season"), ("episodes", "episode")] {
        let rows = s
            .pool
            .query(
                &format!("SELECT series_id FROM {table} WHERE content_id = $1"),
                &[&content],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = rows.first() else {
            continue;
        };
        let series: Option<String> = row.try_get(0).map_err(|e| e.to_string())?;
        let series = series.unwrap_or_default();
        if !ensure_accessible(&s.pool, &series, filter).await? {
            return Ok(Lookup::NotFound);
        }
        return Ok(Lookup::Found(Target {
            kind: kind.to_owned(),
            series,
        }));
    }
    Ok(Lookup::NotFound)
}

/// `PostgresUserStore.ClearResumePosition`.
const CLEAR_RESUME_POSITION: &str = "
		UPDATE user_watch_progress
		SET position_seconds = 0,
			updated_at = GREATEST($4::timestamptz, updated_at, event_at),
			event_at = GREATEST($4::timestamptz, event_at)
		WHERE user_id = $1 AND profile_id = $2 AND media_item_id = $3
		  AND position_seconds > 0
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = user_watch_progress.user_id
			  AND hhi.profile_id = user_watch_progress.profile_id
			  AND hhi.media_item_id = user_watch_progress.media_item_id
			  AND user_watch_progress.updated_at <= hhi.hidden_before
		  )";

/// `ItemsHandler.ClearResumePosition`.
async fn clear_resume_position(
    s: &Stack,
    r: &Request,
    user: i64,
    profile: &str,
    content: &str,
) -> Result<(), ApiError> {
    let not_found = || api(404, "not_found", "Item not found");
    if content.contains('\0') {
        return Err(not_found());
    }
    let target = match lookup_target(s, content, &access_of(r)).await {
        Ok(Lookup::Found(target)) => target,
        Ok(Lookup::NotFound) => return Err(not_found()),
        Err(e) => {
            tracing::error!(component = "api", content_id = content, error = %e, "clear resume position: lookup failed");
            return Err(api(500, INTERNAL, "Failed to clear resume position"));
        }
    };
    if target.kind == "audiobook" {
        return Err(not_found());
    }
    if target.kind != "movie" && target.kind != "episode" {
        return Err(api(
            400,
            "invalid_watch_target",
            "Only a movie or an episode has a resume position",
        ));
    }
    let cleared = s
        .pool
        .execute(
            CLEAR_RESUME_POSITION,
            &[&AnyInt(user), &profile, &content, &SystemTime::now()],
        )
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to clear resume position"))?;
    if cleared == 0 {
        return Ok(());
    }
    interest::queue_item(user, profile, content);
    mark_profile_stale(s, user, profile).await;
    publish_state(
        s,
        user,
        profile,
        content,
        &target.series,
        "progress",
        None,
        None,
    )
    .await;
    Ok(())
}

/// Registers the watched-state commands.
pub fn mount(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/progress/{media_item_id}/position";
    let st = stack.clone();
    v2.delete(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            handler_fn(move |w, r| {
                let s = st.clone();
                Box::pin(async move {
                    let item = r.url_param("media_item_id").to_owned();
                    match clear_resume_position(&s, r, user_of(r), &get_profile_id(r), &item).await
                    {
                        Ok(()) => w.write_header(204).await,
                        // `watchTargetProblem`: a target without a resume position fails validation
                        // of the path parameter.
                        Err(e) if e.code == "invalid_watch_target" => {
                            write_problem(w, r, validation("path.media_item_id", &e.message)).await
                        }
                        Err(e) => write_problem(w, r, service_problem(&e)).await,
                    }
                })
            }),
        ),
    );
}
