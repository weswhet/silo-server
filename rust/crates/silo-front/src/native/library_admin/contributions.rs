//! `listAdminFileMarkerContributions`: local audit history, with catalog/file authorization.
use super::*;
use silo_api_v2::problem::{ProblemError, type_for_status, validation_failed};
use silo_api_v2::wire::Id;
use silo_gocompat::time::GoTime;
use silo_store::catalog::access::AccessFilter;
use silo_store::library_admin_reads::contributions as db;

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Position {
    #[serde(rename = "UpdatedAt")]
    updated_at: GoTime,
    #[serde(rename = "ID")]
    id: String,
}

#[derive(Serialize)]
struct Contribution {
    id: String,
    media_file_id: String,
    provider: String,
    segment: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    submitted_start_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    submitted_end_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    video_duration_ms: Option<i64>,
    content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    submission_id: Option<String>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    submitted_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<Instant>,
}

fn timestamp(t: SystemTime) -> Option<Instant> {
    (!GoTime::from_system_time(t).is_zero()).then(|| instant(t))
}
impl From<db::Contribution> for Contribution {
    fn from(v: db::Contribution) -> Self {
        Self {
            id: v.id,
            media_file_id: v.media_file_id.to_string(),
            provider: v.provider,
            segment: v.segment,
            source: v.source,
            submitted_start_ms: v.submitted_start_ms,
            submitted_end_ms: v.submitted_end_ms,
            video_duration_ms: v.video_duration_ms,
            content_hash: v.content_hash,
            submission_id: v.submission_id,
            status: v.status,
            http_status: v.http_status,
            error: v.error,
            submitted_at: timestamp(v.submitted_at),
            updated_at: timestamp(v.updated_at),
        }
    }
}

pub(super) fn mount(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/admin/files/{fileId}/contributions";
    let s = stack.clone();
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    let Some(id) = Id(r.url_param("fileId").to_owned()).to_int() else {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                validation_failed(),
                                "The request did not pass validation; see errors.",
                            )
                            .with_errors([ProblemError {
                                location: "path.fileId".into(),
                                code: "invalid".into(),
                                detail: "expected a positive integer identifier".into(),
                            }]),
                        )
                        .await;
                    };
                    let Some(claims) = get_claims(r) else {
                        return;
                    };
                    // Acting-admin middleware has resolved CatalogAccess's effective viewer scope.
                    let access = r.extensions.get::<Arc<AccessScope>>();
                    let filter = AccessFilter::of(access.map(AsRef::as_ref));
                    let quality = access
                        .map(|s| s.max_playback_quality.as_str())
                        .unwrap_or_default();
                    let limit = query(r, "limit").parse::<i64>().unwrap_or(50);
                    let scope = CursorScope {
                        operation_id: "listAdminFileMarkerContributions".into(),
                        security: format!(
                            "{}/{}/{}",
                            claims.user_id,
                            get_profile_id(r),
                            viewer_digest(r)
                        ),
                        filter: format!("{id}/{limit}"),
                        sort: "-updated_at,-id".into(),
                        tiebreaker: "id".into(),
                    };
                    let cursor = query(r, "cursor");
                    let pos: Position = if cursor.is_empty() {
                        Position::default()
                    } else {
                        match s.cursors.decode(&scope, &cursor) {
                            Ok(v) => v,
                            Err(p) => return write_problem(w, r, p).await,
                        }
                    };
                    match db::authorize(&s.pool, id, &filter, quality).await {
                        Ok(true) => {}
                        Ok(false) => {
                            return write_problem(
                                w,
                                r,
                                Problem::new(type_for_status(404), "Media file not found"),
                            )
                            .await;
                        }
                        Err(_) => return write_problem(w, r, internal_problem()).await,
                    }
                    let after =
                        (!pos.updated_at.is_zero()).then(|| pos.updated_at.to_system_time());
                    let (rows, more) = match db::list(&s.pool, id, limit, after, &pos.id).await {
                        Ok(v) => v,
                        Err(_) => return write_problem(w, r, internal_problem()).await,
                    };
                    let mut next = String::new();
                    if more && let Some(last) = rows.last() {
                        let updated_at = GoTime::from_system_time(last.updated_at);
                        if updated_at.is_zero() {
                            return write_problem(
                                w,
                                r,
                                Problem::new(
                                    internal_error(),
                                    "Contribution cursor is unavailable.",
                                ),
                            )
                            .await;
                        }
                        next = match s.cursors.encode(
                            &scope,
                            &Position {
                                updated_at,
                                id: last.id.clone(),
                            },
                        ) {
                            Ok(v) => v,
                            Err(p) => return write_problem(w, r, p).await,
                        };
                    }
                    write_v2_json(
                        w,
                        &paginated(rows.into_iter().map(Contribution::from).collect(), next),
                    )
                    .await;
                })
            }),
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contribution_wire_omits_absent_values_and_zero_times() {
        let row = db::Contribution {
            id: "audit".into(),
            media_file_id: 9,
            provider: "provider".into(),
            segment: "intro".into(),
            source: "manual".into(),
            submitted_start_ms: Some(0),
            submitted_end_ms: None,
            video_duration_ms: None,
            content_hash: "hash".into(),
            submission_id: Some(String::new()),
            status: "accepted".into(),
            http_status: Some(0),
            error: None,
            submitted_at: GoTime::ZERO.to_system_time(),
            updated_at: GoTime::ZERO.to_system_time(),
        };
        assert_eq!(
            serde_json::to_string(&Contribution::from(row)).unwrap(),
            r#"{"id":"audit","media_file_id":"9","provider":"provider","segment":"intro","source":"manual","submitted_start_ms":0,"content_hash":"hash","submission_id":"","status":"accepted","http_status":0}"#
        );
        let pos: Position = serde_json::from_str("{}").unwrap();
        assert!(pos.updated_at.is_zero());
        assert!(pos.id.is_empty());
        assert_eq!(
            serde_json::to_string(&Position {
                updated_at: GoTime::from_unix(0, 0),
                id: "audit".into(),
            })
            .unwrap(),
            r#"{"UpdatedAt":"1970-01-01T00:00:00Z","ID":"audit"}"#
        );
    }
}
