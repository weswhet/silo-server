//! The library read rows: `libraries.go`, `libraries_service.go`, `user_libraries_service.go`, the listings of
//! `library_playback_prefs.go`, `LibraryLayout`, and v2 `libraries.go`, `library_monitoring.go`,
//! `user_libraries.go`, `getLibraryJob`, `listLibraryPlaybackPreferences`.
//!
//! Every library write stays on Go, because each reaches the scanner, matcher, job, or blob domains:
//! create, update, delete, reorder, check-mount, confirm-empty-root-cleanup, refresh-metadata, the matcher's retry and
//! cancel, root overrides, stale-id rematch, unmatched ignore, providers, poster, the preference writes, and job cancel.
//! Reads whose items need the catalog or sections services stay on Go too: section and collection items, the
//! Collections tab, and the personal collections listing.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;
use silo_api_v2::problem::{Problem, internal_error, type_for_status};
use silo_api_v2::wire::{Collection, Id, Instant, PageInfo, new_collection, paginated};
use silo_auth::claims::Claims;
use silo_config::settings::Scope as SettingScope;
use silo_config::settings::keys;
use silo_core::apiv2::{CursorScope, EntityTag};
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::json::{RawMessage, omit_empty};
use silo_gocompat::strings::trim_space;
use silo_gocompat::time::GoTime;
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_store::access::Scope as AccessScope;
use silo_store::catalog::folders::{self, Folder, FolderError};
use silo_store::catalog::library_admin as admin;
use silo_store::catalog::library_admin::RawBacklogMode;
use silo_store::catalog::sections;
use silo_store::userstore::pgstore::PostgresUserStore;

use super::auth::{ApiError, service_problem, write_v1_error};
use super::chain::{
    Stack, Step, V2Class, capability_json, client_ip_of, write_capability, write_problem,
    write_v1_json, write_v2_json,
};
use super::settings::{api, write_api};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/"),
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/metadata-match-queue"),
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/provider-defaults"),
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/roots"),
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/skipped-roots"),
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/stale-ids"),
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/unmatched-items"),
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/{id}/metadata-match-queue"),
    NativeRow::new(ApiV1, "GET", "/api/v1/libraries/{id}/providers"),
    NativeRow::new(ApiV1, "GET", "/api/v1/library-playback-prefs/"),
    NativeRow::new(ApiV1, "GET", "/api/v1/library/{id}/layout"),
    NativeRow::new(ApiV1, "GET", "/api/v1/user/libraries"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/metadata-match-queue"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/provider-defaults"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/realtime-monitoring"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/roots"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/skipped-roots"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/stale-ids"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/unmatched-items"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/{id}/metadata-match-queue"),
    NativeRow::new(ApiV2, "GET", "/api/v2/libraries/{id}/providers"),
    NativeRow::new(ApiV2, "GET", "/api/v2/library-jobs/{job_id}"),
    NativeRow::new(ApiV2, "GET", "/api/v2/library-playback-prefs"),
    NativeRow::new(ApiV2, "GET", "/api/v2/library/{id}/layout"),
    NativeRow::new(ApiV2, "GET", "/api/v2/user/libraries"),
];

const V1_LIBRARIES: &[Step] = &[
    Step::Auth,
    Step::Demo,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
];
const V1_PREFS: &[Step] = &[
    Step::Auth,
    Step::Demo,
    Step::RateLimit,
    Step::Viewer,
    Step::Profile,
];
const V1_VIEWER: &[Step] = &[Step::Auth, Step::Demo, Step::RateLimit, Step::Viewer];
const INTERNAL: &str = "internal_error";
const NOT_FOUND: &str = "not_found";
const LIBRARY_NOT_FOUND: &str = "Library not found";

macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

fn query_param(r: &Request, name: &str) -> String {
    let (values, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    values
        .get(name)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
}

fn claims_of(r: &Request) -> Option<Arc<Claims>> {
    get_claims(r)
}

fn scope_of(r: &Request) -> Option<Arc<AccessScope>> {
    r.extensions.get::<Arc<AccessScope>>().cloned()
}

fn instant(t: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(t))
}

fn instant_opt(t: Option<SystemTime>) -> Option<Instant> {
    t.map(instant)
}

fn go_time(t: SystemTime) -> GoTime {
    GoTime::from_system_time(t).to_utc()
}

fn raw(text: Option<String>) -> Option<RawMessage> {
    text.filter(|t| !t.is_empty()).map(RawMessage::from)
}

/// `libraryProblem` for what these reads can fail with.
fn library_problem(e: &ApiError) -> Problem {
    service_problem(e)
}

/// `libraryID`.
fn library_id(raw_id: &str) -> Result<i64, Problem> {
    Id(raw_id.to_owned())
        .to_int()
        .ok_or_else(|| Problem::new(type_for_status(404), "No library has that identifier."))
}

/// Go's `strconv.Atoi` on a v1 path parameter.
fn atoi(raw_id: &str) -> Option<i64> {
    raw_id.parse().ok()
}

fn internal_problem() -> Problem {
    Problem::new(internal_error(), "An unexpected error occurred.")
}

/// `offsetPosition`.
#[derive(Serialize, serde::Deserialize, Default)]
#[serde(default)]
struct OffsetPosition {
    o: i64,
}

/// `decodeOffset`.
fn decode_offset(s: &Stack, scope: &CursorScope, cursor: &str) -> Result<i64, Problem> {
    if cursor.is_empty() {
        return Ok(0);
    }
    Ok(s.cursors.decode::<OffsetPosition>(scope, cursor)?.o)
}

/// `offsetPage`.
fn offset_page<T>(
    s: &Stack,
    scope: &CursorScope,
    mut rows: Vec<T>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<T>, String), Problem> {
    if rows.len() as i64 <= limit {
        return Ok((rows, String::new()));
    }
    let next = s
        .cursors
        .encode(scope, &OffsetPosition { o: offset + limit })
        .map_err(|_| internal_problem())?;
    rows.truncate(limit as usize);
    Ok((rows, next))
}

fn limit_of(r: &Request, default: i64) -> i64 {
    query_param(r, "limit").parse().unwrap_or(default)
}

/// `h.ArtworkResolver.ResolveURLs(...)[path].URL`, over the local store's server resolver. Rows with a
/// bucket go to Go.
fn poster_url(s: &Stack, path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    super::profiles::sign_artwork(&s.artwork_secret, path, s.artwork_url_ttl)
}

#[derive(Serialize)]
struct V1Library {
    id: i32,
    paths: Vec<String>,
    #[serde(rename = "type")]
    kind: String,
    name: String,
    enabled: bool,
    metadata_language: String,
    auto_translate_metadata: bool,
    chapter_thumbnails_enabled: bool,
    chapter_thumbnails_supported: bool,
    intro_detection_enabled: bool,
    trailer_kinds: Vec<String>,
    sort_order: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_scanned_at: Option<GoTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_warning_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_warning_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_warning_at: Option<GoTime>,
}

fn v1_library(s: &Stack, f: Folder) -> V1Library {
    V1Library {
        id: f.id,
        poster_url: poster_url(s, &f.poster_path),
        paths: f.paths,
        kind: f.kind,
        name: f.name,
        enabled: f.enabled,
        metadata_language: f.metadata_language,
        auto_translate_metadata: f.auto_translate_metadata,
        chapter_thumbnails_enabled: f.chapter_thumbnails_enabled,
        chapter_thumbnails_supported: true,
        intro_detection_enabled: f.intro_detection_enabled,
        trailer_kinds: f.trailer_kinds,
        sort_order: f.sort_order,
        last_scanned_at: f.last_scanned_at.map(go_time),
        scan_warning_code: f.scan_warning_code,
        scan_warning_message: f.scan_warning_message,
        scan_warning_at: f.scan_warning_at.map(go_time),
    }
}

#[derive(Serialize)]
struct V2Library {
    id: Id,
    paths: Vec<String>,
    #[serde(rename = "type")]
    kind: String,
    name: String,
    enabled: bool,
    metadata_language: String,
    auto_translate_metadata: bool,
    chapter_thumbnails_enabled: bool,
    chapter_thumbnails_supported: bool,
    intro_detection_enabled: bool,
    trickplay_enabled: bool,
    trickplay_supported: bool,
    trailer_kinds: Vec<String>,
    realtime_monitoring: bool,
    sort_order: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_scanned_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_warning_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_warning_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_warning_at: Option<Instant>,
}

fn v2_library(s: &Stack, f: Folder) -> V2Library {
    V2Library {
        id: Id::from_int(i64::from(f.id)),
        poster_url: poster_url(s, &f.poster_path),
        paths: f.paths,
        kind: f.kind,
        name: f.name,
        enabled: f.enabled,
        metadata_language: f.metadata_language,
        auto_translate_metadata: f.auto_translate_metadata,
        chapter_thumbnails_enabled: f.chapter_thumbnails_enabled,
        chapter_thumbnails_supported: true,
        intro_detection_enabled: f.intro_detection_enabled,
        trickplay_enabled: f.trickplay_enabled,
        trickplay_supported: true,
        trailer_kinds: f.trailer_kinds,
        realtime_monitoring: f.realtime_monitoring,
        sort_order: f.sort_order,
        last_scanned_at: instant_opt(f.last_scanned_at),
        scan_warning_code: f.scan_warning_code,
        scan_warning_message: f.scan_warning_message,
        scan_warning_at: instant_opt(f.scan_warning_at),
    }
}

/// `LibraryHandler.ListLibraries`.
async fn list_libraries(s: &Stack) -> Result<Vec<Folder>, ApiError> {
    folders::list(&s.pool)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to list libraries"))
}

/// `metadataMatchQueueStatus` counts.
#[derive(Clone, Copy, Default)]
struct QueueStatus {
    library_id: i32,
    movie_count: i64,
    series_count: i64,
    raw_file_count: i64,
    total_count: i64,
    pending_count: i64,
    parked_count: i64,
}

/// `rawMatchBacklogMode`: both queues are always wired.
fn raw_mode(s: &Stack) -> RawBacklogMode {
    if s.tv_series_root_queue {
        RawBacklogMode::Mixed
    } else {
        RawBacklogMode::Generic
    }
}

/// `metadataMatchQueueStatuses`.
async fn queue_statuses(s: &Stack, ids: &[i32]) -> Result<HashMap<i32, QueueStatus>, String> {
    let mut statuses: HashMap<i32, QueueStatus> = ids
        .iter()
        .map(|id| {
            (
                *id,
                QueueStatus {
                    library_id: *id,
                    ..QueueStatus::default()
                },
            )
        })
        .collect();
    for (id, c) in admin::movie_state_counts(&s.pool, ids).await? {
        let st = statuses.entry(id).or_default();
        st.movie_count = c.pending + c.parked;
        st.pending_count += c.pending;
        st.parked_count += c.parked;
    }
    for (id, c) in admin::series_state_counts(&s.pool, ids).await? {
        let st = statuses.entry(id).or_default();
        st.series_count = c.pending + c.parked;
        st.pending_count += c.pending;
        st.parked_count += c.parked;
    }
    for (id, count) in admin::raw_backlog_counts(&s.pool, ids, raw_mode(s)).await? {
        let st = statuses.entry(id).or_default();
        st.raw_file_count = count;
        st.pending_count += count;
    }
    for st in statuses.values_mut() {
        st.total_count = st.movie_count + st.series_count + st.raw_file_count;
    }
    Ok(statuses)
}

/// `ListMetadataMatchQueues`.
async fn list_queues(s: &Stack) -> Result<Vec<QueueStatus>, ApiError> {
    let listed = folders::list(&s.pool)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to list metadata matcher queues"))?;
    let ids: Vec<i32> = listed.iter().map(|f| f.id).collect();
    let statuses = queue_statuses(s, &ids)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to load metadata matcher queues"))?;
    Ok(ids
        .iter()
        .map(|id| statuses.get(id).copied().unwrap_or_default())
        .collect())
}

#[derive(Serialize)]
struct V1QueueStatus {
    library_id: i32,
    movie_count: i64,
    series_count: i64,
    raw_file_count: i64,
    total_count: i64,
    pending_count: i64,
    parked_count: i64,
}

impl From<QueueStatus> for V1QueueStatus {
    fn from(q: QueueStatus) -> Self {
        Self {
            library_id: q.library_id,
            movie_count: q.movie_count,
            series_count: q.series_count,
            raw_file_count: q.raw_file_count,
            total_count: q.total_count,
            pending_count: q.pending_count,
            parked_count: q.parked_count,
        }
    }
}

#[derive(Serialize)]
struct V2QueueStatus {
    library_id: Id,
    movie_count: i64,
    series_count: i64,
    raw_file_count: i64,
    total_count: i64,
    pending_count: i64,
    parked_count: i64,
}

impl From<QueueStatus> for V2QueueStatus {
    fn from(q: QueueStatus) -> Self {
        Self {
            library_id: Id::from_int(i64::from(q.library_id)),
            movie_count: q.movie_count,
            series_count: q.series_count,
            raw_file_count: q.raw_file_count,
            total_count: q.total_count,
            pending_count: q.pending_count,
            parked_count: q.parked_count,
        }
    }
}

/// What `GetMetadataMatchQueue` read.
struct QueueDetail {
    status: QueueStatus,
    movies: Vec<admin::QueueEntry>,
    movie_total: i64,
    series: Vec<admin::QueueEntry>,
    series_total: i64,
    raw_files: Vec<admin::RawBacklogFile>,
    raw_total: i64,
}

/// `GetMetadataMatchQueue`.
async fn queue_detail(
    s: &Stack,
    id: i64,
    limit: i64,
    offset: i64,
) -> Result<QueueDetail, ApiError> {
    let folder = folders::get_by_id(&s.pool, id).await.map_err(|e| match e {
        FolderError::NotFound => api(404, NOT_FOUND, LIBRARY_NOT_FOUND),
        FolderError::Db(_) => api(500, INTERNAL, "Failed to fetch library"),
    })?;
    let failed = |message: &'static str| move |_| api(500, INTERNAL, message);
    let status = queue_statuses(s, &[folder.id])
        .await
        .map_err(failed("Failed to load metadata matcher queue"))?
        .remove(&folder.id)
        .unwrap_or_default();
    let (movies, movie_total) = admin::list_movie_queue(&s.pool, folder.id, limit, offset)
        .await
        .map_err(failed("Failed to list metadata matcher queue"))?;
    let (series, series_total) = admin::list_series_queue(&s.pool, folder.id, limit, offset)
        .await
        .map_err(failed("Failed to list metadata matcher queue"))?;
    let (raw_files, raw_total) =
        admin::list_raw_backlog(&s.pool, folder.id, raw_mode(s), limit, offset)
            .await
            .map_err(failed("Failed to list metadata matcher backlog"))?;
    Ok(QueueDetail {
        status,
        movies,
        movie_total,
        series,
        series_total,
        raw_files,
        raw_total,
    })
}

#[derive(Serialize)]
struct V1MovieEntry {
    media_file_id: i64,
    media_folder_id: i64,
    file_path: String,
    first_queued_at: GoTime,
    available_at: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_attempted_at: Option<GoTime>,
    attempt_count: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    failure_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_detail: Option<RawMessage>,
    deterministic_attempt_count: i64,
    matcher_revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    parked_at: Option<GoTime>,
    updated_at: GoTime,
}

#[derive(Serialize)]
struct V1SeriesEntry {
    media_folder_id: i64,
    observed_root_path: String,
    first_queued_at: GoTime,
    available_at: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_attempted_at: Option<GoTime>,
    attempt_count: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    failure_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_detail: Option<RawMessage>,
    deterministic_attempt_count: i64,
    matcher_revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    parked_at: Option<GoTime>,
    updated_at: GoTime,
}

#[derive(Serialize)]
struct V1RawEntry {
    media_file_id: i64,
    media_folder_id: i64,
    file_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    base_title: String,
    #[serde(skip_serializing_if = "omit_empty")]
    base_year: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    base_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_attempted_at: Option<GoTime>,
    created_at: GoTime,
    updated_at: GoTime,
}

#[derive(Serialize)]
struct V1QueueDetail {
    #[serde(flatten)]
    status: V1QueueStatus,
    limit: i64,
    offset: i64,
    movies: Vec<V1MovieEntry>,
    series: Vec<V1SeriesEntry>,
    raw_files: Vec<V1RawEntry>,
}

fn v1_queue_detail(d: QueueDetail, limit: i64, offset: i64) -> V1QueueDetail {
    V1QueueDetail {
        status: d.status.into(),
        limit,
        offset,
        movies: d
            .movies
            .into_iter()
            .map(|e| V1MovieEntry {
                media_file_id: e.media_file_id,
                media_folder_id: e.media_folder_id,
                file_path: e.path,
                first_queued_at: go_time(e.first_queued_at),
                available_at: go_time(e.available_at),
                last_attempted_at: e.last_attempted_at.map(go_time),
                attempt_count: e.attempt_count,
                last_error: e.last_error,
                state: e.state,
                failure_kind: e.failure_kind,
                failure_detail: raw(e.failure_detail),
                deterministic_attempt_count: e.deterministic_attempt_count,
                matcher_revision: e.matcher_revision,
                parked_at: e.parked_at.map(go_time),
                updated_at: go_time(e.updated_at),
            })
            .collect(),
        series: d
            .series
            .into_iter()
            .map(|e| V1SeriesEntry {
                media_folder_id: e.media_folder_id,
                observed_root_path: e.path,
                first_queued_at: go_time(e.first_queued_at),
                available_at: go_time(e.available_at),
                last_attempted_at: e.last_attempted_at.map(go_time),
                attempt_count: e.attempt_count,
                last_error: e.last_error,
                state: e.state,
                failure_kind: e.failure_kind,
                failure_detail: raw(e.failure_detail),
                deterministic_attempt_count: e.deterministic_attempt_count,
                matcher_revision: e.matcher_revision,
                parked_at: e.parked_at.map(go_time),
                updated_at: go_time(e.updated_at),
            })
            .collect(),
        raw_files: d
            .raw_files
            .into_iter()
            .map(|f| V1RawEntry {
                media_file_id: f.id,
                media_folder_id: f.media_folder_id,
                file_path: f.file_path,
                base_title: f.base_title,
                base_year: f.base_year,
                base_type: f.base_type,
                last_attempted_at: f.match_attempted_at.map(go_time),
                created_at: go_time(f.created_at),
                updated_at: go_time(f.updated_at),
            })
            .collect(),
    }
}

#[derive(Serialize)]
struct V2MovieEntry {
    media_file_id: Id,
    library_id: Id,
    file_path: String,
    first_queued_at: Instant,
    available_at: Instant,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_attempted_at: Option<Instant>,
    attempt_count: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    failure_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_detail: Option<RawMessage>,
    deterministic_attempt_count: i64,
    matcher_revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    parked_at: Option<Instant>,
    updated_at: Instant,
}

#[derive(Serialize)]
struct V2SeriesEntry {
    library_id: Id,
    observed_root_path: String,
    first_queued_at: Instant,
    available_at: Instant,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_attempted_at: Option<Instant>,
    attempt_count: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_error: String,
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    failure_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_detail: Option<RawMessage>,
    deterministic_attempt_count: i64,
    matcher_revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    parked_at: Option<Instant>,
    updated_at: Instant,
}

#[derive(Serialize)]
struct V2RawEntry {
    media_file_id: Id,
    library_id: Id,
    file_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    base_title: String,
    #[serde(skip_serializing_if = "omit_empty")]
    base_year: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    base_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_attempted_at: Option<Instant>,
    created_at: Instant,
    updated_at: Instant,
}

#[derive(Serialize)]
struct V2QueueDetail {
    #[serde(flatten)]
    status: V2QueueStatus,
    movies: Vec<V2MovieEntry>,
    series: Vec<V2SeriesEntry>,
    raw_files: Vec<V2RawEntry>,
    page: PageInfo,
}

/// `chainLevelEntry`, v1: the local flag is not on its wire.
#[derive(Serialize)]
struct V1ChainEntry {
    plugin_installation_id: i64,
    capability_id: String,
    provider_slug: String,
    priority: i64,
    enabled: bool,
}

#[derive(Serialize)]
struct V1Levels {
    levels: BTreeMap<String, Vec<V1ChainEntry>>,
}

#[derive(Serialize)]
struct V2ChainEntry {
    plugin_installation_id: Id,
    capability_id: String,
    provider_slug: String,
    priority: i64,
    enabled: bool,
    local: bool,
}

#[derive(Serialize)]
struct V2ChainLevel {
    content_level: String,
    entries: Vec<V2ChainEntry>,
}

#[derive(Serialize)]
struct V2Levels {
    levels: Vec<V2ChainLevel>,
}

fn group_chain(entries: Vec<admin::ChainEntry>) -> BTreeMap<String, Vec<admin::ChainEntry>> {
    let mut out: BTreeMap<String, Vec<admin::ChainEntry>> = BTreeMap::new();
    for e in entries {
        out.entry(e.content_level.clone()).or_default().push(e);
    }
    out
}

fn v1_levels(by_level: BTreeMap<String, Vec<admin::ChainEntry>>) -> V1Levels {
    V1Levels {
        levels: by_level
            .into_iter()
            .map(|(level, entries)| {
                (
                    level,
                    entries
                        .into_iter()
                        .map(|e| V1ChainEntry {
                            plugin_installation_id: e.plugin_installation_id,
                            provider_slug: e.capability_id.clone(),
                            capability_id: e.capability_id,
                            priority: e.priority,
                            enabled: e.enabled,
                        })
                        .collect(),
                )
            })
            .collect(),
    }
}

/// `providerChainLevelsOf`: a `BTreeMap` iterates in `sort.Strings` order.
fn v2_levels(by_level: BTreeMap<String, Vec<admin::ChainEntry>>) -> V2Levels {
    V2Levels {
        levels: by_level
            .into_iter()
            .map(|(level, entries)| V2ChainLevel {
                content_level: level,
                entries: entries
                    .into_iter()
                    .map(|e| V2ChainEntry {
                        plugin_installation_id: Id::from_int(e.plugin_installation_id),
                        provider_slug: e.capability_id.clone(),
                        capability_id: e.capability_id,
                        priority: e.priority,
                        enabled: e.enabled,
                        local: e.local,
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// `LibraryHandler.LibraryProviders`.
async fn library_providers(
    s: &Stack,
    id: i64,
) -> Result<BTreeMap<String, Vec<admin::ChainEntry>>, ApiError> {
    let folder = folders::get_by_id(&s.pool, id).await.map_err(|e| match e {
        FolderError::NotFound => api(404, NOT_FOUND, LIBRARY_NOT_FOUND),
        FolderError::Db(_) => api(500, INTERNAL, "Failed to fetch library"),
    })?;
    let entries = admin::all_chain_entries(&s.pool, folder.id)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to get provider chain"))?;
    Ok(group_chain(entries))
}

/// `LibraryHandler.LibraryProviderDefaults`.
async fn provider_defaults(
    s: &Stack,
    library_type: &str,
) -> BTreeMap<String, Vec<admin::ChainEntry>> {
    let levels = admin::content_levels(library_type);
    let mut out: BTreeMap<String, Vec<admin::ChainEntry>> = levels
        .iter()
        .map(|level| ((*level).to_owned(), Vec::new()))
        .collect();
    for e in admin::seed_default_chain(&s.pool, library_type).await {
        out.entry(e.content_level.clone()).or_default().push(e);
    }
    out
}

/// `groupOverrideLookupKey`.
fn group_key(version: i64, key: &str) -> String {
    format!("{version}|{key}")
}

/// One `LibraryRootView`.
struct RootView {
    root_path: String,
    group: admin::ScannedGroup,
    content_id: String,
    active: Option<admin::GroupOverride>,
}

/// `ListLibraryRoots`.
async fn library_roots(
    s: &Stack,
    id: i64,
    state: &str,
    search: &str,
    limit: i64,
    offset: i64,
) -> Result<(String, Vec<RootView>, i64), ApiError> {
    let Ok(folder) = folders::get_by_id(&s.pool, id).await else {
        return Err(api(404, NOT_FOUND, LIBRARY_NOT_FOUND));
    };
    let (groups, total) =
        admin::list_scanned_groups(&s.pool, folder.id, state, search, limit, offset)
            .await
            .map_err(|_| api(500, INTERNAL, "Failed to list roots"))?;
    // Go logs both of these and answers without them.
    let mut overrides: HashMap<String, admin::GroupOverride> = HashMap::new();
    if let Ok(listed) = admin::list_group_overrides(&s.pool, folder.id).await {
        for o in listed {
            overrides.insert(group_key(o.group_key_version, &o.content_group_key), o);
        }
    }
    let mut claims: HashMap<String, String> = HashMap::new();
    if let Ok(listed) = admin::list_group_claims(&s.pool, folder.id).await {
        for (version, key, content) in listed {
            claims.insert(group_key(version, &key), content);
        }
    }
    let views = groups
        .into_iter()
        .map(|group| {
            let trimmed = trim_space(&group.sample_observed_root_path);
            let root_path = if trimmed.is_empty() {
                silo_gocompat::path::dir(&group.sample_file_path)
            } else {
                trimmed.to_owned()
            };
            let key = group_key(group.group_key_version, &group.content_group_key);
            RootView {
                root_path,
                content_id: claims.get(&key).cloned().unwrap_or_default(),
                active: overrides.get(&key).cloned(),
                group,
            }
        })
        .collect();
    Ok((folder.name, views, total))
}

/// `rootOverride`, on both wires.
#[derive(Serialize)]
struct WireOverride {
    #[serde(skip_serializing_if = "String::is_empty")]
    forced_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    forced_title: String,
    #[serde(skip_serializing_if = "omit_empty")]
    forced_year: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    forced_tmdb_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    forced_imdb_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    forced_tvdb_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    note: String,
}

fn wire_override(o: admin::GroupOverride) -> WireOverride {
    WireOverride {
        forced_type: o.forced_type,
        forced_title: o.forced_title,
        forced_year: o.forced_year,
        forced_tmdb_id: o.forced_tmdb_id,
        forced_imdb_id: o.forced_imdb_id,
        forced_tvdb_id: o.forced_tvdb_id,
        note: o.note,
    }
}

#[derive(Serialize)]
struct V1Root {
    library_id: i64,
    library_name: String,
    root_path: String,
    state: String,
    inferred_type: String,
    type_confidence: String,
    title: String,
    year: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    tmdb_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    imdb_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    tvdb_id: String,
    observed_file_count: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    sample_file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_json: Option<RawMessage>,
    #[serde(skip_serializing_if = "String::is_empty")]
    override_source: String,
    first_seen_at: GoTime,
    last_seen_at: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_override: Option<WireOverride>,
    #[serde(skip_serializing_if = "String::is_empty")]
    content_id: String,
}

#[derive(Serialize)]
struct V1Roots {
    items: Vec<V1Root>,
    total: i64,
}

#[derive(Serialize)]
struct V2Root {
    library_id: Id,
    library_name: String,
    root_path: String,
    state: String,
    inferred_type: String,
    type_confidence: String,
    title: String,
    year: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    tmdb_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    imdb_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    tvdb_id: String,
    observed_file_count: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    sample_file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_json: Option<RawMessage>,
    #[serde(skip_serializing_if = "String::is_empty")]
    override_source: String,
    first_seen_at: Instant,
    last_seen_at: Instant,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_override: Option<WireOverride>,
    #[serde(skip_serializing_if = "String::is_empty")]
    content_id: String,
}

#[derive(Serialize)]
struct WithTotal<T: Serialize> {
    items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page: Option<PageInfo>,
    total: i64,
}

fn with_total<T: Serialize>(items: Vec<T>, next: String, total: i64) -> WithTotal<T> {
    let page: Collection<T> = paginated(items, next);
    WithTotal {
        items: page.items,
        page: page.page,
        total,
    }
}

/// One `SkippedRootView`, with its library name.
struct SkippedView {
    name: String,
    root: admin::SkippedRoot,
}

/// `ListSkippedRoots`. A zero limit is v1's whole list.
async fn skipped_roots(
    s: &Stack,
    search: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<SkippedView>, i64), ApiError> {
    let listed = folders::list(&s.pool)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to list libraries"))?;
    let names: HashMap<i64, String> = listed
        .into_iter()
        .map(|f| (i64::from(f.id), f.name))
        .collect();
    let roots = if limit > 0 {
        admin::list_skipped_page(&s.pool, search, limit, offset).await
    } else {
        admin::list_all_skipped(&s.pool).await
    }
    .map_err(|_| api(500, INTERNAL, "Failed to list skipped roots"))?;
    let mut total = roots.len() as i64;
    if limit > 0 {
        total = admin::count_skipped(&s.pool, search)
            .await
            .map_err(|_| api(500, INTERNAL, "Failed to count skipped roots"))?;
    }
    let views = roots
        .into_iter()
        .map(|root| SkippedView {
            name: names
                .get(&root.media_folder_id)
                .cloned()
                .unwrap_or_default(),
            root,
        })
        .collect();
    Ok((views, total))
}

#[derive(Serialize)]
struct V1Skipped {
    library_id: i64,
    library_name: String,
    root_path: String,
    reason: String,
    sample_file_path: String,
    file_count: i64,
    first_seen_at: GoTime,
    last_seen_at: GoTime,
}

#[derive(Serialize)]
struct V2Skipped {
    library_id: Id,
    library_name: String,
    root_path: String,
    reason: String,
    sample_file_path: String,
    file_count: i64,
    first_seen_at: Instant,
    last_seen_at: Instant,
}

#[derive(Serialize)]
struct V1Stale {
    content_id: String,
    library_id: i64,
    library_name: String,
    title: String,
    year: i64,
    content_type: String,
    provider: String,
    provider_id: String,
    first_seen_at: String,
    last_seen_at: String,
}

#[derive(Serialize)]
struct V2Stale {
    content_id: String,
    library_id: Id,
    library_name: String,
    title: String,
    year: i64,
    content_type: String,
    provider: String,
    provider_id: String,
    first_seen_at: Instant,
    last_seen_at: Instant,
}

/// `listAllStaleIDs`.
async fn all_stale(s: &Stack) -> Result<Vec<V1Stale>, ApiError> {
    let stale = admin::list_all_stale(&s.pool)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to list stale IDs"))?;
    if stale.is_empty() {
        return Ok(Vec::new());
    }
    let mut ids: Vec<String> = Vec::with_capacity(stale.len());
    for row in &stale {
        if !ids.contains(&row.content_id) {
            ids.push(row.content_id.clone());
        }
    }
    let items = admin::stale_items(&s.pool, &ids)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to load item data"))?;
    let zero = admin::StaleItem::default();
    let layout = "2006-01-02T15:04:05Z";
    let mut out = Vec::new();
    for row in stale {
        let info = items.get(&row.content_id).unwrap_or(&zero);
        if !admin::is_actionable_stale(&row.content_id, info, &row) {
            continue;
        }
        out.push(V1Stale {
            library_id: info.library_id,
            library_name: info.library_name.clone(),
            title: info.title.clone(),
            year: info.year,
            content_type: info.content_type.clone(),
            first_seen_at: go_time(row.first_seen_at).format(layout),
            last_seen_at: go_time(row.last_seen_at).format(layout),
            content_id: row.content_id,
            provider: row.provider,
            provider_id: row.provider_id,
        });
    }
    Ok(out)
}

/// The rows `ListUnmatchedItems` reads.
struct UnmatchedRow {
    content_id: String,
    title: String,
    year: i64,
    content_type: String,
    library_id: i64,
    library_name: String,
    status: String,
    ignored_at: Option<SystemTime>,
}

/// `ListUnmatchedItems`.
async fn unmatched(
    s: &Stack,
    search: &str,
    ignored: bool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<UnmatchedRow>, i64), ApiError> {
    let search = trim_space(search);
    let pattern = format!("%{search}%");
    let filter = if search.is_empty() {
        ""
    } else {
        " AND (
			mi.title ILIKE $1
			OR mi.type ILIKE $1
			OR mi.status ILIKE $1
			OR EXISTS (
				SELECT 1
				FROM media_item_libraries search_mil
				JOIN media_folders search_f ON search_f.id = search_mil.media_folder_id
				WHERE search_mil.content_id = mi.content_id
				  AND search_f.name ILIKE $1
			)
		)"
    };
    let guards = format!(
        " AND NOT EXISTS (SELECT 1 FROM manga_chapters mc WHERE mc.chapter_content_id = mi.content_id) AND EXISTS (SELECT 1 FROM media_item_libraries in_library WHERE in_library.content_id = mi.content_id){}",
        if ignored {
            " AND mi.match_ignored_at IS NOT NULL"
        } else {
            " AND mi.match_ignored_at IS NULL"
        }
    );
    let count_sql = format!(
        "
		SELECT COUNT(*)
		FROM media_items mi
		WHERE mi.status IN ('unmatched', 'pending', 'ambiguous'){guards}{filter}"
    );
    let mut args: Vec<&(dyn silo_pg::ToSql + Sync)> = Vec::new();
    if !search.is_empty() {
        args.push(&pattern);
    }
    let count = s
        .pool
        .query(&count_sql, &args)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to count unmatched items"))?;
    let total: i64 = count
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(|| api(500, INTERNAL, "Failed to count unmatched items"))?;
    let at = args.len() + 1;
    let list_sql = format!(
        "
		SELECT mi.content_id, mi.title, mi.year, mi.type, mi.status,
		       COALESCE(lib.folder_id, 0),
		       COALESCE(lib.folder_name, ''),
		       mi.match_ignored_at
		FROM media_items mi
		LEFT JOIN LATERAL (
			SELECT mil.media_folder_id AS folder_id, f.name AS folder_name
			FROM media_item_libraries mil
			JOIN media_folders f ON f.id = mil.media_folder_id
			WHERE mil.content_id = mi.content_id
			LIMIT 1
		) lib ON true
		WHERE mi.status IN ('unmatched', 'pending', 'ambiguous'){guards}{filter}
		ORDER BY mi.title ASC, mi.content_id ASC
		LIMIT ${at} OFFSET ${}
	",
        at + 1
    );
    args.push(&limit);
    args.push(&offset);
    let rows = s
        .pool
        .query(&list_sql, &args)
        .await
        .map_err(|_| api(500, INTERNAL, "Failed to list unmatched items"))?;
    let scan = || api(500, INTERNAL, "Failed to scan item");
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        use silo_pg::AnyInt;
        out.push(UnmatchedRow {
            content_id: r.try_get(0).map_err(|_| scan())?,
            title: r.try_get(1).map_err(|_| scan())?,
            year: r.try_get::<_, AnyInt>(2).map_err(|_| scan())?.0,
            content_type: r.try_get(3).map_err(|_| scan())?,
            status: r.try_get(4).map_err(|_| scan())?,
            library_id: r.try_get::<_, AnyInt>(5).map_err(|_| scan())?.0,
            library_name: r.try_get(6).map_err(|_| scan())?,
            ignored_at: r.try_get(7).map_err(|_| scan())?,
        });
    }
    Ok((out, total))
}

#[derive(Serialize)]
struct V1Unmatched {
    content_id: String,
    title: String,
    year: i64,
    content_type: String,
    library_id: i64,
    library_name: String,
    status: String,
}

#[derive(Serialize)]
struct V1UnmatchedList {
    items: Vec<V1Unmatched>,
    total: i64,
}

#[derive(Serialize)]
struct V2Unmatched {
    content_id: String,
    title: String,
    year: i64,
    content_type: String,
    library_id: Id,
    library_name: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ignored_at: Option<Instant>,
}

#[derive(Serialize)]
struct V1UserLibrary {
    id: i32,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    sort_order: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_url: String,
}

#[derive(Serialize)]
struct V2UserLibrary {
    id: Id,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    sort_order: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_url: String,
}

/// `ListUserLibraries`: the viewer gate always leaves a scope.
async fn user_libraries(
    r: &Request,
    s: &Stack,
    include_hidden: bool,
) -> Result<Vec<Folder>, ApiError> {
    let scope = scope_of(r);
    let listed = match scope.as_deref() {
        Some(scope) if scope.libraries_restricted => {
            let mut ids = scope.allowed_library_ids.clone();
            if include_hidden {
                ids.extend(scope.hidden_library_ids.iter().flatten());
            }
            folders::list_by_ids(&s.pool, &ids).await
        }
        _ => folders::get_enabled(&s.pool).await,
    };
    listed.map_err(|_| api(500, INTERNAL, "Failed to list libraries"))
}

/// `viewerCanAccessLibrary`.
fn viewer_can_access(r: &Request, library: i64) -> bool {
    let Some(scope) = scope_of(r) else {
        return true;
    };
    if scope.libraries_restricted {
        scope.allowed_library_ids.contains(&library)
    } else {
        !scope.disabled_library_ids.contains(&library)
    }
}

#[derive(Serialize)]
struct LayoutEntry {
    id: String,
    section_type: String,
    title: String,
    featured: bool,
    item_limit: i64,
    is_custom: bool,
    customized: bool,
}

#[derive(Serialize)]
struct Layout {
    sections: Vec<LayoutEntry>,
}

/// `LibraryLayout`.
async fn library_layout(r: &Request, s: &Stack, library: i64) -> Result<Layout, ApiError> {
    let missing = || api(404, NOT_FOUND, LIBRARY_NOT_FOUND);
    if !viewer_can_access(r, library) {
        return Err(missing());
    }
    let folder = folders::get_by_id(&s.pool, library)
        .await
        .map_err(|e| match e {
            FolderError::NotFound => missing(),
            FolderError::Db(_) => api(500, INTERNAL, "Failed to load library"),
        })?;
    if !folder.enabled {
        return Err(missing());
    }
    let failed = |_| api(500, INTERNAL, "Failed to load sections");
    let mut admin_sections = sections::list_library_sections(&s.pool, folder.id)
        .await
        .map_err(failed)?;
    if admin_sections.is_empty() {
        admin_sections = sections::default_library_sections(&folder.kind);
    }
    let profile = get_profile_id(r);
    let user_id = claims_of(r).map_or(0, |c| c.user_id) as i32;
    let overrides = if profile.is_empty() {
        Vec::new()
    } else {
        sections::list_section_overrides(&s.pool, user_id, &profile, &folder.id.to_string())
            .await
            .map_err(failed)?
    };
    let mut resolved = sections::resolve(&admin_sections, &overrides);
    // `NextUpMode`: the profile gate leaves a scope that carries the mode.
    if user_id > 0
        && !profile.is_empty()
        && scope_of(r).is_some_and(|scope| scope.next_up_mode == "separate")
    {
        resolved = sections::inject_next_up(resolved);
    }
    Ok(Layout {
        sections: resolved
            .into_iter()
            .map(|s| LayoutEntry {
                id: s.id,
                section_type: s.section_type,
                title: s.title,
                featured: s.featured,
                item_limit: s.item_limit,
                is_custom: s.is_custom,
                customized: s.customized,
            })
            .collect(),
    })
}

#[derive(Serialize)]
struct V1Pref {
    profile_id: String,
    library_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    audio_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subtitle_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subtitle_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    show_forced_subtitles: Option<bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    updated_at: String,
}

#[derive(Serialize)]
struct V1Prefs {
    preferences: Vec<V1Pref>,
}

#[derive(Serialize)]
struct V2Pref {
    profile_id: String,
    library_id: Id,
    #[serde(skip_serializing_if = "Option::is_none")]
    audio_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subtitle_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subtitle_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    show_forced_subtitles: Option<bool>,
    updated_at: String,
}

const PLAYBACK_KEYS: [&str; 4] = [
    keys::PLAYBACK_AUDIO_LANGUAGE,
    keys::PLAYBACK_SUBTITLE_LANGUAGE,
    keys::PLAYBACK_SUBTITLE_MODE,
    keys::PLAYBACK_SHOW_FORCED_SUBTITLES,
];

/// `ListLibraryPlaybackPreferencesCanonical`, then `libraryPlaybackPreferenceOf`.
async fn canonical_prefs(s: &Stack, user_id: i32, profile: &str) -> Result<Vec<V2Pref>, Problem> {
    let store = PostgresUserStore::new(s.pool.clone(), user_id);
    let keys_owned: Vec<String> = PLAYBACK_KEYS.iter().map(|k| (*k).to_owned()).collect();
    let values = store
        .list_setting_values_by_scope(
            profile,
            &SettingScope::new("profile_library".to_owned()),
            &keys_owned,
        )
        .await
        .map_err(|_| internal_problem())?;
    let mut by_library: BTreeMap<i64, V2Pref> = BTreeMap::new();
    let mut newest: BTreeMap<i64, String> = BTreeMap::new();
    for v in values {
        let library = v.identity.library_id;
        let pref = by_library.entry(library).or_insert_with(|| V2Pref {
            profile_id: profile.to_owned(),
            library_id: Id::from_int(library),
            audio_language: None,
            subtitle_language: None,
            subtitle_mode: None,
            show_forced_subtitles: None,
            updated_at: String::new(),
        });
        match v.identity.key.as_str() {
            keys::PLAYBACK_SHOW_FORCED_SUBTITLES => {
                pref.show_forced_subtitles = Some(
                    silo_gocompat::json::unmarshal::<bool>(&v.value)
                        .map_err(|_| internal_problem())?,
                );
            }
            key => {
                let text = silo_gocompat::json::unmarshal::<String>(&v.value)
                    .map_err(|_| internal_problem())?;
                match key {
                    keys::PLAYBACK_AUDIO_LANGUAGE => pref.audio_language = Some(text),
                    keys::PLAYBACK_SUBTITLE_LANGUAGE => pref.subtitle_language = Some(text),
                    keys::PLAYBACK_SUBTITLE_MODE => pref.subtitle_mode = Some(text),
                    _ => {}
                }
            }
        }
        let latest = newest.entry(library).or_default();
        if v.updated_at > *latest {
            latest.clone_from(&v.updated_at);
        }
    }
    let mut out = Vec::with_capacity(by_library.len());
    for (library, mut pref) in by_library {
        let at = newest.remove(&library).unwrap_or_default();
        pref.updated_at = super::settings::stored_instant(&at)?.unwrap_or_default();
        out.push(pref);
    }
    Ok(out)
}

#[derive(Serialize)]
struct JobProgress {
    current: i64,
    total: i64,
    unit: &'static str,
}

#[derive(Serialize)]
struct RefreshResult {
    library_id: Id,
    refreshed: i64,
    failed: i64,
}

#[derive(Serialize)]
struct DeletionResult {
    library_id: Id,
    deleted_media_files: i64,
    deleted_item_links: i64,
    deleted_orphaned_items: i64,
}

#[derive(Serialize)]
struct JobFailure {
    #[serde(rename = "type")]
    kind: String,
    title: &'static str,
    detail: &'static str,
    retryable: bool,
}

/// `apiv2.AdminJob`. `template_result` is only on template jobs, which this row hides.
#[derive(Serialize)]
struct WireJob {
    id: String,
    kind: String,
    state: String,
    terminal: bool,
    cancelable: bool,
    created_at: Instant,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at: Option<Instant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<JobProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_result: Option<RefreshResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion_result: Option<DeletionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<JobFailure>,
}

const JOB_REFRESH: &str = "library_refresh";
const JOB_DELETE: &str = "delete_library";

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct RefreshPayload {
    library_id: i64,
    refreshed_ok: i64,
    pipeline_ok: i64,
    refreshed_failed: i64,
    pipeline_failed: i64,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct DeletePayload {
    library_id: i64,
    deleted_media_files: i64,
    deleted_item_links: i64,
    deleted_orphaned_items: i64,
}

/// `adminJobOf`.
fn wire_job(job: admin::AdminJob) -> WireJob {
    let (mut state, mut terminal) = (job.status.clone(), false);
    match job.status.as_str() {
        "completed" => {
            state = "succeeded".to_owned();
            terminal = true;
        }
        "failed" => terminal = true,
        "cancelled" => {
            state = "canceled".to_owned();
            terminal = true;
        }
        _ => {}
    }
    if job.cancel_requested && !terminal {
        state = "canceling".to_owned();
    }
    let payload = job.result_payload.unwrap_or_default();
    let done = job.status == "completed";
    WireJob {
        cancelable: job.job_type == JOB_REFRESH && !terminal,
        progress: (job.job_type == JOB_REFRESH
            && job.progress_total > 0
            && job.progress_current >= 0
            && job.progress_current <= job.progress_total)
            .then_some(JobProgress {
                current: job.progress_current,
                total: job.progress_total,
                unit: "items",
            }),
        refresh_result: (done && job.job_type == JOB_REFRESH)
            .then(|| silo_gocompat::json::unmarshal::<RefreshPayload>(payload.as_bytes()).ok())
            .flatten()
            .map(|p| RefreshResult {
                library_id: Id::from_int(p.library_id),
                refreshed: p.refreshed_ok + p.pipeline_ok,
                failed: p.refreshed_failed + p.pipeline_failed,
            }),
        deletion_result: (done && job.job_type == JOB_DELETE)
            .then(|| silo_gocompat::json::unmarshal::<DeletePayload>(payload.as_bytes()).ok())
            .flatten()
            .map(|p| DeletionResult {
                library_id: Id::from_int(p.library_id),
                deleted_media_files: p.deleted_media_files,
                deleted_item_links: p.deleted_item_links,
                deleted_orphaned_items: p.deleted_orphaned_items,
            }),
        failure: (job.status == "failed").then(|| JobFailure {
            kind: format!("{}job_failed", silo_api_v2::problem::PROBLEM_TYPE_ORIGIN),
            title: "Job failed",
            detail: "The operation could not finish. Inspect administrator diagnostics before submitting new work.",
            retryable: false,
        }),
        id: job.id,
        kind: job.job_type,
        state,
        terminal,
        created_at: instant(job.requested_at),
        started_at: instant_opt(job.started_at),
        finished_at: instant_opt(job.completed_at),
    }
}

/// `monitoringReportRank`.
fn report_rank(state: &str) -> i32 {
    match state {
        "monitoring" => 7,
        "starting" => 6,
        "limit_reached" => 5,
        "root_unavailable" => 4,
        "unsupported_filesystem" => 3,
        "unsupported_platform" => 2,
        "error" => 1,
        _ => 0,
    }
}

/// `betterMonitoringReport`.
fn better_report(a: &admin::NodeReport, b: &admin::NodeReport) -> bool {
    let (ra, rb) = (report_rank(&a.state), report_rank(&b.state));
    if ra != rb {
        return ra > rb;
    }
    if a.updated_at != b.updated_at {
        return a.updated_at > b.updated_at;
    }
    a.node_id < b.node_id
}

#[derive(Serialize)]
struct MonitoringEntry {
    library_id: Id,
    enabled: bool,
    state: String,
    backend: String,
    detail: String,
    directories: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<Instant>,
}

#[derive(Serialize)]
struct Monitoring {
    server_enabled: bool,
    libraries: Vec<MonitoringEntry>,
}

/// `realtimeMonitoringOf`, over `RealtimeMonitoringStatus`.
async fn realtime_monitoring(s: &Stack) -> Result<Monitoring, String> {
    let listed = folders::list(&s.pool)
        .await
        .map_err(|_| "list".to_owned())?;
    let reports = admin::fresh_reports(&s.pool, 180.0).await?;
    let server_enabled = s
        .settings
        .get("scanner.realtime_monitoring")
        .await
        .ok()
        .filter(|v| !v.is_empty())
        .is_none_or(|v| matches!(v.as_str(), "1" | "t" | "T" | "TRUE" | "true" | "True"));
    let mut best: HashMap<i64, admin::NodeReport> = HashMap::new();
    for report in reports {
        match best.get(&report.library_id) {
            Some(current) if !better_report(&report, current) => {}
            _ => {
                best.insert(report.library_id, report);
            }
        }
    }
    let libraries = listed
        .into_iter()
        .map(|f| {
            let mut entry = MonitoringEntry {
                library_id: Id::from_int(i64::from(f.id)),
                enabled: f.realtime_monitoring,
                state: String::new(),
                backend: String::new(),
                detail: String::new(),
                directories: 0,
                node_id: String::new(),
                updated_at: None,
            };
            let report = best.get(&i64::from(f.id));
            if !server_enabled {
                entry.state = "server_disabled".to_owned();
            } else if !f.enabled {
                entry.state = "library_disabled".to_owned();
            } else if !f.realtime_monitoring {
                entry.state = "monitoring_off".to_owned();
            } else if let Some(report) = report {
                entry.state = if report_rank(&report.state) == 0 {
                    "error".to_owned()
                } else {
                    report.state.clone()
                };
                entry.backend.clone_from(&report.backend);
                entry.detail.clone_from(&report.detail);
                entry.directories = report.directories;
                entry.node_id.clone_from(&report.node_id);
                entry.updated_at = Some(instant(report.updated_at));
            } else {
                entry.state = "not_reporting".to_owned();
                entry.detail = "No server node can see this library's folders".to_owned();
            }
            entry
        })
        .collect();
    Ok(Monitoring {
        server_enabled,
        libraries,
    })
}

#[derive(Serialize)]
struct LibraryCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    realtime_monitoring: bool,
    trickplay: bool,
    trickplay_supported: bool,
    ignore_unmatched: bool,
}

/// `ListStaleIDs`' v2 page.
async fn stale_page(
    s: &Stack,
    search: &str,
    limit: i64,
    offset: i64,
) -> Result<(Vec<admin::ActionableStale>, i64), Problem> {
    let page = admin::list_actionable_stale(&s.pool, limit, offset, search)
        .await
        .map_err(|_| internal_problem())?;
    let total = admin::count_actionable_stale(&s.pool, search)
        .await
        .map_err(|_| internal_problem())?;
    Ok((page, total))
}

fn v1_roots(name: &str, id: i64, views: Vec<RootView>, total: i64) -> V1Roots {
    V1Roots {
        total,
        items: views
            .into_iter()
            .map(|v| V1Root {
                library_id: id,
                library_name: name.to_owned(),
                root_path: v.root_path,
                state: v.group.state,
                inferred_type: v.group.inferred_type,
                type_confidence: v.group.type_confidence,
                title: v.group.base_title,
                year: v.group.base_year,
                tmdb_id: v.group.tmdb_id,
                imdb_id: v.group.imdb_id,
                tvdb_id: v.group.tvdb_id,
                observed_file_count: v.group.observed_file_count,
                sample_file_path: v.group.sample_file_path,
                evidence_json: raw(v.group.evidence_json),
                override_source: v.group.override_source,
                first_seen_at: go_time(v.group.first_seen_at),
                last_seen_at: go_time(v.group.last_seen_at),
                active_override: v.active.map(wire_override),
                content_id: v.content_id,
            })
            .collect(),
    }
}

fn v2_root(name: &str, id: i64, v: RootView) -> V2Root {
    V2Root {
        library_id: Id::from_int(id),
        library_name: name.to_owned(),
        root_path: v.root_path,
        state: v.group.state,
        inferred_type: v.group.inferred_type,
        type_confidence: v.group.type_confidence,
        title: v.group.base_title,
        year: v.group.base_year,
        tmdb_id: v.group.tmdb_id,
        imdb_id: v.group.imdb_id,
        tvdb_id: v.group.tvdb_id,
        observed_file_count: v.group.observed_file_count,
        sample_file_path: v.group.sample_file_path,
        evidence_json: raw(v.group.evidence_json),
        override_source: v.group.override_source,
        first_seen_at: instant(v.group.first_seen_at),
        last_seen_at: instant(v.group.last_seen_at),
        active_override: v.active.map(wire_override),
        content_id: v.content_id,
    }
}

/// Go's `url.Values.Encode`, for names already in order.
fn encoded(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                silo_gocompat::url::query_escape(k),
                silo_gocompat::url::query_escape(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// `strconv.Atoi` of a query value, then a positive bound; the `HandleListRoots` and `HandleListUnmatchedItems` limit.
fn v1_limit(raw_value: &str, default: i64, max: i64) -> i64 {
    match raw_value.parse::<i64>() {
        Ok(n) if n > 0 && n <= max => n,
        _ => default,
    }
}

fn v1_offset(raw_value: &str) -> i64 {
    match raw_value.parse::<i64>() {
        Ok(n) if n >= 0 => n,
        _ => 0,
    }
}

/// A method Go owns at a native v1 path: never reached, because `Gate` sends it to Go. It is here so the
/// subrouter's 405 lists what chi's does.
fn go_owned() -> silo_http::BoxHandler {
    handler_fn(|w, _r| {
        Box::pin(async move {
            write_v1_error(w, 500, INTERNAL, "This method is served by Go").await;
        })
    })
}

fn mount_v1(stack: &Arc<Stack>, api_mux: &Mux) {
    let libs = Mux::new();
    libs.use_middleware([stack.v1_group(V1_LIBRARIES)]);
    libs.post("/", go_owned());
    libs.put("/reorder", go_owned());
    libs.put("/roots/override", go_owned());
    libs.delete("/roots/override", go_owned());
    libs.put("/{id}/providers", go_owned());
    libs.get(
        "/",
        route!(stack, |s, w, _r| {
            match list_libraries(&s).await {
                Ok(listed) => {
                    let out: Vec<V1Library> =
                        listed.into_iter().map(|f| v1_library(&s, f)).collect();
                    write_v1_json(w, 200, &out).await;
                }
                Err(e) => write_api(w, &e).await,
            }
        }),
    );
    libs.get(
        "/roots",
        route!(stack, |s, w, r| {
            let id = match query_param(r, "library_id").parse::<i64>() {
                Ok(n) if n > 0 => n,
                _ => return write_v1_error(w, 400, "bad_request", "library_id is required").await,
            };
            let limit = v1_limit(trim_space(&query_param(r, "limit")), 100, 500);
            let offset = v1_offset(trim_space(&query_param(r, "offset")));
            let state = query_param(r, "state");
            match library_roots(&s, id, trim_space(&state), "", limit, offset).await {
                Ok((name, views, total)) => {
                    write_v1_json(w, 200, &v1_roots(&name, id, views, total)).await;
                }
                Err(e) => write_api(w, &e).await,
            }
        }),
    );
    libs.get(
        "/skipped-roots",
        route!(stack, |s, w, _r| {
            match skipped_roots(&s, "", 0, 0).await {
                Ok((views, _)) => {
                    let out: Vec<V1Skipped> = views
                        .into_iter()
                        .map(|v| V1Skipped {
                            library_id: v.root.media_folder_id,
                            library_name: v.name,
                            root_path: v.root.root_path,
                            reason: v.root.reason,
                            sample_file_path: v.root.sample_file_path,
                            file_count: v.root.file_count,
                            first_seen_at: go_time(v.root.first_seen_at),
                            last_seen_at: go_time(v.root.last_seen_at),
                        })
                        .collect();
                    write_v1_json(w, 200, &out).await;
                }
                Err(e) => write_api(w, &e).await,
            }
        }),
    );
    libs.get(
        "/stale-ids",
        route!(stack, |s, w, _r| {
            match all_stale(&s).await {
                Ok(out) => write_v1_json(w, 200, &out).await,
                Err(e) => write_api(w, &e).await,
            }
        }),
    );
    libs.get(
        "/unmatched-items",
        route!(stack, |s, w, r| {
            let limit = v1_limit(&query_param(r, "limit"), 100, 500);
            let offset = v1_offset(&query_param(r, "offset"));
            match unmatched(&s, &query_param(r, "q"), false, limit, offset).await {
                Ok((rows, total)) => {
                    let items = rows
                        .into_iter()
                        .map(|v| V1Unmatched {
                            content_id: v.content_id,
                            title: v.title,
                            year: v.year,
                            content_type: v.content_type,
                            library_id: v.library_id,
                            library_name: v.library_name,
                            status: v.status,
                        })
                        .collect();
                    write_v1_json(w, 200, &V1UnmatchedList { items, total }).await;
                }
                Err(e) => write_api(w, &e).await,
            }
        }),
    );
    libs.get(
        "/metadata-match-queue",
        route!(stack, |s, w, _r| {
            match list_queues(&s).await {
                Ok(list) => {
                    let out: Vec<V1QueueStatus> = list.into_iter().map(Into::into).collect();
                    write_v1_json(w, 200, &out).await;
                }
                Err(e) => write_api(w, &e).await,
            }
        }),
    );
    libs.get(
        "/{id}/metadata-match-queue",
        route!(stack, |s, w, r| {
            let Some(id) = atoi(r.url_param("id")) else {
                return write_v1_error(w, 400, "bad_request", "Invalid library ID").await;
            };
            let limit = v1_limit(trim_space(&query_param(r, "limit")), 10, 50);
            let offset = v1_offset(trim_space(&query_param(r, "offset")));
            match queue_detail(&s, id, limit, offset).await {
                Ok(detail) => write_v1_json(w, 200, &v1_queue_detail(detail, limit, offset)).await,
                Err(e) => write_api(w, &e).await,
            }
        }),
    );
    libs.get(
        "/provider-defaults",
        route!(stack, |s, w, r| {
            let kind = query_param(r, "library_type");
            write_v1_json(w, 200, &v1_levels(provider_defaults(&s, &kind).await)).await;
        }),
    );
    libs.get(
        "/{id}/providers",
        route!(stack, |s, w, r| {
            let Some(id) = atoi(r.url_param("id")) else {
                return write_v1_error(w, 400, "bad_request", "Invalid library ID").await;
            };
            match library_providers(&s, id).await {
                Ok(levels) => write_v1_json(w, 200, &v1_levels(levels)).await,
                Err(e) => write_api(w, &e).await,
            }
        }),
    );
    api_mux.mount("/api/v1/libraries", libs);

    let prefs = Mux::new();
    prefs.use_middleware([stack.v1_group(V1_PREFS)]);
    prefs.put("/{library_id}", go_owned());
    prefs.delete("/{library_id}", go_owned());
    prefs.get(
        "/",
        route!(stack, |s, w, r| {
            let user_id = claims_of(r).map_or(0, |c| c.user_id) as i32;
            let profile = get_profile_id(r);
            match admin::legacy_playback_prefs(&s.pool, user_id, &profile).await {
                Ok(rows) => {
                    let preferences = rows
                        .into_iter()
                        .map(|p| V1Pref {
                            profile_id: p.profile_id,
                            library_id: p.library_id,
                            audio_language: p.audio_language,
                            subtitle_language: p.subtitle_language,
                            subtitle_mode: p.subtitle_mode,
                            show_forced_subtitles: p.show_forced_subtitles,
                            updated_at: p.updated_at,
                        })
                        .collect();
                    write_v1_json(w, 200, &V1Prefs { preferences }).await;
                }
                Err(_) => {
                    write_v1_error(
                        w,
                        500,
                        INTERNAL,
                        "Failed to list library playback preferences",
                    )
                    .await;
                }
            }
        }),
    );
    api_mux.mount("/api/v1/library-playback-prefs", prefs);

    let at = "/api/v1/user/libraries";
    api_mux.get(
        at,
        stack.v1(
            at,
            V1_VIEWER,
            route!(stack, |s, w, r| {
                match user_libraries(r, &s, false).await {
                    Ok(listed) => {
                        let out: Vec<V1UserLibrary> = listed
                            .into_iter()
                            .map(|f| V1UserLibrary {
                                poster_url: poster_url(&s, &f.poster_path),
                                id: f.id,
                                name: f.name,
                                kind: f.kind,
                                sort_order: f.sort_order,
                            })
                            .collect();
                        write_v1_json(w, 200, &out).await;
                    }
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );

    let at = "/api/v1/library/{id}/layout";
    api_mux.get(
        at,
        stack.v1(
            at,
            V1_PREFS,
            route!(stack, |s, w, r| {
                let Some(id) = atoi(r.url_param("id")) else {
                    return write_v1_error(w, 400, "bad_request", "Invalid library ID").await;
                };
                match library_layout(r, &s, id).await {
                    Ok(layout) => write_v1_json(w, 200, &layout).await,
                    Err(e) => write_api(w, &e).await,
                }
            }),
        ),
    );
}

/// `actingUserID`.
fn acting_user(r: &Request) -> Option<i32> {
    claims_of(r).map(|c| c.user_id as i32)
}

fn require_acting(r: &Request) -> Result<i32, Problem> {
    acting_user(r).ok_or_else(|| {
        Problem::new(
            super::chain::problem_type("authentication_required"),
            "Authentication is required.",
        )
    })
}

fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/libraries";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                match list_libraries(&s).await {
                    Ok(listed) => {
                        let items: Vec<V2Library> =
                            listed.into_iter().map(|f| v2_library(&s, f)).collect();
                        write_v2_json(w, &new_collection(items)).await;
                    }
                    Err(e) => write_problem(w, r, library_problem(&e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/libraries/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getLibraryCapabilities", |revision| {
                        capability_json(&LibraryCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            realtime_monitoring: true,
                            trickplay: true,
                            trickplay_supported: true,
                            ignore_unmatched: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    let path = "/api/v2/libraries/realtime-monitoring";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                match realtime_monitoring(&s).await {
                    Ok(out) => write_v2_json(w, &out).await,
                    Err(_) => write_problem(w, r, internal_problem()).await,
                }
            }),
        ),
    );

    let path = "/api/v2/libraries/metadata-match-queue";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                match list_queues(&s).await {
                    Ok(list) => {
                        let items: Vec<V2QueueStatus> = list.into_iter().map(Into::into).collect();
                        write_v2_json(w, &new_collection(items)).await;
                    }
                    Err(e) => write_problem(w, r, library_problem(&e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/libraries/provider-defaults";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let kind = query_param(r, "library_type");
                write_v2_json(w, &v2_levels(provider_defaults(&s, &kind).await)).await;
            }),
        ),
    );

    let path = "/api/v2/libraries/{id}/providers";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let id = match library_id(r.url_param("id")) {
                    Ok(id) => id,
                    Err(p) => return write_problem(w, r, p).await,
                };
                match library_providers(&s, id).await {
                    Ok(mut levels) => {
                        // v2 content levels are named; the legacy unlevelled rows stay hidden.
                        levels.remove("");
                        write_v2_json(w, &v2_levels(levels)).await;
                    }
                    Err(e) => write_problem(w, r, library_problem(&e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/libraries/{id}/metadata-match-queue";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let raw_id = r.url_param("id").to_owned();
                let id = match library_id(&raw_id) {
                    Ok(id) => id,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let user = match require_acting(r) {
                    Ok(user) => user,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let scope = CursorScope {
                    operation_id: "getMetadataMatchQueue".to_owned(),
                    security: user.to_string(),
                    filter: raw_id,
                    sort: "queue".to_owned(),
                    tiebreaker: "offset".to_owned(),
                };
                let offset = match decode_offset(&s, &scope, &query_param(r, "cursor")) {
                    Ok(offset) => offset,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let limit = limit_of(r, 10);
                let d = match queue_detail(&s, id, limit, offset).await {
                    Ok(d) => d,
                    Err(e) => return write_problem(w, r, library_problem(&e)).await,
                };
                let end = offset + limit;
                let more = d.movie_total > end || d.series_total > end || d.raw_total > end;
                let next = if more {
                    match s.cursors.encode(&scope, &OffsetPosition { o: end }) {
                        Ok(next) => next,
                        Err(_) => return write_problem(w, r, internal_problem()).await,
                    }
                } else {
                    String::new()
                };
                let body = V2QueueDetail {
                    status: d.status.into(),
                    movies: d
                        .movies
                        .into_iter()
                        .map(|e| V2MovieEntry {
                            media_file_id: Id::from_int(e.media_file_id),
                            library_id: Id::from_int(e.media_folder_id),
                            file_path: e.path,
                            first_queued_at: instant(e.first_queued_at),
                            available_at: instant(e.available_at),
                            last_attempted_at: instant_opt(e.last_attempted_at),
                            attempt_count: e.attempt_count,
                            last_error: e.last_error,
                            state: e.state,
                            failure_kind: e.failure_kind,
                            failure_detail: raw(e.failure_detail),
                            deterministic_attempt_count: e.deterministic_attempt_count,
                            matcher_revision: e.matcher_revision,
                            parked_at: instant_opt(e.parked_at),
                            updated_at: instant(e.updated_at),
                        })
                        .collect(),
                    series: d
                        .series
                        .into_iter()
                        .map(|e| V2SeriesEntry {
                            library_id: Id::from_int(e.media_folder_id),
                            observed_root_path: e.path,
                            first_queued_at: instant(e.first_queued_at),
                            available_at: instant(e.available_at),
                            last_attempted_at: instant_opt(e.last_attempted_at),
                            attempt_count: e.attempt_count,
                            last_error: e.last_error,
                            state: e.state,
                            failure_kind: e.failure_kind,
                            failure_detail: raw(e.failure_detail),
                            deterministic_attempt_count: e.deterministic_attempt_count,
                            matcher_revision: e.matcher_revision,
                            parked_at: instant_opt(e.parked_at),
                            updated_at: instant(e.updated_at),
                        })
                        .collect(),
                    raw_files: d
                        .raw_files
                        .into_iter()
                        .map(|f| V2RawEntry {
                            media_file_id: Id::from_int(f.id),
                            library_id: Id::from_int(f.media_folder_id),
                            file_path: f.file_path,
                            base_title: f.base_title,
                            base_year: f.base_year,
                            base_type: f.base_type,
                            last_attempted_at: instant_opt(f.match_attempted_at),
                            created_at: instant(f.created_at),
                            updated_at: instant(f.updated_at),
                        })
                        .collect(),
                    page: PageInfo {
                        has_more: !next.is_empty(),
                        next_cursor: next,
                    },
                };
                write_v2_json(w, &body).await;
            }),
        ),
    );

    let path = "/api/v2/libraries/roots";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let id = match library_id(&query_param(r, "library_id")) {
                    Ok(id) => id,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let user = match require_acting(r) {
                    Ok(user) => user,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let state_raw = query_param(r, "state");
                let search_raw = query_param(r, "q");
                let (state, search) = (trim_space(&state_raw), trim_space(&search_raw));
                let id_text = id.to_string();
                let scope = CursorScope {
                    operation_id: "listLibraryRoots".to_owned(),
                    security: user.to_string(),
                    filter: encoded(&[("library_id", &id_text), ("q", search), ("state", state)]),
                    sort: "store".to_owned(),
                    tiebreaker: "store".to_owned(),
                };
                let offset = match decode_offset(&s, &scope, &query_param(r, "cursor")) {
                    Ok(offset) => offset,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let limit = limit_of(r, 50);
                let (name, views, total) =
                    match library_roots(&s, id, state, search, limit + 1, offset).await {
                        Ok(out) => out,
                        Err(e) => return write_problem(w, r, library_problem(&e)).await,
                    };
                let (views, next) = match offset_page(&s, &scope, views, limit, offset) {
                    Ok(out) => out,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let items: Vec<V2Root> = views.into_iter().map(|v| v2_root(&name, id, v)).collect();
                write_v2_json(w, &with_total(items, next, total)).await;
            }),
        ),
    );

    let path = "/api/v2/libraries/skipped-roots";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let user = match require_acting(r) {
                    Ok(user) => user,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let search_raw = query_param(r, "q");
                let search = trim_space(&search_raw);
                let scope = CursorScope {
                    operation_id: "listSkippedRoots".to_owned(),
                    security: user.to_string(),
                    filter: search.to_owned(),
                    sort: "last_seen_at".to_owned(),
                    tiebreaker: "library_id,root_path".to_owned(),
                };
                let offset = match decode_offset(&s, &scope, &query_param(r, "cursor")) {
                    Ok(offset) => offset,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let limit = limit_of(r, 50);
                let (views, total) = match skipped_roots(&s, search, limit + 1, offset).await {
                    Ok(out) => out,
                    Err(e) => return write_problem(w, r, library_problem(&e)).await,
                };
                let (views, next) = match offset_page(&s, &scope, views, limit, offset) {
                    Ok(out) => out,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let items: Vec<V2Skipped> = views
                    .into_iter()
                    .map(|v| V2Skipped {
                        library_id: Id::from_int(v.root.media_folder_id),
                        library_name: v.name,
                        root_path: v.root.root_path,
                        reason: v.root.reason,
                        sample_file_path: v.root.sample_file_path,
                        file_count: v.root.file_count,
                        first_seen_at: instant(v.root.first_seen_at),
                        last_seen_at: instant(v.root.last_seen_at),
                    })
                    .collect();
                write_v2_json(w, &with_total(items, next, total)).await;
            }),
        ),
    );

    let path = "/api/v2/libraries/stale-ids";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let user = match require_acting(r) {
                    Ok(user) => user,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let search_raw = query_param(r, "q");
                let search = trim_space(&search_raw);
                let scope = CursorScope {
                    operation_id: "listStaleIds".to_owned(),
                    security: user.to_string(),
                    filter: search.to_owned(),
                    sort: "last_seen_at".to_owned(),
                    tiebreaker: "content_id".to_owned(),
                };
                let offset = match decode_offset(&s, &scope, &query_param(r, "cursor")) {
                    Ok(offset) => offset,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let limit = limit_of(r, 50);
                let (rows, total) = match stale_page(&s, search, limit + 1, offset).await {
                    Ok(out) => out,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let (rows, next) = match offset_page(&s, &scope, rows, limit, offset) {
                    Ok(out) => out,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let items: Vec<V2Stale> = rows
                    .into_iter()
                    .map(|v| V2Stale {
                        content_id: v.stale.content_id,
                        library_id: Id::from_int(v.library_id),
                        library_name: v.library_name,
                        title: v.title,
                        year: v.year,
                        content_type: v.content_type,
                        provider: v.stale.provider,
                        provider_id: v.stale.provider_id,
                        first_seen_at: instant(v.stale.first_seen_at),
                        last_seen_at: instant(v.stale.last_seen_at),
                    })
                    .collect();
                write_v2_json(w, &with_total(items, next, total)).await;
            }),
        ),
    );

    let path = "/api/v2/libraries/unmatched-items";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let user = match require_acting(r) {
                    Ok(user) => user,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let search_raw = query_param(r, "q");
                let search = trim_space(&search_raw);
                let ignored = matches!(
                    query_param(r, "ignored").as_str(),
                    "1" | "t" | "T" | "TRUE" | "true" | "True"
                );
                // Encoded when ignored, so no search text can spell this filter.
                let filter = if ignored {
                    encoded(&[("ignored", "true"), ("q", search)])
                } else {
                    format!("q={search}")
                };
                let scope = CursorScope {
                    operation_id: "listUnmatchedItems".to_owned(),
                    security: user.to_string(),
                    filter,
                    sort: "title".to_owned(),
                    tiebreaker: "content_id".to_owned(),
                };
                let offset = match decode_offset(&s, &scope, &query_param(r, "cursor")) {
                    Ok(offset) => offset,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let limit = limit_of(r, 50);
                let (rows, total) = match unmatched(&s, search, ignored, limit + 1, offset).await {
                    Ok(out) => out,
                    Err(e) => return write_problem(w, r, library_problem(&e)).await,
                };
                let (rows, next) = match offset_page(&s, &scope, rows, limit, offset) {
                    Ok(out) => out,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let items: Vec<V2Unmatched> = rows
                    .into_iter()
                    .map(|v| V2Unmatched {
                        content_id: v.content_id,
                        title: v.title,
                        year: v.year,
                        content_type: v.content_type,
                        library_id: Id::from_int(v.library_id),
                        library_name: v.library_name,
                        status: v.status,
                        ignored_at: instant_opt(v.ignored_at),
                    })
                    .collect();
                write_v2_json(w, &with_total(items, next, total)).await;
            }),
        ),
    );

    let path = "/api/v2/user/libraries";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            route!(stack, |s, w, r| {
                let hidden = matches!(
                    query_param(r, "include_hidden").as_str(),
                    "1" | "t" | "T" | "TRUE" | "true" | "True"
                );
                match user_libraries(r, &s, hidden).await {
                    Ok(listed) => {
                        let items: Vec<V2UserLibrary> = listed
                            .into_iter()
                            .map(|f| V2UserLibrary {
                                id: Id::from_int(i64::from(f.id)),
                                poster_url: poster_url(&s, &f.poster_path),
                                name: f.name,
                                kind: f.kind,
                                sort_order: f.sort_order,
                            })
                            .collect();
                        write_v2_json(w, &new_collection(items)).await;
                    }
                    Err(e) => write_problem(w, r, library_problem(&e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/library-playback-prefs";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let user = match require_acting(r) {
                    Ok(user) => user,
                    Err(p) => return write_problem(w, r, p).await,
                };
                match canonical_prefs(&s, user, &get_profile_id(r)).await {
                    Ok(items) => write_v2_json(w, &new_collection(items)).await,
                    Err(p) => write_problem(w, r, p).await,
                }
            }),
        ),
    );

    let path = "/api/v2/library/{id}/layout";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let id = match library_id(r.url_param("id")) {
                    Ok(id) => id,
                    Err(p) => return write_problem(w, r, p).await,
                };
                match library_layout(r, &s, id).await {
                    Ok(layout) => write_v2_json(w, &layout).await,
                    Err(e) => write_problem(w, r, library_problem(&e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/library-jobs/{job_id}";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            route!(stack, |s, w, r| {
                let hidden = || Problem::new(type_for_status(404), "Job not found");
                match s.gates.acting_admin(r, &client_ip_of(r)).await {
                    Ok(true) => {}
                    Ok(false) => return write_problem(w, r, hidden()).await,
                    Err(_) => return write_problem(w, r, internal_problem()).await,
                }
                let job = match admin::admin_job(&s.pool, r.url_param("job_id")).await {
                    Ok(Some(job)) if matches!(job.job_type.as_str(), JOB_REFRESH | JOB_DELETE) => {
                        job
                    }
                    Ok(_) => return write_problem(w, r, hidden()).await,
                    Err(_) => return write_problem(w, r, internal_problem()).await,
                };
                let body = wire_job(job);
                let bytes = silo_gocompat::json::marshal(&body).expect("a job marshals");
                let opaque = {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(&bytes)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                };
                let tag = EntityTag {
                    opaque,
                    weak: false,
                };
                let joined = |name: &str| -> String {
                    r.header
                        .values(name)
                        .iter()
                        .map(|v| String::from_utf8_lossy(v).into_owned())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let (unchanged, problem) = silo_api_v2::precondition::evaluate_read_preconditions(
                    &joined("If-Match"),
                    &joined("If-None-Match"),
                    &tag,
                );
                if let Some(problem) = problem {
                    return write_problem(w, r, problem).await;
                }
                let h = w.header();
                h.set("ETag", tag.to_wire());
                if !body.terminal {
                    h.set("Retry-After", "5");
                }
                if unchanged {
                    w.write_header(304).await;
                    return;
                }
                write_v2_json(w, &body).await;
            }),
        ),
    );
}

pub fn mount(stack: &Arc<Stack>, api_mux: &Mux, v2: &Mux) {
    mount_v1(stack, api_mux);
    mount_v2(stack, v2);
}
