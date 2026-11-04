//! The inbox, preferences, capability, and channel-preference rows: `handlers/notifications*.go`,
//! `apiv2/notification_inbox.go`, `apiv2/notification_channels.go`, and `internal/notifications`.
//!
//! Settings are read live: Go caches them for 15 seconds per key (`settingsCacheTTL`), so a change can
//! reach these rows up to that much sooner than it reaches Go's.

use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::problem::Problem;
use silo_api_v2::wire::{Instant, paginated};
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::json::RawMessage;
use silo_gocompat::time::GoTime;
use silo_http::chi::Mux;
use silo_http::{Request, ResponseWriter, handler_fn};
use silo_pg::{AnyInt, Pool, Row};

use super::auth::write_v1_error;
use super::chain::{
    Stack, Step, V2Class, capability_json, problem_type, write_capability, write_problem,
    write_v1_json, write_v2_json,
};
use super::huma::RawBody;
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};
use silo_store::catalog::access::ensure_accessible;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/"),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/sync"),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/unread-count"),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/capability"),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/preferences"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/notifications/preferences"),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/email-preferences"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/notifications/email-preferences"),
    NativeRow::new(ApiV1, "POST", "/api/v1/notifications/read-all"),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/{id}"),
    NativeRow::new(ApiV1, "POST", "/api/v1/notifications/{id}/read"),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/discord-preferences"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/sync"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/unread-count"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/preferences"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/notifications/preferences"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/email-preferences"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/notifications/email-preferences"),
    NativeRow::new(ApiV2, "POST", "/api/v2/notifications/read-all"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/{id}"),
    NativeRow::new(ApiV2, "POST", "/api/v2/notifications/{id}/read"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/discord-preferences"),
    NativeRow::new(
        ApiV2,
        "PUT",
        "/api/v2/notifications/series/{series_id}/mute",
    ),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/notifications/series/{series_id}/mute",
    ),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/webhooks/"),
    NativeRow::new(ApiV1, "POST", "/api/v1/notifications/webhooks/"),
    NativeRow::new(ApiV1, "PUT", "/api/v1/notifications/webhooks/{id}"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/notifications/webhooks/{id}"),
    NativeRow::new(
        ApiV1,
        "POST",
        "/api/v1/notifications/webhooks/{id}/rotate-secret",
    ),
    NativeRow::new(ApiV1, "GET", "/api/v1/notifications/web-push/subscriptions"),
    NativeRow::new(
        ApiV1,
        "POST",
        "/api/v1/notifications/web-push/subscriptions",
    ),
    NativeRow::new(
        ApiV1,
        "DELETE",
        "/api/v1/notifications/web-push/subscriptions/{id}",
    ),
    NativeRow::new(ApiV1, "POST", "/api/v1/notifications/web-push/unsubscribe"),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/webhooks"),
    NativeRow::new(ApiV2, "POST", "/api/v2/notifications/webhooks"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/notifications/webhooks/{id}"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/notifications/webhooks/{id}"),
    NativeRow::new(
        ApiV2,
        "POST",
        "/api/v2/notifications/webhooks/{id}/rotate-secret",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/notifications/web-push/subscriptions"),
    NativeRow::new(
        ApiV2,
        "POST",
        "/api/v2/notifications/web-push/subscriptions",
    ),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/notifications/web-push/subscriptions/{id}",
    ),
    NativeRow::new(ApiV2, "POST", "/api/v2/notifications/web-push/unsubscribe"),
    NativeRow::new(
        ApiV1,
        "DELETE",
        "/api/v1/notifications/email-preferences/address",
    ),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/notifications/email-preferences/address",
    ),
    NativeRow::new(ApiV1, "PUT", "/api/v1/notifications/discord-preferences"),
    NativeRow::new(ApiV1, "DELETE", "/api/v1/notifications/discord-link"),
    NativeRow::new(ApiV2, "PUT", "/api/v2/notifications/discord-preferences"),
    NativeRow::new(ApiV2, "DELETE", "/api/v2/notifications/discord-link"),
    NativeRow::new(ApiV1, "POST", "/api/v1/notifications/push/devices"),
    NativeRow::new(
        ApiV2,
        "GET",
        "/api/v2/notifications/push/devices/capabilities",
    ),
    NativeRow::new(ApiV2, "POST", "/api/v2/notifications/push/devices"),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/notifications/push/devices/{device_id}",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/devices/push/apple/capabilities"),
    NativeRow::new(
        ApiV1,
        "DELETE",
        "/api/v1/notifications/push/devices/{device_id}",
    ),
    NativeRow::new(ApiV1, "GET", "/api/v1/admin/notifications/server-channels/"),
    NativeRow::new(
        ApiV1,
        "POST",
        "/api/v1/admin/notifications/server-channels/",
    ),
    NativeRow::new(
        ApiV1,
        "PUT",
        "/api/v1/admin/notifications/server-channels/{id}",
    ),
    NativeRow::new(
        ApiV1,
        "DELETE",
        "/api/v1/admin/notifications/server-channels/{id}",
    ),
    NativeRow::new(
        ApiV1,
        "POST",
        "/api/v1/admin/notifications/server-channels/{id}/rotate-secret",
    ),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/notifications/server-channels"),
    NativeRow::new(ApiV2, "POST", "/api/v2/admin/notifications/server-channels"),
    NativeRow::new(
        ApiV2,
        "PUT",
        "/api/v2/admin/notifications/server-channels/{id}",
    ),
    NativeRow::new(
        ApiV2,
        "DELETE",
        "/api/v2/admin/notifications/server-channels/{id}",
    ),
    NativeRow::new(
        ApiV2,
        "POST",
        "/api/v2/admin/notifications/server-channels/{id}/rotate-secret",
    ),
];

/// Go's subrouters under `/notifications`. These rows stay on Go, and `/{id}` must not take their
/// bare paths.
pub fn is_go_subtree(bare: &str) -> bool {
    bare == "/api/v1/notifications/push"
        || bare == "/api/v1/notifications/email"
        || bare == "/api/v1/notifications/discord"
}

const V1_GROUP: &[Step] = &[Step::Auth, Step::Demo, Step::RateLimit, Step::Viewer];
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

mod addresses;
mod channels;
mod destinations;
mod push;

fn go_time(t: SystemTime) -> String {
    GoTime::from_system_time(t).format(silo_gocompat::time::RFC3339_NANO)
}

fn user_of(r: &Request) -> i64 {
    get_claims(r).map_or(0, |c| c.user_id)
}

fn query_param(r: &Request, name: &str) -> String {
    let (query, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    query
        .get(name)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default()
}

fn internal() -> Problem {
    Problem::new(
        problem_type("internal_error"),
        "An unexpected error occurred.",
    )
}

/// `DeliveryRow`, with the columns the API reads.
struct Delivery {
    id: String,
    profile_id: String,
    library_id: Option<i32>,
    series_id: Option<String>,
    episode_id: Option<String>,
    kind: String,
    reason_flags: String,
    read_at: Option<SystemTime>,
    created_at: SystemTime,
    series_title: String,
    episode_title: String,
    season_number: Option<i32>,
    episode_number: Option<i32>,
    poster_path: String,
    poster_thumbhash: String,
}

/// `deliveryRowSelect`. `reason_flags` is read as text: jsonb's own rendering is what Go's `[]byte` scan
/// gets too.
const SELECT: &str = "
	SELECT d.id, d.profile_id, d.library_id, d.series_id, d.episode_id,
	       d.type, d.reason_flags::text, d.read_at, d.created_at,
	       COALESCE(s.title, '') AS series_title,
	       COALESCE(e.title, '') AS episode_title,
	       e.season_number, e.episode_number,
	       COALESCE(s.poster_path, '') AS poster_path,
	       COALESCE(s.poster_thumbhash, '') AS poster_thumbhash
	FROM notification_deliveries d
	LEFT JOIN episodes e ON e.content_id = d.episode_id
	LEFT JOIN media_items s ON s.content_id = d.series_id";

fn scan(row: &Row) -> Result<Delivery, String> {
    fn e(x: silo_pg::DriverError) -> String {
        x.to_string()
    }
    Ok(Delivery {
        id: row.try_get(0).map_err(e)?,
        profile_id: row.try_get(1).map_err(e)?,
        library_id: row.try_get(2).map_err(e)?,
        series_id: row.try_get(3).map_err(e)?,
        episode_id: row.try_get(4).map_err(e)?,
        kind: row.try_get(5).map_err(e)?,
        reason_flags: row.try_get(6).map_err(e)?,
        read_at: row.try_get(7).map_err(e)?,
        created_at: row.try_get(8).map_err(e)?,
        series_title: row.try_get(9).map_err(e)?,
        episode_title: row.try_get(10).map_err(e)?,
        season_number: row.try_get(11).map_err(e)?,
        episode_number: row.try_get(12).map_err(e)?,
        poster_path: row.try_get(13).map_err(e)?,
        poster_thumbhash: row.try_get(14).map_err(e)?,
    })
}

fn scan_all(rows: &[Row]) -> Result<Vec<Delivery>, String> {
    rows.iter().map(scan).collect()
}

/// `Cursor`.
#[derive(Clone, Serialize, Deserialize)]
struct Cursor {
    #[serde(rename = "CreatedAt", default)]
    created_at: String,
    #[serde(rename = "ID", default)]
    id: String,
}

impl Cursor {
    /// `through.CreatedAt.UTC().Format(time.RFC3339Nano)`: a cursor minted where `time.Local` is not UTC
    /// carries an offset, and the event names the instant in UTC.
    fn created_at_utc(&self) -> String {
        silo_gocompat::time::parse(silo_gocompat::time::RFC3339_NANO, &self.created_at)
            .map(|t| t.to_utc().rfc3339_nano())
            .unwrap_or_else(|_| self.created_at.clone())
    }
    fn at(&self) -> Option<SystemTime> {
        silo_gocompat::time::parse(silo_gocompat::time::RFC3339_NANO, &self.created_at)
            .ok()
            .map(|t| t.to_system_time())
    }
    fn of(row: &Delivery) -> Self {
        Cursor {
            created_at: go_time(row.created_at),
            id: row.id.clone(),
        }
    }
    /// `Encode`.
    fn encode_v1(&self) -> String {
        URL_SAFE_NO_PAD.encode(format!("{}|{}", self.created_at, self.id))
    }
    /// `DecodeCursor`.
    fn decode_v1(encoded: &str) -> Option<Self> {
        let raw = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (created_at, id) = raw.split_once('|')?;
        if created_at.is_empty() || id.is_empty() {
            return None;
        }
        let t = silo_gocompat::time::parse(silo_gocompat::time::RFC3339_NANO, created_at).ok()?;
        Some(Cursor {
            created_at: go_time(t.to_system_time()),
            id: id.to_owned(),
        })
    }
}

/// `publicArtworkURL`, then the image resolver's signed URL.
fn poster_url(s: &Stack, path: &str) -> String {
    let public = if let Some(rest) = path.strip_prefix("tmdb://") {
        match rest.split_once('/') {
            Some((_, file)) if !file.is_empty() => {
                format!("https://image.tmdb.org/t/p/w500/{file}")
            }
            _ => String::new(),
        }
    } else if let Some(rest) = path.strip_prefix("tvdb://") {
        format!("https://artworks.thetvdb.com/{rest}")
    } else if path.starts_with("http://") || path.starts_with("https://") {
        path.to_owned()
    } else if path.starts_with('/') {
        format!("https://image.tmdb.org/t/p/w500{path}")
    } else {
        String::new()
    };
    if public.is_empty() {
        super::profiles::sign_artwork(&s.artwork_secret, path, s.artwork_url_ttl)
    } else {
        public
    }
}

#[derive(Deserialize, Default)]
struct RequestFlags {
    #[serde(default)]
    poster_path: String,
}

/// `PayloadForRow`'s poster: a request lifecycle row keeps it in its flags.
fn poster_path_of(row: &Delivery) -> String {
    if row.poster_path.is_empty()
        && (row.kind == "request.approved" || row.kind == "request.declined")
    {
        return serde_json::from_str::<RequestFlags>(&row.reason_flags)
            .unwrap_or_default()
            .poster_path;
    }
    row.poster_path.clone()
}

fn empty(v: &str) -> bool {
    v.is_empty()
}

/// `DeliveryRowPayload`.
#[derive(Serialize)]
struct V1Item {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    profile_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    library_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    series_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    episode_id: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    episode_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    season_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    episode_number: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_thumbhash: String,
    reason_flags: RawMessage,
    created_at: String,
    read_at: Option<String>,
}

fn v1_item(s: &Stack, row: Delivery) -> V1Item {
    let poster_path = poster_path_of(&row);
    let poster_url = if empty(&poster_path) {
        String::new()
    } else {
        poster_url(s, &poster_path)
    };
    V1Item {
        id: row.id,
        kind: row.kind,
        profile_id: row.profile_id,
        library_id: row.library_id,
        series_id: row.series_id,
        episode_id: row.episode_id,
        series_title: row.series_title,
        episode_title: row.episode_title,
        season_number: row.season_number,
        episode_number: row.episode_number,
        poster_path,
        poster_url,
        poster_thumbhash: row.poster_thumbhash,
        reason_flags: RawMessage::from(row.reason_flags.into_bytes()),
        created_at: go_time(row.created_at),
        read_at: row.read_at.map(go_time),
    }
}

/// `NotificationItem`.
#[derive(Serialize)]
struct V2Item {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    profile_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    library_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    series_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    episode_id: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    episode_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    season_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    episode_number: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_thumbhash: String,
    reason_flags: RawMessage,
    created_at: Instant,
    read_at: Option<Instant>,
}

fn instant(t: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(t))
}

fn v2_item(s: &Stack, row: Delivery) -> V2Item {
    let (created, read) = (row.created_at, row.read_at);
    let item = v1_item(s, row);
    V2Item {
        id: item.id,
        kind: item.kind,
        profile_id: item.profile_id,
        library_id: item.library_id.map(|v| v.to_string()),
        series_id: item.series_id,
        episode_id: item.episode_id,
        series_title: item.series_title,
        episode_title: item.episode_title,
        season_number: item.season_number,
        episode_number: item.episode_number,
        poster_path: item.poster_path,
        poster_url: item.poster_url,
        poster_thumbhash: item.poster_thumbhash,
        reason_flags: item.reason_flags,
        created_at: instant(created),
        read_at: read.map(instant),
    }
}

async fn list_inbox(
    pool: &Pool,
    user: i64,
    profile: &str,
    unread: bool,
    limit: i64,
    before: Option<&Cursor>,
) -> Result<Vec<Delivery>, String> {
    let user = AnyInt(user);
    let rows = match before.and_then(|c| c.at().map(|t| (t, &c.id))) {
        Some((at, id)) => pool
            .query(
                &format!(
                    "{SELECT} WHERE d.user_id = $1 AND d.profile_id = $2 AND (NOT $3 OR d.read_at IS NULL) AND (d.created_at, d.id) < ($4, $5) ORDER BY d.created_at DESC, d.id DESC LIMIT $6"
                ),
                &[&user, &profile, &unread, &at, id, &limit],
            )
            .await,
        None => pool
            .query(
                &format!(
                    "{SELECT} WHERE d.user_id = $1 AND d.profile_id = $2 AND (NOT $3 OR d.read_at IS NULL) ORDER BY d.created_at DESC, d.id DESC LIMIT $4"
                ),
                &[&user, &profile, &unread, &limit],
            )
            .await,
    }
    .map_err(|e| e.to_string())?;
    scan_all(&rows)
}

/// `ListSync`.
async fn list_sync(
    pool: &Pool,
    user: i64,
    profile: &str,
    since: Option<&Cursor>,
    limit: i64,
) -> Result<Vec<Delivery>, String> {
    let user = AnyInt(user);
    let rows = match since.and_then(|c| c.at().map(|t| (t, &c.id))) {
        Some((at, id)) => {
            pool.query(
                &format!(
                    "{SELECT}
			WHERE d.user_id = $1 AND d.profile_id = $2 AND (d.created_at, d.id) > ($3, $4)
			ORDER BY d.created_at ASC, d.id ASC
			LIMIT $5"
                ),
                &[&user, &profile, &at, id, &limit],
            )
            .await
        }
        None => {
            pool.query(
                &format!(
                    "SELECT * FROM ({SELECT}
			WHERE d.user_id = $1 AND d.profile_id = $2
			ORDER BY d.created_at DESC, d.id DESC
			LIMIT $3
		) recent ORDER BY recent.created_at ASC, recent.id ASC"
                ),
                &[&user, &profile, &limit],
            )
            .await
        }
    }
    .map_err(|e| e.to_string())?;
    scan_all(&rows)
}

/// `GetByID`.
async fn get_row(
    pool: &Pool,
    user: i64,
    profile: &str,
    id: &str,
) -> Result<Option<Delivery>, String> {
    let rows = pool
        .query(
            &format!("{SELECT} WHERE d.user_id = $1 AND d.profile_id = $2 AND d.id = $3"),
            &[&AnyInt(user), &profile, &id],
        )
        .await
        .map_err(|e| e.to_string())?;
    rows.first().map(scan).transpose()
}

/// `UnreadCount`.
async fn unread_count(pool: &Pool, user: i64, profile: &str) -> Result<i64, String> {
    let rows = pool
        .query(
            "SELECT count(*) FROM notification_deliveries WHERE user_id = $1 AND profile_id = $2 AND read_at IS NULL",
            &[&AnyInt(user), &profile],
        )
        .await
        .map_err(|e| e.to_string())?;
    rows[0]
        .try_get(0)
        .map_err(|e: silo_pg::DriverError| e.to_string())
}

/// `MarkRead` then `Exists`. `Ok(None)` is an unknown ID; `Ok(Some(changed))` otherwise.
async fn mark_read(
    pool: &Pool,
    user: i64,
    profile: &str,
    id: &str,
) -> Result<Option<bool>, String> {
    let changed = pool
        .execute(
            "
		UPDATE notification_deliveries
		SET read_at = now()
		WHERE user_id = $1 AND profile_id = $2 AND id = $3 AND read_at IS NULL",
            &[&AnyInt(user), &profile, &id],
        )
        .await
        .map_err(|e| e.to_string())?
        > 0;
    if changed {
        return Ok(Some(true));
    }
    let rows = pool
        .query(
            "SELECT EXISTS (SELECT 1 FROM notification_deliveries WHERE user_id = $1 AND profile_id = $2 AND id = $3)",
            &[&AnyInt(user), &profile, &id],
        )
        .await
        .map_err(|e| e.to_string())?;
    let exists: bool = rows[0]
        .try_get(0)
        .map_err(|e: silo_pg::DriverError| e.to_string())?;
    Ok(exists.then_some(false))
}

/// `ChannelNotifications` and `EventNotificationRead`.
async fn publish_read<T: Serialize>(s: &Stack, user: i64, profile: &str, data: &T) {
    let Ok(data) = silo_gocompat::json::marshal(data) else {
        return;
    };
    super::settings::publish_envelope(
        s,
        "notifications",
        "notification.read",
        data,
        user,
        profile,
        false,
        false,
    )
    .await;
}

#[derive(Serialize)]
struct ReadOne<'a> {
    id: &'a str,
    profile_id: &'a str,
}

#[derive(Serialize)]
struct ReadAll<'a> {
    all: bool,
    profile_id: &'a str,
}

#[derive(Serialize)]
struct ReadThrough<'a> {
    profile_id: &'a str,
    through_created_at: &'a str,
    through_id: &'a str,
}

/// `notifications.Preferences`.
#[derive(Serialize)]
struct Prefs {
    profile_id: String,
    enabled: bool,
    notify_favorites: bool,
    notify_watchlist: bool,
    notify_continue_watching: bool,
    notify_next_up: bool,
}

async fn get_prefs(pool: &Pool, user: i64, profile: &str) -> Result<Prefs, String> {
    let rows = pool
        .query(
            "
		SELECT enabled, notify_favorites, notify_watchlist, notify_continue_watching, notify_next_up, updated_at
		FROM notification_preferences
		WHERE user_id = $1 AND profile_id = $2",
            &[&AnyInt(user), &profile],
        )
        .await
        .map_err(|e| e.to_string())?;
    prefs_of(rows.first(), profile)
}

fn prefs_of(row: Option<&Row>, profile: &str) -> Result<Prefs, String> {
    fn e(x: silo_pg::DriverError) -> String {
        x.to_string()
    }
    Ok(match row {
        None => Prefs {
            profile_id: profile.to_owned(),
            enabled: true,
            notify_favorites: true,
            notify_watchlist: true,
            notify_continue_watching: true,
            notify_next_up: true,
        },
        Some(row) => Prefs {
            profile_id: profile.to_owned(),
            enabled: row.try_get(0).map_err(e)?,
            notify_favorites: row.try_get(1).map_err(e)?,
            notify_watchlist: row.try_get(2).map_err(e)?,
            notify_continue_watching: row.try_get(3).map_err(e)?,
            notify_next_up: row.try_get(4).map_err(e)?,
        },
    })
}

#[derive(Deserialize, Default)]
struct PrefsPatch {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    notify_favorites: Option<bool>,
    #[serde(default)]
    notify_watchlist: Option<bool>,
    #[serde(default)]
    notify_continue_watching: Option<bool>,
    #[serde(default)]
    notify_next_up: Option<bool>,
}

/// `PreferencesRepository.Patch`.
async fn patch_prefs(
    pool: &Pool,
    user: i64,
    profile: &str,
    p: &PrefsPatch,
) -> Result<Prefs, String> {
    let rows = pool
        .query(
            "INSERT INTO notification_preferences(user_id,profile_id,enabled,notify_favorites,notify_watchlist,notify_continue_watching,notify_next_up,updated_at) VALUES($1,$2,COALESCE($3,true),COALESCE($4,true),COALESCE($5,true),COALESCE($6,true),COALESCE($7,true),now()) ON CONFLICT(user_id,profile_id) DO UPDATE SET enabled=COALESCE($3,notification_preferences.enabled),notify_favorites=COALESCE($4,notification_preferences.notify_favorites),notify_watchlist=COALESCE($5,notification_preferences.notify_watchlist),notify_continue_watching=COALESCE($6,notification_preferences.notify_continue_watching),notify_next_up=COALESCE($7,notification_preferences.notify_next_up),updated_at=now() RETURNING enabled,notify_favorites,notify_watchlist,notify_continue_watching,notify_next_up,updated_at",
            &[&AnyInt(user), &profile, &p.enabled, &p.notify_favorites, &p.notify_watchlist, &p.notify_continue_watching, &p.notify_next_up],
        )
        .await
        .map_err(|e| e.to_string())?;
    prefs_of(rows.first(), profile)
}

/// `capabilityResponse`.
#[derive(Serialize, Default, Clone)]
struct Push {
    available: bool,
    provider: &'static str,
    supported_modes: Vec<&'static str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    display_token: bool,
}

#[derive(Serialize, Default)]
struct WebPush {
    available: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    public_key: String,
}

#[derive(Serialize, Default)]
struct Webhooks {
    available: bool,
    max_per_profile: i64,
    supported_types: Vec<&'static str>,
}

#[derive(Serialize, Default)]
struct Channel {
    available: bool,
    modes: Vec<&'static str>,
    digest_hour: i64,
}

#[derive(Serialize)]
struct InApp {
    enabled: bool,
}

#[derive(Serialize)]
struct Capabilities {
    in_app: InApp,
    apple_push: Push,
    android_push: Push,
    web_push: WebPush,
    webhooks: Webhooks,
    email: Channel,
    discord: Channel,
}

#[derive(Serialize)]
struct Series {
    available: bool,
    mute: bool,
}

#[derive(Serialize)]
struct V2Capabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    in_app: &'a InApp,
    apple_push: &'a Push,
    android_push: &'a Push,
    web_push: &'a WebPush,
    webhooks: &'a Webhooks,
    email: &'a Channel,
    discord: &'a Channel,
    series: Series,
}

fn parse_bool(value: &str, fallback: bool) -> bool {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => fallback,
    }
}

fn parse_int(value: &str, fallback: i64, min: i64, max: i64) -> i64 {
    match value.trim().parse::<i64>() {
        Ok(v) if (min..=max).contains(&v) => v,
        _ => fallback,
    }
}

/// `NotificationCapabilities`.
async fn capabilities(s: &Stack) -> Capabilities {
    let all = s.encrypted.get_all().await.unwrap_or_default();
    let raw = |key: &str| all.get(key).map_or("", |v| v.as_str());
    let flag = |key: &str, fallback: bool| parse_bool(raw(key), fallback);
    let modes = |per_episode: bool| {
        let mut modes = vec!["daily_digest"];
        if per_episode {
            modes.push("per_episode");
            modes.push("per_episode_and_digest");
        }
        modes
    };
    let webhooks = if flag("notifications.webhooks_enabled", false) {
        Webhooks {
            available: true,
            max_per_profile: parse_int(raw("notifications.webhooks.max_per_profile"), 10, 1, 100),
            supported_types: vec!["discord", "generic"],
        }
    } else {
        Webhooks::default()
    };
    let mut web_push = WebPush::default();
    if flag("notifications.web_push_enabled", true) {
        #[derive(Deserialize, Default)]
        struct Pair {
            #[serde(default)]
            public: String,
        }
        let public = serde_json::from_str::<Pair>(raw("notifications.web_push.vapid_keypair"))
            .unwrap_or_default()
            .public;
        if !public.is_empty() {
            web_push = WebPush {
                available: true,
                public_key: public,
            };
        }
    }
    let smtp =
        !raw("email.smtp_host").trim().is_empty() && !raw("email.smtp_from").trim().is_empty();
    let email = if flag("notifications.email_enabled", true) && smtp {
        Channel {
            available: true,
            modes: modes(flag("notifications.email.allow_per_episode", true)),
            digest_hour: parse_int(raw("notifications.email.digest_hour"), 8, 0, 23),
        }
    } else {
        Channel::default()
    };
    let discord_configured = !raw("discord.client_id").trim().is_empty()
        && !raw("discord.client_secret").trim().is_empty()
        && !raw("discord.bot_token").trim().is_empty();
    let discord = if discord_configured && flag("notifications.discord_enabled", false) {
        Channel {
            available: true,
            modes: modes(flag("notifications.discord.allow_per_episode", true)),
            digest_hour: parse_int(raw("notifications.discord.digest_hour"), 8, 0, 23),
        }
    } else {
        Channel::default()
    };
    let push = |key: &str, display_token: bool| {
        if flag(key, true) {
            Push {
                available: true,
                provider: "silo_relay",
                supported_modes: vec!["private_push", "in_app_only"],
                display_token,
            }
        } else {
            Push {
                available: false,
                provider: "off",
                supported_modes: vec!["in_app_only"],
                display_token: false,
            }
        }
    };
    Capabilities {
        in_app: InApp {
            enabled: flag("notifications.ui_enabled", true),
        },
        apple_push: push("notifications.apple_push_delivery_enabled", true),
        android_push: push("notifications.android_push_delivery_enabled", false),
        web_push,
        webhooks,
        email,
        discord,
    }
}

/// `profileIsChild`.
async fn profile_is_child(s: &Stack, user: i64, profile: &str) -> bool {
    match s.viewer.get_profile(user, profile).await {
        Ok(Some(p)) => p.is_child,
        _ => true,
    }
}

/// `emailPreferencesResponse` and `NotificationEmailPreferences`.
#[derive(Serialize)]
struct EmailPrefs {
    mode: String,
    custom_email: String,
    pending_email: String,
    can_edit_address: bool,
}

async fn email_prefs(s: &Stack, user: i64, profile: &str) -> Result<EmailPrefs, String> {
    let rows = s
        .pool
        .query(
            "
		SELECT mode, custom_email, pending_email, pending_expires_at
		FROM notification_email_prefs WHERE profile_id = $1",
            &[&profile],
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut out = EmailPrefs {
        mode: "off".to_owned(),
        custom_email: String::new(),
        pending_email: String::new(),
        can_edit_address: !profile_is_child(s, user, profile).await,
    };
    if let Some(row) = rows.first() {
        fn e(x: silo_pg::DriverError) -> String {
            x.to_string()
        }
        out.mode = row.try_get(0).map_err(e)?;
        out.custom_email = row.try_get(1).map_err(e)?;
        out.pending_email = row.try_get(2).map_err(e)?;
        let expires: Option<SystemTime> = row.try_get(3).map_err(e)?;
        if expires.is_some_and(|t| t < SystemTime::now()) {
            out.pending_email.clear();
        }
    }
    Ok(out)
}

fn valid_mode(mode: &str) -> bool {
    matches!(
        mode,
        "off" | "per_episode" | "daily_digest" | "per_episode_and_digest"
    )
}

enum ModeError {
    Invalid,
    NotAllowed,
    NoAddress,
    Failed,
}

/// `SetEmailMode`.
async fn set_email_mode(s: &Stack, user: i64, profile: &str, mode: &str) -> Result<(), ModeError> {
    if !valid_mode(mode) {
        return Err(ModeError::Invalid);
    }
    if mode.starts_with("per_episode") {
        let allowed = s
            .encrypted
            .get("notifications.email.allow_per_episode")
            .await
            .unwrap_or_default();
        if !parse_bool(&allowed, true) {
            return Err(ModeError::NotAllowed);
        }
    }
    if mode != "off" {
        let prefs = email_prefs(s, user, profile)
            .await
            .map_err(|_| ModeError::Failed)?;
        if prefs.custom_email.is_empty() {
            return Err(ModeError::NoAddress);
        }
    }
    s.pool
        .execute(
            "
		INSERT INTO notification_email_prefs (profile_id, user_id, mode)
		VALUES ($1, $2, $3)
		ON CONFLICT (profile_id) DO UPDATE SET
			mode = EXCLUDED.mode,
			user_id = EXCLUDED.user_id,
			watermark_created_at = CASE
				WHEN notification_email_prefs.mode = 'off' THEN now()
				ELSE notification_email_prefs.watermark_created_at
			END,
			watermark_id = CASE
				WHEN notification_email_prefs.mode = 'off' THEN ''
				ELSE notification_email_prefs.watermark_id
			END,
			last_attempt_at = NULL,
			consecutive_failures = 0,
			updated_at = now()",
            &[&profile, &AnyInt(user), &mode],
        )
        .await
        .map_err(|_| ModeError::Failed)?;
    Ok(())
}

/// `discordPreferencesResponse` and `NotificationDiscordPreferences`.
#[derive(Serialize)]
struct DiscordPrefs {
    linked: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    discord_username: String,
    mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    link_failure: String,
}

async fn discord_prefs(pool: &Pool, user: i64) -> Result<DiscordPrefs, String> {
    let rows = pool
        .query(
            "
		SELECT discord_user_id, discord_username, mode, link_failure
		FROM notification_discord_prefs WHERE user_id = $1",
            &[&AnyInt(user)],
        )
        .await
        .map_err(|e| e.to_string())?;
    let Some(row) = rows.first() else {
        return Ok(DiscordPrefs {
            linked: false,
            discord_username: String::new(),
            mode: "off".to_owned(),
            link_failure: String::new(),
        });
    };
    fn e(x: silo_pg::DriverError) -> String {
        x.to_string()
    }
    let id: String = row.try_get(0).map_err(e)?;
    Ok(DiscordPrefs {
        linked: !id.is_empty(),
        discord_username: row.try_get(1).map_err(e)?,
        mode: row.try_get(2).map_err(e)?,
        link_failure: row.try_get(3).map_err(e)?,
    })
}

#[derive(Deserialize, Default)]
struct ModeBody {
    #[serde(default)]
    mode: String,
}

/// `parseNotificationsLimit`.
fn v1_limit(r: &Request, fallback: i64) -> i64 {
    match query_param(r, "limit").parse::<i64>() {
        Ok(limit) if limit > 0 => limit.min(100),
        _ => fallback,
    }
}

#[derive(Serialize)]
struct V1List {
    notifications: Vec<V1Item>,
    #[serde(skip_serializing_if = "String::is_empty")]
    next_cursor: String,
}

#[derive(Serialize)]
struct V1Sync {
    notifications: Vec<V1Item>,
    #[serde(skip_serializing_if = "String::is_empty")]
    next_cursor: String,
    unread_count: i64,
}

#[derive(Serialize)]
struct Count {
    count: i64,
}

fn mount_v1(stack: &Arc<Stack>, api: &Mux) {
    let mux = Mux::new();
    mux.use_middleware([stack.v1_group(V1_PROFILE)]);
    mux.get(
        "/",
        route!(stack, |s, w, r| {
            let (user, profile) = (user_of(r), get_profile_id(r));
            let unread = query_param(r, "status") == "unread";
            let limit = v1_limit(r, 25);
            let raw = query_param(r, "before");
            let before = if raw.is_empty() {
                None
            } else {
                match Cursor::decode_v1(&raw) {
                    Some(c) => Some(c),
                    None => {
                        return write_v1_error(w, 400, "bad_request", "Invalid before cursor")
                            .await;
                    }
                }
            };
            let Ok(rows) =
                list_inbox(&s.pool, user, &profile, unread, limit, before.as_ref()).await
            else {
                return write_v1_error(w, 500, "internal_error", "Failed to list notifications")
                    .await;
            };
            let next_cursor = if rows.len() as i64 == limit {
                rows.last()
                    .map_or(String::new(), |l| Cursor::of(l).encode_v1())
            } else {
                String::new()
            };
            let notifications = rows.into_iter().map(|row| v1_item(&s, row)).collect();
            write_v1_json(
                w,
                200,
                &V1List {
                    notifications,
                    next_cursor,
                },
            )
            .await;
        }),
    );
    mux.get(
        "/sync",
        route!(stack, |s, w, r| {
            let (user, profile) = (user_of(r), get_profile_id(r));
            let limit = v1_limit(r, 50);
            let raw = query_param(r, "since");
            let since = if raw.is_empty() {
                None
            } else {
                match Cursor::decode_v1(&raw) {
                    Some(c) => Some(c),
                    None => {
                        return write_v1_error(w, 400, "bad_request", "Invalid since cursor").await;
                    }
                }
            };
            let Ok(rows) = list_sync(&s.pool, user, &profile, since.as_ref(), limit).await else {
                return write_v1_error(w, 500, "internal_error", "Failed to sync notifications")
                    .await;
            };
            let Ok(unread_count) = unread_count(&s.pool, user, &profile).await else {
                return write_v1_error(
                    w,
                    500,
                    "internal_error",
                    "Failed to count unread notifications",
                )
                .await;
            };
            let next_cursor = match (rows.last(), &since) {
                (Some(last), _) => Cursor::of(last).encode_v1(),
                (None, Some(c)) => c.encode_v1(),
                _ => String::new(),
            };
            let notifications = rows.into_iter().map(|row| v1_item(&s, row)).collect();
            write_v1_json(
                w,
                200,
                &V1Sync {
                    notifications,
                    next_cursor,
                    unread_count,
                },
            )
            .await;
        }),
    );
    mux.get(
        "/unread-count",
        route!(stack, |s, w, r| {
            match unread_count(&s.pool, user_of(r), &get_profile_id(r)).await {
                Ok(count) => write_v1_json(w, 200, &Count { count }).await,
                Err(_) => {
                    write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to count unread notifications",
                    )
                    .await
                }
            }
        }),
    );
    mux.get(
        "/capability",
        route!(stack, |s, w, _r| {
            write_v1_json(w, 200, &capabilities(&s).await).await;
        }),
    );
    mux.get(
        "/preferences",
        route!(stack, |s, w, r| {
            match get_prefs(&s.pool, user_of(r), &get_profile_id(r)).await {
                Ok(p) => write_v1_json(w, 200, &p).await,
                Err(_) => {
                    write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to load notification preferences",
                    )
                    .await
                }
            }
        }),
    );
    mux.put(
        "/preferences",
        route!(stack, |s, w, r| {
            let (bytes, _) = r.read_all().await;
            let Ok(patch) = silo_gocompat::json::Decoder::new()
                .stream(bytes.as_slice())
                .decode::<PrefsPatch>()
            else {
                return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
            };
            match patch_prefs(&s.pool, user_of(r), &get_profile_id(r), &patch).await {
                Ok(p) => write_v1_json(w, 200, &p).await,
                Err(_) => {
                    write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to save notification preferences",
                    )
                    .await
                }
            }
        }),
    );
    mux.get(
        "/email-preferences",
        route!(stack, |s, w, r| {
            match email_prefs(&s, user_of(r), &get_profile_id(r)).await {
                Ok(p) => write_v1_json(w, 200, &p).await,
                Err(_) => {
                    write_v1_error(w, 500, "internal_error", "Failed to load email preferences")
                        .await
                }
            }
        }),
    );
    mux.put(
        "/email-preferences",
        route!(stack, |s, w, r| {
            let (user, profile) = (user_of(r), get_profile_id(r));
            let (bytes, _) = r.read_all().await;
            let Ok(body) = silo_gocompat::json::Decoder::new()
                .stream(bytes.as_slice())
                .decode::<ModeBody>()
            else {
                return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
            };
            match set_email_mode(&s, user, &profile, &body.mode).await {
                Ok(()) => {}
                Err(ModeError::Invalid) => {
                    return write_v1_error(
                        w,
                        400,
                        "bad_request",
                        "Unknown email notification mode",
                    )
                    .await;
                }
                Err(ModeError::NotAllowed) => {
                    return write_v1_error(
                        w,
                        400,
                        "not_allowed",
                        "Per-episode email is disabled by the administrator",
                    )
                    .await;
                }
                Err(ModeError::NoAddress) => {
                    return write_v1_error(
                        w,
                        400,
                        "no_email",
                        "Verify an email address for this profile first",
                    )
                    .await;
                }
                Err(ModeError::Failed) => {
                    return write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to save email preferences",
                    )
                    .await;
                }
            }
            match email_prefs(&s, user, &profile).await {
                Ok(p) => write_v1_json(w, 200, &p).await,
                Err(_) => {
                    write_v1_error(w, 500, "internal_error", "Failed to load email preferences")
                        .await
                }
            }
        }),
    );
    mux.post(
        "/read-all",
        route!(stack, |s, w, r| {
            let (user, profile) = (user_of(r), get_profile_id(r));
            let done = s
                .pool
                .execute(
                    "
		UPDATE notification_deliveries
		SET read_at = now()
		WHERE user_id = $1 AND profile_id = $2 AND read_at IS NULL",
                    &[&AnyInt(user), &profile],
                )
                .await;
            if done.is_err() {
                return write_v1_error(
                    w,
                    500,
                    "internal_error",
                    "Failed to mark notifications read",
                )
                .await;
            }
            publish_read(
                &s,
                user,
                &profile,
                &ReadAll {
                    all: true,
                    profile_id: &profile,
                },
            )
            .await;
            w.write_header(204).await;
        }),
    );
    mux.get(
        "/{id}",
        route!(stack, |s, w, r| {
            let id = r.url_param("id").to_owned();
            match get_row(&s.pool, user_of(r), &get_profile_id(r), &id).await {
                Ok(Some(row)) => write_v1_json(w, 200, &v1_item(&s, row)).await,
                Ok(None) => write_v1_error(w, 404, "not_found", "Notification not found").await,
                Err(_) => {
                    write_v1_error(w, 500, "internal_error", "Failed to load notification").await
                }
            }
        }),
    );
    mux.post(
        "/{id}/read",
        route!(stack, |s, w, r| {
            let id = r.url_param("id").to_owned();
            let (user, profile) = (user_of(r), get_profile_id(r));
            match mark_read(&s.pool, user, &profile, &id).await {
                Ok(None) => write_v1_error(w, 404, "not_found", "Notification not found").await,
                Err(_) => {
                    write_v1_error(w, 500, "internal_error", "Failed to mark notification read")
                        .await
                }
                Ok(Some(changed)) => {
                    if changed {
                        publish_read(
                            &s,
                            user,
                            &profile,
                            &ReadOne {
                                id: &id,
                                profile_id: &profile,
                            },
                        )
                        .await;
                    }
                    w.write_header(204).await;
                }
            }
        }),
    );
    destinations::mount_v1(stack, &mux);
    push::mount_v1(stack, &mux);
    addresses::mount_v1_subrouter(stack, &mux);
    api.mount("/api/v1/notifications", mux);

    // Outside the `RequireProfile` subrouter, as Go's static paths are.
    let path = "/api/v1/notifications/discord-preferences";
    api.get(
        path,
        stack.v1(
            path,
            V1_GROUP,
            route!(stack, |s, w, r| {
                match discord_prefs(&s.pool, user_of(r)).await {
                    Ok(p) => write_v1_json(w, 200, &p).await,
                    Err(_) => {
                        write_v1_error(
                            w,
                            500,
                            "internal_error",
                            "Failed to load Discord preferences",
                        )
                        .await
                    }
                }
            }),
        ),
    );
}

#[derive(Serialize)]
struct V2List {
    #[serde(flatten)]
    collection: silo_api_v2::wire::Collection<V2Item>,
    read_cutoff: String,
}

#[derive(Serialize)]
struct V2Sync {
    #[serde(flatten)]
    collection: silo_api_v2::wire::Collection<V2Item>,
    sync_cursor: String,
    unread_count: i64,
    initial_snapshot: bool,
}

/// `notificationListPosition`.
#[derive(Serialize, Deserialize)]
struct Position {
    #[serde(rename = "Before", default)]
    before: Option<Cursor>,
    #[serde(rename = "Through", default = "no_cursor")]
    through: Cursor,
}

fn no_cursor() -> Cursor {
    Cursor {
        created_at: "0001-01-01T00:00:00Z".to_owned(),
        id: String::new(),
    }
}

fn scope(r: &Request, operation: &str, filter: String) -> CursorScope {
    CursorScope {
        operation_id: operation.to_owned(),
        security: format!("{}/{}", user_of(r), get_profile_id(r)),
        filter,
        sort: "created_at,id".to_owned(),
        tiebreaker: "id".to_owned(),
    }
}

fn limit_of(r: &Request) -> i64 {
    query_param(r, "limit").parse().unwrap_or(50)
}

/// `InboxCutoff`.
async fn inbox_cutoff(pool: &Pool, user: i64, profile: &str) -> Result<Cursor, String> {
    let rows = pool
        .query(
            "SELECT created_at,id FROM notification_deliveries WHERE user_id = $1 AND profile_id = $2 ORDER BY created_at DESC,id DESC LIMIT 1",
            &[&AnyInt(user), &profile],
        )
        .await
        .map_err(|e| e.to_string())?;
    let Some(row) = rows.first() else {
        return Ok(no_cursor());
    };
    let at: SystemTime = row
        .try_get(0)
        .map_err(|e: silo_pg::DriverError| e.to_string())?;
    Ok(Cursor {
        created_at: go_time(at),
        id: row
            .try_get(1)
            .map_err(|e: silo_pg::DriverError| e.to_string())?,
    })
}

/// `ListInboxWindow`.
async fn list_window(
    pool: &Pool,
    user: i64,
    profile: &str,
    unread: bool,
    limit: i64,
    before: Option<&Cursor>,
    through: &Cursor,
) -> Result<(Vec<Delivery>, bool), String> {
    let limit = limit.clamp(1, 200);
    let Some(through_at) = through.at().filter(|_| !through.id.is_empty()) else {
        return Ok((Vec::new(), false));
    };
    let before_at = before.and_then(Cursor::at);
    let before_id = before.map_or(String::new(), |c| c.id.clone());
    let rows = pool
        .query(
            &format!(
                "{SELECT} WHERE d.user_id = $1 AND d.profile_id = $2 AND (NOT $3 OR d.read_at IS NULL) AND (d.created_at,d.id)<=($4,$5) AND ($6::timestamptz IS NULL OR (d.created_at,d.id)<($6,$7)) ORDER BY d.created_at DESC,d.id DESC LIMIT $8"
            ),
            &[&AnyInt(user), &profile, &unread, &through_at, &through.id, &before_at, &before_id, &(limit + 1)],
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut out = scan_all(&rows)?;
    let more = out.len() as i64 > limit;
    out.truncate(limit as usize);
    Ok((out, more))
}

fn mode_problem(e: ModeError) -> Problem {
    let invalid = |detail: &str| Problem::new(problem_type("validation_failed"), detail);
    match e {
        ModeError::Invalid => invalid("Unknown notification mode."),
        ModeError::NotAllowed => invalid("Per-episode delivery is disabled by the administrator."),
        ModeError::NoAddress => invalid("Verify an email address for this profile first."),
        ModeError::Failed => internal(),
    }
}

fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/notifications";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let limit = limit_of(r);
                let status = match query_param(r, "status") {
                    v if v.is_empty() => "all".to_owned(),
                    v => v,
                };
                let page = scope(r, "listNotifications", format!("{status}/{limit}"));
                let raw = query_param(r, "cursor");
                let mut pos = Position {
                    before: None,
                    through: no_cursor(),
                };
                let mut through = None;
                if !raw.is_empty() {
                    pos = match s.cursors.decode(&page, &raw) {
                        Ok(p) => p,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                    through = Some(pos.through.clone());
                }
                let through = match through {
                    Some(c) => c,
                    None => match inbox_cutoff(&s.pool, user, &profile).await {
                        Ok(c) => c,
                        Err(_) => return write_problem(w, r, internal()).await,
                    },
                };
                let Ok((rows, more)) = list_window(
                    &s.pool,
                    user,
                    &profile,
                    status == "unread",
                    limit,
                    pos.before.as_ref(),
                    &through,
                )
                .await
                else {
                    return write_problem(w, r, internal()).await;
                };
                let mut next = String::new();
                if more && let Some(last) = rows.last() {
                    let position = Position {
                        before: Some(Cursor::of(last)),
                        through: through.clone(),
                    };
                    next = match s.cursors.encode(&page, &position) {
                        Ok(n) => n,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                }
                let read_cutoff = match s
                    .cursors
                    .encode(&scope(r, "notificationReadCutoff", String::new()), &through)
                {
                    Ok(n) => n,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let items = rows.into_iter().map(|row| v2_item(&s, row)).collect();
                write_v2_json(
                    w,
                    &V2List {
                        collection: paginated(items, next),
                        read_cutoff,
                    },
                )
                .await;
            }),
        ),
    );

    let path = "/api/v2/notifications/sync";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let limit = limit_of(r);
                let page = scope(r, "syncNotifications", limit.to_string());
                let raw = query_param(r, "cursor");
                let since: Option<Cursor> = if raw.is_empty() {
                    None
                } else {
                    match s.cursors.decode(&page, &raw) {
                        Ok(c) => Some(c),
                        Err(problem) => return write_problem(w, r, problem).await,
                    }
                };
                let requested = if since.is_some() { limit + 1 } else { limit };
                let Ok(mut rows) =
                    list_sync(&s.pool, user, &profile, since.as_ref(), requested).await
                else {
                    return write_problem(w, r, internal()).await;
                };
                let more = since.is_some() && rows.len() as i64 > limit;
                rows.truncate(limit as usize);
                let Ok(unread_count) = unread_count(&s.pool, user, &profile).await else {
                    return write_problem(w, r, internal()).await;
                };
                let position = match (rows.last(), &since) {
                    (Some(last), _) => Cursor::of(last),
                    (None, Some(c)) => c.clone(),
                    _ => Cursor {
                        created_at: "1970-01-01T00:00:00Z".to_owned(),
                        id: "00000000-0000-0000-0000-000000000000".to_owned(),
                    },
                };
                let sync_cursor = match s.cursors.encode(&page, &position) {
                    Ok(n) => n,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                let next = if more {
                    sync_cursor.clone()
                } else {
                    String::new()
                };
                let items = rows.into_iter().map(|row| v2_item(&s, row)).collect();
                write_v2_json(
                    w,
                    &V2Sync {
                        collection: paginated(items, next),
                        sync_cursor,
                        unread_count,
                        initial_snapshot: since.is_none(),
                    },
                )
                .await;
            }),
        ),
    );

    let path = "/api/v2/notifications/unread-count";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                match unread_count(&s.pool, user_of(r), &get_profile_id(r)).await {
                    Ok(count) => write_v2_json(w, &Count { count }).await,
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let c = capabilities(&s).await;
                let on = c.in_app.enabled
                    || c.apple_push.available
                    || c.android_push.available
                    || c.web_push.available
                    || c.webhooks.available
                    || c.email.available
                    || c.discord.available;
                write_capability(w, r, "getNotificationCapabilities", |revision| {
                    capability_json(&V2Capabilities {
                        revision,
                        state: if on { "available" } else { "disabled" },
                        allowed: on,
                        in_app: &c.in_app,
                        apple_push: &c.apple_push,
                        android_push: &c.android_push,
                        web_push: &c.web_push,
                        webhooks: &c.webhooks,
                        email: &c.email,
                        discord: &c.discord,
                        series: Series {
                            available: true,
                            mute: true,
                        },
                    })
                })
                .await;
            }),
        ),
    );

    let path = "/api/v2/notifications/preferences";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                match get_prefs(&s.pool, user_of(r), &get_profile_id(r)).await {
                    Ok(p) => write_v2_json(w, &p).await,
                    Err(_) => write_problem(w, r, internal()).await,
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
                let raw = r
                    .extensions
                    .get::<RawBody>()
                    .map_or(Vec::new(), |b| b.0.clone());
                let fields: Result<std::collections::BTreeMap<String, serde_json::Value>, _> =
                    serde_json::from_slice(&raw);
                let Ok(fields) = fields else {
                    return write_problem(
                        w,
                        r,
                        Problem::new(
                            problem_type("validation_failed"),
                            "Invalid preference document.",
                        ),
                    )
                    .await;
                };
                if fields.values().any(serde_json::Value::is_null) {
                    return write_problem(
                        w,
                        r,
                        Problem::new(
                            problem_type("validation_failed"),
                            "Preference booleans cannot be null.",
                        ),
                    )
                    .await;
                }
                let patch: PrefsPatch = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                match patch_prefs(&s.pool, user_of(r), &get_profile_id(r), &patch).await {
                    Ok(p) => write_v2_json(w, &p).await,
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/email-preferences";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                match email_prefs(&s, user_of(r), &get_profile_id(r)).await {
                    Ok(p) => write_v2_json(w, &p).await,
                    Err(_) => write_problem(w, r, internal()).await,
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
                let (user, profile) = (user_of(r), get_profile_id(r));
                let raw = r
                    .extensions
                    .get::<RawBody>()
                    .map_or(Vec::new(), |b| b.0.clone());
                let body: ModeBody = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                if let Err(e) = set_email_mode(&s, user, &profile, &body.mode).await {
                    return write_problem(w, r, mode_problem(e)).await;
                }
                match email_prefs(&s, user, &profile).await {
                    Ok(p) => write_v2_json(w, &p).await,
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/read-all";
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                #[derive(Deserialize, Default)]
                struct Body {
                    #[serde(default)]
                    through: String,
                }
                let (user, profile) = (user_of(r), get_profile_id(r));
                let raw = r.extensions.get::<RawBody>().map_or(Vec::new(), |b| b.0.clone());
                let body: Body = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                let through: Cursor = match s.cursors.decode(&scope(r, "notificationReadCutoff", String::new()), &body.through) {
                    Ok(c) => c,
                    Err(problem) => return write_problem(w, r, problem).await,
                };
                if !through.id.is_empty() {
                    let Some(at) = through.at() else {
                        return write_problem(w, r, internal()).await;
                    };
                    let changed = s
                        .pool
                        .execute(
                            "UPDATE notification_deliveries SET read_at=now() WHERE user_id = $1 AND profile_id = $2 AND read_at IS NULL AND (created_at,id)<=($3,$4)",
                            &[&AnyInt(user), &profile, &at, &through.id],
                        )
                        .await;
                    match changed {
                        Ok(0) => {}
                        Ok(_) => {
                            let through_created_at = through.created_at_utc();
                            publish_read(&s, user, &profile, &ReadThrough {
                                profile_id: &profile,
                                through_created_at: &through_created_at,
                                through_id: &through.id,
                            })
                            .await;
                        }
                        Err(_) => return write_problem(w, r, internal()).await,
                    }
                }
                write_v2_empty(w).await;
            }),
        ),
    );

    let path = "/api/v2/notifications/{id}";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let id = r.url_param("id").to_owned();
                match get_row(&s.pool, user_of(r), &get_profile_id(r), &id).await {
                    Ok(Some(row)) => write_v2_json(w, &v2_item(&s, row)).await,
                    Ok(None) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(problem_type("not_found"), "Notification not found"),
                        )
                        .await
                    }
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );
    let path = "/api/v2/notifications/{id}/read";
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let id = r.url_param("id").to_owned();
                let (user, profile) = (user_of(r), get_profile_id(r));
                match mark_read(&s.pool, user, &profile, &id).await {
                    Ok(None) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(problem_type("not_found"), "Notification not found"),
                        )
                        .await
                    }
                    Err(_) => write_problem(w, r, internal()).await,
                    Ok(Some(changed)) => {
                        if changed {
                            publish_read(
                                &s,
                                user,
                                &profile,
                                &ReadOne {
                                    id: &id,
                                    profile_id: &profile,
                                },
                            )
                            .await;
                        }
                        write_v2_empty(w).await;
                    }
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/discord-preferences";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            route!(stack, |s, w, r| {
                match discord_prefs(&s.pool, user_of(r)).await {
                    Ok(p) => write_v2_json(w, &p).await,
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );
}

/// `muteNotificationSeries` and `unmuteNotificationSeries` (`apiv2/notification_series.go`).
fn mount_series(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/notifications/series/{series_id}/mute";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let series = r.url_param("series_id").to_owned();
                let (user, profile) = (user_of(r), get_profile_id(r));
                match ensure_accessible(&s.pool, &series, &super::personal::access_of(r)).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return write_problem(
                            w,
                            r,
                            Problem::new(problem_type("not_found"), "Series not found."),
                        )
                        .await;
                    }
                    Err(_) => return write_problem(w, r, internal()).await,
                }
                let found = s
                    .pool
                    .query(
                        "
		WITH series AS (
			SELECT content_id FROM media_items WHERE content_id = $3 AND type = 'series'
		), muted AS (
			INSERT INTO profile_series_notification_mutes (user_id, profile_id, series_id)
			SELECT $1, $2, content_id FROM series
			ON CONFLICT (user_id, profile_id, series_id) DO NOTHING
		)
		SELECT EXISTS (SELECT 1 FROM series)",
                        &[&AnyInt(user), &profile, &series],
                    )
                    .await
                    .map_err(|_| ())
                    .and_then(|rows| {
                        rows.first()
                            .and_then(|row| row.try_get::<_, bool>(0).ok())
                            .ok_or(())
                    });
                match found {
                    Ok(true) => write_v2_empty(w).await,
                    Ok(false) => {
                        write_problem(
                            w,
                            r,
                            Problem::new(problem_type("not_found"), "Series not found"),
                        )
                        .await
                    }
                    Err(_) => write_problem(w, r, internal()).await,
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
                let series = r.url_param("series_id").to_owned();
                let (user, profile) = (user_of(r), get_profile_id(r));
                match s
                    .pool
                    .execute(
                        "DELETE FROM profile_series_notification_mutes WHERE user_id = $1 AND profile_id = $2 AND series_id = $3",
                        &[&AnyInt(user), &profile, &series],
                    )
                    .await
                {
                    Ok(_) => write_v2_empty(w).await,
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );
}

async fn write_v2_empty(w: &mut dyn ResponseWriter) {
    w.write_header(204).await;
}

/// The server channel rows on the `/api/v1/admin` subrouter.
pub fn mount_v1_admin(stack: &Arc<Stack>, admin: &Mux) {
    channels::mount_v1(stack, admin);
}

pub fn mount(stack: &Arc<Stack>, api: &Mux, v2: &Mux) {
    mount_v1(stack, api);
    addresses::mount_v1(stack, api);
    mount_v2(stack, v2);
    mount_series(stack, v2);
    destinations::mount_v2(stack, v2);
    channels::mount_v2(stack, v2);
    addresses::mount_v2(stack, v2);
    push::mount_v2(stack, v2);
    push::mount_v2_ordered(stack, v2);
}

#[cfg(test)]
mod tests {
    use super::Cursor;

    #[test]
    fn read_through_event_names_the_cursor_instant_in_utc() {
        for (minted, want) in [
            ("2026-01-02T05:04:05.5+02:00", "2026-01-02T03:04:05.5Z"),
            ("2026-01-02T03:04:05.123456Z", "2026-01-02T03:04:05.123456Z"),
        ] {
            let cursor = Cursor {
                created_at: minted.to_owned(),
                id: String::new(),
            };
            assert_eq!(cursor.created_at_utc(), want);
        }
    }
}
