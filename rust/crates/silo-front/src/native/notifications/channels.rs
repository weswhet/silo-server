//! Server notification channels: `handlers/admin_server_channels.go`, the server channel operations in
//! `apiv2/notification_destinations.go`, `apiv2/notification_destination_create.go`, and
//! `apiv2/notification_server_channel_update.go`, over `ServerChannelService` and
//! `ServerChannelRepository`.
//!
//! The test send stays on Go: it needs the content digest payloads, signing, and guarded transport.

use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use silo_api_v2::problem::Problem;
use silo_api_v2::wire::{Instant, NullableInstant, paginated};
use silo_gocompat::json::Decoder;
use silo_gocompat::strings::trim_space;
use silo_http::chi::Mux;
use silo_http::{Request, ResponseWriter, handler_fn};
use silo_pg::{AnyInt, Row};

use super::super::auth::write_v1_error;
use super::super::chain::{
    Stack, Step, V2Class, problem_type, write_problem, write_v1_json, write_v2_json_status,
};
use super::super::huma::RawBody;
use super::destinations::{
    Created, bool_setting, new_signing_secret, null_instant, resolve_type, ulid, validate_name,
    validate_replacement, validate_webhook_url, write_secret,
};
use super::{Cursor, go_time, instant, internal, limit_of, query_param};

macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

const V1_ACTING_ADMIN: &[Step] = &[Step::ActingAdmin];
const V2_ADMIN_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
];

/// `serverChannelMaxChannels`.
const MAX_CHANNELS: i64 = 20;
const INVALID: &str = "invalid server channel";
const NAME_TAKEN: &str = "a server channel with this name already exists";

const COLUMNS: &str = "
	id, name, type, url_ciphertext, url_host, signing_secret_ciphertext, enabled,
	notify_new_movies, notify_new_episodes,
	notify_new_audiobooks, notify_new_ebooks,
	notify_request_submitted, notify_request_approved,
	notify_request_declined, notify_request_fulfilled,
	watermark_created_at, watermark_id,
	last_attempt_at, consecutive_failures, disabled_reason,
	last_success_at, last_failure_at, last_failure_status, last_failure_message,
	created_by_user_id, created_at, updated_at";

/// `ServerChannel`, with the columns the API and the writes read.
#[derive(Clone)]
struct Channel {
    id: String,
    name: String,
    kind: String,
    url_ciphertext: String,
    url_host: String,
    signing_secret_ciphertext: Option<String>,
    enabled: bool,
    notify_new_movies: bool,
    notify_new_episodes: bool,
    notify_new_audiobooks: bool,
    notify_new_ebooks: bool,
    notify_request_submitted: bool,
    notify_request_approved: bool,
    notify_request_declined: bool,
    notify_request_fulfilled: bool,
    consecutive_failures: i32,
    disabled_reason: Option<String>,
    last_success_at: Option<SystemTime>,
    last_failure_at: Option<SystemTime>,
    last_failure_status: Option<i32>,
    last_failure_message: Option<String>,
    /// `None` is Go's zero time: a created channel answers the struct it inserted.
    created_at: Option<SystemTime>,
}

fn scan(row: &Row) -> Result<Channel, String> {
    let e = |e: silo_pg::DriverError| e.to_string();
    Ok(Channel {
        id: row.try_get(0).map_err(e)?,
        name: row.try_get(1).map_err(e)?,
        kind: row.try_get(2).map_err(e)?,
        url_ciphertext: row.try_get(3).map_err(e)?,
        url_host: row.try_get(4).map_err(e)?,
        signing_secret_ciphertext: row.try_get(5).map_err(e)?,
        enabled: row.try_get(6).map_err(e)?,
        notify_new_movies: row.try_get(7).map_err(e)?,
        notify_new_episodes: row.try_get(8).map_err(e)?,
        notify_new_audiobooks: row.try_get(9).map_err(e)?,
        notify_new_ebooks: row.try_get(10).map_err(e)?,
        notify_request_submitted: row.try_get(11).map_err(e)?,
        notify_request_approved: row.try_get(12).map_err(e)?,
        notify_request_declined: row.try_get(13).map_err(e)?,
        notify_request_fulfilled: row.try_get(14).map_err(e)?,
        consecutive_failures: row.try_get(18).map_err(e)?,
        disabled_reason: row.try_get(19).map_err(e)?,
        last_success_at: row.try_get(20).map_err(e)?,
        last_failure_at: row.try_get(21).map_err(e)?,
        last_failure_status: row.try_get(22).map_err(e)?,
        last_failure_message: row.try_get(23).map_err(e)?,
        created_at: Some(row.try_get(25).map_err(e)?),
    })
}

#[derive(Serialize)]
struct V1Channel {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    url_host: String,
    enabled: bool,
    notify_new_movies: bool,
    notify_new_episodes: bool,
    notify_new_audiobooks: bool,
    notify_new_ebooks: bool,
    notify_request_submitted: bool,
    notify_request_approved: bool,
    notify_request_declined: bool,
    notify_request_fulfilled: bool,
    consecutive_failures: i32,
    disabled_reason: Option<String>,
    last_success_at: Option<String>,
    last_failure_at: Option<String>,
    last_failure_status: Option<i32>,
    last_failure_message: Option<String>,
    created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    signing_secret: String,
}

fn v1_channel(c: Channel, signing_secret: String) -> V1Channel {
    V1Channel {
        id: c.id,
        name: c.name,
        kind: c.kind,
        url_host: c.url_host,
        enabled: c.enabled,
        notify_new_movies: c.notify_new_movies,
        notify_new_episodes: c.notify_new_episodes,
        notify_new_audiobooks: c.notify_new_audiobooks,
        notify_new_ebooks: c.notify_new_ebooks,
        notify_request_submitted: c.notify_request_submitted,
        notify_request_approved: c.notify_request_approved,
        notify_request_declined: c.notify_request_declined,
        notify_request_fulfilled: c.notify_request_fulfilled,
        consecutive_failures: c.consecutive_failures,
        disabled_reason: c.disabled_reason,
        last_success_at: c.last_success_at.map(go_time),
        last_failure_at: c.last_failure_at.map(go_time),
        last_failure_status: c.last_failure_status,
        last_failure_message: c.last_failure_message,
        created_at: c
            .created_at
            .map_or_else(|| "0001-01-01T00:00:00Z".to_owned(), go_time),
        signing_secret,
    }
}

#[derive(Serialize)]
struct V2Channel {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    url_host: String,
    enabled: bool,
    notify_new_movies: bool,
    notify_new_episodes: bool,
    notify_new_audiobooks: bool,
    notify_new_ebooks: bool,
    notify_request_submitted: bool,
    notify_request_approved: bool,
    notify_request_declined: bool,
    notify_request_fulfilled: bool,
    consecutive_failures: i32,
    disabled_reason: Option<String>,
    last_success_at: NullableInstant,
    last_failure_at: NullableInstant,
    last_failure_status: Option<i32>,
    last_failure_message: Option<String>,
    created_at: Instant,
}

fn v2_channel(c: Channel) -> V2Channel {
    V2Channel {
        id: c.id,
        name: c.name,
        kind: c.kind,
        url_host: c.url_host,
        enabled: c.enabled,
        notify_new_movies: c.notify_new_movies,
        notify_new_episodes: c.notify_new_episodes,
        notify_new_audiobooks: c.notify_new_audiobooks,
        notify_new_ebooks: c.notify_new_ebooks,
        notify_request_submitted: c.notify_request_submitted,
        notify_request_approved: c.notify_request_approved,
        notify_request_declined: c.notify_request_declined,
        notify_request_fulfilled: c.notify_request_fulfilled,
        consecutive_failures: c.consecutive_failures,
        disabled_reason: c.disabled_reason,
        last_success_at: null_instant(c.last_success_at),
        last_failure_at: null_instant(c.last_failure_at),
        last_failure_status: c.last_failure_status,
        last_failure_message: c.last_failure_message,
        created_at: instant(c.created_at.unwrap_or(SystemTime::UNIX_EPOCH)),
    }
}

fn url_aad(id: &str) -> String {
    silo_core::secret::aad::server_channel(id, "url")
}

fn secret_aad(id: &str) -> String {
    silo_core::secret::aad::server_channel(id, "signing_secret")
}

/// `ServerChannelInput`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Input {
    name: Option<String>,
    url: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    enabled: Option<bool>,
    notify_new_movies: Option<bool>,
    notify_new_episodes: Option<bool>,
    notify_new_audiobooks: Option<bool>,
    notify_new_ebooks: Option<bool>,
    notify_request_submitted: Option<bool>,
    notify_request_approved: Option<bool>,
    notify_request_declined: Option<bool>,
    notify_request_fulfilled: Option<bool>,
}

enum ChannelError {
    NotFound,
    Limit,
    Invalid(String),
    Failed,
}

fn is_name_violation(e: &silo_pg::Error) -> bool {
    e.as_db_error().is_some_and(|d| {
        d.code().code() == "23505"
            && d.constraint() == Some("notification_server_channels_name_key")
    })
}

async fn allow_private(s: &Stack) -> bool {
    bool_setting(
        s,
        "notifications.webhooks.allow_private_destinations",
        false,
    )
    .await
}

/// `ServerChannelService.Create`.
async fn create(s: &Stack, user: i64, input: Input) -> Result<(Channel, String), ChannelError> {
    let (Some(name), Some(url)) = (input.name.as_deref(), input.url.as_deref()) else {
        return Err(ChannelError::Invalid(format!(
            "{INVALID}: name and url are required"
        )));
    };
    let name = validate_name(name, INVALID).map_err(ChannelError::Invalid)?;
    let raw_url = trim_space(url).to_owned();
    let host = validate_webhook_url(&raw_url, allow_private(s).await)
        .await
        .map_err(|e| ChannelError::Invalid(format!("{INVALID}: {e}")))?;
    let explicit = input.kind.as_deref().map(trim_space).unwrap_or_default();
    let kind = resolve_type(&raw_url, explicit, INVALID).map_err(ChannelError::Invalid)?;
    let id = ulid();
    let url_ciphertext = s
        .cipher
        .encrypt(raw_url.as_bytes(), url_aad(&id))
        .map_err(|_| ChannelError::Failed)?;
    let mut signing_secret = String::new();
    let mut secret_ciphertext = None;
    if kind == "generic" {
        signing_secret = new_signing_secret();
        secret_ciphertext = Some(
            s.cipher
                .encrypt(signing_secret.as_bytes(), secret_aad(&id))
                .map_err(|_| ChannelError::Failed)?,
        );
    }
    let ch = Channel {
        id,
        name,
        kind,
        url_ciphertext,
        url_host: host,
        signing_secret_ciphertext: secret_ciphertext,
        enabled: input.enabled.unwrap_or(true),
        notify_new_movies: input.notify_new_movies.unwrap_or(true),
        notify_new_episodes: input.notify_new_episodes.unwrap_or(true),
        notify_new_audiobooks: input.notify_new_audiobooks.unwrap_or(true),
        notify_new_ebooks: input.notify_new_ebooks.unwrap_or(true),
        notify_request_submitted: input.notify_request_submitted.unwrap_or(false),
        notify_request_approved: input.notify_request_approved.unwrap_or(false),
        notify_request_declined: input.notify_request_declined.unwrap_or(false),
        notify_request_fulfilled: input.notify_request_fulfilled.unwrap_or(false),
        consecutive_failures: 0,
        disabled_reason: None,
        last_success_at: None,
        last_failure_at: None,
        last_failure_status: None,
        last_failure_message: None,
        created_at: None,
    };
    let mut conn = s.pool.acquire().await.map_err(|_| ChannelError::Failed)?;
    let mut tx = conn.begin().await.map_err(|_| ChannelError::Failed)?;
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended('notification_server_channels', 0))",
        &[],
    )
    .await
    .map_err(|_| ChannelError::Failed)?;
    let count: i64 = tx
        .query("SELECT count(*) FROM notification_server_channels", &[])
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get(0).ok()))
        .ok_or(ChannelError::Failed)?;
    if count >= MAX_CHANNELS {
        return Err(ChannelError::Limit);
    }
    let inserted = tx
        .execute(
            "
		INSERT INTO notification_server_channels
			(id, name, type, url_ciphertext, url_host, signing_secret_ciphertext, enabled,
			 notify_new_movies, notify_new_episodes,
			 notify_new_audiobooks, notify_new_ebooks,
			 notify_request_submitted, notify_request_approved,
			 notify_request_declined, notify_request_fulfilled,
			 created_by_user_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            &[
                &ch.id,
                &ch.name,
                &ch.kind,
                &ch.url_ciphertext,
                &ch.url_host,
                &ch.signing_secret_ciphertext,
                &ch.enabled,
                &ch.notify_new_movies,
                &ch.notify_new_episodes,
                &ch.notify_new_audiobooks,
                &ch.notify_new_ebooks,
                &ch.notify_request_submitted,
                &ch.notify_request_approved,
                &ch.notify_request_declined,
                &ch.notify_request_fulfilled,
                &AnyInt(user),
            ],
        )
        .await;
    match inserted {
        Ok(_) => {}
        Err(e) if is_name_violation(&e) => {
            return Err(ChannelError::Invalid(format!("{INVALID}: {NAME_TAKEN}")));
        }
        Err(_) => return Err(ChannelError::Failed),
    }
    tx.commit().await.map_err(|_| ChannelError::Failed)?;
    Ok((ch, signing_secret))
}

async fn get(s: &Stack, id: &str) -> Result<Option<Channel>, ChannelError> {
    let sql = format!("SELECT {COLUMNS} FROM notification_server_channels WHERE id = $1");
    let rows = s
        .pool
        .query(&sql, &[&id])
        .await
        .map_err(|_| ChannelError::Failed)?;
    rows.first()
        .map(scan)
        .transpose()
        .map_err(|_| ChannelError::Failed)
}

/// `applyChannelInput`: whether dispatch state resets.
async fn apply(s: &Stack, ch: &mut Channel, input: &Input) -> Result<bool, ChannelError> {
    let was_delivering = ch.enabled && ch.disabled_reason.is_none();
    if let Some(name) = &input.name {
        ch.name = validate_name(name, INVALID).map_err(ChannelError::Invalid)?;
    }
    let mut reset = false;
    if let Some(url) = &input.url {
        let raw_url = trim_space(url).to_owned();
        let host = validate_webhook_url(&raw_url, allow_private(s).await)
            .await
            .map_err(|e| ChannelError::Invalid(format!("{INVALID}: {e}")))?;
        validate_replacement(&ch.kind, &raw_url, INVALID).map_err(ChannelError::Invalid)?;
        ch.url_ciphertext = s
            .cipher
            .encrypt(raw_url.as_bytes(), url_aad(&ch.id))
            .map_err(|_| ChannelError::Failed)?;
        ch.url_host = host;
        reset = true;
    }
    let set = |field: &mut bool, v: Option<bool>| {
        if let Some(v) = v {
            *field = v;
        }
    };
    set(&mut ch.enabled, input.enabled);
    set(&mut ch.notify_new_movies, input.notify_new_movies);
    set(&mut ch.notify_new_episodes, input.notify_new_episodes);
    set(&mut ch.notify_new_audiobooks, input.notify_new_audiobooks);
    set(&mut ch.notify_new_ebooks, input.notify_new_ebooks);
    set(
        &mut ch.notify_request_submitted,
        input.notify_request_submitted,
    );
    set(
        &mut ch.notify_request_approved,
        input.notify_request_approved,
    );
    set(
        &mut ch.notify_request_declined,
        input.notify_request_declined,
    );
    set(
        &mut ch.notify_request_fulfilled,
        input.notify_request_fulfilled,
    );
    Ok(reset || (ch.enabled && !was_delivering))
}

/// `ServerChannelRepository.Update`.
async fn store(s: &Stack, ch: &Channel) -> Result<(), ChannelError> {
    let updated = s
        .pool
        .execute(
            "
		UPDATE notification_server_channels SET
			name = $2, url_ciphertext = $3, url_host = $4,
			signing_secret_ciphertext = $5, enabled = $6,
			notify_new_movies = $7, notify_new_episodes = $8,
			notify_new_audiobooks = $9, notify_new_ebooks = $10,
			notify_request_submitted = $11, notify_request_approved = $12,
			notify_request_declined = $13, notify_request_fulfilled = $14,
			updated_at = now()
		WHERE id = $1",
            &[
                &ch.id,
                &ch.name,
                &ch.url_ciphertext,
                &ch.url_host,
                &ch.signing_secret_ciphertext,
                &ch.enabled,
                &ch.notify_new_movies,
                &ch.notify_new_episodes,
                &ch.notify_new_audiobooks,
                &ch.notify_new_ebooks,
                &ch.notify_request_submitted,
                &ch.notify_request_approved,
                &ch.notify_request_declined,
                &ch.notify_request_fulfilled,
            ],
        )
        .await;
    match updated {
        Ok(_) => Ok(()),
        Err(e) if is_name_violation(&e) => {
            Err(ChannelError::Invalid(format!("{INVALID}: {NAME_TAKEN}")))
        }
        Err(_) => Err(ChannelError::Failed),
    }
}

/// `ServerChannelService.Update` (v1).
async fn update_v1(s: &Stack, id: &str, input: Input) -> Result<Channel, ChannelError> {
    let Some(mut ch) = get(s, id).await? else {
        return Err(ChannelError::NotFound);
    };
    let reset = apply(s, &mut ch, &input).await?;
    store(s, &ch).await?;
    if reset {
        s.pool
            .execute(
                "
		UPDATE notification_server_channels SET
			consecutive_failures = 0, disabled_reason = NULL, last_attempt_at = NULL,
			watermark_created_at = now(), watermark_id = '',
			updated_at = now()
		WHERE id = $1",
                &[&ch.id],
            )
            .await
            .map_err(|_| ChannelError::Failed)?;
        ch.consecutive_failures = 0;
        ch.disabled_reason = None;
    }
    Ok(ch)
}

/// `ServerChannelService.UpdateV2`.
async fn update_v2(s: &Stack, id: &str, input: Input) -> Result<Channel, ChannelError> {
    let mut conn = s.pool.acquire().await.map_err(|_| ChannelError::Failed)?;
    let mut tx = conn.begin().await.map_err(|_| ChannelError::Failed)?;
    let sql = format!("SELECT {COLUMNS} FROM notification_server_channels WHERE id=$1 FOR UPDATE");
    let rows = tx
        .query(&sql, &[&id])
        .await
        .map_err(|_| ChannelError::Failed)?;
    let Some(row) = rows.first() else {
        return Err(ChannelError::NotFound);
    };
    let mut ch = scan(row).map_err(|_| ChannelError::Failed)?;
    let reset = apply(s, &mut ch, &input).await?;
    let sql = format!(
        "UPDATE notification_server_channels SET
 name=$2,url_ciphertext=$3,url_host=$4,enabled=$5,
 notify_new_movies=$6,notify_new_episodes=$7,notify_new_audiobooks=$8,notify_new_ebooks=$9,
 notify_request_submitted=$10,notify_request_approved=$11,notify_request_declined=$12,notify_request_fulfilled=$13,
 consecutive_failures=CASE WHEN $14 THEN 0 ELSE consecutive_failures END,
 disabled_reason=CASE WHEN $14 THEN NULL ELSE disabled_reason END,
 last_attempt_at=CASE WHEN $14 THEN NULL ELSE last_attempt_at END,
 watermark_created_at=CASE WHEN $14 THEN clock_timestamp() ELSE watermark_created_at END,
 watermark_id=CASE WHEN $14 THEN '' ELSE watermark_id END,updated_at=now()
 WHERE id=$1 RETURNING {COLUMNS}"
    );
    let updated = tx
        .query(
            &sql,
            &[
                &id,
                &ch.name,
                &ch.url_ciphertext,
                &ch.url_host,
                &ch.enabled,
                &ch.notify_new_movies,
                &ch.notify_new_episodes,
                &ch.notify_new_audiobooks,
                &ch.notify_new_ebooks,
                &ch.notify_request_submitted,
                &ch.notify_request_approved,
                &ch.notify_request_declined,
                &ch.notify_request_fulfilled,
                &reset,
            ],
        )
        .await;
    let row = match updated {
        Ok(rows) => match rows.first() {
            Some(row) => scan(row).map_err(|_| ChannelError::Failed)?,
            None => return Err(ChannelError::Failed),
        },
        Err(e) if is_name_violation(&e) => {
            return Err(ChannelError::Invalid(format!("{INVALID}: {NAME_TAKEN}")));
        }
        Err(_) => return Err(ChannelError::Failed),
    };
    tx.commit().await.map_err(|_| ChannelError::Failed)?;
    Ok(row)
}

/// `RotateSecret` (v1, the whole row written back) and `RotateSecretV2` (the secret alone).
async fn rotate(s: &Stack, id: &str, v2: bool) -> Result<String, ChannelError> {
    let Some(mut ch) = get(s, id).await? else {
        return Err(ChannelError::NotFound);
    };
    if ch.kind != "generic" {
        return Err(ChannelError::Invalid(format!(
            "{INVALID}: only generic channels have signing secrets"
        )));
    }
    let value = new_signing_secret();
    let ciphertext = s
        .cipher
        .encrypt(value.as_bytes(), secret_aad(&ch.id))
        .map_err(|_| ChannelError::Failed)?;
    if v2 {
        let changed = s
            .pool
            .execute(
                "UPDATE notification_server_channels SET signing_secret_ciphertext=$2, updated_at=now() WHERE id=$1 AND type='generic'",
                &[&id, &ciphertext],
            )
            .await
            .map_err(|_| ChannelError::Failed)?;
        if changed == 0 {
            return Err(ChannelError::NotFound);
        }
    } else {
        ch.signing_secret_ciphertext = Some(ciphertext);
        store(s, &ch).await?;
    }
    Ok(value)
}

async fn delete(s: &Stack, id: &str) -> bool {
    s.pool
        .execute(
            "DELETE FROM notification_server_channels WHERE id = $1",
            &[&id],
        )
        .await
        .is_ok()
}

/// `writeServerChannelError`.
async fn write_v1_channel_error(w: &mut dyn ResponseWriter, e: ChannelError) {
    match e {
        ChannelError::NotFound => {
            write_v1_error(w, 404, "not_found", "Server channel not found").await
        }
        ChannelError::Limit => {
            write_v1_error(w, 422, "limit_reached", "Server channel limit reached").await
        }
        ChannelError::Invalid(message) => write_v1_error(w, 400, "bad_request", &message).await,
        ChannelError::Failed => {
            write_v1_error(w, 500, "internal_error", "Server channel operation failed").await
        }
    }
}

fn decode_v1(bytes: &[u8]) -> Option<Input> {
    Decoder::new().stream(bytes).decode::<Input>().ok()
}

/// The v1 rows, on the `/api/v1/admin` subrouter.
pub(crate) fn mount_v1(stack: &Arc<Stack>, admin: &Mux) {
    let base = "/api/v1/admin/notifications/server-channels";
    // The administrator gate sits above Go's `r.Route`, so it refuses before the subrouter matches.
    let r = &Mux::new();
    r.use_middleware([stack.v1_group(V1_ACTING_ADMIN)]);
    let v1 = |at: &str, handler| stack.v1(at, &[], handler);
    {
        r.get(
            "/",
            v1(
                &format!("{base}/"),
                route!(stack, |s, w, _r| {
                    let sql = format!(
                        "SELECT {COLUMNS} FROM notification_server_channels ORDER BY created_at"
                    );
                    let listed = s
                        .pool
                        .query(&sql, &[])
                        .await
                        .map_err(|_| ())
                        .and_then(|rows| {
                            rows.iter()
                                .map(scan)
                                .collect::<Result<Vec<_>, _>>()
                                .map_err(|_| ())
                        });
                    let Ok(channels) = listed else {
                        return write_v1_error(
                            w,
                            500,
                            "internal_error",
                            "Failed to list server channels",
                        )
                        .await;
                    };
                    #[derive(Serialize)]
                    struct List {
                        channels: Vec<V1Channel>,
                    }
                    let channels = channels
                        .into_iter()
                        .map(|c| v1_channel(c, String::new()))
                        .collect();
                    write_v1_json(w, 200, &List { channels }).await;
                }),
            ),
        );
        r.post(
            "/",
            v1(
                &format!("{base}/"),
                route!(stack, |s, w, r| {
                    let (bytes, _) = r.read_all().await;
                    let Some(input) = decode_v1(&bytes) else {
                        return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                    };
                    match create(&s, super::user_of(r), input).await {
                        Ok((ch, secret)) => write_v1_json(w, 201, &v1_channel(ch, secret)).await,
                        Err(e) => write_v1_channel_error(w, e).await,
                    }
                }),
            ),
        );
        r.put(
            "/{id}",
            v1(
                &format!("{base}/{{id}}"),
                route!(stack, |s, w, r| {
                    let id = r.url_param("id").to_owned();
                    let (bytes, _) = r.read_all().await;
                    let Some(input) = decode_v1(&bytes) else {
                        return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                    };
                    match update_v1(&s, &id, input).await {
                        Ok(ch) => write_v1_json(w, 200, &v1_channel(ch, String::new())).await,
                        Err(e) => write_v1_channel_error(w, e).await,
                    }
                }),
            ),
        );
        r.delete(
            "/{id}",
            v1(
                &format!("{base}/{{id}}"),
                route!(stack, |s, w, r| {
                    let id = r.url_param("id").to_owned();
                    if delete(&s, &id).await {
                        w.write_header(204).await;
                    } else {
                        write_v1_channel_error(w, ChannelError::Failed).await;
                    }
                }),
            ),
        );
        r.post(
            "/{id}/rotate-secret",
            v1(
                &format!("{base}/{{id}}/rotate-secret"),
                route!(stack, |s, w, r| {
                    let id = r.url_param("id").to_owned();
                    match rotate(&s, &id, false).await {
                        Ok(signing_secret) => {
                            #[derive(Serialize)]
                            struct Out {
                                signing_secret: String,
                            }
                            write_v1_json(w, 200, &Out { signing_secret }).await
                        }
                        Err(e) => write_v1_channel_error(w, e).await,
                    }
                }),
            ),
        );
    }
    admin.mount("/notifications/server-channels", r.clone());
}

fn body_of(r: &Request) -> Vec<u8> {
    r.extensions
        .get::<RawBody>()
        .map_or(Vec::new(), |b| b.0.clone())
}

fn not_found() -> Problem {
    Problem::new(problem_type("not_found"), "Server channel not found.")
}

fn validation(detail: &str) -> Problem {
    Problem::new(problem_type("validation_failed"), detail)
}

/// `notificationCursorScope` for the administrator's listing.
fn page_scope(r: &Request, limit: i64) -> silo_api_v2::cursor::CursorScope {
    super::scope(r, "listAdminNotificationServerChannels", limit.to_string())
}

/// The v2 rows.
pub(crate) fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    let path = "/api/v2/admin/notifications/server-channels";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ActingAdmin,
            route!(stack, |s, w, r| {
                let limit = limit_of(r);
                let page = page_scope(r, limit);
                let raw = query_param(r, "cursor");
                let after: Option<Cursor> = if raw.is_empty() {
                    None
                } else {
                    match s.cursors.decode(&page, &raw) {
                        Ok(c) => Some(c),
                        Err(problem) => return write_problem(w, r, problem).await,
                    }
                };
                let lookahead = limit + 1;
                let rows = match &after {
                    Some(c) => {
                        let Some(at) = c.at() else {
                            return write_problem(w, r, internal()).await;
                        };
                        let sql = format!(
                            "SELECT {COLUMNS} FROM notification_server_channels WHERE (created_at, id) > ($1, $2) ORDER BY created_at, id LIMIT $3"
                        );
                        s.pool.query(&sql, &[&at, &c.id, &lookahead]).await
                    }
                    None => {
                        let sql = format!(
                            "SELECT {COLUMNS} FROM notification_server_channels ORDER BY created_at, id LIMIT $1"
                        );
                        s.pool.query(&sql, &[&lookahead]).await
                    }
                };
                let Ok(mut channels) = rows.map_err(|_| ()).and_then(|rows| {
                    rows.iter()
                        .map(scan)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ())
                }) else {
                    return write_problem(w, r, internal()).await;
                };
                let more = channels.len() as i64 > limit;
                if more {
                    channels.truncate(limit as usize);
                }
                let mut next = String::new();
                if more && let Some(last) = channels.last() {
                    let cursor = Cursor {
                        created_at: last.created_at.map(go_time).unwrap_or_default(),
                        id: last.id.clone(),
                    };
                    next = match s.cursors.encode(&page, &cursor) {
                        Ok(n) => n,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                }
                let items: Vec<V2Channel> = channels.into_iter().map(v2_channel).collect();
                write_v2_json_status(w, 200, &paginated(items, next)).await;
            }),
        ),
    );
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let input: Input = silo_gocompat::json::unmarshal(&body_of(r)).unwrap_or_default();
                let input = Input {
                    name: Some(input.name.unwrap_or_default()),
                    url: Some(input.url.unwrap_or_default()),
                    ..input
                };
                match create(&s, super::user_of(r), input).await {
                    Ok((ch, secret)) => {
                        write_v2_json_status(
                            w,
                            201,
                            &Created {
                                id: ch.id,
                                name: ch.name,
                                kind: ch.kind,
                                url_host: ch.url_host,
                                signing_secret: secret,
                            },
                        )
                        .await
                    }
                    Err(ChannelError::Limit) => {
                        write_problem(w, r, validation("Notification destination limit reached."))
                            .await
                    }
                    Err(ChannelError::Invalid(_)) => {
                        write_problem(
                            w,
                            r,
                            validation("Invalid notification destination configuration."),
                        )
                        .await
                    }
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );

    let path = "/api/v2/admin/notifications/server-channels/{id}";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let id = r.url_param("id").to_owned();
                let mut input: Input =
                    silo_gocompat::json::unmarshal(&body_of(r)).unwrap_or_default();
                input.kind = None;
                match update_v2(&s, &id, input).await {
                    Ok(ch) => write_v2_json_status(w, 200, &v2_channel(ch)).await,
                    Err(ChannelError::NotFound) => write_problem(w, r, not_found()).await,
                    Err(ChannelError::Invalid(_)) => {
                        write_problem(w, r, validation("Invalid server channel configuration."))
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
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let id = r.url_param("id").to_owned();
                if delete(&s, &id).await {
                    w.write_header(204).await;
                } else {
                    write_problem(w, r, internal()).await;
                }
            }),
        ),
    );

    let path = "/api/v2/admin/notifications/server-channels/{id}/rotate-secret";
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_ADMIN_WRITE,
            route!(stack, |s, w, r| {
                let id = r.url_param("id").to_owned();
                match rotate(&s, &id, true).await {
                    Ok(secret) => write_secret(w, secret).await,
                    Err(ChannelError::NotFound) => write_problem(w, r, not_found()).await,
                    Err(ChannelError::Invalid(_)) => {
                        write_problem(
                            w,
                            r,
                            validation("Only generic server channels have signing secrets."),
                        )
                        .await
                    }
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );
}
