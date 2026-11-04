//! Profile webhooks and browser push subscriptions: `handlers/notifications_webhooks.go`,
//! `handlers/notifications_webpush.go`, `apiv2/notification_destinations.go`,
//! `apiv2/notification_destination_create.go`, `apiv2/notification_webhook_update.go`, and the
//! `WebhookService`, `WebhookRepository`, `WebPushService`, and `WebPushRepository` they call.
//!
//! The test send stays on Go: it needs the webhook sender's payloads, signing, and guarded transport.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use silo_api_v2::precondition::evaluate_guarded_preconditions;
use silo_api_v2::problem::Problem;
use silo_api_v2::wire::{Instant, NullableInstant, paginated};
use silo_core::apiv2::{EntityTag, render_etag};
use silo_gate::mw::auth::get_profile_id;
use silo_gocompat::json::Decoder;
use silo_gocompat::strings::trim_space;
use silo_http::chi::Mux;
use silo_http::{Request, ResponseWriter, handler_fn};
use silo_pg::{AnyInt, Row};
use silo_runtime::netguard;

use super::super::auth::write_v1_error;
use super::super::chain::{
    Stack, problem_type, write_problem, write_v1_json, write_v2_json_status,
};
use super::super::huma::RawBody;
use super::{Cursor, V2_WRITE, go_time, instant, internal, limit_of, query_param, scope, user_of};

macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

const WEBHOOK_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// `validateWebhookURL`: HTTPS only, no credentials, and every resolved address allowed. Returns the host.
pub(super) async fn validate_webhook_url(raw: &str, allow_private: bool) -> Result<String, String> {
    let Ok(parsed) = silo_gocompat::url::parse(trim_space(raw)) else {
        return Err("invalid URL".into());
    };
    if parsed.scheme != "https" {
        return Err("webhook URLs must use https".into());
    }
    let host = netguard::hostname(&parsed.host).to_owned();
    if host.is_empty() {
        return Err("webhook URL has no host".into());
    }
    if host.len() > 253 {
        return Err("webhook URL host is too long".into());
    }
    if parsed.user.is_some() {
        return Err("webhook URLs must not embed credentials".into());
    }
    const REFUSED: &str = "webhook destinations on private or special-use networks are not allowed";
    if let Some(addr) = netguard::parse_addr(&host) {
        if netguard::check_addr(addr, allow_private).is_err() {
            return Err(REFUSED.into());
        }
        return Ok(host);
    }
    let Some(addrs) = netguard::lookup(&host, WEBHOOK_LOOKUP_TIMEOUT).await else {
        return Err("webhook host could not be resolved".into());
    };
    if addrs
        .into_iter()
        .any(|a| netguard::check_addr(a, allow_private).is_err())
    {
        return Err(REFUSED.into());
    }
    Ok(host)
}

/// `discordWebhookURL`.
pub(super) fn discord_webhook_url(raw: &str) -> bool {
    let Ok(parsed) = silo_gocompat::url::parse(trim_space(raw)) else {
        return false;
    };
    let host = silo_gocompat::strings::to_lower(netguard::hostname(&parsed.host));
    matches!(
        host.as_str(),
        "discord.com" | "discordapp.com" | "ptb.discord.com" | "canary.discord.com"
    ) && parsed.path.starts_with("/api/webhooks/")
}

/// `validateChannelName`; `invalid` is the sentinel's text.
pub(super) fn validate_name(name: &str, invalid: &str) -> Result<String, String> {
    let trimmed = trim_space(name);
    if trimmed.is_empty() {
        return Err(format!("{invalid}: name is required"));
    }
    if trimmed.len() > 64 {
        return Err(format!("{invalid}: name must be 64 characters or fewer"));
    }
    Ok(trimmed.to_owned())
}

/// `resolveWebhookType`.
pub(super) fn resolve_type(raw: &str, explicit: &str, invalid: &str) -> Result<String, String> {
    let discord = discord_webhook_url(raw);
    match explicit {
        "" => return Ok(if discord { "discord" } else { "generic" }.into()),
        "discord" | "generic" => {}
        _ => return Err(format!("{invalid}: type must be discord or generic")),
    }
    if explicit == "discord" && !discord {
        return Err(format!(
            "{invalid}: type discord requires a Discord webhook URL"
        ));
    }
    if explicit == "generic" && discord {
        return Err(format!(
            "{invalid}: Discord webhook URLs must use type discord"
        ));
    }
    Ok(explicit.into())
}

/// `validateReplacementURL`.
pub(super) fn validate_replacement(kind: &str, raw: &str, invalid: &str) -> Result<(), String> {
    let discord = discord_webhook_url(raw);
    if kind == "discord" && !discord {
        return Err(format!(
            "{invalid}: a Discord webhook needs a Discord webhook URL"
        ));
    }
    if kind == "generic" && discord {
        return Err(format!(
            "{invalid}: Discord webhook URLs must use type discord"
        ));
    }
    Ok(())
}

/// `newSigningSecret`.
pub(super) fn new_signing_secret() -> String {
    let raw: [u8; 32] = rand::random();
    STANDARD.encode(raw)
}

/// A ULID, as `ulid.Make`.
pub(super) fn ulid() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let millis = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let random = u128::from_be_bytes(*uuid::Uuid::new_v4().as_bytes()) >> 48;
    let mut value = (millis << 80) | random;
    let mut out = [0u8; 26];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) async fn setting(s: &Stack, key: &str) -> String {
    s.encrypted.get(key).await.unwrap_or_default()
}

pub(super) async fn bool_setting(s: &Stack, key: &str, fallback: bool) -> bool {
    super::parse_bool(&setting(s, key).await, fallback)
}

pub(super) async fn int_setting(s: &Stack, key: &str, fallback: i64, min: i64, max: i64) -> i64 {
    super::parse_int(&setting(s, key).await, fallback, min, max)
}

pub(super) fn null_instant(t: Option<SystemTime>) -> NullableInstant {
    NullableInstant {
        valid: t.is_some(),
        time: t.map(instant),
    }
}

fn v1_time(t: Option<SystemTime>) -> Option<String> {
    t.map(go_time)
}

fn body_of(r: &Request) -> Vec<u8> {
    r.extensions
        .get::<RawBody>()
        .map_or(Vec::new(), |b| b.0.clone())
}

fn header_text(r: &Request, name: &str) -> String {
    String::from_utf8_lossy(r.header.get(name)).into_owned()
}

fn not_found(detail: &str) -> Problem {
    Problem::new(problem_type("not_found"), detail)
}

fn validation(detail: &str) -> Problem {
    Problem::new(problem_type("validation_failed"), detail)
}

async fn write_empty(w: &mut dyn ResponseWriter) {
    w.write_header(204).await;
}

// ---- Web push -------------------------------------------------------------------------------------

const WEB_PUSH_COLUMNS: &str = "
	id, user_id, profile_id, endpoint, p256dh, auth, device_name, enabled,
	consecutive_failures, last_success_at, last_failure_at, last_failure_status,
	created_at, updated_at";

/// `WebPushSubscription`, with the columns the API reads.
struct Subscription {
    id: String,
    endpoint: String,
    device_name: String,
    enabled: bool,
    created_at: SystemTime,
    last_success_at: Option<SystemTime>,
    last_failure_at: Option<SystemTime>,
}

fn scan_subscription(row: &Row) -> Result<Subscription, String> {
    let e = |e: silo_pg::DriverError| e.to_string();
    Ok(Subscription {
        id: row.try_get(0).map_err(e)?,
        endpoint: row.try_get(3).map_err(e)?,
        device_name: row.try_get(6).map_err(e)?,
        enabled: row.try_get(7).map_err(e)?,
        last_success_at: row.try_get(9).map_err(e)?,
        last_failure_at: row.try_get(10).map_err(e)?,
        created_at: row.try_get(12).map_err(e)?,
    })
}

#[derive(Serialize)]
struct V1Subscription {
    id: String,
    endpoint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_name: String,
    enabled: bool,
    created_at: String,
    last_success_at: Option<String>,
    last_failure_at: Option<String>,
}

fn v1_subscription(sub: Subscription) -> V1Subscription {
    V1Subscription {
        id: sub.id,
        endpoint: sub.endpoint,
        device_name: sub.device_name,
        enabled: sub.enabled,
        created_at: go_time(sub.created_at),
        last_success_at: v1_time(sub.last_success_at),
        last_failure_at: v1_time(sub.last_failure_at),
    }
}

#[derive(Serialize)]
struct V2Subscription {
    id: String,
    endpoint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_name: String,
    enabled: bool,
    created_at: Instant,
    last_success_at: NullableInstant,
    last_failure_at: NullableInstant,
}

fn v2_subscription(sub: Subscription) -> V2Subscription {
    V2Subscription {
        id: sub.id,
        endpoint: sub.endpoint,
        device_name: sub.device_name,
        enabled: sub.enabled,
        created_at: instant(sub.created_at),
        last_success_at: null_instant(sub.last_success_at),
        last_failure_at: null_instant(sub.last_failure_at),
    }
}

/// `WebPushService.Subscribe`'s outcome: `Err(Some(message))` is `ErrWebPushInvalid`, `Err(None)` a failure.
async fn subscribe(
    s: &Stack,
    user: i64,
    profile: &str,
    endpoint: &str,
    p256dh: &str,
    auth: &str,
    device_name: &str,
) -> Result<Subscription, Option<String>> {
    const INVALID: &str = "invalid web push subscription";
    let endpoint = trim_space(endpoint);
    if endpoint.is_empty() || p256dh.is_empty() || auth.is_empty() {
        return Err(Some(format!("{INVALID}: endpoint and keys are required")));
    }
    if endpoint.len() > 2048 {
        return Err(Some(format!("{INVALID}: endpoint is too long")));
    }
    if let Err(e) = validate_webhook_url(endpoint, false).await {
        return Err(Some(format!("{INVALID}: {e}")));
    }
    // `deviceName[:128]` cuts bytes; a cut through a character is text Postgres refuses.
    let device_name = if device_name.len() > 128 {
        match std::str::from_utf8(&device_name.as_bytes()[..128]) {
            Ok(cut) => cut.to_owned(),
            Err(_) => return Err(None),
        }
    } else {
        device_name.to_owned()
    };
    let mut conn = s.pool.acquire().await.map_err(|_| None)?;
    let mut tx = conn.begin().await.map_err(|_| None)?;
    tx.execute(
        "
		DELETE FROM web_push_delivery_attempts
		WHERE outcome IN ('pending', 'retrying')
		  AND subscription_id IN (
			SELECT id FROM web_push_subscriptions
			WHERE endpoint = $1 AND (user_id <> $2 OR profile_id <> $3)
		  )",
        &[&endpoint, &AnyInt(user), &profile],
    )
    .await
    .map_err(|_| None)?;
    let sql = format!(
        "
		INSERT INTO web_push_subscriptions
			(id, user_id, profile_id, endpoint, p256dh, auth, device_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (endpoint) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			profile_id = EXCLUDED.profile_id,
			p256dh = EXCLUDED.p256dh,
			auth = EXCLUDED.auth,
			device_name = EXCLUDED.device_name,
			enabled = true,
			consecutive_failures = 0,
			updated_at = now()
		RETURNING {WEB_PUSH_COLUMNS}"
    );
    let id = ulid();
    let rows = tx
        .query(
            &sql,
            &[
                &id,
                &AnyInt(user),
                &profile,
                &endpoint,
                &p256dh,
                &auth,
                &device_name,
            ],
        )
        .await
        .map_err(|_| None)?;
    let saved = rows
        .first()
        .ok_or(None)
        .and_then(|r| scan_subscription(r).map_err(|_| None))?;
    tx.commit().await.map_err(|_| None)?;
    Ok(saved)
}

async fn delete_subscription(s: &Stack, user: i64, profile: &str, id: &str) -> bool {
    s.pool
        .execute(
            "DELETE FROM web_push_subscriptions WHERE user_id = $1 AND profile_id = $2 AND id = $3",
            &[&AnyInt(user), &profile, &id],
        )
        .await
        .is_ok()
}

async fn delete_by_endpoint(s: &Stack, user: i64, endpoint: &str) -> bool {
    s.pool
        .execute(
            "DELETE FROM web_push_subscriptions WHERE user_id = $1 AND endpoint = $2",
            &[&AnyInt(user), &endpoint],
        )
        .await
        .is_ok()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Keys {
    p256dh: String,
    auth: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SubscribeBody {
    endpoint: String,
    keys: Keys,
    device_name: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UnsubscribeBody {
    endpoint: String,
}

// ---- Webhooks -------------------------------------------------------------------------------------

const WEBHOOK_COLUMNS: &str = "
	id, user_id, profile_id, name, type, url_ciphertext, url_host,
	signing_secret_ciphertext, enabled,
	notify_favorites, notify_watchlist, notify_continue_watching, notify_next_up,
	notify_requests,
	consecutive_failures, disabled_reason,
	last_success_at, last_failure_at, last_failure_status, last_failure_message,
	created_at, updated_at, revision";

/// `Webhook`.
#[derive(Clone)]
struct Webhook {
    id: String,
    profile_id: String,
    name: String,
    kind: String,
    url_ciphertext: String,
    url_host: String,
    signing_secret_ciphertext: Option<String>,
    enabled: bool,
    notify_favorites: bool,
    notify_watchlist: bool,
    notify_continue_watching: bool,
    notify_next_up: bool,
    notify_requests: bool,
    consecutive_failures: i32,
    disabled_reason: Option<String>,
    last_success_at: Option<SystemTime>,
    last_failure_at: Option<SystemTime>,
    last_failure_status: Option<i32>,
    last_failure_message: Option<String>,
    created_at: SystemTime,
    revision: i64,
}

fn scan_webhook(row: &Row) -> Result<Webhook, String> {
    let e = |e: silo_pg::DriverError| e.to_string();
    Ok(Webhook {
        id: row.try_get(0).map_err(e)?,
        profile_id: row.try_get(2).map_err(e)?,
        name: row.try_get(3).map_err(e)?,
        kind: row.try_get(4).map_err(e)?,
        url_ciphertext: row.try_get(5).map_err(e)?,
        url_host: row.try_get(6).map_err(e)?,
        signing_secret_ciphertext: row.try_get(7).map_err(e)?,
        enabled: row.try_get(8).map_err(e)?,
        notify_favorites: row.try_get(9).map_err(e)?,
        notify_watchlist: row.try_get(10).map_err(e)?,
        notify_continue_watching: row.try_get(11).map_err(e)?,
        notify_next_up: row.try_get(12).map_err(e)?,
        notify_requests: row.try_get(13).map_err(e)?,
        consecutive_failures: row.try_get(14).map_err(e)?,
        disabled_reason: row.try_get(15).map_err(e)?,
        last_success_at: row.try_get(16).map_err(e)?,
        last_failure_at: row.try_get(17).map_err(e)?,
        last_failure_status: row.try_get(18).map_err(e)?,
        last_failure_message: row.try_get(19).map_err(e)?,
        created_at: row.try_get(20).map_err(e)?,
        revision: row.try_get(22).map_err(e)?,
    })
}

#[derive(Serialize)]
struct V1Webhook {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    url_host: String,
    enabled: bool,
    notify_favorites: bool,
    notify_watchlist: bool,
    notify_continue_watching: bool,
    notify_next_up: bool,
    notify_requests: bool,
    consecutive_failures: i32,
    disabled_reason: Option<String>,
    last_success_at: Option<String>,
    last_failure_at: Option<String>,
    last_failure_status: Option<i32>,
    last_failure_message: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    signing_secret: String,
}

fn v1_webhook(h: Webhook, signing_secret: String) -> V1Webhook {
    V1Webhook {
        id: h.id,
        name: h.name,
        kind: h.kind,
        url_host: h.url_host,
        enabled: h.enabled,
        notify_favorites: h.notify_favorites,
        notify_watchlist: h.notify_watchlist,
        notify_continue_watching: h.notify_continue_watching,
        notify_next_up: h.notify_next_up,
        notify_requests: h.notify_requests,
        consecutive_failures: h.consecutive_failures,
        disabled_reason: h.disabled_reason,
        last_success_at: v1_time(h.last_success_at),
        last_failure_at: v1_time(h.last_failure_at),
        last_failure_status: h.last_failure_status,
        last_failure_message: h.last_failure_message,
        signing_secret,
    }
}

/// `notificationWebhookTag`.
fn webhook_tag(profile: &str, id: &str, revision: i64) -> EntityTag {
    render_etag(
        format!("notification-webhook:{profile}").as_bytes(),
        id.as_bytes(),
        revision,
    )
}

#[derive(Serialize)]
struct V2Webhook {
    etag: String,
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    url_host: String,
    enabled: bool,
    notify_favorites: bool,
    notify_watchlist: bool,
    notify_continue_watching: bool,
    notify_next_up: bool,
    notify_requests: bool,
    consecutive_failures: i32,
    disabled_reason: Option<String>,
    last_success_at: NullableInstant,
    last_failure_at: NullableInstant,
    last_failure_status: Option<i32>,
    last_failure_message: Option<String>,
}

fn v2_webhook(h: Webhook) -> V2Webhook {
    V2Webhook {
        etag: webhook_tag(&h.profile_id, &h.id, h.revision).to_wire(),
        id: h.id,
        name: h.name,
        kind: h.kind,
        url_host: h.url_host,
        enabled: h.enabled,
        notify_favorites: h.notify_favorites,
        notify_watchlist: h.notify_watchlist,
        notify_continue_watching: h.notify_continue_watching,
        notify_next_up: h.notify_next_up,
        notify_requests: h.notify_requests,
        consecutive_failures: h.consecutive_failures,
        disabled_reason: h.disabled_reason,
        last_success_at: null_instant(h.last_success_at),
        last_failure_at: null_instant(h.last_failure_at),
        last_failure_status: h.last_failure_status,
        last_failure_message: h.last_failure_message,
    }
}

fn url_aad(id: &str) -> String {
    silo_core::secret::aad::notification_webhook(id, "url")
}

fn secret_aad(id: &str) -> String {
    silo_core::secret::aad::notification_webhook(id, "signing_secret")
}

/// `WebhookInput`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct WebhookInput {
    name: Option<String>,
    url: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    enabled: Option<bool>,
    notify_favorites: Option<bool>,
    notify_watchlist: Option<bool>,
    notify_continue_watching: Option<bool>,
    notify_next_up: Option<bool>,
    notify_requests: Option<bool>,
}

/// A webhook service failure, as the sentinels `writeWebhookError` and the v2 handlers tell apart.
enum HookError {
    Disabled,
    NotFound,
    Limit,
    Invalid(String),
    Problem(Problem),
    Failed,
}

const INVALID: &str = "invalid webhook";
const NAME_TAKEN: &str = "a webhook with this name already exists";

fn is_name_violation(e: &silo_pg::Error) -> bool {
    e.as_db_error().is_some_and(|d| {
        d.code().code() == "23505"
            && d.constraint() == Some("notification_webhooks_profile_name_key")
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

/// `WebhookService.Create`.
async fn create_webhook(
    s: &Stack,
    user: i64,
    profile: &str,
    input: WebhookInput,
) -> Result<(Webhook, String), HookError> {
    if !bool_setting(s, "notifications.webhooks_enabled", false).await {
        return Err(HookError::Disabled);
    }
    let (Some(name), Some(url)) = (input.name.as_deref(), input.url.as_deref()) else {
        return Err(HookError::Invalid(format!(
            "{INVALID}: name and url are required"
        )));
    };
    let name = validate_name(name, INVALID).map_err(HookError::Invalid)?;
    let raw_url = trim_space(url);
    let host = validate_webhook_url(raw_url, allow_private(s).await)
        .await
        .map_err(|e| HookError::Invalid(format!("{INVALID}: {e}")))?;
    let explicit = input.kind.as_deref().map(trim_space).unwrap_or_default();
    let kind = resolve_type(raw_url, explicit, INVALID).map_err(HookError::Invalid)?;
    let id = ulid();
    let url_ciphertext = s
        .cipher
        .encrypt(raw_url.as_bytes(), url_aad(&id))
        .map_err(|_| HookError::Failed)?;
    let mut signing_secret = String::new();
    let mut secret_ciphertext: Option<String> = None;
    if kind == "generic" {
        signing_secret = new_signing_secret();
        secret_ciphertext = Some(
            s.cipher
                .encrypt(signing_secret.as_bytes(), secret_aad(&id))
                .map_err(|_| HookError::Failed)?,
        );
    }
    let flag = |v: Option<bool>| v.unwrap_or(true);
    let hook = Webhook {
        id: id.clone(),
        profile_id: profile.to_owned(),
        name,
        kind,
        url_ciphertext,
        url_host: host,
        signing_secret_ciphertext: secret_ciphertext,
        enabled: true,
        notify_favorites: flag(input.notify_favorites),
        notify_watchlist: flag(input.notify_watchlist),
        notify_continue_watching: flag(input.notify_continue_watching),
        notify_next_up: flag(input.notify_next_up),
        notify_requests: flag(input.notify_requests),
        consecutive_failures: 0,
        disabled_reason: None,
        last_success_at: None,
        last_failure_at: None,
        last_failure_status: None,
        last_failure_message: None,
        created_at: SystemTime::UNIX_EPOCH,
        revision: 0,
    };
    let max = int_setting(s, "notifications.webhooks.max_per_profile", 10, 1, 100).await;
    // `InsertWithLimit`.
    let mut conn = s.pool.acquire().await.map_err(|_| HookError::Failed)?;
    let mut tx = conn.begin().await.map_err(|_| HookError::Failed)?;
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended('notification_webhooks:' || $1, 0))",
        &[&profile],
    )
    .await
    .map_err(|_| HookError::Failed)?;
    let count: i64 = tx
        .query(
            "SELECT count(*) FROM notification_webhooks WHERE user_id = $1 AND profile_id = $2",
            &[&AnyInt(user), &profile],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get(0).ok()))
        .ok_or(HookError::Failed)?;
    if count >= max {
        return Err(HookError::Limit);
    }
    let inserted = tx
        .execute(
            "
		INSERT INTO notification_webhooks
			(id, user_id, profile_id, name, type, url_ciphertext, url_host,
			 signing_secret_ciphertext, enabled,
			 notify_favorites, notify_watchlist, notify_continue_watching, notify_next_up,
			 notify_requests)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            &[
                &hook.id,
                &AnyInt(user),
                &hook.profile_id,
                &hook.name,
                &hook.kind,
                &hook.url_ciphertext,
                &hook.url_host,
                &hook.signing_secret_ciphertext,
                &hook.enabled,
                &hook.notify_favorites,
                &hook.notify_watchlist,
                &hook.notify_continue_watching,
                &hook.notify_next_up,
                &hook.notify_requests,
            ],
        )
        .await;
    match inserted {
        Ok(_) => {}
        Err(e) if is_name_violation(&e) => {
            return Err(HookError::Invalid(format!("{INVALID}: {NAME_TAKEN}")));
        }
        Err(_) => return Err(HookError::Failed),
    }
    tx.commit().await.map_err(|_| HookError::Failed)?;
    Ok((hook, signing_secret))
}

async fn get_webhook(s: &Stack, user: i64, profile: &str, id: &str) -> Result<Option<Webhook>, ()> {
    let sql = format!(
        "SELECT {WEBHOOK_COLUMNS} FROM notification_webhooks WHERE user_id = $1 AND profile_id = $2 AND id = $3"
    );
    let rows = s
        .pool
        .query(&sql, &[&AnyInt(user), &profile, &id])
        .await
        .map_err(|_| ())?;
    rows.first().map(scan_webhook).transpose().map_err(|_| ())
}

/// `applyWebhookInput`.
async fn apply_input(s: &Stack, hook: &mut Webhook, input: &WebhookInput) -> Result<(), HookError> {
    if let Some(name) = &input.name {
        hook.name = validate_name(name, INVALID).map_err(HookError::Invalid)?;
    }
    if let Some(url) = &input.url {
        let raw_url = trim_space(url);
        let host = validate_webhook_url(raw_url, allow_private(s).await)
            .await
            .map_err(|e| HookError::Invalid(format!("{INVALID}: {e}")))?;
        validate_replacement(&hook.kind, raw_url, INVALID).map_err(HookError::Invalid)?;
        hook.url_ciphertext = s
            .cipher
            .encrypt(raw_url.as_bytes(), url_aad(&hook.id))
            .map_err(|_| HookError::Failed)?;
        hook.url_host = host;
        hook.consecutive_failures = 0;
        hook.disabled_reason = None;
    }
    if let Some(enabled) = input.enabled {
        hook.enabled = enabled;
        if enabled {
            hook.disabled_reason = None;
            hook.consecutive_failures = 0;
        }
    }
    if let Some(v) = input.notify_favorites {
        hook.notify_favorites = v;
    }
    if let Some(v) = input.notify_watchlist {
        hook.notify_watchlist = v;
    }
    if let Some(v) = input.notify_continue_watching {
        hook.notify_continue_watching = v;
    }
    if let Some(v) = input.notify_next_up {
        hook.notify_next_up = v;
    }
    if let Some(v) = input.notify_requests {
        hook.notify_requests = v;
    }
    Ok(())
}

/// `WebhookRepository.Update`, with the signing secret column given.
async fn store_webhook(s: &Stack, hook: &Webhook) -> Result<(), HookError> {
    let updated = s
        .pool
        .execute(
            "
		UPDATE notification_webhooks SET
			name = $2, type = $3, url_ciphertext = $4, url_host = $5,
			signing_secret_ciphertext = $6, enabled = $7,
			notify_favorites = $8, notify_watchlist = $9,
			notify_continue_watching = $10, notify_next_up = $11,
			notify_requests = $12,
			consecutive_failures = $13, disabled_reason = $14,
			updated_at = now()
		WHERE id = $1",
            &[
                &hook.id,
                &hook.name,
                &hook.kind,
                &hook.url_ciphertext,
                &hook.url_host,
                &hook.signing_secret_ciphertext,
                &hook.enabled,
                &hook.notify_favorites,
                &hook.notify_watchlist,
                &hook.notify_continue_watching,
                &hook.notify_next_up,
                &hook.notify_requests,
                &hook.consecutive_failures,
                &hook.disabled_reason,
            ],
        )
        .await;
    match updated {
        Ok(_) => Ok(()),
        Err(e) if is_name_violation(&e) => {
            Err(HookError::Invalid(format!("{INVALID}: {NAME_TAKEN}")))
        }
        Err(_) => Err(HookError::Failed),
    }
}

/// `WebhookService.Update` (v1).
async fn update_webhook_v1(
    s: &Stack,
    user: i64,
    profile: &str,
    id: &str,
    input: WebhookInput,
) -> Result<Webhook, HookError> {
    let mut hook = match get_webhook(s, user, profile, id).await {
        Ok(Some(h)) => h,
        Ok(None) => return Err(HookError::NotFound),
        Err(()) => return Err(HookError::Failed),
    };
    apply_input(s, &mut hook, &input).await?;
    store_webhook(s, &hook).await?;
    Ok(hook)
}

/// `WebhookService.RotateSecret` (v1): the whole row is written back with the new secret.
async fn rotate_v1(s: &Stack, user: i64, profile: &str, id: &str) -> Result<String, HookError> {
    let mut hook = match get_webhook(s, user, profile, id).await {
        Ok(Some(h)) => h,
        Ok(None) => return Err(HookError::NotFound),
        Err(()) => return Err(HookError::Failed),
    };
    if hook.kind != "generic" {
        return Err(HookError::Invalid(format!(
            "{INVALID}: only generic webhooks have signing secrets"
        )));
    }
    let value = new_signing_secret();
    let ciphertext = s
        .cipher
        .encrypt(value.as_bytes(), secret_aad(&hook.id))
        .map_err(|_| HookError::Failed)?;
    hook.signing_secret_ciphertext = Some(ciphertext);
    store_webhook(s, &hook).await?;
    Ok(value)
}

/// `WebhookService.RotateSecretV2`.
async fn rotate_v2(s: &Stack, user: i64, profile: &str, id: &str) -> Result<String, HookError> {
    let hook = match get_webhook(s, user, profile, id).await {
        Ok(Some(h)) => h,
        Ok(None) => return Err(HookError::NotFound),
        Err(()) => return Err(HookError::Failed),
    };
    if hook.kind != "generic" {
        return Err(HookError::Invalid(format!(
            "{INVALID}: only generic webhooks have signing secrets"
        )));
    }
    let value = new_signing_secret();
    let ciphertext = s
        .cipher
        .encrypt(value.as_bytes(), secret_aad(id))
        .map_err(|_| HookError::Failed)?;
    let changed = s
        .pool
        .execute(
            "UPDATE notification_webhooks SET signing_secret_ciphertext=$4, updated_at=now() WHERE user_id=$1 AND profile_id=$2 AND id=$3 AND type='generic'",
            &[&AnyInt(user), &profile, &id, &ciphertext],
        )
        .await
        .map_err(|_| HookError::Failed)?;
    if changed == 0 {
        return Err(HookError::NotFound);
    }
    Ok(value)
}

/// `WebhookService.UpdateGuarded`.
async fn update_guarded(
    s: &Stack,
    user: i64,
    profile: &str,
    id: &str,
    input: WebhookInput,
    if_match: &str,
    if_none: &str,
) -> Result<Webhook, HookError> {
    let mut conn = s.pool.acquire().await.map_err(|_| HookError::Failed)?;
    let mut tx = conn.begin().await.map_err(|_| HookError::Failed)?;
    let sql = format!(
        "SELECT {WEBHOOK_COLUMNS} FROM notification_webhooks WHERE user_id=$1 AND profile_id=$2 AND id=$3 FOR UPDATE"
    );
    let rows = tx
        .query(&sql, &[&AnyInt(user), &profile, &id])
        .await
        .map_err(|_| HookError::Failed)?;
    let Some(row) = rows.first() else {
        return Err(HookError::NotFound);
    };
    let mut hook = scan_webhook(row).map_err(|_| HookError::Failed)?;
    if let Some(p) =
        evaluate_guarded_preconditions(if_match, if_none, &webhook_tag(profile, id, hook.revision))
    {
        return Err(HookError::Problem(p));
    }
    apply_input(s, &mut hook, &input).await?;
    let sql = format!(
        "UPDATE notification_webhooks SET
 name=$4, url_ciphertext=$5, url_host=$6, enabled=$7,
 notify_favorites=$8, notify_watchlist=$9, notify_continue_watching=$10,
 notify_next_up=$11, notify_requests=$12, consecutive_failures=$13,
 disabled_reason=$14, updated_at=now()
 WHERE user_id=$1 AND profile_id=$2 AND id=$3 RETURNING {WEBHOOK_COLUMNS}"
    );
    let updated = tx
        .query(
            &sql,
            &[
                &AnyInt(user),
                &profile,
                &id,
                &hook.name,
                &hook.url_ciphertext,
                &hook.url_host,
                &hook.enabled,
                &hook.notify_favorites,
                &hook.notify_watchlist,
                &hook.notify_continue_watching,
                &hook.notify_next_up,
                &hook.notify_requests,
                &hook.consecutive_failures,
                &hook.disabled_reason,
            ],
        )
        .await;
    let row = match updated {
        Ok(rows) => match rows.first() {
            Some(row) => scan_webhook(row).map_err(|_| HookError::Failed)?,
            None => return Err(HookError::Failed),
        },
        Err(e) if is_name_violation(&e) => {
            return Err(HookError::Invalid(format!("{INVALID}: {NAME_TAKEN}")));
        }
        Err(_) => return Err(HookError::Failed),
    };
    tx.commit().await.map_err(|_| HookError::Failed)?;
    Ok(row)
}

/// `WebhookRepository.DeleteGuarded`.
async fn delete_guarded(
    s: &Stack,
    user: i64,
    profile: &str,
    id: &str,
    if_match: &str,
    if_none: &str,
) -> Result<(), HookError> {
    let mut conn = s.pool.acquire().await.map_err(|_| HookError::Failed)?;
    let mut tx = conn.begin().await.map_err(|_| HookError::Failed)?;
    let rows = tx
        .query(
            "SELECT revision FROM notification_webhooks WHERE user_id=$1 AND profile_id=$2 AND id=$3 FOR UPDATE",
            &[&AnyInt(user), &profile, &id],
        )
        .await
        .map_err(|_| HookError::Failed)?;
    let Some(revision) = rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()) else {
        return Err(HookError::NotFound);
    };
    if let Some(p) =
        evaluate_guarded_preconditions(if_match, if_none, &webhook_tag(profile, id, revision))
    {
        return Err(HookError::Problem(p));
    }
    tx.execute(
        "DELETE FROM notification_webhooks WHERE user_id=$1 AND profile_id=$2 AND id=$3",
        &[&AnyInt(user), &profile, &id],
    )
    .await
    .map_err(|_| HookError::Failed)?;
    tx.commit().await.map_err(|_| HookError::Failed)
}

/// `writeWebhookError`.
async fn write_hook_error(w: &mut dyn ResponseWriter, e: HookError) {
    match e {
        HookError::Disabled => {
            write_v1_error(
                w,
                403,
                "webhooks_disabled",
                "Webhooks are disabled by the server administrator",
            )
            .await
        }
        HookError::NotFound => write_v1_error(w, 404, "not_found", "Webhook not found").await,
        HookError::Limit => {
            write_v1_error(
                w,
                422,
                "limit_reached",
                "Webhook limit reached for this profile",
            )
            .await
        }
        HookError::Invalid(message) => write_v1_error(w, 400, "bad_request", &message).await,
        HookError::Problem(_) | HookError::Failed => {
            write_v1_error(w, 500, "internal_error", "Webhook operation failed").await
        }
    }
}

fn decode_v1<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    Decoder::new().stream(bytes).decode::<T>().ok()
}

/// The v1 rows, on the `/api/v1/notifications` subrouter.
pub(super) fn mount_v1(stack: &Arc<Stack>, mux: &Mux) {
    mux.route("/webhooks", |r| {
        r.get(
            "/",
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let sql = format!(
                    "SELECT {WEBHOOK_COLUMNS} FROM notification_webhooks WHERE user_id = $1 AND profile_id = $2 ORDER BY created_at"
                );
                let hooks = s
                    .pool
                    .query(&sql, &[&AnyInt(user), &profile])
                    .await
                    .map_err(|_| ())
                    .and_then(|rows| rows.iter().map(scan_webhook).collect::<Result<Vec<_>, _>>().map_err(|_| ()));
                let Ok(hooks) = hooks else {
                    return write_v1_error(w, 500, "internal_error", "Failed to list webhooks").await;
                };
                #[derive(Serialize)]
                struct List {
                    webhooks: Vec<V1Webhook>,
                }
                let webhooks = hooks.into_iter().map(|h| v1_webhook(h, String::new())).collect();
                write_v1_json(w, 200, &List { webhooks }).await;
            }),
        );
        r.post(
            "/",
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let (bytes, _) = r.read_all().await;
                let Some(input) = decode_v1::<WebhookInput>(&bytes) else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                match create_webhook(&s, user, &profile, input).await {
                    Ok((hook, secret)) => write_v1_json(w, 201, &v1_webhook(hook, secret)).await,
                    Err(e) => write_hook_error(w, e).await,
                }
            }),
        );
        r.put(
            "/{id}",
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let id = r.url_param("id").to_owned();
                let (bytes, _) = r.read_all().await;
                let Some(input) = decode_v1::<WebhookInput>(&bytes) else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                match update_webhook_v1(&s, user, &profile, &id, input).await {
                    Ok(hook) => write_v1_json(w, 200, &v1_webhook(hook, String::new())).await,
                    Err(e) => write_hook_error(w, e).await,
                }
            }),
        );
        r.delete(
            "/{id}",
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let id = r.url_param("id").to_owned();
                let deleted = s
                    .pool
                    .execute(
                        "DELETE FROM notification_webhooks WHERE user_id = $1 AND profile_id = $2 AND id = $3",
                        &[&AnyInt(user), &profile, &id],
                    )
                    .await;
                match deleted {
                    Ok(_) => write_empty(w).await,
                    Err(_) => write_hook_error(w, HookError::Failed).await,
                }
            }),
        );
        r.post(
            "/{id}/rotate-secret",
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let id = r.url_param("id").to_owned();
                match rotate_v1(&s, user, &profile, &id).await {
                    Ok(secret) => {
                        #[derive(Serialize)]
                        struct Out {
                            signing_secret: String,
                        }
                        write_v1_json(w, 200, &Out { signing_secret: secret }).await
                    }
                    Err(e) => write_hook_error(w, e).await,
                }
            }),
        );
    });
    mux.route("/web-push", |r| {
        r.get(
            "/subscriptions",
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let sql = format!(
                    "SELECT {WEB_PUSH_COLUMNS} FROM web_push_subscriptions WHERE user_id = $1 AND profile_id = $2 ORDER BY created_at"
                );
                let subs = s
                    .pool
                    .query(&sql, &[&AnyInt(user), &profile])
                    .await
                    .map_err(|_| ())
                    .and_then(|rows| {
                        rows.iter()
                            .map(scan_subscription)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|_| ())
                    });
                let Ok(subs) = subs else {
                    return write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to list push subscriptions",
                    )
                    .await;
                };
                #[derive(Serialize)]
                struct List {
                    subscriptions: Vec<V1Subscription>,
                }
                let subscriptions = subs.into_iter().map(v1_subscription).collect();
                write_v1_json(w, 200, &List { subscriptions }).await;
            }),
        );
        r.post(
            "/subscriptions",
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let (bytes, _) = r.read_all().await;
                let Some(req) = decode_v1::<SubscribeBody>(&bytes) else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                match subscribe(
                    &s,
                    user,
                    &profile,
                    &req.endpoint,
                    &req.keys.p256dh,
                    &req.keys.auth,
                    &req.device_name,
                )
                .await
                {
                    Ok(sub) => write_v1_json(w, 201, &v1_subscription(sub)).await,
                    Err(Some(message)) => write_v1_error(w, 400, "bad_request", &message).await,
                    Err(None) => {
                        write_v1_error(
                            w,
                            500,
                            "internal_error",
                            "Failed to register push subscription",
                        )
                        .await
                    }
                }
            }),
        );
        r.delete(
            "/subscriptions/{id}",
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let id = r.url_param("id").to_owned();
                if id.is_empty() {
                    // `Unsubscribe` with neither an id nor an endpoint.
                    return write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to remove push subscription",
                    )
                    .await;
                }
                if delete_subscription(&s, user, &profile, &id).await {
                    write_empty(w).await;
                } else {
                    write_v1_error(w, 500, "internal_error", "Failed to remove push subscription")
                        .await;
                }
            }),
        );
        r.post(
            "/unsubscribe",
            route!(stack, |s, w, r| {
                let user = user_of(r);
                let (bytes, _) = r.read_all().await;
                let req = decode_v1::<UnsubscribeBody>(&bytes);
                let Some(req) = req.filter(|b| !b.endpoint.is_empty()) else {
                    return write_v1_error(w, 400, "bad_request", "An endpoint is required").await;
                };
                if delete_by_endpoint(&s, user, &req.endpoint).await {
                    write_empty(w).await;
                } else {
                    write_v1_error(w, 500, "internal_error", "Failed to remove push subscription")
                        .await;
                }
            }),
        );
    });
}

/// `notificationDestinationCreateProblem`, and the v2 webhook handlers' own translations.
fn create_problem(e: HookError) -> Problem {
    match e {
        HookError::Disabled => Problem::new(
            problem_type("permission_denied"),
            "Notification channel is disabled.",
        ),
        HookError::Limit => validation("Notification destination limit reached."),
        HookError::Invalid(_) => validation("Invalid notification destination configuration."),
        HookError::Problem(p) => p,
        HookError::NotFound => not_found("Webhook not found."),
        HookError::Failed => internal(),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UpdateBody {
    name: Option<String>,
    url: Option<String>,
    enabled: Option<bool>,
    notify_favorites: Option<bool>,
    notify_watchlist: Option<bool>,
    notify_continue_watching: Option<bool>,
    notify_next_up: Option<bool>,
    notify_requests: Option<bool>,
}

/// Pages a (created_at, id) keyset the way `ListPage` does.
fn page_sql(columns: &str, table: &str, after: bool) -> String {
    let mut sql = format!("SELECT {columns} FROM {table} WHERE user_id = $1 AND profile_id = $2");
    if after {
        sql.push_str(" AND (created_at, id) > ($3, $4)");
        sql.push_str(" ORDER BY created_at, id LIMIT $5");
    } else {
        sql.push_str(" ORDER BY created_at, id LIMIT $3");
    }
    sql
}

/// The v2 rows.
pub(super) fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    use super::super::chain::V2Class;

    let path = "/api/v2/notifications/webhooks";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let limit = limit_of(r);
                let page = scope(r, "listNotificationWebhooks", limit.to_string());
                let raw = query_param(r, "cursor");
                let after: Option<Cursor> = if raw.is_empty() {
                    None
                } else {
                    match s.cursors.decode(&page, &raw) {
                        Ok(c) => Some(c),
                        Err(problem) => return write_problem(w, r, problem).await,
                    }
                };
                let sql = page_sql(WEBHOOK_COLUMNS, "notification_webhooks", after.is_some());
                let lookahead = limit + 1;
                let rows = match &after {
                    Some(c) => {
                        let Some(at) = c.at() else {
                            return write_problem(w, r, internal()).await;
                        };
                        s.pool
                            .query(&sql, &[&AnyInt(user), &profile, &at, &c.id, &lookahead])
                            .await
                    }
                    None => {
                        s.pool
                            .query(&sql, &[&AnyInt(user), &profile, &lookahead])
                            .await
                    }
                };
                let Ok(mut hooks) = rows.map_err(|_| ()).and_then(|rows| {
                    rows.iter()
                        .map(scan_webhook)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ())
                }) else {
                    return write_problem(w, r, internal()).await;
                };
                let more = hooks.len() as i64 > limit;
                if more {
                    hooks.truncate(limit as usize);
                }
                let mut next = String::new();
                if more && let Some(last) = hooks.last() {
                    let cursor = Cursor {
                        created_at: go_time(last.created_at),
                        id: last.id.clone(),
                    };
                    next = match s.cursors.encode(&page, &cursor) {
                        Ok(n) => n,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                }
                let items: Vec<V2Webhook> = hooks.into_iter().map(v2_webhook).collect();
                write_v2_json_status(w, 200, &paginated(items, next)).await;
            }),
        ),
    );
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let input: WebhookInput =
                    silo_gocompat::json::unmarshal(&body_of(r)).unwrap_or_default();
                // Huma's body leaves `enabled` unset on create.
                let input = WebhookInput {
                    enabled: None,
                    name: Some(input.name.unwrap_or_default()),
                    url: Some(input.url.unwrap_or_default()),
                    ..input
                };
                match create_webhook(&s, user, &profile, input).await {
                    Ok((hook, secret)) => {
                        write_v2_json_status(
                            w,
                            201,
                            &Created {
                                id: hook.id,
                                name: hook.name,
                                kind: hook.kind,
                                url_host: hook.url_host,
                                signing_secret: secret,
                            },
                        )
                        .await
                    }
                    Err(e) => write_problem(w, r, create_problem(e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/webhooks/{id}";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let id = r.url_param("id").to_owned();
                let b: UpdateBody = silo_gocompat::json::unmarshal(&body_of(r)).unwrap_or_default();
                let input = WebhookInput {
                    name: b.name,
                    url: b.url,
                    kind: None,
                    enabled: b.enabled,
                    notify_favorites: b.notify_favorites,
                    notify_watchlist: b.notify_watchlist,
                    notify_continue_watching: b.notify_continue_watching,
                    notify_next_up: b.notify_next_up,
                    notify_requests: b.notify_requests,
                };
                let (if_match, if_none) =
                    (header_text(r, "If-Match"), header_text(r, "If-None-Match"));
                match update_guarded(&s, user, &profile, &id, input, &if_match, &if_none).await {
                    Ok(row) => {
                        w.header().set(
                            "ETag",
                            webhook_tag(&row.profile_id, &row.id, row.revision).to_wire(),
                        );
                        write_v2_json_status(w, 200, &v2_webhook(row)).await
                    }
                    Err(HookError::Invalid(_)) => {
                        write_problem(w, r, validation("Invalid webhook configuration.")).await
                    }
                    Err(e) => write_problem(w, r, create_problem(e)).await,
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
                let (user, profile) = (user_of(r), get_profile_id(r));
                let id = r.url_param("id").to_owned();
                let (if_match, if_none) =
                    (header_text(r, "If-Match"), header_text(r, "If-None-Match"));
                match delete_guarded(&s, user, &profile, &id, &if_match, &if_none).await {
                    Ok(()) => write_empty(w).await,
                    Err(e) => write_problem(w, r, create_problem(e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/webhooks/{id}/rotate-secret";
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let id = r.url_param("id").to_owned();
                match rotate_v2(&s, user, &profile, &id).await {
                    Ok(secret) => write_secret(w, secret).await,
                    Err(HookError::Invalid(_)) => {
                        write_problem(
                            w,
                            r,
                            validation("Only generic webhooks have signing secrets."),
                        )
                        .await
                    }
                    Err(e) => write_problem(w, r, create_problem(e)).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/web-push/subscriptions";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let limit = limit_of(r);
                let page = scope(r, "listNotificationWebPushSubscriptions", limit.to_string());
                let raw = query_param(r, "cursor");
                let after: Option<Cursor> = if raw.is_empty() {
                    None
                } else {
                    match s.cursors.decode(&page, &raw) {
                        Ok(c) => Some(c),
                        Err(problem) => return write_problem(w, r, problem).await,
                    }
                };
                let sql = page_sql(WEB_PUSH_COLUMNS, "web_push_subscriptions", after.is_some());
                let lookahead = limit + 1;
                let rows = match &after {
                    Some(c) => {
                        let Some(at) = c.at() else {
                            return write_problem(w, r, internal()).await;
                        };
                        s.pool
                            .query(&sql, &[&AnyInt(user), &profile, &at, &c.id, &lookahead])
                            .await
                    }
                    None => {
                        s.pool
                            .query(&sql, &[&AnyInt(user), &profile, &lookahead])
                            .await
                    }
                };
                let Ok(mut subs) = rows.map_err(|_| ()).and_then(|rows| {
                    rows.iter()
                        .map(scan_subscription)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ())
                }) else {
                    return write_problem(w, r, internal()).await;
                };
                let more = subs.len() as i64 > limit;
                if more {
                    subs.truncate(limit as usize);
                }
                let mut next = String::new();
                if more && let Some(last) = subs.last() {
                    let cursor = Cursor {
                        created_at: go_time(last.created_at),
                        id: last.id.clone(),
                    };
                    next = match s.cursors.encode(&page, &cursor) {
                        Ok(n) => n,
                        Err(problem) => return write_problem(w, r, problem).await,
                    };
                }
                let items: Vec<V2Subscription> = subs.into_iter().map(v2_subscription).collect();
                write_v2_json_status(w, 200, &paginated(items, next)).await;
            }),
        ),
    );
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let b: SubscribeBody =
                    silo_gocompat::json::unmarshal(&body_of(r)).unwrap_or_default();
                match subscribe(
                    &s,
                    user,
                    &profile,
                    &b.endpoint,
                    &b.keys.p256dh,
                    &b.keys.auth,
                    &b.device_name,
                )
                .await
                {
                    Ok(sub) => write_v2_json_status(w, 201, &v2_subscription(sub)).await,
                    Err(Some(_)) => {
                        write_problem(w, r, validation("Invalid browser push subscription.")).await
                    }
                    Err(None) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/web-push/unsubscribe";
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let user = user_of(r);
                let b: UnsubscribeBody =
                    silo_gocompat::json::unmarshal(&body_of(r)).unwrap_or_default();
                if b.endpoint.is_empty() {
                    // `Unsubscribe` with neither an id nor an endpoint is `ErrWebPushInvalid`, a 500 here.
                    return write_problem(w, r, internal()).await;
                }
                if delete_by_endpoint(&s, user, &b.endpoint).await {
                    write_empty(w).await;
                } else {
                    write_problem(w, r, internal()).await;
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/web-push/subscriptions/{id}";
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let id = r.url_param("id").to_owned();
                if id.is_empty() {
                    return write_problem(w, r, internal()).await;
                }
                if delete_subscription(&s, user, &profile, &id).await {
                    write_empty(w).await;
                } else {
                    write_problem(w, r, internal()).await;
                }
            }),
        ),
    );
}

#[derive(Serialize)]
pub(super) struct Created {
    pub(super) id: String,
    pub(super) name: String,
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) url_host: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(super) signing_secret: String,
}

/// `NotificationWebhookSecretOutput`.
pub(super) async fn write_secret(w: &mut dyn ResponseWriter, signing_secret: String) {
    #[derive(Serialize)]
    struct Out {
        signing_secret: String,
    }
    w.header().set("Cache-Control", "no-store");
    write_v2_json_status(w, 200, &Out { signing_secret }).await;
}
