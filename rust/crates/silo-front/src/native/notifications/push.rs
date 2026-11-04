//! The bridge push device rows: `handlers/notifications_push_devices.go` (`HandleRegisterPushDevice`,
//! `HandleUnregisterPushDevice`) over `PushDeviceService` and `PushDeviceRepository`.
//!
//! Apple's bridge registration stays on Go: its answer carries a display token minted by the JWT
//! service's Apple display issuer, which is not ported.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use silo_gate::mw::auth::get_profile_id;
use silo_gocompat::json::Decoder;
use silo_gocompat::strings::trim_space;
use silo_http::chi::Mux;
use silo_http::handler_fn;
use silo_pg::{AnyInt, Row, Session};

use super::super::auth::write_v1_error;
use super::super::chain::{Stack, write_v1_json};
use super::destinations::ulid;
use super::user_of;

macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

const INVALID: &str = "invalid push device registration";
const UNSUPPORTED: &str = "unsupported push device registration";

/// Platform-specific token columns are NULL for the other platform's rows.
const COLUMNS: &str = "
	id,
	user_id,
	profile_id,
	device_id,
	platform,
	provider,
	COALESCE(apns_environment, ''),
	COALESCE(apns_topic, ''),
	COALESCE(apns_token_ciphertext, ''),
	COALESCE(apns_token_hash, ''),
	COALESCE(fcm_token_ciphertext, ''),
	COALESCE(fcm_token_hash, ''),
	server_device_id,
	push_mode,
	enabled,
	last_seen_at,
	last_success_at,
	last_failure_at,
	last_failure_code,
	created_at,
	updated_at";

/// A push device failure, as `HandleRegisterPushDevice` and `HandleUnregisterPushDevice` tell them apart.
enum PushError {
    Conflict,
    LegacyWriter,
    Invalid(String),
    Unsupported(String),
    Failed,
}

/// `PushDevice`, with the columns the answer reads.
struct Device {
    id: String,
    server_device_id: String,
    push_mode: String,
    enabled: bool,
}

fn scan(row: &Row) -> Result<Device, PushError> {
    let get = || -> Result<Device, silo_pg::DriverError> {
        Ok(Device {
            id: row.try_get(0)?,
            server_device_id: row.try_get(12)?,
            push_mode: row.try_get(13)?,
            enabled: row.try_get(14)?,
        })
    };
    get().map_err(|_| PushError::Failed)
}

/// `fcmTokenPattern`: `^[A-Za-z0-9_:-]{64,512}$`.
fn plausible_fcm_token(token: &str) -> bool {
    (64..=512).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-'))
}

/// `normalizeFCMPushRegistration`.
fn normalize_fcm(
    device_id: &str,
    token: &str,
    push_mode: &str,
) -> Result<(String, String, String), PushError> {
    let device_id = trim_space(device_id);
    if device_id.is_empty() {
        return Err(PushError::Invalid(format!(
            "{INVALID}: device_id is required"
        )));
    }
    if device_id.len() > 128 {
        return Err(PushError::Invalid(format!(
            "{INVALID}: device_id is too long"
        )));
    }
    let token = trim_space(token);
    if token.is_empty() {
        return Err(PushError::Invalid(format!("{INVALID}: token is required")));
    }
    if !plausible_fcm_token(token) {
        return Err(PushError::Invalid(format!(
            "{INVALID}: token is not a plausible FCM registration token"
        )));
    }
    let mut mode = trim_space(push_mode);
    if mode.is_empty() {
        mode = "private_push";
    }
    if !matches!(mode, "off" | "in_app_only" | "private_push") {
        return Err(PushError::Unsupported(format!(
            "{UNSUPPORTED}: push_mode is not supported"
        )));
    }
    Ok((device_id.to_owned(), token.to_owned(), mode.to_owned()))
}

/// `fcmTokenHash`.
fn fcm_token_hash(token: &str) -> String {
    let sum = Sha256::digest(trim_space(token).as_bytes());
    sum.iter().map(|b| format!("{b:02x}")).collect()
}

/// `pushDeviceFCMTokenAAD`: `secret.RowAAD("push_devices", "fcm_token", id)`.
fn fcm_aad(id: &str) -> String {
    silo_core::secret::aad::push_device_token("fcm_token", id)
}

/// `lockAndroidPushInstallation` and `lockApplePushInstallation`.
async fn lock_installation(tx: &mut Session, table: &str, device: &str) -> Result<i64, PushError> {
    tx.execute(
        &format!("INSERT INTO {table}(device_id) VALUES($1) ON CONFLICT DO NOTHING"),
        &[&device],
    )
    .await
    .map_err(|_| PushError::Failed)?;
    let rows = tx
        .query(
            &format!("SELECT generation FROM {table} WHERE device_id=$1 FOR UPDATE"),
            &[&device],
        )
        .await
        .map_err(|_| PushError::Failed)?;
    rows.first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or(PushError::Failed)
}

async fn select_for_update(
    tx: &mut Session,
    profile: &str,
    device: &str,
    platform: &str,
) -> Result<Option<Device>, PushError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM push_devices WHERE profile_id = $1 AND device_id = $2 AND platform = $3 FOR UPDATE"
    );
    let rows = tx
        .query(&sql, &[&profile, &device, &platform])
        .await
        .map_err(|_| PushError::Failed)?;
    rows.first().map(scan).transpose()
}

/// `PushDeviceService.RegisterFCM` over `PushDeviceRepository.UpsertFCM`.
async fn register_fcm(
    s: &Stack,
    user: i64,
    profile: &str,
    device_id: &str,
    token: &str,
    push_mode: &str,
) -> Result<Device, PushError> {
    if user <= 0 {
        return Err(PushError::Invalid(format!(
            "{INVALID}: user_id is required"
        )));
    }
    let profile = trim_space(profile);
    if profile.is_empty() {
        return Err(PushError::Invalid(format!(
            "{INVALID}: profile_id is required"
        )));
    }
    let (device_id, token, mode) = normalize_fcm(device_id, token, push_mode)?;
    let mut conn = s.pool.acquire().await.map_err(|_| PushError::Failed)?;
    let mut tx = conn.begin().await.map_err(|_| PushError::Failed)?;
    if lock_installation(&mut tx, "android_push_installations", &device_id).await? > 0 {
        return Err(PushError::LegacyWriter);
    }
    let foreign: bool = tx
        .query(
            "SELECT EXISTS(SELECT 1 FROM push_devices WHERE device_id=$1 AND platform=$2 AND user_id<>$3)",
            &[&device_id, &"android", &AnyInt(user)],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get(0).ok()))
        .ok_or(PushError::Failed)?;
    if foreign {
        return Err(PushError::Conflict);
    }
    tx.execute(
        "DELETE FROM push_devices WHERE device_id = $1 AND platform = $2 AND user_id = $3 AND profile_id <> $4",
        &[&device_id, &"android", &AnyInt(user), &profile],
    )
    .await
    .map_err(|_| PushError::Failed)?;
    let hash = fcm_token_hash(&token);
    let mut existing = select_for_update(&mut tx, profile, &device_id, "android").await?;
    if existing.is_none() {
        // `insertFCM`.
        let id = ulid();
        let server_device_id = ulid();
        let ciphertext = s
            .cipher
            .encrypt(token.as_bytes(), fcm_aad(&id))
            .map_err(|_| PushError::Failed)?;
        let sql = format!(
            "
		INSERT INTO push_devices (
			id,
			user_id,
			profile_id,
			device_id,
			platform,
			provider,
			fcm_token_ciphertext,
			fcm_token_hash,
			server_device_id,
			push_mode,
			enabled,
			last_seen_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, now())
		ON CONFLICT (profile_id, device_id, platform) DO NOTHING
		RETURNING {COLUMNS}"
        );
        let rows = tx
            .query(
                &sql,
                &[
                    &id,
                    &AnyInt(user),
                    &profile,
                    &device_id,
                    &"android",
                    &"silo_relay",
                    &ciphertext,
                    &hash,
                    &server_device_id,
                    &mode,
                ],
            )
            .await
            .map_err(|_| PushError::Failed)?;
        if let Some(row) = rows.first() {
            let device = scan(row)?;
            tx.commit().await.map_err(|_| PushError::Failed)?;
            return Ok(device);
        }
        existing = select_for_update(&mut tx, profile, &device_id, "android").await?;
    }
    let Some(existing) = existing else {
        return Err(PushError::Failed);
    };
    // `updateFCM`.
    let ciphertext = s
        .cipher
        .encrypt(token.as_bytes(), fcm_aad(&existing.id))
        .map_err(|_| PushError::Failed)?;
    let sql = format!(
        "
		UPDATE push_devices
		SET user_id = $1,
			provider = $2,
			fcm_token_ciphertext = $3,
			fcm_token_hash = $4,
			push_mode = $5,
			enabled = true,
			last_seen_at = now(),
			last_failure_at = NULL,
			last_failure_code = NULL,
			updated_at = now()
		WHERE id = $6
		RETURNING {COLUMNS}"
    );
    let rows = tx
        .query(
            &sql,
            &[
                &AnyInt(user),
                &"silo_relay",
                &ciphertext,
                &hash,
                &mode,
                &existing.id,
            ],
        )
        .await
        .map_err(|_| PushError::Failed)?;
    let device = rows.first().ok_or(PushError::Failed).and_then(scan)?;
    tx.commit().await.map_err(|_| PushError::Failed)?;
    Ok(device)
}

/// `PushDeviceService.Unregister` over `DeleteByProfileDevice`.
async fn unregister(s: &Stack, user: i64, profile: &str, device_id: &str) -> Result<(), PushError> {
    let profile = trim_space(profile);
    let device_id = trim_space(device_id);
    if profile.is_empty() || device_id.is_empty() {
        return Err(PushError::Invalid(format!(
            "{INVALID}: profile_id and device_id are required"
        )));
    }
    let mut conn = s.pool.acquire().await.map_err(|_| PushError::Failed)?;
    let mut tx = conn.begin().await.map_err(|_| PushError::Failed)?;
    // Cross-platform bridge deletion always locks Android before Apple.
    if lock_installation(&mut tx, "android_push_installations", device_id).await? > 0 {
        return Err(PushError::LegacyWriter);
    }
    if lock_installation(&mut tx, "apple_push_installations", device_id).await? > 0 {
        return Err(PushError::LegacyWriter);
    }
    tx.execute(
        "DELETE FROM push_devices WHERE user_id=$1 AND profile_id=$2 AND device_id=$3",
        &[&AnyInt(user), &profile, &device_id],
    )
    .await
    .map_err(|_| PushError::Failed)?;
    tx.commit().await.map_err(|_| PushError::Failed)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RegisterBody {
    platform: String,
    token: String,
    device_id: String,
    push_mode: String,
}

/// `applePushRegisterResponse`, without the display token.
#[derive(Serialize)]
struct Registered {
    id: String,
    server_device_id: String,
    enabled: bool,
    push_mode: String,
}

/// The v1 rows, on the `/api/v1/notifications` subrouter.
pub(super) fn mount_v1(stack: &Arc<Stack>, mux: &Mux) {
    mux.post(
        "/push/devices",
        route!(stack, |s, w, r| {
            let (user, profile) = (user_of(r), get_profile_id(r));
            let (bytes, _) = r.read_all().await;
            let Ok(req) = Decoder::new().stream(&bytes[..]).decode::<RegisterBody>() else {
                return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
            };
            if req.platform != "android" {
                return write_v1_error(
                    w,
                    422,
                    "unsupported_push_device",
                    "platform is not supported on this endpoint",
                )
                .await;
            }
            match register_fcm(
                &s,
                user,
                &profile,
                &req.device_id,
                &req.token,
                &req.push_mode,
            )
            .await
            {
                Ok(device) => {
                    write_v1_json(
                        w,
                        200,
                        &Registered {
                            id: device.id,
                            server_device_id: device.server_device_id,
                            enabled: device.enabled,
                            push_mode: device.push_mode,
                        },
                    )
                    .await
                }
                Err(PushError::Conflict) => {
                    write_v1_error(
                        w,
                        409,
                        "conflict",
                        "Push registration conflicts with the current installation",
                    )
                    .await
                }
                Err(PushError::LegacyWriter) => {
                    write_v1_error(
                        w,
                        409,
                        "push_registration_upgrade_required",
                        "This installation requires ordered push registration",
                    )
                    .await
                }
                Err(PushError::Invalid(m)) => write_v1_error(w, 400, "bad_request", &m).await,
                Err(PushError::Unsupported(m)) => {
                    write_v1_error(w, 422, "unsupported_push_device", &m).await
                }
                Err(PushError::Failed) => {
                    write_v1_error(w, 500, "internal_error", "Failed to register push device").await
                }
            }
        }),
    );
    mux.delete(
        "/push/devices/{device_id}",
        route!(stack, |s, w, r| {
            let (user, profile) = (user_of(r), get_profile_id(r));
            let device = r.url_param("device_id").to_owned();
            match unregister(&s, user, &profile, &device).await {
                Ok(()) => w.write_header(204).await,
                Err(PushError::LegacyWriter) => {
                    write_v1_error(
                        w,
                        409,
                        "push_registration_upgrade_required",
                        "This installation requires ordered push registration",
                    )
                    .await
                }
                Err(PushError::Invalid(m)) => write_v1_error(w, 400, "bad_request", &m).await,
                Err(_) => {
                    write_v1_error(w, 500, "internal_error", "Failed to unregister push device")
                        .await
                }
            }
        }),
    );
}

/// `capabilityLoginAllowed`: a current login session's access token.
fn login_allowed(r: &silo_http::Request) -> bool {
    let Some(claims) = silo_gate::mw::auth::get_claims(r) else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i128);
    claims.token_type == silo_auth::claims::token_type::ACCESS
        && !claims.session_id.is_empty()
        && claims
            .registered
            .expires_at
            .is_some_and(|e| i128::from(e.0) * 1_000_000_000 > now)
}

/// `getPushRegistrationCapabilities` and `getApplePushRegistrationCapabilities`. Ordered registration
/// storage is configured whenever the cipher is, which the front always has.
pub(super) fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    use super::super::chain::{V2Class, capability_json, write_capability};

    #[derive(Serialize)]
    struct Android<'a> {
        revision: &'a str,
        state: &'static str,
        allowed: bool,
        registration_available: bool,
        platforms: [&'static str; 1],
    }
    #[derive(Serialize)]
    struct Apple<'a> {
        revision: &'a str,
        state: &'static str,
        allowed: bool,
        registration_available: bool,
    }

    let path = "/api/v2/notifications/push/devices/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getPushRegistrationCapabilities", |revision| {
                        capability_json(&Android {
                            revision,
                            state: "available",
                            allowed: true,
                            registration_available: true,
                            platforms: ["android"],
                        })
                    })
                    .await;
                })
            }),
        ),
    );
    let path = "/api/v2/devices/push/apple/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileScoped,
            handler_fn(|w, r| {
                Box::pin(async move {
                    let allowed = login_allowed(r);
                    write_capability(w, r, "getApplePushRegistrationCapabilities", |revision| {
                        capability_json(&Apple {
                            revision,
                            state: "available",
                            allowed,
                            registration_available: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}

/// `ErrPushGenerationConflict`, `ErrPushLegacyWriter`, `ErrPushInstallationProof`, and the rest, as
/// `orderedPushProblem` tells them apart.
enum OrderedError {
    Conflict,
    Proof,
    Invalid,
    Failed,
}

/// `validInstallationKey`: 32 bytes in canonical unpadded base64url.
fn valid_installation_key(value: &str) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|key| key.len() == 32 && URL_SAFE_NO_PAD.encode(&key) == value)
}

fn push_digest(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `androidPushIntent`.
fn android_intent(user: i64, profile: &str, token: &str, mode: &str, remove: bool) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Intent<'a> {
        user: i64,
        profile: &'a str,
        token_hash: String,
        mode: &'a str,
        remove: bool,
    }
    let payload = silo_gocompat::json::marshal(&Intent {
        user,
        profile,
        token_hash: fcm_token_hash(token),
        mode,
        remove,
    })
    .unwrap_or_default();
    push_digest(&payload)
}

/// `AndroidPushReceipt`.
#[derive(Default)]
struct Receipt {
    generation: i64,
    registration_id: String,
    server_device_id: String,
    push_mode: String,
}

/// `PushDeviceRepository.ApplyAndroidPush`.
#[allow(clippy::too_many_arguments)]
async fn apply_android(
    s: &Stack,
    user: i64,
    profile: &str,
    device_id: &str,
    key: &str,
    generation_in: i64,
    token: &str,
    push_mode: &str,
    remove: bool,
) -> Result<Receipt, OrderedError> {
    // `validateAndroidPushCommand`.
    if user <= 0
        || trim_space(profile).is_empty()
        || device_id.is_empty()
        || device_id.len() > 128
        || device_id != trim_space(device_id)
        || generation_in <= 0
    {
        return Err(OrderedError::Invalid);
    }
    if !valid_installation_key(key) {
        return Err(OrderedError::Proof);
    }
    let (token, mode) = if remove {
        if !token.is_empty() || !push_mode.is_empty() {
            return Err(OrderedError::Invalid);
        }
        (String::new(), String::new())
    } else {
        match normalize_fcm(device_id, token, push_mode) {
            Ok((_, token, mode)) => (token, mode),
            Err(_) => return Err(OrderedError::Invalid),
        }
    };
    let intent = android_intent(user, profile, &token, &mode, remove);
    let key_hash = push_digest(key.as_bytes());
    let failed = |_| OrderedError::Failed;
    let mut conn = s.pool.acquire().await.map_err(failed)?;
    let mut tx = conn.begin().await.map_err(failed)?;
    let generation = lock_installation(&mut tx, "android_push_installations", device_id)
        .await
        .map_err(|_| OrderedError::Failed)?;
    let rows = tx
        .query(
            "SELECT installation_key_hash,intent_hash,user_id,profile_id,generation,registration_id,server_device_id,push_mode,removed FROM android_push_installations WHERE device_id=$1",
            &[&device_id],
        )
        .await
        .map_err(failed)?;
    let row = rows.first().ok_or(OrderedError::Failed)?;
    let stored_key: String = row.try_get(0).map_err(|_| OrderedError::Failed)?;
    let stored_intent: String = row.try_get(1).map_err(|_| OrderedError::Failed)?;
    let stored_user: i32 = row.try_get(2).map_err(|_| OrderedError::Failed)?;
    let stored_profile: String = row.try_get(3).map_err(|_| OrderedError::Failed)?;
    let stored = Receipt {
        generation: row.try_get(4).map_err(|_| OrderedError::Failed)?,
        registration_id: row.try_get(5).map_err(|_| OrderedError::Failed)?,
        server_device_id: row.try_get(6).map_err(|_| OrderedError::Failed)?,
        push_mode: row.try_get(7).map_err(|_| OrderedError::Failed)?,
    };
    if generation > 0 {
        if !constant_eq(stored_key.as_bytes(), key_hash.as_bytes()) {
            return Err(OrderedError::Proof);
        }
        if generation_in < generation || (generation_in == generation && intent != stored_intent) {
            return Err(OrderedError::Conflict);
        }
        if generation_in == generation {
            tx.commit().await.map_err(failed)?;
            return Ok(stored);
        }
        if remove && (i64::from(stored_user) != user || stored_profile != profile) {
            return Err(OrderedError::Conflict);
        }
    } else {
        let foreign: bool = tx
            .query(
                "SELECT EXISTS(SELECT 1 FROM push_devices WHERE device_id=$1 AND platform=$2 AND user_id<>$3)",
                &[&device_id, &"android", &AnyInt(user)],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(|r| r.try_get(0).ok()))
            .ok_or(OrderedError::Failed)?;
        if foreign {
            return Err(OrderedError::Conflict);
        }
        if remove {
            let foreign: bool = tx
                .query(
                    "SELECT EXISTS(SELECT 1 FROM push_devices WHERE device_id=$1 AND platform=$2 AND profile_id<>$3)",
                    &[&device_id, &"android", &profile],
                )
                .await
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.try_get(0).ok()))
                .ok_or(OrderedError::Failed)?;
            if foreign {
                return Err(OrderedError::Conflict);
            }
        }
    }
    tx.execute(
        "DELETE FROM push_devices WHERE device_id=$1 AND platform=$2",
        &[&device_id, &"android"],
    )
    .await
    .map_err(failed)?;
    let mut result = Receipt {
        generation: generation_in,
        ..Receipt::default()
    };
    if !remove {
        let id = ulid();
        let server_device_id = ulid();
        let ciphertext = s
            .cipher
            .encrypt(token.as_bytes(), fcm_aad(&id))
            .map_err(|_| OrderedError::Failed)?;
        let sql = format!(
            "
		INSERT INTO push_devices (
			id,
			user_id,
			profile_id,
			device_id,
			platform,
			provider,
			fcm_token_ciphertext,
			fcm_token_hash,
			server_device_id,
			push_mode,
			enabled,
			last_seen_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, now())
		ON CONFLICT (profile_id, device_id, platform) DO NOTHING
		RETURNING {COLUMNS}"
        );
        let rows = tx
            .query(
                &sql,
                &[
                    &id,
                    &AnyInt(user),
                    &profile,
                    &device_id,
                    &"android",
                    &"silo_relay",
                    &ciphertext,
                    &fcm_token_hash(&token),
                    &server_device_id,
                    &mode,
                ],
            )
            .await
            .map_err(failed)?;
        // A conflict leaves no row, which Go's scan reports as `pgx.ErrNoRows`.
        let device = rows
            .first()
            .ok_or(OrderedError::Failed)
            .and_then(|r| scan(r).map_err(|_| OrderedError::Failed))?;
        result.registration_id = device.id;
        result.server_device_id = device.server_device_id;
        result.push_mode = device.push_mode;
    }
    tx.execute(
        "UPDATE android_push_installations SET installation_key_hash=$2,generation=$3,user_id=$4,profile_id=$5,intent_hash=$6,registration_id=$7,server_device_id=$8,push_mode=$9,removed=$10 WHERE device_id=$1",
        &[
            &device_id,
            &key_hash,
            &generation_in,
            &AnyInt(user),
            &profile,
            &intent,
            &result.registration_id,
            &result.server_device_id,
            &result.push_mode,
            &remove,
        ],
    )
    .await
    .map_err(failed)?;
    tx.commit().await.map_err(failed)?;
    Ok(result)
}

/// `hmac.Equal`.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `orderedPushProblem`.
fn ordered_problem(e: OrderedError) -> silo_api_v2::problem::Problem {
    use super::super::chain::problem_type;
    use silo_api_v2::problem::Problem;
    match e {
        OrderedError::Conflict => Problem::new(
            problem_type("conflict"),
            "The installation generation, current owner, or bootstrap ownership conflicts. Do not rebase an uncertain command.",
        ),
        OrderedError::Proof => Problem::new(
            problem_type("permission_denied"),
            "The installation credential is invalid.",
        ),
        OrderedError::Invalid => Problem::new(
            problem_type("validation_failed"),
            "Invalid Android push registration.",
        ),
        OrderedError::Failed => super::internal(),
    }
}

/// `pushGeneration`.
fn push_generation(value: &str) -> Result<i64, silo_api_v2::problem::Problem> {
    match value.parse::<i64>() {
        Ok(g) if g > 0 && g.to_string() == value => Ok(g),
        _ => Err(silo_api_v2::problem::Problem::new(
            super::super::chain::problem_type("validation_failed"),
            "X-Push-Generation must be a positive canonical decimal int64.",
        )),
    }
}

/// `registerPushDevice` and `unregisterPushDevice`.
pub(super) fn mount_v2_ordered(stack: &Arc<Stack>, v2: &Mux) {
    use super::super::chain::{write_problem, write_v2_json_status};
    use super::super::huma::RawBody;
    use super::V2_WRITE;

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Body {
        device_id: String,
        token: String,
        push_mode: String,
    }
    #[derive(Serialize)]
    struct Out {
        generation: String,
        registration_id: String,
        server_device_id: String,
        push_mode: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        server_id: String,
    }
    fn header(r: &silo_http::Request, name: &str) -> String {
        String::from_utf8_lossy(r.header.get(name)).into_owned()
    }

    let path = "/api/v2/notifications/push/devices";
    v2.post(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let generation = match push_generation(&header(r, "X-Push-Generation")) {
                    Ok(g) => g,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let raw = r
                    .extensions
                    .get::<RawBody>()
                    .map_or(Vec::new(), |b| b.0.clone());
                let b: Body = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                let key = header(r, "X-Push-Installation-Key");
                match apply_android(
                    &s,
                    user,
                    &profile,
                    &b.device_id,
                    &key,
                    generation,
                    &b.token,
                    &b.push_mode,
                    false,
                )
                .await
                {
                    Ok(receipt) => {
                        let server_id = s
                            .encrypted
                            .get("server.identity_id")
                            .await
                            .unwrap_or_default();
                        write_v2_json_status(
                            w,
                            200,
                            &Out {
                                generation: receipt.generation.to_string(),
                                registration_id: receipt.registration_id,
                                server_device_id: receipt.server_device_id,
                                push_mode: receipt.push_mode,
                                server_id,
                            },
                        )
                        .await
                    }
                    Err(e) => write_problem(w, r, ordered_problem(e)).await,
                }
            }),
        ),
    );
    let path = "/api/v2/notifications/push/devices/{device_id}";
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                let generation = match push_generation(&header(r, "X-Push-Generation")) {
                    Ok(g) => g,
                    Err(p) => return write_problem(w, r, p).await,
                };
                let device = r.url_param("device_id").to_owned();
                let key = header(r, "X-Push-Installation-Key");
                match apply_android(&s, user, &profile, &device, &key, generation, "", "", true)
                    .await
                {
                    Ok(_) => w.write_header(204).await,
                    Err(e) => write_problem(w, r, ordered_problem(e)).await,
                }
            }),
        ),
    );
}
