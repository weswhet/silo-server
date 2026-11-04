//! Clearing the profile's email address and the account's Discord writes: `HandleClearEmailAddress`
//! (`handlers/notifications_email.go`), `HandleUpdatePreferences` and `HandleUnlink`
//! (`handlers/notifications_discord.go`), and `registerNotificationChannels`
//! (`apiv2/notification_channels.go`).
//!
//! Requesting a verification email, the link and unsubscribe pages, and Discord linking stay on Go:
//! they send mail, run the durable verification outbox, and call Discord's OAuth endpoints.

use std::sync::Arc;

use silo_api_v2::problem::Problem;
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::json::Decoder;
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_pg::AnyInt;

use super::super::auth::write_v1_error;
use super::super::chain::{Stack, problem_type, write_problem, write_v1_json, write_v2_json};
use super::super::huma::RawBody;
use super::super::settings::{HouseholdError, Verifier, household_manager};
use super::{
    DiscordPrefs, ModeBody, V1_GROUP, V2_WRITE, discord_prefs, email_prefs, internal, parse_bool,
    profile_is_child, user_of, valid_mode,
};

macro_rules! route {
    ($stack:ident, |$s:ident, $w:ident, $r:ident| $body:block) => {{
        let stack = $stack.clone();
        handler_fn(move |$w, $r| {
            let $s = stack.clone();
            Box::pin(async move { $body })
        })
    }};
}

/// `ClearEmailAddress`: `Err(true)` is `ErrEmailChildProfile`.
async fn clear_email_address(s: &Stack, user: i64, profile: &str) -> Result<(), bool> {
    if profile_is_child(s, user, profile).await {
        return Err(true);
    }
    s.pool
        .execute(
            "
		UPDATE notification_email_prefs SET
			custom_email = '',
			pending_email = '',
			pending_token_hash = '',
			pending_expires_at = NULL,
			mode = 'off',
			updated_at = now()
		WHERE profile_id = $1",
            &[&profile],
        )
        .await
        .map(|_| ())
        .map_err(|_| false)
}

enum Manage {
    Allowed,
    Denied,
    Unverified,
    Failed,
}

/// `MayManageDiscordNotifications`.
async fn may_manage(s: &Stack, r: &Request, active: &str, verify: &Verifier) -> Manage {
    let Some(claims) = get_claims(r) else {
        return Manage::Denied;
    };
    match household_manager(s, &claims, claims.user_id, active, verify).await {
        Ok((true, _)) => Manage::Allowed,
        Ok((false, _)) => Manage::Denied,
        Err(HouseholdError::Unverified) => Manage::Unverified,
        Err(HouseholdError::Other) => Manage::Failed,
    }
}

/// `activeProfileIDOf`.
fn active_profile_v1(r: &Request) -> String {
    let id = get_profile_id(r);
    if !id.is_empty() {
        return id;
    }
    String::from_utf8_lossy(r.header.get("X-Profile-Id")).into_owned()
}

/// `requireManagement`, answered on v1.
async fn require_v1(s: &Stack, w: &mut dyn silo_http::ResponseWriter, r: &Request) -> bool {
    let Some(claims) = get_claims(r) else {
        write_v1_error(
            w,
            403,
            "forbidden",
            "Discord notification changes require the account's primary profile",
        )
        .await;
        return false;
    };
    let verify = Verifier::v1(s, r, &claims);
    match may_manage(s, r, &active_profile_v1(r), &verify).await {
        Manage::Allowed => true,
        Manage::Unverified => {
            write_v1_error(
                w,
                403,
                "forbidden",
                "Discord notification changes require verifying the primary profile PIN",
            )
            .await;
            false
        }
        Manage::Failed => {
            write_v1_error(
                w,
                500,
                "internal_error",
                "Failed to check Discord notification permissions",
            )
            .await;
            false
        }
        Manage::Denied => {
            write_v1_error(
                w,
                403,
                "forbidden",
                "Discord notification changes require the account's primary profile",
            )
            .await;
            false
        }
    }
}

/// `requireDiscordNotificationManagement`.
async fn require_v2(s: &Stack, r: &Request) -> Option<Problem> {
    match may_manage(s, r, &get_profile_id(r), &Verifier::v2(r)).await {
        Manage::Allowed => None,
        Manage::Unverified => Some(Problem::new(
            problem_type("profile_verification_required"),
            "Discord notification changes require verifying the primary profile PIN.",
        )),
        Manage::Failed => Some(internal()),
        Manage::Denied => Some(Problem::new(
            problem_type("permission_denied"),
            "Discord notification changes require the account's primary profile.",
        )),
    }
}

enum DiscordModeError {
    Invalid,
    NotAllowed,
    NotLinked,
    Failed,
}

/// `SetDiscordMode` over `DiscordPrefsRepository.SetMode`.
async fn set_discord_mode(s: &Stack, user: i64, mode: &str) -> Result<(), DiscordModeError> {
    if !valid_mode(mode) {
        return Err(DiscordModeError::Invalid);
    }
    if mode.contains("per_episode") {
        let raw = s
            .encrypted
            .get("notifications.discord.allow_per_episode")
            .await
            .unwrap_or_default();
        if !parse_bool(&raw, true) {
            return Err(DiscordModeError::NotAllowed);
        }
    }
    let changed = s
        .pool
        .execute(
            "
		UPDATE notification_discord_prefs SET
			mode = $2,
			watermark_created_at = CASE
				WHEN notification_discord_prefs.mode = 'off' THEN now()
				ELSE notification_discord_prefs.watermark_created_at
			END,
			watermark_id = CASE
				WHEN notification_discord_prefs.mode = 'off' THEN ''
				ELSE notification_discord_prefs.watermark_id
			END,
			last_attempt_at = NULL,
			consecutive_failures = 0,
			updated_at = now()
		WHERE user_id = $1 AND discord_user_id <> ''",
            &[&AnyInt(user), &mode],
        )
        .await
        .map_err(|_| DiscordModeError::Failed)?;
    if changed == 0 && mode != "off" {
        return Err(DiscordModeError::NotLinked);
    }
    Ok(())
}

/// `DiscordPrefsRepository.ClearIdentity`.
async fn unlink(s: &Stack, user: i64) -> bool {
    s.pool
        .execute(
            "
		UPDATE notification_discord_prefs SET
			discord_user_id = '',
			discord_username = '',
			dm_channel_id = '',
			mode = 'off',
			last_attempt_at = NULL,
			consecutive_failures = 0,
			link_failure = '',
			updated_at = now()
		WHERE user_id = $1",
            &[&AnyInt(user)],
        )
        .await
        .is_ok()
}

/// The v1 email address row, on the `/api/v1/notifications` subrouter.
pub(super) fn mount_v1_subrouter(stack: &Arc<Stack>, mux: &Mux) {
    mux.delete(
        "/email-preferences/address",
        route!(stack, |s, w, r| {
            let (user, profile) = (user_of(r), get_profile_id(r));
            match clear_email_address(&s, user, &profile).await {
                Ok(()) => {}
                Err(true) => {
                    return write_v1_error(
                        w,
                        403,
                        "child_profile",
                        "Child profiles cannot change the notification address",
                    )
                    .await;
                }
                Err(false) => {
                    return write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to remove the custom address",
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
}

/// The v1 Discord rows, on the group outside the `/notifications` subrouter.
pub(super) fn mount_v1(stack: &Arc<Stack>, api: &Mux) {
    let path = "/api/v1/notifications/discord-preferences";
    api.put(
        path,
        stack.v1(
            path,
            V1_GROUP,
            route!(stack, |s, w, r| {
                // `readHouseholdRequestBody`.
                let (bytes, error) = r.read_all().await;
                if error.is_some() || bytes.len() > 1 << 20 {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                }
                if !require_v1(&s, w, r).await {
                    return;
                }
                let user = user_of(r);
                let Ok(req) = Decoder::new().stream(&bytes[..]).decode::<ModeBody>() else {
                    return write_v1_error(w, 400, "bad_request", "Invalid request body").await;
                };
                match set_discord_mode(&s, user, &req.mode).await {
                    Ok(()) => {}
                    Err(DiscordModeError::Invalid) => {
                        return write_v1_error(
                            w,
                            400,
                            "bad_request",
                            "Unknown Discord notification mode",
                        )
                        .await;
                    }
                    Err(DiscordModeError::NotAllowed) => {
                        return write_v1_error(
                            w,
                            400,
                            "not_allowed",
                            "Per-episode Discord DMs are disabled by the administrator",
                        )
                        .await;
                    }
                    Err(DiscordModeError::NotLinked) => {
                        return write_v1_error(
                            w,
                            400,
                            "not_linked",
                            "Link a Discord account first",
                        )
                        .await;
                    }
                    Err(DiscordModeError::Failed) => {
                        return write_v1_error(
                            w,
                            500,
                            "internal_error",
                            "Failed to save Discord preferences",
                        )
                        .await;
                    }
                }
                match discord_prefs(&s.pool, user).await {
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
    let path = "/api/v1/notifications/discord-link";
    api.delete(
        path,
        stack.v1(
            path,
            V1_GROUP,
            route!(stack, |s, w, r| {
                if !require_v1(&s, w, r).await {
                    return;
                }
                if !unlink(&s, user_of(r)).await {
                    return write_v1_error(
                        w,
                        500,
                        "internal_error",
                        "Failed to unlink Discord account",
                    )
                    .await;
                }
                write_v1_json(
                    w,
                    200,
                    &DiscordPrefs {
                        linked: false,
                        discord_username: String::new(),
                        mode: "off".to_owned(),
                        link_failure: String::new(),
                    },
                )
                .await;
            }),
        ),
    );
}

/// The v2 rows.
pub(super) fn mount_v2(stack: &Arc<Stack>, v2: &Mux) {
    use super::super::chain::Step;
    const V2_WRITE_OPTIONAL: &[Step] = &[
        Step::Auth,
        Step::DemoRestricted,
        Step::RateLimit,
        Step::Viewer,
    ];

    let path = "/api/v2/notifications/email-preferences/address";
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE,
            route!(stack, |s, w, r| {
                let (user, profile) = (user_of(r), get_profile_id(r));
                match clear_email_address(&s, user, &profile).await {
                    Ok(()) => {}
                    Err(true) => {
                        return write_problem(
                            w,
                            r,
                            Problem::new(
                                problem_type("permission_denied"),
                                "Child profiles cannot change the notification address.",
                            ),
                        )
                        .await;
                    }
                    Err(false) => return write_problem(w, r, internal()).await,
                }
                match email_prefs(&s, user, &profile).await {
                    Ok(p) => write_v2_json(w, &p).await,
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/discord-preferences";
    v2.put(
        path,
        stack.v2_steps(
            path,
            V2_WRITE_OPTIONAL,
            route!(stack, |s, w, r| {
                if let Some(p) = require_v2(&s, r).await {
                    return write_problem(w, r, p).await;
                }
                let user = user_of(r);
                let raw = r
                    .extensions
                    .get::<RawBody>()
                    .map_or(Vec::new(), |b| b.0.clone());
                let body: ModeBody = silo_gocompat::json::unmarshal(&raw).unwrap_or_default();
                let invalid = |d: &str| Problem::new(problem_type("validation_failed"), d);
                match set_discord_mode(&s, user, &body.mode).await {
                    Ok(()) => {}
                    Err(DiscordModeError::Invalid) => {
                        return write_problem(w, r, invalid("Unknown notification mode.")).await;
                    }
                    Err(DiscordModeError::NotAllowed) => {
                        return write_problem(
                            w,
                            r,
                            invalid("Per-episode delivery is disabled by the administrator."),
                        )
                        .await;
                    }
                    Err(DiscordModeError::NotLinked) => {
                        return write_problem(w, r, invalid("Link a Discord account first.")).await;
                    }
                    Err(DiscordModeError::Failed) => return write_problem(w, r, internal()).await,
                }
                match discord_prefs(&s.pool, user).await {
                    Ok(p) => write_v2_json(w, &p).await,
                    Err(_) => write_problem(w, r, internal()).await,
                }
            }),
        ),
    );

    let path = "/api/v2/notifications/discord-link";
    v2.delete(
        path,
        stack.v2_steps(
            path,
            V2_WRITE_OPTIONAL,
            route!(stack, |s, w, r| {
                if let Some(p) = require_v2(&s, r).await {
                    return write_problem(w, r, p).await;
                }
                if unlink(&s, user_of(r)).await {
                    w.write_header(204).await;
                } else {
                    write_problem(w, r, internal()).await;
                }
            }),
        ),
    );
}
