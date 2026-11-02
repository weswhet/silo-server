//! The current user: v1 `HandleMe` and `HandleAccountPasswordCapability`, v2 `getCurrentUser` and
//! `getAccountPasswordCapability`.

use std::sync::Arc;

use serde::Serialize;
use silo_auth::claims::{Claims, token_type};
use silo_auth::user::{User, effective_permissions};
use silo_gate::mw::auth::{declared_profile_id, get_claims, get_profile_id};
use silo_http::chi::Mux;
use silo_http::{ResponseWriter, handler_fn};

use super::chain::{
    Stack, Step, V2Class, capability_json, write_capability, write_problem, write_v1_json,
    write_v2_json,
};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/auth/me"),
    NativeRow::new(ApiV1, "GET", "/api/v1/auth/account/capability"),
    NativeRow::new(ApiV2, "GET", "/api/v2/account/me"),
    NativeRow::new(ApiV2, "GET", "/api/v2/account/password/capability"),
];

const V1_ME: &[Step] = &[Step::Auth];
const V1_ACCOUNT_CAPABILITY: &[Step] = &[Step::Auth, Step::OptionalViewer];

/// `auth.MinimumPasswordLength` and `MaximumPasswordBytes`.
const MINIMUM_PASSWORD_LENGTH: i32 = 8;
const MAXIMUM_PASSWORD_BYTES: i32 = 72;

/// `handlers.ImpersonationView`.
#[derive(Serialize)]
pub(super) struct V1Impersonation {
    pub active: bool,
    pub impersonator_user_id: i64,
    pub impersonator_username: String,
}

/// `handlers.UserView`.
#[derive(Serialize)]
pub(super) struct V1User {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub download_allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation: Option<V1Impersonation>,
}

/// `apiv2.Impersonation`.
#[derive(Serialize)]
pub(super) struct V2Impersonation {
    pub active: bool,
    pub impersonator_user_id: String,
    pub impersonator_username: String,
}

/// `apiv2.Account`.
#[derive(Serialize)]
pub(super) struct V2Account {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub download_allowed: bool,
    pub password_change_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation: Option<V2Impersonation>,
}

/// What `AuthHandler.CurrentUser` reads.
struct CurrentUser {
    user: User,
    download_allowed: bool,
    impersonator: Option<(i64, String)>,
}

/// `AuthHandler.CurrentUser`. An error is the 500 both surfaces render.
async fn current_user(stack: &Stack, claims: &Claims) -> Result<CurrentUser, ()> {
    let user = stack
        .users
        .get_by_id(claims.user_id)
        .await
        .map_err(|_| ())?;
    let impersonator = match claims.impersonator_user_id {
        None => None,
        Some(id) => match stack.users.get_by_id(id).await {
            Ok(found) => Some((id, found.username)),
            Err(silo_auth::user::UserError::NotFound) => Some((id, String::new())),
            Err(_) => return Err(()),
        },
    };
    // `effectiveDownloadAllowed`: a failed lookup logs and reads as not allowed.
    let download_allowed = match stack.groups.effective_policy(&user).await {
        Ok(effective) => effective.download_allowed,
        Err(e) => {
            tracing::warn!(component = "api", user_id = user.id, error = %e, "failed to resolve effective download policy");
            false
        }
    };
    Ok(CurrentUser {
        user,
        download_allowed,
        impersonator,
    })
}

/// `effectiveDownloadAllowed`.
pub(super) async fn download_allowed(stack: &Stack, user: &User) -> bool {
    match stack.groups.effective_policy(user).await {
        Ok(effective) => effective.download_allowed,
        Err(e) => {
            tracing::warn!(component = "api", user_id = user.id, error = %e, "failed to resolve effective download policy");
            false
        }
    }
}

/// `buildUserResponse` with no impersonator, in the v1 shape.
pub(super) async fn v1_user(stack: &Stack, user: &User) -> V1User {
    V1User {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
        permissions: effective_permissions(user),
        download_allowed: download_allowed(stack, user).await,
        impersonation: None,
    }
}

/// `buildUserResponse` with no impersonator, then `accountFromView`.
pub(super) async fn v2_account(stack: &Stack, user: &User) -> V2Account {
    V2Account {
        id: user.id.to_string(),
        username: user.username.clone(),
        email: user.email.clone(),
        role: if user.role == "admin" {
            "admin"
        } else {
            "user"
        }
        .to_owned(),
        permissions: effective_permissions(user),
        download_allowed: download_allowed(stack, user).await,
        password_change_required: user.password_change_required,
        impersonation: None,
    }
}

/// `passwordChangeAllowed`.
pub(super) async fn password_change_allowed(
    stack: &Stack,
    claims: &Claims,
    profile_id: &str,
) -> Result<bool, ()> {
    if claims.token_type != token_type::ACCESS
        || claims.session_id.is_empty()
        || claims.impersonator_user_id.is_some()
    {
        return Ok(false);
    }
    if claims.password_change_required {
        return Ok(true);
    }
    let profile_id = silo_gocompat::strings::trim_space(profile_id);
    if profile_id.is_empty() {
        return Ok(claims.role == "admin");
    }
    let profile = stack
        .viewer
        .get_profile(claims.user_id, profile_id)
        .await
        .map_err(|_| ())?;
    Ok(profile.is_some_and(|p| p.is_primary))
}

/// `passwordChangeAllowed`, then `PasswordChangeAvailable`. An error is a 500 on both surfaces.
async fn password_change(
    stack: &Stack,
    claims: &Claims,
    profile_id: &str,
) -> Result<bool, &'static str> {
    const VERIFY: &str = "Failed to verify the active profile";
    if claims.token_type != token_type::ACCESS
        || claims.session_id.is_empty()
        || claims.impersonator_user_id.is_some()
    {
        return Ok(false);
    }
    let allowed = if claims.password_change_required {
        true
    } else {
        let profile_id = silo_gocompat::strings::trim_space(profile_id);
        if profile_id.is_empty() {
            claims.role == "admin"
        } else {
            let profile = stack
                .viewer
                .get_profile(claims.user_id, profile_id)
                .await
                .map_err(|_| VERIFY)?;
            profile.is_some_and(|p| p.is_primary)
        }
    };
    if !allowed {
        return Ok(false);
    }
    let user = stack
        .users
        .get_by_id(claims.user_id)
        .await
        .map_err(|_| "Failed to load password capabilities")?;
    Ok(user.local_password_login_enabled && !user.password_hash.is_empty())
}

/// `accountPasswordCapabilityResponse`.
#[derive(Serialize)]
struct V1PasswordCapability {
    schema_version: i32,
    change_password: bool,
    requires_current_password: bool,
    minimum_password_length: i32,
    maximum_password_bytes: i32,
}

/// `apiv2.AccountPasswordCapability`.
#[derive(Serialize)]
struct V2PasswordCapability<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    requires_current_password: bool,
    minimum_password_length: i32,
    maximum_password_bytes: i32,
    sign_out_other_sessions: bool,
}

async fn v1_internal(w: &mut dyn ResponseWriter, message: &str) {
    super::chain::write_v1_denial(w, &silo_gate::mw::Denial::internal(message)).await;
}

async fn v2_internal(w: &mut dyn ResponseWriter, r: &silo_http::Request) {
    let problem = silo_api_v2::problem::Problem::new(
        silo_api_v2::problem::internal_error(),
        "An unexpected error occurred.",
    );
    write_problem(w, r, problem).await;
}

/// Registers this domain's handlers.
pub fn mount(stack: &Arc<Stack>, api: &Mux, v2: &Mux) {
    let s = stack.clone();
    api.get(
        "/api/v1/auth/me",
        stack.v1(
            "/api/v1/auth/me",
            V1_ME,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    let Some(claims) = s.auth.extract_claims(r) else {
                        let denial = silo_gate::mw::Denial::unauthorized(
                            "Invalid or missing authentication token",
                            "",
                        );
                        super::chain::write_v1_denial(w, &denial).await;
                        return;
                    };
                    let Ok(me) = current_user(&s, &claims).await else {
                        v1_internal(w, "An unexpected error occurred").await;
                        return;
                    };
                    let permissions = effective_permissions(&me.user);
                    let view = V1User {
                        id: me.user.id,
                        username: me.user.username,
                        email: me.user.email,
                        role: me.user.role,
                        permissions,
                        download_allowed: me.download_allowed,
                        impersonation: me.impersonator.map(|(id, name)| V1Impersonation {
                            active: true,
                            impersonator_user_id: id,
                            impersonator_username: name,
                        }),
                    };
                    write_v1_json(w, 200, &view).await;
                })
            }),
        ),
    );

    let s = stack.clone();
    api.get(
        "/api/v1/auth/account/capability",
        stack.v1(
            "/api/v1/auth/account/capability",
            V1_ACCOUNT_CAPABILITY,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    let Some(claims) = get_claims(r) else {
                        return;
                    };
                    match password_change(&s, &claims, &declared_profile_id(r)).await {
                        Ok(change_password) => {
                            write_v1_json(
                                w,
                                200,
                                &V1PasswordCapability {
                                    schema_version: 1,
                                    change_password,
                                    requires_current_password: true,
                                    minimum_password_length: MINIMUM_PASSWORD_LENGTH,
                                    maximum_password_bytes: MAXIMUM_PASSWORD_BYTES,
                                },
                            )
                            .await;
                        }
                        Err(message) => v1_internal(w, message).await,
                    }
                })
            }),
        ),
    );

    let s = stack.clone();
    v2.get(
        "/api/v2/account/me",
        stack.v2(
            "/api/v2/account/me",
            V2Class::Authenticated,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    let Some(claims) = get_claims(r) else {
                        return;
                    };
                    let Ok(me) = current_user(&s, &claims).await else {
                        v2_internal(w, r).await;
                        return;
                    };
                    let permissions = effective_permissions(&me.user);
                    // `buildUserResponse`: an impersonating administrator is not restricted.
                    let required =
                        me.user.password_change_required && claims.impersonator_user_id.is_none();
                    // `roleOf`.
                    let role = if me.user.role == "admin" {
                        "admin"
                    } else {
                        "user"
                    };
                    let view = V2Account {
                        id: me.user.id.to_string(),
                        username: me.user.username,
                        email: me.user.email,
                        role: role.to_owned(),
                        permissions,
                        download_allowed: me.download_allowed,
                        password_change_required: required,
                        impersonation: me.impersonator.map(|(id, name)| V2Impersonation {
                            active: true,
                            impersonator_user_id: id.to_string(),
                            impersonator_username: name,
                        }),
                    };
                    write_v2_json(w, &view).await;
                })
            }),
        ),
    );

    let s = stack.clone();
    v2.get(
        "/api/v2/account/password/capability",
        stack.v2(
            "/api/v2/account/password/capability",
            V2Class::ProfileOptional,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    let Some(claims) = get_claims(r) else {
                        return;
                    };
                    let allowed = match password_change(&s, &claims, &get_profile_id(r)).await {
                        Ok(allowed) => allowed,
                        Err(_) => {
                            v2_internal(w, r).await;
                            return;
                        }
                    };
                    write_capability(w, r, "getAccountPasswordCapability", |revision| {
                        capability_json(&V2PasswordCapability {
                            revision,
                            state: "available",
                            allowed,
                            requires_current_password: true,
                            minimum_password_length: MINIMUM_PASSWORD_LENGTH,
                            maximum_password_bytes: MAXIMUM_PASSWORD_BYTES,
                            sign_out_other_sessions: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}
