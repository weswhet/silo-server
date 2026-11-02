//! `acting_admin.go`, `policy_gates.go`, and the metadata and marker gates of `permissions.go`.

use std::sync::Arc;

use silo_auth::claims::{Claims, token_type};
use silo_auth::user::UserRepository;
use silo_http::Request;
use silo_pg::Pool;

use super::auth::{declared_profile_id, get_claims, get_profile_id};
use super::denial::{Denial, reason};
use super::viewer::{GroupStore, ViewerResolver, household_requires_profile};
use crate::policy::{Domain, Engine, PermissionDecision, PermissionInput};

const ACTIVE_PROFILE_FAILED: &str = "Failed to verify active profile";
const METADATA_REQUIRED: &str = "Metadata curation permission required";
const MARKER_REQUIRED: &str = "Marker editing permission required";

/// `actingAdminFacts`.
#[derive(Default)]
struct Facts {
    declared_profile_id: String,
    acting_as_primary: bool,
    household_requires_profile: bool,
}

/// The policy-backed gates, over the viewer resolver's lookups.
pub struct PolicyGates {
    pub viewer: Arc<ViewerResolver>,
    pub users: UserRepository,
    pub groups: GroupStore,
    pub pool: Arc<Pool>,
    pub engine: Arc<std::sync::Mutex<Engine>>,
}

impl PolicyGates {
    async fn check_primary(&self, user_id: i64, profile_id: &str) -> Result<(bool, bool), String> {
        Ok(match self.viewer.get_profile(user_id, profile_id).await? {
            Some(profile) => (profile.is_primary, true),
            None => (false, false),
        })
    }

    /// `resolveActingAdminFactsFor`.
    async fn facts(
        &self,
        claims: &Claims,
        profile_id: &str,
        with_household: bool,
    ) -> Result<Facts, String> {
        if profile_id.is_empty() {
            if claims.role != "admin" {
                return Ok(Facts::default());
            }
            // `profileLessAdminRefused`.
            let refused = with_household
                && claims.token_type != token_type::API_KEY
                && household_requires_profile(&self.viewer.list_profiles(claims.user_id).await?);
            return Ok(Facts {
                household_requires_profile: refused,
                ..Facts::default()
            });
        }
        let (primary, found) = self.check_primary(claims.user_id, profile_id).await?;
        Ok(Facts {
            declared_profile_id: profile_id.to_owned(),
            acting_as_primary: found && primary,
            household_requires_profile: false,
        })
    }

    async fn decide(&self, input: PermissionInput) -> Result<PermissionDecision, String> {
        let engine = self.engine.clone();
        let value = serde_json::to_value(&input).map_err(|e| e.to_string())?;
        tokio::task::spawn_blocking(move || {
            engine
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .evaluate::<PermissionDecision>(Domain::Permission, &value)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
    }

    fn request_input(r: &Request, mut input: PermissionInput, client_ip: &str) -> PermissionInput {
        input.schema_version = 1;
        input.request_time = super::viewer::now_rfc3339();
        input.device_id = r.header.get_str("X-Silo-Device-Id").to_owned();
        input.client_ip = client_ip.to_owned();
        input
    }

    /// `NewPolicyActingAdminDecider`.
    pub async fn acting_admin_decision(
        &self,
        r: &Request,
        claims: &Claims,
        profile_id: &str,
        client_ip: &str,
    ) -> Result<bool, String> {
        let facts = self.facts(claims, profile_id, true).await?;
        let input = PermissionInput {
            user_id: claims.user_id,
            role: claims.role.clone(),
            user_enabled: true,
            permission: "acting_admin".to_owned(),
            declared_profile_id: facts.declared_profile_id,
            acting_as_primary: facts.acting_as_primary,
            household_requires_profile: facts.household_requires_profile,
            ..PermissionInput::default()
        };
        Ok(self
            .decide(Self::request_input(r, input, client_ip))
            .await?
            .allowed)
    }

    /// `RequireActingAdminWith`.
    pub async fn require_acting_admin(&self, r: &Request, client_ip: &str) -> Result<(), Denial> {
        let claims = get_claims(r).ok_or_else(|| {
            Denial::unauthorized("Authentication required", reason::AUTHENTICATION_REQUIRED)
        })?;
        if claims.role != "admin" {
            return Err(Denial::forbidden("Admin access required"));
        }
        let allowed = self
            .acting_admin_decision(r, &claims, &declared_profile_id(r), client_ip)
            .await
            .map_err(|_| Denial::internal(ACTIVE_PROFILE_FAILED))?;
        if !allowed {
            return Err(Denial::forbidden(
                "Admin access requires the account's primary profile",
            ));
        }
        Ok(())
    }

    /// `ActingAdmin`.
    pub async fn acting_admin(&self, r: &Request, client_ip: &str) -> Result<bool, String> {
        let mut profile_id = get_profile_id(r);
        if profile_id.is_empty() {
            profile_id = r.header.get_str("X-Profile-Id").to_owned();
        }
        if !profile_id.is_empty() {
            let verified = r
                .extensions
                .get::<Arc<silo_store::access::Scope>>()
                .is_some_and(|s| s.profile_id == profile_id && s.profile_verified);
            if !verified {
                return Ok(false);
            }
        }
        let Some(claims) = get_claims(r).filter(|c| c.role == "admin") else {
            return Ok(false);
        };
        self.acting_admin_decision(r, &claims, &profile_id, client_ip)
            .await
    }

    /// `PolicyPermissionMiddleware.RequireMarkerEdit`.
    pub async fn require_marker_edit(&self, r: &Request, client_ip: &str) -> Result<(), Denial> {
        let claims = get_claims(r).ok_or_else(|| {
            Denial::unauthorized("Authentication required", reason::AUTHENTICATION_REQUIRED)
        })?;
        let facts = self
            .facts(&claims, &declared_profile_id(r), false)
            .await
            .map_err(|_| Denial::internal(ACTIVE_PROFILE_FAILED))?;
        let denied = || Denial::forbidden(MARKER_REQUIRED);
        let user = self
            .users
            .get_by_id(claims.user_id)
            .await
            .ok()
            .filter(|u| u.enabled)
            .ok_or_else(denied)?;
        if self.groups.effective_policy(&user).await.is_err() {
            return Err(denied());
        }
        let input = PermissionInput {
            user_id: user.id,
            role: user.role.clone(),
            user_enabled: user.enabled,
            assigned_permissions: effective_permissions_assigned(&user, &self.groups).await,
            permission: "marker_edit".to_owned(),
            declared_profile_id: facts.declared_profile_id,
            acting_as_primary: facts.acting_as_primary,
            household_requires_profile: facts.household_requires_profile,
            ..PermissionInput::default()
        };
        let decision = self
            .decide(Self::request_input(r, input, client_ip))
            .await
            .map_err(|_| Denial::internal("Failed to verify marker edit permission"))?;
        if !decision.allowed {
            return Err(denied());
        }
        Ok(())
    }

    /// `PolicyPermissionMiddleware.RequireMetadataCurationForItem`, up to the authorizer it installs.
    pub async fn require_metadata_curation(
        &self,
        r: &Request,
        content_id: &str,
        client_ip: &str,
    ) -> Result<(), Denial> {
        let claims = get_claims(r).ok_or_else(|| {
            Denial::unauthorized("Authentication required", reason::AUTHENTICATION_REQUIRED)
        })?;
        let facts = self
            .facts(&claims, &declared_profile_id(r), true)
            .await
            .map_err(|_| Denial::internal(ACTIVE_PROFILE_FAILED))?;
        let base = |permission: &str, user_id: i64, role: String, enabled: bool| PermissionInput {
            user_id,
            role,
            user_enabled: enabled,
            permission: permission.to_owned(),
            declared_profile_id: facts.declared_profile_id.clone(),
            acting_as_primary: facts.acting_as_primary,
            household_requires_profile: facts.household_requires_profile,
            ..PermissionInput::default()
        };
        if claims.role == "admin" {
            let input = base("acting_admin", claims.user_id, claims.role.clone(), true);
            let decision = self
                .decide(Self::request_input(r, input, client_ip))
                .await
                .map_err(|_| Denial::internal(ACTIVE_PROFILE_FAILED))?;
            if decision.allowed {
                return Ok(());
            }
        }
        let denied = || Denial::forbidden(METADATA_REQUIRED);
        if content_id.is_empty() {
            return Err(Denial {
                reason: reason::ITEM_ID_REQUIRED,
                ..Denial::new(400, "bad_request", "Item ID is required")
            });
        }
        let user = self
            .users
            .get_by_id(claims.user_id)
            .await
            .ok()
            .filter(|u| u.enabled)
            .ok_or_else(denied)?;
        let effective = self
            .groups
            .effective_policy(&user)
            .await
            .map_err(|_| denied())?;
        let assigned = effective_permissions_assigned(&user, &self.groups).await;
        let failed = || Denial::internal("Failed to verify metadata curation permission");
        let mut input = base(
            "metadata_curation",
            user.id,
            user.role.clone(),
            user.enabled,
        );
        input.assigned_permissions = assigned;
        input.target_library_ids = vec![0];
        let only = self
            .decide(Self::request_input(r, input.clone(), client_ip))
            .await
            .map_err(|_| failed())?;
        if !only.allowed {
            return Err(denied());
        }
        let targets = self
            .target_libraries(content_id)
            .await
            .map_err(|_| Denial::internal("Failed to resolve item libraries"))?;
        if targets.is_empty() {
            return Err(Denial::new(404, "not_found", "Item not found"));
        }
        input.target_library_ids = targets;
        input.user_library_ids = effective
            .library_ids
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(i64::from)
            .collect();
        input.user_libraries_restricted = effective.library_ids.is_some();
        let decision = self
            .decide(Self::request_input(r, input, client_ip))
            .await
            .map_err(|_| failed())?;
        if !decision.allowed {
            if decision.reason_code == "item_outside_user_libraries" {
                return Err(Denial::forbidden("Item is outside your assigned libraries"));
            }
            return Err(denied());
        }
        Ok(())
    }

    /// `PGMetadataTargetLibraryResolver`.
    async fn target_libraries(&self, content_id: &str) -> Result<Vec<i64>, String> {
        let rows = self
            .pool
            .query(
                "WITH target_root AS (
                    SELECT mi.content_id FROM media_items mi WHERE mi.content_id = $1
                    UNION SELECT s.series_id FROM seasons s WHERE s.content_id = $1
                    UNION SELECT e.series_id FROM episodes e WHERE e.content_id = $1
                )
                SELECT DISTINCT mil.media_folder_id::bigint
                FROM target_root tr
                JOIN media_item_libraries mil ON mil.content_id = tr.content_id
                ORDER BY 1",
                &[&content_id],
            )
            .await
            .map_err(|e| e.to_string())?;
        rows.iter()
            .map(|row| row.try_get(0).map_err(|e| e.to_string()))
            .collect()
    }
}

/// `effective.Permissions`: the user's list, masked by the group's allowed list when it has one.
async fn effective_permissions_assigned(
    user: &silo_auth::user::User,
    groups: &GroupStore,
) -> Vec<String> {
    if user.role != "admin"
        && user.access_group_id.is_some()
        && let Ok(Some(mask)) = groups.allowed_permissions(user.id).await
    {
        let mut out: Vec<String> = user
            .permissions
            .iter()
            .map(|p| silo_gocompat::strings::trim_space(p).to_owned())
            .filter(|p| !p.is_empty() && mask.iter().any(|m| m.trim() == p))
            .collect();
        out.sort();
        out.dedup();
        return out;
    }
    user.permissions.clone()
}
