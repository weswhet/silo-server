//! `acting_admin.go`, `policy_gates.go`, and the metadata and marker gates of `permissions.go`.

use std::sync::Arc;

use silo_auth::claims::{Claims, token_type};
use silo_auth::user::{User, UserRepository};
use silo_http::Request;
use silo_pg::Pool;

use super::auth::{declared_profile_id, get_claims, get_profile_id};
use super::denial::{Denial, reason};
use super::viewer::{EffectivePolicy, GroupStore, ViewerResolver, household_requires_profile};
use crate::pdp::Pdp;
use crate::policy::{PermissionDecision, PermissionInput};

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

/// The fields every permission gate sets. The rest stay Go's nil, which a policy can tell from `[]`.
fn gate_input(
    permission: &str,
    user_id: i64,
    role: &str,
    enabled: bool,
    facts: &Facts,
) -> PermissionInput {
    PermissionInput {
        user_id,
        role: role.to_owned(),
        user_enabled: enabled,
        permission: permission.to_owned(),
        declared_profile_id: facts.declared_profile_id.clone(),
        acting_as_primary: facts.acting_as_primary,
        household_requires_profile: facts.household_requires_profile,
        ..PermissionInput::default()
    }
}

/// The input `RequireMarkerEdit` sends.
fn marker_edit_input(user: &User, effective: &EffectivePolicy, facts: &Facts) -> PermissionInput {
    PermissionInput {
        assigned_permissions: Some(effective.permissions.clone()),
        ..gate_input("marker_edit", user.id, &user.role, user.enabled, facts)
    }
}

/// The inputs `RequireMetadataCurationForItem` sends: `permissionOnlyInput` without targets, then the full one.
fn curation_input(
    user: &User,
    effective: &EffectivePolicy,
    facts: &Facts,
    targets: Option<Vec<i64>>,
) -> PermissionInput {
    let mut input = PermissionInput {
        assigned_permissions: Some(effective.permissions.clone()),
        ..gate_input(
            "metadata_curation",
            user.id,
            &user.role,
            user.enabled,
            facts,
        )
    };
    match targets {
        None => input.target_library_ids = Some(vec![0]),
        Some(targets) => {
            input.target_library_ids = Some(targets);
            input.user_library_ids = effective
                .library_ids
                .as_ref()
                .map(|ids| ids.iter().copied().map(i64::from).collect());
            input.user_libraries_restricted = effective.library_ids.is_some();
        }
    }
    input
}

/// The policy-backed gates, over the viewer resolver's lookups.
pub struct PolicyGates {
    pub viewer: Arc<ViewerResolver>,
    pub users: UserRepository,
    pub groups: GroupStore,
    pub pool: Arc<Pool>,
    pub pdp: Arc<Pdp>,
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

    async fn decide(
        &self,
        r: &Request,
        input: PermissionInput,
    ) -> Result<PermissionDecision, String> {
        let request_id = r
            .extensions
            .get::<super::RequestId>()
            .map(|id| id.0.clone())
            .unwrap_or_default();
        self.pdp
            .check_permission(&input, &request_id)
            .await
            .map_err(|e| e.to_string())
    }

    fn request_input(r: &Request, mut input: PermissionInput, client_ip: &str) -> PermissionInput {
        input.schema_version = 1;
        input.request_time = super::viewer::now_rfc3339();
        input.device_id = String::from_utf8_lossy(r.header.get("X-Silo-Device-Id")).into_owned();
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
        let input = gate_input("acting_admin", claims.user_id, &claims.role, true, &facts);
        Ok(self
            .decide(r, Self::request_input(r, input, client_ip))
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
            profile_id = String::from_utf8_lossy(r.header.get("X-Profile-Id")).into_owned();
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
        let effective = self
            .groups
            .effective_policy(&user)
            .await
            .map_err(|_| denied())?;
        let input = marker_edit_input(&user, &effective, &facts);
        let decision = self
            .decide(r, Self::request_input(r, input, client_ip))
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
        if claims.role == "admin" {
            let input = gate_input("acting_admin", claims.user_id, &claims.role, true, &facts);
            let decision = self
                .decide(r, Self::request_input(r, input, client_ip))
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
        let failed = || Denial::internal("Failed to verify metadata curation permission");
        let input = curation_input(&user, &effective, &facts, None);
        let only = self
            .decide(r, Self::request_input(r, input.clone(), client_ip))
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
        let input = curation_input(&user, &effective, &facts, Some(targets));
        let decision = self
            .decide(r, Self::request_input(r, input, client_ip))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mw::viewer::{GroupPolicy, apply_group_policy};

    /// Each list's nil against what Go's real gates sent a fake decider.
    #[test]
    fn permission_input_nil_lists_match_go() {
        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/vectors/access/access.json"
        ))
        .unwrap();
        let data: serde_json::Value = silo_gocompat::json::unmarshal(&raw).unwrap();
        let cases = data["permission_input_nil"].as_array().unwrap();
        assert!(cases.len() >= 8);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let ints = |v: &serde_json::Value| -> Option<Vec<i32>> {
                v.as_array().map(|a| {
                    a.iter()
                        .map(|n| i32::try_from(n.as_i64().unwrap()).unwrap())
                        .collect()
                })
            };
            let strings = |v: &serde_json::Value| -> Option<Vec<String>> {
                v.as_array()
                    .map(|a| a.iter().map(|n| n.as_str().unwrap().to_owned()).collect())
            };
            let user = User {
                id: 2,
                role: "user".to_owned(),
                enabled: true,
                permissions: strings(&case["permissions"]).unwrap(),
                library_ids: ints(&case["library_ids"]),
                ..User::default()
            };
            let group = case["mask"].as_array().map(|_| GroupPolicy {
                allowed_permissions: strings(&case["mask"]),
                ..GroupPolicy::default()
            });
            let effective = apply_group_policy(&user, group.as_ref());
            let facts = Facts::default();
            let targets = case["targets"]
                .as_array()
                .map(|a| a.iter().map(|n| n.as_i64().unwrap()).collect());
            let got = match case["gate"].as_str().unwrap() {
                "acting_admin" => gate_input("acting_admin", 2, "admin", true, &facts),
                "marker_edit" => marker_edit_input(&user, &effective, &facts),
                "curation_only" => curation_input(&user, &effective, &facts, None),
                "curation" => curation_input(&user, &effective, &facts, targets),
                other => panic!("{other}"),
            };
            let got = serde_json::to_value(&got).unwrap();
            for field in [
                "assigned_permissions",
                "target_library_ids",
                "user_library_ids",
                "user_libraries_restricted",
            ] {
                assert_eq!(got[field], case["input"][field], "{name}: {field}");
            }
        }
    }
}
