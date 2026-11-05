//! Static v2 capability documents for the user-management domains: `getAdminDeviceCapabilities`
//! (`internal/apiv2/admin_devices.go`), `getAdminInviteCodeCapabilities`
//! (`internal/apiv2/admin_invite_codes.go`), and `getOnboardingCapabilities`
//! (`internal/apiv2/onboarding.go`). Every dependency they report on is always wired in Go's
//! server, so each answers `available`.

use std::sync::Arc;

use serde::Serialize;
use silo_http::chi::Mux;
use silo_http::handler_fn;

use super::chain::{Stack, V2Class, capability_json, write_capability};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/devices/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/admin/invite-codes/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/onboarding/capabilities"),
];

#[derive(Serialize)]
struct AdminDeviceCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    available: bool,
}

#[derive(Serialize)]
struct AdminInviteCodeCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    available: bool,
    client_selected_code: bool,
}

#[derive(Serialize)]
struct OnboardingCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    available: bool,
    revision_guarded: bool,
}

pub fn mount(stack: &Arc<Stack>, v2: &Mux) {
    const DEVICES: &str = "/api/v2/admin/devices/capabilities";
    v2.get(
        DEVICES,
        stack.v2(
            DEVICES,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getAdminDeviceCapabilities", |revision| {
                        capability_json(&AdminDeviceCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    const INVITE_CODES: &str = "/api/v2/admin/invite-codes/capabilities";
    v2.get(
        INVITE_CODES,
        stack.v2(
            INVITE_CODES,
            V2Class::ActingAdmin,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getAdminInviteCodeCapabilities", |revision| {
                        capability_json(&AdminInviteCodeCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                            client_selected_code: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    const ONBOARDING: &str = "/api/v2/onboarding/capabilities";
    v2.get(
        ONBOARDING,
        stack.v2(
            ONBOARDING,
            V2Class::ProfileScoped,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getOnboardingCapabilities", |revision| {
                        capability_json(&OnboardingCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                            revision_guarded: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}
