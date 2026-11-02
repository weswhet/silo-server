//! Capability documents that answer from this build alone: images, device login, user libraries.

use std::sync::Arc;

use serde::Serialize;
use silo_http::chi::Mux;
use silo_http::handler_fn;

use super::chain::{
    GoMap, Stack, Step, V2Class, capability_json, v2_public, write_capability, write_v1_json,
};
use crate::rows::NativeRow;
use crate::rows::Surface::{ApiV1, ApiV2};

pub const PUBLIC_ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV1, "GET", "/api/v1/auth/device/capability"),
    NativeRow::new(ApiV2, "GET", "/api/v2/auth/device/capability"),
];

pub const ROWS: &[NativeRow] = &[
    PUBLIC_ROWS[0],
    PUBLIC_ROWS[1],
    NativeRow::new(ApiV1, "GET", "/api/v1/images/capability"),
    NativeRow::new(ApiV2, "GET", "/api/v2/images/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/user/libraries/capabilities"),
];

/// The v1 authenticated viewer group in `newChiRouter`.
const V1_VIEWER_GROUP: &[Step] = &[Step::Auth, Step::Demo, Step::RateLimit, Step::Viewer];

/// `imagesize.All`.
const SIZES: [&str; 4] = ["small", "medium", "large", "original"];
/// `imageutil.MaxCachedOriginalDimension`.
const ORIGINAL_MAX_WIDTH_PX: i32 = 3840;

/// `ImageSizeWidths`.
#[derive(Clone, Copy, Serialize)]
struct Widths {
    small: i32,
    medium: i32,
    large: i32,
}

const fn widths(small: i32, medium: i32, large: i32) -> Widths {
    Widths {
        small,
        medium,
        large,
    }
}

/// `ImageWidthsFor` for each type v1 lists (`imageTypesWithWidths`), from `imagesize.VariantWidthPx`.
fn v1_widths() -> GoMap<Widths> {
    GoMap::from([
        ("backdrop", widths(300, 1920, 2560)),
        ("logo", widths(500, 500, 1280)),
        ("poster", widths(300, 500, 1000)),
        ("profile", widths(300, 500, 500)),
        ("still", widths(300, 500, 1280)),
    ])
}

/// v1's list plus `extendedItemArtworkTypes`.
fn v2_widths() -> GoMap<Widths> {
    let mut map = v1_widths();
    map.insert("banner", widths(500, 500, 1000));
    map.insert("clearart", widths(500, 500, 1000));
    map.insert("disc", widths(300, 500, 1000));
    map.insert("thumb", widths(300, 500, 1280));
    map
}

#[derive(Serialize)]
struct V1Images {
    schema_version: i32,
    season_list_artwork_param: &'static str,
    param: &'static str,
    sizes: [&'static str; 4],
    widths: GoMap<Widths>,
    original_max_width_px: i32,
}

#[derive(Serialize)]
struct V2Images<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    episode_still_provenance: bool,
    episode_parent_artwork: bool,
    extended_item_artwork: bool,
    season_list_artwork_param: &'a str,
    param: &'a str,
    slot_width_params: GoMap<&'static str>,
    sizes: [&'a str; 4],
    widths: GoMap<Widths>,
    original_max_width_px: i32,
    storage_backend: &'a str,
    delivery: &'a str,
}

#[derive(Serialize)]
struct V1DeviceCapability {
    remote_playback_handoff: bool,
    protocol_versions: [i32; 1],
}

#[derive(Serialize)]
struct V2DeviceCapability<'a> {
    revision: &'a str,
    state: &'a str,
    remote_playback_handoff: bool,
    jellyfin_quick_connect: bool,
    protocol_versions: [i32; 1],
    cancel: bool,
    opened_signal: bool,
}

#[derive(Serialize)]
struct V2UserLibraries<'a> {
    revision: &'a str,
    state: &'a str,
    allowed: bool,
    available: bool,
    supports_include_hidden: bool,
}

/// The rows behind no credential.
pub fn mount_public(api: &Mux, v2: &Mux) {
    api.get(
        "/api/v1/auth/device/capability",
        handler_fn(|w, _r| {
            Box::pin(async move {
                write_v1_json(
                    w,
                    200,
                    &V1DeviceCapability {
                        remote_playback_handoff: true,
                        protocol_versions: [2],
                    },
                )
                .await;
            })
        }),
    );
    let path = "/api/v2/auth/device/capability";
    v2.get(
        path,
        v2_public(
            path,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getDeviceLoginCapability", |revision| {
                        capability_json(&V2DeviceCapability {
                            revision,
                            state: "available",
                            remote_playback_handoff: true,
                            jellyfin_quick_connect: true,
                            protocol_versions: [2],
                            cancel: true,
                            opened_signal: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}

/// The rows behind the viewer chain.
pub fn mount(stack: &Arc<Stack>, api: &Mux, v2: &Mux) {
    let path = "/api/v1/images/capability";
    api.get(
        path,
        stack.v1(
            path,
            V1_VIEWER_GROUP,
            handler_fn(|w, _r| {
                Box::pin(async move {
                    write_v1_json(
                        w,
                        200,
                        &V1Images {
                            schema_version: 1,
                            season_list_artwork_param: "include_artwork",
                            param: "image_size",
                            sizes: SIZES,
                            widths: v1_widths(),
                            original_max_width_px: ORIGINAL_MAX_WIDTH_PX,
                        },
                    )
                    .await;
                })
            }),
        ),
    );

    let path = "/api/v2/images/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getImageCapabilities", |revision| {
                        capability_json(&V2Images {
                            revision,
                            state: "available",
                            allowed: true,
                            episode_still_provenance: true,
                            episode_parent_artwork: true,
                            extended_item_artwork: true,
                            season_list_artwork_param: "include_artwork",
                            param: "image_size",
                            slot_width_params: GoMap::from([
                                ("backdrop", "backdrop_width"),
                                ("logo", "logo_width"),
                                ("photo", "photo_width"),
                                ("poster", "poster_width"),
                                ("still", "still_width"),
                            ]),
                            sizes: SIZES,
                            widths: v2_widths(),
                            original_max_width_px: ORIGINAL_MAX_WIDTH_PX,
                            storage_backend: "local",
                            delivery: "server",
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    let path = "/api/v2/user/libraries/capabilities";
    v2.get(
        path,
        stack.v2(
            path,
            V2Class::ProfileOptional,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getUserLibraryCapabilities", |revision| {
                        capability_json(&V2UserLibraries {
                            revision,
                            state: "available",
                            allowed: true,
                            available: true,
                            supports_include_hidden: true,
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}
