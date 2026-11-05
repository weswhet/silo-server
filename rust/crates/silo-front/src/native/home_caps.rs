//! Static v2 capability documents for the home and shuffle domains: `getHomeCapabilities`
//! (`internal/apiv2/home.go`) and `getShuffleCapability` (`internal/apiv2/shuffles.go`). Go's
//! server always wires the home sections, shuffle, and catalog services, so both answer
//! `available`.

use std::sync::Arc;

use serde::Serialize;
use silo_http::chi::Mux;
use silo_http::handler_fn;

use super::chain::{Stack, V2Class, capability_json, write_capability};
use crate::rows::NativeRow;
use crate::rows::Surface::ApiV2;

pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", "/api/v2/home/capabilities"),
    NativeRow::new(ApiV2, "GET", "/api/v2/shuffles/capabilities"),
];

/// `handlers.MaxHomeLayoutIncludedSections`.
const MAX_HOME_LAYOUT_INCLUDED_SECTIONS: i64 = 4;
/// `handlers.MaxSectionItemLimitCap`.
const MAX_SECTION_ITEM_LIMIT_CAP: i64 = 100;

#[derive(Serialize)]
struct HomeCapabilities<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    include_items_max: i64,
    section_item_limit_max: i64,
    row_item_limit_max: i64,
}

#[derive(Serialize)]
struct ShuffleCapability<'a> {
    revision: &'a str,
    state: &'static str,
    allowed: bool,
    scope_kinds: [&'static str; 5],
}

pub fn mount(stack: &Arc<Stack>, v2: &Mux) {
    const HOME: &str = "/api/v2/home/capabilities";
    v2.get(
        HOME,
        stack.v2(
            HOME,
            V2Class::ProfileScoped,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getHomeCapabilities", |revision| {
                        capability_json(&HomeCapabilities {
                            revision,
                            state: "available",
                            allowed: true,
                            include_items_max: MAX_HOME_LAYOUT_INCLUDED_SECTIONS,
                            section_item_limit_max: MAX_SECTION_ITEM_LIMIT_CAP,
                            row_item_limit_max: MAX_SECTION_ITEM_LIMIT_CAP,
                        })
                    })
                    .await;
                })
            }),
        ),
    );

    const SHUFFLES: &str = "/api/v2/shuffles/capabilities";
    v2.get(
        SHUFFLES,
        stack.v2(
            SHUFFLES,
            V2Class::ProfileScoped,
            handler_fn(|w, r| {
                Box::pin(async move {
                    write_capability(w, r, "getShuffleCapability", |revision| {
                        capability_json(&ShuffleCapability {
                            revision,
                            state: "available",
                            allowed: true,
                            scope_kinds: [
                                "library",
                                "series",
                                "season",
                                "library_collection",
                                "user_collection",
                            ],
                        })
                    })
                    .await;
                })
            }),
        ),
    );
}
