//! Success paths for ratings, favorites, watchlist membership, watch progress, home dismissals, and
//! devices. The plan's generic cases name no seeded item, so they never reach these.

use crate::auth_flows::{Flows, Step};
use crate::model::*;
use crate::plan::Builder;
use Surface::{ApiV1, ApiV2};

const MOVIE: &str = "movie-tmdb-9000001";
const SERIES: &str = "series-tvdb-9000003";
const EPISODE: &str = "episode-tvdb-9000003-1-1";
/// Rated R, above the seeded kid profile's PG ceiling; `MOVIE` is PG.
const ABOVE: &str = "movie-tmdb-9000002";

struct Call<'a> {
    method: &'a str,
    route: &'a str,
    at: Option<String>,
    name: &'a str,
    body: Option<&'a str>,
}

fn call<'a>(method: &'a str, route: &'a str, at: Option<String>, name: &'a str) -> Call<'a> {
    Call {
        method,
        route,
        at,
        name,
        body: None,
    }
}

fn go(f: &mut Flows, surface: Surface, c: Call) {
    let v1 = surface == ApiV1;
    let name = format!("personal:{}:{}", if v1 { "v1" } else { "v2" }, c.name);
    let (at, query) = match c.at.as_deref().and_then(|a| a.split_once('?')) {
        Some((at, q)) => (Some(at.to_owned()), q),
        None => (c.at.clone(), ""),
    };
    let pairs: Vec<(&str, &str)> = query.split('&').filter_map(|p| p.split_once('=')).collect();
    f.step(Step {
        query: &pairs,
        identity: if v1 { Identity::User } else { Identity::Admin },
        at: at.as_deref(),
        body: c.body,
        profile: Some(if v1 {
            "${user_profile_id}"
        } else {
            "${admin_profile_id}"
        }),
        ..Step::new(surface, c.method, c.route, &name)
    });
}

fn list_flow(f: &mut Flows, surface: Surface, base: &str, label: &str) {
    let route = format!("{base}/{{item_id}}");
    let at = format!("{base}/{MOVIE}");
    let ep = format!("{base}/{EPISODE}");
    let n = |s: &str| format!("{label}_{s}");
    go(
        f,
        surface,
        call("GET", &route, Some(at.clone()), &n("absent")),
    );
    go(f, surface, call("PUT", &route, Some(at.clone()), &n("add")));
    go(
        f,
        surface,
        call("PUT", &route, Some(at.clone()), &n("add_again")),
    );
    go(
        f,
        surface,
        call("GET", &route, Some(at.clone()), &n("present")),
    );
    go(
        f,
        surface,
        call("PUT", &route, Some(ep.clone()), &n("add_episode")),
    );
    go(
        f,
        surface,
        call(
            "PUT",
            &route,
            Some(format!("{base}/no-such-item")),
            &n("add_missing"),
        ),
    );
    if surface == ApiV2 {
        let member = format!("{route}/membership");
        go(
            f,
            surface,
            call(
                "GET",
                &member,
                Some(format!("{at}/membership")),
                &n("member"),
            ),
        );
        go(
            f,
            surface,
            call(
                "GET",
                &member,
                Some(format!("{base}/{SERIES}/membership")),
                &n("not_member"),
            ),
        );
    }
    go(
        f,
        surface,
        call("DELETE", &route, Some(at.clone()), &n("remove")),
    );
    go(
        f,
        surface,
        call("DELETE", &route, Some(at), &n("remove_again")),
    );
    go(
        f,
        surface,
        call("DELETE", &route, Some(ep), &n("remove_episode")),
    );
}

fn ratings_flow(f: &mut Flows, surface: Surface, root: &str, base: &str) {
    let route = format!("{base}/{{item_id}}");
    let at = format!("{base}/{MOVIE}");
    go(
        f,
        surface,
        call("GET", &route, Some(at.clone()), "rating_absent"),
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"rating\":4}"),
            ..call("PUT", &route, Some(at.clone()), "rating_set")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"rating\":9}"),
            ..call("PUT", &route, Some(at.clone()), "rating_range")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"rating\":3}"),
            ..call(
                "PUT",
                &route,
                Some(format!("{base}/no-such-item")),
                "rating_missing",
            )
        },
    );
    go(
        f,
        surface,
        call("GET", &route, Some(at.clone()), "rating_get"),
    );
    go(f, surface, call("GET", root, None, "rating_list"));
    go(
        f,
        surface,
        call("DELETE", &route, Some(at), "rating_delete"),
    );
}

fn progress_flow(f: &mut Flows) {
    let sync = |f: &mut Flows, surface: Surface, route: &str, name: &str, body: &str| {
        go(
            f,
            surface,
            Call {
                body: Some(Box::leak(body.to_owned().into_boxed_str())),
                ..call(
                    "POST",
                    route,
                    None,
                    Box::leak(name.to_owned().into_boxed_str()),
                )
            },
        );
    };
    let v1 = "/api/v1/sync/progress";
    sync(f, ApiV1, v1, "sync", "{\"items\":[{\"media_item_id\":\"movie-tmdb-9000001\",\"position\":600,\"duration\":3000},{\"media_item_id\":\"episode-tvdb-9000003-1-1\",\"position\":2900,\"duration\":3000},{\"media_item_id\":\"movie-tmdb-9000002\",\"position\":1,\"duration\":3000},{\"media_item_id\":\"\",\"position\":1},{\"media_item_id\":\"movie-tmdb-9000002\",\"position\":700,\"duration\":3000,\"updated_at\":\"nonsense\"}]}");
    sync(f, ApiV1, v1, "sync_force", "{\"items\":[{\"media_item_id\":\"movie-tmdb-9000001\",\"position\":300,\"duration\":3000,\"force_overwrite\":true},{\"media_item_id\":\"movie-tmdb-9000002\",\"position\":700,\"duration\":3000,\"updated_at\":\"2026-01-02T03:04:05Z\"}]}");
    sync(f, ApiV1, v1, "sync_empty", "{\"items\":[]}");
    sync(f, ApiV1, v1, "sync_bad", "[");
    let list = "/api/v1/progress/";
    go(f, ApiV1, call("GET", list, None, "progress"));
    go(
        f,
        ApiV1,
        call(
            "GET",
            list,
            Some(format!("{list}?status=in_progress&limit=1")),
            "progress_status",
        ),
    );
    go(
        f,
        ApiV1,
        call(
            "GET",
            list,
            Some(format!("{list}?library_id=1")),
            "progress_library",
        ),
    );
    go(
        f,
        ApiV1,
        call(
            "GET",
            list,
            Some(format!("{list}?library_id=x")),
            "progress_bad_library",
        ),
    );
    let v2 = "/api/v2/sync/progress";
    sync(f, ApiV2, v2, "sync", "{\"items\":[{\"client_ref\":\"a\",\"media_item_id\":\"movie-tmdb-9000001\",\"position_ms\":600000,\"duration_ms\":3000000},{\"media_item_id\":\"episode-tvdb-9000003-1-2\",\"position_ms\":600000,\"duration_ms\":3000000},{\"media_item_id\":\"no-such-item\",\"position_ms\":1,\"duration_ms\":2}]}");
    sync(f, ApiV2, v2, "sync_dupe", "{\"items\":[{\"media_item_id\":\"movie-tmdb-9000001\",\"position_ms\":1,\"duration_ms\":0},{\"media_item_id\":\"movie-tmdb-9000001\",\"position_ms\":2,\"duration_ms\":0}]}");
    let list = "/api/v2/progress";
    go(f, ApiV2, call("GET", list, None, "progress"));
    go(
        f,
        ApiV2,
        call(
            "GET",
            list,
            Some(format!("{list}?status=in_progress&library_id=1")),
            "progress_filter",
        ),
    );
    go(
        f,
        ApiV2,
        call(
            "GET",
            list,
            Some(format!("{list}?library_id=x")),
            "progress_bad_library",
        ),
    );
}

fn dismissal_flow(f: &mut Flows, surface: Surface, base: &str) {
    let route = format!("{base}/{{surface}}/{{item_id}}");
    let cw = format!("{base}/continue_watching/{MOVIE}");
    let up = format!("{base}/next_up/{MOVIE}");
    let ep = format!("{base}/continue_watching/{EPISODE}");
    go(
        f,
        surface,
        Call {
            body: Some("{}"),
            ..call("PUT", &route, Some(cw.clone()), "dismiss_no_stamp")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"progress_updated_at\":\"2026-01-02T03:04:05Z\"}"),
            ..call("PUT", &route, Some(cw.clone()), "dismiss")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"series_id\":\"series-tvdb-9000003\"}"),
            ..call("PUT", &route, Some(up.clone()), "dismiss_next_up")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"progress_updated_at\":\"2026-01-02T03:04:05Z\"}"),
            ..call("PUT", &route, Some(ep.clone()), "dismiss_episode")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{}"),
            ..call(
                "PUT",
                &route,
                Some(format!("{base}/bogus/{MOVIE}")),
                "dismiss_bad_surface",
            )
        },
    );
    go(
        f,
        surface,
        call("DELETE", &route, Some(ep), "undismiss_episode"),
    );
    go(
        f,
        surface,
        call("DELETE", &route, Some(up), "undismiss_next_up"),
    );
    go(f, surface, call("DELETE", &route, Some(cw), "undismiss"));
}

fn device_flow(f: &mut Flows) {
    // The devices are in the accounts seed: a sighting is throttled per process, so a repeat run registers none.
    go(f, ApiV1, call("GET", "/api/v1/devices/", None, "devices"));
    go(
        f,
        ApiV1,
        call(
            "GET",
            "/api/v1/devices/",
            Some("/api/v1/devices/?scope=household".to_owned()),
            "devices_household",
        ),
    );
    go(
        f,
        ApiV1,
        call(
            "DELETE",
            "/api/v1/devices/{device_id}/settings",
            Some("/api/v1/devices/conf-device-1/settings".to_owned()),
            "device_clear",
        ),
    );
    go(
        f,
        ApiV1,
        call(
            "DELETE",
            "/api/v1/devices/{device_id}",
            Some("/api/v1/devices/conf-device-2".to_owned()),
            "device_forget",
        ),
    );
    go(
        f,
        ApiV1,
        call(
            "DELETE",
            "/api/v1/devices/{device_id}",
            Some("/api/v1/devices/no-device".to_owned()),
            "device_forget_missing",
        ),
    );
    go(
        f,
        ApiV1,
        call(
            "DELETE",
            "/api/v1/devices/{device_id}/settings",
            Some("/api/v1/devices/no-device/settings".to_owned()),
            "device_clear_missing",
        ),
    );
    go(f, ApiV2, call("GET", "/api/v2/devices", None, "devices"));
    go(
        f,
        ApiV2,
        call(
            "GET",
            "/api/v2/devices",
            Some("/api/v2/devices?scope=household".to_owned()),
            "devices_household",
        ),
    );
    go(
        f,
        ApiV2,
        Call {
            body: Some("{\"custom_name\":\"  Den\\tTV \"}"),
            ..call(
                "PATCH",
                "/api/v2/devices/{device_id}",
                Some("/api/v2/devices/conf-admin-1".to_owned()),
                "device_rename",
            )
        },
    );
    go(
        f,
        ApiV2,
        Call {
            body: Some("{\"custom_name\":\"\\u200b\"}"),
            ..call(
                "PATCH",
                "/api/v2/devices/{device_id}",
                Some("/api/v2/devices/conf-admin-1".to_owned()),
                "device_rename_invisible",
            )
        },
    );
    go(
        f,
        ApiV2,
        Call {
            body: Some("{\"custom_name\":null}"),
            ..call(
                "PATCH",
                "/api/v2/devices/{device_id}",
                Some("/api/v2/devices/conf-admin-1".to_owned()),
                "device_rename_clear",
            )
        },
    );
    go(
        f,
        ApiV2,
        call(
            "DELETE",
            "/api/v2/devices/{device_id}/settings",
            Some("/api/v2/devices/conf-admin-1/settings".to_owned()),
            "device_clear",
        ),
    );
    go(
        f,
        ApiV2,
        call(
            "DELETE",
            "/api/v2/devices/{device_id}",
            Some("/api/v2/devices/conf-admin-2".to_owned()),
            "device_forget",
        ),
    );
    go(
        f,
        ApiV2,
        Call {
            body: Some("{\"custom_name\":\"Den\"}"),
            ..call(
                "PATCH",
                "/api/v2/devices/{device_id}",
                Some("/api/v2/devices/no-device".to_owned()),
                "device_rename_missing",
            )
        },
    );
    go(
        f,
        ApiV2,
        call(
            "DELETE",
            "/api/v2/devices/{device_id}",
            Some("/api/v2/devices/no-device".to_owned()),
            "device_forget_missing",
        ),
    );
    go(
        f,
        ApiV2,
        call(
            "DELETE",
            "/api/v2/devices/{device_id}/settings",
            Some("/api/v2/devices/no-device/settings".to_owned()),
            "device_clear_missing",
        ),
    );
}

/// The seeded kid profile (PG ceiling) on the user account, so every personal row binds the maturity filter.
fn kid(
    f: &mut Flows,
    surface: Surface,
    method: &str,
    route: &str,
    at: &str,
    name: &str,
    body: Option<&str>,
) {
    let v1 = surface == ApiV1;
    let name = format!("personal:kid:{}:{name}", if v1 { "v1" } else { "v2" });
    let (at, query) = at.split_once('?').unwrap_or((at, ""));
    let pairs: Vec<(&str, &str)> = query.split('&').filter_map(|p| p.split_once('=')).collect();
    f.step(Step {
        query: &pairs,
        identity: Identity::Kid,
        at: Some(at),
        body,
        profile: Some("${kid_profile_id}"),
        ..Step::new(surface, method, route, &name)
    });
}

fn kid_flow(f: &mut Flows) {
    for (surface, v) in [(ApiV1, "v1"), (ApiV2, "v2")] {
        // Progress first, so the listings below have rows to filter.
        let sync = format!("/api/{v}/sync/progress");
        let body = if surface == ApiV1 {
            format!("{{\"items\":[{{\"media_item_id\":\"{MOVIE}\",\"position\":600,\"duration\":3000}},{{\"media_item_id\":\"{ABOVE}\",\"position\":600,\"duration\":3000}},{{\"media_item_id\":\"{EPISODE}\",\"position\":60,\"duration\":3000}}]}}")
        } else {
            format!("{{\"items\":[{{\"media_item_id\":\"{MOVIE}\",\"position_ms\":700000,\"duration_ms\":3000000}},{{\"media_item_id\":\"{ABOVE}\",\"position_ms\":1,\"duration_ms\":2}},{{\"media_item_id\":\"{EPISODE}\",\"position_ms\":70000,\"duration_ms\":3000000}}]}}")
        };
        kid(f, surface, "POST", &sync, &sync, "sync", Some(&body));
        let list = if surface == ApiV1 {
            "/api/v1/progress/"
        } else {
            "/api/v2/progress"
        };
        kid(f, surface, "GET", list, list, "progress", None);
        kid(
            f,
            surface,
            "GET",
            list,
            &format!("{list}?library_id=1"),
            "progress_library",
            None,
        );
        if surface == ApiV2 {
            let route = "/api/v2/progress/{media_item_id}/position";
            for (id, name) in [(MOVIE, "clear_position"), (ABOVE, "clear_position_above")] {
                let at = format!("/api/v2/progress/{id}/position");
                kid(f, surface, "DELETE", route, &at, name, None);
            }
        }
        for (base, label) in [("favorites", "favorite"), ("watchlist", "watchlist")] {
            let route = format!("/api/{v}/{base}/{{item_id}}");
            let at = |id: &str| format!("/api/{v}/{base}/{id}");
            let n = |s: &str| format!("{label}_{s}");
            kid(f, surface, "PUT", &route, &at(MOVIE), &n("add"), None);
            kid(f, surface, "GET", &route, &at(MOVIE), &n("present"), None);
            kid(f, surface, "PUT", &route, &at(ABOVE), &n("add_above"), None);
            kid(f, surface, "GET", &route, &at(ABOVE), &n("get_above"), None);
            kid(
                f,
                surface,
                "PUT",
                &route,
                &at(EPISODE),
                &n("add_episode"),
                None,
            );
            if surface == ApiV2 {
                let member = format!("{route}/membership");
                kid(
                    f,
                    surface,
                    "GET",
                    &member,
                    &format!("{}/membership", at(MOVIE)),
                    &n("member"),
                    None,
                );
                kid(
                    f,
                    surface,
                    "GET",
                    &member,
                    &format!("{}/membership", at(ABOVE)),
                    &n("member_above"),
                    None,
                );
            }
            kid(f, surface, "DELETE", &route, &at(MOVIE), &n("remove"), None);
            kid(
                f,
                surface,
                "DELETE",
                &route,
                &at(EPISODE),
                &n("remove_episode"),
                None,
            );
        }
        let route = format!("/api/{v}/ratings/{{item_id}}");
        let at = |id: &str| format!("/api/{v}/ratings/{id}");
        kid(
            f,
            surface,
            "PUT",
            &route,
            &at(MOVIE),
            "rating_set",
            Some("{\"rating\":4}"),
        );
        kid(
            f,
            surface,
            "PUT",
            &route,
            &at(ABOVE),
            "rating_above",
            Some("{\"rating\":4}"),
        );
        kid(f, surface, "GET", &route, &at(MOVIE), "rating_get", None);
        let root = if surface == ApiV1 {
            "/api/v1/ratings/"
        } else {
            "/api/v2/ratings"
        };
        kid(f, surface, "GET", root, root, "rating_list", None);
        kid(
            f,
            surface,
            "DELETE",
            &route,
            &at(MOVIE),
            "rating_delete",
            None,
        );
        let route = format!("/api/{v}/home/dismissals/{{surface}}/{{item_id}}");
        let at = |id: &str| format!("/api/{v}/home/dismissals/continue_watching/{id}");
        let stamp = Some("{\"progress_updated_at\":\"2026-01-02T03:04:05Z\"}");
        kid(
            f,
            surface,
            "PUT",
            &route,
            &at(EPISODE),
            "dismiss_episode",
            stamp,
        );
        kid(f, surface, "PUT", &route, &at(MOVIE), "dismiss", stamp);
        kid(
            f,
            surface,
            "PUT",
            &route,
            &at(ABOVE),
            "dismiss_above",
            stamp,
        );
        kid(
            f,
            surface,
            "DELETE",
            &route,
            &at(EPISODE),
            "undismiss_episode",
            None,
        );
        let devices = if surface == ApiV1 {
            "/api/v1/devices/"
        } else {
            "/api/v2/devices"
        };
        kid(f, surface, "GET", devices, devices, "devices", None);
    }
}

pub(crate) fn add(b: &mut Builder) {
    let mut flows = Flows {
        b,
        seq: 0,
        prefix: "xflow",
    };
    let f = &mut flows;
    ratings_flow(f, ApiV1, "/api/v1/ratings/", "/api/v1/ratings");
    ratings_flow(f, ApiV2, "/api/v2/ratings", "/api/v2/ratings");
    list_flow(f, ApiV1, "/api/v1/favorites", "favorite");
    list_flow(f, ApiV2, "/api/v2/favorites", "favorite");
    list_flow(f, ApiV1, "/api/v1/watchlist", "watchlist");
    list_flow(f, ApiV2, "/api/v2/watchlist", "watchlist");
    progress_flow(f);
    dismissal_flow(f, ApiV1, "/api/v1/home/dismissals");
    dismissal_flow(f, ApiV2, "/api/v2/home/dismissals");
    device_flow(f);
    kid_flow(f);
    go(
        f,
        ApiV2,
        call(
            "GET",
            "/api/v2/capabilities/personal-lists",
            None,
            "cap_lists",
        ),
    );
    go(
        f,
        ApiV2,
        call(
            "GET",
            "/api/v2/capabilities/not-interested",
            None,
            "cap_not_interested",
        ),
    );
    go(
        f,
        ApiV2,
        call("GET", "/api/v2/progress/capabilities", None, "cap_progress"),
    );
    go(
        f,
        ApiV2,
        call("GET", "/api/v2/home/capabilities", None, "cap_home"),
    );
}
