//! Success paths for reading and cancelling media requests, route administration, and server deletion. The
//! requests and servers come from the seed, because creating them needs TMDB or a plugin.

use crate::auth_flows::{Flows, Step};
use crate::model::*;
use crate::plan::Builder;
use Surface::{ApiV1, ApiV2};

#[derive(Default)]
struct Call<'a> {
    at: Option<&'a str>,
    body: Option<&'a str>,
    capture: &'a [(&'a str, &'a str)],
    headers: &'a [(&'a str, &'a str)],
    query: &'a [(&'a str, &'a str)],
    admin: bool,
}

fn go(f: &mut Flows, surface: Surface, method: &str, route: &str, name: &str, c: Call) {
    let v1 = surface == ApiV1;
    let name = format!("requests:{}:{name}", if v1 { "v1" } else { "v2" });
    f.step(Step {
        identity: if c.admin {
            Identity::Admin
        } else {
            Identity::User
        },
        at: c.at,
        body: c.body,
        capture: c.capture,
        headers: c.headers,
        query: c.query,
        profile: Some(if c.admin {
            "${admin_profile_id}"
        } else {
            "${user_profile_id}"
        }),
        ..Step::new(surface, method, route, &name)
    });
}

fn user<'a>() -> Call<'a> {
    Call::default()
}

fn admin<'a>() -> Call<'a> {
    Call {
        admin: true,
        ..Call::default()
    }
}

fn v1(f: &mut Flows) {
    let mine = "/api/v1/requests/mine";
    go(f, ApiV1, "GET", mine, "mine", user());
    let c = Call {
        query: &[("status", "pending"), ("limit", "2"), ("offset", "1")],
        ..user()
    };
    go(f, ApiV1, "GET", mine, "mine_filtered", c);
    go(
        f,
        ApiV1,
        "GET",
        mine,
        "mine_none",
        Call {
            query: &[("status", "nope")],
            ..user()
        },
    );
    go(f, ApiV1, "GET", "/api/v1/requests/status", "status", user());
    let one = "/api/v1/requests/{id}";
    for (name, id) in [
        ("get", "conf-req-pending"),
        ("get_series", "conf-req-series"),
        ("get_queued", "conf-req-queued"),
    ] {
        let at = format!("/api/v1/requests/{id}");
        go(
            f,
            ApiV1,
            "GET",
            one,
            name,
            Call {
                at: Some(&at),
                ..user()
            },
        );
    }
    let c = Call {
        at: Some("/api/v1/requests/conf-req-admin-vtwo"),
        ..user()
    };
    go(f, ApiV1, "GET", one, "get_forbidden", c);
    go(
        f,
        ApiV1,
        "GET",
        one,
        "get_missing",
        Call {
            at: Some("/api/v1/requests/none"),
            ..user()
        },
    );
    let cancel = "/api/v1/requests/{id}/cancel";
    let at = Some("/api/v1/requests/conf-req-cancel-vone/cancel");
    go(
        f,
        ApiV1,
        "POST",
        cancel,
        "cancel",
        Call {
            at,
            body: Some(r#"{"reason":" changed my mind "}"#),
            ..user()
        },
    );
    go(
        f,
        ApiV1,
        "POST",
        cancel,
        "cancel_again",
        Call { at, ..user() },
    );
    go(
        f,
        ApiV1,
        "POST",
        cancel,
        "cancel_bad_body",
        Call {
            at,
            body: Some("{"),
            ..user()
        },
    );
    let c = Call {
        at: Some("/api/v1/requests/conf-req-admin-vtwo/cancel"),
        ..user()
    };
    go(f, ApiV1, "POST", cancel, "cancel_forbidden", c);
    let list = "/api/v1/admin/requests";
    go(f, ApiV1, "GET", list, "admin_list", admin());
    go(
        f,
        ApiV1,
        "GET",
        list,
        "admin_list_filtered",
        Call {
            query: &[("outcome", "failed")],
            ..admin()
        },
    );
    let c = Call {
        at: Some("/api/v1/admin/requests/conf-req-admin-vone/cancel"),
        ..admin()
    };
    go(
        f,
        ApiV1,
        "POST",
        "/api/v1/admin/requests/{id}/cancel",
        "admin_cancel",
        c,
    );
    let c = Call {
        at: Some("/api/v1/admin/requests/conf-req-failed/cancel"),
        ..admin()
    };
    go(
        f,
        ApiV1,
        "POST",
        "/api/v1/admin/requests/{id}/cancel",
        "admin_cancel_failed_refused",
        c,
    );
    go(
        f,
        ApiV1,
        "GET",
        "/api/v1/admin/request-integrations",
        "integrations",
        admin(),
    );
    let del = "/api/v1/admin/request-integrations/{id}";
    let c = Call {
        at: Some("/api/v1/admin/request-integrations/conf-drop-vone"),
        ..admin()
    };
    go(f, ApiV1, "DELETE", del, "integration_delete", c);
    let c = Call {
        at: Some("/api/v1/admin/request-integrations/conf-drop-vone"),
        ..admin()
    };
    go(f, ApiV1, "DELETE", del, "integration_delete_missing", c);
}

fn v2_requests(f: &mut Flows) {
    let mine = "/api/v2/requests/mine";
    go(f, ApiV2, "GET", mine, "mine", user());
    let c = Call {
        query: &[("limit", "1")],
        capture: &[("flow_req_cursor", "/page/next_cursor")],
        ..user()
    };
    go(f, ApiV2, "GET", mine, "mine_page", c);
    let c = Call {
        query: &[("limit", "1"), ("cursor", "${flow_req_cursor}")],
        ..user()
    };
    go(f, ApiV2, "GET", mine, "mine_next", c);
    go(
        f,
        ApiV2,
        "GET",
        mine,
        "mine_bad_cursor",
        Call {
            query: &[("cursor", "nope")],
            ..user()
        },
    );
    go(
        f,
        ApiV2,
        "GET",
        mine,
        "mine_outcome",
        Call {
            query: &[("outcome", "declined")],
            ..user()
        },
    );
    go(f, ApiV2, "GET", "/api/v2/requests/status", "status", user());
    let one = "/api/v2/requests/{id}";
    for (name, id, is_admin) in [
        ("get", "conf-req-pending", false),
        ("get_series", "conf-req-series", false),
        ("get_queued_user", "conf-req-queued", false),
        ("get_queued_admin", "conf-req-queued", true),
        ("get_failed_admin", "conf-req-failed", true),
        ("get_forbidden", "conf-req-admin-vtwo", false),
    ] {
        let at = format!("/api/v2/requests/{id}");
        go(
            f,
            ApiV2,
            "GET",
            one,
            name,
            Call {
                at: Some(&at),
                admin: is_admin,
                ..user()
            },
        );
    }
    let cancel = "/api/v2/requests/{id}/cancel";
    let at = Some("/api/v2/requests/conf-req-cancel-vtwo/cancel");
    go(
        f,
        ApiV2,
        "POST",
        cancel,
        "cancel",
        Call {
            at,
            body: Some(r#"{"reason":"later"}"#),
            ..user()
        },
    );
    go(
        f,
        ApiV2,
        "POST",
        cancel,
        "cancel_again",
        Call {
            at,
            body: Some("{}"),
            ..user()
        },
    );
    let follow = "/api/v2/requests/follows/{media_type}/{tmdb_id}";
    let at = Some("/api/v2/requests/follows/movie/9100001");
    go(
        f,
        ApiV2,
        "DELETE",
        follow,
        "unfollow",
        Call { at, ..user() },
    );
    go(
        f,
        ApiV2,
        "DELETE",
        follow,
        "unfollow_again",
        Call { at, ..user() },
    );
}

fn v2_admin(f: &mut Flows) {
    let list = "/api/v2/admin/requests";
    go(f, ApiV2, "GET", list, "admin_list", admin());
    for (name, query) in [
        ("admin_view", &[("view", "needs_approval")][..]),
        ("admin_done", &[("view", "done")][..]),
        ("admin_q", &[("q", "50%")][..]),
        ("admin_tmdb", &[("q", "9100002")][..]),
        ("admin_type", &[("media_type", "series")][..]),
        ("admin_by", &[("requested_by_user_id", "1")][..]),
        (
            "admin_by_range",
            &[("requested_by_user_id", "9999999999")][..],
        ),
    ] {
        go(f, ApiV2, "GET", list, name, Call { query, ..admin() });
    }
    let c = Call {
        query: &[("limit", "2")],
        capture: &[("flow_adm_cursor", "/page/next_cursor")],
        ..admin()
    };
    go(f, ApiV2, "GET", list, "admin_page", c);
    let c = Call {
        query: &[("limit", "2"), ("cursor", "${flow_adm_cursor}")],
        ..admin()
    };
    go(f, ApiV2, "GET", list, "admin_next", c);
    go(
        f,
        ApiV2,
        "GET",
        "/api/v2/admin/requests/capabilities",
        "capabilities",
        admin(),
    );
    go(
        f,
        ApiV2,
        "GET",
        "/api/v2/admin/requests/counts",
        "counts",
        admin(),
    );
    let events = "/api/v2/admin/requests/{id}/events";
    for (name, id) in [
        ("events", "conf-req-series"),
        ("events_after_cancel", "conf-req-cancel-vtwo"),
        ("events_missing", "none"),
    ] {
        let at = format!("/api/v2/admin/requests/{id}/events");
        go(
            f,
            ApiV2,
            "GET",
            events,
            name,
            Call {
                at: Some(&at),
                ..admin()
            },
        );
    }
    let cancel = "/api/v2/admin/requests/{id}/cancel";
    let c = Call {
        at: Some("/api/v2/admin/requests/conf-req-admin-vtwo/cancel"),
        body: Some(r#"{"reason":"dup"}"#),
        ..admin()
    };
    go(f, ApiV2, "POST", cancel, "admin_cancel", c);
    let c = Call {
        at: Some("/api/v2/admin/requests/conf-req-failed/cancel"),
        body: Some("{}"),
        ..admin()
    };
    go(f, ApiV2, "POST", cancel, "admin_close_failed", c);
    let c = Call {
        at: Some("/api/v2/admin/requests/conf-req-queued/cancel"),
        body: Some("{}"),
        ..admin()
    };
    go(f, ApiV2, "POST", cancel, "admin_cancel_sent_refused", c);
}

const FALLBACK: &str = r#"{"enabled":true,"conditions":{},"skip_uhd":false,"hd":{"integration_id":"conf-radarr"},"uhd":{}}"#;

fn v2_routes(f: &mut Flows) {
    let root = "/api/v2/admin/request-routes";
    let one = "/api/v2/admin/request-routes/{id}";
    go(f, ApiV2, "GET", root, "routes_empty", admin());
    let fallback = Some("/api/v2/admin/request-routes/fallback-movie");
    go(
        f,
        ApiV2,
        "GET",
        one,
        "route_unsaved",
        Call {
            at: fallback,
            ..admin()
        },
    );
    go(
        f,
        ApiV2,
        "GET",
        one,
        "route_missing",
        Call {
            at: Some("/api/v2/admin/request-routes/none"),
            ..admin()
        },
    );
    let rule = r#"{"media_type":"movie","name":"Anime","enabled":true,"conditions":{"anime":true,"genre_ids":[3,1,3],"original_languages":["ja"]},"hd":{"integration_id":"conf-radarr","overrides":{"root_folder":"/a","n":2.0}},"uhd":{},"skip_uhd":true}"#;
    let c = Call {
        body: Some(rule),
        ..admin()
    };
    go(f, ApiV2, "POST", root, "route_needs_fallback", c);
    let c = Call {
        at: fallback,
        headers: &[("If-Match", "*")],
        body: Some(
            r#"{"enabled":false,"conditions":{},"skip_uhd":false,"hd":{"integration_id":"conf-radarr"},"uhd":{"integration_id":"conf-sonarr"}}"#,
        ),
        ..admin()
    };
    go(f, ApiV2, "PUT", one, "fallback_wrong_kind", c);
    let c = Call {
        at: fallback,
        headers: &[("If-Match", "*")],
        body: Some(FALLBACK),
        ..admin()
    };
    go(f, ApiV2, "PUT", one, "fallback_save", c);
    let c = Call {
        at: fallback,
        body: Some(FALLBACK),
        ..admin()
    };
    go(f, ApiV2, "PUT", one, "fallback_no_precondition", c);
    let c = Call {
        at: fallback,
        headers: &[("If-Match", "\"stale\"")],
        body: Some(FALLBACK),
        ..admin()
    };
    go(f, ApiV2, "PUT", one, "fallback_stale", c);
    let c = Call {
        body: Some(rule),
        capture: &[("flow_route_a", "/id")],
        ..admin()
    };
    go(f, ApiV2, "POST", root, "route_create", c);
    let second = r#"{"media_type":"movie","name":"Old","enabled":true,"conditions":{"year_to":1980},"hd":{"integration_id":"conf-radarr"},"uhd":{},"skip_uhd":false}"#;
    let c = Call {
        body: Some(second),
        capture: &[("flow_route_b", "/id")],
        ..admin()
    };
    go(f, ApiV2, "POST", root, "route_create_second", c);
    for (name, body) in [
        (
            "route_bad_conditions",
            r#"{"media_type":"movie","name":"x","conditions":{"genre_ids":[-1],"year_from":1,"series_statuses":["ended"],"max_content_rating":"nope"},"hd":{"integration_id":"none"},"uhd":{},"enabled":true,"skip_uhd":false}"#,
        ),
        (
            "route_empty",
            r#"{"media_type":"movie","name":" ","enabled":true,"conditions":{},"hd":{},"uhd":{},"skip_uhd":false}"#,
        ),
        (
            "route_owned_override",
            r#"{"media_type":"movie","name":"x","conditions":{"year_to":1},"hd":{"integration_id":"conf-radarr","overrides":{"is_4k":true}},"uhd":{},"enabled":true,"skip_uhd":false}"#,
        ),
    ] {
        go(
            f,
            ApiV2,
            "POST",
            root,
            name,
            Call {
                body: Some(body),
                ..admin()
            },
        );
    }
    go(f, ApiV2, "GET", root, "routes_list", admin());
    let a = "/api/v2/admin/request-routes/${flow_route_a}";
    let b = "/api/v2/admin/request-routes/${flow_route_b}";
    go(
        f,
        ApiV2,
        "GET",
        one,
        "route_get",
        Call {
            at: Some(a),
            ..admin()
        },
    );
    let order = "/api/v2/admin/request-routes/order";
    let body = r#"{"media_type":"movie","ids":["${flow_route_b}","${flow_route_a}"]}"#;
    go(
        f,
        ApiV2,
        "POST",
        order,
        "routes_order",
        Call {
            body: Some(body),
            ..admin()
        },
    );
    let body = r#"{"media_type":"movie","ids":["none"]}"#;
    go(
        f,
        ApiV2,
        "POST",
        order,
        "routes_order_wrong",
        Call {
            body: Some(body),
            ..admin()
        },
    );
    let body = r#"{"media_type":"series","ids":[]}"#;
    go(
        f,
        ApiV2,
        "POST",
        order,
        "routes_order_series",
        Call {
            body: Some(body),
            ..admin()
        },
    );
    let body = r#"{"name":"Renamed","enabled":false,"conditions":{"company_ids":[7]},"hd":{},"uhd":{},"skip_uhd":true}"#;
    let c = Call {
        at: Some(a),
        headers: &[("If-Match", "*")],
        body: Some(body),
        ..admin()
    };
    go(f, ApiV2, "PUT", one, "route_update", c);
    let del = Call {
        at: Some(b),
        headers: &[("If-Match", "*")],
        ..admin()
    };
    go(f, ApiV2, "DELETE", one, "route_delete", del);
    let del = Call {
        at: Some(b),
        headers: &[("If-Match", "*")],
        ..admin()
    };
    go(f, ApiV2, "DELETE", one, "route_delete_missing", del);
    let del = Call {
        at: fallback,
        headers: &[("If-Match", "*")],
        ..admin()
    };
    go(f, ApiV2, "DELETE", one, "fallback_delete_refused", del);
}

fn v2_integrations(f: &mut Flows) {
    let root = "/api/v2/admin/request-integrations";
    let one = "/api/v2/admin/request-integrations/{id}";
    go(f, ApiV2, "GET", root, "integrations", admin());
    let c = Call {
        query: &[("limit", "1")],
        capture: &[("flow_int_cursor", "/page/next_cursor")],
        ..admin()
    };
    go(f, ApiV2, "GET", root, "integrations_page", c);
    let c = Call {
        query: &[("limit", "1"), ("cursor", "${flow_int_cursor}")],
        ..admin()
    };
    go(f, ApiV2, "GET", root, "integrations_next", c);
    let at = Some("/api/v2/admin/request-integrations/conf-radarr");
    go(f, ApiV2, "GET", one, "integration", Call { at, ..admin() });
    go(
        f,
        ApiV2,
        "GET",
        one,
        "integration_missing",
        Call {
            at: Some("/api/v2/admin/request-integrations/none"),
            ..admin()
        },
    );
    let c = Call {
        at,
        headers: &[("If-Match", "*")],
        ..admin()
    };
    go(f, ApiV2, "DELETE", one, "integration_routed_refused", c);
    let c = Call {
        at: Some("/api/v2/admin/request-integrations/conf-sonarr"),
        headers: &[("If-Match", "\"stale\"")],
        ..admin()
    };
    go(f, ApiV2, "DELETE", one, "integration_stale", c);
    let series = Some("/api/v2/admin/request-routes/fallback-series");
    let body = r#"{"enabled":true,"conditions":{},"skip_uhd":false,"hd":{"integration_id":"conf-sonarr"},"uhd":{}}"#;
    let c = Call {
        at: series,
        headers: &[("If-Match", "*")],
        body: Some(body),
        ..admin()
    };
    go(
        f,
        ApiV2,
        "PUT",
        "/api/v2/admin/request-routes/{id}",
        "fallback_series",
        c,
    );
    let body = r#"{"media_type":"series","name":"Ended","enabled":true,"conditions":{"series_statuses":["ended"]},"hd":{"integration_id":"conf-sonarr"},"uhd":{},"skip_uhd":false}"#;
    let c = Call {
        body: Some(body),
        capture: &[("flow_route_c", "/id")],
        ..admin()
    };
    go(
        f,
        ApiV2,
        "POST",
        "/api/v2/admin/request-routes",
        "route_series_rule",
        c,
    );
    let sonarr = Some("/api/v2/admin/request-integrations/conf-sonarr");
    let c = Call {
        at: sonarr,
        headers: &[("If-Match", "*")],
        ..admin()
    };
    go(f, ApiV2, "DELETE", one, "integration_rule_refused", c);
    let c = Call {
        at: Some("/api/v2/admin/request-routes/${flow_route_c}"),
        headers: &[("If-Match", "*")],
        ..admin()
    };
    go(
        f,
        ApiV2,
        "DELETE",
        "/api/v2/admin/request-routes/{id}",
        "route_series_rule_delete",
        c,
    );
    let c = Call {
        at: sonarr,
        headers: &[("If-Match", "*")],
        ..admin()
    };
    go(f, ApiV2, "DELETE", one, "integration_clears_fallback", c);
    let c = Call {
        at: Some("/api/v2/admin/request-integrations/conf-drop-vtwo"),
        headers: &[("If-Match", "*")],
        ..admin()
    };
    go(f, ApiV2, "DELETE", one, "integration_delete", c);
}

pub(crate) fn add(b: &mut Builder) {
    let mut flows = Flows {
        b,
        seq: 0,
        prefix: "yflow",
    };
    let f = &mut flows;
    v1(f);
    v2_requests(f);
    v2_admin(f);
    v2_routes(f);
    v2_integrations(f);
}
