//! Success paths for personal collection membership, orders, sort preferences, and groups. A collection is
//! made through the create row, so each later step addresses what that side was given.

use crate::auth_flows::{Flows, Step};
use crate::model::*;
use crate::plan::Builder;
use Surface::{ApiV1, ApiV2};

const MOVIE: &str = "movie-tmdb-9000001";
const SERIES: &str = "series-tvdb-9000003";

struct Call<'a> {
    method: &'a str,
    route: &'a str,
    at: Option<String>,
    name: &'a str,
    body: Option<&'a str>,
    capture: &'a [(&'a str, &'a str)],
    headers: &'a [(&'a str, &'a str)],
    query: &'a [(&'a str, &'a str)],
}

fn call<'a>(method: &'a str, route: &'a str, name: &'a str) -> Call<'a> {
    Call {
        method,
        route,
        at: None,
        name,
        body: None,
        capture: &[],
        headers: &[],
        query: &[],
    }
}

fn go(f: &mut Flows, surface: Surface, c: Call) {
    let v1 = surface == ApiV1;
    let name = format!("collections:{}:{}", if v1 { "v1" } else { "v2" }, c.name);
    f.step(Step {
        identity: if v1 { Identity::User } else { Identity::Admin },
        at: c.at.as_deref(),
        body: c.body,
        capture: c.capture,
        headers: c.headers,
        query: c.query,
        profile: Some(if v1 {
            "${user_profile_id}"
        } else {
            "${admin_profile_id}"
        }),
        ..Step::new(surface, c.method, c.route, &name)
    });
}

fn membership(f: &mut Flows, surface: Surface, root: &str, tag: &'static str) {
    let v1 = surface == ApiV1;
    let (first, second) = if v1 {
        ("flow_cola_vone", "flow_colb_vone")
    } else {
        ("flow_cola_vtwo", "flow_colb_vtwo")
    };
    let create_route = if v1 {
        format!("{root}/")
    } else {
        root.to_owned()
    };
    let cap1: Vec<(&str, &str)> = vec![(first, "/id")];
    let cap2: Vec<(&str, &str)> = vec![(second, "/id")];
    go(
        f,
        surface,
        Call {
            body: Some("{\"name\":\"Flow one\"}"),
            capture: &cap1,
            ..call("POST", &create_route, "create_first")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"name\":\"Flow two\",\"is_shared\":true}"),
            capture: &cap2,
            ..call("POST", &create_route, "create_second")
        },
    );
    let item_route = format!("{root}/{{id}}/items/{{item_id}}");
    let add = |f: &mut Flows, name: &str, id: &str, item: &str, body: &str| {
        go(
            f,
            surface,
            Call {
                at: Some(format!("{root}/${{{id}}}/items/{item}")),
                body: Some(body),
                ..call("PUT", &item_route, name)
            },
        );
    };
    add(f, "add_movie", first, MOVIE, "{\"position\":0}");
    add(f, "add_series", first, SERIES, "{\"position\":1}");
    add(f, "add_again", first, MOVIE, "{\"position\":9}");
    add(
        f,
        "add_missing_item",
        first,
        "movie-tmdb-404",
        "{\"position\":2}",
    );
    add(f, "add_to_missing", "flow_none", MOVIE, "{\"position\":0}");
    let order_route = format!("{root}/{{id}}/items/order");
    let order_at = format!("{root}/${{{first}}}/items/order");
    if !v1 {
        go(
            f,
            surface,
            Call {
                at: Some(order_at.clone()),
                ..call("GET", &order_route, "items_order")
            },
        );
    }
    let items_body = format!("{{\"ordered_ids\":[\"{SERIES}\",\"{MOVIE}\"]}}");
    let star: &[(&str, &str)] = &[("If-Match", "*")];
    go(
        f,
        surface,
        Call {
            at: Some(order_at.clone()),
            body: Some(&items_body),
            headers: if v1 { &[] } else { star },
            ..call("PUT", &order_route, "items_reorder")
        },
    );
    go(
        f,
        surface,
        Call {
            at: Some(order_at.clone()),
            body: Some("{\"ordered_ids\":[\"movie-tmdb-404\"]}"),
            headers: if v1 { &[] } else { star },
            ..call("PUT", &order_route, "items_reorder_mismatch")
        },
    );
    let duplicates = format!("{{\"ordered_ids\":[\"{MOVIE}\",\"{MOVIE}\"]}}");
    go(
        f,
        surface,
        Call {
            at: Some(order_at),
            body: Some(&duplicates),
            headers: if v1 { &[] } else { star },
            ..call("PUT", &order_route, "items_reorder_duplicates")
        },
    );
    if v1 {
        go(
            f,
            surface,
            Call {
                at: Some(format!("{root}/${{{first}}}/items")),
                ..call("GET", &format!("{root}/{{id}}/items"), "items_list")
            },
        );
    }
    go(
        f,
        surface,
        Call {
            at: Some(format!("{root}/${{{first}}}/items/{MOVIE}")),
            ..call("DELETE", &item_route, "remove_movie")
        },
    );
    // Sort preferences.
    let pref = format!("{root}/sort-preference");
    let user_kind = format!(
        "{{\"collection_kind\":\"user\",\"collection_id\":\"${{{first}}}\",\"field\":\"title\",\"order\":\"desc\"}}"
    );
    for (name, body) in [
        ("sort_user", user_kind.as_str()),
        ("sort_watchlist", "{\"collection_kind\":\"watchlist\",\"field\":\"year\",\"order\":\"\"}"),
        ("sort_empty_field", "{\"collection_kind\":\"favorites\",\"field\":\"\",\"order\":\"\"}"),
        ("sort_personal_field", "{\"collection_kind\":\"favorites\",\"field\":\"plays\",\"order\":\"\"}"),
        ("sort_missing", "{\"collection_kind\":\"user\",\"collection_id\":\"nope\",\"field\":\"title\",\"order\":\"\"}"),
        ("sort_library_missing", "{\"collection_kind\":\"library\",\"collection_id\":\"nope\",\"field\":\"plays\",\"order\":\"\"}"),
    ] {
        go(
            f,
            surface,
            Call {
                body: Some(body),
                ..call("PUT", &pref, name)
            },
        );
    }
    go(
        f,
        surface,
        Call {
            query: &[("collection_kind", "watchlist")],
            ..call("DELETE", &pref, "sort_clear")
        },
    );
    if v1 {
        go(
            f,
            surface,
            Call {
                query: &[("collection_kind", "bad")],
                ..call("DELETE", &pref, "sort_clear_bad")
            },
        );
    }
    // The profile's order.
    let order = format!("{root}/order");
    if !v1 {
        go(f, surface, call("GET", &order, "order"));
        go(
            f,
            surface,
            Call {
                query: &[("group_id", "g1")],
                ..call("GET", &order, "order_grouped")
            },
        );
    }
    let new_order = format!("{{\"ordered_ids\":[\"${{{second}}}\",\"${{{first}}}\"]}}");
    go(
        f,
        surface,
        Call {
            body: Some(&new_order),
            headers: if v1 { &[] } else { star },
            ..call("PUT", &order, "reorder")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"ordered_ids\":[]}"),
            headers: if v1 { &[] } else { star },
            ..call("PUT", &order, "reorder_mismatch")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"ordered_ids\":[\"a\",\"a\"]}"),
            headers: if v1 { &[] } else { star },
            ..call("PUT", &order, "reorder_duplicates")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"ordered_ids\":[],\"group_id\":\"g1\"}"),
            ..call("PUT", &order, "reorder_grouped")
        },
    );
    // Groups were removed, and each operation says so.
    let groups = format!("{root}/groups");
    go(
        f,
        surface,
        Call {
            body: Some("{\"name\":\"G\"}"),
            ..call("POST", &groups, "group_create")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"name\":\"  \"}"),
            ..call("POST", &groups, "group_create_blank")
        },
    );
    let group_order = format!("{groups}/order");
    go(
        f,
        surface,
        Call {
            body: Some("{\"ordered_ids\":[]}"),
            ..call("PUT", &group_order, "group_reorder")
        },
    );
    let group = format!("{groups}/{{id}}");
    let group_at = format!("{groups}/g1");
    go(
        f,
        surface,
        Call {
            at: Some(group_at.clone()),
            ..call("DELETE", &group, "group_delete")
        },
    );
    if v1 {
        go(
            f,
            surface,
            Call {
                at: Some(group_at),
                body: Some("{\"name\":\"\"}"),
                ..call("PUT", &group, "group_update_blank")
            },
        );
        go(
            f,
            surface,
            Call {
                at: Some(format!("{groups}/g1")),
                body: Some("{\"name\":\"N\"}"),
                ..call("PUT", &group, "group_update")
            },
        );
    } else {
        go(f, surface, call("GET", &group_order, "group_order"));
        go(
            f,
            surface,
            Call {
                at: Some(group_at.clone()),
                ..call("GET", &group, "group_read")
            },
        );
        go(
            f,
            surface,
            Call {
                at: Some(group_at),
                body: Some("{\"name\":\"N\"}"),
                ..call("PATCH", &group, "group_update")
            },
        );
    }
    let _ = tag;
}

/// A profile holding only what this flow creates, so its whole order can be named.
fn own_order(f: &mut Flows) {
    // A new profile, because the plan's own create cases give the seeded ones collections.
    f.step(Step {
        identity: Identity::User,
        profile: Some("${user_profile_id}"),
        body: Some("{\"name\":\"Flow orders\"}"),
        capture: &[("flow_order_profile", "/id")],
        ..Step::new(
            ApiV1,
            "POST",
            "/api/v1/profiles",
            "collections:v1:own_profile",
        )
    });
    let kid = Some("${flow_order_profile}");
    let make = |f: &mut Flows, surface, route, name: &str, capture: &[(&str, &str)]| {
        f.step(Step {
            identity: Identity::User,
            profile: kid,
            body: Some("{\"name\":\"Own\"}"),
            capture,
            ..Step::new(surface, "POST", route, name)
        });
    };
    make(
        f,
        ApiV1,
        "/api/v1/collections/",
        "collections:v1:own_create",
        &[("flow_own_vone", "/id")],
    );
    f.step(Step {
        identity: Identity::User,
        profile: kid,
        body: Some("{\"ordered_ids\":[\"${flow_own_vone}\"]}"),
        ..Step::new(
            ApiV1,
            "PUT",
            "/api/v1/collections/order",
            "collections:v1:own_reorder",
        )
    });
    make(
        f,
        ApiV2,
        "/api/v2/collections",
        "collections:v2:own_create",
        &[("flow_own_vtwo", "/id")],
    );
    f.step(Step {
        identity: Identity::User,
        profile: kid,
        headers: &[("If-Match", "*")],
        body: Some("{\"ordered_ids\":[\"${flow_own_vtwo}\",\"${flow_own_vone}\"]}"),
        ..Step::new(
            ApiV2,
            "PUT",
            "/api/v2/collections/order",
            "collections:v2:own_reorder",
        )
    });
}

fn admin_groups(f: &mut Flows) {
    let admin = |route,
                 name,
                 at: Option<&'static str>,
                 capture: &'static [(&'static str, &'static str)]| Step {
        identity: Identity::Admin,
        profile: Some("${admin_profile_id}"),
        at,
        capture,
        ..Step::new(ApiV2, "GET", route, name)
    };
    f.step(admin(
        "/api/v2/admin/libraries/{library_id}/collection-groups",
        "collections:v2:admin_groups",
        None,
        &[("flow_admin_group", "/items/0/id")],
    ));
    f.step(admin(
        "/api/v2/admin/libraries/{library_id}/collection-groups/order",
        "collections:v2:admin_group_order",
        None,
        &[],
    ));
    f.step(admin(
        "/api/v2/admin/collection-groups/{id}",
        "collections:v2:admin_group",
        Some("/api/v2/admin/collection-groups/${flow_admin_group}"),
        &[],
    ));
    f.step(admin(
        "/api/v2/admin/collection-groups/{id}",
        "collections:v2:admin_group_missing",
        Some("/api/v2/admin/collection-groups/nope"),
        &[],
    ));
    f.step(Step {
        identity: Identity::Admin,
        profile: Some("${admin_profile_id}"),
        ..Step::new(
            ApiV1,
            "GET",
            "/api/v1/admin/libraries/{libraryID}/collection-groups/",
            "collections:v1:admin_groups",
        )
    });
}

pub(crate) fn add(b: &mut Builder) {
    let mut flows = Flows {
        b,
        seq: 0,
        prefix: "yflow",
    };
    let f = &mut flows;
    own_order(f);
    admin_groups(f);
    membership(f, ApiV1, "/api/v1/collections", "v1");
    membership(f, ApiV2, "/api/v2/collections", "v2");
    go(
        f,
        ApiV1,
        call("GET", "/api/v1/collections/capabilities", "capabilities"),
    );
    go(
        f,
        ApiV1,
        call("GET", "/api/v1/collections/templates", "templates"),
    );
    go(
        f,
        ApiV2,
        call("GET", "/api/v2/collections/capabilities", "capabilities"),
    );
    go(
        f,
        ApiV2,
        call("GET", "/api/v2/collections/templates", "templates"),
    );
    go(
        f,
        ApiV2,
        call(
            "GET",
            "/api/v2/admin/collections/templates",
            "admin_templates",
        ),
    );
    go(
        f,
        ApiV2,
        call(
            "GET",
            "/api/v2/admin/collections/template-bundles",
            "admin_bundles",
        ),
    );
    for (route, name) in [
        (
            "/api/v1/admin/collections/templates",
            "collections:v1:admin_templates",
        ),
        (
            "/api/v1/admin/collections/template-bundles",
            "collections:v1:admin_bundles",
        ),
    ] {
        f.step(Step {
            identity: Identity::Admin,
            profile: Some("${admin_profile_id}"),
            ..Step::new(ApiV1, "GET", route, name)
        });
    }
}
