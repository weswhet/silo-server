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

/// Manual membership of an administrator collection, made through the v1 create row.
fn admin_membership(f: &mut Flows) {
    let step = |surface: Surface,
                method: &'static str,
                route: &'static str,
                name: &'static str,
                at: Option<&'static str>,
                body: Option<&'static str>,
                capture: &'static [(&'static str, &'static str)]| Step {
        identity: Identity::Admin,
        profile: Some("${admin_profile_id}"),
        at,
        body,
        capture,
        ..Step::new(surface, method, route, name)
    };
    const V1_ITEM: &str = "/api/v1/admin/collections/{id}/items/{item_id}";
    const V2_ITEM: &str = "/api/v2/admin/collections/{id}/items/{item_id}";
    const V1_ORDER: &str = "/api/v1/admin/collections/{id}/items/order";
    f.step(step(
        ApiV1,
        "POST",
        "/api/v1/admin/collections/",
        "collections:v1:admin_create",
        None,
        Some("{\"library_id\":1,\"title\":\"Flow admin\",\"collection_type\":\"manual\"}"),
        &[("flow_admin_col", "/id")],
    ));
    type Row<'a> = (
        Surface,
        &'a str,
        &'a str,
        &'a str,
        Option<&'a str>,
        Option<&'a str>,
    );
    let rows: &[Row] = &[
        (
            ApiV1,
            "PUT",
            V1_ITEM,
            "collections:v1:admin_add_movie",
            Some("/api/v1/admin/collections/${flow_admin_col}/items/movie-tmdb-9000001"),
            Some("{\"position\":0}"),
        ),
        (
            ApiV1,
            "PUT",
            V1_ITEM,
            "collections:v1:admin_add_empty_body",
            Some("/api/v1/admin/collections/${flow_admin_col}/items/movie-tmdb-9000002"),
            None,
        ),
        (
            ApiV1,
            "PUT",
            V1_ITEM,
            "collections:v1:admin_add_bad_body",
            Some("/api/v1/admin/collections/${flow_admin_col}/items/movie-tmdb-9000002"),
            Some("{"),
        ),
        (
            ApiV1,
            "PUT",
            V1_ITEM,
            "collections:v1:admin_add_missing",
            Some("/api/v1/admin/collections/nope/items/movie-tmdb-9000001"),
            Some("{}"),
        ),
        (
            ApiV1,
            "PUT",
            V1_ORDER,
            "collections:v1:admin_reorder",
            Some("/api/v1/admin/collections/${flow_admin_col}/items/order"),
            Some("{\"ordered_ids\":[\"movie-tmdb-9000002\",\"movie-tmdb-9000001\"]}"),
        ),
        (
            ApiV1,
            "PUT",
            V1_ORDER,
            "collections:v1:admin_reorder_mismatch",
            Some("/api/v1/admin/collections/${flow_admin_col}/items/order"),
            Some("{\"ordered_ids\":[\"movie-tmdb-9000002\"]}"),
        ),
        (
            ApiV1,
            "DELETE",
            V1_ITEM,
            "collections:v1:admin_remove_movie",
            Some("/api/v1/admin/collections/${flow_admin_col}/items/movie-tmdb-9000001"),
            None,
        ),
        (
            ApiV2,
            "PUT",
            V2_ITEM,
            "collections:v2:admin_add_other_library",
            Some("/api/v2/admin/collections/${flow_admin_col}/items/series-tvdb-9000003"),
            Some("{\"position\":0}"),
        ),
        (
            ApiV2,
            "PUT",
            V2_ITEM,
            "collections:v2:admin_add_movie",
            Some("/api/v2/admin/collections/${flow_admin_col}/items/movie-tmdb-9000001"),
            Some("{\"position\":3}"),
        ),
        (
            ApiV2,
            "PUT",
            V2_ITEM,
            "collections:v2:admin_add_missing",
            Some("/api/v2/admin/collections/nope/items/movie-tmdb-9000001"),
            Some("{\"position\":0}"),
        ),
        (
            ApiV2,
            "DELETE",
            V2_ITEM,
            "collections:v2:admin_remove_movie",
            Some("/api/v2/admin/collections/${flow_admin_col}/items/movie-tmdb-9000001"),
            None,
        ),
    ];
    for &(surface, method, route, name, at, body) in rows {
        f.step(step(surface, method, route, name, at, body, &[]));
    }
}

/// One step as `identity` with the profile header `profile`, named `collections:kid:<name>`.
#[allow(clippy::too_many_arguments)]
fn as_profile(
    f: &mut Flows,
    identity: Identity,
    profile: &str,
    surface: Surface,
    method: &str,
    route: &str,
    at: &str,
    name: &str,
    body: Option<&str>,
    capture: &[(&str, &str)],
) {
    let name = format!("collections:kid:{name}");
    f.step(Step {
        identity,
        profile: Some(profile),
        at: Some(at),
        body,
        capture,
        headers: if method == "PUT" && surface == ApiV2 {
            &[("If-Match", "*")]
        } else {
            &[]
        },
        ..Step::new(surface, method, route, &name)
    });
}

/// The seeded kid profile (PG ceiling) reading a shared collection that holds an R title, and the
/// primary profile reading the kid's shared collection through the owner's ceiling.
fn kid_collections(f: &mut Flows) {
    const ABOVE: &str = "movie-tmdb-9000002";
    #[allow(clippy::too_many_arguments)]
    fn user(
        f: &mut Flows,
        surface: Surface,
        method: &str,
        route: &str,
        at: &str,
        name: &str,
        body: Option<&str>,
        capture: &[(&str, &str)],
    ) {
        as_profile(
            f,
            Identity::User,
            "${user_profile_id}",
            surface,
            method,
            route,
            at,
            name,
            body,
            capture,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn kid(
        f: &mut Flows,
        surface: Surface,
        method: &str,
        route: &str,
        at: &str,
        name: &str,
        body: Option<&str>,
        capture: &[(&str, &str)],
    ) {
        as_profile(
            f,
            Identity::Kid,
            "${kid_profile_id}",
            surface,
            method,
            route,
            at,
            name,
            body,
            capture,
        )
    }
    let create = "/api/v1/collections/";
    let item = "/api/v1/collections/{id}/items/{item_id}";
    let items = "/api/v1/collections/{id}/items";
    let order = "/api/v2/collections/{id}/items/order";
    let position = Some("{\"position\":0}");
    user(
        f,
        ApiV1,
        "POST",
        create,
        create,
        "parent_create",
        Some("{\"name\":\"Mixed\",\"is_shared\":true}"),
        &[("flow_kid_mixed", "/id")],
    );
    for id in [MOVIE, ABOVE] {
        let at = format!("/api/v1/collections/${{flow_kid_mixed}}/items/{id}");
        user(
            f,
            ApiV1,
            "PUT",
            item,
            &at,
            &format!("parent_add_{id}"),
            position,
            &[],
        );
    }
    kid(
        f,
        ApiV1,
        "GET",
        items,
        "/api/v1/collections/${flow_kid_mixed}/items",
        "kid_reads_shared",
        None,
        &[],
    );
    kid(
        f,
        ApiV2,
        "GET",
        order,
        "/api/v2/collections/${flow_kid_mixed}/items/order",
        "kid_order_shared",
        None,
        &[],
    );
    kid(
        f,
        ApiV1,
        "POST",
        create,
        create,
        "kid_create",
        Some("{\"name\":\"Kid\",\"is_shared\":true}"),
        &[("flow_kid_own", "/id")],
    );
    for id in [MOVIE, ABOVE] {
        let at = format!("/api/v1/collections/${{flow_kid_own}}/items/{id}");
        kid(
            f,
            ApiV1,
            "PUT",
            item,
            &at,
            &format!("kid_add_{id}"),
            position,
            &[],
        );
    }
    // An R member, the way a later ceiling leaves one: another profile cannot add to the kid's collection, so
    // the parent lifts the kid's ceiling, the kid adds the R title, and the parent restores PG.
    let at = format!("/api/v1/collections/${{flow_kid_own}}/items/{ABOVE}");
    user(
        f,
        ApiV1,
        "PUT",
        item,
        &at,
        "parent_add_to_kid",
        position,
        &[],
    );
    let profile = "/api/v2/profiles/{id}";
    let kid_at = "/api/v2/profiles/${kid_profile_id}";
    user(
        f,
        ApiV2,
        "PATCH",
        profile,
        kid_at,
        "lift_ceiling",
        Some("{\"max_content_rating\":null}"),
        &[],
    );
    kid(
        f,
        ApiV1,
        "PUT",
        item,
        &at,
        "kid_add_above_unlimited",
        position,
        &[],
    );
    user(
        f,
        ApiV2,
        "PATCH",
        profile,
        kid_at,
        "restore_ceiling",
        Some("{\"max_content_rating\":\"PG\"}"),
        &[],
    );
    kid(
        f,
        ApiV1,
        "GET",
        items,
        "/api/v1/collections/${flow_kid_own}/items",
        "kid_reads_own",
        None,
        &[],
    );
    kid(
        f,
        ApiV2,
        "GET",
        order,
        "/api/v2/collections/${flow_kid_own}/items/order",
        "kid_order_own",
        None,
        &[],
    );
    user(
        f,
        ApiV1,
        "GET",
        items,
        "/api/v1/collections/${flow_kid_own}/items",
        "parent_reads_kid",
        None,
        &[],
    );
    user(
        f,
        ApiV2,
        "GET",
        order,
        "/api/v2/collections/${flow_kid_own}/items/order",
        "parent_order_kid",
        None,
        &[],
    );
    kid(
        f,
        ApiV2,
        "GET",
        "/api/v2/collections/order",
        "/api/v2/collections/order",
        "kid_order",
        None,
        &[],
    );
    let reorder = Some("{\"ordered_ids\":[\"${flow_kid_own}\"]}");
    kid(
        f,
        ApiV1,
        "PUT",
        "/api/v1/collections/order",
        "/api/v1/collections/order",
        "kid_reorder",
        reorder,
        &[],
    );
    kid(
        f,
        ApiV2,
        "PUT",
        "/api/v2/collections/order",
        "/api/v2/collections/order",
        "kid_reorder",
        reorder,
        &[],
    );
    // Membership writes under the ceiling: the R title is hidden from the kid, and the v2 order editor refuses
    // an order the kid cannot see in full.
    let item_v2 = "/api/v2/collections/{id}/items/{item_id}";
    for (name, id) in [("kid_add_v2_above", ABOVE), ("kid_add_v2_movie", MOVIE)] {
        kid(
            f,
            ApiV2,
            "PUT",
            item_v2,
            &format!("/api/v2/collections/${{flow_kid_own}}/items/{id}"),
            name,
            position,
            &[],
        );
    }
    kid(
        f,
        ApiV2,
        "PUT",
        item_v2,
        &format!("/api/v2/collections/${{flow_kid_mixed}}/items/{MOVIE}"),
        "kid_add_v2_shared",
        position,
        &[],
    );
    let items_body = format!("{{\"ordered_ids\":[\"{ABOVE}\",\"{MOVIE}\"]}}");
    kid(
        f,
        ApiV1,
        "PUT",
        "/api/v1/collections/{id}/items/order",
        "/api/v1/collections/${flow_kid_own}/items/order",
        "kid_items_reorder_v1",
        Some(&items_body),
        &[],
    );
    f.step(Step {
        identity: Identity::Kid,
        profile: Some("${kid_profile_id}"),
        at: Some("/api/v2/collections/${flow_kid_own}/items/order"),
        body: Some(&items_body),
        headers: &[("If-Match", "*")],
        ..Step::new(ApiV2, "PUT", order, "collections:kid:kid_items_reorder_v2")
    });
    kid(
        f,
        ApiV1,
        "DELETE",
        item,
        &format!("/api/v1/collections/${{flow_kid_own}}/items/{ABOVE}"),
        "kid_remove_v1_above",
        None,
        &[],
    );
    kid(
        f,
        ApiV2,
        "PUT",
        order,
        "/api/v2/collections/${flow_kid_own}/items/order",
        "kid_items_reorder_v2_visible",
        Some(&format!("{{\"ordered_ids\":[\"{MOVIE}\"]}}")),
        &[],
    );
    kid(
        f,
        ApiV2,
        "DELETE",
        item_v2,
        &format!("/api/v2/collections/${{flow_kid_own}}/items/{MOVIE}"),
        "kid_remove_v2_movie",
        None,
        &[],
    );
    for (surface, v) in [(ApiV1, "v1"), (ApiV2, "v2")] {
        let pref = format!("/api/{v}/collections/sort-preference");
        for (name, id) in [("own", "${flow_kid_own}"), ("shared", "${flow_kid_mixed}")] {
            let body = format!("{{\"collection_kind\":\"user\",\"collection_id\":\"{id}\",\"field\":\"title\",\"order\":\"desc\"}}");
            kid(
                f,
                surface,
                "PUT",
                &pref,
                &pref,
                &format!("kid_sort_{name}_{v}"),
                Some(&body),
                &[],
            );
        }
        f.step(Step {
            identity: Identity::Kid,
            profile: Some("${kid_profile_id}"),
            query: &[
                ("collection_kind", "user"),
                ("collection_id", "${flow_kid_own}"),
            ],
            ..Step::new(
                surface,
                "DELETE",
                &pref,
                &format!("collections:kid:kid_sort_clear_{v}"),
            )
        });
    }
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
    admin_membership(f);
    membership(f, ApiV1, "/api/v1/collections", "v1");
    membership(f, ApiV2, "/api/v2/collections", "v2");
    kid_collections(f);
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
