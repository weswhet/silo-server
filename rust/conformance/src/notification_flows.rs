//! Requests that reach the success path of the notification rows, over the deliveries the accounts seed
//! holds: the plan's generic cases never name one, and no request can make one.

use crate::auth_flows::{Flows, Step};
use crate::model::*;
use crate::plan::Builder;
use Surface::{ApiV1, ApiV2};

const PROFILE: &str = "${user_profile_id}";
const ADMIN_PROFILE: &str = "${admin_profile_id}";
const ONE: &str = "01JCONFNOTIFICATION0000001";
const TWO: &str = "01JCONFNOTIFICATION0000002";
const THREE: &str = "01JCONFNOTIFICATION0000003";
const FOUR: &str = "01JCONFNOTIFICATION0000004";

struct Call<'a> {
    method: &'a str,
    route: &'a str,
    at: Option<&'a str>,
    name: &'a str,
    query: &'a [(&'a str, &'a str)],
    body: Option<&'a str>,
    capture: &'a [(&'a str, &'a str)],
}

fn call<'a>(method: &'a str, route: &'a str, name: &'a str) -> Call<'a> {
    Call {
        method,
        route,
        at: None,
        name,
        query: &[],
        body: None,
        capture: &[],
    }
}

fn go(f: &mut Flows, surface: Surface, c: Call) {
    let name = format!(
        "notifications:{}:{}",
        if surface == ApiV1 { "v1" } else { "v2" },
        c.name
    );
    f.step(Step {
        identity: if surface == ApiV1 {
            Identity::User
        } else {
            Identity::Admin
        },
        at: c.at,
        query: c.query,
        body: c.body,
        profile: Some(if surface == ApiV1 {
            PROFILE
        } else {
            ADMIN_PROFILE
        }),
        capture: c.capture,
        ..Step::new(surface, c.method, c.route, &name)
    });
}

fn prefs_and_channels(f: &mut Flows, surface: Surface, base: &str) {
    let prefs = format!("{base}/preferences");
    let email = format!("{base}/email-preferences");
    let discord = format!("{base}/discord-preferences");
    let partial = "{\"notify_next_up\":false}";
    go(f, surface, call("GET", &prefs, "prefs"));
    go(
        f,
        surface,
        Call {
            body: Some(partial),
            ..call("PUT", &prefs, "prefs_partial")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"enabled\":null}"),
            ..call("PUT", &prefs, "prefs_null")
        },
    );
    go(f, surface, call("GET", &prefs, "prefs_after"));
    go(f, surface, call("GET", &email, "email"));
    for (name, body) in [
        ("email_off", "{\"mode\":\"off\"}"),
        ("email_no_address", "{\"mode\":\"daily_digest\"}"),
        ("email_bad_mode", "{\"mode\":\"sometimes\"}"),
    ] {
        go(
            f,
            surface,
            Call {
                body: Some(body),
                ..call("PUT", &email, name)
            },
        );
    }
    go(f, surface, call("GET", &email, "email_after"));
    go(f, surface, call("GET", &discord, "discord"));
}

pub(crate) fn add(b: &mut Builder) {
    let mut flows = Flows {
        b,
        seq: 0,
        prefix: "xflow",
    };
    let f = &mut flows;
    // v1.
    let root = "/api/v1/notifications/";
    let item = "/api/v1/notifications/{id}";
    let read = "/api/v1/notifications/{id}/read";
    go(f, ApiV1, call("GET", root, "list"));
    go(
        f,
        ApiV1,
        Call {
            query: &[("limit", "1")],
            capture: &[("flow_inbox_before", "/next_cursor")],
            ..call("GET", root, "list_limit")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            query: &[("before", "${flow_inbox_before}")],
            ..call("GET", root, "list_before")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            query: &[("before", "%%%")],
            ..call("GET", root, "list_bad_before")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            capture: &[("flow_inbox_since", "/next_cursor")],
            ..call("GET", "/api/v1/notifications/sync", "sync")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            query: &[("since", "${flow_inbox_since}")],
            ..call("GET", "/api/v1/notifications/sync", "sync_since")
        },
    );
    go(
        f,
        ApiV1,
        call("GET", "/api/v1/notifications/unread-count", "unread"),
    );
    go(
        f,
        ApiV1,
        call("GET", "/api/v1/notifications/capability", "capability"),
    );
    let at_one = format!("/api/v1/notifications/{ONE}");
    let at_two = format!("/api/v1/notifications/{TWO}");
    let read_one = format!("{at_one}/read");
    go(
        f,
        ApiV1,
        Call {
            at: Some(&at_one),
            ..call("GET", item, "get")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            at: Some(&at_two),
            ..call("GET", item, "get_request")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            at: Some("/api/v1/notifications/missing"),
            ..call("GET", item, "get_missing")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            at: Some(&read_one),
            ..call("POST", read, "read")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            at: Some(&read_one),
            ..call("POST", read, "read_again")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            at: Some("/api/v1/notifications/missing/read"),
            ..call("POST", read, "read_missing")
        },
    );
    go(
        f,
        ApiV1,
        call("POST", "/api/v1/notifications/read-all", "read_all"),
    );
    prefs_and_channels(f, ApiV1, "/api/v1/notifications");

    // v2, on the administrator: v1's read-all leaves its account nothing unread.
    let root = "/api/v2/notifications";
    let item = "/api/v2/notifications/{id}";
    let read = "/api/v2/notifications/{id}/read";
    go(
        f,
        ApiV2,
        Call {
            capture: &[("flow_inbox_cutoff", "/read_cutoff")],
            ..call("GET", root, "list")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            query: &[("status", "unread"), ("limit", "1")],
            capture: &[("flow_inbox_next", "/page/next_cursor")],
            ..call("GET", root, "list_limit")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            query: &[
                ("status", "unread"),
                ("limit", "1"),
                ("cursor", "${flow_inbox_next}"),
            ],
            ..call("GET", root, "list_next")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            capture: &[("flow_inbox_sync", "/sync_cursor")],
            ..call("GET", "/api/v2/notifications/sync", "sync")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            query: &[("cursor", "${flow_inbox_sync}")],
            ..call("GET", "/api/v2/notifications/sync", "sync_cursor")
        },
    );
    go(
        f,
        ApiV2,
        call("GET", "/api/v2/notifications/unread-count", "unread"),
    );
    go(
        f,
        ApiV2,
        call("GET", "/api/v2/notifications/capabilities", "capabilities"),
    );
    let at_one = format!("/api/v2/notifications/{THREE}");
    let at_two = format!("/api/v2/notifications/{FOUR}");
    let read_two = format!("{at_two}/read");
    go(
        f,
        ApiV2,
        Call {
            at: Some(&at_one),
            ..call("GET", item, "get")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            at: Some(&at_two),
            ..call("GET", item, "get_request")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            at: Some("/api/v2/notifications/missing"),
            ..call("GET", item, "get_missing")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            at: Some(&read_two),
            ..call("POST", read, "read")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            body: Some("{\"through\":\"${flow_inbox_cutoff}\"}"),
            ..call("POST", "/api/v2/notifications/read-all", "read_all")
        },
    );
    go(
        f,
        ApiV2,
        Call {
            body: Some("{\"through\":\"nonsense\"}"),
            ..call("POST", "/api/v2/notifications/read-all", "read_all_bad")
        },
    );
    prefs_and_channels(f, ApiV2, "/api/v2/notifications");
}
