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

/// A seeded series, a PG movie (not a series), and an R movie above the kid profile's PG ceiling.
const SERIES: &str = "series-tvdb-9000003";
const MOVIE: &str = "movie-tmdb-9000001";
const ABOVE: &str = "movie-tmdb-9000002";

/// One step as `identity` on `profile`, named `notifications:<who>:<name>`.
#[allow(clippy::too_many_arguments)]
fn as_who(
    f: &mut Flows,
    who: &str,
    identity: Identity,
    profile: &str,
    method: &str,
    route: &str,
    at: &str,
    name: &str,
    body: Option<&str>,
) {
    let name = format!("notifications:{who}:{name}");
    f.step(Step {
        identity,
        at: Some(at),
        body,
        profile: Some(profile),
        ..Step::new(ApiV2, method, route, &name)
    });
}

/// Muting and unmuting a series, as the user and as the kid profile, whose PG ceiling hides `ABOVE`.
fn series_mutes(f: &mut Flows) {
    let route = "/api/v2/notifications/series/{series_id}/mute";
    let at = |id: &str| format!("/api/v2/notifications/series/{id}/mute");
    for (who, identity, profile) in [
        ("user", Identity::User, PROFILE),
        ("kid", Identity::Kid, "${kid_profile_id}"),
    ] {
        for (method, id, name) in [
            ("PUT", SERIES, "mute"),
            ("PUT", SERIES, "mute_again"),
            ("PUT", MOVIE, "mute_movie"),
            ("PUT", ABOVE, "mute_above"),
            ("PUT", "series-missing", "mute_missing"),
            ("DELETE", SERIES, "unmute"),
            ("DELETE", SERIES, "unmute_again"),
            ("DELETE", ABOVE, "unmute_above"),
        ] {
            as_who(
                f,
                who,
                identity,
                profile,
                method,
                route,
                &at(id),
                name,
                None,
            );
        }
        as_who(
            f,
            who,
            identity,
            profile,
            "PUT",
            route,
            &at(SERIES),
            "mute_kept",
            None,
        );
    }
}

/// One step with headers and captures, as `identity` on `profile`.
#[allow(clippy::too_many_arguments)]
fn dest(
    f: &mut Flows,
    who: &str,
    surface: Surface,
    identity: Identity,
    profile: &str,
    method: &str,
    route: &str,
    at: &str,
    name: &str,
    body: Option<&str>,
    headers: &[(&str, &str)],
    capture: &[(&str, &str)],
) {
    let v = if surface == ApiV1 { "v1" } else { "v2" };
    let name = format!("destinations:{who}:{v}:{name}");
    f.step(Step {
        identity,
        at: Some(at),
        body,
        headers,
        capture,
        profile: Some(profile),
        ..Step::new(surface, method, route, &name)
    });
}

/// Webhook and browser push management. Destinations are IP literals or reserved names, so no case
/// depends on what the host running each side can resolve.
fn destinations(f: &mut Flows) {
    const HOOK: &str =
        "{\"name\":\"Conf hook\",\"url\":\"https://93.184.215.14/hook\",\"notify_next_up\":false}";
    const PUSH: &str = "{\"endpoint\":\"https://93.184.215.14/push/${flow_dest_who}\",\"keys\":{\"p256dh\":\"BOFWwXKf\",\"auth\":\"conf\"},\"device_name\":\"Conf browser\"}";
    for (who, identity, profile) in [
        ("user", Identity::User, PROFILE),
        ("kid", Identity::Kid, "${kid_profile_id}"),
    ] {
        let push = PUSH.replace("${flow_dest_who}", who);
        // v1.
        let list = "/api/v1/notifications/webhooks/";
        let one = "/api/v1/notifications/webhooks/{id}";
        let rotate = "/api/v1/notifications/webhooks/{id}/rotate-secret";
        let hook_var = format!("flow_hook_{who}");
        let at_hook = format!("/api/v1/notifications/webhooks/${{{hook_var}}}");
        let at_rotate = format!("{at_hook}/rotate-secret");
        let d = |f: &mut Flows,
                 method: &str,
                 route: &str,
                 at: &str,
                 name: &str,
                 body: Option<&str>,
                 capture: &[(&str, &str)]| {
            dest(
                f,
                who,
                ApiV1,
                identity,
                profile,
                method,
                route,
                at,
                name,
                body,
                &[],
                capture,
            );
        };
        d(f, "GET", list, list, "hooks_empty", None, &[]);
        d(
            f,
            "POST",
            list,
            list,
            "hook_create",
            Some(HOOK),
            &[(&hook_var, "/id")],
        );
        for (name, body) in [
            ("hook_dup", HOOK),
            (
                "hook_private",
                "{\"name\":\"p\",\"url\":\"https://10.0.0.1/x\"}",
            ),
            (
                "hook_blocked",
                "{\"name\":\"b\",\"url\":\"https://169.254.169.254/x\"}",
            ),
            (
                "hook_http",
                "{\"name\":\"h\",\"url\":\"http://93.184.215.14/x\"}",
            ),
            (
                "hook_creds",
                "{\"name\":\"c\",\"url\":\"https://u:p@93.184.215.14/x\"}",
            ),
            (
                "hook_unresolved",
                "{\"name\":\"u\",\"url\":\"https://conf.invalid/x\"}",
            ),
            ("hook_no_url", "{\"name\":\"n\"}"),
            (
                "hook_blank_name",
                "{\"name\":\"  \",\"url\":\"https://93.184.215.14/x\"}",
            ),
            (
                "hook_bad_type",
                "{\"name\":\"t\",\"url\":\"https://93.184.215.14/x\",\"type\":\"slack\"}",
            ),
            (
                "hook_discord_type",
                "{\"name\":\"d\",\"url\":\"https://93.184.215.14/x\",\"type\":\"discord\"}",
            ),
            ("hook_bad_json", "{"),
        ] {
            d(f, "POST", list, list, name, Some(body), &[]);
        }
        d(f, "GET", list, list, "hooks", None, &[]);
        d(
            f,
            "PUT",
            one,
            &at_hook,
            "hook_update",
            Some("{\"name\":\"Renamed\",\"enabled\":false,\"notify_requests\":false}"),
            &[],
        );
        d(
            f,
            "PUT",
            one,
            &at_hook,
            "hook_update_url",
            Some("{\"url\":\"https://93.184.215.15/other\",\"enabled\":true}"),
            &[],
        );
        d(
            f,
            "PUT",
            one,
            &at_hook,
            "hook_update_private",
            Some("{\"url\":\"https://192.168.1.1/\"}"),
            &[],
        );
        d(
            f,
            "PUT",
            one,
            "/api/v1/notifications/webhooks/missing",
            "hook_update_missing",
            Some("{}"),
            &[],
        );
        d(f, "POST", rotate, &at_rotate, "hook_rotate", None, &[]);
        d(
            f,
            "POST",
            rotate,
            "/api/v1/notifications/webhooks/missing/rotate-secret",
            "hook_rotate_missing",
            None,
            &[],
        );
        d(f, "GET", list, list, "hooks_after", None, &[]);
        d(f, "DELETE", one, &at_hook, "hook_delete", None, &[]);
        d(f, "DELETE", one, &at_hook, "hook_delete_again", None, &[]);

        let subs = "/api/v1/notifications/web-push/subscriptions";
        let sub = "/api/v1/notifications/web-push/subscriptions/{id}";
        let unsub = "/api/v1/notifications/web-push/unsubscribe";
        let sub_var = format!("flow_push_{who}");
        let at_sub = format!("{subs}/${{{sub_var}}}");
        d(f, "GET", subs, subs, "push_empty", None, &[]);
        d(
            f,
            "POST",
            subs,
            subs,
            "push_subscribe",
            Some(&push),
            &[(&sub_var, "/id")],
        );
        d(f, "POST", subs, subs, "push_resubscribe", Some(&push), &[]);
        for (name, body) in [
            ("push_no_keys", "{\"endpoint\":\"https://93.184.215.14/push\"}"),
            ("push_private", "{\"endpoint\":\"https://127.0.0.1/push\",\"keys\":{\"p256dh\":\"k\",\"auth\":\"a\"}}"),
            ("push_bad_json", "[]"),
        ] {
            d(f, "POST", subs, subs, name, Some(body), &[]);
        }
        d(f, "GET", subs, subs, "push_list", None, &[]);
        d(f, "DELETE", sub, &at_sub, "push_delete", None, &[]);
        let again_var = format!("flow_push_again_{who}");
        d(
            f,
            "POST",
            subs,
            subs,
            "push_subscribe_again",
            Some(&push),
            &[(&again_var, "/id")],
        );
        d(
            f,
            "POST",
            unsub,
            unsub,
            "push_unsubscribe",
            Some(&push),
            &[],
        );
        d(
            f,
            "POST",
            unsub,
            unsub,
            "push_unsubscribe_blank",
            Some("{}"),
            &[],
        );
        d(f, "GET", subs, subs, "push_after", None, &[]);

        // v2.
        let list = "/api/v2/notifications/webhooks";
        let one = "/api/v2/notifications/webhooks/{id}";
        let rotate = "/api/v2/notifications/webhooks/{id}/rotate-secret";
        let hook_var = format!("flow_hook_two_{who}");
        let tag_var = format!("flow_hook_tag_two_{who}");
        let at_hook = format!("/api/v2/notifications/webhooks/${{{hook_var}}}");
        let at_rotate = format!("{at_hook}/rotate-secret");
        let if_match = format!("${{{tag_var}}}");
        let d = |f: &mut Flows,
                 method: &str,
                 route: &str,
                 at: &str,
                 name: &str,
                 body: Option<&str>,
                 headers: &[(&str, &str)],
                 capture: &[(&str, &str)]| {
            dest(
                f, who, ApiV2, identity, profile, method, route, at, name, body, headers, capture,
            );
        };
        d(f, "GET", list, list, "hooks_empty", None, &[], &[]);
        d(
            f,
            "POST",
            list,
            list,
            "hook_create",
            Some(HOOK),
            &[],
            &[(&hook_var, "/id")],
        );
        d(f, "POST", list, list, "hook_dup", Some(HOOK), &[], &[]);
        d(
            f,
            "POST",
            list,
            list,
            "hook_private",
            Some("{\"name\":\"p\",\"url\":\"https://10.0.0.1/x\"}"),
            &[],
            &[],
        );
        d(
            f,
            "POST",
            list,
            list,
            "hook_relative",
            Some("{\"name\":\"p\",\"url\":\":nope\"}"),
            &[],
            &[],
        );
        d(
            f,
            "GET",
            list,
            list,
            "hooks",
            None,
            &[],
            &[(&tag_var, "/items/0/etag")],
        );
        let second_var = format!("flow_hook_second_two_{who}");
        d(
            f,
            "POST",
            list,
            list,
            "hook_create_second",
            Some("{\"name\":\"Second\",\"url\":\"https://93.184.215.16/\"}"),
            &[],
            &[(&second_var, "/id")],
        );
        d(f, "GET", list, list, "hooks_page", None, &[], &[]);
        d(
            f,
            "PUT",
            one,
            &at_hook,
            "hook_update_unguarded",
            Some("{\"name\":\"x\"}"),
            &[],
            &[],
        );
        d(
            f,
            "PUT",
            one,
            &at_hook,
            "hook_update_stale",
            Some("{\"name\":\"x\"}"),
            &[("If-Match", "\"stale\"")],
            &[],
        );
        d(
            f,
            "PUT",
            one,
            &at_hook,
            "hook_update_invalid",
            Some("{\"url\":\"https://10.2.2.2/\"}"),
            &[("If-Match", &if_match)],
            &[],
        );
        d(
            f,
            "PUT",
            one,
            &at_hook,
            "hook_update",
            Some("{\"name\":\"Renamed\",\"enabled\":false}"),
            &[("If-Match", &if_match)],
            &[(&tag_var, "/etag")],
        );
        d(
            f,
            "PUT",
            one,
            "/api/v2/notifications/webhooks/missing",
            "hook_update_missing",
            Some("{}"),
            &[("If-Match", "*")],
            &[],
        );
        d(f, "POST", rotate, &at_rotate, "hook_rotate", None, &[], &[]);
        d(
            f,
            "POST",
            rotate,
            "/api/v2/notifications/webhooks/missing/rotate-secret",
            "hook_rotate_missing",
            None,
            &[],
            &[],
        );
        d(
            f,
            "DELETE",
            one,
            &at_hook,
            "hook_delete_unguarded",
            None,
            &[],
            &[],
        );
        d(
            f,
            "DELETE",
            one,
            &at_hook,
            "hook_delete",
            None,
            &[("If-Match", &if_match)],
            &[],
        );
        d(
            f,
            "DELETE",
            one,
            &at_hook,
            "hook_delete_again",
            None,
            &[("If-Match", "*")],
            &[],
        );
        d(f, "GET", list, list, "hooks_after", None, &[], &[]);

        let subs = "/api/v2/notifications/web-push/subscriptions";
        let sub = "/api/v2/notifications/web-push/subscriptions/{id}";
        let unsub = "/api/v2/notifications/web-push/unsubscribe";
        let sub_var = format!("flow_push_two_{who}");
        let at_sub = format!("{subs}/${{{sub_var}}}");
        d(f, "GET", subs, subs, "push_empty", None, &[], &[]);
        d(
            f,
            "POST",
            subs,
            subs,
            "push_subscribe",
            Some(&push),
            &[],
            &[(&sub_var, "/id")],
        );
        d(f, "POST", subs, subs, "push_private", Some("{\"endpoint\":\"https://127.0.0.1/push\",\"keys\":{\"p256dh\":\"k\",\"auth\":\"a\"}}"), &[], &[]);
        d(
            f,
            "POST",
            subs,
            subs,
            "push_not_uri",
            Some("{\"endpoint\":\":x\",\"keys\":{\"p256dh\":\"k\",\"auth\":\"a\"}}"),
            &[],
            &[],
        );
        d(f, "GET", subs, subs, "push_list", None, &[], &[]);
        d(f, "DELETE", sub, &at_sub, "push_delete", None, &[], &[]);
        let again_var = format!("flow_push_again_two_{who}");
        d(
            f,
            "POST",
            subs,
            subs,
            "push_subscribe_again",
            Some(&push),
            &[],
            &[(&again_var, "/id")],
        );
        let endpoint_only = format!("{{\"endpoint\":\"https://93.184.215.14/push/{who}\"}}");
        d(
            f,
            "POST",
            unsub,
            unsub,
            "push_unsubscribe",
            Some(&endpoint_only),
            &[],
            &[],
        );
        d(f, "GET", subs, subs, "push_after", None, &[], &[]);
    }
}

/// Server channel administration, as the administrator, with the user's refusal.
fn server_channels(f: &mut Flows) {
    const CHANNEL: &str = "{\"name\":\"Conf channel\",\"url\":\"https://93.184.215.14/channel\",\"notify_request_approved\":true}";
    for surface in [ApiV1, ApiV2] {
        let (list, one, rotate) = if surface == ApiV1 {
            (
                "/api/v1/admin/notifications/server-channels/",
                "/api/v1/admin/notifications/server-channels/{id}",
                "/api/v1/admin/notifications/server-channels/{id}/rotate-secret",
            )
        } else {
            (
                "/api/v2/admin/notifications/server-channels",
                "/api/v2/admin/notifications/server-channels/{id}",
                "/api/v2/admin/notifications/server-channels/{id}/rotate-secret",
            )
        };
        let base = list.trim_end_matches('/');
        let tag = if surface == ApiV1 { "one" } else { "two" };
        let var = format!("flow_channel_{tag}");
        let second = format!("flow_channel_second_{tag}");
        let at = format!("{base}/${{{var}}}");
        let at_rotate = format!("{at}/rotate-secret");
        let missing = format!("{base}/missing");
        let missing_rotate = format!("{missing}/rotate-secret");
        let d = |f: &mut Flows,
                 identity: Identity,
                 method: &str,
                 route: &str,
                 at: &str,
                 name: &str,
                 body: Option<&str>,
                 capture: &[(&str, &str)]| {
            let profile = if identity == Identity::Admin {
                ADMIN_PROFILE
            } else {
                PROFILE
            };
            dest(
                f,
                "channels",
                surface,
                identity,
                profile,
                method,
                route,
                at,
                name,
                body,
                &[],
                capture,
            );
        };
        let admin = Identity::Admin;
        d(f, admin, "GET", list, list, "empty", None, &[]);
        d(
            f,
            Identity::User,
            "POST",
            list,
            list,
            "create_user",
            Some(CHANNEL),
            &[],
        );
        d(
            f,
            admin,
            "POST",
            list,
            list,
            "create",
            Some(CHANNEL),
            &[(&var, "/id")],
        );
        d(
            f,
            admin,
            "POST",
            list,
            list,
            "create_disabled",
            Some("{\"name\":\"Second\",\"url\":\"https://93.184.215.15/\",\"enabled\":false}"),
            &[(&second, "/id")],
        );
        for (name, body) in [
            ("create_dup", CHANNEL),
            ("create_private", "{\"name\":\"p\",\"url\":\"https://172.16.0.1/\"}"),
            ("create_unresolved", "{\"name\":\"u\",\"url\":\"https://conf.invalid/\"}"),
            ("create_bad_type", "{\"name\":\"t\",\"url\":\"https://93.184.215.14/\",\"type\":\"discord\"}"),
            ("create_long_name", "{\"name\":\"0123456789012345678901234567890123456789012345678901234567890123456789\",\"url\":\"https://93.184.215.14/\"}"),
        ] {
            d(f, admin, "POST", list, list, name, Some(body), &[]);
        }
        if surface == ApiV1 {
            d(
                f,
                admin,
                "POST",
                list,
                list,
                "create_no_url",
                Some("{\"name\":\"n\"}"),
                &[],
            );
            d(
                f,
                admin,
                "POST",
                list,
                list,
                "create_bad_json",
                Some("nope"),
                &[],
            );
        }
        d(f, admin, "GET", list, list, "list", None, &[]);
        d(
            f,
            admin,
            "PUT",
            one,
            &at,
            "update",
            Some("{\"name\":\"Renamed\",\"notify_new_movies\":false}"),
            &[],
        );
        d(
            f,
            admin,
            "PUT",
            one,
            &at,
            "update_url",
            Some("{\"url\":\"https://93.184.215.16/next\"}"),
            &[],
        );
        d(
            f,
            admin,
            "PUT",
            one,
            &at,
            "update_private",
            Some("{\"url\":\"https://10.9.9.9/\"}"),
            &[],
        );
        let at_second = format!("{base}/${{{second}}}");
        d(
            f,
            admin,
            "PUT",
            one,
            &at_second,
            "update_enable",
            Some("{\"enabled\":true}"),
            &[],
        );
        d(
            f,
            admin,
            "PUT",
            one,
            &missing,
            "update_missing",
            Some("{}"),
            &[],
        );
        d(f, admin, "POST", rotate, &at_rotate, "rotate", None, &[]);
        d(
            f,
            admin,
            "POST",
            rotate,
            &missing_rotate,
            "rotate_missing",
            None,
            &[],
        );
        d(f, admin, "GET", list, list, "list_after", None, &[]);
        d(f, admin, "DELETE", one, &at, "delete", None, &[]);
        d(
            f,
            admin,
            "DELETE",
            one,
            &at_second,
            "delete_second",
            None,
            &[],
        );
        d(f, admin, "DELETE", one, &at, "delete_again", None, &[]);
        d(f, admin, "GET", list, list, "list_empty", None, &[]);
    }
}

/// Bridge push device registration on v1, as the user and the kid profile.
fn push_devices(f: &mut Flows) {
    let token = "c".repeat(70);
    let route = "/api/v1/notifications/push/devices";
    let one = "/api/v1/notifications/push/devices/{device_id}";
    for (who, identity, profile) in [
        ("user", Identity::User, PROFILE),
        ("kid", Identity::Kid, "${kid_profile_id}"),
    ] {
        let device = format!("conf-push-{who}");
        let at_one = format!("{route}/{device}");
        let body = |mode: &str, tok: &str, platform: &str| {
            format!("{{\"platform\":\"{platform}\",\"token\":\"{tok}\",\"device_id\":\"{device}\",\"push_mode\":\"{mode}\"}}")
        };
        let d =
            |f: &mut Flows, method: &str, route: &str, at: &str, name: &str, body: Option<&str>| {
                let capture: &[(&str, &str)] = &[];
                dest(
                    f,
                    who,
                    ApiV1,
                    identity,
                    profile,
                    method,
                    route,
                    at,
                    name,
                    body,
                    &[],
                    capture,
                );
            };
        d(
            f,
            "POST",
            route,
            route,
            "push_register",
            Some(&body("", &token, "android")),
        );
        d(
            f,
            "POST",
            route,
            route,
            "push_register_again",
            Some(&body("in_app_only", &token, "android")),
        );
        d(
            f,
            "POST",
            route,
            route,
            "push_register_ios",
            Some(&body("", &token, "ios")),
        );
        d(
            f,
            "POST",
            route,
            route,
            "push_register_short",
            Some(&body("", "abc", "android")),
        );
        d(
            f,
            "POST",
            route,
            route,
            "push_register_mode",
            Some(&body("loud", &token, "android")),
        );
        d(f, "POST", route, route, "push_register_bad_json", Some("{"));
        d(f, "DELETE", one, &at_one, "push_unregister", None);
        d(f, "DELETE", one, &at_one, "push_unregister_again", None);
    }
}

/// Clearing the email address and the Discord writes, as the user's primary profile and the kid.
fn channel_writes(f: &mut Flows) {
    for (surface, v) in [(ApiV1, "v1"), (ApiV2, "v2")] {
        let address = format!("/api/{v}/notifications/email-preferences/address");
        let discord = format!("/api/{v}/notifications/discord-preferences");
        let link = format!("/api/{v}/notifications/discord-link");
        for (who, identity, profile) in [
            ("user", Identity::User, PROFILE),
            ("kid", Identity::Kid, "${kid_profile_id}"),
        ] {
            let d = |f: &mut Flows, method: &str, route: &str, name: &str, body: Option<&str>| {
                dest(
                    f,
                    who,
                    surface,
                    identity,
                    profile,
                    method,
                    route,
                    route,
                    name,
                    body,
                    &[],
                    &[],
                );
            };
            d(f, "DELETE", &address, "email_clear", None);
            d(
                f,
                "PUT",
                &discord,
                "discord_off",
                Some("{\"mode\":\"off\"}"),
            );
            d(
                f,
                "PUT",
                &discord,
                "discord_digest",
                Some("{\"mode\":\"daily_digest\"}"),
            );
            d(
                f,
                "PUT",
                &discord,
                "discord_bad",
                Some("{\"mode\":\"loud\"}"),
            );
            d(f, "DELETE", &link, "discord_unlink", None);
        }
    }
}

/// Ordered Android registration on v2, as the user and the kid profile.
fn ordered_push(f: &mut Flows) {
    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const OTHER_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
    let token = "d".repeat(80);
    let route = "/api/v2/notifications/push/devices";
    let one = "/api/v2/notifications/push/devices/{device_id}";
    for (who, identity, profile) in [
        ("user", Identity::User, PROFILE),
        ("kid", Identity::Kid, "${kid_profile_id}"),
    ] {
        let device = format!("conf-ordered-{who}");
        let at_one = format!("{route}/{device}");
        let body = format!("{{\"device_id\":\"{device}\",\"platform\":\"android\",\"token\":\"{token}\",\"push_mode\":\"private_push\"}}");
        let in_app = format!("{{\"device_id\":\"{device}\",\"platform\":\"android\",\"token\":\"{token}\",\"push_mode\":\"in_app_only\"}}");
        let d = |f: &mut Flows,
                 method: &str,
                 route: &str,
                 at: &str,
                 name: &str,
                 body: Option<&str>,
                 key: &str,
                 generation: &str| {
            let headers = [
                ("X-Push-Installation-Key", key),
                ("X-Push-Generation", generation),
            ];
            dest(
                f,
                who,
                ApiV2,
                identity,
                profile,
                method,
                route,
                at,
                name,
                body,
                &headers,
                &[],
            );
        };
        d(
            f,
            "POST",
            route,
            route,
            "ordered_register",
            Some(&body),
            KEY,
            "1",
        );
        d(
            f,
            "POST",
            route,
            route,
            "ordered_replay",
            Some(&body),
            KEY,
            "1",
        );
        d(
            f,
            "POST",
            route,
            route,
            "ordered_same_generation",
            Some(&in_app),
            KEY,
            "1",
        );
        d(
            f,
            "POST",
            route,
            route,
            "ordered_wrong_key",
            Some(&in_app),
            OTHER_KEY,
            "2",
        );
        d(
            f,
            "POST",
            route,
            route,
            "ordered_bad_generation",
            Some(&in_app),
            KEY,
            "02",
        );
        d(
            f,
            "POST",
            route,
            route,
            "ordered_next",
            Some(&in_app),
            KEY,
            "2",
        );
        d(
            f,
            "DELETE",
            one,
            &at_one,
            "ordered_stale_remove",
            None,
            KEY,
            "1",
        );
        d(f, "DELETE", one, &at_one, "ordered_remove", None, KEY, "3");
        d(
            f,
            "DELETE",
            one,
            &at_one,
            "ordered_remove_replay",
            None,
            KEY,
            "3",
        );
        d(
            f,
            "POST",
            route,
            route,
            "ordered_after_remove",
            Some(&body),
            KEY,
            "3",
        );
    }
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
    series_mutes(f);
    destinations(f);
    server_channels(f);
    push_devices(f);
    channel_writes(f);
    ordered_push(f);
}
