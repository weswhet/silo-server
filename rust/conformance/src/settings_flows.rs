//! Requests that reach the success path of the settings, profile, and account rows: the plan's generic
//! cases stop at a refusal without a device header, a scope, or a known key.

use crate::auth_flows::{Flows, Step};
use crate::model::*;
use crate::plan::Builder;
use Surface::{ApiV1, ApiV2};

const USER_PROFILE: &str = "${user_profile_id}";
const KID_PROFILE: &str = "${kid_profile_id}";
const ADMIN_PROFILE: &str = "${admin_profile_id}";
const DEVICE: &[(&str, &str)] = &[
    ("X-Silo-Device-Id", "conformance-settings"),
    ("X-Silo-Device-Name", "Flow device"),
    ("X-Silo-Device-Platform", "flow"),
];
const FAMILY: &[(&str, &str)] = &[("X-Silo-Client-Family", "tv")];
const BOTH: &[(&str, &str)] = &[
    ("X-Silo-Device-Id", "conformance-settings"),
    ("X-Silo-Client-Family", "tv"),
];
const IDEMPOTENT: &[(&str, &str)] = &[("X-Silo-Mutation-Id", "settings-flow-1")];
const IDEMPOTENT_OTHER: &[(&str, &str)] = &[("X-Silo-Mutation-Id", "settings-flow-2")];

struct Call<'a> {
    method: &'a str,
    route: &'a str,
    at: Option<&'a str>,
    name: &'a str,
    query: &'a [(&'a str, &'a str)],
    headers: &'a [(&'a str, &'a str)],
    body: Option<&'a str>,
    profile: Option<&'a str>,
    admin: bool,
}

impl<'a> Call<'a> {
    fn new(method: &'a str, route: &'a str, name: &'a str) -> Self {
        Self {
            method,
            route,
            at: None,
            name,
            query: &[],
            headers: &[],
            body: None,
            profile: Some(USER_PROFILE),
            admin: false,
        }
    }
}

fn go(f: &mut Flows, surface: Surface, c: Call) {
    let name = format!(
        "settings:{}:{}",
        if surface == ApiV1 { "v1" } else { "v2" },
        c.name
    );
    f.step(Step {
        identity: if c.admin {
            Identity::Admin
        } else {
            Identity::User
        },
        at: c.at,
        query: c.query,
        headers: c.headers,
        body: c.body,
        profile: c.profile,
        ..Step::new(surface, c.method, c.route, &name)
    });
}

/// Writes through the legacy registry, then the canonical rows it mirrors.
fn legacy_v1(f: &mut Flows) {
    let device = "/api/v1/settings/device/{key}";
    let key = "/api/v1/settings/{key}";
    for (method, at, name, body, headers) in [
        (
            "PUT",
            "/api/v1/settings/device/playback.auto_skip_recap",
            "device_put",
            Some("{\"value\":\"true\"}"),
            DEVICE,
        ),
        (
            "GET",
            "/api/v1/settings/device/playback.auto_skip_recap",
            "device_get",
            None,
            DEVICE,
        ),
        (
            "PUT",
            "/api/v1/settings/device/player.next_up_prompt_seconds",
            "device_alias_put",
            Some("{\"value\":\"45\"}"),
            DEVICE,
        ),
        (
            "GET",
            "/api/v1/settings/device/player.next_up_prompt_seconds",
            "device_alias_get",
            None,
            DEVICE,
        ),
        (
            "PUT",
            "/api/v1/settings/device/playback.preferred_quality",
            "device_quality",
            Some("{\"value\":\"1080p-high\"}"),
            DEVICE,
        ),
        (
            "PUT",
            "/api/v1/settings/device/playback.auto_skip_intro",
            "device_intro",
            Some("{\"value\":\"true\"}"),
            DEVICE,
        ),
        (
            "PUT",
            "/api/v1/settings/device/playback.auto_skip_recap",
            "device_bad_value",
            Some("{\"value\":\"maybe\"}"),
            DEVICE,
        ),
        (
            "PUT",
            "/api/v1/settings/device/ui.date_format",
            "device_wrong_scope",
            Some("{\"value\":\"auto\"}"),
            DEVICE,
        ),
        (
            "GET",
            "/api/v1/settings/device/playback.auto_skip_credits",
            "device_unset",
            None,
            DEVICE,
        ),
        (
            "PUT",
            "/api/v1/settings/device/playback.auto_skip_recap",
            "device_no_id",
            Some("{\"value\":\"true\"}"),
            &[],
        ),
    ] {
        go(
            f,
            ApiV1,
            Call {
                at: Some(at),
                body,
                headers,
                ..Call::new(method, device, name)
            },
        );
    }
    let keys = [("keys", "playback.auto_skip_recap,ui.date_format,subtitle_appearance,playback.next_up_prompt_seconds,unknown.key")];
    go(
        f,
        ApiV1,
        Call {
            query: &keys,
            headers: DEVICE,
            ..Call::new("GET", "/api/v1/settings/effective", "effective")
        },
    );
    go(
        f,
        ApiV1,
        Call {
            query: &keys,
            ..Call::new("GET", "/api/v1/settings/effective", "effective_no_device")
        },
    );
    for (method, at, name, body) in [
        (
            "PUT",
            "/api/v1/settings/ui.date_format",
            "user_put",
            Some("{\"value\":\"YYYY-MM-DD\"}"),
        ),
        ("GET", "/api/v1/settings/ui.date_format", "user_get", None),
        (
            "PUT",
            "/api/v1/settings/ui.date_format",
            "user_bad",
            Some("{\"value\":\"nope\"}"),
        ),
        (
            "PUT",
            "/api/v1/settings/search.media_scope",
            "user_put_2",
            Some("{\"value\":\"all\"}"),
        ),
        (
            "DELETE",
            "/api/v1/settings/search.media_scope",
            "user_delete",
            None,
        ),
    ] {
        go(
            f,
            ApiV1,
            Call {
                at: Some(at),
                body,
                ..Call::new(method, key, name)
            },
        );
    }
    go(f, ApiV1, Call::new("GET", "/api/v1/settings/", "user_list"));
    go(
        f,
        ApiV1,
        Call {
            headers: DEVICE,
            body: Some("{\"value\":\"{\\\"fontSize\\\":\\\"large\\\"}\"}"),
            ..Call::new(
                "PUT",
                "/api/v1/settings/device/subtitle_appearance",
                "subtitle_put",
            )
        },
    );
    go(
        f,
        ApiV1,
        Call {
            headers: DEVICE,
            ..Call::new(
                "GET",
                "/api/v1/settings/subtitle_appearance/effective",
                "subtitle_effective",
            )
        },
    );
    go(
        f,
        ApiV1,
        Call {
            at: Some("/api/v1/settings/device/playback.auto_skip_recap"),
            headers: DEVICE,
            ..Call::new("DELETE", device, "device_delete")
        },
    );
}

/// One canonical value at each scope.
fn values(f: &mut Flows, surface: Surface) {
    let v1 = surface == ApiV1;
    let base = if v1 {
        "/api/v1/settings/values"
    } else {
        "/api/v2/settings/values"
    };
    let one = format!("{base}/{{key}}");
    let at = |key: &str| format!("{base}/{key}");
    let theme = at("ui.theme");
    let quality = at("playback.preferred_quality");
    let language = at("playback.subtitle_language");
    let overlays = at("ui.card_overlays_enabled");
    let intro = at("playback.intro_skip_mode");
    let skip = at("playback.auto_skip_intro");
    let shortcuts = at("nav.shortcuts");
    let unknown = at("no.such.key");
    let local = at("downloads.wifi_only");
    let profile = [("scope", "profile")];
    let device = [("scope", "profile_device")];
    let client = [("scope", "profile_client")];
    let library = [("scope", "profile_library"), ("library_id", "1")];
    let series = [("scope", "profile_series"), ("series_id", "series-flow")];
    let other = [("scope", "profile"), ("profile_id", KID_PROFILE)];
    let dark = "{\"value\":\"cinema-light\"}";
    for (method, url, name, query, headers, body) in [
        (
            "PUT",
            &theme,
            "value_put",
            &profile[..],
            &[][..],
            Some(dark),
        ),
        ("GET", &theme, "value_get", &profile[..], &[][..], None),
        (
            "PUT",
            &theme,
            "value_bad",
            &profile[..],
            &[][..],
            Some("{\"value\":\"chartreuse\"}"),
        ),
        (
            "PUT",
            &theme,
            "value_trailing",
            &profile[..],
            &[][..],
            Some("{\"value\":\"cinema-light\"} x"),
        ),
        (
            "PUT",
            &theme,
            "value_missing",
            &profile[..],
            &[][..],
            Some("{}"),
        ),
        (
            "PUT",
            &theme,
            "value_for_other",
            &other[..],
            &[][..],
            Some(dark),
        ),
        ("GET", &theme, "value_of_other", &other[..], &[][..], None),
        (
            "PUT",
            &theme,
            "value_wrong_scope",
            &device[..],
            DEVICE,
            Some(dark),
        ),
        ("GET", &theme, "value_no_scope", &[][..], &[][..], None),
        (
            "PUT",
            &quality,
            "device_value_put",
            &device[..],
            DEVICE,
            Some("{\"value\":\"1080p\"}"),
        ),
        (
            "GET",
            &quality,
            "device_value_get",
            &device[..],
            DEVICE,
            None,
        ),
        (
            "GET",
            &quality,
            "device_value_no_header",
            &device[..],
            &[][..],
            None,
        ),
        (
            "PUT",
            &overlays,
            "client_value_put",
            &client[..],
            FAMILY,
            Some("{\"value\":true}"),
        ),
        (
            "GET",
            &overlays,
            "client_value_get",
            &client[..],
            FAMILY,
            None,
        ),
        (
            "GET",
            &overlays,
            "client_value_no_header",
            &client[..],
            &[][..],
            None,
        ),
        (
            "PUT",
            &language,
            "library_value_put",
            &library[..],
            &[][..],
            Some("{\"value\":\"eng\"}"),
        ),
        (
            "GET",
            &language,
            "library_value_get",
            &library[..],
            &[][..],
            None,
        ),
        (
            "PUT",
            &language,
            "series_value_put",
            &series[..],
            &[][..],
            Some("{\"value\":\"fr\"}"),
        ),
        (
            "GET",
            &language,
            "series_value_get",
            &series[..],
            &[][..],
            None,
        ),
        (
            "PUT",
            &intro,
            "mirror_put",
            &profile[..],
            &[][..],
            Some("{\"value\":\"always\"}"),
        ),
        ("GET", &skip, "mirror_read", &profile[..], &[][..], None),
        (
            "DELETE",
            &skip,
            "mirror_delete",
            &profile[..],
            &[][..],
            None,
        ),
        ("GET", &intro, "mirror_gone", &profile[..], &[][..], None),
        (
            "DELETE",
            &intro,
            "mirror_delete_again",
            &profile[..],
            &[][..],
            None,
        ),
        (
            "PUT",
            &shortcuts,
            "shortcuts_refused",
            &profile[..],
            &[][..],
            Some("{\"value\":{\"items\":[]}}"),
        ),
        (
            "DELETE",
            &shortcuts,
            "shortcuts_delete_refused",
            &profile[..],
            &[][..],
            None,
        ),
        ("GET", &unknown, "unknown_key", &profile[..], &[][..], None),
        (
            "GET",
            &local,
            "client_local_key",
            &profile[..],
            &[][..],
            None,
        ),
    ] {
        go(
            f,
            surface,
            Call {
                at: Some(url),
                query,
                headers,
                body,
                ..Call::new(method, &one, name)
            },
        );
    }
    if v1 {
        go(
            f,
            surface,
            Call {
                at: Some(&quality),
                query: &profile,
                headers: IDEMPOTENT,
                body: Some("{\"value\":\"720p\"}"),
                ..Call::new("PUT", &one, "idempotent")
            },
        );
        go(
            f,
            surface,
            Call {
                at: Some(&quality),
                query: &profile,
                headers: IDEMPOTENT,
                body: Some("{\"value\":\"720p\"}"),
                ..Call::new("PUT", &one, "idempotent_replay")
            },
        );
        go(
            f,
            surface,
            Call {
                at: Some(&quality),
                query: &profile,
                headers: IDEMPOTENT,
                body: Some("{\"value\":\"1080p\"}"),
                ..Call::new("PUT", &one, "idempotent_conflict")
            },
        );
    }

    // The plural read and the resolver.
    if v1 {
        let keys = [
            ("scope", "profile"),
            ("keys", "ui.theme,ui.text_scale,ui.theme"),
        ];
        go(
            f,
            surface,
            Call {
                query: &keys,
                ..Call::new("GET", base, "list")
            },
        );
        let bad = [("scope", "profile"), ("keys", "ui.theme,no.such.key")];
        go(
            f,
            surface,
            Call {
                query: &bad,
                ..Call::new("GET", base, "list_unknown")
            },
        );
        let wrong = [
            ("scope", "profile_series"),
            ("series_id", "x"),
            ("keys", "playback.subtitle_language,ui.custom_css"),
        ];
        go(
            f,
            surface,
            Call {
                query: &wrong,
                ..Call::new("GET", base, "list_wrong_scope")
            },
        );
    } else {
        let keys = [
            ("scope", "profile"),
            ("keys", "ui.theme"),
            ("keys", "ui.text_scale"),
            ("keys", "ui.theme"),
        ];
        go(
            f,
            surface,
            Call {
                query: &keys,
                ..Call::new("GET", base, "list")
            },
        );
        let bad = [
            ("scope", "profile"),
            ("keys", "ui.theme"),
            ("keys", "no.such.key"),
        ];
        go(
            f,
            surface,
            Call {
                query: &bad,
                ..Call::new("GET", base, "list_unknown")
            },
        );
        let wrong = [
            ("scope", "profile_series"),
            ("series_id", "x"),
            ("keys", "playback.subtitle_language"),
            ("keys", "ui.custom_css"),
        ];
        go(
            f,
            surface,
            Call {
                query: &wrong,
                ..Call::new("GET", base, "list_wrong_scope")
            },
        );
    }
    let effective = format!("{base}/effective");
    go(
        f,
        surface,
        Call {
            headers: BOTH,
            ..Call::new("GET", &effective, "effective_all")
        },
    );
    if v1 {
        let some = [
            (
                "keys",
                "ui.theme,catalog.metadata_language,playback.subtitle_language",
            ),
            ("library_ids", "1,2,x"),
            ("series_ids", "series-flow"),
        ];
        go(
            f,
            surface,
            Call {
                query: &some,
                headers: BOTH,
                ..Call::new("GET", &effective, "effective_some")
            },
        );
        let unknown = [("keys", "no.such.key")];
        go(
            f,
            surface,
            Call {
                query: &unknown,
                headers: BOTH,
                ..Call::new("GET", &effective, "effective_unknown")
            },
        );
        let other = [("keys", "ui.theme"), ("profile_id", KID_PROFILE)];
        go(
            f,
            surface,
            Call {
                query: &other,
                ..Call::new("GET", &effective, "effective_other")
            },
        );
        let device = [
            ("keys", "playback.preferred_quality"),
            ("device_id", "conformance-settings"),
        ];
        go(
            f,
            surface,
            Call {
                query: &device,
                ..Call::new("GET", &effective, "effective_named_device")
            },
        );
        let missing = [
            ("keys", "playback.preferred_quality"),
            ("device_id", "no-such-device"),
        ];
        go(
            f,
            surface,
            Call {
                query: &missing,
                ..Call::new("GET", &effective, "effective_unknown_device")
            },
        );
    } else {
        let some = [
            ("keys", "ui.theme"),
            ("keys", "catalog.metadata_language"),
            ("keys", "playback.subtitle_language"),
            ("library_ids", "1"),
            ("series_ids", "series-flow"),
        ];
        go(
            f,
            surface,
            Call {
                query: &some,
                headers: BOTH,
                ..Call::new("GET", &effective, "effective_some")
            },
        );
        let unknown = [("keys", "no.such.key")];
        go(
            f,
            surface,
            Call {
                query: &unknown,
                headers: BOTH,
                ..Call::new("GET", &effective, "effective_unknown")
            },
        );
        let other = [("keys", "ui.theme"), ("profile_id", KID_PROFILE)];
        go(
            f,
            surface,
            Call {
                query: &other,
                ..Call::new("GET", &effective, "effective_other")
            },
        );
        let device = [
            ("keys", "playback.preferred_quality"),
            ("device_id", "conformance-settings"),
        ];
        go(
            f,
            surface,
            Call {
                query: &device,
                ..Call::new("GET", &effective, "effective_named_device")
            },
        );
        let bad = [("keys", "ui.theme"), ("library_ids", "x")];
        go(
            f,
            surface,
            Call {
                query: &bad,
                ..Call::new("GET", &effective, "effective_bad_library")
            },
        );
    }
    let batch = "{\"keys\":[\"playback.subtitle_language\",\"ui.theme\",\"ui.theme\"],\"contexts\":[{\"context_id\":\"a\",\"library_id\":\"1\"},{\"context_id\":\"b\",\"series_id\":\"series-flow\"},{\"context_id\":\"c\",\"library_id\":\"2\",\"series_id\":\"s2\"}]}";
    go(
        f,
        surface,
        Call {
            headers: BOTH,
            body: Some(batch),
            ..Call::new("POST", &effective, "batch")
        },
    );
    go(
        f,
        surface,
        Call {
            headers: DEVICE,
            body: Some("{\"keys\":[\"ui.theme\"],\"contexts\":[{\"context_id\":\"a\"}]}"),
            ..Call::new("POST", &effective, "batch_no_content")
        },
    );
    go(f, surface, Call { headers: DEVICE, body: Some("{\"keys\":[\"ui.theme\"],\"contexts\":[{\"context_id\":\"a\",\"library_id\":\"1\"},{\"context_id\":\"a\",\"library_id\":\"1\"}]}"), ..Call::new("POST", &effective, "batch_duplicate") });
    go(f, surface, Call { body: Some("{\"keys\":[\"playback.preferred_quality\"],\"contexts\":[{\"context_id\":\"a\",\"library_id\":\"1\"}]}"), ..Call::new("POST", &effective, "batch_no_device") });
    go(f, surface, Call { headers: DEVICE, body: Some("{\"keys\":[\"no.such.key\"],\"contexts\":[{\"context_id\":\"a\",\"library_id\":\"1\"}]}"), ..Call::new("POST", &effective, "batch_unknown") });

    // Shortcuts.
    let item = format!("{base}/nav.shortcuts/item");
    let add =
        "{\"item\":{\"type\":\"library\",\"library_id\":1,\"label\":\"Films\"},\"present\":true}";
    let relabel =
        "{\"item\":{\"type\":\"library\",\"library_id\":1,\"label\":\"Movies\"},\"present\":true}";
    let remove =
        "{\"item\":{\"type\":\"library\",\"library_id\":1,\"label\":\"x\"},\"present\":false}";
    for (name, body) in [
        ("shortcut_add", add),
        ("shortcut_same", add),
        ("shortcut_relabel", relabel),
        ("shortcut_remove", remove),
        ("shortcut_remove_again", remove),
        (
            "shortcut_bad",
            "{\"item\":{\"type\":\"nope\"},\"present\":true}",
        ),
    ] {
        go(
            f,
            surface,
            Call {
                body: Some(body),
                ..Call::new("PUT", &item, name)
            },
        );
    }
    if v1 {
        go(
            f,
            surface,
            Call {
                headers: IDEMPOTENT_OTHER,
                body: Some(add),
                ..Call::new("PUT", &item, "shortcut_idempotent")
            },
        );
        go(
            f,
            surface,
            Call {
                headers: IDEMPOTENT_OTHER,
                body: Some(add),
                ..Call::new("PUT", &item, "shortcut_replay")
            },
        );
        go(
            f,
            surface,
            Call {
                body: Some("{\"present\":true}"),
                ..Call::new("PUT", &item, "shortcut_no_item")
            },
        );
        go(
            f,
            surface,
            Call {
                body: Some("{\"item\":{},\"present\":true,\"extra\":1}"),
                ..Call::new("PUT", &item, "shortcut_unknown_field")
            },
        );
    }
    for (method, url, name, query, headers) in [
        ("DELETE", &theme, "value_delete", &profile[..], &[][..]),
        (
            "DELETE",
            &theme,
            "value_delete_again",
            &profile[..],
            &[][..],
        ),
        (
            "DELETE",
            &quality,
            "device_value_delete",
            &device[..],
            DEVICE,
        ),
        (
            "DELETE",
            &overlays,
            "client_value_delete",
            &client[..],
            FAMILY,
        ),
        (
            "DELETE",
            &language,
            "library_value_delete",
            &library[..],
            &[][..],
        ),
    ] {
        go(
            f,
            surface,
            Call {
                at: Some(url),
                query,
                headers,
                ..Call::new(method, &one, name)
            },
        );
    }
    if !v1 {
        go(
            f,
            surface,
            Call {
                headers: DEVICE,
                body: Some("{\"value\":\"{}\"}"),
                ..Call::new(
                    "PUT",
                    "/api/v2/settings/device/subtitle-appearance",
                    "subtitle_put",
                )
            },
        );
        go(
            f,
            surface,
            Call {
                headers: DEVICE,
                ..Call::new(
                    "GET",
                    "/api/v2/settings/subtitle-appearance/effective",
                    "subtitle_effective",
                )
            },
        );
        go(
            f,
            surface,
            Call {
                headers: DEVICE,
                ..Call::new(
                    "DELETE",
                    "/api/v2/settings/device/subtitle-appearance",
                    "subtitle_delete",
                )
            },
        );
    }
}

/// The household: as the primary profile, with a PIN on a new member.
fn profiles(f: &mut Flows, surface: Surface) {
    let v1 = surface == ApiV1;
    let (list, one, pin, verb) = if v1 {
        (
            "/api/v1/profiles/",
            "/api/v1/profiles/{id}",
            "/api/v1/profiles/{id}/verify-pin",
            "PUT",
        )
    } else {
        (
            "/api/v2/profiles",
            "/api/v2/profiles/{id}",
            "/api/v2/profiles/{id}/verify-pin",
            "PATCH",
        )
    };
    let tag = if v1 { "flow_member_a" } else { "flow_member_b" };
    let member = if v1 {
        "${flow_member_a}"
    } else {
        "${flow_member_b}"
    };
    let at_member = one.replace("{id}", member);
    let at_pin = pin.replace("{id}", member);
    let at_kid = one.replace("{id}", KID_PROFILE);
    let at_user = one.replace("{id}", USER_PROFILE);
    let at_none = one.replace("{id}", "00000000-0000-4000-8000-000000000000");
    let create_body = if v1 {
        "{\"name\":\" Flow v1 \",\"pin\":\"4321\",\"language\":\"en\",\"subtitle_language\":\"fr\",\"subtitle_mode\":\"always\",\"auto_skip_intro\":true,\"show_forced_subtitles\":false,\"avatar\":\"avatar-2\",\"is_child\":true,\"max_playback_quality\":\"1080p\",\"allowed_library_ids\":[1],\"library_restrictions_enabled\":true}"
    } else {
        "{\"name\":\" Flow v2 \",\"pin\":\"4321\",\"language\":\"en\",\"subtitle_language\":\"fr\",\"subtitle_mode\":\"always\",\"auto_skip_intro\":true,\"show_forced_subtitles\":false,\"avatar\":\"preset:avatar-2\",\"is_child\":true,\"max_playback_quality\":\"1080p\",\"max_advisory_age\":12,\"require_advisory_age\":true,\"allowed_library_ids\":[\"1\"],\"library_restrictions_enabled\":true}"
    };
    let name = format!("settings:{}:create", if v1 { "v1" } else { "v2" });
    f.step(Step {
        identity: Identity::Admin,
        profile: Some(ADMIN_PROFILE),
        body: Some(create_body),
        capture: &[(tag, "/id")],
        ..Step::new(surface, "POST", list, &name)
    });
    let admin = |c: Call<'_>| -> () {
        let _ = c;
    };
    let _ = admin;
    go(
        f,
        surface,
        Call {
            admin: true,
            profile: Some(ADMIN_PROFILE),
            ..Call::new("GET", list, "list_after_create")
        },
    );
    for (url, name, body) in [
        (&at_member, "update_all", "{\"name\":\"Flow renamed\",\"quality_preference\":\"auto\",\"language\":\"\",\"subtitle_language\":\"pt-BR\",\"auto_skip_credits\":true,\"max_content_rating\":\"PG-13\",\"avatar\":\"dicebear:initials:flow\"}"),
        (&at_member, "update_bad_quality", "{\"max_playback_quality\":\"nope\"}"),
        (&at_member, "update_bad_avatar", "{\"avatar\":\"upload:x\"}"),
        (&at_member, "update_bad_language", "{\"language\":\"!!\"}"),
        (&at_member, "update_name_conflict", "{\"name\":\"Flow renamed\"}"),
        (&at_user, "update_self", "{\"subtitle_mode\":\"off\",\"auto_skip_recap\":true}"),
        (&at_none, "update_missing", "{\"name\":\"x\"}"),
    ] {
        let admin = !std::ptr::eq(url, &at_user);
        go(f, surface, Call { at: Some(url), body: Some(body), admin, profile: Some(if admin { ADMIN_PROFILE } else { USER_PROFILE }), ..Call::new(verb, one, name) });
    }
    if !v1 {
        go(
            f,
            surface,
            Call {
                at: Some(&at_member),
                body: Some("{\"max_advisory_age\":null,\"pin\":null}"),
                admin: true,
                profile: Some(ADMIN_PROFILE),
                ..Call::new(verb, one, "update_clear")
            },
        );
        go(
            f,
            surface,
            Call {
                at: Some(&at_member),
                body: Some("{\"name\":null}"),
                admin: true,
                profile: Some(ADMIN_PROFILE),
                ..Call::new(verb, one, "update_null_refused")
            },
        );
        go(
            f,
            surface,
            Call {
                at: Some(&at_member),
                body: Some("{\"pin\":\"4321\"}"),
                admin: true,
                profile: Some(ADMIN_PROFILE),
                ..Call::new(verb, one, "update_pin_again")
            },
        );
        go(
            f,
            surface,
            Call {
                at: Some(&at_member),
                body: Some("{\"allowed_library_ids\":[\"1\",\"1\"]}"),
                admin: true,
                profile: Some(ADMIN_PROFILE),
                ..Call::new(verb, one, "update_duplicate_library")
            },
        );
        go(
            f,
            surface,
            Call {
                at: Some(&at_member),
                body: Some("{\"allowed_library_ids\":[\"99999\"]}"),
                admin: true,
                profile: Some(ADMIN_PROFILE),
                ..Call::new(verb, one, "update_unknown_library")
            },
        );
    }
    // A child asking for its own limits, and a member's own preferences.
    go(
        f,
        surface,
        Call {
            at: Some(&at_kid),
            profile: Some(KID_PROFILE),
            body: Some("{\"subtitle_mode\":\"always\"}"),
            ..Call::new(verb, one, "kid_self")
        },
    );
    go(
        f,
        surface,
        Call {
            at: Some(&at_kid),
            profile: Some(KID_PROFILE),
            body: Some("{\"is_child\":false}"),
            ..Call::new(verb, one, "kid_access")
        },
    );
    go(
        f,
        surface,
        Call {
            at: Some(&at_user),
            profile: Some(KID_PROFILE),
            body: Some("{\"name\":\"x\"}"),
            ..Call::new(verb, one, "kid_other")
        },
    );
    for (name, body) in [
        ("pin_wrong", "{\"pin\":\"0000\"}"),
        ("pin_right", "{\"pin\":\"4321\"}"),
    ] {
        go(
            f,
            surface,
            Call {
                at: Some(&at_pin),
                body: Some(body),
                admin: true,
                profile: Some(ADMIN_PROFILE),
                ..Call::new("POST", pin, name)
            },
        );
    }
    go(
        f,
        surface,
        Call {
            body: Some("{\"name\":\"Flow renamed\"}"),
            admin: true,
            profile: Some(ADMIN_PROFILE),
            ..Call::new("POST", list, "create_conflict")
        },
    );
    go(
        f,
        surface,
        Call {
            body: Some("{\"name\":\"  \"}"),
            admin: true,
            profile: Some(ADMIN_PROFILE),
            ..Call::new("POST", list, "create_blank")
        },
    );
    go(
        f,
        surface,
        Call {
            at: Some(&at_user),
            body: Some("{\"subtitle_mode\":\"auto\",\"auto_skip_recap\":false}"),
            ..Call::new(verb, one, "update_restore")
        },
    );
    // Go serves these rows, over what the native writes left.
    if v1 {
        go(
            f,
            surface,
            Call {
                at: Some("/api/v1/admin/users/${admin_user_id}/profiles"),
                admin: true,
                profile: Some(ADMIN_PROFILE),
                ..Call::new(
                    "GET",
                    "/api/v1/admin/users/{id}/profiles",
                    "go_reads_profile",
                )
            },
        );
        go(
            f,
            surface,
            Call {
                ..Call::new("GET", "/api/v1/devices/", "go_reads_devices")
            },
        );
    } else {
        go(
            f,
            surface,
            Call {
                at: Some("/api/v2/admin/users/${admin_user_id}/profiles"),
                admin: true,
                profile: Some(ADMIN_PROFILE),
                ..Call::new(
                    "GET",
                    "/api/v2/admin/users/{id}/profiles",
                    "go_reads_profile",
                )
            },
        );
    }
    go(
        f,
        surface,
        Call {
            at: Some(&at_member),
            admin: true,
            profile: Some(ADMIN_PROFILE),
            ..Call::new("DELETE", one, "go_deletes_member")
        },
    );
}

/// The admin projection of the settings API, and a validator Go must accept from a native read.
fn admin(f: &mut Flows, surface: Surface) {
    let v1 = surface == ApiV1;
    let base = if v1 { "/api/v1/admin" } else { "/api/v2/admin" };
    let list = format!("{base}/users/{{id}}/settings/values");
    let one = format!("{base}/users/{{id}}/settings/values/{{key}}");
    // The admin account: other flows give the member profiles with generated ids, which would sort differently.
    let list_at = list.replace("{id}", "${admin_user_id}");
    let theme = one
        .replace("{id}", "${member_user_id}")
        .replace("{key}", "ui.theme");
    let nav = one
        .replace("{id}", "${member_user_id}")
        .replace("{key}", "nav.shortcuts");
    let missing = one.replace("{id}", "999999").replace("{key}", "ui.theme");
    let profile = [("scope", "profile"), ("profile_id", USER_PROFILE)];
    let nobody = [("scope", "profile"), ("profile_id", "no-such-profile")];
    let bare = [("scope", "profile")];
    let device = [("scope", "profile_device"), ("profile_id", USER_PROFILE)];
    let call = |method, route, at, name, query, body| Call {
        at,
        query,
        body,
        admin: true,
        profile: Some(ADMIN_PROFILE),
        ..Call::new(method, route, name)
    };
    for c in [
        call(
            "PUT",
            one.as_str(),
            Some(theme.as_str()),
            "admin_value_put",
            &profile[..],
            Some("{\"value\":\"cinema-light\"}"),
        ),
        call(
            "PUT",
            one.as_str(),
            Some(theme.as_str()),
            "admin_value_bad",
            &profile[..],
            Some("{\"value\":\"nope\"}"),
        ),
        call(
            "PUT",
            one.as_str(),
            Some(theme.as_str()),
            "admin_value_nobody",
            &nobody[..],
            Some("{\"value\":\"cinema-light\"}"),
        ),
        call(
            "PUT",
            one.as_str(),
            Some(theme.as_str()),
            "admin_value_no_profile",
            &bare[..],
            Some("{\"value\":\"cinema-light\"}"),
        ),
        call(
            "PUT",
            one.as_str(),
            Some(theme.as_str()),
            "admin_value_device",
            &device[..],
            Some("{\"value\":\"cinema-light\"}"),
        ),
        call(
            "PUT",
            one.as_str(),
            Some(missing.as_str()),
            "admin_value_no_user",
            &profile[..],
            Some("{\"value\":\"cinema-light\"}"),
        ),
        call(
            "GET",
            list.as_str(),
            Some(list_at.as_str()),
            "admin_list",
            &[][..],
            None,
        ),
        call(
            "DELETE",
            one.as_str(),
            Some(nav.as_str()),
            "admin_nav_refused",
            &profile[..],
            None,
        ),
        call(
            "DELETE",
            one.as_str(),
            Some(theme.as_str()),
            "admin_value_delete",
            &profile[..],
            None,
        ),
        call(
            "DELETE",
            one.as_str(),
            Some(theme.as_str()),
            "admin_value_delete_again",
            &profile[..],
            None,
        ),
    ] {
        go(f, surface, c);
    }
    // Go checks If-Match against the tag a native read gave out.
    if !v1 {
        let read = Step {
            identity: Identity::Admin,
            profile: Some(ADMIN_PROFILE),
            capture: &[("settings_etag", "header:etag")],
            ..Step::new(
                surface,
                "GET",
                "/api/v2/admin/settings",
                "settings:v2:admin_snapshot",
            )
        };
        f.step(read);
        let write = Step {
            identity: Identity::Admin,
            profile: Some(ADMIN_PROFILE),
            headers: &[("If-Match", "${settings_etag}")],
            body: Some("{\"values\":{\"ui.dashboard.flow\":\"x\"}}"),
            ..Step::new(
                surface,
                "PUT",
                "/api/v2/admin/settings",
                "settings:v2:go_checks_native_etag",
            )
        };
        f.step(write);
    }
}

/// Adds the settings steps. They run before the auth flows, which can leave no account to sign in with.
pub(crate) fn add(b: &mut Builder) {
    let mut f = Flows {
        b,
        seq: 0,
        prefix: "yflow",
    };
    admin(&mut f, ApiV1);
    admin(&mut f, ApiV2);
    legacy_v1(&mut f);
    values(&mut f, ApiV1);
    values(&mut f, ApiV2);
    profiles(&mut f, ApiV1);
    profiles(&mut f, ApiV2);
}
