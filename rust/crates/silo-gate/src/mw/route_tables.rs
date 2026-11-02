//! Generated from `internal/api/middleware/api_key_scopes.go` and `remote_playback.go` by
//! `rust/conformance/vectors/generators/mwroutes/gen.py`: (method, Go regexp).

pub const API_KEY_SCOPE_ROUTES: &[(&str, &str, &str)] = &[
    (
        "admin:sessions:summary:read",
        "GET",
        r"^/api/v2/admin/sessions/summary$",
    ),
    (
        "admin:sessions:summary:read",
        "GET",
        r"^/api/v2/admin/sessions/capabilities$",
    ),
    ("libraries:read", "GET", r"^/api/v2/user/libraries$"),
    (
        "libraries:read",
        "GET",
        r"^/api/v2/user/libraries/capabilities$",
    ),
    ("admin:users", "GET", r"^/api/v1/admin/users$"),
    ("admin:users", "POST", r"^/api/v1/admin/users$"),
    ("admin:users", "GET", r"^/api/v1/admin/users/[0-9]+$"),
    ("admin:users", "PUT", r"^/api/v1/admin/users/[0-9]+$"),
    ("admin:users", "DELETE", r"^/api/v1/admin/users/[0-9]+$"),
    (
        "admin:users",
        "GET",
        r"^/api/v1/admin/users/[0-9]+/profiles$",
    ),
    ("admin:users", "POST", r"^/api/v2/admin/users$"),
    ("admin:users", "GET", r"^/api/v2/admin/users/capabilities$"),
    (
        "admin:users",
        "GET",
        r"^/api/v2/admin/users/policy-defaults$",
    ),
    ("admin:users", "GET", r"^/api/v2/admin/users/[0-9]+$"),
    ("admin:users", "PUT", r"^/api/v2/admin/users/[0-9]+$"),
    ("admin:users", "DELETE", r"^/api/v2/admin/users/[0-9]+$"),
    (
        "admin:users",
        "GET",
        r"^/api/v2/admin/users/[0-9]+/profiles$",
    ),
    ("admin:users", "GET", r"^/api/v2/admin/users$"),
    ("admin:monitor:read", "GET", r"^/api/v2/admin/sessions$"),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/sessions/capabilities$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/sessions/command-capabilities$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/sessions/summary$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/events/capabilities$",
    ),
    ("admin:monitor:read", "POST", r"^/api/v2/events/ws-ticket$"),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/playback-history$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/playback-history/capabilities$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/stats/(timeseries|playback-activity|top-activity|downloads)$",
    ),
    ("admin:monitor:read", "GET", r"^/api/v2/admin/users$"),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/users/capabilities$",
    ),
    ("admin:monitor:read", "GET", r"^/api/v2/admin/users/[0-9]+$"),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/users/[0-9]+/(profiles|devices|ips|downloads|downloads/summary|watch-summary)$",
    ),
    ("admin:monitor:read", "GET", r"^/api/v2/admin/devices$"),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/devices/capabilities$",
    ),
    ("admin:monitor:read", "GET", r"^/api/v2/admin/ips$"),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/downloads/(entries|devices|preparations|preparations/capabilities)$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/system/resources$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/system/resources/capabilities$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/nodes/summary$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/nodes/capabilities$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/server/status$",
    ),
    (
        "admin:monitor:read",
        "GET",
        r"^/api/v2/admin/catalog/(items|capabilities)$",
    ),
    (
        "admin:sessions:control",
        "GET",
        r"^/api/v2/admin/sessions/command-capabilities$",
    ),
    (
        "admin:sessions:control",
        "POST",
        r"^/api/v2/admin/sessions/[^/]+/(pause|resume|stop|message|terminate)$",
    ),
    (
        "admin:access-groups:read",
        "GET",
        r"^/api/v2/admin/access-groups$",
    ),
    (
        "admin:access-groups:read",
        "GET",
        r"^/api/v2/admin/access-groups/[0-9]+$",
    ),
    (
        "admin:access-groups:read",
        "GET",
        r"^/api/v1/admin/access-groups$",
    ),
    (
        "admin:access-groups:read",
        "GET",
        r"^/api/v1/admin/access-groups/[0-9]+$",
    ),
];

pub const REMOTE_PLAYBACK_ROUTES: &[(&str, &str)] = &[
    ("GET", r"^/api/v2/account/me$"),
    ("POST", r"^/api/v2/auth/logout$"),
    ("GET", r"^/api/v2/profiles$"),
    ("GET", r"^/api/v2/playback/capabilities$"),
    ("POST", r"^/api/v2/playback/(start|route-events)$"),
    ("DELETE", r"^/api/v2/playback/[^/]+$"),
    ("POST", r"^/api/v2/playback/[^/]+/(progress|replan)$"),
    (
        "GET",
        r"^/api/v2/playback/transcode/[^/]+/(master\.m3u8|segment/[^/]+)$",
    ),
    ("GET", r"^/api/v2/playback/sessions/control/capabilities$"),
    (
        "POST",
        r"^/api/v2/playback/sessions/[^/]+/control/ws-ticket$",
    ),
    ("GET", r"^/api/v2/stream/[^/]+(/subtitles/[^/]+(/fonts)?)?$"),
    ("HEAD", r"^/api/v2/stream/[^/]+(/subtitles/[^/]+)?$"),
    ("GET", r"^/api/v2/watch/[^/]+(/trickplay)?$"),
    ("GET", r"^/api/v2/markers/(items|files)/[^/]+$"),
    (
        "GET",
        r"^/api/v2/sync/progress/(capabilities|snapshots/[^/]+)$",
    ),
    ("POST", r"^/api/v2/sync/progress(/snapshots)?$"),
    ("GET", r"^/api/v2/(audio|subtitle)-prefs/[^/]+$"),
    ("PUT", r"^/api/v2/(audio|subtitle)-prefs/[^/]+$"),
    ("DELETE", r"^/api/v2/(audio|subtitle)-prefs/[^/]+$"),
    ("GET", r"^/api/v2/library-playback-prefs$"),
    (
        "GET",
        r"^/api/v2/subtitles/(providers/status|sync/status|ai/(status|quota|jobs(/[^/]+)?)|[0-9]+)$",
    ),
    (
        "POST",
        r"^/api/v2/subtitles/(search|download|detect-language|ai/translate|ai/jobs/[^/]+/cancel)$",
    ),
    (
        "GET",
        r"^/api/v2/subtitles/([0-9]+/sync(/[^/]+)?|stored/[^/]+/(sync|metadata))$",
    ),
    (
        "POST",
        r"^/api/v2/subtitles/([0-9]+/sync/[^/]+|stored/[^/]+/sync)$",
    ),
    (
        "PUT",
        r"^/api/v2/subtitles/([0-9]+/sync/[^/]+|stored/[^/]+)/timing$",
    ),
    (
        "GET",
        r"^/api/v2/home/(capabilities|layout|sections(/[^/]+/items)?)$",
    ),
    (
        "GET",
        r"^/api/v2/catalog(/(filters(/search)?|search/capabilities|people(/[^/]+)?|works/[^/]+|items/[^/]+(/(episodes|versions))?|series/[^/]+/seasons(/[0-9]+(/episodes)?)?))?$",
    ),
    ("POST", r"^/api/v2/catalog/query$"),
    (
        "GET",
        r"^/api/v2/library/[^/]+/(layout|sections(/[^/]+/items)?|collections(/[^/]+/items)?)$",
    ),
    ("GET", r"^/api/v2/user/libraries(/capabilities)?$"),
    ("GET", r"^/api/v2/images/capabilities$"),
    (
        "GET",
        r"^/api/v2/settings/(contract(/capabilities)?|values/effective|subtitle-appearance/effective|overlay-config)$",
    ),
    ("POST", r"^/api/v2/settings/values/effective$"),
    ("GET", r"^/api/v2/events/capabilities$"),
    ("POST", r"^/api/v2/events/ws-ticket$"),
];
