//! Success paths for the v2 series monitor reads: an empty page, a monitor created through Go, the
//! page and the monitor read back, a page cursor, another device's view, and an unknown id, for the
//! user, the administrator, and the seeded kid profile.

use crate::auth_flows::{Flows, Step};
use crate::model::*;
use crate::plan::Builder;
use Surface::ApiV2;

const SERIES: &str = "series-tvdb-9000003";
const DEVICE: &[(&str, &str)] = &[("X-Silo-Device-Id", "conformance-device-1")];
const OTHER: &[(&str, &str)] = &[("X-Silo-Device-Id", "conformance-device-2")];

#[allow(clippy::too_many_arguments)]
fn go(
    f: &mut Flows,
    who: (&str, Identity, &str),
    method: &str,
    route: &str,
    at: &str,
    name: &str,
    headers: &[(&str, &str)],
    query: &[(&str, &str)],
    body: Option<&str>,
    capture: &[(&str, &str)],
) {
    let (label, identity, profile) = who;
    let name = format!("downloads:{label}:{name}");
    f.step(Step {
        identity,
        at: Some(at),
        body,
        profile: Some(profile),
        headers,
        query,
        capture,
        ..Step::new(ApiV2, method, route, &name)
    });
}

fn monitors(f: &mut Flows, who: (&str, Identity, &str)) {
    let list = "/api/v2/downloads/subscriptions";
    let one = "/api/v2/downloads/subscriptions/{id}";
    let fact = format!("download_sub_{}", who.0);
    let at = format!("/api/v2/downloads/subscriptions/${{{fact}}}");
    go(
        f,
        who,
        "GET",
        list,
        list,
        "list_empty",
        DEVICE,
        &[],
        None,
        &[],
    );
    let body = format!(
        "{{\"series_id\":\"{SERIES}\",\"mode\":\"specific_seasons\",\"season_numbers\":[2,1],\"delete_watched\":true,\"max_storage_bytes\":1073741824}}"
    );
    go(
        f,
        who,
        "POST",
        list,
        list,
        "create",
        DEVICE,
        &[],
        Some(&body),
        &[(&fact, "/id")],
    );
    go(f, who, "GET", list, list, "list", DEVICE, &[], None, &[]);
    go(
        f,
        who,
        "GET",
        list,
        list,
        "list_page",
        DEVICE,
        &[("limit", "1")],
        None,
        &[],
    );
    go(
        f,
        who,
        "GET",
        list,
        list,
        "list_other_device",
        OTHER,
        &[],
        None,
        &[],
    );
    go(f, who, "GET", one, &at, "get", DEVICE, &[], None, &[]);
    go(
        f,
        who,
        "GET",
        one,
        &at,
        "get_other_device",
        OTHER,
        &[],
        None,
        &[],
    );
    go(
        f,
        who,
        "GET",
        one,
        "/api/v2/downloads/subscriptions/conformance-missing",
        "get_missing",
        DEVICE,
        &[],
        None,
        &[],
    );
    go(
        f,
        who,
        "GET",
        list,
        list,
        "list_bad_cursor",
        DEVICE,
        &[("cursor", "not-a-cursor")],
        None,
        &[],
    );
}

pub(crate) fn add(b: &mut Builder) {
    let mut flows = Flows {
        b,
        seq: 0,
        prefix: "xflow-downloads",
    };
    let f = &mut flows;
    for who in [
        ("user", Identity::User, "${user_profile_id}"),
        ("admin", Identity::Admin, "${admin_profile_id}"),
        // The seeded kid profile (PG ceiling): creating may be refused, and the reads must agree.
        ("kid", Identity::Kid, "${kid_profile_id}"),
    ] {
        monitors(f, who);
    }
}
