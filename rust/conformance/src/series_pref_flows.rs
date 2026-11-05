//! Success paths for the v2 per-series audio and subtitle preferences: a read before any write, a
//! replace, a read back, the forced-subtitle merge, a refused body, and a delete, for the user, the
//! administrator, and the seeded kid profile.

use crate::auth_flows::{Flows, Step};
use crate::model::*;
use crate::plan::Builder;
use Surface::ApiV2;

const SERIES: &str = "series-tvdb-9000003";

fn go(
    f: &mut Flows,
    who: (&str, Identity, &str),
    method: &str,
    route: &str,
    name: &str,
    body: Option<&str>,
) {
    let (label, identity, profile) = who;
    let name = format!("series_prefs:{label}:{name}");
    let at = route.replace("{series_id}", SERIES);
    f.step(Step {
        identity,
        at: Some(&at),
        body,
        profile: Some(profile),
        ..Step::new(ApiV2, method, route, &name)
    });
}

fn audio(f: &mut Flows, who: (&str, Identity, &str)) {
    let r = "/api/v2/audio-prefs/{series_id}";
    go(f, who, "GET", r, "audio_absent", None);
    go(f, who, "DELETE", r, "audio_delete_absent", None);
    let body = "{\"audio_track_index\":1,\"audio_language\":\" ENG \",\"track_signature\":{\"language\":\"en\",\"codec\":\"eac3\",\"channels\":6,\"default\":true}}";
    go(f, who, "PUT", r, "audio_set", Some(body));
    go(f, who, "GET", r, "audio_get", None);
    go(
        f,
        who,
        "PUT",
        r,
        "audio_bad_language",
        Some("{\"audio_track_index\":0,\"audio_language\":\"not a language\"}"),
    );
    go(
        f,
        who,
        "PUT",
        r,
        "audio_bad_index",
        Some("{\"audio_track_index\":-2}"),
    );
    go(
        f,
        who,
        "PUT",
        r,
        "audio_replace",
        Some("{\"audio_track_index\":0}"),
    );
    go(f, who, "GET", r, "audio_replaced", None);
    go(f, who, "DELETE", r, "audio_delete", None);
    go(f, who, "GET", r, "audio_gone", None);
}

fn subtitle(f: &mut Flows, who: (&str, Identity, &str)) {
    let r = "/api/v2/subtitle-prefs/{series_id}";
    go(f, who, "GET", r, "subtitle_absent", None);
    let body = "{\"subtitle_track_index\":2,\"subtitle_language\":\"pt_br\",\"subtitle_mode\":\"always\",\"external_subtitle_path\":\"Show.S01E01.eng.srt\",\"show_forced_subtitles\":true,\"track_signature\":{\"source\":\"external\",\"label\":\"English (SDH)\",\"hearing_impaired\":true}}";
    go(f, who, "PUT", r, "subtitle_set", Some(body));
    go(f, who, "GET", r, "subtitle_get", None);
    // An omitted show_forced_subtitles keeps the canonical override.
    go(
        f,
        who,
        "PUT",
        r,
        "subtitle_keep_forced",
        Some("{\"subtitle_track_index\":-1}"),
    );
    go(f, who, "GET", r, "subtitle_kept", None);
    go(
        f,
        who,
        "PUT",
        r,
        "subtitle_bad_mode",
        Some("{\"subtitle_track_index\":0,\"subtitle_mode\":\"sometimes\"}"),
    );
    go(
        f,
        who,
        "PUT",
        r,
        "subtitle_clear_forced",
        Some("{\"subtitle_track_index\":0,\"show_forced_subtitles\":false}"),
    );
    go(f, who, "GET", r, "subtitle_cleared", None);
    go(f, who, "DELETE", r, "subtitle_delete", None);
    go(f, who, "GET", r, "subtitle_gone", None);
}

pub(crate) fn add(b: &mut Builder) {
    let mut flows = Flows {
        b,
        seq: 0,
        prefix: "xflow-series-prefs",
    };
    let f = &mut flows;
    for who in [
        ("user", Identity::User, "${user_profile_id}"),
        ("admin", Identity::Admin, "${admin_profile_id}"),
        // The seeded kid profile (PG ceiling): these rows read no catalog, so the ceiling must not change them.
        ("kid", Identity::Kid, "${kid_profile_id}"),
    ] {
        audio(f, who);
        subtitle(f, who);
    }
}
