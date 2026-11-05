//! Per-series track preferences and their canonical profile_series overrides.
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use silo_api_v2::problem::{Problem, ProblemError, type_for_status, validation_failed};
use silo_config::resolve::SettingIdentity;
use silo_config::settings::{Scope, keys};
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::json::unmarshal;
use silo_gocompat::time::{GoTime, RFC3339_NANO};
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_store::userstore::prefs::Writer;

use super::auth::service_problem;
use super::chain::{Stack, Step, V2Class, write_problem, write_v2_json};
use super::huma::decode_body;
use super::profiles::{Sync, plan_sync, string_sync};
use super::settings::{api, publish_user_settings, stored_instant, write_canonical_sync};
use crate::rows::{NativeRow, Surface::ApiV2};

const AUDIO: &str = "/api/v2/audio-prefs/{series_id}";
const SUBTITLE: &str = "/api/v2/subtitle-prefs/{series_id}";
pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", AUDIO),
    NativeRow::new(ApiV2, "PUT", AUDIO),
    NativeRow::new(ApiV2, "DELETE", AUDIO),
    NativeRow::new(ApiV2, "GET", SUBTITLE),
    NativeRow::new(ApiV2, "PUT", SUBTITLE),
    NativeRow::new(ApiV2, "DELETE", SUBTITLE),
];
const MUTATE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::Profile,
];
const SUBTITLE_KEYS: [&str; 3] = [
    keys::PLAYBACK_SUBTITLE_LANGUAGE,
    keys::PLAYBACK_SUBTITLE_MODE,
    keys::PLAYBACK_SHOW_FORCED_SUBTITLES,
];

fn zero(n: &i64) -> bool {
    *n == 0
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename = "AudioTrackSignature")]
struct AudioSignature {
    #[serde(skip_serializing_if = "String::is_empty")]
    language: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    embedded_title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    codec: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    layout: String,
    #[serde(skip_serializing_if = "zero")]
    channels: i64,
    default: bool,
}
impl AudioSignature {
    fn is_zero(&self) -> bool {
        self.language.is_empty()
            && self.title.is_empty()
            && self.embedded_title.is_empty()
            && self.codec.is_empty()
            && self.layout.is_empty()
            && self.channels == 0
            && !self.default
    }
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename = "SubtitleTrackSignature")]
struct SubtitleSignature {
    #[serde(skip_serializing_if = "String::is_empty")]
    source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    language: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    codec: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,
    forced: bool,
    hearing_impaired: bool,
}
impl SubtitleSignature {
    fn is_zero(&self) -> bool {
        self.source.is_empty()
            && self.language.is_empty()
            && self.codec.is_empty()
            && self.label.is_empty()
            && !self.forced
            && !self.hearing_impaired
    }
}
#[derive(Default, Deserialize)]
#[serde(default, rename = "AudioPreferenceUpdate")]
struct AudioUpdate {
    audio_track_index: i64,
    audio_language: String,
    track_signature: Option<AudioSignature>,
}
#[derive(Default, Deserialize)]
#[serde(default, rename = "SubtitlePreferenceUpdate")]
struct SubtitleUpdate {
    subtitle_track_index: i64,
    subtitle_language: String,
    external_subtitle_path: String,
    subtitle_mode: String,
    track_signature: Option<SubtitleSignature>,
    show_forced_subtitles: Option<bool>,
}
#[derive(Serialize)]
struct AudioPreference {
    profile_id: String,
    series_id: String,
    audio_track_index: i32,
    audio_language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    track_signature: Option<AudioSignature>,
    updated_at: String,
}
#[derive(Serialize)]
struct SubtitlePreference {
    profile_id: String,
    series_id: String,
    subtitle_language: String,
    subtitle_track_index: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    external_subtitle_path: String,
    subtitle_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    track_signature: Option<SubtitleSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    show_forced_subtitles: Option<bool>,
    updated_at: String,
}

fn problem(status: u16, message: &str) -> Problem {
    service_problem(&api(
        status,
        if status == 404 {
            "not_found"
        } else if status == 400 {
            "bad_request"
        } else {
            "internal_error"
        },
        message,
    ))
}
fn audio_invalid(detail: String) -> Problem {
    Problem::new(
        validation_failed(),
        "The request did not pass validation; see errors.",
    )
    .with_errors([ProblemError {
        location: "body.audio_language".to_owned(),
        code: "invalid".to_owned(),
        detail,
    }])
}
fn identity(profile: &str, series: &str) -> SettingIdentity {
    SettingIdentity {
        scope: Scope::PROFILE_SERIES,
        profile_id: profile.to_owned(),
        series_id: series.to_owned(),
        ..Default::default()
    }
}
fn acting(r: &Request) -> Result<(i64, String), Problem> {
    let profile = get_profile_id(r);
    match get_claims(r) {
        Some(c) if !profile.is_empty() => Ok((c.user_id, profile)),
        _ => Err(Problem::new(
            type_for_status(401),
            "Authentication is required.",
        )),
    }
}

fn instant(raw: &str) -> Result<String, Problem> {
    if !raw.is_empty()
        && silo_gocompat::time::parse(RFC3339_NANO, raw)
            .map_or(true, |t| t.unix() == -62_135_596_800 && t.nanosecond() == 0)
    {
        return Err(Problem::new(
            type_for_status(500),
            "An unexpected error occurred.",
        ));
    }
    Ok(stored_instant(raw)?.unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_owned()))
}
fn newest(current: &mut String, candidate: &str) {
    let Ok(next) = silo_gocompat::time::parse(RFC3339_NANO, candidate) else {
        return;
    };
    if silo_gocompat::time::parse(RFC3339_NANO, current).map_or(true, |old| {
        (next.unix(), next.nanosecond()) > (old.unix(), old.nanosecond())
    }) {
        *current = candidate.to_owned();
    }
}
async fn member<T: serde::de::DeserializeOwned + Default>(
    writer: &mut Writer<'_>,
    base: &SettingIdentity,
    key: &str,
) -> Result<(Option<T>, String), String> {
    let mut id = base.clone();
    id.key = key.to_owned();
    let Some(value) = writer
        .get_setting_value(&id)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok((None, String::new()));
    };
    Ok((
        Some(unmarshal(&value.value).map_err(|e| e.to_string())?),
        value.updated_at,
    ))
}
fn signature_json<T: Serialize>(signature: Option<&T>) -> serde_json::Value {
    signature.map_or_else(
        || serde_json::json!({}),
        |s| serde_json::to_value(s).expect("track signature serializes"),
    )
}
fn subtitle_sync(body: &SubtitleUpdate) -> Result<Vec<Sync>, String> {
    let mut writes = plan_sync(
        None,
        Some(&body.subtitle_language),
        None,
        Some(&body.subtitle_mode),
        None,
        None,
        None,
        None,
        None,
    )?;
    writes.push((
        keys::PLAYBACK_SHOW_FORCED_SUBTITLES.to_owned(),
        body.show_forced_subtitles.map(|v| v.to_string()),
    ));
    Ok(writes)
}

async fn get_audio(
    s: &Stack,
    user: i64,
    profile: &str,
    series: &str,
) -> Result<AudioPreference, Problem> {
    let failed = || problem(500, "Failed to get audio preference");
    let mut conn = s.pool.acquire().await.map_err(|_| failed())?;
    let mut tx = conn.begin().await.map_err(|_| failed())?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await
        .map_err(|_| failed())?;
    let rows = tx
        .query(GET_AUDIO, &[&silo_pg::AnyInt(user), &profile, &series])
        .await
        .map_err(|_| failed())?;
    let row = rows
        .first()
        .ok_or_else(|| problem(404, "Audio preference not found"))?;
    let _: String = row.try_get(3).map_err(|_| failed())?;
    let signature: silo_pg::TextValue = row.try_get(4).map_err(|_| failed())?;
    let signature: Option<AudioSignature> =
        unmarshal(signature.0.as_bytes()).map_err(|_| failed())?;
    let mut at = GoTime::from_system_time(row.try_get::<_, SystemTime>(5).map_err(|_| failed())?)
        .format("2006-01-02T15:04:05Z07:00");
    let mut writer = Writer {
        tx: &mut tx,
        user_id: silo_pg::AnyInt(user),
    };
    let (language, language_at) = member::<String>(
        &mut writer,
        &identity(profile, series),
        keys::PLAYBACK_AUDIO_LANGUAGE,
    )
    .await
    .map_err(|_| failed())?;
    newest(&mut at, &language_at);
    let out = AudioPreference {
        profile_id: row.try_get(0).map_err(|_| failed())?,
        series_id: row.try_get(1).map_err(|_| failed())?,
        audio_track_index: row.try_get(2).map_err(|_| failed())?,
        audio_language: language.unwrap_or_default(),
        track_signature: signature.filter(|s| !s.is_zero()),
        updated_at: instant(&at)?,
    };
    tx.commit().await.map_err(|_| failed())?;
    Ok(out)
}
async fn get_subtitle(
    s: &Stack,
    user: i64,
    profile: &str,
    series: &str,
) -> Result<SubtitlePreference, Problem> {
    let failed = || problem(500, "Failed to get subtitle preference");
    let mut conn = s.pool.acquire().await.map_err(|_| failed())?;
    let mut tx = conn.begin().await.map_err(|_| failed())?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await
        .map_err(|_| failed())?;
    let rows = tx
        .query(GET_SUBTITLE, &[&silo_pg::AnyInt(user), &profile, &series])
        .await
        .map_err(|_| failed())?;
    let row = rows
        .first()
        .ok_or_else(|| problem(404, "Subtitle preference not found"))?;
    let signature: silo_pg::TextValue = row.try_get(6).map_err(|_| failed())?;
    let signature: Option<SubtitleSignature> =
        unmarshal(signature.0.as_bytes()).map_err(|_| failed())?;
    let mut at = GoTime::from_system_time(row.try_get::<_, SystemTime>(8).map_err(|_| failed())?)
        .format("2006-01-02T15:04:05Z07:00");
    let mut writer = Writer {
        tx: &mut tx,
        user_id: silo_pg::AnyInt(user),
    };
    let base = identity(profile, series);
    let (language, language_at) = member::<String>(&mut writer, &base, SUBTITLE_KEYS[0])
        .await
        .map_err(|_| failed())?;
    let (mode, mode_at) = member::<String>(&mut writer, &base, SUBTITLE_KEYS[1])
        .await
        .map_err(|_| failed())?;
    let (forced, forced_at) = member::<bool>(&mut writer, &base, SUBTITLE_KEYS[2])
        .await
        .map_err(|_| failed())?;
    for candidate in [&language_at, &mode_at, &forced_at] {
        newest(&mut at, candidate);
    }
    let out = SubtitlePreference {
        profile_id: row.try_get(0).map_err(|_| failed())?,
        series_id: row.try_get(1).map_err(|_| failed())?,
        subtitle_language: language.unwrap_or_default(),
        subtitle_track_index: row.try_get(3).map_err(|_| failed())?,
        external_subtitle_path: row.try_get(4).map_err(|_| failed())?,
        subtitle_mode: mode.unwrap_or_default(),
        track_signature: signature.filter(|s| !s.is_zero()),
        show_forced_subtitles: forced,
        updated_at: instant(&at)?,
    };
    tx.commit().await.map_err(|_| failed())?;
    Ok(out)
}

enum Mutation {
    Audio(AudioUpdate),
    Subtitle(SubtitleUpdate),
    DeleteAudio,
    DeleteSubtitle,
}
async fn mutate(
    s: &Stack,
    user: i64,
    profile: &str,
    series: &str,
    mut change: Mutation,
) -> Result<(), Problem> {
    let message = match &change {
        Mutation::Audio(_) => "Failed to store audio preference",
        Mutation::Subtitle(_) => "Failed to store subtitle preference",
        Mutation::DeleteAudio => "Failed to delete audio preference",
        Mutation::DeleteSubtitle => "Failed to delete subtitle preference",
    };
    let failed = || problem(500, message);
    let mut writes = match &change {
        Mutation::Audio(body) => {
            let mut writes = Vec::new();
            string_sync(
                &mut writes,
                keys::PLAYBACK_AUDIO_LANGUAGE,
                Some(&body.audio_language),
            )
            .map_err(audio_invalid)?;
            writes
        }
        Mutation::Subtitle(body) => subtitle_sync(body).map_err(|e| problem(400, &e))?,
        Mutation::DeleteAudio => vec![(keys::PLAYBACK_AUDIO_LANGUAGE.to_owned(), None)],
        Mutation::DeleteSubtitle => SUBTITLE_KEYS
            .iter()
            .map(|key| ((*key).to_owned(), None))
            .collect(),
    };
    let mut conn = s.pool.acquire().await.map_err(|_| failed())?;
    let mut tx = conn.begin().await.map_err(|_| failed())?;
    let base = identity(profile, series);
    let changed = {
        let mut writer = Writer {
            tx: &mut tx,
            user_id: silo_pg::AnyInt(user),
        };
        writer.lock_preferences().await.map_err(|_| failed())?;
        let now = GoTime::now_utc().to_utc().format("2006-01-02T15:04:05Z");
        let now = silo_gocompat::time::parse(RFC3339_NANO, &now)
            .expect("RFC3339 time")
            .to_system_time();
        match &mut change {
            Mutation::Audio(body) => {
                let signature =
                    signature_json(body.track_signature.as_ref().filter(|s| !s.is_zero()));
                writer
                    .tx
                    .execute(
                        SET_AUDIO,
                        &[
                            &silo_pg::AnyInt(user),
                            &profile,
                            &series,
                            &silo_pg::AnyInt(body.audio_track_index),
                            &body.audio_language,
                            &silo_pg::PgText(&signature.to_string()),
                            &now,
                        ],
                    )
                    .await
                    .map_err(|_| failed())?;
            }
            Mutation::Subtitle(body) => {
                if body.show_forced_subtitles.is_none() {
                    body.show_forced_subtitles =
                        member::<bool>(&mut writer, &base, keys::PLAYBACK_SHOW_FORCED_SUBTITLES)
                            .await
                            .map_err(|_| failed())?
                            .0;
                    writes = subtitle_sync(body).map_err(|_| failed())?;
                }
                let signature =
                    signature_json(body.track_signature.as_ref().filter(|s| !s.is_zero()));
                writer
                    .tx
                    .execute(
                        SET_SUBTITLE,
                        &[
                            &silo_pg::AnyInt(user),
                            &profile,
                            &series,
                            &body.subtitle_language,
                            &silo_pg::AnyInt(body.subtitle_track_index),
                            &body.external_subtitle_path,
                            &body.subtitle_mode,
                            &silo_pg::PgText(&signature.to_string()),
                            &body.show_forced_subtitles,
                            &now,
                        ],
                    )
                    .await
                    .map_err(|_| failed())?;
            }
            Mutation::DeleteAudio => {
                writer
                    .tx
                    .execute(DELETE_AUDIO, &[&silo_pg::AnyInt(user), &profile, &series])
                    .await
                    .map_err(|_| failed())?;
            }
            Mutation::DeleteSubtitle => {
                writer
                    .tx
                    .execute(
                        DELETE_SUBTITLE,
                        &[&silo_pg::AnyInt(user), &profile, &series],
                    )
                    .await
                    .map_err(|_| failed())?;
            }
        }
        write_canonical_sync(&mut writer, &base, &writes)
            .await
            .map_err(|_| failed())?
    };
    tx.commit().await.map_err(|_| failed())?;
    for key in changed {
        publish_user_settings(s, user, profile, &key, "profile_series").await;
    }
    Ok(())
}

pub fn mount(stack: &Arc<Stack>, _api: &Mux, v2: &Mux) {
    for (path, audio) in [(AUDIO, true), (SUBTITLE, false)] {
        let s = stack.clone();
        v2.get(
            path,
            stack.v2(
                path,
                V2Class::ProfileScoped,
                handler_fn(move |w, r| {
                    let s = s.clone();
                    Box::pin(async move {
                        let (user, profile) = match acting(r) {
                            Ok(v) => v,
                            Err(p) => return write_problem(w, r, p).await,
                        };
                        if audio {
                            match get_audio(&s, user, &profile, r.url_param("series_id")).await {
                                Ok(v) => write_v2_json(w, &v).await,
                                Err(p) => write_problem(w, r, p).await,
                            }
                        } else {
                            match get_subtitle(&s, user, &profile, r.url_param("series_id")).await {
                                Ok(v) => write_v2_json(w, &v).await,
                                Err(p) => write_problem(w, r, p).await,
                            }
                        }
                    })
                }),
            ),
        );
        for delete in [false, true] {
            let s = stack.clone();
            let handler = stack.v2_steps(
                path,
                MUTATE,
                handler_fn(move |w, r| {
                    let s = s.clone();
                    Box::pin(async move {
                        let (user, profile) = match acting(r) {
                            Ok(v) => v,
                            Err(p) => return write_problem(w, r, p).await,
                        };
                        let change = match (audio, delete) {
                            (true, true) => Mutation::DeleteAudio,
                            (false, true) => Mutation::DeleteSubtitle,
                            (true, false) => Mutation::Audio(match decode_body(r) {
                                Ok(body) => body,
                                Err(p) => return write_problem(w, r, p).await,
                            }),
                            (false, false) => Mutation::Subtitle(match decode_body(r) {
                                Ok(body) => body,
                                Err(p) => return write_problem(w, r, p).await,
                            }),
                        };
                        match mutate(&s, user, &profile, r.url_param("series_id"), change).await {
                            Ok(()) => w.write_header(204).await,
                            Err(p) => write_problem(w, r, p).await,
                        }
                    })
                }),
            );
            if delete {
                v2.delete(path, handler);
            } else {
                v2.put(path, handler);
            }
        }
    }
}

const SET_AUDIO: &str = r#"
		INSERT INTO user_audio_preferences (
			user_id, profile_id, series_id, audio_track_index,
			audio_language, audio_track_signature, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT(user_id, profile_id, series_id) DO UPDATE SET
			audio_track_index = excluded.audio_track_index,
			audio_language = excluded.audio_language,
			audio_track_signature = excluded.audio_track_signature,
			updated_at = excluded.updated_at"#;

const GET_AUDIO: &str = r#"
		SELECT profile_id, series_id, audio_track_index,
		       audio_language, audio_track_signature, updated_at
		FROM user_audio_preferences
		WHERE user_id = $1 AND profile_id = $2 AND series_id = $3"#;

const DELETE_AUDIO: &str = r#"DELETE FROM user_audio_preferences WHERE user_id = $1 AND profile_id = $2 AND series_id = $3"#;

const SET_SUBTITLE: &str = r#"
		INSERT INTO user_subtitle_preferences (
			user_id, profile_id, series_id, subtitle_language, subtitle_track_index,
			external_subtitle_path, subtitle_mode, subtitle_track_signature, show_forced_subtitles, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT(user_id, profile_id, series_id) DO UPDATE SET
			subtitle_language = excluded.subtitle_language,
			subtitle_track_index = excluded.subtitle_track_index,
			external_subtitle_path = excluded.external_subtitle_path,
			subtitle_mode = excluded.subtitle_mode,
			subtitle_track_signature = excluded.subtitle_track_signature,
			show_forced_subtitles = excluded.show_forced_subtitles,
			updated_at = excluded.updated_at"#;

const GET_SUBTITLE: &str = r#"
		SELECT profile_id, series_id, subtitle_language, subtitle_track_index,
		       external_subtitle_path, subtitle_mode, subtitle_track_signature, show_forced_subtitles, updated_at
		FROM user_subtitle_preferences
		WHERE user_id = $1 AND profile_id = $2 AND series_id = $3"#;

const DELETE_SUBTITLE: &str = r#"DELETE FROM user_subtitle_preferences WHERE user_id = $1 AND profile_id = $2 AND series_id = $3"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_preserve_false_flags_but_omit_zero_signatures() {
        let audio: AudioSignature = unmarshal(br#"{"language":"en","default":false}"#).unwrap();
        assert!(!audio.is_zero());
        assert_eq!(
            signature_json(Some(&audio)),
            serde_json::json!({"language":"en","default":false})
        );
        let subtitle: SubtitleSignature = unmarshal(br#"{"label":"SDH"}"#).unwrap();
        assert!(!subtitle.is_zero());
        assert_eq!(
            signature_json(Some(&subtitle)),
            serde_json::json!({"label":"SDH","forced":false,"hearing_impaired":false})
        );
        let zero: AudioSignature = unmarshal(br#"{"default":false}"#).unwrap();
        assert!(zero.is_zero());
        assert_eq!(
            signature_json(Some(&zero).filter(|s| !s.is_zero())),
            serde_json::json!({})
        );
    }

    #[test]
    fn body_uses_go_zero_values_and_case_insensitive_members() {
        let body: AudioUpdate = unmarshal(br#"{"AUDIO_LANGUAGE":"en","audio_language":null,"track_signature":{"TITLE":"commentary"}}"#).unwrap();
        assert_eq!(body.audio_track_index, 0);
        assert_eq!(body.audio_language, "en");
        let sig = body.track_signature.unwrap();
        assert_eq!(sig.title, "commentary");
        assert!(!sig.default);
        let body: SubtitleUpdate = unmarshal(br#"{"show_forced_subtitles":false}"#).unwrap();
        assert_eq!(body.show_forced_subtitles, Some(false));
        assert_eq!(body.subtitle_track_index, 0);
        assert!(body.subtitle_language.is_empty());
        assert!(
            unmarshal::<SubtitleUpdate>(b"{}")
                .unwrap()
                .show_forced_subtitles
                .is_none()
        );
    }

    #[test]
    fn preference_instants_and_latest_canonical_time() {
        assert_eq!(instant("").unwrap(), "1970-01-01T00:00:00.000Z");
        let mut stamp = "2026-01-02T03:04:05Z".to_owned();
        newest(&mut stamp, "2026-01-02T04:04:04+01:00");
        assert_eq!(stamp, "2026-01-02T03:04:05Z");
        newest(&mut stamp, "2026-01-02T04:04:06+01:00");
        assert_eq!(instant(&stamp).unwrap(), "2026-01-02T03:04:06.000Z");
        newest(&mut stamp, "invalid");
        assert!(instant("invalid").is_err());
        assert!(instant("0001-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn typed_huma_decode_rejects_nested_fractional_and_overflow_integers() {
        for (raw, detail) in [
            (
                br#"{"audio_track_index":0,"track_signature":{"channels":1.0}}"#.as_slice(),
                "json: cannot unmarshal number 1.0 into Go struct field AudioTrackSignature.track_signature.channels of type int",
            ),
            (
                br#"{"audio_track_index":9223372036854775808}"#.as_slice(),
                "json: cannot unmarshal number 9223372036854775808 into Go struct field AudioPreferenceUpdate.audio_track_index of type int",
            ),
        ] {
            let mut request = Request::new_for_test("PUT", "/api/v2/audio-prefs/series");
            request
                .extensions
                .insert(super::super::huma::RawBody(raw.to_vec()));
            let problem = match decode_body::<AudioUpdate>(&request) {
                Ok(_) => panic!("integer decoding must fail"),
                Err(problem) => problem,
            };
            assert_eq!(problem.status, 422);
            assert_eq!(problem.errors[0].detail, detail);
        }
    }
}
