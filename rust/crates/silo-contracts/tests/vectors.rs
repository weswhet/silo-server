//! Differential tests against vectors from the real Go packages. The generators are under
//! `rust/conformance/vectors/generators/{lang,settings,migrate}`.

use serde_json::Value;
use silo_contracts::jsonschema::go_getwd;
use silo_contracts::lang::{
    canonical_tag, compatible_tag, primary_language, registered_tag, x_text_parse,
};
use silo_contracts::naming::sidecar_subtitle_tags;
use silo_contracts::settingscontract::load_contract;
use silo_contracts::settingsmigrate::{
    Input, LegacyDeviceSetting, LegacyLibraryPreference, LegacyProfile, LegacySeriesPreference,
    LegacySetting, Planner, canonical_key,
};

fn vector(name: &str) -> Value {
    let path = format!(
        "{}/../../conformance/vectors/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}")))
        .expect("valid JSON")
}

fn s<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key].as_str().unwrap_or_default()
}

fn report(failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} failures, first: \n{}",
        failures.len(),
        failures
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn language_tags_match_go() {
    let vectors = vector("lang/tags");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 40_000);
    let mut failures = Vec::new();
    for case in cases {
        let input = s(case, "in");
        let checks = [
            ("canonical", canonical_tag(input)),
            ("compatible", compatible_tag(input)),
            ("registered", registered_tag(input)),
            ("primary", primary_language(input)),
        ];
        for (key, got) in checks {
            if got != s(case, key) {
                failures.push(format!(
                    "{key}({input:?}) = {got:?}, want {:?}",
                    s(case, key)
                ));
            }
        }
    }
    report(&failures);
}

#[test]
fn x_text_parse_matches_go() {
    let vectors = vector("lang/parse");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 40_000);
    let mut failures = Vec::new();
    for case in cases {
        let input = s(case, "in");
        let got = x_text_parse(input);
        let want_err = case["err"].as_bool().unwrap();
        match got {
            None if want_err => {}
            Some(text) if !want_err && text == s(case, "out") => {}
            other => failures.push(format!(
                "parse({input:?}) = {other:?}, want err={want_err} out={:?}",
                s(case, "out")
            )),
        }
    }
    report(&failures);
}

#[test]
fn sidecar_tags_match_go() {
    let vectors = vector("lang/sidecar");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 1000);
    let mut failures = Vec::new();
    for case in cases {
        let got = sidecar_subtitle_tags(s(case, "video"), s(case, "subtitle"));
        let (ok, language, forced, hi) = match &got {
            Some(tags) => (
                true,
                tags.language.as_str(),
                tags.forced,
                tags.hearing_impaired,
            ),
            None => (false, "", false, false),
        };
        if ok != case["ok"].as_bool().unwrap()
            || language != s(case, "language")
            || forced != case["forced"].as_bool().unwrap()
            || hi != case["hearing_impaired"].as_bool().unwrap()
        {
            failures.push(format!("{case} got {got:?}"));
        }
    }
    report(&failures);
}

// Go validates an object's properties in map order, so when several fail, the order of their messages
// is random. A short run can't tell which messages are affected, so a mismatch falls back to comparing
// the message as a bag of tokens.
//
// Go also reports a propertyNames failure at a location it shares with its sibling properties, so the
// location it prints is whichever sibling ran last. The port prints the object's real location, and
// the comparison ignores that one token.
fn normalize_unstable(text: &str) -> Vec<String> {
    static LOCATION: std::sync::LazyLock<silo_gocompat::regexp::GoRegex> =
        std::sync::LazyLock::new(|| {
            silo_gocompat::regexp::GoRegex::must_compile(r"at '[^']*': invalid propertyName")
        });
    let text = LOCATION.replace_all_literal_string(text, "at ?: invalid propertyName");
    let mut tokens: Vec<String> = text
        .split([' ', '\n', ','])
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    tokens.sort();
    tokens
}

fn scrub(text: &str, cwd: &str) -> String {
    text.replace(&format!("file://{cwd}/"), "file://{CWD}/")
}

#[test]
fn value_validation_messages_match_go() {
    let contract = load_contract();
    let cwd = go_getwd();
    let vectors = vector("settings/validate");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 5000);
    let mut failures = Vec::new();
    for case in cases {
        let key = s(case, "key");
        let raw = s(case, "raw");
        let def = contract.manifest.lookup(key).expect("known key");
        let got = match def
            .value_schema
            .validate_value(raw.as_bytes(), &contract.schemas)
        {
            Ok(()) => String::new(),
            Err(err) => scrub(&err, &cwd),
        };
        let want = s(case, "err");
        if got != want && normalize_unstable(&got) != normalize_unstable(want) {
            failures.push(format!("{key} {raw}\n  got  {got}\n  want {want}"));
        }
    }
    report(&failures);
}

fn opt(case: &Value, key: &str) -> Option<String> {
    case[key].as_str().map(str::to_string)
}

fn opt_bool(case: &Value, key: &str) -> Option<bool> {
    case[key].as_bool()
}

fn input_of(case: &Value) -> Input {
    let empty = Vec::new();
    let list = |key: &str| case[key].as_array().unwrap_or(&empty).clone();
    Input {
        settings: list("settings")
            .iter()
            .map(|v| LegacySetting {
                key: s(v, "Key").to_string(),
                value: s(v, "Value").to_string(),
            })
            .collect(),
        device_settings: list("device_settings")
            .iter()
            .map(|v| LegacyDeviceSetting {
                profile_id: s(v, "ProfileID").to_string(),
                device_id: s(v, "DeviceID").to_string(),
                key: s(v, "Key").to_string(),
                value: s(v, "Value").to_string(),
            })
            .collect(),
        profiles: case["profiles"].as_array().map(|items| {
            items
                .iter()
                .map(|v| LegacyProfile {
                    id: s(v, "ID").to_string(),
                    language: opt(v, "Language"),
                    subtitle_language: opt(v, "SubtitleLanguage"),
                    subtitle_mode: opt(v, "SubtitleMode"),
                    show_forced_subtitles: opt_bool(v, "ShowForcedSubtitles"),
                    quality_preference: opt(v, "QualityPreference"),
                    preferred_metadata_language: opt(v, "PreferredMetadataLanguage"),
                    auto_skip_intro: opt_bool(v, "AutoSkipIntro"),
                    auto_skip_credits: opt_bool(v, "AutoSkipCredits"),
                    auto_skip_recap: opt_bool(v, "AutoSkipRecap"),
                    auto_play_next_preview: opt_bool(v, "AutoPlayNextPreview"),
                })
                .collect()
        }),
        series_prefs: list("series_prefs")
            .iter()
            .map(|v| LegacySeriesPreference {
                profile_id: s(v, "ProfileID").to_string(),
                series_id: s(v, "SeriesID").to_string(),
                audio_source_table: s(v, "AudioSourceTable").to_string(),
                subtitle_source_table: s(v, "SubtitleSourceTable").to_string(),
                audio_language: opt(v, "AudioLanguage"),
                subtitle_language: opt(v, "SubtitleLanguage"),
                subtitle_mode: opt(v, "SubtitleMode"),
                show_forced_subtitles: opt_bool(v, "ShowForcedSubtitles"),
            })
            .collect(),
        library_prefs: list("library_prefs")
            .iter()
            .map(|v| LegacyLibraryPreference {
                profile_id: s(v, "ProfileID").to_string(),
                library_id: v["LibraryID"].as_i64().unwrap_or(0),
                source_table: s(v, "SourceTable").to_string(),
                audio_language: opt(v, "AudioLanguage"),
                subtitle_language: opt(v, "SubtitleLanguage"),
                subtitle_mode: opt(v, "SubtitleMode"),
                show_forced_subtitles: opt_bool(v, "ShowForcedSubtitles"),
            })
            .collect(),
    }
}

#[test]
fn planner_matches_go() {
    let contract = load_contract();
    let cwd = go_getwd();
    let planner = Planner::new(contract);
    let vectors = vector("settings/plan");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 1000);
    // snapToStep's result depends on whether the CPU's fused multiply-add was used, so a snapped value
    // only reproduces on the architecture family the vectors came from.
    let fused_vectors = vectors["goarch"].as_str() == Some("arm64");
    let same_snap = fused_vectors == cfg!(target_arch = "aarch64");
    let empty = Vec::new();
    let mut failures = Vec::new();
    for case in cases {
        let name = s(case, "name");
        if !same_snap && name.contains("playback_speed") {
            continue;
        }
        let input = input_of(&case["input"]);
        let result = planner.plan(&input);
        let want_rows: Vec<String> = case["rows"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    s(r, "key"),
                    s(r, "scope"),
                    s(r, "profile_id"),
                    s(r, "device_id"),
                    r["library_id"].as_i64().unwrap_or(0),
                    s(r, "series_id"),
                    s(r, "value")
                )
            })
            .collect();
        let got_rows: Vec<String> = result
            .rows
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    r.key,
                    r.scope.map_or("", |scope| scope.as_str()),
                    r.profile_id,
                    r.device_id,
                    r.library_id,
                    r.series_id,
                    r.value
                )
            })
            .collect();
        let want_rejects: Vec<String> = case["rejects"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}|{}",
                    s(r, "source_table"),
                    s(r, "source_key"),
                    s(r, "identity"),
                    s(r, "value"),
                    s(r, "reason")
                )
            })
            .collect();
        let got_rejects: Vec<String> = result
            .rejects
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}|{}",
                    r.source_table,
                    r.source_key,
                    r.identity,
                    r.value,
                    scrub(&r.reason, &cwd)
                )
            })
            .collect();
        let bag = |items: &[String]| normalize_unstable(&items.join("\n"));
        let rejects_same = got_rejects == want_rejects || bag(&got_rejects) == bag(&want_rejects);
        if got_rows != want_rows {
            failures.push(format!(
                "{name}\n input {}\n  rows {got_rows:?}\n  want {want_rows:?}",
                case["input"]
            ));
        }
        if !rejects_same {
            failures.push(format!(
                "{name}\n input {}\n  rejects {got_rejects:?}\n  want    {want_rejects:?}",
                case["input"]
            ));
        }
    }
    report(&failures);
    assert_eq!(canonical_key("ui_theme"), "ui.theme");
}

#[test]
fn embedded_contracts_are_the_committed_bytes() {
    use silo_contracts::embedded::{MIGRATION_FILES, contract, openapi_v2};
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
    assert_eq!(
        openapi_v2(),
        std::fs::read(format!("{root}/contracts/api/v2/openapi.json")).unwrap()
    );
    assert_eq!(
        contract("settings/v1/manifest.json").unwrap(),
        std::fs::read(format!("{root}/contracts/settings/v1/manifest.json")).unwrap()
    );
    assert!(
        contract("api/v2/embed.go").is_none(),
        "Go source is not embedded"
    );
    assert_eq!(MIGRATION_FILES.len(), 629);
}

#[test]
fn migration_conversions_match_go() {
    use silo_contracts::migrate::{repair_external_subtitle_names, subtitle_language_rewrites};
    let vectors = vector("migrate/conversions");
    let repairs = vectors["repairs"].as_array().unwrap();
    assert!(repairs.len() > 40);
    let mut failures = Vec::new();
    for case in repairs {
        let got = repair_external_subtitle_names(s(case, "video"), s(case, "stored"));
        let want_err = !s(case, "err").is_empty();
        let want_ok = case["ok"].as_bool().unwrap();
        let same = match &got {
            Err(_) => want_err,
            Ok(None) => !want_err && !want_ok,
            Ok(Some(repaired)) => want_ok && repaired == s(case, "repaired"),
        };
        if !same {
            failures.push(format!("{case}\n  got {got:?}"));
        }
    }
    report(&failures);

    let rewrites = &vectors["rewrites"];
    let stored: Vec<String> = rewrites["stored"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let (rewrite, unparseable) = subtitle_language_rewrites(&stored);
    let want_rewrite: std::collections::BTreeMap<String, String> =
        serde_json::from_value(rewrites["rewrite"].clone()).unwrap();
    let want_unparseable: Vec<String> =
        serde_json::from_value(rewrites["unparseable"].clone()).unwrap();
    assert_eq!(rewrite, want_rewrite);
    assert_eq!(unparseable, want_unparseable);
}
