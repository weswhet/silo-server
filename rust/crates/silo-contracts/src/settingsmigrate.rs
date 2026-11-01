//! Port of `internal/settingsmigrate`: turns legacy settings storage into canonical values.
//!
//! This is the pure planning half, which the settings backfill uses. The legacy API's runtime
//! conversions (`PlanRuntimeValue`, `RuntimeKeys`, `PlanRetiredFallback`) belong with the handlers
//! that call them and aren't ported yet.

use std::collections::{BTreeMap, HashMap};

use silo_gocompat::json::marshal_to_string;
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strconv::{format_float, quote};
use silo_gocompat::strings::trim_space;

use crate::displayprefs;
use crate::gojson::{self, Value};
use crate::lang::compatible_tag;
use crate::settingscontract::{
    Contract, Definition, Scope, ValueType, go_parse_int, mirror_key, mirror_write,
};
use crate::settingskeys;

/// One row of the account-wide `user_settings` table.
#[derive(Clone, Debug, Default)]
pub struct LegacySetting {
    pub key: String,
    pub value: String,
}

/// One row of `user_device_settings`.
#[derive(Clone, Debug, Default)]
pub struct LegacyDeviceSetting {
    pub profile_id: String,
    pub device_id: String,
    pub key: String,
    pub value: String,
}

/// The preference columns on a profile row.
#[derive(Clone, Debug, Default)]
pub struct LegacyProfile {
    pub id: String,
    pub language: Option<String>,
    pub subtitle_language: Option<String>,
    pub subtitle_mode: Option<String>,
    pub show_forced_subtitles: Option<bool>,
    pub quality_preference: Option<String>,
    pub preferred_metadata_language: Option<String>,
    pub auto_skip_intro: Option<bool>,
    pub auto_skip_credits: Option<bool>,
    pub auto_skip_recap: Option<bool>,
    pub auto_play_next_preview: Option<bool>,
}

/// One merged `user_subtitle_preferences` and `user_audio_preferences` record.
#[derive(Clone, Debug, Default)]
pub struct LegacySeriesPreference {
    pub profile_id: String,
    pub series_id: String,
    pub audio_source_table: String,
    pub subtitle_source_table: String,
    pub audio_language: Option<String>,
    pub subtitle_language: Option<String>,
    pub subtitle_mode: Option<String>,
    pub show_forced_subtitles: Option<bool>,
}

/// One `user_library_playback_preferences` row.
#[derive(Clone, Debug, Default)]
pub struct LegacyLibraryPreference {
    pub profile_id: String,
    pub library_id: i64,
    pub source_table: String,
    pub audio_language: Option<String>,
    pub subtitle_language: Option<String>,
    pub subtitle_mode: Option<String>,
    pub show_forced_subtitles: Option<bool>,
}

/// Everything one user's migration reads.
#[derive(Clone, Debug, Default)]
pub struct Input {
    pub settings: Vec<LegacySetting>,
    pub device_settings: Vec<LegacyDeviceSetting>,
    /// `None` is Go's nil slice: the caller could not load profiles.
    pub profiles: Option<Vec<LegacyProfile>>,
    pub series_prefs: Vec<LegacySeriesPreference>,
    pub library_prefs: Vec<LegacyLibraryPreference>,
}

/// One canonical value to write.
#[derive(Clone, Debug, Default)]
pub struct Row {
    pub key: String,
    pub scope: Option<Scope>,
    pub profile_id: String,
    pub device_id: String,
    pub library_id: i64,
    pub series_id: String,
    pub value: String,
    source_table: String,
    source_key: String,
    source_identity: String,
    from_renamed_key: bool,
}

/// A legacy value that could not be converted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reject {
    pub source_table: String,
    pub source_key: String,
    pub identity: String,
    pub value: String,
    pub reason: String,
}

/// What one user's migration produced.
#[derive(Clone, Debug, Default)]
pub struct PlanResult {
    pub rows: Vec<Row>,
    pub rejects: Vec<Reject>,
}

const DEFAULT_SUBTITLE_MODE: &str = "auto";
const SOURCE_USER_SETTINGS: &str = "user_settings";
const SOURCE_USER_DEVICE_SETTINGS: &str = "user_device_settings";
const SOURCE_USER_PROFILES: &str = "user_profiles";
const SOURCE_AUDIO_PREFS: &str = "audio_preferences";
const SOURCE_SUBTITLE_PREFS: &str = "subtitle_preferences";
const SOURCE_LIBRARY_PREFS: &str = "library_playback_preferences";
const KEY_PREFERRED_QUALITY: &str = "playback.preferred_quality";
const KEY_CARD_OVERLAYS: &str = "ui.card_overlays";
const KEY_AUDIO_LANGUAGE: &str = "playback.audio_language";

const LEGACY_QUALITY_DECOMPOSITION: &[(&str, &str, i64)] = &[
    ("1080p-high", "1080p", 10000),
    ("1080p", "1080p", 6000),
    ("1080p-medium", "1080p", 4500),
    ("1080p-8", "1080p", 6000),
    ("720p-high", "720p", 4000),
    ("720p-medium", "720p", 3000),
    ("720p", "720p", 2000),
    ("480p", "480p", 1500),
    ("420p", "480p", 720),
    ("328p", "480p", 720),
];

const LEGACY_KEY_RENAMES: &[(&str, &str)] = &[
    ("subtitle_appearance", "playback.subtitle_appearance"),
    (
        "player.next_up_prompt_seconds",
        "playback.next_up_prompt_seconds",
    ),
    ("ui_theme", "ui.theme"),
    ("ui_text_scale", "ui.text_scale"),
    ("ui_text_weight", "ui.text_weight"),
    ("ui_high_contrast", "ui.high_contrast"),
    ("ui_custom_theme_vars", "ui.custom_theme_vars"),
    ("ui_custom_css", "ui.custom_css"),
    ("card_overlays", "ui.card_overlays"),
    ("next_up_mode", "ui.next_up_mode"),
    ("sidebar_pins", "ui.sidebar_pins"),
    ("disabled_library_ids", "ui.disabled_library_ids"),
    ("library_order", "ui.library_order"),
];

const CARD_OVERLAY_IDS: &[&str] = &[
    "resolution",
    "hdr",
    "resolution_hdr",
    "audio",
    "audio_channels",
    "video_codec",
    "container",
    "aspect_ratio",
    "release_type",
    "edition",
    "multi_audio",
    "multi_sub",
    "rating_imdb",
    "rating_tmdb",
    "rating_rt",
    "rating_rt_audience",
    "content_rating",
    "advisory_age",
    "request_status",
    "year",
    "runtime",
    "original_language",
    "studio",
    "network",
    "show_status",
    "imdb_top_250",
    "rt_certified_fresh",
];

const CARD_OVERLAY_POSITIONS: &[&str] = &["top-left", "top-right", "bottom-left", "bottom-right"];

/// `settingsmigrate.CanonicalKey`.
pub fn canonical_key(legacy: &str) -> &str {
    LEGACY_KEY_RENAMES
        .iter()
        .find(|(from, _)| *from == legacy)
        .map_or(legacy, |(_, to)| to)
}

fn json_string(value: &str) -> String {
    // A Go string always marshals; so does this.
    marshal_to_string(value).expect("a string marshals")
}

// identityJSON: json.Marshal of a map with string and int values.
fn identity_json(fields: &[(&str, IdentityValue<'_>)]) -> String {
    let mut map = BTreeMap::new();
    for (key, value) in fields {
        let value = match value {
            IdentityValue::Text(text) => serde_json::Value::from(*text),
            IdentityValue::Int(n) => serde_json::Value::from(*n),
        };
        map.insert((*key).to_string(), value);
    }
    marshal_to_string(&map).unwrap_or_else(|_| "{}".to_string())
}

enum IdentityValue<'a> {
    Text(&'a str),
    Int(i64),
}

use IdentityValue::{Int, Text};

fn account_identity() -> String {
    identity_json(&[("scope", Text("account"))])
}

/// `strconv.ParseBool`.
fn go_parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// `strconv.ParseFloat(s, 64)`, returning `None` for its errors, including out of range.
pub fn go_parse_float(s: &str) -> Option<f64> {
    if let Some(value) = parse_float_special(s) {
        return value;
    }
    let read = read_float(s.as_bytes())?;
    if read.end != s.len() {
        return None;
    }
    if read.hex {
        return atof_hex(read.mantissa, read.exp, read.neg, read.trunc);
    }
    // readFloat has checked the syntax, and Rust's parser rounds to nearest as Go's does.
    let digits: String = s.chars().filter(|c| *c != '_').collect();
    let parsed: f64 = digits.parse().ok()?;
    (!parsed.is_infinite()).then_some(parsed)
}

fn common_prefix_len_ignore_case(s: &str, prefix: &str) -> usize {
    s.bytes()
        .zip(prefix.bytes())
        .take_while(|(a, b)| a.to_ascii_lowercase() == *b)
        .count()
}

// special: `Some` when s starts as a special value, holding `None` if more input follows it.
fn parse_float_special(s: &str) -> Option<Option<f64>> {
    let (sign, nsign, body) = match s.as_bytes().first()? {
        b'+' => (1.0, 1, &s[1..]),
        b'-' => (-1.0, 1, &s[1..]),
        b'i' | b'I' | b'n' | b'N' => (1.0, 0, s),
        _ => return None,
    };
    if nsign == 1 || matches!(s.as_bytes()[0], b'i' | b'I') {
        let mut n = common_prefix_len_ignore_case(body, "infinity");
        if 3 < n && n < 8 {
            n = 3;
        }
        if n == 3 || n == 8 {
            let value = (nsign + n == s.len()).then_some(sign * f64::INFINITY);
            return Some(value);
        }
        return None;
    }
    if common_prefix_len_ignore_case(s, "nan") == 3 {
        return Some((s.len() == 3).then_some(f64::NAN));
    }
    None
}

struct ReadFloat {
    mantissa: u64,
    exp: i64,
    neg: bool,
    trunc: bool,
    hex: bool,
    end: usize,
}

// readFloat
fn read_float(s: &[u8]) -> Option<ReadFloat> {
    let lower = |c: u8| c | (b'x' - b'X');
    let mut i = 0;
    let mut neg = false;
    match s.first()? {
        b'+' => i += 1,
        b'-' => {
            i += 1;
            neg = true;
        }
        _ => {}
    }
    let mut base = 10u64;
    let mut max_mant_digits = 19;
    let mut exp_char = b'e';
    let mut hex = false;
    if i + 2 < s.len() && s[i] == b'0' && lower(s[i + 1]) == b'x' {
        base = 16;
        max_mant_digits = 16;
        i += 2;
        exp_char = b'p';
        hex = true;
    }
    let (mut sawdot, mut sawdigits, mut underscores, mut trunc) = (false, false, false, false);
    let (mut nd, mut nd_mant, mut dp) = (0i64, 0i64, 0i64);
    let mut mantissa = 0u64;
    while i < s.len() {
        let c = s[i];
        if c == b'_' {
            underscores = true;
        } else if c == b'.' {
            if sawdot {
                break;
            }
            sawdot = true;
            dp = nd;
        } else if c.is_ascii_digit() {
            sawdigits = true;
            if c == b'0' && nd == 0 {
                dp -= 1;
                i += 1;
                continue;
            }
            nd += 1;
            if nd_mant < max_mant_digits {
                mantissa = mantissa
                    .wrapping_mul(base)
                    .wrapping_add(u64::from(c - b'0'));
                nd_mant += 1;
            } else if c != b'0' {
                trunc = true;
            }
        } else if base == 16 && (b'a'..=b'f').contains(&lower(c)) {
            sawdigits = true;
            nd += 1;
            if nd_mant < max_mant_digits {
                mantissa = mantissa
                    .wrapping_mul(16)
                    .wrapping_add(u64::from(lower(c) - b'a' + 10));
                nd_mant += 1;
            } else {
                trunc = true;
            }
        } else {
            break;
        }
        i += 1;
    }
    if !sawdigits {
        return None;
    }
    if !sawdot {
        dp = nd;
    }
    if base == 16 {
        dp *= 4;
        nd_mant *= 4;
    }
    if i < s.len() && lower(s[i]) == exp_char {
        i += 1;
        if i >= s.len() {
            return None;
        }
        let mut esign = 1;
        match s[i] {
            b'+' => i += 1,
            b'-' => {
                i += 1;
                esign = -1;
            }
            _ => {}
        }
        if i >= s.len() || !s[i].is_ascii_digit() {
            return None;
        }
        let mut e = 0i64;
        while i < s.len() && (s[i].is_ascii_digit() || s[i] == b'_') {
            if s[i] == b'_' {
                underscores = true;
            } else if e < 10000 {
                e = e * 10 + i64::from(s[i] - b'0');
            }
            i += 1;
        }
        dp += e * esign;
    } else if base == 16 {
        return None;
    }
    let exp = if mantissa != 0 { dp - nd_mant } else { 0 };
    if underscores && !underscore_ok(&s[..i]) {
        return None;
    }
    Some(ReadFloat {
        mantissa,
        exp,
        neg,
        trunc,
        hex,
        end: i,
    })
}

// underscoreOK
fn underscore_ok(s: &[u8]) -> bool {
    let lower = |c: u8| c | (b'x' - b'X');
    let mut saw = b'^';
    let mut i = 0;
    let s = match s.first() {
        Some(b'-' | b'+') => &s[1..],
        _ => s,
    };
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(lower(s[1]), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = lower(s[1]) == b'x';
    }
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&lower(c))) {
            saw = b'0';
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
    }
    saw != b'_'
}

// atofHex for float64.
fn atof_hex(mut mantissa: u64, exp: i64, neg: bool, trunc: bool) -> Option<f64> {
    const MANT_BITS: u32 = 52;
    const EXP_BITS: u32 = 11;
    const BIAS: i64 = -1023;
    let max_exp = (1i64 << EXP_BITS) + BIAS - 2;
    let min_exp = BIAS + 1;
    let mut exp = exp + i64::from(MANT_BITS);
    while mantissa != 0 && mantissa >> (MANT_BITS + 2) == 0 {
        mantissa <<= 1;
        exp -= 1;
    }
    if trunc {
        mantissa |= 1;
    }
    while mantissa >> (1 + MANT_BITS + 2) != 0 {
        mantissa = mantissa >> 1 | mantissa & 1;
        exp += 1;
    }
    while mantissa > 1 && exp < min_exp - 2 {
        mantissa = mantissa >> 1 | mantissa & 1;
        exp += 1;
    }
    let mut round = mantissa & 3;
    mantissa >>= 2;
    round |= mantissa & 1;
    exp += 2;
    if round == 3 {
        mantissa += 1;
        if mantissa == 1 << (1 + MANT_BITS) {
            mantissa >>= 1;
            exp += 1;
        }
    }
    if mantissa >> MANT_BITS == 0 {
        exp = BIAS;
    }
    if exp > max_exp {
        return None;
    }
    let mut bits = mantissa & ((1 << MANT_BITS) - 1);
    bits |= (((exp - BIAS) as u64) & ((1 << EXP_BITS) - 1)) << MANT_BITS;
    if neg {
        bits |= 1 << MANT_BITS << EXP_BITS;
    }
    Some(f64::from_bits(bits))
}

fn cards_look_like_v2(doc: &BTreeMap<String, Value>) -> bool {
    if let Some(Value::Number(n)) = doc.get("version")
        && go_parse_float(n) == Some(2.0)
    {
        return true;
    }
    matches!(doc.get("preset"), Some(Value::String(_)))
        && matches!(doc.get("items"), Some(Value::Object(_)))
}

// upgradeCardOverlaysV1. Go's Unmarshal into a map leaves a JSON null as a nil map, which is not v2
// and has no entries, so null also upgrades to the empty v2 document.
fn upgrade_card_overlays_v1(raw: &str) -> String {
    let empty = BTreeMap::new();
    let doc = match gojson::unmarshal_any(raw.as_bytes()) {
        Ok(Value::Object(doc)) => doc,
        Ok(Value::Null) => empty,
        _ => return raw.to_string(),
    };
    if cards_look_like_v2(&doc) {
        return raw.to_string();
    }
    static ACCENT: std::sync::LazyLock<GoRegex> =
        std::sync::LazyLock::new(|| GoRegex::must_compile("^#[0-9a-fA-F]{6}$"));

    let mut items: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
    for (id, entry) in &doc {
        if !CARD_OVERLAY_IDS.contains(&id.as_str()) {
            continue;
        }
        let Value::Object(fields) = entry else {
            continue;
        };
        let (Some(Value::Bool(enabled)), Some(Value::String(position))) =
            (fields.get("enabled"), fields.get("position"))
        else {
            continue;
        };
        if !CARD_OVERLAY_POSITIONS.contains(&position.as_str()) {
            continue;
        }
        let mut item = BTreeMap::new();
        item.insert("enabled".to_string(), serde_json::Value::from(*enabled));
        item.insert(
            "position".to_string(),
            serde_json::Value::from(position.as_str()),
        );
        if let Some(Value::String(accent)) = fields.get("accentColor")
            && ACCENT.match_string(accent)
        {
            item.insert(
                "accentColor".to_string(),
                serde_json::Value::from(accent.as_str()),
            );
        }
        if let Some(Value::Bool(show_icon)) = fields.get("showIcon") {
            item.insert("showIcon".to_string(), serde_json::Value::from(*show_icon));
        }
        items.insert(id.clone(), item);
    }
    let mut upgraded: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    upgraded.insert("version".to_string(), serde_json::Value::from(2));
    upgraded.insert("preset".to_string(), serde_json::Value::from("classic"));
    upgraded.insert("order".to_string(), serde_json::Value::Array(Vec::new()));
    upgraded.insert(
        "items".to_string(),
        serde_json::to_value(&items).unwrap_or_default(),
    );
    marshal_to_string(&upgraded).unwrap_or_else(|_| raw.to_string())
}

/// Converts legacy rows using one contract.
pub struct Planner<'a> {
    contract: &'a Contract,
}

impl<'a> Planner<'a> {
    pub fn new(contract: &'a Contract) -> Self {
        Self { contract }
    }

    fn lookup(&self, key: &str) -> Option<&'a Definition> {
        self.contract.manifest.lookup(key)
    }

    fn validate(&self, def: &Definition, value: &str) -> Result<(), String> {
        def.value_schema
            .validate_value(value.as_bytes(), &self.contract.schemas)
    }

    /// `Planner.Plan`: converts one user's legacy rows.
    pub fn plan(&self, input: &Input) -> PlanResult {
        let mut res = PlanResult::default();
        let profiles = input.profiles.as_deref().unwrap_or(&[]);
        self.plan_profiles(profiles, &mut res);
        self.plan_account_settings(&input.settings, profiles, &mut res);
        self.plan_device_settings(&input.device_settings, &mut res);
        self.plan_series_prefs(&input.series_prefs, &mut res);
        self.plan_library_prefs(&input.library_prefs, &mut res);
        self.plan_mirrored_rows(&mut res);
        res.rows = dedupe_rows(std::mem::take(&mut res.rows));
        res.rows = drop_orphan_profile_rows(
            std::mem::take(&mut res.rows),
            input.profiles.as_deref(),
            &mut res.rejects,
        );
        res
    }

    fn plan_mirrored_rows(&self, res: &mut PlanResult) {
        let planned = res.rows.len();
        let mut explicit: HashMap<RowIdentity, usize> = HashMap::with_capacity(planned);
        for i in 0..planned {
            if mirror_key(&res.rows[i].key).is_some() {
                explicit.insert(identity_of_row(&res.rows[i]), i);
            }
        }
        for i in 0..planned {
            let row = res.rows[i].clone();
            let mirror = match mirror_write(&row.key, &row.value) {
                Ok(Some(mirror)) => mirror,
                _ => continue,
            };
            let mut companion = row.clone();
            companion.key = mirror.key.to_string();
            companion.value = mirror.value;
            if let Some(at) = explicit.get(&identity_of_row(&companion)).copied() {
                if self.supersedes(&row.key, &res.rows[at].key) {
                    res.rows[at].value = companion.value;
                }
                continue;
            }
            res.rows.push(companion);
        }
    }

    fn supersedes(&self, key: &str, other: &str) -> bool {
        match (self.lookup(key), self.lookup(other)) {
            (Some(def), Some(other_def)) => !def.deprecated && other_def.deprecated,
            _ => false,
        }
    }

    fn plan_profiles(&self, profiles: &[LegacyProfile], res: &mut PlanResult) {
        for profile in profiles {
            let id = |field: &str| {
                identity_json(&[("profile_id", Text(&profile.id)), ("column", Text(field))])
            };
            let base = Row {
                profile_id: profile.id.clone(),
                ..Row::default()
            };
            self.add_language(
                res,
                SOURCE_USER_PROFILES,
                &id("language"),
                "playback.audio_language",
                Scope::Profile,
                &base,
                profile.language.as_deref(),
            );
            self.add_language(
                res,
                SOURCE_USER_PROFILES,
                &id("subtitle_language"),
                "playback.subtitle_language",
                Scope::Profile,
                &base,
                profile.subtitle_language.as_deref(),
            );
            self.add_language(
                res,
                SOURCE_USER_PROFILES,
                &id("preferred_metadata_language"),
                "catalog.metadata_language",
                Scope::Profile,
                &base,
                profile.preferred_metadata_language.as_deref(),
            );

            let mode = profile.subtitle_mode.as_deref().unwrap_or("");
            if !mode.is_empty() && mode != DEFAULT_SUBTITLE_MODE {
                self.add_value(
                    res,
                    SOURCE_USER_PROFILES,
                    &id("subtitle_mode"),
                    "playback.subtitle_mode",
                    Scope::Profile,
                    &base,
                    json_string(mode),
                );
            }
            if profile.show_forced_subtitles == Some(false) {
                self.add_value(
                    res,
                    SOURCE_USER_PROFILES,
                    &id("show_forced_subtitles"),
                    "playback.show_forced_subtitles",
                    Scope::Profile,
                    &base,
                    "false".to_string(),
                );
            }
            self.add_quality(
                res,
                SOURCE_USER_PROFILES,
                &id("quality_preference"),
                Scope::Profile,
                &base,
                profile.quality_preference.as_deref().unwrap_or(""),
            );
            for (column, key, value) in [
                (
                    "auto_skip_intro",
                    "playback.auto_skip_intro",
                    profile.auto_skip_intro,
                ),
                (
                    "auto_skip_credits",
                    "playback.auto_skip_credits",
                    profile.auto_skip_credits,
                ),
                (
                    "auto_skip_recap",
                    "playback.auto_skip_recap",
                    profile.auto_skip_recap,
                ),
                (
                    "auto_play_next_preview",
                    "playback.auto_play_next_preview",
                    profile.auto_play_next_preview,
                ),
            ] {
                if value == Some(true) {
                    self.add_value(
                        res,
                        SOURCE_USER_PROFILES,
                        &id(column),
                        key,
                        Scope::Profile,
                        &base,
                        "true".to_string(),
                    );
                }
            }
        }
    }

    fn plan_account_settings(
        &self,
        settings: &[LegacySetting],
        profiles: &[LegacyProfile],
        res: &mut PlanResult,
    ) {
        for setting in settings {
            let key = canonical_key(&setting.key);
            if setting.key.starts_with(displayprefs::NAMESPACE_PREFIX) {
                continue;
            }
            let Some(def) = self.lookup(key) else {
                res.rejects.push(Reject {
                    source_table: SOURCE_USER_SETTINGS.to_string(),
                    source_key: setting.key.clone(),
                    identity: account_identity(),
                    value: setting.value.clone(),
                    reason: "no contract definition; the key was only ever accepted by the unknown-key extension bag".to_string(),
                });
                continue;
            };
            let value = match self.coerce(def, &setting.value) {
                Err(reason) => {
                    res.rejects.push(Reject {
                        source_table: SOURCE_USER_SETTINGS.to_string(),
                        source_key: setting.key.clone(),
                        identity: account_identity(),
                        value: setting.value.clone(),
                        reason,
                    });
                    continue;
                }
                Ok(None) => continue,
                Ok(Some(value)) => value,
            };
            if !def.allows_scope(Scope::Profile) {
                res.rejects.push(Reject {
                    source_table: SOURCE_USER_SETTINGS.to_string(),
                    source_key: setting.key.clone(),
                    identity: account_identity(),
                    value: setting.value.clone(),
                    reason: format!("{key} does not allow profile scope"),
                });
                continue;
            }
            for profile in profiles {
                res.rows.push(Row {
                    key: key.to_string(),
                    scope: Some(Scope::Profile),
                    profile_id: profile.id.clone(),
                    value: value.clone(),
                    from_renamed_key: key != setting.key,
                    source_table: SOURCE_USER_SETTINGS.to_string(),
                    source_key: setting.key.clone(),
                    source_identity: account_identity(),
                    ..Row::default()
                });
            }
        }
    }

    fn plan_device_settings(&self, devices: &[LegacyDeviceSetting], res: &mut PlanResult) {
        for row in devices {
            let key = canonical_key(&row.key);
            let identity = identity_json(&[
                ("profile_id", Text(&row.profile_id)),
                ("device_id", Text(&row.device_id)),
            ]);
            let reject = |reason: String| Reject {
                source_table: SOURCE_USER_DEVICE_SETTINGS.to_string(),
                source_key: row.key.clone(),
                identity: identity.clone(),
                value: row.value.clone(),
                reason,
            };
            if key == KEY_PREFERRED_QUALITY {
                let base = Row {
                    profile_id: row.profile_id.clone(),
                    device_id: row.device_id.clone(),
                    ..Row::default()
                };
                self.add_quality(
                    res,
                    SOURCE_USER_DEVICE_SETTINGS,
                    &identity,
                    Scope::ProfileDevice,
                    &base,
                    &row.value,
                );
                continue;
            }
            if key == KEY_AUDIO_LANGUAGE {
                if !trim_space(&row.value).is_empty() {
                    res.rejects.push(reject("stranded device-scope audio language: never read by playback before the contract, so promoting it would change track selection".to_string()));
                }
                continue;
            }
            let Some(def) = self.lookup(key) else {
                res.rejects
                    .push(reject("no contract definition".to_string()));
                continue;
            };
            let value = match self.coerce(def, &row.value) {
                Err(reason) => {
                    res.rejects.push(reject(reason));
                    continue;
                }
                Ok(None) => continue,
                Ok(Some(value)) => value,
            };
            if !def.allows_scope(Scope::ProfileDevice) {
                res.rejects
                    .push(reject(format!("{key} does not allow profile_device scope")));
                continue;
            }
            res.rows.push(Row {
                key: key.to_string(),
                scope: Some(Scope::ProfileDevice),
                profile_id: row.profile_id.clone(),
                device_id: row.device_id.clone(),
                value,
                from_renamed_key: key != row.key,
                source_table: SOURCE_USER_DEVICE_SETTINGS.to_string(),
                source_key: row.key.clone(),
                source_identity: identity.clone(),
                ..Row::default()
            });
        }
    }

    fn plan_series_prefs(&self, prefs: &[LegacySeriesPreference], res: &mut PlanResult) {
        for pref in prefs {
            let base = Row {
                profile_id: pref.profile_id.clone(),
                series_id: pref.series_id.clone(),
                ..Row::default()
            };
            let identity = identity_json(&[
                ("profile_id", Text(&pref.profile_id)),
                ("series_id", Text(&pref.series_id)),
            ]);
            let audio_source = if pref.audio_source_table.is_empty() {
                SOURCE_AUDIO_PREFS
            } else {
                &pref.audio_source_table
            };
            let subtitle_source = if pref.subtitle_source_table.is_empty() {
                SOURCE_SUBTITLE_PREFS
            } else {
                &pref.subtitle_source_table
            };
            self.add_playback_triple(
                res,
                audio_source,
                subtitle_source,
                &identity,
                Scope::ProfileSeries,
                &base,
                pref.audio_language.as_deref(),
                pref.subtitle_language.as_deref(),
                pref.subtitle_mode.as_deref(),
                pref.show_forced_subtitles,
            );
        }
    }

    fn plan_library_prefs(&self, prefs: &[LegacyLibraryPreference], res: &mut PlanResult) {
        for pref in prefs {
            let base = Row {
                profile_id: pref.profile_id.clone(),
                library_id: pref.library_id,
                ..Row::default()
            };
            let identity = identity_json(&[
                ("profile_id", Text(&pref.profile_id)),
                ("library_id", Int(pref.library_id)),
            ]);
            let source = if pref.source_table.is_empty() {
                SOURCE_LIBRARY_PREFS
            } else {
                &pref.source_table
            };
            self.add_playback_triple(
                res,
                source,
                source,
                &identity,
                Scope::ProfileLibrary,
                &base,
                pref.audio_language.as_deref(),
                pref.subtitle_language.as_deref(),
                pref.subtitle_mode.as_deref(),
                pref.show_forced_subtitles,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_playback_triple(
        &self,
        res: &mut PlanResult,
        audio_source: &str,
        subtitle_source: &str,
        identity: &str,
        scope: Scope,
        base: &Row,
        audio: Option<&str>,
        subtitle: Option<&str>,
        mode: Option<&str>,
        forced: Option<bool>,
    ) {
        self.add_language(
            res,
            audio_source,
            identity,
            "playback.audio_language",
            scope,
            base,
            audio,
        );
        self.add_language(
            res,
            subtitle_source,
            identity,
            "playback.subtitle_language",
            scope,
            base,
            subtitle,
        );
        if let Some(mode) = mode
            && !mode.is_empty()
        {
            self.add_value(
                res,
                subtitle_source,
                identity,
                "playback.subtitle_mode",
                scope,
                base,
                json_string(mode),
            );
        }
        if let Some(forced) = forced {
            self.add_value(
                res,
                subtitle_source,
                identity,
                "playback.show_forced_subtitles",
                scope,
                base,
                forced.to_string(),
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_language(
        &self,
        res: &mut PlanResult,
        source_table: &str,
        identity: &str,
        key: &str,
        scope: Scope,
        base: &Row,
        raw: Option<&str>,
    ) {
        let value = trim_space(raw.unwrap_or(""));
        if value.is_empty() {
            return;
        }
        let normalized = compatible_tag(value);
        if normalized.is_empty() {
            res.rejects.push(Reject {
                source_table: source_table.to_string(),
                source_key: key.to_string(),
                identity: identity.to_string(),
                value: value.to_string(),
                reason: "not a well-formed BCP 47 language tag".to_string(),
            });
            return;
        }
        self.add_value(
            res,
            source_table,
            identity,
            key,
            scope,
            base,
            json_string(&normalized),
        );
    }

    fn add_quality(
        &self,
        res: &mut PlanResult,
        source_table: &str,
        identity: &str,
        scope: Scope,
        base: &Row,
        raw: &str,
    ) {
        let value = trim_space(raw);
        if value.is_empty() {
            return;
        }
        if value == "auto" || value == "original" || value == "2160p" {
            self.add_value(
                res,
                source_table,
                identity,
                "playback.preferred_quality",
                scope,
                base,
                json_string(value),
            );
            return;
        }
        let Some((_, resolution, kbps)) = LEGACY_QUALITY_DECOMPOSITION
            .iter()
            .find(|(name, _, _)| *name == value)
        else {
            res.rejects.push(Reject {
                source_table: source_table.to_string(),
                source_key: KEY_PREFERRED_QUALITY.to_string(),
                identity: identity.to_string(),
                value: value.to_string(),
                reason: "not a recognized legacy quality value".to_string(),
            });
            return;
        };
        self.add_value(
            res,
            source_table,
            identity,
            KEY_PREFERRED_QUALITY,
            scope,
            base,
            json_string(resolution),
        );
        self.add_value(
            res,
            source_table,
            identity,
            settingskeys::PLAYBACK_MAX_BITRATE_KBPS,
            scope,
            base,
            kbps.to_string(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn add_value(
        &self,
        res: &mut PlanResult,
        source_table: &str,
        identity: &str,
        key: &str,
        scope: Scope,
        base: &Row,
        value: String,
    ) {
        let Some(def) = self.lookup(key) else {
            res.rejects.push(Reject {
                source_table: source_table.to_string(),
                source_key: key.to_string(),
                identity: identity.to_string(),
                value,
                reason: "no contract definition".to_string(),
            });
            return;
        };
        if let Err(reason) = self.validate(def, &value) {
            res.rejects.push(Reject {
                source_table: source_table.to_string(),
                source_key: key.to_string(),
                identity: identity.to_string(),
                value,
                reason,
            });
            return;
        }
        let mut row = base.clone();
        row.key = key.to_string();
        row.scope = Some(scope);
        row.value = value;
        row.source_table = source_table.to_string();
        row.source_key = key.to_string();
        row.source_identity = identity.to_string();
        res.rows.push(row);
    }

    // coerce: Ok(None) is the legacy spelling of unset.
    fn coerce(&self, def: &Definition, raw: &str) -> Result<Option<String>, String> {
        let trimmed = trim_space(raw);
        if trimmed.is_empty() {
            return Ok(None);
        }
        let candidate = match def.value_schema.value_type {
            ValueType::Boolean => match go_parse_bool(trimmed) {
                Some(parsed) => parsed.to_string(),
                None => return Err(format!("{} is not a boolean", quote(raw))),
            },
            ValueType::Integer => match go_parse_int(trimmed) {
                Some(parsed) => parsed.to_string(),
                None => return Err(format!("{} is not an integer", quote(raw))),
            },
            ValueType::Number => {
                let Some(parsed) = go_parse_float(trimmed) else {
                    return Err(format!("{} is not a number", quote(raw)));
                };
                format_float(snap_to_step(def, parsed), b'g', -1, 64)
            }
            ValueType::Object => {
                if def.key == KEY_CARD_OVERLAYS {
                    upgrade_card_overlays_v1(trimmed)
                } else {
                    trimmed.to_string()
                }
            }
            ValueType::LanguageTag => {
                let normalized = compatible_tag(trimmed);
                if normalized.is_empty() {
                    return Err(format!(
                        "{} is not a well-formed BCP 47 language tag",
                        quote(raw)
                    ));
                }
                json_string(&normalized)
            }
            ValueType::String | ValueType::Enum => json_string(trimmed),
        };
        self.validate(def, &candidate)?;
        Ok(Some(candidate))
    }
}

fn snap_to_step(def: &Definition, value: f64) -> f64 {
    let Some(step) = def.value_schema.step else {
        return value;
    };
    if step <= 0.0 {
        return value;
    }
    let base = def
        .value_schema
        .minimum
        .as_ref()
        .and_then(crate::settingscontract::Bound::current)
        .unwrap_or(0.0);
    let steps = ((value - base) / step).round();
    // Go's compiler fuses x*y + z on arm64 but not on baseline amd64, so the stored value of a
    // snapped speed depends on the build's CPU. Each target here matches Go on that target.
    if cfg!(target_arch = "aarch64") {
        steps.mul_add(step, base)
    } else {
        base + steps * step
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RowIdentity {
    key: String,
    scope: Option<Scope>,
    profile_id: String,
    device_id: String,
    library_id: i64,
    series_id: String,
}

fn identity_of_row(row: &Row) -> RowIdentity {
    RowIdentity {
        key: row.key.clone(),
        scope: row.scope,
        profile_id: row.profile_id.clone(),
        device_id: row.device_id.clone(),
        library_id: row.library_id,
        series_id: row.series_id.clone(),
    }
}

fn dedupe_rows(rows: Vec<Row>) -> Vec<Row> {
    let mut kept: HashMap<RowIdentity, usize> = HashMap::with_capacity(rows.len());
    let mut out: Vec<Row> = Vec::with_capacity(rows.len());
    for row in rows {
        let id = identity_of_row(&row);
        match kept.get(&id) {
            None => {
                kept.insert(id, out.len());
                out.push(row);
            }
            Some(at) => {
                if out[*at].from_renamed_key && !row.from_renamed_key {
                    out[*at] = row;
                }
            }
        }
    }
    out
}

fn drop_orphan_profile_rows(
    rows: Vec<Row>,
    profiles: Option<&[LegacyProfile]>,
    rejects: &mut Vec<Reject>,
) -> Vec<Row> {
    let Some(profiles) = profiles else {
        return rows;
    };
    let mut kept = Vec::with_capacity(rows.len());
    for row in rows {
        if row.profile_id.is_empty() || profiles.iter().any(|p| p.id == row.profile_id) {
            kept.push(row);
            continue;
        }
        rejects.push(Reject {
            source_table: row.source_table,
            source_key: row.source_key,
            identity: row.source_identity,
            value: row.value,
            reason: "profile no longer exists; the legacy row outlived the profile it belonged to"
                .to_string(),
        });
    }
    kept
}
