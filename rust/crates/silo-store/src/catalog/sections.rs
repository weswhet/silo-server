//! What a section layout needs: `sections.Repository.ListByScope`, the typed defaults, `sections.Resolve`, the
//! profile overrides (`pgstore/section_overrides.go`) and the Next Up injection. Fetching a section's items is not
//! ported, so the item rows stay on Go.
//!
//! The defaults' `config` is only what a layout can observe: the continue type. Every default row has a title,
//! so `readableTitle` never reads the rest.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;
use silo_gocompat::json::unmarshal;
use silo_pg::{AnyInt, Pool, TextValue};

/// `sections.PageSection`, what a layout reads.
#[derive(Clone, Debug, Default)]
pub struct PageSection {
    pub id: String,
    pub position: i64,
    pub section_type: String,
    pub title: String,
    pub featured: bool,
    pub item_limit: i64,
    pub config: Vec<u8>,
}

/// `sections.ResolvedSection`, what a layout reads.
#[derive(Clone, Debug, Default)]
pub struct ResolvedSection {
    pub id: String,
    pub section_type: String,
    pub title: String,
    pub featured: bool,
    pub item_limit: i64,
    pub is_custom: bool,
    pub customized: bool,
    pub config: Vec<u8>,
    pub position: i64,
}

/// `userstore.SectionOverride` as stored: Go's field names, no tags.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SectionOverride {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "ProfileID")]
    pub profile_id: String,
    #[serde(rename = "SectionID")]
    pub section_id: String,
    #[serde(rename = "Position")]
    pub position: Option<i64>,
    #[serde(rename = "Hidden")]
    pub hidden: bool,
    #[serde(rename = "Removed")]
    pub removed: bool,
    #[serde(rename = "SectionType")]
    pub section_type: String,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Featured")]
    pub featured: Option<bool>,
    #[serde(rename = "ItemLimit")]
    pub item_limit: Option<i64>,
    #[serde(rename = "Config")]
    pub config: String,
    #[serde(rename = "UserSectionType")]
    pub user_section_type: String,
    #[serde(rename = "UserConfig")]
    pub user_config: String,
    #[serde(rename = "UserTitle")]
    pub user_title: String,
}

/// `ListByScope("library", &id)`.
pub async fn list_library_sections(
    pool: &Pool,
    library_id: i32,
) -> Result<Vec<PageSection>, String> {
    let scope = "library";
    let rows = pool
        .query(
            "SELECT id, scope, library_id, position, section_type, title, featured,
	item_limit, config, enabled, created_at, updated_at FROM page_sections WHERE scope = $1 AND library_id = $2 AND enabled = true ORDER BY position ASC, id ASC",
            &[&scope, &AnyInt(i64::from(library_id))],
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(rows.len());
    let err = |e: silo_pg::DriverError| e.to_string();
    for r in &rows {
        out.push(PageSection {
            id: r.try_get(0).map_err(err)?,
            position: r.try_get::<_, AnyInt>(3).map_err(err)?.0,
            section_type: r.try_get(4).map_err(err)?,
            title: r.try_get(5).map_err(err)?,
            featured: r.try_get(6).map_err(err)?,
            item_limit: r.try_get::<_, AnyInt>(7).map_err(err)?.0,
            config: r
                .try_get::<_, Option<TextValue>>(8)
                .map_err(err)?
                .map(|t| t.0.into_bytes())
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

/// `pgstore.ListSectionOverrides(profile, "library", id)`, through `GetSetting`.
pub async fn list_section_overrides(
    pool: &Pool,
    user_id: i32,
    profile_id: &str,
    library_id: &str,
) -> Result<Vec<SectionOverride>, String> {
    let key = format!("section_overrides:library:{library_id}");
    let rows = pool
        .query(
            "SELECT value FROM user_settings WHERE user_id = $1 AND key = $2",
            &[&user_id, &key],
        )
        .await
        .map_err(|e| e.to_string())?;
    let value: String = match rows.first() {
        Some(r) => r.try_get(0).map_err(|e| e.to_string())?,
        None => String::new(),
    };
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: Option<Vec<SectionOverride>> =
        unmarshal(value.as_bytes()).map_err(|e| e.to_string())?;
    Ok(parsed
        .unwrap_or_default()
        .into_iter()
        .filter(|o| o.profile_id == profile_id)
        .collect())
}

const DEFAULT_ITEM_LIMIT: i64 = 100;
const MAX_ITEM_LIMIT: i64 = 500;
const BETA_LIBRARY_ITEM_LIMIT: i64 = 20;

/// `ClampItemLimit`.
fn clamp_item_limit(limit: i64) -> i64 {
    limit.min(MAX_ITEM_LIMIT)
}

fn section(
    position: i64,
    id: &str,
    kind: &str,
    title: &str,
    limit: i64,
    config: &str,
) -> PageSection {
    PageSection {
        id: id.to_owned(),
        position,
        section_type: kind.to_owned(),
        title: title.to_owned(),
        featured: false,
        item_limit: limit,
        config: config.as_bytes().to_vec(),
    }
}

const WATCHING: &str = r#"{"continue_type":"watching"}"#;
const LISTENING: &str = r#"{"continue_type":"listening"}"#;
const READING: &str = r#"{"continue_type":"reading"}"#;

/// `librarykind.normalize`, then `IsVideoLibraryType`.
fn is_video(library_type: &str) -> bool {
    let kind = silo_gocompat::strings::to_lower(silo_gocompat::strings::trim_space(library_type));
    matches!(
        kind.as_str(),
        "movie" | "movies" | "series" | "tv" | "show" | "tvshows" | "mixed"
    )
}

/// `DefaultLibrarySectionsForType`.
pub fn default_library_sections(library_type: &str) -> Vec<PageSection> {
    const CW: &str = "continue_watching";
    const RA: &str = "recently_added";
    const RR: &str = "recently_released";
    const CF: &str = "custom_filter";
    const RF: &str = "recommended_for_you";
    const RD: &str = "random";
    const REC_ID: &str = "default-recommended-for-you";
    const REC: &str = "Recommended for You";
    const RP: &str = "Random Picks";
    let e = "{}";
    let d = DEFAULT_ITEM_LIMIT;
    let b = BETA_LIBRARY_ITEM_LIMIT;
    match library_type {
        "movies" | "movie" => vec![
            section(
                0,
                "default-continue-watching",
                CW,
                "Continue Watching",
                d,
                WATCHING,
            ),
            section(
                1,
                "default-recently-added-movies",
                RA,
                "Recently Added Movies",
                d,
                e,
            ),
            section(
                2,
                "default-recently-released-movies",
                RR,
                "Recently Released Movies",
                d,
                e,
            ),
            section(3, "default-top-rated-movies", CF, "Top Rated Movies", d, e),
            section(4, REC_ID, RF, REC, d, e),
            section(5, "default-random-movies", RD, RP, d, e),
        ],
        "series" => vec![
            section(
                0,
                "default-continue-watching",
                CW,
                "Continue Watching",
                d,
                WATCHING,
            ),
            section(
                1,
                "default-recently-added-tv",
                RA,
                "Recently Added TV",
                d,
                e,
            ),
            section(
                2,
                "default-returning-shows",
                "returning_shows",
                "Returning Shows",
                d,
                e,
            ),
            section(
                3,
                "default-recently-released-episodes",
                CF,
                "Recently Released Episodes",
                d,
                e,
            ),
            section(4, "default-top-rated-tv", CF, "Top Rated TV", d, e),
            section(5, REC_ID, RF, REC, d, e),
            section(6, "default-random-tv", RD, RP, d, e),
        ],
        "audiobooks" | "audiobook" => {
            let mut hero = section(
                0,
                "default-continue-listening",
                CW,
                "Continue Listening",
                b,
                LISTENING,
            );
            hero.featured = true;
            vec![
                hero,
                section(
                    1,
                    "default-next-in-series",
                    "next_in_series",
                    "Next in Your Series",
                    b,
                    e,
                ),
                section(
                    2,
                    "default-recently-added-audiobooks",
                    RA,
                    "Recently Added Audiobooks",
                    b,
                    e,
                ),
                section(
                    3,
                    "default-recently-released-audiobooks",
                    RR,
                    "Recently Released Audiobooks",
                    b,
                    e,
                ),
                section(4, REC_ID, RF, REC, b, e),
                section(5, "default-random-audiobooks", RD, RP, b, e),
            ]
        }
        "ebooks" | "ebook" => vec![
            section(
                0,
                "default-continue-reading",
                CW,
                "Continue Reading",
                b,
                READING,
            ),
            section(
                1,
                "default-recently-added-ebooks",
                RA,
                "Recently Added Ebooks",
                b,
                e,
            ),
            section(
                2,
                "default-recently-released-ebooks",
                RR,
                "Recently Released Ebooks",
                b,
                e,
            ),
            section(3, REC_ID, RF, REC, b, e),
            section(4, "default-random-ebooks", RD, RP, b, e),
        ],
        "manga" => vec![
            section(
                0,
                "default-continue-reading",
                CW,
                "Continue Reading",
                b,
                READING,
            ),
            section(
                1,
                "default-recently-added-manga",
                RA,
                "Recently Added Manga",
                b,
                e,
            ),
            section(
                2,
                "default-recently-released-manga",
                RR,
                "Recently Released Manga",
                b,
                e,
            ),
            section(3, REC_ID, RF, REC, b, e),
            section(4, "default-random-manga", RD, RP, b, e),
        ],
        _ => {
            let limit = if is_video(library_type) { d } else { b };
            vec![
                section(
                    0,
                    "default-continue-watching",
                    CW,
                    "Continue Watching",
                    limit,
                    WATCHING,
                ),
                section(1, "default-recently-added", RA, "Recently Added", limit, e),
                section(
                    2,
                    "default-recently-released",
                    RR,
                    "Recently Released",
                    limit,
                    e,
                ),
            ]
        }
    }
}

#[derive(Deserialize)]
struct Preset {
    display_name: String,
    default_params: Value,
}

/// Every registered recipe's presets, from `rust/conformance/vectors/generators/recipes`.
fn presets() -> &'static BTreeMap<String, Vec<Preset>> {
    static PRESETS: OnceLock<BTreeMap<String, Vec<Preset>>> = OnceLock::new();
    PRESETS.get_or_init(|| {
        unmarshal(include_bytes!("recipe_presets.json")).expect("the generated presets parse")
    })
}

/// `reflect.DeepEqual` over `json.Unmarshal`'s `any`, where every number is a float64.
fn go_any_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| go_any_equal(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| go_any_equal(v, w)))
        }
        _ => a == b,
    }
}

/// `readableTitle`.
fn readable_title(section_type: &str, title: &str, config: &[u8]) -> String {
    let trimmed = silo_gocompat::strings::trim_space(title);
    if !trimmed.is_empty() && trimmed != section_type {
        return title.to_owned();
    }
    let Some(list) = presets().get(section_type).filter(|p| !p.is_empty()) else {
        return title.to_owned();
    };
    let cfg: HashMap<String, Value> = unmarshal::<Option<HashMap<String, Value>>>(config)
        .ok()
        .flatten()
        .unwrap_or_default();
    let mut best = list[0].display_name.as_str();
    let mut best_score: i64 = -1;
    for preset in list {
        let Some(params) = preset.default_params.as_object() else {
            if !preset.default_params.is_null() {
                continue;
            }
            if best_score < 0 {
                best = &preset.display_name;
                best_score = 0;
            }
            continue;
        };
        let matched = params
            .iter()
            .all(|(k, v)| go_any_equal(cfg.get(k).unwrap_or(&Value::Null), v));
        if matched && params.len() as i64 > best_score {
            best = &preset.display_name;
            best_score = params.len() as i64;
        }
    }
    best.to_owned()
}

/// `resolveUserAdded`.
fn resolve_user_added(o: &SectionOverride) -> ResolvedSection {
    let limit = o.item_limit.map_or(20, clamp_item_limit);
    let section_type = if o.user_section_type.is_empty() {
        o.section_type.clone()
    } else {
        o.user_section_type.clone()
    };
    let title = if o.user_title.is_empty() {
        &o.title
    } else {
        &o.user_title
    };
    let config = if !o.user_config.is_empty() {
        o.user_config.as_bytes().to_vec()
    } else if !o.config.is_empty() {
        o.config.as_bytes().to_vec()
    } else {
        b"{}".to_vec()
    };
    ResolvedSection {
        id: o.id.clone(),
        title: readable_title(&section_type, title, &config),
        section_type,
        featured: o.featured.unwrap_or(false),
        item_limit: limit,
        is_custom: true,
        customized: false,
        config,
        position: o.position.unwrap_or(0),
    }
}

/// `sections.Resolve`. Go's `sort.Slice` is an insertion sort up to 12 rows, so it keeps ties in order there, as this
/// does; past 12 it may not, and two rows at one position have no contract order.
pub fn resolve(admin: &[PageSection], overrides: &[SectionOverride]) -> Vec<ResolvedSection> {
    let mut by_section: HashMap<&str, &SectionOverride> = HashMap::new();
    let mut user_added = Vec::new();
    for o in overrides {
        if o.section_id.is_empty() {
            user_added.push(o);
        } else {
            by_section.insert(&o.section_id, o);
        }
    }
    let mut result = Vec::new();
    for s in admin {
        let o = by_section.get(s.id.as_str()).copied();
        if o.is_some_and(|o| o.removed || o.hidden) {
            continue;
        }
        let mut rs = ResolvedSection {
            id: s.id.clone(),
            section_type: s.section_type.clone(),
            title: s.title.clone(),
            featured: s.featured,
            item_limit: clamp_item_limit(s.item_limit),
            is_custom: false,
            customized: false,
            config: s.config.clone(),
            position: s.position,
        };
        if let Some(o) = o {
            rs.customized = true;
            if let Some(position) = o.position {
                rs.position = position;
            }
            if !o.title.is_empty() {
                rs.title.clone_from(&o.title);
            }
            if let Some(featured) = o.featured {
                rs.featured = featured;
            }
            if let Some(limit) = o.item_limit {
                rs.item_limit = clamp_item_limit(limit);
            }
            if !o.config.is_empty() && o.config != "null" {
                rs.config = o.config.as_bytes().to_vec();
            }
        }
        rs.title = readable_title(&rs.section_type, &rs.title, &rs.config);
        result.push(rs);
    }
    for o in user_added {
        if o.removed || o.hidden {
            continue;
        }
        result.push(resolve_user_added(o));
    }
    result.sort_by_key(|r| r.position);
    result
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ContinueConfig {
    continue_type: String,
    filter_type: String,
    media_scope: String,
}

/// `ContinueTypeFromConfig` is `watching`.
fn continues_watching(config: &[u8]) -> bool {
    use silo_gocompat::strings::trim_space;
    let raw: ContinueConfig = if config.is_empty() {
        ContinueConfig::default()
    } else {
        match unmarshal::<Option<ContinueConfig>>(config) {
            Ok(parsed) => parsed.unwrap_or_default(),
            Err(_) => return true,
        }
    };
    let direct = silo_gocompat::strings::to_lower(trim_space(&raw.continue_type));
    if !direct.is_empty() {
        return !matches!(direct.as_str(), "listening" | "reading");
    }
    for field in [&raw.filter_type, &raw.media_scope] {
        let value = silo_gocompat::strings::to_lower(trim_space(field));
        if value == "audiobook" || value == "ebook" {
            return false;
        }
    }
    true
}

/// `injectNextUpSection`.
pub fn inject_next_up(resolved: Vec<ResolvedSection>) -> Vec<ResolvedSection> {
    const CW: &str = "continue_watching";
    let mut next_up = ResolvedSection {
        id: "system-next-up".to_owned(),
        section_type: "next_up".to_owned(),
        title: "Next Up".to_owned(),
        item_limit: 20,
        ..ResolvedSection::default()
    };
    let at = if let Some(i) = resolved
        .iter()
        .position(|s| s.section_type == CW && continues_watching(&s.config))
    {
        if resolved[i].item_limit > 0 {
            next_up.item_limit = resolved[i].item_limit;
        }
        let mut at = i + 1;
        while at < resolved.len() && resolved[at].section_type == CW {
            at += 1;
        }
        Some(at)
    } else {
        resolved
            .iter()
            .position(|s| s.section_type == CW)
            .map(|i| i + 1)
    };
    let mut result = resolved;
    // With no resume row, Go prepends.
    result.insert(at.unwrap_or(0), next_up);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin(id: &str, position: i64, kind: &str, title: &str) -> PageSection {
        section(position, id, kind, title, 100, "{}")
    }

    #[test]
    fn resolve_applies_overrides_and_keeps_custom_rows() {
        let overrides = vec![
            SectionOverride {
                section_id: "a".to_owned(),
                hidden: true,
                ..SectionOverride::default()
            },
            SectionOverride {
                section_id: "b".to_owned(),
                item_limit: Some(900),
                position: Some(9),
                ..SectionOverride::default()
            },
            SectionOverride {
                id: "mine".to_owned(),
                position: Some(5),
                user_section_type: "random".to_owned(),
                ..SectionOverride::default()
            },
        ];
        let out = resolve(
            &[admin("a", 0, "random", "A"), admin("b", 1, "random", "B")],
            &overrides,
        );
        let ids: Vec<&str> = out.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["mine", "b"]);
        assert_eq!(out[1].item_limit, MAX_ITEM_LIMIT);
        assert!(out[1].customized);
        assert!(out[0].is_custom);
        assert_eq!(out[0].item_limit, 20);
    }

    #[test]
    fn next_up_follows_the_watching_rows() {
        let rows = |kinds: &[(&str, &str)]| -> Vec<ResolvedSection> {
            kinds
                .iter()
                .map(|(kind, config)| ResolvedSection {
                    section_type: (*kind).to_owned(),
                    config: config.as_bytes().to_vec(),
                    item_limit: 7,
                    ..ResolvedSection::default()
                })
                .collect()
        };
        let cw = "continue_watching";
        let out = inject_next_up(rows(&[(cw, WATCHING), (cw, LISTENING), ("random", "{}")]));
        assert_eq!(out[2].section_type, "next_up");
        assert_eq!(out[2].item_limit, 7);
        let out = inject_next_up(rows(&[(cw, READING), ("random", "{}")]));
        assert_eq!(out[1].section_type, "next_up");
        assert_eq!(out[1].item_limit, 20);
        let out = inject_next_up(rows(&[("random", "{}")]));
        assert_eq!(out[0].section_type, "next_up");
    }

    #[test]
    fn a_raw_title_reads_as_the_recipes_preset() {
        assert_eq!(readable_title("random", "Mine", b"{}"), "Mine");
        assert_eq!(readable_title("no_such_recipe", " ", b"{}"), " ");
        let first = &presets()["anniversaries"][0].display_name;
        assert_eq!(&readable_title("anniversaries", "", b"not json"), first);
    }
}
