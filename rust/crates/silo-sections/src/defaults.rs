//! Port of `internal/sections/defaults.go`: the canonical default home and library section sets.

use serde_json::{Value, json};
use silo_gocompat::strings::to_lower;

use crate::continue_type::{ContinueType, continue_type_config, is_audiobook_library_type};
use crate::generated;

pub const DEFAULT_ITEM_LIMIT: i64 = 100;
pub const MAX_ITEM_LIMIT: i64 = 500;
const BETA_LIBRARY_ITEM_LIMIT: i64 = 20;
const SCOPE_HOME: &str = "home";
const SCOPE_LIBRARY: &str = "library";
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";
/// `recipes.DefaultSeasonalConfig`.
pub const DEFAULT_SEASONAL_CONFIG: &str = r#"{"enabled_themes":["halloween","christmas","new_year","valentines","st_patricks","easter","thanksgiving","summer_blockbuster","saturday_morning"]}"#;

/// Go's `models.MediaFolder`, reduced to what the defaults read.
#[derive(Debug, Clone, Default)]
pub struct MediaFolder {
    pub id: i64,
    pub name: String,
    pub r#type: String,
}

/// Go's `PageSection`. `config` holds raw JSON bytes; timestamps are left at Go's zero time.
#[derive(Debug, Clone, PartialEq)]
pub struct PageSection {
    pub id: String,
    pub scope: String,
    pub library_id: Option<i64>,
    pub position: i64,
    pub section_type: String,
    pub title: String,
    pub featured: bool,
    pub item_limit: i64,
    pub config: String,
    pub enabled: bool,
}

impl PageSection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: &str,
        scope: &str,
        library_id: Option<i64>,
        position: i64,
        section_type: &str,
        title: &str,
        item_limit: i64,
        config: String,
    ) -> Self {
        Self {
            id: id.into(),
            scope: scope.into(),
            library_id,
            position,
            section_type: section_type.into(),
            title: title.into(),
            featured: false,
            item_limit,
            config,
            enabled: true,
        }
    }

    /// The Go JSON encoding (`created_at`/`updated_at` at the zero time).
    pub fn to_json(&self) -> Value {
        let config: Value = serde_json::from_str(&self.config).unwrap_or(Value::Null);
        json!({
            "id": self.id, "scope": self.scope, "library_id": self.library_id,
            "position": self.position, "section_type": self.section_type, "title": self.title,
            "featured": self.featured, "item_limit": self.item_limit, "config": config,
            "enabled": self.enabled, "created_at": ZERO_TIME, "updated_at": ZERO_TIME,
        })
    }
}

pub fn clamp_item_limit(limit: i64) -> i64 {
    limit.min(MAX_ITEM_LIMIT)
}

fn library_row_item_limit(library_type: &str) -> i64 {
    if is_video_library_type(library_type) {
        DEFAULT_ITEM_LIMIT
    } else {
        BETA_LIBRARY_ITEM_LIMIT
    }
}

/// `IsVideoLibraryType`: librarykind movie, TV, or mixed.
pub fn is_video_library_type(library_type: &str) -> bool {
    matches!(
        to_lower(library_type.trim()).as_str(),
        "movie" | "movies" | "series" | "tv" | "show" | "tvshows" | "mixed"
    )
}

fn query_config(media_scope: &str, sort_field: &str) -> String {
    format!(
        r#"{{"media_scope":"{media_scope}","match":"all","groups":[],"sort":{{"field":"{sort_field}","order":"desc"}}}}"#
    )
}
fn media_scope_config(s: &str) -> String {
    query_config(s, "added_at")
}
fn top_rated_config(s: &str) -> String {
    query_config(s, "rating_imdb")
}
fn ct(t: &str) -> String {
    continue_type_config(&ContinueType::new(t))
}
fn raw(s: &str) -> String {
    s.to_string()
}

fn generated_home_library_recent_defaults(
    library_id: i64,
    name: &str,
    library_type: &str,
) -> Vec<PageSection> {
    let (added, released) = if library_type == "manga" {
        (
            generated::home_library_recent_config_scoped(library_id, "manga"),
            generated::home_library_recent_config_scoped(library_id, "manga"),
        )
    } else {
        (
            generated::home_library_recent_config(library_id),
            generated::home_library_recent_config(library_id),
        )
    };
    let limit = library_row_item_limit(library_type);
    let mut out = vec![PageSection::new(
        "",
        SCOPE_HOME,
        None,
        0,
        "recently_added",
        &generated::home_library_recent_title("recently_added", name),
        limit,
        added,
    )];
    if library_type == "series" {
        out.push(PageSection::new(
            "",
            SCOPE_HOME,
            None,
            0,
            "custom_filter",
            &format!("Recently Released Episodes in {name}"),
            limit,
            generated::home_library_recent_episodes_config(library_id),
        ));
    } else {
        out.push(PageSection::new(
            "",
            SCOPE_HOME,
            None,
            0,
            "recently_released",
            &generated::home_library_recent_title("recently_released", name),
            limit,
            released,
        ));
    }
    out
}

/// `generatedHomeLibraryRecentID` for the sections built above: their config carries a
/// generated kind only for the released-episodes row.
fn generated_home_library_recent_id(section: &PageSection, library_id: i64) -> String {
    if section.config.contains(generated::KIND_RELEASED_EPISODES) {
        return format!(
            "default-home-{}-library-{library_id}",
            generated::KIND_RELEASED_EPISODES
        );
    }
    format!("default-home-{}-library-{library_id}", section.section_type)
}

/// `DefaultHomeSections`. `None` entries mirror Go's nil folders and are skipped.
pub fn default_home_sections(libraries: &[Option<MediaFolder>]) -> Vec<PageSection> {
    let h = |id: &str, ty: &str, title: &str, limit: i64, cfg: String| {
        PageSection::new(id, SCOPE_HOME, None, 0, ty, title, limit, cfg)
    };
    let mut out = vec![h(
        "default-continue-watching",
        "continue_watching",
        "Continue Watching",
        DEFAULT_ITEM_LIMIT,
        ct("watching"),
    )];
    if libraries
        .iter()
        .flatten()
        .any(|l| is_audiobook_library_type(&l.r#type))
    {
        out.push(h(
            "default-continue-listening",
            "continue_watching",
            "Continue Listening",
            BETA_LIBRARY_ITEM_LIMIT,
            ct("listening"),
        ));
    }
    out.push(h(
        "default-trending-discover",
        "trending_discover",
        "Trending This Week",
        DEFAULT_ITEM_LIMIT,
        raw(r#"{"source":"tmdb","window":"week"}"#),
    ));
    out.push(h(
        "default-recently-added-movies",
        "recently_added",
        "Recently Added Movies",
        DEFAULT_ITEM_LIMIT,
        media_scope_config("movie"),
    ));
    out.push(h(
        "default-recently-added-tv",
        "recently_added",
        "Recently Added TV",
        DEFAULT_ITEM_LIMIT,
        media_scope_config("series"),
    ));
    for lib in libraries.iter().flatten() {
        if is_video_library_type(&lib.r#type) {
            continue;
        }
        for mut s in generated_home_library_recent_defaults(lib.id, &lib.name, &lib.r#type) {
            s.id = generated_home_library_recent_id(&s, lib.id);
            out.push(s);
        }
    }
    out.push(h(
        "default-recommended-for-you",
        "recommended_for_you",
        "Recommended for You",
        DEFAULT_ITEM_LIMIT,
        raw("{}"),
    ));
    out.push(h(
        "default-because-you-watched",
        "because_you_watched",
        "Because You Watched",
        DEFAULT_ITEM_LIMIT,
        raw("{}"),
    ));
    out.push(h(
        "default-returning-shows",
        "returning_shows",
        "Returning Shows",
        DEFAULT_ITEM_LIMIT,
        raw("{}"),
    ));
    out.push(h(
        "default-top-rated",
        "critically_acclaimed",
        "Top Rated",
        DEFAULT_ITEM_LIMIT,
        raw("{}"),
    ));
    out.push(h(
        "default-hidden-gems",
        "hidden_gems",
        "Hidden Gems",
        DEFAULT_ITEM_LIMIT,
        raw(r#"{"min_rating":7.5}"#),
    ));
    out.push(h(
        "default-seasonal",
        "seasonal_themed",
        "Seasonal Picks",
        DEFAULT_ITEM_LIMIT,
        raw(DEFAULT_SEASONAL_CONFIG),
    ));
    for (i, s) in out.iter_mut().enumerate() {
        s.position = i as i64;
    }
    out
}

type Row = (&'static str, &'static str, &'static str, String);

fn library_rows(library_id: Option<i64>, limit: i64, rows: Vec<Row>) -> Vec<PageSection> {
    rows.into_iter()
        .enumerate()
        .map(|(i, (id, ty, title, cfg))| {
            PageSection::new(
                id,
                SCOPE_LIBRARY,
                library_id,
                i as i64,
                ty,
                title,
                limit,
                cfg,
            )
        })
        .collect()
}

/// `DefaultLibrarySectionsForType`.
pub fn default_library_sections_for_type(
    library_id: Option<i64>,
    library_type: &str,
) -> Vec<PageSection> {
    let e = || raw("{}");
    let rfy = (
        "default-recommended-for-you",
        "recommended_for_you",
        "Recommended for You",
    );
    match library_type {
        "movies" | "movie" => library_rows(
            library_id,
            DEFAULT_ITEM_LIMIT,
            vec![
                (
                    "default-continue-watching",
                    "continue_watching",
                    "Continue Watching",
                    ct("watching"),
                ),
                (
                    "default-recently-added-movies",
                    "recently_added",
                    "Recently Added Movies",
                    media_scope_config("movie"),
                ),
                (
                    "default-recently-released-movies",
                    "recently_released",
                    "Recently Released Movies",
                    media_scope_config("movie"),
                ),
                (
                    "default-top-rated-movies",
                    "custom_filter",
                    "Top Rated Movies",
                    top_rated_config("movie"),
                ),
                (rfy.0, rfy.1, rfy.2, e()),
                (
                    "default-random-movies",
                    "random",
                    "Random Picks",
                    media_scope_config("movie"),
                ),
            ],
        ),
        "series" => library_rows(
            library_id,
            DEFAULT_ITEM_LIMIT,
            vec![
                (
                    "default-continue-watching",
                    "continue_watching",
                    "Continue Watching",
                    ct("watching"),
                ),
                (
                    "default-recently-added-tv",
                    "recently_added",
                    "Recently Added TV",
                    media_scope_config("series"),
                ),
                (
                    "default-returning-shows",
                    "returning_shows",
                    "Returning Shows",
                    e(),
                ),
                (
                    "default-recently-released-episodes",
                    "custom_filter",
                    "Recently Released Episodes",
                    query_config("episode", "release_date"),
                ),
                (
                    "default-top-rated-tv",
                    "custom_filter",
                    "Top Rated TV",
                    top_rated_config("series"),
                ),
                (rfy.0, rfy.1, rfy.2, e()),
                (
                    "default-random-tv",
                    "random",
                    "Random Picks",
                    media_scope_config("series"),
                ),
            ],
        ),
        "audiobooks" | "audiobook" => {
            let mut v = library_rows(
                library_id,
                BETA_LIBRARY_ITEM_LIMIT,
                vec![
                    (
                        "default-continue-listening",
                        "continue_watching",
                        "Continue Listening",
                        ct("listening"),
                    ),
                    (
                        "default-next-in-series",
                        "next_in_series",
                        "Next in Your Series",
                        e(),
                    ),
                    (
                        "default-recently-added-audiobooks",
                        "recently_added",
                        "Recently Added Audiobooks",
                        media_scope_config("audiobook"),
                    ),
                    (
                        "default-recently-released-audiobooks",
                        "recently_released",
                        "Recently Released Audiobooks",
                        media_scope_config("audiobook"),
                    ),
                    (rfy.0, rfy.1, rfy.2, e()),
                    (
                        "default-random-audiobooks",
                        "random",
                        "Random Picks",
                        media_scope_config("audiobook"),
                    ),
                ],
            );
            v[0].featured = true;
            v
        }
        "ebooks" | "ebook" => library_rows(
            library_id,
            BETA_LIBRARY_ITEM_LIMIT,
            vec![
                (
                    "default-continue-reading",
                    "continue_watching",
                    "Continue Reading",
                    ct("reading"),
                ),
                (
                    "default-recently-added-ebooks",
                    "recently_added",
                    "Recently Added Ebooks",
                    media_scope_config("ebook"),
                ),
                (
                    "default-recently-released-ebooks",
                    "recently_released",
                    "Recently Released Ebooks",
                    media_scope_config("ebook"),
                ),
                (rfy.0, rfy.1, rfy.2, e()),
                (
                    "default-random-ebooks",
                    "random",
                    "Random Picks",
                    media_scope_config("ebook"),
                ),
            ],
        ),
        "manga" => library_rows(
            library_id,
            BETA_LIBRARY_ITEM_LIMIT,
            vec![
                (
                    "default-continue-reading",
                    "continue_watching",
                    "Continue Reading",
                    ct("reading"),
                ),
                (
                    "default-recently-added-manga",
                    "recently_added",
                    "Recently Added Manga",
                    media_scope_config("manga"),
                ),
                (
                    "default-recently-released-manga",
                    "recently_released",
                    "Recently Released Manga",
                    media_scope_config("manga"),
                ),
                (rfy.0, rfy.1, rfy.2, e()),
                (
                    "default-random-manga",
                    "random",
                    "Random Picks",
                    media_scope_config("manga"),
                ),
            ],
        ),
        _ => fallback(library_id, library_row_item_limit(library_type)),
    }
}

/// `DefaultLibrarySections`.
pub fn default_library_sections(library_id: Option<i64>) -> Vec<PageSection> {
    fallback(library_id, DEFAULT_ITEM_LIMIT)
}

fn fallback(library_id: Option<i64>, limit: i64) -> Vec<PageSection> {
    library_rows(
        library_id,
        limit,
        vec![
            (
                "default-continue-watching",
                "continue_watching",
                "Continue Watching",
                ct("watching"),
            ),
            (
                "default-recently-added",
                "recently_added",
                "Recently Added",
                raw("{}"),
            ),
            (
                "default-recently-released",
                "recently_released",
                "Recently Released",
                raw("{}"),
            ),
        ],
    )
}
