//! `item_repo.go`'s media item select lists (`itemColumnNames` through `qualifiedListItemColumns`).
//!
//! [`MediaItem`] is `models.MediaItem` as these select lists fill it (`listItemScanDests`,
//! `scanItemsWithMangaCounts`). Fields other reads fill (people, series membership, artwork
//! hints) join it with the chunks that port those reads.

use std::time::SystemTime;

use silo_pg::Row;

use crate::query::episode_source::effective_last_air_date_expr;

/// `models.MediaItem`, the columns of [`ITEM_COLUMN_NAMES`] plus the manga counts and `AddedAt`.
#[derive(Clone, Debug, PartialEq)]
pub struct MediaItem {
    pub content_id: String,
    pub item_type: String,
    pub title: String,
    pub sort_title: String,
    pub default_metadata_language: String,
    pub original_title: String,
    pub year: i64,
    pub genres: Vec<String>,
    pub content_rating: String,
    pub runtime: i64,
    pub overview: String,
    pub tagline: String,
    pub rating_imdb: Option<f64>,
    pub rating_tmdb: Option<f64>,
    pub rating_rt_critic: Option<i64>,
    pub rating_rt_audience: Option<i64>,
    pub imdb_id: String,
    pub tmdb_id: String,
    pub tvdb_id: String,
    pub poster_path: String,
    pub poster_source_path: String,
    pub poster_thumbhash: String,
    pub backdrop_path: String,
    pub backdrop_source_path: String,
    pub backdrop_thumbhash: String,
    pub logo_path: String,
    pub logo_source_path: String,
    pub banner_path: String,
    pub banner_source_path: String,
    pub banner_thumbhash: String,
    pub thumb_path: String,
    pub thumb_source_path: String,
    pub thumb_thumbhash: String,
    pub clear_art_path: String,
    pub clear_art_source_path: String,
    pub disc_path: String,
    pub disc_source_path: String,
    pub metadata_s3_path: String,
    pub metadata_etag: String,
    pub season_count: Option<i64>,
    pub studios: Vec<String>,
    pub networks: Vec<String>,
    pub countries: Vec<String>,
    pub keywords: Vec<String>,
    pub original_language: String,
    pub release_date: Option<String>,
    pub first_air_date: Option<String>,
    pub last_air_date: Option<String>,
    pub air_time: Option<String>,
    pub air_timezone: Option<String>,
    pub show_status: String,
    pub matched_at: Option<SystemTime>,
    pub last_refreshed: Option<SystemTime>,
    pub refresh_failures: i64,
    pub episode_metadata_incomplete: bool,
    pub episode_metadata_last_checked_at: Option<SystemTime>,
    pub locked_fields: Vec<i64>,
    pub status: String,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub advisory_age: Option<i64>,
    pub advisory_source: String,
    pub manga_chapter_count: Option<i64>,
    pub manga_volume_count: Option<i64>,
    /// `AddedAt`: browse reads set it; the preview path falls back to `created_at`.
    pub added_at: Option<SystemTime>,
}

fn int(row: &Row, i: usize) -> Result<Option<i64>, String> {
    row.try_get::<_, Option<silo_pg::AnyInt>>(i)
        .map(|v| v.map(|v| v.0))
        .map_err(|e| format!("scanning media item row: {e}"))
}

fn get<'a, T: silo_pg::pg_types::FromSql<'a>>(row: &'a Row, i: usize) -> Result<T, String> {
    row.try_get::<_, T>(i)
        .map_err(|e| format!("scanning media item row: {e}"))
}

impl MediaItem {
    /// `listItemScanDests` from column `0`, followed by the manga counts when `manga` is set
    /// (`scanItemsWithMangaCounts`, which keeps them only on manga rows).
    pub fn scan(row: &Row, manga: bool) -> Result<MediaItem, String> {
        let s = |i| get::<String>(row, i);
        let strs = |i| get::<Option<Vec<String>>>(row, i).map(Option::unwrap_or_default);
        let mut item = MediaItem {
            content_id: s(0)?,
            item_type: s(1)?,
            title: s(2)?,
            sort_title: s(3)?,
            default_metadata_language: s(4)?,
            original_title: s(5)?,
            year: int(row, 6)?.unwrap_or(0),
            genres: strs(7)?,
            content_rating: s(8)?,
            runtime: int(row, 9)?.unwrap_or(0),
            overview: s(10)?,
            tagline: s(11)?,
            rating_imdb: get(row, 12)?,
            rating_tmdb: get(row, 13)?,
            rating_rt_critic: int(row, 14)?,
            rating_rt_audience: int(row, 15)?,
            imdb_id: s(16)?,
            tmdb_id: s(17)?,
            tvdb_id: s(18)?,
            poster_path: s(19)?,
            poster_source_path: s(20)?,
            poster_thumbhash: s(21)?,
            backdrop_path: s(22)?,
            backdrop_source_path: s(23)?,
            backdrop_thumbhash: s(24)?,
            logo_path: s(25)?,
            logo_source_path: s(26)?,
            banner_path: s(27)?,
            banner_source_path: s(28)?,
            banner_thumbhash: s(29)?,
            thumb_path: s(30)?,
            thumb_source_path: s(31)?,
            thumb_thumbhash: s(32)?,
            clear_art_path: s(33)?,
            clear_art_source_path: s(34)?,
            disc_path: s(35)?,
            disc_source_path: s(36)?,
            metadata_s3_path: s(37)?,
            metadata_etag: s(38)?,
            season_count: int(row, 39)?,
            studios: strs(40)?,
            networks: strs(41)?,
            countries: strs(42)?,
            keywords: strs(43)?,
            original_language: s(44)?,
            release_date: get(row, 45)?,
            first_air_date: get(row, 46)?,
            last_air_date: get(row, 47)?,
            air_time: get(row, 48)?,
            air_timezone: get(row, 49)?,
            show_status: s(50)?,
            matched_at: get(row, 51)?,
            last_refreshed: get(row, 52)?,
            refresh_failures: int(row, 53)?.unwrap_or(0),
            episode_metadata_incomplete: get(row, 54)?,
            episode_metadata_last_checked_at: get(row, 55)?,
            locked_fields: get::<Option<Vec<i32>>>(row, 56)?
                .unwrap_or_default()
                .into_iter()
                .map(i64::from)
                .collect(),
            status: s(57)?,
            created_at: get(row, 58)?,
            updated_at: get(row, 59)?,
            advisory_age: int(row, 60)?,
            advisory_source: s(61)?,
            manga_chapter_count: None,
            manga_volume_count: None,
            added_at: None,
        };
        if manga && item.item_type == "manga" {
            item.manga_chapter_count = int(row, 62)?;
            item.manga_volume_count = int(row, 63)?;
        }
        Ok(item)
    }
}

/// `itemColumnNames`, in scan order.
pub const ITEM_COLUMN_NAMES: &[&str] = &[
    "content_id",
    "type",
    "title",
    "sort_title",
    "default_metadata_language",
    "original_title",
    "year",
    "genres",
    "content_rating",
    "runtime",
    "overview",
    "tagline",
    "rating_imdb",
    "rating_tmdb",
    "rating_rt_critic",
    "rating_rt_audience",
    "imdb_id",
    "tmdb_id",
    "tvdb_id",
    "poster_path",
    "poster_source_path",
    "poster_thumbhash",
    "backdrop_path",
    "backdrop_source_path",
    "backdrop_thumbhash",
    "logo_path",
    "logo_source_path",
    "banner_path",
    "banner_source_path",
    "banner_thumbhash",
    "thumb_path",
    "thumb_source_path",
    "thumb_thumbhash",
    "clearart_path",
    "clearart_source_path",
    "disc_path",
    "disc_source_path",
    "metadata_s3_path",
    "metadata_etag",
    "season_count",
    "studios",
    "networks",
    "countries",
    "keywords",
    "original_language",
    "release_date::text",
    "first_air_date",
    "last_air_date",
    "air_time",
    "air_timezone",
    "show_status",
    "matched_at",
    "last_refreshed",
    "refresh_failures",
    "episode_metadata_incomplete",
    "episode_metadata_last_checked_at",
    "locked_fields",
    "status",
    "created_at",
    "updated_at",
    "advisory_age",
    "advisory_source",
];

/// `nullableStringItemColumns`.
fn nullable_string_item_column(col: &str) -> bool {
    matches!(
        col,
        "advisory_source"
            | "poster_path"
            | "poster_source_path"
            | "poster_thumbhash"
            | "backdrop_path"
            | "backdrop_source_path"
            | "backdrop_thumbhash"
            | "logo_path"
            | "logo_source_path"
            | "metadata_s3_path"
            | "metadata_etag"
    )
}

/// `itemColumnExpr`.
pub fn item_column_expr(alias: &str, col: &str) -> String {
    let qualified = if alias.is_empty() {
        col.to_owned()
    } else {
        format!("{alias}.{col}")
    };
    if nullable_string_item_column(col) {
        return format!("COALESCE({qualified}, '') AS {col}");
    }
    qualified
}

/// `joinItemColumns` (and `qualifiedItemColumns`).
pub fn join_item_columns(alias: &str) -> String {
    ITEM_COLUMN_NAMES
        .iter()
        .map(|c| item_column_expr(alias, c))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `qualifiedItemColumnRefs`.
pub fn qualified_item_column_refs(alias: &str) -> String {
    ITEM_COLUMN_NAMES
        .iter()
        .map(|c| format!("{alias}.{c}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `qualifiedListItemColumns`.
pub fn qualified_list_item_columns(alias: &str) -> String {
    ITEM_COLUMN_NAMES
        .iter()
        .map(|c| {
            if *c == "last_air_date" {
                format!("{} AS last_air_date", effective_last_air_date_expr(alias))
            } else {
                item_column_expr(alias, c)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
