//! The query engine's preview pages against Postgres, compared with the content IDs Go's
//! `QueryExecutor.PreviewPage` returned on the same database (`query_db.json`).
//!
//! Needs `SILO_CATALOG_DATABASE_URL`: the scratch database
//! `rust/conformance/vectors/generators/catalogquery/fixture.sh` prints (the conformance seed plus
//! the synthetic fixture). The test skips when it is unset.
//!
//! `cargo test -p silo-catalog --test query_db -- --test-threads=1`

use serde::Deserialize;
use silo_catalog::query::run::SeekAnchorCache;
use silo_catalog::query::{AccessFilter, QueryCursor, QueryDefinition, QueryExecutor};
use silo_pg::{Pool, PoolConfig};

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
struct GoAccess {
    allowed: Option<Vec<i32>>,
    disabled: Option<Vec<i32>>,
    max_content_rating: String,
    allow_unrated_content: bool,
    max_advisory_age: i32,
    require_advisory_age: bool,
    allowed_content_ids: Option<Vec<String>>,
    user_id: i64,
    profile_id: String,
    name_prefix: String,
    excluded_media_types: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Case {
    def: String,
    access: GoAccess,
    limit: i64,
    offset: i64,
    ids: Vec<String>,
    total: i64,
    has_more: bool,
    error: String,
}

impl GoAccess {
    fn filter(&self) -> AccessFilter {
        let a = self;
        AccessFilter {
            allowed: a.allowed.clone(),
            disabled: a.disabled.clone().unwrap_or_default(),
            max_content_rating: a.max_content_rating.clone(),
            allow_unrated_content: a.allow_unrated_content,
            max_advisory_age: a.max_advisory_age,
            require_advisory_age: a.require_advisory_age,
            allowed_content_ids: a.allowed_content_ids.clone(),
            user_id: a.user_id,
            profile_id: a.profile_id.clone(),
            name_prefix: a.name_prefix.clone(),
            excluded_media_types: a.excluded_media_types.clone().unwrap_or_default(),
        }
    }
}

async fn pool() -> Option<Pool> {
    let url = std::env::var("SILO_CATALOG_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty());
    let Some(url) = url else {
        eprintln!("SILO_CATALOG_DATABASE_URL is not set; skipping");
        return None;
    };
    Some(
        Pool::connect(PoolConfig::parse(&url).unwrap())
            .await
            .unwrap(),
    )
}

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let raw = std::fs::read(format!(
        "{}/../../conformance/vectors/catalog/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    serde_json::from_slice(&raw).unwrap()
}

#[tokio::test]
async fn preview_pages_match_go() {
    let Some(pool) = pool().await else { return };
    let cases: Vec<Case> = load("query_db");
    let mut compared = 0;
    for c in &cases {
        let ctx = format!("{} {:?} {}/{}", c.def, c.access, c.limit, c.offset);
        let def: QueryDefinition = silo_gocompat::json::unmarshal(c.def.as_bytes()).unwrap();
        let filter = c.access.filter();
        if let Err(e) =
            QueryExecutor::default().build_preview_page_plan(&def, &filter, c.limit, c.offset)
        {
            assert_eq!(e, c.error, "{ctx}");
            continue;
        }
        assert_eq!(c.error, "", "{ctx}");
        let (items, total, has_more) = QueryExecutor::default()
            .preview_page(&pool, &def, &filter, c.limit, c.offset, true)
            .await
            .unwrap_or_else(|e| panic!("{ctx}: {e}"));
        let ids: Vec<String> = items.iter().map(|i| i.content_id.clone()).collect();
        assert_eq!(ids, c.ids, "{ctx}");
        assert_eq!((total, has_more), (c.total, c.has_more), "{ctx}");
        compared += 1;
    }
    assert!(compared > 500, "only {compared} pages compared");
}

#[derive(Deserialize)]
struct SeekOut {
    index: i64,
    cursor: Option<QueryCursor>,
    error: String,
}

#[derive(Deserialize)]
struct CursorCase {
    def: String,
    access: GoAccess,
    limit: i64,
    page1: Option<Vec<String>>,
    next1: Option<QueryCursor>,
    total: i64,
    page2: Option<Vec<String>>,
    next2: Option<QueryCursor>,
    error: String,
    seeks: Vec<SeekOut>,
}

/// `PreviewCursorPage` two pages deep, then `SeekCursor` with seek anchors, against Go's results.
#[tokio::test]
async fn cursor_pages_and_seeks_match_go() {
    let Some(pool) = pool().await else { return };
    let cases: Vec<CursorCase> = load("query_db_cursor");
    for c in &cases {
        let ctx = format!("{} {:?}", c.def, c.access);
        let def: QueryDefinition = silo_gocompat::json::unmarshal(c.def.as_bytes()).unwrap();
        let filter = c.access.filter();
        let ex = QueryExecutor::default();
        let anchors = SeekAnchorCache::new();
        let p1 = match ex
            .preview_cursor_page(&pool, &def, &filter, c.limit, None, true)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                assert_eq!(e, c.error, "{ctx}");
                continue;
            }
        };
        let ids = |items: &[silo_catalog::model::MediaItem]| -> Vec<String> {
            items.iter().map(|i| i.content_id.clone()).collect()
        };
        assert_eq!(ids(&p1.items), c.page1.clone().unwrap_or_default(), "{ctx}");
        assert_eq!(p1.next, c.next1, "{ctx}");
        assert_eq!(p1.total, c.total, "{ctx}");
        if let Some(next) = &p1.next {
            let p2 = ex
                .preview_cursor_page(&pool, &def, &filter, c.limit, Some(next), false)
                .await
                .unwrap();
            assert_eq!(ids(&p2.items), c.page2.clone().unwrap_or_default(), "{ctx}");
            assert_eq!(p2.next, c.next2, "{ctx}");
        }
        for s in &c.seeks {
            match ex
                .seek_cursor(&pool, Some(&anchors), &def, &filter, s.index)
                .await
            {
                Ok(key) => assert_eq!(
                    (key, ""),
                    (s.cursor.clone(), s.error.as_str()),
                    "{ctx} seek {}",
                    s.index
                ),
                Err(e) => assert_eq!(e, s.error, "{ctx} seek {}", s.index),
            }
        }
    }
}
