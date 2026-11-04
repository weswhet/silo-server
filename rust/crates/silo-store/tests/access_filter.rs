//! The access filter's queries against a seeded conformance database, for a viewer with a rating
//! ceiling and an advisory limit. `media_items.content_rating_age` and `advisory_age` are `smallint`, so
//! a bind of the wrong integer width fails before the query runs (M4 review, H1).
//!
//! Needs `SILO_STORE_ACCESS_DATABASE_URL`: a database holding the conformance seed, where
//! `movie-tmdb-9000001` is rated PG and `movie-tmdb-9000002` is rated R. The test skips when it is unset.
//!
//! `cargo test -p silo-store --test access_filter -- --test-threads=1`

use silo_pg::{Pool, PoolConfig};
use silo_store::catalog::access::{
    AccessFilter, ensure_accessible, filter_accessible, visible_items,
};

const PG: &str = "movie-tmdb-9000001";
const R: &str = "movie-tmdb-9000002";

async fn pool() -> Option<Pool> {
    let url = std::env::var("SILO_STORE_ACCESS_DATABASE_URL")
        .ok()
        .filter(|v| !v.is_empty());
    let Some(url) = url else {
        eprintln!("SILO_STORE_ACCESS_DATABASE_URL is not set; skipping");
        return None;
    };
    Some(
        Pool::connect(PoolConfig::parse(&url).unwrap())
            .await
            .unwrap(),
    )
}

fn kid(advisory: i32) -> AccessFilter {
    AccessFilter {
        max_content_rating: "PG".to_owned(),
        max_advisory_age: advisory,
        allow_unrated_content: true,
        ..AccessFilter::default()
    }
}

#[tokio::test]
async fn ceiling_and_advisory_limits_bind_against_smallint_columns() {
    let Some(pool) = pool().await else { return };
    for filter in [kid(0), kid(18)] {
        assert!(ensure_accessible(&pool, PG, &filter).await.unwrap());
        assert!(!ensure_accessible(&pool, R, &filter).await.unwrap());
        let ids = vec![PG.to_owned(), R.to_owned()];
        let seen = filter_accessible(&pool, &ids, &filter).await.unwrap();
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![PG.to_owned()]);
        let items = visible_items(&pool, &ids, &filter).await.unwrap();
        assert_eq!(
            items.keys().cloned().collect::<Vec<_>>(),
            vec![PG.to_owned()]
        );
    }
}

/// `scanLibraryCollection`: a collection with no `library_collection_libraries` rows is scoped to its own
/// `library_id`, so a viewer without that library is refused (M4 review, L2).
#[tokio::test]
async fn library_collection_without_library_rows_is_scoped_to_its_library() {
    let Some(pool) = pool().await else { return };
    let id = "access-filter-legacy-collection";
    let library = pool
        .query("SELECT id::int FROM media_folders ORDER BY id LIMIT 1", &[])
        .await
        .unwrap()[0]
        .get::<_, i32>(0);
    pool.execute("DELETE FROM library_collections WHERE id = $1", &[&id])
        .await
        .unwrap();
    pool.execute(
        "INSERT INTO library_collections (id, library_id, slug, title, collection_type) VALUES ($1, $2, $1, $1, 'manual')",
        &[&id, &library],
    )
    .await
    .unwrap();
    let scope = silo_store::userstore::collections::library_collection_scope(&pool, id).await;
    pool.execute("DELETE FROM library_collections WHERE id = $1", &[&id])
        .await
        .unwrap();
    let (_, libraries) = scope.unwrap().expect("the collection exists");
    assert_eq!(libraries, vec![library]);
}
