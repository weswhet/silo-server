//! Read-only administrator collection-group and unmatched-file queries.
//! SQL follows `internal/catalog/library_collection_group_repo.go`,
//! `library_collection_mutations.go`, and `internal/api/handlers/admin.go`.

use silo_pg::Pool;
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct CollectionGroup {
    pub id: String,
    pub library_id: i32,
    pub name: String,
    pub slug: String,
    pub kind: String,
    pub default_sort_mode: String,
    pub sort_order: i32,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

pub async fn list_collection_groups(
    pool: &Pool,
    library_id: i32,
) -> Result<Vec<CollectionGroup>, String> {
    let rows = pool
        .query(
            "
		SELECT id, library_id, name, slug, kind, default_sort_mode, sort_order, created_at, updated_at
		FROM library_collection_groups
		WHERE library_id = $1
		ORDER BY sort_order ASC, name ASC, id ASC",
            &[&library_id],
        )
        .await
        .map_err(|e| e.to_string())?;
    rows.iter()
        .map(|row| {
            Ok(CollectionGroup {
                id: row.try_get(0)?,
                library_id: row.try_get(1)?,
                name: row.try_get(2)?,
                slug: row.try_get(3)?,
                kind: row.try_get(4)?,
                default_sort_mode: row.try_get(5)?,
                sort_order: row.try_get(6)?,
                created_at: row.try_get(7)?,
                updated_at: row.try_get(8)?,
            })
        })
        .collect::<Result<Vec<_>, silo_pg::DriverError>>()
        .map_err(|e| e.to_string())
}

pub async fn ungrouped_sort_order(pool: &Pool, library_id: i32) -> Result<i32, String> {
    pool.query(
        "
		SELECT collection_ungrouped_sort_order
		FROM media_folders
		WHERE id = $1
	",
        &[&library_id],
    )
    .await
    .map_err(|e| e.to_string())?
    .first()
    .ok_or_else(|| "loading ungrouped collection sort order: no rows in result set".to_owned())?
    .try_get(0)
    .map_err(|e| e.to_string())
}

pub async fn collection_order_revision(
    pool: &Pool,
    library_id: i32,
) -> Result<Option<i64>, String> {
    pool.query(
        "SELECT COALESCE(v.revision,1) FROM media_folders f LEFT JOIN library_collection_order_revisions v ON v.library_id=f.id WHERE f.id=$1",
        &[&library_id],
    )
    .await
    .map_err(|e| e.to_string())?
    .first()
    .map(|row| row.try_get(0).map_err(|e| e.to_string()))
    .transpose()
}

#[derive(Clone, Debug)]
pub struct UnmatchedFile {
    pub id: i64,
    pub media_folder_id: i32,
    pub file_path: String,
    pub file_size: i64,
    pub container: String,
}

/// Fetches the caller's requested number of rows, including any pagination lookahead.
pub async fn list_unmatched_files(
    pool: &Pool,
    limit: i64,
    after: i64,
) -> Result<Vec<UnmatchedFile>, String> {
    let offset = 0_i64;
    let rows = pool
        .query(
            "SELECT id, media_folder_id, file_path, file_size, container
		 FROM media_files
		 WHERE content_id IS NULL AND extra_id IS NULL AND ($3::bigint IS NULL OR id > $3)
		 ORDER BY id ASC
		 LIMIT $1 OFFSET $2",
            &[&limit, &offset, &after],
        )
        .await
        .map_err(|_| "Failed to list unmatched files".to_owned())?;
    rows.iter()
        .map(|row| {
            Ok(UnmatchedFile {
                id: i64::from(row.try_get::<_, i32>(0)?),
                media_folder_id: row.try_get(1)?,
                file_path: row.try_get(2)?,
                file_size: row.try_get(3)?,
                container: row.try_get(4)?,
            })
        })
        .collect::<Result<Vec<_>, silo_pg::DriverError>>()
        .map_err(|_| "Failed to scan file".to_owned())
}
