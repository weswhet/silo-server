//! Database-only group creation and guarded ordering from Go's group repository.
use super::CollectionGroup;
use silo_pg::{Error, Pool};

#[derive(Debug)]
pub enum MutationError {
    NotFound,
    Stale,
    OrderedMismatch,
    Duplicates,
    Db(Error),
}
impl From<Error> for MutationError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

pub async fn create(
    pool: &Pool,
    id: &str,
    library_id: i32,
    name: &str,
    slug: &str,
    sort: &str,
) -> Result<CollectionGroup, Error> {
    let rows = pool.query("
		INSERT INTO library_collection_groups (
			id, library_id, label, title, name, slug, kind, default_sort_mode, sort_order
		)
		VALUES ($1, $2, $3, $4, $4, $3, $5, $6,
			COALESCE((SELECT MAX(sort_order) + 1 FROM library_collection_groups WHERE library_id = $2), 0))
		RETURNING id, library_id, name, slug, kind, default_sort_mode, sort_order, created_at, updated_at", &[&id, &library_id, &slug, &name, &"regular", &sort]).await?;
    let row = rows.first().ok_or(Error::NoRows)?;
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
}

const REVISION: &str = "SELECT COALESCE(v.revision,1) FROM media_folders f LEFT JOIN library_collection_order_revisions v ON v.library_id=f.id WHERE f.id=$1";

pub async fn reorder(
    pool: &Pool,
    library_id: i32,
    ids: &[String],
    expected: i64,
) -> Result<(), MutationError> {
    if ids.is_empty() {
        return Err(MutationError::OrderedMismatch);
    }
    let mut seen = std::collections::HashSet::new();
    if ids.iter().any(|id| !seen.insert(id)) {
        return Err(MutationError::Duplicates);
    }
    for attempt in 0..3 {
        let result = reorder_attempt(pool, library_id, ids, expected).await;
        let Err(MutationError::Db(ref error)) = result else {
            return result;
        };
        if !error.code().is_some_and(|code| code.code() == "40001") {
            return result;
        }
        if expected != -1 {
            let rows = pool.query(REVISION, &[&library_id]).await?;
            let row = rows.first().ok_or(MutationError::NotFound)?;
            if row.get::<_, i64>(0) != expected {
                return Err(MutationError::Stale);
            }
        }
        if attempt == 2 {
            return result;
        }
    }
    unreachable!()
}

async fn reorder_attempt(
    pool: &Pool,
    library_id: i32,
    ids: &[String],
    expected: i64,
) -> Result<(), MutationError> {
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .await?;
    let rows = tx.query(REVISION, &[&library_id]).await?;
    let row = rows.first().ok_or(MutationError::NotFound)?;
    if expected != -1 && row.get::<_, i64>(0) != expected {
        return Err(MutationError::Stale);
    }
    let mut real_ids = Vec::new();
    let mut positions = Vec::new();
    let mut ungrouped = None;
    for (idx, id) in ids.iter().enumerate() {
        if id == "ungrouped" {
            ungrouped = Some(idx as i32);
        } else {
            real_ids.push(id.clone());
            positions.push(idx as i32);
        }
    }
    let total: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM library_collection_groups WHERE library_id = $1",
            &[&library_id],
        )
        .await?
        .get(0);
    if total != real_ids.len() as i64 {
        return Err(MutationError::OrderedMismatch);
    }
    if !real_ids.is_empty() {
        let found: i64 = tx
            .query_one(
                "
			WITH supplied AS (
			  SELECT *
			  FROM unnest($1::text[], $2::integer[]) AS u(id, pos)
			),
			upd AS (
			  UPDATE library_collection_groups g
			  SET sort_order = supplied.pos, updated_at = NOW()
			  FROM supplied
			  WHERE g.library_id = $3 AND g.id = supplied.id
			  RETURNING 1
			)
			SELECT COUNT(*) FROM upd
		",
                &[&real_ids, &positions, &library_id],
            )
            .await?
            .get(0);
        if found != real_ids.len() as i64 {
            return Err(MutationError::OrderedMismatch);
        }
    }
    if let Some(position) = ungrouped {
        tx.execute(
            "
			UPDATE media_folders
			SET collection_ungrouped_sort_order = $1
			WHERE id = $2
		",
            &[&position, &library_id],
        )
        .await?;
    }
    tx.execute("INSERT INTO library_collection_order_revisions(library_id,revision) VALUES($1,2) ON CONFLICT(library_id) DO UPDATE SET revision=library_collection_order_revisions.revision+1", &[&library_id]).await?;
    tx.commit().await?;
    Ok(())
}
