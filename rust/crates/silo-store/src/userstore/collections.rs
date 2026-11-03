//! The personal collection half of `internal/userstore/pgstore` that needs no catalog query: membership,
//! the two orders, revisions, and sort preferences. The SQL is Go's.

use silo_gocompat::time::{GoTime, RFC3339};
use silo_pg::{AnyInt, Error as PgError, Pool, ToSql};

/// `collectionutil.ErrOrderedIDsMismatch`.
pub const ORDERED_MISMATCH: &str = "ordered_ids does not match the current set";
const DUPLICATES: &str = "ordered_ids contains duplicates";

/// What a guarded or plain order write can come to.
#[derive(Debug)]
pub enum MutationError {
    /// `userstore.ErrCollectionRevisionMismatch`.
    RevisionMismatch,
    /// `fmt.Errorf("ordered_ids contains duplicates")`.
    Duplicates,
    /// `collectionutil.ErrOrderedIDsMismatch`.
    OrderedMismatch,
    Db(PgError),
}

impl From<PgError> for MutationError {
    fn from(e: PgError) -> Self {
        MutationError::Db(e)
    }
}

impl MutationError {
    /// `err.Error()`.
    pub fn message(&self) -> String {
        match self {
            MutationError::RevisionMismatch => "collection revision mismatch".to_owned(),
            MutationError::Duplicates => DUPLICATES.to_owned(),
            MutationError::OrderedMismatch => ORDERED_MISMATCH.to_owned(),
            MutationError::Db(e) => e.to_string(),
        }
    }

    fn serialization_failure(&self) -> bool {
        matches!(self, MutationError::Db(e) if e.code().is_some_and(|c| c.code() == "40001"))
    }
}

/// The stored collection's fields the membership rows read.
#[derive(Clone, Debug)]
pub struct CollectionHead {
    pub creator_profile_id: String,
    pub collection_type: String,
    pub is_shared: bool,
}

impl CollectionHead {
    /// `Collection.VisibleTo`.
    pub fn visible_to(&self, profile_id: &str) -> bool {
        !profile_id.is_empty() && (self.creator_profile_id == profile_id || self.is_shared)
    }
}

/// One stored member.
#[derive(Clone, Debug)]
pub struct Member {
    pub collection_id: String,
    pub media_item_id: String,
    pub position: i32,
    pub added_at: String,
}

fn now_utc() -> String {
    GoTime::now_utc().format(RFC3339)
}

const STAMP: &str = "to_char(added_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

/// `GetCollection`: `None` is `ErrCollectionNotFound`.
pub async fn get_head(
    pool: &Pool,
    user: AnyInt,
    id: &str,
) -> Result<Option<CollectionHead>, PgError> {
    let rows = pool
        .query(
            "SELECT creator_profile_id, collection_type, is_shared
             FROM user_personal_collections WHERE user_id = $1 AND id = $2 AND native",
            &[&user, &id],
        )
        .await?;
    Ok(rows.first().map(|r| CollectionHead {
        creator_profile_id: r.get(0),
        collection_type: r.get(1),
        is_shared: r.get(2),
    }))
}

/// `ListCollections`' IDs for a profile's own collections, in its order.
pub async fn own_order(pool: &Pool, user: AnyInt, profile: &str) -> Result<Vec<String>, PgError> {
    let rows = pool
        .query(
            "SELECT id, creator_profile_id
             FROM user_personal_collections
             WHERE user_id = $1
               AND native
               AND (creator_profile_id = $2 OR is_shared)
             ORDER BY (creator_profile_id = $2) DESC, creator_profile_id ASC, sort_order ASC, created_at ASC, id ASC",
            &[&user, &profile],
        )
        .await?;
    Ok(rows
        .iter()
        .filter(|r| r.get::<_, String>(1) == profile)
        .map(|r| r.get(0))
        .collect())
}

/// `ListCollectionItems`.
pub async fn list_items(pool: &Pool, user: AnyInt, id: &str) -> Result<Vec<Member>, PgError> {
    let sql = format!(
        "SELECT collection_id, media_item_id, position, {STAMP}
         FROM user_personal_collection_items
         WHERE user_id = $1 AND collection_id = $2 AND sub_item_id = '' ORDER BY position ASC, media_item_id ASC"
    );
    let rows = pool.query(&sql, &[&user, &id]).await?;
    Ok(rows.iter().map(member).collect())
}

fn member(r: &silo_pg::Row) -> Member {
    Member {
        collection_id: r.get(0),
        media_item_id: r.get(1),
        position: r.get(2),
        added_at: r.get(3),
    }
}

/// `CollectionOrderRevision`.
pub async fn order_revision(pool: &Pool, user: AnyInt) -> Result<i64, PgError> {
    let rows = pool
        .query(
            "SELECT COALESCE((SELECT revision FROM user_collection_order_revisions WHERE user_id=$1),1)",
            &[&user],
        )
        .await?;
    Ok(rows[0].get(0))
}

/// `CollectionRevision`: `None` is `ErrCollectionNotFound`.
pub async fn revision(pool: &Pool, user: AnyInt, id: &str) -> Result<Option<i64>, PgError> {
    let rows = pool
        .query(
            "SELECT v.revision FROM user_personal_collections p JOIN user_collection_revisions v ON v.collection_id = p.id AND v.user_id = p.user_id WHERE p.user_id = $1 AND p.id = $2",
            &[&user, &id],
        )
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

/// A page of members with the revision it was read at, as `ListCollectionItemsPage` reads the first page.
pub struct FirstPage {
    pub revision: i64,
    pub items: Vec<Member>,
    pub has_more: bool,
}

/// `ListCollectionItemsPage` without a cursor. `None` is `ErrCollectionNotFound`.
pub async fn first_page(
    pool: &Pool,
    user: AnyInt,
    id: &str,
    limit: i64,
) -> Result<Option<FirstPage>, PgError> {
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await?;
    let rows = tx
        .query(
            "SELECT v.revision FROM user_personal_collections p JOIN user_collection_revisions v ON v.collection_id = p.id AND v.user_id = p.user_id WHERE p.user_id = $1 AND p.id = $2",
            &[&user, &id],
        )
        .await?;
    let Some(revision) = rows.first().map(|r| r.get::<_, i64>(0)) else {
        return Ok(None);
    };
    let sql = format!(
        "SELECT collection_id, media_item_id, COALESCE(position, 0), {STAMP} FROM user_personal_collection_items WHERE user_id = $1 AND collection_id = $2 AND sub_item_id = '' ORDER BY COALESCE(position, 0), media_item_id LIMIT $3"
    );
    let want = limit + 1;
    let rows = tx.query(&sql, &[&user, &id, &want]).await?;
    tx.commit().await?;
    let mut items: Vec<Member> = rows.iter().map(member).collect();
    let has_more = items.len() as i64 > limit;
    items.truncate(limit as usize);
    Ok(Some(FirstPage {
        revision,
        items,
        has_more,
    }))
}

/// `runCollectionMutation`'s decision after a failed attempt: `Some` ends the retries. `id` empty means the
/// order revision.
async fn after_failure(
    pool: &Pool,
    user: AnyInt,
    id: &str,
    expected: i64,
    attempt: usize,
    e: MutationError,
) -> Result<Option<MutationError>, PgError> {
    if !e.serialization_failure() {
        return Ok(Some(e));
    }
    if expected != -1 {
        let current = if id.is_empty() {
            Some(order_revision(pool, user).await?)
        } else {
            revision(pool, user, id).await?
        };
        if current != Some(expected) {
            return Ok(Some(MutationError::RevisionMismatch));
        }
    }
    Ok((attempt == 2).then_some(e))
}

fn has_duplicates(ids: &[String]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(ids.len());
    ids.iter().any(|id| !seen.insert(id))
}

async fn reorder_collections_attempt(
    pool: &Pool,
    user: AnyInt,
    profile: &str,
    ids: &[String],
    expected: Option<i64>,
) -> Result<(), MutationError> {
    let mut session = pool.acquire().await?;
    let mut tx = session.begin().await?;
    if let Some(expected) = expected {
        tx.batch_execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .await?;
        let row = tx
            .query_one(
                "SELECT COALESCE((SELECT revision FROM user_collection_order_revisions WHERE user_id=$1),1)",
                &[&user],
            )
            .await?;
        if expected != -1 && row.get::<_, i64>(0) != expected {
            return Err(MutationError::RevisionMismatch);
        }
    }
    tx.execute(
        "SELECT 1 FROM user_personal_collections WHERE user_id = $1 AND creator_profile_id = $2 AND native ORDER BY id FOR UPDATE",
        &[&user, &profile],
    )
    .await?;
    let owned = ids.to_vec();
    let args: [&(dyn ToSql + Sync); 4] = [&owned, &user, &now_utc(), &profile];
    let row = tx
        .query_one(
            "
		WITH supplied AS (
		  SELECT id, pos FROM unnest($1::text[]) WITH ORDINALITY AS u(id, pos)
		),
		upd AS (
		  UPDATE user_personal_collections t
		  SET sort_order = supplied.pos - 1, updated_at = $3::text::timestamptz
		  FROM supplied
		  WHERE t.user_id = $2
		    AND t.id = supplied.id
		    AND t.creator_profile_id = $4
		    AND t.native
		  RETURNING 1
		)
		SELECT (SELECT count(*) FROM upd),
		       (SELECT count(*) FROM user_personal_collections
		         WHERE user_id = $2 AND creator_profile_id = $4 AND native)
	",
            &args,
        )
        .await?;
    let (updated, total): (i64, i64) = (row.get(0), row.get(1));
    if updated as usize != ids.len() || updated != total {
        return Err(MutationError::OrderedMismatch);
    }
    if expected.is_some() {
        tx.execute(
            "INSERT INTO user_collection_order_revisions(user_id,revision) VALUES($1,2) ON CONFLICT(user_id) DO UPDATE SET revision=user_collection_order_revisions.revision+1",
            &[&user],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// `ReorderCollections` and `ReorderCollectionsIfRevision`.
pub async fn reorder_collections(
    pool: &Pool,
    user: AnyInt,
    profile: &str,
    ids: &[String],
    expected: Option<i64>,
) -> Result<(), MutationError> {
    if has_duplicates(ids) {
        return Err(MutationError::Duplicates);
    }
    match expected {
        None => reorder_collections_attempt(pool, user, profile, ids, None).await,
        Some(expected) => {
            for attempt in 0..3 {
                let Err(e) =
                    reorder_collections_attempt(pool, user, profile, ids, Some(expected)).await
                else {
                    return Ok(());
                };
                if let Some(last) = after_failure(pool, user, "", expected, attempt, e).await? {
                    return Err(last);
                }
            }
            unreachable!("the third attempt returns")
        }
    }
}

/// `SetCollectionSortPreference`.
pub async fn set_sort_preference(
    pool: &Pool,
    user: AnyInt,
    profile: &str,
    kind: &str,
    id: &str,
    field: &str,
    order: &str,
) -> Result<(), PgError> {
    pool.execute(
        "
		INSERT INTO user_collection_sort_preferences (
			user_id, profile_id, collection_kind, collection_id, sort_field, sort_order, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7::text::timestamptz)
		ON CONFLICT(user_id, profile_id, collection_kind, collection_id) DO UPDATE SET
			sort_field = excluded.sort_field,
			sort_order = excluded.sort_order,
			updated_at = excluded.updated_at",
        &[&user, &profile, &kind, &id, &field, &order, &now_utc()],
    )
    .await?;
    Ok(())
}

/// `ClearCollectionSortPreference`.
pub async fn clear_sort_preference(
    pool: &Pool,
    user: AnyInt,
    profile: &str,
    kind: &str,
    id: &str,
) -> Result<(), PgError> {
    pool.execute(
        "
		DELETE FROM user_collection_sort_preferences
		WHERE user_id = $1 AND profile_id = $2 AND collection_kind = $3 AND collection_id = $4",
        &[&user, &profile, &kind, &id],
    )
    .await?;
    Ok(())
}

/// `LibraryCollectionRepository.GetByID`, the visibility and library scope `CanAccessLibraryCollection`
/// reads. `None` when the collection does not exist.
pub async fn library_collection_scope(
    pool: &Pool,
    id: &str,
) -> Result<Option<(String, Vec<i32>)>, PgError> {
    let rows = pool
        .query(
            "SELECT lc.visibility, COALESCE(ARRAY_AGG(DISTINCT lcl.library_id) FILTER (WHERE lcl.library_id IS NOT NULL), ARRAY[]::integer[])
             FROM library_collections lc
             LEFT JOIN library_collection_libraries lcl ON lcl.collection_id = lc.id
             WHERE lc.id = $1
             GROUP BY lc.id",
            &[&id],
        )
        .await?;
    Ok(rows.first().map(|r| (r.get(0), r.get(1))))
}

/// `models.LibraryCollectionGroup`, what the admin reads show.
#[derive(Clone, Debug)]
pub struct AdminGroup {
    pub id: String,
    pub library_id: i32,
    pub name: String,
    pub slug: String,
    pub kind: String,
    pub default_sort_mode: String,
    pub sort_order: i32,
}

const GROUP_COLUMNS: &str = "id, library_id, name, slug, kind, default_sort_mode, sort_order";

fn admin_group(r: &silo_pg::Row) -> AdminGroup {
    AdminGroup {
        id: r.get(0),
        library_id: r.get(1),
        name: r.get(2),
        slug: r.get(3),
        kind: r.get(4),
        default_sort_mode: r.get(5),
        sort_order: r.get(6),
    }
}

/// `LibraryCollectionGroupRepository.ListByLibrary`.
pub async fn admin_groups(pool: &Pool, library: AnyInt) -> Result<Vec<AdminGroup>, PgError> {
    let sql = format!(
        "SELECT {GROUP_COLUMNS}
		FROM library_collection_groups
		WHERE library_id = $1
		ORDER BY sort_order ASC, name ASC, id ASC"
    );
    Ok(pool
        .query(&sql, &[&library])
        .await?
        .iter()
        .map(admin_group)
        .collect())
}

/// `LibraryCollectionGroupRepository.GetByID`.
pub async fn admin_group_by_id(pool: &Pool, id: &str) -> Result<Option<AdminGroup>, PgError> {
    let sql = format!("SELECT {GROUP_COLUMNS} FROM library_collection_groups WHERE id = $1");
    Ok(pool.query(&sql, &[&id]).await?.first().map(admin_group))
}

/// `GetUngroupedSortOrder`: `None` is a missing library.
pub async fn ungrouped_sort_order(pool: &Pool, library: AnyInt) -> Result<Option<i32>, PgError> {
    let rows = pool
        .query(
            "SELECT collection_ungrouped_sort_order
		FROM media_folders
		WHERE id = $1",
            &[&library],
        )
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

/// `CollectionOrderRevision`: `None` is `ErrLibraryCollectionNotFound`.
pub async fn library_order_revision(pool: &Pool, library: AnyInt) -> Result<Option<i64>, PgError> {
    let rows = pool
        .query(
            "SELECT COALESCE(v.revision,1) FROM media_folders f LEFT JOIN library_collection_order_revisions v ON v.library_id=f.id WHERE f.id=$1",
            &[&library],
        )
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}
