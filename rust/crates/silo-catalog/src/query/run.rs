//! The `QueryExecutor` reads that run a plan: `PreviewPage`, `Count`, `PreviewCursorPage`, and
//! `SeekCursor` with its seek anchors (`seek_anchors.go`), plus `query_cache.go`.
//!
//! An "episode" definition scoped to one library is answered from the `episode_catalog_entries`
//! read model, as Go does (`episode_catalog_entries_executor.go`); a database without it falls back
//! to the general plan.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use silo_pg::{Pool, Row, Session, ToSql};

use super::access::AccessFilter;
use super::cursor::{CursorTerm, QueryCursor, QueryCursorValue};
use super::definition::QueryDefinition;
use super::episode_entries::{
    EPISODE_CATALOG_SEEK_SORTS, EpisodeCatalogQuery, episode_catalog_count_sql, hydrate_sql,
};
use super::executor::{PreviewPagePlan, QueryExecutor, normalize_preview_page_bounds};
use super::{Arg, sprintf};
use crate::model::MediaItem;

/// `seekAnchorStride`.
pub const SEEK_ANCHOR_STRIDE: i64 = 256;
const SEEK_ANCHOR_CACHE_TTL: Duration = Duration::from_secs(300);
const SEEK_ANCHOR_CACHE_BUDGET: usize = 100_000;

/// `QueryCursorPage`.
#[derive(Clone, Debug, Default)]
pub struct QueryCursorPage {
    pub items: Vec<MediaItem>,
    pub total: i64,
    pub total_exact: bool,
    pub has_more: bool,
    pub next: Option<QueryCursor>,
}

fn params(args: &[Arg]) -> Vec<&(dyn ToSql + Sync)> {
    args.iter().map(|a| a as &(dyn ToSql + Sync)).collect()
}

async fn query(pool: &Pool, sql: &str, args: &[Arg]) -> Result<Vec<Row>, String> {
    pool.query(sql, &params(args))
        .await
        .map_err(|e| e.to_string())
}

async fn session_query(s: &mut Session, sql: &str, args: &[Arg]) -> Result<Vec<Row>, String> {
    s.query(sql, &params(args)).await.map_err(|e| e.to_string())
}

/// `scanItemsWithMangaCounts`, with the preview path's `AddedAt` fallback to `CreatedAt`.
fn scan_items(rows: &[Row]) -> Result<Vec<MediaItem>, String> {
    rows.iter()
        .map(|row| {
            MediaItem::scan(row, true).map(|mut item| {
                item.added_at.get_or_insert(item.created_at);
                item
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("scanning media item row with manga counts: {e}"))
}

/// The sort tuple text columns after the item columns (`cursorRows`).
fn cursor_key(row: &Row, terms: &[CursorTerm], first: usize) -> Result<QueryCursor, String> {
    let mut keys = Vec::with_capacity(terms.len());
    for (i, term) in terms.iter().enumerate() {
        let value: Option<String> = row.try_get(first + i).map_err(|e| e.to_string())?;
        keys.push(QueryCursorValue {
            kind: term.kind.clone(),
            value,
        });
    }
    Ok(QueryCursor {
        keys,
        ..QueryCursor::default()
    })
}

impl PreviewPagePlan {
    /// `seekAnchorSQL`.
    pub fn seek_anchor_sql(&self) -> (String, Vec<Arg>) {
        let mut args = self.cte_args.clone();
        args.extend(self.args.iter().cloned());
        args.extend(self.sort_args.iter().cloned());
        let inner: Vec<String> = self
            .cursor_terms
            .iter()
            .enumerate()
            .map(|(i, t)| format!("({})::text AS seek_key_{i}", t.expression))
            .collect();
        let outer: Vec<String> = (0..self.cursor_terms.len())
            .map(|i| format!("seek_key_{i}"))
            .collect();
        let sql = sprintf(
            "%sSELECT %s FROM (SELECT %s, ROW_NUMBER() OVER (%s) - 1 AS seek_position %s %s) ranked WHERE seek_position %% %d = 0 ORDER BY seek_position",
            &[
                &self.with_clause(),
                &outer.join(", "),
                &inner.join(", "),
                &self.order_by,
                &self.from_clause_paged,
                &self.where_clause,
                &SEEK_ANCHOR_STRIDE,
            ],
        );
        (sql, args)
    }
}

/// `queryCache` for seek anchors: entries keyed by the hashed SQL and arguments, dropped after the
/// TTL, and evicted least recently used past the budget. Go also runs one load per key for
/// concurrent misses and bounds concurrent loads; here concurrent misses each load.
#[derive(Debug, Default)]
pub struct SeekAnchorCache {
    inner: Mutex<CacheState>,
}

#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<Vec<u8>, (Vec<QueryCursor>, Instant, u64)>,
    used: usize,
    tick: u64,
}

impl SeekAnchorCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup(&self, key: &[u8]) -> Option<Vec<QueryCursor>> {
        let mut st = self.inner.lock().ok()?;
        st.tick += 1;
        let tick = st.tick;
        let entry = st.entries.get_mut(key)?;
        entry.2 = tick;
        let (value, expires) = (entry.0.clone(), entry.1);
        if Instant::now() >= expires {
            st.entries.remove(key);
            st.used -= value.len().max(1);
            return None;
        }
        Some(value)
    }

    fn store(&self, key: Vec<u8>, value: Vec<QueryCursor>) {
        let weight = value.len().max(1);
        if weight > SEEK_ANCHOR_CACHE_BUDGET {
            return;
        }
        let Ok(mut st) = self.inner.lock() else {
            return;
        };
        st.tick += 1;
        let tick = st.tick;
        if let Some(old) = st.entries.remove(&key) {
            st.used -= old.0.len().max(1);
        }
        st.entries
            .insert(key, (value, Instant::now() + SEEK_ANCHOR_CACHE_TTL, tick));
        st.used += weight;
        while st.used > SEEK_ANCHOR_CACHE_BUDGET {
            let Some(oldest) = st
                .entries
                .iter()
                .min_by_key(|(_, e)| e.2)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(e) = st.entries.remove(&oldest) {
                st.used -= e.0.len().max(1);
            }
        }
    }
}

/// `queryCacheKey`: SHA-256 over the query, a zero byte, and the arguments as JSON.
fn query_cache_key(sql: &str, args: &[Arg]) -> Vec<u8> {
    let encoded = silo_gocompat::json::marshal(&args.iter().map(Arg::json).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut material = sql.as_bytes().to_vec();
    material.push(0);
    material.extend(encoded);
    use sha2::Digest;
    sha2::Sha256::digest(&material).to_vec()
}

/// `episodeCatalogEntriesUnavailable`: the read model's table or function is missing.
fn entries_unavailable(e: &silo_pg::Error) -> bool {
    e.code()
        .is_some_and(|c| c.code() == "42P01" || c.code() == "42883")
}

/// `pgx.ErrNoRows`'s text.
pub const ERR_NO_ROWS: &str = "no rows in result set";

impl QueryExecutor {
    /// `PreviewPage`: a page of items, the total when asked, and whether more follow.
    pub async fn preview_page(
        &self,
        pool: &Pool,
        def: &QueryDefinition,
        access: &AccessFilter,
        limit: i64,
        offset: i64,
        include_total: bool,
    ) -> Result<(Vec<MediaItem>, i64, bool), String> {
        if self.uses_episode_catalog_queries() {
            if let Some(q) = self.episode_catalog_user_state_query(def, access, include_total)?
                && let Some(page) = self
                    .episode_catalog_preview_page(pool, &q, def, limit, offset, include_total)
                    .await?
            {
                return Ok(page);
            }
            if let Some(q) = self.episode_catalog_entries_query(def, access)?
                && let Some(page) = self
                    .episode_catalog_preview_page(pool, &q, def, limit, offset, include_total)
                    .await?
            {
                return Ok(page);
            }
        }
        let plan = self.build_preview_page_plan(def, access, limit, offset)?;
        let (sql, args) = plan.paged_sql(false);
        let rows = query(pool, &sql, &args)
            .await
            .map_err(|e| format!("querying preview items: {e}"))?;
        let mut items = scan_items(&rows)?;
        let mut has_more = false;
        if items.len() as i64 > plan.limit {
            has_more = true;
            items.truncate(plan.limit.max(0) as usize);
        }
        if !include_total {
            return Ok((items, 0, has_more));
        }
        let total = if !has_more && plan.limit > 0 && (!items.is_empty() || plan.offset == 0) {
            plan.offset + items.len() as i64
        } else {
            let (sql, args) = plan.count_sql();
            let rows = query(pool, &sql, &args)
                .await
                .map_err(|e| format!("counting preview items: {e}"))?;
            rows[0].get::<_, silo_pg::AnyInt>(0).0
        };
        let has_more = total > plan.offset + items.len() as i64;
        Ok((items, total, has_more))
    }

    /// `Count`.
    pub async fn count(
        &self,
        pool: &Pool,
        def: &QueryDefinition,
        access: &AccessFilter,
    ) -> Result<i64, String> {
        let (sql, args) = self.build_count_query(def, access)?;
        let rows = query(pool, &sql, &args)
            .await
            .map_err(|e| format!("counting query matches: {e}"))?;
        Ok(rows[0].get::<_, silo_pg::AnyInt>(0).0)
    }

    /// `episodeCatalogPreviewPage`. `Ok(None)` sends the read to the general query.
    async fn episode_catalog_preview_page(
        &self,
        pool: &Pool,
        q: &EpisodeCatalogQuery,
        def: &QueryDefinition,
        limit: i64,
        offset: i64,
        include_total: bool,
    ) -> Result<Option<(Vec<MediaItem>, i64, bool)>, String> {
        if q.empty {
            return Ok(Some((Vec::new(), 0, false)));
        }
        let (limit, offset, max) = normalize_preview_page_bounds(&def.normalize(), limit, offset);
        let (sql, args, page_limit) = q.page_sql(def, limit, offset);
        let rows = match pool.query(&sql, &params(&args)).await {
            Ok(rows) => rows,
            Err(e) if entries_unavailable(&e) => return Ok(None),
            Err(e) => return Err(format!("querying episode catalog entry page: {e}")),
        };
        let mut page: Vec<(String, SystemTime)> = Vec::with_capacity(rows.len());
        for row in &rows {
            page.push((
                row.try_get(0)
                    .map_err(|e| format!("scanning episode catalog entry page: {e}"))?,
                row.try_get(1)
                    .map_err(|e| format!("scanning episode catalog entry page: {e}"))?,
            ));
        }
        if q.requires_full_page_gate && (page.len() as i64) < page_limit {
            return Ok(None);
        }
        let mut has_more = page.len() as i64 > limit;
        if has_more {
            page.truncate(limit.max(0) as usize);
        }
        let items = match self.hydrate_episode_catalog_entry_page(pool, &page).await {
            Ok(items) => items,
            Err(None) => return Ok(None),
            Err(Some(e)) => return Err(e),
        };
        let mut total = 0;
        if include_total {
            let (sql, args) =
                episode_catalog_count_sql(&q.with_ctes, &q.from, &q.where_, &q.args, max);
            match pool.query(&sql, &params(&args)).await {
                Ok(rows) => total = rows[0].get::<_, silo_pg::AnyInt>(0).0,
                Err(e) if entries_unavailable(&e) => return Ok(None),
                Err(e) => return Err(format!("counting episode catalog entries: {e}")),
            }
            has_more = total > offset + items.len() as i64;
        }
        Ok(Some((items, total, has_more)))
    }

    /// `hydrateEpisodeCatalogEntryPage`: the page's episodes in page order, dated by the entry.
    async fn hydrate_episode_catalog_entry_page(
        &self,
        pool: &Pool,
        page: &[(String, SystemTime)],
    ) -> Result<Vec<MediaItem>, Option<String>> {
        if page.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<String> = page.iter().map(|(id, _)| id.clone()).collect();
        let rows = match pool.query(&hydrate_sql(), &[&ids]).await {
            Ok(rows) => rows,
            Err(e) if entries_unavailable(&e) => return Err(None),
            Err(e) => return Err(Some(format!("hydrating episode catalog entry page: {e}"))),
        };
        let mut by_id = HashMap::with_capacity(rows.len());
        for row in &rows {
            let mut item = MediaItem::scan(row, false)
                .map_err(|e| Some(format!("scanning media item row: {e}")))?;
            let added = page
                .iter()
                .find(|(id, _)| *id == item.content_id)
                .map(|(_, at)| *at);
            item.added_at = Some(added.unwrap_or(item.created_at));
            by_id.insert(item.content_id.clone(), item);
        }
        Ok(page.iter().filter_map(|(id, _)| by_id.remove(id)).collect())
    }

    /// `episodeCatalogSeek`. `None` sends the seek to the general query.
    async fn episode_catalog_seek(
        &self,
        pool: &Pool,
        def: &QueryDefinition,
        access: &AccessFilter,
        plan: &PreviewPagePlan,
        offset: i64,
    ) -> Option<Result<QueryCursor, String>> {
        let field = super::definition::normalize_query_sort(&def.sort).field;
        if !EPISODE_CATALOG_SEEK_SORTS.contains(&field.as_str()) {
            return None;
        }
        let q = match self.episode_catalog_total_query(def, access) {
            Err(e) => return Some(Err(e)),
            Ok(None) => return None,
            Ok(Some(q)) => q,
        };
        if q.empty {
            return Some(Err(ERR_NO_ROWS.into()));
        }
        let (sql, args) = q.seek_sql(offset);
        let episode_id: String = match pool.query(&sql, &params(&args)).await {
            Ok(rows) => match rows.first() {
                Some(row) => row.get(0),
                None => return Some(Err(ERR_NO_ROWS.into())),
            },
            Err(e) if entries_unavailable(&e) => return None,
            Err(e) => return Some(Err(e.to_string())),
        };
        let (sql, args) = match plan.tuple_for_sql(&episode_id) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        match query(pool, &sql, &args).await {
            // The projection listed an episode the general relation does not: seek there.
            Ok(rows) if rows.is_empty() => None,
            Ok(rows) => Some(cursor_key(&rows[0], &plan.cursor_terms, 0)),
            Err(e) => Some(Err(e)),
        }
    }

    /// `PreviewCursorPage`: the page after `after`, its rows and optional count in one
    /// repeatable-read snapshot.
    pub async fn preview_cursor_page(
        &self,
        pool: &Pool,
        def: &QueryDefinition,
        access: &AccessFilter,
        mut limit: i64,
        after: Option<&QueryCursor>,
        include_total: bool,
    ) -> Result<QueryCursorPage, String> {
        if !(1..=200).contains(&limit) {
            return Err("cursor limit must be between 1 and 200".into());
        }
        let consumed = after.map(|a| a.consumed).unwrap_or(0);
        if consumed < 0 {
            return Err("invalid cursor consumed count".into());
        }
        if let Some(l) = def.limit
            && !self.group_by_work
        {
            if l <= 0 {
                return Err("query limit must be positive".into());
            }
            if consumed >= l {
                return Ok(QueryCursorPage::default());
            }
            limit = limit.min(l - consumed);
        }
        let mut plan = self.build_preview_page_plan(def, access, limit, 0)?;
        if let Some(l) = def.limit
            && !self.group_by_work
        {
            plan.max_results = l - consumed;
        }
        let (sql, args) = plan.cursor_sql(after)?;
        let mut session = pool.acquire().await.map_err(|e| e.to_string())?;
        let mut tx = session.begin().await.map_err(|e| e.to_string())?;
        tx.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await
            .map_err(|e| e.to_string())?;
        let rows = session_query(&mut tx, &sql, &args)
            .await
            .map_err(|e| format!("querying cursor page: {e}"))?;
        let mut items = scan_items(&rows)?;
        let first_key = crate::model::ITEM_COLUMN_NAMES.len() + 2;
        let mut keys = Vec::with_capacity(rows.len());
        for row in &rows {
            keys.push(cursor_key(row, &plan.cursor_terms, first_key)?);
        }
        let mut page = QueryCursorPage {
            has_more: items.len() as i64 > plan.limit,
            ..QueryCursorPage::default()
        };
        if page.has_more {
            items.truncate(plan.limit as usize);
        }
        if page.has_more && !items.is_empty() {
            let mut next = keys[items.len() - 1].clone();
            next.consumed = consumed + items.len() as i64;
            page.next = Some(next);
        }
        page.items = items;
        if include_total {
            let (sql, args) = self.build_count_query(def, access)?;
            let rows = session_query(&mut tx, &sql, &args)
                .await
                .map_err(|e| format!("counting cursor page: {e}"))?;
            page.total = rows[0].get::<_, silo_pg::AnyInt>(0).0;
            page.total_exact = true;
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(page)
    }

    /// `SeekCursor`: the cursor just before zero-based position `index`. `Ok(None)` is position 0;
    /// `Err(ERR_NO_ROWS)` is a position past the end.
    pub async fn seek_cursor(
        &self,
        pool: &Pool,
        anchors: Option<&SeekAnchorCache>,
        def: &QueryDefinition,
        access: &AccessFilter,
        index: i64,
    ) -> Result<Option<QueryCursor>, String> {
        if !(0..=10_000_000).contains(&index) {
            return Err("jump index must be between 0 and 10000000".into());
        }
        if index == 0 {
            return Ok(None);
        }
        if let Some(l) = def.limit
            && l > 0
            && index >= l
        {
            return Err(ERR_NO_ROWS.into());
        }
        let plan = self.build_preview_page_plan(def, access, 1, 0)?;
        let target = index - 1;
        let mut found = self
            .episode_catalog_seek(pool, def, access, &plan, target)
            .await;
        if found.is_none() {
            found = self.anchored_seek(pool, anchors, &plan, target).await;
        }
        let key = match found {
            Some(result) => result,
            None => self.query_tuple(pool, &plan, None, target).await,
        }
        .map_err(|e| format!("seeking cursor: {e}"))?;
        let mut key = key;
        key.consumed = index;
        Ok(Some(key))
    }

    async fn query_tuple(
        &self,
        pool: &Pool,
        plan: &PreviewPagePlan,
        after: Option<&QueryCursor>,
        offset: i64,
    ) -> Result<QueryCursor, String> {
        let (sql, args) = plan.tuple_sql(after, offset)?;
        let rows = query(pool, &sql, &args).await?;
        let row = rows.first().ok_or_else(|| ERR_NO_ROWS.to_owned())?;
        cursor_key(row, &plan.cursor_terms, 0)
    }

    /// `anchoredSeek`. `None` means anchors don't apply and the caller seeks with OFFSET.
    async fn anchored_seek(
        &self,
        pool: &Pool,
        anchors: Option<&SeekAnchorCache>,
        plan: &PreviewPagePlan,
        target: i64,
    ) -> Option<Result<QueryCursor, String>> {
        let cache = anchors?;
        if target < SEEK_ANCHOR_STRIDE || plan.cursor_terms.first().is_none_or(|t| !t.not_null) {
            return None;
        }
        let (sql, args) = plan.seek_anchor_sql();
        let key = query_cache_key(&sql, &args);
        let list = match cache.lookup(&key) {
            Some(list) => list,
            None => {
                let rows = query(pool, &sql, &args).await.ok()?;
                let mut list = Vec::with_capacity(rows.len());
                for row in &rows {
                    list.push(cursor_key(row, &plan.cursor_terms, 0).ok()?);
                }
                cache.store(key, list.clone());
                list
            }
        };
        if list.is_empty() {
            return Some(Err(ERR_NO_ROWS.into()));
        }
        let slot = (target / SEEK_ANCHOR_STRIDE).min(list.len() as i64 - 1);
        let anchor = &list[slot as usize];
        let walk = target - slot * SEEK_ANCHOR_STRIDE;
        if walk > 0 {
            return Some(self.query_tuple(pool, plan, Some(anchor), walk - 1).await);
        }
        Some(Ok(QueryCursor {
            keys: anchor.keys.clone(),
            ..QueryCursor::default()
        }))
    }
}
