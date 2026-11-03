//! `notifications.InterestUpdater` and the store hooks that feed it: the (profile, series) rows release
//! notifications match against. Each process keeps its own queue, as each Go replica does, and flushes it
//! every 2 seconds. A mutation lost in a crash is left to Go's rebuild task, as it is in Go.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use silo_pg::{AnyInt, Pool};
use silo_store::access::ResolveInput;

use super::chain::Stack;

const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const SESSION_GAP: Duration = Duration::from_secs(600);
const RECOMPUTE_TIME: Duration = Duration::from_secs(30);
const MAX_FLUSH_ATTEMPTS: u32 = 5;
const QUERY_CHUNK: usize = 500;
const SEASON_MULTIPLIER: i64 = 1_000_000;
const MAX_SEASON: i64 = (i32::MAX as i64 - (SEASON_MULTIPLIER - 1)) / SEASON_MULTIPLIER;
const FIRST_REGULAR_KEY: i64 = SEASON_MULTIPLIER;

#[derive(Clone, PartialEq, Eq, Hash)]
struct Mutation {
    user: i64,
    profile: String,
    item: String,
}

#[derive(Default)]
struct Queue {
    pending: HashMap<Mutation, u32>,
    deferred: HashMap<Mutation, Instant>,
    home_changed: HashMap<(i64, String), SystemTime>,
}

static QUEUE: OnceLock<Mutex<Queue>> = OnceLock::new();

fn queue() -> std::sync::MutexGuard<'static, Queue> {
    QUEUE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Starts the flush loop. `Run`.
pub fn start(stack: Arc<Stack>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(FLUSH_INTERVAL);
        loop {
            tick.tick().await;
            flush(&stack).await;
        }
    });
}

/// `QueueItemMutation`.
pub fn queue_item(user: i64, profile: &str, item: &str) {
    if user <= 0 || profile.is_empty() || item.is_empty() {
        return;
    }
    queue()
        .pending
        .entry(Mutation {
            user,
            profile: profile.to_owned(),
            item: item.to_owned(),
        })
        .or_insert(0);
}

/// `queueHomeChange`.
pub fn queue_home_change(user: i64, profile: &str, item: &str) {
    if user <= 0 || profile.is_empty() || item.is_empty() {
        return;
    }
    let mutation = Mutation {
        user,
        profile: profile.to_owned(),
        item: item.to_owned(),
    };
    let mut q = queue();
    q.home_changed
        .insert((user, profile.to_owned()), SystemTime::now());
    q.pending.entry(mutation.clone()).or_insert(0);
    let due = Instant::now() + SESSION_GAP;
    let slot = q.deferred.entry(mutation).or_insert(due);
    if due > *slot {
        *slot = due;
    }
}

/// `progressState`.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct ProgressState {
    pub exists: bool,
    pub in_progress: bool,
    pub completed: bool,
}

/// `currentProgressState`, with the row's whole-second stamp apart.
pub async fn current_state(
    pool: &Pool,
    user: i64,
    profile: &str,
    item: &str,
) -> (ProgressState, Option<SystemTime>) {
    let rows = pool
        .query(
            "
		SELECT position_seconds, completed, updated_at
		FROM user_watch_progress
		WHERE user_id = $1 AND profile_id = $2 AND media_item_id = $3
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = user_watch_progress.user_id
			  AND hhi.profile_id = user_watch_progress.profile_id
			  AND hhi.media_item_id = user_watch_progress.media_item_id
			  AND user_watch_progress.updated_at <= hhi.hidden_before
		  )",
            &[&AnyInt(user), &profile, &item],
        )
        .await;
    let Some(row) = rows.ok().and_then(|mut r| r.pop()) else {
        return (ProgressState::default(), None);
    };
    let position: f64 = row.get(0);
    let completed: bool = row.get(1);
    (
        ProgressState {
            exists: true,
            in_progress: !completed && position > 0.0,
            completed,
        },
        Some(whole_second(row.get(2))),
    )
}

fn whole_second(t: SystemTime) -> SystemTime {
    let seconds = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

/// `queueOnTransition`.
pub fn queue_on_transition(
    user: i64,
    profile: &str,
    item: &str,
    before: ProgressState,
    before_at: Option<SystemTime>,
    after: ProgressState,
    written_at: SystemTime,
) {
    let resumed = before.exists
        && before_at.is_some_and(|at| {
            let late =
                |later: SystemTime| later.duration_since(at).is_ok_and(|gap| gap > SESSION_GAP);
            late(written_at)
                || late(SystemTime::now())
                || queue()
                    .home_changed
                    .get(&(user, profile.to_owned()))
                    .is_some_and(|changed| *changed > at)
        });
    if before != after || resumed {
        queue_item(user, profile, item);
    }
}

async fn flush(s: &Arc<Stack>) {
    let batch = {
        let mut q = queue();
        let now = SystemTime::now();
        q.home_changed.retain(|_, at| {
            now.duration_since(*at)
                .map_or(true, |gap| gap <= SESSION_GAP)
        });
        let instant = Instant::now();
        let due: Vec<Mutation> = q
            .deferred
            .iter()
            .filter(|(_, at)| **at <= instant)
            .map(|(m, _)| m.clone())
            .collect();
        for mutation in due {
            q.deferred.remove(&mutation);
            q.pending.entry(mutation).or_insert(0);
        }
        std::mem::take(&mut q.pending)
    };
    if batch.is_empty() {
        return;
    }
    let ids: Vec<String> = batch
        .keys()
        .map(|m| m.item.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let series = resolve_series(&s.pool, &ids).await;
    let mut requeue: Vec<(Mutation, u32)> = Vec::new();
    let mut seen = HashSet::new();
    for (mutation, failures) in batch {
        let Ok(series) = &series else {
            requeue.push((mutation, failures + 1));
            continue;
        };
        let Some(of) = series.get(&mutation.item) else {
            continue;
        };
        if !seen.insert((mutation.user, mutation.profile.clone(), of.clone())) {
            continue;
        }
        let result = tokio::time::timeout(
            RECOMPUTE_TIME,
            recompute_series(s, mutation.user, &mutation.profile, of),
        )
        .await
        .unwrap_or_else(|_| Err("timed out".to_owned()));
        if let Err(e) = result {
            tracing::warn!(component = "notifications", user_id = mutation.user, profile_id = mutation.profile, series_id = of, error = %e, "interest recompute failed");
            requeue.push((mutation, failures + 1));
        }
    }
    let mut q = queue();
    for (mutation, failures) in requeue {
        if failures >= MAX_FLUSH_ATTEMPTS {
            tracing::warn!(
                component = "notifications",
                item_id = mutation.item,
                profile_id = mutation.profile,
                "interest mutation dropped after repeated failures"
            );
        } else {
            q.pending.entry(mutation).or_insert(failures);
        }
    }
}

/// `resolveSeriesIDs`.
async fn resolve_series(pool: &Pool, ids: &[String]) -> Result<HashMap<String, String>, String> {
    let rows = pool
        .query(
            "
		SELECT content_id, series_id FROM episodes WHERE content_id = ANY($1::text[])
		UNION ALL
		SELECT content_id, series_id FROM seasons WHERE content_id = ANY($1::text[])
		UNION ALL
		SELECT content_id, content_id FROM media_items WHERE content_id = ANY($1::text[]) AND type = 'series'",
            &[&ids],
        )
        .await
        .map_err(|e| e.to_string())?;
    let mut result = HashMap::new();
    for row in rows {
        let series: Option<String> = row.try_get(1).map_err(|e| e.to_string())?;
        let series = series.unwrap_or_default();
        if !series.is_empty() {
            result.entry(row.get(0)).or_insert(series);
        }
    }
    Ok(result)
}

async fn any_member(
    pool: &Pool,
    table: &str,
    user: &AnyInt,
    profile: &str,
    targets: &[String],
) -> Result<bool, String> {
    let sql = format!(
        "SELECT media_item_id FROM {table}
		 WHERE user_id = $1 AND profile_id = $2 AND media_item_id = ANY($3::text[])"
    );
    for chunk in targets.chunks(QUERY_CHUNK) {
        let chunk = chunk.to_vec();
        let rows = pool
            .query(&sql, &[user, &profile, &chunk])
            .await
            .map_err(|e| e.to_string())?;
        if !rows.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `RecomputeSeries`.
pub async fn recompute_series(
    s: &Stack,
    user_id: i64,
    profile: &str,
    series: &str,
) -> Result<(), String> {
    let pool = &s.pool;
    let e = |x: silo_pg::Error| x.to_string();
    let user = AnyInt(user_id);
    let mut keys: HashMap<String, i64> = HashMap::new();
    for row in pool
        .query(
            "SELECT content_id, season_number, episode_number FROM episodes WHERE series_id = $1",
            &[&series],
        )
        .await
        .map_err(e)?
    {
        let (season, episode) = (
            i64::from(row.try_get::<_, i32>(1).map_err(|x| x.to_string())?),
            i64::from(row.try_get::<_, i32>(2).map_err(|x| x.to_string())?),
        );
        if (0..=MAX_SEASON).contains(&season) && (0..SEASON_MULTIPLIER).contains(&episode) {
            keys.insert(row.get(0), season * SEASON_MULTIPLIER + episode);
        }
    }
    let seasons: Vec<String> = pool
        .query(
            "SELECT content_id FROM seasons WHERE series_id = $1",
            &[&series],
        )
        .await
        .map_err(e)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let episode_ids: Vec<String> = keys.keys().cloned().collect();
    let mut targets = vec![series.to_owned()];
    targets.extend(seasons);
    targets.extend(episode_ids.iter().cloned());
    let favorite = any_member(pool, "user_favorites", &user, profile, &targets).await?;
    let watchlist = any_member(pool, "user_watchlist", &user, profile, &targets).await?;

    let mut in_progress: Vec<(String, SystemTime)> = Vec::new();
    let mut started: Vec<String> = Vec::new();
    let mut completed: Vec<(i64, SystemTime)> = Vec::new();
    let mut anchor: Option<(i64, SystemTime)> = None;
    let mut regular: Option<(i64, SystemTime)> = None;
    let mut has_progression = false;
    let mut last_completed: Option<i64> = None;
    for chunk in episode_ids.chunks(QUERY_CHUNK) {
        let chunk = chunk.to_vec();
        for row in pool
            .query(
                "
		SELECT media_item_id, position_seconds, completed, updated_at
		FROM user_watch_progress
		WHERE user_id = $1 AND profile_id = $2 AND media_item_id = ANY($3::text[])
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = user_watch_progress.user_id
			  AND hhi.profile_id = user_watch_progress.profile_id
			  AND hhi.media_item_id = user_watch_progress.media_item_id
			  AND user_watch_progress.updated_at <= hhi.hidden_before
		  )",
                &[&user, &profile, &chunk],
            )
            .await
            .map_err(e)?
        {
            let id: String = row.get(0);
            let position: f64 = row.get(1);
            let done: bool = row.get(2);
            let at = whole_second(row.get(3));
            has_progression = true;
            if done || position > 0.0 {
                started.push(id.clone());
            }
            if !done && position > 0.0 {
                in_progress.push((id.clone(), at));
            }
            if done && let Some(&key) = keys.get(&id) {
                last_completed = Some(last_completed.map_or(key, |k: i64| k.max(key)));
                completed.push((key, at));
                let later = |current: &Option<(i64, SystemTime)>| {
                    current.is_none_or(|(k, a)| at > a || (at == a && key > k))
                };
                if later(&anchor) {
                    anchor = Some((key, at));
                }
                if key >= FIRST_REGULAR_KEY && later(&regular) {
                    regular = Some((key, at));
                }
            }
        }
    }
    let has_regular = keys.values().any(|k| *k >= FIRST_REGULAR_KEY);
    let mut anchor_key = anchor.map(|(k, _)| k);
    if let Some(k) = anchor_key
        && k < FIRST_REGULAR_KEY
        && has_regular
    {
        anchor_key = Some(regular.map_or(FIRST_REGULAR_KEY - 1, |(k, _)| k));
    }
    for chunk in episode_ids.chunks(QUERY_CHUNK) {
        let chunk = chunk.to_vec();
        let mut offset = 0i64;
        loop {
            let rows = pool
                .query(
                    "
		SELECT h.media_item_id
		FROM user_watch_history h
		WHERE h.user_id = $1
		  AND h.profile_id = $2
		  AND h.completed = true
		  AND (cardinality($3::text[]) = 0 OR h.media_item_id = ANY($3::text[]))
		  AND NOT EXISTS (
			SELECT 1
			FROM user_history_hidden_items hhi
			WHERE hhi.user_id = h.user_id
			  AND hhi.profile_id = h.profile_id
			  AND hhi.media_item_id = h.media_item_id
			  AND h.watched_at <= hhi.hidden_before
		)
		ORDER BY h.watched_at ASC, h.id ASC
		LIMIT $4 OFFSET $5",
                    &[
                        &user,
                        &profile,
                        &chunk,
                        &AnyInt(QUERY_CHUNK as i64),
                        &AnyInt(offset),
                    ],
                )
                .await
                .map_err(e)?;
            for row in &rows {
                has_progression = true;
                let id: String = row.get(0);
                if let Some(&key) = keys.get(&id) {
                    last_completed = Some(last_completed.map_or(key, |k: i64| k.max(key)));
                }
            }
            if rows.len() < QUERY_CHUNK {
                break;
            }
            offset += rows.len() as i64;
        }
    }

    // supersededInProgress.
    in_progress.retain(|(id, at)| {
        let Some(&key) = keys.get(id) else {
            return true;
        };
        let special = key < FIRST_REGULAR_KEY;
        !completed
            .iter()
            .any(|(k, a)| *k > key && a > at && special == (*k < FIRST_REGULAR_KEY))
    });

    let (mut continue_watching, mut next_up) = (false, false);
    if has_progression {
        let dropped = active_drop(pool, &user, profile, series).await?;
        if !dropped {
            let mut held: HashMap<String, Option<SystemTime>> = HashMap::new();
            if !in_progress.is_empty() {
                let ids: Vec<String> = in_progress.iter().map(|(i, _)| i.clone()).collect();
                for row in dismissals(pool, &user, profile, "continue_watching", &ids).await? {
                    held.insert(row.get(0), row.get(1));
                }
            }
            continue_watching = in_progress.iter().any(|(id, at)| match held.get(id) {
                Some(Some(stamp)) => whole_second(*stamp) != *at,
                _ => true,
            });
            next_up = true;
            let mut dismissed: HashSet<String> = HashSet::new();
            if anchor.is_some() {
                for row in dismissals(pool, &user, profile, "next_up", &episode_ids).await? {
                    dismissed.insert(row.get(0));
                }
            }
            if !dismissed.is_empty() {
                let from = anchor_key.unwrap_or(0) + 1;
                let rows = pool
                    .query(
                        "
		SELECT e.content_id FROM episodes e
		WHERE e.series_id = $3
		  AND e.season_number BETWEEN 0 AND 2147 AND e.episode_number BETWEEN 0 AND 999999
		  AND e.season_number * 1000000 + e.episode_number >= $4
		  AND EXISTS (
			SELECT 1 FROM media_files mf
			WHERE mf.episode_id = e.content_id AND mf.missing_since IS NULL)
		  AND NOT (e.content_id = ANY($5))
		  AND NOT EXISTS (
			SELECT 1 FROM user_watch_progress uwp
			WHERE uwp.user_id = $1 AND uwp.profile_id = $2
			  AND uwp.media_item_id = e.content_id
			  AND (uwp.completed = TRUE OR uwp.position_seconds > 0))
		ORDER BY e.season_number, e.episode_number, e.content_id
		LIMIT 1",
                        &[&user, &profile, &series, &AnyInt(from), &started],
                    )
                    .await
                    .map_err(e)?;
                let next: String = rows.first().map_or(String::new(), |r| r.get(0));
                next_up = !dismissed.contains(&next);
            }
        }
    }

    let delete_stale = |keep: Vec<i32>| async move {
        pool.execute(
            "
		DELETE FROM profile_series_interest
		WHERE user_id = $1 AND profile_id = $2 AND series_id = $3 AND NOT (library_id = ANY($4))",
            &[&AnyInt(user_id), &profile, &series, &keep],
        )
        .await
        .map(|_| ())
        .map_err(|x| x.to_string())
    };
    if !(favorite || watchlist || continue_watching || next_up) && last_completed.is_none() {
        return delete_stale(Vec::new()).await;
    }

    // visibleSeriesLibraries.
    let memberships: Vec<i32> = pool
        .query(
            "SELECT media_folder_id FROM media_item_libraries WHERE content_id = $1",
            &[&series],
        )
        .await
        .map_err(e)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut visible = Vec::new();
    if !memberships.is_empty() {
        let scope = s
            .viewer
            .resolve(
                &ResolveInput {
                    user_id: user_id as i32,
                    profile_id: profile.to_owned(),
                    skip_pin_verification: true,
                    ..Default::default()
                },
                "",
            )
            .await
            .map_err(|x| format!("resolve profile scope: {x:?}"))?;
        for library in memberships {
            let id = i64::from(library);
            if scope.libraries_restricted && !scope.allowed_library_ids.contains(&id) {
                continue;
            }
            if scope.disabled_library_ids.contains(&id) {
                continue;
            }
            visible.push(library);
        }
    }
    if visible.is_empty() {
        return delete_stale(Vec::new()).await;
    }
    let last = last_completed.map(|k| k as i32);
    let expected = last_completed.map(|k| (k + 1) as i32);
    for library in &visible {
        pool.execute(
            "
		INSERT INTO profile_series_interest
			(user_id, profile_id, library_id, series_id,
			 favorite, watchlist, continue_watching, next_up_candidate,
			 last_completed_episode_key, next_expected_episode_key, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())
		ON CONFLICT (user_id, profile_id, library_id, series_id) DO UPDATE SET
			favorite = EXCLUDED.favorite,
			watchlist = EXCLUDED.watchlist,
			continue_watching = EXCLUDED.continue_watching,
			next_up_candidate = EXCLUDED.next_up_candidate,
			last_completed_episode_key = EXCLUDED.last_completed_episode_key,
			next_expected_episode_key = EXCLUDED.next_expected_episode_key,
			updated_at = now()
		WHERE (profile_series_interest.favorite,
		       profile_series_interest.watchlist,
		       profile_series_interest.continue_watching,
		       profile_series_interest.next_up_candidate,
		       profile_series_interest.last_completed_episode_key,
		       profile_series_interest.next_expected_episode_key)
		IS DISTINCT FROM
		      (EXCLUDED.favorite, EXCLUDED.watchlist, EXCLUDED.continue_watching,
		       EXCLUDED.next_up_candidate, EXCLUDED.last_completed_episode_key,
		       EXCLUDED.next_expected_episode_key)",
            &[
                &user,
                &profile,
                library,
                &series,
                &favorite,
                &watchlist,
                &continue_watching,
                &next_up,
                &last,
                &expected,
            ],
        )
        .await
        .map_err(e)?;
    }
    delete_stale(visible).await
}

/// `ListDropped` for one series: whether its drop is active.
async fn active_drop(
    pool: &Pool,
    user: &AnyInt,
    profile: &str,
    series: &str,
) -> Result<bool, String> {
    let ids = vec![series.to_owned()];
    let rows = pool
        .query(
            "
		WITH d AS MATERIALIZED (
			SELECT series_id, dropped_at FROM user_dropped_series
			WHERE user_id = $1 AND profile_id = $2 AND series_id = ANY($3)
		), recent AS (
			SELECT media_item_id, updated_at FROM user_watch_progress
			WHERE user_id = $1 AND profile_id = $2 AND updated_at > (SELECT min(dropped_at) FROM d)
			UNION ALL
			SELECT media_item_id, updated_at FROM user_history_hidden_items
			WHERE user_id = $1 AND profile_id = $2 AND updated_at > (SELECT min(dropped_at) FROM d)
		), activity AS (
			SELECT e.series_id, max(r.updated_at) AS at
			FROM recent r JOIN episodes e ON e.content_id = r.media_item_id
			WHERE e.series_id = ANY(ARRAY(SELECT series_id FROM d))
			GROUP BY e.series_id
		)
		SELECT (a.at IS NULL OR a.at <= d.dropped_at) AS active
		FROM d LEFT JOIN activity a ON a.series_id = d.series_id",
            &[user, &profile, &ids],
        )
        .await
        .map_err(|x| x.to_string())?;
    Ok(rows.iter().any(|r| r.get::<_, bool>(0)))
}

async fn dismissals(
    pool: &Pool,
    user: &AnyInt,
    profile: &str,
    surface: &str,
    items: &[String],
) -> Result<Vec<silo_pg::Row>, String> {
    let items = items.to_vec();
    pool.query(
        "SELECT media_item_id, progress_updated_at
		 FROM user_home_item_dismissals
		 WHERE user_id = $1 AND profile_id = $2 AND surface = $3 AND media_item_id = ANY($4)
		 ORDER BY dismissed_at DESC",
        &[user, &profile, &surface, &items],
    )
    .await
    .map_err(|x| x.to_string())
}
