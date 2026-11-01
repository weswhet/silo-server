//! The six migrations Go registers in code, at their exact versions. They are Go rather than SQL
//! because their conversion rules live in code shared with other write paths.

use std::collections::BTreeMap;

use serde::Serialize;
use silo_gocompat::json::{self, RawMessage, marshal_to_string};
use silo_pg::goose::{GoFunc, GoFuture, Migration};
use silo_pg::{AnyInt, Error as PgError, Pool, Session, TextValue, ToSql};

use crate::displayprefs;
use crate::gojson::{self, Value};
use crate::lang::compatible_tag;
use crate::naming::sidecar_subtitle_tags;
use crate::settingscontract::load_contract;
use crate::settingsmigrate::{
    Input, LegacyDeviceSetting, LegacyLibraryPreference, LegacyProfile, LegacySeriesPreference,
    LegacySetting, Planner,
};

use silo_pg::PgText;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const SETTINGS_BACKFILL_VERSION: i64 = 20260727010622;
const DISPLAY_PREFS_MOVE_VERSION: i64 = 20260728132327;
const SUBTITLE_LANGUAGE_BACKFILL_VERSION: i64 = 20260912120000;
const INVALID_INDEX_REBUILD_VERSION: i64 = 20261008165913;
const PUSH_ATTEMPT_KEY_SCOPE_VERSION: i64 = 20261012230946;
const EXTERNAL_SUBTITLE_NAME_BACKFILL_VERSION: i64 = 20261014033149;

pub(super) fn all() -> Vec<Migration> {
    vec![
        Migration::go(
            SETTINGS_BACKFILL_VERSION,
            format!("{SETTINGS_BACKFILL_VERSION}_settings_backfill.go"),
            GoFunc::Tx(|s| Box::pin(backfill_setting_values(s))),
            GoFunc::Tx(|s| Box::pin(rollback_setting_values(s))),
        ),
        Migration::go(
            DISPLAY_PREFS_MOVE_VERSION,
            format!("{DISPLAY_PREFS_MOVE_VERSION}_displayprefs_move.go"),
            GoFunc::Tx(|s| Box::pin(move_display_prefs(s))),
            GoFunc::Tx(|s| Box::pin(unmove_display_prefs(s))),
        ),
        Migration::go(
            SUBTITLE_LANGUAGE_BACKFILL_VERSION,
            format!("{SUBTITLE_LANGUAGE_BACKFILL_VERSION}_subtitle_language_backfill.go"),
            GoFunc::Db(|p| Box::pin(backfill_subtitle_languages(p))),
            GoFunc::Db(noop_db),
        ),
        Migration::go(
            INVALID_INDEX_REBUILD_VERSION,
            format!("{INVALID_INDEX_REBUILD_VERSION}_rebuild_invalid_concurrent_indexes.go"),
            GoFunc::Db(|p| Box::pin(rebuild_invalid_indexes(p, "public"))),
            GoFunc::Db(noop_db),
        ),
        Migration::go(
            PUSH_ATTEMPT_KEY_SCOPE_VERSION,
            format!("{PUSH_ATTEMPT_KEY_SCOPE_VERSION}_scope_push_attempt_key_to_deliveries.go"),
            GoFunc::Db(|p| Box::pin(scope_push_attempt_key(p, "public"))),
            GoFunc::Db(|p| Box::pin(widen_push_attempt_key(p, "public"))),
        ),
        Migration::go(
            EXTERNAL_SUBTITLE_NAME_BACKFILL_VERSION,
            format!("{EXTERNAL_SUBTITLE_NAME_BACKFILL_VERSION}_external_subtitle_name_backfill.go"),
            GoFunc::Db(|p| Box::pin(backfill_external_subtitle_names(p))),
            GoFunc::Db(noop_db),
        ),
    ]
}

fn noop_db(_: &Pool) -> GoFuture<'_> {
    Box::pin(async { Ok(()) })
}

fn ctx(prefix: impl std::fmt::Display, err: impl std::fmt::Display) -> BoxError {
    format!("{prefix}: {err}").into()
}

fn opt_text(row: &silo_pg::Row, index: usize) -> Result<Option<String>, PgError> {
    let value: Option<TextValue> = row.try_get(index)?;
    Ok(value.map(|v| v.0))
}

fn text(row: &silo_pg::Row, index: usize) -> Result<String, PgError> {
    let value: TextValue = row.try_get(index)?;
    Ok(value.0)
}

// nullText and nullInt: Go stores the zero value as NULL.
fn null_text(value: &str) -> Option<PgText<'_>> {
    (!value.is_empty()).then_some(PgText(value))
}

fn null_int(value: i64) -> Option<AnyInt> {
    (value != 0).then_some(AnyInt(value))
}

// --- settings backfill ---

async fn backfill_setting_values(tx: &mut Session) -> Result<(), BoxError> {
    let contract = load_contract();
    let planner = Planner::new(contract);

    let rows = tx
        .query(
            "
SELECT id FROM users
 WHERE EXISTS (SELECT 1 FROM user_profiles p WHERE p.user_id = users.id)
    OR EXISTS (SELECT 1 FROM user_settings s WHERE s.user_id = users.id)
 ORDER BY id",
            &[],
        )
        .await
        .map_err(|e| ctx("listing users", e))?;
    let mut user_ids = Vec::with_capacity(rows.len());
    for row in &rows {
        let id: AnyInt = row.try_get(0).map_err(|e| ctx("scanning user id", e))?;
        user_ids.push(id.0);
    }

    for user_id in user_ids {
        let input = read_legacy_settings_for_user(tx, user_id)
            .await
            .map_err(|e| ctx(format!("reading legacy settings for user {user_id}"), e))?;
        let result = planner.plan(&input);

        for row in &result.rows {
            let scope = row.scope.expect("planned rows have a scope").as_str();
            tx.execute(
                "
INSERT INTO user_setting_values
    (user_id, key, scope, profile_id, device_id, library_id, series_id, value)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)",
                &[
                    &AnyInt(user_id),
                    &PgText(&row.key),
                    &PgText(scope),
                    &null_text(&row.profile_id),
                    &null_text(&row.device_id),
                    &null_int(row.library_id),
                    &null_text(&row.series_id),
                    &PgText(&row.value),
                ],
            )
            .await
            .map_err(|e| {
                ctx(
                    format!("writing {} at {scope} for user {user_id}", row.key),
                    e,
                )
            })?;
        }

        for reject in &result.rejects {
            tx.execute(
                "
INSERT INTO user_setting_migration_rejects
    (user_id, source_table, source_key, identity, value, reason)
VALUES ($1, $2, $3, $4::jsonb, $5, $6)",
                &[
                    &AnyInt(user_id),
                    &PgText(&reject.source_table),
                    &PgText(&reject.source_key),
                    &PgText(&reject.identity),
                    &PgText(&reject.value),
                    &PgText(&reject.reason),
                ],
            )
            .await
            .map_err(|e| {
                ctx(
                    format!("recording reject {} for user {user_id}", reject.source_key),
                    e,
                )
            })?;
        }
    }
    Ok(())
}

async fn rollback_setting_values(tx: &mut Session) -> Result<(), BoxError> {
    for table in ["user_setting_values", "user_setting_migration_rejects"] {
        tx.execute(&format!("DELETE FROM {table}"), &[])
            .await
            .map_err(|e| ctx(format!("clearing {table}"), e))?;
    }
    Ok(())
}

async fn read_legacy_settings_for_user(tx: &mut Session, user_id: i64) -> Result<Input, BoxError> {
    // Some, even when empty: the profile list was loaded, so a profile-scoped orphan is rejected.
    let mut input = Input {
        profiles: Some(Vec::new()),
        ..Input::default()
    };
    let uid = AnyInt(user_id);

    let rows = tx
        .query(
            "
SELECT id, quality_preference, language, subtitle_language, subtitle_mode,
       show_forced_subtitles, preferred_metadata_language,
       auto_skip_intro, auto_skip_credits, auto_skip_recap, auto_play_next_preview
  FROM user_profiles WHERE user_id = $1",
            &[&uid],
        )
        .await
        .map_err(|e| ctx("reading user_profiles", e))?;
    let mut profiles = Vec::with_capacity(rows.len());
    for row in &rows {
        let read = || -> Result<LegacyProfile, PgError> {
            Ok(LegacyProfile {
                id: text(row, 0)?,
                quality_preference: opt_text(row, 1)?,
                language: opt_text(row, 2)?,
                subtitle_language: opt_text(row, 3)?,
                subtitle_mode: opt_text(row, 4)?,
                show_forced_subtitles: row.try_get(5).map_err(PgError::from)?,
                preferred_metadata_language: opt_text(row, 6)?,
                auto_skip_intro: row.try_get(7).map_err(PgError::from)?,
                auto_skip_credits: row.try_get(8).map_err(PgError::from)?,
                auto_skip_recap: row.try_get(9).map_err(PgError::from)?,
                auto_play_next_preview: row.try_get(10).map_err(PgError::from)?,
            })
        };
        profiles.push(read().map_err(|e| ctx("reading user_profiles", e))?);
    }
    input.profiles = Some(profiles);

    let rows = tx
        .query(
            "SELECT key, value FROM user_settings WHERE user_id = $1",
            &[&uid],
        )
        .await
        .map_err(|e| ctx("reading user_settings", e))?;
    for row in &rows {
        input.settings.push(LegacySetting {
            key: text(row, 0).map_err(|e| ctx("reading user_settings", e))?,
            value: text(row, 1).map_err(|e| ctx("reading user_settings", e))?,
        });
    }

    let rows = tx
        .query(
            "
SELECT profile_id, device_id, key, value
  FROM user_device_settings WHERE user_id = $1",
            &[&uid],
        )
        .await
        .map_err(|e| ctx("reading user_device_settings", e))?;
    for row in &rows {
        let read = || -> Result<LegacyDeviceSetting, PgError> {
            Ok(LegacyDeviceSetting {
                profile_id: text(row, 0)?,
                device_id: text(row, 1)?,
                key: text(row, 2)?,
                value: text(row, 3)?,
            })
        };
        input
            .device_settings
            .push(read().map_err(|e| ctx("reading user_device_settings", e))?);
    }

    // Subtitle and audio preferences merge into one record per series. Go ranges over a map here,
    // so its order is random. This port keeps first-seen order.
    let mut by_series: Vec<LegacySeriesPreference> = Vec::new();
    let mut index: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut record = |profile_id: String, series_id: String| -> usize {
        *index
            .entry((profile_id.clone(), series_id.clone()))
            .or_insert_with(|| {
                by_series.push(LegacySeriesPreference {
                    profile_id,
                    series_id,
                    ..LegacySeriesPreference::default()
                });
                by_series.len() - 1
            })
    };

    let rows = tx
        .query(
            "
SELECT profile_id, series_id, subtitle_language, subtitle_mode, show_forced_subtitles
  FROM user_subtitle_preferences WHERE user_id = $1",
            &[&uid],
        )
        .await
        .map_err(|e| ctx("reading user_subtitle_preferences", e))?;
    let mut subtitle_rows = Vec::with_capacity(rows.len());
    for row in &rows {
        let read = || -> Result<_, PgError> {
            Ok((
                text(row, 0)?,
                text(row, 1)?,
                opt_text(row, 2)?,
                opt_text(row, 3)?,
                row.try_get::<_, Option<bool>>(4).map_err(PgError::from)?,
            ))
        };
        subtitle_rows.push(read().map_err(|e| ctx("reading user_subtitle_preferences", e))?);
    }
    let mut assignments = Vec::with_capacity(subtitle_rows.len());
    for (profile, series, language, mode, forced) in subtitle_rows {
        assignments.push((record(profile, series), language, mode, forced));
    }

    let rows = tx
        .query(
            "
SELECT profile_id, series_id, audio_language
  FROM user_audio_preferences WHERE user_id = $1",
            &[&uid],
        )
        .await
        .map_err(|e| ctx("reading user_audio_preferences", e))?;
    let mut audio_assignments = Vec::with_capacity(rows.len());
    for row in &rows {
        let read =
            || -> Result<_, PgError> { Ok((text(row, 0)?, text(row, 1)?, opt_text(row, 2)?)) };
        let (profile, series, language) =
            read().map_err(|e| ctx("reading user_audio_preferences", e))?;
        audio_assignments.push((record(profile, series), language));
    }
    for (at, language, mode, forced) in assignments {
        let target = &mut by_series[at];
        target.subtitle_source_table = "user_subtitle_preferences".to_string();
        target.subtitle_language = language;
        target.subtitle_mode = mode;
        target.show_forced_subtitles = forced;
    }
    for (at, language) in audio_assignments {
        let target = &mut by_series[at];
        target.audio_source_table = "user_audio_preferences".to_string();
        target.audio_language = language;
    }
    input.series_prefs = by_series;

    let rows = tx
        .query(
            "
SELECT profile_id, library_id, audio_language, subtitle_language, subtitle_mode,
       show_forced_subtitles
  FROM user_library_playback_preferences WHERE user_id = $1",
            &[&uid],
        )
        .await
        .map_err(|e| ctx("reading user_library_playback_preferences", e))?;
    for row in &rows {
        let read = || -> Result<LegacyLibraryPreference, PgError> {
            let library: AnyInt = row.try_get(1).map_err(PgError::from)?;
            Ok(LegacyLibraryPreference {
                profile_id: text(row, 0)?,
                library_id: library.0,
                source_table: "user_library_playback_preferences".to_string(),
                audio_language: opt_text(row, 2)?,
                subtitle_language: opt_text(row, 3)?,
                subtitle_mode: opt_text(row, 4)?,
                show_forced_subtitles: row.try_get(5).map_err(PgError::from)?,
            })
        };
        input
            .library_prefs
            .push(read().map_err(|e| ctx("reading user_library_playback_preferences", e))?);
    }
    Ok(input)
}

// --- displayprefs move ---

async fn move_display_prefs(tx: &mut Session) -> Result<(), BoxError> {
    let pattern = displayprefs::legacy_key_pattern();
    let rows = tx
        .query(
            "SELECT user_id, key, value FROM user_settings WHERE key LIKE $1",
            &[&pattern.as_str()],
        )
        .await
        .map_err(|e| ctx("reading jellycompat rows from user_settings", e))?;
    let mut legacy = Vec::with_capacity(rows.len());
    for row in &rows {
        let read = || -> Result<_, PgError> {
            let user: AnyInt = row.try_get(0).map_err(PgError::from)?;
            Ok((user.0, text(row, 1)?, text(row, 2)?))
        };
        legacy.push(read().map_err(|e| ctx("reading jellycompat rows from user_settings", e))?);
    }

    for (user_id, key, value) in legacy {
        match displayprefs::plan_legacy_row(&key, &value) {
            Ok(blob) => {
                tx.execute(
                    "
INSERT INTO jellycompat_displayprefs (user_id, prefs_id, client, value)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, prefs_id, client) DO NOTHING",
                    &[
                        &AnyInt(user_id),
                        &PgText(&blob.prefs_id),
                        &PgText(&blob.client),
                        &PgText(&blob.value),
                    ],
                )
                .await
                .map_err(|e| {
                    ctx(
                        format!(
                            "moving display prefs {} for user {user_id}",
                            silo_gocompat::strconv::quote(&key)
                        ),
                        e,
                    )
                })?;
            }
            Err(reject) => {
                tx.execute(
                    "
INSERT INTO user_setting_migration_rejects
    (user_id, source_table, source_key, identity, value, reason)
VALUES ($1, 'user_settings', $2, '{\"scope\":\"account\"}'::jsonb, $3, $4)",
                    &[
                        &AnyInt(user_id),
                        &PgText(&reject.key),
                        &PgText(&reject.value),
                        &PgText(&reject.reason),
                    ],
                )
                .await
                .map_err(|e| {
                    ctx(
                        format!(
                            "recording displayprefs reject {} for user {user_id}",
                            silo_gocompat::strconv::quote(&reject.key)
                        ),
                        e,
                    )
                })?;
            }
        }
        tx.execute(
            "DELETE FROM user_settings WHERE user_id = $1 AND key = $2 AND value = $3",
            &[&AnyInt(user_id), &PgText(&key), &PgText(&value)],
        )
        .await
        .map_err(|e| {
            ctx(
                format!(
                    "deleting jellycompat row {} for user {user_id}",
                    silo_gocompat::strconv::quote(&key)
                ),
                e,
            )
        })?;
    }
    Ok(())
}

async fn unmove_display_prefs(tx: &mut Session) -> Result<(), BoxError> {
    let rows = tx
        .query(
            "SELECT user_id, prefs_id, client, value FROM jellycompat_displayprefs",
            &[],
        )
        .await
        .map_err(|e| ctx("reading jellycompat_displayprefs", e))?;
    let mut moved = Vec::with_capacity(rows.len());
    for row in &rows {
        let read = || -> Result<_, PgError> {
            let user: AnyInt = row.try_get(0).map_err(PgError::from)?;
            Ok((user.0, text(row, 1)?, text(row, 2)?, text(row, 3)?))
        };
        moved.push(read().map_err(|e| ctx("reading jellycompat_displayprefs", e))?);
    }
    for (user_id, prefs_id, client, value) in moved {
        let describe = || {
            format!(
                "{}/{} for user {user_id}",
                silo_gocompat::strconv::quote(&prefs_id),
                silo_gocompat::strconv::quote(&client)
            )
        };
        let key = displayprefs::legacy_key(&prefs_id, &client);
        tx.execute(
            "
INSERT INTO user_settings (user_id, key, value)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, key) DO NOTHING",
            &[&AnyInt(user_id), &PgText(&key), &PgText(&value)],
        )
        .await
        .map_err(|e| ctx(format!("restoring display prefs {}", describe()), e))?;
        tx.execute(
            "
DELETE FROM jellycompat_displayprefs
	WHERE user_id = $1 AND prefs_id = $2 AND client = $3 AND value = $4",
            &[
                &AnyInt(user_id),
                &PgText(&prefs_id),
                &PgText(&client),
                &PgText(&value),
            ],
        )
        .await
        .map_err(|e| ctx(format!("clearing moved display prefs {}", describe()), e))?;
    }

    let pattern = displayprefs::legacy_key_pattern();
    let rows = tx
        .query(
            "
SELECT id, user_id, source_key, COALESCE(value, '')
  FROM user_setting_migration_rejects
 WHERE source_table = 'user_settings' AND source_key LIKE $1",
            &[&pattern.as_str()],
        )
        .await
        .map_err(|e| ctx("reading displayprefs rejects", e))?;
    let mut rejects = Vec::with_capacity(rows.len());
    for row in &rows {
        let read = || -> Result<_, PgError> {
            let id: AnyInt = row.try_get(0).map_err(PgError::from)?;
            let user: AnyInt = row.try_get(1).map_err(PgError::from)?;
            Ok((id.0, user.0, text(row, 2)?, text(row, 3)?))
        };
        rejects.push(read().map_err(|e| ctx("reading displayprefs rejects", e))?);
    }
    for (id, user_id, key, value) in rejects {
        tx.execute(
            "
INSERT INTO user_settings (user_id, key, value)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, key) DO NOTHING",
            &[&AnyInt(user_id), &PgText(&key), &PgText(&value)],
        )
        .await
        .map_err(|e| {
            ctx(
                format!(
                    "restoring rejected jellycompat row {} for user {user_id}",
                    silo_gocompat::strconv::quote(&key)
                ),
                e,
            )
        })?;
        tx.execute(
            "DELETE FROM user_setting_migration_rejects WHERE id = $1",
            &[&AnyInt(id)],
        )
        .await
        .map_err(|e| ctx(format!("clearing displayprefs reject {id}"), e))?;
    }
    Ok(())
}

// --- subtitle language backfill ---

const SUBTITLE_LANGUAGE_BATCH_SIZE: i64 = 20000;
const SUBTITLE_LANGUAGE_MAX_PASSES: usize = 3;
const SUBTITLE_LANGUAGE_COLUMNS: [&str; 2] = ["subtitle_tracks", "external_subtitles"];

async fn backfill_subtitle_languages(pool: &Pool) -> Result<(), BoxError> {
    for pass in 1..=SUBTITLE_LANGUAGE_MAX_PASSES {
        if backfill_subtitle_languages_pass(pool, pass).await? == 0 {
            return Ok(());
        }
    }
    Err(format!(
        "subtitle language repair still found legacy values after {SUBTITLE_LANGUAGE_MAX_PASSES} passes; retry after older writers stop"
    )
    .into())
}

/// `subtitleLanguageRewrites`: the stored values whose canonical form differs, and those the
/// canonicalizer can't parse, which are never rewritten.
pub fn subtitle_language_rewrites(stored: &[String]) -> (BTreeMap<String, String>, Vec<String>) {
    let mut rewrite = BTreeMap::new();
    let mut unparseable = Vec::new();
    for value in stored {
        if value.is_empty() {
            continue;
        }
        let canonical = compatible_tag(value);
        if canonical.is_empty() {
            unparseable.push(value.clone());
        } else if canonical != *value {
            rewrite.insert(value.clone(), canonical);
        }
    }
    unparseable.sort();
    (rewrite, unparseable)
}

async fn backfill_subtitle_languages_pass(pool: &Pool, pass: usize) -> Result<i64, BoxError> {
    let mut session = pool.acquire().await?;
    let rows = session
        .query(
            "
SELECT DISTINCT t->>'language'
  FROM public.media_files mf,
       jsonb_array_elements(CASE WHEN jsonb_typeof(mf.subtitle_tracks) = 'array' THEN mf.subtitle_tracks ELSE '[]'::jsonb END) t
 WHERE jsonb_typeof(t->'language') = 'string'
UNION
SELECT DISTINCT t->>'language'
  FROM public.media_files mf,
       jsonb_array_elements(CASE WHEN jsonb_typeof(mf.external_subtitles) = 'array' THEN mf.external_subtitles ELSE '[]'::jsonb END) t
 WHERE jsonb_typeof(t->'language') = 'string'",
            &[],
        )
        .await
        .map_err(|e| ctx("listing stored subtitle languages", e))?;
    let mut stored = Vec::with_capacity(rows.len());
    for row in &rows {
        stored.push(text(row, 0).map_err(|e| ctx("scanning stored subtitle language", e))?);
    }
    let (rewrite, unparseable) = subtitle_language_rewrites(&stored);
    if !unparseable.is_empty() {
        tracing::warn!(values = ?unparseable, "subtitle language repair: leaving values the canonicalizer cannot parse untouched");
    }
    if rewrite.is_empty() {
        tracing::info!(
            pass,
            distinct_values = stored.len(),
            "subtitle language repair pass: every stored tag is already canonical"
        );
        return Ok(0);
    }
    tracing::info!(
        pass,
        distinct_values = stored.len(),
        rewrites = rewrite.len(),
        "subtitle language repair starting"
    );
    let mapping = marshal_to_string(&rewrite)
        .map_err(|e| ctx("encoding subtitle language rewrite map", e))?;

    let mut last_id = 0i64;
    let mut batches = 0;
    let mut changed = [0i64; 2];
    loop {
        let row = session
            .query_one(
                "
SELECT max(id) FROM (
  SELECT id FROM public.media_files WHERE id > $1 ORDER BY id LIMIT $2
) q",
                &[&AnyInt(last_id), &AnyInt(SUBTITLE_LANGUAGE_BATCH_SIZE)],
            )
            .await
            .map_err(|e| {
                ctx(
                    format!("locating next subtitle language batch after id {last_id}"),
                    e,
                )
            })?;
        let batch_max: Option<AnyInt> = row.try_get(0)?;
        let Some(batch_max) = batch_max.map(|v| v.0) else {
            break;
        };
        let counts =
            rewrite_subtitle_language_batch(&mut session, &mapping, last_id, batch_max).await?;
        batches += 1;
        changed[0] += counts[0];
        changed[1] += counts[1];
        last_id = batch_max;
        tracing::info!(
            batch = batches,
            through_media_file_id = batch_max,
            subtitle_tracks_rows = counts[0],
            external_subtitles_rows = counts[1],
            "subtitle language repair batch committed"
        );
    }
    tracing::info!(
        pass,
        batches,
        subtitle_tracks_rows = changed[0],
        external_subtitles_rows = changed[1],
        "subtitle language repair finished"
    );
    Ok(changed[0] + changed[1])
}

async fn rewrite_subtitle_language_batch(
    session: &mut Session,
    mapping: &str,
    last_id: i64,
    batch_max: i64,
) -> Result<[i64; 2], BoxError> {
    let mut tx = session
        .begin()
        .await
        .map_err(|e| ctx("beginning subtitle language batch", e))?;
    let mut counts = [0i64; 2];
    for (i, column) in SUBTITLE_LANGUAGE_COLUMNS.iter().enumerate() {
        // column is one of two fixed identifiers, never user input.
        let query = format!(
            "
UPDATE public.media_files mf
   SET {column} = (
     SELECT jsonb_agg(
              CASE WHEN $1::jsonb ? (elem->>'language')
                   THEN jsonb_set(elem, '{{language}}', $1::jsonb -> (elem->>'language'))
                   ELSE elem END
              ORDER BY ord)
       FROM jsonb_array_elements(mf.{column}) WITH ORDINALITY x(elem, ord))
 WHERE mf.id > $2 AND mf.id <= $3
   AND jsonb_typeof(mf.{column}) = 'array'
   AND EXISTS (
     SELECT 1 FROM jsonb_array_elements(mf.{column}) t
      WHERE $1::jsonb ? (t->>'language'))"
        );
        let params: [&(dyn ToSql + Sync); 3] =
            [&PgText(mapping), &AnyInt(last_id), &AnyInt(batch_max)];
        let n = tx.execute(&query, &params).await.map_err(|e| {
            ctx(
                format!("rewriting {column} languages for media_files {last_id}..{batch_max}"),
                e,
            )
        })?;
        counts[i] = i64::try_from(n)?;
    }
    tx.commit().await.map_err(|e| {
        ctx(
            format!("committing subtitle language batch through id {batch_max}"),
            e,
        )
    })?;
    Ok(counts)
}

// --- invalid index rebuild and push attempt key scope ---

const REBUILT_CONCURRENT_INDEXES: [(&str, &str); 6] = [
    (
        "idx_media_files_folder_lower_file_path",
        "media_files (media_folder_id, lower(file_path))",
    ),
    (
        "idx_media_files_folder_file_path_pattern",
        "media_files (media_folder_id, file_path text_pattern_ops)",
    ),
    (
        "idx_media_items_content_type",
        "media_items USING btree (content_id, type)",
    ),
    (
        "idx_uwp_profile_completed_cursor",
        "user_watch_progress USING btree (user_id, profile_id, updated_at DESC, media_item_id DESC) WHERE completed = TRUE",
    ),
    (
        "idx_abs_playback_sessions_user_profile_started",
        "abs_playback_sessions USING btree (user_id, profile_id, started_at)",
    ),
    (
        "idx_manga_enrichment_state_next_attempt",
        "manga_enrichment_state (next_attempt_at) WHERE next_attempt_at IS NOT NULL",
    ),
];

// pgx.Identifier.Sanitize for one part.
fn quote_ident(part: &str) -> String {
    format!("\"{}\"", part.replace('\0', "").replace('"', "\"\""))
}

async fn rebuild_invalid_indexes(pool: &Pool, schema: &str) -> Result<(), BoxError> {
    let quoted_schema = quote_ident(schema);
    for (name, definition) in REBUILT_CONCURRENT_INDEXES {
        let quoted_name = quote_ident(name);
        ensure_index_concurrently(
            pool,
            &format!("{quoted_schema}.{quoted_name}"),
            &format!(
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS {quoted_name} ON {quoted_schema}.{definition}"
            ),
        )
        .await?;
    }
    Ok(())
}

async fn ensure_index_concurrently(
    pool: &Pool,
    qualified_name: &str,
    build: &str,
) -> Result<(), BoxError> {
    let mut session = pool.acquire().await?;
    let row = session
        .query_one(
            "SELECT coalesce((SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)), false)",
            &[&qualified_name],
        )
        .await
        .map_err(|e| ctx(format!("checking index {qualified_name}"), e))?;
    let valid: bool = row
        .try_get(0)
        .map_err(|e| ctx(format!("checking index {qualified_name}"), e))?;
    if valid {
        return Ok(());
    }
    session
        .execute(
            &format!("DROP INDEX CONCURRENTLY IF EXISTS {qualified_name}"),
            &[],
        )
        .await
        .map_err(|e| ctx(format!("dropping invalid index {qualified_name}"), e))?;
    session
        .execute(build, &[])
        .await
        .map_err(|e| ctx(format!("building index {qualified_name}"), e))?;
    Ok(())
}

const PUSH_ATTEMPT_KEY: &str = "push_delivery_attempts_delivery_unique";
const PUSH_ATTEMPT_DELIVERY_KEY: &str = "push_delivery_attempts_delivery_trigger_unique";
const PUSH_ATTEMPT_KEY_COLUMNS: &str =
    "push_delivery_attempts (push_device_id, notification_delivery_id, attempt_number)";

async fn scope_push_attempt_key(pool: &Pool, schema: &str) -> Result<(), BoxError> {
    swap_push_attempt_key(
        pool,
        schema,
        PUSH_ATTEMPT_DELIVERY_KEY,
        "trigger_type = 'delivery'",
        PUSH_ATTEMPT_KEY,
    )
    .await
}

async fn widen_push_attempt_key(pool: &Pool, schema: &str) -> Result<(), BoxError> {
    let mut session = pool.acquire().await?;
    session
        .execute(
            &format!(
                "UPDATE {}.push_delivery_attempts
		SET notification_delivery_id = NULL
		WHERE trigger_type = 'test' AND notification_delivery_id IS NOT NULL",
                quote_ident(schema)
            ),
            &[],
        )
        .await
        .map_err(|e| ctx("detaching test push attempts", e))?;
    drop(session);
    swap_push_attempt_key(
        pool,
        schema,
        PUSH_ATTEMPT_KEY,
        "notification_delivery_id IS NOT NULL",
        PUSH_ATTEMPT_DELIVERY_KEY,
    )
    .await
}

async fn swap_push_attempt_key(
    pool: &Pool,
    schema: &str,
    keep: &str,
    predicate: &str,
    drop_key: &str,
) -> Result<(), BoxError> {
    let quoted_schema = quote_ident(schema);
    ensure_index_concurrently(
        pool,
        &format!("{quoted_schema}.{keep}"),
        &format!(
            "CREATE UNIQUE INDEX CONCURRENTLY {keep} ON {quoted_schema}.{PUSH_ATTEMPT_KEY_COLUMNS} WHERE {predicate}"
        ),
    )
    .await?;
    let mut session = pool.acquire().await?;
    session
        .execute(
            &format!("DROP INDEX CONCURRENTLY IF EXISTS {quoted_schema}.{drop_key}"),
            &[],
        )
        .await
        .map_err(|e| ctx(format!("dropping {drop_key}"), e))?;
    Ok(())
}

// --- sidecar subtitle name backfill ---

const EXTERNAL_SUBTITLE_NAME_BATCH_SIZE: i64 = 5000;
const EXTERNAL_SUBTITLE_NAME_MAX_PASSES: usize = 3;

async fn backfill_external_subtitle_names(pool: &Pool) -> Result<(), BoxError> {
    for pass in 1..=EXTERNAL_SUBTITLE_NAME_MAX_PASSES {
        if backfill_external_subtitle_names_pass(pool, pass).await? == 0 {
            return Ok(());
        }
    }
    Err(format!(
        "sidecar subtitle name repair still found stale rows after {EXTERNAL_SUBTITLE_NAME_MAX_PASSES} passes; retry after older writers stop"
    )
    .into())
}

#[derive(Serialize)]
struct ExternalSubtitleNameRepair {
    id: i64,
    stored: RawMessage,
    repaired: RawMessage,
}

async fn backfill_external_subtitle_names_pass(pool: &Pool, pass: usize) -> Result<i64, BoxError> {
    let mut session = pool.acquire().await?;
    let (mut last_id, mut stale, mut changed) = (0i64, 0i64, 0i64);
    let mut batches = 0;
    loop {
        let rows = session
            .query(
                "
SELECT id, file_path, external_subtitles
  FROM public.media_files
 WHERE id > $1
   AND jsonb_typeof(external_subtitles) = 'array'
   AND external_subtitles <> '[]'::jsonb
 ORDER BY id
 LIMIT $2",
                &[&AnyInt(last_id), &AnyInt(EXTERNAL_SUBTITLE_NAME_BATCH_SIZE)],
            )
            .await
            .map_err(|e| {
                ctx(
                    format!("loading sidecar subtitles after media_files id {last_id}"),
                    e,
                )
            })?;
        if rows.is_empty() {
            break;
        }
        let mut repairs = Vec::new();
        for row in &rows {
            let id: AnyInt = row.try_get(0).map_err(|e| {
                ctx(
                    format!("scanning sidecar subtitles after media_files id {last_id}"),
                    e,
                )
            })?;
            let file_path = text(row, 1).map_err(|e| {
                ctx(
                    format!("scanning sidecar subtitles after media_files id {last_id}"),
                    e,
                )
            })?;
            let subtitles = text(row, 2).map_err(|e| {
                ctx(
                    format!("scanning sidecar subtitles after media_files id {last_id}"),
                    e,
                )
            })?;
            last_id = id.0;
            match repair_external_subtitle_names(&file_path, &subtitles) {
                Err(err) => {
                    tracing::warn!(media_file_id = id.0, error = %err, "sidecar subtitle name repair: leaving a row it cannot decode untouched");
                }
                Ok(None) => {}
                Ok(Some(repaired)) => repairs.push(ExternalSubtitleNameRepair {
                    id: id.0,
                    stored: RawMessage::from(subtitles.into_bytes()),
                    repaired: RawMessage::from(repaired.into_bytes()),
                }),
            }
        }
        let n = if repairs.is_empty() {
            0
        } else {
            let payload = json::marshal_to_string(&repairs)
                .map_err(|e| ctx("encoding sidecar subtitle repairs", e))?;
            let through = repairs.last().map_or(0, |r| r.id);
            let n = session
                .execute(
                    "
UPDATE public.media_files mf
   SET external_subtitles = r.repaired
  FROM jsonb_to_recordset($1::jsonb) AS r(id bigint, stored jsonb, repaired jsonb)
 WHERE mf.id = r.id
   AND mf.external_subtitles = r.stored",
                    &[&PgText(&payload)],
                )
                .await
                .map_err(|e| {
                    ctx(
                        format!(
                            "writing sidecar subtitle repairs through media_files id {through}"
                        ),
                        e,
                    )
                })?;
            i64::try_from(n)?
        };
        stale += repairs.len() as i64;
        changed += n;
        batches += 1;
        if n > 0 {
            tracing::info!(
                pass,
                batch = batches,
                through_media_file_id = last_id,
                rows = n,
                "sidecar subtitle name repair batch committed"
            );
        }
    }
    tracing::info!(
        pass,
        batches,
        rows = changed,
        skipped_changed_rows = stale - changed,
        "sidecar subtitle name repair pass finished"
    );
    Ok(stale)
}

// foldName's folding for the three field names: Go matches a JSON key to a struct field by exact
// name, then by simple case folding.
fn field_matches(key: &str, field: &str) -> bool {
    key == field || silo_gocompat::strings::equal_fold(key, field)
}

/// `repairExternalSubtitleNames`: re-reads each sidecar's language and hearing-impaired flag from
/// its path. `Ok(None)` means nothing changed.
pub fn repair_external_subtitle_names(
    video_path: &str,
    stored: &str,
) -> Result<Option<String>, String> {
    // json.Unmarshal into []json.RawMessage. The elements stay as raw text for re-marshaling.
    let elements = split_array(stored)?;
    let mut out: Vec<RawMessage> = Vec::with_capacity(elements.len());
    let mut changed = false;
    for raw in elements {
        let Some(replacement) = repair_element(video_path, raw) else {
            out.push(RawMessage::from(raw.as_bytes().to_vec()));
            continue;
        };
        out.push(RawMessage::from(replacement.into_bytes()));
        changed = true;
    }
    if !changed {
        return Ok(None);
    }
    json::marshal_to_string(&out)
        .map(Some)
        .map_err(|e| e.to_string())
}

// One element's repair, or None when Go's `continue` keeps it as it was.
fn repair_element(video_path: &str, raw: &str) -> Option<String> {
    let parsed = gojson::unmarshal_any(raw.as_bytes()).ok()?;
    let Value::Object(fields) = &parsed else {
        // Null decodes without error, leaving an empty path; anything else is a type error.
        return None;
    };

    // Decoding into the struct, in document order of Go's field matching. A wrong type on a matched
    // key is an error, which skips the element. jsonb's text form orders keys, so each folded
    // spelling's last value in that order is the one Go keeps.
    let ordered = document_keys(raw);
    let (mut path, mut language, mut hearing_impaired) = (String::new(), String::new(), false);
    for key in &ordered {
        let value = fields.get(key)?;
        if field_matches(key, "path") {
            match value {
                Value::String(s) => path = s.clone(),
                Value::Null => {}
                _ => return None,
            }
        } else if field_matches(key, "language") {
            match value {
                Value::String(s) => language = s.clone(),
                Value::Null => {}
                _ => return None,
            }
        } else if field_matches(key, "hearing_impaired") {
            match value {
                Value::Bool(b) => hearing_impaired = *b,
                Value::Null => {}
                _ => return None,
            }
        }
    }
    if path.is_empty() {
        return None;
    }
    let tags = sidecar_subtitle_tags(video_path, &path)?;
    if tags.language == language && tags.hearing_impaired == hearing_impaired {
        return None;
    }

    // json.Unmarshal into map[string]json.RawMessage, then json.Marshal: sorted keys, each value as
    // it was stored.
    let mut map: BTreeMap<String, RawMessage> = split_object(raw);
    map.insert(
        "language".to_string(),
        RawMessage::from(marshal_to_string(&tags.language).ok()?.into_bytes()),
    );
    map.insert(
        "hearing_impaired".to_string(),
        RawMessage::from(tags.hearing_impaired.to_string().into_bytes()),
    );
    marshal_to_string(&map).ok()
}

// The top-level elements of a JSON array, as raw text. jsonb text is always valid JSON.
fn split_array(stored: &str) -> Result<Vec<&str>, String> {
    let bytes = stored.as_bytes();
    let mut i = skip_space(bytes, 0);
    // A JSON null leaves the slice nil, without error.
    if &bytes[i..] == b"null" {
        return Ok(Vec::new());
    }
    if bytes.get(i) != Some(&b'[') {
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type []json.RawMessage",
            kind_at(bytes, i)
        ));
    }
    i = skip_space(bytes, i + 1);
    let mut out = Vec::new();
    if bytes.get(i) == Some(&b']') {
        return Ok(out);
    }
    loop {
        let end = value_end(stored, i)?;
        out.push(&stored[i..end]);
        i = skip_space(bytes, end);
        match bytes.get(i) {
            Some(b',') => i = skip_space(bytes, i + 1),
            Some(b']') => return Ok(out),
            _ => return Err("invalid array".to_string()),
        }
    }
}

fn kind_at(bytes: &[u8], i: usize) -> &'static str {
    match bytes.get(i) {
        Some(b'{') => "object",
        Some(b'"') => "string",
        Some(b't' | b'f') => "bool",
        _ => "number",
    }
}

fn skip_space(bytes: &[u8], mut i: usize) -> usize {
    while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        i += 1;
    }
    i
}

fn value_end(text: &str, start: usize) -> Result<usize, String> {
    let (_, consumed) = gojson::decode(&text.as_bytes()[start..])?;
    Ok(start + consumed)
}

// An object's keys in document order, decoded.
fn document_keys(raw: &str) -> Vec<String> {
    object_entries(raw).into_iter().map(|(k, _)| k).collect()
}

fn split_object(raw: &str) -> BTreeMap<String, RawMessage> {
    object_entries(raw)
        .into_iter()
        .map(|(k, v)| (k, RawMessage::from(v.as_bytes().to_vec())))
        .collect()
}

fn object_entries(raw: &str) -> Vec<(String, &str)> {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = skip_space(bytes, 0);
    if bytes.get(i) != Some(&b'{') {
        return out;
    }
    i = skip_space(bytes, i + 1);
    while bytes.get(i) == Some(&b'"') {
        let Ok((Value::String(key), used)) = gojson::decode(&bytes[i..]) else {
            return out;
        };
        i = skip_space(bytes, i + used);
        if bytes.get(i) != Some(&b':') {
            return out;
        }
        i = skip_space(bytes, i + 1);
        let Ok(end) = value_end(raw, i) else {
            return out;
        };
        out.push((key, &raw[i..end]));
        i = skip_space(bytes, end);
        if bytes.get(i) == Some(&b',') {
            i = skip_space(bytes, i + 1);
        } else {
            return out;
        }
    }
    out
}
