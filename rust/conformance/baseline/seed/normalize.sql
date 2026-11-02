-- Removes everything from a freshly scanned database that varies between runs,
-- leaving only the seed state. Runs with the server stopped. Triggers are off for
-- the session so revision counters and updated_at columns are left alone.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL session_replication_role = replica;

-- Per-request and per-process records: request ids, durations, disk usage, and
-- random leases, none of which are seed state.
TRUNCATE activity_log, operational_logs, policy_decisions, task_executions,
         download_storage_samples, dashboard_metric_samples, node_heartbeats,
         idgen_machine_leases
  RESTART IDENTITY;

-- Scheduled and startup tasks would keep changing data while tests read it, and
-- several of them call the internet. Their schedule rows stay, so the server
-- treats an empty trigger list as a choice and does not restore the defaults. A
-- test that needs a task starts it through the admin API.
DELETE FROM task_triggers;

-- Sonyflake and ULID ids embed the clock. Replace them with fixed ids in a stable
-- order, updating every reference.
CREATE TEMP TABLE section_ids ON COMMIT DROP AS
  SELECT id AS old_id,
         (900000000000000000 + row_number() OVER (ORDER BY scope, library_id NULLS FIRST, position))::text AS new_id
  FROM page_sections;
UPDATE page_section_revisions r SET section_id = m.new_id FROM section_ids m WHERE r.section_id = m.old_id;
UPDATE page_sections s SET id = m.new_id FROM section_ids m WHERE s.id = m.old_id;

CREATE TEMP TABLE person_ids ON COMMIT DROP AS
  SELECT id AS old_id, 910000000000000000 + row_number() OVER (ORDER BY name) AS new_id FROM people;
UPDATE item_people p SET person_id = m.new_id FROM person_ids m WHERE p.person_id = m.old_id;
UPDATE people p SET id = m.new_id FROM person_ids m WHERE p.id = m.old_id;

CREATE TEMP TABLE item_people_ids ON COMMIT DROP AS
  SELECT id AS old_id, 920000000000000000 + row_number() OVER (ORDER BY content_id, person_id, id) AS new_id
  FROM item_people;
UPDATE item_people p SET id = m.new_id FROM item_people_ids m WHERE p.id = m.old_id;

CREATE TEMP TABLE scan_ids ON COMMIT DROP AS
  SELECT id AS old_id, '01CONF0RMANCE0000000000' || lpad(media_folder_id::text, 3, '0') AS new_id FROM scan_runs;
UPDATE media_files f SET first_seen_scan_run_id = m.new_id FROM scan_ids m WHERE f.first_seen_scan_run_id = m.old_id;
UPDATE media_files f SET held_episode_first_seen_scan_run_id = m.new_id FROM scan_ids m WHERE f.held_episode_first_seen_scan_run_id = m.old_id;
UPDATE episode_libraries e SET first_seen_scan_run_id = m.new_id FROM scan_ids m WHERE e.first_seen_scan_run_id = m.old_id;
UPDATE scan_runs s SET id = m.new_id FROM scan_ids m WHERE s.id = m.old_id;

UPDATE server_settings
SET value = '{"identity":"local|/var/lib/silo/artwork","armed_at":"2026-01-01T00:00:00Z"}'
WHERE key = 'chapter_thumbnails.originals_cleanup_checkpoint';

-- Every remaining timestamp gets one fixed value.
DO $$
DECLARE col record;
BEGIN
  FOR col IN
    SELECT c.relname, a.attname
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_type t ON t.oid = a.atttypid
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT c.relispartition
      AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = ''
      AND t.typname IN ('timestamptz', 'timestamp')
  LOOP
    EXECUTE format('UPDATE %I SET %I = %L WHERE %I IS NOT NULL',
                   col.relname, col.attname, '2026-01-01T00:00:00Z', col.attname);
  END LOOP;
END $$;

-- Nothing is left due for refresh. A read of a series with incomplete episodes
-- would otherwise start a refresh that rewrites updated_at on the item, its seasons
-- and its episodes mid-test. The sample series is complete by construction: its
-- metadata comes from NFO files and there is no provider to ask for more.
UPDATE metadata_refresh_debt SET next_refresh_at = '2099-01-01T00:00:00Z';
UPDATE media_items SET episode_metadata_incomplete = false;

-- Then spread the catalog's so "recently added" has a defined order: oldest first
-- by content id, movies before series, one hour apart.
UPDATE media_items i SET created_at = '2026-01-01T00:00:00Z'::timestamptz + (o.n * interval '1 hour')
FROM (SELECT content_id, row_number() OVER (ORDER BY content_id) AS n FROM media_items) o
WHERE i.content_id = o.content_id;
UPDATE media_files f SET created_at = '2026-01-01T00:00:00Z'::timestamptz + (f.id * interval '1 hour');

-- Rows only a long run would otherwise leave behind, so the library reads have something to show. They are all
-- terminal, which nothing picks up by itself. Queue rows cannot be seeded: the matcher revives parked rows at start.
INSERT INTO admin_jobs (id, job_type, status, created_by_user_id, request_payload, result_payload,
                        progress_current, progress_total, requested_at, started_at, completed_at, updated_at)
VALUES
  ('01CONF0RMANCEJ0B000000REFR', 'library_refresh', 'completed', 1, '{"library_id":1}',
   '{"library_id":1,"refreshed_ok":2,"refreshed_failed":1,"pipeline_ok":1,"pipeline_failed":0}', 3, 3,
   '2026-01-01T00:00:00Z', '2026-01-01T00:00:01.5Z', '2026-01-01T00:00:02Z', '2026-01-01T00:00:02Z'),
  ('01CONF0RMANCEJ0B000000FAIL', 'library_refresh', 'failed', 1, '{"library_id":2}', '{}', 1, 2,
   '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z', '2026-01-01T00:00:02Z'),
  ('01CONF0RMANCEJ0B000000DELE', 'delete_library', 'cancelled', 1, '{"library_id":9}', '{}', 0, 0,
   '2026-01-01T00:00:00Z', NULL, '2026-01-01T00:00:02Z', '2026-01-01T00:00:02Z');
INSERT INTO stale_media_ids (content_id, provider, provider_id, first_seen_at, last_seen_at)
VALUES
  ('movie-tmdb-9000001', 'tmdb', '9000001', '2026-01-01T00:00:00Z', '2026-01-01T00:00:03Z'),
  ('series-tvdb-9000003', 'imdb', 'tt0000999', '2026-01-01T00:00:00Z', '2026-01-01T00:00:02Z');

COMMIT;
