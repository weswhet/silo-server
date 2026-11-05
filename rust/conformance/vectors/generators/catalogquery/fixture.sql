-- Synthetic catalog for the catalogquery database vectors: 300 items across the two seeded
-- libraries, with files, people, episodes, and personal state for the seeded user's profiles.
-- Every value is derived from the row number, so the fixture is deterministic.
INSERT INTO media_items (content_id, type, title, sort_title, year, genres, content_rating,
  content_rating_age, advisory_age, runtime, rating_imdb, rating_tmdb, rating_rt_critic,
  rating_rt_audience, release_date, first_air_date, created_at, updated_at, studios, countries,
  original_language, latest_episode_added_at, latest_available_episode_air_date_at, status)
SELECT
  'fx-' || lpad(n::text, 4, '0'),
  CASE WHEN n % 5 = 0 THEN 'series' WHEN n % 37 = 0 THEN 'ebook' ELSE 'movie' END,
  (ARRAY['The ', '', 'A ', 'Star '])[n % 4 + 1] || 'Title ' || (n * 7919 % 1000)::text,
  CASE WHEN n % 6 = 0 THEN 'Sort ' || (n % 50)::text ELSE '' END,
  CASE WHEN n % 11 = 0 THEN 0 ELSE 1960 + n % 64 END,
  CASE n % 4 WHEN 0 THEN ARRAY['Drama'] WHEN 1 THEN ARRAY['Comedy', 'Drama'] WHEN 2 THEN '{}'::text[] ELSE NULL END,
  (ARRAY['G', 'PG', 'PG-13', 'R', '', 'TV-MA'])[n % 6 + 1],
  (ARRAY[0, 8, 13, 17, NULL, 17])[n % 6 + 1]::smallint,
  CASE WHEN n % 3 = 0 THEN NULL ELSE (n % 19)::smallint END,
  CASE WHEN n % 9 = 0 THEN 0 ELSE 60 + n % 120 END,
  CASE WHEN n % 8 = 0 THEN NULL ELSE (n % 100) / 10.0 END,
  CASE WHEN n % 7 = 0 THEN NULL ELSE (n * 3 % 100) / 10.0 END,
  CASE WHEN n % 10 = 0 THEN NULL ELSE n % 101 END,
  CASE WHEN n % 13 = 0 THEN NULL ELSE n * 7 % 101 END,
  CASE WHEN n % 5 = 0 OR n % 17 = 0 THEN NULL ELSE DATE '1960-01-01' + (n * 97 % 23000) END,
  CASE WHEN n % 5 = 0 THEN (DATE '1980-01-01' + (n * 89 % 15000))::text WHEN n % 17 = 0 THEN ' bad ' ELSE NULL END,
  TIMESTAMPTZ '2020-01-01 00:00:00+00' + (n * 3631 % 2000) * INTERVAL '1 day',
  TIMESTAMPTZ '2020-01-01 00:00:00+00',
  CASE WHEN n % 3 = 0 THEN ARRAY['Studio A'] ELSE '{}'::text[] END,
  CASE WHEN n % 2 = 0 THEN ARRAY['US'] ELSE ARRAY['FR'] END,
  CASE WHEN n % 3 = 0 THEN 'fr' ELSE 'en' END,
  CASE WHEN n % 5 = 0 THEN TIMESTAMPTZ '2023-01-01 00:00:00+00' + (n % 40) * INTERVAL '3 day' ELSE NULL END,
  CASE WHEN n % 5 = 0 AND n % 10 <> 0 THEN DATE '2022-01-01' + (n % 300) ELSE NULL END,
  CASE WHEN n % 23 = 0 THEN 'pending' ELSE 'matched' END
FROM generate_series(1, 300) AS n;

-- Library membership: movies in 1, series in 2, every 7th item in both, every 29th in none.
INSERT INTO media_item_libraries (content_id, media_folder_id, first_seen_at)
SELECT 'fx-' || lpad(n::text, 4, '0'), CASE WHEN n % 5 = 0 THEN 2 ELSE 1 END,
  TIMESTAMPTZ '2021-01-01 00:00:00+00' + (n * 61 % 900) * INTERVAL '1 hour'
FROM generate_series(1, 300) AS n WHERE n % 29 <> 0;
INSERT INTO media_item_libraries (content_id, media_folder_id, first_seen_at)
SELECT 'fx-' || lpad(n::text, 4, '0'), CASE WHEN n % 5 = 0 THEN 1 ELSE 2 END,
  TIMESTAMPTZ '2022-06-01 00:00:00+00' + n * INTERVAL '1 hour'
FROM generate_series(1, 300) AS n WHERE n % 7 = 0 AND n % 29 <> 0;

INSERT INTO media_files (id, media_folder_id, file_path, content_id, resolution, bitrate, hdr)
SELECT 900000 + n, CASE WHEN n % 5 = 0 THEN 2 ELSE 1 END, '/fixture/' || n || '.mkv',
  'fx-' || lpad(n::text, 4, '0'),
  (ARRAY['720p', '1080p', '4K', 'uhd', NULL, '2160p'])[n % 6 + 1], 1000 + n * 37 % 9000, n % 4 = 0
FROM generate_series(1, 300) AS n WHERE n % 3 <> 1;

INSERT INTO people (id, name) SELECT 990000 + n, 'Person ' || n FROM generate_series(1, 20) AS n;
INSERT INTO item_people (id, content_id, person_id, kind)
SELECT 990000 + n, 'fx-' || lpad(n::text, 4, '0'), 990000 + n % 20 + 1, (n % 3 + 1)::smallint
FROM generate_series(1, 300) AS n WHERE n % 2 = 0;

INSERT INTO episodes (content_id, series_id, season_number, episode_number, title, air_date)
SELECT 'fx-ep-' || s || '-' || e, 'fx-' || lpad(s::text, 4, '0'), 1, e,
  CASE WHEN e % 4 = 0 THEN '' ELSE 'Episode title ' || (s * e % 17) END,
  CASE WHEN e % 5 = 0 THEN NULL ELSE DATE '2010-01-01' + (s * 13 + e * 7) END
FROM generate_series(5, 300, 5) AS s, generate_series(1, 6) AS e;
INSERT INTO episode_libraries (episode_id, media_folder_id)
SELECT 'fx-ep-' || s || '-' || e, 2 FROM generate_series(5, 300, 5) AS s, generate_series(1, 6) AS e WHERE e % 6 <> 0;

INSERT INTO user_favorites (user_id, profile_id, media_item_id)
SELECT 2, p, 'fx-' || lpad(n::text, 4, '0')
FROM generate_series(1, 300) AS n, (VALUES ('c0f00000-0000-4000-8000-000000000002'), ('c0f00000-0000-4000-8000-000000000003')) AS v(p)
WHERE n % 4 = 1;
INSERT INTO user_watchlist (user_id, profile_id, media_item_id)
SELECT 2, 'c0f00000-0000-4000-8000-000000000002', 'fx-' || lpad(n::text, 4, '0') FROM generate_series(1, 300) AS n WHERE n % 6 = 2;
INSERT INTO user_watch_progress (user_id, profile_id, media_item_id, position_seconds, duration_seconds, completed, updated_at)
SELECT 2, p, 'fx-' || lpad(n::text, 4, '0'), n * 10, 3000, n % 9 = 0,
  TIMESTAMPTZ '2024-01-01 00:00:00+00' + n * INTERVAL '1 day'
FROM generate_series(1, 300) AS n, (VALUES ('c0f00000-0000-4000-8000-000000000002'), ('c0f00000-0000-4000-8000-000000000003')) AS v(p)
WHERE n % 3 = 0;
INSERT INTO user_watch_history (id, user_id, profile_id, media_item_id, watched_at, completed)
SELECT 'fx-h-' || n, 2, 'c0f00000-0000-4000-8000-000000000002', 'fx-' || lpad(n::text, 4, '0'),
  TIMESTAMPTZ '2023-01-01 00:00:00+00' + n * INTERVAL '2 day', true
FROM generate_series(1, 300) AS n WHERE n % 8 = 0;
INSERT INTO user_watch_history (id, user_id, profile_id, media_item_id, watched_at, completed)
SELECT 'fx-he-' || s || '-' || e, 2, 'c0f00000-0000-4000-8000-000000000002', 'fx-ep-' || s || '-' || e,
  TIMESTAMPTZ '2023-06-01 00:00:00+00' + (s + e) * INTERVAL '1 day', true
FROM generate_series(5, 300, 5) AS s, generate_series(1, 6) AS e WHERE s % 15 = 0;

-- Columns that default to now(): pinned so cursor vectors that carry them stay reproducible.
UPDATE episodes SET
  created_at = TIMESTAMPTZ '2022-01-01 00:00:00+00' + (split_part(content_id, '-', 3)::int * 7 + split_part(content_id, '-', 4)::int) * INTERVAL '1 hour',
  updated_at = TIMESTAMPTZ '2022-01-01 00:00:00+00'
WHERE content_id LIKE 'fx-ep-%';
UPDATE episode_libraries SET
  first_seen_at = TIMESTAMPTZ '2022-02-01 00:00:00+00' + (split_part(episode_id, '-', 3)::int * 11 + split_part(episode_id, '-', 4)::int) * INTERVAL '1 hour'
WHERE episode_id LIKE 'fx-ep-%';
UPDATE media_files SET
  created_at = TIMESTAMPTZ '2022-03-01 00:00:00+00' + (id - 900000) * INTERVAL '1 hour',
  updated_at = TIMESTAMPTZ '2022-03-01 00:00:00+00'
WHERE id > 900000 AND id <= 900300;
UPDATE people SET created_at = TIMESTAMPTZ '2022-04-01 00:00:00+00', updated_at = TIMESTAMPTZ '2022-04-01 00:00:00+00'
WHERE id > 990000 AND id <= 990020;
UPDATE user_favorites SET added_at = TIMESTAMPTZ '2022-05-01 00:00:00+00' + substr(media_item_id, 4)::int * INTERVAL '1 hour'
WHERE media_item_id LIKE 'fx-%';
UPDATE user_watchlist SET added_at = TIMESTAMPTZ '2022-06-01 00:00:00+00' + substr(media_item_id, 4)::int * INTERVAL '1 hour'
WHERE media_item_id LIKE 'fx-%';
