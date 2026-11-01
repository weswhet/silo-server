"""Seed data for the migrator's exit gate.

Each snapshot stops just before one Go migration and is seeded with rows that migration and the later
ones transform. Reject reasons must be deterministic for the Go-against-Go noise run to leave the
column unmasked, so no seeded object value fails on more than one property: Go's message order for
several failures is random, and the planner's vector tests cover those.
"""

COMMON = r"""
SET session_replication_role = replica;
INSERT INTO users (id, email, username, role) VALUES
  (1, 'a@example.test', 'a', 'admin'),
  (2, 'b@example.test', 'b', 'user'),
  (3, 'c@example.test', 'c', 'user'),
  (4, 'd@example.test', 'd', 'user'),
  (5, 'e@example.test', 'e', 'user');
SELECT setval('users_id_seq', 5);
INSERT INTO user_profiles (id, user_id, name, is_primary, quality_preference, language, subtitle_language,
    subtitle_mode, show_forced_subtitles, auto_skip_intro, auto_skip_credits) VALUES
  ('p1', 1, 'one', true, '1080p-high', 'eng', 'fre', 'always', false, true, true),
  ('p2', 1, 'two', false, '1080p', 'en', '', 'auto', true, false, false),
  ('p3', 2, 'three', true, 'not-a-quality', 'not a tag', 'English', 'bogus', true, false, false),
  ('p5', 5, 'five', true, 'auto', '', 'pt_br', 'forced', false, false, false);
INSERT INTO media_folders (id, type, name) VALUES (1, 'movies', 'Movies'), (2, 'tv', 'Shows');
"""

MEDIA_LANGUAGES = r"""
INSERT INTO media_files (id, media_folder_id, file_path, subtitle_tracks, external_subtitles) VALUES
 (1, 1, '/lib/m/One.mkv',
  '[{"language":"eng","codec":"srt"},{"language":"English","forced":true},{"language":"pt-br"},{"language":"en"},
    {"language":"forced"},{"language":""},{"language":null},{"language":5},{"title":"no language"},
    {"language":"i-klingon"},{"language":"x-foo"},{"language":"zh-hans"},{"language":"Монгол"},{"language":"und"}]',
  '[{"path":"/lib/m/One.ger.srt","language":"ger","hearing_impaired":false},
    {"path":"/lib/m/One.fra.srt","language":"French"}]'),
 (2, 1, '/lib/m/Two.mkv', NULL, 'null'),
 (3, 1, '/lib/m/Three.mkv', NULL, NULL),
 (4, 1, '/lib/m/Four.mkv', '[]', '[]'),
 (5, 2, '/lib/s/S01E01.mkv', '[{"language":"spa"},{"language":"es"}]', '[{"path":"/lib/s/S01E01.es.srt","language":"spa"}]'),
 (6, 2, '/lib/s/S01E02.mkv', NULL, '12');
"""

MEDIA_SIDECARS = r"""
INSERT INTO media_files (id, media_folder_id, file_path, external_subtitles) VALUES
 (101, 1, '/lib/m/Movie.mkv', '[
   {"path":"/lib/m/Movie.sdh.en.srt","language":"sdh","hearing_impaired":false,"codec":"subrip"},
   {"path":"/lib/m/Movie.en.srt","language":"en","hearing_impaired":false},
   {"path":"/lib/m/Movie.fr.forced.srt","language":"fra","hearing_impaired":false,"forced":true},
   {"path":"/lib/m/Other.en.srt","language":"xx","hearing_impaired":true},
   {"language":"keep"},
   {"path":12,"language":"bad path"},
   {"path":"/lib/m/Movie.de.srt","language":7},
   {"path":"/lib/m/Movie.it.srt","language":null},
   {"Path":"/lib/m/Movie.ja.srt","LANGUAGE":"xx"},
   {"path":"/lib/m/Movie.hi.srt","language":"","hearing_impaired":true,"note":"<&> ","n":1.50},
   null, 12, "text"]'),
 (102, 1, '/lib/m/Straße.mkv', '[{"path":"/lib/m/STRASSE.en.srt","language":"zz"},{"path":"/lib/m/straße.en.srt","language":"zz"}]'),
 (103, 1, '/lib/m/Clean.mkv', '[{"path":"/lib/m/Clean.en.srt","language":"en","hearing_impaired":false}]'),
 (104, 1, '/lib/m/Bad.mkv', '{"not":"an array"}');
"""

# Crosses the 5,000-row sidecar batch and the 20,000-row language batch.
MEDIA_BULK = r"""
INSERT INTO media_files (id, media_folder_id, file_path, subtitle_tracks, external_subtitles)
SELECT 1000 + n, 2, '/lib/s/Bulk.' || n || '.mkv',
       jsonb_build_array(jsonb_build_object('language', CASE WHEN n % 2 = 0 THEN 'eng' ELSE 'en' END)),
       jsonb_build_array(jsonb_build_object('path', '/lib/s/Bulk.' || n || '.sdh.de.srt', 'language', 'sdh', 'hearing_impaired', false))
  FROM generate_series(1, 21000) n;
"""

LEGACY_SETTINGS = r"""
INSERT INTO user_settings (user_id, key, value) VALUES
  (1, 'ui_theme', 'dark'),
  (1, 'ui.text_scale', 'large'),
  (1, 'ui_text_weight', 'nope'),
  (1, 'ui_high_contrast', 'TRUE'),
  (1, 'ui_custom_css', 'body { color: <red>; }'),
  (1, 'ui_custom_theme_vars', '{"accent":"#fff"}'),
  (1, 'card_overlays', '{"hdr":{"enabled":true,"position":"top-left","accentColor":"#ABCDEF","showIcon":false,"junk":1},"bad":{"enabled":true,"position":"top-left"},"year":{"enabled":false},"studio":{"enabled":false,"position":"bottom-left","accentColor":"red"}}'),
  (1, 'subtitle_appearance', '{"fontSize":"large"}'),
  (1, 'next_up_mode', 'nope'),
  (1, 'sidebar_pins', '{"1":[{"type":"section","id":"a","label":"b"}]}'),
  (1, 'disabled_library_ids', '[1,2,3]'),
  (1, 'library_order', '[1,1]'),
  (1, 'player.playback_speed', '1.26'),
  (1, 'playback.auto_skip_intro', 'true'),
  (1, 'unknown.key', 'x'),
  (1, 'jellycompat:displayprefs:usersettings:emby', '{"SortBy":"SortName"}'),
  (1, 'jellycompat:displayprefs:a:b:jellyfin-web', '{"x":1}'),
  (1, 'jellycompat:displayprefs:usersettings:', '{"empty":"client"}'),
  (1, 'jellycompat:displayprefs:plain', 'no separator'),
  (1, 'jellycompat:other', 'not displayprefs'),
  (2, 'ui_theme', 'light'),
  (2, 'ui_custom_theme_vars', '{"accent":1}'),
  (2, 'disabled_library_ids', '["x"]'),
  (2, 'subtitle_appearance', '{"fontSize":"small","fontSize":"large"}'),
  (2, 'player.video_skip_back_seconds', '15'),
  (2, 'card_overlays', '{"version":2,"preset":"classic","order":[],"items":{}}'),
  (2, 'playback.max_bitrate_kbps', '5000'),
  (2, 'playback.next_up_prompt_seconds', '999'),
  (2, 'ui.custom_css', '   '),
  (2, 'playback.subtitle_appearance', 'not json'),
  (4, 'ui_theme', 'dark'),
  (4, 'next_up_mode', '');
INSERT INTO user_device_settings (user_id, profile_id, device_id, key, value) VALUES
  (1, 'p1', 'd1', 'player.playback_speed', '0.3'),
  (1, 'p1', 'd2', 'player.playback_speed', '9'),
  (1, 'p1', 'd3', 'player.playback_speed', 'inf'),
  (1, 'p1', 'd1', 'player.audio_sync_ms', '100'),
  (1, 'p1', 'd1', 'player.subtitle_sync_ms', 'abc'),
  (1, 'p1', 'd1', 'playback.preferred_quality', '720p-medium'),
  (1, 'p1', 'd2', 'playback.preferred_quality', 'bogus'),
  (1, 'p1', 'd1', 'playback.audio_language', 'en'),
  (1, 'p1', 'd2', 'playback.audio_language', '  '),
  (1, 'p1', 'd1', 'player.next_up_prompt_seconds', '10'),
  (1, 'p1', 'd1', 'playback.next_up_prompt_seconds', '20'),
  (1, 'p1', 'd1', 'playback.auto_skip_intro', 'true'),
  (1, 'p1', 'd1', 'playback.intro_skip_mode', 'never'),
  (1, 'p1', 'd1', 'ui.custom_css', 'no device scope'),
  (1, 'p1', 'd1', 'unknown.device.key', 'x'),
  (1, 'gone', 'd9', 'ui.theme', 'dark'),
  (2, 'p3', 'd5', 'ui_theme', 'light');
INSERT INTO user_subtitle_preferences (user_id, profile_id, series_id, subtitle_language, subtitle_mode, show_forced_subtitles) VALUES
  (1, 'p1', 'series-a', 'eng', 'always', true),
  (1, 'p1', 'series-b', 'not a tag', 'bogus', false),
  (1, 'p2', 'series-a', '', '', NULL),
  (2, 'gone', 'series-a', 'en', 'always', NULL);
INSERT INTO user_audio_preferences (user_id, profile_id, series_id, audio_language) VALUES
  (1, 'p1', 'series-a', 'jpn'),
  (1, 'p1', 'series-c', 'bad tag here'),
  (2, 'p3', 'series-z', NULL);
INSERT INTO user_library_playback_preferences (user_id, profile_id, library_id, audio_language, subtitle_language, subtitle_mode, show_forced_subtitles) VALUES
  (1, 'p1', 1, 'ger', 'fre', 'forced', true),
  (1, 'p2', 2, NULL, NULL, NULL, false),
  (2, 'p3', 1, 'nonsense tag', '', 'bogus', NULL);
"""

DISPLAY_PREFS = r"""
INSERT INTO user_settings (user_id, key, value) VALUES
  (1, 'jellycompat:displayprefs:usersettings:emby', '{"SortBy":"SortName"}'),
  (1, 'jellycompat:displayprefs:a:b:jellyfin-web', '{"x":1}'),
  (1, 'jellycompat:displayprefs:plain', 'no separator'),
  (1, 'jellycompat:displayprefs:', 'empty remainder'),
  (2, 'jellycompat:other', 'not displayprefs'),
  (2, 'jellycompat:displayprefs:usersettings:', '{"empty":"client"}'),
  (2, 'ui_theme', 'kept');
INSERT INTO jellycompat_displayprefs (user_id, prefs_id, client, value) VALUES (2, 'usersettings', '', '{"already":"moved"}');
"""

INVALID_INDEXES = r"""
UPDATE pg_index SET indisvalid = false WHERE indexrelid IN (
  'public.idx_media_items_content_type'::regclass,
  'public.idx_media_files_folder_lower_file_path'::regclass);
DROP INDEX IF EXISTS public.idx_abs_playback_sessions_user_profile_started;
"""

PUSH_ATTEMPTS = r"""
INSERT INTO push_devices (id, user_id, profile_id, device_id, platform, provider, server_device_id, fcm_token_ciphertext, fcm_token_hash)
  VALUES ('dev1', 1, 'p1', 'phone', 'android', 'silo_relay', 'srv1', 'cipher', 'hash');
INSERT INTO notification_deliveries (id, user_id, profile_id, type, reason_flags)
  VALUES ('del1', 1, 'p1', 'new_episode', '{}');
"""

PUSH_ATTEMPT_ROWS = r"""
INSERT INTO push_delivery_attempts (id, notification_delivery_id, push_device_id, trigger_type, provider, platform, attempt_number) VALUES
  ('a1', 'del1', 'dev1', 'delivery', 'silo_relay', 'android', 0),
  ('a2', 'del1', 'dev1', 'delivery', 'silo_relay', 'android', 1),
  ('a3', NULL, 'dev1', 'test', 'silo_relay', 'android', 0),
  ('a4', 'del1', 'dev1', 'test', 'silo_relay', 'android', 2);
"""

SNAPSHOTS = {
    # Before the settings backfill: every Go migration transforms this database.
    20260727010621: COMMON + LEGACY_SETTINGS + MEDIA_LANGUAGES + MEDIA_SIDECARS + MEDIA_BULK,
    # Before the displayprefs move.
    20260728132326: COMMON + DISPLAY_PREFS + MEDIA_LANGUAGES + MEDIA_SIDECARS,
    # Before the subtitle language backfill.
    20260911010527: COMMON + MEDIA_LANGUAGES + MEDIA_SIDECARS + MEDIA_BULK + PUSH_ATTEMPTS + PUSH_ATTEMPT_ROWS,
    # Before the invalid index rebuild.
    20261008165511: COMMON + MEDIA_SIDECARS + INVALID_INDEXES + PUSH_ATTEMPTS + PUSH_ATTEMPT_ROWS,
    # Before the push attempt key scope.
    20261012171715: COMMON + MEDIA_SIDECARS + PUSH_ATTEMPTS + PUSH_ATTEMPT_ROWS,
    # Before the sidecar name backfill.
    20261013231605: COMMON + MEDIA_SIDECARS + MEDIA_BULK,
}

# Each query must return true on the finished database, proving the seed reached the Go migration
# that the snapshot stops before, and that it did something.
EVIDENCE = {
    20260727010621: [
        "SELECT count(*) > 20 FROM user_setting_values",
        "SELECT count(*) > 15 FROM user_setting_migration_rejects",
        "SELECT count(*) > 0 FROM user_setting_migration_rejects WHERE reason LIKE 'does not satisfy %'",
        "SELECT count(*) > 0 FROM user_setting_migration_rejects WHERE reason LIKE 'profile no longer exists%'",
        "SELECT count(*) > 0 FROM user_setting_values WHERE key = 'ui.card_overlays' AND value->'items' ? 'hdr'",
        "SELECT count(*) > 0 FROM user_setting_values WHERE key = 'playback.intro_skip_mode'",
        "SELECT count(*) = 3 FROM jellycompat_displayprefs",
        "SELECT NOT EXISTS (SELECT 1 FROM user_settings WHERE key LIKE 'jellycompat:%')",
        "SELECT subtitle_tracks->0->>'language' = 'en' FROM media_files WHERE id = 1",
        "SELECT external_subtitles->0->>'language' = 'sdh' IS FALSE FROM media_files WHERE id = 101",
    ],
    20260728132326: [
        "SELECT count(*) = 3 FROM jellycompat_displayprefs",
        "SELECT value = '{\"already\":\"moved\"}' FROM jellycompat_displayprefs WHERE user_id = 2 AND prefs_id = 'usersettings'",
        "SELECT count(*) >= 3 FROM user_setting_migration_rejects WHERE source_table = 'user_settings' AND source_key LIKE 'jellycompat:%'",
        "SELECT NOT EXISTS (SELECT 1 FROM user_settings WHERE key LIKE 'jellycompat:%')",
    ],
    20260911010527: [
        "SELECT subtitle_tracks->0->>'language' = 'en' FROM media_files WHERE id = 1",
        "SELECT subtitle_tracks->4->>'language' = 'forced' FROM media_files WHERE id = 1",
        "SELECT subtitle_tracks->9->>'language' = 'tlh' FROM media_files WHERE id = 1",
        "SELECT NOT EXISTS (SELECT 1 FROM media_files WHERE id > 1000 AND subtitle_tracks->0->>'language' = 'eng')",
        "SELECT count(*) = 21000 FROM media_files WHERE id > 1000 AND external_subtitles->0->>'language' = 'de'",
    ],
    20261008165511: [
        "SELECT bool_and(indisvalid) AND count(*) >= 5 FROM pg_index WHERE indexrelid::regclass::text IN ('idx_media_files_folder_lower_file_path','idx_media_files_folder_file_path_pattern','idx_media_items_content_type','idx_uwp_profile_completed_cursor','idx_abs_playback_sessions_user_profile_started','idx_manga_enrichment_state_next_attempt')",
        "SELECT to_regclass('public.idx_abs_playback_sessions_user_profile_started') IS NOT NULL",
    ],
    20261012171715: [
        "SELECT to_regclass('public.push_delivery_attempts_delivery_trigger_unique') IS NOT NULL",
        "SELECT to_regclass('public.push_delivery_attempts_delivery_unique') IS NULL",
        "SELECT count(*) = 4 FROM push_delivery_attempts",
    ],
    20261013231605: [
        "SELECT external_subtitles->0->>'language' = 'en' AND (external_subtitles->0->>'hearing_impaired')::boolean FROM media_files WHERE id = 101",
        "SELECT external_subtitles->3->>'language' = 'xx' FROM media_files WHERE id = 101",
        "SELECT external_subtitles->4->>'language' = 'keep' FROM media_files WHERE id = 101",
        "SELECT external_subtitles = '{\"not\":\"an array\"}' FROM media_files WHERE id = 104",
        "SELECT count(*) = 21000 FROM media_files WHERE id > 1000 AND external_subtitles->0->>'language' = 'de'",
    ],
}
