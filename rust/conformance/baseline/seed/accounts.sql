-- Deterministic accounts and settings for the conformance baseline. Applied
-- after migrations, before the server's first start, so nothing it mints at
-- startup (JWT secret, server identity) comes out random.
--
-- All credentials are synthetic; see ../fixture.env. The bcrypt hashes and key
-- digests below are of those values. Timestamps are fixed so API responses that
-- report them stay stable across resets.
\set ON_ERROR_STOP on
BEGIN;

INSERT INTO users (id, email, username, password_hash, role, permissions, enabled,
                   is_owner, break_glass, access_group_id, created_at, updated_at)
VALUES
  (1, 'conf-admin@silo.example.test', 'conf-admin',
   '$2a$10$g0jd28BFtxM04aqRWaOoeudu0TtteaEarLBqrK3EnCiyS3i7XVAHy',
   'admin', '{}', true, true, true, NULL,
   '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
  (2, 'conf-user@silo.example.test', 'conf-user',
   '$2a$10$WJxViktGfEzkqN/HP2PmMuYHLcmlIylSxuaX9uH30Kg.ZP3gw4Bqy',
   'user', '{marker_edit}', true, false, false,
   (SELECT id FROM access_groups WHERE is_default),
   '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
SELECT setval(pg_get_serial_sequence('users', 'id'), 100);

INSERT INTO user_profiles (id, user_id, name, is_primary, is_child, max_content_rating,
                           created_at, updated_at)
VALUES
  (:'admin_profile', 1, 'Conf Admin', true, false, '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
  (:'user_profile', 2, 'Conf User', true, false, '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
  (:'user_second_profile', 2, 'Conf Kid', false, true, 'PG', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');

INSERT INTO api_keys (id, user_id, label, key_hash, key_prefix, scopes, created_at)
VALUES
  (1, 1, 'conformance-admin', '5a9ed66843d062193fa12c5ae19dcc3a6fc4882f01ef3b2656aa99715fd77832',
   'sa_c0fa0000', '{}', '2026-01-01T00:00:00Z'),
  (2, 2, 'conformance-user', 'abc4112b65799b949252d50aebe0c5bf13312f1eb6804c1d867ed3a0315ddf34',
   'sa_c0fb0000', '{}', '2026-01-01T00:00:00Z');
SELECT setval(pg_get_serial_sequence('api_keys', 'id'), 100);

-- Stored in the clear here; the server encrypts it on first start and reads back
-- this value, so the signing key is the same after every reset.
INSERT INTO server_settings (key, value) VALUES
  ('auth.jwt_secret', :'jwt_secret'),
  ('server.identity_id', 'c0f00000-0000-4000-8000-00000000f001'),
  ('diagnostics.server_instance_id', 'c0f00000-0000-4000-8000-00000000f002'),
  ('notifications.web_push.vapid_keypair', '{"public":"BOFWwXKfFhOw0WXSDgg_PTwEe5_e8yjcZxQoaLY5_ZdLBvVKOfp8FbXAsd2yepnYQj6SLPMRdz7tX61x_NzuZDM","private":"fb_aJ6N_oJg3S4wMm0AM148T_XckXjkvUbi_xV5Afig"}'),
  ('branding.server_name', 'Silo Conformance'),
  ('playback.ffmpeg_path', '/usr/bin/ffmpeg'),
  ('jellyfin_compat.server_name', 'Silo Conformance'),
  -- One worker each: files reach the database in walk order, so media_files ids
  -- come out the same on every reset.
  ('scanner.workers', '1'),
  ('matcher.workers', '1'),
  -- Generous limits: a comparison run logs in many times from one address.
  ('ratelimit.auth.login.requests_per_minute', '6000'),
  ('ratelimit.auth.login.burst', '1000'),
  ('ratelimit.auth.autoscan_webhook.requests_per_minute', '6000'),
  ('ratelimit.auth.autoscan_webhook.burst', '1000'),
  ('ratelimit.auth.device_lookup.requests_per_minute', '6000'),
  ('ratelimit.auth.device_lookup.burst', '1000'),
  ('ratelimit.auth.device_poll.requests_per_minute', '6000'),
  ('ratelimit.auth.device_poll.burst', '1000'),
  ('ratelimit.auth.device_start.requests_per_minute', '6000'),
  ('ratelimit.auth.device_start.burst', '1000'),
  ('ratelimit.auth.invitation.requests_per_minute', '6000'),
  ('ratelimit.auth.invitation.burst', '1000'),
  ('ratelimit.auth.password_change.requests_per_minute', '6000'),
  ('ratelimit.auth.password_change.burst', '1000'),
  ('ratelimit.auth.setup.requests_per_minute', '6000'),
  ('ratelimit.auth.setup.burst', '1000'),
  ('ratelimit.auth.signup.requests_per_minute', '6000'),
  ('ratelimit.auth.signup.burst', '1000'),
  ('ratelimit.tier.standard.requests_per_second', '1000'),
  ('ratelimit.tier.standard.requests_per_minute', '60000'),
  ('ratelimit.tier.standard.burst', '1000'),
  ('ratelimit.ip.requests_per_second', '1000'),
  ('ratelimit.ip.requests_per_minute', '60000'),
  ('ratelimit.ip.burst', '1000'),
  -- Features off by default whose routes would otherwise only ever answer "disabled".
  ('download.enabled', 'true'),
  ('notifications.webhooks_enabled', 'true'),
  ('policy.editor_enabled', 'true'),
  ('server.public_url', 'https://silo.conformance.test')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

INSERT INTO request_settings (id, requests_enabled, created_at, updated_at)
VALUES (true, true, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
ON CONFLICT (id) DO UPDATE SET requests_enabled = true;

-- Deliveries for the notification rows' success paths: fanout needs a scan and a release, and no request makes one.
-- The insert trigger stamps created_at, so an update pins it.
INSERT INTO notification_deliveries (id, user_id, profile_id, type, reason_flags, status, delivered_at) VALUES
  ('01JCONFNOTIFICATION0000001', 2, :'user_profile', 'webhook.auto_disabled', '{"webhook_id":"w1","webhook_name":"Conf hook","last_failure_status":410}', 'delivered', '2026-01-01T00:00:00Z'),
  ('01JCONFNOTIFICATION0000002', 2, :'user_profile', 'request.declined', '{"request_id":"r1","tmdb_id":1,"media_type":"movie","title":"Conf","poster_path":"tmdb://poster/conf.jpg","reason":"no"}', 'delivered', '2026-01-01T00:00:00Z'),
  ('01JCONFNOTIFICATION0000003', 1, :'admin_profile', 'webhook.auto_disabled', '{"webhook_id":"w2","webhook_name":"Admin hook","last_failure_status":410}', 'delivered', '2026-01-01T00:00:00Z'),
  ('01JCONFNOTIFICATION0000004', 1, :'admin_profile', 'request.declined', '{"request_id":"r2","tmdb_id":2,"media_type":"movie","title":"Conf 2","poster_path":"tmdb://poster/conf2.jpg","reason":"no"}', 'delivered', '2026-01-01T00:00:00Z');
UPDATE notification_deliveries SET created_at = '2026-01-02T00:00:00Z' WHERE id = '01JCONFNOTIFICATION0000001';
UPDATE notification_deliveries SET created_at = '2026-01-03T00:00:00Z' WHERE id = '01JCONFNOTIFICATION0000002';
UPDATE notification_deliveries SET created_at = '2026-01-02T00:00:00Z' WHERE id = '01JCONFNOTIFICATION0000003';
UPDATE notification_deliveries SET created_at = '2026-01-03T00:00:00Z' WHERE id = '01JCONFNOTIFICATION0000004';

-- Devices for the device rows' success paths: a sighting is throttled per process.
INSERT INTO user_devices (user_id, profile_id, device_id, device_name, device_platform, last_seen_at) VALUES
  (2, :'user_profile', 'conf-device-1', 'Conf One', 'ios', '2026-01-04T00:00:00Z'),
  (2, :'user_profile', 'conf-device-2', 'Conf Two', 'android', '2026-01-03T00:00:00Z'),
  (1, :'admin_profile', 'conf-admin-1', 'Admin One', 'ios', '2026-01-04T00:00:00Z'),
  (1, :'admin_profile', 'conf-admin-2', 'Admin Two', 'web', '2026-01-03T00:00:00Z');
INSERT INTO user_setting_values (user_id, key, scope, profile_id, device_id, value) VALUES
  (2, 'playback.buffering_quality_mode', 'profile_device', :'user_profile', 'conf-device-1', '"never"'),
  (1, 'playback.buffering_quality_mode', 'profile_device', :'admin_profile', 'conf-admin-1', '"never"');

COMMIT;

-- Requests and servers for the request rows' success paths: creating a request needs TMDB, and saving a server
-- needs its plugin. The servers stay disabled, so nothing submits to them.
INSERT INTO request_integrations (id, name, enabled, base_url, api_key_ref, capability_id, supported_media_types, plugin_config, updated_at) VALUES
  ('conf-radarr', 'Conf Radarr', false, 'http://radarr.invalid', 'conf-key', 'arr', '{movie}', '{"service_kind":"radarr","quality_profile_id":4}', '2026-01-01T00:00:00Z'),
  ('conf-sonarr', 'Conf Sonarr', false, 'http://sonarr.invalid', '', 'arr', '{series}', '{"service_kind":"sonarr","ratio":1.5}', '2026-01-01T00:00:00Z'),
  ('conf-drop-vone', 'Conf drop one', false, '', '', 'arr', '{}', '{}', '2026-01-01T00:00:00Z'),
  ('conf-drop-vtwo', 'Conf drop two', false, '', '', 'seerr', '{}', '{}', '2026-01-01T00:00:00Z');

INSERT INTO media_requests (id, media_type, tmdb_id, tvdb_id, imdb_id, title, year, overview, poster_path, backdrop_path, status, outcome, requested_by_user_id, requested_by_profile_id, last_error, outcome_reason, seasons, source, created_at, updated_at, approved_at, completed_at) VALUES
  ('conf-req-pending', 'movie', 9100001, NULL, 'tt9100001', 'Conf Pending', 2001, 'Waiting', '/p.jpg', '/b.jpg', 'pending', 'active', 2, :'user_profile', '', '', '{}', 'direct', '2020-01-01T00:00:01Z', '2020-01-01T00:00:01Z', NULL, NULL),
  ('conf-req-series', 'series', 9100002, 9100022, '', 'Conf Series', 2002, '', '', '', 'completed', 'active', 2, :'user_profile', '', '', '{1,2}', 'watchlist', '2020-01-01T00:00:02Z', '2020-01-01T00:00:02Z', '2020-01-02T00:00:00Z', '2020-01-03T00:00:00Z'),
  ('conf-req-cancel-vone', 'movie', 9100003, NULL, '', 'Conf Cancel One', NULL, '', '', '', 'pending', 'active', 2, :'user_profile', '', '', '{}', 'direct', '2020-01-01T00:00:03Z', '2020-01-01T00:00:03Z', NULL, NULL),
  ('conf-req-cancel-vtwo', 'movie', 9100004, NULL, '', 'Conf Cancel Two', NULL, '', '', '', 'pending', 'active', 2, :'user_profile', '', '', '{}', 'direct', '2020-01-01T00:00:04Z', '2020-01-01T00:00:04Z', NULL, NULL),
  ('conf-req-admin-vone', 'movie', 9100005, NULL, '', 'Conf Admin One', NULL, '', '', '', 'pending', 'active', 2, :'user_profile', '', '', '{}', 'direct', '2020-01-01T00:00:05Z', '2020-01-01T00:00:05Z', NULL, NULL),
  ('conf-req-admin-vtwo', 'movie', 9100006, NULL, '', 'Conf Admin Two', NULL, '', '', '', 'pending', 'active', 1, :'admin_profile', '', '', '{}', 'direct', '2020-01-01T00:00:06Z', '2020-01-01T00:00:06Z', NULL, NULL),
  ('conf-req-failed', 'movie', 9100007, NULL, '', 'Conf Failed 50%', NULL, '', '', '', 'approved', 'failed', 2, :'user_profile', 'server gone', '', '{}', 'direct', '2020-01-01T00:00:07Z', '2020-01-01T00:00:07Z', '2020-01-02T00:00:00Z', NULL),
  ('conf-req-declined', 'series', 9100008, NULL, '', 'Conf Declined', NULL, '', '', '', 'pending', 'declined', 2, :'user_profile', '', 'not now', '{}', 'direct', '2020-01-01T00:00:08Z', '2020-01-01T00:00:08Z', NULL, NULL),
  ('conf-req-queued', 'movie', 9100009, NULL, '', 'Conf Queued', NULL, '', '', '', 'downloading', 'active', 2, :'user_profile', '', '', '{}', 'direct', '2020-01-01T00:00:09Z', '2020-01-01T00:00:09Z', '2020-01-02T00:00:00Z', NULL);

INSERT INTO media_request_targets (id, request_id, integration_id, integration_kind, quality, external_id, external_status, status, last_error, route_name, download_phase, download_bytes_total, download_bytes_left, download_count, download_updated_at, created_at, updated_at) VALUES
  (9100001, 'conf-req-series', 'conf-sonarr', 'sonarr', '1080p', 'ext-1', 'done', 'completed', '', 'Everything else', NULL, NULL, NULL, NULL, NULL, '2020-01-02T00:00:00Z', '2020-01-02T00:00:00Z'),
  (9100002, 'conf-req-queued', 'conf-radarr', 'radarr', '1080p', 'ext-2', 'downloading', 'downloading', 'slow', 'Everything else', 'stalled', 1000, 250, 2, '2020-01-03T00:00:00Z', '2020-01-02T00:00:00Z', '2020-01-02T00:00:00Z'),
  (9100003, 'conf-req-queued', 'conf-radarr', 'radarr', '2160p', 'ext-3', 'queued', 'queued', '', '', 'queued', 4000, 4000, 1, '2020-01-02T00:00:00Z', '2020-01-02T00:00:00Z', '2020-01-02T00:00:00Z');

INSERT INTO media_request_events (request_id, event_type, actor_user_id, actor_profile_id, message, created_at) VALUES
  ('conf-req-pending', 'created', 2, :'user_profile', '', '2020-01-01T00:00:01Z'),
  ('conf-req-series', 'created', 2, :'user_profile', '', '2020-01-01T00:00:02Z'),
  ('conf-req-series', 'approved', NULL, '', 'auto approved', '2020-01-02T00:00:00Z');

INSERT INTO media_request_follows (request_id, media_type, tmdb_id, user_id, profile_id)
VALUES ('conf-req-pending', 'movie', 9100001, 2, :'user_profile');
