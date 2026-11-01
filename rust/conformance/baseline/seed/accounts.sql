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

COMMIT;
