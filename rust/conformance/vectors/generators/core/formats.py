#!/usr/bin/env python3
"""Writes rust/parity/formats.json, the format-family denominator, and prints it as a table.

    python3 rust/conformance/vectors/generators/core/formats.py <gate log> [--check]

Commands assume the repository root is the cwd. Case counts come from the committed vectors, and each
direction's status comes from the log gate.sh wrote, so nothing here is typed in by hand except which
format each row covers.
"""

import collections
import json
import re
import sys
from pathlib import Path

VECTORS = Path("rust/conformance/vectors/core")
OUTPUT = Path("rust/parity/formats.json")

# id, what it is, vector family, selector within the family, owning Go package, Rust path, tier.
# A selector names the `fn` value in a family that holds several functions.
ROWS = [
    ("jwt.hs.semantics", "golang-jwt v5 parse and validation under Silo's verifier options", "jwt_semantics", None, "github.com/golang-jwt/jwt/v5", "silo-jwt", "signed"),
    ("jwt.rs256.chatgpt_identity", "RS256 identity token with issuer, audience, nonce, and required exp", "jwt_rs256", None, "internal/ai/chatgpt", "silo_core::tokens::verify_chatgpt_id_token", "signed"),
    ("jwt.es256.vapid", "VAPID Authorization header for web push", "jwt_vapid", None, "webpush-go", "silo_jwt::vapid_authorization_header", "signed"),
    ("token.access", "Access, refresh, plugin_access, apple_push_display, and direct_download_link JWTs", "token_access", None, "internal/auth", "silo_core::tokens", "signed"),
    ("token.stream", "Stream token and its 75 claim names", "token_stream", None, "internal/streamtoken", "silo_core::streamtoken", "signed"),
    ("token.profile", "X-Profile-Token, durable with no exp", "token_profile", None, "internal/access", "silo_core::tokens", "signed"),
    ("token.room", "Watch Together room token and socket proof", "token_room", None, "internal/watchtogether", "silo_core::tokens", "signed"),
    ("token.theme_grant", "Theme audio grant and its derived key", "token_theme_grant", None, "internal/themesongs", "silo_core::tokens", "signed"),
    ("token.abs", "Audiobookshelf access, refresh, and session JWTs", "token_abs", None, "internal/audiobooks/abs", "silo_core::tokens", "signed"),
    ("secret.enc_v1", "enc:v1 envelope, HKDF data key, AES-256-GCM, AAD binding", "secret_enc_v1", None, "internal/secret", "silo_core::secret", "persisted"),
    ("secret.read_contract", "Decrypt and DecryptIfEncrypted outcomes, including tampering and enc:vN", "secret_read_contract", None, "internal/secret", "silo_core::secret", "persisted"),
    ("secret.aad_strings", "All 31 AAD builders across the owning packages", "secret_aad_strings", None, "internal/secret and owners", "silo_core::secret::aad", "persisted"),
    ("secret.backfill_targets", "Credential columns swept by the startup backfill and their AAD expressions", "secret_backfill_targets", None, "internal/secret", "silo_core::secret", "persisted"),
    ("secret.plugin_instance_state", "empty:v1 marker and instance state wrapper", "secret_plugin_state", None, "internal/plugins", "silo_core::secret", "persisted"),
    ("secret.plugin_runtime_config", "__silo_encrypted_runtime_config_v1 wrapper, number text preserved", "secret_plugin_config", None, "internal/plugins", "silo_core::secret", "persisted"),
    ("oauth.completion_aead", "OAuth completion and pending-link AEAD", "oauth_completion_aead", None, "internal/auth", "silo_core::oauth::CompletionCipher", "persisted"),
    ("oauth.state", "Signed OAuth state and its derived secret", "oauth_state", None, "internal/auth", "silo_core::oauth", "signed"),
    ("oauth.state_verify", "VerifyState outcomes", "oauth_state_verify", None, "internal/auth", "silo_core::oauth", "signed"),
    ("contentid.provider", "movie, series, season, and episode IDs and precedence", "contentid_provider", None, "internal/contentid", "silo_core::contentid", "persisted"),
    ("contentid.local", "ForLocal, NFC with Go's tables and stream-safe limit", "contentid_local", None, "internal/contentid", "silo_core::contentid", "persisted"),
    ("contentid.transform_pack", "Series transform, arity rules, Pack, and Unpack of IDs", "contentid_codec", None, "internal/contentid", "silo_core::contentid", "persisted"),
    ("contentid.unpack_bytes", "Unpack of arbitrary bytes", "contentid_unpack", None, "internal/contentid", "silo_core::contentid", "persisted"),
    ("unicode.norm_tables", "Every code point's NFC, NFD, and CCC under Go's x/text tables", "unicode_norm_table", None, "golang.org/x/text/unicode/norm", "silo_core::contentid", "persisted"),
    ("fspath", "Encode, Decode, Display, and IsEncoded", "fspath", None, "internal/fspath", "silo_core::fspath", "persisted"),
    ("idgen.sonyflake_layout", "Compose, Decompose, and ToTime under Silo's settings", "sonyflake_compose", None, "internal/idgen", "silo_core::idgen", "persisted"),
    ("idgen.sonyflake_mint", "Monotonic minting across sequence overflow", "sonyflake_mint", None, "internal/idgen", "silo_core::idgen::Generator", "persisted"),
    ("lantls.pin", "HKDF P-256 key and SPKI pin", "lantls_pin", None, "internal/lantls", "silo_core::lantls", "signed"),
    ("nodeauth.sign", "Silo-Node-HMAC-SHA256 header, with node URL prefix handling", "nodeauth_sign", None, "internal/nodeauth", "silo_core::nodeauth", "signed"),
    ("nodeauth.verify", "Verification outcomes, skew, legacy bearer, and body hash", "nodeauth_verify", None, "internal/nodeauth", "silo_core::nodeauth", "signed"),
    ("artworkurl", "Artwork and job artifact capability URLs and windows", "artworkurl", None, "internal/artworkurl", "silo_core::artworkurl", "signed"),
    ("s3.presign", "Windowed SigV4 presigned read URL", "s3_presign", None, "internal/s3client", "silo_core::blobstore", "signed"),
    ("s3.cloudflare_token_url", "Cloudflare token URL", "persisted_hashes", "cloudflare_url", "internal/s3client", "silo_core::digest", "signed"),
    ("s3.delivery_scope", "ArtworkDeliveryScope", "persisted_hashes", "delivery_scope", "internal/s3client", "silo_core::digest", "persisted"),
    ("s3.object_sha256", "silo-sha256 metadata and other plain hex digests", "credential_hashes", "plain_sha256_hex", "internal/s3client", "silo_core::digest", "persisted"),
    ("blobstore.keys_identity", "ValidateKey, NormalizeEndpoint, key prefixing", "blobstore_keys", None, "internal/blobstore", "silo_core::blobstore", "persisted"),
    ("webhook.signature", "X-Silo-Signature", "persisted_hashes", "webhook_signature", "internal/notifications", "silo_core::digest", "signed"),
    ("apiv2.etag", "RenderETag", "apiv2_etag", None, "internal/apiv2", "silo_core::apiv2", "signed"),
    ("apiv2.etag_list", "ParseETagList grammar", "apiv2_etag_list", None, "internal/apiv2", "silo_core::apiv2", "signed"),
    ("apiv2.cursor", "Cursor encoding", "apiv2_cursor", None, "internal/apiv2", "silo_core::apiv2", "signed"),
    ("apiv2.cursor_decode", "Cursor decoding, including forged shapes", "apiv2_cursor_decode", None, "internal/apiv2", "silo_core::apiv2", "signed"),
    ("apiv2.viewer_scope_digest", "viewerScopeDigest", "apiv2_viewer_scope_digest", None, "internal/apiv2", "silo_core::apiv2", "signed"),
    ("playback.direct_play_etag", "dsr1 validator on real files, Darwin", "playback_directplay_etag", None, "internal/playback", "silo_core::playback", "signed"),
    ("playback.direct_play_etag_linux", "dsr1 validator on real files, Linux", "playback_directplay_etag_linux", None, "internal/playback", "silo_core::playback", "signed"),
    ("playback.plan_identity", "Plan ID and attempt key", "playback_plan_identity", None, "internal/playback", "silo_core::playback", "persisted"),
    ("playback.stop_id.expired", "silo-expired stop ID", "credential_hashes", "expired_stop_id", "internal/api/handlers", "silo_core::playback", "persisted"),
    ("playback.stop_id.abort", "silo-abort stop ID", "credential_hashes", "abort_stop_id", "internal/api/handlers", "silo_core::playback", "persisted"),
    ("playback.stop_id.admin", "silo-admin-stop stop ID", "credential_hashes", "admin_stop_id", "internal/api/handlers", "silo_core::playback", "persisted"),
    ("playback.connection_key", "Connection key, IPv6 masked to /64", "playback_connection_key", None, "internal/playback/connectionstore", "silo_core::playback", "persisted"),
    ("playback.keyframe_plan", "PlanSegments, SegmentDurations, keyframe-plan.json", "keyframe_plan", None, "internal/playback/keyframes", "silo_core::keyframes", "persisted"),
    ("nodes.session_hash", "nodeHash in session keys", "credential_hashes", "node_hash", "internal/nodesessions", "silo_core::playback", "persisted"),
    ("nodes.recipe_digest", "Recipe digest", "credential_hashes", "node_recipe_digest", "internal/noderecipe", "silo_core::playback", "persisted"),
    ("downloads.params_hash", "Prepared-download params hash", "downloads_params_hash", None, "internal/downloads", "silo_core::downloads", "persisted"),
    ("downloads.metadata_etag", "Offline MetadataETag", "downloads_metadata_etag", None, "internal/downloads", "silo_core::downloads", "persisted"),
    ("downloads.execution_fingerprint", "Execution fingerprint and the Request JSON behind it", "downloads_execution_fingerprint", None, "internal/downloadprepare", "silo_core::downloads", "persisted"),
    ("tonemap.source_revision", "SourceRevision fingerprint and encoding", "tonemap_revision", None, "internal/tonemap", "silo_core::downloads", "persisted"),
    ("auth.api_key", "sa_ bearer, key_hash, and key_prefix", "api_key", None, "internal/auth", "silo_core::apikey", "persisted"),
    ("auth.api_key_valid_text", "ValidTextKey", "api_key_valid_text", None, "internal/auth", "silo_core::apikey", "persisted"),
    ("auth.bcrypt_hash", "bcrypt $2a$ generation, byte-equal under the same salt", "bcrypt_generate", None, "internal/auth/passwordhash", "silo_core::passwordhash", "persisted"),
    ("auth.bcrypt_compare", "CompareHashAndPassword and its parsing quirks", "bcrypt_compare", None, "golang.org/x/crypto/bcrypt", "silo_core::passwordhash", "persisted"),
    ("auth.link_token_hash", "HashLinkToken", "credential_hashes", "hash_link_token", "internal/auth", "silo_core::apikey", "persisted"),
    ("auth.device_login_hash", "hashDeviceLoginSecret", "credential_hashes", "hash_device_login_secret", "internal/auth", "silo_core::apikey", "persisted"),
    ("auth.user_code_normalize", "normalizeUserCode", "credential_hashes", "normalize_user_code", "internal/auth", "silo_core::apikey", "persisted"),
    ("auth.user_code_format", "formatUserCode", "credential_hashes", "format_user_code", "internal/auth", "silo_core::apikey", "persisted"),
    ("auth.quick_connect_code", "QuickConnectCode", "credential_hashes", "quick_connect_code", "internal/auth", "silo_core::apikey", "persisted"),
    ("auth.quick_connect_session", "quickConnectSessionToken", "credential_hashes", "quick_connect_session_token", "internal/jellycompat", "silo_core::apikey", "persisted"),
    ("auth.sign_in_attempt_key", "signInAttemptKey", "credential_hashes", "sign_in_attempt_key", "internal/auth", "silo_core::apikey", "persisted"),
    ("auth.minted_shapes", "Generated API key, user code, Quick Connect secret, link token, jwt_secret", "minted_credentials", None, "internal/auth, cmd/silo", "silo_core::apikey", "persisted"),
    ("oauth.binder_hash", "oauthBinderHash", "credential_hashes", "binder_hash", "internal/auth", "silo_core::oauth", "persisted"),
    ("oauth.binder_cookie_name", "silo_oauth_<hash> cookie name", "credential_hashes", "binder_cookie_name", "internal/auth", "silo_core::oauth", "signed"),
    ("oauth.pkce", "PKCEChallengeS256", "credential_hashes", "pkce_challenge", "internal/auth", "silo_core::oauth", "signed"),
    ("oauth.completion_code_hash", "oauthCompletionCodeHash", "credential_hashes", "completion_code_hash", "internal/auth", "silo_core::oauth", "persisted"),
    ("push.apns_token_hash", "apnsTokenHash", "credential_hashes", "apns_token_hash", "internal/notifications", "silo_core::apikey", "persisted"),
    ("push.fcm_token_hash", "fcmTokenHash", "credential_hashes", "fcm_token_hash", "internal/notifications", "silo_core::apikey", "persisted"),
    ("push.intent_hash", "Apple and Android intent_hash, installation_key_hash", "push_intent", None, "internal/notifications", "silo_core::apikey", "persisted"),
    ("notifications.email_token_hash", "hashEmailToken", "credential_hashes", "hash_email_token", "internal/notifications", "silo_core::apikey", "persisted"),
    ("autoscan.webhook_token_hash", "hashWebhookToken", "credential_hashes", "hash_webhook_token", "internal/autoscan", "silo_core::apikey", "persisted"),
    ("abs.token_hash", "absTokenHash", "credential_hashes", "abs_token_hash", "internal/audiobooks", "silo_core::apikey", "persisted"),
    ("jellycompat.ids", "Numeric, packed, and hashed IDs, PseudoUserID, and decode order", "jellycompat_ids", None, "internal/jellycompat", "silo_core::jellycompat", "persisted"),
    ("jellycompat.uuid_parse", "uuid.Parse input forms", "uuid_parse", None, "github.com/google/uuid", "silo_core::goid", "persisted"),
    ("jellycompat.image_tags", "Signed image tag, its seed, and collage tag", "jellycompat_image_tags", None, "internal/jellycompat", "silo_core::jellycompat", "signed"),
    ("jellycompat.tag_value", "Unsigned fallback tag", "credential_hashes", "tag_value", "internal/jellycompat", "silo_core::jellycompat", "persisted"),
    ("jellycompat.canonical_image_tag", "Proxy tag suffix", "credential_hashes", "canonical_image_tag", "internal/jellycompat", "silo_core::jellycompat", "persisted"),
    ("identity.uuid_v5", "NameSpaceOID and NameSpaceURL IDs, default jellyfin_compat.server_id", "uuid_v5_ids", None, "cmd/silo, internal/config", "silo_core::goid", "persisted"),
    ("artwork.key_layout", "artworkkey Build, Variant, OriginalOf, Revision, ladder", "artworkkey", None, "internal/artworkkey", "silo_core::artworkkey", "persisted"),
    ("artwork.base_path", "buildBasePath and normalizeImageLanguage", "artwork_base_path", None, "internal/imagecache", "silo_core::artworkkey", "persisted"),
    ("artwork.variant_revision", "variantRevision", "persisted_hashes", "variant_revision", "internal/imagecache", "silo_core::digest", "persisted"),
    ("artwork.uploaded_source", "upload://sha256 source string", "persisted_hashes", "uploaded_source", "internal/metadata", "silo_core::digest", "persisted"),
    ("artwork.thumbhash", "Thumbhash after decode, amd64", "thumbhash", None, "internal/imageutil, go.n16f.net/thumbhash", "silo_core::thumbhash", "persisted"),
    ("catalog.collage_key", "CollectionCollageKey", "persisted_hashes", "collection_collage_key", "internal/catalog", "silo_core::digest", "persisted"),
    ("catalog.smart_definition_key", "smartDefinitionKey", "credential_hashes", "smart_definition_key", "internal/catalog", "silo_core::digest", "persisted"),
    ("catalog.meili_schema_version", "Meilisearch schema version", "persisted_hashes", "meili_schema_version", "internal/catalog", "silo_core::digest", "persisted"),
    ("catalog.search_fold", "foldSearchDiacritics", "search_fold", None, "internal/catalog", "silo_core::searchfold", "persisted"),
    ("metadata.sidecar_entry", "Sidecar entry key", "persisted_hashes", "sidecar_entry", "internal/metadata", "silo_core::digest", "persisted"),
    ("metadata.sidecar_fingerprint", "hashSidecarEntries", "persisted_hashes", "sidecar_hash", "internal/metadata", "silo_core::digest", "persisted"),
    ("metadata.translation_key", "Translation idempotency key", "persisted_hashes", "translation_idempotency", "internal/metadata/translation", "silo_core::digest", "persisted"),
    ("metadata.translation_key_legacy", "Legacy translation idempotency key", "persisted_hashes", "translation_legacy", "internal/metadata/translation", "silo_core::digest", "persisted"),
    ("literary.work_id", "generatedWorkID", "persisted_hashes", "generated_work_id", "internal/literaryworks", "silo_core::digest", "persisted"),
    ("mediaartifact.config_hash", "ConfigHash", "persisted_hashes", "media_artifact_config_hash", "internal/mediaartifact", "silo_core::digest", "persisted"),
    ("ebook.cache_key", "SourceKey hash", "persisted_hashes", "ebook_cache_key", "internal/ebookconvert", "silo_core::digest", "persisted"),
    ("ebook.module_version", "mobitool.wasm fingerprint", "persisted_hashes", "ebook_module_version", "internal/ebookconvert", "tests/support", "persisted"),
    ("models.marker_identity", "MarkerFileIdentity and MarkerThumbnailIdentity", "marker_identity", None, "internal/models", "silo_core::digest", "persisted"),
    ("scanner.oshash", "ComputeOSHash on real files", "oshash", None, "internal/scanner", "silo_core::digest", "persisted"),
    ("inline.expressions", "Chapter lock, setting mutation lock, daily mix score, local artwork discriminator, chapter thumbnail key", "inline_hash_expressions", None, "cited in the vector's source field", "silo_core::digest", "persisted"),
    ("naming.content_group_key", "makeContentGroupKey and normalizeGroupComparable", "naming_group_key", None, "internal/naming", "silo_core::naming", "persisted"),
    ("naming.presentation_group", "normalizePresentationGroup", "naming_presentation_group", None, "internal/naming", "silo_core::naming", "persisted"),
    ("recommendations.embedding_text", "BuildEmbeddingText", "embedding_text", None, "internal/recommendations/embeddings", "silo_core::embeddings", "persisted"),
    ("recommendations.rotation_uniform", "rotationUniform", "persisted_hashes", "rotation_uniform", "internal/recommendations", "silo_core::digest", "persisted"),
    ("sections.rotation_index", "RotationIndex and bucketTime", "persisted_hashes", "rotation_index", "internal/sections/recipes", "silo_core::digest", "persisted"),
    ("locks.local_sidecar", "localSidecarLockKey", "persisted_hashes", "local_sidecar_lock", "internal/metadata", "silo_core::digest", "mixed-fleet"),
    ("locks.profile_refresh", "profileRefreshLock", "persisted_hashes", "profile_refresh_lock", "internal/recommendations", "silo_core::digest", "mixed-fleet"),
    ("locks.library_refresh", "libraryRefreshLockKey", "persisted_hashes", "library_refresh_lock", "internal/adminjob", "silo_core::digest", "mixed-fleet"),
    ("locks.constants", "Every fixed advisory lock integer", "advisory_lock_constants", None, "42 sites in internal", "silo_core::advisory_locks", "mixed-fleet"),
    ("redis.channels_events", "Channel names with @dbN, event JSON, attempt key, search session prefix", "redis_channels_events", None, "internal/cache, ratelimit, catalog", "silo_core::redis", "mixed-fleet"),
    ("redis.lua_and_prefixes", "Lua script hashes and key prefixes", "redis_contract", None, "owning packages", "silo_core::{redis, redis_lua}", "mixed-fleet"),
    ("settings.jcs", "Canonical JSON with notes stripped for the public projection", "settings_jcs", None, "internal/settingscontract", "silo_core::jcs", "persisted"),
    ("settings.ecmascript_number", "formatECMAScript", "settings_ecmascript_number", None, "internal/settingscontract", "silo_core::jcs", "persisted"),
    ("settings.etag_digest", "digestWithSchemas", "settings_etag_digest", None, "internal/settingscontract", "silo_core::jcs", "persisted"),
    ("settings.contract_etag", "ETag and PublicETag of the real contract files", "settings_contract_etag", None, "internal/settingscontract", "silo_core::jcs", "persisted"),
    ("frontend.content_etag", "contentETag", "credential_hashes", "frontend_content_etag", "internal/server", "silo_core::digest", "persisted"),
]

# Families whose input is a single fixed thing, so a count of 500 cannot apply: real files or one table.
FIXED_INPUT = {
    "unicode_norm_table": "exhaustive over every code point",
    "sonyflake_mint": "20 runs of 600 IDs each",
    "advisory_lock_constants": "every constant, read from the Go source on both sides",
    "redis_contract": "every script hash and key prefix",
    "settings_contract_etag": "the real contract files",
    "secret_backfill_targets": "the one fixed list",
}

# Formats in the maps that this table deliberately does not hold, and why.
NOT_IN_DENOMINATOR = [
    {"name": "Naming parser output (provider tags, season and episode numbers)", "reason": "A parser, not a format. The IDs it feeds are contentid.provider. The plan's M7 gate covers it with real path lists.", "owner": "silo-store"},
    {"name": "Language tag canonicalization (internal/lang)", "reason": "Not ported. It needs x/text language tables frozen from Go, and contracts/language-canonicalization.json is its oracle. It feeds a stored tag, so it needs a family when ported.", "owner": "silo-core, not yet"},
    {"name": "k-means seed and Go math/rand sequences", "reason": "Map tier OPTIONAL: results persist but nothing compares them, and recomputation converges.", "owner": "silo-discovery"},
    {"name": "Match queue input_fingerprint", "reason": "Built by SQL md5 in Postgres. The SQL text and the matcher revision constants move with the query.", "owner": "silo-ingest"},
    {"name": "Embedding canonical text's SQL copy", "reason": "A SQL query in recommendations/repo.go; the Go function is recommendations.embedding_text.", "owner": "silo-discovery"},
    {"name": "Redis values: RecipeCard, SessionInfo, SocketIdentity, and ticket payload JSON", "reason": "Value schemas owned by the crates that write them. Keys and scripts are redis.*.", "owner": "silo-playback, silo-notify"},
    {"name": "jsonb columns: TriggerConfig, room runtime, QueryDefinition, and others", "reason": "jsonb normalizes bytes, so only field names and shapes matter. Row digests in the conformance harness cover them.", "owner": "owning crates"},
    {"name": "Thumbhash's libvips stage", "reason": "Needs libvips. artwork.thumbhash covers everything after the decode.", "owner": "silo-ingest"},
    {"name": "WebP bytes, HLS playlists, FFmpeg argv, net/http behaviour, error bodies, socket frames, plugin protocol", "reason": "Wire behaviour counted by the row surfaces, not persisted or signed formats.", "owner": "owning crates"},
    {"name": "Web push aes128gcm body framing", "reason": "Wire format, randomized per message, with no persisted form. VAPID signing is jwt.es256.vapid.", "owner": "silo-notify"},
]

# Hash and HMAC sites found by grep that the maps did not list. They are not in the denominator yet.
DISCOVERED = [
    "internal/subtitles/manager.go:297,316 subtitle content hash",
    "internal/subtitles/ai/job.go:101 subtitle AI job key",
    "internal/subtitles/sync_key.go:25 subtitle sync key",
    "internal/playback/subtitle_cache.go:427 subtitle cache key",
    "internal/playback/directplay.go:283 direct-play validator digest",
    "internal/playback/capabilityhash.go:41 capability hash",
    "internal/markers/population.go:602, contribution_repo.go:77",
    "internal/intromarkers/*.go config and fingerprint hashes",
    "internal/jellycompat/handlers_auth.go:464,466, handlers_items.go:1003, handlers_recommendations.go:348, handlers_playback.go:3085, deviceprofile_limits.go:46, playback_sessions_postgres.go:84",
    "internal/api/handlers/playback.go:1389, playback_service.go:208,831, playback_v3.go:2234,5145, settings_values.go:900",
    "internal/apiv2/admin_settings_write.go:32 settings mutation HMAC, capability_response.go:106, download_subscriptions.go:56, ebook_config.go:64, ebook_annotations.go:138",
    "internal/notifications/relay_credentials.go:123,130",
    "internal/streamtelemetry/bounds.go:39, store_redis.go:46, global.go:618",
    "internal/watchsync/ratelimit.go:110, internal/progresssync/service.go:59, internal/ai/chatgpt/service.go:223",
    "internal/policy/decisionlog.go:423 input_digest",
    "internal/branding/service.go:120, internal/diagnostics/bundle.go:537, internal/database/queryattr/shape.go:34",
    "internal/userdb/bridgeimport/*.go table digests",
    "internal/watchtogether/suggestion_receipt.go:36",
]


def counts(family, selector):
    data = json.loads((VECTORS / f"{family}.json").read_text())
    if selector is None:
        return len(data["cases"])
    return sum(1 for case in data["cases"] if case["in"].get("fn") == selector)


def verified_families(log_text):
    """Reads gate.sh's log: which families each direction passed."""
    go_to_rust = "GATE go_to_rust ok" in log_text
    rust_to_go = set(re.findall(r"^verify (\S+)\s+\d+ cases, ok$", log_text, re.M))
    linux = "GATE directplay_linux ok" in log_text
    return go_to_rust, rust_to_go, linux


def main():
    log_text = Path(sys.argv[1]).read_text()
    go_to_rust, rust_to_go, linux = verified_families(log_text)
    deterministic = set(re.findall(r"^DET (\S+)$", log_text, re.M))
    pg = "GATE conformance_pg ok" in log_text

    rows = []
    failures = []
    for row_id, what, family, selector, go_source, rust_path, tier in ROWS:
        cases = counts(family, selector)
        is_det = family in deterministic or family == "playback_directplay_etag_linux"
        randomized = not is_det
        if family == "playback_directplay_etag_linux":
            g2r, r2g = linux, "GATE directplay_linux_rust ok" in log_text
        else:
            g2r, r2g = go_to_rust, family in rust_to_go
        min_ok = randomized or family in FIXED_INPUT or cases >= 500
        if family == "secret_aad_strings":
            min_ok = cases >= 500
        status = "verified" if g2r and r2g and min_ok else "failed"
        if status != "verified":
            failures.append(row_id)
        rows.append(
            {
                "id": row_id,
                "format": what,
                "tier": tier,
                "go_source": go_source,
                "rust": rust_path,
                "vector_family": family,
                "selector": selector,
                "cases": cases,
                "deterministic_byte_equal": not randomized,
                "go_to_rust": g2r,
                "rust_to_go": r2g,
                "note": FIXED_INPUT.get(family),
                "status": status,
            }
        )

    report = {
        "source": "rust/conformance/vectors/generators/core/formats.py",
        "denominator": len(rows),
        "verified": sum(1 for r in rows if r["status"] == "verified"),
        "real_stack": {
            "enc_v1_rows_decrypted": pg,
            "go_server_accepted_rust_token": pg,
            "served_lan_pin_matches": pg,
        },
        "families": rows,
        "not_in_denominator": NOT_IN_DENOMINATOR,
        "discovered_not_in_maps": DISCOVERED,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n")

    tiers = collections.Counter(r["tier"] for r in rows)
    print(f"{'family':<36} {'tier':<12} {'cases':>6}  det  G>R  R>G  status")
    for r in rows:
        print(
            f"{r['id']:<36} {r['tier']:<12} {r['cases']:>6}  "
            f"{'yes' if r['deterministic_byte_equal'] else 'no ':<3}  "
            f"{'ok ' if r['go_to_rust'] else 'NO '}  {'ok ' if r['rust_to_go'] else '-  '}  {r['status']}"
        )
    print(f"\n{report['verified']}/{report['denominator']} verified; tiers {dict(tiers)}; real stack: {pg}")
    if failures:
        print("FAILED:", ", ".join(failures))
        sys.exit(1)


main()
