//! The smaller persisted hashes and lock keys, each named after the Go function it ports. A mismatch in
//! most of these triggers a rebuild rather than data loss; advisory lock keys only matter while Go and
//! Rust share a database, but then they decide mutual exclusion.

use silo_gocompat::json::{self, RawMessage};
use silo_gocompat::strings::{self, to_lower, trim_space};
use silo_gocompat::unicode::{is_digit, is_letter, is_number};
use silo_gocompat::url::query_escape;

use crate::hexgo::{encode as hex_encode, fnv32a, fnv64a, hmac_sha256, sha256, sha256_hex};
use crate::models::{MarkerFile, MarkerSegment};

/// `catalog.CollectionCollageKey`.
pub fn collection_collage_key(sources: &[String]) -> String {
    let mut preimage = b"collage-v1".to_vec();
    for source in sources {
        preimage.push(0);
        preimage.extend_from_slice(source.as_bytes());
    }
    hex_encode(&sha256(preimage)[..8])
}

/// `catalog.smartDefinitionKey` and `shortHash`.
pub fn smart_definition_key(query_definition: &[u8]) -> String {
    hex_encode(&sha256(query_definition)[..8])
}

/// `mediaartifact.ConfigHash`.
pub fn media_artifact_config_hash(kind: &str, params: &str) -> String {
    sha256_hex(format!("{kind}:{params}"))[..16].to_owned()
}

/// The object key `chapterthumbs.uploadThumbnail` writes.
pub fn chapter_thumbnail_key(
    prefix: &str,
    file_id: i64,
    identity: &str,
    data: &[u8],
    width: i64,
) -> String {
    format!(
        "{prefix}{file_id}/{identity}-{}/w{width}.webp",
        sha256_hex(data)
    )
}

/// `translation.idempotencyKey`.
pub fn translation_idempotency_key(
    kind: &str,
    content_id: &str,
    target_lang: &str,
    model: &str,
    include_children: bool,
    force: bool,
) -> String {
    sha256_hex(format!(
        "{kind}|{content_id}|{target_lang}|{model}|{include_children}|{force}"
    ))
}

/// `translation.legacyIdempotencyKey`.
pub fn translation_legacy_idempotency_key(
    kind: &str,
    content_id: &str,
    target_lang: &str,
    model: &str,
) -> String {
    sha256_hex(format!("{kind}|{content_id}|{target_lang}|{model}"))
}

/// `literaryworks.normalizeKey`.
fn literary_normalize_key(value: &str) -> String {
    let value = to_lower(trim_space(value));
    let mut out = String::with_capacity(value.len());
    let mut last_space = true;
    for c in value.chars() {
        if is_letter(c as u32) || is_digit(c as u32) {
            out.push(c);
            last_space = false;
            continue;
        }
        if !last_space {
            out.push(' ');
            last_space = true;
        }
    }
    strings::fields(&out)
        .into_iter()
        .filter(|part| !matches!(*part, "a" | "an" | "the"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `literaryworks.generatedWorkID`.
pub fn generated_work_id(title: &str, authors: &[String]) -> String {
    let title = literary_normalize_key(title);
    let author = authors
        .iter()
        .map(|name| literary_normalize_key(name))
        .find(|key| !key.is_empty())
        .unwrap_or_default();
    format!("work-{}", &sha256_hex(format!("{title}|{author}"))[..16])
}

/// `metadata.sidecarEntryKey`.
pub fn sidecar_entry_key(name: &str, size: i64, mod_time_nanos: i64) -> String {
    format!("{name}\0{size}\0{mod_time_nanos}")
}

/// `metadata.hashSidecarEntries`: sorted, compacted, joined with newlines.
pub fn hash_sidecar_entries(entries: &[String]) -> String {
    let mut sorted: Vec<&[u8]> = entries.iter().map(|e| e.as_bytes()).collect();
    sorted.sort();
    sorted.dedup();
    sha256_hex(sorted.join(&b'\n'))
}

/// `imagecache.variantRevision`, over `(key, data)` pairs.
pub fn variant_revision(ext: &str, variants: &[(String, Vec<u8>)]) -> String {
    let mut sorted: Vec<&(String, Vec<u8>)> = variants.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut preimage = b"silo-artwork-v1\0".to_vec();
    preimage.extend_from_slice(ext.as_bytes());
    preimage.push(0);
    for (key, data) in sorted {
        preimage.extend_from_slice(key.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&(data.len() as u64).to_be_bytes());
        preimage.extend_from_slice(data);
    }
    sha256_hex(preimage)
}

/// The key discriminator of cached local artwork. Item backdrops also hash the sidecar's own path.
pub fn local_artwork_discriminator(data: &[u8], item_backdrop_path: Option<&str>) -> String {
    let mut out = hex_encode(&sha256(data)[..4]);
    if let Some(path) = item_backdrop_path {
        out.push('-');
        out.push_str(&hex_encode(&sha256(path)[..4]));
    }
    out
}

/// `metadata.uploaded_artwork`'s source string.
pub fn uploaded_image_source(data: &[u8]) -> String {
    format!("upload://sha256:{}", sha256_hex(data))
}

/// `catalog.NormalizeCatalogSearchEmbedderName`, falling back to the default on an invalid name as
/// `catalogSearchMeilisearchSchemaVersion` does.
fn meili_embedder_name(value: &str) -> String {
    const DEFAULT: &str = "silo_recommendations";
    let value = trim_space(value);
    if value.is_empty() || value.len() > 128 {
        return DEFAULT.to_owned();
    }
    let valid = value
        .chars()
        .all(|c| is_letter(c as u32) || is_number(c as u32) || c == '_' || c == '-');
    if valid {
        value.to_owned()
    } else {
        DEFAULT.to_owned()
    }
}

/// `catalog.catalogSearchMeilisearchSchemaVersion`.
pub fn meilisearch_schema_version(
    embedder: &str,
    item_types: &[String],
    semantic_enabled: bool,
    binary_quantized: bool,
) -> i64 {
    const SCHEMA_VERSION: i64 = 3;
    const DIMENSIONS: i64 = 3072;
    let mut seen = std::collections::HashSet::new();
    let mut types = Vec::new();
    for item_type in item_types {
        let lowered = to_lower(trim_space(item_type));
        if !lowered.is_empty() && seen.insert(lowered.clone()) {
            types.push(lowered);
        }
    }
    let mut identity = format!(
        "embedder={};dimensions={DIMENSIONS};index_types={};semantic={semantic_enabled}",
        meili_embedder_name(embedder),
        types.join(",")
    );
    if semantic_enabled && binary_quantized {
        identity.push_str(";binary_quantized=true");
    }
    SCHEMA_VERSION * 1_000_000 + i64::from(fnv32a(identity) % 1_000_000)
}

/// `metadata.localSidecarLockKey`.
pub fn local_sidecar_lock_key(folder_id: i64, content_id: &str) -> i64 {
    fnv64a(format!("local_sidecar:{folder_id}:{content_id}")) as i64
}

/// `recommendations.profileRefreshLock`.
pub fn profile_refresh_lock(user_id: i64, profile_id: &str) -> i64 {
    fnv64a(format!("silo-recs-profile-refresh:{user_id}:{profile_id}")) as i64
}

/// `scanner.TryLockChapterThumbnails`' key.
pub fn chapter_thumbnails_lock_key(file_id: i64) -> i64 {
    let digest = sha256(format!("silo-chapter-thumbnails:{file_id}"));
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) as i64
}

/// `pgstore.SettingMutationTx`'s second advisory key.
pub fn setting_mutation_lock(user_id: i64, mutation_id: &str) -> i32 {
    fnv32a(format!("{user_id}\0{mutation_id}")) as i32
}

/// `adminjob.libraryRefreshLockKey`.
pub fn library_refresh_lock_key(library_id: i64) -> i64 {
    crate::advisory_locks::LIBRARY_REFRESH_NAMESPACE << 32 | i64::from(library_id as u32)
}

/// `sections.daily_mix`'s per-item score.
pub fn daily_mix_score(key: &str, day: i64, content_id: &str) -> u64 {
    let digest = sha256(format!("{key}|{day}|{content_id}"));
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

/// `recipes.bucketTime` for a UTC instant.
pub fn bucket_time(unix_utc: i64, cadence_days: i64) -> i64 {
    if cadence_days <= 1 {
        return unix_utc / 86400;
    }
    let (year, month, _) = silo_gocompat::time::GoTime::from_unix(unix_utc, 0).date();
    if cadence_days >= 28 {
        return year * 100 + i64::from(month);
    }
    let (iso_year, week) = iso_week(unix_utc);
    iso_year * 100 + week
}

/// `Time.ISOWeek` for a UTC instant.
fn iso_week(unix_utc: i64) -> (i64, i64) {
    let days = unix_utc.div_euclid(86400);
    // 1970-01-01 was a Thursday. The ISO year of a date is the calendar year of its week's Thursday.
    let weekday_from_monday = (days + 3).rem_euclid(7);
    let thursday = days - weekday_from_monday + 3;
    let (year, _, _) = silo_gocompat::time::GoTime::from_unix(thursday * 86400, 0).date();
    let first_day = days_from_civil(year, 1, 1);
    (year, (thursday - first_day) / 7 + 1)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `recipes.RotationIndex`.
pub fn rotation_index(unix_utc: i64, key: &str, count: i64, cadence_days: i64) -> i64 {
    if count <= 0 {
        return 0;
    }
    let bucket = bucket_time(unix_utc, cadence_days);
    (fnv64a(format!("{key}|{bucket}")) % count as u64) as i64
}

/// `recommendations.rotationUniform`.
pub fn rotation_uniform(seed_key: &str, day: &str, item_id: &str) -> f64 {
    let digest = sha256(format!("{seed_key}|{day}|{item_id}"));
    let bits = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) >> 11;
    (bits as f64 + 0.5) / 9_007_199_254_740_992.0
}

/// `models.MarkerFileIdentity`.
pub fn marker_file_identity(file: &MarkerFile) -> String {
    let modified: RawMessage = match &file.modified_at {
        None => RawMessage::from("null"),
        Some(text) => RawMessage::from(format!("\"{text}\"")),
    };
    let identity = (
        file.id,
        &file.file_hash,
        file.file_size,
        modified,
        file.duration,
        &file.content_id,
        &file.episode_id,
        &file.extra_id,
        file.season_number,
        file.episode_number,
    );
    sha256_hex(json::marshal(&identity).unwrap_or_default())
}

/// `models.MarkerThumbnailIdentity`.
pub fn marker_thumbnail_identity(file: &MarkerFile, segment: &MarkerSegment) -> String {
    let value = (marker_file_identity(file), &file.file_path, segment);
    sha256_hex(json::marshal(&value).unwrap_or_default())
}

/// `notifications.SignGenericWebhook`: `t=<epoch>,v1=<hex hmac of "<epoch>.<body>">`.
pub fn sign_generic_webhook(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mac = hmac_sha256(secret, &[timestamp.to_string().as_bytes(), b".", body]);
    format!("t={timestamp},v1={}", hex_encode(mac))
}

/// `s3client.cloudflareTokenURL`.
pub fn cloudflare_token_url(
    public_endpoint: &str,
    token_param: &str,
    token_secret: &str,
    key: &str,
    issued_unix: i64,
) -> String {
    let path = format!("/{key}");
    let ts = issued_unix.to_string();
    let mac = hmac_sha256(token_secret.as_bytes(), &[path.as_bytes(), ts.as_bytes()]);
    let token = silo_jwt::base64go::std_encode(mac);
    format!(
        "{}{path}?{token_param}={ts}-{}",
        public_endpoint.trim_end_matches('/'),
        query_escape(token)
    )
}

/// `s3client.ArtworkDeliveryScope`.
pub fn artwork_delivery_scope(
    endpoint: &str,
    bucket: &str,
    key_prefix: &str,
    public_endpoint: &str,
    url_auth: &str,
    token_param: &str,
) -> String {
    sha256_hex(
        [
            endpoint,
            bucket,
            key_prefix,
            public_endpoint,
            url_auth,
            token_param,
        ]
        .join("\0"),
    )
}

/// The `silo-sha256` object metadata value.
pub fn object_sha256(data: &[u8]) -> String {
    sha256_hex(data)
}

/// `server.contentETag`.
pub fn frontend_content_etag(data: &[u8]) -> String {
    format!("\"{}\"", hex_encode(&sha256(data)[..16]))
}

/// `ebookconvert.SourceKey.hash`. `module_version` is the first 16 hex digits of the wasm's SHA-256.
pub fn ebook_cache_key(
    module_version: &str,
    file_id: i64,
    size: i64,
    mod_time_nanos: i64,
    checksum: &str,
) -> String {
    sha256_hex(format!(
        "v1|mod={module_version}|id={file_id}|sz={size}|mt={mod_time_nanos}|ck={checksum}"
    ))
}

/// The manifest checksum of a plugin binary.
pub fn plugin_binary_checksum(data: &[u8]) -> String {
    sha256_hex(data)
}

/// `scanner.ComputeOSHash` over the first and last 64 KiB and the file size. Shorter files are an
/// error in Go, so the caller checks for that.
pub fn oshash(head: &[u8; 65536], tail: &[u8; 65536], file_size: i64) -> String {
    let sum_block = |buf: &[u8; 65536]| -> u64 {
        buf.as_chunks::<8>().0.iter().fold(0u64, |acc, word| {
            acc.wrapping_add(u64::from_le_bytes(*word))
        })
    };
    let hash = sum_block(head)
        .wrapping_add(sum_block(tail))
        .wrapping_add(file_size as u64);
    format!("{hash:016x}")
}
