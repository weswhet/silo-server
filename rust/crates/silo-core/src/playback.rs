//! `internal/playback`: the identities that name output directories and validators that clients hold
//! across a cutover.

use silo_gocompat::strings::{to_lower, trim_space};

use crate::goid::{NAMESPACE_OID, Uuid};
use crate::hexgo::{encode as hex_encode, fnv64a, hmac_sha256, sha256, sha256_hex};

/// `PlanRecipeVersionV3`.
pub const PLAN_RECIPE_VERSION_V3: &str = "v3.4";
const DIRECT_PLAY_ETAG_VERSION: &str = "dsr1";

/// `TransformationV3`'s identity fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transformation {
    pub executor: String,
    pub name: String,
    pub recipe_version: String,
}

/// `TrackIdentityV3`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrackIdentity {
    pub id: String,
    pub index: Option<i64>,
}

/// `AppliedQuirkV3`'s identity fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppliedQuirk {
    pub registry_revision: String,
    pub id: String,
}

/// The fields of `PlanV3` that feed the plan ID and attempt key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanIdentity {
    pub plan_id: String,
    pub delivery: String,
    pub stream_protocol: String,
    pub stream_container: String,
    pub video_codec: String,
    pub audio_codec: String,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub bitrate_kbps: Option<i64>,
    pub dynamic_range: String,
    pub video_sample_entry: String,
    pub segment_container: String,
    pub selected_audio: Option<TrackIdentity>,
    pub selected_subtitle: Option<TrackIdentity>,
    pub subtitle_mode: String,
    /// `(stream_index, container_track_id)` of `Subtitle.Embedded`.
    pub embedded_subtitle: Option<(i64, String)>,
    /// `(group_id, format)` of `Subtitle.HLSRendition`.
    pub hls_rendition: Option<(String, String)>,
    pub transformations: Vec<Transformation>,
    pub applied_quirks: Vec<AppliedQuirk>,
    pub runtime_corrections: Vec<String>,
}

fn optional_int(v: Option<i64>) -> String {
    v.unwrap_or(0).to_string()
}

fn track_identity(v: &Option<TrackIdentity>) -> String {
    match v {
        None => String::new(),
        Some(t) => format!("{}:{}", t.id, optional_int(t.index)),
    }
}

fn sorted_transformations(plan: &PlanIdentity) -> String {
    let mut list: Vec<String> = plan
        .transformations
        .iter()
        .map(|t| format!("{}:{}:{}", t.executor, t.name, t.recipe_version))
        .collect();
    list.sort();
    list.join(",")
}

fn append_identity_tail(parts: &mut Vec<String>, plan: &PlanIdentity) {
    if let Some((index, track)) = &plan.embedded_subtitle {
        parts.push(format!("embedded_subtitle={index}:{track}"));
    }
    if let Some((group, format)) = &plan.hls_rendition {
        parts.push(format!("hls_subtitle_rendition={group}:{format}"));
    }
    let sample = to_lower(trim_space(&plan.video_sample_entry));
    if !sample.is_empty() {
        parts.push(format!("sample_entry={sample}"));
    }
    let container = to_lower(trim_space(&plan.segment_container));
    if !container.is_empty() {
        parts.push(format!("segment_container={container}"));
    }
    if !plan.applied_quirks.is_empty() || !plan.runtime_corrections.is_empty() {
        let mut quirks: Vec<String> = plan
            .applied_quirks
            .iter()
            .map(|q| format!("{}:{}", q.registry_revision, q.id))
            .collect();
        let mut corrections = plan.runtime_corrections.clone();
        quirks.sort();
        corrections.sort();
        parts.push(quirks.join(","));
        parts.push(corrections.join(","));
    }
}

/// `DeterministicPlanIDV3`.
pub fn deterministic_plan_id(
    attempt_id: &str,
    requested_file_id: i64,
    effective_file_id: i64,
    plan: &PlanIdentity,
) -> String {
    let mut parts = vec![
        attempt_id.to_owned(),
        requested_file_id.to_string(),
        effective_file_id.to_string(),
        plan.delivery.clone(),
        plan.stream_protocol.clone(),
        to_lower(&plan.stream_container),
        to_lower(&plan.video_codec),
        to_lower(&plan.audio_codec),
        optional_int(plan.width),
        optional_int(plan.height),
        optional_int(plan.bitrate_kbps),
        to_lower(&plan.dynamic_range),
        track_identity(&plan.selected_audio),
        track_identity(&plan.selected_subtitle),
        plan.subtitle_mode.clone(),
        sorted_transformations(plan),
    ];
    append_identity_tail(&mut parts, plan);
    parts.push(PLAN_RECIPE_VERSION_V3.to_owned());
    let sum = sha256(parts.join("|"));
    format!("plan:{}", hex_encode(&sum[..16]))
}

/// `PlanAttemptKeyV3`.
pub fn plan_attempt_key(
    plan: &PlanIdentity,
    output_context_id: &str,
    local_mutations: &[String],
) -> String {
    let mut mutations = local_mutations.to_vec();
    mutations.sort();
    let mut parts = vec![
        plan.plan_id.clone(),
        plan.delivery.clone(),
        plan.stream_protocol.clone(),
        to_lower(&plan.stream_container),
        to_lower(&plan.video_codec),
        to_lower(&plan.audio_codec),
        format!("{}x{}", optional_int(plan.width), optional_int(plan.height)),
        optional_int(plan.bitrate_kbps),
        to_lower(&plan.dynamic_range),
        plan.subtitle_mode.clone(),
        sorted_transformations(plan),
    ];
    append_identity_tail(&mut parts, plan);
    parts.push(output_context_id.to_owned());
    parts.push(mutations.join(","));
    format!("v3:{:016x}", fnv64a(parts.join("|")))
}

/// `directPlayFilesystemRevision` on Linux. Values print as the unsigned or signed integers Go has.
pub fn direct_play_revision_linux(
    dev: u64,
    ino: u64,
    ctime_sec: i64,
    ctime_nsec: i64,
    mtime_unix_nanos: i64,
    size: i64,
) -> String {
    format!(
        "linux:{dev:x}:{ino:x}:{}:{}:{}:{}",
        go_hex(ctime_sec),
        go_hex(ctime_nsec),
        go_hex(mtime_unix_nanos),
        go_hex(size)
    )
}

/// `directPlayFilesystemRevision` on Darwin.
pub fn direct_play_revision_darwin(
    dev: u64,
    ino: u64,
    ctime_sec: i64,
    ctime_nsec: i64,
    mtime_unix_nanos: i64,
    size: i64,
) -> String {
    format!(
        "darwin:{dev:x}:{ino:x}:{}:{}:{}:{}",
        go_hex(ctime_sec),
        go_hex(ctime_nsec),
        go_hex(mtime_unix_nanos),
        go_hex(size)
    )
}

/// `%x` of a signed integer: a minus sign and the magnitude.
fn go_hex(v: i64) -> String {
    if v < 0 {
        format!("-{:x}", v.unsigned_abs())
    } else {
        format!("{v:x}")
    }
}

/// `DirectPlayEntityTag` of a revision string: the strong validator, quotes included.
pub fn direct_play_etag(revision: &str) -> String {
    let digest = sha256_hex(format!("{DIRECT_PLAY_ETAG_VERSION}\0{revision}"));
    format!("\"{DIRECT_PLAY_ETAG_VERSION}-{digest}\"")
}

/// `expiredStopID`.
pub fn expired_stop_id(session_id: &str) -> String {
    Uuid::new_sha1(NAMESPACE_OID, format!("silo-expired:{session_id}")).to_string()
}

/// `abortStopID`.
pub fn abort_stop_id(session_id: &str) -> String {
    Uuid::new_sha1(NAMESPACE_OID, format!("silo-abort:{session_id}")).to_string()
}

/// `adminStopID`.
pub fn admin_stop_id(session_id: &str) -> String {
    Uuid::new_sha1(NAMESPACE_OID, format!("silo-admin-stop:{session_id}")).to_string()
}

/// `connectionstore`'s key of a remote client: IPv4 whole, IPv6 masked to /64.
pub fn connection_key(secret: &str, ip: std::net::IpAddr) -> String {
    let bytes: Vec<u8> = match ip {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.octets().to_vec(),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                octets.to_vec()
            }
        },
    };
    let mac = hmac_sha256(secret.as_bytes(), &[b"playback-connection-v1\0", &bytes]);
    format!("remote:{}", hex_encode(mac))
}

/// `nodesessions.NewTracker`'s `nodeHash`: 8 hex digits of the node URL.
pub fn node_hash(node_url: &str) -> String {
    hex_encode(&sha256(node_url)[..4])
}

/// `noderecipe.nodeAuthorityRecordDigest`.
pub fn node_recipe_digest(data: &[u8]) -> String {
    sha256_hex(data)
}
