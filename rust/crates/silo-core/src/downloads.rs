//! `internal/downloads`, `internal/downloadprepare`, and `internal/tonemap`: fingerprints compared
//! between an API server and a node and stored with prepared artifacts.

use serde::{Deserialize, Serialize};
use silo_gocompat::json::{self, omit_empty};
use silo_jwt::base64go::raw_url_encode;

use crate::hexgo::sha256_hex;
use crate::models::{PreparedTracks, SourceRevision};

/// `SourceRevision.Fingerprint`.
pub fn source_revision_fingerprint(revision: &SourceRevision) -> String {
    sha256_hex(json::marshal(revision).unwrap_or_default())
}

/// `SourceRevision.Encode`: empty for a zero revision.
pub fn source_revision_encode(revision: &SourceRevision) -> String {
    if revision.is_zero() {
        return String::new();
    }
    raw_url_encode(json::marshal(revision).unwrap_or_default())
}

/// `paramsHashParams`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParamsHashParams {
    pub format: String,
    pub container: String,
    pub codec_video: String,
    pub codec_audio: String,
    pub resolution: String,
    pub audio_track_index: i64,
    pub target_bitrate_kbps: i64,
    pub subtitle_burn_in: bool,
    pub policy: String,
    pub mode: String,
    pub source_kind: String,
    pub recipe_version: String,
    pub preflight_required: bool,
    pub source_revision: SourceRevision,
}

/// `tonemap.PolicyNone`.
const POLICY_NONE: &str = "none";

/// `paramsHashWithToneMapRevision`.
pub fn params_hash(p: &ParamsHashParams) -> String {
    let mut input = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        p.format,
        p.container,
        p.codec_video,
        p.codec_audio,
        p.resolution,
        p.audio_track_index,
        p.target_bitrate_kbps,
        p.subtitle_burn_in
    );
    if (!p.policy.is_empty() && p.policy != POLICY_NONE)
        || !p.mode.is_empty()
        || !p.source_kind.is_empty()
        || !p.recipe_version.is_empty()
        || p.preflight_required
        || !p.source_revision.is_zero()
    {
        input.push_str(&format!(
            "|{}|{}|{}|{}|{}|{}",
            p.policy,
            p.mode,
            p.source_kind,
            p.recipe_version,
            p.preflight_required,
            source_revision_fingerprint(&p.source_revision)
        ));
    }
    sha256_hex(input)
}

/// The input of `OfflineIntegrity.MetadataETag`. `modified` is the RFC3339Nano UTC text of the file's
/// modification time, or empty.
#[allow(clippy::too_many_arguments)]
pub fn metadata_etag(
    id: &str,
    revision: i64,
    format: &str,
    quality: &str,
    effective_quality: &str,
    target_bitrate_kbps: i64,
    file_size: i64,
    modified: &str,
) -> String {
    sha256_hex(format!(
        "{id}|{revision}|{format}|{quality}|{effective_quality}|{target_bitrate_kbps}|{file_size}|{modified}"
    ))
}

/// `downloadprepare.Request`, in Go's field order.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrepareRequest {
    pub artifact_id: String,
    pub input_path: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub source_video_codec: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub source_video_profile: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub source_video_bit_depth: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub software_video_decode: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_policy: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_mode: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_source_kind: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_recipe_version: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_preflight_required: bool,
    #[serde(skip_serializing_if = "revision_is_zero_value")]
    pub tone_map_source_revision: SourceRevision,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_dv_config_present: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_dv_bl_compat_id_present: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_dv_bl_present: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    pub tone_map_dv_rpu_present: bool,
    pub target_codec_video: String,
    pub target_codec_audio: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub target_audio_channels: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub target_audio_bitrate_kbps: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub target_resolution: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub target_bitrate_kbps: i64,
    pub audio_track_index: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub audio_recipe_version: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub source_audio_channels: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub track_recipe_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepared_tracks: Option<PreparedTracks>,
    #[serde(skip_serializing_if = "omit_empty")]
    pub total_duration: f64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub log_session_id: String,
}

/// `omitzero` on a type with an `IsZero` method calls it, which ignores the video stream index.
fn revision_is_zero_value(r: &SourceRevision) -> bool {
    r.is_zero()
}

/// `Request.ExecutionFingerprint`: every transported byte-affecting field, without the idempotency
/// handle or the log label.
pub fn execution_fingerprint(request: &PrepareRequest) -> String {
    let mut request = request.clone();
    request.artifact_id.clear();
    request.log_session_id.clear();
    match json::marshal(&request) {
        Ok(data) => sha256_hex(data),
        Err(_) => String::new(),
    }
}
