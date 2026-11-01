//! `internal/streamtoken`: the JWT a proxy or transcode node serves a session from without a database.
//!
//! The token is also the durable reconstruction descriptor: a re-presented token must rebuild the same
//! FFmpeg recipe, so every claim name and type is a contract. `ostn` is an exact int64 of nanoseconds.

use serde::{Deserialize, Serialize};
use silo_gocompat::json::omit_empty;
use silo_gocompat::strings::trim_space;
use silo_jwt::gojson::{pointer, value};
use silo_jwt::{Error as JwtError, NumericDate, Parser, RegisteredClaims, impl_claims, sign_hs256};

pub const PLAY_METHOD_BANDWIDTH_PROBE: &str = "bandwidth_probe_v1";
pub const PLAY_METHOD_DOWNLOAD: &str = "download";
pub const PLAY_METHOD_TONE_MAP_DOWNLOAD: &str = "download_tonemap_v1";
pub const PLAY_METHOD_TONE_MAP_TRANSCODE: &str = "transcode_tonemap_v1";
pub const PLAY_METHOD_AUDIO_DOWNMIX_TRANSCODE: &str = "transcode_audio_downmix_v1";
pub const PLAY_METHOD_AUDIO_DOWNMIX_REMUX: &str = "remux_audio_downmix_v1";
pub const PLAY_METHOD_COPY_FMP4_TRANSCODE: &str = "transcode_copy_fmp4_v1";
pub const PLAY_METHOD_THEME_DIRECT: &str = "theme_direct_v1";
pub const PLAY_METHOD_THEME_AAC: &str = "theme_aac_v1";

/// `streamtoken.Claims`, in Go's field order.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Claims {
    #[serde(rename = "sid")]
    pub session_id: String,
    #[serde(rename = "path")]
    pub media_path: String,
    #[serde(rename = "method")]
    pub play_method: String,
    #[serde(rename = "ta", skip_serializing_if = "omit_empty")]
    pub transcode_audio: bool,
    #[serde(rename = "tnode", skip_serializing_if = "omit_empty")]
    pub transcode_node: String,
    #[serde(rename = "tid", skip_serializing_if = "omit_empty")]
    pub transcode_transport_id: String,
    #[serde(rename = "rnp", skip_serializing_if = "Option::is_none")]
    pub routing_network_provider: Option<String>,
    #[serde(rename = "sl", skip_serializing_if = "omit_empty")]
    pub stream_location: String,
    #[serde(rename = "rwl", skip_serializing_if = "omit_empty")]
    pub routing_workload: String,
    #[serde(rename = "rex", skip_serializing_if = "omit_empty")]
    pub routing_execution: String,
    #[serde(rename = "rxnid", skip_serializing_if = "omit_empty")]
    pub routing_execution_node_id: i64,
    #[serde(rename = "reg", skip_serializing_if = "omit_empty")]
    pub routing_egress: String,
    #[serde(rename = "renid", skip_serializing_if = "omit_empty")]
    pub routing_egress_node_id: i64,
    #[serde(rename = "tc", skip_serializing_if = "omit_empty")]
    pub target_codec: String,
    #[serde(rename = "tres", skip_serializing_if = "omit_empty")]
    pub target_res: String,
    #[serde(rename = "ac", skip_serializing_if = "omit_empty")]
    pub audio_codec: String,
    #[serde(rename = "ach", skip_serializing_if = "omit_empty")]
    pub audio_channels: i64,
    #[serde(rename = "ati", skip_serializing_if = "omit_empty")]
    pub audio_track_index: i64,
    #[serde(rename = "ao", skip_serializing_if = "omit_empty")]
    pub audio_only: bool,
    #[serde(rename = "cac", skip_serializing_if = "omit_empty")]
    pub copy_audio_codec: String,
    #[serde(rename = "dvp", skip_serializing_if = "omit_empty")]
    pub dv_profile: i64,
    #[serde(rename = "dvm", skip_serializing_if = "omit_empty")]
    pub remux_dv_mode: String,
    #[serde(rename = "rlpd", skip_serializing_if = "omit_empty")]
    pub remux_resume_leading_picture_drop: bool,
    #[serde(rename = "uid", skip_serializing_if = "omit_empty")]
    pub user_id: i64,
    #[serde(rename = "pid", skip_serializing_if = "omit_empty")]
    pub profile_id: String,
    #[serde(rename = "mfid", skip_serializing_if = "omit_empty")]
    pub media_file_id: i64,
    #[serde(rename = "ostn", skip_serializing_if = "omit_empty")]
    pub original_started_at_unix_nano: i64,
    #[serde(rename = "daid", skip_serializing_if = "omit_empty")]
    pub download_artifact_id: String,
    #[serde(rename = "darid", skip_serializing_if = "omit_empty")]
    pub download_artifact_row_id: String,
    #[serde(rename = "dasz", skip_serializing_if = "omit_empty")]
    pub download_artifact_size: i64,
    #[serde(rename = "daef", skip_serializing_if = "omit_empty")]
    pub download_execution_fingerprint: String,
    #[serde(rename = "dfn", skip_serializing_if = "omit_empty")]
    pub download_filename: String,
    #[serde(rename = "thid", skip_serializing_if = "omit_empty")]
    pub theme_id: i64,
    #[serde(rename = "thsz", skip_serializing_if = "omit_empty")]
    pub theme_size: i64,
    #[serde(rename = "thmt", skip_serializing_if = "omit_empty")]
    pub theme_modified_unix_nano: i64,
    #[serde(rename = "svc", skip_serializing_if = "omit_empty")]
    pub source_video_codec: String,
    #[serde(rename = "svp", skip_serializing_if = "omit_empty")]
    pub source_video_profile: String,
    #[serde(rename = "svb", skip_serializing_if = "omit_empty")]
    pub source_video_bit_depth: i64,
    #[serde(rename = "sach", skip_serializing_if = "omit_empty")]
    pub source_audio_channels: i64,
    #[serde(rename = "svd", skip_serializing_if = "omit_empty")]
    pub software_video_decode: bool,
    #[serde(rename = "tmp", skip_serializing_if = "omit_empty")]
    pub tone_map_policy: String,
    #[serde(rename = "tmm", skip_serializing_if = "omit_empty")]
    pub tone_map_mode: String,
    #[serde(rename = "tms", skip_serializing_if = "omit_empty")]
    pub tone_map_source_kind: String,
    #[serde(rename = "tmv", skip_serializing_if = "omit_empty")]
    pub tone_map_recipe_version: String,
    #[serde(rename = "cfv", skip_serializing_if = "omit_empty")]
    pub copy_fmp4_recipe_version: String,
    #[serde(rename = "tmpf", skip_serializing_if = "omit_empty")]
    pub tone_map_preflight_required: bool,
    #[serde(rename = "tmsr", skip_serializing_if = "omit_empty")]
    pub tone_map_source_revision: String,
    #[serde(rename = "tmdc", skip_serializing_if = "omit_empty")]
    pub tone_map_dv_config_present: bool,
    #[serde(rename = "tmdbci", skip_serializing_if = "omit_empty")]
    pub tone_map_dv_bl_compat_id_present: bool,
    #[serde(rename = "tmdb", skip_serializing_if = "omit_empty")]
    pub tone_map_dv_bl_present: bool,
    #[serde(rename = "tmdr", skip_serializing_if = "omit_empty")]
    pub tone_map_dv_rpu_present: bool,
    #[serde(rename = "vbsf", skip_serializing_if = "omit_empty")]
    pub video_bitstream_filter: String,
    #[serde(rename = "vse", skip_serializing_if = "omit_empty")]
    pub video_sample_entry: String,
    #[serde(rename = "vrg", skip_serializing_if = "omit_empty")]
    pub video_range: String,
    #[serde(rename = "cvts", skip_serializing_if = "omit_empty")]
    pub copy_video_mpegts: bool,
    #[serde(rename = "kfp", skip_serializing_if = "omit_empty")]
    pub keyframe_playlist: bool,
    #[serde(rename = "osd", skip_serializing_if = "omit_empty")]
    pub output_subdir: String,
    #[serde(rename = "seek", skip_serializing_if = "omit_empty")]
    pub seek_seconds: f64,
    #[serde(rename = "origin", skip_serializing_if = "omit_empty")]
    pub stream_origin_seconds: f64,
    #[serde(rename = "origin_ok", skip_serializing_if = "omit_empty")]
    pub copy_seek_anchor_resolved: bool,
    #[serde(rename = "segd", skip_serializing_if = "omit_empty")]
    pub segment_duration: i64,
    #[serde(rename = "ssn", skip_serializing_if = "omit_empty")]
    pub start_segment_number: i64,
    #[serde(rename = "sti", skip_serializing_if = "omit_empty")]
    pub subtitle_track_index: i64,
    #[serde(rename = "sbi", skip_serializing_if = "omit_empty")]
    pub subtitle_burn_in: bool,
    #[serde(rename = "sbc", skip_serializing_if = "omit_empty")]
    pub subtitle_codec: String,
    #[serde(rename = "srn", skip_serializing_if = "omit_empty")]
    pub subtitle_rendition: bool,
    #[serde(rename = "tbr", skip_serializing_if = "omit_empty")]
    pub target_bitrate_kbps: i64,
    #[serde(rename = "dur", skip_serializing_if = "omit_empty")]
    pub total_duration: f64,
    #[serde(rename = "fs", skip_serializing_if = "omit_empty")]
    pub fast_start: bool,
    #[serde(rename = "ths", skip_serializing_if = "omit_empty")]
    pub throttle_seconds: i64,
    #[serde(rename = "tca", skip_serializing_if = "omit_empty")]
    pub target_codec_audio: String,
    #[serde(rename = "tac", skip_serializing_if = "omit_empty")]
    pub target_audio_channels: i64,
    #[serde(rename = "tabr", skip_serializing_if = "omit_empty")]
    pub target_audio_bitrate_kbps: i64,
    #[serde(rename = "hvs", skip_serializing_if = "omit_empty")]
    pub hls_variable_substitution: bool,
    #[serde(rename = "ver", skip_serializing_if = "omit_empty")]
    pub version: i64,
    #[serde(flatten)]
    pub registered: RegisteredClaims,
}

impl_claims!(
    Claims,
    [
        value("sid"),
        value("path"),
        value("method"),
        value("ta"),
        value("tnode"),
        value("tid"),
        pointer("rnp"),
        value("sl"),
        value("rwl"),
        value("rex"),
        value("rxnid"),
        value("reg"),
        value("renid"),
        value("tc"),
        value("tres"),
        value("ac"),
        value("ach"),
        value("ati"),
        value("ao"),
        value("cac"),
        value("dvp"),
        value("dvm"),
        value("rlpd"),
        value("uid"),
        value("pid"),
        value("mfid"),
        value("ostn"),
        value("daid"),
        value("darid"),
        value("dasz"),
        value("daef"),
        value("dfn"),
        value("thid"),
        value("thsz"),
        value("thmt"),
        value("svc"),
        value("svp"),
        value("svb"),
        value("sach"),
        value("svd"),
        value("tmp"),
        value("tmm"),
        value("tms"),
        value("tmv"),
        value("cfv"),
        value("tmpf"),
        value("tmsr"),
        value("tmdc"),
        value("tmdbci"),
        value("tmdb"),
        value("tmdr"),
        value("vbsf"),
        value("vse"),
        value("vrg"),
        value("cvts"),
        value("kfp"),
        value("osd"),
        value("seek"),
        value("origin"),
        value("origin_ok"),
        value("segd"),
        value("ssn"),
        value("sti"),
        value("sbi"),
        value("sbc"),
        value("srn"),
        value("tbr"),
        value("dur"),
        value("fs"),
        value("ths"),
        value("tca"),
        value("tac"),
        value("tabr"),
        value("hvs"),
        value("ver"),
    ]
);

/// Stream token failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `ErrNoSecret`: an empty HMAC key is one anyone can sign with.
    NoSecret,
    Jwt(JwtError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSecret => f.write_str("stream token: signing secret is not configured"),
            Self::Jwt(e) => write!(f, "invalid stream token: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// `streamtoken.Sign` at a given time. It overwrites the registered claims, as Go does.
pub fn sign(
    mut claims: Claims,
    secret: &str,
    ttl_nanos: i64,
    now_unix_nanos: i128,
) -> Result<String, Error> {
    if trim_space(secret).is_empty() {
        return Err(Error::NoSecret);
    }
    claims.registered = RegisteredClaims {
        expires_at: Some(NumericDate(
            (now_unix_nanos + i128::from(ttl_nanos)).div_euclid(1_000_000_000) as i64,
        )),
        issued_at: Some(NumericDate(now_unix_nanos.div_euclid(1_000_000_000) as i64)),
        ..RegisteredClaims::default()
    };
    sign_hs256(&claims, secret.as_bytes()).map_err(Error::Jwt)
}

/// `streamtoken.Verify`: any HMAC algorithm, `exp` optional.
pub fn verify(token: &str, secret: &str) -> Result<Claims, Error> {
    verify_with(token, secret, Parser::new())
}

/// `verify` with a chosen parser, so a caller can fix the clock.
pub fn verify_with<'a>(token: &str, secret: &'a str, parser: Parser<'a>) -> Result<Claims, Error> {
    if trim_space(secret).is_empty() {
        return Err(Error::NoSecret);
    }
    parser
        .parse_hmac::<Claims>(token, secret.as_bytes())
        .map(|t| t.claims)
        .map_err(Error::Jwt)
}

/// `StartedAtSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartedAtSource {
    Claim,
    IssuedAt,
    None,
}

impl Claims {
    /// `Claims.StartedAt`, as Unix nanoseconds. Only the explicit claim is authoritative, because
    /// signing rewrites the registered claims on every mint.
    pub fn started_at(&self) -> (Option<i128>, StartedAtSource) {
        if self.original_started_at_unix_nano != 0 {
            return (
                Some(i128::from(self.original_started_at_unix_nano)),
                StartedAtSource::Claim,
            );
        }
        if let Some(iat) = self.registered.issued_at {
            return (
                Some(i128::from(iat.0) * 1_000_000_000),
                StartedAtSource::IssuedAt,
            );
        }
        (None, StartedAtSource::None)
    }
}
