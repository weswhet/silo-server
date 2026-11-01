//! The fields of `internal/models`, `internal/playback`, and `internal/tonemap` types that persisted
//! formats read. The full catalog models arrive with the crates that query them.

use serde::{Deserialize, Serialize};
use silo_gocompat::json::omit_empty;

/// `tonemap.SourceRevision`, in Go's field order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceRevision {
    pub media_file_id: i64,
    pub file_size: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub file_modified_unix_nano: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub file_hash: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub probe_updated_unix_nano: i64,
    pub video_stream_index: i64,
    pub stream_signature: String,
}

impl SourceRevision {
    /// `IsZero`.
    pub fn is_zero(&self) -> bool {
        self.media_file_id == 0
            && self.file_size == 0
            && self.file_modified_unix_nano == 0
            && self.file_hash.is_empty()
            && self.probe_updated_unix_nano == 0
            && self.stream_signature.is_empty()
    }
}

/// `playback.PreparedAudioTrack`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PreparedAudioTrack {
    pub source_index: i64,
    pub codec: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub source_channels: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub language: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub title: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub default: bool,
}

/// `playback.PreparedSubtitleTrack`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PreparedSubtitleTrack {
    pub source_index: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    pub language: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub title: String,
    #[serde(skip_serializing_if = "omit_empty")]
    pub default: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    pub forced: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    pub hearing_impaired: bool,
}

/// `playback.PreparedTracks`. A nil `Audio` slice encodes as `null`, as in Go.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PreparedTracks {
    pub audio: Option<Vec<PreparedAudioTrack>>,
    #[serde(skip_serializing_if = "omit_empty")]
    pub subtitles: Vec<PreparedSubtitleTrack>,
}

/// The fields of `models.MediaFile` that `MarkerFileIdentity` reads. `modified_at` is the normalized
/// RFC 3339 text of a non-nil time, as `time.Time` marshals it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MarkerFile {
    pub id: i64,
    pub file_hash: String,
    pub file_size: i64,
    pub modified_at: Option<String>,
    pub duration: i64,
    pub content_id: String,
    pub episode_id: String,
    pub extra_id: String,
    pub season_number: i64,
    pub episode_number: i64,
    pub file_path: String,
}

/// `models.MarkerSegment`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MarkerSegment {
    pub kind: String,
    pub start_seconds: f64,
    pub end_seconds: f64,
}
