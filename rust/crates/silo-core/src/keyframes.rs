//! `internal/playback/keyframes` and the `keyframe-plan.json` record: the cuts a rebuilt session must
//! reproduce, because its player already holds the playlist.

use serde::Serialize;
use silo_gocompat::json::{self, omit_empty};

const TARGET_SLACK: f64 = 1e-6;

/// `PlanSegments`.
pub fn plan_segments(keyframes: &[f64], segment_seconds: f64) -> Vec<f64> {
    let Some(&first) = keyframes.first() else {
        return Vec::new();
    };
    if segment_seconds <= 0.0 {
        return Vec::new();
    }
    let mut starts = vec![first];
    let mut target = segment_seconds;
    for &k in &keyframes[1..] {
        if k - first >= target - TARGET_SLACK {
            starts.push(k);
            target += segment_seconds;
        }
    }
    starts
}

/// `SegmentDurations`.
pub fn segment_durations(starts: &[f64], end: f64) -> Vec<f64> {
    starts
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let next = starts.get(i + 1).copied().unwrap_or(end);
            if next > start { next - start } else { 0.0 }
        })
        .collect()
}

/// `copyPlanRecord`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CopyPlanRecord {
    pub planned: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    pub durations: Vec<f64>,
}

impl CopyPlanRecord {
    /// The file's bytes.
    pub fn to_json(&self) -> Vec<u8> {
        json::marshal(self).unwrap_or_default()
    }
}
