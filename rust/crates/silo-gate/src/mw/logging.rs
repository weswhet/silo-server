//! `request_logger.go` and `metrics.go`. The metrics stay in this process until the metrics listener
//! is ported, so they are readable through [`Metrics::snapshot`] and not yet exposed.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

/// `metricMethod`.
pub fn metric_method(method: &str) -> &str {
    match method {
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "CONNECT" | "TRACE" => {
            method
        }
        _ => "other",
    }
}

type Series = BTreeMap<(String, String, u16), (u64, f64)>;

/// `httpRequestsTotal` and the sum and count of `httpRequestDuration`.
#[derive(Default)]
pub struct Metrics {
    series: Mutex<Series>,
}

impl Metrics {
    pub fn observe(&self, method: &str, pattern: &str, status: u16, duration: Duration) {
        let path = if pattern.is_empty() {
            "unmatched"
        } else {
            pattern
        };
        let key = (metric_method(method).to_owned(), path.to_owned(), status);
        let mut series = self.series.lock().unwrap_or_else(|e| e.into_inner());
        let entry = series.entry(key).or_default();
        entry.0 += 1;
        entry.1 += duration.as_secs_f64();
    }

    pub fn snapshot(&self) -> Series {
        self.series
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// The prefixes `RequestLogger` skips.
pub fn request_logger_skips(path: &str) -> bool {
    [
        "/api/v1/health",
        "/api/v1/ready",
        "/api/v1/admin/logs",
        super::API_V2_PREFIX,
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}
