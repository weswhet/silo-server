//! Reads the candidate's origin log: one JSON line per request, naming who answered it. It sits outside
//! the response, so marking origin cannot change the header set being compared.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct OriginEntry {
    pub origin: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub target: String,
}

/// A position in the log. The candidate writes a request's line before answering it, and cases run
/// one at a time, so everything new after an answer belongs to that case.
pub struct OriginLog {
    path: PathBuf,
    offset: u64,
}

impl OriginLog {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            offset: 0,
        }
    }

    /// The whole lines written since the last call.
    pub fn drain(&mut self) -> Result<Vec<OriginEntry>> {
        let mut file = match fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| format!("reading {}", self.path.display()));
            }
        };
        let len = file.metadata()?.len();
        if len < self.offset {
            // The candidate restarted with a new log.
            self.offset = 0;
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let mut text = Vec::new();
        file.read_to_end(&mut text)?;
        let complete = text.iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
        self.offset += complete as u64;
        text[..complete]
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| {
                serde_json::from_slice(l)
                    .with_context(|| format!("origin log line {}", String::from_utf8_lossy(l)))
            })
            .collect()
    }
}

/// A case counts as served by the candidate only if lines exist for it and every one says native. No
/// line at all means the log cannot vouch for the answer, so it counts against the route.
pub fn proxied(entries: &[OriginEntry]) -> bool {
    entries.is_empty() || entries.iter().any(|e| e.origin != "native")
}
