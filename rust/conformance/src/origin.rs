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
/// line at all means the log cannot vouch for the answer, so it counts against the route. Only lines for
/// the case's own method and path count: a stray request from another process (a host probing new
/// listeners, a health check) says nothing about this case.
pub fn proxied(entries: &[OriginEntry], method: &str, path_and_query: &str) -> bool {
    let path = |target: &str| target.split('?').next().unwrap_or_default().to_string();
    let wanted = path(path_and_query);
    let mine: Vec<&OriginEntry> = entries
        .iter()
        .filter(|e| e.method == method && path(&e.target) == wanted)
        .collect();
    mine.is_empty() || mine.iter().any(|e| e.origin != "native")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stray_line_is_not_the_case() {
        let line = |origin: &str, method: &str, target: &str| OriginEntry {
            origin: origin.to_string(),
            method: method.to_string(),
            target: target.to_string(),
        };
        let native = line("native", "GET", "/a?x=1");
        let go = line("go", "GET", "/");
        assert!(!proxied(&[native.clone(), go.clone()], "GET", "/a?x=1"));
        assert!(proxied(std::slice::from_ref(&go), "GET", "/a"));
        assert!(proxied(&[], "GET", "/a"));
        assert!(proxied(
            &[native, line("go", "GET", "/a?y=2")],
            "GET",
            "/a?x=1"
        ));
    }
}
