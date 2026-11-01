//! Port of Go's `path/filepath` on Unix, the only platform the server targets for these calls.
//!
//! On Unix `filepath.Clean`, `Base`, `Ext`, `Split`, and `Dir` behave like their `path`
//! counterparts. `Match` and `Rel` differ.

pub use crate::path::{BadPattern, base, clean, dir, ext, is_abs, split};

/// `filepath.Join`. Leading empty elements are skipped; later empty elements still contribute a
/// separator that `Clean` removes.
pub fn join<S: AsRef<str>>(elems: &[S]) -> String {
    let Some(first) = elems.iter().position(|e| !e.as_ref().is_empty()) else {
        return String::new();
    };
    let mut buf = String::new();
    for (i, elem) in elems[first..].iter().enumerate() {
        if i > 0 {
            buf.push('/');
        }
        buf.push_str(elem.as_ref());
    }
    clean(&buf)
}

/// `filepath.ToSlash`, the identity on Unix.
pub fn to_slash(path: &str) -> &str {
    path
}

/// `filepath.FromSlash`, the identity on Unix.
pub fn from_slash(path: &str) -> &str {
    path
}

/// `filepath.Match` on Unix. Unlike [`crate::path::match_pattern`], it does not validate the rest
/// of the pattern once the name has stopped matching.
pub fn match_pattern(pattern: &str, name: &str) -> Result<bool, BadPattern> {
    crate::path::match_impl(pattern.as_bytes(), name.as_bytes(), false)
}

/// The error `filepath.Rel` returns when no relative path exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelError(String);

impl std::fmt::Display for RelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RelError {}

/// `filepath.Rel` on Unix.
pub fn rel(base_path: &str, targ_path: &str) -> Result<String, RelError> {
    let base = clean(base_path);
    let targ = clean(targ_path);
    if targ == base {
        return Ok(".".to_string());
    }
    let base = if base == "." { "" } else { base.as_str() };
    let cant = || {
        RelError(format!(
            "Rel: can't make {targ_path} relative to {base_path}"
        ))
    };
    if base.starts_with('/') != targ.starts_with('/') {
        return Err(cant());
    }
    let (b, t) = (base.as_bytes(), targ.as_bytes());
    let (bl, tl) = (b.len(), t.len());
    let (mut b0, mut bi, mut t0, mut ti) = (0, 0, 0, 0);
    loop {
        while bi < bl && b[bi] != b'/' {
            bi += 1;
        }
        while ti < tl && t[ti] != b'/' {
            ti += 1;
        }
        if t[t0..ti] != b[b0..bi] {
            break;
        }
        if bi < bl {
            bi += 1;
        }
        if ti < tl {
            ti += 1;
        }
        b0 = bi;
        t0 = ti;
    }
    if &b[b0..bi] == b".." {
        return Err(cant());
    }
    if b0 != bl {
        // Base elements left: go up before going down.
        let seps = b[b0..bl].iter().filter(|&&c| c == b'/').count();
        let mut buf = String::from("..");
        for _ in 0..seps {
            buf.push_str("/..");
        }
        if t0 != tl {
            buf.push('/');
            buf.push_str(&targ[t0..]);
        }
        return Ok(clean(&buf));
    }
    Ok(targ[t0..].to_string())
}
