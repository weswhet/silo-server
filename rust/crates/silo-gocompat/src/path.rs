//! Port of Go's `path` package: slash-separated, purely lexical.

/// `path.Clean`. `path.Clean("")` is `"."`.
pub fn clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let bytes = path.as_bytes();
    let rooted = bytes[0] == b'/';
    let n = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0usize, 0usize);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if bytes[r] == b'/' {
            // Empty path element.
            r += 1;
        } else if bytes[r] == b'.' && (r + 1 == n || bytes[r + 1] == b'/') {
            // "." element.
            r += 1;
        } else if bytes[r] == b'.' && bytes[r + 1] == b'.' && (r + 2 == n || bytes[r + 2] == b'/') {
            // ".." element: remove back to the last slash.
            r += 2;
            if out.len() > dotdot {
                // Back up to the slash before the last element, or to dotdot.
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            // Real path element.
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && bytes[r] != b'/' {
                out.push(bytes[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return ".".to_string();
    }
    // Only whole path elements and ASCII were copied, so the bytes stay valid UTF-8.
    String::from_utf8(out).unwrap_or_default()
}

/// `path.Split`: `path == dir + file`.
pub fn split(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => path.split_at(i + 1),
        None => ("", path),
    }
}

/// `path.Join`. Empty elements are ignored and the result is cleaned. Unlike `Path::join`, an
/// absolute element does not replace what came before it.
pub fn join<S: AsRef<str>>(elems: &[S]) -> String {
    let mut buf = String::new();
    for elem in elems {
        let elem = elem.as_ref();
        if !buf.is_empty() || !elem.is_empty() {
            if !buf.is_empty() {
                buf.push('/');
            }
            buf.push_str(elem);
        }
    }
    if buf.is_empty() {
        return String::new();
    }
    clean(&buf)
}

/// `path.Ext`. `Ext(".bashrc")` is `".bashrc"`, unlike `Path::extension`.
pub fn ext(path: &str) -> &str {
    for (i, b) in path.bytes().enumerate().rev() {
        if b == b'/' {
            break;
        }
        if b == b'.' {
            return &path[i..];
        }
    }
    ""
}

/// `path.Base`.
pub fn base(path: &str) -> &str {
    if path.is_empty() {
        return ".";
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    }
}

/// `path.IsAbs`.
pub fn is_abs(path: &str) -> bool {
    path.starts_with('/')
}

/// `path.Dir`.
pub fn dir(path: &str) -> String {
    clean(split(path).0)
}

/// `path.ErrBadPattern`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadPattern;

impl std::fmt::Display for BadPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("syntax error in pattern")
    }
}

impl std::error::Error for BadPattern {}

/// `path.Match`. Reports a malformed pattern even after the name has stopped matching.
pub fn match_pattern(pattern: &str, name: &str) -> Result<bool, BadPattern> {
    match_impl(pattern.as_bytes(), name.as_bytes(), true)
}

/// Shared by `path.Match` and `filepath.Match`, which differ only in `check_rest`: `path.Match`
/// validates the rest of the pattern before it returns false, and `filepath.Match` does not.
pub(crate) fn match_impl(
    mut pattern: &[u8],
    mut name: &[u8],
    check_rest: bool,
) -> Result<bool, BadPattern> {
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            // A trailing * matches the rest of the string unless it has a /.
            return Ok(!name.contains(&b'/'));
        }
        // Look for a match at the current position.
        let (t, ok, err) = match_chunk(chunk, name);
        // The last chunk must exhaust the name, otherwise the star could still match.
        if ok && (t.is_empty() || !pattern.is_empty()) {
            name = t;
            continue;
        }
        if let Some(err) = err {
            return Err(err);
        }
        if star {
            // Look for a match skipping i+1 bytes. A star cannot skip a /.
            let mut i = 0;
            while i < name.len() && name[i] != b'/' {
                let (t, ok, err) = match_chunk(chunk, &name[i + 1..]);
                if ok {
                    if pattern.is_empty() && !t.is_empty() {
                        i += 1;
                        continue;
                    }
                    name = t;
                    continue 'pattern;
                }
                if let Some(err) = err {
                    return Err(err);
                }
                i += 1;
            }
        }
        if check_rest {
            while !pattern.is_empty() {
                let (_, chunk, rest) = scan_chunk(pattern);
                pattern = rest;
                if let (_, _, Some(err)) = match_chunk(chunk, b"") {
                    return Err(err);
                }
            }
        }
        return Ok(false);
    }
    Ok(name.is_empty())
}

fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while pattern.first() == Some(&b'*') {
        pattern = &pattern[1..];
        star = true;
    }
    let mut in_range = false;
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' => {
                // The error check is in match_chunk: bad pattern.
                if i + 1 < pattern.len() {
                    i += 1;
                }
            }
            b'[' => in_range = true,
            b']' => in_range = false,
            b'*' if !in_range => return (star, &pattern[..i], &pattern[i..]),
            _ => {}
        }
        i += 1;
    }
    (star, pattern, b"")
}

/// `utf8.DecodeRune`: an invalid encoding is U+FFFD with width 1, empty input is U+FFFD width 0.
fn decode_rune(bytes: &[u8]) -> (u32, usize) {
    let Some(&first) = bytes.first() else {
        return (crate::unicode::REPLACEMENT, 0);
    };
    if first < 0x80 {
        return (u32::from(first), 1);
    }
    let len = bytes.len().min(4);
    let valid = match std::str::from_utf8(&bytes[..len]) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or_default(),
    };
    match valid.chars().next() {
        Some(c) => (c as u32, c.len_utf8()),
        None => (crate::unicode::REPLACEMENT, 1),
    }
}

/// Returns `(rest, ok, err)` with Go's meaning. A failed match keeps walking the chunk to validate
/// it without reading the name.
fn match_chunk<'a>(mut chunk: &[u8], mut s: &'a [u8]) -> (&'a [u8], bool, Option<BadPattern>) {
    let mut failed = false;
    while let Some(&first) = chunk.first() {
        failed = failed || s.is_empty();
        match first {
            b'[' => {
                let mut r = 0u32;
                if !failed {
                    let (decoded, n) = decode_rune(s);
                    r = decoded;
                    s = &s[n..];
                }
                chunk = &chunk[1..];
                let mut negated = false;
                if chunk.first() == Some(&b'^') {
                    negated = true;
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut nrange = 0;
                loop {
                    if chunk.first() == Some(&b']') && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = match get_esc(chunk) {
                        Ok(v) => v,
                        Err(e) => return (b"", false, Some(e)),
                    };
                    chunk = rest;
                    let mut hi = lo;
                    if chunk[0] == b'-' {
                        let (h, rest) = match get_esc(&chunk[1..]) {
                            Ok(v) => v,
                            Err(e) => return (b"", false, Some(e)),
                        };
                        hi = h;
                        chunk = rest;
                    }
                    matched = matched || (lo <= r && r <= hi);
                    nrange += 1;
                }
                failed = failed || matched == negated;
            }
            b'?' => {
                if !failed {
                    failed = s[0] == b'/';
                    let (_, n) = decode_rune(s);
                    s = &s[n..];
                }
                chunk = &chunk[1..];
            }
            _ => {
                if first == b'\\' {
                    chunk = &chunk[1..];
                    if chunk.is_empty() {
                        return (b"", false, Some(BadPattern));
                    }
                }
                if !failed {
                    failed = chunk[0] != s[0];
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    if failed {
        (b"", false, None)
    } else {
        (s, true, None)
    }
}

fn get_esc(mut chunk: &[u8]) -> Result<(u32, &[u8]), BadPattern> {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return Err(BadPattern);
    }
    if chunk[0] == b'\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return Err(BadPattern);
        }
    }
    let (r, n) = decode_rune(chunk);
    if r == crate::unicode::REPLACEMENT && n == 1 {
        return Err(BadPattern);
    }
    let rest = &chunk[n..];
    if rest.is_empty() {
        return Err(BadPattern);
    }
    Ok((r, rest))
}
