//! Port of Go's `regexp` package API over the Rust `regex` engine.
//!
//! Patterns are parsed with Go's rules by [`syntax`] and handed to `regex` with every class
//! expanded. Both engines give leftmost-first matches with the same submatch semantics.
//!
//! Inputs are `&str`. Go also accepts invalid UTF-8, where each bad byte matches as U+FFFD; callers
//! holding raw bytes have to decide on a conversion themselves.

mod syntax;

pub use syntax::Error;

use regex::{CaptureLocations, Regex, RegexBuilder};

use crate::unicode::{is_digit, is_letter};

/// A compiled regular expression with Go's `regexp.Regexp` semantics.
#[derive(Clone, Debug)]
pub struct GoRegex {
    re: Regex,
    source: String,
    names: Vec<String>,
}

/// Rust's own compiled-size limit, set above anything Go's `expression too large` check accepts in
/// practice. A class-heavy pattern compiles larger in `regex` than in Go, because classes compile
/// to UTF-8 automata.
const RUST_SIZE_LIMIT: usize = 1 << 30;
/// The emitted pattern can nest up to Go's limit of 1000 groups, each possibly wrapped.
const RUST_NEST_LIMIT: u32 = 4000;
/// Deeply nested patterns recurse through the parser and compiler, so they get a dedicated stack.
const DEEP_PATTERN_PARENS: usize = 200;
const DEEP_PATTERN_STACK: usize = 256 << 20;

fn compile_on_this_thread(pattern: &str) -> Result<GoRegex, Error> {
    let parsed = syntax::parse(pattern)?;
    let re = RegexBuilder::new(&parsed.rust_pattern)
        .size_limit(RUST_SIZE_LIMIT)
        .nest_limit(RUST_NEST_LIMIT)
        .build()
        .map_err(|_| Error::new(syntax::ERR_LARGE, pattern))?;
    Ok(GoRegex {
        re,
        source: pattern.to_string(),
        names: parsed.names,
    })
}

impl GoRegex {
    /// `regexp.Compile`. Errors carry Go's exact text.
    pub fn compile(pattern: &str) -> Result<Self, Error> {
        if pattern.bytes().filter(|&b| b == b'(').count() < DEEP_PATTERN_PARENS {
            return compile_on_this_thread(pattern);
        }
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(DEEP_PATTERN_STACK)
                .spawn_scoped(scope, || compile_on_this_thread(pattern))
                .map_err(|_| Error::new(syntax::ERR_LARGE, pattern))?
                .join()
                .unwrap_or_else(|_| Err(Error::new(syntax::ERR_LARGE, pattern)))
        })
    }

    /// `regexp.MustCompile`.
    ///
    /// # Panics
    ///
    /// Panics if the pattern does not compile.
    pub fn must_compile(pattern: &str) -> Self {
        match Self::compile(pattern) {
            Ok(re) => re,
            Err(err) => panic!("regexp: Compile(`{pattern}`): {err}"),
        }
    }

    /// `Regexp.String`: the source pattern.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// The Rust pattern this compiled to, for debugging.
    pub fn rust_pattern(&self) -> &str {
        self.re.as_str()
    }

    /// `Regexp.NumSubexp`.
    pub fn num_subexp(&self) -> usize {
        self.names.len() - 1
    }

    /// `Regexp.SubexpNames`: index 0 and unnamed groups are empty.
    pub fn subexp_names(&self) -> &[String] {
        &self.names
    }

    /// `Regexp.SubexpIndex`: the leftmost group with that name.
    pub fn subexp_index(&self, name: &str) -> Option<usize> {
        if name.is_empty() {
            return None;
        }
        self.names.iter().position(|n| n == name)
    }

    /// `Regexp.MatchString`.
    pub fn match_string(&self, s: &str) -> bool {
        self.re.is_match(s)
    }

    /// `Regexp.FindString`, which is `""` for both no match and an empty match.
    pub fn find_string<'s>(&self, s: &'s str) -> &'s str {
        self.re.find(s).map_or("", |m| m.as_str())
    }

    /// `Regexp.FindStringIndex`.
    pub fn find_string_index(&self, s: &str) -> Option<(usize, usize)> {
        self.re.find(s).map(|m| (m.start(), m.end()))
    }

    fn exec(&self, locs: &mut CaptureLocations, s: &str, pos: usize) -> bool {
        self.re.captures_read_at(locs, s, pos).is_some()
    }

    fn offsets(locs: &CaptureLocations) -> Vec<isize> {
        let mut out = Vec::with_capacity(locs.len() * 2);
        for i in 0..locs.len() {
            match locs.get(i) {
                Some((start, end)) => {
                    out.push(start as isize);
                    out.push(end as isize);
                }
                None => {
                    out.push(-1);
                    out.push(-1);
                }
            }
        }
        out
    }

    /// `Regexp.FindStringSubmatchIndex`: offset pairs with -1 for groups that did not participate.
    pub fn find_string_submatch_index(&self, s: &str) -> Option<Vec<isize>> {
        let mut locs = self.re.capture_locations();
        self.exec(&mut locs, s, 0).then(|| Self::offsets(&locs))
    }

    /// `Regexp.FindStringSubmatch`: `""` for groups that did not participate.
    pub fn find_string_submatch<'s>(&self, s: &'s str) -> Option<Vec<&'s str>> {
        let mut locs = self.re.capture_locations();
        if !self.exec(&mut locs, s, 0) {
            return None;
        }
        Some(
            (0..locs.len())
                .map(|i| locs.get(i).map_or("", |(a, b)| &s[a..b]))
                .collect(),
        )
    }

    /// Port of `Regexp.allMatches`. `deliver` receives accepted matches.
    fn all_matches(&self, s: &str, n: isize, mut deliver: impl FnMut(&CaptureLocations)) {
        let n = if n < 0 { s.len() + 1 } else { n as usize };
        let end = s.len();
        let mut locs = self.re.capture_locations();
        let (mut pos, mut i) = (0usize, 0usize);
        let mut prev_match_end: Option<usize> = None;
        while i < n && pos <= end {
            if !self.exec(&mut locs, s, pos) {
                break;
            }
            let (m0, m1) = locs.get(0).unwrap_or((pos, pos));
            let mut accept = true;
            if m1 == pos {
                // An empty match right after a previous match is not allowed.
                if prev_match_end == Some(m0) {
                    accept = false;
                }
                pos = match s[pos..].chars().next() {
                    Some(c) => pos + c.len_utf8(),
                    None => end + 1,
                };
            } else {
                pos = m1;
            }
            prev_match_end = Some(m1);
            if accept {
                deliver(&locs);
                i += 1;
            }
        }
    }

    /// `Regexp.FindAllStringSubmatchIndex`. A negative `n` means all matches.
    pub fn find_all_string_submatch_index(&self, s: &str, n: isize) -> Vec<Vec<isize>> {
        let mut out = Vec::new();
        self.all_matches(s, n, |locs| out.push(Self::offsets(locs)));
        out
    }

    /// `Regexp.FindAllStringIndex`. A negative `n` means all matches.
    pub fn find_all_string_index(&self, s: &str, n: isize) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        self.all_matches(s, n, |locs| {
            if let Some(m) = locs.get(0) {
                out.push(m);
            }
        });
        out
    }

    /// `Regexp.FindAllString`. A negative `n` means all matches.
    pub fn find_all_string<'s>(&self, s: &'s str, n: isize) -> Vec<&'s str> {
        self.find_all_string_index(s, n)
            .into_iter()
            .map(|(a, b)| &s[a..b])
            .collect()
    }

    /// `Regexp.FindAllStringSubmatch`. A negative `n` means all matches.
    pub fn find_all_string_submatch<'s>(&self, s: &'s str, n: isize) -> Vec<Vec<&'s str>> {
        let mut out = Vec::new();
        self.all_matches(s, n, |locs| {
            out.push(
                (0..locs.len())
                    .map(|i| locs.get(i).map_or("", |(a, b)| &s[a..b]))
                    .collect(),
            );
        });
        out
    }

    /// Port of `Regexp.replaceAll`.
    fn replace_all(
        &self,
        src: &str,
        mut repl: impl FnMut(&mut String, &CaptureLocations),
    ) -> String {
        let end = src.len();
        let (mut last_match_end, mut search_pos) = (0usize, 0usize);
        let mut buf = String::new();
        let mut locs = self.re.capture_locations();
        while search_pos <= end {
            if !self.exec(&mut locs, src, search_pos) {
                break;
            }
            let (a0, a1) = locs.get(0).unwrap_or((search_pos, search_pos));
            // Copy the unmatched characters before this match.
            buf.push_str(&src[last_match_end..a0]);
            // Insert the replacement, but not for an empty match immediately after another match.
            if a1 > last_match_end || a0 == 0 {
                repl(&mut buf, &locs);
            }
            last_match_end = a1;
            // Advance past this match; always advance at least one character.
            let width = src[search_pos..].chars().next().map_or(0, char::len_utf8);
            if search_pos + width > a1 {
                search_pos += width;
            } else if search_pos + 1 > a1 {
                // Only needed at the end of the input, where the width is 0.
                search_pos += 1;
            } else {
                search_pos = a1;
            }
        }
        buf.push_str(&src[last_match_end..]);
        buf
    }

    /// `Regexp.ReplaceAllString`. `$1`, `${1}`, `$name`, and `$$` expand as in Go, where `$1x` is
    /// the group named `1x`, and name characters include any Unicode letter or digit.
    pub fn replace_all_string(&self, src: &str, repl: &str) -> String {
        self.replace_all(src, |buf, locs| self.expand(buf, repl, src, locs))
    }

    /// `Regexp.ReplaceAllLiteralString`.
    pub fn replace_all_literal_string(&self, src: &str, repl: &str) -> String {
        self.replace_all(src, |buf, _| buf.push_str(repl))
    }

    /// `Regexp.ReplaceAllStringFunc`.
    pub fn replace_all_string_func(
        &self,
        src: &str,
        mut repl: impl FnMut(&str) -> String,
    ) -> String {
        self.replace_all(src, |buf, locs| {
            if let Some((a, b)) = locs.get(0) {
                buf.push_str(&repl(&src[a..b]));
            }
        })
    }

    /// Port of `Regexp.expand`.
    fn expand(&self, dst: &mut String, mut template: &str, src: &str, locs: &CaptureLocations) {
        while let Some((before, after)) = template.split_once('$') {
            dst.push_str(before);
            template = after;
            if let Some(rest) = template.strip_prefix('$') {
                // Treat $$ as $.
                dst.push('$');
                template = rest;
                continue;
            }
            let Some((name, num, rest)) = extract(template) else {
                // Malformed; treat $ as raw text.
                dst.push('$');
                continue;
            };
            template = rest;
            if let Some(num) = num {
                if num < locs.len()
                    && let Some((a, b)) = locs.get(num)
                {
                    dst.push_str(&src[a..b]);
                }
            } else {
                // Go allows repeated names, and the first group that took part wins.
                for (i, group) in self.names.iter().enumerate() {
                    if group == name
                        && let Some((a, b)) = locs.get(i)
                    {
                        dst.push_str(&src[a..b]);
                        break;
                    }
                }
            }
        }
        dst.push_str(template);
    }

    /// `Regexp.Split`.
    pub fn split<'s>(&self, s: &'s str, n: isize) -> Vec<&'s str> {
        if n == 0 {
            return Vec::new();
        }
        if !self.source.is_empty() && s.is_empty() {
            return vec![""];
        }
        let matches = self.find_all_string_index(s, n);
        let mut out = Vec::with_capacity(matches.len());
        let (mut beg, mut end) = (0usize, 0usize);
        for (m0, m1) in matches {
            if n > 0 && out.len() as isize >= n - 1 {
                break;
            }
            end = m0;
            if m1 != 0 {
                out.push(&s[beg..end]);
            }
            beg = m1;
        }
        if end != s.len() {
            out.push(&s[beg..]);
        }
        out
    }
}

/// Port of `regexp.extract`: `(name, group number, rest)`.
fn extract(input: &str) -> Option<(&str, Option<usize>, &str)> {
    if input.is_empty() {
        return None;
    }
    let (brace, body) = match input.strip_prefix('{') {
        Some(rest) => (true, rest),
        None => (false, input),
    };
    let mut i = 0;
    for c in body.chars() {
        if !is_letter(c as u32) && !is_digit(c as u32) && c != '_' {
            break;
        }
        i += c.len_utf8();
    }
    if i == 0 {
        return None;
    }
    let name = &body[..i];
    if brace {
        if body.as_bytes().get(i) != Some(&b'}') {
            return None;
        }
        i += 1;
    }
    let mut num = Some(0usize);
    for &b in name.as_bytes() {
        match num {
            Some(n) if b.is_ascii_digit() && n < 100_000_000 => {
                num = Some(n * 10 + usize::from(b - b'0'))
            }
            _ => {
                num = None;
                break;
            }
        }
    }
    // Disallow leading zeros.
    if name.as_bytes()[0] == b'0' && name.len() > 1 {
        num = None;
    }
    Some((name, num, &body[i..]))
}

/// `regexp.QuoteMeta`.
pub fn quote_meta(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
