//! `internal/lang` with the parts of `golang.org/x/text/language` it rests on.
//!
//! BCP 47 tags in settings values canonicalize exactly as `language.Parse` does: same aliases, same
//! unknown-subtag failures, same extension ordering. The parser below is a port of x/text's
//! `internal/language/parse.go`, and `lang_tables.rs` is dumped from the real package by the
//! generator under `rust/conformance/vectors/generators/config`.

use crate::lang_tables as tables;
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strings::{to_lower, trim_space};
use std::sync::OnceLock;

fn in_fixed(table: &str, width: usize, code: &str) -> bool {
    let b = table.as_bytes();
    let n = b.len() / width;
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let elem = &b[mid * width..(mid + 1) * width];
        match elem.cmp(code.as_bytes()) {
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    false
}

fn in_map(table: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table
        .binary_search_by(|(k, _)| (*k).cmp(key))
        .ok()
        .map(|i| table[i].1)
}

/// `getLangID`: the canonical id of a 2- or 3-letter code.
fn get_lang_id(token: &[u8]) -> Option<String> {
    let n = token.len();
    if n != 2 && n != 3 {
        return None;
    }
    if !token.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let code: String = token.iter().map(|c| (c | 0x20) as char).collect();
    if n == 2 {
        return in_fixed(tables::LANG2, 2, &code).then_some(code);
    }
    if let Some(id) = in_map(tables::LANG3_MAP, &code) {
        return Some(id.to_owned());
    }
    in_fixed(tables::LANG3, 3, &code).then_some(code)
}

fn get_script_id(token: &[u8]) -> Option<String> {
    if token.len() != 4 || !token.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let mut code = String::with_capacity(4);
    code.push((token[0] & !0x20) as char);
    for c in &token[1..] {
        code.push((c | 0x20) as char);
    }
    in_fixed(tables::SCRIPTS, 4, &code).then_some(code)
}

fn is_alpha(b: u8) -> bool {
    b > b'9'
}

fn get_region_id(token: &[u8]) -> Option<String> {
    if token.len() == 3 {
        if is_alpha(token[0]) {
            if !token.iter().all(u8::is_ascii_alphabetic) {
                return None;
            }
            let code: String = token.iter().map(|c| (c & !0x20) as char).collect();
            return in_map(tables::REGION3_MAP, &code).map(str::to_owned);
        }
        if token.iter().all(u8::is_ascii_digit) {
            let code = std::str::from_utf8(token).ok()?;
            return in_map(tables::M49_MAP, code).map(str::to_owned);
        }
        return None;
    }
    if token.len() != 2 || !token.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let code: String = token.iter().map(|c| (c & !0x20) as char).collect();
    in_fixed(tables::REGIONS2, 2, &code).then_some(code)
}

fn variant_index(token: &[u8]) -> Option<u8> {
    let name = std::str::from_utf8(token).ok()?;
    tables::VARIANTS
        .binary_search_by(|(k, _)| (*k).cmp(name))
        .ok()
        .map(|i| tables::VARIANTS[i].1)
}

#[derive(Debug, Clone, Default)]
struct Tag {
    lang: String,
    script: Option<String>,
    region: Option<String>,
    str_: Option<String>,
    p_variant: usize,
}

impl Tag {
    fn und() -> Self {
        Tag {
            lang: "und".to_owned(),
            ..Default::default()
        }
    }

    fn core(&self) -> String {
        let mut out = self.lang.clone();
        if let Some(s) = &self.script {
            out.push('-');
            out.push_str(s);
        }
        if let Some(r) = &self.region {
            out.push('-');
            out.push_str(r);
        }
        out
    }

    fn string(&self) -> String {
        self.str_.clone().unwrap_or_else(|| self.core())
    }

    fn is_bare_und(&self) -> bool {
        self.lang == "und" && self.script.is_none() && self.region.is_none()
    }

    fn remake_string(&mut self) {
        let Some(str_) = &self.str_ else {
            return;
        };
        let mut extra = &str_[self.p_variant..];
        if self.p_variant > 0 {
            extra = extra.strip_prefix('-').unwrap_or(extra);
        }
        if self.is_bare_und() && extra.starts_with("x-") {
            let e = extra.to_owned();
            self.str_ = Some(e);
            self.p_variant = 0;
            return;
        }
        let core = self.core();
        if extra.is_empty() {
            self.p_variant = core.len();
            self.str_ = Some(core);
        } else {
            let joined = format!("{core}-{extra}");
            self.p_variant = core.len();
            self.str_ = Some(joined);
        }
    }
}

struct Scanner {
    b: Vec<u8>,
    token: Vec<u8>,
    start: usize,
    end: usize,
    next: usize,
    err: bool,
}

fn is_alnum(s: &[u8]) -> bool {
    s.iter().all(u8::is_ascii_alphanumeric)
}

impl Scanner {
    fn new(s: &str) -> Self {
        let mut b = s.as_bytes().to_vec();
        for c in &mut b {
            if *c == b'_' {
                *c = b'-';
            }
        }
        let mut sc = Scanner {
            b,
            token: Vec::new(),
            start: 0,
            end: 0,
            next: 0,
            err: false,
        };
        sc.scan();
        sc
    }

    fn lowercase_range(&mut self, start: usize, end: usize) {
        for c in &mut self.b[start..end] {
            c.make_ascii_lowercase();
        }
    }

    fn resize_range(&mut self, old_start: usize, old_end: usize, new_size: usize) {
        self.start = old_start;
        let end = old_start + new_size;
        if end != old_end {
            let tail = self.b[old_end..].to_vec();
            self.b.truncate(old_start);
            self.b.resize(end, 0);
            self.b.extend_from_slice(&tail);
            self.next = (end + self.next).wrapping_sub(self.end);
            self.end = end;
        }
    }

    fn replace(&mut self, repl: &str) {
        self.resize_range(self.start, self.end, repl.len());
        let s = self.start;
        self.b[s..s + repl.len()].copy_from_slice(repl.as_bytes());
    }

    fn gobble(&mut self, set_err: bool) {
        if set_err {
            self.err = true;
        }
        if self.start == 0 {
            self.b.drain(..self.next);
            self.end = 0;
        } else {
            self.b.drain(self.start - 1..self.end);
            self.end = self.start - 1;
        }
        self.next = self.start;
    }

    fn delete_range(&mut self, start: usize, end: usize) {
        self.b.drain(start..end);
        let diff = end - start;
        self.next -= diff;
        self.start -= diff;
        self.end -= diff;
    }

    fn scan(&mut self) -> usize {
        let end = self.end;
        self.token.clear();
        self.start = self.next;
        while self.next < self.b.len() {
            let i;
            match self.b[self.next..].iter().position(|&c| c == b'-') {
                None => {
                    self.end = self.b.len();
                    self.next = self.b.len();
                    i = self.end - self.start;
                }
                Some(p) => {
                    i = p;
                    self.end = self.next + p;
                    self.next = self.end + 1;
                }
            }
            let token = &self.b[self.start..self.end];
            if !(1..=8).contains(&i) || !is_alnum(token) {
                self.gobble(true);
                self.start = self.next;
                continue;
            }
            self.token = token.to_vec();
            return end;
        }
        if let Some(&last) = self.b.last()
            && last == b'-'
        {
            self.err = true;
            self.b.pop();
        }
        end
    }

    fn accept_min_size(&mut self, min: usize) -> usize {
        let mut end = self.end;
        self.scan();
        while self.token.len() >= min {
            end = self.end;
            self.scan();
        }
        end
    }
}

fn parse_tag(scan: &mut Scanner, do_norm: bool) -> (Tag, usize) {
    let mut t = Tag::default();
    let lang = get_lang_id(&scan.token);
    if lang.is_none() {
        scan.err = true;
    }
    t.lang = lang.unwrap_or_else(|| "und".to_owned());
    let l = t.lang.clone();
    scan.replace(&l);
    let lang_start = scan.start;
    let mut end = scan.scan();
    while scan.token.len() == 3 && is_alpha(scan.token[0]) {
        if do_norm {
            let lang = get_lang_id(&scan.token);
            let failed = lang.is_none();
            if let Some(lang) = lang.filter(|l| l != "und") {
                t.lang.clone_from(&lang);
                let n = lang.len();
                scan.b[lang_start..lang_start + n].copy_from_slice(lang.as_bytes());
                scan.b[lang_start + n] = b'-';
                scan.start = lang_start + n + 1;
            }
            scan.gobble(failed);
        }
        end = scan.scan();
    }
    if scan.token.len() == 4 && is_alpha(scan.token[0]) {
        match get_script_id(&scan.token) {
            Some(s) => {
                let st = scan.start;
                scan.b[st..st + 4].copy_from_slice(s.as_bytes());
                t.script = Some(s);
            }
            None => scan.gobble(true),
        }
        end = scan.scan();
    }
    let n = scan.token.len();
    if (2..=3).contains(&n) {
        match get_region_id(&scan.token) {
            Some(r) => {
                scan.replace(&r);
                t.region = Some(r);
            }
            None => scan.gobble(true),
        }
        end = scan.scan();
    }
    let (st, len) = (scan.start, scan.b.len());
    if st <= len {
        scan.lowercase_range(st, len);
    }
    t.p_variant = end;
    end = parse_variants(scan, end);
    (t, end)
}

fn parse_variants(scan: &mut Scanner, mut end: usize) -> usize {
    let start = scan.start;
    let mut var_id: Vec<u8> = Vec::new();
    let mut variant: Vec<Vec<u8>> = Vec::new();
    let mut last = -1i32;
    let mut need_sort = false;
    while scan.token.len() >= 4 {
        let Some(v) = variant_index(&scan.token) else {
            scan.gobble(true);
            scan.scan();
            continue;
        };
        var_id.push(v);
        variant.push(scan.token.clone());
        if !need_sort {
            if last < i32::from(v) {
                last = i32::from(v);
            } else {
                need_sort = true;
                if var_id.len() > 8 {
                    break;
                }
            }
        }
        end = scan.end;
        scan.scan();
    }
    if need_sort {
        let mut pairs: Vec<(u8, Vec<u8>)> = var_id.into_iter().zip(variant).collect();
        pairs.sort_by_key(|p| p.0);
        pairs.dedup_by_key(|p| p.0);
        let joined = pairs
            .iter()
            .map(|p| p.1.clone())
            .collect::<Vec<_>>()
            .join(&b'-');
        if joined.is_empty() {
            end = start - 1;
        } else {
            scan.resize_range(start, end, joined.len());
            let s = scan.start;
            scan.b[s..s + joined.len()].copy_from_slice(&joined);
            end = scan.end;
        }
    }
    end
}

fn parse_extensions(scan: &mut Scanner) -> usize {
    let start = scan.start;
    let mut exts: Vec<Vec<u8>> = Vec::new();
    let mut private: Vec<u8> = Vec::new();
    let mut end = scan.end;
    while scan.token.len() == 1 {
        let ext_start = scan.start;
        let ext = scan.token[0];
        end = parse_extension(scan);
        let extension = scan.b[ext_start..end].to_vec();
        if extension.len() < 3 || (ext != b'x' && extension.len() < 4) {
            scan.err = true;
            end = ext_start;
            continue;
        } else if start == ext_start && (ext == b'x' || scan.start == scan.b.len()) {
            scan.b.truncate(end);
            return end;
        } else if ext == b'x' {
            private = extension;
            break;
        }
        exts.push(extension);
    }
    exts.sort_by_key(|e| e[0]);
    if !private.is_empty() {
        exts.push(private);
    }
    scan.b.truncate(start);
    if !exts.is_empty() {
        scan.b.extend_from_slice(&exts.join(&b'-'));
    } else if start > 0 {
        scan.b.truncate(start - 1);
    }
    end
}

fn parse_extension(scan: &mut Scanner) -> usize {
    let (start, mut end) = (scan.start, scan.end);
    match scan.token[0] {
        b'u' => {
            let attr_start = end;
            scan.scan();
            if scan.token.len() > 2 {
                let p = attr_start + 1;
                scan.next = p;
                let mut attrs: Vec<Vec<u8>> = Vec::new();
                scan.scan();
                while scan.token.len() > 2 {
                    attrs.push(scan.token.clone());
                    end = scan.end;
                    scan.scan();
                }
                attrs.sort_by(|a, b| a[..3].cmp(&b[..3]));
                let joined = attrs.join(&b'-');
                scan.b[p..p + joined.len()].copy_from_slice(&joined);
            }
            let attr_end = end;
            let mut last: Vec<u8> = Vec::new();
            while scan.token.len() == 2 {
                let key = scan.token.clone();
                end = scan.end;
                scan.scan();
                while end < scan.end && scan.token.len() > 2 {
                    end = scan.end;
                    scan.scan();
                }
                if key <= last || scan.err {
                    let p = attr_end + 1;
                    scan.next = p;
                    let mut keys: Vec<Vec<u8>> = Vec::new();
                    scan.scan();
                    while scan.token.len() == 2 {
                        let key_start = scan.start;
                        end = scan.end;
                        scan.scan();
                        while end < scan.end && scan.token.len() > 2 {
                            end = scan.end;
                            scan.scan();
                        }
                        keys.push(scan.b[key_start..end].to_vec());
                    }
                    keys.sort_by(|a, b| a[..2].cmp(&b[..2]));
                    if !keys.is_empty() {
                        let mut k = 0;
                        for i in 1..keys.len() {
                            if keys[k][..2] != keys[i][..2] {
                                k += 1;
                                keys[k] = keys[i].clone();
                            } else if keys[k] != keys[i] {
                                scan.err = true;
                            }
                        }
                        keys.truncate(k + 1);
                    }
                    let reordered = keys.join(&b'-');
                    let e = p + reordered.len();
                    if e < end {
                        scan.delete_range(e, end);
                        end = e;
                    }
                    scan.b[p..p + reordered.len()].copy_from_slice(&reordered);
                    break;
                }
                last = key;
            }
        }
        b't' => {
            scan.scan();
            let n = scan.token.len();
            if (2..=3).contains(&n) && is_alpha(scan.token[1]) {
                let (_, e) = parse_tag(scan, false);
                end = e;
                scan.lowercase_range(start, end);
            }
            while scan.token.len() == 2 && !is_alpha(scan.token[1]) {
                end = scan.accept_min_size(3);
            }
        }
        b'x' => end = scan.accept_min_size(1),
        _ => end = scan.accept_min_size(2),
    }
    end
}

const MAX_ALT_TAG_LEN: usize = 11;

fn grandfathered(s: &str) -> Option<Tag> {
    if s.chars().count() > MAX_ALT_TAG_LEN || s.len() > MAX_ALT_TAG_LEN {
        return None;
    }
    let key: String = s
        .bytes()
        .map(|c| match c {
            b'A'..=b'Z' => (c + 32) as char,
            b'_' => '-',
            _ => c as char,
        })
        .collect();
    let lang = match key.as_str() {
        "art-lojban" => "jbo",
        "i-ami" => "ami",
        "i-bnn" => "bnn",
        "i-hak" => "hak",
        "i-klingon" => "tlh",
        "i-lux" => "lb",
        "i-navajo" => "nv",
        "i-pwn" => "pwn",
        "i-tao" => "tao",
        "i-tay" => "tay",
        "i-tsu" => "tsu",
        "no-bok" => "nb",
        "no-nyn" => "nn",
        "sgn-be-fr" => "sfb",
        "sgn-be-nl" => "vgt",
        "sgn-ch-de" => "sgg",
        "zh-guoyu" => "cmn",
        "zh-hakka" => "hak",
        "zh-min-nan" => "nan",
        "zh-xiang" => "hsn",
        "root" => "und",
        "cel-gaulish" => return Some(parse_raw("xtg-x-cel-gaulish").0),
        "en-gb-oed" => return Some(parse_raw("en-GB-oxendict").0),
        "i-default" => return Some(parse_raw("en-x-i-default").0),
        "i-enochian" => return Some(parse_raw("und-x-i-enochian").0),
        "i-mingo" => return Some(parse_raw("see-x-i-mingo").0),
        "zh-min" => return Some(parse_raw("nan-x-zh-min").0),
        "en-us-posix" => return Some(parse_raw("en-US-u-va-posix").0),
        _ => return None,
    };
    Some(Tag {
        lang: lang.to_owned(),
        ..Default::default()
    })
}

fn parse_raw(s: &str) -> (Tag, bool) {
    let mut scan = Scanner::new(s);
    let mut t = Tag::und();
    let mut end;
    let n = scan.token.len();
    if n <= 1 {
        let len = scan.b.len();
        scan.lowercase_range(0, len);
        if n == 0 || scan.token[0] != b'x' {
            return (t, true);
        }
        end = parse_extensions(&mut scan);
    } else if n >= 4 {
        return (Tag::und(), true);
    } else {
        (t, end) = parse_tag(&mut scan, true);
        if scan.token.len() == 1 {
            end = parse_extensions(&mut scan);
        } else if end < scan.b.len() {
            scan.err = true;
            scan.b.truncate(end);
        }
    }
    let _ = &mut end;
    if t.p_variant < scan.b.len() {
        t.str_ = Some(String::from_utf8_lossy(&scan.b).into_owned());
    } else {
        t.p_variant = 0;
    }
    (t, scan.err)
}

/// `language.Parse`: `Some` with the canonical string, `None` for any parse error.
pub fn language_parse(s: &str) -> Option<String> {
    let (mut t, failed) = if s.is_empty() {
        return None;
    } else if let Some(t) = grandfathered(s) {
        (t, false)
    } else {
        parse_raw(s)
    };
    if failed {
        return None;
    }
    // canonicalize with language.Default: DeprecatedBase | Legacy.
    let mut changed = false;
    let mut guard = 0;
    while let Some(to) = in_map(tables::LANG_CANON, &t.lang) {
        guard += 1;
        if to == t.lang || guard > 8 {
            break;
        }
        if t.lang == "sh" && t.script.is_none() {
            t.script = Some("Latn".to_owned());
        }
        if t.lang == "mo" && t.region.is_none() {
            t.region = Some("MD".to_owned());
        }
        t.lang = to.to_owned();
        changed = true;
    }
    if changed {
        t.remake_string();
    }
    Some(t.string())
}

/// `language.ParseBase`: the canonical language id, or `None` when unknown.
pub fn parse_base(s: &str) -> Option<String> {
    if !(2..=3).contains(&s.len()) {
        return None;
    }
    get_lang_id(s.as_bytes())
}

fn language_tag_pattern() -> &'static GoRegex {
    static RE: OnceLock<GoRegex> = OnceLock::new();
    RE.get_or_init(|| {
        GoRegex::must_compile(concat!(
            r"^([a-zA-Z]{2,3}(-[a-zA-Z]{3}){0,3}(-[a-zA-Z]{4})?(-([a-zA-Z]{2}|[0-9]{3}))?",
            r"(-([0-9a-zA-Z]{5,8}|[0-9][0-9a-zA-Z]{3}))*",
            r"(-[0-9a-wy-zA-WY-Z](-[0-9a-zA-Z]{2,8})+)*",
            r"(-[xX](-[0-9a-zA-Z]{1,8})+)?",
            r"|[xX](-[0-9a-zA-Z]{1,8})+)$",
        ))
    })
}

fn is_alpha_str(value: &str) -> bool {
    value.chars().all(|r| r.is_ascii_alphabetic())
}

fn canonical_tag_case(tag: &str) -> String {
    let mut parts: Vec<String> = tag.split('-').map(str::to_owned).collect();
    parts[0] = to_lower(&parts[0]);
    let mut in_extension = parts[0] == "x";
    for part in parts.iter_mut().skip(1) {
        let p = part.clone();
        if p.len() == 1 {
            in_extension = true;
            *part = to_lower(&p);
        } else if in_extension {
            *part = to_lower(&p);
        } else if p.len() == 4 && is_alpha_str(&p) {
            *part = silo_gocompat::strings::to_upper(&p[..1]) + &to_lower(&p[1..]);
        } else if p.len() == 2 && is_alpha_str(&p) {
            *part = silo_gocompat::strings::to_upper(&p);
        } else {
            *part = to_lower(&p);
        }
    }
    parts.join("-")
}

fn has_duplicate_subtags(value: &str) -> bool {
    let lowered = to_lower(value);
    let parts: Vec<&str> = lowered.split('-').collect();
    let mut variants = std::collections::HashSet::new();
    let mut singletons = std::collections::HashSet::new();
    let mut private_use = parts[0] == "x";
    let mut extension_started = false;
    for part in parts.iter().skip(1) {
        if private_use {
            continue;
        }
        if part.len() == 1 {
            if !singletons.insert(*part) {
                return true;
            }
            extension_started = true;
            if *part == "x" {
                private_use = true;
            }
            continue;
        }
        let first_digit = part.as_bytes().first().is_some_and(u8::is_ascii_digit);
        if !extension_started
            && (part.len() >= 5 || (part.len() == 4 && first_digit))
            && !variants.insert(*part)
        {
            return true;
        }
    }
    false
}

fn grandfathered_tag(value: &str) -> String {
    if !value.contains('-') {
        return String::new();
    }
    match language_parse(value) {
        Some(tag) if tag != "und" => tag,
        _ => String::new(),
    }
}

/// `lang.CanonicalTag`.
pub fn canonical_tag(value: &str) -> String {
    let value = trim_space(value).replace('_', "-");
    if !language_tag_pattern().match_string(&value) {
        return grandfathered_tag(&value);
    }
    if has_duplicate_subtags(&value) {
        return String::new();
    }
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() > 1 && parts[1].len() == 3 && is_alpha_str(parts[1]) {
        return canonical_tag_case(&value);
    }
    if let Some(tag) = language_parse(&value) {
        return tag;
    }
    canonical_tag_case(&value)
}

fn language_name(lowered: &str) -> Option<&'static str> {
    Some(match lowered {
        "english" => "en",
        "spanish" => "es",
        "french" => "fr",
        "german" => "de",
        "italian" => "it",
        "portuguese" => "pt",
        "japanese" => "ja",
        "korean" => "ko",
        "chinese" => "zh",
        "russian" => "ru",
        "arabic" => "ar",
        "dutch" => "nl",
        "polish" => "pl",
        "swedish" => "sv",
        "norwegian" => "no",
        "danish" => "da",
        "finnish" => "fi",
        "greek" => "el",
        "turkish" => "tr",
        "hungarian" => "hu",
        "czech" => "cs",
        "romanian" => "ro",
        "hebrew" => "he",
        "hindi" => "hi",
        "thai" => "th",
        "vietnamese" => "vi",
        "indonesian" => "id",
        "ukrainian" => "uk",
        "bengali" | "bangla" => "bn",
        "bulgarian" => "bg",
        "croatian" => "hr",
        "persian" | "farsi" => "fa",
        "malay" => "ms",
        "serbian" => "sr",
        "slovak" => "sk",
        "slovenian" => "sl",
        "tamil" => "ta",
        "telugu" => "te",
        "estonian" => "et",
        "latvian" => "lv",
        "lithuanian" => "lt",
        "icelandic" => "is",
        "brazilian portuguese" | "brazillian portuguese" | "portuguese (brazil)" => "pt-BR",
        "portuguese (portugal)" | "european portuguese" => "pt-PT",
        "chinese (traditional)" | "traditional chinese" => "zh-Hant",
        "chinese (simplified)" | "simplified chinese" => "zh-Hans",
        _ => return None,
    })
}

/// `lang.CompatibleTag`.
pub fn compatible_tag(value: &str) -> String {
    let value = trim_space(value);
    match language_name(&to_lower(value)) {
        Some(mapped) => canonical_tag(mapped),
        None => canonical_tag(value),
    }
}

/// `lang.RegisteredTag`.
pub fn registered_tag(value: &str) -> String {
    let tag = compatible_tag(value);
    let primary = tag.split('-').next().unwrap_or("");
    if primary.is_empty() || parse_base(primary).is_none() {
        return String::new();
    }
    tag
}

/// `lang.PrimaryLanguage`.
pub fn primary_language(value: &str) -> String {
    let canonical = compatible_tag(value);
    let base = canonical.split('-').next().unwrap_or("");
    if base == "und" || base == "x" {
        return String::new();
    }
    base.to_owned()
}

fn iso3_of(id: &str) -> String {
    in_map(tables::LANG_ISO3, id).unwrap_or(id).to_owned()
}

/// `lang.ISO6392`.
pub fn iso6392(value: &str) -> String {
    let primary = primary_language(value);
    if primary.is_empty() {
        return String::new();
    }
    let Some(tag) = language_parse(&primary) else {
        return String::new();
    };
    let base = tag.split('-').next().unwrap_or("");
    let code = iso3_of(base);
    if code == "und" { String::new() } else { code }
}

/// `lang.CodeAliases`.
pub fn code_aliases(value: &str) -> Vec<String> {
    let canonical = canonical_tag(value);
    if canonical.is_empty() {
        return Vec::new();
    }
    let mut aliases = vec![canonical.clone()];
    if canonical.contains('-') {
        return aliases;
    }
    if let Some(tag) = language_parse(&canonical) {
        let base = tag.split('-').next().unwrap_or("");
        // Tag.Base infers English for an undetermined language.
        let iso3 = if base == "und" {
            "eng".to_owned()
        } else {
            iso3_of(base)
        };
        if iso3 != canonical && iso3 != "und" {
            aliases.push(iso3);
        }
    }
    let biblio = match canonical.as_str() {
        "sq" => "alb",
        "hy" => "arm",
        "eu" => "baq",
        "my" => "bur",
        "zh" => "chi",
        "cs" => "cze",
        "nl" => "dut",
        "fr" => "fre",
        "ka" => "geo",
        "de" => "ger",
        "el" => "gre",
        "is" => "ice",
        "mk" => "mac",
        "mi" => "mao",
        "ms" => "may",
        "fa" => "per",
        "ro" => "rum",
        "sk" => "slo",
        "bo" => "tib",
        "cy" => "wel",
        _ => "",
    };
    if !biblio.is_empty() {
        aliases.push(biblio.to_owned());
    }
    aliases
}

/// `lang.CanonicalCountry`.
pub fn canonical_country(value: &str) -> String {
    let trimmed = silo_gocompat::strings::to_upper(trim_space(value));
    if trimmed.is_empty() {
        return String::new();
    }
    if !(2..=3).contains(&trimmed.len()) {
        return trimmed;
    }
    get_region_id(trimmed.as_bytes()).unwrap_or(trimmed)
}
