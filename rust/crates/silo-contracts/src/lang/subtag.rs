//! Port of the parts of `golang.org/x/text/internal/language` and `.../language` that
//! `language.Parse`, `language.ParseBase`, and `Tag.String` need, using Go's frozen tables.
//!
//! The scanner edits its buffer in place, as Go's does, so behavior on malformed input follows the
//! same steps. Go recovers from an out-of-range panic while parsing and reports a syntax error. Here
//! the same out-of-range cases return [`ParseError::Syntax`].

#[allow(unused_imports)]
use super::tables::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Syntax,
    /// Well-formed but unknown (`ValueError`).
    Value,
    /// Different values for one key in a `-u` extension.
    DuplicateKey,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Tag {
    lang: u16,
    region: u16,
    script: u16,
    // Offset in str, includes the preceding '-'. These wrap like Go's byte and uint16 fields.
    p_variant: u8,
    p_ext: u16,
    str: String,
}

const MAX_ALT_TAGLEN: usize = "en-US-POSIX".len();

// grandfatheredMap: positive entries name a language, the others the alternate tags.
const GRANDFATHERED: &[(&str, Grandfathered)] = &[
    ("art-lojban", Grandfathered::Lang("jbo")),
    ("i-ami", Grandfathered::Lang("ami")),
    ("i-bnn", Grandfathered::Lang("bnn")),
    ("i-hak", Grandfathered::Lang("hak")),
    ("i-klingon", Grandfathered::Lang("tlh")),
    ("i-lux", Grandfathered::Lang("lb")),
    ("i-navajo", Grandfathered::Lang("nv")),
    ("i-pwn", Grandfathered::Lang("pwn")),
    ("i-tao", Grandfathered::Lang("tao")),
    ("i-tay", Grandfathered::Lang("tay")),
    ("i-tsu", Grandfathered::Lang("tsu")),
    ("no-bok", Grandfathered::Lang("nb")),
    ("no-nyn", Grandfathered::Lang("nn")),
    ("sgn-be-fr", Grandfathered::Lang("sfb")),
    ("sgn-be-nl", Grandfathered::Lang("vgt")),
    ("sgn-ch-de", Grandfathered::Lang("sgg")),
    ("zh-guoyu", Grandfathered::Lang("cmn")),
    ("zh-hakka", Grandfathered::Lang("hak")),
    ("zh-min-nan", Grandfathered::Lang("nan")),
    ("zh-xiang", Grandfathered::Lang("hsn")),
    ("cel-gaulish", Grandfathered::Alt("xtg-x-cel-gaulish")),
    ("en-gb-oed", Grandfathered::Alt("en-GB-oxendict")),
    ("i-default", Grandfathered::Alt("en-x-i-default")),
    ("i-enochian", Grandfathered::Alt("und-x-i-enochian")),
    ("i-mingo", Grandfathered::Alt("see-x-i-mingo")),
    ("zh-min", Grandfathered::Alt("nan-x-zh-min")),
    ("root", Grandfathered::Root),
    ("en-us-posix", Grandfathered::Alt("en-US-u-va-posix")),
];

#[derive(Clone, Copy)]
enum Grandfathered {
    Lang(&'static str),
    Alt(&'static str),
    Root,
}

// --- internal/tag ---

fn cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.cmp(b)
}

fn elem(table: &[u8], x: usize) -> &[u8] {
    &table[x * 4..x * 4 + 4]
}

// tag.Index.Index: table entries are 4 bytes and the key a prefix of 1 to 4 bytes.
fn index(table: &[u8], key: &[u8]) -> Option<usize> {
    let n = key.len();
    let count = table.len() / 4;
    let (mut lo, mut hi) = (0, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if cmp(&table[mid * 4..mid * 4 + n], key) == std::cmp::Ordering::Less {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let i = lo * 4;
    if i + n > table.len() || &table[i..i + n] != key {
        return None;
    }
    Some(lo)
}

fn next(table: &[u8], key: &[u8], x: usize) -> Option<usize> {
    let x = x + 1;
    if x * 4 < table.len() && &table[x * 4..x * 4 + key.len()] == key {
        Some(x)
    } else {
        None
    }
}

// tag.FixCase: rewrites b to the case form uses, if it fits the form.
fn fix_case(form: &[u8], b: &mut [u8]) -> bool {
    if form.len() != b.len() {
        return false;
    }
    let mut out = b.to_vec();
    for (i, slot) in out.iter_mut().enumerate() {
        let mut c = *slot;
        if form[i] <= b'Z' {
            if c >= b'a' {
                c = c.wrapping_sub(b'z' - b'Z');
            }
            if !c.is_ascii_uppercase() {
                return false;
            }
        } else {
            if c <= b'Z' {
                c = c.wrapping_add(b'z' - b'Z');
            }
            if !c.is_ascii_lowercase() {
                return false;
            }
        }
        *slot = c;
    }
    b.copy_from_slice(&out);
    true
}

// --- lookup.go ---

fn get_lang_id(s: &mut [u8]) -> Result<u16, ParseError> {
    if s.len() == 2 {
        get_lang_iso2(s)
    } else {
        get_lang_iso3(s)
    }
}

fn get_lang_iso2(s: &mut [u8]) -> Result<u16, ParseError> {
    if !fix_case(b"zz", s) {
        return Err(ParseError::Syntax);
    }
    if let Some(i) = index(LANG, s)
        && elem(LANG, i)[3] != 0
    {
        return Ok(i as u16);
    }
    Err(ParseError::Value)
}

fn str_to_int(s: &[u8]) -> usize {
    s.iter()
        .fold(0, |v, c| v * 26 + usize::from(c.wrapping_sub(b'a')))
}

fn get_lang_iso3(s: &mut [u8]) -> Result<u16, ParseError> {
    if !fix_case(b"und", s) {
        return Err(ParseError::Syntax);
    }
    let mut at = index(LANG, &s[..2]);
    while let Some(i) = at {
        let e = elem(LANG, i);
        if e[3] == 0 && e[2] == s[2] {
            if i as u16 == NON_CANONICAL_UND {
                return Ok(0);
            }
            return Ok(i as u16);
        }
        at = next(LANG, &s[..2], i);
    }
    if let Some(i) = index(ALT_LANG_ISO3, s) {
        return Ok(ALT_LANG_INDEX[usize::from(elem(ALT_LANG_ISO3, i)[3])]);
    }
    let n = str_to_int(s);
    if LANG_NO_INDEX[n / 8] & (1 << (n % 8)) != 0 {
        return Ok(n as u16 + LANG_NO_INDEX_OFFSET);
    }
    let mut at = index(LANG, &s[..1]);
    while let Some(i) = at {
        let e = elem(LANG, i);
        if e[2] == s[1] && e[3] == s[2] {
            return Ok(i as u16);
        }
        at = next(LANG, &s[..1], i);
    }
    Err(ParseError::Value)
}

fn lang_string(id: u16) -> String {
    if id == 0 {
        return "und".to_string();
    }
    if id >= LANG_NO_INDEX_OFFSET {
        let mut v = usize::from(id - LANG_NO_INDEX_OFFSET);
        let mut buf = [0u8; 3];
        for slot in buf.iter_mut().rev() {
            *slot = (v % 26) as u8 + b'a';
            v /= 26;
        }
        return String::from_utf8_lossy(&buf).into_owned();
    }
    let l = elem(LANG, usize::from(id));
    let n = if l[3] == 0 { 3 } else { 2 };
    String::from_utf8_lossy(&l[..n]).into_owned()
}

fn get_region_id(s: &mut [u8]) -> Result<u16, ParseError> {
    if s.len() == 3 {
        if s[0] > b'9' {
            return get_region_iso3(s);
        }
        // strconv.ParseUint(s, 10, 10)
        if s.iter().all(u8::is_ascii_digit) {
            let n = s
                .iter()
                .fold(0usize, |v, c| v * 10 + usize::from(*c - b'0'));
            if n < 1024 {
                return get_region_m49(n);
            }
        }
    }
    get_region_iso2(s)
}

fn get_region_iso2(s: &mut [u8]) -> Result<u16, ParseError> {
    if !fix_case(b"ZZ", s) {
        return Err(ParseError::Syntax);
    }
    match index(REGION_ISO, s) {
        Some(i) => Ok(i as u16 + ISO_REGION_OFFSET),
        None => Err(ParseError::Value),
    }
}

fn get_region_iso3(s: &mut [u8]) -> Result<u16, ParseError> {
    if !fix_case(b"ZZZ", s) {
        return Err(ParseError::Syntax);
    }
    let mut at = index(REGION_ISO, &s[..1]);
    while let Some(i) = at {
        let e = elem(REGION_ISO, i);
        if e[2] == s[1] && e[3] == s[2] {
            return Ok(i as u16 + ISO_REGION_OFFSET);
        }
        at = next(REGION_ISO, &s[..1], i);
    }
    for (i, chunk) in ALT_REGION_ISO3.as_chunks::<3>().0.iter().enumerate() {
        if chunk.as_slice() == &*s {
            return Ok(ALT_REGION_IDS[i]);
        }
    }
    Err(ParseError::Value)
}

fn get_region_m49(n: usize) -> Result<u16, ParseError> {
    if n > 0 && n <= 999 {
        const REGION_BITS: u32 = 9;
        const REGION_MASK: u16 = (1 << REGION_BITS) - 1;
        let idx = n >> 7;
        let from = M49_INDEX[idx] as usize;
        let to = M49_INDEX[idx + 1] as usize;
        let buf = &FROM_M49[from..to];
        let val = (n as u16) << REGION_BITS;
        let i = buf.partition_point(|&v| v < val);
        // Go indexes past the table here for the largest codes, and recovers from the panic.
        let Some(r) = FROM_M49.get(from + i) else {
            return Err(ParseError::Syntax);
        };
        if r & !REGION_MASK == val {
            return Ok(r & REGION_MASK);
        }
    }
    Err(ParseError::Value)
}

fn region_string(r: u16) -> String {
    if r < ISO_REGION_OFFSET {
        if r == 0 {
            return "ZZ".to_string();
        }
        return format!("{:03}", M49[usize::from(r)]);
    }
    let e = elem(REGION_ISO, usize::from(r - ISO_REGION_OFFSET));
    String::from_utf8_lossy(&e[..2]).into_owned()
}

fn get_script_id(s: &mut [u8]) -> Result<u16, ParseError> {
    if !fix_case(b"Zzzz", s) {
        return Err(ParseError::Syntax);
    }
    match index(SCRIPT, s) {
        Some(i) => Ok(i as u16),
        None => Err(ParseError::Value),
    }
}

fn script_string(s: u16) -> String {
    if s == 0 {
        return "Zzzz".to_string();
    }
    String::from_utf8_lossy(elem(SCRIPT, usize::from(s))).into_owned()
}

fn variant_id(token: &[u8]) -> Option<u8> {
    let token = std::str::from_utf8(token).ok()?;
    VARIANT_INDEX
        .binary_search_by(|(name, _)| (*name).cmp(token))
        .ok()
        .map(|i| VARIANT_INDEX[i].1)
}

// --- parse.go ---

fn is_alpha_byte(b: u8) -> bool {
    b > b'9'
}

struct Scanner {
    b: Vec<u8>,
    // Go's scan.token. It is a slice that outlives edits to the buffer, so resizing around it doesn't
    // move or change it. A copy has the same effect, and to_lower keeps it in step where Go's would
    // see the change through the shared bytes.
    token: Vec<u8>,
    token_at: usize,
    start: usize,
    end: usize,
    next: usize,
    err: Option<ParseError>,
    done: bool,
}

impl Scanner {
    fn new(s: &str) -> Result<Self, ParseError> {
        let mut scan = Scanner {
            b: s.bytes()
                .map(|c| if c == b'_' { b'-' } else { c })
                .collect(),
            token: Vec::new(),
            token_at: 0,
            start: 0,
            end: 0,
            next: 0,
            err: None,
            done: false,
        };
        scan.scan()?;
        Ok(scan)
    }

    fn token_len(&self) -> usize {
        self.token.len()
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    fn lower_range(&mut self, start: usize, end: usize) -> Result<(), ParseError> {
        if start >= end {
            return Ok(());
        }
        if end > self.b.len() {
            return Err(ParseError::Syntax);
        }
        self.b[start..end].make_ascii_lowercase();
        if self.token_at >= start && self.token_at + self.token.len() <= end {
            self.token.make_ascii_lowercase();
        }
        Ok(())
    }

    fn set_error(&mut self, e: ParseError) {
        if self.err.is_none() || (e == ParseError::Syntax && self.err != Some(ParseError::Syntax)) {
            self.err = Some(e);
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

    fn replace(&mut self, repl: &[u8]) {
        self.resize_range(self.start, self.end, repl.len());
        self.b[self.start..self.start + repl.len()].copy_from_slice(repl);
    }

    fn gobble(&mut self, e: ParseError) -> Result<(), ParseError> {
        self.set_error(e);
        if self.start == 0 {
            if self.next > self.b.len() {
                return Err(ParseError::Syntax);
            }
            self.b.drain(..self.next);
            self.end = 0;
        } else {
            if self.end > self.b.len() || self.start - 1 > self.end {
                return Err(ParseError::Syntax);
            }
            self.b.drain(self.start - 1..self.end);
            self.end = self.start - 1;
        }
        self.next = self.start;
        Ok(())
    }

    fn delete_range(&mut self, start: usize, end: usize) -> Result<(), ParseError> {
        if end > self.b.len() || start > end {
            return Err(ParseError::Syntax);
        }
        self.b.drain(start..end);
        let diff = end - start;
        self.next = self.next.wrapping_sub(diff);
        self.start = self.start.wrapping_sub(diff);
        self.end = self.end.wrapping_sub(diff);
        Ok(())
    }

    // Returns the end position of the last token consumed.
    fn scan(&mut self) -> Result<usize, ParseError> {
        let end = self.end;
        self.token.clear();
        self.start = self.next;
        while self.next < self.b.len() {
            let found = self.b[self.next..].iter().position(|c| *c == b'-');
            let i = match found {
                None => {
                    self.end = self.b.len();
                    self.next = self.b.len();
                    self.end - self.start
                }
                Some(i) => {
                    self.end = self.next + i;
                    self.next = self.end + 1;
                    i
                }
            };
            if self.start > self.end || self.end > self.b.len() {
                return Err(ParseError::Syntax);
            }
            let token = &self.b[self.start..self.end];
            if !(1..=8).contains(&i) || !token.iter().all(u8::is_ascii_alphanumeric) {
                self.gobble(ParseError::Syntax)?;
                self.start = self.next;
                continue;
            }
            self.token = token.to_vec();
            self.token_at = self.start;
            return Ok(end);
        }
        if self.b.last() == Some(&b'-') {
            self.set_error(ParseError::Syntax);
            self.b.pop();
        }
        self.done = true;
        Ok(end)
    }

    fn accept_min_size(&mut self, min: usize) -> Result<usize, ParseError> {
        let mut end = self.end;
        self.scan()?;
        while self.token_len() >= min {
            end = self.end;
            self.scan()?;
        }
        Ok(end)
    }

    fn copy_at(&mut self, p: usize, data: &[u8]) -> Result<(), ParseError> {
        if p > self.b.len() {
            return Err(ParseError::Syntax);
        }
        let n = data.len().min(self.b.len() - p);
        self.b[p..p + n].copy_from_slice(&data[..n]);
        Ok(())
    }
}

// language.Parse in internal/language.
fn internal_parse(s: &str) -> Result<Tag, ParseError> {
    if s.is_empty() {
        return Err(ParseError::Syntax);
    }
    if s.len() <= MAX_ALT_TAGLEN {
        let mut b = [0u8; MAX_ALT_TAGLEN];
        for (i, c) in s.char_indices() {
            // Generating invalid UTF-8 is okay in Go: it won't match. A rune truncates to its low
            // byte, so a few non-ASCII runes do match, as in Go.
            let mut c = c as u32;
            if (u32::from(b'A')..=u32::from(b'Z')).contains(&c) {
                c += u32::from(b'a' - b'A');
            } else if c == u32::from(b'_') {
                c = u32::from(b'-');
            }
            b[i] = c as u8;
        }
        if let Some(tag) = grandfathered(&b) {
            return Ok(tag);
        }
    }
    let mut scan = Scanner::new(s)?;
    run_parse(&mut scan)
}

fn grandfathered(key: &[u8; MAX_ALT_TAGLEN]) -> Option<Tag> {
    let len = key.iter().position(|c| *c == 0).unwrap_or(MAX_ALT_TAGLEN);
    if key[len..].iter().any(|c| *c != 0) {
        return None;
    }
    let name = std::str::from_utf8(&key[..len]).ok()?;
    let (_, entry) = GRANDFATHERED.iter().find(|(n, _)| *n == name)?;
    Some(match entry {
        Grandfathered::Root => Tag::default(),
        Grandfathered::Lang(code) => {
            let mut buf = code.as_bytes().to_vec();
            Tag {
                lang: get_lang_id(&mut buf).ok()?,
                ..Tag::default()
            }
        }
        // Make ignores the error.
        Grandfathered::Alt(alt) => internal_parse(alt).unwrap_or_default(),
    })
}

fn run_parse(scan: &mut Scanner) -> Result<Tag, ParseError> {
    let mut t = Tag::default();
    let end;
    let n = scan.token_len();
    if n <= 1 {
        let len = scan.b.len();
        scan.lower_range(0, len)?;
        if n == 0 || scan.token()[0] != b'x' {
            return Err(ParseError::Syntax);
        }
        end = parse_extensions(scan)?;
    } else if n >= 4 {
        return Err(ParseError::Syntax);
    } else {
        let (parsed, parsed_end) = parse_tag(scan, true)?;
        t = parsed;
        if scan.token_len() == 1 {
            t.p_ext = parsed_end as u16;
            end = parse_extensions(scan)?;
        } else {
            end = parsed_end;
            if end < scan.b.len() {
                scan.set_error(ParseError::Syntax);
                scan.b.truncate(end);
            }
        }
    }
    let _ = end;
    if usize::from(t.p_variant) < scan.b.len() {
        t.str = String::from_utf8_lossy(&scan.b).into_owned();
    } else {
        t.p_variant = 0;
        t.p_ext = 0;
    }
    match scan.err {
        Some(err) => Err(err),
        None => Ok(t),
    }
}

fn parse_tag(scan: &mut Scanner, do_norm: bool) -> Result<(Tag, usize), ParseError> {
    let mut t = Tag::default();
    let (start, token_end) = (scan.start, scan.end);
    let lang = get_lang_id(&mut scan.b[start..token_end]);
    t.lang = match lang {
        Ok(id) => id,
        Err(e) => {
            scan.set_error(e);
            0
        }
    };
    scan.replace(lang_string(t.lang).as_bytes());
    let lang_start = scan.start;
    let mut end = scan.scan()?;
    while scan.token_len() == 3 && is_alpha_byte(scan.token()[0]) {
        if do_norm {
            let (start, token_end) = (scan.start, scan.end);
            let found = get_lang_id(&mut scan.b[start..token_end]);
            let id = found.unwrap_or(0);
            if id != 0 {
                t.lang = id;
                let lang_str = lang_string(id);
                let bytes = lang_str.as_bytes();
                let at = lang_start + bytes.len();
                if at >= scan.b.len() {
                    return Err(ParseError::Syntax);
                }
                scan.copy_at(lang_start, bytes)?;
                scan.b[at] = b'-';
                scan.start = at + 1;
            }
            // gobble(nil) leaves the error alone.
            match found {
                Ok(_) => gobble_without_error(scan)?,
                Err(e) => scan.gobble(e)?,
            }
        }
        end = scan.scan()?;
    }
    if scan.token_len() == 4 && is_alpha_byte(scan.token()[0]) {
        let (start, token_end) = (scan.start, scan.end);
        let found = get_script_id(&mut scan.b[start..token_end]);
        t.script = found.unwrap_or(0);
        if t.script == 0 {
            match found {
                Ok(_) => gobble_without_error(scan)?,
                Err(e) => scan.gobble(e)?,
            }
        }
        end = scan.scan()?;
    }
    let n = scan.token_len();
    if (2..=3).contains(&n) {
        let (start, token_end) = (scan.start, scan.end);
        let found = get_region_id(&mut scan.b[start..token_end]);
        t.region = found.unwrap_or(0);
        if t.region == 0 {
            match found {
                Ok(_) => gobble_without_error(scan)?,
                Err(e) => scan.gobble(e)?,
            }
        } else {
            let text = region_string(t.region);
            scan.replace(text.as_bytes());
        }
        end = scan.scan()?;
    }
    let len = scan.b.len();
    scan.lower_range(scan.start.min(len), len)?;
    t.p_variant = end as u8;
    let end = parse_variants(scan, end)?;
    t.p_ext = end as u16;
    Ok((t, end))
}

fn gobble_without_error(scan: &mut Scanner) -> Result<(), ParseError> {
    let saved = scan.err;
    scan.gobble(ParseError::Value)?;
    scan.err = saved;
    Ok(())
}

fn parse_variants(scan: &mut Scanner, mut end: usize) -> Result<usize, ParseError> {
    let start = scan.start;
    let mut var_id: Vec<u8> = Vec::new();
    let mut variant: Vec<Vec<u8>> = Vec::new();
    let mut last: i32 = -1;
    let mut need_sort = false;
    while scan.token_len() >= 4 {
        let Some(v) = variant_id(scan.token()) else {
            scan.gobble(ParseError::Value)?;
            scan.scan()?;
            continue;
        };
        var_id.push(v);
        variant.push(scan.token().to_vec());
        if !need_sort {
            if last < i32::from(v) {
                last = i32::from(v);
            } else {
                need_sort = true;
                const MAX_VARIANTS: usize = 8;
                if var_id.len() > MAX_VARIANTS {
                    break;
                }
            }
        }
        end = scan.end;
        scan.scan()?;
    }
    if need_sort {
        let mut pairs: Vec<(u8, Vec<u8>)> = var_id.into_iter().zip(variant).collect();
        pairs.sort_by_key(|(id, _)| *id);
        pairs.dedup_by_key(|(id, _)| *id);
        let joined = pairs
            .iter()
            .map(|(_, token)| token.as_slice())
            .collect::<Vec<_>>()
            .join(&b'-');
        if joined.is_empty() {
            end = start.wrapping_sub(1);
        } else {
            if end > scan.b.len() || start > end {
                return Err(ParseError::Syntax);
            }
            scan.resize_range(start, end, joined.len());
            let at = scan.start;
            scan.copy_at(at, &joined)?;
            end = scan.end;
        }
    }
    Ok(end)
}

fn parse_extensions(scan: &mut Scanner) -> Result<usize, ParseError> {
    let start = scan.start;
    let mut exts: Vec<Vec<u8>> = Vec::new();
    let mut private: Vec<u8> = Vec::new();
    let mut end = scan.end;
    while scan.token_len() == 1 {
        let ext_start = scan.start;
        let ext = scan.token()[0];
        end = parse_extension(scan)?;
        if ext_start > end || end > scan.b.len() {
            return Err(ParseError::Syntax);
        }
        let extension = scan.b[ext_start..end].to_vec();
        if extension.len() < 3 || (ext != b'x' && extension.len() < 4) {
            scan.set_error(ParseError::Syntax);
            end = ext_start;
            continue;
        } else if start == ext_start && (ext == b'x' || scan.start == scan.b.len()) {
            scan.b.truncate(end);
            return Ok(end);
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
    if start > scan.b.len() {
        return Err(ParseError::Syntax);
    }
    scan.b.truncate(start);
    if !exts.is_empty() {
        let joined = exts
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>()
            .join(&b'-');
        scan.b.extend_from_slice(&joined);
    } else if start > 0 {
        scan.b.truncate(start - 1);
    }
    Ok(end)
}

fn parse_extension(scan: &mut Scanner) -> Result<usize, ParseError> {
    let (start, mut end) = (scan.start, scan.end);
    match scan.token()[0] {
        b'u' => {
            let attr_start = end;
            scan.scan()?;
            let mut last: Vec<u8> = Vec::new();
            while scan.token_len() > 2 {
                if scan.token() >= last.as_slice() {
                    // Attributes are unsorted. Start over from scratch.
                    let p = attr_start + 1;
                    scan.next = p;
                    let mut attrs: Vec<Vec<u8>> = Vec::new();
                    scan.scan()?;
                    while scan.token_len() > 2 {
                        attrs.push(scan.token().to_vec());
                        end = scan.end;
                        scan.scan()?;
                    }
                    attrs.sort_by(|a, b| a[..3].cmp(&b[..3]));
                    let joined = attrs
                        .iter()
                        .map(Vec::as_slice)
                        .collect::<Vec<_>>()
                        .join(&b'-');
                    scan.copy_at(p, &joined)?;
                    break;
                }
                last = scan.token().to_vec();
                end = scan.end;
                scan.scan()?;
            }
            // Key-type sequences: a two-byte key and any number of longer type subtags.
            let attr_end = end;
            let mut last_key: Vec<u8> = Vec::new();
            while scan.token_len() == 2 {
                let key = scan.token().to_vec();
                end = scan.end;
                scan.scan()?;
                while end < scan.end && scan.token_len() > 2 {
                    end = scan.end;
                    scan.scan()?;
                }
                if key <= last_key || scan.err.is_some() {
                    // An invalid key, or keys out of order: reorder from scratch.
                    let p = attr_end + 1;
                    scan.next = p;
                    let mut keys: Vec<Vec<u8>> = Vec::new();
                    scan.scan()?;
                    while scan.token_len() == 2 {
                        let key_start = scan.start;
                        end = scan.end;
                        scan.scan()?;
                        while end < scan.end && scan.token_len() > 2 {
                            end = scan.end;
                            scan.scan()?;
                        }
                        if key_start > end || end > scan.b.len() {
                            return Err(ParseError::Syntax);
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
                                scan.set_error(ParseError::DuplicateKey);
                            }
                        }
                        keys.truncate(k + 1);
                    }
                    let reordered = keys
                        .iter()
                        .map(Vec::as_slice)
                        .collect::<Vec<_>>()
                        .join(&b'-');
                    let e = p + reordered.len();
                    if e < end {
                        scan.delete_range(e, end)?;
                        end = e;
                    }
                    scan.copy_at(p, &reordered)?;
                    break;
                }
                last_key = key;
            }
        }
        b't' => {
            scan.scan()?;
            let n = scan.token_len();
            if (2..=3).contains(&n) && is_alpha_byte(scan.token()[1]) {
                let (_, tag_end) = parse_tag(scan, false)?;
                end = tag_end;
                scan.lower_range(start, end)?;
            }
            while scan.token_len() == 2 && !is_alpha_byte(scan.token()[1]) {
                end = scan.accept_min_size(3)?;
            }
        }
        b'x' => end = scan.accept_min_size(1)?,
        _ => end = scan.accept_min_size(2)?,
    }
    Ok(end)
}

// --- language.go ---

impl Tag {
    fn equal_tags_und(&self) -> bool {
        self.lang == 0 && self.script == 0 && self.region == 0
    }

    fn gen_core(&self) -> String {
        let mut out = lang_string(self.lang);
        if self.script != 0 {
            out.push('-');
            out.push_str(&script_string(self.script));
        }
        if self.region != 0 {
            out.push('-');
            out.push_str(&region_string(self.region));
        }
        out
    }

    fn remake_string(&mut self) -> Result<(), ParseError> {
        if self.str.is_empty() {
            return Ok(());
        }
        let p = usize::from(self.p_variant);
        let mut extra = self.str.get(p..).ok_or(ParseError::Syntax)?.to_string();
        if self.p_variant > 0 {
            extra = extra.get(1..).ok_or(ParseError::Syntax)?.to_string();
        }
        if self.equal_tags_und() && extra.starts_with("x-") {
            self.str = extra;
            self.p_variant = 0;
            self.p_ext = 0;
            return Ok(());
        }
        let core = self.gen_core();
        if !extra.is_empty() {
            let diff = core.len() as i64 - i64::from(self.p_variant);
            self.p_variant = (i64::from(self.p_variant) + diff) as u8;
            self.p_ext = (i64::from(self.p_ext) + diff) as u16;
            self.str = format!("{core}-{extra}");
        } else {
            self.p_variant = core.len() as u8;
            self.p_ext = core.len() as u16;
            self.str = core;
        }
        Ok(())
    }

    /// `Tag.String`.
    pub fn string(&self) -> String {
        if !self.str.is_empty() {
            return self.str.clone();
        }
        if self.script == 0 && self.region == 0 {
            return lang_string(self.lang);
        }
        self.gen_core()
    }

    /// `tag == language.Und`: exactly the undefined tag, with nothing extra.
    pub fn is_und(&self) -> bool {
        self.equal_tags_und() && self.str.is_empty()
    }
}

// AliasType values in tables.go.
const ALIAS_DEPRECATED: u8 = 0;
const ALIAS_LEGACY: u8 = 2;

fn norm_lang(id: u16) -> (u16, Option<u8>) {
    for k in 0..ALIAS_TYPES.len() {
        if ALIAS_MAP[k * 2] == id {
            return (ALIAS_MAP[k * 2 + 1], Some(ALIAS_TYPES[k]));
        }
    }
    (id, None)
}

fn norm_region(r: u16) -> u16 {
    let count = REGION_OLD_MAP.len() / 2;
    for k in 0..count {
        if REGION_OLD_MAP[k * 2] == r {
            return REGION_OLD_MAP[k * 2 + 1];
        }
    }
    0
}

// canonicalize with language.Default, which is Deprecated | Legacy.
fn canonicalize(t: &mut Tag) -> bool {
    let mut changed = false;
    loop {
        let (l, alias) = norm_lang(t.lang);
        if l != t.lang {
            match alias {
                Some(ALIAS_LEGACY) => {
                    if t.lang == LANG_SH && t.script == 0 {
                        t.script = SCRIPT_LATN;
                    }
                    t.lang = l;
                    changed = true;
                }
                Some(ALIAS_DEPRECATED) => {
                    if t.lang == LANG_MO && t.region == 0 {
                        t.region = REGION_MD;
                    }
                    t.lang = l;
                    changed = true;
                    continue;
                }
                // Macro mappings are not part of the default canonicalization.
                _ => {}
            }
        }
        break;
    }
    if t.script == SCRIPT_QAAI {
        changed = true;
        t.script = SCRIPT_ZINH;
    }
    let r = norm_region(t.region);
    if r != 0 && r != t.region {
        changed = true;
        t.region = r;
    }
    changed
}

/// `language.Parse`: a tag only when Go reports no error.
pub fn parse(s: &str) -> Result<Tag, ParseError> {
    let mut t = internal_parse(s)?;
    if canonicalize(&mut t) {
        t.remake_string()?;
    }
    Ok(t)
}

/// `language.ParseBase` succeeded.
pub fn parse_base(s: &str) -> bool {
    if s.len() < 2 || s.len() > 3 {
        return false;
    }
    let mut buf = s.as_bytes().to_vec();
    get_lang_id(&mut buf).is_ok()
}
