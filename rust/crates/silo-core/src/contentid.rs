//! `internal/contentid`: deterministic content IDs and their reversible binary form.
//!
//! `content_id` is the anchor that artwork, watch history, and credits hang off, so a different ID for
//! the same file silently splits a user's history. The precedence and the string format are frozen.

use silo_gocompat::strings::{equal_fold, to_lower, trim_space};
use unicode_normalization::UnicodeNormalization;

use crate::hexgo::{decode as hex_decode, encode as hex_encode, sha256};

const SEP: char = '-';
const LOCAL_HASH_LEN: usize = 14;

/// Canonical provider tokens.
pub const PROVIDER_TMDB: &str = "tmdb";
pub const PROVIDER_IMDB: &str = "imdb";
pub const PROVIDER_TVDB: &str = "tvdb";

const MOVIE_PRECEDENCE: [&str; 3] = [PROVIDER_TMDB, PROVIDER_IMDB, PROVIDER_TVDB];
const SERIES_PRECEDENCE: [&str; 3] = [PROVIDER_TVDB, PROVIDER_TMDB, PROVIDER_IMDB];

const TAG_MOVIE: u8 = 0xC0;
const TAG_SERIES: u8 = 0xC1;
const TAG_SEASON: u8 = 0xC2;
const TAG_EPISODE: u8 = 0xC3;
const TAG_LOCAL: u8 = 0xC4;

/// `contentid.ProviderIDs`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderIds {
    pub tmdb: String,
    pub imdb: String,
    pub tvdb: String,
}

impl ProviderIds {
    fn get(&self, provider: &str) -> &str {
        match provider {
            PROVIDER_TMDB => &self.tmdb,
            PROVIDER_IMDB => &self.imdb,
            PROVIDER_TVDB => &self.tvdb,
            _ => "",
        }
    }
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn normalize_provider_id(provider: &str, raw: &str) -> Option<String> {
    let id = trim_space(raw);
    if id.is_empty() {
        return None;
    }
    match provider {
        PROVIDER_IMDB => {
            let id = to_lower(id);
            id.strip_prefix("tt").is_some_and(all_digits).then_some(id)
        }
        PROVIDER_TMDB | PROVIDER_TVDB => all_digits(id).then(|| id.to_owned()),
        _ => None,
    }
}

fn anchor(ids: &ProviderIds, precedence: &[&'static str]) -> Option<(&'static str, String)> {
    precedence
        .iter()
        .find_map(|p| normalize_provider_id(p, ids.get(p)).map(|id| (*p, id)))
}

/// `contentid.ForMovie`.
pub fn for_movie(ids: &ProviderIds) -> Option<String> {
    let (provider, id) = anchor(ids, &MOVIE_PRECEDENCE)?;
    Some(format!("movie{SEP}{provider}{SEP}{id}"))
}

/// `contentid.ForSeries`.
pub fn for_series(ids: &ProviderIds) -> Option<String> {
    let (provider, id) = anchor(ids, &SERIES_PRECEDENCE)?;
    Some(format!("series{SEP}{provider}{SEP}{id}"))
}

/// `contentid.AnchorPrecedence`.
pub fn anchor_precedence(item_type: &str) -> [&'static str; 3] {
    if equal_fold(trim_space(item_type), "series") {
        SERIES_PRECEDENCE
    } else {
        MOVIE_PRECEDENCE
    }
}

fn series_body(series_content_id: &str) -> Option<&str> {
    let rest = trim_space(series_content_id).strip_prefix("series-")?;
    if rest.is_empty() {
        return None;
    }
    let parts: Vec<&str> = rest.split(SEP).collect();
    if parts.len() != 2 {
        return None;
    }
    normalize_provider_id(parts[0], parts[1])?;
    Some(rest)
}

/// `contentid.ForSeason`.
pub fn for_season(series_content_id: &str, season: i64) -> Option<String> {
    let body = series_body(series_content_id)?;
    Some(format!("season{SEP}{body}{SEP}{season}"))
}

/// `contentid.ForEpisode`.
pub fn for_episode(series_content_id: &str, season: i64, episode: i64) -> Option<String> {
    let body = series_body(series_content_id)?;
    Some(format!("episode{SEP}{body}{SEP}{season}{SEP}{episode}"))
}

/// `contentid.ForLocal`: the first 112 bits of SHA-256 over the trimmed, NFC-normalized path.
pub fn for_local(path: &str) -> String {
    let normalized = nfc(trim_space(path));
    let sum = sha256(normalized.as_bytes());
    format!("local{SEP}{}", hex_encode(&sum[..LOCAL_HASH_LEN]))
}

/// Code points the `unicode-normalization` crate has data for and `x/text` does not, because its tables
/// are from a newer Unicode version. To Go these are unassigned: inert starters that neither reorder nor
/// compose. The `unicode_norm_table` vector fails when either side's tables move.
const NEWER_THAN_GO: &[(u32, u32)] = &[
    (0x5C8, 0x5C9),
    (0x897, 0x897),
    (0x1ACF, 0x1AF0),
    (0x105C9, 0x105C9),
    (0x105D2, 0x105D2),
    (0x105DA, 0x105DA),
    (0x105E4, 0x105E4),
    (0x10D69, 0x10D6D),
    (0x10ECB, 0x10ECF),
    (0x10EF0, 0x10EFB),
    (0x11382, 0x11385),
    (0x1138B, 0x1138B),
    (0x1138E, 0x1138E),
    (0x11390, 0x11391),
    (0x113B8, 0x113B8),
    (0x113BB, 0x113BB),
    (0x113C2, 0x113C2),
    (0x113C5, 0x113C5),
    (0x113C7, 0x113C9),
    (0x113CE, 0x113D0),
    (0x1611E, 0x16129),
    (0x1612F, 0x1612F),
    (0x16D63, 0x16D63),
    (0x16D67, 0x16D6A),
    (0x1D127, 0x1D128),
    (0x1D250, 0x1D252),
    (0x1D25B, 0x1D25C),
    (0x1D25F, 0x1D25F),
    (0x1D280, 0x1D281),
    (0x1E5EE, 0x1E5EF),
    (0x1E6E3, 0x1E6E3),
    (0x1E6E6, 0x1E6E6),
    (0x1E6EE, 0x1E6EF),
    (0x1E6F5, 0x1E6F5),
];

/// Whether the normalization crate knows `c` and Go's tables do not.
pub fn newer_than_go(c: char) -> bool {
    let cp = c as u32;
    NEWER_THAN_GO
        .binary_search_by(|&(low, high)| {
            if cp < low {
                std::cmp::Ordering::Greater
            } else if cp > high {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Normalizes the pieces between code points Go treats as unassigned.
fn normalize_pieces(s: &str, normalize: impl Fn(&str, &mut String)) -> String {
    let mut out = String::with_capacity(s.len());
    if !s.chars().any(newer_than_go) {
        normalize(s, &mut out);
        return out;
    }
    for piece in s.split_inclusive(newer_than_go) {
        let (body, barrier) = match piece.chars().next_back() {
            Some(last) if newer_than_go(last) => {
                (&piece[..piece.len() - last.len_utf8()], Some(last))
            }
            _ => (piece, None),
        };
        normalize(body, &mut out);
        if let Some(barrier) = barrier {
            out.push(barrier);
        }
    }
    out
}

/// `norm.NFC.String`. Like Go, it keeps text in the Stream-Safe form, breaking a run of more than 30
/// non-starters with U+034F.
pub fn nfc(s: &str) -> String {
    normalize_pieces(s, |piece, out| out.extend(piece.stream_safe().nfc()))
}

/// `norm.NFD.String`, under the same rules as [`nfc`].
pub fn nfd(s: &str) -> String {
    normalize_pieces(s, |piece, out| out.extend(piece.stream_safe().nfd()))
}

fn parse_anchored(id: &str) -> Option<(&str, &str)> {
    let (kind, rest) = id.split_once(SEP)?;
    let parts: Vec<&str> = rest.split(SEP).collect();
    let want = match kind {
        "movie" | "series" => 2,
        "season" => 3,
        "episode" => 4,
        _ => return None,
    };
    if parts.len() != want {
        return None;
    }
    normalize_provider_id(parts[0], parts[1])?;
    if !parts[2..].iter().all(|n| all_digits(n)) {
        return None;
    }
    Some((parts[0], parts[1]))
}

/// `contentid.SeriesIDFromContentID`.
pub fn series_id_from_content_id(content_id: &str) -> Option<String> {
    let id = trim_space(content_id);
    if id.starts_with("movie-") || id.starts_with("series-") {
        return is_provider_anchored(id).then(|| id.to_owned());
    }
    let (provider, series_id) = parse_anchored(id)?;
    Some(format!("series{SEP}{provider}{SEP}{series_id}"))
}

/// `contentid.IsProviderAnchored`.
pub fn is_provider_anchored(content_id: &str) -> bool {
    parse_anchored(trim_space(content_id)).is_some()
}

/// `contentid.ProviderAnchor`.
pub fn provider_anchor(content_id: &str) -> Option<(&str, &str)> {
    parse_anchored(trim_space(content_id))
}

/// `contentid.IsLocal`.
pub fn is_local(content_id: &str) -> bool {
    trim_space(content_id).starts_with("local-")
}

fn provider_code(p: &str) -> Option<u8> {
    match p {
        PROVIDER_TMDB => Some(1),
        PROVIDER_IMDB => Some(2),
        PROVIDER_TVDB => Some(3),
        _ => None,
    }
}

fn append_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// `binary.Uvarint`: the value and its width, or `None` for short or overflowing input.
fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0u64;
    let mut s = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if i == 10 {
            return None;
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None;
            }
            return Some((x | u64::from(b) << s, i + 1));
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    None
}

fn pack_anchored(tag: u8, provider: &str, id: &str, nums: &[u64]) -> Option<Vec<u8>> {
    let code = provider_code(provider)?;
    let normalized = normalize_provider_id(provider, id)?;
    let digits = if provider == PROVIDER_IMDB {
        normalized.strip_prefix("tt").unwrap_or(&normalized)
    } else {
        &normalized
    };
    let value: u64 = digits.parse().ok()?;
    let mut out = Vec::with_capacity(16);
    out.push(tag);
    out.push(code);
    append_uvarint(&mut out, digits.len() as u64);
    append_uvarint(&mut out, value);
    for n in nums {
        append_uvarint(&mut out, *n);
    }
    Some(out)
}

fn parse_nums(parts: &[&str]) -> Option<Vec<u64>> {
    parts
        .iter()
        .map(|s| if all_digits(s) { s.parse().ok() } else { None })
        .collect()
}

/// `contentid.Pack`. `None` for legacy numeric IDs, values that overflow `u64`, and malformed IDs.
pub fn pack(content_id: &str) -> Option<Vec<u8>> {
    let id = trim_space(content_id);
    if let Some(rest) = id.strip_prefix("local-") {
        let raw = hex_decode(rest)?;
        if raw.len() != LOCAL_HASH_LEN {
            return None;
        }
        let mut out = Vec::with_capacity(1 + LOCAL_HASH_LEN);
        out.push(TAG_LOCAL);
        out.extend_from_slice(&raw);
        return Some(out);
    }
    let parts: Vec<&str> = id.split(SEP).collect();
    match parts[0] {
        "movie" | "series" => {
            if parts.len() != 3 {
                return None;
            }
            let tag = if parts[0] == "series" {
                TAG_SERIES
            } else {
                TAG_MOVIE
            };
            pack_anchored(tag, parts[1], parts[2], &[])
        }
        "season" => {
            if parts.len() != 4 {
                return None;
            }
            pack_anchored(TAG_SEASON, parts[1], parts[2], &parse_nums(&parts[3..])?)
        }
        "episode" => {
            if parts.len() != 5 {
                return None;
            }
            pack_anchored(TAG_EPISODE, parts[1], parts[2], &parse_nums(&parts[3..])?)
        }
        _ => None,
    }
}

/// `contentid.Unpack`. Trailing bytes after a structured ID are the zero padding the compat layer adds.
pub fn unpack(data: &[u8]) -> Option<String> {
    let (&tag, body) = data.split_first()?;
    if tag == TAG_LOCAL {
        if body.len() != LOCAL_HASH_LEN {
            return None;
        }
        return Some(format!("local{SEP}{}", hex_encode(body)));
    }
    let (kind, n_nums) = match tag {
        TAG_MOVIE => ("movie", 0),
        TAG_SERIES => ("series", 0),
        TAG_SEASON => ("season", 1),
        TAG_EPISODE => ("episode", 2),
        _ => return None,
    };
    let (&code, body) = body.split_first()?;
    let provider = match code {
        1 => PROVIDER_TMDB,
        2 => PROVIDER_IMDB,
        3 => PROVIDER_TVDB,
        _ => return None,
    };
    let (digit_count, n) = read_uvarint(body)?;
    let body = &body[n..];
    let (value, n) = read_uvarint(body)?;
    let mut body = &body[n..];
    if digit_count == 0 || digit_count > 64 {
        return None;
    }
    let mut nums = Vec::with_capacity(n_nums);
    for _ in 0..n_nums {
        let (v, n) = read_uvarint(body)?;
        nums.push(v);
        body = &body[n..];
    }
    let digits = format!("{value:0>width$}", width = digit_count as usize);
    let id = if provider == PROVIDER_IMDB {
        format!("tt{digits}")
    } else {
        digits
    };
    let mut out = format!("{kind}{SEP}{provider}{SEP}{id}");
    for n in nums {
        out.push(SEP);
        out.push_str(&n.to_string());
    }
    Some(out)
}
