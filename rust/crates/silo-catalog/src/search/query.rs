//! `search_query.go` and `search_fold.go`: parsing a search box query into text, a quoted
//! phrase, a year hint, and the normalized forms that must match
//! `public.normalize_search_text` in Postgres.

use silo_gocompat::strings::{fields, trim_space};
use silo_gocompat::unicode::{is_digit, is_letter, to_lower_rune};
use unicode_normalization::UnicodeNormalization;

/// Go's `parsedSearchQuery`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedSearchQuery {
    pub raw: String,
    pub text: String,
    pub phrase: String,
    pub exact_title_hint: String,
    pub normalized_text: String,
    pub year: Option<i64>,
}

/// Shortest longest-token that enables the trigram fuzzy fallback.
pub const FUZZY_MIN_TOKEN_LEN: usize = 4;
/// Single-token inputs shorter than this stay on the exact whole-title path.
pub const SEARCH_PREFIX_MIN_TOKEN_LEN: usize = 4;

/// Go's `parseSearchQuery`.
pub fn parse_search_query(raw: &str) -> ParsedSearchQuery {
    let trimmed = collapse_search_whitespace(trim_space(raw));
    let (phrase, remainder) = extract_balanced_phrase(&trimmed);
    let (year, remainder) = extract_year_hint(&remainder, !phrase.is_empty());

    let mut parts: Vec<&str> = Vec::with_capacity(2);
    if !phrase.is_empty() {
        parts.push(&phrase);
    }
    if !remainder.is_empty() {
        parts.push(&remainder);
    }
    let mut text = collapse_search_whitespace(&parts.join(" "));
    if text.is_empty() {
        text = collapse_search_whitespace(&trimmed.replace('"', " "));
    }
    let hint_src = if phrase.is_empty() {
        text.as_str()
    } else {
        phrase.as_str()
    };
    ParsedSearchQuery {
        raw: raw.to_string(),
        exact_title_hint: normalize_title_for_comparison(hint_src),
        normalized_text: normalize_title_for_comparison(&text),
        text,
        phrase,
        year,
    }
}

fn rune_len(s: &str) -> usize {
    s.chars().count()
}

/// Go's `eligibleForFuzzy`.
pub fn eligible_for_fuzzy(parsed: &ParsedSearchQuery) -> bool {
    if !parsed.phrase.is_empty() && use_leading_short_title_search(parsed) {
        return false;
    }
    let longest = fields(&parsed.normalized_text)
        .into_iter()
        .map(rune_len)
        .max()
        .unwrap_or(0);
    longest >= FUZZY_MIN_TOKEN_LEN
}

/// Go's `useExactShortTitleSearch`.
pub fn use_exact_short_title_search(parsed: &ParsedSearchQuery) -> bool {
    let f = fields(&parsed.normalized_text);
    f.len() == 1 && rune_len(f[0]) < SEARCH_PREFIX_MIN_TOKEN_LEN
}

/// Go's `useLeadingShortTitleSearch`.
pub fn use_leading_short_title_search(parsed: &ParsedSearchQuery) -> bool {
    let f = fields(&parsed.normalized_text);
    f.len() > 1 && rune_len(f[f.len() - 1]) < SEARCH_PREFIX_MIN_TOKEN_LEN
}

/// Go's `extractBalancedPhrase`.
pub fn extract_balanced_phrase(input: &str) -> (String, String) {
    let Some(start) = input.find('"') else {
        return (String::new(), input.to_string());
    };
    let Some(end) = input[start + 1..].find('"') else {
        return (
            String::new(),
            collapse_search_whitespace(&input.replace('"', " ")),
        );
    };
    let end = end + start + 1;
    let phrase = collapse_search_whitespace(&input[start + 1..end]);
    let remainder = collapse_search_whitespace(&[&input[..start], &input[end + 1..]].join(" "));
    (phrase, remainder)
}

/// Go's `extractYearHint`.
pub fn extract_year_hint(input: &str, has_phrase: bool) -> (Option<i64>, String) {
    let f = fields(input);
    if f.is_empty() {
        return (None, String::new());
    }
    for i in (0..f.len()).rev() {
        let Some(year) = parse_year_token(f[i]) else {
            continue;
        };
        if f.len() == 1 && !has_phrase {
            return (None, collapse_search_whitespace(input));
        }
        let remaining: Vec<&str> = f[..i].iter().chain(f[i + 1..].iter()).copied().collect();
        return (Some(year), collapse_search_whitespace(&remaining.join(" ")));
    }
    (None, collapse_search_whitespace(input))
}

/// Go's `parseYearToken` (`strconv.Atoi` on exactly four bytes, 1900 to 2100).
pub fn parse_year_token(token: &str) -> Option<i64> {
    if token.len() != 4 {
        return None;
    }
    let year: i64 = token.parse().ok()?;
    (1900..=2100).contains(&year).then_some(year)
}

/// Go's `buildTitlePrefixTsQuery`.
pub fn build_title_prefix_ts_query(input: &str) -> String {
    let normalized = normalize_title_for_comparison(input);
    let f = fields(&normalized);
    if f.is_empty() {
        return String::new();
    }
    if f.len() == 1 && rune_len(f[0]) < SEARCH_PREFIX_MIN_TOKEN_LEN {
        return String::new();
    }
    let last = f.len() - 1;
    f.iter()
        .enumerate()
        .map(|(i, field)| {
            if i == last {
                format!("{field}:*")
            } else {
                (*field).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" & ")
}

/// Go's `foldSearchDiacritics`, mirroring `public.fold_search_diacritics`.
pub fn fold_search_diacritics(input: &str) -> String {
    if input.is_ascii() {
        return input.to_string();
    }
    let stripped: String = input
        .nfd()
        .filter(|c| !(0x300..=0x36f).contains(&(*c as u32)))
        .collect();
    let mut out = String::with_capacity(stripped.len());
    for c in stripped.nfc() {
        match c {
            'Ø' => out.push('O'),
            'ø' => out.push('o'),
            'Đ' | 'Ð' => out.push('D'),
            'đ' | 'ð' => out.push('d'),
            'Ł' | 'Ŀ' => out.push('L'),
            'ł' | 'ŀ' => out.push('l'),
            'Ħ' => out.push('H'),
            'ħ' => out.push('h'),
            'ı' => out.push('i'),
            'Ŧ' => out.push('T'),
            'ŧ' => out.push('t'),
            'ß' => out.push_str("ss"),
            'ẞ' => out.push_str("SS"),
            'æ' => out.push_str("ae"),
            'Æ' => out.push_str("AE"),
            'œ' => out.push_str("oe"),
            'Œ' => out.push_str("OE"),
            other => out.push(other),
        }
    }
    out
}

/// Go's `normalizeTitleForComparison`; must match `public.normalize_search_text`.
pub fn normalize_title_for_comparison(input: &str) -> String {
    let mut b = String::with_capacity(input.len());
    for c in fold_search_diacritics(input).chars() {
        let r = c as u32;
        if is_letter(r) || is_digit(r) {
            b.push(char::from_u32(to_lower_rune(r)).unwrap_or(c));
        } else {
            b.push(' ');
        }
    }
    normalize_search_tokens(&collapse_search_whitespace(&b))
}

/// Go's `normalizeSearchTokens`.
pub fn normalize_search_tokens(input: &str) -> String {
    fields(input)
        .into_iter()
        .filter(|f| *f != "and")
        .map(normalize_search_number_token)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Go's `normalizeSearchNumberToken`.
pub fn normalize_search_number_token(token: &str) -> String {
    let n = match token {
        "zero" | "zeroth" => "0",
        "one" | "first" => "1",
        "two" | "second" => "2",
        "three" | "third" => "3",
        "four" | "fourth" => "4",
        "five" | "fifth" => "5",
        "six" | "sixth" => "6",
        "seven" | "seventh" => "7",
        "eight" | "eighth" => "8",
        "nine" | "ninth" => "9",
        "ten" | "tenth" => "10",
        "eleven" | "eleventh" => "11",
        "twelve" | "twelfth" => "12",
        "thirteen" | "thirteenth" => "13",
        "fourteen" | "fourteenth" => "14",
        "fifteen" | "fifteenth" => "15",
        "sixteen" | "sixteenth" => "16",
        "seventeen" | "seventeenth" => "17",
        "eighteen" | "eighteenth" => "18",
        "nineteen" | "nineteenth" => "19",
        "twenty" | "twentieth" => "20",
        _ => {
            for suffix in ["st", "nd", "rd", "th"] {
                if let Some(stem) = token.strip_suffix(suffix)
                    && !stem.is_empty()
                    && stem.chars().all(|c| is_digit(c as u32))
                {
                    return stem.to_string();
                }
            }
            token
        }
    };
    n.to_string()
}

/// Go's `collapseSearchWhitespace`.
pub fn collapse_search_whitespace(input: &str) -> String {
    fields(input).join(" ")
}
