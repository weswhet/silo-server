//! The group keys of `internal/naming`, stored in `media_files`, `media_item_groups`, and
//! `media_group_overrides` and fed into the SQL match-queue fingerprint. A different key silently
//! splits or merges items. The file-name parser that supplies the title arrives with the scanner.

use std::sync::LazyLock;

use silo_gocompat::filepath;
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strings::{fields, to_lower, trim_space};
use silo_gocompat::unicode::is_letter;

use crate::fspath;
use crate::hexgo::fnv64a;

/// `ContentGroupKeyVersion`.
pub const CONTENT_GROUP_KEY_VERSION: i64 = 1;

static INFER_PROVIDER_TAG: LazyLock<GoRegex> = LazyLock::new(|| {
    GoRegex::must_compile(
        r"(?i)\s*[{\[](?:tmdb|tmdbid|imdb|imdbid|tvdb|tvdbid)[-=](?:\{[^}]*\}|[\w]*)[}\]]",
    )
});
static JUSTICE_IS_GRAY: LazyLock<GoRegex> =
    LazyLock::new(|| GoRegex::must_compile(r"(?i)\bjustice\s+is\s+gr(?:a|e)y\b"));
static VARIANT_WHITESPACE: LazyLock<GoRegex> = LazyLock::new(|| GoRegex::must_compile(r"\s+"));

fn collapse_whitespace(value: &str) -> String {
    fields(value).join(" ")
}

/// `comparisonSafeEditionSuffix`'s prefix. `justice_is_gray` is the only rule marked safe to compare.
pub fn strip_comparison_safe_edition_suffix(surface: &str) -> String {
    let cleaned = collapse_whitespace(&trim_space(surface).replace(['.', '_'], " "));
    if cleaned.is_empty() {
        return surface.to_owned();
    }
    let mut best: Option<(usize, String)> = None;
    for span in JUSTICE_IS_GRAY.find_all_string_index(&cleaned, -1) {
        let (start, end) = (span.0, span.1);
        if end != cleaned.len() {
            continue;
        }
        let prefix = collapse_whitespace(trim_space(&cleaned[..start]));
        if prefix.is_empty() {
            continue;
        }
        if best.as_ref().is_none_or(|(s, _)| start > *s) {
            best = Some((start, prefix));
        }
    }
    best.map_or_else(|| surface.to_owned(), |(_, prefix)| prefix)
}

fn numeric_rune(c: char) -> Option<char> {
    Some(match c {
        '0'..='9' => c,
        '⁰' | '₀' => '0',
        '¹' | '₁' => '1',
        '²' | '₂' => '2',
        '³' | '₃' => '3',
        '⁴' | '₄' => '4',
        '⁵' | '₅' => '5',
        '⁶' | '₆' => '6',
        '⁷' | '₇' => '7',
        '⁸' | '₈' => '8',
        '⁹' | '₉' => '9',
        _ => return None,
    })
}

fn styled_numeric(c: char) -> bool {
    matches!(
        c,
        '⁰' | '¹'
            | '²'
            | '³'
            | '⁴'
            | '⁵'
            | '⁶'
            | '⁷'
            | '⁸'
            | '⁹'
            | '₀'
            | '₁'
            | '₂'
            | '₃'
            | '₄'
            | '₅'
            | '₆'
            | '₇'
            | '₈'
            | '₉'
    )
}

fn ordinal(token: &str) -> &str {
    match token {
        "i" | "one" | "first" => "1",
        "ii" | "two" | "second" => "2",
        "iii" | "three" | "third" => "3",
        "iv" | "four" | "fourth" => "4",
        "v" | "five" | "fifth" => "5",
        _ => token,
    }
}

fn is_article(token: &str) -> bool {
    matches!(token, "the" | "a" | "an")
}

/// `normalizeInferTokens`.
pub fn normalize_infer_tokens(name: &str) -> Vec<String> {
    let displayed = String::from_utf8_lossy(&fspath::display(name)).into_owned();
    let stripped = INFER_PROVIDER_TAG.replace_all_literal_string(&displayed, " ");
    let surface = to_lower(trim_space(&stripped));
    let mut built = String::with_capacity(surface.len());
    let mut last_comparable_was_alnum = false;
    for c in surface.chars() {
        if let Some(digit) = numeric_rune(c) {
            if styled_numeric(c) && last_comparable_was_alnum {
                built.push(' ');
            }
            built.push(digit);
            last_comparable_was_alnum = true;
        } else if is_letter(c as u32) {
            built.push(c);
            last_comparable_was_alnum = true;
        } else if c == '&' {
            built.push_str(" and ");
            last_comparable_was_alnum = true;
        } else if c != '\'' {
            built.push(' ');
            last_comparable_was_alnum = false;
        }
    }
    let mut normalized: Vec<String> = fields(&built)
        .into_iter()
        .map(|field| {
            if is_article(field) {
                field.to_owned()
            } else {
                ordinal(field).to_owned()
            }
        })
        .collect();
    while normalized.len() > 1 && is_article(&normalized[0]) {
        normalized.remove(0);
    }
    while normalized.len() > 1 && is_article(&normalized[normalized.len() - 1]) {
        normalized.pop();
    }
    normalized
}

fn looks_like_initialism(token: &str, rest: &[String]) -> bool {
    if token.len() < 2 || rest.len() < 2 {
        return false;
    }
    let initials: Vec<u8> = rest
        .iter()
        .filter(|part| !part.is_empty())
        .map(|part| part.as_bytes()[0])
        .collect();
    token.as_bytes() == initials.as_slice()
}

/// `normalizeGroupComparable`.
pub fn normalize_group_comparable(title: &str) -> String {
    let mut tokens = normalize_infer_tokens(&strip_comparison_safe_edition_suffix(title));
    if tokens.len() >= 4 && looks_like_initialism(&tokens[0], &tokens[1..]) {
        tokens.remove(0);
    }
    tokens.join(" ")
}

/// `isolatedGroupKey`.
pub fn isolated_group_key(content_type: &str, observed_root_path: &str, file_path: &str) -> String {
    let mut seed = filepath::clean(observed_root_path);
    if seed.is_empty() {
        seed = filepath::clean(file_path);
    }
    format!(
        "v{CONTENT_GROUP_KEY_VERSION}|{content_type}|isolated|{:x}",
        fnv64a(seed)
    )
}

/// `makeContentGroupKey`.
pub fn make_content_group_key(
    content_type: &str,
    title: &str,
    year: i64,
    observed_root_path: &str,
    file_path: &str,
) -> String {
    let comparable = normalize_group_comparable(title);
    if comparable.is_empty() {
        return isolated_group_key(content_type, observed_root_path, file_path);
    }
    format!("v{CONTENT_GROUP_KEY_VERSION}|{content_type}|{comparable}|{year:04}")
}

/// `normalizePresentationGroup`.
pub fn normalize_presentation_group(base_no_ext: &str, matched: &str) -> String {
    let group = base_no_ext
        .replacen(matched, " ", 1)
        .replace(['.', '_', '-'], " ");
    let group = VARIANT_WHITESPACE.replace_all_literal_string(&group, " ");
    trim_space(&group).to_owned()
}
