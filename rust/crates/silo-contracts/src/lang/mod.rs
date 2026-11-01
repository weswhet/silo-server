//! Port of `internal/lang`: the language-tag rules the scanner and the settings contract share.
//!
//! [`subtag`] holds the part of `golang.org/x/text/language` this needs, over tables frozen from Go.

mod subtag;
#[rustfmt::skip]
#[allow(dead_code)]
mod tables;

use std::sync::LazyLock;

use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strings::{to_lower, to_upper, trim_space};

use subtag::{Tag, parse, parse_base};

static LANGUAGE_TAG_PATTERN: LazyLock<GoRegex> = LazyLock::new(|| {
    GoRegex::must_compile(concat!(
        r"^([a-zA-Z]{2,3}(-[a-zA-Z]{3}){0,3}(-[a-zA-Z]{4})?(-([a-zA-Z]{2}|[0-9]{3}))?",
        r"(-([0-9a-zA-Z]{5,8}|[0-9][0-9a-zA-Z]{3}))*",
        r"(-[0-9a-wy-zA-WY-Z](-[0-9a-zA-Z]{2,8})+)*",
        r"(-[xX](-[0-9a-zA-Z]{1,8})+)?",
        r"|[xX](-[0-9a-zA-Z]{1,8})+)$",
    ))
});

const LANGUAGE_NAMES: &[(&str, &str)] = &[
    ("english", "en"),
    ("spanish", "es"),
    ("french", "fr"),
    ("german", "de"),
    ("italian", "it"),
    ("portuguese", "pt"),
    ("japanese", "ja"),
    ("korean", "ko"),
    ("chinese", "zh"),
    ("russian", "ru"),
    ("arabic", "ar"),
    ("dutch", "nl"),
    ("polish", "pl"),
    ("swedish", "sv"),
    ("norwegian", "no"),
    ("danish", "da"),
    ("finnish", "fi"),
    ("greek", "el"),
    ("turkish", "tr"),
    ("hungarian", "hu"),
    ("czech", "cs"),
    ("romanian", "ro"),
    ("hebrew", "he"),
    ("hindi", "hi"),
    ("thai", "th"),
    ("vietnamese", "vi"),
    ("indonesian", "id"),
    ("ukrainian", "uk"),
    ("bengali", "bn"),
    ("bangla", "bn"),
    ("bulgarian", "bg"),
    ("croatian", "hr"),
    ("persian", "fa"),
    ("farsi", "fa"),
    ("malay", "ms"),
    ("serbian", "sr"),
    ("slovak", "sk"),
    ("slovenian", "sl"),
    ("tamil", "ta"),
    ("telugu", "te"),
    ("estonian", "et"),
    ("latvian", "lv"),
    ("lithuanian", "lt"),
    ("icelandic", "is"),
    ("brazilian portuguese", "pt-BR"),
    ("brazillian portuguese", "pt-BR"),
    ("portuguese (brazil)", "pt-BR"),
    ("portuguese (portugal)", "pt-PT"),
    ("european portuguese", "pt-PT"),
    ("chinese (traditional)", "zh-Hant"),
    ("traditional chinese", "zh-Hant"),
    ("chinese (simplified)", "zh-Hans"),
    ("simplified chinese", "zh-Hans"),
];

/// `lang.CanonicalTag`: validates a BCP 47 tag, canonicalizing ISO aliases and casing. Accepts
/// underscores but no display names. Empty and malformed values return `""`.
pub fn canonical_tag(value: &str) -> String {
    let value = trim_space(value).replace('_', "-");
    if !LANGUAGE_TAG_PATTERN.match_string(&value) {
        return grandfathered_tag(&value);
    }
    if has_duplicate_subtags(&value) {
        return String::new();
    }
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() > 1 && parts[1].len() == 3 && is_alpha(parts[1]) {
        return canonical_tag_case(&value);
    }
    if let Ok(tag) = parse(&value) {
        return tag.string();
    }
    // The settings contract is open to well-formed, unregistered subtags.
    canonical_tag_case(&value)
}

fn grandfathered_tag(value: &str) -> String {
    if !value.contains('-') {
        return String::new();
    }
    match parse(value) {
        Ok(tag) if !tag.is_und() => tag.string(),
        _ => String::new(),
    }
}

fn has_duplicate_subtags(value: &str) -> bool {
    let lowered = to_lower(value);
    let parts: Vec<&str> = lowered.split('-').collect();
    let mut variants = Vec::new();
    let mut singletons = Vec::new();
    let mut private_use = parts[0] == "x";
    let mut extension_started = false;
    for part in &parts[1..] {
        if private_use {
            continue;
        }
        if part.len() == 1 {
            if singletons.contains(part) {
                return true;
            }
            singletons.push(*part);
            extension_started = true;
            if *part == "x" {
                private_use = true;
            }
            continue;
        }
        let first_digit = part.as_bytes()[0].is_ascii_digit();
        if !extension_started && (part.len() >= 5 || (part.len() == 4 && first_digit)) {
            if variants.contains(part) {
                return true;
            }
            variants.push(*part);
        }
    }
    false
}

/// `lang.CompatibleTag`: [`canonical_tag`], also recognizing known English display names.
pub fn compatible_tag(value: &str) -> String {
    let trimmed = trim_space(value);
    let lowered = to_lower(trimmed);
    match LANGUAGE_NAMES.iter().find(|(name, _)| *name == lowered) {
        Some((_, mapped)) => canonical_tag(mapped),
        None => canonical_tag(trimmed),
    }
}

/// `lang.RegisteredTag`: [`compatible_tag`], limited to tags whose primary subtag is registered.
pub fn registered_tag(value: &str) -> String {
    let tag = compatible_tag(value);
    let primary = tag.split('-').next().unwrap_or_default();
    if primary.is_empty() || !parse_base(primary) {
        return String::new();
    }
    tag
}

/// `lang.PrimaryLanguage`: the primary subtag, never inferred from an undefined or private-use tag.
pub fn primary_language(value: &str) -> String {
    let canonical = compatible_tag(value);
    let base = canonical.split('-').next().unwrap_or_default();
    if base == "und" || base == "x" {
        return String::new();
    }
    base.to_string()
}

fn canonical_tag_case(tag: &str) -> String {
    let mut parts: Vec<String> = tag.split('-').map(str::to_string).collect();
    parts[0] = to_lower(&parts[0]);
    let mut in_extension = parts[0] == "x";
    for part in parts.iter_mut().skip(1) {
        let new = if part.len() == 1 {
            in_extension = true;
            to_lower(part)
        } else if in_extension {
            to_lower(part)
        } else if part.len() == 4 && is_alpha(part) {
            format!("{}{}", to_upper(&part[..1]), to_lower(&part[1..]))
        } else if part.len() == 2 && is_alpha(part) {
            to_upper(part)
        } else {
            to_lower(part)
        };
        *part = new;
    }
    parts.join("-")
}

fn is_alpha(value: &str) -> bool {
    value.chars().all(|c| c.is_ascii_alphabetic())
}

/// `language.Parse` then `Tag.String`, for vector tests. `None` means Go returned an error.
#[doc(hidden)]
pub fn x_text_parse(value: &str) -> Option<String> {
    parse(value).ok().map(|tag: Tag| tag.string())
}
