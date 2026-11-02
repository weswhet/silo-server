//! The ceiling half of `internal/access/rating.go`: `Normalize`, `AgeForCeiling`, `HasCeiling`, and
//! `StricterCeiling`. `tests/rating_vectors.rs` checks them against the real package.

use silo_gocompat::strings::{fields, to_upper, trim_space};

const MPAA: &str = "mpaa";
const US_TV: &str = "us-tv";
const BBFC: &str = "bbfc";
const FSK: &str = "fsk";
const CNC: &str = "cnc";
const ACB: &str = "acb";
const KIJKWIJZER: &str = "kijkwijzer";
const EIRIN: &str = "eirin";
const ICAA: &str = "icaa";
const DJCTQ: &str = "djctq";
const IGAC: &str = "igac";
const CBFC: &str = "cbfc";
const INCAA: &str = "incaa";
const RTC: &str = "rtc";
const KMRB: &str = "kmrb";
const AGE: &str = "age";
const UNRATED: &str = "unrated";

/// `maxRatingAge`.
const MAX_RATING_AGE: i32 = 21;

/// `ratingLadder`. A token several systems share resolves to the first listed.
const LADDER: &[(&str, &[(&str, i32)])] = &[
    (
        MPAA,
        &[("G", 0), ("PG", 8), ("PG13", 13), ("R", 17), ("NC17", 18)],
    ),
    (
        US_TV,
        &[
            ("TVY", 0),
            ("TVG", 0),
            ("TVY7", 7),
            ("TVY7FV", 7),
            ("TVPG", 8),
            ("TV14", 14),
            ("TVMA", 17),
        ],
    ),
    (
        BBFC,
        &[
            ("U", 0),
            ("UC", 0),
            ("PG", 8),
            ("12", 12),
            ("12A", 12),
            ("15", 15),
            ("18", 18),
            ("R18", 18),
        ],
    ),
    (
        FSK,
        &[
            ("0", 0),
            ("FSK0", 0),
            ("6", 6),
            ("FSK6", 6),
            ("12", 12),
            ("FSK12", 12),
            ("16", 16),
            ("FSK16", 16),
            ("18", 18),
            ("FSK18", 18),
        ],
    ),
    (
        CNC,
        &[
            ("TOUSPUBLICS", 0),
            ("TP", 0),
            ("U", 0),
            ("10", 10),
            ("12", 12),
            ("16", 16),
            ("18", 18),
        ],
    ),
    (
        ACB,
        &[
            ("G", 0),
            ("PG", 8),
            ("M", 15),
            ("MA15", 15),
            ("MA15+", 15),
            ("R18", 18),
            ("R18+", 18),
            ("X18", 18),
            ("X18+", 18),
        ],
    ),
    (
        KIJKWIJZER,
        &[
            ("AL", 0),
            ("6", 6),
            ("9", 9),
            ("12", 12),
            ("14", 14),
            ("16", 16),
            ("18", 18),
        ],
    ),
    (
        EIRIN,
        &[
            ("G", 0),
            ("PG12", 12),
            ("R15", 15),
            ("R15+", 15),
            ("R18+", 18),
        ],
    ),
    (
        ICAA,
        &[
            ("APTA", 0),
            ("TP", 0),
            ("7", 7),
            ("12", 12),
            ("16", 16),
            ("18", 18),
            ("X", 18),
        ],
    ),
    (
        DJCTQ,
        &[
            ("L", 0),
            ("10", 10),
            ("12", 12),
            ("14", 14),
            ("16", 16),
            ("18", 18),
        ],
    ),
    (
        IGAC,
        &[
            ("M3", 3),
            ("M6", 6),
            ("M12", 12),
            ("M14", 14),
            ("M16", 16),
            ("M18", 18),
        ],
    ),
    (
        CBFC,
        &[
            ("U", 0),
            ("UA", 12),
            ("UA7", 7),
            ("UA7+", 7),
            ("UA13", 13),
            ("UA13+", 13),
            ("UA16", 16),
            ("UA16+", 16),
        ],
    ),
    (
        INCAA,
        &[("ATP", 0), ("SAM13", 13), ("SAM16", 16), ("SAM18", 18)],
    ),
    (RTC, &[("AA", 0), ("B15", 15)]),
    (KMRB, &[("ALL", 0)]),
];

/// `unratedTokens`.
const UNRATED_TOKENS: &[&str] = &[
    "NR",
    "UR",
    "NA",
    "NONE",
    "UNRATED",
    "UNKNOWN",
    "NOTRATED",
    "NOTYETRATED",
];

/// `countrySystems`.
fn country_systems(code: &str) -> &'static [&'static str] {
    match code {
        "US" | "USA" => &[MPAA, US_TV],
        "GB" | "GBR" | "UK" => &[BBFC],
        "DE" | "DEU" | "GER" => &[FSK],
        "FR" | "FRA" => &[CNC],
        "AU" | "AUS" => &[ACB],
        "NL" | "NLD" => &[KIJKWIJZER],
        "JP" | "JPN" => &[EIRIN],
        "ES" | "ESP" => &[ICAA],
        "BR" | "BRA" => &[DJCTQ],
        "PT" | "PRT" => &[IGAC],
        "IN" | "IND" => &[CBFC],
        "AR" | "ARG" => &[INCAA],
        "MX" | "MEX" => &[RTC],
        "KR" | "KOR" => &[KMRB],
        _ => &[],
    }
}

fn system_age(system: &str, token: &str) -> Option<i32> {
    LADDER
        .iter()
        .find(|(name, _)| *name == system)
        .and_then(|(_, ages)| ages.iter().find(|(t, _)| *t == token))
        .map(|(_, age)| *age)
}

fn index_age(token: &str) -> Option<(&'static str, i32)> {
    LADDER.iter().find_map(|(system, ages)| {
        ages.iter()
            .find(|(t, _)| *t == token)
            .map(|(_, age)| (*system, *age))
    })
}

/// `cutRatedPrefix`.
fn cut_rated_prefix(upper: &str) -> Option<&str> {
    let rest = upper.strip_prefix("RATED")?;
    let next = *rest.as_bytes().first()?;
    if next.is_ascii_uppercase() {
        return None;
    }
    Some(trim_space(rest))
}

/// `canonicalRatingToken`.
fn canonical_token(raw: &str) -> String {
    let upper = to_upper(trim_space(raw));
    cut_rated_prefix(&upper)
        .unwrap_or(&upper)
        .chars()
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '+')
        .collect()
}

/// `ratingTokens`.
fn rating_tokens(rest: &str) -> Vec<String> {
    let token = canonical_token(rest);
    if token.is_empty() {
        return Vec::new();
    }
    let upper = to_upper(trim_space(rest));
    let Some(stripped) = cut_rated_prefix(&upper) else {
        return vec![token];
    };
    let words = fields(stripped);
    if words.len() < 2 {
        return vec![token];
    }
    let first = canonical_token(words[0]);
    if first.is_empty() || first == token {
        return vec![token];
    }
    vec![token, first]
}

/// `bareAge`.
fn bare_age(token: &str) -> Option<i32> {
    let digits = token.strip_prefix('+').unwrap_or(token);
    let digits = digits.strip_suffix('+').unwrap_or(digits);
    if digits.is_empty() || digits.len() > 2 {
        return None;
    }
    // `strconv.Atoi` also takes a sign, and "+" is the only one a canonical token can hold.
    let age = digits.strip_prefix('+').unwrap_or(digits).parse().ok()?;
    (age <= MAX_RATING_AGE).then_some(age)
}

/// `resolveRatingToken`.
fn resolve_token(token: &str, systems: &[&'static str]) -> Option<(&'static str, Option<i32>)> {
    if UNRATED_TOKENS.contains(&token) {
        return Some((UNRATED, None));
    }
    for system in systems {
        if let Some(age) = system_age(system, token) {
            return Some((system, Some(age)));
        }
    }
    if let Some((system, age)) = index_age(token) {
        return Some((system, Some(age)));
    }
    bare_age(token).map(|age| (AGE, Some(age)))
}

/// `splitCountryPrefix`.
fn split_country_prefix(raw: &str) -> (&str, &'static [&'static str]) {
    let trimmed = trim_space(raw);
    let Some(idx) = trimmed.find(':').filter(|i| *i > 0) else {
        return (trimmed, &[]);
    };
    let code = to_upper(trim_space(&trimmed[..idx]));
    let alpha = code.chars().all(|c| c.is_ascii_uppercase());
    if code.len() < 2 || code.len() > 3 || !alpha {
        return (trimmed, &[]);
    }
    (trim_space(&trimmed[idx + 1..]), country_systems(&code))
}

/// `Normalize`: the system and the age. `None` is an unrecognized string, and an age of `None` is an
/// explicit "not rated" marker.
pub fn normalize(raw: &str) -> Option<(&'static str, Option<i32>)> {
    let (rest, systems) = split_country_prefix(raw);
    rating_tokens(rest)
        .iter()
        .find_map(|token| resolve_token(token, systems))
}

/// `rankForAge`.
fn rank_for_age(age: i32) -> usize {
    match age {
        i32::MIN..=0 => 0,
        1..=12 => 1,
        13..=16 => 2,
        _ => 3,
    }
}

/// `usTierCeilingAge`: the oldest age any US rating in each tier stands for.
const US_TIER_CEILING_AGE: [i32; 4] = [0, 8, 14, 18];

/// `AgeForCeiling`.
pub fn age_for_ceiling(ceiling: &str) -> Option<i32> {
    let (system, age) = normalize(ceiling)?;
    let age = age?;
    if system == MPAA || system == US_TV {
        return Some(US_TIER_CEILING_AGE[rank_for_age(age)]);
    }
    Some(age)
}

/// `HasCeiling`: only the empty string means no ceiling.
pub fn has_ceiling(ceiling: &str) -> bool {
    !ceiling.is_empty()
}

/// `StricterCeiling`: an unusable ceiling beats a usable one, because it blocks everything.
pub fn stricter_ceiling<'a>(a: &'a str, b: &'a str) -> &'a str {
    if !has_ceiling(a) {
        return b;
    }
    if !has_ceiling(b) {
        return a;
    }
    let (Some(age_a), age_b) = (age_for_ceiling(a), age_for_ceiling(b)) else {
        return a;
    };
    match age_b {
        None => b,
        Some(age_b) if age_b < age_a => b,
        Some(_) => a,
    }
}
