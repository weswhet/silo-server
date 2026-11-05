//! Bounded typo scoring for candidates selected by PostgreSQL.

use std::{cmp::Ordering, collections::HashMap};

use silo_gocompat::{strings::fields, unicode::is_digit};

use super::query::{FUZZY_MIN_TOKEN_LEN, normalize_title_for_comparison};

pub const FUZZY_RERANK_MAX_QUERY_TOKENS: usize = 16;
pub const FUZZY_RERANK_MAX_TITLE_TOKENS: usize = 64;
pub const FUZZY_RERANK_MAX_TOKEN_RUNES: usize = 64;
pub const FUZZY_RERANK_MAX_TITLE_BYTES: usize = 1024;
pub const FUZZY_STOPWORDS: &[&str] = &[
    "a", "an", "the", "of", "in", "on", "at", "to", "for", "by", "with", "from",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FuzzyItem {
    pub content_id: String,
    pub title: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FuzzyTitleScore {
    pub exact: bool,
    pub contiguous: bool,
    pub matched_tokens: usize,
    pub missing_words: usize,
    pub edit_distance: usize,
    pub extra_tokens: usize,
}

fn unmatched_fuzzy_title_score() -> FuzzyTitleScore {
    FuzzyTitleScore {
        missing_words: usize::MAX,
        edit_distance: usize::MAX,
        extra_tokens: usize::MAX,
        ..FuzzyTitleScore::default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzyRankedItem {
    pub item: FuzzyItem,
    pub score: FuzzyTitleScore,
    pub order: usize,
}

/// Score each title and alias, retaining candidate order when scores tie.
/// Oversized or empty queries retain PostgreSQL's order and require no words.
pub fn rank_fuzzy_items(
    search_text: &str,
    items: &[FuzzyItem],
    aliases: &HashMap<String, Vec<String>>,
) -> (Vec<FuzzyRankedItem>, usize) {
    let query = normalize_title_for_comparison(search_text);
    let tokens = bounded_fuzzy_tokens(&query, FUZZY_RERANK_MAX_QUERY_TOKENS);
    let scored = tokens.as_ref().is_some_and(|tokens| !tokens.is_empty());
    let query_tokens = tokens.unwrap_or_default();
    let required = if scored {
        fuzzy_required_words(&query_tokens)
            .iter()
            .filter(|word| **word)
            .count()
    } else {
        0
    };
    let mut ranks: Vec<_> = items
        .iter()
        .enumerate()
        .map(|(order, item)| {
            let mut score = FuzzyTitleScore::default();
            if scored {
                score = unmatched_fuzzy_title_score();
                let variants = aliases
                    .get(&item.content_id)
                    .into_iter()
                    .flatten()
                    .map(String::as_str)
                    .chain(
                        (item.title.len() <= FUZZY_RERANK_MAX_TITLE_BYTES)
                            .then_some(item.title.as_str()),
                    );
                for variant in variants {
                    let candidate = score_fuzzy_title_variant(&query, &query_tokens, variant);
                    if fuzzy_title_score_better(candidate, score) {
                        score = candidate;
                    }
                }
            }
            FuzzyRankedItem {
                item: item.clone(),
                score,
                order,
            }
        })
        .collect();
    ranks.sort_by(|a, b| {
        if fuzzy_title_score_better(a.score, b.score) {
            Ordering::Less
        } else if fuzzy_title_score_better(b.score, a.score) {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    });
    (ranks, required)
}

/// Prefer candidates covering every required word. Relax only when the exact
/// search found nothing, keeping candidates missing the fewest words.
pub fn admit_fuzzy_ranks(
    mut ranks: Vec<FuzzyRankedItem>,
    required: usize,
    exact_hits: bool,
) -> Vec<FuzzyRankedItem> {
    let Some(first) = ranks.first() else {
        return ranks;
    };
    let fewest = first.score.missing_words;
    if fewest > 0 && (exact_hits || fewest >= required) {
        ranks.clear();
    } else {
        let end = ranks
            .iter()
            .take_while(|rank| rank.score.missing_words == fewest)
            .count();
        ranks.truncate(end);
    }
    ranks
}

/// Remove optional stopwords only when another word supplies enough trigrams.
pub fn fuzzy_candidate_text(search_text: &str) -> String {
    let normalized = normalize_title_for_comparison(search_text);
    let words = fields(&normalized);
    let content: Vec<_> = words
        .iter()
        .copied()
        .filter(|word| !FUZZY_STOPWORDS.contains(word))
        .collect();
    if content
        .iter()
        .any(|word| word.chars().count() >= FUZZY_MIN_TOKEN_LEN)
    {
        content.join(" ")
    } else {
        words.join(" ")
    }
}

pub fn fuzzy_token_max_edits(token: &[char]) -> usize {
    if FUZZY_STOPWORDS.contains(&token.iter().collect::<String>().as_str()) {
        0
    } else {
        fuzzy_auto_max_edits(token.len())
    }
}

pub fn fuzzy_required_words(query_tokens: &[Vec<char>]) -> Vec<bool> {
    let mut required: Vec<_> = query_tokens
        .iter()
        .map(|token| !FUZZY_STOPWORDS.contains(&token.iter().collect::<String>().as_str()))
        .collect();
    if !required.iter().any(|word| *word) {
        required.fill(true);
    }
    required
}

pub fn score_fuzzy_title_variant(
    _query: &str,
    query_tokens: &[Vec<char>],
    raw_title: &str,
) -> FuzzyTitleScore {
    let title = normalize_title_for_comparison(raw_title);
    let Some(title_tokens) = bounded_fuzzy_tokens(&title, FUZZY_RERANK_MAX_TITLE_TOKENS)
        .filter(|tokens| !tokens.is_empty())
    else {
        return unmatched_fuzzy_title_score();
    };
    let compact_title = compact_fuzzy_tokens(&title_tokens);
    let compact_query = compact_fuzzy_tokens(query_tokens);
    let mut score = FuzzyTitleScore {
        exact: compact_title == compact_query,
        contiguous: compact_title.contains(&compact_query),
        extra_tokens: title_tokens.len().abs_diff(query_tokens.len()),
        ..FuzzyTitleScore::default()
    };
    let joined = join_adjacent_fuzzy_tokens(&title_tokens);
    let terms: Vec<_> = title_tokens.iter().chain(&joined).cloned().collect();
    let matches: Vec<_> = query_tokens
        .iter()
        .map(|token| best_fuzzy_token_match(token, &title_tokens, &joined))
        .collect();
    let mut matched = vec![false; query_tokens.len()];
    let mut i = 0;
    while i < query_tokens.len() {
        if i + 1 < query_tokens.len()
            && (!matches[i].ok || !matches[i + 1].ok)
            && fuzzy_tokens_joinable(&query_tokens[i], &query_tokens[i + 1])
        {
            let pair = best_fuzzy_pair_match(&query_tokens[i], &query_tokens[i + 1], &terms);
            if pair.ok {
                matched[i] = true;
                matched[i + 1] = true;
                score.matched_tokens += 2;
                score.edit_distance += pair.distance;
                i += 2;
                continue;
            }
        }
        if matches[i].ok {
            matched[i] = true;
            score.matched_tokens += 1;
        }
        score.edit_distance += matches[i].distance;
        i += 1;
    }
    if !score.exact && !spells_consecutive_fuzzy_tokens(&title_tokens, &compact_query) {
        score.missing_words = fuzzy_required_words(query_tokens)
            .iter()
            .zip(matched)
            .filter(|(required, matched)| **required && !matched)
            .count();
    }
    score
}

/// Match runs of whole words typed without spaces, without matching inside a word.
pub fn spells_consecutive_fuzzy_tokens(title_tokens: &[Vec<char>], compact_query: &str) -> bool {
    for start in 0..title_tokens.len() {
        for end in start + 1..=title_tokens.len() {
            let run = compact_fuzzy_tokens(&title_tokens[start..end]);
            if run == compact_query {
                return true;
            }
            if run.len() >= compact_query.len() {
                break;
            }
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FuzzyTokenMatch {
    pub distance: usize,
    pub ok: bool,
}

/// Joining title words costs one extra edit so a single-word spelling ranks first.
pub fn best_fuzzy_token_match(
    token: &[char],
    words: &[Vec<char>],
    joined: &[Vec<char>],
) -> FuzzyTokenMatch {
    let max_edits = fuzzy_token_max_edits(token);
    let mut best = FuzzyTokenMatch {
        distance: max_edits + 1,
        ok: false,
    };
    for (penalty, terms) in [words, joined].iter().enumerate() {
        for term in *terms {
            let distance = bounded_levenshtein_runes(token, term, max_edits);
            if distance <= max_edits && (!best.ok || distance + penalty < best.distance) {
                best = FuzzyTokenMatch {
                    distance: distance + penalty,
                    ok: true,
                };
            }
        }
    }
    best
}

/// Each query word keeps its own typo allowance when matching a split title term.
pub fn best_fuzzy_pair_match(
    first: &[char],
    second: &[char],
    terms: &[Vec<char>],
) -> FuzzyTokenMatch {
    let first_edits = fuzzy_token_max_edits(first);
    let second_edits = fuzzy_token_max_edits(second);
    let mut best = first_edits + second_edits + 1;
    for term in terms {
        if term.len().abs_diff(first.len() + second.len()) > first_edits + second_edits {
            continue;
        }
        for split in
            first.len().saturating_sub(first_edits)..=term.len().min(first.len() + first_edits)
        {
            let head = bounded_levenshtein_runes(first, &term[..split], first_edits);
            if head > first_edits {
                continue;
            }
            let tail = bounded_levenshtein_runes(second, &term[split..], second_edits);
            if tail <= second_edits {
                best = best.min(head + tail);
            }
        }
    }
    FuzzyTokenMatch {
        distance: best,
        ok: best <= first_edits + second_edits,
    }
}

pub fn join_adjacent_fuzzy_tokens(tokens: &[Vec<char>]) -> Vec<Vec<char>> {
    tokens
        .windows(2)
        .filter(|pair| fuzzy_tokens_joinable(&pair[0], &pair[1]))
        .map(|pair| pair[0].iter().chain(&pair[1]).copied().collect())
        .collect()
}

pub fn compact_fuzzy_tokens(tokens: &[Vec<char>]) -> String {
    let mut compact = String::new();
    for (i, token) in tokens.iter().enumerate() {
        if i > 0 && !fuzzy_tokens_joinable(&tokens[i - 1], token) {
            compact.push(' ');
        }
        compact.extend(token);
    }
    compact
}

/// Preserve boundaries between numbers: normalized "one two" is not "twelve".
pub fn fuzzy_tokens_joinable(left: &[char], right: &[char]) -> bool {
    !is_digit(left[left.len() - 1] as u32) || !is_digit(right[0] as u32)
}

pub fn fuzzy_title_score_better(a: FuzzyTitleScore, b: FuzzyTitleScore) -> bool {
    if a.exact != b.exact {
        return a.exact;
    }
    if a.missing_words != b.missing_words {
        return a.missing_words < b.missing_words;
    }
    if a.matched_tokens != b.matched_tokens {
        return a.matched_tokens > b.matched_tokens;
    }
    if a.contiguous != b.contiguous {
        return a.contiguous;
    }
    if a.edit_distance != b.edit_distance {
        return a.edit_distance < b.edit_distance;
    }
    a.extra_tokens < b.extra_tokens
}

pub fn bounded_fuzzy_tokens(normalized: &str, max_tokens: usize) -> Option<Vec<Vec<char>>> {
    let words = fields(normalized);
    if words.len() > max_tokens {
        return None;
    }
    words
        .into_iter()
        .map(|word| {
            let runes: Vec<_> = word.chars().collect();
            (runes.len() <= FUZZY_RERANK_MAX_TOKEN_RUNES).then_some(runes)
        })
        .collect()
}

pub fn fuzzy_auto_max_edits(token_runes: usize) -> usize {
    match token_runes {
        0..=2 => 0,
        3..=5 => 1,
        _ => 2,
    }
}

pub fn bounded_levenshtein_runes(a: &[char], b: &[char], max_edits: usize) -> usize {
    if a.len().abs_diff(b.len()) > max_edits {
        return max_edits + 1;
    }
    if a.is_empty() {
        return b.len().min(max_edits + 1);
    }
    if b.is_empty() {
        return a.len().min(max_edits + 1);
    }
    let (a, b) = if a.len() > b.len() { (b, a) } else { (a, b) };
    let mut previous: Vec<_> = (0..=a.len()).collect();
    let mut current = vec![0; a.len() + 1];
    for (row, right) in b.iter().enumerate() {
        current[0] = row + 1;
        let mut row_min = current[0];
        for (col, left) in a.iter().enumerate() {
            let cost = usize::from(left != right);
            current[col + 1] = (previous[col + 1] + 1)
                .min(current[col] + 1)
                .min(previous[col] + cost);
            row_min = row_min.min(current[col + 1]);
        }
        if row_min > max_edits {
            return max_edits + 1;
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[a.len()].min(max_edits + 1)
}
