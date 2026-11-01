//! `internal/recommendations/embeddings`: the canonical text compared with `canonical_text`. A mismatch
//! re-embeds items through a paid API, so its shape is part of the embedding contract.

use silo_gocompat::strings::decode_runes;

/// `models.PersonKind` values that credit text reads.
pub const PERSON_KIND_ACTOR: i64 = 1;
pub const PERSON_KIND_DIRECTOR: i64 = 2;
pub const PERSON_KIND_WRITER: i64 = 3;
pub const PERSON_KIND_AUTHOR: i64 = 7;
pub const PERSON_KIND_NARRATOR: i64 = 8;

const MAX_OVERVIEW_RUNES: usize = 1000;
const MAX_KEYWORDS: usize = 5;

/// The fields of `models.ItemPerson` the text reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemPerson {
    pub id: i64,
    pub name: String,
    pub kind: i64,
    pub character: String,
    pub sort_order: i64,
}

/// The fields of `models.MediaItem` the text reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmbeddingItem {
    pub item_type: String,
    pub title: String,
    pub year: i64,
    pub overview: String,
    pub genres: Vec<String>,
    pub content_rating: String,
    pub tagline: String,
    pub people: Vec<ItemPerson>,
    pub keywords: Vec<String>,
    pub original_language: String,
    pub studios: Vec<String>,
    pub networks: Vec<String>,
    pub countries: Vec<String>,
}

/// `TruncateRunes`.
pub fn truncate_runes(s: &str, limit: usize) -> &str {
    if limit == 0 {
        return "";
    }
    match s.char_indices().nth(limit) {
        Some((at, _)) => &s[..at],
        None => s,
    }
}

fn type_label(t: &str) -> &'static str {
    match t {
        "series" => "TV series",
        "audiobook" => "audiobook",
        "ebook" => "ebook",
        _ => "movie",
    }
}

fn sorted_people(item: &EmbeddingItem, kind: i64) -> Vec<&ItemPerson> {
    let mut people: Vec<&ItemPerson> = item.people.iter().filter(|p| p.kind == kind).collect();
    people.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.name.as_bytes().cmp(b.name.as_bytes()))
            .then_with(|| a.character.as_bytes().cmp(b.character.as_bytes()))
            .then_with(|| a.id.cmp(&b.id))
    });
    people
}

fn names(people: &[&ItemPerson]) -> String {
    people
        .iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `BuildEmbeddingText`.
pub fn build_embedding_text(item: &EmbeddingItem) -> String {
    let mut parts: Vec<String> = Vec::new();
    let type_name = type_label(&item.item_type);
    let genres = item.genres.join(", ");
    if !item.genres.is_empty() && !item.overview.is_empty() {
        let overview = truncate_runes(&item.overview, MAX_OVERVIEW_RUNES);
        parts.push(format!("{genres} {type_name} about {overview}"));
    } else if !item.genres.is_empty() {
        parts.push(format!("{genres} {type_name}"));
    } else if !item.overview.is_empty() {
        let overview = truncate_runes(&item.overview, MAX_OVERVIEW_RUNES);
        parts.push(format!("{type_name}. {overview}"));
    }
    if item.year > 0 {
        parts.push(format!("{} ({})", item.title, item.year));
    } else {
        parts.push(item.title.clone());
    }
    if !item.content_rating.is_empty() {
        parts.push(format!("Rated {}", item.content_rating));
    }
    if !item.tagline.is_empty() {
        parts.push(format!("\"{}\"", item.tagline));
    }
    if item.item_type == "audiobook" || item.item_type == "ebook" {
        let authors = sorted_people(item, PERSON_KIND_AUTHOR);
        if !authors.is_empty() {
            parts.push(format!("Written by {}", names(&authors)));
        }
        if item.item_type == "audiobook" {
            let narrators = sorted_people(item, PERSON_KIND_NARRATOR);
            if !narrators.is_empty() {
                parts.push(format!("Narrated by {}", names(&narrators)));
            }
        }
    } else {
        let actors = sorted_people(item, PERSON_KIND_ACTOR);
        if !actors.is_empty() {
            let credits: Vec<String> = actors
                .iter()
                .take(5)
                .map(|p| {
                    if p.character.is_empty() {
                        p.name.clone()
                    } else {
                        format!("{} as {}", p.name, p.character)
                    }
                })
                .collect();
            parts.push(format!("Cast: {}", credits.join(", ")));
        }
        let directors = sorted_people(item, PERSON_KIND_DIRECTOR);
        if !directors.is_empty() {
            parts.push(format!("Directed by {}", names(&directors)));
        }
        let writers = sorted_people(item, PERSON_KIND_WRITER);
        if !writers.is_empty() {
            parts.push(format!("Written by {}", names(&writers)));
        }
    }
    if !item.keywords.is_empty() {
        let keywords = &item.keywords[..item.keywords.len().min(MAX_KEYWORDS)];
        parts.push(format!("Keywords: {}", keywords.join(", ")));
    }
    if !item.original_language.is_empty() {
        parts.push(format!("Original language: {}", item.original_language));
    }
    if !item.studios.is_empty() {
        parts.push(format!("Studios: {}", item.studios.join(", ")));
    }
    if !item.networks.is_empty() {
        parts.push(format!("Network: {}", item.networks.join(", ")));
    }
    if !item.countries.is_empty() {
        let countries = &item.countries[..item.countries.len().min(2)];
        parts.push(format!("Country: {}", countries.join(", ")));
    }
    decode_runes(parts.join(". ").as_bytes()).into_owned()
}
