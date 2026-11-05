//! The search query parser against the `catalogsearch` vectors Go wrote
//! (`rust/conformance/vectors/generators/catalogsearch`).

use serde::Deserialize;
use silo_catalog::search::query::*;

#[derive(Deserialize, Debug)]
#[serde(default)]
#[derive(Default)]
struct Case {
    raw: String,
    text: String,
    phrase: String,
    exact_title_hint: String,
    normalized_text: String,
    year: Option<i64>,
    fuzzy: bool,
    exact_short: bool,
    leading_short: bool,
    prefix_tsquery: String,
    fold: String,
}

#[test]
fn search_query_matches_go() {
    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/catalog/search_query.json"
    ))
    .unwrap();
    let cases: Vec<Case> = serde_json::from_slice(&raw).unwrap();
    assert!(cases.len() > 50);
    for c in cases {
        let p = parse_search_query(&c.raw);
        let got = (
            p.text.as_str(),
            p.phrase.as_str(),
            p.exact_title_hint.as_str(),
            p.normalized_text.as_str(),
            p.year,
            eligible_for_fuzzy(&p),
            use_exact_short_title_search(&p),
            use_leading_short_title_search(&p),
            build_title_prefix_ts_query(&c.raw),
            fold_search_diacritics(&c.raw),
        );
        let want = (
            c.text.as_str(),
            c.phrase.as_str(),
            c.exact_title_hint.as_str(),
            c.normalized_text.as_str(),
            c.year,
            c.fuzzy,
            c.exact_short,
            c.leading_short,
            c.prefix_tsquery.clone(),
            c.fold.clone(),
        );
        assert_eq!(got, want, "input {:?}", c.raw);
    }
}
