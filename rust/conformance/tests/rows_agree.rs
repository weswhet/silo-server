//! The routes this harness measures and the row table in `silo-front` must name the same set. A row
//! the harness never sends can never be scored, and a route outside the table has no disposition.

use std::collections::BTreeSet;
use std::path::Path;

fn table_rows(repo: &Path) -> BTreeSet<(String, String)> {
    let table =
        std::fs::read_to_string(repo.join("rust/crates/silo-front/src/rows_table.rs")).unwrap();
    let mut rows = BTreeSet::new();
    for line in table.lines() {
        let line = line.trim_start();
        if !(line.starts_with("go(") || line.starts_with("native(")) {
            continue;
        }
        let quoted: Vec<&str> = line.split('"').collect();
        rows.insert((quoted[1].to_owned(), quoted[3].to_owned()));
    }
    rows
}

#[test]
fn harness_routes_match_the_row_table() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sources = silo_conformance::sources::load(&repo).unwrap();
    let harness: BTreeSet<(String, String)> = sources
        .routes
        .iter()
        .map(|r| (r.method.clone(), r.path.clone()))
        .collect();
    let table = table_rows(&repo);
    let only_harness: Vec<_> = harness.difference(&table).collect();
    let only_table: Vec<_> = table.difference(&harness).collect();
    assert!(
        only_harness.is_empty() && only_table.is_empty(),
        "only in the harness: {only_harness:#?}\nonly in the table: {only_table:#?}"
    );
}
