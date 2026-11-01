//! Go's real output, checked here. Regenerate with `rust/conformance/vectors/generators/core/run.sh gen`.

#![allow(clippy::disallowed_methods)] // Plain relative paths to test data.

mod support;

use support::{Kind2, families, read_cases};

#[test]
fn go_vectors() {
    let mut failures = Vec::new();
    let mut total = 0usize;
    for family in families() {
        let cases = read_cases(family.name);
        let mut bad = 0usize;
        for (index, (input, output)) in cases.iter().enumerate() {
            total += 1;
            let result = match &family.kind {
                Kind2::Det(compute) => {
                    let got = compute(input);
                    if &got == output {
                        Ok(())
                    } else {
                        Err(format!("got {got}\n   want {output}"))
                    }
                }
                Kind2::Nondet { check, .. } => check(input, output),
            };
            if let Err(message) = result {
                bad += 1;
                if bad <= 2 {
                    failures.push(format!(
                        "{} case {index}: {message}\n   in {input}",
                        family.name
                    ));
                }
            }
        }
        if bad > 0 {
            failures.push(format!("{}: {bad} of {} failed", family.name, cases.len()));
        }
    }
    assert!(
        failures.is_empty(),
        "{} problems across {total} cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("{total} cases");
}

#[test]
fn directplay_linux_vector() {
    let cases = read_cases("playback_directplay_etag_linux");
    assert!(cases.len() >= 500);
    for (input, output) in &cases {
        assert_eq!(output["os"], "linux");
        support::check_directplay(input, output).unwrap();
    }
}

/// The published denominator has to name only families this harness runs, with the counts on disk.
#[test]
fn formats_table_matches_the_harness() {
    let path = support::vectors_dir().join("../../../parity/formats.json");
    let table: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("rust/parity/formats.json"))
            .expect("JSON");
    let harness: std::collections::HashSet<&str> = families().iter().map(|f| f.name).collect();
    let rows = table["families"].as_array().expect("families");
    assert_eq!(table["denominator"].as_u64(), Some(rows.len() as u64));
    let mut covered = std::collections::HashSet::new();
    for row in rows {
        let family = row["vector_family"].as_str().expect("family");
        if family != "playback_directplay_etag_linux" {
            assert!(harness.contains(family), "{family} is not in the harness");
        }
        covered.insert(family.to_owned());
        let cases = read_cases(family);
        let want = match row["selector"].as_str() {
            None => cases.len(),
            Some(selector) => cases.iter().filter(|(i, _)| i["fn"] == selector).count(),
        };
        assert_eq!(row["cases"].as_u64(), Some(want as u64), "{}", row["id"]);
    }
    for family in &harness {
        assert!(
            covered.contains(*family),
            "{family} has no row in formats.json"
        );
    }
}
