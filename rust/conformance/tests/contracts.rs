//! Checks the plan built from the real contract files in this repository.

use silo_conformance::model::{is_mutating, Identity, Phase, Surface};
use silo_conformance::{plan, sources};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn repo() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// The harness's universe and the front's row table are the same set of rows. A row only one of them
/// knows either can't be scored or isn't declared.
#[test]
fn harness_universe_is_the_row_table() {
    let src = sources::load(repo()).unwrap();
    let harness: BTreeSet<String> = src.routes.iter().map(|r| r.key()).collect();
    let table: BTreeSet<String> = silo_front::rows::ROWS
        .iter()
        .map(|r| format!("{} {} {}", r.surface.name(), r.method, r.path))
        .collect();
    let only_harness: Vec<_> = harness.difference(&table).collect();
    let only_table: Vec<_> = table.difference(&harness).collect();
    assert!(
        only_harness.is_empty(),
        "not in the table: {only_harness:?}"
    );
    assert!(only_table.is_empty(), "not in the harness: {only_table:?}");
}

/// An entry the doc no longer produces, or whose parent is gone, is stale.
#[test]
fn doc_illustrations_are_current() {
    let doc = std::fs::read_to_string(repo().join(sources::JELLY_DOC)).unwrap();
    let mentioned = sources::doc_routes(&doc);
    let src = sources::load(repo()).unwrap();
    for ill in sources::DOC_ILLUSTRATIONS {
        assert!(
            mentioned
                .iter()
                .any(|(m, p)| m == ill.method && p == ill.path),
            "{} is no longer in the doc",
            ill.path
        );
        assert!(
            !src.routes.iter().any(|r| r.path == ill.path),
            "{}",
            ill.path
        );
        if let Some(parent) = ill.parent {
            assert!(src.routes.iter().any(|r| r.path == parent), "{parent}");
        }
    }
}

#[test]
fn every_source_route_is_counted_and_gets_a_case() {
    let src = sources::load(repo()).unwrap();
    let totals = sources::surface_totals(&src.routes);

    let openapi: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo().join(sources::OPENAPI)).unwrap())
            .unwrap();
    let mut ops = 0;
    for item in openapi["paths"].as_object().unwrap().values() {
        for key in item.as_object().unwrap().keys() {
            if [
                "get", "put", "post", "delete", "patch", "head", "options", "trace",
            ]
            .contains(&key.as_str())
            {
                ops += 1;
            }
        }
    }
    assert_eq!(totals[&Surface::ApiV2], ops);

    let inventory: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo().join(sources::INVENTORY)).unwrap())
            .unwrap();
    let in_listener = inventory["routes"].as_array().unwrap().len();
    let from_inventory: usize = [
        Surface::ApiV1,
        Surface::ApiDelegate,
        Surface::Root,
        Surface::Metrics,
        Surface::Debug,
        Surface::ProxyNode,
        Surface::TranscodeNode,
    ]
    .iter()
    .map(|s| totals[s])
    .sum();
    assert_eq!(from_inventory, in_listener);

    let p = plan::build(&src);
    let planned: BTreeSet<usize> = p.cases.iter().map(|c| c.route).collect();
    let unplanned: Vec<String> = src
        .routes
        .iter()
        .enumerate()
        .filter(|(i, _)| !planned.contains(i))
        .map(|(_, r)| r.key())
        .collect();
    assert!(unplanned.is_empty(), "routes with no case: {unplanned:?}");

    let ids: BTreeSet<&str> = p.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), p.cases.len(), "case ids must be unique");
}

#[test]
fn writes_cannot_reach_the_read_phase_and_run_in_a_safe_order() {
    let src = sources::load(repo()).unwrap();
    let p = plan::build(&src);
    for c in &p.cases {
        if c.phase == Phase::Reads {
            assert!(
                !is_mutating(&c.method),
                "{} would write before the reads are done",
                c.id
            );
        }
        if is_mutating(&c.method)
            && matches!(c.identity, Identity::Admin | Identity::User)
            && c.body.is_some()
        {
            assert!(c.phase > Phase::Reads || c.phase == Phase::Seed, "{}", c.id);
        }
    }
    // Phases are monotonic, and within a write stage deletes follow creates.
    let phases: Vec<Phase> = p.cases.iter().map(|c| c.phase).collect();
    assert!(phases.windows(2).all(|w| w[0] <= w[1]));
    for stage in [Phase::MutateV2, Phase::MutateV1] {
        let methods: Vec<&str> = p
            .cases
            .iter()
            .filter(|c| c.phase == stage)
            .map(|c| c.method.as_str())
            .collect();
        let last_post = methods.iter().rposition(|m| *m == "POST").unwrap();
        let first_delete = methods.iter().position(|m| *m == "DELETE").unwrap();
        assert!(last_post < first_delete, "{stage:?}");
    }
}

#[test]
fn no_privileged_case_can_restart_the_server() {
    let src = sources::load(repo()).unwrap();
    let p = plan::build(&src);
    let restart: Vec<_> = p
        .cases
        .iter()
        .filter(|c| c.path.ends_with("/admin/server/restart") && c.method == "POST")
        .collect();
    assert!(!restart.is_empty());
    for c in restart {
        assert!(
            matches!(c.identity, Identity::Anon | Identity::User),
            "{} sends a restart as {:?}",
            c.id,
            c.identity
        );
    }
}

#[test]
fn each_route_gets_anonymous_and_invalid_input_coverage_where_it_can() {
    let src = sources::load(repo()).unwrap();
    let p = plan::build(&src);
    let mut names: BTreeMap<usize, BTreeSet<&str>> = BTreeMap::new();
    for c in &p.cases {
        names.entry(c.route).or_default().insert(c.name.as_str());
    }
    let mut missing_anon = Vec::new();
    let mut missing_invalid = Vec::new();
    for (i, r) in src.routes.iter().enumerate() {
        let set = &names[&i];
        if !set.contains("anon") {
            missing_anon.push(r.key());
        }
        if r.path.contains('{')
            && !r.handle_all
            && !set.contains("invalid_path")
            && !r.path.contains("/admin/server/restart")
        {
            missing_invalid.push(r.key());
        }
    }
    assert!(missing_anon.is_empty(), "{missing_anon:?}");
    assert!(missing_invalid.is_empty(), "{missing_invalid:?}");
}

#[test]
fn checked_in_normalizers_are_valid_and_explained() {
    let dir = repo().join("rust/conformance/baseline");
    let text = std::fs::read_to_string(dir.join("normalizers.json")).unwrap();
    let rules = silo_conformance::normalize::Rules::parse(&text).unwrap();
    assert!(!rules.rules.is_empty());
    for r in &rules.rules {
        assert!(
            r.spec.why.len() > 10,
            "rule {} does not say why it exists",
            r.spec.id
        );
    }
}
