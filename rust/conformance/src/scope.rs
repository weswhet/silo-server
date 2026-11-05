//! Selects the surfaces and dependencies a run needs.

use crate::model::{Case, Phase, Route, Surface};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Full,
    V2,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "full" => Some(Self::Full),
            "v2" => Some(Self::V2),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::V2 => "v2",
        }
    }

    pub fn includes(self, surface: Surface) -> bool {
        self == Self::Full
            || matches!(
                surface,
                Surface::ApiV2 | Surface::ApiV2Walked | Surface::Root | Surface::ApiDelegate
            )
    }
}

/// Facts named by any part of a case's request.
pub fn referenced_facts(case: &Case) -> BTreeSet<String> {
    use std::sync::LazyLock;
    static PLACEHOLDER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\$\{([a-zA-Z_][a-zA-Z_0-9]*)(:int)?\}").unwrap());
    static FLOW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"flow_[a-zA-Z_0-9]+").unwrap());
    let body = case.body.as_deref().map(String::from_utf8_lossy);
    let texts = std::iter::once(case.path.as_str())
        .chain(case.query.iter().map(|(_, value)| value.as_str()))
        .chain(case.raw_query.as_deref())
        .chain(case.headers.iter().map(|(_, value)| value.as_str()))
        .chain(body.as_deref())
        .chain(case.path_override.as_deref());
    let mut names = BTreeSet::new();
    for text in texts {
        names.extend(PLACEHOLDER.captures_iter(text).map(|c| c[1].to_string()));
        names.extend(FLOW.find_iter(text).map(|m| m.as_str().to_string()));
    }
    names
}

/// A write step of a multi-request flow. Later steps can depend on what it changed, such as a v1 settings
/// write that turns on sign-up before a v2 sign-up, so a scoped run keeps it.
fn is_flow_write(case: &Case) -> bool {
    case.name.starts_with("flow:") && case.may_mutate
}

/// Keeps the in-scope cases and what they depend on: seed cases, flow writes, and every case that captures
/// a fact a kept case uses.
pub fn select(cases: Vec<Case>, routes: &[Route], scope: Scope) -> Vec<Case> {
    if scope == Scope::Full {
        return cases;
    }
    let references: Vec<_> = cases.iter().map(referenced_facts).collect();
    let mut kept: Vec<_> = cases
        .iter()
        .map(|case| {
            scope.includes(routes[case.route].surface)
                || case.phase == Phase::Seed
                || is_flow_write(case)
        })
        .collect();
    loop {
        let needed: BTreeSet<_> = references
            .iter()
            .zip(&kept)
            .filter(|(_, keep)| **keep)
            .flat_map(|(names, _)| names.iter())
            .collect();
        let mut changed = false;
        for (case, keep) in cases.iter().zip(&mut kept) {
            if !*keep
                && case.phase != Phase::Peers
                && case
                    .capture_facts
                    .iter()
                    .any(|(name, _)| needed.contains(name))
            {
                *keep = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    cases
        .into_iter()
        .zip(kept)
        .filter_map(|(case, keep)| keep.then_some(case))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Auth, Identity};

    fn route(surface: Surface) -> Route {
        Route {
            surface,
            method: "GET".into(),
            path: "/items".into(),
            auth: Auth::Public,
            op: None,
            streams: false,
            websocket: false,
            handle_all: false,
            request_kind: None,
            source: "test",
        }
    }

    fn case(name: &str, route: usize, phase: Phase) -> Case {
        Case {
            id: name.into(),
            route,
            name: name.into(),
            phase,
            identity: Identity::Anon,
            method: "GET".into(),
            path: "/items".into(),
            query: vec![],
            raw_query: None,
            headers: vec![],
            body: None,
            content_type: None,
            path_override: None,
            capture_as: None,
            may_mutate: false,
            skip_body: None,
            timeout_secs: 1,
            sort_key: name.into(),
            source: None,
            host: None,
            settle_on: None,
            wait_ms: 0,
            capture_facts: vec![],
            needs_empty_users: false,
        }
    }

    fn names(cases: Vec<Case>) -> Vec<String> {
        cases.into_iter().map(|case| case.name).collect()
    }

    #[test]
    fn v2_keeps_seeds_and_drops_unneeded_v1_and_peers() {
        let routes = [route(Surface::ApiV1), route(Surface::ApiV2)];
        let mut peer = case("peer", 0, Phase::Peers);
        peer.capture_facts.push(("peer_fact".into(), "/id".into()));
        let mut native = case("native", 1, Phase::Reads);
        native.path = "/items/${peer_fact}".into();
        let mut flow_write = case("flow:v1:enable", 0, Phase::MutateScenarios);
        flow_write.may_mutate = true;
        let cases = vec![
            case("legacy", 0, Phase::Reads),
            case("seed", 0, Phase::Seed),
            peer,
            case("flow:v1:read", 0, Phase::MutateScenarios),
            flow_write,
            native,
        ];
        assert_eq!(
            names(select(cases, &routes, Scope::V2)),
            ["seed", "flow:v1:enable", "native"]
        );
    }

    #[test]
    fn v2_keeps_transitive_fact_producers_in_original_order() {
        let routes = [route(Surface::ApiV1), route(Surface::ApiV2)];
        let mut first = case("first", 0, Phase::Reads);
        first.capture_facts.push(("first_id".into(), "/id".into()));
        let mut second = case("second", 0, Phase::Reads);
        second
            .capture_facts
            .push(("second_id".into(), "/id".into()));
        second.path = "/items/${first_id}".into();
        let mut native = case("native", 1, Phase::Reads);
        native.path = "/items/${second_id:int}".into();
        assert_eq!(
            names(select(vec![first, second, native], &routes, Scope::V2)),
            ["first", "second", "native"]
        );
    }

    #[test]
    fn references_include_every_request_field_and_literal_flow_facts() {
        let routes = [route(Surface::ApiV1), route(Surface::ApiV2)];
        for field in [
            "path",
            "query",
            "raw_query",
            "header",
            "body",
            "override",
            "flow",
        ] {
            let fact = if field == "flow" {
                "flow_token"
            } else {
                "item_id"
            };
            let mut producer = case("producer", 0, Phase::Reads);
            producer.capture_facts.push((fact.into(), "/id".into()));
            let mut native = case("native", 1, Phase::Reads);
            match field {
                "path" => native.path = "/${item_id}".into(),
                "query" => native.query.push(("id".into(), "${item_id}".into())),
                "raw_query" => native.raw_query = Some("id=${item_id}".into()),
                "header" => native.headers.push(("X-Id".into(), "${item_id}".into())),
                "body" => native.body = Some(b"\xff${item_id:int}".to_vec()),
                "override" => native.path_override = Some("${item_id}".into()),
                "flow" => native
                    .headers
                    .push(("Authorization".into(), "flow_token".into())),
                _ => unreachable!(),
            }
            assert_eq!(
                names(select(vec![producer, native], &routes, Scope::V2)),
                ["producer", "native"],
                "{field}"
            );
        }
    }

    #[test]
    fn full_leaves_cases_unchanged() {
        let routes = [route(Surface::ApiV1), route(Surface::ApiV2)];
        let cases = vec![
            case("legacy", 0, Phase::Reads),
            case("peer", 0, Phase::Peers),
            case("native", 1, Phase::Reads),
        ];
        assert_eq!(
            names(select(cases, &routes, Scope::Full)),
            ["legacy", "peer", "native"]
        );
    }
}
