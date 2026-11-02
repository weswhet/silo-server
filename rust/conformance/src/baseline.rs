//! The stored expectation. A self-compare baseline (Go vs Go) records which cases are
//! genuinely unstable and what the reference answered, so a later run can tell a real
//! regression from known noise. A strangler baseline ratchets: once a route is served
//! by the candidate and matches, proxying it again or breaking it is a regression.

use crate::report::{FlakeSet, Regression, RouteReport, RouteState, SurfaceCounts};
use crate::runner::RunOutput;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// 2: a route with no compared success is `weak_evidence`, not `matched`.
pub const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// Both servers run the same Go build: any difference is flake by definition.
    SelfCompare,
    /// The candidate is the Rust server.
    Strangler,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlakeRecord {
    pub runs_with_difference: u32,
    pub runs: u32,
    pub reference_status_varied: bool,
    pub signatures: BTreeSet<String>,
    /// Set on a flake listed by hand in known-flakes.json.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

/// Flakes too rare for a recording to reliably catch, listed by hand with a reason.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualFlake {
    pub cases: Vec<String>,
    pub signatures: BTreeSet<String>,
    pub why: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualFlakes {
    pub flakes: Vec<ManualFlake>,
}

impl ManualFlakes {
    pub fn parse(text: &str) -> Result<ManualFlakes> {
        Ok(serde_json::from_str(text)?)
    }

    /// Adds these to a flake table without forgetting what a recording observed.
    pub fn merge_into(&self, flakes: &mut BTreeMap<String, FlakeRecord>) {
        for f in &self.flakes {
            for case in &f.cases {
                let rec = flakes.entry(case.clone()).or_insert_with(|| FlakeRecord {
                    runs_with_difference: 0,
                    runs: 0,
                    reference_status_varied: false,
                    signatures: BTreeSet::new(),
                    why: None,
                });
                rec.signatures.extend(f.signatures.iter().cloned());
                rec.why = Some(f.why.clone());
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineRoute {
    pub state: RouteState,
    pub depth: crate::report::Depth,
    /// Case name -> what the reference answered, to catch drift in the ground truth.
    pub statuses: BTreeMap<String, u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: u32,
    pub candidate_kind: CandidateKind,
    pub runs: u32,
    pub source_revision: String,
    pub surfaces: BTreeMap<String, SurfaceCounts>,
    pub known_flakes: BTreeMap<String, FlakeRecord>,
    pub routes: BTreeMap<String, BaselineRoute>,
}

impl Baseline {
    pub fn load(path: &Path) -> Result<Baseline> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let baseline: Baseline =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if baseline.schema_version != SCHEMA_VERSION {
            anyhow::bail!(
                "{} has schema {}, this tool needs {SCHEMA_VERSION}; record it again",
                path.display(),
                baseline.schema_version
            );
        }
        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }
}

pub fn flake_set(baselines: &[Baseline]) -> FlakeSet {
    let mut out = FlakeSet::new();
    for b in baselines {
        for (case, rec) in &b.known_flakes {
            out.entry(case.clone())
                .or_default()
                .extend(rec.signatures.iter().cloned());
        }
    }
    out
}

/// Flakes across repeated self-compare runs: any case that differed in any run, or
/// whose reference status changed between runs.
pub fn collect_flakes(runs: &[RunOutput]) -> BTreeMap<String, FlakeRecord> {
    let mut statuses: BTreeMap<&str, BTreeSet<u16>> = BTreeMap::new();
    let mut out: BTreeMap<String, FlakeRecord> = BTreeMap::new();
    let total = runs.len() as u32;
    for run in runs {
        for c in &run.results {
            statuses
                .entry(&c.id)
                .or_default()
                .insert(c.reference_status);
            if !c.diffs.is_empty() {
                let rec = out.entry(c.id.clone()).or_insert_with(|| FlakeRecord {
                    runs_with_difference: 0,
                    runs: total,
                    reference_status_varied: false,
                    signatures: BTreeSet::new(),
                    why: None,
                });
                rec.runs_with_difference += 1;
                rec.signatures.extend(c.diffs.iter().map(|d| d.signature()));
            }
        }
    }
    for (case, seen) in statuses {
        if seen.len() > 1 {
            out.entry(case.to_string())
                .or_insert_with(|| FlakeRecord {
                    runs_with_difference: 0,
                    runs: total,
                    reference_status_varied: false,
                    signatures: BTreeSet::new(),
                    why: None,
                })
                .reference_status_varied = true;
        }
    }
    out
}

pub fn record(
    kind: CandidateKind,
    runs: &[RunOutput],
    last: &[RouteReport],
    surfaces: BTreeMap<String, SurfaceCounts>,
    source_revision: &str,
    manual: &ManualFlakes,
) -> Baseline {
    let mut known_flakes = if kind == CandidateKind::SelfCompare {
        collect_flakes(runs)
    } else {
        BTreeMap::new()
    };
    manual.merge_into(&mut known_flakes);
    let flaky_routes: BTreeSet<String> = known_flakes
        .keys()
        .filter_map(|c| c.split_once('#').map(|(r, _)| r.to_string()))
        .collect();
    let varied: BTreeSet<&String> = known_flakes
        .iter()
        .filter(|(_, r)| r.reference_status_varied)
        .map(|(c, _)| c)
        .collect();
    let routes = last
        .iter()
        .map(|r| {
            // A status that varied between runs is not an expectation.
            let statuses = r
                .statuses
                .iter()
                .filter(|(name, _)| !varied.contains(&format!("{}#{name}", r.key)))
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            let state = if flaky_routes.contains(&r.key) {
                RouteState::KnownFlake
            } else {
                r.state
            };
            (
                r.key.clone(),
                BaselineRoute {
                    state,
                    depth: r.depth,
                    statuses,
                },
            )
        })
        .collect();
    Baseline {
        schema_version: SCHEMA_VERSION,
        candidate_kind: kind,
        runs: runs.len() as u32,
        source_revision: source_revision.to_string(),
        surfaces,
        known_flakes,
        routes,
    }
}

pub struct Comparison {
    pub regressions: Vec<Regression>,
    pub improvements: Vec<String>,
}

pub fn compare(baseline: &Baseline, current: &[RouteReport]) -> Comparison {
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut push = |kind: &str, target: &str, detail: String| {
        regressions.push(Regression {
            kind: kind.to_string(),
            target: target.to_string(),
            detail,
        })
    };
    let by_key: BTreeMap<&str, &RouteReport> =
        current.iter().map(|r| (r.key.as_str(), r)).collect();
    for (key, base) in &baseline.routes {
        let Some(cur) = by_key.get(key.as_str()) else {
            push(
                "route_removed",
                key,
                "in the baseline, gone from the sources".to_string(),
            );
            continue;
        };
        if cur.proxied_diff_cases > 0 {
            push(
                "proxy_not_transparent",
                key,
                format!(
                    "{} proxied case(s) differ from the reference",
                    cur.proxied_diff_cases
                ),
            );
        }
        use RouteState::*;
        match (base.state, cur.state) {
            (NotExercised, _) => {}
            (_, NotExercised) => push(
                "coverage_lost",
                key,
                cur.not_exercised_reason.clone().unwrap_or_default(),
            ),
            (Matched, WeakEvidence) => push(
                "evidence_lost",
                key,
                cur.weak_reason.clone().unwrap_or_default(),
            ),
            (Matched | WeakEvidence | KnownFlake, Differs) => {
                let first = cur
                    .differing
                    .first()
                    .and_then(|c| {
                        c.diffs
                            .first()
                            .map(|d| format!("{}: {}", c.case, d.signature()))
                    })
                    .unwrap_or_default();
                push("route_differs", key, first);
            }
            (Matched | WeakEvidence, NotPorted)
                if baseline.candidate_kind == CandidateKind::Strangler =>
            {
                push(
                    "ported_route_now_proxied",
                    key,
                    "served natively in the baseline".to_string(),
                )
            }
            (Differs | NotPorted | WeakEvidence, Matched) => improvements.push(key.clone()),
            _ => {}
        }
        if cur.state == NotExercised {
            continue;
        }
        for (name, status) in &base.statuses {
            let case_id = format!("{key}#{name}");
            if baseline.known_flakes.contains_key(&case_id) {
                continue;
            }
            match cur.statuses.get(name) {
                None => push(
                    "case_lost",
                    &case_id,
                    "in the baseline, not run now".to_string(),
                ),
                Some(s) if s != status => push(
                    "reference_drift",
                    &case_id,
                    format!("reference answered {s}, baseline recorded {status}"),
                ),
                _ => {}
            }
        }
    }
    regressions.sort();
    improvements.sort();
    Comparison {
        regressions,
        improvements,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{Diff, DiffKind};
    use crate::model::{Auth, Identity, Phase, Route, Surface};
    use crate::report::{count, route_reports};
    use crate::runner::CaseResult;

    fn route(path: &str) -> Route {
        Route {
            surface: Surface::ApiV2,
            method: "GET".into(),
            path: path.into(),
            auth: Auth::Public,
            op: None,
            streams: false,
            websocket: false,
            handle_all: false,
            request_kind: None,
            source: "test",
        }
    }

    fn case(path: &str, name: &str, status: u16, diffs: Vec<Diff>, proxied: bool) -> CaseResult {
        let key = format!("api_v2 GET {path}");
        CaseResult {
            id: format!("{key}#{name}"),
            route_key: key,
            name: name.into(),
            phase: Phase::Reads,
            identity: Identity::Anon,
            method: "GET".into(),
            path: path.into(),
            reference_status: status,
            candidate_status: status,
            diffs,
            proxied,
            body_compared: true,
            body_skip_reason: None,
            feed_relaxed: false,
            feed_reference: Default::default(),
            exercised: true,
            reference_error: None,
            effect: None,
            empty_body: false,
        }
    }

    fn value_diff(at: &str) -> Diff {
        Diff {
            kind: DiffKind::ValueMismatch,
            at: at.into(),
            reference: "1".into(),
            candidate: "2".into(),
        }
    }

    fn run(results: Vec<CaseResult>) -> RunOutput {
        RunOutput {
            results,
            ..RunOutput::default()
        }
    }

    fn state_of(routes: &[Route], out: &RunOutput, flakes: &FlakeSet, key: &str) -> RouteState {
        route_reports(routes, out, flakes)
            .into_iter()
            .find(|r| r.key == key)
            .unwrap()
            .state
    }

    #[test]
    fn a_route_nothing_reached_counts_as_not_matched() {
        let routes = vec![route("/a"), route("/never")];
        let out = run(vec![case("/a", "anon", 200, vec![], false)]);
        let reports = route_reports(&routes, &out, &FlakeSet::new());
        let refs: Vec<&RouteReport> = reports.iter().collect();
        let c = count(&refs);
        assert_eq!((c.total_routes, c.matched, c.not_exercised), (2, 1, 1));
        assert_eq!(c.parity_percent, 50.0);
    }

    #[test]
    fn parity_stays_low_when_every_route_only_refuses_identically() {
        let routes = vec![route("/a"), route("/b"), route("/c"), route("/d")];
        let out = run(vec![
            case("/a", "anon", 401, vec![], false),
            case("/b", "user", 404, vec![], false),
            case("/c", "user", 403, vec![], false),
            case("/d", "user", 200, vec![], false),
        ]);
        let reports = route_reports(&routes, &out, &FlakeSet::new());
        let refs: Vec<&RouteReport> = reports.iter().collect();
        let c = count(&refs);
        assert_eq!(
            (c.matched, c.weak_evidence, c.weak_refusals_only),
            (1, 3, 3)
        );
        assert_eq!(c.parity_percent, 25.0);
        assert_eq!(reports[0].state, RouteState::WeakEvidence);
        assert!(reports[0].weak_reason.as_deref().unwrap().contains("401"));
    }

    #[test]
    fn a_success_only_counts_if_the_handler_answered_and_its_body_was_compared() {
        let routes = vec![
            route("/preflight"),
            route("/stream"),
            route("/feed"),
            route("/ok"),
        ];
        let mut preflight_ok = case("/preflight", "cors_preflight", 200, vec![], false);
        preflight_ok.method = "OPTIONS".into();
        let mut uncompared = case("/stream", "user", 200, vec![], false);
        uncompared.body_compared = false;
        let mut feed = case("/feed", "user", 200, vec![], false);
        feed.feed_relaxed = true;
        let out = run(vec![
            preflight_ok,
            case("/preflight", "anon", 401, vec![], false),
            uncompared,
            feed,
            case("/ok", "user", 200, vec![], false),
        ]);
        let reports = route_reports(&routes, &out, &FlakeSet::new());
        let states: Vec<RouteState> = reports.iter().map(|r| r.state).collect();
        assert_eq!(
            states,
            [
                RouteState::WeakEvidence,
                RouteState::WeakEvidence,
                RouteState::WeakEvidence,
                RouteState::Matched
            ]
        );
    }

    #[test]
    fn losing_the_only_compared_success_is_a_regression() {
        let routes = vec![route("/a")];
        let good = run(vec![case("/a", "user", 200, vec![], false)]);
        let base = baseline(CandidateKind::SelfCompare, &[good], &routes);
        let mut skipped = case("/a", "user", 200, vec![], false);
        skipped.body_compared = false;
        let reports = route_reports(&routes, &run(vec![skipped]), &FlakeSet::new());
        assert_eq!(kinds(&compare(&base, &reports)), ["evidence_lost"]);
    }

    #[test]
    fn both_sides_failing_does_not_count_as_exercised() {
        let routes = vec![route("/dead")];
        let mut c = case("/dead", "anon", 0, vec![], false);
        c.exercised = false;
        let out = run(vec![c]);
        assert_eq!(
            state_of(&routes, &out, &FlakeSet::new(), "api_v2 GET /dead"),
            RouteState::NotExercised
        );
    }

    #[test]
    fn a_proxied_route_is_not_ported_even_when_identical() {
        let routes = vec![route("/p"), route("/q")];
        let out = run(vec![
            case("/p", "anon", 200, vec![], true),
            case("/q", "anon", 200, vec![], false),
            case("/q", "user", 200, vec![], true),
        ]);
        let reports = route_reports(&routes, &out, &FlakeSet::new());
        assert_eq!(reports[0].state, RouteState::NotPorted);
        // One proxied case is enough: the route is not fully served by the candidate.
        assert_eq!(reports[1].state, RouteState::NotPorted);
        let refs: Vec<&RouteReport> = reports.iter().collect();
        let c = count(&refs);
        assert_eq!((c.matched, c.not_ported), (0, 2));
    }

    #[test]
    fn a_flake_allows_only_its_recorded_differences() {
        let routes = vec![route("/f")];
        let key = "api_v2 GET /f";
        let mut flakes = FlakeSet::new();
        flakes.insert(
            format!("{key}#anon"),
            BTreeSet::from([value_diff("$.t").signature()]),
        );
        let known = run(vec![case(
            "/f",
            "anon",
            200,
            vec![value_diff("$.t")],
            false,
        )]);
        assert_eq!(
            state_of(&routes, &known, &flakes, key),
            RouteState::KnownFlake
        );
        let new_field = run(vec![case(
            "/f",
            "anon",
            200,
            vec![value_diff("$.t"), value_diff("$.new")],
            false,
        )]);
        assert_eq!(
            state_of(&routes, &new_field, &flakes, key),
            RouteState::Differs
        );
        let other_case = run(vec![case(
            "/f",
            "user",
            200,
            vec![value_diff("$.t")],
            false,
        )]);
        assert_eq!(
            state_of(&routes, &other_case, &flakes, key),
            RouteState::Differs
        );
    }

    fn baseline(kind: CandidateKind, runs: &[RunOutput], routes: &[Route]) -> Baseline {
        let reports = route_reports(routes, runs.last().unwrap(), &FlakeSet::new());
        record(
            kind,
            runs,
            &reports,
            BTreeMap::new(),
            "test",
            &ManualFlakes::default(),
        )
    }

    fn kinds(c: &Comparison) -> Vec<String> {
        c.regressions.iter().map(|r| r.kind.clone()).collect()
    }

    #[test]
    fn regression_kinds_against_a_self_compare_baseline() {
        let routes = vec![route("/a")];
        let good = run(vec![case("/a", "anon", 200, vec![], false)]);
        let base = baseline(CandidateKind::SelfCompare, &[good], &routes);
        let cmp = |out: RunOutput| {
            let reports = route_reports(&routes, &out, &flake_set(std::slice::from_ref(&base)));
            compare(&base, &reports)
        };
        assert!(cmp(run(vec![case("/a", "anon", 200, vec![], false)]))
            .regressions
            .is_empty());
        assert_eq!(
            kinds(&cmp(run(vec![case(
                "/a",
                "anon",
                200,
                vec![value_diff("$.x")],
                false
            )]))),
            ["route_differs"]
        );
        assert_eq!(kinds(&cmp(run(vec![]))), ["coverage_lost"]);
        assert_eq!(
            kinds(&cmp(run(vec![case("/a", "anon", 500, vec![], false)]))),
            ["evidence_lost", "reference_drift"]
        );
        assert_eq!(
            kinds(&cmp(run(vec![case("/a", "other", 200, vec![], false)]))),
            ["case_lost"]
        );
        // Proxying is expected while the port is in progress, so it is not a regression...
        assert!(cmp(run(vec![case("/a", "anon", 200, vec![], true)]))
            .regressions
            .is_empty());
        // ...unless the proxy changes the answer.
        assert_eq!(
            kinds(&cmp(run(vec![case(
                "/a",
                "anon",
                200,
                vec![value_diff("$.x")],
                true
            )]))),
            ["proxy_not_transparent"]
        );
    }

    #[test]
    fn a_strangler_baseline_ratchets_ported_routes() {
        let routes = vec![route("/a")];
        let good = run(vec![case("/a", "anon", 200, vec![], false)]);
        let base = baseline(CandidateKind::Strangler, &[good], &routes);
        let reports = route_reports(
            &routes,
            &run(vec![case("/a", "anon", 200, vec![], true)]),
            &FlakeSet::new(),
        );
        assert_eq!(
            kinds(&compare(&base, &reports)),
            ["ported_route_now_proxied"]
        );
    }

    #[test]
    fn repeated_runs_record_intermittent_flakes_with_their_signatures() {
        let routes = vec![route("/a"), route("/b")];
        let first = run(vec![
            case("/a", "anon", 200, vec![value_diff("$.t")], false),
            case("/b", "anon", 200, vec![], false),
        ]);
        let second = run(vec![
            case("/a", "anon", 200, vec![], false),
            case("/b", "anon", 503, vec![], false),
        ]);
        let base = baseline(CandidateKind::SelfCompare, &[first, second], &routes);
        let a = &base.known_flakes["api_v2 GET /a#anon"];
        assert_eq!((a.runs_with_difference, a.runs), (1, 2));
        assert!(base.known_flakes["api_v2 GET /b#anon"].reference_status_varied);
        assert_eq!(base.routes["api_v2 GET /a"].state, RouteState::KnownFlake);
        // A status that varied is not stored as an expectation.
        assert!(base.routes["api_v2 GET /b"].statuses.is_empty());
    }

    #[test]
    fn a_hand_listed_flake_allows_only_its_signatures_and_keeps_its_reason() {
        let manual = ManualFlakes::parse(
            r#"{"flakes":[{"cases":["api_v2 GET /a#anon"],"signatures":["ValueMismatch $.t"],"why":"race"}]}"#,
        )
        .unwrap();
        let mut table = BTreeMap::new();
        manual.merge_into(&mut table);
        assert_eq!(table["api_v2 GET /a#anon"].why.as_deref(), Some("race"));
        let routes = vec![route("/a")];
        let flakes: FlakeSet = table
            .iter()
            .map(|(k, v)| (k.clone(), v.signatures.clone()))
            .collect();
        let ok = run(vec![case(
            "/a",
            "anon",
            200,
            vec![value_diff("$.t")],
            false,
        )]);
        assert_eq!(
            state_of(&routes, &ok, &flakes, "api_v2 GET /a"),
            RouteState::KnownFlake
        );
        let other = run(vec![case(
            "/a",
            "anon",
            200,
            vec![value_diff("$.u")],
            false,
        )]);
        assert_eq!(
            state_of(&routes, &other, &flakes, "api_v2 GET /a"),
            RouteState::Differs
        );
    }
}
