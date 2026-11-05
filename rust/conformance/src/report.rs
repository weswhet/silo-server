//! Turns case results into per-route states and per-surface parity. Every total is
//! the size of the route universe, so an unexercised route lowers parity rather than
//! disappearing from the denominator.

use crate::diff::Diff;
use crate::model::{Route, Surface};
use crate::normalize::RuleSpec;
use crate::plan::Skip;
use crate::runner::{CaseResult, Event, RunOutput};
use crate::scope::Scope;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RouteState {
    /// Identical on every case, answered by the candidate itself, and at least one
    /// case got a success whose body was really compared.
    Matched,
    /// Identical on every case, but the handler's work was never compared: only
    /// refusals, or a success with no comparable body. Not matched.
    WeakEvidence,
    /// A case differed in a way no known flake explains.
    Differs,
    /// Every remaining difference is a recorded flake. Not matched, not a regression.
    KnownFlake,
    /// The candidate proxied at least one case to Go. Not matched whatever it returned.
    NotPorted,
    /// No case reached the route on both servers.
    NotExercised,
}

/// The furthest into the handler the route was driven, judged by the reference status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Depth {
    None,
    MethodNotAllowed,
    AuthRejected,
    NotFound,
    ServerError,
    ClientError,
    Success,
}

pub fn depth_of(status: u16) -> Depth {
    match status {
        200..=399 => Depth::Success,
        401 | 403 => Depth::AuthRejected,
        404 => Depth::NotFound,
        405 => Depth::MethodNotAllowed,
        400..=499 => Depth::ClientError,
        500..=599 => Depth::ServerError,
        _ => Depth::None,
    }
}

/// Case names that say nothing about a route's handler. A CORS preflight is answered
/// by middleware, and a slash variant checks the router's path handling.
fn probes_only_routing(case_name: &str) -> bool {
    case_name == "cors_preflight" || case_name.starts_with("slash_variant")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaseDiffs {
    pub case: String,
    pub reference_status: u16,
    pub candidate_status: u16,
    pub diffs: Vec<Diff>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteReport {
    pub key: String,
    pub surface: Surface,
    pub state: RouteState,
    pub depth: Depth,
    pub cases_run: usize,
    pub proxied_cases: usize,
    /// Proxied cases that differed beyond known flake: the proxy is not transparent.
    pub proxied_diff_cases: usize,
    pub body_never_compared: bool,
    pub flake_cases: usize,
    pub statuses: BTreeMap<String, u16>,
    /// Why an identical route still does not count as matched.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub weak_reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub differing: Vec<CaseDiffs>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not_exercised_reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SurfaceCounts {
    pub total_routes: usize,
    /// Routes where a success was compared. `parity_percent` counts only these.
    pub matched: usize,
    /// Routes with no difference and no compared success. Not evidence of a port.
    pub weak_evidence: usize,
    /// Of `weak_evidence`, routes that never got past a 401, 403, 404 or 405.
    pub weak_refusals_only: usize,
    pub differs: usize,
    pub known_flake: usize,
    pub not_ported: usize,
    pub not_ported_with_diffs: usize,
    pub not_exercised: usize,
    pub parity_percent: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct NormalizerUse {
    pub rule: RuleSpec,
    pub hits: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Regression {
    pub kind: String,
    pub target: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub scope: Scope,
    pub schema_version: u32,
    pub partial: bool,
    pub surfaces: BTreeMap<String, SurfaceCounts>,
    pub overall: SurfaceCounts,
    pub regressions: Vec<Regression>,
    /// What each stage logged differently, compared with `--effects-*`.
    pub stage_effects: Vec<String>,
    pub improvements: Vec<String>,
    pub normalizers: Vec<NormalizerUse>,
    pub routes: Vec<RouteReport>,
    pub events: Vec<Event>,
    pub skipped_inputs: Vec<Skip>,
}

/// Known flakes: case id -> the difference signatures that are allowed on it.
pub type FlakeSet = BTreeMap<String, BTreeSet<String>>;

pub fn route_reports(routes: &[Route], out: &RunOutput, flakes: &FlakeSet) -> Vec<RouteReport> {
    let mut by_route: BTreeMap<&str, Vec<&CaseResult>> = BTreeMap::new();
    for r in &out.results {
        by_route.entry(&r.route_key).or_default().push(r);
    }
    let mut reasons: BTreeMap<String, String> = BTreeMap::new();
    for (case_id, why) in &out.not_run {
        if let Some((route, _)) = case_id.split_once('#') {
            reasons
                .entry(route.to_string())
                .or_insert_with(|| why.clone());
        }
    }
    routes
        .iter()
        .map(|route| {
            let key = route.key();
            let cases = by_route.get(key.as_str()).cloned().unwrap_or_default();
            let exercised: Vec<&&CaseResult> = cases.iter().filter(|c| c.exercised).collect();
            let mut report = RouteReport {
                not_exercised_reason: None,
                key: key.clone(),
                surface: route.surface,
                state: RouteState::NotExercised,
                depth: Depth::None,
                cases_run: exercised.len(),
                proxied_cases: 0,
                proxied_diff_cases: 0,
                body_never_compared: false,
                flake_cases: 0,
                statuses: BTreeMap::new(),
                weak_reason: None,
                differing: Vec::new(),
            };
            if exercised.is_empty() {
                report.not_exercised_reason =
                    Some(reasons.get(&key).cloned().unwrap_or_else(|| {
                        if cases.is_empty() {
                            "no case planned".to_string()
                        } else {
                            "every case failed at the transport level on both servers".to_string()
                        }
                    }));
                return report;
            }
            let mut unexplained = 0;
            let mut any_body = false;
            // A success counts only if its answer was compared in full.
            let (mut compared_success, mut uncompared_success, mut feed_success) =
                (false, false, false);
            let mut no_effect_success = false;
            for c in &exercised {
                if !probes_only_routing(&c.name) {
                    let depth = depth_of(c.reference_status);
                    report.depth = report.depth.max(depth);
                    if depth == Depth::Success {
                        match (c.body_compared, c.feed_relaxed) {
                            // An empty answer says nothing: the write's effect has to be the evidence.
                            (true, false)
                                if c.empty_body
                                    && c.effect.is_some_and(|e| e.rows + e.events == 0) =>
                            {
                                no_effect_success = true
                            }
                            (true, false) => compared_success = true,
                            (true, true) => feed_success = true,
                            (false, _) => uncompared_success = true,
                        }
                    }
                }
                report.statuses.insert(c.name.clone(), c.reference_status);
                any_body |= c.body_compared;
                // A preflight or slash probe of a native row goes to Go when a sibling route also takes the path,
                // and that says nothing about who answers the row. A difference on it still counts below.
                if c.proxied && !probes_only_routing(&c.name) {
                    report.proxied_cases += 1;
                }
                if c.diffs.is_empty() {
                    continue;
                }
                let allowed = flakes.get(&c.id);
                let explained =
                    allowed.is_some_and(|set| c.diffs.iter().all(|d| set.contains(&d.signature())));
                if explained {
                    report.flake_cases += 1;
                } else {
                    unexplained += 1;
                    // Behind the relay Go's workers still race the case's clock, and the relay cannot change
                    // what Go writes. A row's effects count once it answers natively.
                    if c.proxied
                        && !c
                            .diffs
                            .iter()
                            .all(|d| d.kind == crate::diff::DiffKind::Effect)
                    {
                        report.proxied_diff_cases += 1;
                    }
                }
                report.differing.push(CaseDiffs {
                    case: c.id.clone(),
                    reference_status: c.reference_status,
                    candidate_status: c.candidate_status,
                    diffs: c.diffs.clone(),
                });
            }
            report.body_never_compared = !any_body;
            report.state = if report.proxied_cases > 0 {
                RouteState::NotPorted
            } else if unexplained > 0 {
                RouteState::Differs
            } else if report.flake_cases > 0 {
                RouteState::KnownFlake
            } else if compared_success {
                RouteState::Matched
            } else {
                report.weak_reason = Some(
                    if no_effect_success {
                        "only success was an empty body from a write that changed nothing"
                    } else if feed_success {
                        "only success was a feed, whose contents are not compared"
                    } else if uncompared_success {
                        "only success had a body that could not be compared"
                    } else {
                        match report.depth {
                            Depth::ServerError => "never got past a 5xx",
                            Depth::ClientError => "never got past a validation or state error",
                            _ => "never got past a 401, 403, 404 or 405",
                        }
                    }
                    .to_string(),
                );
                RouteState::WeakEvidence
            };
            report
        })
        .collect()
}

pub fn count(reports: &[&RouteReport]) -> SurfaceCounts {
    let mut c = SurfaceCounts {
        total_routes: reports.len(),
        ..SurfaceCounts::default()
    };
    for r in reports {
        match r.state {
            RouteState::Matched => c.matched += 1,
            RouteState::WeakEvidence => {
                c.weak_evidence += 1;
                if matches!(
                    r.depth,
                    Depth::None | Depth::MethodNotAllowed | Depth::AuthRejected | Depth::NotFound
                ) {
                    c.weak_refusals_only += 1;
                }
            }
            RouteState::Differs => c.differs += 1,
            RouteState::KnownFlake => c.known_flake += 1,
            RouteState::NotPorted => {
                c.not_ported += 1;
                if r.proxied_diff_cases > 0 {
                    c.not_ported_with_diffs += 1;
                }
            }
            RouteState::NotExercised => c.not_exercised += 1,
        }
    }
    if c.total_routes > 0 {
        c.parity_percent = (c.matched as f64 * 10000.0 / c.total_routes as f64).round() / 100.0;
    }
    c
}

pub fn surface_counts(reports: &[RouteReport]) -> BTreeMap<String, SurfaceCounts> {
    let mut grouped: BTreeMap<Surface, Vec<&RouteReport>> = BTreeMap::new();
    for r in reports {
        grouped.entry(r.surface).or_default().push(r);
    }
    grouped
        .into_iter()
        .map(|(s, rs)| (s.name().to_string(), count(&rs)))
        .collect()
}

pub fn summary_text(report: &Report) -> String {
    let mut s = format!("scope: {}\n", report.scope.name());
    s.push_str(&format!(
        "{:<15} {:>16} {:>8} {:>6} {:>8} {:>7} {:>6} {:>10} {:>13}\n",
        "surface",
        "matched/total",
        "parity",
        "weak",
        "refusals",
        "differ",
        "flake",
        "not_ported",
        "not_exercised"
    ));
    let line = |name: &str, c: &SurfaceCounts| {
        format!(
            "{:<15} {:>16} {:>7.2}% {:>6} {:>8} {:>7} {:>6} {:>10} {:>13}\n",
            name,
            format!("{}/{}", c.matched, c.total_routes),
            c.parity_percent,
            c.weak_evidence,
            c.weak_refusals_only,
            c.differs,
            c.known_flake,
            c.not_ported,
            c.not_exercised
        )
    };
    for surface in Surface::ALL {
        if let Some(c) = report.surfaces.get(surface.name()) {
            s.push_str(&line(surface.name(), c));
        }
    }
    s.push_str(&line("overall", &report.overall));
    s.push_str(
        "matched = no difference, and a success whose body was compared in full.\n\
         weak = no difference, but no such success; not counted in parity. \
         refusals = weak routes that never got past a 401, 403, 404 or 405.\n",
    );
    if report.regressions.is_empty() && report.overall.differs > 0 {
        s.push_str(&format!(
            "{} routes differ. No baseline regressions does not mean no differences.\n",
            report.overall.differs
        ));
    }
    if report.partial {
        s.push_str("PARTIAL RUN (--only): parity is meaningless and no baseline was compared.\n");
    }
    let hits: u64 = report.normalizers.iter().map(|n| n.hits).sum();
    s.push_str(&format!(
        "normalizers: {} rules, {hits} values relaxed\n",
        report.normalizers.len()
    ));
    if !report.improvements.is_empty() {
        s.push_str(&format!(
            "improvements against baseline: {}\n",
            report.improvements.len()
        ));
    }
    if report.regressions.is_empty() {
        s.push_str("regressions: 0\n");
    } else {
        s.push_str(&format!("REGRESSIONS: {}\n", report.regressions.len()));
        for r in report.regressions.iter().take(40) {
            s.push_str(&format!("  {} {}: {}\n", r.kind, r.target, r.detail));
        }
        if report.regressions.len() > 40 {
            s.push_str(&format!(
                "  ... and {} more in report.json\n",
                report.regressions.len() - 40
            ));
        }
    }
    s
}
