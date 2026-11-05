//! Distributes independent units and restores their plan order.

use crate::model::{Case, Route};
use crate::runner::{Config, RunOutput, Runner, Unit};
use anyhow::{anyhow, ensure, Result};
use std::time::Instant;

fn assignments(units: &[Unit], lanes: usize) -> Vec<Vec<usize>> {
    let mut order: Vec<_> = (0..units.len()).collect();
    order.sort_by_key(|&index| (std::cmp::Reverse(units[index].weight), index));
    let mut assigned = vec![Vec::new(); lanes];
    let mut loads = vec![0; lanes];
    for index in order {
        let lane = (0..lanes).min_by_key(|&lane| (loads[lane], lane)).unwrap();
        loads[lane] += units[index].weight;
        assigned[lane].push(index);
    }
    for indices in &mut assigned {
        indices.sort_unstable();
    }
    assigned
}

/// Runs each lane concurrently, keeping the report in plan order.
pub fn run(
    configs: &[Config],
    routes: &[Route],
    cases: &[Case],
    units: &[Unit],
    run_start: i64,
    start: Instant,
) -> Result<RunOutput> {
    ensure!(!configs.is_empty(), "at least one lane is required");
    if configs.len() == 1 {
        return Runner::new(&configs[0], routes, run_start)?
            .with_start(start)
            .run_units(cases, units, true);
    }
    let assigned = assignments(units, configs.len());
    let outputs = std::thread::scope(|scope| {
        let handles: Vec<_> = configs
            .iter()
            .zip(assigned)
            .enumerate()
            .map(|(lane, (config, indices))| {
                scope.spawn(move || {
                    let selected: Vec<_> = indices
                        .into_iter()
                        .map(|index| units[index].clone())
                        .collect();
                    Runner::new(config, routes, run_start)?
                        .with_start(start)
                        .with_lane(lane)
                        .run_units(cases, &selected, lane == 0)
                })
            })
            .collect();
        handles
            .into_iter()
            .enumerate()
            .map(|(lane, handle)| {
                handle
                    .join()
                    .map_err(|_| anyhow!("lane {lane} panicked"))?
                    .map_err(|error| error.context(format!("lane {lane}")))
            })
            .collect::<Result<Vec<_>>>()
    })?;
    Ok(merge(units, outputs))
}

fn merge(units: &[Unit], outputs: Vec<RunOutput>) -> RunOutput {
    let mut merged = RunOutput::default();
    for output in &outputs {
        for (rule, hits) in &output.rule_hits {
            *merged.rule_hits.entry(rule.clone()).or_default() += hits;
        }
        merged.not_run.extend(output.not_run.clone());
        merged.elapsed_ms = merged.elapsed_ms.max(output.elapsed_ms);
    }
    for name in units
        .iter()
        .map(|unit| unit.name.as_str())
        .chain(std::iter::once("peers"))
    {
        for (lane, output) in outputs.iter().enumerate() {
            for part in output.unit_outputs.iter().filter(|part| part.name == name) {
                merged
                    .results
                    .extend_from_slice(&output.results[part.results.clone()]);
                merged
                    .events
                    .extend(
                        output.events[part.events.clone()]
                            .iter()
                            .cloned()
                            .map(|mut event| {
                                event.detail = format!("lane {lane}: {}", event.detail);
                                event
                            }),
                    );
                merged
                    .stage_effects
                    .extend_from_slice(&output.stage_effects[part.stage_effects.clone()]);
            }
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Identity, Phase};
    use crate::runner::{CaseResult, Event, UnitOutput};

    fn unit(name: &str, count: usize) -> Unit {
        Unit {
            name: name.into(),
            cases: (0..count).collect(),
            weight: count,
            compare_seed: false,
        }
    }

    #[test]
    fn largest_units_go_to_the_lightest_lane() {
        let units = [unit("a", 2), unit("b", 8), unit("c", 5), unit("d", 1)];
        assert_eq!(assignments(&units, 2), vec![vec![1], vec![0, 2, 3]]);
    }

    #[test]
    fn merge_restores_unit_order_and_appends_peers() {
        let units = [unit("a", 1), unit("b", 1), unit("c", 1)];
        let output = |names: &[&str], elapsed_ms| {
            let mut out = RunOutput {
                elapsed_ms,
                ..RunOutput::default()
            };
            out.rule_hits.insert("rule".into(), 2);
            for (index, name) in names.iter().enumerate() {
                out.results.push(CaseResult {
                    id: (*name).into(),
                    route_key: "api_v2 GET /example".into(),
                    name: (*name).into(),
                    phase: Phase::Reads,
                    identity: Identity::Anon,
                    method: "GET".into(),
                    path: "/example".into(),
                    reference_status: 200,
                    candidate_status: 200,
                    diffs: vec![],
                    proxied: false,
                    body_compared: true,
                    body_skip_reason: None,
                    feed_relaxed: false,
                    feed_reference: Default::default(),
                    exercised: true,
                    reference_error: None,
                    effect: None,
                    empty_body: false,
                });
                out.events.push(Event {
                    kind: "unit_done".into(),
                    detail: (*name).into(),
                    elapsed_ms: index as u64,
                });
                out.stage_effects.push((*name).into());
                out.not_run.insert((*name).into(), "unavailable".into());
                out.unit_outputs.push(UnitOutput {
                    name: (*name).into(),
                    results: index..index + 1,
                    events: index..index + 1,
                    stage_effects: index..index + 1,
                });
            }
            out
        };
        let merged = merge(
            &units,
            vec![output(&["b", "peers"], 50), output(&["a", "c"], 100)],
        );
        assert_eq!(
            merged
                .events
                .iter()
                .map(|event| event.detail.as_str())
                .collect::<Vec<_>>(),
            ["lane 1: a", "lane 0: b", "lane 1: c", "lane 0: peers"]
        );
        assert_eq!(
            merged
                .results
                .iter()
                .map(|result| result.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b", "c", "peers"]
        );
        assert_eq!(merged.stage_effects, ["a", "b", "c", "peers"]);
        assert_eq!(merged.rule_hits["rule"], 4);
        assert_eq!(merged.not_run.len(), 4);
        assert_eq!(merged.elapsed_ms, 100);
    }
}
