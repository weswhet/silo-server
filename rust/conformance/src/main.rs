use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use silo_conformance::baseline::{self, Baseline, CandidateKind, ManualFlakes};
use silo_conformance::model::{Surface, PROXY_MARKER_HEADER};
use silo_conformance::normalize::Rules;
use silo_conformance::report::{self, NormalizerUse, Report, RouteReport};
use silo_conformance::runner::{self, Config, RunOutput};
use silo_conformance::scope::{self, Scope};
use silo_conformance::{http, lanes, plan, sources};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "silo-conformance",
    about = "Compares a candidate Silo server with a reference, route by route"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once at startup
enum Cmd {
    /// Print the route universe and the request plan without sending anything.
    List {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long, default_value = "full", value_parser = parse_scope)]
        scope: Scope,
    },
    /// Replay the plan against both servers and report parity.
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Surface scope to plan and score.
    #[arg(long, default_value = "full", value_parser = parse_scope)]
    scope: Scope,
    /// Base URL of the reference server's main listener.
    #[arg(long)]
    reference: String,
    /// Base URL of the candidate server's main listener.
    #[arg(long)]
    candidate: String,
    /// Another listener, as SURFACE=REFERENCE_URL,CANDIDATE_URL. Surfaces: jellycompat,
    /// abs, metrics, debug, proxy_node, transcode_node. Without one, that surface's
    /// routes are not exercised and count as not matched.
    #[arg(long = "surface", value_name = "SURFACE=REF,CAND")]
    surfaces: Vec<String>,
    /// Another independent stack pair, described by a JSON file. Repeatable.
    #[arg(long, value_name = "FILE")]
    lane: Vec<PathBuf>,
    /// Repository root (default: found by walking up from the current directory).
    #[arg(long)]
    repo: Option<PathBuf>,
    /// Credentials file (default: rust/conformance/baseline/fixture.env).
    #[arg(long)]
    fixture_env: Option<PathBuf>,
    /// Normalizer rules (default: rust/conformance/baseline/normalizers.json).
    #[arg(long)]
    normalizers: Option<PathBuf>,
    /// Shell command that resets the reference database and waits until it is ready.
    #[arg(long)]
    reset_reference: Option<String>,
    /// Shell command that resets the candidate database and waits until it is ready.
    #[arg(long)]
    reset_candidate: Option<String>,
    /// Compare what each write case did: `pg=URL,redis=HOST:PORT` for the reference.
    #[arg(long)]
    effects_reference: Option<String>,
    /// The same for the candidate.
    #[arg(long)]
    effects_candidate: Option<String>,
    /// Shell command that deletes every account on the reference, for the first-run setup cases.
    #[arg(long)]
    empty_users_reference: Option<String>,
    /// Shell command that deletes every account on the candidate.
    #[arg(long)]
    empty_users_candidate: Option<String>,
    /// Compare with a stored baseline; any regression exits 1. Repeatable.
    #[arg(long)]
    baseline: Vec<PathBuf>,
    /// Write a new baseline from this run instead of comparing.
    #[arg(long)]
    record_baseline: Option<PathBuf>,
    /// What the recorded baseline's candidate is: self (Go vs Go) or strangler.
    #[arg(long, default_value = "self")]
    candidate_kind: String,
    /// Run the whole plan this many times; used when recording a self-compare baseline.
    #[arg(long, default_value_t = 1)]
    runs: u32,
    /// Response header that marks a candidate answer as proxied to Go.
    #[arg(long, default_value = PROXY_MARKER_HEADER)]
    proxied_header: String,
    /// The candidate's origin log (`SILO_FRONT_ORIGIN_LOG`). Each case must have lines in it saying
    /// `native`, or its route counts as not ported.
    #[arg(long)]
    origin_log: Option<PathBuf>,
    /// The peer lab's clients, as `scripts/peer-lab.sh` writes them. Without it the peer cases do not
    /// run.
    #[arg(long)]
    sources: Option<PathBuf>,
    /// Send the reference `X-Forwarded-For: ADDR` on every request, as a front on loopback does for
    /// the candidate's Go server, so both Go servers see one client address without a front on the
    /// reference. It also drops the `client-address` normalizer, which only excuses two addresses.
    #[arg(long, value_name = "ADDR")]
    reference_forwarded_for: Option<String>,
    /// Milliseconds to wait before each case, to run Go vs Go at a slower candidate's pace.
    #[arg(long, default_value_t = 0)]
    pace_ms: u64,
    /// Directory for report.json and summary.txt.
    #[arg(long, default_value = "rust/conformance/.run/report")]
    out: PathBuf,
    /// Only run cases whose id matches this regex. Marks the report partial.
    #[arg(long)]
    only: Option<String>,
    #[arg(long)]
    quiet: bool,
    /// Name each case on its candidate request, for `conformance-mutproxy`.
    #[arg(long)]
    tag_cases: bool,
    /// Git revision the servers were built from, stored in a recorded baseline.
    #[arg(long, default_value = "unknown")]
    source_revision: String,
}

fn parse_scope(value: &str) -> std::result::Result<Scope, String> {
    Scope::parse(value).ok_or_else(|| "scope must be full or v2".to_string())
}

fn find_repo(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join(sources::OPENAPI).exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            bail!("no repository root above the current directory; pass --repo");
        }
    }
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> Result<ExitCode> {
    match Cli::parse().command {
        Cmd::List { repo, scope } => list(&find_repo(repo)?, scope),
        Cmd::Run(args) => run(args),
    }
}

fn list(repo: &Path, scope: Scope) -> Result<ExitCode> {
    let src = sources::load(repo)?;
    let mut p = plan::build(&src);
    p.cases = scope::select(p.cases, &src.routes, scope);
    println!("scope: {}", scope.name());
    let mut per_surface: BTreeMap<Surface, usize> = BTreeMap::new();
    for c in &p.cases {
        *per_surface.entry(src.routes[c.route].surface).or_default() += 1;
    }
    println!("{:<16} {:>7} {:>7}", "surface", "routes", "cases");
    for (s, total) in sources::surface_totals(&src.routes) {
        if !scope.includes(s) {
            continue;
        }
        println!(
            "{:<16} {:>7} {:>7}",
            s.name(),
            total,
            per_surface.get(&s).unwrap_or(&0)
        );
    }
    let mut per_phase: BTreeMap<String, usize> = BTreeMap::new();
    for c in &p.cases {
        *per_phase.entry(format!("{:?}", c.phase)).or_default() += 1;
    }
    println!("phases: {per_phase:?}");
    let routes: Vec<_> = src
        .routes
        .iter()
        .filter(|r| scope.includes(r.surface))
        .cloned()
        .collect();
    println!("mutating routes: {}", sources::mutating_count(&routes));
    println!("skipped inputs: {}", p.skipped.len());
    for s in &p.skipped {
        println!("  {}: {}", s.what, s.reason);
    }
    Ok(ExitCode::SUCCESS)
}

fn parse_surfaces(args: &RunArgs) -> Result<BTreeMap<Surface, (String, String)>> {
    let mut urls = BTreeMap::new();
    for s in [
        Surface::ApiV2,
        Surface::ApiV2Walked,
        Surface::ApiV1,
        Surface::ApiDelegate,
        Surface::Root,
    ] {
        urls.insert(s, (args.reference.clone(), args.candidate.clone()));
    }
    for spec in &args.surfaces {
        let (name, rest) = spec
            .split_once('=')
            .context("--surface wants SURFACE=REF,CAND")?;
        let (a, b) = rest
            .split_once(',')
            .context("--surface wants SURFACE=REF,CAND")?;
        let surface = Surface::parse(name).with_context(|| format!("unknown surface {name}"))?;
        urls.insert(surface, (a.to_string(), b.to_string()));
    }
    validate_surfaces(&urls)?;
    Ok(urls)
}

fn validate_surfaces(urls: &BTreeMap<Surface, (String, String)>) -> Result<()> {
    for (surface, (a, b)) in urls {
        if a.trim_end_matches('/') == b.trim_end_matches('/') {
            bail!(
                "{} points both sides at {a}: writes would land twice and every value would trivially match",
                surface.name()
            );
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct Lane {
    reference: String,
    candidate: String,
    #[serde(default)]
    surfaces: BTreeMap<String, (String, String)>,
    #[serde(default)]
    reset_reference: Option<String>,
    #[serde(default)]
    reset_candidate: Option<String>,
    #[serde(default)]
    empty_users_reference: Option<String>,
    #[serde(default)]
    empty_users_candidate: Option<String>,
    #[serde(default)]
    effects_reference: Option<String>,
    #[serde(default)]
    effects_candidate: Option<String>,
    #[serde(default)]
    origin_log: Option<String>,
}

impl Lane {
    fn config(self, base: &Config, repo: &Path) -> Result<Config> {
        let mut cfg = base.clone();
        cfg.urls.clear();
        for surface in [
            Surface::ApiV2,
            Surface::ApiV2Walked,
            Surface::ApiV1,
            Surface::ApiDelegate,
            Surface::Root,
        ] {
            cfg.urls
                .insert(surface, (self.reference.clone(), self.candidate.clone()));
        }
        for (name, urls) in self.surfaces {
            let surface =
                Surface::parse(&name).with_context(|| format!("unknown surface {name}"))?;
            cfg.urls.insert(surface, urls);
        }
        validate_surfaces(&cfg.urls)?;
        cfg.reset_reference = self.reset_reference;
        cfg.reset_candidate = self.reset_candidate;
        cfg.empty_users_reference = self.empty_users_reference;
        cfg.empty_users_candidate = self.empty_users_candidate;
        cfg.origin_log = self.origin_log.map(PathBuf::from);
        cfg.effects = match (self.effects_reference, self.effects_candidate) {
            (Some(reference), Some(candidate)) => {
                let path = repo.join("rust/conformance/baseline/effects.json");
                let config = serde_json::from_str(
                    &fs::read_to_string(&path)
                        .with_context(|| format!("reading {}", path.display()))?,
                )
                .with_context(|| format!("parsing {}", path.display()))?;
                Some((
                    silo_conformance::effects::parse_spec(&reference)?,
                    silo_conformance::effects::parse_spec(&candidate)?,
                    config,
                ))
            }
            (None, None) => None,
            _ => bail!("lane effects_reference and effects_candidate go together"),
        };
        Ok(cfg)
    }
}

fn run(args: RunArgs) -> Result<ExitCode> {
    let repo = find_repo(args.repo.clone())?;
    let urls = parse_surfaces(&args)?;
    let fixture_path = args
        .fixture_env
        .clone()
        .unwrap_or_else(|| repo.join("rust/conformance/baseline/fixture.env"));
    let fixture = runner::parse_fixture_env(
        &fs::read_to_string(&fixture_path)
            .with_context(|| format!("reading {}", fixture_path.display()))?,
    );
    let rules_path = args
        .normalizers
        .clone()
        .unwrap_or_else(|| repo.join("rust/conformance/baseline/normalizers.json"));
    let rules = Rules::parse(
        &fs::read_to_string(&rules_path)
            .with_context(|| format!("reading {}", rules_path.display()))?,
    )
    .map_err(anyhow::Error::msg)?;
    let only = args.only.as_deref().map(Regex::new).transpose()?;
    let partial = only.is_some();
    let kind = match args.candidate_kind.as_str() {
        "self" => CandidateKind::SelfCompare,
        "strangler" => CandidateKind::Strangler,
        other => bail!("--candidate-kind must be self or strangler, not {other}"),
    };
    if partial && (args.record_baseline.is_some()) {
        bail!("a partial run cannot record a baseline");
    }
    if args.record_baseline.is_some()
        && (args.reset_reference.is_none() || args.reset_candidate.is_none())
    {
        bail!("recording a baseline needs --reset-reference and --reset-candidate");
    }
    if let Some(path) = &args.record_baseline {
        // Fail before a long run rather than after it.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.is_dir() {
            bail!("--record-baseline: no directory {}", parent.display());
        }
    }
    let manual_path = repo.join("rust/conformance/baseline/known-flakes.json");
    let manual = match fs::read_to_string(&manual_path) {
        Ok(text) => ManualFlakes::parse(&text)
            .with_context(|| format!("parsing {}", manual_path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ManualFlakes::default(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", manual_path.display())),
    };
    let mut baselines = args
        .baseline
        .iter()
        .map(|p| Baseline::load(p))
        .collect::<Result<Vec<_>>>()?;
    for (path, b) in args.baseline.iter().zip(&mut baselines) {
        if b.scope != args.scope {
            bail!(
                "{} was recorded with scope {}; pass --scope {} or record it again",
                path.display(),
                b.scope.name(),
                b.scope.name()
            );
        }
        manual.merge_into(&mut b.known_flakes);
    }

    let peer_sources = match &args.sources {
        Some(path) => runner::parse_sources(
            &fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?,
        None => BTreeMap::new(),
    };

    let rules = if peer_sources.is_empty() && args.reference_forwarded_for.is_none() {
        rules
    } else {
        rules.for_peer_lab()
    };

    let effects = match (&args.effects_reference, &args.effects_candidate) {
        (Some(reference), Some(candidate)) => {
            let path = repo.join("rust/conformance/baseline/effects.json");
            let config: silo_conformance::effects::EffectConfig = serde_json::from_str(
                &fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?,
            )
            .with_context(|| format!("parsing {}", path.display()))?;
            Some((
                silo_conformance::effects::parse_spec(reference)?,
                silo_conformance::effects::parse_spec(candidate)?,
                config,
            ))
        }
        (None, None) => None,
        _ => bail!("--effects-reference and --effects-candidate go together"),
    };
    let src = sources::load(&repo)?;
    let mut p = plan::build(&src);
    p.cases = scope::select(p.cases, &src.routes, args.scope);
    let cfg = Config {
        effects,
        urls,
        fixture,
        rules,
        proxy_header: args.proxied_header.clone(),
        origin_log: args.origin_log.clone(),
        reset_reference: args.reset_reference.clone(),
        reset_candidate: args.reset_candidate.clone(),
        empty_users_reference: args.empty_users_reference.clone(),
        empty_users_candidate: args.empty_users_candidate.clone(),
        only,
        progress: !args.quiet,
        tag_cases: args.tag_cases,
        sources: peer_sources,
        pace: std::time::Duration::from_millis(args.pace_ms),
    };
    let mut configs = vec![cfg.clone()];
    for path in &args.lane {
        let lane: Lane = serde_json::from_str(
            &fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?;
        configs.push(lane.config(&cfg, &repo)?);
    }
    if args.record_baseline.is_some()
        && configs
            .iter()
            .any(|cfg| cfg.reset_reference.is_none() || cfg.reset_candidate.is_none())
    {
        bail!("recording a baseline needs both reset commands on every lane");
    }
    if let Some(addr) = &args.reference_forwarded_for {
        http::set_reference_headers(
            configs
                .iter()
                .flat_map(|cfg| cfg.urls.values().map(|(reference, _)| reference.clone()))
                .collect(),
            vec![("X-Forwarded-For".to_string(), addr.clone())],
        );
    }
    let units = runner::units(&p.cases);
    let mut runs: Vec<RunOutput> = Vec::new();
    for n in 0..args.runs.max(1) {
        let clock = Instant::now();
        let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let output = lanes::run(&configs, &src.routes, &p.cases, &units, start, clock)?;
        if !args.quiet {
            eprintln!(
                "[conformance] run {} of {}: {} cases in {:.3} s over {} lane(s)",
                n + 1,
                args.runs.max(1),
                output.results.len(),
                output.elapsed_ms as f64 / 1000.0,
                configs.len()
            );
        }
        runs.push(output);
    }
    let scoped_keys: std::collections::BTreeSet<_> = src
        .routes
        .iter()
        .filter(|r| args.scope.includes(r.surface))
        .map(|r| r.key())
        .collect();
    for output in &mut runs {
        output
            .results
            .retain(|r| scoped_keys.contains(&r.route_key));
        output.not_run.retain(|key, _| {
            key.split_once('#')
                .is_some_and(|(route, _)| scoped_keys.contains(route))
        });
    }
    // The report and cases.jsonl keep the last run; a flake seen in an earlier one needs its cases too.
    if runs.len() > 1 {
        fs::create_dir_all(&args.out)
            .with_context(|| format!("creating {}", args.out.display()))?;
        for (n, run) in runs.iter().enumerate() {
            let cases: Vec<String> = run
                .results
                .iter()
                .map(serde_json::to_string)
                .collect::<std::result::Result<_, _>>()?;
            fs::write(
                args.out.join(format!("cases-run-{}.jsonl", n + 1)),
                cases.join("\n") + "\n",
            )?;
        }
    }
    let last = runs.last().expect("at least one run");
    let flakes = baseline::flake_set(&baselines);
    let reports: Vec<RouteReport> = report::route_reports(&src.routes, last, &flakes)
        .into_iter()
        .filter(|r| args.scope.includes(r.surface))
        .collect();
    let surfaces = report::surface_counts(&reports);
    let all: Vec<&RouteReport> = reports.iter().collect();
    let overall = report::count(&all);

    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    if !partial {
        for b in &baselines {
            let cmp = baseline::compare(b, &reports);
            regressions.extend(cmp.regressions);
            improvements.extend(cmp.improvements);
        }
        regressions.sort();
        regressions.dedup();
    }
    if let Some(path) = &args.record_baseline {
        let recorded = baseline::record(
            kind,
            args.scope,
            &runs,
            &reports,
            surfaces.clone(),
            &args.source_revision,
            &manual,
        );
        recorded.save(path)?;
        eprintln!(
            "[conformance] wrote baseline: {} known flakes",
            recorded.known_flakes.len()
        );
    }
    for detail in &last.stage_effects {
        regressions.push(report::Regression {
            kind: "stage_effect_differs".to_string(),
            target: "operational_logs and the live tail".to_string(),
            detail: detail.clone(),
        });
    }
    let report_doc = Report {
        schema_version: 1,
        scope: args.scope,
        partial,
        surfaces,
        overall,
        stage_effects: last.stage_effects.clone(),
        regressions,
        improvements,
        normalizers: cfg
            .rules
            .rules
            .iter()
            .map(|r| NormalizerUse {
                rule: r.spec.clone(),
                hits: last.rule_hits.get(&r.spec.id).copied().unwrap_or(0),
            })
            .collect(),
        routes: reports,
        events: last.events.clone(),
        skipped_inputs: p.skipped.clone(),
    };
    fs::create_dir_all(&args.out).with_context(|| format!("creating {}", args.out.display()))?;
    fs::write(
        args.out.join("report.json"),
        serde_json::to_vec_pretty(&report_doc)?,
    )?;
    let cases: Vec<String> = last
        .results
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<_, _>>()?;
    fs::write(args.out.join("cases.jsonl"), cases.join("\n") + "\n")?;
    let text = report::summary_text(&report_doc);
    fs::write(args.out.join("summary.txt"), &text)?;
    print!("{text}");
    if report_doc.regressions.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_requires_both_main_urls_and_defaults_optional_fields() {
        assert!(serde_json::from_str::<Lane>(r#"{"reference":"http://reference"}"#).is_err());
        let lane: Lane = serde_json::from_str(
            r#"{"reference":"http://reference","candidate":"http://candidate"}"#,
        )
        .unwrap();
        assert!(lane.surfaces.is_empty());
        assert!(lane.reset_reference.is_none());
        assert!(lane.effects_candidate.is_none());
        assert!(lane.origin_log.is_none());
    }

    #[test]
    fn lane_surfaces_use_two_urls() {
        let lane: Lane = serde_json::from_str(r#"{"reference":"http://reference","candidate":"http://candidate","surfaces":{"jellycompat":["http://ref-jf","http://cand-jf"]}}"#).unwrap();
        assert_eq!(
            lane.surfaces["jellycompat"],
            ("http://ref-jf".into(), "http://cand-jf".into())
        );
        assert!(validate_surfaces(&BTreeMap::from([(
            Surface::ApiV2,
            ("http://same/".into(), "http://same".into())
        )]))
        .is_err());
    }
}
