use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use silo_conformance::baseline::{self, Baseline, CandidateKind, ManualFlakes};
use silo_conformance::model::{Surface, PROXY_MARKER_HEADER};
use silo_conformance::normalize::Rules;
use silo_conformance::report::{self, NormalizerUse, Report, RouteReport};
use silo_conformance::runner::{self, Config, RunOutput, Runner};
use silo_conformance::{plan, sources};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

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
enum Cmd {
    /// Print the route universe and the request plan without sending anything.
    List {
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Replay the plan against both servers and report parity.
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
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
        Cmd::List { repo } => list(&find_repo(repo)?),
        Cmd::Run(args) => run(args),
    }
}

fn list(repo: &Path) -> Result<ExitCode> {
    let src = sources::load(repo)?;
    let p = plan::build(&src);
    let mut per_surface: BTreeMap<Surface, usize> = BTreeMap::new();
    for c in &p.cases {
        *per_surface.entry(src.routes[c.route].surface).or_default() += 1;
    }
    println!("{:<16} {:>7} {:>7}", "surface", "routes", "cases");
    for (s, total) in sources::surface_totals(&src.routes) {
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
    println!("mutating routes: {}", sources::mutating_count(&src.routes));
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
    for (surface, (a, b)) in &urls {
        if a.trim_end_matches('/') == b.trim_end_matches('/') {
            bail!(
                "{} points both sides at {a}: writes would land twice and every value would trivially match",
                surface.name()
            );
        }
    }
    Ok(urls)
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
    for b in &mut baselines {
        manual.merge_into(&mut b.known_flakes);
    }

    let peer_sources = match &args.sources {
        Some(path) => runner::parse_sources(
            &fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?,
        None => BTreeMap::new(),
    };

    let rules = if peer_sources.is_empty() {
        rules
    } else {
        rules.for_peer_lab()
    };

    let src = sources::load(&repo)?;
    let p = plan::build(&src);
    let cfg = Config {
        urls,
        fixture,
        rules,
        proxy_header: args.proxied_header.clone(),
        origin_log: args.origin_log.clone(),
        reset_reference: args.reset_reference.clone(),
        reset_candidate: args.reset_candidate.clone(),
        only,
        progress: !args.quiet,
        tag_cases: args.tag_cases,
        sources: peer_sources,
        pace: std::time::Duration::from_millis(args.pace_ms),
    };
    let mut runs: Vec<RunOutput> = Vec::new();
    for n in 0..args.runs.max(1) {
        if !args.quiet {
            eprintln!(
                "[conformance] run {} of {}: {} cases",
                n + 1,
                args.runs.max(1),
                p.cases.len()
            );
        }
        let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        runs.push(Runner::new(&cfg, &src.routes, start).run(&p.cases)?);
    }
    let last = runs.last().expect("at least one run");
    let flakes = baseline::flake_set(&baselines);
    let reports: Vec<RouteReport> = report::route_reports(&src.routes, last, &flakes);
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
    let report_doc = Report {
        schema_version: 1,
        partial,
        surfaces,
        overall,
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
