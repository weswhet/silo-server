//! A reverse proxy that injects one named fault into the answers of a server, plus
//! the check that the harness reported each one. See "Testing the differ" in the README.
//!
//!   conformance-mutproxy serve --listen PORT=UPSTREAM... --mutation NAME --log FILE
//!   conformance-mutproxy check --log FILE --report DIR [--json FILE]
//!
//! It speaks HTTP/1.1 directly so requests reach the upstream exactly as sent, whatever
//! the method. A body that does not finish promptly is passed through unmutated.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use silo_conformance::mutate::{self, Applied, Req, Resp, CASE_TAG_HEADER};
use silo_conformance::normalize::{FeedSummary, Rules};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "conformance-mutproxy")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Proxy each PORT to its UPSTREAM, applying the named fault.
    Serve {
        /// LISTEN_PORT=UPSTREAM_HOST:PORT. Repeatable.
        #[arg(long = "listen", required = true)]
        listen: Vec<String>,
        #[arg(long)]
        mutation: String,
        /// Applied faults, one JSON object per line.
        #[arg(long)]
        log: PathBuf,
        #[arg(long, default_value = "rust/conformance/baseline/normalizers.json")]
        normalizers: PathBuf,
        /// Picks different sites for the same fault.
        #[arg(long, default_value_t = 0)]
        salt: u64,
        /// Answer every request with this status and a fixed body, never reaching the
        /// upstream. Put on both sides, it shows what parity reads when nothing works.
        #[arg(long)]
        refuse: Option<u16>,
    },
    /// Confirm each logged fault was reported on its case.
    Check {
        #[arg(long)]
        log: PathBuf,
        /// The harness output directory holding cases.jsonl.
        #[arg(long)]
        report: PathBuf,
        /// Also write the result as JSON.
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// List the known fault names.
    List,
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
        Cmd::Serve {
            listen,
            mutation,
            log,
            normalizers,
            salt,
            refuse,
        } => serve(listen, mutation, log, normalizers, salt, refuse),
        Cmd::Check { log, report, json } => check(log, report, json),
        Cmd::List => {
            for m in mutate::SINGLE_SITE.iter().chain(mutate::RULE_PROBES) {
                println!("{m}");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

// ---- proxy ---------------------------------------------------------------------

struct Shared {
    mutation: String,
    salt: u64,
    refuse: Option<u16>,
    rules: Rules,
    log: Mutex<BufWriter<fs::File>>,
}

const MAX_BUFFERED: usize = 32 * 1024 * 1024;
/// A body still arriving after this long is a stream: forward it untouched.
const BODY_IDLE: Duration = Duration::from_millis(1500);
const HEAD_WAIT: Duration = Duration::from_secs(40);

fn serve(
    listen: Vec<String>,
    mutation: String,
    log: PathBuf,
    normalizers: PathBuf,
    salt: u64,
    refuse: Option<u16>,
) -> Result<ExitCode> {
    let known = mutate::SINGLE_SITE
        .iter()
        .chain(mutate::RULE_PROBES)
        .chain(mutate::CONTROLS)
        .any(|m| *m == mutation)
        || mutation == "all";
    if !known {
        bail!("unknown mutation {mutation}; see `list`");
    }
    let rules = Rules::parse(&fs::read_to_string(&normalizers).context("reading normalizers")?)
        .map_err(anyhow::Error::msg)?;
    if let Some(dir) = log.parent() {
        fs::create_dir_all(dir)?;
    }
    let file = fs::File::create(&log).with_context(|| format!("creating {}", log.display()))?;
    let shared = Arc::new(Shared {
        mutation,
        salt,
        refuse,
        rules,
        log: Mutex::new(BufWriter::new(file)),
    });
    let mut handles = Vec::new();
    for spec in listen {
        let (port, upstream) = spec
            .split_once('=')
            .context("--listen wants PORT=UPSTREAM_HOST:PORT")?;
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .with_context(|| format!("binding {port}"))?;
        let upstream = upstream.to_string();
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let upstream = upstream.clone();
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let _ = connection(conn, &upstream, &shared);
                });
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(ExitCode::SUCCESS)
}

fn read_head(r: &mut impl BufRead) -> std::io::Result<Option<Vec<String>>> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return if lines.is_empty() {
                Ok(None)
            } else {
                Ok(Some(lines))
            };
        }
        lines.push(trimmed.to_string());
    }
}

fn parse_headers(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn header<'a>(hs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    hs.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn read_chunked(r: &mut impl BufRead) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut size = String::new();
        r.read_line(&mut size)?;
        let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or(""), 16)
            .map_err(std::io::Error::other)?;
        if n == 0 {
            let mut end = String::new();
            r.read_line(&mut end)?;
            return Ok(out);
        }
        let start = out.len();
        out.resize(start + n, 0);
        r.read_exact(&mut out[start..])?;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf)?;
    }
}

fn connection(client: TcpStream, upstream: &str, shared: &Shared) -> std::io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(120)))?;
    let mut reader = BufReader::new(client.try_clone()?);
    let mut writer = client;
    loop {
        let Some(head) = read_head(&mut reader)? else {
            return Ok(());
        };
        let mut parts = head[0].split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        let mut headers = parse_headers(&head[1..]);
        let body = if let Some(n) = header(&headers, "content-length") {
            let n: usize = n.parse().unwrap_or(0);
            let mut b = vec![0u8; n];
            reader.read_exact(&mut b)?;
            b
        } else if header(&headers, "transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
        {
            read_chunked(&mut reader)?
        } else {
            Vec::new()
        };
        let case_id = header(&headers, CASE_TAG_HEADER).map(str::to_string);
        headers.retain(|(k, _)| {
            !k.eq_ignore_ascii_case(CASE_TAG_HEADER)
                && !k.eq_ignore_ascii_case("connection")
                && !k.eq_ignore_ascii_case("transfer-encoding")
        });
        let client_close = head[1..]
            .iter()
            .any(|l| l.to_ascii_lowercase().starts_with("connection: close"));
        if let Some(status) = shared.refuse {
            let body = "{\"error\":\"refused\"}";
            let head = format!(
                "HTTP/1.1 {status} Refused\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            writer.write_all(head.as_bytes())?;
            if method != "HEAD" {
                writer.write_all(body.as_bytes())?;
            }
            if client_close {
                return Ok(());
            }
            continue;
        }
        let keep = exchange(
            &mut writer,
            upstream,
            &method,
            &target,
            &headers,
            &body,
            case_id.as_deref(),
            shared,
        )?;
        if !keep || client_close {
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn exchange(
    client: &mut TcpStream,
    upstream: &str,
    method: &str,
    target: &str,
    seen: &[(String, String)],
    body: &[u8],
    case_id: Option<&str>,
    shared: &Shared,
) -> std::io::Result<bool> {
    let up = TcpStream::connect(upstream)?;
    up.set_read_timeout(Some(HEAD_WAIT))?;
    let mut request = format!("{method} {target} HTTP/1.1\r\n");
    for (k, v) in seen {
        if !k.eq_ignore_ascii_case("content-length") {
            request.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    if !body.is_empty() || header(seen, "content-length").is_some() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("Connection: close\r\n\r\n");
    let mut w = up.try_clone()?;
    w.write_all(request.as_bytes())?;
    w.write_all(body)?;

    let mut r = BufReader::new(up.try_clone()?);
    let Some(head) = read_head(&mut r)? else {
        return Ok(false);
    };
    let mut status_line = head[0].splitn(3, ' ');
    status_line.next();
    let status: u16 = status_line
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);
    let reason = status_line.next().unwrap_or("").to_string();
    let up_headers = parse_headers(&head[1..]);
    let bodyless =
        method == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status);
    let chunked = header(&up_headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));

    // CONNECT answers are compared byte for byte by the harness, framing included.
    if method == "CONNECT" {
        client.write_all(head_bytes(&head).as_slice())?;
        std::io::copy(&mut r, client)?;
        return Ok(false);
    }

    // Read everything if it arrives promptly. A stream goes straight through.
    let mut raw = Vec::new();
    up.set_read_timeout(Some(BODY_IDLE))?;
    let mut buf = [0u8; 65536];
    let mut finished = bodyless;
    while !finished {
        match r.read(&mut buf) {
            Ok(0) => finished = true,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_BUFFERED {
                    break;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => {
                finished = true;
            }
        }
    }
    if !finished {
        // Not comparable anyway; never mutated, so the fault log stays truthful.
        let mut text = format!("HTTP/1.1 {status} {reason}\r\n");
        for (k, v) in &up_headers {
            if !k.eq_ignore_ascii_case("connection") {
                text.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        text.push_str("Connection: close\r\n\r\n");
        client.write_all(text.as_bytes())?;
        client.write_all(&raw)?;
        up.set_read_timeout(Some(Duration::from_secs(30)))?;
        let _ = std::io::copy(&mut r, client);
        return Ok(false);
    }
    let decoded = if chunked && !bodyless {
        read_chunked(&mut std::io::Cursor::new(&raw)).unwrap_or(raw)
    } else {
        raw
    };

    let mut resp = Resp {
        status,
        headers: up_headers
            .iter()
            .filter(|(k, _)| {
                !k.eq_ignore_ascii_case("connection")
                    && !k.eq_ignore_ascii_case("transfer-encoding")
            })
            .cloned()
            .collect(),
        body: decoded,
        ..Resp::default()
    };
    let mut applied: Vec<Applied> = Vec::new();
    if let Some(id) = case_id {
        if let Some(req) = Req::parse(id, method, target, seen) {
            if header(seen, "if-none-match").is_none() {
                applied = mutate::apply(
                    &shared.mutation,
                    &req,
                    &mut resp,
                    &shared.rules,
                    shared.salt,
                );
            } else if resp.status == 304
                && (shared.mutation == "ignore_if_none_match" || shared.mutation == "all")
            {
                // A replay of a case: answer as if the tag did not match.
                resp.status = 200;
                applied.push(Applied {
                    case: id.to_string(),
                    mutation: "ignore_if_none_match".to_string(),
                    at: "revalidation status".to_string(),
                    before: "304".to_string(),
                    after: "200".to_string(),
                    rule: None,
                    by_design: false,
                    feed_fault: None,
                });
            }
        }
    }
    if !applied.is_empty() {
        let mut log = shared.log.lock().unwrap();
        for a in &applied {
            let _ = serde_json::to_writer(&mut *log, a);
            let _ = log.write_all(b"\n");
        }
        let _ = log.flush();
    }

    let body_out: Vec<u8> = match &resp.raw_json_prefix {
        Some(prefix) => {
            let mut b = prefix.clone();
            b.extend_from_slice(&resp.body[1..]);
            b
        }
        None => resp.body.clone(),
    };
    let mut text = format!("HTTP/1.1 {} {reason}\r\n", resp.status);
    for (k, v) in &resp.headers {
        if !k.eq_ignore_ascii_case("content-length") {
            text.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    let status_bodyless = resp.status == 204 || resp.status == 304;
    if method == "HEAD" {
        if let Some(n) = header(&resp.headers, "content-length") {
            text.push_str(&format!("Content-Length: {n}\r\n"));
        }
    } else if !status_bodyless {
        text.push_str(&format!("Content-Length: {}\r\n", body_out.len()));
    }
    text.push_str("\r\n");
    client.write_all(text.as_bytes())?;
    if method != "HEAD" && !status_bodyless {
        match resp.truncate_at {
            Some(at) => {
                client.write_all(&body_out[..at.min(body_out.len())])?;
                client.flush()?;
                return Ok(false);
            }
            None => client.write_all(&body_out)?,
        }
    }
    client.flush()?;
    Ok(true)
}

fn head_bytes(head: &[String]) -> Vec<u8> {
    let mut out = head.join("\r\n").into_bytes();
    out.extend_from_slice(b"\r\n\r\n");
    out
}

// ---- check ---------------------------------------------------------------------

#[derive(Default, Serialize)]
struct Tally {
    applied: usize,
    cases: usize,
    /// A difference on this case at the mutated location.
    detected_at_path: usize,
    /// A difference on this case, somewhere else. Reordering can move it.
    detected_elsewhere: usize,
    /// The rule accepted it, as the rule says it should.
    allowed_by_design: usize,
    /// A rule's by-design allowance that was reported anyway.
    by_design_reported: usize,
    /// A feed fault that left the candidate holding what the reference's feed already holds, so no
    /// differ could report it. The escapes the check rules out, listed so they stay visible.
    reference_matches_fault: usize,
    /// No difference, but the report says this body was not compared.
    body_not_compared: usize,
    escaped: usize,
    escapes: Vec<Value>,
}

#[derive(Serialize)]
struct CheckResult {
    mutations: BTreeMap<String, Tally>,
    rules: BTreeMap<String, Tally>,
    routes_differing: usize,
    regressions: usize,
    total_escaped: usize,
}

fn covers(diff_at: &str, at: &str) -> bool {
    let (d, a) = (diff_at.to_ascii_lowercase(), at.to_ascii_lowercase());
    let inside = |outer: &str, inner: &str| {
        inner.len() > outer.len()
            && inner.starts_with(outer)
            && matches!(inner.as_bytes()[outer.len()], b'.' | b'[')
    };
    d == a || inside(&a, &d) || inside(&d, &a) || (a == "body" && d == "body")
}

fn add(
    t: &mut Tally,
    a: &Applied,
    diffs: Option<&Vec<Value>>,
    body_compared: bool,
    feeds: Option<&BTreeMap<String, FeedSummary>>,
) {
    t.applied += 1;
    let list: &[Value] = diffs.map_or(&[], Vec::as_slice);
    let at_path = list
        .iter()
        .any(|d| d["at"].as_str().is_some_and(|x| covers(x, &a.at)));
    if at_path {
        if a.by_design {
            t.by_design_reported += 1;
        } else {
            t.detected_at_path += 1;
        }
    } else if !list.is_empty() {
        if a.by_design {
            t.by_design_reported += 1;
        } else {
            t.detected_elsewhere += 1;
        }
    } else if a.by_design {
        t.allowed_by_design += 1;
    } else if a.feed_fault.as_ref().is_some_and(|fault| {
        feeds
            .and_then(|f| f.get(&a.at))
            .is_some_and(|reference| !fault.observable(reference))
    }) {
        t.reference_matches_fault += 1;
    } else if !body_compared
        && (!a.at.starts_with("header:") || a.at == "header:content-length")
        && a.at != "status"
    {
        t.body_not_compared += 1;
    } else {
        t.escaped += 1;
        if t.escapes.len() < 12 {
            t.escapes.push(serde_json::json!({
                "case": a.case, "at": a.at, "before": a.before, "after": a.after,
                "rule": a.rule,
            }));
        }
    }
}

fn check(log: PathBuf, report: PathBuf, json_out: Option<PathBuf>) -> Result<ExitCode> {
    let mut by_case: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let cases = fs::read_to_string(report.join("cases.jsonl"))
        .with_context(|| format!("reading {}", report.display()))?;
    let mut known = BTreeMap::new();
    let mut feeds: BTreeMap<String, BTreeMap<String, FeedSummary>> = BTreeMap::new();
    for line in cases.lines().filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_str(line)?;
        let id = v["id"].as_str().unwrap_or_default().to_string();
        known.insert(id.clone(), v["body_compared"].as_bool().unwrap_or(false));
        if let Some(f) = v.get("feed_reference") {
            feeds.insert(id.clone(), serde_json::from_value(f.clone())?);
        }
        if let Some(d) = v["diffs"].as_array() {
            if !d.is_empty() {
                by_case.insert(id, d.clone());
            }
        }
    }
    let mut mutations: BTreeMap<String, Tally> = BTreeMap::new();
    let mut rules: BTreeMap<String, Tally> = BTreeMap::new();
    let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let text = fs::read_to_string(&log).with_context(|| format!("reading {}", log.display()))?;
    for line in text.lines().filter(|l| !l.is_empty()) {
        let a: Applied = serde_json::from_str(line)?;
        let Some(&compared) = known.get(&a.case) else {
            continue;
        };
        let diffs = by_case.get(&a.case);
        let feed = feeds.get(&a.case);
        add(
            mutations.entry(a.mutation.clone()).or_default(),
            &a,
            diffs,
            compared,
            feed,
        );
        seen.entry(a.mutation.clone())
            .or_default()
            .insert(a.case.clone());
        if let Some(rule) = &a.rule {
            add(
                rules.entry(rule.clone()).or_default(),
                &a,
                diffs,
                compared,
                feed,
            );
        }
    }
    for (m, t) in mutations.iter_mut() {
        t.cases = seen.get(m).map_or(0, BTreeSet::len);
    }
    let report_doc: Value = serde_json::from_str(
        &fs::read_to_string(report.join("report.json")).context("reading report.json")?,
    )?;
    let routes_differing = report_doc["overall"]["differs"].as_u64().unwrap_or(0) as usize;
    let regressions = report_doc["regressions"].as_array().map_or(0, Vec::len);
    let total_escaped = mutations.values().map(|t| t.escaped).sum();
    let result = CheckResult {
        mutations,
        rules,
        routes_differing,
        regressions,
        total_escaped,
    };
    println!(
        "{:<28} {:>8} {:>8} {:>9} {:>9} {:>8} {:>10} {:>12}",
        "mutation",
        "applied",
        "cases",
        "at_path",
        "elsewhere",
        "escaped",
        "by_design",
        "not_compared"
    );
    for (name, t) in &result.mutations {
        println!(
            "{:<28} {:>8} {:>8} {:>9} {:>9} {:>8} {:>10} {:>12}",
            name,
            t.applied,
            t.cases,
            t.detected_at_path,
            t.detected_elsewhere,
            t.escaped,
            t.allowed_by_design,
            t.body_not_compared
        );
    }
    if !result.rules.is_empty() {
        println!("per rule:");
        for (name, t) in &result.rules {
            println!(
                "{:<28} {:>8} {:>8} {:>9} {:>9} {:>8} {:>10} {:>12}",
                name,
                t.applied,
                "",
                t.detected_at_path,
                t.detected_elsewhere,
                t.escaped,
                t.allowed_by_design,
                t.body_not_compared
            );
        }
    }
    println!(
        "routes differing: {routes_differing}, regressions: {regressions}, escaped: {total_escaped}"
    );
    if let Some(path) = json_out {
        fs::write(path, serde_json::to_vec_pretty(&result)?)?;
    }
    Ok(if total_escaped == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}
