//! `silo`: the test-only front. It owns public listeners and forwards to a Go reference server. It must
//! not serve users until Go is gone, and it says so when it starts.

use std::path::PathBuf;
use std::process::ExitCode;

use silo_front::{FrontConfig, FrontSpec, parse_force_go, start};

const USAGE: &str = "usage: silo --front NAME=LISTEN,UPSTREAM [--front ...]

Test-only front. Answers the rows ported so far and relays everything else to a Go server.

  NAME      main, jellycompat, abs, metrics, debug, proxy_node, or transcode_node
  LISTEN    address to listen on, such as 127.0.0.1:18080
  UPSTREAM  the Go listener behind it, such as http://127.0.0.1:28080

Environment:
  DATABASE_URL           the Go server's database; read for the trust list, health identity, and branding
  SILO_TRUSTED_PROXIES   the trusted list when there is no DATABASE_URL
  SECRET_KEY             decrypts the signing secret; without it rows behind a credential stay on Go
  REDIS_URL              the Go server's Redis, for shared rate limit counters and its change events
  SILO_FRONT_SPLIT_RATE_BUDGETS  serve rows natively on Go's memory rate limit backend, with separate
                         counters; for comparing one row at a time
  SILO_FRONT_WEB_DIST    the web build output the Go server embeds; without it the SPA stays on Go
  SILO_FRONT_ORIGIN_LOG  file to append one JSON line per request to, naming who answered it
  SILO_FRONT_FORCE_GO    comma-separated surfaces to send back to Go (api_v1, api_v2, root), or all
";

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn config() -> Result<FrontConfig, String> {
    let mut fronts = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--front" => {
                let value = args.next().ok_or("--front needs a value")?;
                fronts.push(FrontSpec::parse(&value)?);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if fronts.is_empty() {
        return Err("at least one --front is required".to_owned());
    }
    Ok(FrontConfig {
        fronts,
        database_url: non_empty_env("DATABASE_URL"),
        trusted_proxies: non_empty_env("SILO_TRUSTED_PROXIES"),
        web_dist: non_empty_env("SILO_FRONT_WEB_DIST").map(PathBuf::from),
        origin_log: non_empty_env("SILO_FRONT_ORIGIN_LOG").map(PathBuf::from),
        secret_key: non_empty_env("SECRET_KEY"),
        redis_url: non_empty_env("REDIS_URL"),
        split_rate_budgets: non_empty_env("SILO_FRONT_SPLIT_RATE_BUDGETS").is_some(),
        force_go: non_empty_env("SILO_FRONT_FORCE_GO")
            .map_or_else(|| Ok(Vec::new()), |raw| parse_force_go(&raw))?,
    })
}

fn main() -> ExitCode {
    let cfg = match config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("silo: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        // Tokio's 2 MiB default overflows on a JSON value at Go's 10,000-level limit, a 60 KB body.
        .thread_stack_size(silo_gocompat::json::VALUE_STACK_BYTES)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("silo: starting the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        if let Err(e) = start(cfg).await {
            eprintln!("silo: {e}");
            return ExitCode::FAILURE;
        }
        let _ = tokio::signal::ctrl_c().await;
        ExitCode::SUCCESS
    })
}
