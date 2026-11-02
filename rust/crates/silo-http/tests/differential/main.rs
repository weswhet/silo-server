//! The exit gate for silo-http: real net/http and chi on one side, this crate on the other, and the
//! bytes on the wire compared.
//!
//! Two things are normalized before comparing, because Go itself does not reproduce them run to run:
//! the `Date` value and the random multipart boundary, each checked for shape first. `Allow` lines
//! from chi's default 405 are also sorted, because chi builds them by ranging over a Go map. Compressed
//! bodies are compared decoded, since the encoders are different implementations. See
//! `rust/crates/silo-http/README.md`.

// The harness uses lookalikes on data it generated itself, not on anything a Go server would compute.
#![allow(clippy::disallowed_methods)]

mod cases;
mod mirror;
mod wire;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use wire::{Case, compare_all};

fn repo_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(silo_gocompat::filepath::join(&[manifest, "../../.."]))
}

/// The toolchain Silo ships with (`Dockerfile`'s `golang:1.26` resolves to this patch today).
///
/// This used to alias `silo_gocompat::unicode::GO_VERSION` (then go1.26.7), which drifted from the
/// shipped image and hid real behavior changes between those patches: the 200-range Range-header
/// limit (`net/http/fs.go`) and the CONNECT response-writer changes (`net/http/server.go`), both
/// ported in this crate. `unicode.Version` is identical across both patches, so repinning here
/// does not need `silo-gocompat`'s tables regenerated.
const GO_TOOLCHAIN: &str = "go1.26.10";

struct GoProcess(Child);

impl Drop for GoProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_go(repo: &Path, files: &Path, scratch: &Path) -> (GoProcess, BTreeMap<String, u16>) {
    let bin = scratch.join("silohttp-ref");
    let status = Command::new("go")
        .args(["build", "-tags", "silohttp_diff", "-o"])
        .arg(&bin)
        .arg("./rust/conformance/vectors/generators/silohttp")
        .current_dir(repo)
        .env("GOTOOLCHAIN", GO_TOOLCHAIN)
        .status()
        .expect("go is required for the differential: install it or skip this test");
    assert!(status.success(), "go build of the reference server failed");
    let log = scratch.join("silohttp-ref.log");
    let mut child = Command::new(&bin)
        .arg(repo)
        .arg(files)
        .current_dir(repo)
        .env("TZ", "UTC")
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).expect("log file"))
        .spawn()
        .expect("reference server starts");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(stdout), &mut line)
        .expect("reference server prints its ports");
    let ports: BTreeMap<String, u16> = serde_json::from_str(&line).unwrap_or_else(|e| {
        panic!(
            "reference server failed ({e}): {}",
            std::fs::read_to_string(&log).unwrap_or_default()
        )
    });
    (GoProcess(child), ports)
}

#[test]
fn wire_differential() {
    let repo = repo_root();
    let scratch = std::env::temp_dir().join(format!("silo-http-diff-{}", std::process::id()));
    let files = scratch.join("files");
    std::fs::create_dir_all(&files).unwrap();
    cases::write_fixtures(&files);
    let (_go, go_ports) = start_go(&repo, &files, &scratch);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let failed = rt.block_on(async {
        let rust = mirror::start(&repo, &files).await;
        let mut failed = 0usize;
        let mut total = 0usize;
        let sections: Vec<(&str, Vec<Case>)> = vec![
            ("route-inventory", cases::route_cases(&repo)),
            ("media-routes", cases::media_route_cases(&repo)),
            ("chi-adversarial", cases::chi_cases()),
            ("servemux", cases::servemux_cases()),
            ("range-matrix", cases::range_cases()),
            ("range-limit", cases::range_limit_cases()),
            ("conditional-matrix", cases::conditional_cases()),
            ("content-config", cases::content_config_cases()),
            ("serve-file", cases::serve_file_cases()),
            ("response-writer", cases::ops_cases()),
            ("protocol", cases::protocol_cases()),
            ("compression", cases::compression_cases()),
        ];
        for (name, list) in sections {
            let n = list.len();
            let bad = compare_all(name, list, &go_ports, &rust.ports).await;
            eprintln!("{name}: {n} cases, {bad} different");
            failed += bad;
            total += n;
        }
        let (n, bad) = wire::control_checks(&go_ports, &rust).await;
        eprintln!("control: {n} checks, {bad} different");
        failed += bad;
        total += n;
        let (n, bad) = wire::scenario_checks(&go_ports, &rust).await;
        eprintln!("scenarios: {n} checks, {bad} different");
        failed += bad;
        total += n;
        eprintln!("total: {total} comparisons, {failed} different");
        failed
    });
    rt.shutdown_background();
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(failed, 0, "wire differences found, see stderr");
}
