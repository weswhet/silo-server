//! Writes Rust's output for every format family, for the Go verifier to check:
//!
//!     cargo run -p silo-core --example emit_core_vectors -- <directory>
//!     rust/conformance/vectors/generators/core/run.sh verify <directory>
//!
//! Inputs start from Go's corpus and are mutated, so Go also sees inputs its own generator never chose.

#![allow(clippy::disallowed_methods)]

#[path = "../tests/support/mod.rs"]
mod support;

use serde_json::{Value, json};
use support::{Kind2, Rng, families, mutate, read_cases};

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: emit_core_vectors <directory>");
    std::fs::create_dir_all(&dir).expect("output directory");
    // SAFETY: no other thread runs yet.
    unsafe { std::env::set_var("SILO_CORE_EMIT_DIR", &dir) };
    let only = std::env::var("CORE_ONLY").ok();
    for family in families() {
        if only
            .as_deref()
            .is_some_and(|names| !names.split(',').any(|n| n == family.name))
        {
            continue;
        }
        let mut rng = Rng(0x9e3779b97f4a7c15 ^ family.name.len() as u64);
        let mut cases = Vec::new();
        for (index, (input, _)) in read_cases(family.name).iter().enumerate() {
            let changed = mutate(input, &mut rng, family.frozen);
            let compute = |input: &Value| match &family.kind {
                Kind2::Det(compute) => compute(input),
                Kind2::Nondet { produce, .. } => produce(input),
            };
            let output = std::panic::catch_unwind(|| compute(&changed));
            let output = match output {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("{} case {index}: panicked on {changed}", family.name);
                    std::process::exit(1);
                }
            };
            cases.push(json!({"in": changed, "out": output}));
        }
        let file = json!({"family": family.name, "cases": cases});
        std::fs::write(
            format!("{dir}/{}.json", family.name),
            serde_json::to_vec(&file).expect("json"),
        )
        .expect("write");
        println!("emit {:<34} {:>5} cases", family.name, cases.len());
        if matches!(family.kind, Kind2::Det(_)) {
            println!("emit-det {}", family.name);
        }
    }
}
