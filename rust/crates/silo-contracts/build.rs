//! Generates the tables that embed `contracts/` and `migrations/sql/`, which stay at the repository
//! root. Go embeds the same files with `go:embed`, so a served artifact is the committed bytes.

// A build script handles this checkout's own paths, so std's Path semantics are the right ones, and it
// can't depend on silo-gocompat without building it twice.
#![allow(clippy::disallowed_methods)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .nth(3)
        .expect("repository root")
        .to_path_buf();
    let mut code = String::new();

    let mut contracts = Vec::new();
    walk(&root.join("contracts"), &mut contracts);
    code.push_str("pub static CONTRACT_FILES: &[(&str, &[u8])] = &[\n");
    for path in &contracts {
        let name = path.file_name().unwrap().to_string_lossy();
        // Go source, and the post-lock marker that Go leaves out of its embed on purpose.
        if name.ends_with(".go") || name == "LOCKED" {
            continue;
        }
        let rel = path.strip_prefix(root.join("contracts")).unwrap();
        writeln!(
            code,
            "    ({:?}, include_bytes!({:?})),",
            rel.to_string_lossy(),
            path.to_string_lossy()
        )
        .unwrap();
    }
    code.push_str("];\n");

    let mut migrations = Vec::new();
    walk(&root.join("migrations/sql"), &mut migrations);
    code.push_str("pub static MIGRATION_FILES: &[(&str, &str)] = &[\n");
    for path in &migrations {
        let name = path.file_name().unwrap().to_string_lossy();
        if !name.ends_with(".sql") {
            continue;
        }
        writeln!(
            code,
            "    ({:?}, include_str!({:?})),",
            name,
            path.to_string_lossy()
        )
        .unwrap();
    }
    code.push_str("];\n");

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("embedded.rs");
    fs::write(out, code).expect("write embedded.rs");
}
