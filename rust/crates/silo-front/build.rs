//! Fails the build when the row table and the contract artifacts disagree, in either direction.

#[path = "src/reconcile.rs"]
#[allow(dead_code)]
mod reconcile;

#[allow(dead_code)]
mod rows {
    include!("src/rows_types.rs");
    include!("src/rows_table.rs");
}

use std::fs;
use std::path::PathBuf;

fn read(root: &std::path::Path, rel: &str) -> String {
    // `rel` is a constant relative path, so the two joins agree.
    #[allow(clippy::disallowed_methods)]
    let path = root.join(rel);
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/reconcile.rs");
    println!("cargo:rerun-if-changed=src/rows_types.rs");
    println!("cargo:rerun-if-changed=src/rows_table.rs");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .nth(3)
        .expect("the crate sits at rust/crates/silo-front");
    let inventory = read(root, "contracts/api/v2/route-inventory.json");
    let openapi = read(root, "contracts/api/v2/openapi.json");
    let api_manifest = read(root, "internal/api/testdata/media_routes.txt");
    let jelly_manifest = read(root, "internal/jellycompat/testdata/media_routes.txt");
    let abs_manifest = read(root, "internal/audiobooks/abs/testdata/media_routes.txt");
    let denominators = reconcile::denominators(&reconcile::Sources {
        inventory: &inventory,
        openapi: &openapi,
        api_manifest: &api_manifest,
        jelly_manifest: &jelly_manifest,
        abs_manifest: &abs_manifest,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let declared: Vec<reconcile::Key> = rows::ROWS
        .iter()
        .map(|r| {
            (
                r.surface.variant().to_string(),
                r.method.to_string(),
                r.path.to_string(),
            )
        })
        .collect();
    if let Err(msg) = reconcile::reconcile(&declared, &denominators) {
        panic!("{msg}");
    }
}
