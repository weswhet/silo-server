//! The row table: every denominator row, declared `Native` or `GoProxy`.
//!
//! `build.rs` fails the build when this table and the contract artifacts disagree in either
//! direction. The table is written by hand on purpose, so a contract change cannot silently move a
//! row: the failure message prints the lines to add or delete.

include!("rows_types.rs");
include!("rows_table.rs");

/// The native row for a method and exact path on a surface.
pub fn native_row(surface: Surface, method: &str, path: &str) -> Option<NativeId> {
    ROWS.iter().find_map(|r| match r.disposition {
        Disposition::Native(id) if r.surface == surface && r.method == method && r.path == path => {
            Some(id)
        }
        _ => None,
    })
}
