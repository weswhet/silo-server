//! The row table: every denominator row, declared `Native` or `GoProxy`.
//!
//! `build.rs` fails the build when this table and the contract artifacts disagree in either
//! direction. The table is written by hand on purpose, so a contract change cannot silently move a
//! row: the failure message prints the lines to add or delete.

include!("rows_types.rs");
include!("rows_table.rs");

/// A row a domain file serves itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeRow {
    pub surface: Surface,
    pub method: &'static str,
    pub path: &'static str,
}

impl NativeRow {
    pub const fn new(surface: Surface, method: &'static str, path: &'static str) -> Self {
        Self {
            surface,
            method,
            path,
        }
    }
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether the table lists a row. A domain file naming a row the table lacks fails the build.
pub const fn in_table(row: NativeRow) -> bool {
    let mut i = 0;
    while i < ROWS.len() {
        let r = &ROWS[i];
        if r.surface as u8 == row.surface as u8
            && str_eq(r.method, row.method)
            && str_eq(r.path, row.path)
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether a row is native: any domain's `ROWS` names it.
pub fn is_native(surface: Surface, method: &str, path: &str) -> bool {
    crate::native::DOMAINS.iter().any(|rows| {
        rows.iter()
            .any(|r| r.surface == surface && r.method == method && r.path == path)
    })
}

/// How many rows are native.
pub fn native_count() -> usize {
    crate::native::DOMAINS.iter().map(|rows| rows.len()).sum()
}
