//! The catalog query engine: `query_definition.go`, `query_builder.go`, `query_executor.go`'s plan,
//! `query_cursor.go`'s seek, `query_work_groups.go`, `episode_catalog_source.go`, `air_date_sql.go`,
//! and the SQL half of `access_filter.go`.

pub mod access;
pub mod arg;
pub mod builder;
pub mod cursor;
pub mod definition;
pub mod display_filter;
pub mod episode_entries;
pub mod episode_source;
pub mod executor;
pub mod parser;
pub mod run;
pub(crate) mod templates;

pub use access::AccessFilter;
pub use arg::Arg;
pub use builder::{QueryBuilder, QuerySortPlan};
pub use cursor::{QueryCursor, QueryCursorValue};
pub use definition::{QueryDefinition, QueryGroup, QueryRule, QuerySort};
pub use executor::{PreviewPagePlan, QueryExecutor};

use std::fmt::Display;

/// The subset of Go's `fmt.Sprintf` the SQL templates use: `%s`, `%d`, `%[n]s`, `%[n]d`, and `%%`.
/// Templates are copied from Go verbatim, so the whitespace inside them stays Go's.
pub(crate) fn sprintf(template: &str, args: &[&dyn Display]) -> String {
    let mut out = String::with_capacity(template.len() + 64);
    let mut next = 0usize;
    let bytes = template.as_bytes();
    let mut i = 0;
    let mut start = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        out.push_str(&template[start..i]);
        i += 1;
        if bytes.get(i) == Some(&b'%') {
            out.push('%');
            i += 1;
            start = i;
            continue;
        }
        let mut index = None;
        if bytes.get(i) == Some(&b'[') {
            let close = template[i..].find(']').expect("sprintf index") + i;
            index = Some(
                template[i + 1..close]
                    .parse::<usize>()
                    .expect("sprintf index")
                    - 1,
            );
            i = close + 1;
        }
        // The verb: s or d.
        i += 1;
        let at = index.unwrap_or(next);
        out.push_str(&args[at].to_string());
        next = at + 1;
        start = i;
    }
    out.push_str(&template[start..]);
    out
}

/// `rebindSQLPlaceholders`: shifts every `$n` by offset.
pub fn rebind_sql_placeholders(sql: &str, offset: usize) -> String {
    if offset == 0 || silo_gocompat::strings::trim_space(sql).is_empty() {
        return sql.to_owned();
    }
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len() + 8);
    let mut i = 0;
    let mut start = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 {
                out.push_str(&sql[start..i]);
                match sql[i + 1..j].parse::<i64>() {
                    Ok(value) => out.push_str(&format!("${}", value + offset as i64)),
                    Err(_) => out.push_str(&sql[i..j]),
                }
                start = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&sql[start..]);
    out
}

pub(crate) fn lower(s: &str) -> String {
    silo_gocompat::strings::to_lower(s)
}

pub(crate) fn trim(s: &str) -> &str {
    silo_gocompat::strings::trim_space(s)
}

/// `strings.ToLower(strings.TrimSpace(s))`.
pub(crate) fn lower_trim(s: &str) -> String {
    lower(trim(s))
}

/// Go's `%q` for a string.
pub(crate) fn q(s: &str) -> String {
    silo_gocompat::strconv::quote(s)
}
