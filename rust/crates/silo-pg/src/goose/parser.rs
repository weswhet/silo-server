//! Port of goose's `internal/sqlparser/parser.go`.
//!
//! The server's migrations send each parsed statement separately on the simple protocol. A file
//! can't go as one string: `NO TRANSACTION` migrations mix several statements with `CONCURRENTLY`,
//! and Postgres runs a multi-statement simple query as one implicit transaction.

use silo_gocompat::strings::{equal_fold, trim_space};

/// Which half of a migration file to read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Up,
    Down,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Direction::Up => "up",
            Direction::Down => "down",
        })
    }
}

/// A parse failure, with goose's message.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct ParseError(pub String);

/// Both directions of one file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedSql {
    pub use_tx: bool,
    pub up: Vec<String>,
    pub down: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Start = 0,
    GooseUp = 1,
    StatementBeginUp = 2,
    StatementEndUp = 3,
    GooseDown = 4,
    StatementBeginDown = 5,
    StatementEndDown = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Annotation {
    Up,
    Down,
    StatementBegin,
    StatementEnd,
    NoTransaction,
    EnvsubOn,
    EnvsubOff,
}

const SUPPORTED: &[(&str, Annotation)] = &[
    ("Up", Annotation::Up),
    ("Down", Annotation::Down),
    ("StatementBegin", Annotation::StatementBegin),
    ("StatementEnd", Annotation::StatementEnd),
    ("NO TRANSACTION", Annotation::NoTransaction),
    ("ENVSUB ON", Annotation::EnvsubOn),
    ("ENVSUB OFF", Annotation::EnvsubOff),
];

/// goose's `ParseAllFromFS` for one file. The name only appears in error messages.
pub fn parse_all(filename: &str, contents: &str) -> Result<ParsedSql, ParseError> {
    let with_name = |err: ParseError| ParseError(format!("failed to parse {filename}: {}", err.0));
    let (up, use_tx) = parse_sql_migration(contents, Direction::Up).map_err(with_name)?;
    let (down, _) = parse_sql_migration(contents, Direction::Down).map_err(with_name)?;
    Ok(ParsedSql { use_tx, up, down })
}

// bufio.Scanner with ScanLines: a final newline makes no extra line, and "\r\n" loses its "\r".
fn scan_lines(contents: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(contents);
    std::iter::from_fn(move || {
        let current = rest?;
        if current.is_empty() {
            rest = None;
            return None;
        }
        let line = match current.find('\n') {
            Some(at) => {
                rest = Some(&current[at + 1..]);
                &current[..at]
            }
            None => {
                rest = None;
                current
            }
        };
        Some(line.strip_suffix('\r').unwrap_or(line))
    })
}

/// goose's `ParseSQLMigration`: the statements for one direction, and whether the file runs in a
/// transaction.
pub fn parse_sql_migration(
    contents: &str,
    direction: Direction,
) -> Result<(Vec<String>, bool), ParseError> {
    let mut state = State::Start;
    let mut use_tx = true;
    let mut use_envsub = false;
    let mut buf = String::new();
    let mut stmts = Vec::new();

    for line in scan_lines(contents) {
        if state == State::Start && trim_space(line).is_empty() {
            continue;
        }

        if trim_space(line).starts_with("--") && line.contains("+goose") {
            let cmd = extract_annotation(line).map_err(|e| {
                ParseError(format!(
                    "failed to parse annotation line {}: {}",
                    silo_gocompat::strconv::quote(line),
                    e.0
                ))
            })?;
            match cmd {
                Annotation::Up => match state {
                    State::Start => {
                        state = State::GooseUp;
                        continue;
                    }
                    _ => {
                        return Err(ParseError(format!(
                            "duplicate '-- +goose Up' annotations; stateMachine={}, see https://github.com/pressly/goose#sql-migrations",
                            state as i32
                        )));
                    }
                },
                Annotation::Down => match state {
                    State::GooseUp | State::StatementEndUp => {
                        let remaining = trim_space(&buf);
                        if !remaining.is_empty() {
                            return Err(missing_semicolon(state, direction, remaining));
                        }
                        state = State::GooseDown;
                        continue;
                    }
                    _ => {
                        return Err(ParseError(format!(
                            "must start with '-- +goose Up' annotation, stateMachine={}, see https://github.com/pressly/goose#sql-migrations",
                            state as i32
                        )));
                    }
                },
                Annotation::StatementBegin => match state {
                    State::GooseUp | State::StatementEndUp => {
                        state = State::StatementBeginUp;
                        continue;
                    }
                    State::GooseDown | State::StatementEndDown => {
                        state = State::StatementBeginDown;
                        continue;
                    }
                    _ => {
                        return Err(ParseError(format!(
                            "'-- +goose StatementBegin' must be defined after '-- +goose Up' or '-- +goose Down' annotation, stateMachine={}, see https://github.com/pressly/goose#sql-migrations",
                            state as i32
                        )));
                    }
                },
                Annotation::StatementEnd => match state {
                    State::StatementBeginUp => state = State::StatementEndUp,
                    State::StatementBeginDown => state = State::StatementEndDown,
                    _ => {
                        return Err(ParseError(
                            "'-- +goose StatementEnd' must be defined after '-- +goose StatementBegin', see https://github.com/pressly/goose#sql-migrations".to_string(),
                        ));
                    }
                },
                Annotation::NoTransaction => {
                    use_tx = false;
                    continue;
                }
                Annotation::EnvsubOn => {
                    use_envsub = true;
                    continue;
                }
                Annotation::EnvsubOff => {
                    use_envsub = false;
                    continue;
                }
            }
        }

        if buf.is_empty() && (trim_space(line).starts_with("--") || line.is_empty()) {
            continue;
        }

        if !matches!(state, State::StatementEndDown | State::StatementEndUp) {
            if use_envsub {
                // No migration uses ENVSUB, and porting mfridman/interpolate has no caller. Failing
                // beats sending an unexpanded ${VAR} to the server.
                return Err(ParseError(format!(
                    "variable substitution failed: ENVSUB is not implemented:\n{line}"
                )));
            }
            buf.push_str(line);
            buf.push('\n');
        }

        match state {
            State::GooseUp | State::StatementBeginUp | State::StatementEndUp => {
                if direction == Direction::Down {
                    buf.clear();
                    continue;
                }
            }
            State::GooseDown | State::StatementBeginDown | State::StatementEndDown => {
                if direction == Direction::Up {
                    buf.clear();
                    continue;
                }
            }
            State::Start => {
                return Err(ParseError(format!(
                    "failed to parse migration: unexpected state {} on line {}, see https://github.com/pressly/goose#sql-migrations",
                    state as i32,
                    silo_gocompat::strconv::quote(line)
                )));
            }
        }

        match state {
            State::GooseUp | State::GooseDown => {
                if ends_with_semicolon(line) {
                    stmts.push(trim_space(&buf).to_string());
                    buf.clear();
                }
            }
            State::StatementEndUp => {
                stmts.push(trim_space(&buf).to_string());
                buf.clear();
                state = State::GooseUp;
            }
            State::StatementEndDown => {
                stmts.push(trim_space(&buf).to_string());
                buf.clear();
                state = State::GooseDown;
            }
            _ => {}
        }
    }

    match state {
        State::Start => {
            return Err(ParseError(
                "failed to parse migration: must start with '-- +goose Up' annotation, see https://github.com/pressly/goose#sql-migrations".to_string(),
            ));
        }
        State::StatementBeginUp | State::StatementBeginDown => {
            return Err(ParseError(
                "failed to parse migration: missing '-- +goose StatementEnd' annotation"
                    .to_string(),
            ));
        }
        _ => {}
    }

    let remaining = trim_space(&buf);
    if !remaining.is_empty() {
        return Err(missing_semicolon(state, direction, remaining));
    }
    Ok((stmts, use_tx))
}

fn extract_annotation(line: &str) -> Result<Annotation, ParseError> {
    if line.starts_with(' ') || line.starts_with('\t') {
        return Err(ParseError(format!(
            "{} contains leading whitespace: invalid annotation",
            silo_gocompat::strconv::quote(line)
        )));
    }
    let cmd = line.replace("--", "");
    let cmd = cmd.replacen("+goose", "", 1);
    if cmd.contains("+goose") {
        return Err(ParseError(format!(
            "{} contains multiple '+goose' annotations: invalid annotation",
            silo_gocompat::strconv::quote(&cmd)
        )));
    }
    let cmd = trim_space(&cmd);
    if cmd.is_empty() {
        return Err(ParseError("empty annotation".to_string()));
    }
    for (name, annotation) in SUPPORTED {
        if equal_fold(name, cmd) {
            return Ok(*annotation);
        }
    }
    Err(ParseError(format!(
        "{} not supported: invalid annotation",
        silo_gocompat::strconv::quote(cmd)
    )))
}

fn missing_semicolon(state: State, direction: Direction, rest: &str) -> ParseError {
    ParseError(format!(
        "failed to parse migration: state {}, direction: {direction}: unexpected unfinished SQL query: {}: missing semicolon?",
        state as i32,
        silo_gocompat::strconv::quote(rest)
    ))
}

// Whether the last word before any "--" word ends in ";". bufio.ScanWords splits on Unicode space,
// which `strings::fields` also does.
fn ends_with_semicolon(line: &str) -> bool {
    let mut prev = "";
    for word in silo_gocompat::strings::fields(line) {
        if word.starts_with("--") {
            break;
        }
        prev = word;
    }
    prev.ends_with(';')
}
