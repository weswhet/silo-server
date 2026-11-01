//! The parser against goose's real one. Vectors come from
//! `rust/conformance/vectors/generators/goose`.

use serde_json::Value;
use sha2::{Digest, Sha256};
use silo_pg::goose::{Direction, parse_sql_migration};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/goose/statements.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("read vectors")).expect("valid JSON")
}

fn hash(stmts: &[String]) -> String {
    let mut h = Sha256::new();
    for s in stmts {
        h.update(s.as_bytes());
        h.update([0u8]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_migration_file_parses_like_goose() {
    let vectors = vectors();
    let files = vectors["files"].as_array().unwrap();
    assert_eq!(
        files.len(),
        629,
        "a migration was added: regenerate vectors"
    );
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../migrations/sql/");
    for file in files {
        let name = file["file"].as_str().unwrap();
        let contents = std::fs::read_to_string(format!("{dir}{name}")).unwrap();
        let (up, use_tx) = parse_sql_migration(&contents, Direction::Up).unwrap();
        let (down, _) = parse_sql_migration(&contents, Direction::Down).unwrap();
        assert_eq!(use_tx, file["use_tx"].as_bool().unwrap(), "{name} use_tx");
        assert_eq!(
            up.len() as u64,
            file["up_count"].as_u64().unwrap(),
            "{name} up count"
        );
        assert_eq!(hash(&up), file["up_sha256"].as_str().unwrap(), "{name} up");
        assert_eq!(
            down.len() as u64,
            file["down_count"].as_u64().unwrap(),
            "{name} down count"
        );
        assert_eq!(
            hash(&down),
            file["down_sha256"].as_str().unwrap(),
            "{name} down"
        );
    }
}

#[test]
fn edge_inputs_and_errors_match_goose() {
    let vectors = vectors();
    let literals = vectors["literals"].as_array().unwrap();
    assert!(literals.len() > 60);
    for case in literals {
        let name = case["name"].as_str().unwrap();
        let input = case["input"].as_str().unwrap();
        for (direction, stmts_key, err_key) in [
            (Direction::Up, "up", "up_err"),
            (Direction::Down, "down", "down_err"),
        ] {
            let got = parse_sql_migration(input, direction);
            let want_err = case[err_key].as_str().unwrap();
            match got {
                Ok((stmts, use_tx)) => {
                    assert_eq!(want_err, "", "{name} {direction}: expected an error");
                    let want: Vec<&str> = case[stmts_key]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap())
                        .collect();
                    assert_eq!(stmts, want, "{name} {direction}");
                    if direction == Direction::Up {
                        assert_eq!(use_tx, case["use_tx"].as_bool().unwrap(), "{name} use_tx");
                    }
                }
                // No migration uses ENVSUB, so substitution is refused instead of ported.
                Err(err) if err.0.contains("ENVSUB is not implemented") => {
                    assert!(input.contains("ENVSUB"), "{name}");
                }
                Err(err) => assert_eq!(err.0, want_err, "{name} {direction}"),
            }
        }
    }
}
