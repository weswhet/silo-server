//! What a write did, beyond its answer: the rows it touched and the events it published. Triggers on every
//! table record each row change in a separate schema, and a Redis subscriber records every event. After each
//! write case the two sides' effects are compared, so a matched write means the same effect, not only the
//! same status. Request log lines and the live tail are written in batches, so they are compared per stage.

use crate::diff::{Diff, DiffKind};
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

/// `baseline/effects.json`: what Go vs Go shows cannot be compared, with the evidence for each entry.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct EffectConfig {
    /// Tables written on a timer or from a batch, so a row lands in a later case. No trigger goes on them.
    #[serde(default)]
    pub ignored_tables: BTreeMap<String, String>,
    /// Event types published on a timer, not by a request.
    #[serde(default)]
    pub ignored_events: BTreeMap<String, String>,
    /// Notification channels of `events_notification`, which background workers publish on.
    #[serde(default)]
    pub ignored_event_channels: BTreeMap<String, String>,
    /// Columns and event fields whose value is a clock or a random token, by name. Their value is masked.
    #[serde(default)]
    pub volatile_fields: BTreeMap<String, String>,
    /// Request log messages that are not the same on two Go servers.
    #[serde(default)]
    pub ignored_log_messages: BTreeMap<String, String>,
}

/// One side's connections.
#[derive(Clone, Debug)]
pub struct Spec {
    pub pg: String,
    pub redis: String,
}

/// Parses `pg=URL,redis=HOST:PORT`.
pub fn parse_spec(text: &str) -> Result<Spec> {
    let (pg, redis) = text
        .split_once(",redis=")
        .context("--effects-* wants pg=URL,redis=HOST:PORT")?;
    let pg = pg
        .strip_prefix("pg=")
        .context("--effects-* wants pg=URL,redis=HOST:PORT")?;
    Ok(Spec {
        pg: pg.to_string(),
        redis: redis.to_string(),
    })
}

/// The effects of one case, canonical and sorted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    pub rows: Vec<(String, String)>,
    pub events: Vec<(String, String)>,
}

/// How much a case changed, on the reference.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectCounts {
    pub rows: usize,
    pub events: usize,
}

static MASKS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r"eyJ[\w-]+\.[\w-]+\.[\w-]+", "<jwt>"),
        (
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            "<uuid>",
        ),
        (
            r"\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d(:\d\d)?)?",
            "<ts>",
        ),
        (r"\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}", "<bcrypt>"),
        (r"\bsa_[0-9A-Za-z]{8,}", "<key>"),
        (r"enc:v1:[^\s,]+", "<enc>"),
        (r"\b[0-9a-f]{24,}\b", "<hex>"),
        // `idgen` snowflakes and ULIDs: their value depends on the clock and the machine lease.
        (r"\b1\d{17}\b", "<snowflake>"),
        (r"\b[0-9A-HJKMNP-TV-Z]{26}\b", "<ulid>"),
        // The front publishes under its own source (`hub_source`), so Go's hub does not drop its events as
        // its own. No Go server's source has this suffix, so this cannot hide anything on a Go vs Go run.
        (r"-front-\d+\b", ""),
    ]
    .into_iter()
    .map(|(p, m)| (Regex::new(p).expect("a mask compiles"), m))
    .collect()
});

fn mask(text: &str) -> String {
    let mut out = text.to_string();
    for (re, with) in MASKS.iter() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *with).into_owned();
        }
    }
    out
}

/// Sorted keys, masked strings, and a fixed value in each volatile field. A string holding JSON is walked too,
/// so a payload stored as text compares by what it says.
fn canonical(value: &Value, cfg: &EffectConfig) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if cfg.volatile_fields.contains_key(k) {
                        Value::from("<volatile>")
                    } else {
                        canonical(v, cfg)
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|v| canonical(v, cfg)).collect()),
        Value::String(text) => {
            if text.starts_with(['{', '[']) {
                if let Ok(inner) = serde_json::from_str::<Value>(text) {
                    return canonical(&inner, cfg);
                }
            }
            Value::from(mask(text))
        }
        Value::Number(n) if n.as_i64().is_some_and(|n| n >= 100_000_000_000_000_000) => {
            Value::from("<snowflake>")
        }
        other => other.clone(),
    }
}

/// Reference minus candidate and candidate minus reference, per table and operation or per event type.
pub fn compare(reference: &Effects, candidate: &Effects) -> Vec<Diff> {
    let mut out = Vec::new();
    let mut groups: BTreeMap<String, (Vec<&String>, Vec<&String>)> = BTreeMap::new();
    let minus = |a: &[(String, String)], b: &[(String, String)]| {
        let mut left: BTreeMap<&(String, String), usize> = BTreeMap::new();
        for x in b {
            *left.entry(x).or_default() += 1;
        }
        a.iter()
            .filter(|x| match left.get_mut(x) {
                Some(n) if *n > 0 => {
                    *n -= 1;
                    false
                }
                _ => true,
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    let (only_r, only_c) = (
        [
            minus(&reference.rows, &candidate.rows),
            minus(&reference.events, &candidate.events),
        ]
        .concat(),
        [
            minus(&candidate.rows, &reference.rows),
            minus(&candidate.events, &reference.events),
        ]
        .concat(),
    );
    for (group, text) in &only_r {
        groups.entry(group.clone()).or_default().0.push(text);
    }
    for (group, text) in &only_c {
        groups.entry(group.clone()).or_default().1.push(text);
    }
    let say = |list: &[&String]| match list.first() {
        Some(first) => {
            let cut: String = first.chars().take(400).collect();
            format!("{} only here: {cut}", list.len())
        }
        None => "none only here".to_string(),
    };
    for (group, (r, c)) in groups {
        out.push(Diff {
            kind: DiffKind::Effect,
            at: format!("effect.{group}"),
            reference: say(&r),
            candidate: say(&c),
        });
    }
    out
}

/// A `silo:logs` append, and everything else on Redis.
#[derive(Default)]
struct Tail {
    events: Vec<(String, String)>,
    /// `stream component message` counts of live tail rows, kept for the stage's end.
    log_rows: BTreeMap<String, u64>,
}

fn parse_published(channel: &str, payload: &str, cfg: &EffectConfig, tail: &mut Tail) {
    let doc: Value = serde_json::from_str(payload).unwrap_or(Value::from(payload));
    let kind = doc["type"].as_str().unwrap_or("untyped").to_string();
    if cfg.ignored_events.contains_key(&kind) {
        return;
    }
    if channel == "silo:logs" {
        let inner: Value = match &doc["payload"] {
            Value::String(text) => serde_json::from_str(text).unwrap_or(Value::Null),
            other => other.clone(),
        };
        let entry = &inner["entry"];
        if !entry["request_id"].as_str().unwrap_or_default().is_empty() {
            let key = format!(
                "{} {} {}",
                inner["stream"].as_str().unwrap_or_default(),
                entry["component"].as_str().unwrap_or_default(),
                entry["message"].as_str().unwrap_or_default()
            );
            *tail.log_rows.entry(key).or_default() += 1;
        }
        return;
    }
    let notification: Value = match &doc["payload"] {
        Value::String(text) => serde_json::from_str(text).unwrap_or(Value::Null),
        other => other.clone(),
    };
    if notification["channel"]
        .as_str()
        .is_some_and(|c| cfg.ignored_event_channels.contains_key(c))
    {
        return;
    }
    let text = canonical(&doc, cfg).to_string();
    tail.events.push((format!("event.{kind}"), text));
}

/// Reads what the subscription delivers until the connection ends.
fn subscribe(addr: &str, cfg: EffectConfig, tail: Arc<Mutex<Tail>>) -> Result<()> {
    let mut stream = TcpStream::connect(addr).with_context(|| format!("connecting to {addr}"))?;
    stream.write_all(b"*2\r\n$10\r\nPSUBSCRIBE\r\n$6\r\nsilo:*\r\n")?;
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        // Each message is an array of bulk strings: pmessage, pattern, channel, payload.
        let mut read_item = move || -> Option<Vec<Vec<u8>>> {
            let mut line = String::new();
            reader.read_line(&mut line).ok().filter(|n| *n > 0)?;
            let n: usize = line.trim().strip_prefix('*')?.parse().ok()?;
            let mut parts = Vec::with_capacity(n);
            for _ in 0..n {
                line.clear();
                reader.read_line(&mut line).ok().filter(|n| *n > 0)?;
                let text = line.trim();
                if let Some(len) = text.strip_prefix('$') {
                    let len: usize = len.parse().ok()?;
                    let mut buf = vec![0u8; len + 2];
                    std::io::Read::read_exact(&mut reader, &mut buf).ok()?;
                    buf.truncate(len);
                    parts.push(buf);
                } else {
                    parts.push(text.as_bytes().to_vec());
                }
            }
            Some(parts)
        };
        while let Some(parts) = read_item() {
            if parts.len() == 4 && parts[0] == b"pmessage" {
                let channel = String::from_utf8_lossy(&parts[2]).into_owned();
                let payload = String::from_utf8_lossy(&parts[3]).into_owned();
                let mut guard = tail.lock().unwrap_or_else(|e| e.into_inner());
                parse_published(&channel, &payload, &cfg, &mut guard);
            }
        }
    });
    Ok(())
}

const INSTALL: &str = "
CREATE SCHEMA IF NOT EXISTS conformance_fx;
CREATE TABLE IF NOT EXISTS conformance_fx.log (id bigserial PRIMARY KEY, tbl text NOT NULL, op text NOT NULL, row jsonb NOT NULL, old jsonb);
CREATE OR REPLACE FUNCTION conformance_fx.capture() RETURNS trigger LANGUAGE plpgsql AS $fx$
BEGIN
  IF TG_OP = 'DELETE' THEN
    INSERT INTO conformance_fx.log (tbl, op, row) VALUES (TG_ARGV[0], TG_OP, to_jsonb(OLD));
    RETURN OLD;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    INSERT INTO conformance_fx.log (tbl, op, row, old) VALUES (TG_ARGV[0], TG_OP, to_jsonb(NEW), to_jsonb(OLD));
    RETURN NEW;
  END IF;
  INSERT INTO conformance_fx.log (tbl, op, row) VALUES (TG_ARGV[0], TG_OP, to_jsonb(NEW));
  RETURN NEW;
END $fx$;
";

/// One server's effect capture.
pub struct Side {
    spec: Spec,
    cfg: EffectConfig,
    rt: tokio::runtime::Runtime,
    client: Option<tokio_postgres::Client>,
    tail: Arc<Mutex<Tail>>,
}

impl Side {
    pub fn new(spec: Spec, cfg: EffectConfig) -> Result<Self> {
        let tail = Arc::new(Mutex::new(Tail::default()));
        subscribe(&spec.redis, cfg.clone(), tail.clone())?;
        Ok(Self {
            spec,
            cfg,
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            client: None,
            tail,
        })
    }

    /// Lets go of the database, which a reset drops.
    pub fn disconnect(&mut self) {
        self.client = None;
    }

    /// Puts the triggers on the database a reset just restored.
    pub fn install(&mut self) -> Result<()> {
        let (client, connection) = self
            .rt
            .block_on(tokio_postgres::connect(
                &self.spec.pg,
                tokio_postgres::NoTls,
            ))
            .with_context(|| format!("connecting to {}", self.spec.pg))?;
        self.rt.spawn(connection);
        self.rt.block_on(async {
            client.batch_execute(INSTALL).await?;
            let rows = client
                .query(
                    "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition",
                    &[],
                )
                .await?;
            for row in rows {
                let table: String = row.get(0);
                if self.cfg.ignored_tables.contains_key(&table) {
                    continue;
                }
                client
                    .batch_execute(&format!(
                        "DROP TRIGGER IF EXISTS conformance_fx ON public.\"{table}\";
                         CREATE TRIGGER conformance_fx AFTER INSERT OR UPDATE OR DELETE ON public.\"{table}\"
                         FOR EACH ROW EXECUTE FUNCTION conformance_fx.capture('{table}')"
                    ))
                    .await?;
            }
            Ok::<_, tokio_postgres::Error>(())
        })?;
        self.client = Some(client);
        Ok(())
    }

    fn log_len(&self) -> i64 {
        let Some(client) = &self.client else { return 0 };
        self.rt
            .block_on(client.query_one("SELECT count(*) FROM conformance_fx.log", &[]))
            .map(|r| r.get(0))
            .unwrap_or(0)
    }

    /// Everything since the last call.
    pub fn take(&mut self) -> Effects {
        let mut out = Effects::default();
        if let Some(client) = &self.client {
            let rows = self.rt.block_on(client.query(
                "DELETE FROM conformance_fx.log RETURNING tbl, op, row::text, old::text",
                &[],
            ));
            for row in rows.into_iter().flatten() {
                let (table, op, text): (String, String, String) =
                    (row.get(0), row.get(1), row.get(2));
                let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                let value = canonical(&value, &self.cfg);
                // An update that moved only a clock (`last_used_at`, `last_seen_at`) changed nothing compared.
                let old: Option<String> = row.get(3);
                if old
                    .and_then(|old| serde_json::from_str::<Value>(&old).ok())
                    .is_some_and(|old| canonical(&old, &self.cfg) == value)
                {
                    continue;
                }
                out.rows.push((format!("{table}.{op}"), value.to_string()));
            }
        }
        let mut tail = self.tail.lock().unwrap_or_else(|e| e.into_inner());
        out.events = std::mem::take(&mut tail.events);
        out.rows.sort();
        out.events.sort();
        out
    }

    /// The stage's request log rows and live tail rows, by what names them, then clears the tail's count.
    pub fn stage_counts(&mut self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        if let Some(client) = &self.client {
            let rows = self.rt.block_on(client.query(
                "SELECT component, message, COALESCE(attrs->>'method', ''), COALESCE(attrs->>'path_pattern', ''),
                        COALESCE(attrs->>'status', ''), count(*)
                 FROM operational_logs WHERE COALESCE(request_id, '') <> ''
                 GROUP BY 1, 2, 3, 4, 5",
                &[],
            ));
            for row in rows.into_iter().flatten() {
                let message: String = row.get(1);
                if self.cfg.ignored_log_messages.contains_key(&message) {
                    continue;
                }
                let key = format!(
                    "row {} {} {} {} {}",
                    row.get::<_, String>(0),
                    message,
                    row.get::<_, String>(2),
                    row.get::<_, String>(3),
                    row.get::<_, String>(4),
                );
                out.insert(key, row.get::<_, i64>(5) as u64);
            }
        }
        let mut tail = self.tail.lock().unwrap_or_else(|e| e.into_inner());
        for (key, n) in std::mem::take(&mut tail.log_rows) {
            let message = key.split_whitespace().skip(2).collect::<Vec<_>>().join(" ");
            if !self.cfg.ignored_log_messages.contains_key(&message) {
                out.insert(format!("tail {key}"), n);
            }
        }
        out
    }
}

/// Both servers' effect capture.
pub struct Pair {
    pub reference: Side,
    pub candidate: Side,
}

impl Pair {
    pub fn disconnect(&mut self) {
        self.reference.disconnect();
        self.candidate.disconnect();
    }

    pub fn install(&mut self) -> Result<()> {
        self.reference.install()?;
        self.candidate.install()
    }

    pub fn clear(&mut self) {
        self.reference.take();
        self.candidate.take();
    }

    /// Waits for a write's rows to stop arriving, then compares both sides. Events reach the subscriber on
    /// their own connection, so the wait also covers them.
    pub fn collect(&mut self) -> (Vec<Diff>, EffectCounts) {
        let mut last = (-1, -1);
        for _ in 0..12 {
            std::thread::sleep(Duration::from_millis(30));
            let now = (self.reference.log_len(), self.candidate.log_len());
            if now == last {
                break;
            }
            last = now;
        }
        let (r, c) = (self.reference.take(), self.candidate.take());
        (
            compare(&r, &c),
            EffectCounts {
                rows: r.rows.len(),
                events: r.events.len(),
            },
        )
    }

    /// The differences in what a stage logged.
    pub fn stage_diffs(&mut self) -> Vec<String> {
        let (r, c) = (self.reference.stage_counts(), self.candidate.stage_counts());
        let mut keys: Vec<&String> = r.keys().chain(c.keys()).collect();
        keys.sort();
        keys.dedup();
        keys.into_iter()
            // The hub drops rows from a full queue under a burst, so two Go servers differ on the tail's count.
            .filter(|k| {
                if k.starts_with("tail ") {
                    r.contains_key(*k) != c.contains_key(*k)
                } else {
                    r.get(*k) != c.get(*k)
                }
            })
            .map(|k| {
                format!(
                    "{k}: reference {}, candidate {}",
                    r.get(k).copied().unwrap_or(0),
                    c.get(k).copied().unwrap_or(0)
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EffectConfig {
        let mut cfg = EffectConfig::default();
        cfg.volatile_fields
            .insert("updated_at".to_string(), "clock".to_string());
        cfg
    }

    fn row(table: &str, value: Value, cfg: &EffectConfig) -> (String, String) {
        (table.to_string(), canonical(&value, cfg).to_string())
    }

    #[test]
    fn the_same_write_compares_equal_whatever_the_clock_says() {
        let cfg = config();
        let a = serde_json::json!({"id": 1, "value": "720p", "updated_at": 5, "at": "2026-01-02T03:04:05Z",
            "key": "c0f00000-0000-4000-8000-000000000002", "doc": "{\"b\":1,\"a\":2}"});
        let b = serde_json::json!({"id": 1, "value": "720p", "updated_at": 9, "at": "2026-02-02 03:04:05.5+00",
            "key": "c0f00000-0000-4000-8000-000000000009", "doc": "{\"a\":2,\"b\":1}"});
        let (r, c) = (
            Effects {
                rows: vec![row("t.UPDATE", a, &cfg)],
                events: vec![],
            },
            Effects {
                rows: vec![row("t.UPDATE", b, &cfg)],
                events: vec![],
            },
        );
        assert!(compare(&r, &c).is_empty());
    }

    /// The fault M4 is for: an answer of 204 on both sides, and a different value stored.
    #[test]
    fn a_wrong_write_a_missing_row_and_a_missing_event_are_reported() {
        let cfg = config();
        let r = Effects {
            rows: vec![row("t.UPDATE", serde_json::json!({"value": "720p"}), &cfg)],
            events: vec![("event.user_settings.changed".to_string(), "{}".to_string())],
        };
        let wrong = Effects {
            rows: vec![row("t.UPDATE", serde_json::json!({"value": "4K"}), &cfg)],
            events: r.events.clone(),
        };
        let diffs = compare(&r, &wrong);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].at, "effect.t.UPDATE");
        let silent = Effects::default();
        let diffs = compare(&r, &silent);
        assert_eq!(diffs.len(), 2);
        assert!(diffs
            .iter()
            .any(|d| d.at == "effect.event.user_settings.changed"));
    }
}
