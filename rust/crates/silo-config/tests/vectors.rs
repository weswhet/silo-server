//! Differential tests against output of the real Go packages. The vectors come from
//! `rust/conformance/vectors/generators/config`, whose main.go has the command to regenerate them.

// Test paths and fixture re-encoding are plain Rust; nothing here is compared to Go through them.
#![allow(clippy::disallowed_methods)]

use serde_json::Value;
use silo_config::config::*;
use silo_config::cron::{self, Location, Parser, Schedule, ZonedTime};
use silo_config::env::{flags, misc, postgres_tune, stream_telemetry, telemetry, tuning};
use silo_config::{gonet, goparse, lang};
use silo_gocompat::json::marshal_to_string;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

fn vector(name: &str) -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../conformance/vectors/config");
    path.push(name);
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("parsing {name}: {e}"))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn string_map(v: &Value) -> SettingsMap {
    v.as_object()
        .map(|m| {
            m.iter()
                .map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn from_hex(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn outcome<T: serde::Serialize>(r: Result<T, String>) -> String {
    match r {
        Ok(v) => marshal_to_string(&v).unwrap(),
        Err(e) => format!("error: {e}"),
    }
}

#[derive(Default)]
struct Failures(Vec<String>);

impl Failures {
    fn eq<T: std::fmt::Debug + PartialEq>(
        &mut self,
        what: impl std::fmt::Display,
        got: T,
        want: T,
    ) {
        if got != want {
            self.0
                .push(format!("{what}\n   got: {got:?}\n  want: {want:?}"));
        }
    }

    fn done(self, name: &str) {
        if !self.0.is_empty() {
            let shown: Vec<&String> = self.0.iter().take(40).collect();
            panic!(
                "{name}: {} mismatches\n{}",
                self.0.len(),
                shown
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
}

#[test]
fn env_permutations_resolve_like_go() {
    let cases = vector("env_permutations.json");
    let cases = cases.as_array().unwrap();
    assert!(
        cases.len() >= 30,
        "the exit gate needs at least 30 permutations, have {}",
        cases.len()
    );
    let mut f = Failures::default();
    for case in cases {
        let name = s(case, "name");
        let mut e = Env::from_pairs(string_map(&case["env"]));
        let mut file = s(case, "env_file").to_owned();
        if let Some(dotenv) = case.get("dotenv").and_then(Value::as_str) {
            let dir = std::env::temp_dir().join(format!(
                "silo-config-{}-{}",
                std::process::id(),
                name.replace(' ', "_")
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("test.env");
            std::fs::write(&path, dotenv).unwrap();
            file = path.to_string_lossy().into_owned();
        }
        let r = &case["resolved"];
        let mut e2 = e.clone();
        let bootstrap = load_bootstrap(&mut e, &file);
        f.eq(
            format!("{name}: bootstrap"),
            outcome(bootstrap.clone()),
            s(r, "bootstrap").to_owned(),
        );
        if let Ok(bc) = &bootstrap {
            let stored: SettingsMap = [
                ("redis.url".to_owned(), "redis://stored:1/2".to_owned()),
                ("redis.db".to_owned(), "9".to_owned()),
            ]
            .into_iter()
            .collect();
            let mut cfg = load_from_db(&stored).unwrap();
            apply_bootstrap_overrides(&mut cfg, bc);
            f.eq(
                format!("{name}: overrides"),
                marshal_to_string(&cfg).unwrap(),
                s(r, "bootstrap_overrides").to_owned(),
            );
            let stored: SettingsMap = [(
                "audiobookshelf_compat.enabled".to_owned(),
                "false".to_owned(),
            )]
            .into_iter()
            .collect();
            let mut off = load_from_db(&stored).unwrap();
            apply_bootstrap_overrides(&mut off, bc);
            f.eq(
                format!("{name}: abs disabled"),
                off.audiobookshelf_compat.listen,
                s(r, "bootstrap_abs_disabled").to_owned(),
            );
            let (mut configured, mut values) = (HashMap::new(), HashMap::new());
            add_redis_bootstrap_settings(&bc.redis_url, &mut configured, &mut values);
            let c: BTreeMap<_, _> = configured.into_iter().collect();
            let v: BTreeMap<_, _> = values.into_iter().collect();
            f.eq(
                format!("{name}: redis bootstrap settings"),
                format!(
                    "[{},{}]",
                    marshal_to_string(&c).unwrap(),
                    marshal_to_string(&v).unwrap()
                ),
                s(r, "redis_bootstrap_settings").to_owned(),
            );
        }
        f.eq(
            format!("{name}: database_url"),
            outcome(load_database_url(&mut e2, &file)),
            s(r, "database_url").to_owned(),
        );
        let (cfg, adj) = tuning::parse(&e);
        f.eq(
            format!("{name}: tuning"),
            format!(
                "[{},{}]",
                marshal_to_string(&cfg).unwrap(),
                marshal_to_string(&adj).unwrap()
            ),
            s(r, "tuning").to_owned(),
        );
        f.eq(
            format!("{name}: debug_server"),
            outcome(misc::debug_server_config(&e)),
            s(r, "debug_server").to_owned(),
        );
        f.eq(
            format!("{name}: telemetry"),
            marshal_to_string(&telemetry::load_config(&e, "node-1")).unwrap(),
            s(r, "telemetry").to_owned(),
        );
        f.eq(
            format!("{name}: stream_telemetry"),
            marshal_to_string(&stream_telemetry::config_from_env(&e, "node-1")).unwrap(),
            s(r, "stream_telemetry").to_owned(),
        );
        f.eq(
            format!("{name}: postgres_tune"),
            outcome(postgres_tune::load_options(&e, 20)),
            s(r, "postgres_tune").to_owned(),
        );
        f.eq(
            format!("{name}: search_env"),
            outcome(misc::search_settings_from_env(&e)),
            s(r, "search_env").to_owned(),
        );
        f.eq(
            format!("{name}: migration_timeout"),
            misc::migration_timeout(&e).0.to_string(),
            s(r, "migration_timeout").to_owned(),
        );
        let tp = match misc::trusted_proxies_from_env(&e) {
            Ok(None) => String::new(),
            Ok(Some(v)) => v,
            Err(err) => format!(
                "error: {}",
                err.trim_start_matches("invalid SILO_TRUSTED_PROXIES: ")
            ),
        };
        f.eq(
            format!("{name}: trusted_proxies"),
            tp,
            s(r, "trusted_proxies").to_owned(),
        );
        f.eq(
            format!("{name}: node_drain"),
            misc::node_drain_timeout(e.get("SILO_NODE_DRAIN_TIMEOUT"))
                .0
                .to_string(),
            s(r, "node_drain").to_owned(),
        );
        f.eq(
            format!("{name}: shutdown_delay"),
            misc::api_shutdown_delay(e.get("SILO_SHUTDOWN_DELAY"))
                .0
                .to_string(),
            s(r, "shutdown_delay").to_owned(),
        );
        if let Some(id) = r.get("node_identity").and_then(Value::as_str) {
            f.eq(
                format!("{name}: node_identity"),
                misc::resolve_node_identity(&e, "host"),
                id.to_owned(),
            );
        }
        f.eq(
            format!("{name}: metrics_listen"),
            misc::metrics_listen(&e),
            s(r, "metrics_listen").to_owned(),
        );
        f.eq(
            format!("{name}: plugin_cache_dir"),
            misc::plugin_cache_dir_override(&e),
            s(r, "plugin_cache_dir").to_owned(),
        );
        f.eq(
            format!("{name}: stall_window"),
            misc::stream_stall_window(&e).0.to_string(),
            s(r, "stall_window").to_owned(),
        );
        f.eq(
            format!("{name}: ebook_rate_limit"),
            misc::ebook_rate_limit_cooldown(&e).0.to_string(),
            s(r, "ebook_rate_limit").to_owned(),
        );
        f.eq(
            format!("{name}: ebook_workers"),
            misc::ebook_enrich_workers(&e).to_string(),
            s(r, "ebook_workers").to_owned(),
        );
        let batch = misc::audiobook_enrich_batch_size(&e);
        f.eq(
            format!("{name}: audiobook_batch"),
            batch.to_string(),
            s(r, "audiobook_batch").to_owned(),
        );
        f.eq(
            format!("{name}: audiobook_workers"),
            misc::audiobook_enrich_workers(&e, batch).to_string(),
            s(r, "audiobook_workers").to_owned(),
        );
        f.eq(
            format!("{name}: manga_batch"),
            misc::manga_enrich_batch_size(&e).to_string(),
            s(r, "manga_batch").to_owned(),
        );
        f.eq(
            format!("{name}: manga_workers"),
            misc::manga_enrich_workers(&e).to_string(),
            s(r, "manga_workers").to_owned(),
        );
        f.eq(
            format!("{name}: audiobook_scan"),
            misc::audiobook_scan_workers(&e).to_string(),
            s(r, "audiobook_scan").to_owned(),
        );
        f.eq(
            format!("{name}: ebook_scan"),
            misc::ebook_scan_workers(&e).to_string(),
            s(r, "ebook_scan").to_owned(),
        );
        f.eq(
            format!("{name}: match_threshold"),
            marshal_to_string(&misc::metadata_match_threshold(&e)).unwrap(),
            s(r, "match_threshold").to_owned(),
        );
        f.eq(
            format!("{name}: backfill claims"),
            outcome(misc::ebook_backfill_max_claims(
                e.get("SILO_EBOOK_BACKFILL_MAX_CLAIMS"),
            )),
            s(r, "ebook_backfill_claims").to_owned(),
        );
        f.eq(
            format!("{name}: backfill delay"),
            outcome(
                misc::ebook_backfill_batch_delay(e.get("SILO_EBOOK_BACKFILL_BATCH_DELAY"))
                    .map(|d| d.0),
            ),
            s(r, "ebook_backfill_delay").to_owned(),
        );
        f.eq(
            format!("{name}: query attribution"),
            misc::query_attribution_enabled(&e).to_string(),
            s(r, "query_attribution").to_owned(),
        );
    }
    f.done("env permutations");
}

#[test]
fn settings_maps_load_like_go() {
    let doc = vector("settings_maps.json");
    let mut f = Failures::default();
    for case in doc["cases"].as_array().unwrap() {
        let m = string_map(&case["settings"]);
        let label = marshal_to_string(&m.iter().collect::<BTreeMap<_, _>>()).unwrap();
        match load_from_db(&m) {
            Ok(cfg) => f.eq(
                format!("config {label}"),
                Ok::<String, String>(marshal_to_string(&cfg).unwrap()),
                case_config(case),
            ),
            Err(e) => f.eq(
                format!("config {label}"),
                Err::<String, String>(e),
                case_config(case),
            ),
        }
        let effective: BTreeMap<String, String> =
            effective_admin_settings(&m).into_iter().collect();
        f.eq(
            format!("effective {label}"),
            marshal_to_string(&effective).unwrap(),
            s(case, "effective").to_owned(),
        );
        f.eq(
            format!("validate {label}"),
            validate_admin_settings(&m).err().unwrap_or_default(),
            s(case, "validate").to_owned(),
        );
        f.eq(
            format!("validate with redis {label}"),
            validate_admin_settings_with_capabilities(
                &m,
                AdminSettingsCapabilities {
                    redis_bootstrap_available: true,
                },
            )
            .err()
            .unwrap_or_default(),
            s(case, "validate_with_redis").to_owned(),
        );
    }
    let misc = &doc["misc"];
    let want_defaults = string_map(&misc["defaults"]);
    let got_defaults = effective_admin_settings(&SettingsMap::new());
    f.eq("default count", got_defaults.len(), want_defaults.len());
    for (k, v) in &want_defaults {
        f.eq(
            format!("default {k}"),
            got_defaults.get(k).cloned().unwrap_or_default(),
            v.clone(),
        );
    }
    f.eq(
        "restart keys",
        restart_required_keys(),
        misc["restart_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
    );
    f.eq(
        "restart prefixes",
        restart_required_prefixes(),
        misc["restart_prefixes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
    );
    for (k, v) in misc["restart_required"].as_object().unwrap() {
        f.eq(
            format!("restart {k}"),
            restart_required(k),
            v.as_bool().unwrap(),
        );
    }
    f.eq(
        "server id",
        format!("\"{DEFAULT_JELLYFIN_COMPAT_SERVER_ID}\""),
        s(misc, "server_id").to_owned(),
    );
    for row in misc["enabled"].as_array().unwrap() {
        f.eq(
            format!("enabled {} {:?}", s(row, "key"), s(row, "stored")),
            admin_setting_enabled(s(row, "key"), s(row, "stored")),
            row["enabled"].as_bool().unwrap(),
        );
    }
    for (k, v) in misc["preview_widths"].as_object().unwrap() {
        f.eq(
            format!("preview {k:?}"),
            preview_image_width(k),
            v.as_i64().unwrap(),
        );
    }
    for (k, v) in misc["durations"].as_object().unwrap() {
        let m: SettingsMap = [("auth.access_token_expiry".to_owned(), k.clone())]
            .into_iter()
            .collect();
        let got = match load_from_db(&m) {
            Ok(c) => c.auth.access_token_expiry.0.to_string(),
            Err(e) => format!("error: {e}"),
        };
        f.eq(
            format!("duration {k:?}"),
            got,
            v.as_str().unwrap().to_owned(),
        );
    }
    for (k, v) in misc["recheck"].as_object().unwrap() {
        f.eq(
            format!("recheck {k:?}"),
            auth_provider_recheck_interval(k).0,
            v.as_i64().unwrap(),
        );
    }
    for (k, v) in misc["refresh"].as_object().unwrap() {
        f.eq(
            format!("refresh {k:?}"),
            auth_refresh_token_expiry(k).0,
            v.as_i64().unwrap(),
        );
    }
    for (k, v) in misc["rating_lists"].as_object().unwrap() {
        let want: Vec<String> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect();
        f.eq(
            format!("rating list {k:?}"),
            parse_rating_source_list(k),
            want,
        );
    }
    for row in misc["artifact_dirs"].as_array().unwrap() {
        let r: Vec<&str> = row
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        f.eq(
            format!("artifact dir {r:?}"),
            effective_download_artifact_dir(r[0], r[1]),
            r[2].to_owned(),
        );
    }
    for row in misc["validate"].as_array().unwrap() {
        let mut c = Config::default();
        c.server.mode = s(row, "mode").to_owned();
        c.database.url = s(row, "db").to_owned();
        c.redis.url = s(row, "redis").to_owned();
        f.eq(
            format!("Config.Validate {row}"),
            c.validate().err().unwrap_or_default(),
            s(row, "error").to_owned(),
        );
    }
    for row in misc["abs_listen"].as_array().unwrap() {
        let r: Vec<&str> = row
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        let c = AudiobookshelfCompatConfig {
            listen: r[0].to_owned(),
        };
        f.eq(
            format!("abs listen {r:?}"),
            c.with_bootstrap_listen(r[1]).listen,
            r[2].to_owned(),
        );
    }
    for (k, v) in misc["probe_ages"].as_object().unwrap() {
        let c = PlaybackConfig {
            bandwidth_probe_max_age_days: k.parse().unwrap(),
            ..Default::default()
        };
        f.eq(
            format!("probe age {k}"),
            c.bandwidth_probe_max_age().0,
            v.as_i64().unwrap(),
        );
    }
    f.done("settings maps");
}

fn case_config(case: &Value) -> Result<String, String> {
    match case.get("error").and_then(Value::as_str) {
        Some(e) if !e.is_empty() => Err(e.to_owned()),
        _ => Ok(s(case, "config").to_owned()),
    }
}

#[test]
fn admin_settings_normalize_like_go() {
    let doc = vector("normalize_admin.json");
    let rows = doc.as_array().unwrap();
    let mut f = Failures::default();
    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for row in rows {
        let (key, value) = (s(row, "key").to_owned(), s(row, "value").to_owned());
        let got = std::panic::catch_unwind(|| normalize_admin_setting(&key, &value));
        let got = match got {
            Ok(Ok(v)) => ("ok", v),
            Ok(Err(e)) => ("error", e),
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_default();
                ("panic", msg)
            }
        };
        let want = if row.get("panic").is_some() {
            ("panic", s(row, "panic").to_owned())
        } else if row.get("error").is_some() {
            ("error", normalize_cwd(s(row, "error")))
        } else {
            ("ok", s(row, "ok").to_owned())
        };
        let got = (got.0, normalize_cwd(&got.1));
        f.eq(format!("{key} = {value:?}"), got, want);
    }
    std::panic::set_hook(quiet);
    f.done("normalize admin");
}

fn normalize_cwd(msg: &str) -> String {
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let msg = msg.replace(&cwd, "<CWD>");
    let mut lines: Vec<&str> = msg.split('\n').collect();
    let head = lines.len().min(1);
    lines[head..].sort_unstable();
    lines.join("\n")
}

#[test]
fn redis_urls_parse_like_go() {
    let doc = vector("redis_url.json");
    let mut f = Failures::default();
    let target_json = |t: &RedisTarget| match t {
        RedisTarget::Single(o) => marshal_to_string(o.as_ref()).unwrap(),
        RedisTarget::Sentinel(o) => marshal_to_string(o.as_ref()).unwrap(),
    };
    for row in doc["urls"].as_array().unwrap() {
        let url = s(row, "url");
        let want = if !s(row, "error").is_empty() {
            format!("error: {}", s(row, "error"))
        } else if !s(row, "failover").is_empty() {
            s(row, "failover").to_owned()
        } else {
            s(row, "single").to_owned()
        };
        let got = match parse_redis_url(url) {
            Ok(t) => target_json(&t),
            Err(e) => format!("error: {e}"),
        };
        f.eq(format!("parse {url:?}"), got, want);
        let want_n = if row["normalize"].get("error").is_some() {
            Err(s(&row["normalize"], "error").to_owned())
        } else {
            Ok(s(&row["normalize"], "ok").to_owned())
        };
        f.eq(
            format!("normalize {url:?}"),
            normalize_redis_url(url),
            want_n,
        );
        for db in row["db"].as_array().unwrap() {
            let cfg = RedisConfig {
                url: url.to_owned(),
                db: s(db, "db").to_owned(),
            };
            f.eq(
                format!("database {url:?} {:?}", s(db, "db")),
                cfg.database(),
                db["database"].as_i64(),
            );
            let got = match cfg.options() {
                Ok(t) => target_json(&t),
                Err(e) => format!("error: {e}"),
            };
            f.eq(
                format!("options {url:?} {:?}", s(db, "db")),
                got,
                s(db, "options").to_owned(),
            );
            f.eq(
                format!("bootstrap {url:?}"),
                marshal_to_string(&cfg.with_bootstrap_url("redis://boot:1")).unwrap(),
                s(db, "bootstrap").to_owned(),
            );
        }
    }
    for (v, r) in doc["normalize_db"].as_object().unwrap() {
        let want = if r.get("error").is_some() {
            Err(s(r, "error").to_owned())
        } else {
            Ok(s(r, "ok").to_owned())
        };
        f.eq(format!("db {v:?}"), normalize_redis_db(v), want);
    }
    f.done("redis urls");
}

fn scrub_ids(text: &str) -> String {
    // Go's provider ids hold three random bytes. Number them in order of appearance on both sides.
    let re = silo_gocompat::regexp::GoRegex::must_compile(
        r"(openai|gemini|openrouter|groq|ollama|whisper|custom)-[0-9a-f]{6}",
    );
    let mut seen: Vec<String> = Vec::new();
    re.replace_all_string_func(text, |m| {
        let i = seen.iter().position(|x| x == m).unwrap_or_else(|| {
            seen.push(m.to_owned());
            seen.len() - 1
        });
        format!("{}-#{i}", &m[..m.len() - 7])
    })
}

#[test]
fn ai_providers_match_go() {
    let doc = vector("ai_providers.json");
    let mut f = Failures::default();
    for row in doc["registries"].as_array().unwrap() {
        let raw = s(row, "raw");
        match parse_ai_provider_registry(raw) {
            Ok(r) => {
                f.eq(
                    format!("error for {raw:?}"),
                    String::new(),
                    s(row, "error").to_owned(),
                );
                f.eq(
                    format!("encode {raw:?}"),
                    r.encode(),
                    s(row, "encoded").to_owned(),
                );
                f.eq(
                    format!("validate {raw:?}"),
                    r.validate().err().unwrap_or_default(),
                    s(row, "validate").to_owned(),
                );
            }
            Err(e) => f.eq(format!("error for {raw:?}"), e, s(row, "error").to_owned()),
        }
    }
    for row in doc["providers"].as_array().unwrap() {
        let input = s(row, "in");
        let v: Value = serde_json::from_str(input).unwrap();
        let p = AIProvider {
            id: s(&v, "id").to_owned(),
            type_: s(&v, "type").to_owned(),
            name: s(&v, "name").to_owned(),
            base_url: s(&v, "base_url").to_owned(),
            api_key: s(&v, "api_key").to_owned(),
            capabilities: v
                .get("capabilities")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(|x| x.as_str().unwrap().to_owned()).collect()),
        };
        let want = if s(row, "error").is_empty() {
            Ok(s(row, "out").to_owned())
        } else {
            Err(s(row, "error").to_owned())
        };
        f.eq(
            input,
            normalize_ai_provider(p).map(|o| marshal_to_string(&o).unwrap()),
            want,
        );
    }
    for row in doc["plans"].as_array().unwrap() {
        let stored = string_map(&row["stored"]);
        let label = marshal_to_string(&stored.iter().collect::<BTreeMap<_, _>>()).unwrap();
        match plan_ai_provider_conversion(&stored) {
            Err(e) => f.eq(format!("plan {label}"), e, s(row, "error").to_owned()),
            Ok(plan) => {
                f.eq(
                    format!("plan error {label}"),
                    String::new(),
                    s(row, "error").to_owned(),
                );
                f.eq(
                    format!("plan nil {label}"),
                    plan.writes.is_none(),
                    row["nil_writes"].as_bool().unwrap(),
                );
                let got: BTreeMap<String, String> =
                    plan.writes.unwrap_or_default().into_iter().collect();
                let want: BTreeMap<String, String> =
                    string_map(&row["writes"]).into_iter().collect();
                f.eq(
                    format!("plan writes {label}"),
                    scrub_ids(&marshal_to_string(&got).unwrap()),
                    scrub_ids(&marshal_to_string(&want).unwrap()),
                );
                let want_u: Vec<String> = row["unconverted"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap().to_owned())
                    .collect();
                f.eq(
                    format!("plan unconverted {label}"),
                    plan.unconverted,
                    want_u,
                );
            }
        }
    }
    for row in doc["bindings"].as_array().unwrap() {
        let values = string_map(&row["values"]);
        let label = marshal_to_string(&values.iter().collect::<BTreeMap<_, _>>()).unwrap();
        f.eq(
            format!("bindings {label}"),
            validate_ai_provider_bindings(&values)
                .err()
                .unwrap_or_default(),
            s(row, "validate").to_owned(),
        );
        f.eq(
            format!("tier {label}"),
            resolve_ai_service_tier(&values),
            s(row, "tier").to_owned(),
        );
        for (id, users) in row["users"].as_object().unwrap() {
            let want: Vec<String> = users
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect();
            f.eq(
                format!("users {id} {label}"),
                ai_provider_users(&values, id),
                want,
            );
        }
        for (k, ep) in row["endpoint"].as_object().unwrap() {
            let (key, capability) = k.split_once('|').unwrap();
            let want = (
                ep[0].as_str().unwrap().to_owned(),
                ep[1].as_str().unwrap().to_owned(),
            );
            f.eq(
                format!("endpoint {k} {label}"),
                resolve_ai_endpoint(&values, key, capability),
                want,
            );
        }
    }
    for (u, v) in doc["versions"].as_object().unwrap() {
        f.eq(
            format!("has version {u:?}"),
            has_api_version(u),
            v.as_bool().unwrap(),
        );
    }
    for row in doc["efforts"].as_array().unwrap() {
        f.eq(
            format!("effort {} {}", s(row, "model"), s(row, "effort")),
            validate_reasoning(s(row, "model"), s(row, "effort"))
                .err()
                .unwrap_or_default(),
            s(row, "error").to_owned(),
        );
    }
    f.done("ai providers");
}

#[test]
fn yaml_imports_like_go() {
    let rows = vector("yaml_import.json");
    let mut f = Failures::default();
    for row in rows.as_array().unwrap() {
        let doc = s(row, "doc");
        let got = yaml_to_settings_map_bytes(doc.as_bytes());
        let want_err = s(row, "error");
        if want_err.is_empty() {
            let want: BTreeMap<String, String> = string_map(&row["map"]).into_iter().collect();
            let got = got.map(|m| m.into_iter().collect::<BTreeMap<_, _>>());
            f.eq(format!("{doc:?}"), got, Ok(want));
        } else if want_err.contains("unmarshal errors") {
            f.eq(
                format!("{doc:?}"),
                got.map(|_| ()),
                Err(want_err.to_owned()),
            );
        } else {
            // A syntax error's text comes from libyaml's scanner in Go. Only that it failed has to match.
            f.eq(format!("{doc:?} fails"), got.is_err(), true);
        }
    }
    f.done("yaml");
}

#[test]
fn dotenv_parses_like_godotenv() {
    let rows = vector("dotenv.json");
    let mut f = Failures::default();
    for row in rows.as_array().unwrap() {
        let input = s(row, "in");
        let bytes = from_hex(s(row, "in_hex"));
        let got = parse_dotenv(&bytes)
            .map(|m| m.into_iter().collect::<BTreeMap<_, _>>())
            .map_err(|e| e.0);
        let want = if s(row, "error").is_empty() {
            Ok(string_map(&row["out"])
                .into_iter()
                .collect::<BTreeMap<_, _>>())
        } else {
            Err(s(row, "error").to_owned())
        };
        f.eq(format!("{input:?}"), got, want);
    }
    f.done("dotenv");
}

#[test]
fn flags_parse_like_go() {
    let doc = vector("flags.json");
    let mut f = Failures::default();
    let args = |row: &Value| -> Vec<String> {
        row["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect()
    };
    let same_json = |got: String, want: &str| -> (Value, Value) {
        (
            serde_json::from_str(&got).unwrap(),
            serde_json::from_str(want).unwrap(),
        )
    };
    for row in doc["server"].as_array().unwrap() {
        let a = args(row);
        match flags::parse_server_flags(&a) {
            Ok(v) => {
                f.eq(
                    format!("server {a:?} error"),
                    String::new(),
                    s(row, "error").to_owned(),
                );
                let (g, w) = same_json(marshal_to_string(&v).unwrap(), s(row, "ok"));
                f.eq(format!("server {a:?}"), g, w);
            }
            Err(e) => f.eq(
                format!("server {a:?}"),
                e.to_string(),
                s(row, "error").to_owned(),
            ),
        }
    }
    for row in doc["auth"].as_array().unwrap() {
        let a = args(row);
        match flags::parse_auth_command(&a) {
            Ok(v) => {
                f.eq(
                    format!("auth {a:?} error"),
                    String::new(),
                    s(row, "error").to_owned(),
                );
                let (g, w) = same_json(marshal_to_string(&v).unwrap(), s(row, "ok"));
                f.eq(format!("auth {a:?}"), g, w);
            }
            Err(e) => f.eq(format!("auth {a:?}"), e, s(row, "error").to_owned()),
        }
    }
    for row in doc["owner"].as_array().unwrap() {
        let a = args(row);
        match flags::parse_owner_command(&a) {
            Ok((env_file, user)) => {
                f.eq(
                    format!("owner {a:?} error"),
                    String::new(),
                    s(row, "error").to_owned(),
                );
                let (g, w) = same_json(marshal_to_string(&[env_file, user]).unwrap(), s(row, "ok"));
                f.eq(format!("owner {a:?}"), g, w);
            }
            Err(e) => f.eq(format!("owner {a:?}"), e, s(row, "error").to_owned()),
        }
    }
    for row in doc["compat_web"].as_array().unwrap() {
        let a = args(row);
        match flags::parse_compat_web_command(&a) {
            Ok(v) => {
                f.eq(
                    format!("compat-web {a:?} error"),
                    String::new(),
                    s(row, "error").to_owned(),
                );
                let (g, w) = same_json(marshal_to_string(&v).unwrap(), s(row, "ok"));
                f.eq(format!("compat-web {a:?}"), g, w);
            }
            Err(e) => f.eq(format!("compat-web {a:?}"), e, s(row, "error").to_owned()),
        }
    }
    f.done("flags");
}

#[test]
fn language_tags_match_x_text() {
    let rows = vector("lang.json");
    let mut f = Failures::default();
    for row in rows.as_array().unwrap() {
        let v = s(row, "in");
        f.eq(
            format!("canonical {v:?}"),
            lang::canonical_tag(v),
            s(row, "canonical").to_owned(),
        );
        f.eq(
            format!("compatible {v:?}"),
            lang::compatible_tag(v),
            s(row, "compatible").to_owned(),
        );
        f.eq(
            format!("registered {v:?}"),
            lang::registered_tag(v),
            s(row, "registered").to_owned(),
        );
        f.eq(
            format!("primary {v:?}"),
            lang::primary_language(v),
            s(row, "primary").to_owned(),
        );
        f.eq(
            format!("iso6392 {v:?}"),
            lang::iso6392(v),
            s(row, "iso6392").to_owned(),
        );
        let want: Vec<String> = row["aliases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect();
        f.eq(format!("aliases {v:?}"), lang::code_aliases(v), want);
        f.eq(
            format!("country {v:?}"),
            lang::canonical_country(v),
            s(row, "country").to_owned(),
        );
    }
    f.done("lang");
}

#[test]
fn strconv_parsers_match_go() {
    let rows = vector("strconv.json");
    let mut f = Failures::default();
    for row in rows.as_array().unwrap() {
        let v = s(row, "in");
        let pick = |r: &Value| -> Result<String, String> {
            match r.get("error").and_then(Value::as_str) {
                Some(e) => Err(e.to_owned()),
                None => Ok(match r.get("ok") {
                    Some(Value::String(x)) => x.clone(),
                    Some(other) => other.to_string(),
                    None => String::new(),
                }),
            }
        };
        let got_atoi = goparse::atoi(v)
            .map(|x| x.to_string())
            .map_err(|e| e.to_string());
        f.eq(
            format!("atoi {v:?}"),
            got_atoi,
            pick_or_zero(pick(&row["atoi"])),
        );
        let got_bool = goparse::parse_bool(v)
            .map(|x| x.to_string())
            .map_err(|e| e.to_string());
        f.eq(
            format!("bool {v:?}"),
            got_bool,
            pick_bool(pick(&row["bool"])),
        );
        let got_int = goparse::parse_int(v, 0, 64)
            .map(|x| x.to_string())
            .map_err(|e| e.to_string());
        f.eq(format!("int0 {v:?}"), got_int, pick(&row["int0"]));
        let got_uint = goparse::parse_uint(v, 10, 30)
            .map(|x| x.to_string())
            .map_err(|e| e.to_string());
        f.eq(
            format!("uint30 {v:?}"),
            got_uint,
            pick_or_zero(pick(&row["uint30"])),
        );
        match goparse::parse_float(v) {
            Ok(x) => {
                f.eq(
                    format!("float {v:?} ok"),
                    Ok::<(), String>(()),
                    pick(&row["float"]).map(|_| ()),
                );
                if let Some(bits) = row.get("float_bits").and_then(Value::as_u64)
                    && !x.is_nan()
                {
                    f.eq(format!("float bits {v:?}"), x.to_bits(), bits);
                }
            }
            Err(e) => f.eq(
                format!("float {v:?}"),
                Err::<String, String>(e.to_string()),
                pick(&row["float"]),
            ),
        }
    }
    f.done("strconv");
}

// encoding/json omits a zero value under omitempty, and these vectors carry 0 and false that way.
fn pick_or_zero(r: Result<String, String>) -> Result<String, String> {
    r.map(|v| if v.is_empty() { "0".to_owned() } else { v })
}

fn pick_bool(r: Result<String, String>) -> Result<String, String> {
    r.map(|v| if v.is_empty() { "false".to_owned() } else { v })
}

#[test]
fn net_parsers_match_go() {
    let doc = vector("net.json");
    let mut f = Failures::default();
    for row in doc["urls"].as_array().unwrap() {
        let input = s(row, "in");
        match gonet::Url::parse(input) {
            Err(e) => f.eq(
                format!("url {input:?}"),
                e.to_string(),
                s(row, "error").to_owned(),
            ),
            Ok(u) => {
                f.eq(
                    format!("url error {input:?}"),
                    String::new(),
                    s(row, "error").to_owned(),
                );
                f.eq(
                    format!("scheme {input:?}"),
                    u.scheme.clone(),
                    s(row, "scheme").to_owned(),
                );
                f.eq(
                    format!("opaque {input:?}"),
                    u.opaque.clone(),
                    s(row, "opaque").to_owned(),
                );
                f.eq(
                    format!("host {input:?}"),
                    u.host.clone(),
                    s(row, "host").to_owned(),
                );
                f.eq(
                    format!("hostname {input:?}"),
                    u.hostname().to_owned(),
                    s(row, "hostname").to_owned(),
                );
                f.eq(
                    format!("port {input:?}"),
                    u.port().to_owned(),
                    s(row, "port").to_owned(),
                );
                f.eq(
                    format!("path {input:?}"),
                    u.path.clone(),
                    s(row, "path").to_owned(),
                );
                f.eq(
                    format!("query {input:?}"),
                    u.raw_query.clone(),
                    s(row, "raw_query").to_owned(),
                );
                f.eq(
                    format!("fragment {input:?}"),
                    u.fragment.clone(),
                    s(row, "fragment").to_owned(),
                );
                f.eq(
                    format!("username {input:?}"),
                    u.user.as_ref().map(|x| x.username.clone()),
                    row["username"].as_str().map(str::to_owned),
                );
                f.eq(
                    format!("password {input:?}"),
                    u.user.as_ref().and_then(|x| x.password.clone()),
                    row["password"].as_str().map(str::to_owned),
                );
            }
        }
    }
    for row in doc["host_ports"].as_array().unwrap() {
        let input = s(row, "in");
        match gonet::split_host_port(input) {
            Ok((h, p)) => {
                f.eq(
                    format!("hostport {input:?} error"),
                    String::new(),
                    s(row, "error").to_owned(),
                );
                f.eq(
                    format!("hostport {input:?}"),
                    (h, p),
                    (s(row, "host").to_owned(), s(row, "port").to_owned()),
                );
            }
            Err(e) => f.eq(
                format!("hostport {input:?}"),
                e.to_string(),
                s(row, "error").to_owned(),
            ),
        }
    }
    for row in doc["addrs"].as_array().unwrap() {
        let input = s(row, "in");
        f.eq(
            format!("cidr {input:?}"),
            gonet::valid_cidr(input),
            row["cidr"].as_bool().unwrap(),
        );
        if row.get("valid").is_some() {
            let a = gonet::parse_addr(input);
            f.eq(
                format!("addr {input:?}"),
                a.is_ok(),
                row["valid"].as_bool().unwrap(),
            );
            if let Ok(a) = a {
                f.eq(
                    format!("loopback {input:?}"),
                    a.is_loopback(),
                    row["loopback"].as_bool().unwrap(),
                );
                f.eq(
                    format!("zone {input:?}"),
                    a.zone().to_owned(),
                    s(row, "zone").to_owned(),
                );
            }
        }
    }
    for row in doc["mails"].as_array().unwrap() {
        let input = s(row, "in");
        f.eq(
            format!("mail {input:?}"),
            gonet::mail_address_equals_input(input),
            row["equal"].as_bool().unwrap(),
        );
    }
    f.done("net");
}

fn parser_for(name: &str) -> Parser {
    match name {
        "second" => Parser::new(
            cron::SECOND
                | cron::MINUTE
                | cron::HOUR
                | cron::DOM
                | cron::MONTH
                | cron::DOW_OPTIONAL
                | cron::DESCRIPTOR,
        ),
        "standard" => Parser::new(
            cron::MINUTE | cron::HOUR | cron::DOM | cron::MONTH | cron::DOW | cron::DESCRIPTOR,
        ),
        "optsecond" => Parser::new(
            cron::SECOND_OPTIONAL
                | cron::MINUTE
                | cron::HOUR
                | cron::DOM
                | cron::MONTH
                | cron::DOW
                | cron::DESCRIPTOR,
        ),
        "nodesc" => Parser::new(cron::MINUTE | cron::HOUR | cron::DOM | cron::MONTH | cron::DOW),
        "subset" => Parser::new(cron::HOUR | cron::DOM | cron::MONTH | cron::DOW_OPTIONAL),
        other => panic!("unknown parser {other}"),
    }
}

fn location_name(l: &Location) -> String {
    match l {
        Location::Utc => "UTC".to_owned(),
        Location::Local => "Local".to_owned(),
        Location::Zone(tz) => tz.iana_name().unwrap_or("?").to_owned(),
        Location::Fixed(o) => format!("fixed:{o}"),
    }
}

fn describe(s: &Schedule) -> Value {
    match s {
        Schedule::Spec(x) => serde_json::json!({
            "second": format!("{:x}", x.second),
            "minute": format!("{:x}", x.minute),
            "hour": format!("{:x}", x.hour),
            "dom": format!("{:x}", x.dom),
            "month": format!("{:x}", x.month),
            "dow": format!("{:x}", x.dow),
            "location": location_name(&x.location),
        }),
        Schedule::ConstantDelay(c) => serde_json::json!({ "delay": c.delay }),
    }
}

fn location_from(name: &str) -> Location {
    if let Some(o) = name.strip_prefix("fixed:") {
        return Location::Fixed(o.parse().unwrap());
    }
    Location::load(name).unwrap()
}

#[test]
fn cron_parses_like_robfig() {
    let doc = vector("cron.json");
    let mut f = Failures::default();
    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for row in doc["parse"].as_array().unwrap() {
        let (p, spec) = (s(row, "parser").to_owned(), s(row, "spec").to_owned());
        let got = std::panic::catch_unwind(|| parser_for(&p).parse(&spec));
        match got {
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|m| (*m).to_owned()))
                    .unwrap_or_default();
                f.eq(
                    format!("{p} {spec:?} panic"),
                    msg,
                    s(row, "panic").to_owned(),
                );
            }
            Ok(Err(e)) => f.eq(format!("{p} {spec:?}"), e, s(row, "error").to_owned()),
            Ok(Ok(sched)) => f.eq(format!("{p} {spec:?}"), describe(&sched), row["ok"].clone()),
        }
    }
    std::panic::set_hook(quiet);
    f.done("cron parse");
}

#[test]
fn cron_next_fires_like_robfig() {
    let doc = vector("cron.json");
    let rows = doc["next"].as_array().unwrap();
    assert!(
        rows.len() > 500,
        "expected the robfig cases and the DST sweep, have {}",
        rows.len()
    );
    let mut f = Failures::default();
    let mut cache: HashMap<(String, String), Schedule> = HashMap::new();
    for row in rows {
        let (p, spec) = (s(row, "parser").to_owned(), s(row, "spec").to_owned());
        let sched = cache
            .entry((p.clone(), spec.clone()))
            .or_insert_with(|| parser_for(&p).parse(&spec).unwrap())
            .clone();
        let from = &row["from"];
        let t = ZonedTime::new(
            from["unix"].as_i64().unwrap(),
            from["nanos"].as_i64().unwrap() as i32,
            location_from(s(from, "loc")),
        );
        let label = format!("{spec:?} from {from}");
        match (sched.next(&t), row.get("next").filter(|n| !n.is_null())) {
            (None, None) => {}
            (Some(next), Some(want)) => {
                f.eq(
                    format!("{label}: unix"),
                    next.unix,
                    want["unix"].as_i64().unwrap(),
                );
                f.eq(
                    format!("{label}: nanos"),
                    i64::from(next.nanos),
                    want["nanos"].as_i64().unwrap(),
                );
                f.eq(
                    format!("{label}: offset"),
                    next.offset(),
                    row["offset"].as_i64().unwrap(),
                );
                f.eq(
                    format!("{label}: year"),
                    next.year(),
                    row["year"].as_i64().unwrap(),
                );
            }
            (got, want) => f.0.push(format!("{label}: got {got:?}, want {want:?}")),
        }
    }
    f.done("cron next");
}
