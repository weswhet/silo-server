//! `LoadPostgresTuneOptionsFromEnv`: the opt-in PostgreSQL tuning environment.

use super::Env;
use crate::goparse::{atoi, parse_float, parse_int};
use serde::Serialize;
use silo_gocompat::strconv::quote;
use silo_gocompat::strings::{equal_fold, to_lower, to_upper, trim_space};

const PROFILE_OLTP: &str = "oltp";
const DEFAULT_MEMORY_BUDGET_PERCENT: i64 = 75;
const SIZE_KB: i64 = 1024;
const SIZE_MB: i64 = 1024 * SIZE_KB;
const SIZE_GB: i64 = 1024 * SIZE_MB;
const SIZE_TB: i64 = 1024 * SIZE_GB;

/// `database.PostgresTuneOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PostgresTuneOptions {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Profile")]
    pub profile: String,
    #[serde(rename = "MemoryBudgetBytes")]
    pub memory_budget_bytes: i64,
    #[serde(rename = "DetectedMemoryBytes")]
    pub detected_memory_bytes: i64,
    #[serde(rename = "MemorySource")]
    pub memory_source: String,
    #[serde(rename = "MemoryBudgetPercent")]
    pub memory_budget_percent: i64,
    #[serde(rename = "CPUs")]
    pub cpus: i64,
    #[serde(rename = "Connections")]
    pub connections: i64,
    #[serde(rename = "Storage")]
    pub storage: String,
    #[serde(rename = "DBSize")]
    pub db_size: String,
    #[serde(rename = "OSType")]
    pub os_type: String,
    #[serde(rename = "IOMethod")]
    pub io_method: String,
}

/// `firstNonEmptyEnv`.
pub fn first_non_empty_env<'a>(env: &'a Env, keys: &[&str]) -> &'a str {
    for key in keys {
        let value = trim_space(env.get(key));
        if !value.is_empty() {
            return value;
        }
    }
    ""
}

fn parse_mode(raw: &str) -> Result<(bool, String), String> {
    match to_lower(trim_space(raw)).as_str() {
        "1" | "true" | "yes" | "on" | "auto" | PROFILE_OLTP => Ok((true, PROFILE_OLTP.to_owned())),
        "0" | "false" | "no" | "off" | "none" | "disabled" => Ok((false, String::new())),
        _ => Err(format!("invalid POSTGRES_TUNE value {}", quote(raw))),
    }
}

/// `parsePostgresTuneByteSize`.
pub fn parse_byte_size(raw: &str) -> Result<i64, String> {
    let normalized = to_upper(trim_space(raw)).replace(' ', "");
    if normalized.is_empty() {
        return Err("empty size".to_owned());
    }
    const UNITS: [(&str, i64); 13] = [
        ("TIB", SIZE_TB),
        ("TB", SIZE_TB),
        ("GIB", SIZE_GB),
        ("GB", SIZE_GB),
        ("MIB", SIZE_MB),
        ("MB", SIZE_MB),
        ("KIB", SIZE_KB),
        ("KB", SIZE_KB),
        ("T", SIZE_TB),
        ("G", SIZE_GB),
        ("M", SIZE_MB),
        ("K", SIZE_KB),
        ("B", 1),
    ];
    for (suffix, value) in UNITS {
        let Some(number) = normalized.strip_suffix(suffix) else {
            continue;
        };
        if number.is_empty() {
            return Err(format!("missing numeric size in {}", quote(raw)));
        }
        let parsed = parse_float(number).map_err(|e| e.to_string())?;
        if parsed <= 0.0 {
            return Err("size must be positive".to_owned());
        }
        return Ok((parsed * value as f64) as i64);
    }
    Err(format!(
        "size {} must include a unit such as GB or MB",
        quote(raw)
    ))
}

const CGROUP_MEMORY_LIMIT_PATHS: [&str; 2] = [
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
];

fn read_cgroup_memory_limit(path: &str) -> Option<i64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value = trim_space(&raw);
    if value.is_empty() || value == "max" {
        return None;
    }
    let mem = parse_int(value, 10, 64).ok()?;
    if mem <= 0 || mem > 1 << 60 {
        return None;
    }
    Some(mem)
}

fn read_meminfo_total_bytes(path: &str) -> Result<i64, String> {
    let raw = std::fs::read(path).map_err(|e| go_open_error(path, &e))?;
    let text = String::from_utf8_lossy(&raw);
    let mut total = None;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let fields = silo_gocompat::strings::fields(rest);
        if fields.is_empty() {
            continue;
        }
        let Ok(mut value) = parse_int(fields[0], 10, 64) else {
            continue;
        };
        if fields.len() >= 2 && equal_fold(fields[1], "kB") {
            value = value.wrapping_mul(1024);
        }
        if trim_space(key) == "MemTotal" {
            total = Some(value);
        }
    }
    total.ok_or_else(|| "MemTotal not found".to_owned())
}

// *os.PathError text for a failed open.
fn go_open_error(path: &str, e: &std::io::Error) -> String {
    let msg = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_owned(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        _ => e.to_string(),
    };
    format!("open {path}: {msg}")
}

fn running_in_container() -> bool {
    if std::fs::metadata("/.dockerenv").is_ok() {
        return true;
    }
    match std::fs::read_to_string("/proc/1/cgroup") {
        Ok(raw) => raw.contains("docker") || raw.contains("kubepods"),
        Err(_) => false,
    }
}

fn format_byte_size(bytes: i64) -> String {
    if bytes % SIZE_TB == 0 {
        format!("{}TB", bytes / SIZE_TB)
    } else if bytes % SIZE_GB == 0 {
        format!("{}GB", bytes / SIZE_GB)
    } else if bytes % SIZE_MB == 0 {
        format!("{}MB", bytes / SIZE_MB)
    } else {
        format!("{bytes} bytes")
    }
}

fn detect_total_memory_bytes() -> Result<(i64, String), String> {
    for path in CGROUP_MEMORY_LIMIT_PATHS {
        if let Some(mem) = read_cgroup_memory_limit(path) {
            return Ok((mem, path.to_owned()));
        }
    }
    if let Ok(mem) = read_meminfo_total_bytes("/host/proc/meminfo")
        && mem > 0
    {
        return Ok((mem, "/host/proc/meminfo".to_owned()));
    }
    let mem = read_meminfo_total_bytes("/proc/meminfo")?;
    if running_in_container() && mem > 128 * SIZE_GB {
        return Err(format!(
            "/proc/meminfo reports {} inside a container without a finite cgroup memory limit or /host/proc/meminfo mount; set POSTGRES_TUNE_MEMORY explicitly or mount /proc/meminfo:/host/proc/meminfo:ro",
            format_byte_size(mem)
        ));
    }
    Ok((mem, "/proc/meminfo".to_owned()))
}

/// `LoadPostgresTuneOptionsFromEnv`.
pub fn load_options(env: &Env, app_max_connections: i64) -> Result<PostgresTuneOptions, String> {
    let raw_enabled = first_non_empty_env(env, &["POSTGRES_TUNE", "SILO_POSTGRES_TUNE"]);
    if raw_enabled.is_empty() {
        return Ok(PostgresTuneOptions::default());
    }
    let (enabled, profile_from_mode) = parse_mode(raw_enabled)?;
    if !enabled {
        return Ok(PostgresTuneOptions::default());
    }
    let mut profile = first_non_empty_env(
        env,
        &["POSTGRES_TUNE_PROFILE", "SILO_POSTGRES_TUNE_PROFILE"],
    )
    .to_owned();
    if profile.is_empty() {
        profile = profile_from_mode;
    }
    if profile.is_empty() {
        profile = PROFILE_OLTP.to_owned();
    }
    let profile = to_lower(&profile);
    if profile != PROFILE_OLTP {
        return Err(format!(
            "unsupported POSTGRES_TUNE_PROFILE {}; only {} is supported",
            quote(&profile),
            quote(PROFILE_OLTP)
        ));
    }

    let raw = first_non_empty_env(env, &["POSTGRES_TUNE_MEMORY", "SILO_POSTGRES_TUNE_MEMORY"]);
    let (budget, detected, source, percent);
    if raw.is_empty() || equal_fold(raw, "auto") {
        let (mem, src) =
            detect_total_memory_bytes().map_err(|e| format!("POSTGRES_TUNE_MEMORY=auto: {e}"))?;
        let raw_pct = first_non_empty_env(
            env,
            &[
                "POSTGRES_TUNE_MEMORY_BUDGET_PERCENT",
                "SILO_POSTGRES_TUNE_MEMORY_BUDGET_PERCENT",
            ],
        );
        let pct = if raw_pct.is_empty() {
            DEFAULT_MEMORY_BUDGET_PERCENT
        } else {
            match atoi(raw_pct) {
                Ok(p) if (1..=100).contains(&p) => p,
                _ => {
                    return Err(format!(
                        "invalid POSTGRES_TUNE_MEMORY_BUDGET_PERCENT {}",
                        quote(raw_pct)
                    ));
                }
            }
        };
        budget = mem.wrapping_mul(pct) / 100;
        detected = mem;
        source = src;
        percent = pct;
    } else {
        let mem = parse_byte_size(raw).map_err(|e| format!("invalid POSTGRES_TUNE_MEMORY: {e}"))?;
        budget = mem;
        detected = mem;
        source = "env".to_owned();
        percent = 100;
    }

    let raw = first_non_empty_env(env, &["POSTGRES_TUNE_CPUS", "SILO_POSTGRES_TUNE_CPUS"]);
    let cpus = if raw.is_empty() || equal_fold(raw, "auto") {
        std::thread::available_parallelism()
            .map_or(1, |n| n.get() as i64)
            .max(1)
    } else {
        match atoi(raw) {
            Ok(c) if c >= 1 => c,
            _ => return Err(format!("invalid POSTGRES_TUNE_CPUS {}", quote(raw))),
        }
    };

    let min_connections = if app_max_connections > 0 {
        app_max_connections + 20
    } else {
        1
    };
    let raw = first_non_empty_env(
        env,
        &[
            "POSTGRES_TUNE_CONNECTIONS",
            "SILO_POSTGRES_TUNE_CONNECTIONS",
        ],
    );
    let connections = if raw.is_empty() {
        min_connections.max(100)
    } else {
        match atoi(raw) {
            Ok(c) if c >= 1 => c.max(min_connections),
            _ => return Err(format!("invalid POSTGRES_TUNE_CONNECTIONS {}", quote(raw))),
        }
    };

    let raw = first_non_empty_env(
        env,
        &["POSTGRES_TUNE_STORAGE", "SILO_POSTGRES_TUNE_STORAGE"],
    );
    let storage = match to_lower(trim_space(raw)).as_str() {
        "" | "ssd" => "ssd",
        "hdd" | "hard_drive_hdd" => "hdd",
        "san" => "san",
        "nvme" | "optane" => "nvme",
        _ => return Err(format!("invalid POSTGRES_TUNE_STORAGE {}", quote(raw))),
    };

    let raw = first_non_empty_env(
        env,
        &["POSTGRES_TUNE_DB_SIZE", "SILO_POSTGRES_TUNE_DB_SIZE"],
    );
    let db_size = match to_lower(trim_space(raw)).as_str() {
        "" | "auto" => "auto",
        "mid" | "medium" | "mid_ram" => "mid_ram",
        "less" | "less_ram" | "fits_ram" | "fits-in-ram" => "less_ram",
        "greater" | "greater_ram" | "larger_than_ram" => "greater_ram",
        _ => return Err(format!("invalid POSTGRES_TUNE_DB_SIZE {}", quote(raw))),
    };

    let mut os_type = to_lower(first_non_empty_env(
        env,
        &["POSTGRES_TUNE_OS", "SILO_POSTGRES_TUNE_OS"],
    ));
    if os_type.is_empty() {
        os_type = "linux".to_owned();
    }
    let io_method = to_lower(first_non_empty_env(
        env,
        &["POSTGRES_TUNE_IO_METHOD", "SILO_POSTGRES_TUNE_IO_METHOD"],
    ));

    Ok(PostgresTuneOptions {
        enabled: true,
        profile,
        memory_budget_bytes: budget,
        detected_memory_bytes: detected,
        memory_source: source,
        memory_budget_percent: percent,
        cpus,
        connections,
        storage: storage.to_owned(),
        db_size: db_size.to_owned(),
        os_type,
        io_method,
    })
}
