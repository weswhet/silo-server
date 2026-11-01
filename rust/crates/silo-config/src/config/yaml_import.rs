//! `YAMLToSettingsMap`: the one-time import of a legacy `silo.yaml`, with yaml.v3's decoding rules.

use super::SettingsMap;
use super::types::*;
use crate::goparse::{parse_float, parse_int, parse_uint};
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strconv::quote;
use std::sync::OnceLock;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

const NULL_TAG: &str = "!!null";
const BOOL_TAG: &str = "!!bool";
const STR_TAG: &str = "!!str";
const INT_TAG: &str = "!!int";
const FLOAT_TAG: &str = "!!float";
const TIMESTAMP_TAG: &str = "!!timestamp";
const SEQ_TAG: &str = "!!seq";
const MAP_TAG: &str = "!!map";
const BINARY_TAG: &str = "!!binary";
const MERGE_TAG: &str = "!!merge";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Document,
    Mapping,
    Sequence,
    Scalar,
    Alias,
}

#[derive(Clone)]
struct YNode {
    kind: Kind,
    tag: String,
    value: String,
    line: usize,
    quoted: bool,
    content: Vec<usize>,
    alias: usize,
}

#[derive(Default)]
struct Builder {
    arena: Vec<YNode>,
    stack: Vec<usize>,
    anchors: std::collections::HashMap<usize, usize>,
    root: Option<usize>,
    done: bool,
}

fn short_tag(tag: &str) -> String {
    const PREFIX: &str = "tag:yaml.org,2002:";
    match tag.strip_prefix(PREFIX) {
        Some(rest) => format!("!!{rest}"),
        None => tag.to_owned(),
    }
}

fn tag_string(tag: &Option<Tag>) -> String {
    match tag {
        Some(t) if t.handle == "!!" => format!("!!{}", t.suffix),
        Some(t) if t.handle == "tag:yaml.org,2002:" => format!("!!{}", t.suffix),
        Some(t) if t.handle == "!" => format!("!{}", t.suffix),
        Some(t) => format!("{}{}", t.handle, t.suffix),
        None => String::new(),
    }
}

impl Builder {
    fn add(&mut self, node: YNode, anchor: usize) -> usize {
        let id = self.arena.len();
        self.arena.push(node);
        if anchor != 0 {
            self.anchors.insert(anchor, id);
        }
        if let Some(&parent) = self.stack.last() {
            self.arena[parent].content.push(id);
        } else if self.root.is_none() {
            self.root = Some(id);
        }
        id
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        if self.done {
            return;
        }
        let line = mark.line();
        match ev {
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
            Event::DocumentStart => {
                let id = self.add(
                    YNode {
                        kind: Kind::Document,
                        tag: String::new(),
                        value: String::new(),
                        line,
                        quoted: false,
                        content: Vec::new(),
                        alias: 0,
                    },
                    0,
                );
                self.stack.push(id);
            }
            Event::DocumentEnd => {
                self.stack.pop();
                self.done = true;
            }
            Event::Alias(aid) => {
                let target = self.anchors.get(&aid).copied().unwrap_or(usize::MAX);
                self.add(
                    YNode {
                        kind: Kind::Alias,
                        tag: String::new(),
                        value: String::new(),
                        line,
                        quoted: false,
                        content: Vec::new(),
                        alias: target,
                    },
                    0,
                );
            }
            Event::Scalar(value, style, aid, tag) => {
                let quoted = !matches!(style, TScalarStyle::Plain);
                let explicit = tag_string(&tag);
                let (tag, _) = if explicit.is_empty() || explicit == "!" {
                    if quoted {
                        (STR_TAG.to_owned(), ())
                    } else if value == "<<" {
                        (MERGE_TAG.to_owned(), ())
                    } else {
                        (resolve("", &value).map_or(String::new(), |r| r.0), ())
                    }
                } else {
                    (short_tag(&explicit), ())
                };
                self.add(
                    YNode {
                        kind: Kind::Scalar,
                        tag,
                        value,
                        line,
                        quoted,
                        content: Vec::new(),
                        alias: 0,
                    },
                    aid,
                );
            }
            Event::SequenceStart(aid, tag) => {
                let explicit = tag_string(&tag);
                let tag = if explicit.is_empty() || explicit == "!" {
                    SEQ_TAG.to_owned()
                } else {
                    short_tag(&explicit)
                };
                let id = self.add(
                    YNode {
                        kind: Kind::Sequence,
                        tag,
                        value: String::new(),
                        line,
                        quoted: false,
                        content: Vec::new(),
                        alias: 0,
                    },
                    aid,
                );
                self.stack.push(id);
            }
            Event::MappingStart(aid, tag) => {
                let explicit = tag_string(&tag);
                let tag = if explicit.is_empty() || explicit == "!" {
                    MAP_TAG.to_owned()
                } else {
                    short_tag(&explicit)
                };
                let id = self.add(
                    YNode {
                        kind: Kind::Mapping,
                        tag,
                        value: String::new(),
                        line,
                        quoted: false,
                        content: Vec::new(),
                        alias: 0,
                    },
                    aid,
                );
                self.stack.push(id);
            }
            Event::SequenceEnd | Event::MappingEnd => {
                self.stack.pop();
            }
        }
    }
}

#[derive(Clone, PartialEq)]
enum Resolved {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    Timestamp,
}

fn yaml_style_float() -> &'static GoRegex {
    static RE: OnceLock<GoRegex> = OnceLock::new();
    RE.get_or_init(|| {
        GoRegex::must_compile(r"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$")
    })
}

fn parse_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    let i = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if i != 4 || i == b.len() || b[i] != b'-' {
        return false;
    }
    for format in [
        "2006-1-2T15:4:5.999999999Z07:00",
        "2006-1-2t15:4:5.999999999Z07:00",
        "2006-1-2 15:4:5.999999999",
        "2006-1-2",
    ] {
        if silo_gocompat::time::parse(format, s).is_ok() {
            return true;
        }
    }
    false
}

fn resolvable(tag: &str) -> bool {
    matches!(
        tag,
        "" | STR_TAG | BOOL_TAG | INT_TAG | FLOAT_TAG | NULL_TAG | TIMESTAMP_TAG
    )
}

// resolve from yaml.v3's resolve.go. Err is its failf text.
fn resolve(tag: &str, input: &str) -> Result<(String, Resolved), String> {
    let tag = short_tag(tag);
    if !resolvable(&tag) {
        return Ok((tag, Resolved::Str(input.to_owned())));
    }
    let (rtag, out) = resolve_inner(&tag, input);
    if tag.is_empty() || rtag == tag || tag == STR_TAG || tag == BINARY_TAG {
        return Ok((rtag, out));
    }
    if tag == FLOAT_TAG
        && rtag == INT_TAG
        && let Resolved::Int(v) = out
    {
        return Ok((FLOAT_TAG.to_owned(), Resolved::Float(v as f64)));
    }
    Err(format!(
        "cannot decode {} `{input}` as a {}",
        short_tag(&rtag),
        short_tag(&tag)
    ))
}

fn resolve_inner(tag: &str, input: &str) -> (String, Resolved) {
    let hint = match input.as_bytes().first() {
        None => b'N',
        Some(b'+' | b'-') => b'S',
        Some(b'0'..=b'9') => b'D',
        Some(b'y' | b'Y' | b'n' | b'N' | b't' | b'T' | b'f' | b'F' | b'o' | b'O' | b'~') => b'M',
        Some(b'.') => b'.',
        Some(_) => 0,
    };
    if hint != 0 && tag != STR_TAG && tag != BINARY_TAG {
        match input {
            "true" | "True" | "TRUE" => return (BOOL_TAG.to_owned(), Resolved::Bool(true)),
            "false" | "False" | "FALSE" => return (BOOL_TAG.to_owned(), Resolved::Bool(false)),
            "" | "~" | "null" | "Null" | "NULL" => return (NULL_TAG.to_owned(), Resolved::Null),
            ".nan" | ".NaN" | ".NAN" => return (FLOAT_TAG.to_owned(), Resolved::Float(f64::NAN)),
            ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => {
                return (FLOAT_TAG.to_owned(), Resolved::Float(f64::INFINITY));
            }
            "-.inf" | "-.Inf" | "-.INF" => {
                return (FLOAT_TAG.to_owned(), Resolved::Float(f64::NEG_INFINITY));
            }
            "<<" => return (MERGE_TAG.to_owned(), Resolved::Str("<<".to_owned())),
            _ => {}
        }
        match hint {
            b'.' => {
                if let Ok(v) = parse_float(input) {
                    return (FLOAT_TAG.to_owned(), Resolved::Float(v));
                }
            }
            b'D' | b'S' => {
                if (tag.is_empty() || tag == TIMESTAMP_TAG) && parse_timestamp(input) {
                    return (TIMESTAMP_TAG.to_owned(), Resolved::Timestamp);
                }
                let plain = input.replace('_', "");
                if let Ok(v) = parse_int(&plain, 0, 64) {
                    return (INT_TAG.to_owned(), Resolved::Int(v));
                }
                if let Ok(v) = parse_uint(&plain, 0, 64) {
                    return (INT_TAG.to_owned(), Resolved::Uint(v));
                }
                if yaml_style_float().match_string(&plain)
                    && let Ok(v) = parse_float(&plain)
                {
                    return (FLOAT_TAG.to_owned(), Resolved::Float(v));
                }
                if let Some(rest) = plain.strip_prefix("0b") {
                    if let Ok(v) = parse_int(rest, 2, 64) {
                        return (INT_TAG.to_owned(), Resolved::Int(v));
                    }
                    if let Ok(v) = parse_uint(rest, 2, 64) {
                        return (INT_TAG.to_owned(), Resolved::Uint(v));
                    }
                } else if let Some(rest) = plain.strip_prefix("-0b")
                    && let Ok(v) = parse_int(&format!("-{rest}"), 2, 64)
                {
                    return (INT_TAG.to_owned(), Resolved::Int(v));
                }
                if let Some(rest) = plain.strip_prefix("0o") {
                    if let Ok(v) = parse_int(rest, 8, 64) {
                        return (INT_TAG.to_owned(), Resolved::Int(v));
                    }
                    if let Ok(v) = parse_uint(rest, 8, 64) {
                        return (INT_TAG.to_owned(), Resolved::Uint(v));
                    }
                } else if let Some(rest) = plain.strip_prefix("-0o")
                    && let Ok(v) = parse_int(&format!("-{rest}"), 8, 64)
                {
                    return (INT_TAG.to_owned(), Resolved::Int(v));
                }
            }
            _ => {}
        }
    }
    (STR_TAG.to_owned(), Resolved::Str(input.to_owned()))
}

enum Field<'a> {
    Str(&'a mut String),
    Int(&'a mut i64),
    Bool(&'a mut bool),
    Struct(&'a mut dyn YamlStruct),
}

trait YamlStruct {
    fn type_name(&self) -> &'static str;
    fn field(&mut self, name: &str) -> Option<Field<'_>>;
}

macro_rules! yaml_struct {
    ($ty:ty, $name:literal, { $($key:literal => $kind:ident($($f:tt)+)),* $(,)? }) => {
        impl YamlStruct for $ty {
            fn type_name(&self) -> &'static str { $name }
            fn field(&mut self, name: &str) -> Option<Field<'_>> {
                match name {
                    $($key => Some(Field::$kind(&mut self.$($f)+)),)*
                    _ => None,
                }
            }
        }
    };
}

#[derive(Default, Clone)]
struct S3Raw {
    public_endpoint: String,
    public_read_endpoint: String,
    public_region: String,
    public_path_style: bool,
    public_bucket: String,
    public_key_prefix: String,
    public_access_key: String,
    public_secret_key: String,
    public_url_auth: String,
    public_token_secret: String,
    public_token_param: String,
    public_token_ttl: i64,
    metadata_presign_expiry: String,
    private_endpoint: String,
    private_region: String,
    private_path_style: bool,
    private_bucket: String,
    private_key_prefix: String,
    private_access_key: String,
    private_secret_key: String,
    operational_endpoint: String,
    operational_public_endpoint: String,
    operational_region: String,
    operational_path_style: bool,
    operational_bucket: String,
    operational_key_prefix: String,
    operational_access_key: String,
    operational_secret_key: String,
    operational_url_auth: String,
    operational_token_secret: String,
    operational_token_param: String,
    operational_token_ttl: i64,
    user_db_endpoint: String,
    user_db_region: String,
    user_db_path_style: bool,
    user_db_bucket: String,
    user_db_key_prefix: String,
    user_db_access_key: String,
    user_db_secret_key: String,
}

yaml_struct!(S3Raw, "config.s3ConfigRaw", {
    "public_endpoint" => Str(public_endpoint),
    "public_read_endpoint" => Str(public_read_endpoint),
    "public_region" => Str(public_region),
    "public_path_style" => Bool(public_path_style),
    "public_bucket" => Str(public_bucket),
    "public_key_prefix" => Str(public_key_prefix),
    "public_access_key" => Str(public_access_key),
    "public_secret_key" => Str(public_secret_key),
    "public_url_auth" => Str(public_url_auth),
    "public_token_secret" => Str(public_token_secret),
    "public_token_param" => Str(public_token_param),
    "public_token_ttl" => Int(public_token_ttl),
    "metadata_presign_expiry" => Str(metadata_presign_expiry),
    "private_endpoint" => Str(private_endpoint),
    "private_region" => Str(private_region),
    "private_path_style" => Bool(private_path_style),
    "private_bucket" => Str(private_bucket),
    "private_key_prefix" => Str(private_key_prefix),
    "private_access_key" => Str(private_access_key),
    "private_secret_key" => Str(private_secret_key),
    "operational_endpoint" => Str(operational_endpoint),
    "operational_public_endpoint" => Str(operational_public_endpoint),
    "operational_region" => Str(operational_region),
    "operational_path_style" => Bool(operational_path_style),
    "operational_bucket" => Str(operational_bucket),
    "operational_key_prefix" => Str(operational_key_prefix),
    "operational_access_key" => Str(operational_access_key),
    "operational_secret_key" => Str(operational_secret_key),
    "operational_url_auth" => Str(operational_url_auth),
    "operational_token_secret" => Str(operational_token_secret),
    "operational_token_param" => Str(operational_token_param),
    "operational_token_ttl" => Int(operational_token_ttl),
    "user_db_endpoint" => Str(user_db_endpoint),
    "user_db_region" => Str(user_db_region),
    "user_db_path_style" => Bool(user_db_path_style),
    "user_db_bucket" => Str(user_db_bucket),
    "user_db_key_prefix" => Str(user_db_key_prefix),
    "user_db_access_key" => Str(user_db_access_key),
    "user_db_secret_key" => Str(user_db_secret_key),
});

#[derive(Default, Clone)]
struct UserDbRaw {
    backend: String,
    pool_max_open: i64,
    idle_timeout: String,
    litestream_sync: String,
    stale_grace_seconds: i64,
}

yaml_struct!(UserDbRaw, "config.userDBConfigRaw", {
    "backend" => Str(backend),
    "pool_max_open" => Int(pool_max_open),
    "idle_timeout" => Str(idle_timeout),
    "litestream_sync" => Str(litestream_sync),
    "stale_grace_seconds" => Int(stale_grace_seconds),
});

#[derive(Default, Clone)]
struct ScannerRaw {
    file_removal_grace: String,
    workers: i64,
    max_concurrent_libraries: i64,
    max_concurrent_scoped: i64,
    empty_trash_after_scan: bool,
    realtime_monitoring: bool,
}

yaml_struct!(ScannerRaw, "config.scannerConfigRaw", {
    "file_removal_grace" => Str(file_removal_grace),
    "workers" => Int(workers),
    "max_concurrent_libraries" => Int(max_concurrent_libraries),
    "max_concurrent_scoped" => Int(max_concurrent_scoped),
    "empty_trash_after_scan" => Bool(empty_trash_after_scan),
    "realtime_monitoring" => Bool(realtime_monitoring),
});

#[derive(Default, Clone)]
struct AuthRaw {
    jwt_secret: String,
    access_token_expiry: String,
    refresh_token_expiry: String,
}

yaml_struct!(AuthRaw, "config.authConfigRaw", {
    "jwt_secret" => Str(jwt_secret),
    "access_token_expiry" => Str(access_token_expiry),
    "refresh_token_expiry" => Str(refresh_token_expiry),
});

#[derive(Default, Clone)]
struct JellyfinRaw {
    enabled: bool,
    listen: String,
    public_url: String,
    emulated_server_version: String,
    server_id: String,
    server_name: String,
    web_enabled: bool,
    web_version: String,
    web_dir: String,
    web_install_dir: String,
    session_ttl: String,
    playback_session_ttl: String,
}

yaml_struct!(JellyfinRaw, "config.jellyfinCompatConfigRaw", {
    "enabled" => Bool(enabled),
    "listen" => Str(listen),
    "public_url" => Str(public_url),
    "emulated_server_version" => Str(emulated_server_version),
    "server_id" => Str(server_id),
    "server_name" => Str(server_name),
    "web_enabled" => Bool(web_enabled),
    "web_version" => Str(web_version),
    "web_dir" => Str(web_dir),
    "web_install_dir" => Str(web_install_dir),
    "session_ttl" => Str(session_ttl),
    "playback_session_ttl" => Str(playback_session_ttl),
});

yaml_struct!(ServerConfig, "config.ServerConfig", {
    "listen" => Str(listen),
    "mode" => Str(mode),
    "log_level" => Str(log_level),
    "log_format" => Str(log_format),
    "log_quiet" => Str(log_quiet),
    "public_url" => Str(public_url),
});

yaml_struct!(DatabaseConfig, "config.DatabaseConfig", {
    "url" => Str(url),
    "max_connections" => Int(max_connections),
});

yaml_struct!(ArtworkConfig, "config.ArtworkConfig", {
    "storage_backend" => Str(storage_backend),
    "local_path" => Str(local_path),
});

yaml_struct!(MatcherConfig, "config.MatcherConfig", {
    "workers" => Int(workers),
    "batch_size" => Int(batch_size),
    "enable_tv_series_root_queue" => Bool(enable_tv_series_root_queue),
    "enable_tv_series_group_queue" => Bool(enable_tv_series_group_queue_legacy),
});

yaml_struct!(PlaybackConfig, "config.PlaybackConfig", {
    "ffmpeg_path" => Str(ffmpeg_path),
    "transcode_dir" => Str(transcode_dir),
    "segment_retention_seconds" => Int(segment_retention_seconds),
    "hw_accel" => Str(hw_accel),
    "hw_device" => Str(hw_device),
    "chapter_thumbnail_workers" => Int(chapter_thumbnail_workers),
    "chapter_thumbnail_execution" => Str(chapter_thumbnail_execution),
    "chapter_thumbnail_node_capacity" => Int(chapter_thumbnail_node_capacity),
    "transcode_enabled" => Bool(transcode_enabled),
});

yaml_struct!(RedisConfig, "config.RedisConfig", {
    "url" => Str(url),
});

yaml_struct!(RateLimitConfig, "config.RateLimitConfig", {
    "enabled" => Bool(enabled),
    "backend" => Str(backend),
});

#[derive(Default, Clone)]
struct ConfigRaw {
    server: ServerConfig,
    database: DatabaseConfig,
    s3: S3Raw,
    user_db: UserDbRaw,
    scanner: ScannerRaw,
    artwork: ArtworkConfig,
    matcher: MatcherConfig,
    playback: PlaybackConfig,
    redis: RedisConfig,
    rate_limit: RateLimitConfig,
    auth: AuthRaw,
    jellyfin_compat: JellyfinRaw,
}

impl YamlStruct for ConfigRaw {
    fn type_name(&self) -> &'static str {
        "config.configRaw"
    }

    fn field(&mut self, name: &str) -> Option<Field<'_>> {
        Some(Field::Struct(match name {
            "server" => &mut self.server,
            "database" => &mut self.database,
            "s3" => &mut self.s3,
            "user_db" => &mut self.user_db,
            "scanner" => &mut self.scanner,
            "artwork" => &mut self.artwork,
            "matcher" => &mut self.matcher,
            "playback" => &mut self.playback,
            "redis" => &mut self.redis,
            "rate_limiting" => &mut self.rate_limit,
            "auth" => &mut self.auth,
            "jellyfin_compat" => &mut self.jellyfin_compat,
            _ => return None,
        }))
    }
}

fn set_defaults() -> ConfigRaw {
    let mut raw = ConfigRaw::default();
    raw.server.listen = ":8080".to_owned();
    raw.server.mode = "integrated".to_owned();
    raw.server.log_level = "info".to_owned();
    raw.server.log_format = "text".to_owned();
    raw.database.max_connections = 20;
    raw.s3.public_path_style = true;
    raw.s3.private_path_style = true;
    raw.s3.operational_path_style = true;
    raw.s3.user_db_path_style = true;
    raw.s3.metadata_presign_expiry = "4h".to_owned();
    raw.user_db = UserDbRaw {
        backend: "postgres".to_owned(),
        pool_max_open: 500,
        idle_timeout: "12h".to_owned(),
        litestream_sync: "1s".to_owned(),
        stale_grace_seconds: 120,
    };
    raw.scanner.workers = 8;
    raw.scanner.max_concurrent_libraries = 1;
    raw.scanner.max_concurrent_scoped = 2;
    raw.scanner.realtime_monitoring = true;
    raw.artwork = ArtworkConfig {
        storage_backend: ARTWORK_BACKEND_AUTO.to_owned(),
        local_path: "/var/lib/silo/artwork".to_owned(),
    };
    raw.matcher.workers = 8;
    raw.matcher.batch_size = 500;
    raw.matcher.enable_tv_series_root_queue = true;
    raw.playback.transcode_dir = DEFAULT_TRANSCODE_DIR.to_owned();
    raw.playback.segment_retention_seconds = 600;
    raw.playback.hw_accel = "auto".to_owned();
    raw.playback.chapter_thumbnail_workers = 1;
    raw.playback.chapter_thumbnail_execution = "local".to_owned();
    raw.playback.chapter_thumbnail_node_capacity = 1;
    raw.playback.subtitle_sync_node_capacity = 1;
    raw.playback.transcode_enabled = true;
    raw.rate_limit = RateLimitConfig {
        enabled: true,
        backend: "memory".to_owned(),
    };
    raw.auth.access_token_expiry = "8h".to_owned();
    raw.auth.refresh_token_expiry = "30d".to_owned();
    raw.jellyfin_compat = JellyfinRaw {
        enabled: false,
        listen: ":8097".to_owned(),
        public_url: "http://127.0.0.1:8097".to_owned(),
        emulated_server_version: DEFAULT_JELLYFIN_COMPAT_EMULATED_SERVER_VERSION.to_owned(),
        server_id: DEFAULT_JELLYFIN_COMPAT_SERVER_ID.to_owned(),
        server_name: "Silo".to_owned(),
        web_enabled: true,
        web_version: DEFAULT_JELLYFIN_WEB_VERSION.to_owned(),
        web_dir: DEFAULT_JELLYFIN_WEB_DIR.to_owned(),
        web_install_dir: DEFAULT_JELLYFIN_WEB_INSTALL_DIR.to_owned(),
        session_ttl: "87600h".to_owned(),
        playback_session_ttl: DEFAULT_JELLYFIN_COMPAT_PLAYBACK_SESSION_TTL.to_owned(),
    };
    raw
}

struct Decoder<'a> {
    arena: &'a [YNode],
    terrors: Vec<String>,
    decode_count: u64,
    alias_count: u64,
    alias_depth: u64,
    aliases: Vec<usize>,
    merged: Option<std::collections::HashSet<String>>,
}

fn go_quote_key(s: &str) -> String {
    quote(s)
}

fn allowed_alias_ratio(decode_count: u64) -> f64 {
    const LOW: u64 = 400_000;
    const HIGH: u64 = 4_000_000;
    if decode_count <= LOW {
        0.99
    } else if decode_count >= HIGH {
        0.10
    } else {
        0.99 - 0.89 * ((decode_count - LOW) as f64 / (HIGH - LOW) as f64)
    }
}

impl Decoder<'_> {
    fn count(&mut self) -> Result<(), String> {
        self.decode_count += 1;
        if self.alias_depth > 0 {
            self.alias_count += 1;
        }
        if self.alias_count > 100
            && self.decode_count > 1000
            && (self.alias_count as f64) / (self.decode_count as f64)
                > allowed_alias_ratio(self.decode_count)
        {
            return Err("yaml: document contains excessive aliasing".to_owned());
        }
        Ok(())
    }

    fn enter_alias(&mut self, id: usize) -> Result<usize, String> {
        let n = &self.arena[id];
        if self.aliases.contains(&id) {
            return Err(format!("yaml: anchor '{}' value contains itself", n.value));
        }
        self.aliases.push(id);
        self.alias_depth += 1;
        Ok(n.alias)
    }

    fn leave_alias(&mut self) {
        self.alias_depth -= 1;
        self.aliases.pop();
    }

    fn terror(&mut self, id: usize, tag: &str, out: &str) {
        let n = &self.arena[id];
        let tag = if n.tag.is_empty() {
            tag
        } else {
            n.tag.as_str()
        };
        let mut value = String::new();
        if tag != SEQ_TAG && tag != MAP_TAG {
            if n.value.len() > 10 {
                let cut = n.value.as_bytes();
                value = format!(" `{}...`", String::from_utf8_lossy(&cut[..7]));
            } else {
                value = format!(" `{}`", n.value);
            }
        }
        self.terrors.push(format!(
            "line {}: cannot unmarshal {}{value} into {out}",
            n.line,
            short_tag(tag)
        ));
    }

    fn short_tag_of(&self, id: usize) -> String {
        let n = &self.arena[id];
        if n.kind == Kind::Scalar
            && (short_tag(&n.tag) == STR_TAG || ((n.tag.is_empty() || n.tag == "!") && n.quoted))
        {
            return STR_TAG.to_owned();
        }
        if n.tag.is_empty() || n.tag == "!" {
            return match n.kind {
                Kind::Mapping => MAP_TAG.to_owned(),
                Kind::Sequence => SEQ_TAG.to_owned(),
                Kind::Alias => self.short_tag_of(n.alias),
                Kind::Scalar => resolve("", &n.value).map_or(String::new(), |r| r.0),
                Kind::Document => String::new(),
            };
        }
        short_tag(&n.tag)
    }

    fn scalar_resolved(&self, id: usize) -> Result<(String, Resolved), String> {
        let n = &self.arena[id];
        if short_tag(&n.tag) == STR_TAG || ((n.tag.is_empty() || n.tag == "!") && n.quoted) {
            return Ok((STR_TAG.to_owned(), Resolved::Str(n.value.clone())));
        }
        let (tag, resolved) = resolve(&n.tag, &n.value).map_err(|e| format!("yaml: {e}"))?;
        if tag == BINARY_TAG {
            let Resolved::Str(s) = &resolved else {
                return Ok((tag, resolved));
            };
            let data =
                base64_decode(s).ok_or("yaml: !!binary value contains invalid base64 data")?;
            return Ok((
                tag,
                Resolved::Str(String::from_utf8_lossy(&data).into_owned()),
            ));
        }
        Ok((tag, resolved))
    }

    fn string(&mut self, id: usize) -> Result<Option<String>, String> {
        self.count()?;
        let n = self.arena[id].clone();
        match n.kind {
            Kind::Alias => {
                let target = self.enter_alias(id)?;
                let r = self.string(target);
                self.leave_alias();
                r
            }
            Kind::Scalar => {
                if self.short_tag_of(id) == NULL_TAG {
                    return Ok(None);
                }
                let (tag, resolved) = self.scalar_resolved(id)?;
                match resolved {
                    Resolved::Null => Ok(None),
                    Resolved::Str(s) if tag == BINARY_TAG => Ok(Some(s)),
                    Resolved::Str(s) => Ok(Some(s)),
                    _ => Ok(Some(n.value.clone())),
                }
            }
            Kind::Mapping => {
                if self.short_tag_of(id) == NULL_TAG {
                    return Ok(None);
                }
                if !self.unique_keys(id) {
                    return Ok(None);
                }
                self.terror(id, MAP_TAG, "string");
                Ok(None)
            }
            Kind::Sequence => {
                if self.short_tag_of(id) != NULL_TAG {
                    self.terror(id, SEQ_TAG, "string");
                }
                Ok(None)
            }
            Kind::Document => Ok(None),
        }
    }

    fn set_int(&mut self, id: usize, out: &mut i64) -> Result<(), String> {
        self.count()?;
        let n = self.arena[id].clone();
        match n.kind {
            Kind::Alias => {
                let target = self.enter_alias(id)?;
                let r = self.set_int(target, out);
                self.leave_alias();
                r
            }
            Kind::Scalar => {
                if self.short_tag_of(id) == NULL_TAG {
                    return Ok(());
                }
                let (tag, resolved) = self.scalar_resolved(id)?;
                match resolved {
                    Resolved::Null => {}
                    Resolved::Int(v) => *out = v,
                    Resolved::Uint(v) if v <= i64::MAX as u64 => *out = v as i64,
                    Resolved::Float(v) if v <= i64::MAX as f64 => *out = v as i64,
                    _ => self.terror(id, &tag, "int"),
                }
                Ok(())
            }
            Kind::Mapping => {
                if self.unique_keys(id) {
                    self.terror(id, MAP_TAG, "int");
                }
                Ok(())
            }
            Kind::Sequence => {
                self.terror(id, SEQ_TAG, "int");
                Ok(())
            }
            Kind::Document => Ok(()),
        }
    }

    fn set_bool(&mut self, id: usize, out: &mut bool) -> Result<(), String> {
        self.count()?;
        let n = self.arena[id].clone();
        match n.kind {
            Kind::Alias => {
                let target = self.enter_alias(id)?;
                let r = self.set_bool(target, out);
                self.leave_alias();
                r
            }
            Kind::Scalar => {
                if self.short_tag_of(id) == NULL_TAG {
                    return Ok(());
                }
                let (tag, resolved) = self.scalar_resolved(id)?;
                match resolved {
                    Resolved::Null => {}
                    Resolved::Bool(b) => *out = b,
                    Resolved::Str(ref s) => match s.as_str() {
                        "y" | "Y" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" => *out = true,
                        "n" | "N" | "no" | "No" | "NO" | "off" | "Off" | "OFF" => *out = false,
                        _ => self.terror(id, &tag, "bool"),
                    },
                    _ => self.terror(id, &tag, "bool"),
                }
                Ok(())
            }
            Kind::Mapping => {
                if self.unique_keys(id) {
                    self.terror(id, MAP_TAG, "bool");
                }
                Ok(())
            }
            Kind::Sequence => {
                self.terror(id, SEQ_TAG, "bool");
                Ok(())
            }
            Kind::Document => Ok(()),
        }
    }

    fn unique_keys(&mut self, id: usize) -> bool {
        let n = &self.arena[id];
        let nerrs = self.terrors.len();
        let mut new_errs = Vec::new();
        let l = n.content.len();
        let mut i = 0;
        while i < l {
            let ni = &self.arena[n.content[i]];
            let mut j = i + 2;
            while j < l {
                let nj = &self.arena[n.content[j]];
                if ni.kind == nj.kind && ni.value == nj.value {
                    new_errs.push(format!(
                        "line {}: mapping key {} already defined at line {}",
                        nj.line,
                        go_quote_key(&nj.value),
                        ni.line
                    ));
                }
                j += 2;
            }
            i += 2;
        }
        self.terrors.extend(new_errs);
        self.terrors.len() == nerrs
    }

    fn struct_(&mut self, id: usize, out: &mut dyn YamlStruct) -> Result<(), String> {
        self.count()?;
        let n = self.arena[id].clone();
        let type_name = out.type_name();
        match n.kind {
            Kind::Document => {
                if n.content.len() == 1 {
                    return self.struct_(n.content[0], out);
                }
                Ok(())
            }
            Kind::Alias => {
                let target = self.enter_alias(id)?;
                let r = self.struct_(target, out);
                self.leave_alias();
                r
            }
            Kind::Scalar => {
                if self.short_tag_of(id) == NULL_TAG {
                    return Ok(());
                }
                let (tag, resolved) = self.scalar_resolved(id)?;
                if resolved != Resolved::Null {
                    self.terror(id, &tag, type_name);
                }
                Ok(())
            }
            Kind::Sequence => {
                self.terror(id, SEQ_TAG, type_name);
                Ok(())
            }
            Kind::Mapping => {
                if !self.unique_keys(id) {
                    return Ok(());
                }
                let merged_fields = self.merged.take();
                let mut merged_fields = merged_fields;
                let mut merge_node = None;
                let mut done = std::collections::HashSet::new();
                let mut i = 0;
                while i + 1 < n.content.len() {
                    let ni = n.content[i];
                    let nv = n.content[i + 1];
                    i += 2;
                    let key = &self.arena[ni];
                    if key.kind == Kind::Scalar
                        && key.value == "<<"
                        && (key.tag.is_empty()
                            || key.tag == "!"
                            || short_tag(&key.tag) == MERGE_TAG)
                    {
                        merge_node = Some(nv);
                        continue;
                    }
                    let line = key.line;
                    let Some(sname) = self.string(ni)? else {
                        continue;
                    };
                    if let Some(m) = &mut merged_fields {
                        if m.contains(&sname) {
                            continue;
                        }
                        m.insert(sname.clone());
                    }
                    if out.field(&sname).is_none() {
                        continue;
                    }
                    if !done.insert(sname.clone()) {
                        self.terrors.push(format!(
                            "line {line}: field {sname} already set in type {type_name}"
                        ));
                        continue;
                    }
                    let Some(field) = out.field(&sname) else {
                        continue;
                    };
                    match field {
                        Field::Str(s) => {
                            if let Some(v) = self.string(nv)? {
                                *s = v;
                            }
                        }
                        Field::Int(v) => self.set_int(nv, v)?,
                        Field::Bool(v) => self.set_bool(nv, v)?,
                        Field::Struct(st) => self.struct_(nv, st)?,
                    }
                }
                self.merged = merged_fields;
                if let Some(m) = merge_node {
                    self.merge(id, m, out)?;
                }
                Ok(())
            }
        }
    }

    fn merge(
        &mut self,
        parent: usize,
        merge: usize,
        out: &mut dyn YamlStruct,
    ) -> Result<(), String> {
        const WANT_MAP: &str = "yaml: map merge requires map or sequence of maps as the value";
        let saved = self.merged.clone();
        if self.merged.is_none() {
            let mut set = std::collections::HashSet::new();
            let content = self.arena[parent].content.clone();
            let mut i = 0;
            while i < content.len() {
                if self.arena[content[i]].kind == Kind::Scalar {
                    set.insert(self.arena[content[i]].value.clone());
                }
                i += 2;
            }
            self.merged = Some(set);
        }
        let node = self.arena[merge].clone();
        match node.kind {
            Kind::Mapping => self.struct_(merge, out)?,
            Kind::Alias => {
                if self.arena[node.alias].kind != Kind::Mapping {
                    return Err(WANT_MAP.to_owned());
                }
                self.struct_(merge, out)?;
            }
            Kind::Sequence => {
                for &ni in &node.content {
                    let item = &self.arena[ni];
                    if item.kind == Kind::Alias {
                        if self.arena[item.alias].kind != Kind::Mapping {
                            return Err(WANT_MAP.to_owned());
                        }
                    } else if item.kind != Kind::Mapping {
                        return Err(WANT_MAP.to_owned());
                    }
                    self.struct_(ni, out)?;
                }
            }
            _ => return Err(WANT_MAP.to_owned()),
        }
        self.merged = saved;
        Ok(())
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    let mut pad = 0;
    let mut count = 0;
    for c in s.bytes() {
        if c == b'\n' || c == b'\r' {
            continue;
        }
        count += 1;
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad += 1;
                continue;
            }
            _ => return None,
        };
        if pad > 0 {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    if count % 4 != 0 || pad > 2 {
        return None;
    }
    Some(out)
}

fn yaml_has_path(arena: &[YNode], root: Option<usize>, path: &[&str]) -> bool {
    let Some(mut node) = root else {
        return false;
    };
    if arena[node].kind == Kind::Document {
        match arena[node].content.first() {
            None => return false,
            Some(&c) => node = c,
        }
    }
    for key in path {
        if arena[node].kind != Kind::Mapping {
            return false;
        }
        let content = &arena[node].content;
        let mut found = None;
        let mut i = 0;
        while i + 1 < content.len() {
            if arena[content[i]].value == *key {
                found = Some(content[i + 1]);
                break;
            }
            i += 2;
        }
        match found {
            Some(next) => node = next,
            None => return false,
        }
    }
    true
}

fn set_if_non_empty(m: &mut SettingsMap, key: &str, value: &str) {
    if !value.is_empty() {
        m.insert(key.to_owned(), value.to_owned());
    }
}

fn first_non_empty<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() { b } else { a }
}

/// `YAMLToSettingsMap`: reads a YAML config file into a flat settings map.
pub fn yaml_to_settings_map(path: &str) -> Result<SettingsMap, String> {
    let data = std::fs::read(path).map_err(|e| format!("reading YAML config: {e}"))?;
    yaml_to_settings_map_bytes(&data)
}

/// `YAMLToSettingsMap` on file contents.
pub fn yaml_to_settings_map_bytes(data: &[u8]) -> Result<SettingsMap, String> {
    let text = String::from_utf8_lossy(data);
    let mut builder = Builder::default();
    let mut parser = Parser::new_from_str(&text);
    parser
        .load(&mut builder, false)
        .map_err(|e| format!("parsing YAML config: yaml: {e}"))?;
    let mut raw = set_defaults();
    let arena = builder.arena;
    if let Some(root) = builder.root {
        let mut decoder = Decoder {
            arena: &arena,
            terrors: Vec::new(),
            decode_count: 0,
            alias_count: 0,
            alias_depth: 0,
            aliases: Vec::new(),
            merged: None,
        };
        decoder
            .struct_(root, &mut raw)
            .map_err(|e| format!("parsing YAML config: {e}"))?;
        if !decoder.terrors.is_empty() {
            return Err(format!(
                "parsing YAML config: yaml: unmarshal errors:\n  {}",
                decoder.terrors.join("\n  ")
            ));
        }
    }
    let jellyfin_enabled_configured =
        yaml_has_path(&arena, builder.root, &["jellyfin_compat", "enabled"]);
    Ok(settings_from_raw(&raw, jellyfin_enabled_configured))
}

fn settings_from_raw(raw: &ConfigRaw, jellyfin_enabled_configured: bool) -> SettingsMap {
    let mut m = SettingsMap::new();
    set_if_non_empty(&mut m, "server.listen", &raw.server.listen);
    set_if_non_empty(&mut m, "server.mode", &raw.server.mode);
    set_if_non_empty(&mut m, "server.log_level", &raw.server.log_level);
    set_if_non_empty(&mut m, "server.log_format", &raw.server.log_format);
    set_if_non_empty(&mut m, "server.log_quiet", &raw.server.log_quiet);

    set_if_non_empty(&mut m, "database.url", &raw.database.url);
    if raw.database.max_connections != 0 {
        m.insert(
            "database.max_connections".to_owned(),
            raw.database.max_connections.to_string(),
        );
    }

    let s = &raw.s3;
    let legacy_operational = !s.operational_endpoint.is_empty()
        || !s.operational_public_endpoint.is_empty()
        || !s.operational_region.is_empty()
        || !s.operational_bucket.is_empty()
        || !s.operational_key_prefix.is_empty()
        || !s.operational_access_key.is_empty()
        || !s.operational_secret_key.is_empty()
        || !s.operational_url_auth.is_empty()
        || !s.operational_token_secret.is_empty()
        || !s.operational_token_param.is_empty()
        || s.operational_token_ttl > 0
        || !s.operational_path_style;
    let public_configured = !s.public_endpoint.is_empty()
        || !s.public_read_endpoint.is_empty()
        || !s.public_region.is_empty()
        || !s.public_bucket.is_empty()
        || !s.public_key_prefix.is_empty()
        || !s.public_access_key.is_empty()
        || !s.public_secret_key.is_empty()
        || !s.public_url_auth.is_empty()
        || !s.public_token_secret.is_empty()
        || !s.public_token_param.is_empty()
        || s.public_token_ttl > 0
        || !s.metadata_presign_expiry.is_empty();
    let private_configured = !s.private_endpoint.is_empty()
        || !s.private_region.is_empty()
        || !s.private_bucket.is_empty()
        || !s.private_key_prefix.is_empty()
        || !s.private_access_key.is_empty()
        || !s.private_secret_key.is_empty();
    let public_path_style = if !public_configured && legacy_operational {
        s.operational_path_style
    } else {
        s.public_path_style
    };
    let private_path_style = if !private_configured && legacy_operational {
        s.operational_path_style
    } else {
        s.private_path_style
    };

    set_if_non_empty(
        &mut m,
        "s3.public_endpoint",
        first_non_empty(&s.public_endpoint, &s.operational_endpoint),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_read_endpoint",
        first_non_empty(&s.public_read_endpoint, &s.operational_public_endpoint),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_region",
        first_non_empty(&s.public_region, &s.operational_region),
    );
    m.insert(
        "s3.public_path_style".to_owned(),
        public_path_style.to_string(),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_bucket",
        first_non_empty(&s.public_bucket, &s.operational_bucket),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_key_prefix",
        first_non_empty(&s.public_key_prefix, &s.operational_key_prefix),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_access_key",
        first_non_empty(&s.public_access_key, &s.operational_access_key),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_secret_key",
        first_non_empty(&s.public_secret_key, &s.operational_secret_key),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_url_auth",
        first_non_empty(&s.public_url_auth, &s.operational_url_auth),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_token_secret",
        first_non_empty(&s.public_token_secret, &s.operational_token_secret),
    );
    set_if_non_empty(
        &mut m,
        "s3.public_token_param",
        first_non_empty(&s.public_token_param, &s.operational_token_param),
    );
    if s.public_token_ttl > 0 {
        m.insert(
            "s3.public_token_ttl".to_owned(),
            s.public_token_ttl.to_string(),
        );
    } else if s.operational_token_ttl > 0 {
        m.insert(
            "s3.public_token_ttl".to_owned(),
            s.operational_token_ttl.to_string(),
        );
    }
    set_if_non_empty(
        &mut m,
        "s3.metadata_presign_expiry",
        &s.metadata_presign_expiry,
    );

    set_if_non_empty(
        &mut m,
        "s3.private_endpoint",
        first_non_empty(&s.private_endpoint, &s.operational_endpoint),
    );
    set_if_non_empty(
        &mut m,
        "s3.private_region",
        first_non_empty(&s.private_region, &s.operational_region),
    );
    m.insert(
        "s3.private_path_style".to_owned(),
        private_path_style.to_string(),
    );
    set_if_non_empty(
        &mut m,
        "s3.private_bucket",
        first_non_empty(&s.private_bucket, &s.operational_bucket),
    );
    set_if_non_empty(
        &mut m,
        "s3.private_key_prefix",
        first_non_empty(&s.private_key_prefix, &s.operational_key_prefix),
    );
    set_if_non_empty(
        &mut m,
        "s3.private_access_key",
        first_non_empty(&s.private_access_key, &s.operational_access_key),
    );
    set_if_non_empty(
        &mut m,
        "s3.private_secret_key",
        first_non_empty(&s.private_secret_key, &s.operational_secret_key),
    );

    set_if_non_empty(&mut m, "s3.user_db_endpoint", &s.user_db_endpoint);
    set_if_non_empty(&mut m, "s3.user_db_region", &s.user_db_region);
    m.insert(
        "s3.user_db_path_style".to_owned(),
        s.user_db_path_style.to_string(),
    );
    set_if_non_empty(&mut m, "s3.user_db_bucket", &s.user_db_bucket);
    set_if_non_empty(&mut m, "s3.user_db_key_prefix", &s.user_db_key_prefix);
    set_if_non_empty(&mut m, "s3.user_db_access_key", &s.user_db_access_key);
    set_if_non_empty(&mut m, "s3.user_db_secret_key", &s.user_db_secret_key);

    set_if_non_empty(&mut m, "userdb.backend", &raw.user_db.backend);
    if raw.user_db.pool_max_open != 0 {
        m.insert(
            "userdb.pool_max_open".to_owned(),
            raw.user_db.pool_max_open.to_string(),
        );
    }
    set_if_non_empty(&mut m, "userdb.idle_timeout", &raw.user_db.idle_timeout);
    set_if_non_empty(
        &mut m,
        "userdb.litestream_sync",
        &raw.user_db.litestream_sync,
    );
    if raw.user_db.stale_grace_seconds != 0 {
        m.insert(
            "userdb.stale_grace_seconds".to_owned(),
            raw.user_db.stale_grace_seconds.to_string(),
        );
    }

    if raw.scanner.workers != 0 {
        m.insert(
            "scanner.workers".to_owned(),
            raw.scanner.workers.to_string(),
        );
    }
    if raw.scanner.max_concurrent_libraries != 0 {
        m.insert(
            "scanner.max_concurrent_libraries".to_owned(),
            raw.scanner.max_concurrent_libraries.to_string(),
        );
    }
    if raw.scanner.max_concurrent_scoped != 0 {
        m.insert(
            "scanner.max_concurrent_scoped".to_owned(),
            raw.scanner.max_concurrent_scoped.to_string(),
        );
    }
    set_if_non_empty(
        &mut m,
        "scanner.file_removal_grace",
        &raw.scanner.file_removal_grace,
    );
    m.insert(
        "scanner.empty_trash_after_scan".to_owned(),
        raw.scanner.empty_trash_after_scan.to_string(),
    );
    m.insert(
        "scanner.realtime_monitoring".to_owned(),
        raw.scanner.realtime_monitoring.to_string(),
    );

    set_if_non_empty(
        &mut m,
        "artwork.storage_backend",
        &raw.artwork.storage_backend,
    );
    set_if_non_empty(&mut m, "artwork.local_path", &raw.artwork.local_path);

    if raw.matcher.workers != 0 {
        m.insert(
            "matcher.workers".to_owned(),
            raw.matcher.workers.to_string(),
        );
    }
    if raw.matcher.batch_size != 0 {
        m.insert(
            "matcher.batch_size".to_owned(),
            raw.matcher.batch_size.to_string(),
        );
    }
    m.insert(
        "matcher.enable_tv_series_root_queue".to_owned(),
        raw.matcher.tv_series_root_queue_enabled().to_string(),
    );

    set_if_non_empty(&mut m, "playback.ffmpeg_path", &raw.playback.ffmpeg_path);
    set_if_non_empty(
        &mut m,
        PLAYBACK_TRANSCODE_DIR_SETTING_KEY,
        &raw.playback.transcode_dir,
    );
    m.insert(
        super::PLAYBACK_SEGMENT_RETENTION_SETTING_KEY.to_owned(),
        raw.playback.segment_retention_seconds.to_string(),
    );
    set_if_non_empty(&mut m, "playback.hw_accel", &raw.playback.hw_accel);
    if raw.playback.chapter_thumbnail_workers != 0 {
        m.insert(
            "playback.chapter_thumbnail_workers".to_owned(),
            raw.playback.chapter_thumbnail_workers.to_string(),
        );
    }
    set_if_non_empty(
        &mut m,
        "playback.chapter_thumbnail_execution",
        &raw.playback.chapter_thumbnail_execution,
    );
    if raw.playback.chapter_thumbnail_node_capacity != 0 {
        m.insert(
            "playback.chapter_thumbnail_node_capacity".to_owned(),
            raw.playback.chapter_thumbnail_node_capacity.to_string(),
        );
    }
    m.insert(
        "playback.transcode_enabled".to_owned(),
        raw.playback.transcode_enabled.to_string(),
    );

    m.insert("redis.url".to_owned(), raw.redis.url.clone());

    m.insert(
        "ratelimit.enabled".to_owned(),
        raw.rate_limit.enabled.to_string(),
    );
    set_if_non_empty(&mut m, "ratelimit.backend", &raw.rate_limit.backend);

    set_if_non_empty(&mut m, "auth.jwt_secret", &raw.auth.jwt_secret);
    set_if_non_empty(
        &mut m,
        "auth.access_token_expiry",
        &raw.auth.access_token_expiry,
    );
    set_if_non_empty(
        &mut m,
        "auth.refresh_token_expiry",
        &raw.auth.refresh_token_expiry,
    );

    let j = &raw.jellyfin_compat;
    if jellyfin_enabled_configured {
        m.insert("jellyfin_compat.enabled".to_owned(), j.enabled.to_string());
    } else if !j.listen.is_empty() {
        m.insert("jellyfin_compat.enabled".to_owned(), "true".to_owned());
    }
    set_if_non_empty(&mut m, "jellyfin_compat.listen", &j.listen);
    set_if_non_empty(&mut m, "jellyfin_compat.public_url", &j.public_url);
    set_if_non_empty(
        &mut m,
        "jellyfin_compat.emulated_server_version",
        &j.emulated_server_version,
    );
    set_if_non_empty(&mut m, "jellyfin_compat.server_id", &j.server_id);
    set_if_non_empty(&mut m, "jellyfin_compat.server_name", &j.server_name);
    m.insert(
        "jellyfin_compat.web_enabled".to_owned(),
        j.web_enabled.to_string(),
    );
    set_if_non_empty(&mut m, "jellyfin_compat.web_version", &j.web_version);
    set_if_non_empty(&mut m, "jellyfin_compat.web_dir", &j.web_dir);
    set_if_non_empty(
        &mut m,
        "jellyfin_compat.web_install_dir",
        &j.web_install_dir,
    );
    set_if_non_empty(&mut m, "jellyfin_compat.session_ttl", &j.session_ttl);
    set_if_non_empty(
        &mut m,
        "jellyfin_compat.playback_session_ttl",
        &j.playback_session_ttl,
    );
    m
}
