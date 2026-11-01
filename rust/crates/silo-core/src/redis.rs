//! The Redis contract that Go and Rust replicas share: channels, event JSON, key layout, and the Lua
//! scripts in `redis_lua`, copied verbatim because a script's SHA-1 names it on the server.

use serde::{Deserialize, Serialize};

pub const CHANNEL_CATALOG: &str = "silo:catalog";
pub const CHANNEL_ADMIN: &str = "silo:admin";
pub const CHANNEL_PLAYBACK: &str = "silo:playback";
pub const CHANNEL_LOGS: &str = "silo:logs";
pub const CHANNEL_EVENTS: &str = "silo:events";

pub const SUPPRESS_KEY_PREFIX: &str = "silo:autoscan:scanned:";
pub const ROOM_SOCKET_TICKET_PREFIX: &str = "silo:watch-together:v2:ticket:";
pub const API_REPLICA_KEY_PREFIX: &str = "silo:api-replica:";
pub const STREAM_DENY_KEY_PREFIX: &str = "silo:streamauth:";
pub const NODE_RECIPE_KEY_PREFIX: &str = "silo:noderecipe:";
pub const PROXY_GRANT_KEY_PREFIX: &str = "silo:proxygrant:";
pub const SESSION_RECIPE_KEY_PREFIX: &str = "silo:sessionrecipe:";
pub const NODE_AUTHORITY_GENERATION_KEY_PREFIX: &str = "silo:noderecipe-authority-generation:";
pub const NODE_AUTHORITY_RECORD_KEY_PREFIX: &str = "silo:noderecipe-authority-record:";
pub const NODE_AUTHORITY_DIGEST_KEY_PREFIX: &str = "silo:noderecipe-authority-digest:";
pub const PLAYBACK_CONTROL_TICKET_PREFIX: &str = "silo:playback:v2:control-ticket:";
pub const EVENTS_WS_TICKET_PREFIX: &str = "silo:events:ws-ticket:";
pub const EVENTS_WS_TICKET_PROOF_PREFIX: &str = "silo:events:ws-ticket-proof:";
pub const EVENTS_V2_TICKET_PREFIX: &str = "silo:events:v2:ticket:";
pub const SESSIONS_KEY_PREFIX: &str = "silo:sessions:";
pub const PLAYBACK_DELIVERY_KEY_PREFIX: &str = "silo:playback-delivery:";
pub const QUOTA_KEY_PREFIX: &str = "silo:ratelimit:quota:";
pub const STREAM_TELEMETRY_DEFAULT_PREFIX: &str = "silo:stelem";

/// `redisChannel`: a database above zero scopes the channel, and zero or a negative number keeps the
/// bare name.
pub fn channel(channel: &str, db: i64) -> String {
    if db <= 0 {
        return channel.to_owned();
    }
    format!("{channel}@db{db}")
}

/// `cache.Event`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: String,
}

/// `RedisLimiter.count`'s per-second key.
pub fn rate_limit_second_key(key: &str, unix: i64) -> String {
    format!("silo:ratelimit:{key}:s:{unix}")
}

/// `RedisLimiter.count`'s per-minute key.
pub fn rate_limit_minute_key(key: &str, unix: i64) -> String {
    format!("silo:ratelimit:{key}:m:{}", unix / 60)
}

/// `redisAttemptKey`.
pub fn attempt_key(key: &str) -> String {
    format!("silo:attempts:{key}")
}

/// `nodesessions`' session key.
pub fn node_session_key(node_hash: &str, session_id: &str) -> String {
    format!("{SESSIONS_KEY_PREFIX}{node_hash}:{session_id}")
}

/// The shared bandwidth pool keys in `downloads/bandwidth.go`.
pub fn download_bandwidth_keys(user_id: i64) -> [String; 2] {
    [
        "silo:downloads:{bandwidth}:global".to_owned(),
        format!("silo:downloads:{{bandwidth}}:user:{user_id}"),
    ]
}

/// `searchSessionPrefix`. Redis Cluster keeps the account index and its session values together.
pub fn search_session_prefix(user_id: i64) -> String {
    format!("catalog:search:{{{user_id}}}:")
}
