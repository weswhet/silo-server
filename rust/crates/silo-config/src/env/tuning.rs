//! `internal/tuning`: per-node TCP tuning knobs.

use super::Env;
use crate::goparse::parse_uint;
use serde::Serialize;
use silo_gocompat::strings::{to_lower, trim_space};

pub const ENV_TCP_CONGESTION: &str = "SILO_NET_TCP_CONGESTION";
pub const ENV_TCP_SEND_BUFFER: &str = "SILO_NET_TCP_SEND_BUFFER";
pub const DEFAULT_TCP_SEND_BUFFER: i64 = 33_554_432;
pub const TCP_CONGESTION_BBR: &str = "bbr";
pub const TCP_CONGESTION_OFF: &str = "off";

/// The effective tuning values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Config {
    #[serde(rename = "TCPCongestion")]
    pub tcp_congestion: String,
    /// The force request in bytes; zero keeps kernel autotuning.
    #[serde(rename = "TCPSendBuffer")]
    pub tcp_send_buffer: i64,
}

/// A requested value refused in favor of off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Adjustment {
    #[serde(rename = "Env")]
    pub env: String,
    #[serde(rename = "Requested")]
    pub requested: String,
    #[serde(rename = "Effective")]
    pub effective: String,
    #[serde(rename = "Reason")]
    pub reason: String,
}

/// `tuning.Parse`. A value a knob does not recognize turns it off and returns an adjustment.
pub fn parse(env: &Env) -> (Config, Vec<Adjustment>) {
    let mut cfg = Config {
        tcp_congestion: TCP_CONGESTION_BBR.to_owned(),
        tcp_send_buffer: DEFAULT_TCP_SEND_BUFFER,
    };
    let mut adjustments = Vec::new();
    let refuse = |adjustments: &mut Vec<Adjustment>, env_name: &str, requested: &str| {
        adjustments.push(Adjustment {
            env: env_name.to_owned(),
            requested: requested.to_owned(),
            effective: TCP_CONGESTION_OFF.to_owned(),
            reason: "invalid".to_owned(),
        });
    };
    let requested = env.get(ENV_TCP_CONGESTION);
    match to_lower(trim_space(requested)).as_str() {
        "" | TCP_CONGESTION_BBR => {}
        TCP_CONGESTION_OFF => cfg.tcp_congestion = TCP_CONGESTION_OFF.to_owned(),
        _ => {
            cfg.tcp_congestion = TCP_CONGESTION_OFF.to_owned();
            refuse(&mut adjustments, ENV_TCP_CONGESTION, requested);
        }
    }
    let requested = env.get(ENV_TCP_SEND_BUFFER);
    let normalized = to_lower(trim_space(requested));
    match normalized.as_str() {
        "" => {}
        TCP_CONGESTION_OFF => cfg.tcp_send_buffer = 0,
        _ => match parse_uint(&normalized, 10, 30) {
            Ok(bytes) if bytes > 0 => cfg.tcp_send_buffer = bytes as i64,
            _ => {
                cfg.tcp_send_buffer = 0;
                refuse(&mut adjustments, ENV_TCP_SEND_BUFFER, requested);
            }
        },
    }
    (cfg, adjustments)
}
