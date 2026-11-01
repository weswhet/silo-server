//! `internal/telemetry`'s configuration.

use super::{Env, env_bool};
use crate::goparse::parse_float;
use serde::Serialize;
use silo_gocompat::strings::{to_lower, trim_space};

pub const PROTOCOL_GRPC: &str = "grpc";
pub const PROTOCOL_HTTP: &str = "http/protobuf";
pub const SAMPLER_PARENT_BASED_TRACE_ID_RATIO: &str = "parentbased_traceidratio";
const DEFAULT_SERVICE_NAME: &str = "silo-server";
const DEFAULT_SAMPLER_RATIO: f64 = 0.01;

/// The fully-defaulted telemetry configuration.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Config {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Endpoint")]
    pub endpoint: String,
    #[serde(rename = "Protocol")]
    pub protocol: String,
    #[serde(rename = "TracesProtocol")]
    pub traces_protocol: String,
    #[serde(rename = "LogsProtocol")]
    pub logs_protocol: String,
    #[serde(rename = "ServiceName")]
    pub service_name: String,
    #[serde(rename = "ServiceVersion")]
    pub service_version: String,
    #[serde(rename = "NodeID")]
    pub node_id: String,
    #[serde(rename = "Sampler")]
    pub sampler: String,
    #[serde(rename = "SamplerRatio")]
    pub sampler_ratio: f64,
}

fn parse_protocol(raw: &str, fallback: &str) -> String {
    match to_lower(trim_space(raw)).as_str() {
        "http/protobuf" | "http" => PROTOCOL_HTTP.to_owned(),
        "grpc" => PROTOCOL_GRPC.to_owned(),
        _ => fallback.to_owned(),
    }
}

fn parse_sampler(raw: &str) -> String {
    let s = to_lower(trim_space(raw));
    match s.as_str() {
        "always_on"
        | "always_off"
        | "traceidratio"
        | "parentbased_always_on"
        | "parentbased_always_off" => s,
        _ => SAMPLER_PARENT_BASED_TRACE_ID_RATIO.to_owned(),
    }
}

/// `telemetry.LoadConfig`.
pub fn load_config(env: &Env, node_id: &str) -> Config {
    let endpoint = trim_space(env.get("OTEL_EXPORTER_OTLP_ENDPOINT")).to_owned();
    let enabled = env_bool(env, "SILO_OTEL_ENABLED") || !endpoint.is_empty();
    let mut service_name = trim_space(env.get("OTEL_SERVICE_NAME")).to_owned();
    if service_name.is_empty() {
        service_name = DEFAULT_SERVICE_NAME.to_owned();
    }
    let protocol = parse_protocol(env.get("OTEL_EXPORTER_OTLP_PROTOCOL"), PROTOCOL_GRPC);
    let traces_protocol = parse_protocol(env.get("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"), &protocol);
    let logs_protocol = parse_protocol(env.get("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"), &protocol);
    let mut ratio = DEFAULT_SAMPLER_RATIO;
    let raw = trim_space(env.get("OTEL_TRACES_SAMPLER_ARG"));
    if !raw.is_empty()
        && let Ok(v) = parse_float(raw)
        && v >= 0.0
        && v != f64::INFINITY
    {
        ratio = v.min(1.0);
    }
    Config {
        enabled,
        endpoint,
        protocol,
        traces_protocol,
        logs_protocol,
        service_name,
        service_version: trim_space(env.get("OTEL_SERVICE_VERSION")).to_owned(),
        node_id: node_id.to_owned(),
        sampler: parse_sampler(env.get("OTEL_TRACES_SAMPLER")),
        sampler_ratio: ratio,
    }
}
