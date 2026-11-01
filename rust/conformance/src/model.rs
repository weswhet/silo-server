//! Shared vocabulary: surfaces, routes, identities, cases.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    ApiV2,
    ApiV1,
    ApiDelegate,
    Root,
    Jellycompat,
    Abs,
    Metrics,
    Debug,
    ProxyNode,
    TranscodeNode,
}

impl Surface {
    pub const ALL: [Surface; 10] = [
        Surface::ApiV2,
        Surface::ApiV1,
        Surface::ApiDelegate,
        Surface::Root,
        Surface::Jellycompat,
        Surface::Abs,
        Surface::Metrics,
        Surface::Debug,
        Surface::ProxyNode,
        Surface::TranscodeNode,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Surface::ApiV2 => "api_v2",
            Surface::ApiV1 => "api_v1",
            Surface::ApiDelegate => "api_delegate",
            Surface::Root => "root",
            Surface::Jellycompat => "jellycompat",
            Surface::Abs => "abs",
            Surface::Metrics => "metrics",
            Surface::Debug => "debug",
            Surface::ProxyNode => "proxy_node",
            Surface::TranscodeNode => "transcode_node",
        }
    }

    pub fn parse(s: &str) -> Option<Surface> {
        Surface::ALL.into_iter().find(|v| v.name() == s)
    }

    /// True for the surfaces the main listener serves on the base URL.
    pub fn on_main_listener(self) -> bool {
        matches!(
            self,
            Surface::ApiV2 | Surface::ApiV1 | Surface::ApiDelegate | Surface::Root
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    Public,
    Profile,
    Authenticated,
    Admin,
    Permission,
    Node,
    Delegated,
    Unknown,
}

impl Auth {
    pub fn parse(s: &str) -> Auth {
        match s {
            "public" => Auth::Public,
            "profile_scoped" => Auth::Profile,
            "authenticated" => Auth::Authenticated,
            "acting_admin" => Auth::Admin,
            "permission_gated" => Auth::Permission,
            "node_bearer" => Auth::Node,
            "delegated" => Auth::Delegated,
            _ => Auth::Unknown,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Param {
    pub name: String,
    pub location: String,
    pub required: bool,
    pub schema: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct Op {
    pub id: String,
    pub params: Vec<Param>,
    pub body_media: Option<String>,
    pub body_schema: Option<serde_json::Value>,
    pub body_required: bool,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub surface: Surface,
    pub method: String,
    pub path: String,
    pub auth: Auth,
    pub op: Option<Arc<Op>>,
    pub streams: bool,
    pub websocket: bool,
    /// The route was registered for every method rather than this one on purpose.
    pub handle_all: bool,
    pub request_kind: Option<String>,
    pub source: &'static str,
}

impl Route {
    pub fn key(&self) -> String {
        format!("{} {} {}", self.surface.name(), self.method, self.path)
    }

    pub fn mutating(&self) -> bool {
        is_mutating(&self.method)
    }
}

pub fn is_mutating(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

/// Who sends the request. Credentials are resolved per side at send time because
/// session tokens differ between servers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Identity {
    Anon,
    User,
    Admin,
    Kid,
    UserJwt,
    AdminJwt,
    UserNoProfile,
    AdminNoProfile,
}

/// Order of execution. Reads see the pristine seed; mutations follow in stages,
/// each started from a reset database when a reset command is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Seed,
    Reads,
    Rejections,
    MutateV2,
    MutateV1,
    MutateScenarios,
    MutateCompat,
    /// Requests from named transport peers. They need the peer lab (`--sources`).
    Peers,
}

#[derive(Clone, Debug)]
pub struct Case {
    /// Unique across the plan: `<route key>#<name>`.
    pub id: String,
    pub route: usize,
    pub name: String,
    pub phase: Phase,
    pub identity: Identity,
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
    /// Fill every path parameter with this value instead of resolving it.
    pub path_override: Option<String>,
    /// Record the id the response returns under this template prefix.
    pub capture_as: Option<String>,
    /// A success here can change server state, so liveness is probed after it.
    pub may_mutate: bool,
    /// Set when the body cannot be compared; the reason is reported.
    pub skip_body: Option<&'static str>,
    pub timeout_secs: u64,
    /// Keeps a scenario and its follow-up steps contiguous when sorting.
    pub sort_key: String,
    /// The peer-lab client to send from, instead of the run's main base URLs.
    pub source: Option<String>,
    /// The Host to send, instead of `FIXED_HOST`.
    pub host: Option<String>,
    /// Before sending, poll this admin read on both sides until its `items` is not empty, for a
    /// write the server batches.
    pub settle_on: Option<String>,
}

pub const PROXY_MARKER_HEADER: &str = "X-Silo-Strangler-Upstream";
pub const FIXED_HOST: &str = "silo.conformance.test";
pub const CONFORMANCE_ORIGIN: &str = "https://client.conformance.test";
pub const INVALID_ID: &str = "conformance-invalid-id";
