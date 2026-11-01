// The vocabulary of the row table. `build.rs` includes this file and `rows_table.rs` as source, so
// they use nothing outside core.

/// The denominator a row belongs to. The names match the harness's surfaces where both exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Surface {
    ApiV1,
    ApiV2,
    /// `/api/v2` rows `internal/api/testdata/media_routes.txt` walks that `openapi.json` does not list.
    ApiV2Walked,
    ApiDelegate,
    Root,
    Metrics,
    Debug,
    ProxyNode,
    TranscodeNode,
    Jellycompat,
    Abs,
}

impl Surface {
    pub const fn name(self) -> &'static str {
        match self {
            Surface::ApiV1 => "api_v1",
            Surface::ApiV2 => "api_v2",
            Surface::ApiV2Walked => "api_v2_walked",
            Surface::ApiDelegate => "api_delegate",
            Surface::Root => "root",
            Surface::Metrics => "metrics",
            Surface::Debug => "debug",
            Surface::ProxyNode => "proxy_node",
            Surface::TranscodeNode => "transcode_node",
            Surface::Jellycompat => "jellycompat",
            Surface::Abs => "abs",
        }
    }

    /// The enum variant's name, as a table line spells it.
    pub const fn variant(self) -> &'static str {
        match self {
            Surface::ApiV1 => "ApiV1",
            Surface::ApiV2 => "ApiV2",
            Surface::ApiV2Walked => "ApiV2Walked",
            Surface::ApiDelegate => "ApiDelegate",
            Surface::Root => "Root",
            Surface::Metrics => "Metrics",
            Surface::Debug => "Debug",
            Surface::ProxyNode => "ProxyNode",
            Surface::TranscodeNode => "TranscodeNode",
            Surface::Jellycompat => "Jellycompat",
            Surface::Abs => "Abs",
        }
    }
}

/// The handler a native row runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NativeId {
    /// `handlers.HealthHandler`.
    Health,
    /// `getOpenAPIDocument`.
    OpenApi,
    /// `registerAPIDocs`.
    Docs,
    /// `server.FrontendHandler`.
    Spa,
    /// The root listener's explicit `/metrics` 404.
    RootMetrics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Native(NativeId),
    GoProxy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub surface: Surface,
    pub method: &'static str,
    pub path: &'static str,
    pub disposition: Disposition,
}

pub const fn go(surface: Surface, method: &'static str, path: &'static str) -> Row {
    Row {
        surface,
        method,
        path,
        disposition: Disposition::GoProxy,
    }
}

pub const fn native(
    surface: Surface,
    method: &'static str,
    path: &'static str,
    id: NativeId,
) -> Row {
    Row {
        surface,
        method,
        path,
        disposition: Disposition::Native(id),
    }
}
