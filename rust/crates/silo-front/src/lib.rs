//! The test-only front described in the Rust port plan: it owns the public listeners, answers the rows
//! ported so far, and relays everything else to a Go reference server without changing it.
//!
//! It never serves users. It has no TLS of its own, no LAN discovery, and its parity numbers come from
//! the conformance harness reading the origin log, not from anything in the responses.

pub mod frontend;
pub mod http1;
pub mod native;
pub mod origin;
pub mod peer;
pub mod reconcile;
pub mod relay;
pub mod rows;
pub mod trust;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use silo_http::{BoxHandler, Server, ServerConfig, handler_fn};
use silo_pg::{Pool, PoolConfig};
use tokio::net::{TcpListener, lookup_host};

use crate::frontend::{BrandingSource, WebDist};
use crate::native::{Gate, NativeInputs, ServerIdentity, main_handler};
use crate::origin::OriginLog;
use crate::relay::ListenerCtx;
use crate::rows::{ROWS, Surface, native_count};
use crate::trust::{DEFAULT_TRUSTED_PROXIES, SETTING_TRUSTED_PROXIES, TrustList};

/// How often the trusted list is re-read. Go reloads on a settings event; this polls.
const TRUST_POLL: Duration = Duration::from_secs(2);

/// One public listener and the Go listener behind it.
#[derive(Clone, Debug)]
pub struct FrontSpec {
    /// `main`, `jellycompat`, `abs`, `metrics`, `debug`, `proxy_node`, or `transcode_node`.
    pub name: String,
    pub listen: String,
    pub upstream: String,
}

impl FrontSpec {
    /// Parses `NAME=LISTEN,UPSTREAM`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let usage = || format!("--front {raw}: expected NAME=LISTEN,UPSTREAM");
        let (name, rest) = raw.split_once('=').ok_or_else(usage)?;
        let (listen, upstream) = rest.split_once(',').ok_or_else(usage)?;
        if ![
            "main",
            "jellycompat",
            "abs",
            "metrics",
            "debug",
            "proxy_node",
            "transcode_node",
        ]
        .contains(&name)
        {
            return Err(format!("--front {raw}: unknown listener {name}"));
        }
        let upstream = upstream
            .strip_prefix("http://")
            .unwrap_or(upstream)
            .trim_end_matches('/');
        Ok(Self {
            name: name.to_owned(),
            listen: listen.to_owned(),
            upstream: upstream.to_owned(),
        })
    }
}

/// Everything the front is started with.
#[derive(Clone, Debug, Default)]
pub struct FrontConfig {
    pub fronts: Vec<FrontSpec>,
    /// `DATABASE_URL`: the reference's database, read for the trust list, identity, and branding.
    pub database_url: Option<String>,
    /// `SILO_TRUSTED_PROXIES`: the list to use when there is no database.
    pub trusted_proxies: Option<String>,
    /// `SILO_FRONT_WEB_DIST`: the build output Go embeds. Without it the SPA stays on Go.
    pub web_dist: Option<PathBuf>,
    /// `SILO_FRONT_ORIGIN_LOG`.
    pub origin_log: Option<PathBuf>,
    /// `SECRET_KEY`: decrypts `auth.jwt_secret`. Without it the rows behind a credential stay on Go.
    pub secret_key: Option<String>,
    /// `REDIS_URL`: the limiter's counters, shared with Go. Without it they stay in this process.
    pub redis_url: Option<String>,
    /// `SILO_FRONT_FORCE_GO`: comma-separated surfaces to send back to Go, or `all`.
    pub force_go: Vec<Surface>,
}

impl FrontConfig {
    fn trusted_list(&self) -> String {
        self.trusted_proxies.clone().unwrap_or_default()
    }
}

/// Parses `SILO_FRONT_FORCE_GO`.
pub fn parse_force_go(raw: &str) -> Result<Vec<Surface>, String> {
    let all = [Surface::ApiV1, Surface::ApiV2, Surface::Root];
    let mut out = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if item == "all" {
            out.extend(all);
            continue;
        }
        match all.iter().find(|s| s.name() == item) {
            Some(s) => out.push(*s),
            None => return Err(format!("SILO_FRONT_FORCE_GO: no native rows on {item}")),
        }
    }
    Ok(out)
}

/// The refusal handler: reached only if silo-http accepts a head the relay would not vouch for, and
/// then it fails closed.
fn refusal_handler() -> BoxHandler {
    handler_fn(|w, _r| Box::pin(silo_http::error(w, "400 Bad Request", 400)))
}

/// `http.Server` in `cmd/silo/main.go`.
fn main_server_config() -> ServerConfig {
    ServerConfig {
        read_timeout: Some(Duration::from_secs(30)),
        write_timeout: Some(Duration::from_secs(120)),
        idle_timeout: Some(Duration::from_secs(120)),
        ..ServerConfig::default()
    }
}

async fn load_identity(pool: &Pool) -> Result<ServerIdentity, String> {
    let keys: &[&str] = &["jellyfin_compat.server_id", "jellyfin_compat.server_name"];
    let rows = pool
        .query(
            "SELECT key, value FROM server_settings WHERE key = ANY($1)",
            &[&keys],
        )
        .await
        .map_err(|e| e.to_string())?;
    let map: HashMap<String, String> = rows
        .iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
        .collect();
    let cfg = silo_config::config::load_from_db(&map)?;
    Ok(ServerIdentity {
        name: cfg.jellyfin_compat.server_name,
        id: cfg.jellyfin_compat.server_id,
    })
}

async fn read_trusted(pool: &Pool) -> Result<String, String> {
    let rows = pool
        .query(
            "SELECT value FROM server_settings WHERE key = $1",
            &[&SETTING_TRUSTED_PROXIES],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows
        .first()
        .map(|r| r.get::<_, String>(0))
        .unwrap_or_default())
}

/// Starts every listener and returns their bound addresses. The futures run until the process stops.
pub async fn start(cfg: FrontConfig) -> Result<Vec<(String, SocketAddr)>, String> {
    let pool = match &cfg.database_url {
        Some(url) => {
            let config = PoolConfig::parse(url).map_err(|e| format!("DATABASE_URL: {e}"))?;
            let pool = Pool::connect(config)
                .await
                .map_err(|e| format!("connecting to DATABASE_URL: {e}"))?;
            Some(pool)
        }
        None => None,
    };

    let initial = match &pool {
        Some(pool) => read_trusted(pool).await?,
        None => cfg.trusted_proxies.clone().unwrap_or_default(),
    };
    let trust = Arc::new(TrustList::parse(DEFAULT_TRUSTED_PROXIES)?);
    trust.update(&initial)?;
    if let Some(pool) = &pool {
        let pool = pool.clone();
        let trust = trust.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TRUST_POLL);
            loop {
                tick.tick().await;
                match read_trusted(&pool).await.and_then(|raw| trust.update(&raw)) {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "reloading the trusted list failed; keeping the last one")
                    }
                }
            }
        });
    }
    let loopback_trusted = trust.is_trusted(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    let identity = match &pool {
        Some(pool) => Some(load_identity(pool).await?),
        None => None,
    };
    let mut inputs = NativeInputs {
        identity,
        spa: None,
        stack: None,
    };
    if let (Some(pool), Some(secret)) = (&pool, &cfg.secret_key) {
        let stack = native::chain::build(
            Arc::new(pool.clone()),
            secret,
            cfg.redis_url.as_deref(),
            cfg.trusted_list(),
        )
        .await
        .map_err(|e| format!("building the request chain: {e}"))?;
        inputs.stack = Some(stack);
    }
    match (&cfg.web_dist, &pool) {
        (Some(dir), Some(pool)) => {
            let dist = WebDist::load(dir)
                .map_err(|e| format!("SILO_FRONT_WEB_DIST {}: {e}", dir.display()))?;
            if !dist.has_index() {
                return Err(format!(
                    "SILO_FRONT_WEB_DIST {}: no index.html",
                    dir.display()
                ));
            }
            inputs.spa = Some((dist, BrandingSource::Postgres(pool.clone())));
        }
        (Some(_), None) => {
            tracing::warn!(
                "SILO_FRONT_WEB_DIST without DATABASE_URL: the SPA reads branding, so it stays on Go"
            );
        }
        _ => {}
    }

    let origin = match &cfg.origin_log {
        Some(path) => Some(Arc::new(
            OriginLog::create(path).map_err(|e| format!("{}: {e}", path.display()))?,
        )),
        None => None,
    };
    let distinct_sources = peer::distinct_sources_available().await;

    let native_rows = native_count();
    tracing::warn!(
        "TEST ONLY: this front is a conformance tool and must not serve users until the Go server is gone. It answers {native_rows} of {} declared rows natively and forwards the rest to Go.",
        ROWS.len()
    );
    tracing::info!(
        distinct_sources,
        loopback_trusted,
        origin_log = cfg.origin_log.is_some(),
        spa = inputs.spa.is_some(),
        health = inputs.identity.is_some(),
        "front configuration"
    );
    if !distinct_sources {
        tracing::warn!(
            "this host cannot bind arbitrary 127/8 sources, so Go sees one peer for all clients behind this front"
        );
    }
    if !loopback_trusted {
        tracing::warn!(
            "the trusted list excludes loopback, so a Go server on loopback will ignore this front's X-Forwarded-For"
        );
    }

    let gate = Arc::new(Gate::new(&inputs, cfg.force_go.clone()));
    let native_server = Server::new(main_handler(&inputs), main_server_config());
    let refusals = Server::new(refusal_handler(), ServerConfig::default());

    let mut bound = Vec::new();
    for spec in &cfg.fronts {
        let upstream = lookup_host(&spec.upstream)
            .await
            .map_err(|e| format!("resolving {}: {e}", spec.upstream))?
            .next()
            .ok_or_else(|| format!("resolving {}: no address", spec.upstream))?;
        let listener = TcpListener::bind(&spec.listen)
            .await
            .map_err(|e| format!("binding {}: {e}", spec.listen))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        tracing::info!(listener = %spec.name, %addr, %upstream, "listening");
        bound.push((spec.name.clone(), addr));
        let is_main = spec.name == "main";
        let ctx = Arc::new(ListenerCtx {
            name: spec.name.clone(),
            upstream,
            trust: trust.clone(),
            origin: origin.clone(),
            native: is_main.then(|| (native_server.clone(), gate.clone())),
            refusals: refusals.clone(),
            distinct_sources,
            tunnels_tls: is_main,
        });
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        tokio::spawn(relay::serve_client(ctx.clone(), stream, peer));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });
    }
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::reconcile::{Key, Sources, denominators, reconcile};

    const INVENTORY: &str = r#"{"routes":[
        {"listener":"api","namespace":"api_v1","method":"GET","path":"/api/v1/health"},
        {"listener":"api","namespace":"api_v1","method":"GET","path":"/api/v1/health"},
        {"listener":"api","namespace":"api_v2","method":"GET","path":"/api/v2/*"},
        {"listener":"root","namespace":"legacy_unversioned","method":"GET","path":"/"}
    ]}"#;
    const OPENAPI: &str = r#"{"paths":{"/api/v2/x":{"get":{},"parameters":[]}}}"#;

    fn key(s: &str, m: &str, p: &str) -> Key {
        (s.to_owned(), m.to_owned(), p.to_owned())
    }

    fn sources() -> std::collections::BTreeMap<Key, &'static str> {
        denominators(&Sources {
            inventory: INVENTORY,
            openapi: OPENAPI,
            api_manifest: "# fixture\nGET /api/v2/x\tnon-media\nGET /api/v2/plugin-content/y\tnon-media\nGET /api/v1/health\tnon-media\n",
            jelly_manifest: "GET /System/Info\tnon-media\nGET /System/Info\tnon-media\n",
            abs_manifest: "GET /ping\tnon-media\n",
        })
        .unwrap()
    }

    fn complete_table() -> Vec<Key> {
        sources().keys().cloned().collect()
    }

    #[test]
    fn a_row_only_in_the_artifacts_fails_the_build_with_the_line_to_add() {
        let mut declared = complete_table();
        assert!(reconcile(&declared, &sources()).is_ok());
        declared.retain(|k| k.2 != "/api/v2/x");
        let msg = reconcile(&declared, &sources()).unwrap_err();
        assert!(msg.contains(r#"go(ApiV2, "GET", "/api/v2/x")"#), "{msg}");
    }

    #[test]
    fn a_row_only_in_the_table_fails_the_build() {
        let mut declared = complete_table();
        declared.push(key("ApiV1", "POST", "/api/v1/gone"));
        let msg = reconcile(&declared, &sources()).unwrap_err();
        assert!(msg.contains("delete from"), "{msg}");
        assert!(msg.contains("POST /api/v1/gone"), "{msg}");
    }

    #[test]
    fn a_row_declared_twice_fails_the_build() {
        let mut declared = complete_table();
        declared.push(key("Root", "GET", "/"));
        let msg = reconcile(&declared, &sources()).unwrap_err();
        assert!(msg.contains("declared twice"), "{msg}");
    }

    #[test]
    fn the_walked_manifest_only_adds_what_nothing_else_lists() {
        let rows = sources();
        assert!(rows.contains_key(&key("ApiV2Walked", "GET", "/api/v2/plugin-content/y")));
        assert!(!rows.contains_key(&key("ApiV2Walked", "GET", "/api/v2/x")));
        assert!(!rows.contains_key(&key("ApiV2Walked", "GET", "/api/v1/health")));
    }

    #[test]
    fn a_new_inventory_listener_fails_instead_of_being_ignored() {
        let bad = r#"{"routes":[{"listener":"new","namespace":"x","method":"GET","path":"/x"}]}"#;
        let err = denominators(&Sources {
            inventory: bad,
            openapi: OPENAPI,
            api_manifest: "",
            jelly_manifest: "",
            abs_manifest: "",
        })
        .err()
        .unwrap();
        assert!(err.contains("new listener"), "{err}");
    }
}
