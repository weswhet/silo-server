//! The Rust side of `rust/conformance/vectors/generators/silohttp/main.go`: the same handlers and
//! routers, written against silo-http, so every difference on the wire is a port bug.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use silo_gocompat::strconv::quote_bytes as q;
use silo_gocompat::time::GoTime;
use silo_gocompat::url::{path_unescape, query_unescape};
use silo_http::chi::{self, Middleware, Mux, middleware_fn, strip_slashes};
use silo_http::compress::{ResponseInfo, compress_with_exclusions};
use silo_http::fs::{file_server, serve_content, serve_file};
use silo_http::{
    BoxHandler, Header, Request, ResponseWriter, ServeMux, Server, ServerConfig, abort_handler,
    error, handler_fn, max_bytes_reader, not_found, not_found_handler, redirect, strip_prefix,
};
use tokio::net::TcpListener;

#[derive(Default)]
pub struct Side(Mutex<HashMap<String, String>>);

impl Side {
    fn record(&self, id: &str, value: &str) {
        let mut m = self.0.lock().unwrap();
        let e = m.entry(id.to_owned()).or_default();
        e.push_str(value);
        e.push('\n');
    }
}

fn qs(s: &str) -> String {
    q(s.as_bytes())
}

async fn write_echo(w: &mut dyn ResponseWriter, r: &mut Request) {
    let mut b = String::new();
    let t = |s: &[u8]| q(s);
    b += &format!(
        "method={}\nuri={}\nproto={}\nhost={}\n",
        qs(&r.method),
        t(&r.request_uri),
        qs(&r.proto),
        t(&r.host)
    );
    b += &format!(
        "path={}\nrawpath={}\nrawquery={}\nescaped={}\n",
        t(&r.url.path),
        t(&r.url.raw_path),
        t(&r.url.raw_query),
        t(&r.url.escaped_path())
    );
    b += &format!(
        "scheme={}\nurlhost={}\nstring={}\n",
        qs(&r.url.scheme),
        t(&r.url.host),
        t(&r.url.string())
    );
    b += &format!(
        "cl={}\nte={}\nclose={}\npattern={}\n",
        r.content_length,
        qs(&r.transfer_encoding.join(",")),
        r.close,
        qs(&r.pattern)
    );
    if let Some(rctx) = r.route_context() {
        b += &format!(
            "routepath={}\nroutemethod={}\nroutepattern={}\n",
            t(&rctx.route_path),
            qs(&rctx.route_method),
            qs(&rctx.route_pattern())
        );
        for p in &rctx.route_patterns {
            b += &format!("stack={}\n", qs(p));
        }
        for (i, k) in rctx.url_params.keys.iter().enumerate() {
            b += &format!("param={}:{}\n", qs(k), t(&rctx.url_params.values[i]));
            b += &format!(
                "lookup={} pathvalue={}\n",
                t(rctx.url_param(k)),
                t(r.path_value(k))
            );
        }
    }
    let names = String::from_utf8_lossy(r.header.get("X-Path-Values")).into_owned();
    for name in names.split(',').filter(|n| !n.is_empty()) {
        b += &format!("pathvalue={}:{}\n", qs(name), t(r.path_value(name)));
    }
    for (k, vv) in r.header.iter() {
        for v in vv {
            b += &format!("hdr={}:{}\n", qs(k), t(v));
        }
    }
    let (body, err) = r.read_all().await;
    b += &format!("body={}\n", t(&body));
    if let Some(e) = err {
        b += &format!("bodyerr={}\n", qs(&e.to_string()));
    }
    if let Some(trailer) = r.trailer() {
        for (k, vv) in trailer.iter() {
            let joined: Vec<u8> = vv.join(&b","[..]);
            b += &format!("trailer={}:{}\n", qs(k), t(&joined));
        }
    }
    let _ = w.write(b.as_bytes()).await;
}

pub fn echo() -> BoxHandler {
    handler_fn(|w, r| Box::pin(write_echo(w, r)))
}

fn field(parts: &[&str], i: usize) -> Vec<u8> {
    let Some(p) = parts.get(i) else {
        return Vec::new();
    };
    path_unescape(p).unwrap_or_else(|_| p.as_bytes().to_vec())
}

fn field_str(parts: &[&str], i: usize) -> String {
    String::from_utf8_lossy(&field(parts, i)).into_owned()
}

fn repeated(parts: &[&str], n: usize, c: usize) -> Vec<u8> {
    let count: usize = field_str(parts, n).parse().unwrap_or(0);
    field(parts, c).repeat(count)
}

async fn run_ops(w: &mut dyn ResponseWriter, r: &mut Request, side: &Side) {
    let id = String::from_utf8_lossy(r.header.get("X-Id")).into_owned();
    let note = |res: Option<String>| {
        if !id.is_empty() {
            side.record(&id, res.as_deref().unwrap_or("nil"));
        }
    };
    let script = String::from_utf8_lossy(r.header.get("X-Ops")).into_owned();
    for op in script.split('|') {
        let p: Vec<&str> = op.split(',').collect();
        match p[0] {
            "h" => w.header().set(&field_str(&p, 1), field(&p, 2)),
            "a" => w.header().add(&field_str(&p, 1), field(&p, 2)),
            "raw" => w.header().set_raw(field_str(&p, 1), vec![field(&p, 2)]),
            "nil" => w.header().set_raw(field_str(&p, 1), Vec::new()),
            "d" => w.header().del(&field_str(&p, 1)),
            "wh" => w.write_header(field_str(&p, 1).parse().unwrap_or(0)).await,
            "w" => {
                let data = repeated(&p, 1, 2);
                let res = w.write(&data).await;
                note(res.err().map(|e| e.to_string()));
            }
            "ws" => {
                let data = String::from_utf8_lossy(&repeated(&p, 1, 2)).into_owned();
                let res = w.write_string(&data).await;
                note(res.err().map(|e| e.to_string()));
            }
            "rf" => {
                let data = repeated(&p, 1, 2);
                let mut src = std::io::Cursor::new(data);
                let res = w.read_from(&mut src).await;
                match res {
                    Ok(n) => {
                        note(None);
                        if !id.is_empty() {
                            side.record(&id, &n.to_string());
                        }
                    }
                    Err(e) => {
                        note(Some(e.to_string()));
                        if !id.is_empty() {
                            side.record(&id, "0");
                        }
                    }
                }
            }
            "f" => {
                let res = w.flush().await;
                note(res.err().map(|e| e.to_string()));
            }
            "rb" => {
                let (data, err) = r.read_all().await;
                if !id.is_empty() {
                    side.record(&id, &format!("read {}", data.len()));
                }
                note(err.map(|e| e.to_string()));
            }
            "rn" => {
                let n: usize = field_str(&p, 1).parse().unwrap_or(0);
                let mut buf = vec![0u8; n];
                let mut got = 0;
                let mut err = None;
                while got < n {
                    match r.body().read(&mut buf[got..]).await {
                        Ok(0) => {
                            err = Some(if got == 0 {
                                "EOF".to_owned()
                            } else {
                                "unexpected EOF".to_owned()
                            });
                            break;
                        }
                        Ok(k) => got += k,
                        Err(e) => {
                            err = Some(e.to_string());
                            break;
                        }
                    }
                }
                if !id.is_empty() {
                    side.record(&id, &format!("read {got}"));
                }
                note(err);
            }
            "cb" => {
                let res = r.body().close().await;
                note(res.err().map(|e| e.to_string()));
            }
            "mb" => {
                let n: i64 = field_str(&p, 1).parse().unwrap_or(0);
                let body = r.take_body();
                let limited = max_bytes_reader(&*w, body, n);
                r.set_body(limited);
            }
            "fd" => {
                let res = w.enable_full_duplex();
                note(res.err().map(|e| e.to_string()));
            }
            "e" => error(w, &field_str(&p, 2), field_str(&p, 1).parse().unwrap_or(0)).await,
            "nf" => not_found(w, r).await,
            "rd" => {
                redirect(
                    w,
                    r,
                    &field_str(&p, 2),
                    field_str(&p, 1).parse().unwrap_or(0),
                )
                .await
            }
            "panic" => panic!("boom"),
            "abort" => abort_handler(),
            "hj" => match w.hijack().await {
                Err(e) => {
                    note(Some(e.to_string()));
                    return;
                }
                Ok(mut h) => {
                    use tokio::io::AsyncWriteExt;
                    let line = format!("hijacked {} {}", q(&h.read_buf), field_str(&p, 1));
                    let _ = h.io.write_all(line.as_bytes()).await;
                    let _ = h.io.shutdown().await;
                    return;
                }
            },
            "waitctx" => {
                r.cancel.cancelled().await;
                side.record(&id, "canceled");
            }
            "sleep" => {
                tokio::time::sleep(Duration::from_millis(field_str(&p, 1).parse().unwrap_or(0)))
                    .await
            }
            "echo" => write_echo(w, r).await,
            _ => {}
        }
    }
}

fn ops(side: Arc<Side>) -> BoxHandler {
    handler_fn(move |w, r| {
        let side = side.clone();
        Box::pin(async move { run_ops(w, r, &side).await })
    })
}

fn query_map(r: &Request) -> BTreeMap<String, Vec<u8>> {
    let mut m = BTreeMap::new();
    for kv in r.url.raw_query.split(|&b| b == b'&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = match kv.iter().position(|&b| b == b'=') {
            Some(i) => (&kv[..i], &kv[i + 1..]),
            None => (kv, &kv[kv.len()..]),
        };
        let k = String::from_utf8_lossy(&query_unescape(k).unwrap_or_default()).into_owned();
        m.entry(k)
            .or_insert_with(|| query_unescape(v).unwrap_or_default());
    }
    m
}

fn content(root: PathBuf) -> BoxHandler {
    handler_fn(move |w, r| {
        let root = root.clone();
        Box::pin(async move {
            let qmap = query_map(r);
            for (qk, h) in [
                ("etag", "Etag"),
                ("ct", "Content-Type"),
                ("ce", "Content-Encoding"),
                ("cc", "Cache-Control"),
                ("lm", "Last-Modified"),
            ] {
                if let Some(v) = qmap.get(qk) {
                    w.header().set(h, v);
                }
            }
            if qmap.contains_key("noct") {
                w.header().set_raw("Content-Type", Vec::new());
            }
            let f =
                String::from_utf8_lossy(qmap.get("f").map_or(&[][..], Vec::as_slice)).into_owned();
            let path =
                silo_gocompat::filepath::join(&[root.to_string_lossy().as_ref(), f.as_str()]);
            let Ok(mut file) = tokio::fs::File::open(&path).await else {
                error(w, "missing fixture", 500).await;
                return;
            };
            let modtime = match qmap
                .get("mod")
                .map(|m| String::from_utf8_lossy(m).into_owned())
                .as_deref()
            {
                None | Some("") => Some(GoTime::from_unix(1_700_000_000, 0)),
                Some("zero") => None,
                Some("epoch") => Some(GoTime::from_unix(0, 0)),
                Some("nanos") => Some(GoTime::from_unix(1_700_000_000, 123_456_789)),
                Some(_) => None,
            };
            let name = match qmap.get("name") {
                Some(n) => String::from_utf8_lossy(n).into_owned(),
                None => f.clone(),
            };
            serve_content(w, r, &name, modtime, &mut file).await;
        })
    })
}

fn mw(name: &'static str) -> Middleware {
    middleware_fn(move |next| {
        handler_fn(move |w, r| {
            let next = next.clone();
            Box::pin(async move {
                w.header().add("X-Mw", name);
                next.serve_http(w, r).await;
            })
        })
    })
}

fn text(s: &'static str) -> BoxHandler {
    handler_fn(move |w, _r| {
        Box::pin(async move {
            w.header().set("X-Custom", s);
            w.write_header(418).await;
            let _ = w.write(s.as_bytes()).await;
        })
    })
}

fn adversarial() -> Mux {
    let h = echo();
    let r = Mux::new();
    r.get("/s/static", h.clone());
    r.get("/s/{id}", h.clone());
    r.get("/s/{id}/x", h.clone());
    r.get("/s/*", h.clone());
    r.get("/m/{a}.{b}", h.clone());
    r.get("/m/{a}-{b}.{c}", h.clone());
    r.get("/m/{name}.jpg", h.clone());
    r.get("/m/pre-{x}", h.clone());
    r.get("/m/pre-{x}/post", h.clone());
    r.get("/m/{x}-suf", h.clone());
    r.get(
        "/Videos/{id}/hls/{playlistId}/{segmentId}.{segmentContainer}",
        h.clone(),
    );
    r.get("/Videos/{itemId}/Trickplay/{width}/{index}.jpg", h.clone());
    r.get("/feed/{slug}.xml", h.clone());
    r.get("/r/{id:[0-9]+}", h.clone());
    r.get("/r/{id:[a-z]+}", h.clone());
    r.get(r"/r/{slug:[a-z-]+}/{n:\d+}", h.clone());
    r.get(r"/r/{date:\d{4}-\d{2}-\d{2}}", h.clone());
    r.get("/r/{any:.*}/end", h.clone());
    r.get(r"/r/{u:\p{L}+}x", h.clone());
    r.get("/r/{e:}/empty", h.clone());
    r.get("/mm", h.clone());
    r.post("/mm", h.clone());
    r.put("/mm/{x}", h.clone());
    r.delete("/mm/{x}", h.clone());
    r.head("/h", h.clone());
    r.method("QUERY", "/q", h.clone());
    r.connect("/c", h.clone());
    r.trace("/t", h.clone());
    r.options("/o", h.clone());
    r.patch("/p", h.clone());
    r.handle("/all", h.clone());
    r.handle("GET /spaced", h.clone());
    r.handle("POST\t/tabbed", h.clone());
    let hh = h.clone();
    r.route("/sub", move |s| {
        s.get("/", hh.clone());
        s.get("/a", hh.clone());
        s.get("/{p}", hh.clone());
        let hhh = hh.clone();
        s.route("/deep", move |d| {
            d.get("/", hhh.clone());
            d.get("/{q}", hhh.clone());
            d.post("/*", hhh.clone());
        });
    });
    r.mount("/mnt", h.clone());
    let own = Mux::new();
    own.not_found(text("own-404"));
    own.method_not_allowed(text("own-405"));
    own.get("/x", h.clone());
    r.mount("/own", own);
    let inherit = Mux::new();
    inherit.get("/x", h.clone());
    r.mount("/inherit", inherit);
    r.with([mw("with")]).get("/with", h.clone());
    r.with([mw("with1"), mw("with2")])
        .with([mw("with3")])
        .post("/with", h.clone());
    let hh = h.clone();
    r.group(move |g| {
        g.use_middleware([mw("grp")]);
        g.get("/grp", hh.clone());
        let hhh = hh.clone();
        g.group(move |gg| {
            gg.use_middleware([mw("grp2")]);
            gg.get("/grp2", hhh.clone());
        });
    });
    let hh = h.clone();
    r.route("/{tenant}/v", move |s| {
        s.use_middleware([mw("tenant")]);
        s.get("/{id}", hh.clone());
        s.get("/", hh.clone());
    });
    r
}

fn with_handlers() -> Mux {
    let h = echo();
    let r = Mux::new();
    r.use_middleware([mw("root")]);
    let sub = Mux::new();
    sub.get("/x", h.clone());
    r.mount("/sub", sub);
    r.get("/only-get", h.clone());
    r.not_found(text("custom-404"));
    r.method_not_allowed(text("custom-405"));
    let late = Mux::new();
    late.get("/x", h.clone());
    r.mount("/late", late);
    r.with([mw("inline")]).not_found(text("inline-404"));
    r
}

fn canonicalize(path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len());
    for (i, part) in path.split(|&b| b == b'/').enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        let lower = silo_gocompat::strings::to_lower(&String::from_utf8_lossy(part));
        match lower.as_str() {
            "items" => out.extend_from_slice(b"Items"),
            "users" => out.extend_from_slice(b"Users"),
            "system" => out.extend_from_slice(b"System"),
            _ => out.extend_from_slice(part),
        }
    }
    out
}

fn rewriting() -> Mux {
    let h = echo();
    let r = Mux::new();
    r.use_middleware([middleware_fn(|next: BoxHandler| {
        let stripped = strip_slashes(next.clone());
        handler_fn(move |w, r| {
            let (next, stripped) = (next.clone(), stripped.clone());
            Box::pin(async move {
                if r.url.path == b"/web" || r.url.path.starts_with(b"/web/") {
                    next.serve_http(w, r).await;
                    return;
                }
                stripped.serve_http(w, r).await;
            })
        })
    })]);
    r.use_middleware([middleware_fn(|next: BoxHandler| {
        handler_fn(move |w, r| {
            let next = next.clone();
            Box::pin(async move {
                if let Some(rctx) = r.route_context_mut()
                    && !rctx.route_path.is_empty()
                {
                    rctx.route_path = canonicalize(&rctx.route_path);
                }
                let normalized = canonicalize(&r.url.path);
                if normalized == r.url.path {
                    next.serve_http(w, r).await;
                    return;
                }
                r.url.raw_path.clone_from(&normalized);
                r.url.path = normalized;
                next.serve_http(w, r).await;
            })
        })
    })]);
    r.get("/Items", h.clone());
    r.get("/Items/{id}", h.clone());
    r.get("/Users/{id}/Items", h.clone());
    r.get("/System/Info/Public", h.clone());
    r.get("/web", h.clone());
    r.get("/web/", h.clone());
    r.get("/web/*", h.clone());
    r
}

fn redirecting() -> Mux {
    let h = echo();
    let r = Mux::new();
    r.use_middleware([middleware_fn(chi::redirect_slashes)]);
    r.get("/a", h.clone());
    r.get("/a/b", h);
    r
}

/// Real axum handlers behind the mux, through `Handler::with_state` and the `Params` extractor.
fn bridge() -> Mux {
    use axum::handler::Handler as _;
    use axum::http::StatusCode;
    use silo_http::tower_bridge::{Params, service_handler};

    async fn get(
        Params(p): Params,
        axum::extract::State(state): axum::extract::State<&'static str>,
    ) -> impl axum::response::IntoResponse {
        let id =
            String::from_utf8_lossy(p.values.first().map_or(&[][..], Vec::as_slice)).into_owned();
        (
            StatusCode::CREATED,
            [("content-type", "text/x"), ("x-state", state)],
            format!("id={id}"),
        )
    }
    async fn post(method: axum::http::Method, body: String) -> impl axum::response::IntoResponse {
        ([("content-type", "text/x")], format!("{method} {body}"))
    }

    let r = Mux::new();
    r.get("/b/{id}", service_handler(get.with_state("state")));
    r.post("/b/{id}", service_handler(post.with_state(())));
    r
}

pub type Routes = Vec<(String, String)>;

pub fn inventory(repo: &Path, listener: &str) -> Routes {
    let data = std::fs::read(silo_gocompat::filepath::join(&[
        repo.to_string_lossy().as_ref(),
        "contracts/api/v2/route-inventory.json",
    ]))
    .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&data).unwrap();
    doc["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["listener"] == listener)
        .map(|r| {
            (
                r["method"].as_str().unwrap().to_owned(),
                r["path"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

pub fn media_routes(repo: &Path, rel: &str) -> Routes {
    let data = std::fs::read_to_string(silo_gocompat::filepath::join(&[
        repo.to_string_lossy().as_ref(),
        rel,
    ]))
    .unwrap();
    let mut out = Vec::new();
    for line in data.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let first = line.split('\t').next().unwrap();
        if let Some((m, p)) = first.split_once(' ') {
            out.push((m.to_owned(), p.to_owned()));
        }
    }
    out
}

fn chi_from(routes: &Routes) -> Mux {
    let r = Mux::new();
    let h = echo();
    for (m, p) in routes {
        r.method(m, p, h.clone());
    }
    r
}

fn mux_from(routes: &Routes) -> ServeMux {
    let m = ServeMux::new();
    let mut seen = Vec::new();
    for (_, p) in routes {
        if !seen.contains(p) {
            seen.push(p.clone());
            m.handle(p, echo());
        }
    }
    m
}

fn root_mux(api: BoxHandler) -> ServeMux {
    let m = ServeMux::new();
    m.handle("/metrics", not_found_handler());
    m.handle("/api/", api);
    m.handle("/", echo());
    m
}

fn pattern_mux() -> ServeMux {
    let m = ServeMux::new();
    for p in [
        "GET /static/",
        "POST /items/{id}",
        "PUT /items/{id}",
        "/files/{path...}",
        "/exact/{$}",
        "example.com/hosted/",
        "/hosted/",
        "/a%2fb/",
        "CONNECT /conn",
        "HEAD /headonly",
        "/tree/",
        "GET /w/{a}/seg/{b}",
    ] {
        m.handle(p, echo());
    }
    m
}

pub struct RustSide {
    pub ports: BTreeMap<String, u16>,
    pub side: Arc<Side>,
    pub walked: BTreeMap<String, Mux>,
}

impl RustSide {
    pub fn side_value(&self, id: &str) -> String {
        self.side
            .0
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default()
    }
}

async fn listen(
    name: &str,
    handler: BoxHandler,
    config: ServerConfig,
    ports: &mut BTreeMap<String, u16>,
) {
    let ln = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    ports.insert(name.to_owned(), ln.local_addr().unwrap().port());
    let srv = Server::new(handler, config);
    tokio::spawn(async move {
        let _ = srv.serve(ln).await;
    });
}

pub async fn start(repo: &Path, files: &Path) -> RustSide {
    let side = Arc::new(Side::default());
    let mut ports = BTreeMap::new();
    let c = ServerConfig::default;

    let chi_api = chi_from(&inventory(repo, "api"));
    let adv = adversarial();
    let handlers = with_handlers();
    let rewrite = rewriting();
    let redirects = redirecting();

    let media_api = "internal/api/testdata/media_routes.txt";
    let media_jelly = "internal/jellycompat/testdata/media_routes.txt";
    let media_abs = "internal/audiobooks/abs/testdata/media_routes.txt";
    let media_proxy = "internal/proxy/testdata/media_routes.txt";
    let media_node = "internal/transcodenode/testdata/media_routes.txt";

    let chis: Vec<(&str, Mux)> = vec![
        ("chi-api", chi_api.clone()),
        ("chi-proxy", chi_from(&inventory(repo, "proxy"))),
        (
            "chi-transcode",
            chi_from(&inventory(repo, "transcode_node")),
        ),
        ("chi-media-api", chi_from(&media_routes(repo, media_api))),
        (
            "chi-media-jelly",
            chi_from(&media_routes(repo, media_jelly)),
        ),
        ("chi-media-abs", chi_from(&media_routes(repo, media_abs))),
        (
            "chi-media-proxy",
            chi_from(&media_routes(repo, media_proxy)),
        ),
        ("chi-media-node", chi_from(&media_routes(repo, media_node))),
        ("chi-adv", adv.clone()),
        ("chi-handlers", handlers.clone()),
        ("chi-rewrite", rewrite.clone()),
        ("chi-redirect", redirects),
    ];
    for (name, m) in chis {
        listen(name, Arc::new(m), c(), &mut ports).await;
    }
    listen(
        "mux-root",
        Arc::new(root_mux(Arc::new(chi_api.clone()))),
        c(),
        &mut ports,
    )
    .await;
    listen(
        "mux-debug",
        Arc::new(mux_from(&inventory(repo, "operational_debug"))),
        c(),
        &mut ports,
    )
    .await;
    listen(
        "mux-metrics",
        Arc::new(mux_from(&inventory(repo, "operational_metrics"))),
        c(),
        &mut ports,
    )
    .await;
    listen("mux-patterns", Arc::new(pattern_mux()), c(), &mut ports).await;
    listen("ops", ops(side.clone()), c(), &mut ports).await;
    listen("content", content(files.to_path_buf()), c(), &mut ports).await;

    let root = files.to_path_buf();
    let servefile = handler_fn(move |w, r| {
        let root = root.clone();
        Box::pin(async move {
            let qmap = query_map(r);
            let f =
                String::from_utf8_lossy(qmap.get("f").map_or(&[][..], Vec::as_slice)).into_owned();
            let path =
                silo_gocompat::filepath::join(&[root.to_string_lossy().as_ref(), f.as_str()]);
            serve_file(w, r, &path).await;
        })
    });
    listen("servefile", servefile, c(), &mut ports).await;
    listen(
        "fileserver",
        strip_prefix("/pub", file_server(files.to_path_buf())),
        c(),
        &mut ports,
    )
    .await;

    let compress_all = compress_with_exclusions(None, None, &[])(ops(side.clone()));
    listen("compress", compress_all, c(), &mut ports).await;
    let skip: silo_http::compress::SkipResponse =
        Arc::new(|_: &ResponseInfo, h: &Header| !h.get("X-No-Compress").is_empty());
    let compress_types =
        compress_with_exclusions(None, Some(skip), &["text/custom"])(ops(side.clone()));
    listen("compress-types", compress_types, c(), &mut ports).await;
    listen(
        "opts-off",
        ops(side.clone()),
        ServerConfig {
            disable_general_options_handler: true,
            ..ServerConfig::default()
        },
        &mut ports,
    )
    .await;
    listen(
        "timeouts",
        ops(side.clone()),
        ServerConfig {
            read_header_timeout: Some(Duration::from_millis(200)),
            idle_timeout: Some(Duration::from_millis(200)),
            ..ServerConfig::default()
        },
        &mut ports,
    )
    .await;
    listen(
        "smallheaders",
        echo(),
        ServerConfig {
            max_header_bytes: 1024,
            ..ServerConfig::default()
        },
        &mut ports,
    )
    .await;

    listen(
        "timeouts-write",
        ops(side.clone()),
        ServerConfig {
            write_timeout: Some(Duration::from_millis(150)),
            ..ServerConfig::default()
        },
        &mut ports,
    )
    .await;
    listen(
        "timeouts-read",
        ops(side.clone()),
        ServerConfig {
            read_timeout: Some(Duration::from_millis(150)),
            ..ServerConfig::default()
        },
        &mut ports,
    )
    .await;
    listen("bridge", Arc::new(bridge()), c(), &mut ports).await;

    let mut walked = BTreeMap::new();
    walked.insert("chi-adv".to_owned(), adv);
    walked.insert("chi-handlers".to_owned(), handlers);
    walked.insert("chi-rewrite".to_owned(), rewrite);
    walked.insert("chi-api".to_owned(), chi_api);

    RustSide {
        ports,
        side,
        walked,
    }
}
