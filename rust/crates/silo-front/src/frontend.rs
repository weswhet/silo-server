//! Port of `internal/server/frontend.go`: the SPA shell, the static files, and the precompressed
//! asset sidecars. The Go server embeds its build output; this reads the same tree into memory at
//! startup, so a file's modification time never reaches the wire, as with `embed.FS`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use silo_gocompat::path as gopath;
use silo_http::mime::type_by_extension;
use silo_http::response::{BoxFuture, Handler};
use silo_http::{BoxHandler, Request, ResponseWriter, error, fs::serve_content, not_found};
use silo_pg::Pool;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
    script-src 'self' 'wasm-unsafe-eval'; \
    style-src 'self' 'unsafe-inline' blob:; \
    img-src 'self' blob: data: http: https:; \
    font-src 'self' blob: data:; \
    media-src 'self' blob: http: https:; \
    connect-src 'self' ws: wss: http: https:; \
    worker-src 'self' blob:; \
    frame-src 'self' blob: https://www.youtube-nocookie.com; \
    object-src 'none'; \
    base-uri 'self'; \
    form-action 'self'";

const KEY_SERVER_NAME: &str = "branding.server_name";
const KEY_ACCENT_COLOR: &str = "branding.accent_color";
const KEY_FAVICON_REF: &str = "branding.favicon_ref";
const DEFAULT_SERVER_NAME: &str = "Silo";
const FAVICON_ASSET_URL_BASE: &str = "/api/v2/branding/assets/favicon?v=";
const INDEX_FAVICON_LINK: &str = r#"<link rel="icon" href="/favicon.ico" sizes="any" />"#;

/// Where the branding settings come from.
#[derive(Clone)]
pub enum BrandingSource {
    /// `server_settings`, read for every shell, as `Service.Load` does.
    Postgres(Pool),
    /// Fixed values, for the vectors.
    Fixed(HashMap<String, String>),
}

impl BrandingSource {
    async fn load(&self) -> Branding {
        let mut values = match self {
            BrandingSource::Fixed(v) => v.clone(),
            BrandingSource::Postgres(pool) => {
                let keys = [KEY_SERVER_NAME, KEY_ACCENT_COLOR, KEY_FAVICON_REF];
                let keys: &[&str] = &keys;
                // Service.Load tolerates a failed read and renders the defaults.
                let rows = pool
                    .query(
                        "SELECT key, value FROM server_settings WHERE key = ANY($1)",
                        &[&keys],
                    )
                    .await
                    .unwrap_or_default();
                rows.iter()
                    .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
                    .collect()
            }
        };
        let take = |values: &mut HashMap<String, String>, k: &str| {
            values
                .remove(k)
                .filter(|v| !v.is_empty())
                .unwrap_or_default()
        };
        let server_name = take(&mut values, KEY_SERVER_NAME);
        Branding {
            server_name: if server_name.is_empty() {
                DEFAULT_SERVER_NAME.to_owned()
            } else {
                server_name
            },
            accent_color: take(&mut values, KEY_ACCENT_COLOR),
            favicon_ref: take(&mut values, KEY_FAVICON_REF),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Branding {
    server_name: String,
    accent_color: String,
    favicon_ref: String,
}

/// `html.EscapeString`.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            c => out.push(c),
        }
    }
    out
}

fn replace_once(hay: &[u8], needle: &str, with: &str) -> Vec<u8> {
    let n = needle.as_bytes();
    match hay.windows(n.len()).position(|w| w == n) {
        Some(at) => {
            let mut out = Vec::with_capacity(hay.len() + with.len());
            out.extend_from_slice(&hay[..at]);
            out.extend_from_slice(with.as_bytes());
            out.extend_from_slice(&hay[at + n.len()..]);
            out
        }
        None => hay.to_vec(),
    }
}

/// `branding.RenderIndexHTML`.
fn render_index(index: &[u8], b: &Branding) -> Vec<u8> {
    let mut out = replace_once(
        index,
        "<title>Silo</title>",
        &format!("<title>{}</title>", html_escape(&b.server_name)),
    );
    if !b.favicon_ref.is_empty() {
        let url = format!("{FAVICON_ASSET_URL_BASE}{}", b.favicon_ref);
        out = replace_once(
            &out,
            INDEX_FAVICON_LINK,
            &format!(
                r#"<link rel="icon" href="{}" sizes="any" />"#,
                html_escape(&url)
            ),
        );
    }
    if !b.accent_color.is_empty() {
        let meta = format!(
            r#"<meta name="theme-color" content="{}" />"#,
            html_escape(&b.accent_color)
        );
        out = replace_once(&out, "</head>", &format!("  {meta}\n  </head>"));
    }
    out
}

/// `contentETag`.
fn content_etag(b: &[u8]) -> String {
    let sum = Sha256::digest(b);
    let mut out = String::with_capacity(34);
    out.push('"');
    for byte in &sum[..16] {
        out.push_str(&format!("{byte:02x}"));
    }
    out.push('"');
    out
}

/// The build output, in memory.
#[derive(Clone, Debug, Default)]
pub struct WebDist {
    files: BTreeMap<String, Arc<Vec<u8>>>,
    dirs: BTreeSet<String>,
}

impl WebDist {
    /// Reads every file under `root`, dotfiles included, as `//go:embed all:dist` does.
    pub fn load(root: &Path) -> std::io::Result<Self> {
        let mut dist = Self::default();
        let mut pending = vec![(root.to_path_buf(), String::new())];
        while let Some((dir, rel)) = pending.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let child = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}/{name}")
                };
                if entry.file_type()?.is_dir() {
                    dist.dirs.insert(child.clone());
                    pending.push((entry.path(), child));
                } else {
                    dist.files
                        .insert(child, Arc::new(std::fs::read(entry.path())?));
                }
            }
        }
        Ok(dist)
    }

    /// A tree from memory, for the vectors.
    pub fn from_files(files: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        let mut dist = Self::default();
        for (name, body) in files {
            let mut parent = gopath::dir(&name);
            while parent != "." {
                dist.dirs.insert(parent.clone());
                parent = gopath::dir(&parent);
            }
            dist.files.insert(name, Arc::new(body));
        }
        dist
    }

    pub fn has_index(&self) -> bool {
        self.files.contains_key("index.html")
    }

    fn file(&self, path: &str) -> Option<&Arc<Vec<u8>>> {
        self.files.get(path.strip_prefix('/').unwrap_or(path))
    }

    fn is_dir(&self, path: &str) -> bool {
        self.dirs.contains(path.strip_prefix('/').unwrap_or(path))
    }
}

/// File bytes `serve_content` can seek over without a copy.
struct Shared(Arc<Vec<u8>>);

impl AsRef<[u8]> for Shared {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

struct Shell {
    branding: Branding,
    body: Arc<Vec<u8>>,
    etag: String,
}

struct FrontendHandler {
    dist: WebDist,
    branding: BrandingSource,
    shell: Mutex<Option<Arc<Shell>>>,
}

/// `server.FrontendHandler`. Branded `/site.webmanifest` and `/favicon.ico` never reach it: they read
/// the branding service's assets, so the gate leaves them on Go.
pub fn handler(dist: WebDist, branding: BrandingSource) -> BoxHandler {
    Arc::new(FrontendHandler {
        dist,
        branding,
        shell: Mutex::new(None),
    })
}

fn is_precompressed_asset_path(path: &str) -> bool {
    [
        ".js.br", ".js.gz", ".css.br", ".css.gz", ".wasm.br", ".wasm.gz",
    ]
    .iter()
    .any(|s| path.ends_with(s))
}

/// `precompressedEncodingPreferences`: the codings to try in order, and whether identity is allowed.
fn encoding_preferences(header: &str) -> (Vec<&'static str>, bool) {
    let mut qualities: HashMap<String, f64> = HashMap::new();
    let mut wildcard = -1.0;
    for value in header.split(',') {
        let mut parts = value.split(';');
        let coding = silo_gocompat::strings::to_lower(parts.next().unwrap_or_default().trim());
        if coding.is_empty() {
            continue;
        }
        let mut quality = 1.0;
        let mut valid = true;
        for parameter in parts {
            let (key, raw) = match parameter.trim().split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (parameter.trim(), None),
            };
            if !silo_gocompat::strings::equal_fold(key.trim(), "q") {
                continue;
            }
            let Some(raw) = raw else {
                valid = false;
                break;
            };
            match silo_config::goparse::parse_float(raw.trim()) {
                Ok(q) if (0.0..=1.0).contains(&q) => quality = q,
                _ => {
                    valid = false;
                    break;
                }
            }
        }
        if !valid {
            continue;
        }
        if coding == "*" {
            wildcard = quality;
        } else {
            qualities.insert(coding, quality);
        }
    }
    let quality_for = |coding: &str| -> f64 {
        qualities
            .get(coding)
            .copied()
            .unwrap_or(if wildcard >= 0.0 { wildcard } else { 0.0 })
    };
    let br = quality_for("br");
    let gz = quality_for("gzip");
    let identity = match qualities.get("identity") {
        Some(q) => *q > 0.0,
        None => wildcard != 0.0,
    };
    if br <= 0.0 && gz <= 0.0 {
        return (Vec::new(), identity);
    }
    let mut out = Vec::with_capacity(2);
    if br >= gz {
        if br > 0.0 {
            out.push("br");
        }
        if gz > 0.0 {
            out.push("gzip");
        }
    } else {
        if gz > 0.0 {
            out.push("gzip");
        }
        if br > 0.0 {
            out.push("br");
        }
    }
    (out, identity)
}

/// `http.localRedirect`.
async fn local_redirect(w: &mut dyn ResponseWriter, r: &Request, target: &str) {
    let mut location = target.to_owned();
    if !r.url.raw_query.is_empty() {
        location.push('?');
        location.push_str(&String::from_utf8_lossy(&r.url.raw_query));
    }
    w.header().set("Location", location);
    w.write_header(301).await;
}

impl FrontendHandler {
    /// `brandedShell`.
    async fn shell(&self) -> Option<Arc<Shell>> {
        let raw = self.dist.file("index.html")?;
        let branding = self.branding.load().await;
        let cached = self
            .shell
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .filter(|s| s.branding == branding);
        if let Some(shell) = cached {
            return Some(shell);
        }
        let body = render_index(raw, &branding);
        let shell = Arc::new(Shell {
            etag: content_etag(&body),
            body: Arc::new(body),
            branding,
        });
        *self.shell.lock().unwrap_or_else(|e| e.into_inner()) = Some(shell.clone());
        Some(shell)
    }

    /// `http.FileServer(http.FS(WebDistFS))`, for a path `serve` already knows exists.
    async fn serve_file(&self, w: &mut dyn ResponseWriter, r: &Request, path: &str) {
        if path.ends_with("/index.html") {
            local_redirect(w, r, "./").await;
            return;
        }
        if self.dist.is_dir(path) {
            local_redirect(w, r, &format!("{}/", gopath::base(path))).await;
            return;
        }
        let Some(body) = self.dist.file(path) else {
            return not_found_plain(w).await;
        };
        let mut content = Cursor::new(Shared(body.clone()));
        serve_content(w, r, gopath::base(path), None, &mut content).await;
    }

    /// `servePrecompressedAsset`: true when it answered.
    async fn serve_precompressed(
        &self,
        w: &mut dyn ResponseWriter,
        r: &mut Request,
        path: &str,
    ) -> bool {
        if r.method != "GET" && r.method != "HEAD" {
            return false;
        }
        let accept = r
            .header
            .values("Accept-Encoding")
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect::<Vec<_>>()
            .join(",");
        let (encodings, identity) = encoding_preferences(&accept);
        let use_identity_range = r.method == "GET" && !r.header.get("Range").is_empty() && identity;
        if !use_identity_range {
            for encoding in encodings {
                let suffix = if encoding == "gzip" { ".gz" } else { ".br" };
                let sidecar = format!("{path}{suffix}");
                let Some(body) = self.dist.file(&sidecar) else {
                    continue;
                };
                let content_type = type_by_extension(gopath::ext(path));
                let h = w.header();
                if !content_type.is_empty() {
                    h.set("Content-Type", content_type);
                }
                h.set("Content-Encoding", encoding);
                h.set("Content-Length", body.len().to_string());
                // Range is ignored here: HEAD ignores it, and GET cannot use identity.
                r.header.del("Range");
                self.serve_file(w, r, &sidecar).await;
                return true;
            }
        }
        if !identity {
            w.write_header(406).await;
            return true;
        }
        false
    }

    async fn serve(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        w.header().set("X-Content-Type-Options", "nosniff");
        let path = String::from_utf8_lossy(&r.url.path).into_owned();
        if path.starts_with("/assets/") && is_precompressed_asset_path(&path) {
            return not_found(w, r).await;
        }
        let exists = path != "/"
            && path != "/index.html"
            && !path.ends_with('/')
            && (self.dist.file(&path).is_some() || self.dist.is_dir(&path));
        if exists {
            if path.starts_with("/assets/") {
                let h = w.header();
                h.set("Cache-Control", "public, max-age=31536000, immutable");
                h.set("Vary", "Accept-Encoding");
                if self.serve_precompressed(w, r, &path).await {
                    return;
                }
            } else {
                w.header().set("Cache-Control", "no-cache");
                if let Some(body) = self.dist.file(&path) {
                    let etag = content_etag(body);
                    w.header().set("ETag", etag);
                }
            }
            return self.serve_file(w, r, &path).await;
        }
        if path.starts_with("/assets/") {
            return not_found(w, r).await;
        }
        let Some(shell) = self.shell().await else {
            return error(w, "index.html not found", 500).await;
        };
        let h = w.header();
        h.set("Content-Type", "text/html; charset=utf-8");
        h.set("Content-Security-Policy", CONTENT_SECURITY_POLICY);
        h.set("ETag", &shell.etag);
        h.set("Cache-Control", "no-cache");
        let mut content = Cursor::new(Shared(shell.body.clone()));
        serve_content(w, r, "index.html", None, &mut content).await;
    }
}

async fn not_found_plain(w: &mut dyn ResponseWriter) {
    error(w, "404 page not found", 404).await;
}

impl Handler for FrontendHandler {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.serve(w, r))
    }
}
