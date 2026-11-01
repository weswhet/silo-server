//! Port of chi's `mux.go` and `chain.go`.

use std::sync::{Arc, RwLock, Weak};

use crate::chi::context::Context;
use crate::chi::tree::{self, M_STUB, Tree, m_all, method_bit, method_name};
use crate::request::Request;
use crate::response::{
    BoxFuture, BoxHandler, Handler, ResponseWriter, handler_fn, not_found_handler,
};

/// `func(http.Handler) http.Handler`.
pub type Middleware = Arc<dyn Fn(BoxHandler) -> BoxHandler + Send + Sync>;

/// Wraps a closure as a [`Middleware`].
pub fn middleware_fn<F>(f: F) -> Middleware
where
    F: Fn(BoxHandler) -> BoxHandler + Send + Sync + 'static,
{
    Arc::new(f)
}

/// `chi.chain`.
pub fn chain(middlewares: &[Middleware], endpoint: BoxHandler) -> BoxHandler {
    let mut h = endpoint;
    for m in middlewares.iter().rev() {
        h = m(h);
    }
    h
}

/// `chi.ChainHandler`.
pub struct ChainHandler {
    /// `Endpoint`.
    pub endpoint: BoxHandler,
    chain: BoxHandler,
    /// `Middlewares`.
    pub middlewares: Vec<Middleware>,
}

impl Handler for ChainHandler {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        self.chain.serve_http(w, r)
    }
    fn as_chain(&self) -> Option<&ChainHandler> {
        Some(self)
    }
}

/// `Middlewares.Handler`.
fn chain_handler(mws: &[Middleware], h: BoxHandler) -> BoxHandler {
    Arc::new(ChainHandler {
        endpoint: h.clone(),
        chain: chain(mws, h),
        middlewares: mws.to_vec(),
    })
}

struct MuxInner {
    handler: RwLock<Option<BoxHandler>>,
    tree: Arc<RwLock<Tree>>,
    method_not_allowed: RwLock<Option<BoxHandler>>,
    parent: Option<Mux>,
    not_found: RwLock<Option<BoxHandler>>,
    middlewares: RwLock<Vec<Middleware>>,
    inline: bool,
}

/// `chi.Mux`. Cloning shares the same router, like copying Go's `*Mux`.
#[derive(Clone)]
pub struct Mux(Arc<MuxInner>);

/// What `Mux.Mount` can mount: Go checks `handler.(*Mux)` and `handler.(Routes)`.
pub enum Mounted {
    /// A chi router, which `Walk` and `Find` recurse into and which inherits 404 and 405 handlers.
    Mux(Mux),
    /// Any other handler.
    Handler(BoxHandler),
}

impl From<Mux> for Mounted {
    fn from(m: Mux) -> Self {
        Mounted::Mux(m)
    }
}

impl From<BoxHandler> for Mounted {
    fn from(h: BoxHandler) -> Self {
        Mounted::Handler(h)
    }
}

fn read<T: Clone>(l: &RwLock<T>) -> T {
    l.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn write<T>(l: &RwLock<T>, v: T) {
    *l.write().unwrap_or_else(std::sync::PoisonError::into_inner) = v;
}

impl Default for Mux {
    fn default() -> Self {
        Self::new()
    }
}

impl Mux {
    /// `chi.NewMux` and `chi.NewRouter`.
    pub fn new() -> Self {
        Self(Arc::new(MuxInner {
            handler: RwLock::new(None),
            tree: Arc::new(RwLock::new(Tree::new())),
            method_not_allowed: RwLock::new(None),
            parent: None,
            not_found: RwLock::new(None),
            middlewares: RwLock::new(Vec::new()),
            inline: false,
        }))
    }

    fn tree_read(&self) -> std::sync::RwLockReadGuard<'_, Tree> {
        self.0
            .tree
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn tree_write(&self) -> std::sync::RwLockWriteGuard<'_, Tree> {
        self.0
            .tree
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `mx.Use`.
    pub fn use_middleware(&self, middlewares: impl IntoIterator<Item = Middleware>) {
        assert!(
            read(&self.0.handler).is_none(),
            "chi: all middlewares must be defined before routes on a mux"
        );
        self.0
            .middlewares
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(middlewares);
    }

    /// `mx.Handle`: every method, or `"METHOD pattern"`.
    pub fn handle(&self, pattern: &str, handler: BoxHandler) {
        if let Some(i) = pattern.find([' ', '\t']) {
            let method = &pattern[..i];
            let rest = pattern[i + 1..].trim_start_matches([' ', '\t']);
            self.method(method, rest, handler);
            return;
        }
        self.handle_inner(m_all(), pattern, handler);
    }

    /// `mx.Method`.
    pub fn method(&self, method: &str, pattern: &str, handler: BoxHandler) {
        let upper = silo_gocompat::strings::to_upper(method);
        let m = method_bit(&upper)
            .unwrap_or_else(|| panic!("chi: '{method}' http method is not supported."));
        self.handle_inner(m, pattern, handler);
    }

    /// `mx.Connect`.
    pub fn connect(&self, pattern: &str, h: BoxHandler) {
        self.method("CONNECT", pattern, h);
    }
    /// `mx.Delete`.
    pub fn delete(&self, pattern: &str, h: BoxHandler) {
        self.method("DELETE", pattern, h);
    }
    /// `mx.Get`.
    pub fn get(&self, pattern: &str, h: BoxHandler) {
        self.method("GET", pattern, h);
    }
    /// `mx.Head`.
    pub fn head(&self, pattern: &str, h: BoxHandler) {
        self.method("HEAD", pattern, h);
    }
    /// `mx.Options`.
    pub fn options(&self, pattern: &str, h: BoxHandler) {
        self.method("OPTIONS", pattern, h);
    }
    /// `mx.Patch`.
    pub fn patch(&self, pattern: &str, h: BoxHandler) {
        self.method("PATCH", pattern, h);
    }
    /// `mx.Post`.
    pub fn post(&self, pattern: &str, h: BoxHandler) {
        self.method("POST", pattern, h);
    }
    /// `mx.Put`.
    pub fn put(&self, pattern: &str, h: BoxHandler) {
        self.method("PUT", pattern, h);
    }
    /// `mx.Query`.
    pub fn query(&self, pattern: &str, h: BoxHandler) {
        self.method("QUERY", pattern, h);
    }
    /// `mx.Trace`.
    pub fn trace(&self, pattern: &str, h: BoxHandler) {
        self.method("TRACE", pattern, h);
    }

    /// `mx.NotFound`.
    pub fn not_found(&self, handler: BoxHandler) {
        let (m, h) = match (&self.0.inline, &self.0.parent) {
            (true, Some(parent)) => (
                parent.clone(),
                chain_handler(&read(&self.0.middlewares), handler),
            ),
            _ => (self.clone(), handler),
        };
        write(&m.0.not_found, Some(h.clone()));
        m.update_sub_routes(|sub| {
            if read(&sub.0.not_found).is_none() {
                sub.not_found(h.clone());
            }
        });
    }

    /// `mx.MethodNotAllowed`.
    pub fn method_not_allowed(&self, handler: BoxHandler) {
        let (m, h) = match (&self.0.inline, &self.0.parent) {
            (true, Some(parent)) => (
                parent.clone(),
                chain_handler(&read(&self.0.middlewares), handler),
            ),
            _ => (self.clone(), handler),
        };
        write(&m.0.method_not_allowed, Some(h.clone()));
        m.update_sub_routes(|sub| {
            if read(&sub.0.method_not_allowed).is_none() {
                sub.method_not_allowed(h.clone());
            }
        });
    }

    /// `mx.With`.
    pub fn with(&self, middlewares: impl IntoIterator<Item = Middleware>) -> Mux {
        if !self.0.inline && read(&self.0.handler).is_none() {
            self.update_route_handler();
        }
        let mut mws = if self.0.inline {
            read(&self.0.middlewares)
        } else {
            Vec::new()
        };
        mws.extend(middlewares);
        Mux(Arc::new(MuxInner {
            handler: RwLock::new(None),
            tree: self.0.tree.clone(),
            method_not_allowed: RwLock::new(read(&self.0.method_not_allowed)),
            parent: Some(self.clone()),
            not_found: RwLock::new(read(&self.0.not_found)),
            middlewares: RwLock::new(mws),
            inline: true,
        }))
    }

    /// `mx.Group`.
    pub fn group(&self, f: impl FnOnce(&Mux)) -> Mux {
        let im = self.with([]);
        f(&im);
        im
    }

    /// `mx.Route`.
    pub fn route(&self, pattern: &str, f: impl FnOnce(&Mux)) -> Mux {
        let sub = Mux::new();
        f(&sub);
        self.mount(pattern, sub.clone());
        sub
    }

    /// `mx.Mount`.
    pub fn mount(&self, pattern: &str, handler: impl Into<Mounted>) {
        let mounted = handler.into();
        let exists = {
            let t = self.tree_read();
            t.find_pattern(0, &format!("{pattern}*")) || t.find_pattern(0, &format!("{pattern}/*"))
        };
        assert!(
            !exists,
            "chi: attempting to Mount() a handler on an existing path, '{pattern}'"
        );

        if let Mounted::Mux(subr) = &mounted {
            assert!(
                !Arc::ptr_eq(&subr.0.tree, &self.0.tree),
                "chi: attempting to Mount() a router onto itself on '{pattern}'"
            );
            if read(&subr.0.not_found).is_none()
                && let Some(nf) = read(&self.0.not_found)
            {
                subr.not_found(nf);
            }
            if read(&subr.0.method_not_allowed).is_none()
                && let Some(mna) = read(&self.0.method_not_allowed)
            {
                subr.method_not_allowed(mna);
            }
        }

        let (target, subroutes): (BoxHandler, Option<Mux>) = match mounted {
            Mounted::Mux(m) => (Arc::new(m.clone()), Some(m)),
            Mounted::Handler(h) => (h, None),
        };
        let mount_handler: BoxHandler = Arc::new(MountHandler { handler: target });

        let mut pattern = pattern.to_owned();
        if pattern.is_empty() || !pattern.ends_with('/') {
            self.handle_inner(m_all() | M_STUB, &pattern, mount_handler.clone());
            self.handle_inner(
                m_all() | M_STUB,
                &format!("{pattern}/"),
                mount_handler.clone(),
            );
            pattern.push('/');
        }

        let mut method = m_all();
        if subroutes.is_some() {
            method |= M_STUB;
        }
        let n = self.handle_inner(method, &format!("{pattern}*"), mount_handler);
        if let Some(sub) = subroutes {
            self.tree_write().set_subroutes(n, sub);
        }
    }

    /// `mx.Routes`.
    pub fn routes(&self) -> Vec<tree::Route> {
        self.tree_read().routes()
    }

    /// `mx.Middlewares`.
    pub fn middlewares(&self) -> Vec<Middleware> {
        read(&self.0.middlewares)
    }

    /// `mx.Match`.
    pub fn match_route(&self, rctx: &mut Context, method: &str, path: &[u8]) -> bool {
        !self.find(rctx, method, path).is_empty()
    }

    /// `mx.Find`.
    pub fn find(&self, rctx: &mut Context, method: &str, path: &[u8]) -> String {
        let Some(m) = method_bit(method) else {
            return String::new();
        };
        let (node, ep_pattern, sub) = {
            let t = self.tree_read();
            let found = t.find_route(rctx, m, path);
            match found {
                Some((n, _)) => (
                    Some(n),
                    t.endpoint_pattern(n, m),
                    t.subroutes_of(n).cloned(),
                ),
                None => (None, None, None),
            }
        };
        let mut pattern = rctx.route_pattern.clone();
        if node.is_some() {
            let Some(sub) = sub else {
                return ep_pattern.map(|p| p.to_string()).unwrap_or_default();
            };
            rctx.route_path = next_route_path(rctx);
            let path = rctx.route_path.clone();
            let sub_pattern = sub.find(rctx, method, &path);
            if sub_pattern.is_empty() {
                return String::new();
            }
            if let Some(stripped) = pattern.strip_suffix("/*") {
                pattern = stripped.to_owned();
            }
            pattern.push_str(&sub_pattern);
        }
        pattern
    }

    /// `mx.NotFoundHandler`.
    pub fn not_found_handler(&self) -> BoxHandler {
        read(&self.0.not_found).unwrap_or_else(not_found_handler)
    }

    /// `mx.MethodNotAllowedHandler`.
    fn method_not_allowed_handler(&self, methods_allowed: &[u64]) -> BoxHandler {
        if let Some(h) = read(&self.0.method_not_allowed) {
            return h;
        }
        default_method_not_allowed(methods_allowed.to_vec())
    }

    /// `mx.handle`.
    fn handle_inner(&self, method: u64, pattern: &str, handler: BoxHandler) -> usize {
        assert!(
            pattern.starts_with('/'),
            "chi: routing pattern must begin with '/' in '{pattern}'"
        );
        if !self.0.inline && read(&self.0.handler).is_none() {
            self.update_route_handler();
        }
        let h = if self.0.inline {
            write(&self.0.handler, Some(self.route_http_handler()));
            chain_handler(&read(&self.0.middlewares), handler)
        } else {
            handler
        };
        self.tree_write().insert_route(method, pattern, h)
    }

    fn route_http_handler(&self) -> BoxHandler {
        Arc::new(RouteHttp(Arc::downgrade(&self.0)))
    }

    fn update_route_handler(&self) {
        write(
            &self.0.handler,
            Some(chain(&read(&self.0.middlewares), self.route_http_handler())),
        );
    }

    fn update_sub_routes(&self, f: impl Fn(&Mux)) {
        for r in self.routes() {
            if let Some(sub) = &r.sub_routes {
                f(sub);
            }
        }
    }
}

/// `mx.nextRoutePath`.
fn next_route_path(rctx: &Context) -> Vec<u8> {
    let mut out = b"/".to_vec();
    let keys = &rctx.route_params.keys;
    if let Some(nx) = keys.len().checked_sub(1)
        && &*keys[nx] == "*"
        && rctx.route_params.values.len() > nx
    {
        out.extend_from_slice(&rctx.route_params.values[nx]);
    }
    out
}

/// The `mountHandler` closure in `mx.Mount`.
struct MountHandler {
    handler: BoxHandler,
}

impl Handler for MountHandler {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        if let Some(rctx) = r.route_ctx.as_deref_mut() {
            rctx.route_path = next_route_path(rctx);
            let n = rctx.url_params.keys.len().wrapping_sub(1);
            if n < rctx.url_params.keys.len()
                && &*rctx.url_params.keys[n] == "*"
                && rctx.url_params.values.len() > n
            {
                rctx.url_params.values[n].clear();
            }
        }
        self.handler.serve_http(w, r)
    }
}

/// `mx.routeHTTP`. Holds the mux weakly: the mux owns this handler, and a strong reference would
/// keep every router alive forever.
struct RouteHttp(Weak<MuxInner>);

impl Handler for RouteHttp {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let Some(inner) = self.0.upgrade() else {
                return;
            };
            let mx = Mux(inner);
            let mut rctx = r.route_ctx.take().unwrap_or_default();

            let mut route_path = rctx.route_path.clone();
            if route_path.is_empty() {
                route_path = if r.url.raw_path.is_empty() {
                    r.url.path.clone()
                } else {
                    r.url.raw_path.clone()
                };
                if route_path.is_empty() {
                    route_path = b"/".to_vec();
                }
            }

            if rctx.route_method.is_empty() {
                rctx.route_method.clone_from(&r.method);
            }
            let Some(method) = method_bit(&rctx.route_method) else {
                r.route_ctx = Some(rctx);
                mx.method_not_allowed_handler(&[]).serve_http(w, r).await;
                return;
            };

            let found = mx.tree_read().find_route(&mut rctx, method, &route_path);
            if let Some((_, Some(h))) = found {
                for (key, value) in rctx.url_params.keys.iter().zip(&rctx.url_params.values) {
                    r.set_path_value(key, value.clone());
                }
                r.pattern = rctx.route_pattern();
                r.route_ctx = Some(rctx);
                h.serve_http(w, r).await;
                return;
            }
            let not_allowed = rctx.method_not_allowed;
            let allowed = rctx.methods_allowed.clone();
            r.route_ctx = Some(rctx);
            if not_allowed {
                mx.method_not_allowed_handler(&allowed)
                    .serve_http(w, r)
                    .await;
            } else {
                mx.not_found_handler().serve_http(w, r).await;
            }
        })
    }
}

/// `methodNotAllowedHandler`. Go gathers the methods by ranging over a map, so its `Allow` lines come
/// in random order; here they come in chi's method-bit order.
fn default_method_not_allowed(methods: Vec<u64>) -> BoxHandler {
    handler_fn(move |w, _r| {
        let methods = methods.clone();
        Box::pin(async move {
            for m in methods {
                if let Some(name) = method_name(m) {
                    w.header().add("Allow", name);
                }
            }
            w.write_header(405).await;
            let _ = w.write(&[]).await;
        })
    })
}

impl Handler for Mux {
    /// `mx.ServeHTTP`.
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let Some(handler) = read(&self.0.handler) else {
                self.not_found_handler().serve_http(w, r).await;
                return;
            };
            if r.route_ctx.is_some() {
                handler.serve_http(w, r).await;
                return;
            }
            r.route_ctx = Some(Box::new(Context {
                routes: Some(self.clone()),
                ..Context::default()
            }));
            // Go routes on a copy of the request, so its caller keeps the original fields.
            let saved_pattern = r.pattern.clone();
            let saved_values = r.path_values.clone();
            handler.serve_http(w, r).await;
            r.route_ctx = None;
            r.pattern = saved_pattern;
            r.path_values = saved_values;
        })
    }
}

/// `chi.WalkFunc`.
pub type WalkFn<'a, E> = dyn FnMut(&str, &str, &BoxHandler, &[Middleware]) -> Result<(), E> + 'a;

/// `chi.Walk`: `f(method, route, handler, middlewares)`, for every route in the tree.
pub fn walk<E>(r: &Mux, f: &mut WalkFn<'_, E>) -> Result<(), E> {
    walk_inner(r, f, "", &[])
}

fn walk_inner<E>(
    r: &Mux,
    f: &mut WalkFn<'_, E>,
    parent_route: &str,
    parent_mw: &[Middleware],
) -> Result<(), E> {
    for route in r.routes() {
        let mut mws = parent_mw.to_vec();
        mws.extend(r.middlewares());

        if let Some(sub) = &route.sub_routes {
            if let Some(chain) = route.handlers.get("*").and_then(|h| h.as_chain()) {
                mws.extend(chain.middlewares.iter().cloned());
            }
            walk_inner(sub, f, &format!("{parent_route}{}", route.pattern), &mws)?;
            continue;
        }

        for (method, handler) in &route.handlers {
            if method == "*" {
                continue;
            }
            let full = format!("{parent_route}{}", route.pattern).replace("/*/", "/");
            if let Some(chain) = handler.as_chain() {
                let mut with = mws.clone();
                with.extend(chain.middlewares.iter().cloned());
                f(method, &full, &chain.endpoint, &with)?;
            } else {
                f(method, &full, handler, &mws)?;
            }
        }
    }
    Ok(())
}
