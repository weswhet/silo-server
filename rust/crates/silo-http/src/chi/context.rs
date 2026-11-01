//! Port of chi's `context.go`.

use std::sync::Arc;

use crate::chi::mux::Mux;
use crate::request::Request;

/// `chi.RouteParams`. Values are bytes because a decoded path segment can hold any byte.
#[derive(Clone, Debug, Default)]
pub struct RouteParams {
    pub keys: Vec<Arc<str>>,
    pub values: Vec<Vec<u8>>,
}

impl RouteParams {
    /// `s.Add`.
    pub fn add(&mut self, key: &str, value: impl Into<Vec<u8>>) {
        self.keys.push(Arc::from(key));
        self.values.push(value.into());
    }
}

/// `chi.Context`.
#[derive(Clone, Default)]
pub struct Context {
    /// `Routes`.
    pub routes: Option<Mux>,
    /// `RoutePath`: when not empty, routing matches this instead of the request's path. Middleware
    /// may rewrite it before the mux matches.
    pub route_path: Vec<u8>,
    /// `RouteMethod`.
    pub route_method: String,
    /// `URLParams`: the stack across sub-routers.
    pub url_params: RouteParams,
    pub(crate) route_params: RouteParams,
    pub(crate) route_pattern: String,
    /// `RoutePatterns`.
    pub route_patterns: Vec<Arc<str>>,
    pub(crate) methods_allowed: Vec<u64>,
    pub(crate) method_not_allowed: bool,
}

impl Context {
    /// `chi.NewRouteContext`.
    pub fn new() -> Self {
        Self::default()
    }

    /// `x.URLParam`: the last value for `key`, or empty.
    pub fn url_param(&self, key: &str) -> &[u8] {
        for (i, k) in self.url_params.keys.iter().enumerate().rev() {
            if &**k == key {
                return &self.url_params.values[i];
            }
        }
        &[]
    }

    /// `x.RoutePattern`.
    pub fn route_pattern(&self) -> String {
        let mut p: String = self.route_patterns.iter().map(|s| &**s).collect();
        while p.contains("/*/") {
            p = p.replace("/*/", "/");
        }
        if p != "/" {
            if let Some(stripped) = p.strip_suffix("//") {
                p = stripped.to_owned();
            }
            if let Some(stripped) = p.strip_suffix('/') {
                p = stripped.to_owned();
            }
        }
        p
    }
}

/// `chi.URLParam`.
pub fn url_param<'a>(r: &'a Request, key: &str) -> &'a str {
    r.url_param(key)
}

/// `chi.URLParam` as bytes.
pub fn url_param_bytes<'a>(r: &'a Request, key: &str) -> &'a [u8] {
    r.url_param_bytes(key)
}
