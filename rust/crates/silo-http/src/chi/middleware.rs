//! Ports of the chi middleware that shapes routing: `middleware.StripSlashes` and
//! `middleware.RedirectSlashes`. `RequestID`, `Recoverer`, and `WrapResponseWriter` carry no routing
//! semantics and belong with the crates that port their callers.

use std::sync::Arc;

use crate::request::Request;
use crate::response::{BoxFuture, BoxHandler, Handler, ResponseWriter, redirect};

struct StripSlashes {
    next: BoxHandler,
}

impl Handler for StripSlashes {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        let path = match r.route_ctx.as_deref() {
            Some(rctx) if !rctx.route_path.is_empty() => rctx.route_path.clone(),
            _ => r.url.path.clone(),
        };
        if path.len() > 1 && path.ends_with(b"/") {
            let new_path = path[..path.len() - 1].to_vec();
            match r.route_ctx.as_deref_mut() {
                None => r.url.path = new_path,
                Some(rctx) => rctx.route_path = new_path,
            }
        }
        self.next.serve_http(w, r)
    }
}

/// `middleware.StripSlashes`.
pub fn strip_slashes(next: BoxHandler) -> BoxHandler {
    Arc::new(StripSlashes { next })
}

struct RedirectSlashes {
    next: BoxHandler,
}

impl Handler for RedirectSlashes {
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let path = match r.route_ctx.as_deref() {
                Some(rctx) if !rctx.route_path.is_empty() => rctx.route_path.clone(),
                _ => r.url.path.clone(),
            };
            if path.len() > 1 && path.ends_with(b"/") {
                // Normalize backslashes so "/\evil.com" cannot become protocol-relative.
                let text = String::from_utf8_lossy(&path).replace('\\', "/");
                let mut target = format!("/{}", text.trim_matches('/'));
                if !r.url.raw_query.is_empty() {
                    target.push('?');
                    target.push_str(&String::from_utf8_lossy(&r.url.raw_query));
                }
                redirect(w, r, &target, 301).await;
                return;
            }
            self.next.serve_http(w, r).await;
        })
    }
}

/// `middleware.RedirectSlashes`.
pub fn redirect_slashes(next: BoxHandler) -> BoxHandler {
    Arc::new(RedirectSlashes { next })
}
