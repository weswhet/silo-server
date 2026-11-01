//! Adapters between this crate's handler model and `http`/`tower`, so axum handlers can sit behind
//! [`crate::chi::Mux`], plus the `Params` extractor axum handlers read chi's URL parameters with.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum_core::extract::FromRequestParts;
use bytes::Bytes;
use http::request::Parts;
use http_body::Body as HttpBody;
use http_body_util::{BodyExt, StreamBody};
use tower_service::Service;

use crate::chi::RouteParams;
use crate::request::{Body, Request};
use crate::response::{BoxFuture, BoxHandler, Handler, ResponseWriter};

/// The route parameters chi matched, available to axum handlers as an extractor.
#[derive(Clone, Debug, Default)]
pub struct Params(pub RouteParams);

impl Params {
    /// `chi.URLParam`, as bytes.
    pub fn get_bytes(&self, key: &str) -> &[u8] {
        for (i, k) in self.0.keys.iter().enumerate().rev() {
            if &**k == key {
                return &self.0.values[i];
            }
        }
        &[]
    }

    /// `chi.URLParam`. A value that is not UTF-8 reads as empty.
    pub fn get(&self, key: &str) -> &str {
        std::str::from_utf8(self.get_bytes(key)).unwrap_or("")
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Params {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        Ok(parts
            .extensions
            .get::<Params>()
            .cloned()
            .unwrap_or_default())
    }
}

/// The raw request target and decoded path, for handlers that must see what `http::Uri` normalized
/// away or refused.
#[derive(Clone, Debug)]
pub struct RawRequest {
    pub request_uri: Vec<u8>,
    pub path: Vec<u8>,
    pub raw_path: Vec<u8>,
    pub raw_query: Vec<u8>,
    pub pattern: String,
    pub remote_addr: String,
}

/// Sent as a response extension to flush after every body frame, for handlers that stream.
#[derive(Clone, Copy, Debug)]
pub struct FlushEachFrame;

/// A `http::Uri` for the request. Go accepts targets `http::Uri` refuses, such as a raw `<`, so those
/// are percent-encoded here; [`RawRequest`] keeps the original.
fn request_uri(r: &Request) -> http::Uri {
    let mut target = r.url.escaped_path();
    if !r.url.raw_query.is_empty() {
        target.push(b'?');
        let mut q = Vec::with_capacity(r.url.raw_query.len());
        for &b in &r.url.raw_query {
            if b.is_ascii_graphic()
                && !matches!(
                    b,
                    b'"' | b'<' | b'>' | b'`' | b'#' | b'{' | b'}' | b'|' | b'\\' | b'^'
                )
            {
                q.push(b);
            } else {
                q.extend_from_slice(format!("%{b:02X}").as_bytes());
            }
        }
        target.extend_from_slice(&q);
    }
    http::Uri::try_from(target).unwrap_or_else(|_| http::Uri::from_static("/"))
}

fn body_stream(body: Body) -> impl HttpBody<Data = Bytes, Error = std::io::Error> + Send + 'static {
    let stream = futures_util::stream::unfold(Some(body), |state| async move {
        let mut body = state?;
        let mut buf = vec![0u8; 32 * 1024];
        match body.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(http_body::Frame::data(Bytes::from(buf))), Some(body)))
            }
            Err(e) => Some((Err(e), None)),
        }
    });
    StreamBody::new(stream)
}

/// Runs a `tower` service, such as an axum handler from `Handler::with_state`, as a [`Handler`].
///
/// The request body becomes a stream, each response data frame becomes one `w.Write`, and the status
/// and headers go through `w` first, so the Go response writer rules apply to what the service
/// returned.
pub fn service_handler<S, ResB>(svc: S) -> BoxHandler
where
    S: Service<http::Request<axum_core::body::Body>, Response = http::Response<ResB>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: std::fmt::Display,
    ResB: HttpBody<Data = Bytes> + Send + 'static,
    ResB::Error: std::fmt::Display + Send,
{
    Arc::new(ServiceHandler {
        svc: Mutex::new(svc),
        _marker: std::marker::PhantomData,
    })
}

struct ServiceHandler<S, ResB> {
    svc: Mutex<S>,
    _marker: std::marker::PhantomData<fn() -> ResB>,
}

impl<S, ResB> Handler for ServiceHandler<S, ResB>
where
    S: Service<http::Request<axum_core::body::Body>, Response = http::Response<ResB>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: std::fmt::Display,
    ResB: HttpBody<Data = Bytes> + Send + 'static,
    ResB::Error: std::fmt::Display + Send,
{
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut svc = crate::bufio::lock(&self.svc).clone();
            let body = axum_core::body::Body::new(body_stream(r.take_body()));
            let mut builder = http::Request::builder().uri(request_uri(r));
            if let Ok(m) = http::Method::from_bytes(r.method.as_bytes()) {
                builder = builder.method(m);
            }
            builder = builder.version(if r.proto_at_least(1, 1) {
                http::Version::HTTP_11
            } else {
                http::Version::HTTP_10
            });
            let mut req = match builder.body(body) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!(error = %e, "bridge: bad request parts");
                    crate::response::error(w, "500 Internal Server Error", 500).await;
                    return;
                }
            };
            for (key, values) in r.header.iter() {
                let Ok(name) = http::HeaderName::from_bytes(key.as_bytes()) else {
                    continue;
                };
                for v in values {
                    if let Ok(value) = http::HeaderValue::from_bytes(v) {
                        req.headers_mut().append(name.clone(), value);
                    }
                }
            }
            if let Ok(host) = http::HeaderValue::from_bytes(&r.host) {
                req.headers_mut().insert(http::header::HOST, host);
            }
            let params = r
                .route_context()
                .map(|c| c.url_params.clone())
                .unwrap_or_default();
            req.extensions_mut().insert(Params(params));
            req.extensions_mut().insert(RawRequest {
                request_uri: r.request_uri.clone(),
                path: r.url.path.clone(),
                raw_path: r.url.raw_path.clone(),
                raw_query: r.url.raw_query.clone(),
                pattern: r.pattern.clone(),
                remote_addr: r.remote_addr.clone(),
            });

            let resp = match svc.call(req).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!(error = %e, "bridge: service error");
                    crate::response::abort_handler();
                }
            };
            let (parts, body) = resp.into_parts();
            let flush_each = parts.extensions.get::<FlushEachFrame>().is_some();
            for (name, value) in &parts.headers {
                w.header().add(name.as_str(), value.as_bytes());
            }
            w.write_header(parts.status.as_u16()).await;
            let mut body = std::pin::pin!(body);
            loop {
                match body.as_mut().frame().await {
                    None => return,
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "bridge: response body error");
                        crate::response::abort_handler();
                    }
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            let write = w.write(&data).await;
                            if write.is_err() {
                                return;
                            }
                            if flush_each {
                                let _ = w.flush().await;
                            }
                        }
                    }
                }
            }
        })
    }
}
