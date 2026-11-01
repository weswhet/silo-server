//! Sends one request and captures what came back. Redirects are never followed,
//! nothing is decompressed, and every request carries the same fixed Host, so URLs
//! a server derives from Host cannot differ just because the two listen on
//! different ports.

use crate::model::FIXED_HOST;
use reqwest::blocking::Client;
use reqwest::Method;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub struct Exchange {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The body was cut off (size cap, stream, or timeout), so it is not comparable.
    pub truncated: bool,
    pub error: Option<String>,
}

impl Exchange {
    pub fn header(&self, name: &str) -> Option<String> {
        let vals: Vec<&str> = self
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        if vals.is_empty() {
            None
        } else {
            Some(vals.join(", "))
        }
    }

    pub fn is_event_stream(&self) -> bool {
        self.header("content-type")
            .is_some_and(|v| v.to_ascii_lowercase().contains("text/event-stream"))
    }
}

pub struct Request<'a> {
    pub base: &'a str,
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
    pub timeout_secs: u64,
    /// The Host to send. `None` sends `FIXED_HOST`.
    pub host: Option<&'a str>,
}

pub fn client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .pool_max_idle_per_host(8)
        .build()
        .expect("http client")
}

pub fn send(client: &Client, req: &Request) -> Exchange {
    if req.method == "CONNECT" {
        return send_connect(req);
    }
    let method = match Method::from_bytes(req.method.as_bytes()) {
        Ok(m) => m,
        Err(e) => return error_exchange(format!("method: {e}")),
    };
    let url = format!("{}{}", req.base.trim_end_matches('/'), req.path_and_query);
    let mut builder = client
        .request(method, &url)
        .timeout(Duration::from_secs(req.timeout_secs))
        .header("Host", req.host.unwrap_or(FIXED_HOST));
    for (k, v) in req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    if let Some(b) = req.body {
        builder = builder.body(b.to_vec());
    }
    let mut resp = match builder.send() {
        Ok(r) => r,
        Err(e) => return error_exchange(root_error(&e)),
    };
    let mut out = Exchange {
        status: resp.status().as_u16(),
        headers: resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        ..Exchange::default()
    };
    if out.is_event_stream() {
        out.truncated = true;
        return out;
    }
    let mut buf = [0u8; 65536];
    loop {
        match resp.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.body.extend_from_slice(&buf[..n]);
                if out.body.len() > MAX_BODY {
                    out.truncated = true;
                    break;
                }
            }
            Err(_) => {
                out.truncated = true;
                break;
            }
        }
    }
    out
}

fn error_exchange(error: String) -> Exchange {
    Exchange {
        error: Some(error),
        ..Exchange::default()
    }
}

fn root_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".to_string()
    } else if e.is_connect() {
        "connect error".to_string()
    } else {
        format!("transport error: {e}")
    }
}

/// HTTP client libraries send CONNECT in authority form, which never reaches a
/// route. These routes exist on the listener in origin form, so this writes the
/// request directly. The response body is not de-chunked; it is only compared
/// with the other side's bytes.
fn send_connect(req: &Request) -> Exchange {
    let addr = req
        .base
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let run = || -> std::io::Result<Vec<u8>> {
        let target = addr.parse().map_err(std::io::Error::other)?;
        let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(req.timeout_secs)))?;
        let mut head = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {FIXED_HOST}\r\nConnection: close\r\n",
            req.path_and_query
        );
        for (k, v) in req.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        let mut all = Vec::new();
        stream.read_to_end(&mut all)?;
        Ok(all)
    };
    match run() {
        Ok(raw) => parse_raw_response(&raw),
        Err(e) => error_exchange(format!("connect method: {e}")),
    }
}

fn parse_raw_response(raw: &[u8]) -> Exchange {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    if status == 0 {
        return error_exchange("connect method: malformed response".to_string());
    }
    Exchange {
        status,
        headers: lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect(),
        body: raw.get(split + 4..).unwrap_or(&[]).to_vec(),
        ..Exchange::default()
    }
}
