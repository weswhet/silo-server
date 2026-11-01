//! Sending raw requests to both servers and comparing what comes back.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::mirror::RustSide;

/// How a response is compared.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Bytes, after normalizing the Date value, multipart boundaries, and chi's Allow order.
    Raw,
    /// Status line, headers without framing, and the decoded body.
    Decoded,
}

#[derive(Clone, Debug)]
pub struct Case {
    pub listener: String,
    pub request: Vec<u8>,
    pub mode: Mode,
    /// Half-close and read until the server hangs up, instead of reading one response off a kept
    /// connection. For requests that are malformed, pipelined, or end the connection.
    pub half_close: bool,
}

impl Case {
    pub fn new(listener: &str, request: impl Into<Vec<u8>>) -> Self {
        Self {
            listener: listener.to_owned(),
            request: request.into(),
            mode: Mode::Raw,
            half_close: false,
        }
    }

    pub fn raw(listener: &str, request: impl Into<Vec<u8>>) -> Self {
        Self {
            half_close: true,
            ..Self::new(listener, request)
        }
    }
}

/// Sends the request, half-closes, and reads until the server closes. Half-closing lets one read loop
/// serve every case: both servers finish the response and hang up, whatever its framing.
pub async fn exchange(port: u16, request: &[u8]) -> Result<Vec<u8>, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    s.set_nodelay(true).ok();
    let _ = s.write_all(request).await;
    let _ = s.shutdown().await;
    read_to_close(&mut s).await
}

async fn read_to_close(s: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let fut = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .is_err()
    {
        return Err(format!(
            "timed out after {} bytes: {:?}",
            out.len(),
            String::from_utf8_lossy(&out[..out.len().min(300)])
        ));
    }
    Ok(out)
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn looks_like_date(v: &[u8]) -> bool {
    // Mon, 02 Jan 2006 15:04:05 GMT
    v.len() == 29
        && v[3] == b','
        && v[4] == b' '
        && v[7] == b' '
        && v[11] == b' '
        && v[16] == b' '
        && v[19] == b':'
        && v[22] == b':'
        && v[25] == b' '
        && &v[26..] == b"GMT"
}

/// Replaces what Go does not reproduce between two of its own runs. A value in the wrong shape stays
/// in place, so it shows up as a difference.
pub fn normalize(input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();

    // Date values.
    let mut from = 0;
    while let Some(p) = find(&out, b"\r\nDate: ", from) {
        let start = p + 8;
        if start + 29 <= out.len() && looks_like_date(&out[start..start + 29]) {
            out[start..start + 29].copy_from_slice(b"<DATE>                       ");
        }
        from = start;
    }

    // Multipart boundaries: 60 hex characters.
    let mut from = 0;
    while let Some(p) = find(&out, b"boundary=", from) {
        let start = p + 9;
        from = start;
        if start + 60 <= out.len() && out[start..start + 60].iter().all(|b| b.is_ascii_hexdigit()) {
            let boundary = out[start..start + 60].to_vec();
            let placeholder = vec![b'B'; 60];
            let mut i = 0;
            while let Some(q) = find(&out, &boundary, i) {
                out[q..q + 60].copy_from_slice(&placeholder);
                i = q + 60;
            }
        }
    }

    // chi's default 405 ranges over a map, so runs of Allow lines come in random order.
    let mut from = 0;
    while let Some(p) = find(&out, b"\r\nAllow: ", from) {
        let run_start = p + 2;
        let mut end = run_start;
        let mut lines: Vec<Vec<u8>> = Vec::new();
        while out[end..].starts_with(b"Allow: ") {
            let Some(e) = find(&out, b"\r\n", end) else {
                break;
            };
            lines.push(out[end..e + 2].to_vec());
            end = e + 2;
        }
        lines.sort();
        let joined: Vec<u8> = lines.concat();
        out[run_start..end].copy_from_slice(&joined);
        from = end;
    }
    out
}

fn split_head(resp: &[u8]) -> Option<(&[u8], &[u8])> {
    let p = find(resp, b"\r\n\r\n", 0)?;
    Some((&resp[..p], &resp[p + 4..]))
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(p) = find(body, b"\r\n", 0) else {
            return out;
        };
        let size = usize::from_str_radix(&String::from_utf8_lossy(&body[..p]), 16).unwrap_or(0);
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&body[p + 2..p + 2 + size]);
        body = &body[p + 2 + size + 2..];
    }
}

/// The final status line, the headers of every head, and the decoded body.
pub type Decoded = (Vec<u8>, Vec<Vec<u8>>, Vec<u8>);

/// Heads apart from framing and the encoded length, and the decoded body. Compression cases send one
/// request, so the response is one final head, possibly after 1xx heads.
pub fn decode(resp: &[u8], is_head: bool) -> Result<Decoded, String> {
    let mut rest = resp;
    let mut headers: Vec<Vec<u8>> = Vec::new();
    loop {
        let (head, body) = split_head(rest).ok_or("no header terminator")?;
        let mut lines = head
            .split(|&b| b == b'\n')
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec());
        let status = lines.next().unwrap_or_default();
        let mut chunked = false;
        let mut encoding = Vec::new();
        for l in lines {
            if l.starts_with(b"Transfer-Encoding: chunked") {
                chunked = true;
                continue;
            }
            if l.starts_with(b"Content-Length: ") || l.starts_with(b"Date: ") {
                continue;
            }
            if let Some(v) = l.strip_prefix(b"Content-Encoding: ") {
                encoding = v.to_vec();
            }
            headers.push(l);
        }
        let code = String::from_utf8_lossy(status.get(9..12).unwrap_or(b"")).into_owned();
        if code.starts_with('1') {
            rest = body;
            continue;
        }
        if is_head {
            return Ok((status, headers, Vec::new()));
        }
        let raw = if chunked {
            dechunk(body)
        } else {
            body.to_vec()
        };
        // A handler can declare a coding without encoding anything. Those bytes compare as they are.
        let decoded = decode_body(&encoding, &raw).unwrap_or(raw);
        return Ok((status, headers, decoded));
    }
}

fn decode_body(encoding: &[u8], raw: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::new();
    match encoding {
        b"gzip" => {
            flate2::read::GzDecoder::new(raw)
                .read_to_end(&mut out)
                .map_err(|e| format!("gzip: {e}"))?;
        }
        b"zstd" => {
            zstd::stream::read::Decoder::new(raw)
                .map_err(|e| format!("zstd: {e}"))?
                .read_to_end(&mut out)
                .map_err(|e| format!("zstd: {e}"))?;
        }
        b"br" => {
            brotli_decompressor::Decompressor::new(raw, 4096)
                .read_to_end(&mut out)
                .map_err(|e| format!("br: {e}"))?;
        }
        _ => out = raw.to_vec(),
    }
    Ok(out)
}

fn show(b: &[u8]) -> String {
    let s = silo_gocompat::strconv::quote_bytes(&b[..b.len().min(1500)]);
    if b.len() > 1500 {
        format!("{s}...({} bytes)", b.len())
    } else {
        s
    }
}

fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

pub fn report(section: &str, case: &str, go: &[u8], rust: &[u8]) {
    let at = first_difference(go, rust);
    let start = at.saturating_sub(80);
    eprintln!(
        "--- {section}: {case}\n  differ at byte {at}\n  go:   {}\n  rust: {}",
        show(&go[start..]),
        show(&rust[start..])
    );
}

/// One worker's open connections, per port. Reuse keeps the run off the ephemeral port limit, because
/// macOS holds a client-closed port in TIME_WAIT for 30 seconds.
#[derive(Default)]
struct Pool {
    conns: BTreeMap<u16, TcpStream>,
    /// Times a kept connection turned out to be closed. A server that closes without saying so would
    /// otherwise pass unnoticed here, so a section with any of these fails.
    stale: usize,
}

impl Pool {
    /// Sends the request on a kept connection and reads exactly one response, by its framing. The bytes
    /// themselves are compared afterward; the framing only says where to stop reading.
    async fn request(&mut self, port: u16, request: &[u8]) -> Result<Vec<u8>, String> {
        for attempt in 0..2 {
            let stale = self.conns.contains_key(&port);
            let mut s = match self.conns.remove(&port) {
                Some(s) => s,
                None => {
                    let s = TcpStream::connect(("127.0.0.1", port))
                        .await
                        .map_err(|e| e.to_string())?;
                    s.set_nodelay(true).ok();
                    s
                }
            };
            let _ = s.write_all(request).await;
            let (resp, reusable) = read_one_response(&mut s, request).await?;
            if resp.is_empty() && stale && attempt == 0 {
                self.stale += 1;
                continue;
            }
            if reusable {
                self.conns.insert(port, s);
            }
            return Ok(resp);
        }
        Err("no response".to_owned())
    }
}

async fn read_more(s: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    let mut chunk = vec![0u8; 64 * 1024];
    match tokio::time::timeout(Duration::from_secs(20), s.read(&mut chunk)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => false,
        Ok(Ok(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            true
        }
    }
}

/// Reads one response off `s`. `true` if the connection can carry another request.
async fn read_one_response(s: &mut TcpStream, request: &[u8]) -> Result<(Vec<u8>, bool), String> {
    let is_head = request.starts_with(b"HEAD ");
    let mut buf = Vec::new();
    let mut start = 0;
    loop {
        // One head at a time, because 1xx responses come before the real one.
        let head_end = loop {
            if let Some(p) = find(&buf, b"\r\n\r\n", start) {
                break p + 4;
            }
            if !read_more(s, &mut buf).await {
                return Ok((buf, false));
            }
        };
        let head = buf[start..head_end].to_vec();
        let code: u16 = String::from_utf8_lossy(head.get(9..12).unwrap_or(b""))
            .parse()
            .unwrap_or(0);
        if (100..200).contains(&code) && code != 101 {
            start = head_end;
            continue;
        }
        let lower = String::from_utf8_lossy(&head).to_lowercase();
        let close = lower.contains("\r\nconnection: close\r\n") || head.starts_with(b"HTTP/1.0");
        let chunked = lower.contains("\r\ntransfer-encoding: chunked\r\n");
        let length = lower.split("\r\n").find_map(|l| {
            l.strip_prefix("content-length: ")
                .and_then(|v| v.trim().parse::<usize>().ok())
        });
        if is_head || code == 204 || code == 304 {
            return Ok((buf, !close));
        }
        if chunked {
            let mut at = head_end;
            loop {
                let line_end = loop {
                    if let Some(p) = find(&buf, b"\r\n", at) {
                        break p;
                    }
                    if !read_more(s, &mut buf).await {
                        return Ok((buf, false));
                    }
                };
                let size = usize::from_str_radix(&String::from_utf8_lossy(&buf[at..line_end]), 16)
                    .unwrap_or(0);
                if size == 0 {
                    // Trailers, then the blank line.
                    let mut t = line_end + 2;
                    loop {
                        let e = loop {
                            if let Some(p) = find(&buf, b"\r\n", t) {
                                break p;
                            }
                            if !read_more(s, &mut buf).await {
                                return Ok((buf, false));
                            }
                        };
                        if e == t {
                            return Ok((buf, !close));
                        }
                        t = e + 2;
                    }
                }
                at = line_end + 2 + size + 2;
                while buf.len() < at {
                    if !read_more(s, &mut buf).await {
                        return Ok((buf, false));
                    }
                }
            }
        }
        if let Some(n) = length {
            while buf.len() < head_end + n {
                if !read_more(s, &mut buf).await {
                    return Ok((buf, false));
                }
            }
            return Ok((buf, !close));
        }
        // Delimited by close.
        while read_more(s, &mut buf).await {}
        return Ok((buf, false));
    }
}

pub async fn compare_all(
    section: &str,
    cases: Vec<Case>,
    go: &BTreeMap<String, u16>,
    rust: &BTreeMap<String, u16>,
) -> usize {
    const WORKERS: usize = 8;
    let queue = Arc::new(std::sync::Mutex::new(
        cases.into_iter().rev().collect::<Vec<_>>(),
    ));
    let mut tasks = Vec::new();
    for _ in 0..WORKERS {
        let queue = queue.clone();
        let (go, rust) = (go.clone(), rust.clone());
        tasks.push(tokio::spawn(async move {
            let mut pool = Pool::default();
            let mut results = Vec::new();
            loop {
                let Some(case) = queue.lock().unwrap().pop() else {
                    return (results, pool.stale);
                };
                let go_port = *go
                    .get(&case.listener)
                    .unwrap_or_else(|| panic!("go listener {}", case.listener));
                let rust_port = *rust
                    .get(&case.listener)
                    .unwrap_or_else(|| panic!("rust listener {}", case.listener));
                let (g, r) = if case.half_close {
                    tokio::join!(
                        exchange(go_port, &case.request),
                        exchange(rust_port, &case.request)
                    )
                } else {
                    let g = pool.request(go_port, &case.request).await;
                    let r = pool.request(rust_port, &case.request).await;
                    (g, r)
                };
                results.push((case, g, r));
            }
        }));
    }
    let mut bad = 0;
    let mut shown = 0;
    let mut statuses: BTreeMap<String, usize> = BTreeMap::new();
    for t in tasks {
        let (results, stale) = t.await.unwrap();
        if stale > 0 {
            eprintln!("--- {section}: {stale} kept connections closed without Connection: close");
            bad += stale;
        }
        for (case, g, r) in results {
            if let Ok(g) = &g {
                let code = String::from_utf8_lossy(g.get(9..12).unwrap_or(b"none")).into_owned();
                *statuses.entry(code).or_default() += 1;
            }
            let name = format!(
                "{} {}",
                case.listener,
                show(&case.request[..case.request.len().min(400)])
            );
            let (g, r) = match (g, r) {
                (Ok(g), Ok(r)) => (g, r),
                (g, r) => {
                    bad += 1;
                    if shown < 25 {
                        eprintln!(
                            "--- {section}: {name}\n  go {:?}\n  rust {:?}",
                            g.map(|v| v.len()),
                            r.map(|v| v.len())
                        );
                    }
                    shown += 1;
                    continue;
                }
            };
            let same = match case.mode {
                Mode::Raw => {
                    let (ng, nr) = (normalize(&g), normalize(&r));
                    let same = ng == nr;
                    if !same && shown < 25 {
                        report(section, &name, &ng, &nr);
                    }
                    same
                }
                Mode::Decoded => match (
                    decode(&g, case.request.starts_with(b"HEAD ")),
                    decode(&r, case.request.starts_with(b"HEAD ")),
                ) {
                    (Ok(dg), Ok(dr)) => {
                        let same = dg == dr;
                        if !same && shown < 25 {
                            eprintln!(
                                "--- {section}: {name}\n  go:   {} {:?}\n  rust: {} {:?}\n  go body {} bytes, rust body {} bytes, equal {}",
                                show(&dg.0),
                                dg.1.iter()
                                    .map(|h| String::from_utf8_lossy(h).into_owned())
                                    .collect::<Vec<_>>(),
                                show(&dr.0),
                                dr.1.iter()
                                    .map(|h| String::from_utf8_lossy(h).into_owned())
                                    .collect::<Vec<_>>(),
                                dg.2.len(),
                                dr.2.len(),
                                dg.2 == dr.2
                            );
                        }
                        same
                    }
                    (dg, dr) => {
                        if shown < 25 {
                            eprintln!(
                                "--- {section}: {name}\n  decode go {:?}\n  decode rust {:?}",
                                dg.err(),
                                dr.err()
                            );
                        }
                        false
                    }
                },
            };
            if !same {
                bad += 1;
                shown += 1;
            }
        }
    }
    // A zero-difference run means little if everything answered the same way.
    eprintln!("{section}: go statuses {statuses:?}");
    bad
}

async fn go_control(port: u16, target: &str) -> String {
    let req = format!("GET {target} HTTP/1.1\r\nHost: control\r\n\r\n");
    let resp = exchange(port, req.as_bytes()).await.unwrap_or_default();
    let (head, body) = split_head(&resp).unwrap_or((&[], &[]));
    if head.windows(26).any(|w| w == b"Transfer-Encoding: chunked") {
        String::from_utf8_lossy(&dechunk(body)).into_owned()
    } else {
        String::from_utf8_lossy(body).into_owned()
    }
}

fn escape_query(s: &str) -> String {
    silo_gocompat::url::query_escape(s)
}

/// `chi.Walk`, `Mux.Find`, and `Mux.Match` agree with Go on the same routers.
pub async fn control_checks(go: &BTreeMap<String, u16>, rust: &RustSide) -> (usize, usize) {
    let control = go["control"];
    let mut total = 0;
    let mut bad = 0;
    for (name, mux) in &rust.walked {
        let mut lines: Vec<String> = Vec::new();
        silo_http::chi::walk::<()>(mux, &mut |method, route, _h, mws| {
            lines.push(format!("{method} {route} {}", mws.len()));
            Ok(())
        })
        .unwrap();
        lines.sort();
        let ours = lines.join("\n") + "\n";
        let theirs = go_control(control, &format!("/walk?l={name}")).await;
        total += 1;
        if ours != theirs {
            bad += 1;
            let g: std::collections::BTreeSet<_> = theirs.lines().collect();
            let r: std::collections::BTreeSet<_> = ours.lines().collect();
            eprintln!(
                "--- walk {name}\n  only go: {:?}\n  only rust: {:?}",
                g.difference(&r).take(20).collect::<Vec<_>>(),
                r.difference(&g).take(20).collect::<Vec<_>>()
            );
        }
    }
    let probes = [
        ("chi-adv", "GET", "/s/static"),
        ("chi-adv", "GET", "/s/x"),
        ("chi-adv", "GET", "/s/x/y/z"),
        ("chi-adv", "POST", "/s/x"),
        ("chi-adv", "GET", "/sub/deep/1"),
        ("chi-adv", "GET", "/sub/deep/"),
        ("chi-adv", "POST", "/sub/deep/a/b"),
        ("chi-adv", "GET", "/sub"),
        ("chi-adv", "GET", "/own/x"),
        ("chi-adv", "GET", "/own/y"),
        ("chi-adv", "GET", "/mnt"),
        ("chi-adv", "GET", "/mnt/deeper"),
        ("chi-adv", "GET", "/t1/v/9"),
        ("chi-adv", "NOPE", "/s/x"),
        ("chi-adv", "GET", "/r/123"),
        ("chi-adv", "GET", "/r/abc"),
        ("chi-adv", "GET", "/m/a.b"),
        ("chi-handlers", "GET", "/sub/x"),
        ("chi-handlers", "GET", "/none"),
        ("chi-api", "GET", "/api/v1/health"),
        ("chi-api", "GET", "/api/v2/anything"),
    ];
    for (l, m, p) in probes {
        total += 1;
        let mux = &rust.walked[l];
        let mut ctx = silo_http::chi::Context::new();
        let found = mux.find(&mut ctx, m, p.as_bytes());
        let matched = mux.match_route(&mut silo_http::chi::Context::new(), m, p.as_bytes());
        let ours = format!("{} {matched}\n", silo_gocompat::strconv::quote(&found));
        let theirs = go_control(control, &format!("/find?l={l}&m={m}&p={}", escape_query(p))).await;
        if ours != theirs {
            bad += 1;
            eprintln!("--- find {l} {m} {p}\n  go:   {theirs}  rust: {ours}");
        }
    }
    let mut extensions: Vec<String> = [
        ".css",
        ".csv",
        ".gif",
        ".htm",
        ".html",
        ".ico",
        ".ics",
        ".jpeg",
        ".jpg",
        ".js",
        ".json",
        ".m4a",
        ".m4s",
        ".mjs",
        ".mkv",
        ".mov",
        ".mp3",
        ".mp4",
        ".mpd",
        ".m3u8",
        ".ogg",
        ".opus",
        ".pdf",
        ".png",
        ".srt",
        ".svg",
        ".ts",
        ".txt",
        ".vtt",
        ".wasm",
        ".wav",
        ".webm",
        ".weba",
        ".webp",
        ".xml",
        ".zip",
        ".JS",
        ".Html",
        ".PNG",
        ".tar",
        ".gz",
        ".nosuchext",
        "",
        ".",
    ]
    .iter()
    .map(|e| (*e).to_owned())
    .collect();
    // Whatever this machine's mime.types defines, both sides must read it the same way.
    for file in ["/etc/mime.types", "/etc/apache2/mime.types"] {
        if let Ok(text) = std::fs::read_to_string(file) {
            for line in text.lines().filter(|l| !l.starts_with('#')) {
                extensions.extend(
                    line.split_whitespace()
                        .skip(1)
                        .take(2)
                        .map(|e| format!(".{e}")),
                );
            }
        }
    }
    extensions.sort();
    extensions.dedup();
    let mut mime_seen = 0;
    for chunk in extensions.chunks(8) {
        let mut set = Vec::new();
        for e in chunk {
            let target = format!("/mime?e={}", escape_query(e));
            set.push((e.clone(), go_control(control, &target).await));
        }
        for (e, theirs) in set {
            total += 1;
            mime_seen += 1;
            let ours = silo_http::mime::type_by_extension(&e);
            if ours != theirs {
                bad += 1;
                eprintln!("--- mime {e:?}\n  go:   {theirs}\n  rust: {ours}");
            }
        }
    }
    eprintln!("control: compared {mime_seen} extensions");
    (total, bad)
}

async fn step_exchange(port: u16, script: &[Step]) -> Vec<u8> {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await else {
        return b"connect failed".to_vec();
    };
    s.set_nodelay(true).ok();
    let mut out = Vec::new();
    for step in script {
        match step {
            Step::Send(b) => {
                let _ = s.write_all(b).await;
            }
            Step::ReadBytes(n) => {
                let mut got = vec![0u8; *n];
                let r = tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got)).await;
                if matches!(r, Ok(Ok(_))) {
                    out.extend_from_slice(&got);
                } else {
                    out.extend_from_slice(b"<short read>");
                }
            }
            Step::ReadUntil(marker) => {
                let mut buf = Vec::new();
                let mut one = [0u8; 1];
                let fut = async {
                    while !buf.ends_with(marker) {
                        match s.read(&mut one).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => buf.push(one[0]),
                        }
                    }
                };
                if tokio::time::timeout(Duration::from_secs(10), fut)
                    .await
                    .is_err()
                {
                    buf.extend_from_slice(b"<timeout>");
                }
                out.extend_from_slice(&buf);
            }
            Step::HalfClose => {
                let _ = s.shutdown().await;
            }
            Step::ReadToClose => {
                out.extend(
                    read_to_close(&mut s)
                        .await
                        .unwrap_or_else(|e| e.into_bytes()),
                );
            }
            Step::Pause(ms) => tokio::time::sleep(Duration::from_millis(*ms)).await,
        }
    }
    out
}

/// One step of a conversation that needs the server's reply before continuing.
#[derive(Clone)]
pub enum Step {
    Send(Vec<u8>),
    ReadBytes(usize),
    ReadUntil(Vec<u8>),
    HalfClose,
    ReadToClose,
    Pause(u64),
}

/// Conversations where timing or state across requests matters.
pub async fn scenario_checks(go: &BTreeMap<String, u16>, rust: &RustSide) -> (usize, usize) {
    let scenarios = crate::cases::scenarios();
    let mut bad = 0;
    let total = scenarios.len();
    for (name, listener, script, side_id) in scenarios {
        let (g, r) = tokio::join!(
            step_exchange(go[listener], &script),
            step_exchange(rust.ports[listener], &script)
        );
        let (ng, nr) = (normalize(&g), normalize(&r));
        let (mut gs, mut rs) = (String::new(), String::new());
        if let Some(id) = side_id {
            // Handlers record after the response; give both a moment on a case that waits on a hangup.
            tokio::time::sleep(Duration::from_millis(100)).await;
            gs = go_control(go["control"], &format!("/side?id={id}")).await;
            rs = rust.side_value(id);
        }
        if ng != nr || gs != rs {
            bad += 1;
            report("scenario", name, &ng, &nr);
            if gs != rs {
                eprintln!("  side go {gs:?}\n  side rust {rs:?}");
            }
        }
    }
    (total, bad)
}
