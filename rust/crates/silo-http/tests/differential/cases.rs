//! The request corpus: every route pattern from the inventory, adversarial paths, the Range matrix,
//! and raw protocol cases.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::mirror::{Routes, inventory, media_routes};
use crate::wire::{Case, Mode, Step};

const HOST: &str = "example.test";

fn req(method: &str, target: &str) -> Vec<u8> {
    format!("{method} {target} HTTP/1.1\r\nHost: {HOST}\r\n\r\n").into_bytes()
}

fn req_body(method: &str, target: &str, body: &str) -> Vec<u8> {
    format!(
        "{method} {target} HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Fills a chi pattern's `{params}` and `*` with `value`.
fn instantiate(pattern: &str, value: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in pattern.chars() {
        match c {
            '{' => {
                if depth == 0 {
                    out.push_str(value);
                }
                depth += 1;
            }
            '}' => depth -= 1,
            '*' if depth == 0 => out.push_str(value),
            c if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

const VALUES: &[&str] = &[
    "abc123",
    "A%20B",
    "A%2FB",
    "%E2%82%AC",
    "a.b-c_d~e",
    "%ff",
    "123",
    "x%2Fy%2Fz",
    "caf\u{e9}",
    "a:b@c",
    "%25",
];

fn group_by_path(routes: &Routes) -> BTreeMap<String, BTreeSet<String>> {
    let mut m: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (method, path) in routes {
        m.entry(path.clone()).or_default().insert(method.clone());
    }
    m
}

fn cases_for(listener: &str, routes: &Routes, full: bool) -> Vec<Case> {
    let mut out = Vec::new();
    for (pattern, methods) in group_by_path(routes) {
        let first = methods
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "GET".to_owned());
        let dynamic = pattern.contains('{') || pattern.contains('*');
        let values: &[&str] = if dynamic {
            if full { VALUES } else { &VALUES[..3] }
        } else {
            &VALUES[..1]
        };
        for v in values {
            out.push(Case::new(listener, req(&first, &instantiate(&pattern, v))));
        }
        let base = instantiate(&pattern, "abc123");
        for m in &methods {
            out.push(Case::new(listener, req(m, &base)));
        }
        if methods
            .iter()
            .any(|m| m == "POST" || m == "PUT" || m == "PATCH")
        {
            let m = methods
                .iter()
                .find(|m| *m == "POST" || *m == "PUT" || *m == "PATCH")
                .unwrap();
            out.push(Case::new(listener, req_body(m, &base, "{\"a\":1}")));
        }
        for m in ["HEAD", "OPTIONS", "PATCH", "get", "FOO", "QUERY"] {
            out.push(Case::new(listener, req(m, &base)));
        }
        let mut variants = vec![
            format!("{base}/"),
            format!("{base}?q=1&x=%20"),
            format!("{base}?"),
        ];
        if full {
            let upper = silo_gocompat::strings::to_upper(&base);
            let doubled = base.replacen('/', "//", 2);
            let encoded_slash = {
                let mut parts = base.splitn(3, '/');
                let (a, b, c) = (
                    parts.next().unwrap_or(""),
                    parts.next().unwrap_or(""),
                    parts.next().unwrap_or(""),
                );
                format!("{a}/{b}%2F{c}")
            };
            variants.extend([
                format!("{base}//"),
                format!("{base}/."),
                format!("{base}/../x"),
                format!("/{base}"),
                doubled,
                upper,
                encoded_slash,
                format!("{base}%20"),
                format!("{base}#frag"),
            ]);
        }
        for t in variants {
            out.push(Case::new(listener, req(&first, &t)));
        }
    }
    out
}

pub fn route_cases(repo: &Path) -> Vec<Case> {
    let mut out = Vec::new();
    out.extend(cases_for("chi-api", &inventory(repo, "api"), true));
    out.extend(cases_for("chi-proxy", &inventory(repo, "proxy"), true));
    out.extend(cases_for(
        "chi-transcode",
        &inventory(repo, "transcode_node"),
        true,
    ));
    out.extend(cases_for("mux-root", &inventory(repo, "root"), true));
    out.extend(cases_for(
        "mux-debug",
        &inventory(repo, "operational_debug"),
        true,
    ));
    out.extend(cases_for(
        "mux-metrics",
        &inventory(repo, "operational_metrics"),
        true,
    ));
    out
}

pub fn media_route_cases(repo: &Path) -> Vec<Case> {
    let mut out = Vec::new();
    out.extend(cases_for(
        "chi-media-api",
        &media_routes(repo, "internal/api/testdata/media_routes.txt"),
        false,
    ));
    out.extend(cases_for(
        "chi-media-jelly",
        &media_routes(repo, "internal/jellycompat/testdata/media_routes.txt"),
        true,
    ));
    out.extend(cases_for(
        "chi-media-abs",
        &media_routes(repo, "internal/audiobooks/abs/testdata/media_routes.txt"),
        true,
    ));
    out.extend(cases_for(
        "chi-media-proxy",
        &media_routes(repo, "internal/proxy/testdata/media_routes.txt"),
        true,
    ));
    out.extend(cases_for(
        "chi-media-node",
        &media_routes(repo, "internal/transcodenode/testdata/media_routes.txt"),
        true,
    ));
    out
}

pub fn chi_cases() -> Vec<Case> {
    let paths = [
        "/s/static",
        "/s/static/",
        "/s/staticx",
        "/s/x",
        "/s/x/",
        "/s/x/x",
        "/s/x/y",
        "/s/x/x/x",
        "/s/",
        "/s",
        "/s/a/b/c",
        "/s/%2F",
        "/s/a%2Fb",
        "/s/a%2Fb/x",
        "/m/a.b",
        "/m/a.b.c",
        "/m/.b",
        "/m/a.",
        "/m/a-b.c",
        "/m/a-b-c.d",
        "/m/name.jpg",
        "/m/name.png",
        "/m/.jpg",
        "/m/pre-a",
        "/m/pre-",
        "/m/pre-a/post",
        "/m/pre-a/other",
        "/m/a-suf",
        "/m/-suf",
        "/m/a",
        "/m/a%2Eb",
        "/m/a.b%2Fc",
        "/Videos/1/hls/2/3.ts",
        "/Videos/1/hls/2/3.4.ts",
        "/Videos/1/hls/2/3",
        "/Videos/1/hls/2/.ts",
        "/Videos/1/hls/2/3.",
        "/Videos/1/Trickplay/320/0.jpg",
        "/Videos/1/Trickplay/320/0.png",
        "/Videos/1/Trickplay/320/.jpg",
        "/feed/show.xml",
        "/feed/.xml",
        "/feed/show",
        "/feed/show.xml/",
        "/feed/a.b.xml",
        "/feed/a%2Fb.xml",
        "/r/123",
        "/r/abc",
        "/r/ABC",
        "/r/12a",
        "/r/",
        "/r/a-b/1",
        "/r/a-b/x",
        "/r/2024-01-02",
        "/r/2024-1-2",
        "/r/x/end",
        "/r/a/b/end",
        "/r//end",
        "/r/%C3%A9x",
        "/r/\u{e9}x",
        "/r/%ffx",
        "/r/%ff%fex",
        "/r/x/empty",
        "/r/123%0A",
        "/mm",
        "/mm/",
        "/mm/1",
        "/mm/1/2",
        "/h",
        "/q",
        "/c",
        "/t",
        "/o",
        "/p",
        "/all",
        "/all/",
        "/spaced",
        "/tabbed",
        "/sub",
        "/sub/",
        "/sub/a",
        "/sub/a/",
        "/sub/x",
        "/sub/deep",
        "/sub/deep/",
        "/sub/deep/1",
        "/sub/deep/1/2",
        "/sub/none/none",
        "/mnt",
        "/mnt/",
        "/mnt/a",
        "/mnt/a/b",
        "/own",
        "/own/",
        "/own/x",
        "/own/y",
        "/inherit/x",
        "/inherit/y",
        "/inherit",
        "/with",
        "/grp",
        "/grp2",
        "/t1/v/9",
        "/t1/v/",
        "/t1/v",
        "/t%2F1/v/9",
        "/nope",
        "/",
        "//",
        "///",
        "/s//x",
        "/%2e%2e/",
        "/%zz",
        "/a b",
        "/s/a b",
        "/s/\"",
        "/s/<x>",
        "/s/`",
        "/s/^",
        "/s/{",
        "/s/|",
        "/s/\\",
        "/s/;x",
        "/s/x;y=1",
    ];
    let methods = [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "QUERY", "CONNECT", "TRACE",
        "BOGUS", "get",
    ];
    let mut out = Vec::new();
    for p in paths {
        for m in methods {
            out.push(Case::new("chi-adv", req(m, p)));
        }
    }
    for p in [
        "/sub/x",
        "/sub/y",
        "/sub",
        "/only-get",
        "/none",
        "/late/x",
        "/late/y",
        "/",
    ] {
        for m in ["GET", "POST", "BOGUS"] {
            out.push(Case::new("chi-handlers", req(m, p)));
        }
    }
    for p in [
        "/Items",
        "/items",
        "/items/",
        "/ITEMS",
        "/items/5",
        "/items/5/",
        "/users/a/items",
        "/USERS/a/ITEMS/",
        "/system/info/public",
        "/System/Info/Public",
        "/System/Info/Public/",
        "/web",
        "/web/",
        "/web/x",
        "/web/x/",
        "/Web",
        "/items%2F",
        "/items/a%2Fb",
        "/items/a%20b",
        "/users/%E2%82%AC/items",
        "/",
        "//items",
    ] {
        for m in ["GET", "POST", "HEAD"] {
            out.push(Case::new("chi-rewrite", req(m, p)));
        }
    }
    for p in [
        "/a",
        "/a/",
        "/a/b/",
        "/a//",
        "//a/",
        "/a/?x=1",
        "/a/b/?x=1&y=2",
        "/\\evil.com/",
        "/%5Cevil.com/",
        "/x/",
        "/",
    ] {
        for m in ["GET", "HEAD", "POST"] {
            out.push(Case::new("chi-redirect", req(m, p)));
        }
    }
    // Host and scheme forms reach handlers through chi as well.
    for raw in [
        "GET http://other.test/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET http://other.test:8080/s/x?y=1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET HTTP://OTHER.test/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET https://u:p@other.test/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET ftp://a:1:2/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET http://a:1:2/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET http://[::1]:8080/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET http://[::1%25en0]/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET http://[1.2.3.4]/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET http://[bad]/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET http://%41/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET http://%C3%A9/s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET mailto:x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET //s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET ?x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "GET * HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc",
        "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "CONNECT example.test:443 HTTP/1.1\r\n\r\n",
        "CONNECT /s/x HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "CONNECT /c HTTP/1.1\r\nHost: example.test\r\n\r\n",
    ] {
        out.push(Case::raw("chi-adv", raw.as_bytes().to_vec()));
    }
    out
}

pub fn servemux_cases() -> Vec<Case> {
    let targets = [
        "/",
        "/api",
        "/api/",
        "/api?x=1",
        "/api?",
        "/api/?x=1",
        "/api/v1/health",
        "/api//v1/health",
        "/api/./v1/health",
        "/api/../api/v1/health",
        "/api/v1/../v1/health",
        "/api/v1/health/",
        "/API",
        "/api%2F",
        "/%61pi/",
        "/ap%69",
        "/metrics",
        "/metrics/",
        "/metrics?x=1",
        "/x",
        "/x/",
        "//",
        "///",
        "//x",
        "/x//y",
        "/x/./y",
        "/x/../y",
        "/x/..",
        "/x/.",
        "/..",
        "/.",
        "/../",
        "/./",
        "/x/%2e%2e/y",
        "/%2e",
        "/x%2Fy",
        "/x%2F/y",
        "/a b",
        "/a%20b",
        "/\u{e9}",
        "/%C3%A9",
        "/x?y=/../z",
        "/x//y?a=b&c=d",
        "/x//y?",
        "/x#f",
        "/x;y",
        "//api/",
        "/api/%2e%2e/x",
        "*",
    ];
    let mut out = Vec::new();
    for t in targets {
        for m in ["GET", "HEAD", "POST", "PUT", "OPTIONS", "CONNECT", "BOGUS"] {
            out.push(Case::new("mux-root", req(m, t)));
        }
    }
    let pat_targets = [
        "/static",
        "/static/",
        "/static/a/b",
        "/static//a",
        "/items/1",
        "/items/1/",
        "/items",
        "/items/",
        "/items/a%2Fb",
        "/items/%E2%82%AC",
        "/files",
        "/files/",
        "/files/a/b/c",
        "/files/a%2Fb",
        "/files/a//b",
        "/exact",
        "/exact/",
        "/exact/x",
        "/hosted",
        "/hosted/",
        "/hosted/x",
        "/a%2fb",
        "/a%2fb/",
        "/a%2fb/c",
        "/a/b",
        "/a%2Fb/",
        "/conn",
        "/conn/",
        "/headonly",
        "/tree",
        "/tree/",
        "/tree/x",
        "/tree?x=1",
        "/w/x/seg/y",
        "/w/x/seg/y/",
        "/w/x/seg",
        "/none",
        "/",
        "*",
        "/Static/",
    ];
    for t in pat_targets {
        for m in ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT"] {
            let names = "X-Path-Values: id,path,a,b\r\n";
            let plain = format!("{m} {t} HTTP/1.1\r\nHost: {HOST}\r\n{names}\r\n");
            out.push(Case::new("mux-patterns", plain.into_bytes()));
            let hosted = format!("{m} {t} HTTP/1.1\r\nHost: example.com:8080\r\n{names}\r\n");
            out.push(Case::new("mux-patterns", hosted.into_bytes()));
        }
    }
    for r in [
        "GET /b/42",
        "GET /b/a%2Fb",
        "GET /b/42/",
        "PUT /b/42",
        "HEAD /b/42",
    ] {
        out.push(Case::new(
            "bridge",
            format!("{r} HTTP/1.1\r\nHost: {HOST}\r\n\r\n").into_bytes(),
        ));
    }
    out.push(Case::new("bridge", req_body("POST", "/b/1", "payload")));
    for raw in [
        "GET /hosted/ HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
        "GET /hosted/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET http://example.com/hosted/ HTTP/1.1\r\nHost: other\r\n\r\n",
        "GET /tree HTTP/1.0\r\n\r\n",
        "GET /x//y HTTP/1.0\r\n\r\n",
        "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "CONNECT /tree HTTP/1.1\r\nHost: x\r\n\r\n",
        "CONNECT x:1 HTTP/1.1\r\n\r\n",
    ] {
        out.push(Case::raw("mux-patterns", raw.as_bytes().to_vec()));
    }
    out
}

/// A reproducible byte source for the binary fixtures.
fn prng_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xff) as u8
        })
        .collect()
}

const SIZES: &[usize] = &[
    0,
    1,
    100,
    511,
    512,
    513,
    1000,
    2047,
    2048,
    2049,
    4096,
    10_000,
    70_000,
    1 << 20,
];

fn fixture_names() -> Vec<String> {
    let mut names = Vec::new();
    for s in SIZES {
        names.push(format!("text-{s}.txt"));
        names.push(format!("noext-{s}"));
        names.push(format!("bin-{s}.bin"));
        names.push(format!("html-{s}.html"));
        names.push(format!("png-{s}"));
    }
    names
}

pub fn write_fixtures(dir: &Path) {
    for s in SIZES {
        let n = *s;
        let write = |name: String, data: Vec<u8>| {
            std::fs::write(
                silo_gocompat::filepath::join(&[dir.to_string_lossy().as_ref(), name.as_str()]),
                data,
            )
            .unwrap();
        };
        let text: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
        write(format!("text-{n}.txt"), text.clone());
        write(format!("noext-{n}"), text.clone());
        write(format!("bin-{n}.bin"), prng_bytes(n as u64 + 7, n));
        let mut html = b"<html><body>".to_vec();
        html.extend_from_slice(&text);
        html.truncate(n);
        write(format!("html-{n}.html"), html);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&prng_bytes(n as u64 + 11, n));
        png.truncate(n);
        write(format!("png-{n}"), png);
    }
    let sub = silo_gocompat::filepath::join(&[dir.to_string_lossy().as_ref(), "sub"]);
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(
        silo_gocompat::filepath::join(&[sub.as_str(), "index.html"]),
        b"<html>index</html>",
    )
    .unwrap();
    std::fs::write(
        silo_gocompat::filepath::join(&[sub.as_str(), "other.txt"]),
        b"other",
    )
    .unwrap();
    let list = silo_gocompat::filepath::join(&[dir.to_string_lossy().as_ref(), "list"]);
    std::fs::create_dir_all(silo_gocompat::filepath::join(&[list.as_str(), "d?ir"])).unwrap();
    std::fs::write(
        silo_gocompat::filepath::join(&[list.as_str(), "a b&c.txt"]),
        b"x",
    )
    .unwrap();
    std::fs::write(
        silo_gocompat::filepath::join(&[list.as_str(), "z<y>.txt"]),
        b"x",
    )
    .unwrap();
    std::fs::write(silo_gocompat::filepath::join(&[list.as_str(), "x:y"]), b"x").unwrap();
    // A fixed mtime, so the two servers' Last-Modified lines cannot straddle a second.
    let stamp =
        std::process::Command::new("touch")
            .args(["-t", "202301021504.05"])
            .args(fixture_names().iter().map(|n| {
                silo_gocompat::filepath::join(&[dir.to_string_lossy().as_ref(), n.as_str()])
            }))
            .arg(&sub)
            .arg(&list)
            .status()
            .unwrap();
    assert!(stamp.success());
}

const RANGES: &[&str] = &[
    "",
    "bytes=0-0",
    "bytes=0-",
    "bytes=-1",
    "bytes=-0",
    "bytes=0-99",
    "bytes=1-1",
    "bytes=5-2",
    "bytes=99-",
    "bytes=100-",
    "bytes=0-99999999",
    "bytes=-99999999",
    "bytes=0-0,2-2",
    "bytes=0-0,-1",
    "bytes=0-1,1-2",
    "bytes=0-,0-",
    "bytes=0-0, 2-2 , 4-4",
    "bytes=,",
    "bytes=,,0-0",
    "bytes=",
    "bytes",
    "bites=0-1",
    "bytes=a-b",
    "bytes=1-a",
    "bytes=-a",
    "bytes=--1",
    "bytes=0--1",
    "bytes= 0 - 1 ",
    "bytes=18446744073709551616-",
    "bytes=0-18446744073709551616",
    "BYTES=0-1",
    "bytes=0-0,100000-200000",
    "bytes=100000-200000,100001-200001",
    "bytes=+1-2",
    "bytes=1-+2",
    "bytes=512-1023,2048-",
    "bytes=0-511,512-1023,1024-1535",
];

fn content_target(file: &str, extra: &str) -> String {
    format!("/c?f={file}{extra}")
}

fn range_request(method: &str, target: &str, range: &str, extra: &str) -> Vec<u8> {
    let mut r = format!("{method} {target} HTTP/1.1\r\nHost: {HOST}\r\n");
    if !range.is_empty() {
        r += &format!("Range: {range}\r\n");
    }
    r += extra;
    r += "\r\n";
    r.into_bytes()
}

pub fn range_cases() -> Vec<Case> {
    let mut out = Vec::new();
    for file in fixture_names() {
        for range in RANGES {
            for method in ["GET", "HEAD"] {
                out.push(Case::new(
                    "content",
                    range_request(method, &content_target(&file, ""), range, ""),
                ));
            }
        }
    }
    out
}

/// `net/http/fs.go`'s `defaultMaxContentRanges` (200): a `Range` header with more ranges than
/// that is ignored outright (full 200 response) rather than parsed. Needs a fixture bigger than
/// the range count so every range is individually valid and the limit itself is what's tested,
/// not the fallback for ranges past EOF.
pub fn range_limit_cases() -> Vec<Case> {
    let counts = [199usize, 200, 201, 300];
    let mut out = Vec::new();
    for file in ["text-1000.txt", "bin-1000.bin"] {
        for &n in &counts {
            let range = format!(
                "bytes={}",
                (0..n)
                    .map(|i| format!("{i}-{i}"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            for method in ["GET", "HEAD"] {
                out.push(Case::new(
                    "content",
                    range_request(method, &content_target(file, ""), &range, ""),
                ));
            }
        }
    }
    out
}

const STRONG: &str = "\"v1\"";
const LAST_MODIFIED: &str = "Tue, 14 Nov 2023 22:13:20 GMT";

pub fn conditional_cases() -> Vec<Case> {
    let conds: &[&str] = &[
        "",
        "If-Range: \"v1\"\r\n",
        "If-Range: \"other\"\r\n",
        "If-Range: W/\"v1\"\r\n",
        "If-Range: Tue, 14 Nov 2023 22:13:20 GMT\r\n",
        "If-Range: Tue, 14 Nov 2023 22:13:21 GMT\r\n",
        "If-Range: Mon, 13 Nov 2023 22:13:20 GMT\r\n",
        "If-Range: not a date\r\n",
        "If-Range: \"v1\" trailing\r\n",
        "If-Range: Tuesday, 14-Nov-23 22:13:20 GMT\r\n",
        "If-Range: Tue Nov 14 22:13:20 2023\r\n",
        "If-Match: \"v1\"\r\n",
        "If-Match: *\r\n",
        "If-Match: \"other\"\r\n",
        "If-Match: W/\"v1\"\r\n",
        "If-Match: \"a\", \"v1\"\r\n",
        "If-Match: ,,\"v1\"\r\n",
        "If-Match: garbage\r\n",
        "If-None-Match: \"v1\"\r\n",
        "If-None-Match: W/\"v1\"\r\n",
        "If-None-Match: *\r\n",
        "If-None-Match: \"other\"\r\n",
        "If-None-Match: \"a\", W/\"v1\"\r\n",
        "If-None-Match: garbage\r\n",
        "If-Modified-Since: Tue, 14 Nov 2023 22:13:20 GMT\r\n",
        "If-Modified-Since: Tue, 14 Nov 2023 22:13:21 GMT\r\n",
        "If-Modified-Since: Mon, 13 Nov 2023 22:13:20 GMT\r\n",
        "If-Modified-Since: Tuesday, 14-Nov-23 22:13:20 GMT\r\n",
        "If-Modified-Since: Tuesday, 14-Nov-23 22:13:20 PST\r\n",
        "If-Modified-Since: Tue Nov 14 22:13:20 2023\r\n",
        "If-Modified-Since: garbage\r\n",
        "If-Unmodified-Since: Tue, 14 Nov 2023 22:13:20 GMT\r\n",
        "If-Unmodified-Since: Mon, 13 Nov 2023 22:13:20 GMT\r\n",
        "If-Unmodified-Since: garbage\r\n",
        "If-Match: \"v1\"\r\nIf-Unmodified-Since: Mon, 13 Nov 2023 22:13:20 GMT\r\n",
        "If-None-Match: \"other\"\r\nIf-Modified-Since: Tue, 14 Nov 2023 22:13:20 GMT\r\n",
        "If-None-Match: \"v1\"\r\nIf-Range: \"v1\"\r\n",
        "If-Match: \"v1\"\r\nIf-Range: \"v1\"\r\n",
    ];
    let configs = [
        ("&etag=%22v1%22", "etag"),
        ("", "plain"),
        ("&mod=zero", "zero"),
        ("&mod=epoch&etag=%22v1%22", "epoch"),
        ("&mod=nanos", "nanos"),
        ("&etag=W/%22v1%22", "weak"),
        ("&etag=%22v1%22&ct=text/custom&cc=max-age%3D5", "typed"),
    ];
    let _ = (STRONG, LAST_MODIFIED);
    let mut out = Vec::new();
    for file in ["text-1000.txt", "bin-0.bin", "noext-100"] {
        for (cfg, _) in configs {
            for cond in conds {
                for range in ["", "bytes=0-9", "bytes=0-1,4-5", "bytes=99999-"] {
                    for method in ["GET", "HEAD", "POST"] {
                        out.push(Case::new(
                            "content",
                            range_request(method, &content_target(file, cfg), range, cond),
                        ));
                    }
                }
            }
        }
    }
    out
}

pub fn content_config_cases() -> Vec<Case> {
    let configs = [
        "&ce=gzip",
        "&ct=application/x-custom",
        "&noct=1",
        "&cc=no-store",
        "&ce=gzip&etag=%22x%22&cc=no-store",
        "&lm=Mon,%2001%20Jan%202001%2000:00:00%20GMT",
        "&mod=zero&lm=Mon,%2001%20Jan%202001%2000:00:00%20GMT",
        "&name=",
        "&name=x.css",
        "&name=X.CSS",
        "&name=x.mp4",
        "&name=x.webm",
        "&name=x.vtt",
        "&name=x.ts",
        "&name=x.mkv",
        "&name=x.unknownext",
        "&name=dir.d/file",
        "&name=.bashrc",
        "&ct=",
        "&ct=&ce=br",
    ];
    let mut out = Vec::new();
    for cfg in configs {
        for file in [
            "text-0.txt",
            "text-100.txt",
            "text-70000.txt",
            "bin-513.bin",
            "html-513.html",
            "noext-1",
            "png-2049",
        ] {
            for range in [
                "",
                "bytes=0-0",
                "bytes=0-0,2-2",
                "bytes=x",
                "bytes=99999999-",
            ] {
                for method in ["GET", "HEAD"] {
                    out.push(Case::new(
                        "content",
                        range_request(method, &content_target(file, cfg), range, ""),
                    ));
                }
            }
        }
    }
    out
}

pub fn serve_file_cases() -> Vec<Case> {
    let mut out = Vec::new();
    for f in [
        "text-100.txt",
        "bin-513.bin",
        "noext-1000",
        "sub",
        "sub/",
        "sub/index.html",
        "sub/other.txt",
        "list",
        "missing",
        "text-100.txt/x",
        "../escape",
        "text-0.txt",
        "text-70000.txt",
    ] {
        for (method, range, extra) in [
            ("GET", "", ""),
            ("HEAD", "", ""),
            ("GET", "bytes=0-1", ""),
            ("GET", "bytes=0-0,1-1", ""),
            (
                "GET",
                "",
                "If-Modified-Since: Mon, 02 Jan 2023 15:04:05 GMT\r\n",
            ),
            (
                "GET",
                "",
                "If-Modified-Since: Mon, 01 Jan 2024 15:04:05 GMT\r\n",
            ),
        ] {
            let target = format!("/any?f={}", f.replace(' ', "%20"));
            out.push(Case::new(
                "servefile",
                range_request(method, &target, range, extra),
            ));
        }
    }
    out.push(Case::new("servefile", req("GET", "/a/../b?f=text-100.txt")));
    out.push(Case::new(
        "servefile",
        req("GET", "/index.html?f=text-100.txt"),
    ));
    out.push(Case::new(
        "servefile",
        req("GET", "/x/index.html?f=text-100.txt&y=1"),
    ));
    for t in [
        "/pub",
        "/pub/",
        "/pub/text-100.txt",
        "/pub/text-100.txt/",
        "/pub/sub",
        "/pub/sub/",
        "/pub/sub/index.html",
        "/pub/sub/other.txt",
        "/pub/sub/?q=1",
        "/pub/sub?q=1",
        "/pub/list/",
        "/pub/list",
        "/pub/missing",
        "/pub/text-100.txt/x",
        "/pub/../secret",
        "/pub//text-100.txt",
        "/other",
        "/",
        "/pub%2Ftext-100.txt",
        "/pub/%2e%2e/x",
        "/pub/sub%2Fother.txt",
        "/pub/a%00b",
    ] {
        for method in ["GET", "HEAD", "POST"] {
            out.push(Case::new("fileserver", req(method, t)));
        }
        out.push(Case::new(
            "fileserver",
            range_request("GET", t, "bytes=0-1", ""),
        ));
    }
    out
}

/// Scripts for the response writer: `Set`, `WriteHeader`, `Write`, `Flush`, and so on, one call each.
const SCRIPTS: &[&str] = &[
    "",
    "wh,200",
    "wh,204",
    "wh,304",
    "wh,404",
    "wh,500",
    "wh,599",
    "wh,999",
    "wh,100",
    "wh,99",
    "wh,1000",
    "wh,103",
    "wh,103|wh,200",
    "h,Link,%3C/a%3E|wh,103|d,Link|wh,200|w,5,x",
    "h,Content-Length,5|wh,103|wh,200|w,5,x",
    "wh,101",
    "h,Upgrade,x|h,Connection,Upgrade|wh,101",
    "wh,200|wh,404",
    "w,1,a",
    "w,5,a",
    "w,511,a",
    "w,512,a",
    "w,513,a",
    "w,2047,a",
    "w,2048,a",
    "w,2049,a",
    "w,4096,a",
    "w,4097,a",
    "w,10000,a",
    "w,70000,a",
    "w,1000,a|w,1000,b",
    "w,1000,a|w,1048,b",
    "w,1000,a|w,1049,b",
    "w,2048,a|w,1,b",
    "w,1,a|w,2048,b",
    "w,1,a|w,4096,b|w,1,c",
    "w,1,a|f|w,1,b",
    "f",
    "f|f",
    "wh,404|f",
    "w,5,a|f",
    "f|w,5,a",
    "ws,5,a",
    "ws,2048,a",
    "ws,2049,a",
    "ws,5000,a",
    "w,1,a|ws,5000,b",
    "rf,5,a",
    "rf,511,a",
    "rf,512,a",
    "rf,513,a",
    "rf,5000,a",
    "rf,70000,a",
    "h,Content-Length,5000|rf,5000,a",
    "h,Content-Length,100|rf,5000,a",
    "h,Content-Length,5000|rf,100,a",
    "w,5,a|rf,5000,b",
    "h,Content-Type,text/x|w,5,a",
    "nil,Content-Type|w,5,a",
    "h,Content-Type,|w,5,a",
    "nil,Date|w,5,a",
    "h,Date,custom|w,5,a",
    "h,Content-Encoding,gzip|w,5,a",
    "h,Content-Encoding,|w,5,a",
    "h,Content-Length,5|w,5,a",
    "h,Content-Length,5|w,4,a",
    "h,Content-Length,5|w,6,a",
    "h,Content-Length,5",
    "h,Content-Length,0",
    "h,Content-Length,abc|w,5,a",
    "h,Content-Length,-1|w,5,a",
    "h,Content-Length,+5|w,5,a",
    "h,Content-Length,%205|w,5,a",
    "h,Content-Length,5|wh,204",
    "h,Content-Length,5|wh,304",
    "h,Content-Length,5|wh,404|w,5,x",
    "h,Transfer-Encoding,chunked|w,5,a",
    "h,Transfer-Encoding,identity|w,5,a",
    "h,Transfer-Encoding,gzip|w,5,a",
    "h,Transfer-Encoding,chunked|h,Content-Length,5|w,5,a",
    "h,Transfer-Encoding,identity|h,Content-Length,5|w,5,a",
    "h,Transfer-Encoding,gzip|h,Content-Length,5|w,5,a",
    "h,Transfer-Encoding,chunked|wh,204",
    "h,Connection,close|w,5,a",
    "h,Connection,keep-alive|w,5,a",
    "h,Connection,Close|w,5,a",
    "h,Connection,x|w,5,a",
    "h,Connection,close,x|w,3000,a",
    "h,Trailer,X-T|w,5,a|h,X-T,v",
    "h,Trailer,X-T,X-U|w,5,a|h,X-T,1|h,X-U,2",
    "h,Trailer,Content-Length|w,5,a",
    "h,Trailer,If-Match|w,5,a|h,If-Match,x",
    "a,Trailer,X-A|a,Trailer,X-B|w,3000,a|h,X-A,1|h,X-B,2",
    "w,5,a|h,Trailer:X-Late,v",
    "w,3000,a|h,Trailer:X-Late,v|a,Trailer:X-Late,w",
    "h,Trailer:X-Early,v|w,5,a",
    "h,x-lower,v|a,X-Lower,w",
    "raw,x-raw,v|w,5,a",
    "raw,Bad%20Key,v|w,5,a",
    "raw,Bad:Key,v|w,5,a",
    "h,X-New,a%0Ab%0Dc|w,5,a",
    "h,X-Sp,%20%09v%20%09|w,5,a",
    "h,X-High,%C3%A9|w,5,a",
    "h,X-Ff,%FF|w,5,a",
    "h,X-Empty,|w,5,a",
    "nil,X-Nil|w,5,a",
    "a,X-M,1|a,X-M,2|a,x-m,3|w,5,a",
    "w,5,a|h,X-Late,v",
    "wh,200|h,X-After-Wh,v|w,5,a",
    "h,X-B,1|wh,200|d,X-B|w,5,a",
    "w,5000,a|h,X-Too-Late,v",
    "e,500,boom",
    "h,Content-Length,5|h,Content-Encoding,gzip|h,Etag,x|e,404,gone",
    "h,Content-Type,text/x|e,400,a%0Ab",
    "nf",
    "rd,301,/target",
    "rd,302,target",
    "rd,302,../up",
    "rd,307,/a/./b/../c/",
    "rd,301,/%C3%A9",
    "rd,301,/q?x=1&y=%3Cz%3E",
    "rd,301,http://other.test/%3Cz%3E",
    "rd,301,//other.test/x",
    "rd,301,",
    "rd,301,%3Cscript%3E",
    "rd,301,caf%C3%A9",
    "rd,303,x:y",
    "rd,301,http://[bad",
    "h,Content-Type,text/x|rd,301,/t",
    "nil,Content-Type|rd,301,/t",
    "w,5,x|rd,301,/t",
    "panic",
    "abort",
    "w,5,a|panic",
    "w,3000,a|panic",
    "w,3000,a|abort",
    "w,5,a|f|abort",
    "h,X-Before,1|wh,200|abort",
    "wh,204|w,5,a",
    "wh,304|w,5,a",
    "wh,204|w,5,a|f",
    "h,Content-Length,5|rb|w,5,a",
    "rb|w,5,a",
    "rb|echo",
    "cb|w,5,a",
    "cb|cb|w,5,a",
    "rn,2|w,5,a",
    "rn,2|cb|w,5,a",
    "mb,2|rb|e,413,too%20big",
    "mb,2|rb|w,5,a",
    "mb,100|rb|w,5,a",
    "mb,0|rb|w,5,a",
    "mb,-1|rb|w,5,a",
    "mb,2|w,5,a",
    "fd|w,5,a|rb",
    "echo",
    "hj,done",
    "w,5,a|hj,done",
    "wh,200|hj,done",
    "f|hj,done",
];

fn ops_request(script: &str, line: &str, extra: &str, body: &str) -> Vec<u8> {
    let mut r = format!("{line}\r\nHost: {HOST}\r\nX-Ops: {script}\r\n{extra}");
    if !body.is_empty() {
        r += &format!("Content-Length: {}\r\n", body.len());
    }
    r += "\r\n";
    r += body;
    r.into_bytes()
}

pub fn ops_cases() -> Vec<Case> {
    let mut out = Vec::new();
    let lines = [
        ("GET /o HTTP/1.1", "", ""),
        ("HEAD /o HTTP/1.1", "", ""),
        ("GET /o HTTP/1.0", "", ""),
        ("GET /o HTTP/1.0", "Connection: keep-alive\r\n", ""),
        ("HEAD /o HTTP/1.0", "Connection: keep-alive\r\n", ""),
        ("GET /o HTTP/1.1", "Connection: close\r\n", ""),
        ("POST /o HTTP/1.1", "", "hello world"),
        ("POST /o HTTP/1.0", "Connection: keep-alive\r\n", "hello"),
        ("POST /o HTTP/1.1", "Expect: 100-continue\r\n", "hello"),
    ];
    for script in SCRIPTS {
        for (line, extra, body) in lines {
            out.push(Case::raw("ops", ops_request(script, line, extra, body)));
        }
        // Two requests on one connection show whether the first left it reusable.
        let mut pipeline = ops_request(script, "POST /o HTTP/1.1", "", "hello");
        pipeline.extend_from_slice(
            format!("GET /next HTTP/1.1\r\nHost: {HOST}\r\nX-Ops: w,2,z\r\n\r\n").as_bytes(),
        );
        out.push(Case::raw("ops", pipeline));
    }
    out
}

pub fn protocol_cases() -> Vec<Case> {
    let long = "x".repeat(5000);
    let very_long = "x".repeat(70_000);
    let over_limit = "x".repeat(1 << 21);
    let raw: Vec<String> = vec![
        // Request lines.
        "".into(),
        "\r\n".into(),
        "\n".into(),
        "\r\n\r\n".into(),
        "GET".into(),
        "GET /".into(),
        "GET / ".into(),
        "GET / HTTP/1.1".into(),
        "GET / HTTP/1.1\r\n".into(),
        "GET / HTTP/1.1\n\n".into(),
        "GET / HTTP/1.1\nHost: x\n\n".into(),
        "GET  / HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET / HTTP/1.1 \r\nHost: x\r\n\r\n".into(),
        " GET / HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET\t/ HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "G@T / HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "G\u{e9}T / HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET / HTTP/1.2\r\nHost: x\r\n\r\n".into(),
        "GET / HTTP/1.9\r\nHost: x\r\n\r\n".into(),
        "GET / HTTP/2.0\r\nHost: x\r\n\r\n".into(),
        "GET / HTTP/0.9\r\nHost: x\r\n\r\n".into(),
        "GET / HTTP/3.0\r\nHost: x\r\n\r\n".into(),
        "GET / HTTP/11\r\nHost: x\r\n\r\n".into(),
        "GET / HTTP/1.a\r\nHost: x\r\n\r\n".into(),
        "GET / http/1.1\r\nHost: x\r\n\r\n".into(),
        "GET / FTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /\x01 HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /\x7f HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /%zz HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /% HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /a?%zz HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET a HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".into(),
        "PRI * HTTP/2.0\r\nHost: x\r\n\r\nSM\r\n\r\n".into(),
        format!("GET /{long} HTTP/1.1\r\nHost: x\r\n\r\n"),
        format!("GET /{very_long} HTTP/1.1\r\nHost: x\r\n\r\n"),
        // Hosts.
        "GET / HTTP/1.1\r\n\r\n".into(),
        "GET / HTTP/1.0\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost:\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: a b\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: a/b\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: \u{e9}\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nhost: lower\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHOST: upper\r\n\r\n".into(),
        // Header syntax.
        "GET / HTTP/1.1\r\nHost: x\r\nNoColon\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\n: novalue\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nBad Key: v\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nBad Key : v\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey : v\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nK\u{e9}y: v\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey: a\x01b\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey: a\x7fb\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey: a\tb\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey: caf\u{e9}\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey:nospace\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey:   lots   \r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey:\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nK: 1\r\nK: 2\r\nk: 3\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nFold: a\r\n b\r\n\tc\r\n\r\n".into(),
        "GET / HTTP/1.1\r\n Host: x\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\n fold-first: a\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey: v\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nKey: a\rb\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nkEy-nAmE: v\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nx_y: v\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nPragma: no-cache\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nPragma: no-cache\r\nCache-Control: max-age=0\r\n\r\n".into(),
        format!("GET / HTTP/1.1\r\nHost: x\r\nBig: {long}\r\n\r\n"),
        format!("GET / HTTP/1.1\r\nHost: x\r\nBig: {very_long}\r\n\r\n"),
        // Connection.
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: CLOSE\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n".into(),
        "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n".into(),
        "GET / HTTP/1.0\r\nConnection: Keep-Alive, x\r\n\r\n".into(),
        // Bodies.
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhel".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 00005\r\n\r\nhello".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\nhello".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length:\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\nhello".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 9223372036854775807\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 9223372036854775808\r\n\r\n".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello".into(),
        "HEAD / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello".into(),
        // Chunked bodies.
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: CHUNKED\r\n\r\n5\r\nhello\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding:\r\n\r\n".into(),
        "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\na;ext=1\r\n0123456789\r\n0;x\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5  \r\nhello\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n11111111111111111\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nx".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n1\r\na\r\n0\r\nX-T: v\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTrailer: X-T, X-U\r\n\r\n1\r\na\r\n0\r\nX-T: v\r\nX-Other: w\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTrailer: Content-Length\r\n\r\n1\r\na\r\n0\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTrailer: Transfer-Encoding\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTrailer: X-T\r\nContent-Length: 1\r\n\r\na".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nBad Trailer\r\n\r\n".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-T: v\r\n".into(),
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-T: {long}\r\n\r\n"),
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1;{long}\r\na\r\n0\r\n\r\n"),
        format!("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\na\r\n0\r\n\r\n", "e".repeat(3000)),
        // Expect.
        "POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-CONTINUE\r\nContent-Length: 5\r\n\r\nhello".into(),
        "POST / HTTP/1.1\r\nHost: x\r\nExpect: nope\r\nContent-Length: 5\r\n\r\nhello".into(),
        "GET / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n".into(),
        "POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello".into(),
        // Pipelining and leftovers.
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\na\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\na\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /a HTTP/1.0\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\nBAD\r\n\r\n".into(),
        "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        "OPTIONS * HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc".into(),
        format!("OPTIONS * HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\n{}", "a".repeat(5000)),
    ];
    let mut out = Vec::new();
    for r in &raw {
        out.push(Case::raw("ops", ops_with_echo(r)));
    }
    for r in [
        "OPTIONS * HTTP/1.1\r\nHost: x\r\nX-Ops: w,1,a\r\n\r\n",
        "OPTIONS /x HTTP/1.1\r\nHost: x\r\nX-Ops: w,1,a\r\n\r\n",
    ] {
        out.push(Case::raw("opts-off", r.as_bytes().to_vec()));
    }
    // Header limits. Go's real cutoff depends on how its 4 KiB reads line up, so one case on each side.
    let small = "y".repeat(800);
    let big = "y".repeat(6000);
    out.push(Case::raw(
        "smallheaders",
        format!("GET / HTTP/1.1\r\nHost: x\r\nA: {small}\r\n\r\n").into_bytes(),
    ));
    out.push(Case::raw(
        "smallheaders",
        format!("GET / HTTP/1.1\r\nHost: x\r\nA: {big}\r\n\r\n").into_bytes(),
    ));
    out.push(Case::raw(
        "ops",
        format!("GET / HTTP/1.1\r\nHost: x\r\nA: {over_limit}\r\n\r\n").into_bytes(),
    ));
    // Large bodies around the 256 KiB drain limit, unread by the handler.
    for n in [(256usize << 10) - 1, 256 << 10, (256 << 10) + 1, 300 << 10] {
        for script in ["w,5,a", "rn,10|w,5,a", "cb|w,5,a", "mb,10|rb|e,413,big"] {
            let body = "b".repeat(n);
            let head = format!(
                "POST /o HTTP/1.1\r\nHost: x\r\nX-Ops: {script}\r\nContent-Length: {n}\r\n\r\n"
            );
            let mut r = head.into_bytes();
            r.extend_from_slice(body.as_bytes());
            r.extend_from_slice(
                format!("GET /next HTTP/1.1\r\nHost: {HOST}\r\nX-Ops: w,2,z\r\n\r\n").as_bytes(),
            );
            out.push(Case::raw("ops", r));
        }
        // The same with a chunked body, where the unread size is unknown.
        for script in ["w,5,a", "rn,10|w,5,a"] {
            let mut r = format!("POST /o HTTP/1.1\r\nHost: x\r\nX-Ops: {script}\r\nTransfer-Encoding: chunked\r\n\r\n").into_bytes();
            r.extend_from_slice(format!("{n:x}\r\n").as_bytes());
            r.extend_from_slice("b".repeat(n).as_bytes());
            r.extend_from_slice(b"\r\n0\r\n\r\n");
            r.extend_from_slice(
                format!("GET /next HTTP/1.1\r\nHost: {HOST}\r\nX-Ops: w,2,z\r\n\r\n").as_bytes(),
            );
            out.push(Case::raw("ops", r));
        }
    }
    out
}

/// Adds an `X-Ops: echo` header after the request line's Host, when the request has a request line
/// and a header section to carry it. Requests that fail before the handler keep their shape.
fn ops_with_echo(raw: &str) -> Vec<u8> {
    match raw.find("\r\n") {
        Some(i) if raw[i..].len() > 2 && raw[..i].contains(" HTTP/") => {
            let mut out = raw.as_bytes()[..i + 2].to_vec();
            out.extend_from_slice(b"X-Ops: echo\r\n");
            out.extend_from_slice(&raw.as_bytes()[i + 2..]);
            out
        }
        _ => raw.as_bytes().to_vec(),
    }
}

fn compress_case(listener: &str, method: &str, accept: &str, script: &str) -> Case {
    let accept_line = if accept == "<none>" {
        String::new()
    } else {
        format!("Accept-Encoding: {accept}\r\n")
    };
    let mut c = Case::new(
        listener,
        format!("{method} /z HTTP/1.1\r\nHost: {HOST}\r\n{accept_line}X-Ops: {script}\r\n\r\n")
            .into_bytes(),
    );
    c.mode = Mode::Decoded;
    c
}

pub fn compression_cases() -> Vec<Case> {
    let accepts = [
        "<none>",
        "",
        "gzip",
        "br",
        "zstd",
        "identity",
        "*",
        "x-gzip",
        "GZIP",
        "gzip, br",
        "br, gzip",
        "zstd, br, gzip",
        "gzip;q=0.5, br;q=0.5",
        "gzip;q=0.5, br;q=0.6",
        "br;q=0.9, zstd;q=0.8, gzip;q=1",
        "gzip;q=0",
        "gzip;q=0, *",
        "*;q=0",
        "identity;q=0",
        "identity;q=0, gzip",
        "identity;q=0, *;q=0",
        "identity;q=1, gzip;q=0.5",
        "identity;q=0.5, gzip;q=0.5",
        "identity;q=0.1, gzip;q=0.5",
        "*;q=0.5, gzip;q=0.1",
        "gzip;q=2",
        "gzip;q=-1",
        "gzip;q=abc",
        "gzip;q=",
        "gzip;Q=0.5",
        "gzip; q=0.5",
        "gzip ;q=0.5",
        ";q=0.5",
        ",",
        "gzip,",
        ",gzip",
        "deflate",
        "deflate, gzip;q=0.1",
        "unknown, *;q=0.2",
        "gzip;q=0.5;q=0",
        "gzip;x=1",
        "gzip;q=0x1p-1",
        "gzip;q=1e-1",
        "gzip;q=.5",
        "gzip;q=1.",
        "gzip;q=+1",
        "gzip;q=nan",
        "gzip;q=inf",
    ];
    let bodies = [
        "h,Content-Type,application/json|w,2000,a",
        "h,Content-Type,application/json|w,5,a",
        "h,Content-Type,application/json|h,Content-Length,5|w,5,a",
        "h,Content-Type,application/json|h,Content-Length,300|w,300,a",
        "w,3000,a",
        "h,Content-Type,image/png|w,3000,a",
        "h,Content-Type,application/json;%20charset=utf-8|w,3000,a",
        "h,Content-Type,TEXT/PLAIN|w,3000,a",
    ];
    let mut out = Vec::new();
    for a in accepts {
        for b in bodies {
            out.push(compress_case("compress", "GET", a, b));
        }
    }
    for script in [
        "wh,204",
        "wh,304",
        "h,Content-Type,text/plain|wh,204",
        "h,Content-Type,text/plain|wh,206|w,500,a",
        "h,Content-Type,text/plain|h,Content-Encoding,br|w,500,a",
        "h,Content-Type,text/plain|h,Content-Encoding,identity|w,500,a",
        "h,Content-Type,text/plain|h,Content-Range,bytes%200-1/2|w,500,a",
        "h,Content-Type,text/plain|wh,103|wh,200|w,500,a",
        "h,Content-Type,text/plain|f|w,500,a",
        "h,Content-Type,text/plain|w,500,a|f|w,500,b",
        "h,Content-Type,text/plain|w,70000,a",
        "h,Content-Type,text/plain|w,70000,a|f|w,10,b",
        "h,Content-Type,text/plain|h,Vary,Origin|w,500,a",
        "h,Content-Type,text/plain",
        "h,Content-Type,text/plain|wh,200",
        "e,500,boom",
        "nf",
        "rd,301,/x",
        "f",
    ] {
        for a in ["gzip", "br", "zstd", "identity;q=0, gzip", "<none>"] {
            out.push(compress_case("compress", "GET", a, script));
            out.push(compress_case("compress", "HEAD", a, script));
        }
    }
    for script in [
        "h,Content-Type,text/custom|w,500,a",
        "h,Content-Type,text/custom|h,X-No-Compress,1|w,500,a",
        "h,Content-Type,text/plain|w,500,a",
    ] {
        out.push(compress_case("compress-types", "GET", "gzip", script));
    }
    out
}

/// A scenario: a name, a listener, the script, and the side-channel id its handler records under.
pub type Scenario = (&'static str, &'static str, Vec<Step>, Option<&'static str>);

fn send(s: &str) -> Step {
    Step::Send(s.as_bytes().to_vec())
}

pub fn scenarios() -> Vec<Scenario> {
    let hdr_end = b"\r\n\r\n".to_vec();
    vec![
        (
            "expect-continue: the 100 goes out on the first body read, not before",
            "ops",
            vec![
                send(
                    "POST /o HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\nX-Ops: rb|w,2,z\r\n\r\n",
                ),
                Step::ReadUntil(hdr_end.clone()),
                send("hello"),
                Step::ReadUntil(hdr_end.clone()),
                Step::ReadBytes(2),
                Step::HalfClose,
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "expect-continue: a reply without reading closes the connection",
            "ops",
            vec![
                send(
                    "POST /o HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\nX-Ops: w,2,z\r\n\r\n",
                ),
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "keep-alive: a second request on the same connection after the first reply",
            "ops",
            vec![
                send("GET /o HTTP/1.1\r\nHost: x\r\nX-Ops: w,2,z\r\n\r\n"),
                Step::ReadUntil(hdr_end.clone()),
                Step::ReadBytes(2),
                send("GET /o HTTP/1.1\r\nHost: x\r\nX-Ops: w,2,y\r\n\r\n"),
                Step::ReadUntil(hdr_end.clone()),
                Step::ReadBytes(2),
                Step::HalfClose,
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "flush: the header and first chunk arrive before the handler finishes",
            "ops",
            vec![
                send(
                    "POST /o HTTP/1.1\r\nHost: x\r\nX-Ops: w,3,a|f|rn,1|w,3,b\r\nContent-Length: 1\r\n\r\n",
                ),
                Step::ReadUntil(b"aaa\r\n".to_vec()),
                send("x"),
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "hangup: a client closing its side cancels the request context",
            "ops",
            vec![
                send("GET /o HTTP/1.1\r\nHost: x\r\nX-Id: hangup\r\nX-Ops: waitctx|w,2,z\r\n\r\n"),
                Step::Pause(50),
                Step::HalfClose,
                Step::ReadToClose,
            ],
            Some("hangup"),
        ),
        (
            "write errors: what Write returns past Content-Length and on a 204",
            "ops",
            vec![
                send(
                    "GET /o HTTP/1.1\r\nHost: x\r\nX-Id: werr\r\nX-Ops: h,Content-Length,2|w,2,a|w,1,b|rf,1,c\r\nConnection: close\r\n\r\n",
                ),
                Step::ReadToClose,
            ],
            Some("werr"),
        ),
        (
            "write errors: a body on 204",
            "ops",
            vec![
                send(
                    "GET /o HTTP/1.1\r\nHost: x\r\nX-Id: w204\r\nX-Ops: wh,204|w,1,a|f\r\nConnection: close\r\n\r\n",
                ),
                Step::ReadToClose,
            ],
            Some("w204"),
        ),
        (
            "body errors: read to the limit and past it",
            "ops",
            vec![
                send(
                    "POST /o HTTP/1.1\r\nHost: x\r\nX-Id: mb\r\nX-Ops: mb,3|rb|w,1,a\r\nContent-Length: 5\r\n\r\nhello",
                ),
                Step::ReadToClose,
            ],
            Some("mb"),
        ),
        (
            "body errors: a read after close, and a short body",
            "ops",
            vec![
                send(
                    "POST /o HTTP/1.1\r\nHost: x\r\nX-Id: rac\r\nX-Ops: cb|rb|fd|w,1,a\r\nContent-Length: 5\r\n\r\nhello",
                ),
                Step::ReadToClose,
            ],
            Some("rac"),
        ),
        (
            "hijack: bytes buffered past the request go to the new owner",
            "ops",
            vec![
                send("GET /o HTTP/1.1\r\nHost: x\r\nX-Ops: hj,done\r\n\r\npipelined"),
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "timeouts: no request at all ends silently",
            "timeouts",
            vec![Step::ReadToClose],
            None,
        ),
        (
            "timeouts: a partial request ends silently",
            "timeouts",
            vec![send("GET / HTTP/1.1\r\nHost:"), Step::ReadToClose],
            None,
        ),
        (
            "timeouts: an idle connection closes after a reply",
            "timeouts",
            vec![
                send("GET / HTTP/1.1\r\nHost: x\r\nX-Ops: w,2,z\r\n\r\n"),
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "timeouts: a write past WriteTimeout is never seen",
            "timeouts-write",
            vec![
                send("GET / HTTP/1.1\r\nHost: x\r\nX-Ops: sleep,400|w,2,z\r\n\r\n"),
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "timeouts: a write within WriteTimeout is",
            "timeouts-write",
            vec![
                send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Ops: w,2,z\r\n\r\n"),
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "timeouts: ReadTimeout cuts off a slow body, and the handler can still answer",
            "timeouts-read",
            vec![
                send(
                    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nX-Ops: rb|w,2,z\r\n\r\nhe",
                ),
                Step::ReadToClose,
            ],
            None,
        ),
        (
            "timeouts: ReadTimeout on the header",
            "timeouts-read",
            vec![send("GET / HTTP/1.1\r\nHost:"), Step::ReadToClose],
            None,
        ),
    ]
}
