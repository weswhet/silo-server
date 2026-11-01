//! Port of `http.ServeMux` with Go 1.22+ patterns (`net/http/pattern.go`, `routing_tree.go`, and the
//! mux half of `server.go`). The root listener's mux sits in front of chi, so its path-cleaning and
//! trailing-slash redirects are part of the wire contract even though no route inventory row names
//! them.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use silo_gocompat::path;
use silo_gocompat::unicode::{is_digit, is_letter};

use crate::header::valid_header_field_name;
use crate::request::Request;
use crate::response::{
    BoxFuture, BoxHandler, Handler, ResponseWriter, error, handler_fn, not_found_handler,
    redirect_handler,
};
use crate::status::status_text;
use crate::url::{Url, path_unescape};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Segment {
    /// A literal, a wildcard name, or "/" for "/{$}".
    s: Vec<u8>,
    wild: bool,
    multi: bool,
}

/// `http.pattern`.
#[derive(Clone, Debug)]
struct Pattern {
    string: String,
    method: String,
    host: String,
    segments: Vec<Segment>,
}

/// `pathUnescape`.
fn unescape_or_original(p: &[u8]) -> Vec<u8> {
    path_unescape(p).unwrap_or_else(|_| p.to_vec())
}

/// `cleanPath`.
fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return "/".to_owned();
    }
    let owned;
    let p = if p.starts_with('/') {
        p
    } else {
        owned = format!("/{p}");
        owned.as_str()
    };
    let mut np = path::clean(p);
    if p.ends_with('/') && np != "/" {
        if p.len() == np.len() + 1 && p.starts_with(&np) {
            np = p.to_owned();
        } else {
            np.push('/');
        }
    }
    np
}

fn is_valid_wildcard_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .enumerate()
            .all(|(i, c)| is_letter(c as u32) || c == '_' || (i != 0 && is_digit(c as u32)))
}

/// `parsePattern`.
fn parse_pattern(s: &str) -> Result<Pattern, String> {
    if s.is_empty() {
        return Err("empty pattern".to_owned());
    }
    let (method, rest) = match s.find([' ', '\t']) {
        Some(i) => (&s[..i], s[i + 1..].trim_start_matches([' ', '\t'])),
        None => ("", s),
    };
    if !method.is_empty() && !valid_header_field_name(method.as_bytes()) {
        return Err(format!("invalid method {method:?}"));
    }
    let Some(i) = rest.find('/') else {
        return Err("host/path missing /".to_owned());
    };
    let host = &rest[..i];
    let mut rest = &rest[i..];
    if host.contains('{') {
        return Err("host contains '{' (missing initial '/'?)".to_owned());
    }
    if !method.is_empty() && method != "CONNECT" && rest != clean_path(rest) {
        return Err("non-CONNECT pattern with unclean path can never match".to_owned());
    }

    let mut segments = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    while !rest.is_empty() {
        rest = &rest[1..];
        if rest.is_empty() {
            segments.push(Segment {
                s: Vec::new(),
                wild: true,
                multi: true,
            });
            break;
        }
        let i = rest.find('/').unwrap_or(rest.len());
        let seg = &rest[..i];
        rest = &rest[i..];
        match seg.find('{') {
            None => segments.push(Segment {
                s: unescape_or_original(seg.as_bytes()),
                wild: false,
                multi: false,
            }),
            Some(i) => {
                if i != 0 {
                    return Err("bad wildcard segment (must start with '{')".to_owned());
                }
                if !seg.ends_with('}') {
                    return Err("bad wildcard segment (must end with '}')".to_owned());
                }
                let name = &seg[1..seg.len() - 1];
                if name == "$" {
                    if !rest.is_empty() {
                        return Err("{$} not at end".to_owned());
                    }
                    segments.push(Segment {
                        s: b"/".to_vec(),
                        wild: false,
                        multi: false,
                    });
                    break;
                }
                let (name, multi) = match name.strip_suffix("...") {
                    Some(n) => (n, true),
                    None => (name, false),
                };
                if multi && !rest.is_empty() {
                    return Err("{...} wildcard not at end".to_owned());
                }
                if name.is_empty() {
                    return Err("empty wildcard".to_owned());
                }
                if !is_valid_wildcard_name(name) {
                    return Err(format!("bad wildcard name {name:?}"));
                }
                if seen.iter().any(|n| n == name) {
                    return Err(format!("duplicate wildcard name {name:?}"));
                }
                seen.push(name.to_owned());
                segments.push(Segment {
                    s: name.as_bytes().to_vec(),
                    wild: true,
                    multi,
                });
            }
        }
    }
    Ok(Pattern {
        string: s.to_owned(),
        method: method.to_owned(),
        host: host.to_owned(),
        segments,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Relationship {
    Equivalent,
    MoreGeneral,
    MoreSpecific,
    Disjoint,
    Overlaps,
}

fn inverse(r: Relationship) -> Relationship {
    match r {
        Relationship::MoreSpecific => Relationship::MoreGeneral,
        Relationship::MoreGeneral => Relationship::MoreSpecific,
        other => other,
    }
}

fn combine(r1: Relationship, r2: Relationship) -> Relationship {
    match r1 {
        Relationship::Equivalent => r2,
        Relationship::Disjoint => Relationship::Disjoint,
        Relationship::Overlaps => {
            if r2 == Relationship::Disjoint {
                Relationship::Disjoint
            } else {
                Relationship::Overlaps
            }
        }
        Relationship::MoreGeneral | Relationship::MoreSpecific => {
            if r2 == Relationship::Equivalent {
                r1
            } else if r2 == inverse(r1) {
                Relationship::Overlaps
            } else {
                r2
            }
        }
    }
}

fn compare_segments(s1: &Segment, s2: &Segment) -> Relationship {
    if s1.multi && s2.multi {
        return Relationship::Equivalent;
    }
    if s1.multi {
        return Relationship::MoreGeneral;
    }
    if s2.multi {
        return Relationship::MoreSpecific;
    }
    if s1.wild && s2.wild {
        return Relationship::Equivalent;
    }
    if s1.wild {
        return if s2.s == b"/" {
            Relationship::Disjoint
        } else {
            Relationship::MoreGeneral
        };
    }
    if s2.wild {
        return if s1.s == b"/" {
            Relationship::Disjoint
        } else {
            Relationship::MoreSpecific
        };
    }
    if s1.s == s2.s {
        Relationship::Equivalent
    } else {
        Relationship::Disjoint
    }
}

impl Pattern {
    fn last_multi(&self) -> bool {
        self.segments.last().is_some_and(|s| s.multi)
    }

    /// `p1.conflictsWith(p2)`.
    fn conflicts_with(&self, p2: &Pattern) -> bool {
        if self.host != p2.host {
            return false;
        }
        let rel = self.compare_paths_and_methods(p2);
        rel == Relationship::Equivalent || rel == Relationship::Overlaps
    }

    fn compare_paths_and_methods(&self, p2: &Pattern) -> Relationship {
        let mrel = self.compare_methods(p2);
        if mrel == Relationship::Disjoint {
            return Relationship::Disjoint;
        }
        combine(mrel, self.compare_paths(p2))
    }

    fn compare_methods(&self, p2: &Pattern) -> Relationship {
        if self.method == p2.method {
            return Relationship::Equivalent;
        }
        if self.method.is_empty() {
            return Relationship::MoreGeneral;
        }
        if p2.method.is_empty() {
            return Relationship::MoreSpecific;
        }
        if self.method == "GET" && p2.method == "HEAD" {
            return Relationship::MoreGeneral;
        }
        if p2.method == "GET" && self.method == "HEAD" {
            return Relationship::MoreSpecific;
        }
        Relationship::Disjoint
    }

    fn compare_paths(&self, p2: &Pattern) -> Relationship {
        if self.segments.len() != p2.segments.len() && !self.last_multi() && !p2.last_multi() {
            return Relationship::Disjoint;
        }
        let mut rel = Relationship::Equivalent;
        for (a, b) in self.segments.iter().zip(&p2.segments) {
            rel = combine(rel, compare_segments(a, b));
            if rel == Relationship::Disjoint {
                return rel;
            }
        }
        let (n1, n2) = (self.segments.len(), p2.segments.len());
        if n1 == n2 {
            return rel;
        }
        if n1 < n2 && self.last_multi() {
            return combine(rel, Relationship::MoreGeneral);
        }
        if n2 < n1 && p2.last_multi() {
            return combine(rel, Relationship::MoreSpecific);
        }
        Relationship::Disjoint
    }
}

/// `routingNode`.
#[derive(Default)]
struct Node {
    pattern: Option<Arc<Pattern>>,
    handler: Option<BoxHandler>,
    children: HashMap<Vec<u8>, Node>,
    multi_child: Option<Box<Node>>,
    empty_child: Option<Box<Node>>,
}

impl Node {
    fn add_child(&mut self, key: &[u8]) -> &mut Node {
        if key.is_empty() {
            return self.empty_child.get_or_insert_with(Box::default);
        }
        self.children.entry(key.to_vec()).or_default()
    }

    fn find_child(&self, key: &[u8]) -> Option<&Node> {
        if key.is_empty() {
            return self.empty_child.as_deref();
        }
        self.children.get(key)
    }

    fn set(&mut self, p: Arc<Pattern>, h: BoxHandler) {
        assert!(
            self.pattern.is_none() && self.handler.is_none(),
            "non-nil leaf fields"
        );
        self.pattern = Some(p);
        self.handler = Some(h);
    }

    fn add_pattern(&mut self, p: Arc<Pattern>, h: BoxHandler) {
        let host = p.host.clone();
        let method = p.method.clone();
        let segments = p.segments.clone();
        self.add_child(host.as_bytes())
            .add_child(method.as_bytes())
            .add_segments(&segments, p, h);
    }

    fn add_segments(&mut self, segs: &[Segment], p: Arc<Pattern>, h: BoxHandler) {
        let Some(seg) = segs.first() else {
            self.set(p, h);
            return;
        };
        if seg.multi {
            assert!(segs.len() == 1, "multi wildcard not last");
            let mut c = Node::default();
            c.set(p, h);
            self.multi_child = Some(Box::new(c));
        } else if seg.wild {
            self.add_child(b"").add_segments(&segs[1..], p, h);
        } else {
            self.add_child(&seg.s).add_segments(&segs[1..], p, h);
        }
    }

    /// `root.match`.
    fn matches(&self, host: &[u8], method: &str, path: &str) -> Option<(&Node, Vec<Vec<u8>>)> {
        if !host.is_empty()
            && let Some(found) = self
                .find_child(host)
                .and_then(|n| n.match_method_and_path(method, path))
        {
            return Some(found);
        }
        self.empty_child
            .as_deref()
            .and_then(|n| n.match_method_and_path(method, path))
    }

    fn match_method_and_path(&self, method: &str, path: &str) -> Option<(&Node, Vec<Vec<u8>>)> {
        if let Some(found) = self
            .find_child(method.as_bytes())
            .and_then(|n| n.match_path(path, Vec::new()))
        {
            return Some(found);
        }
        if method == "HEAD"
            && let Some(found) = self
                .find_child(b"GET")
                .and_then(|n| n.match_path(path, Vec::new()))
        {
            return Some(found);
        }
        self.empty_child
            .as_deref()
            .and_then(|n| n.match_path(path, Vec::new()))
    }

    /// `n.matchPath`.
    fn match_path(&self, path: &str, matches: Vec<Vec<u8>>) -> Option<(&Node, Vec<Vec<u8>>)> {
        if path.is_empty() {
            self.pattern.as_ref()?;
            return Some((self, matches));
        }
        let (seg, rest) = first_segment(path);
        if let Some(found) = self
            .find_child(&seg)
            .and_then(|n| n.match_path(rest, matches.clone()))
        {
            return Some(found);
        }
        if seg != b"/"
            && let Some(child) = self.empty_child.as_deref()
        {
            let mut with = matches.clone();
            with.push(seg);
            if let Some(found) = child.match_path(rest, with) {
                return Some(found);
            }
        }
        if let Some(c) = self.multi_child.as_deref() {
            let mut matches = matches;
            let named = c
                .pattern
                .as_ref()
                .and_then(|p| p.segments.last())
                .is_some_and(|s| !s.s.is_empty());
            if named {
                matches.push(unescape_or_original(&path.as_bytes()[1..]));
            }
            return Some((c, matches));
        }
        None
    }

    /// `root.matchingMethods`.
    fn matching_methods(&self, host: &[u8], path: &str, set: &mut BTreeSet<String>) {
        if !host.is_empty()
            && let Some(n) = self.find_child(host)
        {
            n.matching_methods_path(path, set);
        }
        if let Some(n) = self.empty_child.as_deref() {
            n.matching_methods_path(path, set);
        }
        if set.contains("GET") {
            set.insert("HEAD".to_owned());
        }
    }

    fn matching_methods_path(&self, path: &str, set: &mut BTreeSet<String>) {
        for (method, c) in &self.children {
            if c.match_path(path, Vec::new()).is_some() {
                set.insert(String::from_utf8_lossy(method).into_owned());
            }
        }
    }
}

/// `firstSegment`.
fn first_segment(path: &str) -> (Vec<u8>, &str) {
    if path == "/" {
        return (b"/".to_vec(), "");
    }
    let path = &path[1..];
    let i = path.find('/').unwrap_or(path.len());
    (unescape_or_original(&path.as_bytes()[..i]), &path[i..])
}

/// `exactMatch`.
fn exact_match(n: Option<&Node>, path: &str) -> bool {
    let Some(p) = n.and_then(|n| n.pattern.as_ref()) else {
        return false;
    };
    if !p.last_multi() {
        return true;
    }
    if !path.is_empty() && !path.ends_with('/') {
        return false;
    }
    p.segments.len() == path.matches('/').count()
}

/// `stripHostPort`.
fn strip_host_port(h: &[u8]) -> Vec<u8> {
    if !h.contains(&b':') {
        return h.to_vec();
    }
    match split_host_port(h) {
        Some(host) => host,
        None => h.to_vec(),
    }
}

/// `net.SplitHostPort`, reduced to the host: `None` where it reports an error.
fn split_host_port(h: &[u8]) -> Option<Vec<u8>> {
    let last = h.iter().rposition(|&b| b == b':')?;
    let (host, skip_start, skip_end): (&[u8], usize, usize);
    if h.first() == Some(&b'[') {
        let end = h.iter().position(|&b| b == b']')?;
        if end + 1 == h.len() {
            return None;
        }
        if end + 1 != last {
            return None;
        }
        host = &h[1..end];
        skip_start = 1;
        skip_end = end + 1;
    } else {
        host = &h[..last];
        if host.contains(&b':') {
            return None;
        }
        skip_start = 0;
        skip_end = last;
    }
    if h[skip_start..].contains(&b'[') || h[skip_end..].contains(&b']') {
        return None;
    }
    Some(host.to_vec())
}

/// `http.ServeMux`.
#[derive(Default)]
pub struct ServeMux {
    inner: RwLock<MuxState>,
}

#[derive(Default)]
struct MuxState {
    tree: Node,
    patterns: Vec<Arc<Pattern>>,
}

/// A matched node's handler, pattern, and wildcard values.
type Matched = (BoxHandler, Arc<Pattern>, Vec<Vec<u8>>);

enum Found {
    Handler {
        handler: BoxHandler,
        pattern: String,
        matches: Vec<(String, Vec<u8>)>,
    },
    Generated(BoxHandler, String),
}

impl ServeMux {
    /// `http.NewServeMux`.
    pub fn new() -> Self {
        Self::default()
    }

    /// `mux.Handle`. Panics like Go on an invalid or conflicting pattern.
    pub fn handle(&self, pattern: &str, handler: BoxHandler) {
        assert!(!pattern.is_empty(), "http: invalid pattern");
        let pat = match parse_pattern(pattern) {
            Ok(p) => Arc::new(p),
            Err(e) => panic!("parsing {pattern:?}: {e}"),
        };
        let mut st = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for existing in &st.patterns {
            assert!(
                !pat.conflicts_with(existing),
                "pattern {:?} conflicts with pattern {:?}",
                pat.string,
                existing.string
            );
        }
        st.patterns.push(pat.clone());
        st.tree.add_pattern(pat, handler);
    }

    /// `mux.matchOrRedirect`: the matched node's handler data, and the redirect URL if the path
    /// needs a trailing slash.
    fn match_or_redirect(
        st: &MuxState,
        host: &[u8],
        method: &str,
        path: &str,
        u: Option<&Url>,
    ) -> (Option<Matched>, Option<(Url, String)>) {
        let found = st.tree.matches(host, method, path);
        let exact = exact_match(found.as_ref().map(|(n, _)| *n), path);
        if !exact
            && let Some(u) = u
            && !path.ends_with('/')
            && !path.is_empty()
        {
            let with_slash = format!("{path}/");
            let found2 = st.tree.matches(host, method, &with_slash);
            if exact_match(found2.as_ref().map(|(n, _)| *n), &with_slash) {
                // Go 1.26: the redirect is rebuilt from the decoded path, not the escaped one.
                let cleaned = clean_path(&String::from_utf8_lossy(&u.path));
                let target = Url {
                    path: format!("{cleaned}/").into_bytes(),
                    raw_query: u.raw_query.clone(),
                    ..Url::default()
                };
                let pattern = found2
                    .and_then(|(n, _)| n.pattern.as_ref().map(|p| p.string.clone()))
                    .unwrap_or_default();
                return (None, Some((target, pattern)));
            }
        }
        let data = found.and_then(|(n, m)| Some((n.handler.clone()?, n.pattern.clone()?, m)));
        (data, None)
    }

    /// `mux.findHandler`.
    fn find_handler(&self, r: &Request) -> Found {
        let st = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let escaped_bytes = r.url.escaped_path();
        let escaped_path = String::from_utf8_lossy(&escaped_bytes).into_owned();
        let mut host = r.url.host.clone();
        let mut path = escaped_path.clone();
        let matched = if r.method == "CONNECT" {
            let (_, redirect) = Self::match_or_redirect(&st, &host, &r.method, &path, Some(&r.url));
            if let Some((u, _)) = redirect {
                let up = String::from_utf8_lossy(&u.path).into_owned();
                return Found::Generated(
                    redirect_handler(String::from_utf8_lossy(&u.string()).into_owned(), 307),
                    up,
                );
            }
            let (m, _) = Self::match_or_redirect(&st, &r.host, &r.method, &path, None);
            m
        } else {
            host = strip_host_port(&r.host);
            path = clean_path(&path);
            let (m, redirect) = Self::match_or_redirect(&st, &host, &r.method, &path, Some(&r.url));
            if let Some((u, pattern)) = redirect {
                return Found::Generated(
                    redirect_handler(String::from_utf8_lossy(&u.string()).into_owned(), 307),
                    pattern,
                );
            }
            if path != escaped_path {
                let pattern = m
                    .as_ref()
                    .map(|(_, p, _)| p.string.clone())
                    .unwrap_or_default();
                let u = Url {
                    path: path.clone().into_bytes(),
                    raw_query: r.url.raw_query.clone(),
                    ..Url::default()
                };
                return Found::Generated(
                    redirect_handler(String::from_utf8_lossy(&u.string()).into_owned(), 307),
                    pattern,
                );
            }
            m
        };
        let Some((handler, pattern, matches)) = matched else {
            let mut allowed = BTreeSet::new();
            st.tree.matching_methods(&host, &path, &mut allowed);
            if !path.ends_with('/') {
                st.tree
                    .matching_methods(&host, &format!("{path}/"), &mut allowed);
            }
            if !allowed.is_empty() {
                let allow = allowed.into_iter().collect::<Vec<_>>().join(", ");
                return Found::Generated(
                    handler_fn(move |w, _r| {
                        let allow = allow.clone();
                        Box::pin(async move {
                            w.header().set("Allow", allow);
                            error(w, status_text(405), 405).await;
                        })
                    }),
                    String::new(),
                );
            }
            return Found::Generated(not_found_handler(), String::new());
        };
        let names: Vec<String> = pattern
            .segments
            .iter()
            .filter(|s| s.wild && !s.s.is_empty())
            .map(|s| String::from_utf8_lossy(&s.s).into_owned())
            .collect();
        Found::Handler {
            handler,
            pattern: pattern.string.clone(),
            matches: names.into_iter().zip(matches).collect(),
        }
    }
}

impl Handler for ServeMux {
    /// `mux.ServeHTTP`.
    fn serve_http<'a>(
        &'a self,
        w: &'a mut dyn ResponseWriter,
        r: &'a mut Request,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if r.request_uri == b"*" {
                if r.proto_at_least(1, 1) {
                    w.header().set("Connection", "close");
                }
                w.write_header(400).await;
                return;
            }
            match self.find_handler(r) {
                Found::Handler {
                    handler,
                    pattern,
                    matches,
                } => {
                    r.pattern = pattern;
                    for (name, value) in matches {
                        r.set_path_value(&name, value);
                    }
                    handler.serve_http(w, r).await;
                }
                Found::Generated(handler, pattern) => {
                    r.pattern = pattern;
                    handler.serve_http(w, r).await;
                }
            }
        })
    }
}
