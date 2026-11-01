//! Port of chi's `tree.go`. Nodes live in an arena because Go's nodes are shared pointers that
//! `InsertRoute` splits and re-parents in place.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strings::{decode_runes, to_upper};

use crate::chi::context::Context;
use crate::chi::mux::Mux;
use crate::response::BoxHandler;

pub(crate) const M_STUB: u64 = 1 << 0;
const M_CONNECT: u64 = 1 << 1;
const M_DELETE: u64 = 1 << 2;
const M_GET: u64 = 1 << 3;
const M_HEAD: u64 = 1 << 4;
const M_OPTIONS: u64 = 1 << 5;
const M_PATCH: u64 = 1 << 6;
const M_POST: u64 = 1 << 7;
const M_PUT: u64 = 1 << 8;
const M_QUERY: u64 = 1 << 9;
const M_TRACE: u64 = 1 << 10;

struct Methods {
    by_name: Vec<(String, u64)>,
    all: u64,
}

fn methods() -> &'static RwLock<Methods> {
    static METHODS: OnceLock<RwLock<Methods>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let by_name: Vec<(String, u64)> = [
            ("CONNECT", M_CONNECT),
            ("DELETE", M_DELETE),
            ("GET", M_GET),
            ("HEAD", M_HEAD),
            ("OPTIONS", M_OPTIONS),
            ("PATCH", M_PATCH),
            ("POST", M_POST),
            ("PUT", M_PUT),
            ("QUERY", M_QUERY),
            ("TRACE", M_TRACE),
        ]
        .into_iter()
        .map(|(n, m)| (n.to_owned(), m))
        .collect();
        let all = by_name.iter().fold(0, |acc, (_, m)| acc | m);
        RwLock::new(Methods { by_name, all })
    })
}

fn read_methods() -> std::sync::RwLockReadGuard<'static, Methods> {
    methods()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn m_all() -> u64 {
    read_methods().all
}

/// `methodMap[method]`.
pub(crate) fn method_bit(method: &str) -> Option<u64> {
    read_methods()
        .by_name
        .iter()
        .find(|(n, _)| n == method)
        .map(|(_, m)| *m)
}

/// `reverseMethodMap[mt]`.
pub(crate) fn method_name(bit: u64) -> Option<String> {
    read_methods()
        .by_name
        .iter()
        .find(|(_, m)| *m == bit)
        .map(|(n, _)| n.clone())
}

/// `chi.RegisterMethod`.
pub fn register_method(method: &str) {
    if method.is_empty() {
        return;
    }
    let method = to_upper(method);
    let mut t = methods()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if t.by_name.iter().any(|(n, _)| *n == method) {
        return;
    }
    let n = t.by_name.len();
    assert!(n <= 62, "chi: max number of methods reached (64)");
    let mt = 2u64 << n;
    t.by_name.push((method, mt));
    t.all |= mt;
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum NodeTyp {
    Static = 0,
    Regexp = 1,
    Param = 2,
    CatchAll = 3,
}

#[derive(Clone)]
pub(crate) struct Endpoint {
    pub(crate) handler: Option<BoxHandler>,
    pub(crate) pattern: Arc<str>,
    pub(crate) param_keys: Vec<Arc<str>>,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            handler: None,
            pattern: Arc::from(""),
            param_keys: Vec::new(),
        }
    }
}

type NodeId = usize;

type NodeVisitor<'a> = dyn FnMut(Option<&BTreeMap<u64, Endpoint>>, Option<&Mux>) + 'a;

/// `chi.node`.
#[derive(Default)]
struct Node {
    subroutes: Option<Mux>,
    rex: Option<GoRegex>,
    endpoints: Option<BTreeMap<u64, Endpoint>>,
    prefix: Vec<u8>,
    children: [Vec<NodeId>; 4],
    tail: u8,
    typ: u8,
    label: u8,
}

const T_STATIC: u8 = NodeTyp::Static as u8;
const T_REGEXP: u8 = NodeTyp::Regexp as u8;
const T_PARAM: u8 = NodeTyp::Param as u8;
const T_CATCHALL: u8 = NodeTyp::CatchAll as u8;

/// A routing tree. Go's `*node` root; inline muxes share it.
pub(crate) struct Tree {
    nodes: Vec<Node>,
}

/// `chi.Route`.
pub struct Route {
    /// `SubRoutes`.
    pub sub_routes: Option<Mux>,
    /// `Handlers`, by method name; `*` holds the catch-all handler.
    pub handlers: BTreeMap<String, BoxHandler>,
    /// `Pattern`.
    pub pattern: String,
}

struct Segment {
    typ: u8,
    key: String,
    rexpat: String,
    tail: u8,
    start: usize,
    end: usize,
}

/// `patNextSegment`.
fn pat_next_segment(pattern: &str) -> Segment {
    let ps = pattern.find('{');
    let ws = pattern.find('*');
    if ps.is_none() && ws.is_none() {
        return Segment {
            typ: T_STATIC,
            key: String::new(),
            rexpat: String::new(),
            tail: 0,
            start: 0,
            end: pattern.len(),
        };
    }
    if let (Some(p), Some(w)) = (ps, ws) {
        assert!(
            w >= p,
            "chi: wildcard '*' must be the last pattern in a route, otherwise use a '{{param}}'"
        );
    }
    let mut tail = b'/';
    if let Some(ps) = ps {
        let mut nt = T_PARAM;
        let mut cc = 0;
        let mut pe = ps;
        for (i, c) in pattern[ps..].char_indices() {
            if c == '{' {
                cc += 1;
            } else if c == '}' {
                cc -= 1;
                if cc == 0 {
                    pe = ps + i;
                    break;
                }
            }
        }
        assert!(
            pe != ps,
            "chi: route param closing delimiter '}}' is missing"
        );
        let whole = &pattern[ps + 1..pe];
        pe += 1;
        if pe < pattern.len() {
            tail = pattern.as_bytes()[pe];
        }
        let (key, mut rexpat) = match whole.split_once(':') {
            Some((k, r)) => {
                nt = T_REGEXP;
                (k.to_owned(), r.to_owned())
            }
            None => (whole.to_owned(), String::new()),
        };
        if !rexpat.is_empty() {
            if !rexpat.starts_with('^') {
                rexpat.insert(0, '^');
            }
            if !rexpat.ends_with('$') {
                rexpat.push('$');
            }
        }
        return Segment {
            typ: nt,
            key,
            rexpat,
            tail,
            start: ps,
            end: pe,
        };
    }
    let ws = ws.unwrap_or(0);
    assert!(
        ws >= pattern.len() - 1,
        "chi: wildcard '*' must be the last value in a route. trim trailing text or use a '{{param}}' instead"
    );
    Segment {
        typ: T_CATCHALL,
        key: "*".to_owned(),
        rexpat: String::new(),
        tail: 0,
        start: ws,
        end: pattern.len(),
    }
}

/// `patParamKeys`.
fn pat_param_keys(pattern: &str) -> Vec<Arc<str>> {
    let mut pat = pattern;
    let mut keys: Vec<Arc<str>> = Vec::new();
    loop {
        let seg = pat_next_segment(pat);
        if seg.typ == T_STATIC {
            return keys;
        }
        assert!(
            !keys.iter().any(|k| **k == *seg.key),
            "chi: routing pattern '{pattern}' contains duplicate param key, '{}'",
            seg.key
        );
        keys.push(Arc::from(seg.key.as_str()));
        pat = &pat[seg.end..];
    }
}

fn longest_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

pub(crate) fn equal_handlers(a: &BoxHandler, b: &BoxHandler) -> bool {
    std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b))
}

impl Tree {
    pub(crate) fn new() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }

    fn alloc(&mut self, n: Node) -> NodeId {
        self.nodes.push(n);
        self.nodes.len() - 1
    }

    /// `nodes.Sort`: Go's `sort.Sort` is insertion sort up to 12 elements, which is every group in
    /// practice, then `tailSort`.
    fn sort_children(&mut self, parent: NodeId, typ: usize) {
        let mut list = std::mem::take(&mut self.nodes[parent].children[typ]);
        for i in 1..list.len() {
            let mut j = i;
            while j > 0 && self.nodes[list[j]].label < self.nodes[list[j - 1]].label {
                list.swap(j, j - 1);
                j -= 1;
            }
        }
        // tailSort: the last node with a '/' tail moves to the end.
        if let Some(i) = (0..list.len()).rev().find(|&i| {
            let n = &self.nodes[list[i]];
            n.typ > T_STATIC && n.tail == b'/'
        }) {
            let last = list.len() - 1;
            list.swap(i, last);
        }
        self.nodes[parent].children[typ] = list;
    }

    /// `n.InsertRoute`.
    pub(crate) fn insert_route(
        &mut self,
        method: u64,
        pattern: &str,
        handler: BoxHandler,
    ) -> usize {
        let mut n: NodeId = 0;
        let mut parent: NodeId;
        let mut search: &str = pattern;
        loop {
            if search.is_empty() {
                self.set_endpoint(n, method, handler, pattern);
                return n;
            }
            let label = search.as_bytes()[0];
            let mut seg_tail = 0u8;
            let mut seg_end = 0usize;
            let mut seg_typ = T_STATIC;
            let mut seg_rexpat = String::new();
            if label == b'{' || label == b'*' {
                let s = pat_next_segment(search);
                seg_typ = s.typ;
                seg_rexpat = s.rexpat;
                seg_tail = s.tail;
                seg_end = s.end;
            }
            let prefix = if seg_typ == T_REGEXP {
                seg_rexpat.as_str()
            } else {
                ""
            };

            parent = n;
            let Some(edge) = self.get_edge(n, seg_typ, label, seg_tail, prefix.as_bytes()) else {
                let child = self.alloc(Node {
                    label,
                    tail: seg_tail,
                    prefix: search.as_bytes().to_vec(),
                    ..Node::default()
                });
                let hn = self.add_child(parent, child, search);
                self.set_endpoint(hn, method, handler, pattern);
                return hn;
            };
            n = edge;

            if self.nodes[n].typ > T_STATIC {
                search = &search[seg_end..];
                continue;
            }

            let common = longest_prefix(search.as_bytes(), &self.nodes[n].prefix);
            if common == self.nodes[n].prefix.len() {
                search = &search[common..];
                continue;
            }

            // Split the node.
            let child = self.alloc(Node {
                typ: T_STATIC,
                prefix: search.as_bytes()[..common].to_vec(),
                ..Node::default()
            });
            self.replace_child(parent, search.as_bytes()[0], seg_tail, child);

            // Restore the existing node.
            let tail_prefix = self.nodes[n].prefix[common..].to_vec();
            self.nodes[n].label = tail_prefix[0];
            self.nodes[n].prefix.clone_from(&tail_prefix);
            let tail_str = String::from_utf8_lossy(&tail_prefix).into_owned();
            self.add_child(child, n, &tail_str);

            search = &search[common..];
            if search.is_empty() {
                self.set_endpoint(child, method, handler, pattern);
                return child;
            }

            let subchild = self.alloc(Node {
                typ: T_STATIC,
                label: search.as_bytes()[0],
                prefix: search.as_bytes().to_vec(),
                ..Node::default()
            });
            let hn = self.add_child(child, subchild, search);
            self.set_endpoint(hn, method, handler, pattern);
            return hn;
        }
    }

    /// `n.addChild`.
    fn add_child(&mut self, parent: NodeId, child: NodeId, prefix: &str) -> NodeId {
        let mut search = prefix;
        let mut hn = child;
        let seg = pat_next_segment(search);
        let mut seg_start = seg.start;

        if seg.typ != T_STATIC {
            if seg.typ == T_REGEXP {
                let rex = GoRegex::compile(&seg.rexpat).unwrap_or_else(|_| {
                    panic!(
                        "chi: invalid regexp pattern '{}' in route param",
                        seg.rexpat
                    )
                });
                self.nodes[child].prefix = seg.rexpat.clone().into_bytes();
                self.nodes[child].rex = Some(rex);
            }

            if seg_start == 0 {
                self.nodes[child].typ = seg.typ;
                seg_start = if seg.typ == T_CATCHALL {
                    search.len()
                } else {
                    seg.end
                };
                self.nodes[child].tail = seg.tail;

                if seg_start != search.len() {
                    search = &search[seg_start..];
                    let nn = self.alloc(Node {
                        typ: T_STATIC,
                        label: search.as_bytes()[0],
                        prefix: search.as_bytes().to_vec(),
                        ..Node::default()
                    });
                    hn = self.add_child(child, nn, search);
                }
            } else {
                self.nodes[child].typ = T_STATIC;
                self.nodes[child].prefix = search.as_bytes()[..seg_start].to_vec();
                self.nodes[child].rex = None;

                search = &search[seg_start..];
                let nn = self.alloc(Node {
                    typ: seg.typ,
                    label: search.as_bytes()[0],
                    tail: seg.tail,
                    ..Node::default()
                });
                hn = self.add_child(child, nn, search);
            }
        }

        let typ = usize::from(self.nodes[child].typ);
        self.nodes[parent].children[typ].push(child);
        self.sort_children(parent, typ);
        hn
    }

    fn replace_child(&mut self, parent: NodeId, label: u8, tail: u8, child: NodeId) {
        let typ = usize::from(self.nodes[child].typ);
        for i in 0..self.nodes[parent].children[typ].len() {
            let id = self.nodes[parent].children[typ][i];
            if self.nodes[id].label == label && self.nodes[id].tail == tail {
                self.nodes[parent].children[typ][i] = child;
                self.nodes[child].label = label;
                self.nodes[child].tail = tail;
                return;
            }
        }
        panic!("chi: replacing missing child");
    }

    fn get_edge(&self, n: NodeId, typ: u8, label: u8, tail: u8, prefix: &[u8]) -> Option<NodeId> {
        for &id in &self.nodes[n].children[usize::from(typ)] {
            let node = &self.nodes[id];
            if node.label == label && node.tail == tail {
                if typ == T_REGEXP && node.prefix != prefix {
                    continue;
                }
                return Some(id);
            }
        }
        None
    }

    /// `n.setEndpoint`.
    fn set_endpoint(&mut self, n: NodeId, method: u64, handler: BoxHandler, pattern: &str) {
        let param_keys = pat_param_keys(pattern);
        let pattern: Arc<str> = Arc::from(pattern);
        let all = m_all();
        let all_bits: Vec<u64> = read_methods().by_name.iter().map(|(_, m)| *m).collect();
        let eps = self.nodes[n].endpoints.get_or_insert_with(BTreeMap::new);
        if method & M_STUB == M_STUB {
            eps.entry(M_STUB).or_default().handler = Some(handler.clone());
        }
        let mut set = |bit: u64| {
            let h = eps.entry(bit).or_default();
            h.handler = Some(handler.clone());
            h.pattern = pattern.clone();
            h.param_keys.clone_from(&param_keys);
        };
        if method & all == all {
            set(all);
            for m in all_bits {
                set(m);
            }
        } else {
            set(method);
        }
    }

    pub(crate) fn set_subroutes(&mut self, n: usize, sub: Mux) {
        self.nodes[n].subroutes = Some(sub);
    }

    /// `n.FindRoute`: the node, and the handler for `method` if there is one.
    pub(crate) fn find_route(
        &self,
        rctx: &mut Context,
        method: u64,
        path: &[u8],
    ) -> Option<(usize, Option<BoxHandler>)> {
        rctx.route_pattern.clear();
        rctx.route_params.keys.clear();
        rctx.route_params.values.clear();

        let rn = self.find_route_inner(rctx, method, path, 0)?;

        rctx.url_params
            .keys
            .extend(rctx.route_params.keys.iter().cloned());
        rctx.url_params
            .values
            .extend(rctx.route_params.values.iter().cloned());

        let ep = self.nodes[rn]
            .endpoints
            .as_ref()
            .and_then(|e| e.get(&method));
        if let Some(ep) = ep
            && !ep.pattern.is_empty()
        {
            rctx.route_pattern = ep.pattern.to_string();
            rctx.route_patterns.push(ep.pattern.clone());
        }
        Some((rn, ep.and_then(|e| e.handler.clone())))
    }

    fn note_leaf(&self, xn: NodeId, rctx: &mut Context, method: u64) -> bool {
        let Some(eps) = &self.nodes[xn].endpoints else {
            return false;
        };
        if let Some(h) = eps.get(&method)
            && h.handler.is_some()
        {
            rctx.route_params.keys.extend(h.param_keys.iter().cloned());
            return true;
        }
        let all = m_all();
        for &bit in eps.keys() {
            if bit == all || bit == M_STUB {
                continue;
            }
            if !rctx.methods_allowed.contains(&bit) {
                rctx.methods_allowed.push(bit);
            }
        }
        rctx.method_not_allowed = true;
        false
    }

    /// `n.findRoute`. Kept as Go has it, down to the param loop leaving `xn` on its last candidate
    /// and recursing into that candidate with the unconsumed path.
    fn find_route_inner(
        &self,
        rctx: &mut Context,
        method: u64,
        path: &[u8],
        n: NodeId,
    ) -> Option<NodeId> {
        let search = path;
        for t in 0..4u8 {
            let nds = &self.nodes[n].children[usize::from(t)];
            if nds.is_empty() {
                continue;
            }
            let mut xn: Option<NodeId> = None;
            let mut xsearch: &[u8] = search;
            let label = search.first().copied().unwrap_or(0);

            match t {
                T_STATIC => match self.find_edge(nds, label) {
                    Some(id) if search.starts_with(&self.nodes[id].prefix) => {
                        xn = Some(id);
                        xsearch = &xsearch[self.nodes[id].prefix.len()..];
                    }
                    _ => continue,
                },
                T_PARAM | T_REGEXP => {
                    if xsearch.is_empty() {
                        continue;
                    }
                    for &cand in nds {
                        xn = Some(cand);
                        let tail = self.nodes[cand].tail;
                        let p = match xsearch.iter().position(|&b| b == tail) {
                            None => {
                                if tail == b'/' {
                                    xsearch.len()
                                } else {
                                    continue;
                                }
                            }
                            Some(0) if t == T_REGEXP => continue,
                            Some(p) => p,
                        };
                        if t == T_REGEXP && self.nodes[cand].rex.is_some() {
                            let matched = self.nodes[cand]
                                .rex
                                .as_ref()
                                .is_some_and(|rex| rex.match_string(&decode_runes(&xsearch[..p])));
                            if !matched {
                                continue;
                            }
                        } else if xsearch[..p].contains(&b'/') {
                            continue;
                        }

                        let prevlen = rctx.route_params.values.len();
                        rctx.route_params.values.push(xsearch[..p].to_vec());
                        xsearch = &xsearch[p..];

                        if xsearch.is_empty() && self.note_leaf(cand, rctx, method) {
                            return Some(cand);
                        }

                        if let Some(fin) = self.find_route_inner(rctx, method, xsearch, cand) {
                            return Some(fin);
                        }

                        rctx.route_params.values.truncate(prevlen);
                        xsearch = search;
                    }
                    rctx.route_params.values.push(Vec::new());
                }
                _ => {
                    rctx.route_params.values.push(search.to_vec());
                    xn = Some(nds[0]);
                    xsearch = &[];
                }
            }

            let Some(xn) = xn else {
                continue;
            };

            if xsearch.is_empty() && self.note_leaf(xn, rctx, method) {
                return Some(xn);
            }

            if let Some(fin) = self.find_route_inner(rctx, method, xsearch, xn) {
                return Some(fin);
            }

            if self.nodes[xn].typ > T_STATIC {
                rctx.route_params.values.pop();
            }
        }
        None
    }

    /// `nodes.findEdge`.
    fn find_edge(&self, ns: &[NodeId], label: u8) -> Option<NodeId> {
        let num = ns.len() as isize;
        let (mut i, mut j) = (0isize, num - 1);
        let mut idx = 0isize;
        while i <= j {
            idx = i + (j - i) / 2;
            let l = self.nodes[ns[idx as usize]].label;
            if label > l {
                i = idx + 1;
            } else if label < l {
                j = idx - 1;
            } else {
                i = num;
            }
        }
        let id = ns[idx as usize];
        (self.nodes[id].label == label).then_some(id)
    }

    /// `n.findEdge(ntyp, label)` for `findPattern`.
    fn find_edge_typed(&self, n: NodeId, typ: usize, label: u8) -> Option<NodeId> {
        let nds = &self.nodes[n].children[typ];
        if typ == usize::from(T_CATCHALL) {
            return nds.first().copied();
        }
        self.find_edge(nds, label)
    }

    /// `n.findPattern`.
    pub(crate) fn find_pattern(&self, n: NodeId, pattern: &str) -> bool {
        for t in 0..4 {
            let nds = &self.nodes[n].children[t];
            if nds.is_empty() {
                continue;
            }
            let typ = usize::from(self.nodes[nds[0]].typ);
            let Some(found) = self.find_edge_typed(n, typ, pattern.as_bytes()[0]) else {
                continue;
            };
            let idx = match self.nodes[found].typ {
                T_STATIC => {
                    let idx = longest_prefix(pattern.as_bytes(), &self.nodes[found].prefix);
                    if idx < self.nodes[found].prefix.len() {
                        continue;
                    }
                    idx
                }
                T_PARAM | T_REGEXP => pattern.find('}').map_or(0, |i| i + 1),
                _ => longest_prefix(pattern.as_bytes(), b"*"),
            };
            let xpattern = &pattern[idx..];
            if xpattern.is_empty() {
                return true;
            }
            return self.find_pattern(found, xpattern);
        }
        false
    }

    pub(crate) fn subroutes_of(&self, n: usize) -> Option<&Mux> {
        self.nodes[n].subroutes.as_ref()
    }

    pub(crate) fn endpoint_pattern(&self, n: usize, method: u64) -> Option<Arc<str>> {
        self.nodes[n]
            .endpoints
            .as_ref()
            .and_then(|e| e.get(&method))
            .map(|e| e.pattern.clone())
    }

    /// `n.routes`. Go's order within a node follows map iteration, so it is unspecified; this one is
    /// by pattern.
    pub(crate) fn routes(&self) -> Vec<Route> {
        let mut rts = Vec::new();
        self.walk(0, &mut |eps, subroutes| {
            let empty = BTreeMap::new();
            let eps = eps.unwrap_or(&empty);
            let stub = eps.get(&M_STUB).and_then(|e| e.handler.clone());
            let mut pats: BTreeMap<Arc<str>, BTreeMap<u64, &Endpoint>> = BTreeMap::new();
            for (&mt, h) in eps {
                if h.pattern.is_empty() {
                    continue;
                }
                pats.entry(h.pattern.clone()).or_default().insert(mt, h);
            }
            let all = m_all();
            for (p, mh) in pats {
                let mut hs: BTreeMap<String, BoxHandler> = BTreeMap::new();
                let is_stub = |h: &BoxHandler| stub.as_ref().is_some_and(|s| equal_handlers(h, s));
                if let Some(h) = mh.get(&all).and_then(|e| e.handler.as_ref())
                    && (subroutes.is_some() || !is_stub(h))
                {
                    hs.insert("*".to_owned(), h.clone());
                }
                for (&mt, h) in &mh {
                    let Some(handler) = &h.handler else { continue };
                    if is_stub(handler) {
                        continue;
                    }
                    if let Some(m) = method_name(mt) {
                        hs.insert(m, handler.clone());
                    }
                }
                if hs.is_empty() && subroutes.is_none() {
                    continue;
                }
                rts.push(Route {
                    sub_routes: subroutes.cloned(),
                    handlers: hs,
                    pattern: p.to_string(),
                });
            }
        });
        rts
    }

    fn walk(&self, n: NodeId, f: &mut NodeVisitor<'_>) {
        let node = &self.nodes[n];
        if node.endpoints.is_some() || node.subroutes.is_some() {
            f(node.endpoints.as_ref(), node.subroutes.as_ref());
        }
        for ns in &node.children {
            for &cn in ns {
                self.walk(cn, f);
            }
        }
    }
}
