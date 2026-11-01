//! Port of `regexp/syntax.Parse` with Perl flags, emitting Rust `regex` syntax.
//!
//! The parser builds a tree with Go's flag state already resolved, so nothing in the output
//! depends on Rust's reading of flags, Perl classes, or Unicode tables:
//!
//! - Classes and case folding are expanded here from Go's tables into explicit ranges. `(?i)` and
//!   `\p{..}` never reach the `regex` crate, which tracks a different Unicode version.
//! - `\d`, `\s`, `\w` are ASCII and `\s` excludes `\v`, as in Go.
//! - `\b` and `\B` emit as `(?-u:\b)` and `(?-u:\B)`.
//! - Syntax only Rust understands (`[a&&b]`, `\<`, `(?x)`, `\u{..}`) is either literal or an error
//!   as in Go, and errors carry Go's exact text.
//!
//! Go's literal factoring in `parser.factor` is not ported: it only shares prefixes between
//! alternatives and does not change what matches, but it can move the point at which the
//! "expression too large" and "nests too deeply" limits fire for patterns right at those limits.

use crate::unicode::{MAX_RUNE, lookup_table, simple_fold};
use crate::unicode_tables::{
    CATEGORIES, CATEGORY_ALIASES, FOLD_CATEGORY, FOLD_SCRIPT, RangeTable, SCRIPTS,
};

const ERR_INVALID_CHAR_CLASS_RANGE: &str = "invalid character class range";
const ERR_INVALID_ESCAPE: &str = "invalid escape sequence";
const ERR_INVALID_NAMED_CAPTURE: &str = "invalid named capture";
const ERR_INVALID_PERL_OP: &str = "invalid or unsupported Perl syntax";
const ERR_INVALID_REPEAT_OP: &str = "invalid nested repetition operator";
const ERR_INVALID_REPEAT_SIZE: &str = "invalid repeat count";
const ERR_MISSING_BRACKET: &str = "missing closing ]";
const ERR_MISSING_PAREN: &str = "missing closing )";
const ERR_MISSING_REPEAT_ARGUMENT: &str = "missing argument to repetition operator";
const ERR_TRAILING_BACKSLASH: &str = "trailing backslash at end of expression";
const ERR_UNEXPECTED_PAREN: &str = "unexpected )";
const ERR_NESTING_DEPTH: &str = "expression nests too deeply";
pub(crate) const ERR_LARGE: &str = "expression too large";

const MAX_HEIGHT: u32 = 1000;
const MAX_SIZE: i64 = (128 << 20) / 40;
const MAX_RUNES: i64 = (128 << 20) / 4;
const MIN_FOLD: u32 = 0x0041;
const MAX_FOLD: u32 = 0x1e943;

/// `syntax.Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub(crate) code: &'static str,
    pub(crate) expr: String,
}

impl Error {
    pub(crate) fn new(code: &'static str, expr: impl Into<String>) -> Self {
        Self {
            code,
            expr: expr.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error parsing regexp: {}: `{}`", self.code, self.expr)
    }
}

impl std::error::Error for Error {}

type Ranges = Vec<(u32, u32)>;

#[derive(Debug)]
enum Kind {
    Literal {
        rune: u32,
        fold: bool,
    },
    Class(Ranges),
    AnyChar,
    AnyCharNotNl,
    BeginLine,
    EndLine,
    BeginText,
    EndText,
    WordBoundary,
    NoWordBoundary,
    Empty,
    Capture {
        sub: Box<Node>,
    },
    Star {
        sub: Box<Node>,
        non_greedy: bool,
    },
    Plus {
        sub: Box<Node>,
        non_greedy: bool,
    },
    Quest {
        sub: Box<Node>,
        non_greedy: bool,
    },
    Repeat {
        sub: Box<Node>,
        min: u32,
        max: i32,
        non_greedy: bool,
    },
    Concat(Vec<Node>),
    Alternate(Vec<Node>),
}

#[derive(Debug)]
struct Node {
    kind: Kind,
    height: u32,
    size: i64,
}

impl Node {
    fn leaf(kind: Kind, size: i64) -> Self {
        Self {
            kind,
            height: 1,
            size,
        }
    }

    fn has_capture(&self) -> bool {
        match &self.kind {
            Kind::Capture { .. } => true,
            Kind::Star { sub, .. }
            | Kind::Plus { sub, .. }
            | Kind::Quest { sub, .. }
            | Kind::Repeat { sub, .. } => sub.has_capture(),
            Kind::Concat(subs) | Kind::Alternate(subs) => subs.iter().any(Self::has_capture),
            _ => false,
        }
    }

    /// Go's `repeatIsValid`: the product of nested counted repetitions stays within `n`.
    fn repeat_is_valid(&self, mut n: i64) -> bool {
        if let Kind::Repeat { min, max, .. } = &self.kind {
            let mut m = i64::from(*max);
            if m == 0 {
                return true;
            }
            if m < 0 {
                m = i64::from(*min);
            }
            if m > n {
                return false;
            }
            if m > 0 {
                n /= m;
            }
        }
        match &self.kind {
            Kind::Capture { sub, .. }
            | Kind::Star { sub, .. }
            | Kind::Plus { sub, .. }
            | Kind::Quest { sub, .. }
            | Kind::Repeat { sub, .. } => sub.repeat_is_valid(n),
            Kind::Concat(subs) | Kind::Alternate(subs) => subs.iter().all(|s| s.repeat_is_valid(n)),
            _ => true,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Flags {
    fold_case: bool,
    /// Inverse of Go's `OneLine`: set by `(?m)`.
    multi_line: bool,
    dot_nl: bool,
    non_greedy: bool,
}

/// One open group, the slice of Go's parse stack above its `opLeftParen`.
struct Frame {
    /// Flags to restore at the closing paren. `None` for the root frame.
    restore: Option<Flags>,
    capture: bool,
    alternatives: Vec<Node>,
    current: Vec<Node>,
}

impl Frame {
    fn new(restore: Option<Flags>, capture: bool) -> Self {
        Self {
            restore,
            capture,
            alternatives: Vec::new(),
            current: Vec::new(),
        }
    }
}

/// The result of parsing: the Rust pattern and the capture names by group index.
pub(crate) struct Parsed {
    pub(crate) rust_pattern: String,
    pub(crate) names: Vec<String>,
}

pub(crate) fn parse(pattern: &str) -> Result<Parsed, Error> {
    let mut parser = Parser {
        whole: pattern,
        flags: Flags::default(),
        stack: vec![Frame::new(None, false)],
        names: vec![String::new()],
        num_runes: 0,
    };
    let root = parser.run()?;
    let mut rust_pattern = String::new();
    emit(&root, &mut rust_pattern);
    Ok(Parsed {
        rust_pattern,
        names: parser.names,
    })
}

struct Parser<'a> {
    whole: &'a str,
    flags: Flags,
    stack: Vec<Frame>,
    names: Vec<String>,
    num_runes: i64,
}

/// `nextRune`: decoding empty input yields U+FFFD without consuming anything.
fn next_rune(t: &str) -> (u32, &str) {
    match t.chars().next() {
        Some(c) => (c as u32, &t[c.len_utf8()..]),
        None => (crate::unicode::REPLACEMENT, t),
    }
}

/// The part of `before` that `after` does not include.
fn consumed<'s>(before: &'s str, after: &str) -> &'s str {
    &before[..before.len() - after.len()]
}

impl Parser<'_> {
    fn top(&mut self) -> &mut Frame {
        self.stack.last_mut().expect("root frame is never popped")
    }

    fn check_limits(&self, node: &Node) -> Result<(), Error> {
        if self.num_runes > MAX_RUNES || node.size > MAX_SIZE {
            return Err(Error::new(ERR_LARGE, self.whole));
        }
        if node.height > MAX_HEIGHT {
            return Err(Error::new(ERR_NESTING_DEPTH, self.whole));
        }
        Ok(())
    }

    fn push(&mut self, node: Node) -> Result<(), Error> {
        match &node.kind {
            Kind::Literal { .. } => self.num_runes += 1,
            Kind::Class(ranges) => self.num_runes += 2 * ranges.len() as i64,
            _ => {}
        }
        self.check_limits(&node)?;
        self.top().current.push(node);
        Ok(())
    }

    fn literal(&mut self, rune: u32) -> Result<(), Error> {
        let fold = self.flags.fold_case;
        self.push(Node::leaf(Kind::Literal { rune, fold }, 1))
    }

    fn op(&mut self, kind: Kind) -> Result<(), Error> {
        self.push(Node::leaf(kind, 1))
    }

    fn run(&mut self) -> Result<Node, Error> {
        let mut t = self.whole;
        let mut last_repeat: Option<&str> = None;
        while let Some(&first) = t.as_bytes().first() {
            let mut repeat = None;
            match first {
                b'(' => {
                    if t.as_bytes().get(1) == Some(&b'?') {
                        t = self.parse_perl_flags(t)?;
                    } else {
                        self.names.push(String::new());
                        let restore = self.flags;
                        self.stack.push(Frame::new(Some(restore), true));
                        t = &t[1..];
                    }
                }
                b'|' => {
                    self.parse_vertical_bar()?;
                    t = &t[1..];
                }
                b')' => {
                    self.parse_right_paren()?;
                    t = &t[1..];
                }
                b'^' => {
                    self.op(if self.flags.multi_line {
                        Kind::BeginLine
                    } else {
                        Kind::BeginText
                    })?;
                    t = &t[1..];
                }
                b'$' => {
                    self.op(if self.flags.multi_line {
                        Kind::EndLine
                    } else {
                        Kind::EndText
                    })?;
                    t = &t[1..];
                }
                b'.' => {
                    self.op(if self.flags.dot_nl {
                        Kind::AnyChar
                    } else {
                        Kind::AnyCharNotNl
                    })?;
                    t = &t[1..];
                }
                b'[' => t = self.parse_class(t)?,
                b'*' | b'+' | b'?' => {
                    let before = t;
                    let after = self.repeat(first, before, &t[1..], last_repeat)?;
                    repeat = Some(before);
                    t = after;
                }
                b'{' => {
                    let before = t;
                    match parse_repeat(t) {
                        None => {
                            // A repeat that cannot be parsed makes { a literal.
                            self.literal(u32::from(b'{'))?;
                            t = &t[1..];
                        }
                        Some((min, max, after)) => {
                            if !(0..=1000).contains(&min)
                                || max > 1000
                                || (max >= 0 && min > i64::from(max))
                            {
                                let expr = consumed(before, after);
                                return Err(Error::new(ERR_INVALID_REPEAT_SIZE, expr));
                            }
                            let after =
                                self.repeat_counted(min as u32, max, before, after, last_repeat)?;
                            repeat = Some(before);
                            t = after;
                        }
                    }
                }
                b'\\' => t = self.parse_backslash(t)?,
                _ => {
                    let (c, rest) = next_rune(t);
                    self.literal(c)?;
                    t = rest;
                }
            }
            last_repeat = repeat;
        }
        self.close_group()?;
        if self.stack.len() != 1 {
            return Err(Error::new(ERR_MISSING_PAREN, self.whole));
        }
        let mut root = self.stack.pop().expect("root frame");
        Ok(root.current.pop().expect("close_group leaves one node"))
    }

    fn parse_backslash<'t>(&mut self, t: &'t str) -> Result<&'t str, Error> {
        match t.as_bytes().get(1) {
            Some(b'A') => {
                self.op(Kind::BeginText)?;
                return Ok(&t[2..]);
            }
            Some(b'b') => {
                self.op(Kind::WordBoundary)?;
                return Ok(&t[2..]);
            }
            Some(b'B') => {
                self.op(Kind::NoWordBoundary)?;
                return Ok(&t[2..]);
            }
            Some(b'C') => return Err(Error::new(ERR_INVALID_ESCAPE, &t[..2])),
            Some(b'Q') => {
                // \Q ... \E: everything between is literal.
                let body = &t[2..];
                let (lit, rest) = body.split_once("\\E").unwrap_or((body, ""));
                for c in lit.chars() {
                    self.literal(c as u32)?;
                }
                return Ok(rest);
            }
            Some(b'z') => {
                self.op(Kind::EndText)?;
                return Ok(&t[2..]);
            }
            _ => {}
        }
        // Unicode character group like \p{Han}.
        if matches!(t.as_bytes().get(1), Some(b'p' | b'P')) {
            let mut ranges = Ranges::new();
            if let Some(rest) = self.parse_unicode_class(t, &mut ranges)? {
                self.push_class(ranges)?;
                return Ok(rest);
            }
        }
        // Perl character class escape.
        let mut ranges = Ranges::new();
        if let Some(rest) = self.parse_perl_class_escape(t, &mut ranges) {
            self.push_class(ranges)?;
            return Ok(rest);
        }
        // Ordinary single-character escape.
        let (c, rest) = parse_escape(t)?;
        self.literal(c)?;
        Ok(rest)
    }

    fn push_class(&mut self, ranges: Ranges) -> Result<(), Error> {
        self.push(Node::leaf(Kind::Class(clean_class(ranges)), 1))
    }

    fn repeat_common<'t>(
        &mut self,
        before: &'t str,
        after: &'t str,
        last_repeat: Option<&'t str>,
    ) -> Result<(&'t str, bool, Node), Error> {
        let mut non_greedy = self.flags.non_greedy;
        let mut after = after;
        if after.as_bytes().first() == Some(&b'?') {
            after = &after[1..];
            non_greedy = !non_greedy;
        }
        if let Some(last) = last_repeat {
            // a** is a syntax error, not a doubled star, and a++ means something else entirely.
            return Err(Error::new(ERR_INVALID_REPEAT_OP, consumed(last, after)));
        }
        match self.top().current.pop() {
            Some(sub) => Ok((after, non_greedy, sub)),
            None => Err(Error::new(
                ERR_MISSING_REPEAT_ARGUMENT,
                consumed(before, after),
            )),
        }
    }

    fn repeat<'t>(
        &mut self,
        op: u8,
        before: &'t str,
        after: &'t str,
        last_repeat: Option<&'t str>,
    ) -> Result<&'t str, Error> {
        let (after, non_greedy, sub) = self.repeat_common(before, after, last_repeat)?;
        let height = sub.height + 1;
        let size = sub.size + if op == b'*' { 2 } else { 1 };
        let sub = Box::new(sub);
        let kind = match op {
            b'*' => Kind::Star { sub, non_greedy },
            b'+' => Kind::Plus { sub, non_greedy },
            _ => Kind::Quest { sub, non_greedy },
        };
        let node = Node { kind, height, size };
        self.check_limits(&node)?;
        self.top().current.push(node);
        Ok(after)
    }

    fn repeat_counted<'t>(
        &mut self,
        min: u32,
        max: i32,
        before: &'t str,
        after: &'t str,
        last_repeat: Option<&'t str>,
    ) -> Result<&'t str, Error> {
        let (after, non_greedy, sub) = self.repeat_common(before, after, last_repeat)?;
        let sub_size = sub.size;
        let size = if max == -1 {
            if min == 0 {
                2 + sub_size
            } else {
                1 + i64::from(min).saturating_mul(sub_size)
            }
        } else {
            i64::from(max).saturating_mul(sub_size) + i64::from(max) - i64::from(min)
        }
        .max(1);
        let node = Node {
            height: sub.height + 1,
            size,
            kind: Kind::Repeat {
                sub: Box::new(sub),
                min,
                max,
                non_greedy,
            },
        };
        self.check_limits(&node)?;
        if (min >= 2 || max >= 2) && !node.repeat_is_valid(1000) {
            return Err(Error::new(ERR_INVALID_REPEAT_SIZE, consumed(before, after)));
        }
        self.top().current.push(node);
        Ok(after)
    }

    fn concat_current(&mut self) -> Result<(), Error> {
        let subs = std::mem::take(&mut self.top().current);
        let node = make_concat(subs);
        self.check_limits(&node)?;
        self.top().current.push(node);
        Ok(())
    }

    fn parse_vertical_bar(&mut self) -> Result<(), Error> {
        self.concat_current()?;
        let frame = self.top();
        let node = frame.current.pop().expect("concat_current pushed a node");
        frame.alternatives.push(node);
        Ok(())
    }

    /// Replaces the current frame's contents with their alternation, the end of `concat`,
    /// `swapVerticalBar`, and `alternate` in Go.
    fn close_group(&mut self) -> Result<(), Error> {
        self.concat_current()?;
        let frame = self.top();
        if frame.alternatives.is_empty() {
            return Ok(());
        }
        let last = frame.current.pop().expect("concat_current pushed a node");
        let mut alternatives = std::mem::take(&mut frame.alternatives);
        alternatives.push(last);
        let node = make_alternate(alternatives);
        self.check_limits(&node)?;
        self.top().current.push(node);
        Ok(())
    }

    fn parse_right_paren(&mut self) -> Result<(), Error> {
        self.close_group()?;
        if self.stack.len() < 2 {
            return Err(Error::new(ERR_UNEXPECTED_PAREN, self.whole));
        }
        let mut frame = self.stack.pop().expect("checked length");
        let sub = frame.current.pop().expect("close_group leaves one node");
        self.flags = frame.restore.expect("non-root frame has saved flags");
        if frame.capture {
            let node = Node {
                height: sub.height + 1,
                size: 2 + sub.size,
                kind: Kind::Capture { sub: Box::new(sub) },
            };
            self.push(node)
        } else {
            // Just for grouping. Go pushes the same node again, and numRunes counts it twice.
            self.push(sub)
        }
    }

    fn parse_perl_flags<'t>(&mut self, s: &'t str) -> Result<&'t str, Error> {
        let bytes = s.as_bytes();
        let starts_with_p = bytes.len() > 4 && bytes[2] == b'P' && bytes[3] == b'<';
        let starts_with_name = bytes.len() > 3 && bytes[2] == b'<';
        if starts_with_p || starts_with_name {
            let expr_start = if starts_with_name { 3 } else { 4 };
            let Some(end) = s.find('>') else {
                return Err(Error::new(ERR_INVALID_NAMED_CAPTURE, s));
            };
            let capture = &s[..=end];
            let name = &s[expr_start..end];
            if !is_valid_capture_name(name) {
                return Err(Error::new(ERR_INVALID_NAMED_CAPTURE, capture));
            }
            self.names.push(name.to_string());
            let restore = self.flags;
            self.stack.push(Frame::new(Some(restore), true));
            return Ok(&s[end + 1..]);
        }

        // Non-capturing group. Might also twiddle Perl flags.
        let mut t = &s[2..];
        let mut flags = self.flags;
        let mut negative = false;
        let mut saw_flag = false;
        while !t.is_empty() {
            let (c, rest) = next_rune(t);
            t = rest;
            match char::from_u32(c) {
                Some('i') => {
                    flags.fold_case = !negative;
                    saw_flag = true;
                }
                Some('m') => {
                    flags.multi_line = !negative;
                    saw_flag = true;
                }
                Some('s') => {
                    flags.dot_nl = !negative;
                    saw_flag = true;
                }
                Some('U') => {
                    flags.non_greedy = !negative;
                    saw_flag = true;
                }
                Some('-') => {
                    if negative {
                        break;
                    }
                    negative = true;
                    saw_flag = false;
                }
                Some(c @ (':' | ')')) => {
                    if negative && !saw_flag {
                        break;
                    }
                    if c == ':' {
                        // Open a new group that restores the flags from before this one.
                        let restore = self.flags;
                        self.stack.push(Frame::new(Some(restore), false));
                    }
                    self.flags = flags;
                    return Ok(t);
                }
                _ => break,
            }
        }
        Err(Error::new(ERR_INVALID_PERL_OP, consumed(s, t)))
    }

    fn append_group(&self, ranges: &mut Ranges, positive: bool, class: &[(u32, u32)]) {
        if self.flags.fold_case {
            let mut tmp = Ranges::new();
            for &(lo, hi) in class {
                append_folded_range(&mut tmp, lo, hi);
            }
            let tmp = clean_class(tmp);
            if positive {
                ranges.extend_from_slice(&tmp);
            } else {
                append_negated(ranges, &tmp);
            }
        } else if positive {
            ranges.extend_from_slice(class);
        } else {
            append_negated(ranges, class);
        }
    }

    fn parse_perl_class_escape<'t>(&self, s: &'t str, ranges: &mut Ranges) -> Option<&'t str> {
        let (positive, class) = perl_group(s.as_bytes().get(..2)?)?;
        self.append_group(ranges, positive, class);
        Some(&s[2..])
    }

    fn parse_named_class<'t>(
        &self,
        s: &'t str,
        ranges: &mut Ranges,
    ) -> Result<Option<&'t str>, Error> {
        if s.len() < 2 || !s.starts_with("[:") {
            return Ok(None);
        }
        let Some(i) = s[2..].find(":]") else {
            return Ok(None);
        };
        let i = i + 2;
        let (name, rest) = s.split_at(i + 2);
        let Some((positive, class)) = posix_group(name) else {
            return Err(Error::new(ERR_INVALID_CHAR_CLASS_RANGE, name));
        };
        self.append_group(ranges, positive, class);
        Ok(Some(rest))
    }

    fn parse_unicode_class<'t>(
        &self,
        s: &'t str,
        ranges: &mut Ranges,
    ) -> Result<Option<&'t str>, Error> {
        let bytes = s.as_bytes();
        if bytes.len() < 2 || bytes[0] != b'\\' || (bytes[1] != b'p' && bytes[1] != b'P') {
            return Ok(None);
        }
        // Committed to parse or return an error.
        let mut positive = bytes[1] == b'p';
        let (c, mut t) = next_rune(&s[2..]);
        let seq;
        let mut name;
        if c != u32::from(b'{') {
            // Single-letter name.
            seq = consumed(s, t);
            name = &seq[2..];
        } else {
            let Some(end) = s.find('}') else {
                return Err(Error::new(ERR_INVALID_CHAR_CLASS_RANGE, s));
            };
            seq = &s[..=end];
            t = &s[end + 1..];
            name = &s[3..end];
        }
        // A group can have leading negation too: \p{^Han} == \P{Han}, \P{^Han} == \p{Han}.
        if let Some(stripped) = name.strip_prefix('^') {
            positive = !positive;
            name = stripped;
        }
        let Some((table, fold, table_positive)) = unicode_table(name) else {
            return Err(Error::new(ERR_INVALID_CHAR_CLASS_RANGE, seq));
        };
        if !table_positive {
            positive = !positive;
        }
        match (self.flags.fold_case, fold) {
            (true, Some(fold)) => {
                let mut tmp = Ranges::new();
                append_table(&mut tmp, table);
                append_table(&mut tmp, fold);
                let tmp = clean_class(tmp);
                if positive {
                    ranges.extend_from_slice(&tmp);
                } else {
                    append_negated(ranges, &tmp);
                }
            }
            _ => {
                let mut tmp = Ranges::new();
                append_table(&mut tmp, table);
                if positive {
                    ranges.extend_from_slice(&tmp);
                } else {
                    let tmp = clean_class(tmp);
                    append_negated(ranges, &tmp);
                }
            }
        }
        Ok(Some(t))
    }

    fn parse_class<'t>(&mut self, s: &'t str) -> Result<&'t str, Error> {
        let mut t = &s[1..]; // chop [
        let mut negated = false;
        if t.as_bytes().first() == Some(&b'^') {
            negated = true;
            t = &t[1..];
        }
        let mut class = Ranges::new();
        let mut first = true; // ] and - are okay as the first character in a class
        while t.is_empty() || t.as_bytes()[0] != b']' || first {
            first = false;

            // POSIX [:alnum:] etc.
            if t.len() > 2
                && t.starts_with("[:")
                && let Some(rest) = self.parse_named_class(t, &mut class)?
            {
                t = rest;
                continue;
            }
            // Unicode character group like \p{Han}.
            if let Some(rest) = self.parse_unicode_class(t, &mut class)? {
                t = rest;
                continue;
            }
            // Perl character class symbols.
            if t.as_bytes().first() == Some(&b'\\')
                && let Some(rest) = self.parse_perl_class_escape(t, &mut class)
            {
                t = rest;
                continue;
            }
            // Single character or simple range.
            let rng = t;
            let (lo, rest) = parse_class_char(t, s)?;
            t = rest;
            let mut hi = lo;
            // [a-] means (a|-), so check for the final ].
            if t.len() >= 2 && t.as_bytes()[0] == b'-' && t.as_bytes()[1] != b']' {
                let (h, rest) = parse_class_char(&t[1..], s)?;
                t = rest;
                hi = h;
                if hi < lo {
                    return Err(Error::new(ERR_INVALID_CHAR_CLASS_RANGE, consumed(rng, t)));
                }
            }
            if self.flags.fold_case {
                append_folded_range(&mut class, lo, hi);
            } else {
                class.push((lo, hi));
            }
        }
        t = &t[1..]; // chop ]
        let mut class = clean_class(class);
        if negated {
            class = negate_class(&class);
        }
        self.push(Node::leaf(Kind::Class(class), 1))?;
        Ok(t)
    }
}

fn make_concat(mut subs: Vec<Node>) -> Node {
    match subs.len() {
        0 => return Node::leaf(Kind::Empty, 1),
        1 => return subs.pop().expect("one element"),
        _ => {}
    }
    // Hoist nested concatenations, like Go's collapse.
    let mut flat = Vec::with_capacity(subs.len());
    for sub in subs {
        match sub.kind {
            Kind::Concat(inner) => flat.extend(inner),
            kind => flat.push(Node {
                kind,
                height: sub.height,
                size: sub.size,
            }),
        }
    }
    // Go merges runs of literals with equal fold state into one node, so a pure literal string is
    // a leaf for the height limit.
    let all_literal = {
        let mut fold_state = None;
        flat.iter().all(|n| match n.kind {
            Kind::Literal { fold, .. } => *fold_state.get_or_insert(fold) == fold,
            _ => false,
        })
    };
    let height = if all_literal {
        1
    } else {
        1 + flat.iter().map(|n| n.height).max().unwrap_or(0)
    };
    let size = flat.iter().map(|n| n.size).sum::<i64>().max(1);
    Node {
        kind: Kind::Concat(flat),
        height,
        size,
    }
}

fn make_alternate(subs: Vec<Node>) -> Node {
    let mut flat = Vec::with_capacity(subs.len());
    for sub in subs {
        match sub.kind {
            Kind::Alternate(inner) => flat.extend(inner),
            kind => flat.push(Node {
                kind,
                height: sub.height,
                size: sub.size,
            }),
        }
    }
    let height = 1 + flat.iter().map(|n| n.height).max().unwrap_or(0);
    let size = flat.iter().map(|n| n.size).sum::<i64>() + flat.len() as i64 - 1;
    Node {
        kind: Kind::Alternate(flat),
        height,
        size: size.max(1),
    }
}

/// `parseRepeat`: `{min}`, `{min,}`, or `{min,max}`. `None` makes the `{` a literal. Numbers too
/// big to track come back as `min == -1`.
fn parse_repeat(s: &str) -> Option<(i64, i32, &str)> {
    let s = s.strip_prefix('{')?;
    let (mut min, s) = parse_int(s)?;
    if s.is_empty() {
        return None;
    }
    let (max, s): (i64, &str) = if let Some(after_comma) = s.strip_prefix(',') {
        if after_comma.is_empty() {
            return None;
        }
        if after_comma.starts_with('}') {
            (-1, after_comma)
        } else {
            let (max, rest) = parse_int(after_comma)?;
            if max < 0 {
                min = -1;
            }
            (max, rest)
        }
    } else {
        (min, s)
    };
    let rest = s.strip_prefix('}')?;
    // Values above 1000 are rejected by the caller, so this conversion cannot truncate one that
    // matters: parse_int caps at 1e8.
    Some((min, max as i32, rest))
}

/// `parseInt`: decimal without leading zeros. Too-large values become -1.
fn parse_int(s: &str) -> Option<(i64, &str)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }
    if bytes.len() >= 2 && bytes[0] == b'0' && bytes[1].is_ascii_digit() {
        return None;
    }
    let end = bytes
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(bytes.len());
    let mut n: i64 = 0;
    for &b in &bytes[..end] {
        if n >= 100_000_000 {
            n = -1;
            break;
        }
        n = n * 10 + i64::from(b - b'0');
    }
    Some((n, &s[end..]))
}

fn is_valid_capture_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn unhex(c: u32) -> Option<u32> {
    char::from_u32(c).and_then(|c| c.to_digit(16))
}

fn parse_escape(s: &str) -> Result<(u32, &str), Error> {
    let t = &s[1..];
    if t.is_empty() {
        return Err(Error::new(ERR_TRAILING_BACKSLASH, ""));
    }
    let (c, mut t) = next_rune(t);
    let invalid = |t: &str| Err(Error::new(ERR_INVALID_ESCAPE, consumed(s, t)));
    let ascii = u8::try_from(c).ok();
    match ascii {
        Some(b'1'..=b'7') if !matches!(t.as_bytes().first(), Some(b'0'..=b'7')) => {
            // A single non-zero digit is a backreference, which is not supported.
            invalid(t)
        }
        Some(b'0'..=b'7') => {
            // Up to three octal digits; one is already consumed.
            let mut r = c - u32::from(b'0');
            for _ in 1..3 {
                match t.as_bytes().first() {
                    Some(&d @ b'0'..=b'7') => {
                        r = r * 8 + u32::from(d - b'0');
                        t = &t[1..];
                    }
                    _ => break,
                }
            }
            Ok((r, t))
        }
        Some(b'x') => {
            if t.is_empty() {
                return invalid(t);
            }
            let (c, rest) = next_rune(t);
            t = rest;
            if c == u32::from(b'{') {
                // Any number of hex digits in braces, at least one.
                let mut nhex = 0;
                let mut r = 0u32;
                loop {
                    if t.is_empty() {
                        return invalid(t);
                    }
                    let (c, rest) = next_rune(t);
                    t = rest;
                    if c == u32::from(b'}') {
                        break;
                    }
                    let Some(v) = unhex(c) else {
                        return invalid(t);
                    };
                    r = r * 16 + v;
                    if r > MAX_RUNE {
                        return invalid(t);
                    }
                    nhex += 1;
                }
                if nhex == 0 {
                    return invalid(t);
                }
                return Ok((r, t));
            }
            // Two hex digits.
            let x = unhex(c);
            let (c2, rest) = next_rune(t);
            t = rest;
            match (x, unhex(c2)) {
                (Some(x), Some(y)) => Ok((x * 16 + y, t)),
                _ => invalid(t),
            }
        }
        // There is no \b here: in Perl it is a word boundary, and Go keeps that in classes too.
        Some(b'a') => Ok((0x07, t)),
        Some(b'f') => Ok((0x0C, t)),
        Some(b'n') => Ok((0x0A, t)),
        Some(b'r') => Ok((0x0D, t)),
        Some(b't') => Ok((0x09, t)),
        Some(b'v') => Ok((0x0B, t)),
        Some(b) if b < 0x80 && !b.is_ascii_alphanumeric() => {
            // Escaped non-word characters are always themselves.
            Ok((c, t))
        }
        _ => invalid(t),
    }
}

fn parse_class_char<'t>(s: &'t str, whole_class: &str) -> Result<(u32, &'t str), Error> {
    if s.is_empty() {
        return Err(Error::new(ERR_MISSING_BRACKET, whole_class));
    }
    if s.as_bytes()[0] == b'\\' {
        return parse_escape(s);
    }
    Ok(next_rune(s))
}

const CODE_D: &[(u32, u32)] = &[(0x30, 0x39)];
const CODE_S: &[(u32, u32)] = &[(0x9, 0xa), (0xc, 0xd), (0x20, 0x20)];
const CODE_W: &[(u32, u32)] = &[(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)];

fn perl_group(name: &[u8]) -> Option<(bool, &'static [(u32, u32)])> {
    Some(match name {
        b"\\d" => (true, CODE_D),
        b"\\D" => (false, CODE_D),
        b"\\s" => (true, CODE_S),
        b"\\S" => (false, CODE_S),
        b"\\w" => (true, CODE_W),
        b"\\W" => (false, CODE_W),
        _ => return None,
    })
}

fn posix_group(name: &str) -> Option<(bool, &'static [(u32, u32)])> {
    let (positive, class): (bool, &str) = match name.strip_prefix("[:^") {
        Some(rest) => (false, rest),
        None => (true, name.strip_prefix("[:")?),
    };
    let ranges: &'static [(u32, u32)] = match class {
        "alnum:]" => &[(0x30, 0x39), (0x41, 0x5a), (0x61, 0x7a)],
        "alpha:]" => &[(0x41, 0x5a), (0x61, 0x7a)],
        "ascii:]" => &[(0x0, 0x7f)],
        "blank:]" => &[(0x9, 0x9), (0x20, 0x20)],
        "cntrl:]" => &[(0x0, 0x1f), (0x7f, 0x7f)],
        "digit:]" => &[(0x30, 0x39)],
        "graph:]" => &[(0x21, 0x7e)],
        "lower:]" => &[(0x61, 0x7a)],
        "print:]" => &[(0x20, 0x7e)],
        "punct:]" => &[(0x21, 0x2f), (0x3a, 0x40), (0x5b, 0x60), (0x7b, 0x7e)],
        "space:]" => &[(0x9, 0xd), (0x20, 0x20)],
        "upper:]" => &[(0x41, 0x5a)],
        "word:]" => CODE_W,
        "xdigit:]" => &[(0x30, 0x39), (0x41, 0x46), (0x61, 0x66)],
        _ => return None,
    };
    Some((positive, ranges))
}

fn canonical_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut first = true;
    for &b in name.as_bytes() {
        match b {
            b'_' | b'-' | b' ' => {}
            _ if first => {
                out.push(char::from(b.to_ascii_uppercase()));
                first = false;
            }
            _ => out.push(char::from(b.to_ascii_lowercase())),
        }
    }
    out
}

const ANY_TABLE: RangeTable = &[(0, 0xFFFF, 1), (0x10000, MAX_RUNE, 1)];
const ASCII_TABLE: RangeTable = &[(0, 0x7F, 1)];
const ASCII_FOLD_TABLE: RangeTable = &[(0, 0x7F, 1), (0x017F, 0x017F, 1), (0x212A, 0x212A, 1)];

/// `unicodeTable`: the table, its fold companion, and whether the sense is positive.
fn unicode_table(name: &str) -> Option<(RangeTable, Option<RangeTable>, bool)> {
    // Names can contain non-ASCII text. Go's canonicalName works on bytes, and no table name
    // contains such bytes, so these names simply fail to resolve.
    if !name.is_ascii() {
        return None;
    }
    let name = canonical_name(name);
    match name.as_str() {
        "Any" => return Some((ANY_TABLE, Some(ANY_TABLE), true)),
        "Assigned" => {
            let cn = lookup_table(CATEGORIES, "Cn")?;
            return Some((cn, Some(cn), false));
        }
        "Ascii" => return Some((ASCII_TABLE, Some(ASCII_FOLD_TABLE), true)),
        "Lc" => {
            return Some((
                lookup_table(CATEGORIES, "LC")?,
                lookup_table(FOLD_CATEGORY, "LC"),
                true,
            ));
        }
        _ => {}
    }
    if let Some(table) = lookup_table(CATEGORIES, &name) {
        return Some((table, lookup_table(FOLD_CATEGORY, &name), true));
    }
    if let Some(table) = lookup_table(SCRIPTS, &name) {
        return Some((table, lookup_table(FOLD_SCRIPT, &name), true));
    }
    let i = CATEGORY_ALIASES
        .binary_search_by_key(&name.as_str(), |entry| entry.0)
        .ok()?;
    let actual = CATEGORY_ALIASES[i].1;
    Some((
        lookup_table(CATEGORIES, actual)?,
        lookup_table(FOLD_CATEGORY, actual),
        true,
    ))
}

fn append_table(ranges: &mut Ranges, table: RangeTable) {
    for &(lo, hi, stride) in table {
        if stride == 1 {
            ranges.push((lo, hi));
        } else {
            let mut c = lo;
            while c <= hi {
                ranges.push((c, c));
                c += stride;
            }
        }
    }
}

fn append_folded_range(ranges: &mut Ranges, mut lo: u32, mut hi: u32) {
    if (lo <= MIN_FOLD && hi >= MAX_FOLD) || hi < MIN_FOLD || lo > MAX_FOLD {
        ranges.push((lo, hi));
        return;
    }
    if lo < MIN_FOLD {
        ranges.push((lo, MIN_FOLD - 1));
        lo = MIN_FOLD;
    }
    if hi > MAX_FOLD {
        ranges.push((MAX_FOLD + 1, hi));
        hi = MAX_FOLD;
    }
    for c in lo..=hi {
        ranges.push((c, c));
        let mut f = simple_fold(c);
        while f != c {
            ranges.push((f, f));
            f = simple_fold(f);
        }
    }
}

/// `cleanClass`: sorted, merged, and without overlaps.
fn clean_class(mut ranges: Ranges) -> Ranges {
    ranges.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut out: Ranges = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// `appendNegatedClass`: `class` must be clean.
fn append_negated(ranges: &mut Ranges, class: &[(u32, u32)]) {
    let mut next_lo = 0u32;
    for &(lo, hi) in class {
        if next_lo < lo {
            ranges.push((next_lo, lo - 1));
        }
        next_lo = hi + 1;
    }
    if next_lo <= MAX_RUNE {
        ranges.push((next_lo, MAX_RUNE));
    }
}

fn negate_class(class: &[(u32, u32)]) -> Ranges {
    let mut out = Ranges::with_capacity(class.len() + 1);
    append_negated(&mut out, class);
    out
}

const EMPTY_CLASS: &str = r"[^\x{0}-\x{10FFFF}]";

fn emit_rune_escape(r: u32, out: &mut String) {
    out.push_str(&format!("\\x{{{r:X}}}"));
}

fn is_surrogate(r: u32) -> bool {
    (0xD800..=0xDFFF).contains(&r)
}

fn emit_class(ranges: &[(u32, u32)], out: &mut String) {
    // Rust patterns can't name surrogates, and they can't occur in a &str anyway.
    let mut emitted = false;
    let mark = out.len();
    out.push('[');
    for &(lo, hi) in ranges {
        let mut pieces: [(u32, u32); 2] = [(lo, hi), (1, 0)];
        if lo <= 0xDFFF && hi >= 0xD800 {
            pieces = [(lo, 0xD7FF.min(hi)), (0xE000.max(lo), hi)];
        }
        for (lo, hi) in pieces {
            if lo > hi || (lo == hi && is_surrogate(lo)) {
                continue;
            }
            emitted = true;
            emit_rune_escape(lo, out);
            if hi != lo {
                out.push('-');
                emit_rune_escape(hi, out);
            }
        }
    }
    out.push(']');
    if !emitted {
        out.truncate(mark);
        out.push_str(EMPTY_CLASS);
    }
}

fn emit_group_if_needed(node: &Node, out: &mut String) {
    let atomic = matches!(
        node.kind,
        Kind::Literal { .. }
            | Kind::Class(_)
            | Kind::Capture { .. }
            | Kind::AnyChar
            | Kind::AnyCharNotNl
    );
    if atomic {
        emit(node, out);
    } else {
        out.push_str("(?:");
        emit(node, out);
        out.push(')');
    }
}

fn emit(node: &Node, out: &mut String) {
    match &node.kind {
        Kind::Literal { rune, fold } => {
            let r = *rune;
            if *fold && (MIN_FOLD..=MAX_FOLD).contains(&r) && simple_fold(r) != r {
                let mut ranges = Ranges::new();
                append_folded_range(&mut ranges, r, r);
                emit_class(&clean_class(ranges), out);
            } else if is_surrogate(r) {
                out.push_str(EMPTY_CLASS);
            } else if r < 0x80 && (r as u8).is_ascii_alphanumeric() {
                out.push(char::from(r as u8));
            } else {
                emit_rune_escape(r, out);
            }
        }
        Kind::Class(ranges) => emit_class(ranges, out),
        Kind::AnyChar => out.push_str("(?s:.)"),
        Kind::AnyCharNotNl => out.push('.'),
        Kind::BeginLine => out.push_str("(?m:^)"),
        Kind::EndLine => out.push_str("(?m:$)"),
        Kind::BeginText => out.push_str(r"\A"),
        Kind::EndText => out.push_str(r"\z"),
        Kind::WordBoundary => out.push_str(r"(?-u:\b)"),
        Kind::NoWordBoundary => out.push_str(r"(?-u:\B)"),
        Kind::Empty => out.push_str("(?:)"),
        Kind::Capture { sub } => {
            // Always unnamed: Go allows repeated names and names that start with a digit, which
            // Rust rejects. GoRegex answers name lookups from the parser's table.
            out.push('(');
            emit(sub, out);
            out.push(')');
        }
        Kind::Star { sub, non_greedy } => {
            emit_group_if_needed(sub, out);
            out.push_str(if *non_greedy { "*?" } else { "*" });
        }
        Kind::Plus { sub, non_greedy } => {
            emit_group_if_needed(sub, out);
            out.push_str(if *non_greedy { "+?" } else { "+" });
        }
        Kind::Quest { sub, non_greedy } => {
            emit_group_if_needed(sub, out);
            out.push_str(if *non_greedy { "??" } else { "?" });
        }
        Kind::Repeat { sub, max: 0, .. } if sub.has_capture() => {
            // Rust drops x{0} from the tree along with any group in it, but Go keeps numbering the
            // group and reports it as unset. An empty class can never match, and the group after
            // it stays in the program without ever taking part.
            out.push_str("(?:");
            out.push_str(EMPTY_CLASS);
            emit_group_if_needed(sub, out);
            out.push_str(")?");
        }
        Kind::Repeat {
            sub,
            min,
            max,
            non_greedy,
        } => {
            emit_group_if_needed(sub, out);
            if *max == -1 {
                out.push_str(&format!("{{{min},}}"));
            } else if i64::from(*min) == i64::from(*max) {
                out.push_str(&format!("{{{min}}}"));
            } else {
                out.push_str(&format!("{{{min},{max}}}"));
            }
            if *non_greedy {
                out.push('?');
            }
        }
        Kind::Concat(subs) => {
            for sub in subs {
                if matches!(sub.kind, Kind::Alternate(_)) {
                    emit_group_if_needed(sub, out);
                } else {
                    emit(sub, out);
                }
            }
        }
        Kind::Alternate(subs) => {
            for (i, sub) in subs.iter().enumerate() {
                if i > 0 {
                    out.push('|');
                }
                emit(sub, out);
            }
        }
    }
}
