//! The static half of [`crate::policy::compile_check`].
//!
//! Go's `CompileCheck` runs OPA's whole-program compiler: every branch of a source is parsed, checked
//! for safety and recursion, and type checked against `LockedCapabilities`. `regorus` has no such
//! compiler, and running a source only ever exercises the branches an input takes. So this module does
//! not approximate OPA. It accepts a deliberately small subset of Rego that it can check completely,
//! and refuses everything else, including much that OPA accepts:
//!
//! - **Syntax:** one `package`, an optional `import rego.v1`, and complete rules or functions with
//!   `:=`, `if`, and `else`. Refused: `default`, partial rules, `every`, `with`, `=`, destructuring,
//!   `data` references, other imports, and whitespace-sensitive forms such as an operator that starts
//!   a line.
//! - **Scope:** a variable is usable only after an earlier statement bound it. No variable may reuse
//!   a name in scope, a rule, `input`, `data`, or a builtin.
//! - **Builtins:** only names in `locked_builtins.json`, the real `LockedCapabilities` as dumped by
//!   the `compilecheck` generator, with a fixed arity. Refused as well: anything variadic or without
//!   a result, anything deprecated, `internal.*`, `rego.*`, `print`, and `numbers.range*` and `net.cidr_expand`, whose one
//!   call can outlast the evaluation budget without yielding to its timer.
//! - **Types:** a value is `Any` only where OPA also has no type: `input`, function arguments, and
//!   what is derived from them. A known type must exactly satisfy each builtin argument, and a value
//!   of a known type cannot be indexed. A union result can go only where any type is accepted.
//! - **Functions:** OPA infers a helper's argument types from its body, so a helper whose parameter
//!   is used anywhere accepts only `Any` arguments there.
//! - **Recursion:** every cycle between rules is refused.
//! - **Size:** nesting is capped so that neither this parser nor `regorus` can exhaust the stack.
//!
//! The direction that matters, "never accept what Go refuses", is checked against the real
//! `CompileCheck` by `tests/compilecheck_differential.rs`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;

/// Bound on nested terms and bodies. Well above what a hand-written policy uses.
const MAX_DEPTH: usize = 32;
/// Bound on a dotted or bracketed reference.
const MAX_REF_SEGMENTS: usize = 32;
/// Bound on one rule's `else` chain.
const MAX_ELSE: usize = 16;

const KEYWORDS: &[&str] = &[
    "as", "contains", "data", "default", "else", "every", "false", "if", "import", "in", "input",
    "not", "null", "package", "set", "some", "true", "with",
];
/// Builtins compile_check refuses even though `LockedCapabilities` holds them: see the module doc.
const REFUSED_BUILTIN_PREFIXES: &[&str] = &["internal.", "rego.", "numbers.range"];
const REFUSED_BUILTINS: &[&str] = &[
    "print",
    "trace",
    "walk",
    "net.cidr_expand",
    "assign",
    "eq",
    "equal",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
];

type Check<T> = Result<T, String>;

fn refuse<T>(message: impl Into<String>) -> Check<T> {
    Err(message.into())
}

// ---- builtin table

#[derive(Deserialize)]
struct BuiltinRecord {
    name: String,
    decl: Value,
    deprecated: bool,
}

struct Builtin {
    args: Vec<Value>,
    result: Value,
}

fn builtins() -> &'static HashMap<String, Builtin> {
    static TABLE: OnceLock<HashMap<String, Builtin>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let records: Vec<BuiltinRecord> =
            silo_gocompat::json::unmarshal(include_bytes!("locked_builtins.json"))
                .expect("locked_builtins.json is generated and valid");
        records
            .into_iter()
            .filter_map(|record| {
                let decl = record.decl.as_object()?;
                // Rego v1 refuses deprecated builtins at compile time.
                if record.deprecated || decl.contains_key("variadic") {
                    return None;
                }
                let result = decl.get("result")?.clone();
                let args = decl
                    .get("args")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                Some((record.name, Builtin { args, result }))
            })
            .collect()
    })
}

fn callable_builtin(name: &str) -> Option<&'static Builtin> {
    if REFUSED_BUILTINS.contains(&name)
        || REFUSED_BUILTIN_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    {
        return None;
    }
    builtins().get(name)
}

/// Whether a local or rule named `name` would collide with a builtin namespace. Checked against the
/// table of all locked builtins plus the families OPA removed from it, whose names stay reserved here
/// so a policy cannot define what looks like a refused builtin.
fn is_builtin_root(name: &str) -> bool {
    const REMOVED_ROOTS: &[&str] = &["http", "opa", "rand", "time", "uuid", "print", "trace"];
    REMOVED_ROOTS.contains(&name)
        || builtins().keys().any(|builtin| {
            builtin == name
                || builtin
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
}

// ---- types

/// What is statically known about a value.
#[derive(Debug, Clone, PartialEq)]
enum Ty {
    /// OPA also has no type for this value, so it passes every check.
    Any,
    /// A union or another type this module does not model. It passes only an untyped slot.
    Opaque,
    Null,
    Bool,
    Num,
    Str,
    Arr(Vec<Ty>),
    Set(Vec<Ty>),
    Obj(Vec<Ty>),
}

/// Whether OPA is certain to accept `ty` in a builtin slot declared as `decl`.
fn accepts(decl: &Value, ty: &Ty) -> bool {
    if *ty == Ty::Any {
        return true;
    }
    let kind = decl.get("type").and_then(Value::as_str).unwrap_or("");
    match kind {
        "any" => match decl.get("of").and_then(Value::as_array) {
            None => true,
            Some(of) if of.is_empty() => true,
            Some(of) => of.iter().any(|member| accepts(member, ty)),
        },
        "null" => *ty == Ty::Null,
        "boolean" => *ty == Ty::Bool,
        "number" => *ty == Ty::Num,
        "string" => *ty == Ty::Str,
        "array" => {
            let Ty::Arr(elements) = ty else { return false };
            if decl.get("static").is_some() {
                return false;
            }
            let dynamic = decl.get("dynamic");
            elements
                .iter()
                .all(|e| dynamic.is_some_and(|d| accepts(d, e)))
        }
        "set" => {
            let Ty::Set(elements) = ty else { return false };
            let of = decl.get("of");
            elements.iter().all(|e| of.is_some_and(|d| accepts(d, e)))
        }
        "object" => {
            let Ty::Obj(values) = ty else { return false };
            if decl.get("static").is_some() {
                return false;
            }
            let Some(dynamic) = decl.get("dynamic") else {
                return false;
            };
            let key_ok = dynamic.get("key").is_some_and(|key| accepts(key, &Ty::Str));
            let value = dynamic.get("value");
            key_ok && values.iter().all(|v| value.is_some_and(|d| accepts(d, v)))
        }
        _ => false,
    }
}

fn result_type(decl: &Value) -> Ty {
    let inner = |value: Option<&Value>| match value.map(result_type) {
        Some(ty) if ty != Ty::Opaque => vec![ty],
        _ => vec![Ty::Opaque],
    };
    match decl.get("type").and_then(Value::as_str).unwrap_or("") {
        "any" => match decl.get("of").and_then(Value::as_array) {
            Some(of) if !of.is_empty() => Ty::Opaque,
            _ => Ty::Any,
        },
        "null" => Ty::Null,
        "boolean" => Ty::Bool,
        "number" => Ty::Num,
        "string" => Ty::Str,
        "array" if decl.get("static").is_none() => Ty::Arr(inner(decl.get("dynamic"))),
        "set" => Ty::Set(inner(decl.get("of"))),
        "object" if decl.get("static").is_none() => {
            Ty::Obj(inner(decl.get("dynamic").and_then(|d| d.get("value"))))
        }
        _ => Ty::Opaque,
    }
}

fn join(a: Ty, b: Ty) -> Ty {
    if a == b { a } else { Ty::Opaque }
}

// ---- lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str,
    Num,
    Punct(&'static str),
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    /// A string literal's value.
    text: String,
    /// Space or a comment directly before this token.
    spaced: bool,
    /// A line break before this token.
    newline: bool,
}

const PUNCTUATION: &[&str] = &[
    ":=", "==", "!=", "<=", ">=", "(", ")", "[", "]", "{", "}", ",", ";", ".", "|", "&", "+", "-",
    "*", "/", "%", "<", ">", ":", "=",
];

fn lex(source: &str) -> Check<Vec<Token>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut spaced = false;
    let mut newline = false;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\r' => {
                spaced = true;
                i += 1;
                continue;
            }
            b'\n' => {
                spaced = true;
                newline = true;
                i += 1;
                continue;
            }
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                let comment = &source[source[..i].rfind('#').unwrap_or(0)..i];
                // OPA reads a `# METADATA` block as an annotation with its own checks.
                if comment.contains("METADATA") {
                    return refuse("METADATA annotations are not supported");
                }
                spaced = true;
                continue;
            }
            _ => {}
        }
        let (tok, text, len) = if c.is_ascii_alphabetic() || c == b'_' {
            let len = bytes[i..]
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
                .count();
            (
                Tok::Ident(source[i..i + len].to_owned()),
                String::new(),
                len,
            )
        } else if c.is_ascii_digit() {
            let len = lex_number(&bytes[i..])?;
            (Tok::Num, String::new(), len)
        } else if c == b'"' {
            let (value, len) = lex_string(&source[i..])?;
            (Tok::Str, value, len)
        } else if c == b'`' {
            let Some(end) = source[i + 1..].find('`') else {
                return refuse("unterminated raw string");
            };
            (Tok::Str, source[i + 1..i + 1 + end].to_owned(), end + 2)
        } else if let Some(p) = PUNCTUATION.iter().find(|p| source[i..].starts_with(**p)) {
            (Tok::Punct(p), String::new(), p.len())
        } else {
            return refuse(format!("unexpected character at byte {i}"));
        };
        tokens.push(Token {
            tok,
            text,
            spaced,
            newline,
        });
        spaced = false;
        newline = false;
        i += len;
    }
    tokens.push(Token {
        tok: Tok::Eof,
        text: String::new(),
        spaced: true,
        newline: true,
    });
    Ok(tokens)
}

fn lex_number(bytes: &[u8]) -> Check<usize> {
    let digits = |b: &[u8]| b.iter().take_while(|c| c.is_ascii_digit()).count();
    let whole = digits(bytes);
    if whole > 15 || (whole > 1 && bytes[0] == b'0') {
        return refuse("number outside the supported form");
    }
    let mut len = whole;
    if bytes.get(len) == Some(&b'.') {
        let fraction = digits(&bytes[len + 1..]);
        if fraction == 0 || fraction > 15 {
            return refuse("number outside the supported form");
        }
        len += 1 + fraction;
    }
    if bytes
        .get(len)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.')
    {
        return refuse("number outside the supported form");
    }
    Ok(len)
}

fn lex_string(source: &str) -> Check<(String, usize)> {
    let mut value = String::new();
    let mut chars = source.char_indices().skip(1);
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((value, i + 1)),
            '\\' => match chars.next() {
                Some((_, '"')) => value.push('"'),
                Some((_, '\\')) => value.push('\\'),
                Some((_, 'n')) => value.push('\n'),
                Some((_, 't')) => value.push('\t'),
                _ => return refuse("unsupported string escape"),
            },
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                return refuse("control character in string");
            }
            c => value.push(c),
        }
    }
    refuse("unterminated string")
}

// ---- syntax tree

#[derive(Debug, Clone)]
enum Expr {
    Literal(Ty),
    Var(String),
    /// A variable, `input`, or a rule, with field and bracket segments.
    Ref(String, Vec<Segment>),
    Call(String, Vec<Expr>),
    Array(Vec<Expr>),
    Set(Vec<Expr>),
    Object(Vec<(String, Expr)>),
    ArrayComprehension(Box<Expr>, Vec<Stmt>),
    SetComprehension(Box<Expr>, Vec<Stmt>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone)]
enum Segment {
    Field,
    Wildcard,
    Index(Expr),
}

#[derive(Debug, Clone)]
enum Stmt {
    Assign(String, Expr),
    Expr(Expr),
    Not(Expr),
    /// `lhs op rhs` with `==`, `!=`, `<`, `<=`, `>`, `>=`. Allowed only as a whole statement.
    Compare(Expr, Expr),
    In(Expr, Expr),
    NotIn(Expr, Expr),
    Some(Vec<String>, Expr),
}

/// One `head [if body]` of a rule, or one `else` link of its chain.
#[derive(Debug)]
struct Branch {
    /// `None` for a bare `name if {...}`, whose value is `true`.
    value: Option<Expr>,
    body: Vec<Stmt>,
}

#[derive(Debug)]
struct Rule {
    name: String,
    /// `None` for a rule that is not a function.
    params: Option<Vec<String>>,
    branches: Vec<Branch>,
}

// ---- parser

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.at]
    }

    fn peek_is(&self, p: &str) -> bool {
        matches!(&self.peek().tok, Tok::Punct(q) if *q == p)
    }

    fn peek_ident(&self, name: &str) -> bool {
        matches!(&self.peek().tok, Tok::Ident(n) if n == name)
    }

    fn bump(&mut self) -> Token {
        let token = self.tokens[self.at].clone();
        if self.at + 1 < self.tokens.len() {
            self.at += 1;
        }
        token
    }

    fn eat(&mut self, p: &str) -> bool {
        let found = self.peek_is(p);
        if found {
            self.bump();
        }
        found
    }

    fn eat_ident(&mut self, name: &str) -> bool {
        let found = self.peek_ident(name);
        if found {
            self.bump();
        }
        found
    }

    fn expect(&mut self, p: &str) -> Check<()> {
        if self.eat(p) {
            Ok(())
        } else {
            refuse(format!("expected {p}"))
        }
    }

    fn name(&mut self) -> Check<String> {
        match self.bump().tok {
            Tok::Ident(name) if !KEYWORDS.contains(&name.as_str()) => Ok(name),
            _ => refuse("expected a name"),
        }
    }

    fn nested<T>(&mut self, inner: impl FnOnce(&mut Self) -> Check<T>) -> Check<T> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return refuse("policy nesting is too deep");
        }
        let result = inner(self);
        self.depth -= 1;
        result
    }

    fn module(&mut self) -> Check<(String, Vec<Rule>)> {
        if !self.eat_ident("package") {
            return refuse("expected package");
        }
        let mut package = self.name()?;
        while self.peek_is(".") && !self.peek().spaced {
            self.bump();
            package.push('.');
            package.push_str(&self.name()?);
        }
        if self.peek_ident("import") {
            self.bump();
            if !(self.eat_ident("rego") && self.eat(".") && self.eat_ident("v1")) {
                return refuse("only `import rego.v1` is supported");
            }
        }
        let mut rules = Vec::new();
        while self.peek().tok != Tok::Eof {
            if !self.peek().newline {
                return refuse("a rule must start on its own line");
            }
            rules.push(self.rule()?);
        }
        Ok((package, rules))
    }

    fn rule(&mut self) -> Check<Rule> {
        let name = self.name()?;
        let params = if self.peek_is("(") && !self.peek().spaced {
            self.bump();
            let mut params = Vec::new();
            if !self.peek_is(")") {
                loop {
                    let Tok::Ident(param) = self.bump().tok else {
                        return refuse("a function argument must be a name");
                    };
                    params.push(param);
                    if !self.eat(",") {
                        break;
                    }
                }
            }
            self.expect(")")?;
            Some(params)
        } else {
            None
        };
        let mut branches = vec![self.branch()?];
        while self.peek_ident("else") {
            if self.peek().newline && self.at + 1 >= self.tokens.len() {
                return refuse("unexpected else");
            }
            self.bump();
            if branches.len() > MAX_ELSE {
                return refuse("too many else branches");
            }
            if !self.peek_is(":=") {
                return refuse("else requires a value");
            }
            branches.push(self.branch()?);
        }
        Ok(Rule {
            name,
            params,
            branches,
        })
    }

    fn branch(&mut self) -> Check<Branch> {
        let value = if self.eat(":=") {
            if self.peek().newline {
                return refuse("a rule value must follow := on the same line");
            }
            Some(self.expr()?)
        } else if self.peek_ident("if") {
            None
        } else {
            return refuse("a rule needs := or if");
        };
        let body = if self.eat_ident("if") {
            if self.eat("{") {
                let body = self.nested(|p| p.statements("}"))?;
                self.expect("}")?;
                body
            } else {
                vec![self.statement()?]
            }
        } else {
            Vec::new()
        };
        Ok(Branch { value, body })
    }

    /// Statements up to, and not including, the `close` token. Each is separated from the next by a
    /// line break or `;`.
    fn statements(&mut self, close: &str) -> Check<Vec<Stmt>> {
        let mut out = Vec::new();
        loop {
            while self.eat(";") {}
            if self.peek_is(close) {
                if out.is_empty() {
                    return refuse("an empty body is not supported");
                }
                return Ok(out);
            }
            out.push(self.statement()?);
            if !(self.peek_is(close) || self.peek_is(";") || self.peek().newline) {
                return refuse("expected the end of a statement");
            }
        }
    }

    fn statement(&mut self) -> Check<Stmt> {
        if self.eat_ident("some") {
            let mut names = vec![self.name_or_wildcard()?];
            if self.eat(",") {
                names.push(self.name_or_wildcard()?);
            }
            if !self.eat_ident("in") {
                return refuse("`some` without `in` is not supported");
            }
            return Ok(Stmt::Some(names, self.expr()?));
        }
        if self.eat_ident("not") {
            let inner = self.expr()?;
            if self.eat_ident("in") {
                return Ok(Stmt::NotIn(inner, self.expr()?));
            }
            return Ok(Stmt::Not(inner));
        }
        if let (Tok::Ident(name), Some(next)) = (&self.peek().tok, self.tokens.get(self.at + 1))
            && next.tok == Tok::Punct(":=")
        {
            let name = name.clone();
            if KEYWORDS.contains(&name.as_str()) || name == "_" {
                return refuse("this name cannot be assigned");
            }
            self.bump();
            self.bump();
            return Ok(Stmt::Assign(name, self.expr()?));
        }
        let left = self.expr()?;
        if self.eat_ident("in") {
            return Ok(Stmt::In(left, self.expr()?));
        }
        for op in ["==", "!=", "<=", ">=", "<", ">"] {
            if self.peek_is(op) {
                self.spaced_operator()?;
                return Ok(Stmt::Compare(left, self.expr()?));
            }
        }
        Ok(Stmt::Expr(left))
    }

    fn name_or_wildcard(&mut self) -> Check<String> {
        if matches!(&self.peek().tok, Tok::Ident(n) if n == "_") {
            self.bump();
            return Ok("_".to_owned());
        }
        self.name()
    }

    /// Consumes a binary operator, which must have space on both sides and stay on one line.
    fn spaced_operator(&mut self) -> Check<()> {
        let operator = self.bump();
        let next = self.peek();
        if !operator.spaced || operator.newline || !next.spaced || next.newline {
            return refuse("a binary operator needs a space on both sides, on one line");
        }
        Ok(())
    }

    fn expr(&mut self) -> Check<Expr> {
        self.binary(0, true)
    }

    /// An array or set element, where a top-level `|` starts a comprehension body.
    fn element(&mut self) -> Check<Expr> {
        self.binary(0, false)
    }

    fn binary(&mut self, level: usize, allow_or: bool) -> Check<Expr> {
        const LEVELS: [&[(&str, &str)]; 4] = [
            &[("|", "or")],
            &[("&", "and")],
            &[("+", "plus"), ("-", "minus")],
            &[("*", "mul"), ("/", "div"), ("%", "rem")],
        ];
        if level == LEVELS.len() {
            return self.primary();
        }
        let mut left = self.binary(level + 1, allow_or)?;
        let mut links = 0;
        loop {
            let Some((_, builtin)) = LEVELS[level]
                .iter()
                .find(|(symbol, _)| self.peek_is(symbol) && (allow_or || *symbol != "|"))
            else {
                return Ok(left);
            };
            self.spaced_operator()?;
            let right = self.binary(level + 1, allow_or)?;
            links += 1;
            if self.depth + links > MAX_DEPTH {
                return refuse("policy expression is too long");
            }
            left = Expr::Binary(builtin, Box::new(left), Box::new(right));
        }
    }

    fn primary(&mut self) -> Check<Expr> {
        self.nested(|p| {
            let token = p.bump();
            match token.tok {
                Tok::Num => Ok(Expr::Literal(Ty::Num)),
                Tok::Str => Ok(Expr::Literal(Ty::Str)),
                Tok::Punct("-") => {
                    let next = p.bump();
                    if next.tok == Tok::Num && !next.spaced {
                        Ok(Expr::Literal(Ty::Num))
                    } else {
                        refuse("unary minus applies only to a number")
                    }
                }
                Tok::Punct("(") => {
                    let inner = p.expr()?;
                    p.expect(")")?;
                    Ok(inner)
                }
                Tok::Punct("[") => p.array(),
                Tok::Punct("{") => p.brace(),
                Tok::Ident(name) => p.named(name),
                _ => refuse("expected a value"),
            }
        })
    }

    fn array(&mut self) -> Check<Expr> {
        if self.eat("]") {
            return Ok(Expr::Array(Vec::new()));
        }
        let first = self.element()?;
        if self.eat("|") {
            let body = self.statements("]")?;
            self.expect("]")?;
            return Ok(Expr::ArrayComprehension(Box::new(first), body));
        }
        let mut items = vec![first];
        while self.eat(",") {
            if self.peek_is("]") {
                break;
            }
            items.push(self.element()?);
        }
        self.expect("]")?;
        Ok(Expr::Array(items))
    }

    fn brace(&mut self) -> Check<Expr> {
        if self.eat("}") {
            return Ok(Expr::Object(Vec::new()));
        }
        if self.peek().tok == Tok::Str && matches!(&self.tokens[self.at + 1].tok, Tok::Punct(":")) {
            let mut entries: Vec<(String, Expr)> = Vec::new();
            loop {
                let key = self.bump();
                if key.tok != Tok::Str || entries.iter().any(|(k, _)| *k == key.text) {
                    return refuse("object keys must be unique string literals");
                }
                self.expect(":")?;
                entries.push((key.text, self.expr()?));
                if !self.eat(",") {
                    break;
                }
                if self.peek_is("}") {
                    break;
                }
            }
            self.expect("}")?;
            return Ok(Expr::Object(entries));
        }
        let first = self.element()?;
        if self.peek_is(":") {
            return refuse("object keys must be string literals");
        }
        if self.eat("|") {
            let body = self.statements("}")?;
            self.expect("}")?;
            return Ok(Expr::SetComprehension(Box::new(first), body));
        }
        let mut items = vec![first];
        while self.eat(",") {
            if self.peek_is("}") {
                break;
            }
            items.push(self.element()?);
        }
        self.expect("}")?;
        Ok(Expr::Set(items))
    }

    fn named(&mut self, name: String) -> Check<Expr> {
        match name.as_str() {
            "null" => return Ok(Expr::Literal(Ty::Null)),
            "true" | "false" => return Ok(Expr::Literal(Ty::Bool)),
            "set" => {
                if self.peek_is("(") && !self.peek().spaced {
                    self.bump();
                    self.expect(")")?;
                    return Ok(Expr::Set(Vec::new()));
                }
                return refuse("set is reserved");
            }
            "input" => {}
            _ if KEYWORDS.contains(&name.as_str()) => {
                return refuse(format!("{name} is not supported here"));
            }
            _ => {}
        }

        // A dotted name directly followed by `(` is a call; anything else is a reference.
        let mut path = name.clone();
        let mut segments = Vec::new();
        loop {
            let token = self.peek();
            if token.spaced {
                break;
            }
            if self.peek_is(".") {
                self.bump();
                if self.peek().spaced {
                    return refuse("a field must follow the dot directly");
                }
                let field = self.name()?;
                if segments.iter().all(|s| matches!(s, Segment::Field)) {
                    path.push('.');
                    path.push_str(&field);
                }
                segments.push(Segment::Field);
            } else if self.peek_is("[") {
                self.bump();
                if matches!(&self.peek().tok, Tok::Ident(n) if n == "_") {
                    self.bump();
                    segments.push(Segment::Wildcard);
                } else {
                    segments.push(Segment::Index(self.expr()?));
                }
                self.expect("]")?;
            } else {
                break;
            }
            if segments.len() > MAX_REF_SEGMENTS {
                return refuse("reference is too long");
            }
        }
        if self.peek_is("(") && !self.peek().spaced {
            if !segments.iter().all(|s| matches!(s, Segment::Field)) {
                return refuse("only a named function can be called");
            }
            self.bump();
            let mut args = Vec::new();
            if !self.peek_is(")") {
                loop {
                    args.push(self.expr()?);
                    if !self.eat(",") {
                        break;
                    }
                }
            }
            self.expect(")")?;
            return Ok(Expr::Call(path, args));
        }
        if segments.is_empty() {
            return Ok(Expr::Var(name));
        }
        Ok(Expr::Ref(name, segments))
    }
}

// ---- checker

/// What is known about one checked rule.
#[derive(Debug, Clone)]
struct RuleInfo {
    ty: Ty,
    /// For a function: per parameter, whether a non-`Any` argument is safe. True only for `_` and for
    /// a parameter no branch mentions.
    param_free: Vec<bool>,
    is_function: bool,
}

struct Checker<'a> {
    defined: &'a BTreeMap<String, Option<usize>>,
    checked: &'a HashMap<String, RuleInfo>,
    params: Vec<String>,
    used_params: BTreeSet<String>,
}

type Scope = Vec<(String, Ty)>;

impl Checker<'_> {
    fn lookup(&mut self, scope: &Scope, name: &str) -> Check<Ty> {
        if let Some((_, ty)) = scope.iter().rev().find(|(n, _)| n == name) {
            if self.params.iter().any(|p| p == name) {
                self.used_params.insert(name.to_owned());
            }
            return Ok(ty.clone());
        }
        if name == "input" {
            return Ok(Ty::Any);
        }
        match self.defined.get(name) {
            Some(None) => Ok(self
                .checked
                .get(name)
                .map_or(Ty::Opaque, |info| info.ty.clone())),
            Some(Some(_)) => refuse(format!("function {name} used as a reference")),
            None => refuse(format!("var {name} is unsafe")),
        }
    }

    fn bind(&self, scope: &mut Scope, name: &str, ty: Ty) -> Check<()> {
        if name == "_" {
            return Ok(());
        }
        if KEYWORDS.contains(&name)
            || self.defined.contains_key(name)
            || is_builtin_root(name)
            || scope.iter().any(|(n, _)| n == name)
        {
            return refuse(format!("{name} cannot be declared here"));
        }
        scope.push((name.to_owned(), ty));
        Ok(())
    }

    fn check_call_args(&mut self, scope: &Scope, name: &str, args: &[Expr]) -> Check<Ty> {
        if !name.contains('.')
            && let Some(arity) = self.defined.get(name)
        {
            let Some(arity) = arity else {
                return refuse(format!("{name} is not a function"));
            };
            if *arity != args.len() {
                return refuse(format!("function {name} has arity {arity}"));
            }
            let info = self.checked.get(name).cloned();
            for (i, arg) in args.iter().enumerate() {
                let ty = self.expr(scope, arg)?;
                let free = info
                    .as_ref()
                    .and_then(|info| info.param_free.get(i))
                    .copied()
                    .unwrap_or(false);
                if ty != Ty::Any && !free {
                    return refuse(format!("{name}: argument {i} has a known type"));
                }
            }
            return Ok(info.map_or(Ty::Opaque, |info| info.ty));
        }
        let Some(builtin) = callable_builtin(name) else {
            return refuse(format!("undefined or unsupported function {name}"));
        };
        if builtin.args.len() != args.len() {
            return refuse(format!(
                "{name} takes {} arguments, got {}",
                builtin.args.len(),
                args.len()
            ));
        }
        for (decl, arg) in builtin.args.iter().zip(args) {
            let ty = self.expr(scope, arg)?;
            if !accepts(decl, &ty) {
                return refuse(format!("{name}: invalid argument"));
            }
        }
        Ok(result_type(&builtin.result))
    }

    fn expr(&mut self, scope: &Scope, expr: &Expr) -> Check<Ty> {
        match expr {
            Expr::Literal(ty) => Ok(ty.clone()),
            Expr::Var(name) => self.lookup(scope, name),
            Expr::Ref(name, segments) => {
                if self.lookup(scope, name)? != Ty::Any {
                    return refuse(format!("{name} has a known type and cannot be indexed"));
                }
                for segment in segments {
                    if let Segment::Index(index) = segment {
                        self.expr(scope, index)?;
                    }
                }
                Ok(Ty::Any)
            }
            Expr::Call(name, args) => self.check_call_args(scope, name, args),
            Expr::Binary(builtin, left, right) => {
                let args = [(**left).clone(), (**right).clone()];
                self.check_call_args(scope, builtin, &args)
            }
            Expr::Array(items) => Ok(Ty::Arr(
                items
                    .iter()
                    .map(|item| self.expr(scope, item))
                    .collect::<Check<_>>()?,
            )),
            Expr::Set(items) => Ok(Ty::Set(
                items
                    .iter()
                    .map(|item| self.expr(scope, item))
                    .collect::<Check<_>>()?,
            )),
            Expr::Object(entries) => Ok(Ty::Obj(
                entries
                    .iter()
                    .map(|(_, value)| self.expr(scope, value))
                    .collect::<Check<_>>()?,
            )),
            Expr::ArrayComprehension(term, body) => {
                let mut inner = scope.clone();
                self.body(&mut inner, body)?;
                Ok(Ty::Arr(vec![self.expr(&inner, term)?]))
            }
            Expr::SetComprehension(term, body) => {
                let mut inner = scope.clone();
                self.body(&mut inner, body)?;
                Ok(Ty::Set(vec![self.expr(&inner, term)?]))
            }
        }
    }

    fn body(&mut self, scope: &mut Scope, body: &[Stmt]) -> Check<()> {
        for statement in body {
            match statement {
                Stmt::Assign(name, value) => {
                    let ty = self.expr(scope, value)?;
                    self.bind(scope, name, ty)?;
                }
                Stmt::Expr(expr) => {
                    if !matches!(
                        expr,
                        Expr::Var(_) | Expr::Ref(..) | Expr::Call(..) | Expr::Literal(Ty::Bool)
                    ) {
                        return refuse("this statement form is not supported");
                    }
                    self.expr(scope, expr)?;
                }
                Stmt::Not(expr) => {
                    if !matches!(expr, Expr::Var(_) | Expr::Ref(..) | Expr::Call(..)) {
                        return refuse("this negation form is not supported");
                    }
                    if has_wildcard(expr) {
                        return refuse("var _ is unsafe under not");
                    }
                    self.expr(scope, expr)?;
                }
                Stmt::Compare(left, right) => {
                    let (l, r) = (self.expr(scope, left)?, self.expr(scope, right)?);
                    let scalar = matches!(l, Ty::Null | Ty::Bool | Ty::Num | Ty::Str);
                    if l != Ty::Any && r != Ty::Any && !(scalar && l == r) {
                        return refuse("comparison of mismatched known types");
                    }
                }
                Stmt::NotIn(item, collection) if has_wildcard(item) || has_wildcard(collection) => {
                    return refuse("var _ is unsafe under not");
                }
                Stmt::In(item, collection) | Stmt::NotIn(item, collection) => {
                    self.expr(scope, item)?;
                    let ty = self.expr(scope, collection)?;
                    if !matches!(ty, Ty::Any | Ty::Arr(_) | Ty::Set(_) | Ty::Obj(_)) {
                        return refuse("`in` needs a collection");
                    }
                }
                Stmt::Some(names, collection) => {
                    let ty = self.expr(scope, collection)?;
                    let element = match &ty {
                        Ty::Any => Ty::Any,
                        Ty::Arr(items) | Ty::Set(items) | Ty::Obj(items) => {
                            match items.split_first() {
                                Some((first, rest)) if rest.iter().all(|t| t == first) => {
                                    first.clone()
                                }
                                _ => Ty::Opaque,
                            }
                        }
                        _ => return refuse("`some` needs a collection"),
                    };
                    if names.len() == 2 {
                        let key = if ty == Ty::Any { Ty::Any } else { Ty::Opaque };
                        self.bind(scope, &names[0], key)?;
                        self.bind(scope, &names[1], element)?;
                    } else {
                        self.bind(scope, &names[0], element)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Whether `expr` has a `_` segment anywhere: OPA treats one under `not` as an unsafe variable.
fn has_wildcard(expr: &Expr) -> bool {
    match expr {
        Expr::Literal(_) | Expr::Var(_) => false,
        Expr::Ref(_, segments) => segments.iter().any(|segment| match segment {
            Segment::Field => false,
            Segment::Wildcard => true,
            Segment::Index(index) => has_wildcard(index),
        }),
        Expr::Call(_, items) | Expr::Array(items) | Expr::Set(items) => {
            items.iter().any(has_wildcard)
        }
        Expr::Object(entries) => entries.iter().any(|(_, value)| has_wildcard(value)),
        Expr::Binary(_, left, right) => has_wildcard(left) || has_wildcard(right),
        // A comprehension can hold anything. Refusing it here is the safe direction.
        Expr::ArrayComprehension(..) | Expr::SetComprehension(..) => true,
    }
}

fn rule_dependencies(rule: &Rule, defined: &BTreeMap<String, Option<usize>>) -> BTreeSet<String> {
    fn walk_expr(expr: &Expr, out: &mut BTreeSet<String>) {
        match expr {
            Expr::Literal(_) => {}
            Expr::Var(name) => {
                out.insert(name.clone());
            }
            Expr::Ref(name, segments) => {
                out.insert(name.clone());
                for segment in segments {
                    if let Segment::Index(index) = segment {
                        walk_expr(index, out);
                    }
                }
            }
            Expr::Call(name, args) => {
                out.insert(name.clone());
                args.iter().for_each(|arg| walk_expr(arg, out));
            }
            Expr::Array(items) | Expr::Set(items) => {
                items.iter().for_each(|item| walk_expr(item, out));
            }
            Expr::Object(entries) => entries.iter().for_each(|(_, v)| walk_expr(v, out)),
            Expr::ArrayComprehension(term, body) | Expr::SetComprehension(term, body) => {
                walk_expr(term, out);
                walk_body(body, out);
            }
            Expr::Binary(_, left, right) => {
                walk_expr(left, out);
                walk_expr(right, out);
            }
        }
    }
    fn walk_body(body: &[Stmt], out: &mut BTreeSet<String>) {
        for statement in body {
            match statement {
                Stmt::Assign(_, e) | Stmt::Expr(e) | Stmt::Not(e) | Stmt::Some(_, e) => {
                    walk_expr(e, out)
                }
                Stmt::Compare(a, b) | Stmt::In(a, b) | Stmt::NotIn(a, b) => {
                    walk_expr(a, out);
                    walk_expr(b, out);
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    for branch in &rule.branches {
        if let Some(value) = &branch.value {
            walk_expr(value, &mut out);
        }
        walk_body(&branch.body, &mut out);
    }
    out.retain(|name| defined.contains_key(name));
    out
}

fn check_rule(
    rule: &Rule,
    defined: &BTreeMap<String, Option<usize>>,
    checked: &HashMap<String, RuleInfo>,
) -> Check<RuleInfo> {
    let params = rule.params.clone().unwrap_or_default();
    let mut checker = Checker {
        defined,
        checked,
        params: params.iter().filter(|p| *p != "_").cloned().collect(),
        used_params: BTreeSet::new(),
    };
    let mut ty: Option<Ty> = None;
    for branch in &rule.branches {
        let mut scope = Scope::new();
        for param in &params {
            checker.bind(&mut scope, param, Ty::Any)?;
        }
        checker.body(&mut scope, &branch.body)?;
        let branch_ty = match &branch.value {
            Some(value) => checker.expr(&scope, value)?,
            None => Ty::Bool,
        };
        ty = Some(match ty {
            Some(previous) => join(previous, branch_ty),
            None => branch_ty,
        });
    }
    let param_free = params
        .iter()
        .map(|p| p == "_" || !checker.used_params.contains(p))
        .collect();
    Ok(RuleInfo {
        ty: ty.unwrap_or(Ty::Opaque),
        param_free,
        is_function: rule.params.is_some(),
    })
}

/// Checks `source` and returns its package path without `data.`, or why it is refused.
pub(crate) fn check_module(source: &str, expected_package: &str) -> Check<()> {
    let tokens = lex(source)?;
    let mut parser = Parser {
        tokens,
        at: 0,
        depth: 0,
    };
    let (package, rules) = parser.module()?;
    if package != expected_package {
        return refuse(format!(
            "policy package must be {expected_package}, got {package}"
        ));
    }

    let mut defined: BTreeMap<String, Option<usize>> = BTreeMap::new();
    for rule in &rules {
        if KEYWORDS.contains(&rule.name.as_str()) || is_builtin_root(&rule.name) {
            return refuse(format!("rule name {} is reserved", rule.name));
        }
        let arity = rule.params.as_ref().map(Vec::len);
        if let Some(existing) = defined.insert(rule.name.clone(), arity)
            && existing != arity
        {
            return refuse(format!("conflicting rules {} found", rule.name));
        }
        if let Some(params) = &rule.params {
            for (i, param) in params.iter().enumerate() {
                if param != "_" && params[..i].contains(param) {
                    return refuse(format!("arg {param} redeclared"));
                }
            }
        }
    }
    if defined.get("override") != Some(&Some(2)) {
        return refuse("policy must define override(base, input)");
    }

    // Check dependencies first, so a caller sees each rule's inferred types. A rule that never
    // becomes ready is on a cycle.
    let mut dependencies: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for rule in &rules {
        dependencies
            .entry(&rule.name)
            .or_default()
            .extend(rule_dependencies(rule, &defined));
    }
    let mut checked: HashMap<String, RuleInfo> = HashMap::new();
    while checked.len() < defined.len() {
        let ready: Vec<&str> = dependencies
            .iter()
            .filter(|(name, deps)| {
                !checked.contains_key(**name) && deps.iter().all(|d| checked.contains_key(d))
            })
            .map(|(name, _)| *name)
            .collect();
        if ready.is_empty() {
            return refuse("policy rules are recursive");
        }
        for name in ready {
            let mut merged: Option<RuleInfo> = None;
            for rule in rules.iter().filter(|rule| rule.name == name) {
                let info = check_rule(rule, &defined, &checked)?;
                merged = Some(match merged {
                    None => info,
                    Some(previous) => RuleInfo {
                        ty: join(previous.ty, info.ty),
                        param_free: previous
                            .param_free
                            .iter()
                            .zip(&info.param_free)
                            .map(|(a, b)| *a && *b)
                            .collect(),
                        is_function: previous.is_function,
                    },
                });
            }
            let merged = merged.expect("every defined name has a rule");
            debug_assert_eq!(merged.is_function, defined[name].is_some());
            checked.insert(name.to_owned(), merged);
        }
    }
    Ok(())
}
