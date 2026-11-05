//! Port of `json.Unmarshal` and `json.Decoder`, on top of serde.
//!
//! [`unmarshal`], [`Decoder::decode`], and [`Stream`] decode into a `Deserialize` type the way Go
//! decodes into the matching Go value.
//!
//! # Design
//!
//! The document is first indexed into a flat tape ([`Tape`]) using an explicit stack, so nesting
//! costs no call stack and dropping the tape is not recursive. Nothing is merged at that point.
//! Go's duplicate-key behavior comes from re-running a decode step on one destination, so each
//! destination here receives every occurrence that reached it (a *slot*), and the destination's
//! kind, which serde reveals by the `deserialize_*` method it calls, decides what they mean:
//!
//! - Scalar: `null` is a no-op, each occurrence is type-checked, the last valid one wins.
//! - Struct: `null` is a no-op, and each key's occurrences join that field's slot.
//! - `Option`: `null` resets, so only the occurrences after the last `null` survive.
//! - `Vec`: `null` and `[]` reset. Otherwise index `i` of each array joins element `i`'s slot, and
//!   the last array sets the length. An element past that length keeps its slot, as a Go slice
//!   keeps its backing array, so a later longer array reuses it.
//! - `[T; N]`: as `Vec`, except `null` is a no-op, short arrays zero the rest, and extras are
//!   skipped.
//! - Map: `null` resets. Every entry starts from a fresh element.
//! - `serde_json::Value` (`any`): the last occurrence replaces everything. An integer literal
//!   whose value a `float64` holds exactly stays an integer, so `as_i64` works; any other number
//!   becomes the `f64` Go would hold.
//! - [`RawMessage`][crate::json::RawMessage]: the last occurrence's exact document bytes, with
//!   `null` stored as `null`. [`GoTime`][crate::time::GoTime]: `Time.UnmarshalJSON` on each raw
//!   literal, `null` a no-op. [`Number`][crate::json::Number]: a string kind, `null` a no-op.
//!
//! As in Go, a type mismatch is saved and decoding continues, and the error returned is the first
//! one in document order. An error from an `UnmarshalJSON` equivalent stops Go at once and beats
//! any saved error; the earliest such error wins here too. Occurrences a reset made dead cannot
//! affect the value but can still raise Go's error, so a document that has any is decoded a second
//! time, discarding the value, to check them.
//!
//! # Field conventions
//!
//! For the built-in kinds, `serde_json::Value`, and this crate's own types, no `#[serde(default)]` is
//! needed: a field missing from the document, or holding only `null`, gets its zero value, including
//! when the top-level document is `null`. **A type with a hand-written `Deserialize` needs
//! `#[serde(default)]`, and so does a newtype.** Go never runs a decoder for an absent field, and only
//! the default gets a value without running one. Without it, the decode fails with an error naming
//! the field, on the first document that omits it. `Default` must then be the Go zero value.
//!
//! One shape escapes that error. Serde's derive answers an absent field by running the field's
//! `Deserialize` against its own deserializer, which reports `None` to `deserialize_option`, before
//! this module can see the field. So a `Deserialize` that calls `Option::deserialize` first would read
//! absent as `null`. Such a type must enter through `deserialize_newtype_struct`, as
//! `silo_api_v2::wire::Patch` does; then absence is the error above.
//!
//! A field with `#[serde(default)]` or `#[serde(default = "..")]` keeps that default for an absent
//! field and for a `null`-only one, which is how to port a Go struct whose fields are set before
//! `Unmarshal`. Serde reports only the first missing field and hides each field's kind, so the first
//! decode of a type that needs this learns it by retrying, and caches what it learned, per destination
//! type, for the life of the process.
//!
//! | Go | Rust |
//! |---|---|
//! | nil-able slice or map where nil and empty differ | `Option<Vec<T>>`, `Option<HashMap<K, V>>` |
//! | `[]byte` | `Vec<u8>` (base64 or an array of numbers), or [`Bytes`][crate::json::Bytes] when nil-able |
//! | `[N]T` | `[T; N]` |
//! | `any` | `serde_json::Value` |
//! | embedded struct | spell out the promoted fields |
//!
//! Error text names a struct by its serde name. Go prints `pkg.Type` where the type itself is named
//! and `Type` for the struct in a field path. To match Go exactly, use
//! `#[serde(rename = "pkg.Type")]`.
//!
//! # `#[serde(flatten)]`
//!
//! Serde hides a flattened struct's field names from the deserializer, so these Go behaviors cannot
//! be reproduced: inner fields match by exact name only, and an inner field needs
//! `#[serde(default)]` on the flattened struct to be absent or `null`. Under
//! [`Decoder::disallow_unknown_fields`], decoding a flattened type returns an error rather than
//! silently accepting unknown fields. New decode targets should spell out the promoted fields.
//!
//! # Known differences
//!
//! - A debug build refuses to build a value nested deeper than 1,000 levels, because using it would
//!   overflow a test thread's stack. Go has no such limit. Optimized builds reach Go's 10,000, and a
//!   thread that holds such a value needs [`VALUE_STACK_BYTES`] for its recursive `Clone`, `Drop`,
//!   `to_value`, and `from_value`.
//! - A document over 512 MiB is an error. Go has no such limit, and Silo's request limits are far
//!   below it.
//! - Rust's `i64` and `isize` both deserialize as serde `i64`, so a mismatch on a Go `int` reads
//!   `int64`, and likewise `uint`.
//! - On a `[]byte` with duplicate keys, a string followed by an array containing `null` loses the
//!   string's bytes at those indexes.
//! - Rust enums are not supported as destinations.
//! - An error from a foreign `Deserialize` impl stops decoding where it happens, which can be out
//!   of document order when a field repeats.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::sync::{OnceLock, RwLock};

use serde::de::{DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::json::scanner::{self, ValueScan};

// ---------------------------------------------------------------------------------------------
// The tape: one flat, pre-order array of nodes over bytes the scanner already accepted.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Tag {
    Null = 0,
    Bool = 1,
    Number = 2,
    Str = 3,
    Array = 4,
    Object = 5,
}

/// One node as the decoder reads it. [`Tape::node`] builds it from the packed form.
#[derive(Clone, Copy)]
struct Node {
    tag: Tag,
    start: usize,
    end: usize,
    /// The index just past this node's subtree. Children start at [`Tape::first_child`]. An object's
    /// children alternate key, value.
    next: usize,
}

/// A tape slot, 8 bytes so a wide document costs far less than the values built from it. `meta` holds
/// the tag in its top 3 bits. Under it, a scalar has its end offset and a container the index past its
/// subtree. A container's first slot is followed by a slot whose `start` is the container's end.
#[derive(Clone, Copy)]
struct Slot {
    start: u32,
    meta: u32,
}

const TAG_SHIFT: u32 = 29;
const META_MASK: u32 = (1 << TAG_SHIFT) - 1;
/// The largest document [`Tape`] can index: offsets and indexes share 29 bits. Every Silo request body
/// limit is far below this; Go itself has none.
const MAX_DOCUMENT_BYTES: usize = META_MASK as usize;

fn pack(tag: Tag, value: usize) -> u32 {
    ((tag as u32) << TAG_SHIFT) | value as u32
}

struct Tape<'d> {
    data: &'d [u8],
    nodes: Vec<Slot>,
}

impl<'d> Tape<'d> {
    /// Precondition: the scanner accepted `data` as one value, and it fits [`MAX_DOCUMENT_BYTES`].
    fn build(data: &'d [u8]) -> Self {
        // An exact upper bound, so a wide document does not double the vector through its peak.
        let capacity = 1 + data
            .iter()
            .map(|c| match c {
                b',' | b':' => 1,
                b'[' | b'{' => 3,
                _ => 0,
            })
            .sum::<usize>();
        let mut nodes = Vec::with_capacity(capacity);
        let mut open: Vec<usize> = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let c = data[i];
            let start = i;
            let tag = match c {
                b' ' | b'\t' | b'\r' | b'\n' | b',' | b':' => {
                    i += 1;
                    continue;
                }
                b'{' | b'[' => {
                    open.push(nodes.len());
                    let tag = if c == b'{' { Tag::Object } else { Tag::Array };
                    nodes.push(Slot {
                        start: start as u32,
                        meta: pack(tag, 0),
                    });
                    nodes.push(Slot { start: 0, meta: 0 });
                    i += 1;
                    continue;
                }
                b'}' | b']' => {
                    i += 1;
                    let at = open.pop().expect("balanced by the scanner");
                    let next = nodes.len();
                    let tag = if c == b'}' { Tag::Object } else { Tag::Array };
                    nodes[at].meta = pack(tag, next);
                    nodes[at + 1].start = i as u32;
                    continue;
                }
                b'"' => {
                    i += 1;
                    while data[i] != b'"' {
                        i += if data[i] == b'\\' { 2 } else { 1 };
                    }
                    i += 1;
                    Tag::Str
                }
                b't' => {
                    i += 4;
                    Tag::Bool
                }
                b'f' => {
                    i += 5;
                    Tag::Bool
                }
                b'n' => {
                    i += 4;
                    Tag::Null
                }
                _ => {
                    while i < data.len()
                        && matches!(data[i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                    {
                        i += 1;
                    }
                    Tag::Number
                }
            };
            nodes.push(Slot {
                start: start as u32,
                meta: pack(tag, i),
            });
        }
        Self { data, nodes }
    }

    fn node(&self, id: usize) -> Node {
        let slot = self.nodes[id];
        let value = (slot.meta & META_MASK) as usize;
        let tag = match slot.meta >> TAG_SHIFT {
            0 => Tag::Null,
            1 => Tag::Bool,
            2 => Tag::Number,
            3 => Tag::Str,
            4 => Tag::Array,
            _ => Tag::Object,
        };
        if matches!(tag, Tag::Array | Tag::Object) {
            Node {
                tag,
                start: slot.start as usize,
                end: self.nodes[id + 1].start as usize,
                next: value,
            }
        } else {
            Node {
                tag,
                start: slot.start as usize,
                end: value,
                next: id + 1,
            }
        }
    }

    /// The index of a container's first child, or of its `next` when it has none.
    fn first_child(&self, id: usize) -> usize {
        id + 2
    }

    fn raw(&self, n: Node) -> &'d [u8] {
        &self.data[n.start..n.end]
    }

    fn literal(&self, n: Node) -> &'d str {
        std::str::from_utf8(self.raw(n)).expect("a JSON number literal is ASCII")
    }

    fn string(&self, n: Node) -> Cow<'d, str> {
        unquote(&self.data[n.start + 1..n.end - 1])
    }

    /// The child indexes of an array or object node.
    fn children(&self, id: usize) -> Children<'_, 'd> {
        Children {
            tape: self,
            at: self.first_child(id),
            end: self.node(id).next,
        }
    }
}

struct Children<'t, 'd> {
    tape: &'t Tape<'d>,
    at: usize,
    end: usize,
}

impl Iterator for Children<'_, '_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.at >= self.end {
            return None;
        }
        let id = self.at;
        self.at = self.tape.node(id).next;
        Some(id)
    }
}

fn kind_word(tag: Tag) -> &'static str {
    match tag {
        Tag::Null => "null",
        Tag::Bool => "bool",
        Tag::Number => "number",
        Tag::Str => "string",
        Tag::Array => "array",
        Tag::Object => "object",
    }
}

/// `utf8.DecodeRune`: decodes one rune from the front of `b`. Returns `(RuneError, 1)` for
/// anything invalid (a lone continuation byte, an overlong or out-of-range encoding, an encoded
/// surrogate half, or a sequence truncated by the end of input), which is how Go always advances
/// on bad UTF-8, one byte at a time.
fn decode_rune(b: &[u8]) -> (u32, usize) {
    const RUNE_ERROR: u32 = 0xFFFD;
    let Some(&b0) = b.first() else {
        return (RUNE_ERROR, 0);
    };
    if b0 < 0x80 {
        return (u32::from(b0), 1);
    }
    let (size, lead_bits, lo, hi): (usize, u32, u8, u8) = match b0 {
        0xC2..=0xDF => (2, u32::from(b0 & 0x1F), 0x80, 0xBF),
        0xE0 => (3, u32::from(b0 & 0x0F), 0xA0, 0xBF),
        0xE1..=0xEC | 0xEE..=0xEF => (3, u32::from(b0 & 0x0F), 0x80, 0xBF),
        0xED => (3, u32::from(b0 & 0x0F), 0x80, 0x9F),
        0xF0 => (4, u32::from(b0 & 0x07), 0x90, 0xBF),
        0xF1..=0xF3 => (4, u32::from(b0 & 0x07), 0x80, 0xBF),
        0xF4 => (4, u32::from(b0 & 0x07), 0x80, 0x8F),
        _ => return (RUNE_ERROR, 1),
    };
    if b.len() < size || b[1] < lo || b[1] > hi {
        return (RUNE_ERROR, 1);
    }
    let mut cp = (lead_bits << 6) | u32::from(b[1] & 0x3F);
    for &byte in &b[2..size] {
        if !(0x80..=0xBF).contains(&byte) {
            return (RUNE_ERROR, 1);
        }
        cp = (cp << 6) | u32::from(byte & 0x3F);
    }
    (cp, size)
}

fn read_hex4(s: &[u8]) -> u32 {
    s[..4].iter().fold(0, |acc, &b| {
        (acc << 4)
            | char::from(b)
                .to_digit(16)
                .expect("hex digits checked by the scanner")
    })
}

/// `unquoteBytes`, for the bytes between a validated string's quotes.
fn unquote(s: &[u8]) -> Cow<'_, str> {
    if !s.contains(&b'\\')
        && let Ok(text) = std::str::from_utf8(s)
    {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            let (cp, size) = decode_rune(&s[i..]);
            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
            i += size;
            continue;
        }
        i += 1;
        let esc = s[i];
        i += 1;
        match esc {
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{C}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let r1 = read_hex4(&s[i..]);
                i += 4;
                let cp = if (0xD800..=0xDBFF).contains(&r1) {
                    if s[i..].starts_with(b"\\u") {
                        let r2 = read_hex4(&s[i + 2..]);
                        if (0xDC00..=0xDFFF).contains(&r2) {
                            i += 6;
                            0x10000 + ((r1 - 0xD800) << 10) + (r2 - 0xDC00)
                        } else {
                            0xFFFD
                        }
                    } else {
                        0xFFFD
                    }
                } else {
                    r1
                };
                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
            }
            other => out.push(char::from(other)),
        }
    }
    Cow::Owned(out)
}

// ---------------------------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------------------------

/// The errors `json.Unmarshal` and `json.Decoder.Decode` return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A [`SyntaxError`][crate::json::SyntaxError]'s text, unchanged.
    Syntax(String),
    /// An `UnmarshalTypeError`.
    Type {
        value: String,
        type_name: String,
        struct_name: String,
        field: String,
    },
    /// `Decoder.DisallowUnknownFields`'s error.
    UnknownField(String),
    /// Anything else: bad base64, an `UnmarshalJSON` failure, serde's own `Error::custom`.
    Message(String),
    /// `io.EOF` from a [`Decoder`]: no value before the end of input.
    Eof,
    /// `io.ErrUnexpectedEOF` from a [`Decoder`]: the input ended inside a value.
    UnexpectedEof,
    /// A read error from a [`Stream`]'s reader.
    Io(String),
    /// A field could not be given a zero value. This arises only from a flattened struct.
    MissingField(&'static str),
}

impl Error {
    /// True for `errors.Is(err, io.EOF)`.
    pub fn is_eof(&self) -> bool {
        matches!(self, Error::Eof)
    }

    /// True for `errors.Is(err, io.ErrUnexpectedEOF)`.
    pub fn is_unexpected_eof(&self) -> bool {
        matches!(self, Error::UnexpectedEof)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Syntax(s) | Error::Message(s) | Error::Io(s) => f.write_str(s),
            Error::Type {
                value,
                type_name,
                struct_name,
                field,
            } => {
                if struct_name.is_empty() && field.is_empty() {
                    write!(
                        f,
                        "json: cannot unmarshal {value} into Go value of type {type_name}"
                    )
                } else {
                    write!(
                        f,
                        "json: cannot unmarshal {value} into Go struct field {struct_name}.{field} of type {type_name}"
                    )
                }
            }
            Error::UnknownField(name) => {
                write!(f, "json: unknown field {}", crate::strconv::quote(name))
            }
            Error::Eof => f.write_str("EOF"),
            Error::UnexpectedEof => f.write_str("unexpected EOF"),
            Error::MissingField(name) => write!(f, "missing field `{name}`"),
        }
    }
}

impl std::error::Error for Error {}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }

    fn missing_field(field: &'static str) -> Self {
        Error::MissingField(field)
    }
}

// ---------------------------------------------------------------------------------------------
// What serde hides about a struct's fields, learned by retrying.
// ---------------------------------------------------------------------------------------------

/// One destination type: the derived visitor's own type, plus the field list for a hand-written
/// visitor shared between lists. Names and field-list addresses do not identify a type: two structs
/// named `Body` in one module share a name, `W<i32>` and `W<Option<i32>>` share both, and a linker may
/// merge equal field lists across modules.
type StructKey = (std::any::TypeId, usize);

#[derive(Default)]
struct Learned {
    /// Fields with no serde default: an absent one is emitted so it decodes to its zero value.
    fill: Vec<&'static str>,
    /// Fields whose kind treats `null` as a no-op: a `null`-only one is treated as absent, so a
    /// serde default survives it.
    null_noop: Vec<&'static str>,
}

fn learned() -> &'static RwLock<HashMap<StructKey, Learned>> {
    static LEARNED: OnceLock<RwLock<HashMap<StructKey, Learned>>> = OnceLock::new();
    LEARNED.get_or_init(RwLock::default)
}

fn struct_key<V>(fields: &'static [&'static str]) -> StructKey {
    (typeid::of::<V>(), fields.as_ptr() as usize)
}

/// Records one fact, and returns whether it was new. The table only grows, is bounded by the
/// program's types, and stays valid if a poisoning panic interrupted a push.
fn learn(
    key: StructKey,
    field: &'static str,
    pick: fn(&mut Learned) -> &mut Vec<&'static str>,
) -> bool {
    let mut table = learned().write().unwrap_or_else(|e| e.into_inner());
    let list = pick(table.entry(key).or_default());
    if list.contains(&field) {
        return false;
    }
    list.push(field);
    true
}

// ---------------------------------------------------------------------------------------------
// Decode state.
// ---------------------------------------------------------------------------------------------

/// Grows onto a new stack segment when this one is low. Serde's recursion through a recursive
/// destination type runs through these frames, and the depth is the scanner's 10,000 at most.
fn grow<R>(f: impl FnOnce() -> R) -> R {
    stacker::maybe_grow(256 * 1024, 4 * 1024 * 1024, f)
}

/// The stack a thread needs to clone, drop, or pass through `serde_json::to_value` and `from_value` a
/// `serde_json::Value` nested to Go's 10,000-level limit, with a margin. Every runtime that handles
/// request bodies sets this as its `thread_stack_size`. It is address space until touched.
pub const VALUE_STACK_BYTES: usize = 32 * 1024 * 1024;

/// How deep a value this decoder will build. The decode itself is safe to the scanner's 10,000, but
/// the caller drops the result on its own stack with recursive drop glue. Unoptimized, a
/// `serde_json::Value` needs about 950 bytes per level, so 2,200 levels overflow a 2 MiB thread, and
/// this decoder cannot run a drop that happens after it returns. Optimized, 10,000 levels need
/// 1.7 MiB, which fits. Skipped values and `RawMessage` build nothing and are not limited.
const MAX_MATERIALIZED_DEPTH: usize = if cfg!(debug_assertions) {
    1000
} else {
    usize::MAX
};

struct Ctx<'a> {
    tape: &'a Tape<'a>,
    strict: bool,
    /// The second pass: resets are ignored so dead occurrences get type-checked.
    check: bool,
    depth: Cell<usize>,
    struct_name: Cell<&'static str>,
    fields: RefCell<Vec<&'static str>>,
    saved: RefCell<Option<(usize, Error)>>,
    aborted: RefCell<Option<(usize, Error)>>,
    needs_check: Cell<bool>,
    retry: Cell<bool>,
    /// A saved error had to unwind through serde; the returned `Err` carries no meaning.
    poison: Cell<bool>,
}

fn keep_first(slot: &RefCell<Option<(usize, Error)>>, pos: usize, err: Error) {
    let mut slot = slot.borrow_mut();
    if slot.as_ref().is_none_or(|(p, _)| pos < *p) {
        *slot = Some((pos, err));
    }
}

impl<'a> Ctx<'a> {
    fn new(tape: &'a Tape<'a>, strict: bool, check: bool) -> Self {
        Self {
            tape,
            strict,
            check,
            depth: Cell::new(0),
            struct_name: Cell::new(""),
            fields: RefCell::new(Vec::new()),
            saved: RefCell::new(None),
            aborted: RefCell::new(None),
            needs_check: Cell::new(false),
            retry: Cell::new(false),
            poison: Cell::new(false),
        }
    }

    fn node(&self, id: usize) -> Node {
        self.tape.node(id)
    }

    fn save(&self, pos: usize, err: Error) {
        keep_first(&self.saved, pos, err);
    }

    fn abort(&self, pos: usize, err: Error) {
        keep_first(&self.aborted, pos, err);
    }

    /// `saveError(&UnmarshalTypeError{..})`, with `addErrorContext`.
    fn save_type(&self, pos: usize, value: impl Into<String>, type_name: impl Into<String>) {
        let struct_name = self.struct_name.get();
        let struct_name = struct_name.rsplit('.').next().unwrap_or(struct_name);
        self.save(
            pos,
            Error::Type {
                value: value.into(),
                type_name: type_name.into(),
                struct_name: struct_name.to_string(),
                field: self.fields.borrow().join("."),
            },
        );
    }
}

/// Which field a `null`-only slot belongs to, for learning that its kind ignores `null`.
#[derive(Clone, Copy)]
struct NullField {
    key: StructKey,
    field: &'static str,
}

// ---------------------------------------------------------------------------------------------
// The destination-kind probe: finds a compound type's Go spelling for error text, by running the
// destination's own `Deserialize` far enough to see what it asks for.
// ---------------------------------------------------------------------------------------------

struct Probe<'p> {
    out: &'p RefCell<String>,
    /// When set, a `u8` destination succeeds with this byte instead of ending the probe.
    byte: Option<u8>,
    depth: usize,
}

fn stop() -> Error {
    Error::Message(String::new())
}

impl Probe<'_> {
    fn record(&self, name: &str) -> Error {
        self.out.borrow_mut().push_str(name);
        stop()
    }

    /// `Option<Vec<T>>` and `Option<HashMap<K, V>>` are this port's nil-able slice and map, not a
    /// Go pointer to one.
    fn drop_nilable_star(&self) {
        let mut out = self.out.borrow_mut();
        if out.ends_with('*') {
            out.pop();
        }
    }

    fn inner(&self) -> Probe<'_> {
        Probe {
            out: self.out,
            byte: None,
            depth: self.depth + 1,
        }
    }
}

macro_rules! probe_scalars {
    ($($method:ident => $name:literal),* $(,)?) => {
        $(fn $method<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
            Err(self.record($name))
        })*
    };
}

struct ProbeSeq<'p>(Probe<'p>);

impl<'de> SeqAccess<'de> for ProbeSeq<'_> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        seed.deserialize(self.0.inner()).map(Some)
    }
}

struct ProbeMap<'p>(Probe<'p>);

impl<'de> MapAccess<'de> for ProbeMap<'_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        seed.deserialize(KeyProbe(self.0.out)).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        self.0.out.borrow_mut().push(']');
        seed.deserialize(self.0.inner())
    }
}

struct KeyProbe<'p>(&'p RefCell<String>);

macro_rules! key_probe_ints {
    ($($method:ident => $name:literal, $visit:ident),* $(,)?) => {
        $(fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            self.0.borrow_mut().push_str($name);
            visitor.$visit(0)
        })*
    };
}

impl<'de> Deserializer<'de> for KeyProbe<'_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.0.borrow_mut().push_str("string");
        visitor.visit_str("")
    }

    key_probe_ints! {
        deserialize_i8 => "int8", visit_i8,
        deserialize_i16 => "int16", visit_i16,
        deserialize_i32 => "int32", visit_i32,
        deserialize_i64 => "int64", visit_i64,
        deserialize_u8 => "uint8", visit_u8,
        deserialize_u16 => "uint16", visit_u16,
        deserialize_u32 => "uint32", visit_u32,
        deserialize_u64 => "uint64", visit_u64,
    }

    serde::forward_to_deserialize_any! {
        bool i128 u128 f32 f64 char str string bytes byte_buf option unit unit_struct
        newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}

impl<'de> Deserializer<'de> for Probe<'_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(self.record("interface {}"))
    }

    probe_scalars! {
        deserialize_bool => "bool",
        deserialize_i8 => "int8",
        deserialize_i16 => "int16",
        deserialize_i32 => "int32",
        deserialize_i64 => "int64",
        deserialize_i128 => "int64",
        deserialize_u16 => "uint16",
        deserialize_u32 => "uint32",
        deserialize_u64 => "uint64",
        deserialize_u128 => "uint64",
        deserialize_f32 => "float32",
        deserialize_f64 => "float64",
        deserialize_char => "int32",
        deserialize_str => "string",
        deserialize_string => "string",
        deserialize_bytes => "[]uint8",
        deserialize_byte_buf => "[]uint8",
        deserialize_unit => "struct {}",
        deserialize_identifier => "string",
        deserialize_ignored_any => "interface {}",
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.byte {
            Some(b) => visitor.visit_u8(b),
            None => Err(self.record("uint8")),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.depth > 16 {
            return Err(stop());
        }
        self.out.borrow_mut().push('*');
        visitor.visit_some(self.inner())
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(self.record(name))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(self.record(match name {
            crate::json::RAW_MESSAGE_TOKEN => "json.RawMessage",
            crate::json::NUMBER_TOKEN => "json.Number",
            crate::json::TIME_TOKEN => "time.Time",
            other => other,
        }))
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.depth > 16 {
            return Err(stop());
        }
        self.drop_nilable_star();
        self.out.borrow_mut().push_str("[]");
        visitor.visit_seq(ProbeSeq(self.inner()))
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Error> {
        if self.depth > 16 {
            return Err(stop());
        }
        self.out.borrow_mut().push_str(&format!("[{len}]"));
        visitor.visit_seq(ProbeSeq(self.inner()))
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(self.record(name))
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.depth > 16 {
            return Err(stop());
        }
        self.drop_nilable_star();
        self.out.borrow_mut().push_str("map[");
        visitor.visit_map(ProbeMap(self.inner()))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(self.record(name))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(self.record(name))
    }
}

// ---------------------------------------------------------------------------------------------
// base64: `base64.StdEncoding.Decode`, with its `CorruptInputError` text.
// ---------------------------------------------------------------------------------------------

fn base64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub(crate) fn base64_decode_standard(src: &[u8]) -> Result<Vec<u8>, String> {
    let corrupt = |at: usize| format!("illegal base64 data at input byte {at}");
    let skip_newlines = |mut si: usize| {
        while si < src.len() && matches!(src[si], b'\n' | b'\r') {
            si += 1;
        }
        si
    };
    let mut out = Vec::with_capacity(src.len() / 4 * 3 + 3);
    let mut si = 0;
    while si < src.len() {
        let mut quantum = [0u32; 4];
        let mut j = 0;
        let mut dlen = 4;
        let mut trailing = None;
        while j < 4 {
            if si == src.len() {
                if j == 0 {
                    return Ok(out);
                }
                return Err(corrupt(si - j));
            }
            let c = src[si];
            si += 1;
            if let Some(v) = base64_value(c) {
                quantum[j] = v;
                j += 1;
                continue;
            }
            if matches!(c, b'\n' | b'\r') {
                continue;
            }
            if c != b'=' || j < 2 {
                return Err(corrupt(si - 1));
            }
            if j == 2 {
                si = skip_newlines(si);
                if si == src.len() {
                    return Err(corrupt(src.len()));
                }
                if src[si] != b'=' {
                    return Err(corrupt(si - 1));
                }
                si += 1;
            }
            si = skip_newlines(si);
            if si < src.len() {
                trailing = Some(si);
            }
            dlen = j;
            break;
        }
        let v = (quantum[0] << 18) | (quantum[1] << 12) | (quantum[2] << 6) | quantum[3];
        out.push((v >> 16) as u8);
        if dlen >= 3 {
            out.push((v >> 8) as u8);
        }
        if dlen == 4 {
            out.push(v as u8);
        }
        if let Some(at) = trailing {
            return Err(corrupt(at));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Field-name matching: exact first, then the first declared field that folds, as `cachedTypeFields`
// builds `byFoldedName`.
// ---------------------------------------------------------------------------------------------

fn match_field(fields: &[&'static str], key: &str) -> Option<usize> {
    fields.iter().position(|&f| f == key).or_else(|| {
        fields
            .iter()
            .position(|&f| crate::strings::equal_fold(f, key))
    })
}

fn parse_integer_literal(lit: &str) -> Option<i128> {
    if lit.bytes().any(|b| matches!(b, b'.' | b'e' | b'E')) {
        return None;
    }
    lit.parse::<i128>().ok()
}

/// The largest integer below which every integer has an exact `float64`.
const MAX_EXACT_F64: i128 = 1 << 53;

/// Saves `convertNumber`'s error for each number under `id` that overflows a `float64`.
fn scan_any_numbers(ctx: &Ctx<'_>, id: usize) {
    // Scalars and container heads occur in order; a container's second slot is only an end offset.
    let mut at = id;
    let end = ctx.node(id).next;
    while at < end {
        let n = ctx.node(at);
        at += if matches!(n.tag, Tag::Array | Tag::Object) {
            2
        } else {
            1
        };
        if n.tag == Tag::Number {
            let lit = ctx.tape.literal(n);
            let may_overflow = lit.len() > 300 || lit.bytes().any(|b| matches!(b, b'e' | b'E'));
            if may_overflow && lit.parse::<f64>().is_ok_and(f64::is_infinite) {
                ctx.save_type(n.start, format!("number {lit}"), "float64");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The Deserializer over one slot.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct De<'a> {
    ctx: &'a Ctx<'a>,
    ops: &'a [usize],
    /// Inside an `any` whose numbers [`scan_any_numbers`] already checked.
    scanned: bool,
    /// Under a flattened struct, where serde buffers values and needs exact integers.
    exact: bool,
    null_field: Option<NullField>,
}

impl<'a> De<'a> {
    fn new(ctx: &'a Ctx<'a>, ops: &'a [usize]) -> Self {
        Self {
            ctx,
            ops,
            scanned: false,
            exact: false,
            null_field: None,
        }
    }

    fn child<'x>(&self, ops: &'x [usize]) -> De<'x>
    where
        'a: 'x,
    {
        De {
            ctx: self.ctx,
            ops,
            scanned: self.scanned,
            exact: self.exact,
            null_field: None,
        }
    }

    /// Called by a kind that ignores `null`. A `null`-only field reached it as if present, which
    /// would replace a serde default with zero, so learn the kind and decode again.
    fn null_is_noop(&self) {
        if let Some(nf) = self.null_field {
            learn(nf.key, nf.field, |l| &mut l.null_noop);
            self.ctx.retry.set(true);
        }
    }

    /// One scalar destination: `null` skips, a mismatch is saved, the last match wins.
    fn scalar<T>(
        &self,
        type_name: &str,
        mut f: impl FnMut(Node) -> Result<T, String>,
    ) -> Option<T> {
        self.null_is_noop();
        let mut out = None;
        for &id in self.ops {
            let n = self.ctx.node(id);
            if n.tag == Tag::Null {
                continue;
            }
            match f(n) {
                Ok(v) => out = Some(v),
                Err(value) => self.ctx.save_type(n.start, value, type_name),
            }
        }
        out
    }

    fn int(&self, min: i128, max: i128, type_name: &str) -> i128 {
        let tape = self.ctx.tape;
        self.scalar(type_name, |n| {
            if n.tag != Tag::Number {
                return Err(kind_word(n.tag).to_string());
            }
            let lit = tape.literal(n);
            parse_integer_literal(lit)
                .filter(|&v| v >= min && v <= max && !(min == 0 && lit.starts_with('-')))
                .ok_or_else(|| format!("number {lit}"))
        })
        .unwrap_or(0)
    }

    fn is_empty_array(&self, id: usize) -> bool {
        let n = self.ctx.node(id);
        n.tag == Tag::Array && n.next == self.ctx.tape.first_child(id)
    }

    /// Runs a compound destination's decode, one level deeper.
    fn nested<R>(&self, f: impl FnOnce() -> Result<R, Error>) -> Result<R, Error> {
        let ctx = self.ctx;
        let depth = ctx.depth.get() + 1;
        // Release builds set the limit to usize::MAX, so this check is constant there.
        #[allow(clippy::absurd_extreme_comparisons)]
        if depth > MAX_MATERIALIZED_DEPTH {
            let pos = self.ops.first().map_or(0, |&id| ctx.node(id).start);
            ctx.abort(
                pos,
                Error::Message(format!(
                    "json: nesting deeper than {MAX_MATERIALIZED_DEPTH} levels is not decoded in a debug build"
                )),
            );
            ctx.poison.set(true);
            return Err(stop());
        }
        ctx.depth.set(depth);
        let out = grow(f);
        ctx.depth.set(depth - 1);
        out
    }

    /// The occurrences a resetting kind keeps. Whatever came before the last reset can no longer
    /// change the value but can still raise an error, which the check pass looks for. In that
    /// pass, nothing resets.
    fn after_reset(&self, is_reset: impl Fn(usize) -> bool) -> Cow<'a, [usize]> {
        let tag = |id: usize| self.ctx.node(id).tag;
        if self.ctx.check {
            return Cow::Owned(
                self.ops
                    .iter()
                    .copied()
                    .filter(|&id| tag(id) != Tag::Null)
                    .collect(),
            );
        }
        match self.ops.iter().rposition(|&id| is_reset(id)) {
            None => Cow::Borrowed(self.ops),
            Some(at) => {
                if self.ops[..=at]
                    .iter()
                    .any(|&id| tag(id) != Tag::Null && !self.is_empty_array(id))
                {
                    self.ctx.needs_check.set(true);
                }
                Cow::Borrowed(&self.ops[at + 1..])
            }
        }
    }
}

macro_rules! deserialize_int {
    ($($method:ident => $ty:ty, $visit:ident, $name:literal);* $(;)?) => {
        $(fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            let n = self.int(<$ty>::MIN as i128, <$ty>::MAX as i128, $name);
            visitor.$visit(n as $ty)
        })*
    };
}

impl<'de, 'a> Deserializer<'de> for De<'a> {
    type Error = Error;

    /// `any`.
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.nested(|| {
            let ctx = self.ctx;
            if !self.scanned {
                for &id in self.ops {
                    scan_any_numbers(ctx, id);
                }
            }
            let Some(&id) = self.ops.last() else {
                return visitor.visit_unit();
            };
            let n = ctx.node(id);
            let mut de = self.child(self.ops);
            de.scanned = true;
            match n.tag {
                Tag::Null => visitor.visit_unit(),
                Tag::Bool => visitor.visit_bool(ctx.tape.raw(n)[0] == b't'),
                Tag::Number => {
                    let lit = ctx.tape.literal(n);
                    if let Some(v) = parse_integer_literal(lit)
                        && lit != "-0"
                        && (self.exact || v.abs() <= MAX_EXACT_F64)
                    {
                        if let Ok(v) = i64::try_from(v) {
                            return visitor.visit_i64(v);
                        }
                        if let Ok(v) = u64::try_from(v) {
                            return visitor.visit_u64(v);
                        }
                    }
                    let f = lit.parse::<f64>().unwrap_or(f64::INFINITY);
                    visitor.visit_f64(if f.is_infinite() { 0.0 } else { f })
                }
                Tag::Str => match ctx.tape.string(n) {
                    Cow::Borrowed(s) => visitor.visit_str(s),
                    Cow::Owned(s) => visitor.visit_string(s),
                },
                Tag::Array => visitor.visit_seq(SeqA::direct(de, id)),
                Tag::Object => visitor.visit_map(MapA::new(de, vec![id], Vec::new())),
            }
        })
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let tape = self.ctx.tape;
        let b = self.scalar("bool", |n| match n.tag {
            Tag::Bool => Ok(tape.raw(n)[0] == b't'),
            tag => Err(kind_word(tag).to_string()),
        });
        visitor.visit_bool(b.unwrap_or(false))
    }

    deserialize_int! {
        deserialize_i8 => i8, visit_i8, "int8";
        deserialize_i16 => i16, visit_i16, "int16";
        deserialize_i32 => i32, visit_i32, "int32";
        deserialize_i64 => i64, visit_i64, "int64";
        deserialize_u8 => u8, visit_u8, "uint8";
        deserialize_u16 => u16, visit_u16, "uint16";
        deserialize_u32 => u32, visit_u32, "uint32";
        deserialize_u64 => u64, visit_u64, "uint64";
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_i128(self.int(i128::from(i64::MIN), i128::from(i64::MAX), "int64"))
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_u128(self.int(0, i128::from(u64::MAX), "uint64") as u128)
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let tape = self.ctx.tape;
        let f = self.scalar("float32", |n| {
            if n.tag != Tag::Number {
                return Err(kind_word(n.tag).to_string());
            }
            let lit = tape.literal(n);
            // Parsed at this width directly: going through f64 rounds twice.
            lit.parse::<f32>()
                .ok()
                .filter(|f| f.is_finite())
                .ok_or_else(|| format!("number {lit}"))
        });
        visitor.visit_f32(f.unwrap_or(0.0))
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let tape = self.ctx.tape;
        let f = self.scalar("float64", |n| {
            if n.tag != Tag::Number {
                return Err(kind_word(n.tag).to_string());
            }
            let lit = tape.literal(n);
            lit.parse::<f64>()
                .ok()
                .filter(|f| f.is_finite())
                .ok_or_else(|| format!("number {lit}"))
        });
        visitor.visit_f64(f.unwrap_or(0.0))
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let tape = self.ctx.tape;
        let c = self.scalar("int32", |n| {
            if n.tag == Tag::Str {
                let s = tape.string(n);
                let mut chars = s.chars();
                if let (Some(c), None) = (chars.next(), chars.next()) {
                    return Ok(c);
                }
            }
            Err(kind_word(n.tag).to_string())
        });
        visitor.visit_char(c.unwrap_or('\0'))
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let tape = self.ctx.tape;
        let s = self.scalar("string", |n| match n.tag {
            Tag::Str => Ok(n),
            tag => Err(kind_word(tag).to_string()),
        });
        match s.map(|n| tape.string(n)) {
            Some(Cow::Owned(s)) => visitor.visit_string(s),
            Some(Cow::Borrowed(s)) => visitor.visit_str(s),
            None => visitor.visit_str(""),
        }
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        grow(|| {
            let ctx = self.ctx;
            let tail = self.after_reset(|id| ctx.node(id).tag == Tag::Null);
            if tail.is_empty() {
                return visitor.visit_none();
            }
            visitor.visit_some(self.child(&tail))
        })
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        let ctx = self.ctx;
        match name {
            // `RawMessage.UnmarshalJSON` runs on every occurrence and keeps `null` as text.
            crate::json::RAW_MESSAGE_TOKEN => match self.ops.last() {
                Some(&id) => visitor.visit_byte_buf(ctx.tape.raw(ctx.node(id)).to_vec()),
                None => visitor.visit_unit(),
            },
            crate::json::SERDE_JSON_RAW_TOKEN => {
                let text = match self.ops.last() {
                    Some(&id) => String::from_utf8_lossy(ctx.tape.raw(ctx.node(id))).into_owned(),
                    None => "null".to_string(),
                };
                visitor.visit_map(RawValueMapAccess { text: Some(text) })
            }
            crate::json::NUMBER_TOKEN => {
                let got = self.scalar("json.Number", |n| match n.tag {
                    Tag::Number => Ok(ctx.tape.literal(n).to_string()),
                    Tag::Str => {
                        let s = ctx.tape.string(n);
                        if scanner::is_valid_number(s.as_bytes()) {
                            Ok(s.into_owned())
                        } else {
                            ctx.abort(
                                n.start,
                                Error::Message(format!(
                                    "json: invalid number literal, trying to unmarshal {} into Number",
                                    crate::strconv::quote_bytes(ctx.tape.raw(n))
                                )),
                            );
                            Ok(String::new())
                        }
                    }
                    tag => Err(kind_word(tag).to_string()),
                });
                visitor.visit_str(&got.unwrap_or_default())
            }
            crate::json::TIME_TOKEN => {
                self.null_is_noop();
                let mut last = None;
                for &id in self.ops {
                    let n = ctx.node(id);
                    let raw = ctx.tape.raw(n);
                    if raw == b"null" {
                        continue;
                    }
                    match crate::time::unmarshal_json_literal(raw) {
                        Ok(_) => last = Some(raw),
                        Err(e) => ctx.abort(n.start, Error::Message(e)),
                    }
                }
                match last {
                    Some(raw) => visitor.visit_byte_buf(raw.to_vec()),
                    None => visitor.visit_unit(),
                }
            }
            _ => grow(|| visitor.visit_newtype_struct(self)),
        }
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.nested(|| {
            let seq = SeqA::slice(self);
            visitor.visit_seq(seq)
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Error> {
        self.nested(|| {
            self.null_is_noop();
            visitor.visit_seq(SeqA::array(self, len))
        })
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.nested(|| {
            let ctx = self.ctx;
            let tail = self.after_reset(|id| ctx.node(id).tag == Tag::Null);
            let (objects, wrong): (Vec<usize>, Vec<usize>) = tail
                .iter()
                .copied()
                .filter(|&id| ctx.node(id).tag != Tag::Null)
                .partition(|&id| ctx.node(id).tag == Tag::Object);
            visitor.visit_map(MapA::new(self, objects, wrong))
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.nested(|| {
            self.null_is_noop();
            let key = struct_key::<V>(fields);
            let access = StructA::new(self, name, fields, key);
            match visitor.visit_map(access) {
                Err(Error::MissingField(f)) if fields.contains(&f) => {
                    let f = fields.iter().copied().find(|&x| x == f).unwrap_or(f);
                    learn(key, f, |l| &mut l.fill);
                    self.ctx.retry.set(true);
                    Err(stop())
                }
                other => other,
            }
        })
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(Error::Message(
            "silo_gocompat::json::decode does not support Rust enums: Go has no matching concept"
                .to_string(),
        ))
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }
}

// ---------------------------------------------------------------------------------------------
// `Box<RawValue>`'s one-entry-map protocol.
// ---------------------------------------------------------------------------------------------

struct RawValueMapAccess {
    text: Option<String>,
}

impl<'de> MapAccess<'de> for RawValueMapAccess {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        if self.text.is_none() {
            return Ok(None);
        }
        let token: serde::de::value::StrDeserializer<'_, Error> =
            serde::de::IntoDeserializer::into_deserializer(crate::json::SERDE_JSON_RAW_TOKEN);
        seed.deserialize(token).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let text = self
            .text
            .take()
            .expect("next_value_seed before next_key_seed");
        let de: serde::de::value::StringDeserializer<Error> =
            serde::de::IntoDeserializer::into_deserializer(text);
        seed.deserialize(de)
    }
}

// ---------------------------------------------------------------------------------------------
// Sequences.
// ---------------------------------------------------------------------------------------------

enum Elems {
    /// One array, so no element has more than one occurrence: child cursor and end.
    Direct(usize, usize),
    /// Per-index occurrences, and the next index to yield.
    Slots(Vec<Vec<usize>>, usize),
}

struct SeqA<'a> {
    de: De<'a>,
    elems: Elems,
    /// Occurrences that are not arrays, each an error unless a string meets a `[]byte`.
    wrong: Vec<usize>,
    strings: Vec<usize>,
    /// The decoded value of a final string occurrence, and the next byte to yield.
    bytes: Option<(Vec<u8>, usize)>,
    array_len: Option<usize>,
    probed: bool,
}

impl<'a> SeqA<'a> {
    fn with(de: De<'a>, elems: Elems) -> Self {
        Self {
            de,
            elems,
            wrong: Vec::new(),
            strings: Vec::new(),
            bytes: None,
            array_len: None,
            probed: true,
        }
    }

    fn direct(de: De<'a>, id: usize) -> Self {
        let elems = Elems::Direct(de.ctx.tape.first_child(id), de.ctx.node(id).next);
        Self::with(de, elems)
    }

    /// A Go slice.
    fn slice(de: De<'a>) -> Self {
        let ctx = de.ctx;
        let ends_in_string = de
            .ops
            .last()
            .is_some_and(|&id| ctx.node(id).tag == Tag::Str);
        let last = de.ops.len().wrapping_sub(1);
        let tail = de.after_reset(|id| {
            let n = ctx.node(id);
            n.tag == Tag::Null
                || de.is_empty_array(id)
                // A string replaces the slice. A final one is decoded below; an earlier one is
                // dead once a later array exists. It is a reset only for a `[]byte`, and any other
                // destination errors in the check pass.
                || (n.tag == Tag::Str && de.ops.get(last) != Some(&id))
        });
        let mut seq = Self::with(de, Elems::Slots(Vec::new(), 0));
        let mut slots: Vec<Vec<usize>> = Vec::new();
        let mut len = 0;
        let arrays = tail
            .iter()
            .filter(|&&id| ctx.node(id).tag == Tag::Array)
            .count();
        for &id in tail.iter() {
            match ctx.node(id).tag {
                Tag::Array if arrays == 1 && tail.len() == 1 => {
                    seq.elems = Elems::Direct(ctx.tape.first_child(id), ctx.node(id).next);
                    return seq;
                }
                Tag::Array => {
                    if ctx.check || !de.is_empty_array(id) {
                        len = 0;
                        for child in ctx.tape.children(id) {
                            if len == slots.len() {
                                slots.push(Vec::new());
                            }
                            slots[len].push(child);
                            len += 1;
                        }
                    }
                }
                Tag::Str => seq.strings.push(id),
                Tag::Null => {}
                _ => seq.wrong.push(id),
            }
        }
        if ctx.check {
            len = slots.len();
        } else if slots.len() > len {
            ctx.needs_check.set(true);
        }
        let slots_were_empty = slots.is_empty();
        slots.truncate(len);
        // `slots` in check mode runs every index, dead ones included.
        if !ctx.check && ends_in_string {
            let id = de.ops[last];
            if !slots_were_empty {
                ctx.needs_check.set(true);
            }
            seq.strings.clear();
            seq.strings.push(id);
            match base64_decode_standard(ctx.tape.string(ctx.node(id)).as_bytes()) {
                Ok(b) => seq.bytes = Some((b, 0)),
                Err(_) => seq.bytes = None,
            }
        }
        seq.elems = Elems::Slots(slots, 0);
        seq.probed = seq.wrong.is_empty() && seq.strings.is_empty();
        seq
    }

    /// A Go array: `null` is a no-op, a short array zeroes the rest, extras are skipped.
    fn array(de: De<'a>, n: usize) -> Self {
        let ctx = de.ctx;
        let mut seq = Self::with(de, Elems::Slots(Vec::new(), 0));
        seq.array_len = Some(n);
        let mut slots: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &id in de.ops {
            match ctx.node(id).tag {
                Tag::Null => {}
                Tag::Array => {
                    let mut i = 0;
                    for child in ctx.tape.children(id).take(n) {
                        slots[i].push(child);
                        i += 1;
                    }
                    if !ctx.check {
                        for slot in &mut slots[i..] {
                            if !slot.is_empty() {
                                ctx.needs_check.set(true);
                                slot.clear();
                            }
                        }
                    }
                }
                _ => seq.wrong.push(id),
            }
        }
        seq.elems = Elems::Slots(slots, 0);
        seq.probed = seq.wrong.is_empty();
        seq
    }

    /// Runs the first element's seed against a [`Probe`] to learn the Go type, and reports every
    /// non-array occurrence against it. Returns the seed's value when it was a `[]byte` element.
    fn probe<'de, T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, Error> {
        self.probed = true;
        let ctx = self.de.ctx;
        let out = RefCell::new(String::new());
        let first = match (&self.array_len, &self.bytes) {
            (Some(_), _) => None,
            (None, Some((b, _))) => Some(b.first().copied().unwrap_or(0)),
            (None, None) => Some(0),
        };
        let probed = seed.deserialize(Probe {
            out: &out,
            byte: first,
            depth: 0,
        });
        let type_name = match (self.array_len, probed.is_ok()) {
            (_, true) => "[]uint8".to_string(),
            (Some(n), false) => format!("[{n}]{}", out.borrow()),
            (None, false) => format!("[]{}", out.borrow()),
        };
        for &id in &self.wrong {
            let n = ctx.node(id);
            ctx.save_type(n.start, kind_word(n.tag), type_name.clone());
        }
        let Ok(value) = probed else {
            for &id in &self.strings {
                ctx.save_type(ctx.node(id).start, "string", type_name.clone());
            }
            self.elems = Elems::Slots(Vec::new(), 0);
            self.bytes = None;
            if self.array_len.is_some() {
                // A Go array's visitor rejects a short sequence, so unwind to the saved error.
                ctx.poison.set(true);
                return Err(stop());
            }
            return Ok(None);
        };
        for &id in &self.strings {
            let n = ctx.node(id);
            if let Err(e) = base64_decode_standard(ctx.tape.string(n).as_bytes()) {
                ctx.save(n.start, Error::Message(e));
            }
        }
        if let Some((b, next)) = &mut self.bytes {
            if b.is_empty() {
                return Ok(None);
            }
            *next = 1;
        }
        Ok(Some(value))
    }
}

impl<'de> SeqAccess<'de> for SeqA<'_> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if !self.probed {
            return self.probe(seed);
        }
        if let Some((b, next)) = &mut self.bytes {
            let Some(&byte) = b.get(*next) else {
                return Ok(None);
            };
            *next += 1;
            let out = RefCell::new(String::new());
            return seed
                .deserialize(Probe {
                    out: &out,
                    byte: Some(byte),
                    depth: 0,
                })
                .map(Some);
        }
        match &mut self.elems {
            Elems::Direct(at, end) => {
                if *at >= *end {
                    return Ok(None);
                }
                let id = *at;
                *at = self.de.ctx.node(id).next;
                seed.deserialize(self.de.child(std::slice::from_ref(&id)))
                    .map(Some)
            }
            Elems::Slots(slots, next) => {
                let Some(slot) = slots.get_mut(*next) else {
                    return Ok(None);
                };
                *next += 1;
                let ops = std::mem::take(slot);
                seed.deserialize(self.de.child(&ops)).map(Some)
            }
        }
    }

    fn size_hint(&self) -> Option<usize> {
        None
    }
}

// ---------------------------------------------------------------------------------------------
// Maps.
// ---------------------------------------------------------------------------------------------

struct KeyDe<'k, 'a> {
    key: &'k str,
    /// Where `decodeState.object` would save a key error: after decoding the entry's value.
    pos: usize,
    ctx: &'k Ctx<'a>,
    is_field: &'k Cell<bool>,
}

macro_rules! key_int {
    ($($method:ident => $ty:ty, $visit:ident, $name:literal, $signed:literal);* $(;)?) => {
        $(fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            // `strconv.ParseUint` has no sign; Rust's parser accepts a leading `+`.
            let parsed = if !$signed && self.key.starts_with('+') {
                None
            } else {
                self.key.parse::<$ty>().ok()
            };
            match parsed {
                Some(n) => visitor.$visit(n),
                None => {
                    self.ctx.save_type(self.pos, format!("number {}", self.key), $name);
                    visitor.$visit(0)
                }
            }
        })*
    };
}

impl<'de> Deserializer<'de> for KeyDe<'_, '_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_str(self.key)
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.is_field.set(true);
        visitor.visit_str(self.key)
    }

    key_int! {
        deserialize_i8 => i8, visit_i8, "int8", true;
        deserialize_i16 => i16, visit_i16, "int16", true;
        deserialize_i32 => i32, visit_i32, "int32", true;
        deserialize_i64 => i64, visit_i64, "int64", true;
        deserialize_u8 => u8, visit_u8, "uint8", false;
        deserialize_u16 => u16, visit_u16, "uint16", false;
        deserialize_u32 => u32, visit_u32, "uint32", false;
        deserialize_u64 => u64, visit_u64, "uint64", false;
    }

    serde::forward_to_deserialize_any! {
        bool i128 u128 f32 f64 char str string bytes byte_buf option unit unit_struct
        newtype_struct seq tuple tuple_struct map struct enum ignored_any
    }
}

struct MapA<'a> {
    de: De<'a>,
    /// Object nodes still to walk, in reverse.
    objects: Vec<usize>,
    at: usize,
    end: usize,
    wrong: Vec<usize>,
    value: Option<usize>,
    /// Set once a key asks for an identifier, which means a derived struct with a flattened field
    /// rather than a map: each key's occurrences then go to the one field together.
    groups: Option<Vec<(usize, Vec<usize>)>>,
    group_value: Option<Vec<usize>>,
    is_field: Cell<bool>,
}

impl<'a> MapA<'a> {
    fn new(de: De<'a>, mut objects: Vec<usize>, wrong: Vec<usize>) -> Self {
        objects.reverse();
        Self {
            de,
            objects,
            at: 0,
            end: 0,
            wrong,
            value: None,
            groups: None,
            group_value: None,
            is_field: Cell::new(false),
        }
    }

    fn next_pair(&mut self) -> Option<(usize, usize)> {
        let ctx = self.de.ctx;
        while self.at >= self.end {
            let id = self.objects.pop()?;
            self.at = ctx.tape.first_child(id);
            self.end = ctx.node(id).next;
        }
        let key = self.at;
        let value = ctx.node(key).next;
        self.at = ctx.node(value).next;
        Some((key, value))
    }

    /// Switches to grouped keys after the first key turned out to be a struct field.
    fn group(&mut self, first_key: usize, first_value: usize) {
        let ctx = self.de.ctx;
        let mut index: HashMap<Cow<'_, str>, usize> = HashMap::new();
        let mut groups: Vec<(usize, Vec<usize>)> = vec![(first_key, vec![first_value])];
        index.insert(ctx.tape.string(ctx.node(first_key)), 0);
        while let Some((k, v)) = self.next_pair() {
            let at = *index
                .entry(ctx.tape.string(ctx.node(k)))
                .or_insert_with(|| {
                    groups.push((k, Vec::new()));
                    groups.len() - 1
                });
            groups[at].1.push(v);
        }
        self.group_value = Some(std::mem::take(&mut groups[0].1));
        groups.remove(0);
        groups.reverse();
        self.groups = Some(groups);
        self.de.exact = true;
        if ctx.strict {
            ctx.save(
                ctx.node(first_key).start,
                Error::Message(
                    "json: DisallowUnknownFields cannot be enforced on a #[serde(flatten)] type"
                        .to_string(),
                ),
            );
        }
    }

    fn report_wrong(&mut self, type_name: &str) {
        let ctx = self.de.ctx;
        for id in self.wrong.drain(..) {
            let n = ctx.node(id);
            ctx.save_type(n.start, kind_word(n.tag), type_name);
        }
    }
}

impl<'de> MapAccess<'de> for MapA<'_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        let ctx = self.de.ctx;
        if !self.wrong.is_empty() {
            // Only a visitor using separate key and value calls gets here, such as
            // `serde_json::Map`, which has one possible Go spelling.
            self.report_wrong("map[string]interface {}");
        }
        if let Some(groups) = &mut self.groups {
            let Some((k, vals)) = groups.pop() else {
                return Ok(None);
            };
            self.group_value = Some(vals);
            let key = ctx.tape.string(ctx.node(k));
            return seed
                .deserialize(KeyDe {
                    key: &key,
                    pos: ctx.node(k).end,
                    ctx,
                    is_field: &self.is_field,
                })
                .map(Some);
        }
        let Some((k, v)) = self.next_pair() else {
            return Ok(None);
        };
        self.value = Some(v);
        let key = ctx.tape.string(ctx.node(k));
        let out = seed.deserialize(KeyDe {
            key: &key,
            pos: ctx.node(v).end,
            ctx,
            is_field: &self.is_field,
        })?;
        if self.is_field.get() {
            self.value = None;
            self.group(k, v);
        }
        Ok(Some(out))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        if let Some(ops) = self.group_value.take() {
            return seed.deserialize(self.de.child(&ops));
        }
        let id = self
            .value
            .take()
            .expect("next_value_seed before next_key_seed");
        seed.deserialize(self.de.child(std::slice::from_ref(&id)))
    }

    /// The path `HashMap` and `BTreeMap` take, which can name the Go type of a mismatch and carry
    /// on with an empty map.
    fn next_entry_seed<K: DeserializeSeed<'de>, V: DeserializeSeed<'de>>(
        &mut self,
        kseed: K,
        vseed: V,
    ) -> Result<Option<(K::Value, V::Value)>, Error> {
        if !self.wrong.is_empty() {
            let out = RefCell::new("map[".to_string());
            let key = kseed.deserialize(KeyProbe(&out));
            out.borrow_mut().push(']');
            let value = vseed.deserialize(Probe {
                out: &out,
                byte: None,
                depth: 0,
            });
            let type_name = out.borrow().clone();
            self.report_wrong(&type_name);
            // Any object occurrence does not matter now: the decode will return that error.
            self.objects.clear();
            self.at = self.end;
            return match (key, value) {
                (Ok(k), Ok(v)) => Ok(Some((k, v))),
                _ => Ok(None),
            };
        }
        match self.next_key_seed(kseed)? {
            Some(k) => Ok(Some((k, self.next_value_seed(vseed)?))),
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Structs.
// ---------------------------------------------------------------------------------------------

struct Emit {
    field: &'static str,
    ops: Vec<usize>,
    null_only: bool,
}

struct StructA<'a> {
    de: De<'a>,
    emits: std::vec::IntoIter<Emit>,
    pending: Option<Emit>,
    name: &'static str,
    key: StructKey,
}

impl<'a> StructA<'a> {
    /// `decodeState.object`'s field dispatch, over every occurrence that reached this struct.
    fn new(
        de: De<'a>,
        name: &'static str,
        fields: &'static [&'static str],
        key: StructKey,
    ) -> Self {
        let ctx = de.ctx;
        let mut slot_of = vec![usize::MAX; fields.len()];
        let mut slots: Vec<Emit> = Vec::new();
        for &id in de.ops {
            let n = ctx.node(id);
            match n.tag {
                Tag::Null => {}
                Tag::Object => {
                    let mut children = ctx.tape.children(id);
                    while let (Some(k), Some(v)) = (children.next(), children.next()) {
                        let key_node = ctx.node(k);
                        let text = ctx.tape.string(key_node);
                        match match_field(fields, &text) {
                            Some(f) => {
                                if slot_of[f] == usize::MAX {
                                    slot_of[f] = slots.len();
                                    slots.push(Emit {
                                        field: fields[f],
                                        ops: Vec::new(),
                                        null_only: true,
                                    });
                                }
                                let slot = &mut slots[slot_of[f]];
                                slot.ops.push(v);
                                slot.null_only &= ctx.node(v).tag == Tag::Null;
                            }
                            None if ctx.strict => {
                                ctx.save(key_node.start, Error::UnknownField(text.into_owned()));
                            }
                            None => {}
                        }
                    }
                }
                tag => ctx.save_type(n.start, kind_word(tag), name),
            }
        }
        let needs_table = slots.len() < fields.len() || slots.iter().any(|s| s.null_only);
        if needs_table {
            let table = learned().read().unwrap_or_else(|e| e.into_inner());
            if let Some(known) = table.get(&key) {
                slots.retain(|s| !(s.null_only && known.null_noop.contains(&s.field)));
                for &f in &known.fill {
                    if !slots.iter().any(|s| s.field == f) {
                        slots.push(Emit {
                            field: f,
                            ops: Vec::new(),
                            null_only: false,
                        });
                    }
                }
            }
        }
        Self {
            de,
            emits: slots.into_iter(),
            pending: None,
            name,
            key,
        }
    }
}

impl<'de> MapAccess<'de> for StructA<'_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        let Some(emit) = self.emits.next() else {
            return Ok(None);
        };
        let field = emit.field;
        self.pending = Some(emit);
        let de: serde::de::value::StrDeserializer<'_, Error> =
            serde::de::IntoDeserializer::into_deserializer(field);
        seed.deserialize(de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let emit = self
            .pending
            .take()
            .expect("next_value_seed before next_key_seed");
        let ctx = self.de.ctx;
        let saved_struct = ctx.struct_name.replace(self.name);
        ctx.fields.borrow_mut().push(emit.field);
        let mut de = self.de.child(&emit.ops);
        if emit.null_only {
            de.null_field = Some(NullField {
                key: self.key,
                field: emit.field,
            });
        }
        let result = if emit.ops.is_empty() && !zero_is_safe(std::any::type_name::<V>()) {
            seed.deserialize(AbsentDe {
                de,
                field: emit.field,
                type_name: std::any::type_name::<V>(),
            })
        } else {
            seed.deserialize(de)
        };
        ctx.fields.borrow_mut().pop();
        ctx.struct_name.set(saved_struct);
        result
    }
}

// ---------------------------------------------------------------------------------------------
// Absent fields.
// ---------------------------------------------------------------------------------------------

/// Whether decoding "nothing" into this seed's type gives Go's zero value. Go leaves an absent field
/// untouched and never runs its `UnmarshalJSON`. Serde gives no way to produce a value without running
/// `Deserialize` except `#[serde(default)]`, so a field without one is safe only for these types,
/// whose decode this module controls. `Option`, `Vec`, and maps construct no inner value here.
fn zero_is_safe(seed: &str) -> bool {
    const SAFE_EXACT: &[&str] = &[
        "bool",
        "char",
        "f32",
        "f64",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "alloc::string::String",
        "serde_json::value::Value",
        "silo_gocompat::json::RawMessage",
        "silo_gocompat::json::Number",
        "silo_gocompat::json::Bytes",
        "silo_gocompat::time::GoTime",
        "serde::de::ignored_any::IgnoredAny",
    ];
    const SAFE_GENERIC: &[&str] = &[
        "core::option::Option<",
        "alloc::vec::Vec<",
        "std::collections::hash::map::HashMap<",
        "std::collections::hash::set::HashSet<",
        "alloc::collections::btree::map::BTreeMap<",
        "alloc::collections::btree::set::BTreeSet<",
    ];
    let name = seed
        .strip_prefix("core::marker::PhantomData<")
        .and_then(|inner| inner.strip_suffix('>'))
        .unwrap_or(seed);
    SAFE_EXACT.contains(&name) || SAFE_GENERIC.iter().any(|prefix| name.starts_with(prefix))
}

/// The deserializer an absent field of any other type sees. A derived struct or Go array recurses,
/// and its own fields come back through this check. Anything else is a hand-written `Deserialize` or a
/// newtype, which would read an absent field as `null` or fail its own validation, so the decode stops
/// and names the fix before that code sees a value.
struct AbsentDe<'a> {
    de: De<'a>,
    field: &'static str,
    type_name: &'static str,
}

impl<'de> Deserializer<'de> for AbsentDe<'_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(Error::Message(format!(
            "json: field `{}` of type {} is absent and needs #[serde(default)]: Go leaves it at its \
             zero value without running its decoder",
            self.field, self.type_name
        )))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.de.deserialize_struct(name, fields, visitor)
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Error> {
        self.de.deserialize_tuple(len, visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.de.deserialize_tuple_struct(name, len, visitor)
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf option
        newtype_struct seq map enum identifier ignored_any
    }
}

// ---------------------------------------------------------------------------------------------
// Running a decode.
// ---------------------------------------------------------------------------------------------

/// Bounds the learning loop against a hand-written visitor that reports a field missing no matter
/// what it receives. Each pass otherwise learns one fact about a finite set of fields.
const MAX_PASSES: usize = 4096;

/// A discarded value may be nested as deep as the document, and its drop glue recurses.
fn drop_deep<T>(value: T) {
    stacker::maybe_grow(8 * 1024 * 1024, 64 * 1024 * 1024, move || drop(value));
}

/// `decodeState.unmarshal`, for bytes the scanner already accepted as one value.
fn decode_value<T: DeserializeOwned>(data: &[u8], strict: bool) -> Result<T, Error> {
    if data.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::Message(format!(
            "json: a document over {MAX_DOCUMENT_BYTES} bytes is not supported"
        )));
    }
    let tape = Tape::build(data);
    let root = [0usize];
    let mut passes = 0;
    loop {
        passes += 1;
        let learning = passes < MAX_PASSES;
        let ctx = Ctx::new(&tape, strict, false);
        let result = T::deserialize(De::new(&ctx, &root));
        if ctx.retry.get() && learning {
            drop_deep(result);
            continue;
        }
        if ctx.needs_check.get() {
            let check = Ctx::new(&tape, strict, true);
            let checked = T::deserialize(De::new(&check, &root));
            if check.retry.get() && learning {
                drop_deep(checked);
                drop_deep(result);
                continue;
            }
            let foreign = !check.poison.get() && checked.is_err();
            match checked {
                Err(e) if foreign && check.aborted.borrow().is_none() => {
                    drop_deep(result);
                    return Err(e);
                }
                other => drop_deep(other),
            }
            if let Some((pos, e)) = check.saved.into_inner() {
                ctx.save(pos, e);
            }
            if let Some((pos, e)) = check.aborted.into_inner() {
                ctx.abort(pos, e);
            }
        }
        if let Some((_, e)) = ctx.aborted.into_inner() {
            drop_deep(result);
            return Err(e);
        }
        let saved = ctx.saved.into_inner();
        return match (result, saved) {
            (Ok(value), None) => Ok(value),
            (Ok(value), Some((_, e))) => {
                drop_deep(value);
                Err(e)
            }
            (Err(_), Some((_, e))) if ctx.poison.get() => Err(e),
            (Err(e), _) => Err(e),
        };
    }
}

// ---------------------------------------------------------------------------------------------
// Public entry points.
// ---------------------------------------------------------------------------------------------

/// `json.Unmarshal`: exactly one document, or a syntax error.
pub fn unmarshal<T: DeserializeOwned>(data: &[u8]) -> Result<T, Error> {
    scanner::check_valid(data).map_err(|e| Error::Syntax(e.to_string()))?;
    decode_value(data, false)
}

/// `json.Decoder`'s settings. [`Decoder::decode`] is `json.NewDecoder(r).Decode(&v)` for one value;
/// [`Decoder::stream`] keeps reading values from a reader.
#[derive(Default, Clone, Copy)]
pub struct Decoder {
    disallow_unknown_fields: bool,
}

impl Decoder {
    /// A decoder with Go's default settings (unknown fields ignored).
    pub fn new() -> Self {
        Self::default()
    }

    /// `Decoder.DisallowUnknownFields`.
    #[must_use]
    pub fn disallow_unknown_fields(mut self) -> Self {
        self.disallow_unknown_fields = true;
        self
    }

    /// Decodes the first JSON value in `data`, as one `Decode` call would. Whatever follows that
    /// value is left unread, and is not an error even if it is not JSON. Empty or space-only input
    /// is [`Error::Eof`], and input ending inside a value is [`Error::UnexpectedEof`].
    pub fn decode<T: DeserializeOwned>(&self, data: &[u8]) -> Result<T, Error> {
        let mut scan = ValueScan::new();
        let n = match scan.run(data) {
            Ok(Some(n)) => n,
            Ok(None) => {
                if scan.eof() {
                    data.len()
                } else if data.iter().any(|c| !scanner::is_space(*c)) {
                    return Err(Error::UnexpectedEof);
                } else {
                    return Err(Error::Eof);
                }
            }
            Err(e) => return Err(Error::Syntax(e.to_string())),
        };
        decode_value(&data[..n], self.disallow_unknown_fields)
    }

    /// `json.NewDecoder(r)`, with these settings.
    pub fn stream<R: Read>(self, reader: R) -> Stream<R> {
        Stream {
            reader,
            strict: self.disallow_unknown_fields,
            buf: Vec::new(),
            scanp: 0,
            consumed: 0,
            err: None,
        }
    }
}

/// `json.Decoder` over a reader: each [`decode`][Stream::decode] reads one value and leaves the rest
/// buffered. A syntax or read error sticks, and a type error does not, as in Go.
pub struct Stream<R> {
    reader: R,
    strict: bool,
    buf: Vec<u8>,
    scanp: usize,
    consumed: u64,
    err: Option<Error>,
}

impl<R: Read> Stream<R> {
    /// `Decoder.Decode`.
    pub fn decode<T: DeserializeOwned>(&mut self) -> Result<T, Error> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        let n = self.read_value()?;
        let result = decode_value(&self.buf[self.scanp..self.scanp + n], self.strict);
        self.scanp += n;
        result
    }

    /// `Decoder.Buffered`: bytes read from the reader but not yet decoded.
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.scanp..]
    }

    /// `Decoder.InputOffset`.
    pub fn input_offset(&self) -> u64 {
        self.consumed + self.scanp as u64
    }

    /// `Decoder.More`.
    pub fn more(&mut self) -> bool {
        loop {
            if let Some(&c) = self.buf[self.scanp..]
                .iter()
                .find(|c| !scanner::is_space(**c))
            {
                return c != b']' && c != b'}';
            }
            self.scanp = self.buf.len();
            match self.refill() {
                Ok(0) | Err(_) => return false,
                Ok(_) => {}
            }
        }
    }

    /// `Decoder.readValue`: returns the length of the next value at `scanp`.
    fn read_value(&mut self) -> Result<usize, Error> {
        let mut scan = ValueScan::new();
        let mut scanned = 0;
        loop {
            match scan.run(&self.buf[self.scanp + scanned..]) {
                Ok(Some(n)) => return Ok(scanned + n),
                Ok(None) => scanned = self.buf.len() - self.scanp,
                Err(e) => {
                    let err = Error::Syntax(e.to_string());
                    self.err = Some(err.clone());
                    return Err(err);
                }
            }
            match self.refill() {
                Ok(0) => {
                    if scan.eof() {
                        return Ok(scanned);
                    }
                    let err = if self.buf[self.scanp..]
                        .iter()
                        .any(|c| !scanner::is_space(*c))
                    {
                        Error::UnexpectedEof
                    } else {
                        Error::Eof
                    };
                    self.err = Some(err.clone());
                    return Err(err);
                }
                Ok(_) => {}
                Err(err) => {
                    self.err = Some(err.clone());
                    return Err(err);
                }
            }
        }
    }

    /// `Decoder.refill`. Returns the number of bytes read, 0 at the end of input.
    fn refill(&mut self) -> Result<usize, Error> {
        if self.scanp > 0 {
            self.consumed += self.scanp as u64;
            self.buf.drain(..self.scanp);
            self.scanp = 0;
        }
        const MIN_READ: usize = 512;
        let len = self.buf.len();
        self.buf.resize(len + MIN_READ.max(len), 0);
        loop {
            match self.reader.read(&mut self.buf[len..]) {
                Ok(n) => {
                    self.buf.truncate(len + n);
                    return Ok(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.buf.truncate(len);
                    return Err(Error::Io(e.to_string()));
                }
            }
        }
    }
}
