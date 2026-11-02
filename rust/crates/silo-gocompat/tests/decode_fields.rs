//! Absent fields and the per-type learned table. Each behavior here was a real divergence from a Go
//! decode of the matching struct: Go never runs a decoder for an absent field, and the result of a
//! decode cannot depend on what was decoded earlier.

use serde::{Deserialize, Deserializer};
use silo_gocompat::json::{Decoder, Number, RawMessage, VALUE_STACK_BYTES, unmarshal};

/// A presence-tracking wrapper, shaped like `apiv2.Patch`.
#[derive(Debug, Default, PartialEq)]
struct Patch {
    present: bool,
    value: Option<String>,
}

impl<'de> Deserialize<'de> for Patch {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Patch;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a patch value")
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Patch, D::Error> {
                Ok(Patch {
                    present: true,
                    value: Option::deserialize(d)?,
                })
            }
        }
        d.deserialize_newtype_struct("Patch", V)
    }
}

/// A validating decoder, shaped like `apiv2.Instant`.
#[derive(Debug, Default, PartialEq)]
struct Validated(String);

impl<'de> Deserialize<'de> for Validated {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        if text.is_empty() {
            return Err(serde::de::Error::custom("empty"));
        }
        Ok(Validated(text))
    }
}

#[test]
fn an_absent_custom_field_with_a_default_never_runs_its_decoder() {
    #[derive(Debug, Deserialize)]
    struct Body {
        #[serde(default)]
        patch: Patch,
        #[serde(default)]
        when: Validated,
    }
    let body: Body = unmarshal(b"{}").unwrap();
    assert_eq!(body.patch, Patch::default());
    assert_eq!(body.when, Validated::default());

    let body: Body = unmarshal(br#"{"patch":null,"when":"x"}"#).unwrap();
    assert_eq!(
        body.patch,
        Patch {
            present: true,
            value: None
        }
    );
    assert_eq!(body.when, Validated("x".to_owned()));
}

#[test]
fn an_absent_custom_field_without_a_default_is_an_error_not_a_wrong_value() {
    #[derive(Debug, Deserialize)]
    struct NoDefault {
        #[allow(dead_code)]
        patch: Patch,
    }
    #[derive(Debug, Deserialize)]
    struct Nested {
        #[allow(dead_code)]
        inner: Inner,
    }
    #[derive(Debug, Deserialize)]
    struct Inner {
        #[allow(dead_code)]
        when: Validated,
    }
    #[derive(Debug, Deserialize)]
    struct InArray {
        #[allow(dead_code)]
        two: [Validated; 2],
    }
    let message = unmarshal::<NoDefault>(b"{}").unwrap_err().to_string();
    assert!(message.contains("`patch`"), "{message}");
    assert!(message.contains("serde(default)"), "{message}");
    assert!(unmarshal::<NoDefault>(br#"{"patch":"x"}"#).is_ok());
    assert!(unmarshal::<Nested>(br#"{"inner":{}}"#).is_err());
    assert!(unmarshal::<InArray>(b"{}").is_err());
}

#[test]
fn absent_builtin_kinds_still_need_no_default() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Inner {
        n: i32,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct All {
        b: bool,
        i: i64,
        f: f64,
        s: String,
        v: Vec<i32>,
        o: Option<Patch>,
        m: std::collections::HashMap<String, Patch>,
        a: [i32; 2],
        any: serde_json::Value,
        raw: RawMessage,
        num: Number,
        inner: Inner,
    }
    let all: All = unmarshal(b"{}").unwrap();
    assert_eq!(
        all,
        All {
            b: false,
            i: 0,
            f: 0.0,
            s: String::new(),
            v: Vec::new(),
            o: None,
            m: Default::default(),
            a: [0, 0],
            any: serde_json::Value::Null,
            raw: RawMessage::nil(),
            num: Number::default(),
            inner: Inner { n: 0 },
        }
    );
}

fn fifty() -> i32 {
    50
}

/// Two function-local structs sharing a name and a field list.
#[test]
fn same_named_local_structs_do_not_share_what_was_learned() {
    fn with_default() -> i32 {
        #[derive(Deserialize)]
        struct Body {
            #[serde(default = "fifty")]
            limit: i32,
            #[allow(dead_code)]
            q: String,
        }
        unmarshal::<Body>(br#"{"q":"x"}"#).unwrap().limit
    }
    fn without_default() -> i32 {
        #[derive(Deserialize)]
        struct Body {
            limit: i32,
            #[allow(dead_code)]
            q: String,
        }
        unmarshal::<Body>(br#"{"q":"x"}"#).unwrap().limit
    }
    for _ in 0..2 {
        assert_eq!(without_default(), 0);
        assert_eq!(with_default(), 50);
    }
}

mod a {
    #[derive(serde::Deserialize)]
    pub struct Req {
        #[serde(default = "super::fifty")]
        pub limit: i32,
        pub q: String,
    }
}

mod b {
    #[derive(serde::Deserialize)]
    pub struct Req {
        pub limit: i32,
        pub q: String,
    }
}

#[test]
fn same_named_structs_in_other_modules_do_not_share_what_was_learned() {
    let b: b::Req = unmarshal(br#"{"q":"x"}"#).unwrap();
    assert_eq!((b.limit, b.q.as_str()), (0, "x"));
    let a: a::Req = unmarshal(br#"{"q":"x"}"#).unwrap();
    assert_eq!((a.limit, a.q.as_str()), (50, "x"));
}

#[derive(Deserialize)]
struct W<T> {
    v: T,
}

/// Every instance of a generic struct shares its name and field list, and `null` means different
/// things to its instances. Order must not matter.
#[test]
fn generic_struct_instances_do_not_share_what_was_learned() {
    #[derive(Deserialize)]
    struct DefaultedInt {
        #[serde(default = "fifty")]
        v: i32,
    }
    #[derive(Deserialize)]
    struct DefaultedOption {
        #[serde(default = "five")]
        v: Option<i32>,
    }
    fn five() -> Option<i32> {
        Some(5)
    }
    assert_eq!(unmarshal::<DefaultedInt>(br#"{"v":null}"#).unwrap().v, 50);
    assert_eq!(
        unmarshal::<DefaultedOption>(br#"{"v":null}"#).unwrap().v,
        None
    );
    assert_eq!(unmarshal::<W<i32>>(br#"{"v":null}"#).unwrap().v, 0);
    assert_eq!(
        unmarshal::<W<Option<i32>>>(br#"{"v":null}"#).unwrap().v,
        None
    );
    assert_eq!(unmarshal::<W<String>>(b"{}").unwrap().v, "");
    assert_eq!(unmarshal::<W<Option<i32>>>(b"{}").unwrap().v, None);
}

#[test]
fn the_tape_handles_empty_containers_and_nesting() {
    let v: serde_json::Value =
        unmarshal(br#" {"a":[],"b":{},"c":[[],{"d":[1,{"e":null}]}],"f":"x"} "#).unwrap();
    assert_eq!(v["c"][1]["d"][1]["e"], serde_json::Value::Null);
    assert_eq!(v["f"], "x");
    let raw: std::collections::BTreeMap<String, RawMessage> =
        unmarshal(br#"{"a":[1, 2],"b":{ "c" : [] }}"#).unwrap();
    assert_eq!(raw["a"].as_bytes().unwrap(), b"[1, 2]");
    assert_eq!(raw["b"].as_bytes().unwrap(), br#"{ "c" : [] }"#);
    let e = Decoder::new()
        .decode::<Vec<i32>>(br#"[1,"x"]"#)
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "json: cannot unmarshal string into Go value of type int32"
    );
}

/// What a caller does with a decoded value at Go's limit, on the stack the server's runtime gives
/// every worker. A debug build stops short of 1,000 levels; run with `--release` to reach 10,000.
#[test]
fn a_value_at_the_depth_limit_is_safe_on_a_runtime_thread() {
    let depth = if cfg!(debug_assertions) { 999 } else { 10_000 };
    let documents = [
        format!("{}1{}", "[".repeat(depth), "]".repeat(depth)),
        format!("{}1{}", "{\"a\":".repeat(depth), "}".repeat(depth)),
    ];
    for document in documents {
        std::thread::Builder::new()
            .stack_size(VALUE_STACK_BYTES)
            .spawn(move || {
                let value: serde_json::Value = unmarshal(document.as_bytes()).unwrap();
                let cloned = value.clone();
                let through: serde_json::Value = serde_json::to_value(&cloned).unwrap();
                #[allow(clippy::disallowed_methods)]
                let back: serde_json::Value = serde_json::from_value(through).unwrap();
                assert!(back == value);
                drop(back);
                drop(cloned);
                drop(value);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
