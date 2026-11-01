//! Differential tests against vectors the real Go standard library generated.
//!
//! The generator is `rust/conformance/vectors/generators/gocompat`. Every test also asserts a
//! minimum case count, so a vector file that shrinks by accident fails instead of passing quietly.

#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use silo_gocompat::json::{
    self, ByteString, Bytes, Decoder, Encoder, Number, RawMessage, omit_empty, omit_nil_or_empty,
};
use silo_gocompat::regexp::{GoRegex, quote_meta};
use silo_gocompat::strings::decode_runes;
use silo_gocompat::time::{Duration, GoTime, parse_bytes, parse_duration};
use silo_gocompat::{filepath, path, strconv, strings, unicode, url};

const MIN_CASES: usize = 200;

fn vector(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../conformance/vectors/gocompat/{name}.json"));
    let text = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let value: Value = serde_json::from_slice(&text).expect("vector is valid JSON");
    assert_eq!(
        value["go_version"].as_str(),
        Some(unicode::GO_VERSION),
        "{name}: regenerate vectors and tables together"
    );
    assert_eq!(
        value["unicode_version"].as_str(),
        Some(unicode::UNICODE_VERSION),
        "{name}"
    );
    value
}

/// Decodes a vector string: plain JSON string, or `{"hex": ...}` for bytes that are not UTF-8.
fn bytes_of(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Object(o) => {
            let h = o["hex"].as_str().expect("hex field");
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
                .collect()
        }
        other => panic!("not a vector string: {other}"),
    }
}

fn str_of(v: &Value) -> String {
    String::from_utf8(bytes_of(v)).expect("valid UTF-8 expected in this field")
}

fn bits_f64(v: &Value) -> f64 {
    f64::from_bits(u64::from_str_radix(v.as_str().expect("bits"), 16).expect("hex bits"))
}

fn bits_f32(v: &Value) -> f32 {
    f32::from_bits(u32::from_str_radix(v.as_str().expect("bits"), 16).expect("hex bits"))
}

/// Collects mismatches and reports them together with how many cases ran.
struct Check {
    name: &'static str,
    cases: usize,
    failures: Vec<String>,
}

impl Check {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            cases: 0,
            failures: Vec::new(),
        }
    }

    fn eq<T: PartialEq + std::fmt::Debug>(
        &mut self,
        context: impl FnOnce() -> String,
        got: T,
        want: T,
    ) {
        self.cases += 1;
        if got != want {
            self.failures
                .push(format!("{}: got {got:?}, want {want:?}", context()));
        }
    }

    fn finish(self, min: usize) {
        println!(
            "{}: {} cases, {} failures",
            self.name,
            self.cases,
            self.failures.len()
        );
        let shown: Vec<&str> = self.failures.iter().take(25).map(String::as_str).collect();
        assert!(
            self.failures.is_empty(),
            "{}: {} of {} failed:\n{}",
            self.name,
            self.failures.len(),
            self.cases,
            shown.join("\n")
        );
        assert!(
            self.cases >= min,
            "{}: only {} cases, want at least {min}",
            self.name,
            self.cases
        );
    }
}

fn array<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("missing array {key}"))
}

#[test]
fn unicode_exhaustive() {
    let v = vector("unicode");
    let mut maps = Sha256::new();
    let mut preds = Sha256::new();
    let mut strs = Sha256::new();
    let mut fold = Sha256::new();
    let le = |h: &mut Sha256, x: u32| h.update(x.to_le_bytes());
    for r in 0..=unicode::MAX_RUNE {
        le(&mut maps, r);
        le(&mut maps, unicode::to_lower_rune(r));
        le(&mut maps, unicode::to_upper_rune(r));
        le(&mut maps, unicode::to_title_rune(r));
        le(&mut maps, unicode::simple_fold(r));
        let predicates: [fn(u32) -> bool; 13] = [
            unicode::is_letter,
            unicode::is_digit,
            unicode::is_number,
            unicode::is_upper,
            unicode::is_lower,
            unicode::is_title,
            unicode::is_space,
            unicode::is_punct,
            unicode::is_symbol,
            unicode::is_mark,
            unicode::is_control,
            unicode::is_print,
            unicode::is_graphic,
        ];
        let mut bits = 0u32;
        for (i, p) in predicates.iter().enumerate() {
            if p(r) {
                bits |= 1 << i;
            }
        }
        le(&mut preds, bits);
        let Some(c) = char::from_u32(r) else {
            continue;
        };
        assert_eq!(
            c.is_whitespace(),
            unicode::is_space(r),
            "str::trim stops matching TrimSpace at {r:#x}"
        );
        let s = c.to_string();
        let wrapped = format!("a{s}b");
        for piece in [
            strings::to_lower(&s).as_str(),
            strings::to_upper(&s).as_str(),
            strings::trim_space(&wrapped),
            strings::trim_space(&s),
        ] {
            strs.update(piece.as_bytes());
            strs.update([0u8]);
        }
        le(&mut strs, strings::fields(&wrapped).len() as u32);

        let as_string =
            |x: u32| char::from_u32(x).map_or_else(|| "\u{FFFD}".to_string(), |c| c.to_string());
        let mut flags = 0u8;
        if strings::equal_fold(&s, &as_string(unicode::to_lower_rune(r))) {
            flags |= 1;
        }
        if strings::equal_fold(&s, &as_string(unicode::to_upper_rune(r))) {
            flags |= 2;
        }
        if strings::equal_fold(&s, &as_string(unicode::simple_fold(r))) {
            flags |= 4;
        }
        if strings::equal_fold(
            &format!("x{s}"),
            &format!(
                "X{}",
                as_string(unicode::simple_fold(unicode::simple_fold(r)))
            ),
        ) {
            flags |= 8;
        }
        fold.update([flags]);
    }
    let hex = |h: Sha256| {
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(maps),
        v["rune_maps_sha256"].as_str().unwrap(),
        "ToLower, ToUpper, ToTitle, SimpleFold over every rune"
    );
    assert_eq!(
        hex(preds),
        v["predicates_sha256"].as_str().unwrap(),
        "unicode.Is* over every rune"
    );
    assert_eq!(
        hex(strs),
        v["string_maps_sha256"].as_str().unwrap(),
        "strings functions over every rune"
    );
    assert_eq!(
        hex(fold),
        v["fold_closure_sha256"].as_str().unwrap(),
        "EqualFold over every rune"
    );
}

#[test]
fn strings_to_lower_upper() {
    let v = vector("strings");
    let mut lower = Check::new("strings.ToLower");
    for c in array(&v, "to_lower") {
        let input = bytes_of(&c["in"]);
        lower.eq(
            || format!("{input:x?}"),
            strings::to_lower(&decode_runes(&input)),
            str_of(&c["out"]),
        );
    }
    lower.finish(MIN_CASES);
    let mut upper = Check::new("strings.ToUpper");
    for c in array(&v, "to_upper") {
        let input = bytes_of(&c["in"]);
        upper.eq(
            || format!("{input:x?}"),
            strings::to_upper(&decode_runes(&input)),
            str_of(&c["out"]),
        );
    }
    upper.finish(MIN_CASES);
}

#[test]
fn strings_equal_fold() {
    let v = vector("strings");
    let mut check = Check::new("strings.EqualFold");
    for c in array(&v, "equal_fold") {
        let (a, b) = (bytes_of(&c["a"]), bytes_of(&c["b"]));
        check.eq(
            || format!("{a:x?} vs {b:x?}"),
            strings::equal_fold(&decode_runes(&a), &decode_runes(&b)),
            c["eq"].as_bool().unwrap(),
        );
    }
    check.finish(MIN_CASES);
}

#[test]
fn strings_trim_and_fields() {
    let v = vector("strings");
    let mut trim = Check::new("strings.TrimSpace");
    for c in array(&v, "trim_space") {
        let input = str_of(&c["in"]);
        trim.eq(
            || format!("{input:?}"),
            strings::trim_space(&input).to_string(),
            str_of(&c["out"]),
        );
    }
    trim.finish(MIN_CASES);
    let mut fields = Check::new("strings.Fields");
    for c in array(&v, "fields") {
        let input = str_of(&c["in"]);
        let want: Vec<String> = array(c, "out").iter().map(str_of).collect();
        fields.eq(
            || format!("{input:?}"),
            strings::fields(&input)
                .iter()
                .map(ToString::to_string)
                .collect(),
            want,
        );
    }
    fields.finish(MIN_CASES);
}

#[test]
fn path_and_filepath_functions() {
    let v = vector("path");
    let mut clean = Check::new("path.Clean");
    let mut fclean = Check::new("filepath.Clean");
    let mut others = Check::new("path.Base/Dir/Ext/IsAbs/Split, filepath same");
    for c in array(&v, "paths") {
        let input = str_of(&c["in"]);
        let ctx = || format!("{input:?}");
        clean.eq(ctx, path::clean(&input), str_of(&c["clean"]));
        fclean.eq(ctx, filepath::clean(&input), str_of(&c["f_clean"]));
        others.eq(ctx, path::base(&input).to_string(), str_of(&c["base"]));
        others.eq(ctx, path::dir(&input), str_of(&c["dir"]));
        others.eq(ctx, path::ext(&input).to_string(), str_of(&c["ext"]));
        others.eq(ctx, path::is_abs(&input), c["is_abs"].as_bool().unwrap());
        let (d, f) = path::split(&input);
        others.eq(
            ctx,
            (d.to_string(), f.to_string()),
            (str_of(&c["split"][0]), str_of(&c["split"][1])),
        );
        others.eq(
            ctx,
            filepath::base(&input).to_string(),
            str_of(&c["f_base"]),
        );
        others.eq(ctx, filepath::dir(&input), str_of(&c["f_dir"]));
        others.eq(ctx, filepath::ext(&input).to_string(), str_of(&c["f_ext"]));
        others.eq(
            ctx,
            filepath::is_abs(&input),
            c["f_is_abs"].as_bool().unwrap(),
        );
        let (d, f) = filepath::split(&input);
        others.eq(
            ctx,
            (d.to_string(), f.to_string()),
            (str_of(&c["f_split"][0]), str_of(&c["f_split"][1])),
        );
    }
    clean.finish(MIN_CASES);
    fclean.finish(MIN_CASES);
    others.finish(MIN_CASES);

    let mut join = Check::new("path.Join, filepath.Join");
    for c in array(&v, "joins") {
        let parts: Vec<String> = array(c, "in").iter().map(str_of).collect();
        join.eq(
            || format!("{parts:?}"),
            path::join(&parts),
            str_of(&c["path"]),
        );
        join.eq(
            || format!("filepath {parts:?}"),
            filepath::join(&parts),
            str_of(&c["f_path"]),
        );
    }
    join.finish(MIN_CASES);

    let mut rel = Check::new("filepath.Rel");
    for c in array(&v, "rels") {
        let (base, targ) = (str_of(&c["base"]), str_of(&c["targ"]));
        let got = match filepath::rel(&base, &targ) {
            Ok(out) => (Some(out), None),
            Err(err) => (None, Some(err.to_string())),
        };
        let want = (
            c["out"].as_str().map(str::to_string),
            c["err"].as_str().map(str::to_string),
        );
        rel.eq(|| format!("{base:?} {targ:?}"), got, want);
    }
    rel.finish(MIN_CASES);
}

#[test]
fn path_and_filepath_match() {
    let v = vector("path");
    let mut p = Check::new("path.Match");
    let mut f = Check::new("filepath.Match");
    for c in array(&v, "match") {
        let (pattern, name) = (str_of(&c["pattern"]), str_of(&c["name"]));
        let to_pair = |r: Result<bool, path::BadPattern>| match r {
            Ok(m) => (m, false),
            Err(_) => (false, true),
        };
        p.eq(
            || format!("{pattern:?} {name:?}"),
            to_pair(path::match_pattern(&pattern, &name)),
            (
                c["path"].as_bool().unwrap(),
                c["path_err"].as_bool().unwrap(),
            ),
        );
        f.eq(
            || format!("{pattern:?} {name:?}"),
            to_pair(filepath::match_pattern(&pattern, &name)),
            (
                c["file"].as_bool().unwrap(),
                c["file_err"].as_bool().unwrap(),
            ),
        );
    }
    p.finish(MIN_CASES);
    f.finish(MIN_CASES);
}

#[test]
fn parse_duration_vectors() {
    let v = vector("time");
    let mut check = Check::new("time.ParseDuration");
    for c in array(&v, "parse_duration") {
        let input = bytes_of(&c["in"]);
        let got = match parse_duration(&input) {
            Ok(d) => (Some(d.0.to_string()), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let want = (
            c["out"].as_str().map(str::to_string),
            c["err"].as_str().map(str::to_string),
        );
        check.eq(
            || format!("{:?}", String::from_utf8_lossy(&input)),
            got,
            want,
        );
    }
    check.finish(MIN_CASES);
}

#[test]
fn duration_string_vectors() {
    let v = vector("time");
    let mut string = Check::new("Duration.String");
    let mut accessors = Check::new("Duration.Seconds/Minutes/Hours/Milliseconds/Microseconds");
    let mut round_trip = Check::new("ParseDuration(Duration.String)");
    for c in array(&v, "durations") {
        let n: i64 = c["nanos"].as_str().unwrap().parse().unwrap();
        let d = Duration(n);
        let ctx = || n.to_string();
        let text = str_of(&c["string"]);
        string.eq(ctx, d.to_string(), text.clone());
        accessors.eq(
            ctx,
            d.seconds().to_bits(),
            bits_f64(&c["seconds_bits"]).to_bits(),
        );
        accessors.eq(
            ctx,
            d.minutes().to_bits(),
            bits_f64(&c["minutes_bits"]).to_bits(),
        );
        accessors.eq(
            ctx,
            d.hours().to_bits(),
            bits_f64(&c["hours_bits"]).to_bits(),
        );
        accessors.eq(ctx, d.milliseconds(), c["millis"].as_i64().unwrap());
        accessors.eq(ctx, d.microseconds(), c["micros"].as_i64().unwrap());
        // Go wrote this text, and Rust must read it back to the same value.
        round_trip.eq(ctx, parse_duration(&text).map(|d| d.0), Ok(n));
    }
    string.finish(MIN_CASES);
    accessors.finish(MIN_CASES);
    round_trip.finish(MIN_CASES);
}

fn make_time(c: &Value) -> GoTime {
    let t = GoTime::from_unix(
        c["secs"].as_i64().unwrap(),
        c["nanos"].as_u64().unwrap_or(0) as u32,
    );
    if c["utc"].as_bool().unwrap() {
        t
    } else {
        t.with_offset(c["offset"].as_i64().unwrap() as i32)
    }
}

#[test]
fn time_format_vectors() {
    let v = vector("time");
    let mut nano = Check::new("Time.Format(RFC3339Nano)");
    let mut other = Check::new("Time.Format(other layouts)");
    for c in array(&v, "format") {
        let t = make_time(c);
        let layout = c["layout"].as_str().unwrap();
        let check = if layout == silo_gocompat::time::RFC3339_NANO {
            &mut nano
        } else {
            &mut other
        };
        check.eq(|| format!("{c}"), t.format(layout), str_of(&c["out"]));
    }
    nano.finish(MIN_CASES);
    other.finish(MIN_CASES);
}

#[test]
fn time_marshal_json_vectors() {
    let v = vector("time");
    let mut check = Check::new("Time.MarshalJSON");
    let mut parts = Check::new("Time.IsZero/Date/Clock");
    for c in array(&v, "marshal_json") {
        let t = make_time(c);
        let got = match json::marshal(&t) {
            Ok(b) => (Some(String::from_utf8(b).unwrap()), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let want = (
            c["out"].as_str().map(str::to_string),
            c["err"].as_str().map(str::to_string),
        );
        check.eq(|| format!("{c}"), got, want);
        parts.eq(
            || format!("{c}"),
            t.is_zero(),
            c["is_zero"].as_bool().unwrap(),
        );
        let date = t.date();
        parts.eq(
            || format!("{c}"),
            [date.0, i64::from(date.1), i64::from(date.2)].to_vec(),
            array(c, "date")
                .iter()
                .map(|x| x.as_i64().unwrap())
                .collect(),
        );
        let clock = t.clock();
        parts.eq(
            || format!("{c}"),
            [i64::from(clock.0), i64::from(clock.1), i64::from(clock.2)].to_vec(),
            array(c, "clock")
                .iter()
                .map(|x| x.as_i64().unwrap())
                .collect(),
        );
    }
    check.finish(MIN_CASES);
    parts.finish(MIN_CASES);
    assert!(GoTime::ZERO.is_zero());
    assert_eq!(GoTime::default().rfc3339_nano(), "0001-01-01T00:00:00Z");
}

#[test]
fn time_parse_vectors() {
    let v = vector("time");
    let mut rfc = Check::new("time.Parse(RFC3339 family)");
    let mut other = Check::new("time.Parse(other layouts)");
    for c in array(&v, "parse") {
        let layout = c["layout"].as_str().unwrap();
        let value = bytes_of(&c["value"]);
        let got = match parse_bytes(layout, &value) {
            Ok(t) => (
                Some((
                    t.unix(),
                    i64::from(t.nanosecond()),
                    i64::from(t.offset()),
                    t.rfc3339_nano(),
                )),
                None,
            ),
            Err(e) => (None, Some(e.to_string())),
        };
        let want = match c.get("err") {
            Some(e) => (None, Some(str_of(e))),
            None => (
                Some((
                    c["secs"].as_i64().unwrap(),
                    c["nanos"].as_i64().unwrap_or(0),
                    c["offset"].as_i64().unwrap_or(0),
                    str_of(&c["nano"]),
                )),
                None,
            ),
        };
        let check = if layout.starts_with("2006-01-02T15:04:05") && layout.ends_with("Z07:00") {
            &mut rfc
        } else {
            &mut other
        };
        check.eq(
            || format!("{layout:?} {:?}", String::from_utf8_lossy(&value)),
            got,
            want,
        );
    }
    rfc.finish(MIN_CASES);
    other.finish(MIN_CASES);
}

#[test]
fn url_vectors() {
    let v = vector("url");
    let mut query = Check::new("url.QueryEscape");
    for c in array(&v, "query_escape") {
        let input = bytes_of(&c["in"]);
        query.eq(
            || format!("{input:x?}"),
            url::query_escape(&input),
            str_of(&c["out"]),
        );
    }
    query.finish(MIN_CASES);
    let mut path = Check::new("url.PathEscape");
    for c in array(&v, "path_escape") {
        let input = bytes_of(&c["in"]);
        path.eq(
            || format!("{input:x?}"),
            url::path_escape(&input),
            str_of(&c["out"]),
        );
    }
    path.finish(MIN_CASES);

    type Unescape = fn(&[u8]) -> Result<Vec<u8>, url::EscapeError>;
    let cases: [(&str, &'static str, Unescape); 2] = [
        ("query_unescape", "url.QueryUnescape", |b| {
            url::query_unescape(b)
        }),
        ("path_unescape", "url.PathUnescape", |b| {
            url::path_unescape(b)
        }),
    ];
    for (key, name, f) in cases {
        let mut check = Check::new(name);
        for c in array(&v, key) {
            let input = bytes_of(&c["in"]);
            let got = match f(&input) {
                Ok(out) => (Some(out), None),
                Err(e) => (None, Some(e.to_string())),
            };
            let want = (
                c.get("out").filter(|o| !o.is_null()).map(bytes_of),
                c.get("err").filter(|o| !o.is_null()).map(str_of),
            );
            check.eq(
                || format!("{:?}", String::from_utf8_lossy(&input)),
                got,
                want,
            );
        }
        check.finish(MIN_CASES);
    }

    let mut encode = Check::new("url.Values.Encode");
    for c in array(&v, "values_encode") {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = c["pairs"]
            .as_array()
            .map(|p| {
                p.iter()
                    .map(|e| (bytes_of(&e[0]), bytes_of(&e[1])))
                    .collect()
            })
            .unwrap_or_default();
        encode.eq(
            || format!("{c}"),
            url::values_encode(&pairs),
            str_of(&c["out"]),
        );
    }
    encode.finish(MIN_CASES);
}

#[test]
fn url_parse_vectors() {
    let v = vector("url");
    let mut check = Check::new("url.Parse and URL.String");
    for c in array(&v, "parse") {
        // `Url`'s fields are Rust `String`s (see the module docs), so a raw URL that is not valid
        // UTF-8 is out of scope for this port; skip the handful of cases built from invalidUTF8.
        if !c["in"].is_string() {
            continue;
        }
        let input = str_of(&c["in"]);
        let got = match url::parse(&input) {
            Ok(u) => Ok((
                u.scheme.clone(),
                u.opaque.clone(),
                u.user.as_ref().map(|user| {
                    (
                        user.username().to_string(),
                        user.password().map(str::to_string),
                    )
                }),
                u.host.clone(),
                u.path.clone(),
                u.raw_path.clone(),
                u.omit_host,
                u.force_query,
                u.raw_query.clone(),
                u.fragment.clone(),
                u.raw_fragment.clone(),
                u.string(),
            )),
            Err(e) => Err(e.to_string()),
        };
        let want = if let Some(ok) = c.get("ok") {
            Ok((
                str_of(&ok["scheme"]),
                str_of(&ok["opaque"]),
                (!ok["user"].is_null()).then(|| {
                    (
                        str_of(&ok["user"]["username"]),
                        ok["user"].get("password").map(str_of),
                    )
                }),
                str_of(&ok["host"]),
                str_of(&ok["path"]),
                str_of(&ok["raw_path"]),
                ok["omit_host"].as_bool().unwrap_or(false),
                ok["force_query"].as_bool().unwrap_or(false),
                str_of(&ok["raw_query"]),
                str_of(&ok["fragment"]),
                str_of(&ok["raw_fragment"]),
                str_of(&ok["str"]),
            ))
        } else {
            Err(str_of(&c["err"]))
        };
        // The exact wording of an invalid IPv6-literal-in-brackets error can differ (see the
        // module docs): accept any error there instead of matching Go's `net/netip` text.
        const INVALID_HOST: &str = "invalid host: ";
        if let (Err(g), Err(w)) = (&got, &want)
            && g.contains(INVALID_HOST)
            && w.contains(INVALID_HOST)
        {
            check.eq(|| input.clone(), true, true);
            continue;
        }
        check.eq(|| input.clone(), got, want);
    }
    check.finish(MIN_CASES);
}

#[test]
fn url_query_vectors() {
    let v = vector("url");
    let mut check = Check::new("URL.Query");
    for c in array(&v, "query") {
        let raw_query = str_of(&c["raw_query"]);
        let got: Vec<(String, Vec<String>)> = url::Url {
            raw_query: raw_query.clone(),
            ..Default::default()
        }
        .query()
        .into_iter()
        .collect();
        let want: Vec<(String, Vec<String>)> = c["pairs"]
            .as_array()
            .map(|pairs| {
                pairs
                    .iter()
                    .map(|p| {
                        (
                            str_of(&p["k"]),
                            p["v"].as_array().unwrap().iter().map(str_of).collect(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        check.eq(|| raw_query.clone(), got, want);
    }
    check.finish(MIN_CASES);
}

#[test]
fn url_resolve_reference_vectors() {
    let v = vector("url");
    let mut check = Check::new("URL.ResolveReference");
    for c in array(&v, "resolve_reference") {
        let base = str_of(&c["base"]);
        let r = str_of(&c["ref"]);
        let got = url::parse(&base)
            .and_then(|b| url::parse(&r).map(|ref_url| b.resolve_reference(&ref_url).string()))
            .map_err(|e| e.to_string());
        check.eq(
            || format!("base={base:?} ref={r:?}"),
            got,
            Ok(str_of(&c["out"])),
        );
    }
    check.finish(MIN_CASES);
}

#[test]
fn strconv_vectors() {
    let v = vector("strconv");
    let mut quote = Check::new("strconv.Quote");
    for c in array(&v, "quote") {
        let input = bytes_of(&c["in"]);
        quote.eq(
            || format!("{input:x?}"),
            strconv::quote_bytes(&input),
            str_of(&c["out"]),
        );
    }
    quote.finish(MIN_CASES);
    let mut float = Check::new("strconv.FormatFloat");
    for c in array(&v, "format_float") {
        let f = bits_f64(&c["bits"]);
        let fmt = c["fmt"].as_str().unwrap().as_bytes()[0];
        let prec = c["prec"].as_i64().unwrap() as i32;
        let size = c["size"].as_u64().unwrap() as u32;
        float.eq(
            || format!("{f:e} {} {prec} {size}", fmt as char),
            strconv::format_float(f, fmt, prec, size),
            c["out"].as_str().unwrap().to_string(),
        );
    }
    float.finish(MIN_CASES);
}

/// A value rebuilt from the same description Go encoded. Maps go through `HashMap`, so a sort that
/// silently relied on input order would fail.
enum Built {
    Null,
    Bool(bool),
    Str(ByteString),
    F64(f64),
    F32(f32),
    Int(i64),
    Uint(u64),
    Arr(Vec<Built>),
    Map(HashMap<String, Built>),
    ByteKeyMap(Vec<(Vec<u8>, Built)>),
    IntMap(HashMap<i64, Built>),
    Raw(RawMessage),
    Num(Number),
    Bytes(Bytes),
}

impl Serialize for Built {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => s.serialize_unit(),
            Self::Bool(b) => s.serialize_bool(*b),
            Self::Str(v) => v.serialize(s),
            Self::F64(f) => s.serialize_f64(*f),
            Self::F32(f) => s.serialize_f32(*f),
            Self::Int(i) => s.serialize_i64(*i),
            Self::Uint(u) => s.serialize_u64(*u),
            Self::Arr(a) => a.serialize(s),
            Self::Map(m) => m.serialize(s),
            Self::ByteKeyMap(entries) => {
                use serde::ser::SerializeMap;
                let mut map = s.serialize_map(Some(entries.len()))?;
                for (k, v) in entries {
                    map.serialize_entry(&ByteString(k.clone()), v)?;
                }
                map.end()
            }
            Self::IntMap(m) => m.serialize(s),
            Self::Raw(r) => r.serialize(s),
            Self::Num(n) => n.serialize(s),
            Self::Bytes(b) => b.serialize(s),
        }
    }
}

fn build(d: &Value) -> Built {
    match d["t"].as_str().unwrap() {
        "null" => Built::Null,
        "bool" => Built::Bool(d["b"].as_bool().unwrap_or(false)),
        "str" => Built::Str(ByteString(bytes_of(&d["s"]))),
        "f64" => Built::F64(bits_f64(&d["bits"])),
        "f32" => Built::F32(bits_f32(&d["bits"])),
        "int" => Built::Int(d["i"].as_str().unwrap().parse().unwrap()),
        "uint" => Built::Uint(d["i"].as_str().unwrap().parse().unwrap()),
        "arr" => Built::Arr(
            d.get("a")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(build).collect())
                .unwrap_or_default(),
        ),
        "map" => {
            let entries = d
                .get("m")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if entries.iter().all(|e| e["k"].is_string()) {
                Built::Map(
                    entries
                        .iter()
                        .map(|e| (str_of(&e["k"]), build(&e["v"])))
                        .collect(),
                )
            } else {
                Built::ByteKeyMap(
                    entries
                        .iter()
                        .map(|e| (bytes_of(&e["k"]), build(&e["v"])))
                        .collect(),
                )
            }
        }
        "imap" => {
            let entries = d
                .get("m")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Built::IntMap(
                entries
                    .iter()
                    .map(|e| (str_of(&e["k"]).parse().unwrap(), build(&e["v"])))
                    .collect(),
            )
        }
        "raw" => Built::Raw(RawMessage::from(bytes_of(&d["s"]))),
        "rawnil" => Built::Raw(RawMessage::nil()),
        "num" => Built::Num(Number(str_of(&d["s"]))),
        "bytes" => {
            let h = str_of(&d["s"]);
            let b = (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect();
            Built::Bytes(Bytes(Some(b)))
        }
        "bytesnil" => Built::Bytes(Bytes(None)),
        other => panic!("unknown description {other}"),
    }
}

fn result_of(r: &Value) -> Result<Vec<u8>, String> {
    match r.get("err") {
        Some(e) => Err(str_of(e)),
        None => Ok(bytes_of(&r["ok"])),
    }
}

fn check_value_case(check: &mut Check, c: &Value) {
    let built = build(&c["in"]);
    let ctx = || format!("{}", c["in"]);
    check.eq(
        ctx,
        json::marshal(&built).map_err(|e| e.to_string()),
        result_of(&c["marshal"]),
    );

    let mut no_html = Vec::new();
    let mut enc = Encoder::new(&mut no_html);
    enc.set_escape_html(false);
    let res = enc
        .encode(&built)
        .map(|()| no_html)
        .map_err(|e| e.to_string());
    check.eq(ctx, res, result_of(&c["no_html"]));

    check.eq(
        ctx,
        json::marshal_indent(&built, ">", "  ").map_err(|e| e.to_string()),
        result_of(&c["indent"]),
    );

    let mut indented = Vec::new();
    let mut enc = Encoder::new(&mut indented);
    enc.set_indent("", "\t");
    let res = enc
        .encode(&built)
        .map(|()| indented)
        .map_err(|e| e.to_string());
    check.eq(ctx, res, result_of(&c["enc_indent"]));
}

#[test]
fn json_values() {
    let v = vector("json");
    let mut check = Check::new("json.Marshal of value trees");
    for c in array(&v, "values") {
        check_value_case(&mut check, c);
    }
    check.finish(MIN_CASES);
}

#[test]
fn json_strings() {
    let v = vector("json");
    let mut check = Check::new("json.Marshal of strings");
    for c in array(&v, "strings") {
        check_value_case(&mut check, c);
    }
    check.finish(MIN_CASES);
}

#[test]
fn json_numbers() {
    let v = vector("json");
    let mut check = Check::new("json.Number");
    for c in array(&v, "numbers") {
        check_value_case(&mut check, c);
    }
    check.finish(100);
}

#[test]
fn json_floats() {
    let v = vector("json");
    let mut f64s = Check::new("json.Marshal(float64)");
    for c in array(&v, "float64") {
        let f = bits_f64(&c["bits"]);
        f64s.eq(
            || format!("{}", c["bits"]),
            json::marshal(&f).map_err(|e| e.to_string()),
            result_of(&c["out"]),
        );
    }
    f64s.finish(MIN_CASES);
    let mut f32s = Check::new("json.Marshal(float32)");
    for c in array(&v, "float32") {
        let f = bits_f32(&c["bits"]);
        f32s.eq(
            || format!("{}", c["bits"]),
            json::marshal(&f).map_err(|e| e.to_string()),
            result_of(&c["out"]),
        );
    }
    f32s.finish(MIN_CASES);
}

#[test]
fn json_documents() {
    let v = vector("json");
    let mut check = Check::new("json.Valid/Compact/Indent/HTMLEscape, RawMessage");
    for c in array(&v, "documents") {
        let input = bytes_of(&c["in"]);
        let ctx = || format!("{:?}", String::from_utf8_lossy(&input));
        check.eq(ctx, json::valid(&input), c["valid"].as_bool().unwrap());
        check.eq(
            ctx,
            json::check_valid(&input).err().map(|e| e.to_string()),
            c.get("check_err").map(str_of),
        );
        check.eq(
            ctx,
            json::compact(&input).map_err(|e| e.to_string()),
            result_of(&c["compact"]),
        );
        check.eq(
            ctx,
            json::marshal(&RawMessage::from(input.clone())).map_err(|e| e.to_string()),
            result_of(&c["raw_escape"]),
        );
        check.eq(
            ctx,
            json::indent(&input, "p", "  ").map_err(|e| e.to_string()),
            result_of(&c["indent"]),
        );
        check.eq(ctx, json::html_escape(&input), bytes_of(&c["html"]));
    }
    check.finish(MIN_CASES);

    // Documents at the scanner's nesting limit are stored without their input.
    let mut deep = Check::new("json nesting limit");
    for c in array(&v, "deep_documents") {
        let depth = c["len"].as_u64().unwrap() as usize / 2;
        let doc = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        deep.eq(
            || depth.to_string(),
            json::valid(doc.as_bytes()),
            c["valid"].as_bool().unwrap(),
        );
        deep.eq(
            || depth.to_string(),
            json::compact(doc.as_bytes()).map_err(|e| e.to_string()),
            result_of(&c["compact"]),
        );
    }
    deep.finish(2);
}

#[derive(Serialize, Default, Clone, PartialEq)]
struct Inner {
    x: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    y: String,
}

impl Inner {
    fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Serialize, Default)]
struct Embedded {
    ea: String,
    #[serde(skip_serializing_if = "omit_empty")]
    eb: i64,
}

/// Mirrors the generator's `All` struct field for field.
#[derive(Serialize, Default)]
struct All {
    #[serde(flatten)]
    embedded: Embedded,
    str: String,
    #[serde(skip_serializing_if = "omit_empty")]
    str_oe: String,
    b: bool,
    #[serde(skip_serializing_if = "omit_empty")]
    b_oe: bool,
    i: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    i_oe: i64,
    u64: u64,
    f64: f64,
    #[serde(skip_serializing_if = "omit_empty")]
    f64_oe: f64,
    f32: f32,
    ptr: Option<String>,
    #[serde(skip_serializing_if = "omit_empty")]
    ptr_oe: Option<String>,
    #[serde(skip_serializing_if = "omit_empty")]
    ptr_int: Option<i64>,
    slice: Option<Vec<i64>>,
    #[serde(skip_serializing_if = "omit_nil_or_empty")]
    slice_oe: Option<Vec<String>>,
    map: Option<HashMap<String, i64>>,
    #[serde(skip_serializing_if = "omit_nil_or_empty")]
    map_oe: Option<BTreeMap<String, String>>,
    int_map: Option<HashMap<i64, String>>,
    bytes: Bytes,
    raw: RawMessage,
    #[serde(skip_serializing_if = "omit_empty")]
    raw_oe: RawMessage,
    num: Number,
    time: GoTime,
    time_oe: GoTime,
    #[serde(skip_serializing_if = "GoTime::is_zero")]
    time_oz: GoTime,
    #[serde(skip_serializing_if = "omit_empty")]
    time_ptr: Option<GoTime>,
    dur: Duration,
    #[serde(skip_serializing_if = "omit_empty")]
    dur_oe: Duration,
    inner: Inner,
    inner_oe: Inner,
    #[serde(skip_serializing_if = "omit_empty")]
    inner_ptr: Option<Inner>,
    #[serde(skip_serializing_if = "Inner::is_zero")]
    inner_oz: Inner,
    any: Value,
    arr: [i64; 3],
    byte_arr: [u8; 2],
    #[serde(rename = "-")]
    dash: String,
    #[serde(rename = "<&>")]
    html: String,
    inners: Option<Vec<Inner>>,
    map_of_inner: Option<HashMap<String, Option<Inner>>>,
}

#[allow(clippy::approx_constant)] // The generator's struct holds this exact literal.
fn struct_cases() -> Vec<(&'static str, All)> {
    let t = GoTime::from_unix(1_709_209_845, 120_000_000);
    let populated = All {
        embedded: Embedded {
            ea: "ea<>".into(),
            eb: 7,
        },
        str: "s&".into(),
        str_oe: "x".into(),
        b: true,
        b_oe: true,
        i: -5,
        i_oe: 5,
        u64: u64::MAX,
        f64: 7200.0,
        f64_oe: 120.5,
        f32: 3.14,
        ptr: Some("p".into()),
        ptr_oe: Some(String::new()),
        ptr_int: Some(0),
        slice: Some(vec![1, 2]),
        slice_oe: Some(vec![String::new()]),
        map: Some(HashMap::from([
            ("z".into(), 1),
            ("a".into(), 2),
            ("é".into(), 3),
            ("<".into(), 4),
        ])),
        map_oe: Some(BTreeMap::from([("k".into(), "v".into())])),
        int_map: Some(HashMap::from([
            (10, "ten".into()),
            (9, "nine".into()),
            (-1, "neg".into()),
        ])),
        bytes: Bytes(Some(b"hello\xff".to_vec())),
        raw: RawMessage::from(r#"{ "b" : "<x>", "a" : [ 1 ] }"#),
        raw_oe: RawMessage::from("1"),
        num: Number("1.50".into()),
        time: t,
        time_oe: t.with_offset(19800),
        time_oz: t,
        time_ptr: Some(t),
        dur: Duration(1_500_000_000),
        dur_oe: Duration::SECOND,
        inner: Inner {
            x: 1,
            y: "y".into(),
        },
        inner_oe: Inner {
            x: 2,
            y: String::new(),
        },
        inner_ptr: Some(Inner::default()),
        inner_oz: Inner {
            x: 3,
            y: String::new(),
        },
        any: serde_json::json!({"b": 1.0, "a": ["x", null]}),
        arr: [1, 2, 3],
        byte_arr: [1, 2],
        dash: "dash".into(),
        html: "html".into(),
        inners: Some(vec![
            Inner::default(),
            Inner {
                x: 1,
                y: "a".into(),
            },
        ]),
        map_of_inner: Some(HashMap::from([
            ("n".into(), None),
            (
                "m".into(),
                Some(Inner {
                    x: 1,
                    y: String::new(),
                }),
            ),
        ])),
    };
    vec![
        ("zero", All::default()),
        ("populated", populated),
        (
            "empty_containers",
            All {
                slice: Some(vec![]),
                slice_oe: Some(vec![]),
                map: Some(HashMap::new()),
                map_oe: Some(BTreeMap::new()),
                int_map: Some(HashMap::new()),
                bytes: Bytes(Some(vec![])),
                raw: RawMessage::from("[]"),
                raw_oe: RawMessage::from(Vec::new()),
                inners: Some(vec![]),
                map_of_inner: Some(HashMap::new()),
                any: serde_json::json!([]),
                ..All::default()
            },
        ),
        (
            "negative_zero",
            All {
                f64: -0.0,
                f64_oe: -0.0,
                f32: -0.0,
                ..All::default()
            },
        ),
        (
            "nan",
            All {
                f64: f64::NAN,
                ..All::default()
            },
        ),
        (
            "bad_raw",
            All {
                raw: RawMessage::from("{"),
                ..All::default()
            },
        ),
        (
            "empty_raw",
            All {
                raw: RawMessage::from(Vec::new()),
                ..All::default()
            },
        ),
        (
            "bad_number",
            All {
                num: Number("abc".into()),
                ..All::default()
            },
        ),
        (
            "bad_time",
            All {
                time: GoTime::from_unix(253_402_300_800, 0),
                ..All::default()
            },
        ),
        (
            "zero_time_with_offset",
            All {
                time_oz: GoTime::ZERO.with_offset(3600),
                time_oe: GoTime::ZERO.with_offset(3600),
                ..All::default()
            },
        ),
    ]
}

#[derive(serde::Deserialize, Default)]
struct DecodeMirror {
    raw: RawMessage,
    num: Number,
    time: GoTime,
}

/// `Deserialize` on the three types that keep Go's literal handling. Only the outcome is compared:
/// serde adds a position to its error text.
#[test]
fn json_decode_literals() {
    let v = vector("json");
    let mut check = Check::new("json.Unmarshal into RawMessage, Number, time.Time");
    for c in array(&v, "decode") {
        let doc = str_of(&c["doc"]);
        let got = serde_json::from_str::<DecodeMirror>(&doc).ok().map(|d| {
            (
                d.raw.as_bytes().map(<[u8]>::to_vec),
                d.num.0,
                d.time.rfc3339_nano(),
            )
        });
        let want = c.get("ok").map(|ok| {
            (
                ok.get("raw").map(bytes_of),
                str_of(&ok["num"]),
                str_of(&ok["time"]),
            )
        });
        check.eq(|| doc.clone(), got, want);
    }
    check.finish(30);
}

#[test]
fn json_structs() {
    let v = vector("json");
    let cases: BTreeMap<&str, All> = struct_cases().into_iter().collect();
    let mut check = Check::new("json.Marshal of a tagged struct");
    for c in array(&v, "structs") {
        let name = c["name"].as_str().unwrap();
        let value = cases
            .get(name)
            .unwrap_or_else(|| panic!("no Rust mirror for case {name}"));
        check.eq(
            || name.to_string(),
            json::marshal(value)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .map_err(|e| e.to_string()),
            result_of(&c["out"]).map(|b| String::from_utf8_lossy(&b).into_owned()),
        );
    }
    check.finish(10);
}

// --- json.Unmarshal: case folding, duplicate-key merging, null handling, unknown fields, and
// --- type-mismatch error text, against `rust/conformance/vectors/gocompat/json_decode.json`.
//
// `Sink` and `Inner` live in their own module so their names match the Go mirror
// (`jsondecode.go`) exactly: that name is what a struct-field type-mismatch error names.
mod decode_sink {
    use super::*;

    #[derive(Deserialize, Default, Debug)]
    #[serde(rename = "main.SinkInner")]
    struct SinkInner {
        x: i32,
        y: String,
    }

    #[derive(Deserialize, Default, Debug)]
    #[serde(rename = "main.Sink")]
    #[allow(non_snake_case)]
    struct Sink {
        str: String,
        b: bool,
        i8: i8,
        i16: i16,
        i32: i32,
        i64: i64,
        u8: u8,
        u16: u16,
        u32: u32,
        u64: u64,
        f32: f32,
        f64: f64,
        r#in: SinkInner,
        arr: Option<Vec<i32>>,
        m: Option<HashMap<String, i32>>,
        im: Option<HashMap<i32, String>>,
        ptr: Option<i32>,
        raw: RawMessage,
        num: Number,
    }

    /// Rebuilds the comparable shape `jsondecode.go`'s `observe` builds on the Go side.
    fn decode_observed(s: &Sink) -> Value {
        let mut m: Vec<(&String, &i32)> = s.m.iter().flatten().collect();
        m.sort_by_key(|(k, _)| k.as_str());
        let mut im: Vec<(&i32, &String)> = s.im.iter().flatten().collect();
        im.sort_by_key(|(k, _)| **k);
        serde_json::json!({
            "str": s.str,
            "b": s.b,
            "i8": s.i8,
            "i16": s.i16,
            "i32": s.i32,
            "i64": s.i64,
            "u8": s.u8,
            "u16": s.u16,
            "u32": s.u32,
            "u64": s.u64,
            "f32": f64::from(s.f32),
            "f64": s.f64,
            "in_x": s.r#in.x,
            "in_y": s.r#in.y,
            "arr": s.arr,
            "m": if m.is_empty() { Value::Null } else { serde_json::json!(m.into_iter().map(|(k, v)| serde_json::json!({"k": k, "v": v.to_string()})).collect::<Vec<_>>()) },
            "im": if im.is_empty() { Value::Null } else { serde_json::json!(im.into_iter().map(|(k, v)| serde_json::json!({"k": k.to_string(), "v": v})).collect::<Vec<_>>()) },
            "ptr": s.ptr,
            "raw": s.raw.as_bytes().map(|b| String::from_utf8_lossy(b).into_owned()),
            "num": s.num.0,
        })
    }

    /// Go's text for a value, so an integer and a float holding it compare equal the way `observe`
    /// printed them, and no other difference is hidden.
    fn canonical(v: &Value) -> String {
        json::marshal_to_string(v).expect("vector values marshal")
    }

    fn run_decode_sink_bucket(name: &'static str, bucket: &str, min: usize) {
        let v = vector("json_decode");
        let mut check = Check::new(name);
        for c in array(&v, bucket) {
            let doc = bytes_of(&c["doc"]);
            let disallow = c["disallow"].as_bool().unwrap_or(false);
            let dec = if disallow {
                Decoder::new().disallow_unknown_fields()
            } else {
                Decoder::new()
            };
            let got = dec
                .decode::<Sink>(&doc)
                .map(|s| canonical(&decode_observed(&s)))
                .map_err(|e| e.to_string());
            let want = match c.get("ok") {
                Some(ok) => Ok(canonical(ok)),
                None => Err(str_of(&c["err"])),
            };
            check.eq(|| String::from_utf8_lossy(&doc).into_owned(), got, want);
        }
        check.finish(min);
    }

    #[test]
    fn json_decode_fold() {
        run_decode_sink_bucket(
            "json.Unmarshal: struct-field case folding",
            "fold",
            MIN_CASES,
        );
    }

    #[test]
    fn json_decode_duplicate_keys() {
        run_decode_sink_bucket(
            "json.Unmarshal: duplicate-key merge behavior",
            "duplicate",
            MIN_CASES,
        );
    }

    #[test]
    fn json_decode_null_noop() {
        run_decode_sink_bucket(
            "json.Unmarshal: null into a non-pointer field",
            "null_noop",
            MIN_CASES,
        );
    }

    #[test]
    fn json_decode_unknown_fields() {
        run_decode_sink_bucket(
            "json.Unmarshal / Decoder.DisallowUnknownFields",
            "unknown_fields",
            MIN_CASES,
        );
    }

    #[test]
    fn json_decode_type_errors() {
        run_decode_sink_bucket(
            "json.Unmarshal: UnmarshalTypeError text",
            "type_errors",
            MIN_CASES,
        );
    }

    #[test]
    fn json_decode_utf8() {
        run_decode_sink_bucket(
            "json.Unmarshal: invalid UTF-8 and lone surrogates",
            "utf8",
            MIN_CASES,
        );
    }
} // mod decode_sink

// --- the review's refuted cases, against `json_decode_adversarial.json`.
mod decode_adversarial {
    use super::*;
    use serde::Serialize;
    use std::collections::BTreeMap;

    #[derive(Deserialize, Serialize)]
    #[serde(rename = "main.AdvSub")]
    struct AdvSub {
        a: i32,
        b: i32,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename = "main.AdvInner")]
    #[allow(non_snake_case)]
    struct AdvInner {
        x: i32,
        y: String,
        ms: Option<BTreeMap<String, AdvSub>>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename = "main.Adv")]
    struct Adv {
        n: i32,
        s: String,
        nums: Option<Vec<i32>>,
        ptr: Option<i32>,
        pp: Option<AdvSub>,
        inner: AdvInner,
        list: Option<Vec<AdvSub>>,
        t: GoTime,
        tp: Option<GoTime>,
        raw: RawMessage,
        jn: Number,
        any: Value,
        arr: [i32; 2],
        bin: Bytes,
        f32: f32,
        im: Option<BTreeMap<i32, String>>,
        um: Option<BTreeMap<u8, String>>,
        nest: Option<Vec<Option<Vec<i32>>>>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename = "main.AdvFold")]
    #[allow(non_snake_case)]
    struct AdvFold {
        foo: String,
        FOO: String,
        #[serde(rename = "BAR")]
        Bar: String,
        #[serde(rename = "bar")]
        BAR: String,
    }

    #[derive(Deserialize)]
    struct AdvRec {
        #[allow(dead_code)]
        n: Option<Box<AdvRec>>,
    }

    #[derive(Deserialize)]
    struct AdvKeep {
        #[allow(dead_code)]
        keep: i32,
    }

    #[derive(Deserialize)]
    struct AdvRawHolder {
        #[allow(dead_code)]
        raw: RawMessage,
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn outcome<T: Serialize>(r: Result<T, json::DecodeError>) -> Result<Vec<u8>, String> {
        r.map(|v| json::marshal(&v).expect("marshal"))
            .map_err(|e| e.to_string())
    }

    fn want(c: &Value) -> Result<Vec<u8>, String> {
        match c.get("ok") {
            Some(ok) => Ok(bytes_of(ok)),
            None => Err(str_of(&c["err"])),
        }
    }

    fn decoder(c: &Value) -> Decoder {
        if c["disallow"].as_bool().unwrap_or(false) {
            Decoder::new().disallow_unknown_fields()
        } else {
            Decoder::new()
        }
    }

    #[test]
    fn json_decode_adversarial_documents() {
        let v = vector("json_decode_adversarial");
        let mut check = Check::new("json.Decoder.Decode: destination-kind semantics");
        for c in array(&v, "decode") {
            let doc = bytes_of(&c["doc"]);
            let label = || String::from_utf8_lossy(&doc).into_owned();
            let decoded = decoder(c).decode::<Adv>(&doc);
            if let (Ok(d), Some(raw)) = (&decoded, c.get("raw_hex")) {
                check.eq(
                    label,
                    hex(d.raw.as_bytes().unwrap_or_default()),
                    str_of(raw),
                );
            }
            check.eq(label, outcome(decoded), want(c));
        }
        for c in array(&v, "unmarshal") {
            let doc = bytes_of(&c["doc"]);
            check.eq(
                || String::from_utf8_lossy(&doc).into_owned(),
                outcome(json::unmarshal::<Adv>(&doc)),
                want(c),
            );
        }
        for c in array(&v, "fold") {
            let doc = bytes_of(&c["doc"]);
            check.eq(
                || String::from_utf8_lossy(&doc).into_owned(),
                outcome(decoder(c).decode::<AdvFold>(&doc)),
                want(c),
            );
        }
        check.finish(100);
    }

    struct OneByte<'a>(&'a [u8]);

    impl std::io::Read for OneByte<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let Some((first, rest)) = self.0.split_first() else {
                return Ok(0);
            };
            out[0] = *first;
            self.0 = rest;
            Ok(1)
        }
    }

    fn check_steps<R: std::io::Read>(
        check: &mut Check,
        doc: &[u8],
        steps: &[Value],
        mut stream: json::Stream<R>,
        compare_position: bool,
    ) {
        for (i, step) in steps.iter().enumerate() {
            let label = || format!("{} step {i}", String::from_utf8_lossy(doc));
            let got = stream.decode::<Adv>();
            let kind = match &got {
                Err(e) if e.is_eof() => "eof",
                Err(e) if e.is_unexpected_eof() => "unexpected",
                _ => "",
            };
            check.eq(label, kind, step["eof"].as_str().unwrap_or(""));
            check.eq(label, outcome(got), want(step));
            if compare_position {
                check.eq(
                    label,
                    stream.buffered().to_vec(),
                    bytes_of(&step["buffered"]),
                );
                check.eq(
                    label,
                    stream.input_offset() as i64,
                    step["offset"].as_i64().unwrap_or(-1),
                );
            }
        }
    }

    #[test]
    fn json_decode_streams() {
        let v = vector("json_decode_adversarial");
        let mut check = Check::new("json.Decoder: streams, Buffered, InputOffset, EOF");
        for c in array(&v, "streams") {
            let doc = bytes_of(&c["doc"]);
            let steps = array(c, "steps");
            check_steps(
                &mut check,
                &doc,
                steps,
                Decoder::new().stream(&doc[..]),
                true,
            );
            // A value split across reads must decode the same; only what is buffered differs.
            check_steps(
                &mut check,
                &doc,
                steps,
                Decoder::new().stream(OneByte(&doc)),
                false,
            );
            // A one-shot decode is the stream's first step.
            check.eq(
                || String::from_utf8_lossy(&doc).into_owned(),
                outcome(Decoder::new().decode::<Adv>(&doc)),
                want(&steps[0]),
            );
        }
        check.finish(20);
    }

    fn depth_doc(shape: &str, depth: usize) -> String {
        match shape {
            "any_array" => "[".repeat(depth) + &"]".repeat(depth),
            "unknown_array" => {
                format!(
                    r#"{{"zzz":{}{}}}"#,
                    "[".repeat(depth - 1),
                    "]".repeat(depth - 1)
                )
            }
            "any_object" | "rec" => r#"{"n":"#.repeat(depth - 1) + "{}" + &"}".repeat(depth - 1),
            "raw" => format!(
                r#"{{"raw":{}{}}}"#,
                "[".repeat(depth - 1),
                "]".repeat(depth - 1)
            ),
            other => panic!("{other}"),
        }
    }

    /// Runs on a 2 MiB thread, the default for a Tokio worker. An overflow aborts the test binary.
    #[test]
    fn json_decode_depth_on_a_small_stack() {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let v = vector("json_decode_adversarial");
                let mut check = Check::new("json.Decoder: nesting up to the 10,000 limit");
                for c in array(&v, "depth") {
                    let shape = str_of(&c["shape"]);
                    let depth = c["depth"].as_u64().expect("depth") as usize;
                    let doc = depth_doc(&shape, depth);
                    let dec = Decoder::new();
                    let err = match shape.as_str() {
                        "any_array" | "any_object" => {
                            dec.decode::<Value>(doc.as_bytes()).map(drop).err()
                        }
                        "unknown_array" => dec.decode::<AdvKeep>(doc.as_bytes()).map(drop).err(),
                        "rec" => dec.decode::<AdvRec>(doc.as_bytes()).map(drop).err(),
                        _ => dec.decode::<AdvRawHolder>(doc.as_bytes()).map(drop).err(),
                    };
                    let builds_value = matches!(shape.as_str(), "any_array" | "any_object" | "rec");
                    let want = if cfg!(debug_assertions)
                        && builds_value
                        && (1001..=10000).contains(&depth)
                    {
                        // A deliberate difference: see MAX_MATERIALIZED_DEPTH in json/decode.rs.
                        Some(
                            "json: nesting deeper than 1000 levels is not decoded in a debug build"
                                .to_string(),
                        )
                    } else {
                        c.get("err").map(str_of)
                    };
                    check.eq(
                        || format!("{shape} {depth}"),
                        err.map(|e| e.to_string()),
                        want,
                    );
                }
                if !cfg!(debug_assertions) {
                    let doc = depth_doc("any_array", 10000);
                    let v: Value = json::unmarshal(doc.as_bytes()).expect("10,000 levels");
                    assert_eq!(json::marshal(&v).expect("marshal"), doc.as_bytes());
                }
                check.finish(20);
            })
            .expect("spawn")
            .join()
            .expect("no panic");
    }

    #[test]
    fn serde_defaults_survive_absent_and_null() {
        #[derive(Deserialize)]
        struct WithDefault {
            #[serde(default = "seven")]
            n: i32,
            #[serde(default = "some_seven")]
            p: Option<i32>,
        }
        fn seven() -> i32 {
            7
        }
        fn some_seven() -> Option<i32> {
            Some(7)
        }
        let absent: WithDefault = json::unmarshal(b"{}").expect("absent");
        assert_eq!((absent.n, absent.p), (7, Some(7)));
        // Go leaves a set int alone on null, and sets a pointer to nil.
        let null: WithDefault = json::unmarshal(br#"{"n":null,"p":null}"#).expect("null");
        assert_eq!((null.n, null.p), (7, None));
    }
}

static COMMON_INPUTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let v = vector("regexp");
    array(&v, "common_inputs").iter().map(str_of).collect()
});

struct RegexRun {
    compile: Check,
    match_string: Check,
    submatch: Check,
    find_all: Check,
    replace: Check,
    split: Check,
}

fn offsets_of(v: &Value) -> Vec<isize> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_i64().unwrap() as isize).collect())
        .unwrap_or_default()
}

fn check_regex_input(
    run: &mut RegexRun,
    re: &GoRegex,
    template: &str,
    input: &str,
    case: Option<&Value>,
) {
    let ctx = || format!("{:?} on {input:?}", re.as_str());
    let want_m = case.and_then(|c| c.get("m")).map(offsets_of);
    run.submatch
        .eq(ctx, re.find_string_submatch_index(input), want_m.clone());
    run.match_string
        .eq(ctx, re.match_string(input), want_m.is_some());
    run.match_string.eq(
        ctx,
        re.find_string_index(input)
            .map(|(a, b)| vec![a as isize, b as isize]),
        want_m.as_ref().map(|m| m[..2].to_vec()),
    );
    if let (Some(m), Some(subs)) = (&want_m, re.find_string_submatch(input)) {
        let expected: Vec<String> = m
            .chunks(2)
            .map(|p| {
                if p[0] < 0 {
                    String::new()
                } else {
                    input[p[0] as usize..p[1] as usize].to_string()
                }
            })
            .collect();
        run.submatch.eq(
            ctx,
            subs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            expected,
        );
    }

    let want_all: Vec<Vec<isize>> = match case.and_then(|c| c.get("all")) {
        Some(all) => all.as_array().unwrap().iter().map(offsets_of).collect(),
        None => want_m.iter().cloned().collect(),
    };
    run.find_all.eq(
        ctx,
        re.find_all_string_submatch_index(input, -1),
        want_all.clone(),
    );
    run.find_all.eq(
        ctx,
        re.find_all_string_index(input, -1),
        want_all
            .iter()
            .map(|m| (m[0] as usize, m[1] as usize))
            .collect(),
    );
    run.find_all.eq(
        ctx,
        re.find_all_string(input, -1)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        want_all
            .iter()
            .map(|m| input[m[0] as usize..m[1] as usize].to_string())
            .collect::<Vec<_>>(),
    );

    // The first n accepted matches, by how allMatches counts.
    run.find_all.eq(
        ctx,
        re.find_all_string_submatch_index(input, 2),
        want_all.iter().take(2).cloned().collect(),
    );
    run.find_all
        .eq(ctx, re.find_all_string_submatch_index(input, 0), Vec::new());
    run.find_all.eq(
        ctx,
        re.find_all_string_submatch(input, -1)
            .iter()
            .map(|m| m.iter().map(ToString::to_string).collect())
            .collect::<Vec<Vec<String>>>(),
        want_all
            .iter()
            .map(|m| {
                m.chunks(2)
                    .map(|p| {
                        if p[0] < 0 {
                            String::new()
                        } else {
                            input[p[0] as usize..p[1] as usize].to_string()
                        }
                    })
                    .collect()
            })
            .collect::<Vec<Vec<String>>>(),
    );
    run.match_string.eq(
        ctx,
        re.find_string(input).to_string(),
        want_m.as_ref().map_or_else(String::new, |m| {
            input[m[0] as usize..m[1] as usize].to_string()
        }),
    );
    let want_func = case
        .and_then(|c| c.get("func"))
        .map_or_else(|| input.to_string(), str_of);
    run.replace.eq(
        ctx,
        re.replace_all_string_func(input, |m| format!("[{}]", strings::to_upper(m))),
        want_func,
    );

    let want_rep = case
        .and_then(|c| c.get("rep"))
        .map_or_else(|| input.to_string(), str_of);
    run.replace
        .eq(ctx, re.replace_all_string(input, template), want_rep);
    let want_lit = case
        .and_then(|c| c.get("lit"))
        .map_or_else(|| input.to_string(), str_of);
    run.replace
        .eq(ctx, re.replace_all_literal_string(input, "lit$1"), want_lit);

    let matched = !want_all.is_empty();
    let want_split: Vec<String> = match case.and_then(|c| c.get("split")) {
        Some(s) => s.as_array().unwrap().iter().map(str_of).collect(),
        // Go's nil and empty are the same here: a match that consumes everything splits to nothing.
        None if matched => Vec::new(),
        None => vec![input.to_string()],
    };
    run.split.eq(
        ctx,
        re.split(input, -1)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        want_split,
    );
    let want_split2: Vec<String> = match case.and_then(|c| c.get("split2")) {
        Some(s) => s.as_array().unwrap().iter().map(str_of).collect(),
        None if matched => Vec::new(),
        None => vec![input.to_string()],
    };
    run.split.eq(
        ctx,
        re.split(input, 2)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        want_split2,
    );
    run.split.eq(ctx, re.split(input, 0).len(), 0);
}

#[test]
fn regexp_vectors() {
    let v = vector("regexp");
    let template = v["template"].as_str().unwrap();
    let mut run = RegexRun {
        compile: Check::new("regexp.Compile"),
        match_string: Check::new("Regexp.MatchString, FindStringIndex"),
        submatch: Check::new("Regexp.FindStringSubmatch(Index)"),
        find_all: Check::new("Regexp.FindAll*"),
        replace: Check::new("Regexp.ReplaceAll(Literal)String"),
        split: Check::new("Regexp.Split"),
    };
    let mut tree_patterns = 0;
    for p in array(&v, "patterns") {
        let pattern = str_of(&p["p"]);
        let compiled = GoRegex::compile(&pattern);
        let got_err = compiled.as_ref().err().map(ToString::to_string);
        let want_err = p.get("err").map(str_of);
        run.compile.eq(
            || format!("{:?}", shorten(&pattern)),
            got_err.map(|e| shorten(&e)),
            want_err.map(|e| shorten(&e)),
        );
        let Ok(re) = compiled else {
            continue;
        };
        if p["source"] == "tree" {
            tree_patterns += 1;
        }
        let want_names: Vec<String> = array(p, "names")
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect();
        for name in want_names.iter().skip(1) {
            if !name.is_empty() {
                run.compile.eq(
                    || pattern.clone(),
                    re.subexp_index(name),
                    want_names.iter().position(|n| n == name),
                );
            }
        }
        run.compile
            .eq(|| pattern.clone(), re.num_subexp(), want_names.len() - 1);
        run.compile
            .eq(|| pattern.clone(), re.subexp_names().to_vec(), want_names);

        let cases = p
            .get("cases")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut by_common: HashMap<usize, &Value> = HashMap::new();
        for c in &cases {
            match c.get("i") {
                Some(i) => {
                    by_common.insert(i.as_u64().unwrap() as usize, c);
                }
                None => check_regex_input(&mut run, &re, template, &str_of(&c["in"]), Some(c)),
            }
        }
        if p.get("common").is_some() {
            for (i, input) in COMMON_INPUTS.iter().enumerate() {
                check_regex_input(&mut run, &re, template, input, by_common.get(&i).copied());
            }
        }
    }
    assert!(
        tree_patterns >= 200,
        "only {tree_patterns} patterns from the Go tree"
    );
    run.compile.finish(MIN_CASES);
    run.match_string.finish(MIN_CASES);
    run.submatch.finish(MIN_CASES);
    run.find_all.finish(MIN_CASES);
    run.replace.finish(MIN_CASES);
    run.split.finish(MIN_CASES);

    let mut quote = Check::new("regexp.QuoteMeta");
    for c in array(&v, "quote_meta") {
        let input = str_of(&c["in"]);
        quote.eq(
            || format!("{input:?}"),
            quote_meta(&input),
            str_of(&c["out"]),
        );
    }
    quote.finish(MIN_CASES);
}

fn shorten(s: &str) -> String {
    if s.len() <= 200 {
        return s.to_string();
    }
    let digest = Sha256::digest(s.as_bytes());
    let cut = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= 100)
        .last()
        .unwrap_or(0);
    format!("{}...<{} bytes {digest:x}>", &s[..cut], s.len())
}

/// The bans in `clippy.toml` steer callers here, so these are the swaps that have to hold on sight.
#[test]
fn documented_divergences_from_rust_std() {
    assert_eq!(strings::to_lower("İ"), "i");
    assert_eq!(strings::to_lower("ΣΑΣ"), "σασ");
    assert_eq!(strings::to_upper("ß"), "ß");
    assert_eq!(json::marshal(&120.0_f64).unwrap(), b"120");
    assert_eq!(
        json::marshal_to_string("<&>").unwrap(),
        "\"\\u003c\\u0026\\u003e\""
    );
    assert!(!GoRegex::must_compile(r"^\d$").match_string("٣"));
    assert!(!GoRegex::must_compile(r"^\s$").match_string("\u{00a0}"));
    assert!(GoRegex::must_compile(r"\bx\b").match_string("éxé"));
    assert_eq!(path::clean(""), ".");
    assert_eq!(path::ext(".bashrc"), ".bashrc");
}
