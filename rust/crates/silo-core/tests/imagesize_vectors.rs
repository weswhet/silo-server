//! Go's `internal/imagesize` output, checked here. Regenerate with
//! `rust/conformance/vectors/generators/imagesize/run.sh`.

#![allow(clippy::disallowed_methods)] // Plain relative paths to test data.

use serde_json::{Value, json};
use silo_core::imagesize::{self, SLOTS, Size, Widths};

#[test]
fn go_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/core/imagesize.json"
    );
    let cases: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(cases.len() > 500);
    let s = |v: &Value| v.as_str().unwrap().to_owned();
    for case in &cases {
        let got = match case["fn"].as_str().unwrap() {
            "parse" => {
                let mut c = json!({"fn": "parse", "raw": case["raw"]});
                match imagesize::parse(&s(&case["raw"])) {
                    Ok(size) => c["size"] = json!(size.0),
                    Err(e) => {
                        c["size"] = json!("");
                        c["err"] = json!(e);
                    }
                }
                c
            }
            "size" => {
                let size = Size(s(&case["size"]));
                let t = size.target_width();
                json!({"fn": "size", "size": size.0, "target": t.unwrap_or(0), "ok": t.is_some(),
                    "plugin": imagesize::plugin_variant(&size), "photo": imagesize::photo_plugin_variant(&size)})
            }
            "variant" => json!({"fn": "variant", "type": case["type"], "size": case["size"],
                "out": imagesize::variant(&s(&case["type"]), &Size(s(&case["size"])))}),
            "width_px" => {
                let px = imagesize::variant_width_px(&s(&case["variant"]));
                json!({"fn": "width_px", "variant": case["variant"], "px": px.unwrap_or(0), "ok": px.is_some()})
            }
            "next_lower" => {
                let n = imagesize::next_lower(&s(&case["type"]), &s(&case["variant"]));
                json!({"fn": "next_lower", "type": case["type"], "variant": case["variant"],
                    "ok": n.is_some(), "out": n.unwrap_or_default()})
            }
            "widths" => {
                let w: Vec<i64> = serde_json::from_value(case["widths"].clone()).unwrap();
                let widths = Widths {
                    poster: w[0],
                    backdrop: w[1],
                    logo: w[2],
                    still: w[3],
                    photo: w[4],
                };
                let req = imagesize::Request {
                    size: Size(s(&case["size"])),
                    widths,
                };
                let fors: Vec<String> = SLOTS
                    .iter()
                    .map(|slot| format!("{}={}", slot.name(), req.for_slot(*slot).0))
                    .collect();
                json!({"fn": "widths", "widths": case["widths"], "size": case["size"],
                    "encode": widths.encode(), "zero": widths.is_zero(), "for": fors})
            }
            other => panic!("unknown fn {other}"),
        };
        assert_eq!(&got, case, "case {case}");
    }
}
