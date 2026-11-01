//! `cron.Parser`.

use super::spec::{ConstantDelaySchedule, STAR_BIT, Schedule, SpecSchedule, every};
use super::time::Location;
use crate::goparse::atoi;
use silo_gocompat::strings::{fields, to_lower};
use silo_gocompat::time::parse_duration;

/// Seconds field, default 0.
pub const SECOND: u32 = 1 << 0;
/// Optional seconds field, default 0.
pub const SECOND_OPTIONAL: u32 = 1 << 1;
/// Minutes field, default 0.
pub const MINUTE: u32 = 1 << 2;
/// Hours field, default 0.
pub const HOUR: u32 = 1 << 3;
/// Day of month field, default *.
pub const DOM: u32 = 1 << 4;
/// Month field, default *.
pub const MONTH: u32 = 1 << 5;
/// Day of week field, default *.
pub const DOW: u32 = 1 << 6;
/// Optional day of week field, default *.
pub const DOW_OPTIONAL: u32 = 1 << 7;
/// Allow descriptors such as @monthly, @weekly, etc.
pub const DESCRIPTOR: u32 = 1 << 8;

const PLACES: [u32; 6] = [SECOND, MINUTE, HOUR, DOM, MONTH, DOW];
const DEFAULTS: [&str; 6] = ["0", "0", "0", "*", "*", "*"];

/// `cron.Parser`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parser {
    options: u32,
}

#[derive(Clone, Copy)]
struct Bounds {
    min: u64,
    max: u64,
    names: Option<&'static [(&'static str, u64)]>,
}

const SECONDS: Bounds = Bounds {
    min: 0,
    max: 59,
    names: None,
};
const MINUTES: Bounds = Bounds {
    min: 0,
    max: 59,
    names: None,
};
const HOURS: Bounds = Bounds {
    min: 0,
    max: 23,
    names: None,
};
const DOM_BOUNDS: Bounds = Bounds {
    min: 1,
    max: 31,
    names: None,
};
const MONTHS: Bounds = Bounds {
    min: 1,
    max: 12,
    names: Some(&[
        ("jan", 1),
        ("feb", 2),
        ("mar", 3),
        ("apr", 4),
        ("may", 5),
        ("jun", 6),
        ("jul", 7),
        ("aug", 8),
        ("sep", 9),
        ("oct", 10),
        ("nov", 11),
        ("dec", 12),
    ]),
};
const DOW_BOUNDS: Bounds = Bounds {
    min: 0,
    max: 6,
    names: Some(&[
        ("sun", 0),
        ("mon", 1),
        ("tue", 2),
        ("wed", 3),
        ("thu", 4),
        ("fri", 5),
        ("sat", 6),
    ]),
};

impl Parser {
    /// `cron.NewParser`. It panics when more than one optional is given, as in Go.
    pub fn new(options: u32) -> Parser {
        let mut optionals = 0;
        if options & DOW_OPTIONAL > 0 {
            optionals += 1;
        }
        if options & SECOND_OPTIONAL > 0 {
            optionals += 1;
        }
        assert!(optionals <= 1, "multiple optionals may not be configured");
        Parser { options }
    }

    /// `Parser.Parse`.
    ///
    /// A spec that starts with `TZ=` or `CRON_TZ=` and has no space panics with Go's slice bounds
    /// message, because robfig v3.0.1 does.
    pub fn parse(&self, spec: &str) -> Result<Schedule, String> {
        if spec.is_empty() {
            return Err("empty spec string".to_owned());
        }
        let mut spec = spec;
        let mut loc = Location::Local;
        if spec.starts_with("TZ=") || spec.starts_with("CRON_TZ=") {
            let eq = spec.find('=').unwrap_or(0);
            // robfig slices spec[eq+1:i] with i of -1.
            let Some(i) = spec.find(' ') else {
                panic!("runtime error: slice bounds out of range [:-1]");
            };
            let name = &spec[eq + 1..i];
            loc = Location::load(name).map_err(|e| format!("provided bad location {name}: {e}"))?;
            spec = silo_gocompat::strings::trim_space(&spec[i..]);
        }
        if spec.starts_with('@') {
            if self.options & DESCRIPTOR == 0 {
                return Err(format!("parser does not accept descriptors: {spec}"));
            }
            return parse_descriptor(spec, &loc);
        }
        let split = fields(spec);
        let normalized = normalize_fields(&split, self.options)?;
        let second = get_field(&normalized[0], SECONDS)?;
        let minute = get_field(&normalized[1], MINUTES)?;
        let hour = get_field(&normalized[2], HOURS)?;
        let dom = get_field(&normalized[3], DOM_BOUNDS)?;
        let month = get_field(&normalized[4], MONTHS)?;
        let dow = get_field(&normalized[5], DOW_BOUNDS)?;
        Ok(Schedule::Spec(SpecSchedule {
            second,
            minute,
            hour,
            dom,
            month,
            dow,
            location: loc,
        }))
    }
}

/// `cron.ParseStandard`: minute, hour, day of month, month, day of week, plus descriptors.
pub fn parse_standard(spec: &str) -> Result<Schedule, String> {
    Parser::new(MINUTE | HOUR | DOM | MONTH | DOW | DESCRIPTOR).parse(spec)
}

fn go_list(items: &[&str]) -> String {
    format!("[{}]", items.join(" "))
}

fn normalize_fields(input: &[&str], options: u32) -> Result<Vec<String>, String> {
    let mut options = options;
    let mut optionals = 0;
    if options & SECOND_OPTIONAL > 0 {
        options |= SECOND;
        optionals += 1;
    }
    if options & DOW_OPTIONAL > 0 {
        options |= DOW;
        optionals += 1;
    }
    if optionals > 1 {
        return Err("multiple optionals may not be configured".to_owned());
    }
    let max = PLACES.iter().filter(|p| options & **p > 0).count();
    let min = max - optionals;
    let count = input.len();
    if count < min || count > max {
        if min == max {
            return Err(format!(
                "expected exactly {min} fields, found {count}: {}",
                go_list(input)
            ));
        }
        return Err(format!(
            "expected {min} to {max} fields, found {count}: {}",
            go_list(input)
        ));
    }
    let mut provided: Vec<&str> = input.to_vec();
    if min < max && count == min {
        if options & DOW_OPTIONAL > 0 {
            provided.push(DEFAULTS[5]);
        } else if options & SECOND_OPTIONAL > 0 {
            provided.insert(0, DEFAULTS[0]);
        } else {
            return Err("unknown optional field".to_owned());
        }
    }
    let mut expanded: Vec<String> = DEFAULTS.iter().map(|s| (*s).to_owned()).collect();
    let mut n = 0;
    for (i, place) in PLACES.iter().enumerate() {
        if options & place > 0 {
            expanded[i] = provided[n].to_owned();
            n += 1;
        }
    }
    Ok(expanded)
}

fn get_field(field: &str, r: Bounds) -> Result<u64, String> {
    let mut bits = 0u64;
    for expr in field.split(',').filter(|s| !s.is_empty()) {
        bits |= get_range(expr, r)?;
    }
    Ok(bits)
}

fn get_range(expr: &str, r: Bounds) -> Result<u64, String> {
    let range_and_step: Vec<&str> = expr.split('/').collect();
    let low_and_high: Vec<&str> = range_and_step[0].split('-').collect();
    let single_digit = low_and_high.len() == 1;
    let (start, mut end);
    let mut extra = 0u64;
    if low_and_high[0] == "*" || low_and_high[0] == "?" {
        start = r.min;
        end = r.max;
        extra = STAR_BIT;
    } else {
        start = parse_int_or_name(low_and_high[0], r.names)?;
        match low_and_high.len() {
            1 => end = start,
            2 => end = parse_int_or_name(low_and_high[1], r.names)?,
            _ => return Err(format!("too many hyphens: {expr}")),
        }
    }
    let step;
    match range_and_step.len() {
        1 => step = 1,
        2 => {
            step = must_parse_int(range_and_step[1])?;
            if single_digit {
                end = r.max;
            }
            if step > 1 {
                extra = 0;
            }
        }
        _ => return Err(format!("too many slashes: {expr}")),
    }
    if start < r.min {
        return Err(format!(
            "beginning of range ({start}) below minimum ({}): {expr}",
            r.min
        ));
    }
    if end > r.max {
        return Err(format!(
            "end of range ({end}) above maximum ({}): {expr}",
            r.max
        ));
    }
    if start > end {
        return Err(format!(
            "beginning of range ({start}) beyond end of range ({end}): {expr}"
        ));
    }
    if step == 0 {
        return Err(format!("step of range should be a positive number: {expr}"));
    }
    Ok(get_bits(start, end, step) | extra)
}

fn parse_int_or_name(
    expr: &str,
    names: Option<&'static [(&'static str, u64)]>,
) -> Result<u64, String> {
    if let Some(names) = names {
        let lowered = to_lower(expr);
        if let Some((_, v)) = names.iter().find(|(n, _)| *n == lowered) {
            return Ok(*v);
        }
    }
    must_parse_int(expr)
}

fn must_parse_int(expr: &str) -> Result<u64, String> {
    let num = atoi(expr).map_err(|e| format!("failed to parse int from {expr}: {e}"))?;
    if num < 0 {
        return Err(format!("negative number ({num}) not allowed: {expr}"));
    }
    Ok(num as u64)
}

fn get_bits(min: u64, max: u64, step: u64) -> u64 {
    if step == 1 {
        let high = u64::MAX.checked_shl((max + 1) as u32).unwrap_or(0);
        let low = u64::MAX.checked_shl(min as u32).unwrap_or(0);
        return !high & low;
    }
    let mut bits = 0u64;
    let mut i = min;
    while i <= max {
        bits |= 1u64.checked_shl(i as u32).unwrap_or(0);
        i += step;
    }
    bits
}

fn all(r: Bounds) -> u64 {
    get_bits(r.min, r.max, 1) | STAR_BIT
}

fn parse_descriptor(descriptor: &str, loc: &Location) -> Result<Schedule, String> {
    let spec = |second, minute, hour, dom, month, dow| {
        Ok(Schedule::Spec(SpecSchedule {
            second,
            minute,
            hour,
            dom,
            month,
            dow,
            location: loc.clone(),
        }))
    };
    let one = |r: Bounds| 1u64 << r.min;
    match descriptor {
        "@yearly" | "@annually" => {
            return spec(
                one(SECONDS),
                one(MINUTES),
                one(HOURS),
                one(DOM_BOUNDS),
                one(MONTHS),
                all(DOW_BOUNDS),
            );
        }
        "@monthly" => {
            return spec(
                one(SECONDS),
                one(MINUTES),
                one(HOURS),
                one(DOM_BOUNDS),
                all(MONTHS),
                all(DOW_BOUNDS),
            );
        }
        "@weekly" => {
            return spec(
                one(SECONDS),
                one(MINUTES),
                one(HOURS),
                all(DOM_BOUNDS),
                all(MONTHS),
                one(DOW_BOUNDS),
            );
        }
        "@daily" | "@midnight" => {
            return spec(
                one(SECONDS),
                one(MINUTES),
                one(HOURS),
                all(DOM_BOUNDS),
                all(MONTHS),
                all(DOW_BOUNDS),
            );
        }
        "@hourly" => {
            return spec(
                one(SECONDS),
                one(MINUTES),
                all(HOURS),
                all(DOM_BOUNDS),
                all(MONTHS),
                all(DOW_BOUNDS),
            );
        }
        _ => {}
    }
    if let Some(rest) = descriptor.strip_prefix("@every ") {
        let duration = parse_duration(rest)
            .map_err(|e| format!("failed to parse duration {descriptor}: {e}"))?;
        let ConstantDelaySchedule { delay } = every(duration.0);
        return Ok(Schedule::ConstantDelay(ConstantDelaySchedule { delay }));
    }
    Err(format!("unrecognized descriptor: {descriptor}"))
}
