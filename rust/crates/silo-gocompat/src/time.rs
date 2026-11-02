//! Port of Go's `time.Duration`, `time.ParseDuration`, `Time.Format`, and `time.Parse`.
//!
//! [`GoTime`] is an instant plus a fixed UTC offset, which is all of a `time.Time` that shows up in
//! these formats. Layouts with a zone abbreviation (`MST`) have limited support: formatting prints
//! `UTC` or a numeric offset, and parsing accepts only `UTC`, because no layout in the server parses
//! abbreviations and resolving them would need Go's local-zone database lookups.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `time.RFC3339`.
pub const RFC3339: &str = "2006-01-02T15:04:05Z07:00";
/// `time.RFC3339Nano`.
pub const RFC3339_NANO: &str = "2006-01-02T15:04:05.999999999Z07:00";
/// `time.DateOnly`.
pub const DATE_ONLY: &str = "2006-01-02";
/// `time.DateTime`.
pub const DATE_TIME: &str = "2006-01-02 15:04:05";
/// `time.TimeOnly`.
pub const TIME_ONLY: &str = "15:04:05";
/// `http.TimeFormat`.
pub const HTTP_TIME_FORMAT: &str = "Mon, 02 Jan 2006 15:04:05 GMT";

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// `time.quote`, which is not `strconv.Quote`: non-ASCII bytes print as `\x` escapes.
fn quote(s: &[u8]) -> String {
    let mut buf = String::with_capacity(s.len() + 2);
    buf.push('"');
    for &b in s {
        if !(b' '..0x80).contains(&b) {
            buf.push_str("\\x");
            buf.push(LOWER_HEX[usize::from(b >> 4)] as char);
            buf.push(LOWER_HEX[usize::from(b & 0xF)] as char);
        } else {
            if b == b'"' || b == b'\\' {
                buf.push('\\');
            }
            buf.push(b as char);
        }
    }
    buf.push('"');
    buf
}

/// `leadingInt`.
fn leading_int(s: &[u8]) -> Result<(u64, &[u8]), ()> {
    let mut x: u64 = 0;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            break;
        }
        if x > (1u64 << 63) / 10 {
            return Err(());
        }
        x = x * 10 + u64::from(c) - u64::from(b'0');
        if x > 1u64 << 63 {
            return Err(());
        }
        i += 1;
    }
    Ok((x, &s[i..]))
}

/// `leadingFraction`.
fn leading_fraction(s: &[u8]) -> (u64, f64, &[u8]) {
    let mut x: u64 = 0;
    let mut scale = 1f64;
    let mut overflow = false;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            break;
        }
        i += 1;
        if overflow {
            continue;
        }
        if x > ((1u64 << 63) - 1) / 10 {
            overflow = true;
            continue;
        }
        let y = x * 10 + u64::from(c) - u64::from(b'0');
        if y > 1u64 << 63 {
            overflow = true;
            continue;
        }
        x = y;
        scale *= 10.0;
    }
    (x, scale, &s[i..])
}

/// The error `time.ParseDuration` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurationError(String);

impl std::fmt::Display for DurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DurationError {}

/// `time.Duration`: signed nanoseconds, which is also its JSON encoding.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Duration(pub i64);

impl Duration {
    /// `time.Nanosecond`.
    pub const NANOSECOND: Self = Self(1);
    /// `time.Microsecond`.
    pub const MICROSECOND: Self = Self(1_000);
    /// `time.Millisecond`.
    pub const MILLISECOND: Self = Self(1_000_000);
    /// `time.Second`.
    pub const SECOND: Self = Self(1_000_000_000);
    /// `time.Minute`.
    pub const MINUTE: Self = Self(60_000_000_000);
    /// `time.Hour`.
    pub const HOUR: Self = Self(3_600_000_000_000);

    /// `Duration.Nanoseconds`.
    pub const fn nanoseconds(self) -> i64 {
        self.0
    }

    /// `Duration.Microseconds`.
    pub const fn microseconds(self) -> i64 {
        self.0 / 1_000
    }

    /// `Duration.Milliseconds`.
    pub const fn milliseconds(self) -> i64 {
        self.0 / 1_000_000
    }

    /// `Duration.Seconds`.
    pub fn seconds(self) -> f64 {
        let sec = self.0 / Self::SECOND.0;
        let nsec = self.0 % Self::SECOND.0;
        sec as f64 + nsec as f64 / 1e9
    }

    /// `Duration.Minutes`.
    pub fn minutes(self) -> f64 {
        let min = self.0 / Self::MINUTE.0;
        let nsec = self.0 % Self::MINUTE.0;
        min as f64 + nsec as f64 / (60.0 * 1e9)
    }

    /// `Duration.Hours`.
    pub fn hours(self) -> f64 {
        let hour = self.0 / Self::HOUR.0;
        let nsec = self.0 % Self::HOUR.0;
        hour as f64 + nsec as f64 / (60.0 * 60.0 * 1e9)
    }
}

/// `fmtFrac`, writing into a string that is built back to front.
fn fmt_frac(rev: &mut Vec<u8>, mut v: u64, prec: u32) -> u64 {
    let mut print = false;
    for _ in 0..prec {
        let digit = (v % 10) as u8;
        print = print || digit != 0;
        if print {
            rev.push(digit + b'0');
        }
        v /= 10;
    }
    if print {
        rev.push(b'.');
    }
    v
}

fn fmt_int(rev: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        rev.push(b'0');
    } else {
        while v > 0 {
            rev.push((v % 10) as u8 + b'0');
            v /= 10;
        }
    }
}

/// `Duration.String`.
impl std::fmt::Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let neg = self.0 < 0;
        let mut u = self.0.unsigned_abs();
        let mut rev: Vec<u8> = Vec::with_capacity(32);
        rev.push(b's');
        if u < 1_000_000_000 {
            if u == 0 {
                return f.write_str("0s");
            }
            let prec;
            if u < 1_000 {
                prec = 0;
                rev.push(b'n');
            } else if u < 1_000_000 {
                prec = 3;
                // U+00B5 micro sign, pushed in reverse.
                rev.extend_from_slice(&[0xB5, 0xC2]);
            } else {
                prec = 6;
                rev.push(b'm');
            }
            u = fmt_frac(&mut rev, u, prec);
            fmt_int(&mut rev, u);
        } else {
            u = fmt_frac(&mut rev, u, 9);
            fmt_int(&mut rev, u % 60);
            u /= 60;
            if u > 0 {
                rev.push(b'm');
                fmt_int(&mut rev, u % 60);
                u /= 60;
                // Stop at hours because days can be different lengths.
                if u > 0 {
                    rev.push(b'h');
                    fmt_int(&mut rev, u);
                }
            }
        }
        if neg {
            rev.push(b'-');
        }
        rev.reverse();
        f.write_str(std::str::from_utf8(&rev).unwrap_or_default())
    }
}

fn unit_nanos(unit: &[u8]) -> Option<u64> {
    // Both U+00B5 (micro sign) and U+03BC (Greek mu) spell microseconds.
    match unit {
        b"ns" => Some(1),
        b"us" | b"\xC2\xB5s" | b"\xCE\xBCs" => Some(1_000),
        b"ms" => Some(1_000_000),
        b"s" => Some(1_000_000_000),
        b"m" => Some(60_000_000_000),
        b"h" => Some(3_600_000_000_000),
        _ => None,
    }
}

/// `time.ParseDuration`. Takes bytes as well as strings, because Go strings can be invalid UTF-8.
pub fn parse_duration(input: impl AsRef<[u8]>) -> Result<Duration, DurationError> {
    let orig = input.as_ref();
    let invalid = || DurationError(format!("time: invalid duration {}", quote(orig)));
    let mut s = orig;
    let mut d: u64 = 0;
    let mut neg = false;

    // Consume [-+]?
    if let Some(&c) = s.first()
        && (c == b'-' || c == b'+')
    {
        neg = c == b'-';
        s = &s[1..];
    }
    // Special case: if all that is left is "0", this is zero.
    if s == b"0" {
        return Ok(Duration(0));
    }
    if s.is_empty() {
        return Err(invalid());
    }
    while !s.is_empty() {
        // The next character must be [0-9.]
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return Err(invalid());
        }
        // Consume [0-9]*
        let pl = s.len();
        let (mut v, rest) = leading_int(s).map_err(|()| invalid())?;
        s = rest;
        let pre = pl != s.len();

        // Consume (\.[0-9]*)?
        let mut post = false;
        let (mut f, mut scale) = (0u64, 1f64);
        if s.first() == Some(&b'.') {
            s = &s[1..];
            let pl = s.len();
            let (ff, ss, rest) = leading_fraction(s);
            f = ff;
            scale = ss;
            s = rest;
            post = pl != s.len();
        }
        if !pre && !post {
            // No digits (e.g. ".s" or "-.s").
            return Err(invalid());
        }

        // Consume the unit.
        let i = s
            .iter()
            .position(|&c| c == b'.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if i == 0 {
            return Err(DurationError(format!(
                "time: missing unit in duration {}",
                quote(orig)
            )));
        }
        let (u, rest) = s.split_at(i);
        s = rest;
        let Some(unit) = unit_nanos(u) else {
            return Err(DurationError(format!(
                "time: unknown unit {} in duration {}",
                quote(u),
                quote(orig)
            )));
        };
        if v > (1u64 << 63) / unit {
            return Err(invalid());
        }
        v *= unit;
        if f > 0 {
            // float64 is needed to be nanosecond accurate for fractions of hours.
            v = v.wrapping_add((f as f64 * (unit as f64 / scale)) as u64);
            if v > 1u64 << 63 {
                return Err(invalid());
            }
        }
        d = d.wrapping_add(v);
        if d > 1u64 << 63 {
            return Err(invalid());
        }
    }
    if neg {
        return Ok(Duration((d as i64).wrapping_neg()));
    }
    if d > (1u64 << 63) - 1 {
        return Err(invalid());
    }
    Ok(Duration(d as i64))
}

/// Seconds between 0001-01-01 and 1970-01-01. Go's zero `Time` is 0001-01-01T00:00:00Z.
const UNIX_TO_INTERNAL: i64 = 62_135_596_800;

/// `time.Time` reduced to an instant and a fixed UTC offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoTime {
    unix_secs: i64,
    nanos: u32,
    offset: i32,
    /// True for Go's `time.UTC` location, which `MST` prints as `UTC`.
    utc: bool,
}

impl Default for GoTime {
    /// The zero value, like `time.Time{}`.
    fn default() -> Self {
        Self::ZERO
    }
}

impl GoTime {
    /// `time.Time{}`: 0001-01-01T00:00:00Z.
    pub const ZERO: Self = Self {
        unix_secs: -UNIX_TO_INTERNAL,
        nanos: 0,
        offset: 0,
        utc: true,
    };

    /// A UTC instant. Nanoseconds above one second carry into the seconds, as in `time.Unix`.
    pub const fn from_unix(secs: i64, nanos: u32) -> Self {
        Self {
            unix_secs: secs + (nanos / 1_000_000_000) as i64,
            nanos: nanos % 1_000_000_000,
            offset: 0,
            utc: true,
        }
    }

    /// The same instant with a fixed offset, like `t.In(time.FixedZone("", offset))`.
    pub const fn with_offset(self, offset_secs: i32) -> Self {
        Self {
            offset: offset_secs,
            utc: false,
            ..self
        }
    }

    /// The instant as a system clock reading.
    pub fn to_system_time(self) -> std::time::SystemTime {
        let epoch = std::time::UNIX_EPOCH;
        if self.unix_secs >= 0 {
            epoch + std::time::Duration::new(self.unix_secs as u64, self.nanos)
        } else {
            epoch - std::time::Duration::from_secs(self.unix_secs.unsigned_abs())
                + std::time::Duration::from_nanos(u64::from(self.nanos))
        }
    }

    /// `Time.UTC`.
    pub const fn to_utc(self) -> Self {
        Self {
            offset: 0,
            utc: true,
            ..self
        }
    }

    /// The current time in UTC.
    pub fn now_utc() -> Self {
        Self::from_system_time(std::time::SystemTime::now())
    }

    /// A system clock reading, in UTC.
    pub fn from_system_time(time: std::time::SystemTime) -> Self {
        match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Self::from_unix(d.as_secs() as i64, d.subsec_nanos()),
            Err(e) => {
                let d = e.duration();
                let (secs, nanos) = (d.as_secs() as i64, d.subsec_nanos());
                if nanos == 0 {
                    Self::from_unix(-secs, 0)
                } else {
                    Self::from_unix(-secs - 1, 1_000_000_000 - nanos)
                }
            }
        }
    }

    /// `Time.Unix`.
    pub const fn unix(self) -> i64 {
        self.unix_secs
    }

    /// `Time.Nanosecond`.
    pub const fn nanosecond(self) -> u32 {
        self.nanos
    }

    /// The UTC offset in seconds.
    pub const fn offset(self) -> i32 {
        self.offset
    }

    /// `Time.IsZero`: true for the zero instant in any zone.
    pub const fn is_zero(&self) -> bool {
        self.unix_secs == -UNIX_TO_INTERNAL && self.nanos == 0
    }

    /// `Time.Equal`: the same instant, whatever the offset.
    pub const fn equal(self, other: Self) -> bool {
        self.unix_secs == other.unix_secs && self.nanos == other.nanos
    }

    fn local_secs(self) -> i64 {
        self.unix_secs + i64::from(self.offset)
    }

    /// `Time.Date`: year, month, and day in this time's offset.
    pub fn date(self) -> (i64, u32, u32) {
        civil_from_days(self.local_secs().div_euclid(86400))
    }

    /// `Time.Clock`: hour, minute, and second in this time's offset.
    pub fn clock(self) -> (u32, u32, u32) {
        let s = self.local_secs().rem_euclid(86400) as u32;
        (s / 3600, s % 3600 / 60, s % 60)
    }

    /// `Time.Format`.
    pub fn format(self, layout: &str) -> String {
        let local = self.local_secs();
        let days = local.div_euclid(86400);
        let (year, month, day) = civil_from_days(days);
        let (hour, min, sec) = self.clock();
        let offset = i64::from(self.offset);
        let mut b = String::with_capacity(layout.len() + 10);
        let mut rest = layout;
        while !rest.is_empty() {
            let (prefix, std, suffix) = next_std_chunk(rest);
            b.push_str(prefix);
            let Some(std) = std else {
                break;
            };
            rest = suffix;
            match std {
                Std::Year => append_int(&mut b, year.abs() % 100, 2),
                Std::LongYear => append_int(&mut b, year, 4),
                Std::Month => b.push_str(&LONG_MONTHS[month as usize - 1][..3]),
                Std::LongMonth => b.push_str(LONG_MONTHS[month as usize - 1]),
                Std::NumMonth => append_int(&mut b, i64::from(month), 0),
                Std::ZeroMonth => append_int(&mut b, i64::from(month), 2),
                Std::WeekDay => b.push_str(&LONG_DAYS[weekday(days)][..3]),
                Std::LongWeekDay => b.push_str(LONG_DAYS[weekday(days)]),
                Std::Day => append_int(&mut b, i64::from(day), 0),
                Std::UnderDay => {
                    if day < 10 {
                        b.push(' ');
                    }
                    append_int(&mut b, i64::from(day), 0);
                }
                Std::ZeroDay => append_int(&mut b, i64::from(day), 2),
                Std::UnderYearDay | Std::ZeroYearDay => {
                    let yday = i64::from(day) + i64::from(days_before(month));
                    let yday = if is_leap(year) && month > 2 {
                        yday + 1
                    } else {
                        yday
                    };
                    if std == Std::UnderYearDay {
                        if yday < 100 {
                            b.push(' ');
                            if yday < 10 {
                                b.push(' ');
                            }
                        }
                        append_int(&mut b, yday, 0);
                    } else {
                        append_int(&mut b, yday, 3);
                    }
                }
                Std::Hour => append_int(&mut b, i64::from(hour), 2),
                Std::Hour12 => append_int(&mut b, i64::from(hour12(hour)), 0),
                Std::ZeroHour12 => append_int(&mut b, i64::from(hour12(hour)), 2),
                Std::Minute => append_int(&mut b, i64::from(min), 0),
                Std::ZeroMinute => append_int(&mut b, i64::from(min), 2),
                Std::Second => append_int(&mut b, i64::from(sec), 0),
                Std::ZeroSecond => append_int(&mut b, i64::from(sec), 2),
                Std::Pm => b.push_str(if hour >= 12 { "PM" } else { "AM" }),
                Std::PmLower => b.push_str(if hour >= 12 { "pm" } else { "am" }),
                Std::Iso8601Tz
                | Std::Iso8601ColonTz
                | Std::Iso8601SecondsTz
                | Std::Iso8601ShortTz
                | Std::Iso8601ColonSecondsTz
                | Std::NumTz
                | Std::NumColonTz
                | Std::NumSecondsTz
                | Std::NumShortTz
                | Std::NumColonSecondsTz => {
                    // The "Z" variants print Z for a zero offset.
                    let is_z = matches!(
                        std,
                        Std::Iso8601Tz
                            | Std::Iso8601ColonTz
                            | Std::Iso8601SecondsTz
                            | Std::Iso8601ShortTz
                            | Std::Iso8601ColonSecondsTz
                    );
                    if offset == 0 && is_z {
                        b.push('Z');
                        continue;
                    }
                    let mut zone = offset / 60;
                    let mut abs_offset = offset;
                    if zone < 0 {
                        b.push('-');
                        zone = -zone;
                        abs_offset = -abs_offset;
                    } else {
                        b.push('+');
                    }
                    append_int(&mut b, zone / 60, 2);
                    let colon = matches!(
                        std,
                        Std::Iso8601ColonTz
                            | Std::NumColonTz
                            | Std::Iso8601ColonSecondsTz
                            | Std::NumColonSecondsTz
                    );
                    if colon {
                        b.push(':');
                    }
                    if !matches!(std, Std::NumShortTz | Std::Iso8601ShortTz) {
                        append_int(&mut b, zone % 60, 2);
                    }
                    if matches!(
                        std,
                        Std::Iso8601SecondsTz
                            | Std::NumSecondsTz
                            | Std::NumColonSecondsTz
                            | Std::Iso8601ColonSecondsTz
                    ) {
                        if matches!(std, Std::NumColonSecondsTz | Std::Iso8601ColonSecondsTz) {
                            b.push(':');
                        }
                        append_int(&mut b, abs_offset % 60, 2);
                    }
                }
                Std::Tz => {
                    if self.utc {
                        b.push_str("UTC");
                        continue;
                    }
                    let mut zone = offset / 60;
                    if zone < 0 {
                        b.push('-');
                        zone = -zone;
                    } else {
                        b.push('+');
                    }
                    append_int(&mut b, zone / 60, 2);
                    append_int(&mut b, zone % 60, 2);
                }
                Std::FracSecond0 { digits, sep } => {
                    append_nano(&mut b, self.nanos, digits, sep, false)
                }
                Std::FracSecond9 { digits, sep } => {
                    append_nano(&mut b, self.nanos, digits, sep, true)
                }
            }
        }
        b
    }

    /// `t.Format(time.RFC3339)`.
    pub fn rfc3339(self) -> String {
        self.format(RFC3339)
    }

    /// `t.Format(time.RFC3339Nano)`. Trailing fractional zeros are removed, so the zero value prints
    /// `0001-01-01T00:00:00Z`.
    pub fn rfc3339_nano(self) -> String {
        self.format(RFC3339_NANO)
    }

    /// `Time.MarshalJSON` without the quotes: RFC 3339 with nanoseconds, or Go's error for a time
    /// that RFC 3339 cannot hold.
    pub fn marshal_text(self) -> Result<String, String> {
        let b = self.rfc3339_nano();
        let bytes = b.as_bytes();
        if bytes.get(4) != Some(&b'-') {
            return Err("Time.MarshalJSON: year outside of range [0,9999]".to_string());
        }
        if bytes.last() != Some(&b'Z') {
            let c = bytes[bytes.len() - 6];
            let tail = &bytes[bytes.len() - 5..];
            let hour =
                u32::from(tail[0].wrapping_sub(b'0')) * 10 + u32::from(tail[1].wrapping_sub(b'0'));
            if c.is_ascii_digit() || hour >= 24 {
                return Err("Time.MarshalJSON: timezone hour outside of range [0,23]".to_string());
            }
        }
        Ok(b)
    }
}

#[cfg(feature = "time")]
impl From<time::OffsetDateTime> for GoTime {
    fn from(t: time::OffsetDateTime) -> Self {
        Self::from_unix(t.unix_timestamp(), t.nanosecond()).with_offset(t.offset().whole_seconds())
    }
}

impl Serialize for GoTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.marshal_text() {
            Ok(text) => serializer.serialize_str(&text),
            Err(err) => Err(serde::ser::Error::custom(format!(
                "json: error calling MarshalJSON for type time.Time: {err}"
            ))),
        }
    }
}

/// `Time.UnmarshalJSON` on a non-`null` literal, which reads it raw, without unescaping.
pub(crate) fn unmarshal_json_literal(raw: &[u8]) -> Result<GoTime, String> {
    let inner = raw
        .strip_prefix(b"\"")
        .and_then(|t| t.strip_suffix(b"\""))
        .ok_or_else(|| "Time.UnmarshalJSON: input is not a JSON string".to_string())?;
    parse_bytes(RFC3339, inner).map_err(|e| e.to_string())
}

impl<'de> Deserialize<'de> for GoTime {
    /// `Time.UnmarshalJSON`. `null` leaves the zero value, and an earlier value under a repeated
    /// key. Deserializers other than `json::unmarshal` and `json::Decoder` must be `serde_json`'s.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = GoTime;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON string holding an RFC 3339 time")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<GoTime, E> {
                Ok(GoTime::ZERO)
            }

            fn visit_byte_buf<E: serde::de::Error>(self, raw: Vec<u8>) -> Result<GoTime, E> {
                unmarshal_json_literal(&raw).map_err(E::custom)
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<GoTime, D::Error> {
                let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
                if raw.get() == "null" {
                    return Ok(GoTime::ZERO);
                }
                unmarshal_json_literal(raw.get().as_bytes()).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_newtype_struct(crate::json::TIME_TOKEN, V)
    }
}

/// `time.ParseError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    layout: Vec<u8>,
    value: Vec<u8>,
    layout_elem: Vec<u8>,
    value_elem: Vec<u8>,
    message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(
                f,
                "parsing time {} as {}: cannot parse {} as {}",
                quote(&self.value),
                quote(&self.layout),
                quote(&self.value_elem),
                quote(&self.layout_elem)
            )
        } else {
            write!(f, "parsing time {}{}", quote(&self.value), self.message)
        }
    }
}

impl std::error::Error for ParseError {}

const LONG_DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const LONG_MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Days before the 1st of a month in a non-leap year, with `days_before(13)` the whole year.
fn days_before(month: u32) -> u32 {
    const TABLE: [u32; 13] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];
    TABLE[month as usize - 1]
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in(month: i64, year: i64) -> i64 {
    if month == 2 {
        return if is_leap(year) { 29 } else { 28 };
    }
    30 + ((month + (month >> 3)) & 1)
}

fn weekday(days_since_epoch: i64) -> usize {
    // 1970-01-01 was a Thursday.
    (days_since_epoch + 4).rem_euclid(7) as usize
}

fn hour12(hour: u32) -> u32 {
    let hr = hour % 12;
    if hr == 0 { 12 } else { hr }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn append_int(b: &mut String, x: i64, width: usize) {
    if x < 0 {
        b.push('-');
    }
    let digits = x.unsigned_abs().to_string();
    for _ in digits.len()..width {
        b.push('0');
    }
    b.push_str(&digits);
}

fn append_nano(b: &mut String, nanos: u32, digits: usize, sep: u8, trim: bool) {
    if trim && (digits == 0 || nanos == 0) {
        return;
    }
    let mark = b.len();
    b.push(sep as char);
    append_int(b, i64::from(nanos), 9);
    if digits < 9 {
        b.truncate(b.len() - 9 + digits);
    }
    if trim {
        while b.len() > mark && b.ends_with('0') {
            b.pop();
        }
        if b.len() > mark && b.as_bytes()[b.len() - 1] == sep {
            b.pop();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Std {
    LongMonth,
    Month,
    NumMonth,
    ZeroMonth,
    LongWeekDay,
    WeekDay,
    Day,
    UnderDay,
    ZeroDay,
    UnderYearDay,
    ZeroYearDay,
    Hour,
    Hour12,
    ZeroHour12,
    Minute,
    ZeroMinute,
    Second,
    ZeroSecond,
    LongYear,
    Year,
    Pm,
    PmLower,
    Tz,
    Iso8601Tz,
    Iso8601SecondsTz,
    Iso8601ShortTz,
    Iso8601ColonTz,
    Iso8601ColonSecondsTz,
    NumTz,
    NumSecondsTz,
    NumShortTz,
    NumColonTz,
    NumColonSecondsTz,
    FracSecond0 { digits: usize, sep: u8 },
    FracSecond9 { digits: usize, sep: u8 },
}

fn starts_with_lower(s: &[u8]) -> bool {
    s.first().is_some_and(u8::is_ascii_lowercase)
}

/// `nextStdChunk`: the literal prefix, the layout element, and the remainder.
fn next_std_chunk(layout: &str) -> (&str, Option<Std>, &str) {
    let l = layout.as_bytes();
    let at = |i: usize, len: usize| l.get(i..i + len);
    let hit = |i: usize, std: Std, len: usize| (&layout[..i], Some(std), &layout[i + len..]);
    for i in 0..l.len() {
        match l[i] {
            b'J' => {
                if at(i, 3) == Some(b"Jan") {
                    if at(i, 7) == Some(b"January") {
                        return hit(i, Std::LongMonth, 7);
                    }
                    if !starts_with_lower(&l[i + 3..]) {
                        return hit(i, Std::Month, 3);
                    }
                }
            }
            b'M' => {
                if at(i, 3) == Some(b"Mon") {
                    if at(i, 6) == Some(b"Monday") {
                        return hit(i, Std::LongWeekDay, 6);
                    }
                    if !starts_with_lower(&l[i + 3..]) {
                        return hit(i, Std::WeekDay, 3);
                    }
                }
                if at(i, 3) == Some(b"MST") {
                    return hit(i, Std::Tz, 3);
                }
            }
            b'0' => {
                if let Some(&d @ b'1'..=b'6') = l.get(i + 1) {
                    let std = match d {
                        b'1' => Std::ZeroMonth,
                        b'2' => Std::ZeroDay,
                        b'3' => Std::ZeroHour12,
                        b'4' => Std::ZeroMinute,
                        b'5' => Std::ZeroSecond,
                        _ => Std::Year,
                    };
                    return hit(i, std, 2);
                }
                if at(i + 1, 2) == Some(b"02") {
                    return hit(i, Std::ZeroYearDay, 3);
                }
            }
            b'1' => {
                if l.get(i + 1) == Some(&b'5') {
                    return hit(i, Std::Hour, 2);
                }
                return hit(i, Std::NumMonth, 1);
            }
            b'2' => {
                if at(i, 4) == Some(b"2006") {
                    return hit(i, Std::LongYear, 4);
                }
                return hit(i, Std::Day, 1);
            }
            b'_' => {
                if l.get(i + 1) == Some(&b'2') {
                    // _2006 is really a literal _, followed by the long year.
                    if at(i + 1, 4) == Some(b"2006") {
                        return (&layout[..=i], Some(Std::LongYear), &layout[i + 5..]);
                    }
                    return hit(i, Std::UnderDay, 2);
                }
                if at(i + 1, 2) == Some(b"_2") {
                    return hit(i, Std::UnderYearDay, 3);
                }
            }
            b'3' => return hit(i, Std::Hour12, 1),
            b'4' => return hit(i, Std::Minute, 1),
            b'5' => return hit(i, Std::Second, 1),
            b'P' => {
                if l.get(i + 1) == Some(&b'M') {
                    return hit(i, Std::Pm, 2);
                }
            }
            b'p' => {
                if l.get(i + 1) == Some(&b'm') {
                    return hit(i, Std::PmLower, 2);
                }
            }
            b'-' => {
                if at(i, 7) == Some(b"-070000") {
                    return hit(i, Std::NumSecondsTz, 7);
                }
                if at(i, 9) == Some(b"-07:00:00") {
                    return hit(i, Std::NumColonSecondsTz, 9);
                }
                if at(i, 5) == Some(b"-0700") {
                    return hit(i, Std::NumTz, 5);
                }
                if at(i, 6) == Some(b"-07:00") {
                    return hit(i, Std::NumColonTz, 6);
                }
                if at(i, 3) == Some(b"-07") {
                    return hit(i, Std::NumShortTz, 3);
                }
            }
            b'Z' => {
                if at(i, 7) == Some(b"Z070000") {
                    return hit(i, Std::Iso8601SecondsTz, 7);
                }
                if at(i, 9) == Some(b"Z07:00:00") {
                    return hit(i, Std::Iso8601ColonSecondsTz, 9);
                }
                if at(i, 5) == Some(b"Z0700") {
                    return hit(i, Std::Iso8601Tz, 5);
                }
                if at(i, 6) == Some(b"Z07:00") {
                    return hit(i, Std::Iso8601ColonTz, 6);
                }
                if at(i, 3) == Some(b"Z07") {
                    return hit(i, Std::Iso8601ShortTz, 3);
                }
            }
            sep @ (b'.' | b',') => {
                if let Some(&ch @ (b'0' | b'9')) = l.get(i + 1) {
                    let mut j = i + 1;
                    while l.get(j) == Some(&ch) {
                        j += 1;
                    }
                    // The string of digits must end here: a fractional second is all digits.
                    if !l.get(j).is_some_and(u8::is_ascii_digit) {
                        let digits = (j - (i + 1)) & 0xfff;
                        let std = if ch == b'0' {
                            Std::FracSecond0 { digits, sep }
                        } else {
                            Std::FracSecond9 { digits, sep }
                        };
                        return (&layout[..i], Some(std), &layout[j..]);
                    }
                }
            }
            _ => {}
        }
    }
    (layout, None, "")
}

fn is_digit_at(s: &[u8], i: usize) -> bool {
    s.get(i).is_some_and(u8::is_ascii_digit)
}

/// `atoi`: an optional sign and digits, with Go's overflow check.
fn atoi(s: &[u8]) -> Result<i64, ()> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let (q, rem) = leading_int(digits)?;
    if !rem.is_empty() {
        return Err(());
    }
    let x = q as i64;
    Ok(if neg { x.wrapping_neg() } else { x })
}

fn getnum(s: &[u8], fixed: bool) -> Result<(i64, &[u8]), ()> {
    if !is_digit_at(s, 0) {
        return Err(());
    }
    if !is_digit_at(s, 1) {
        if fixed {
            return Err(());
        }
        return Ok((i64::from(s[0] - b'0'), &s[1..]));
    }
    Ok((
        i64::from(s[0] - b'0') * 10 + i64::from(s[1] - b'0'),
        &s[2..],
    ))
}

fn getnum3(s: &[u8], fixed: bool) -> Result<(i64, &[u8]), ()> {
    let mut n = 0i64;
    let mut i = 0;
    while i < 3 && is_digit_at(s, i) {
        n = n * 10 + i64::from(s[i] - b'0');
        i += 1;
    }
    if i == 0 || (fixed && i != 3) {
        return Err(());
    }
    Ok((n, &s[i..]))
}

fn cutspace(mut s: &[u8]) -> &[u8] {
    while s.first() == Some(&b' ') {
        s = &s[1..];
    }
    s
}

fn skip<'a>(mut value: &'a [u8], mut prefix: &[u8]) -> Result<&'a [u8], &'a [u8]> {
    while let Some(&p) = prefix.first() {
        if p == b' ' {
            if !value.is_empty() && value[0] != b' ' {
                return Err(value);
            }
            prefix = cutspace(prefix);
            value = cutspace(value);
            continue;
        }
        if value.first() != Some(&p) {
            return Err(value);
        }
        prefix = &prefix[1..];
        value = &value[1..];
    }
    Ok(value)
}

fn comma_or_period(b: u8) -> bool {
    b == b'.' || b == b','
}

/// `parseNanoseconds`: `(ns, range error)`.
fn parse_nanoseconds(value: &[u8], nbytes: usize) -> Result<(i64, Option<&'static str>), ()> {
    if !comma_or_period(value[0]) {
        return Err(());
    }
    let nbytes = nbytes.min(10);
    let mut ns = atoi(&value[1..nbytes])?;
    if ns < 0 {
        return Ok((ns, Some("fractional second")));
    }
    for _ in 0..10 - nbytes {
        ns *= 10;
    }
    Ok((ns, None))
}

fn match_fold(s1: &[u8], s2: &[u8]) -> bool {
    s1.iter().zip(s2).all(|(&a, &b)| {
        if a == b {
            return true;
        }
        let (a, b) = (a | 0x20, b | 0x20);
        a == b && a.is_ascii_lowercase()
    })
}

fn lookup<'a>(table: &[&str], value: &'a [u8]) -> Option<(i64, &'a [u8])> {
    for (i, name) in table.iter().enumerate() {
        if value.len() >= name.len() && match_fold(&value[..name.len()], name.as_bytes()) {
            return Some((i as i64, &value[name.len()..]));
        }
    }
    None
}

const SHORT_DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const SHORT_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `time.Parse`, with `Local` taken as UTC: a time without a zone is UTC, and the result carries the
/// parsed offset. See the module notes about `MST`.
pub fn parse(layout: &str, value: &str) -> Result<GoTime, ParseError> {
    parse_bytes(layout, value.as_bytes())
}

/// [`parse`] for input that may not be valid UTF-8, as a Go string can be.
pub fn parse_bytes(layout: &str, value: &[u8]) -> Result<GoTime, ParseError> {
    if (layout == RFC3339 || layout == RFC3339_NANO)
        && let Some(t) = parse_rfc3339(value)
    {
        return Ok(t);
    }
    parse_general(layout, value)
}

/// `parseRFC3339`.
fn parse_rfc3339(s: &[u8]) -> Option<GoTime> {
    let mut ok = true;
    let mut parse_uint = |s: &[u8], min: i64, max: i64| -> i64 {
        let mut x = 0i64;
        for &c in s {
            if !c.is_ascii_digit() {
                ok = false;
                return min;
            }
            x = x * 10 + i64::from(c - b'0');
        }
        if x < min || max < x {
            ok = false;
            return min;
        }
        x
    };
    if s.len() < "2006-01-02T15:04:05".len() {
        return None;
    }
    let year = parse_uint(&s[0..4], 0, 9999);
    let month = parse_uint(&s[5..7], 1, 12);
    let day = parse_uint(&s[8..10], 1, days_in(month, year));
    let hour = parse_uint(&s[11..13], 0, 23);
    let min = parse_uint(&s[14..16], 0, 59);
    let sec = parse_uint(&s[17..19], 0, 59);
    if !ok || !(s[4] == b'-' && s[7] == b'-' && s[10] == b'T' && s[13] == b':' && s[16] == b':') {
        return None;
    }
    let mut s = &s[19..];

    let mut nsec = 0i64;
    if s.len() >= 2 && s[0] == b'.' && is_digit_at(s, 1) {
        let mut n = 2;
        while n < s.len() && is_digit_at(s, n) {
            n += 1;
        }
        nsec = parse_nanoseconds(s, n).map_or(0, |(ns, _)| ns);
        s = &s[n..];
    }

    let unix = unix_seconds(year, month, day, hour, min, sec);
    if s == b"Z" {
        return Some(GoTime {
            unix_secs: unix,
            nanos: nsec as u32,
            offset: 0,
            utc: true,
        });
    }
    if s.len() != "-07:00".len() {
        return None;
    }
    let mut ok = true;
    let mut parse_uint = |s: &[u8], min: i64, max: i64| -> i64 {
        let mut x = 0i64;
        for &c in s {
            if !c.is_ascii_digit() {
                ok = false;
                return min;
            }
            x = x * 10 + i64::from(c - b'0');
        }
        if x < min || max < x {
            ok = false;
            return min;
        }
        x
    };
    let hr = parse_uint(&s[1..3], 0, 23);
    let mm = parse_uint(&s[4..6], 0, 59);
    if !ok || !((s[0] == b'-' || s[0] == b'+') && s[3] == b':') {
        return None;
    }
    let mut zone_offset = (hr * 60 + mm) * 60;
    if s[0] == b'-' {
        zone_offset = -zone_offset;
    }
    Some(GoTime {
        unix_secs: unix - zone_offset,
        nanos: nsec as u32,
        offset: zone_offset as i32,
        utc: false,
    })
}

fn unix_seconds(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec
}

fn std_len_str(layout: &str, prefix: &str, suffix: &str) -> Vec<u8> {
    layout.as_bytes()[prefix.len()..layout.len() - suffix.len()].to_vec()
}

/// The general branch of `time.parse`.
#[allow(clippy::too_many_lines)]
fn parse_general(alayout: &str, avalue: &[u8]) -> Result<GoTime, ParseError> {
    let new_err = |layout_elem: Vec<u8>, value_elem: &[u8], message: String| ParseError {
        layout: alayout.as_bytes().to_vec(),
        value: avalue.to_vec(),
        layout_elem,
        value_elem: value_elem.to_vec(),
        message,
    };

    let mut layout = alayout;
    let mut value = avalue;
    let mut range_err: Option<&'static str> = None;
    let (mut am_set, mut pm_set) = (false, false);

    let mut year = 0i64;
    let mut month = -1i64;
    let mut day = -1i64;
    let mut yday = -1i64;
    let (mut hour, mut min, mut sec, mut nsec) = (0i64, 0i64, 0i64, 0i64);
    let mut z_utc = false;
    let mut zone_offset = -1i64;

    loop {
        let (prefix, std, suffix) = next_std_chunk(layout);
        let stdstr = std_len_str(layout, prefix, suffix);
        value = match skip(value, prefix.as_bytes()) {
            Ok(rest) => rest,
            Err(rest) => return Err(new_err(prefix.as_bytes().to_vec(), rest, String::new())),
        };
        let Some(std) = std else {
            if !value.is_empty() {
                return Err(new_err(
                    Vec::new(),
                    value,
                    format!(": extra text: {}", quote(value)),
                ));
            }
            break;
        };
        layout = suffix;
        let hold = value;
        let mut err = false;
        macro_rules! take_num {
            ($target:ident, $result:expr) => {
                match $result {
                    Ok((n, rest)) => {
                        $target = n;
                        value = rest;
                    }
                    Err(()) => {
                        $target = 0;
                        err = true;
                    }
                }
            };
        }
        match std {
            Std::Year => {
                if value.len() < 2 {
                    err = true;
                } else {
                    let (p, rest) = value.split_at(2);
                    value = rest;
                    match atoi(p) {
                        Ok(y) => year = if y >= 69 { y + 1900 } else { y + 2000 },
                        Err(()) => {
                            year = 0;
                            err = true;
                        }
                    }
                }
            }
            Std::LongYear => {
                if value.len() < 4 || !is_digit_at(value, 0) {
                    err = true;
                } else {
                    let (p, rest) = value.split_at(4);
                    value = rest;
                    match atoi(p) {
                        Ok(y) => year = y,
                        Err(()) => {
                            year = 0;
                            err = true;
                        }
                    }
                }
            }
            Std::Month | Std::LongMonth => {
                let found = if std == Std::Month {
                    lookup(&SHORT_MONTHS, value)
                } else {
                    lookup(&LONG_MONTHS, value)
                };
                match found {
                    Some((i, rest)) => {
                        month = i + 1;
                        value = rest;
                    }
                    None => {
                        month = 0;
                        err = true;
                    }
                }
            }
            Std::NumMonth | Std::ZeroMonth => {
                take_num!(month, getnum(value, std == Std::ZeroMonth));
                if !err && (month <= 0 || 12 < month) {
                    range_err = Some("month");
                }
            }
            Std::WeekDay | Std::LongWeekDay => {
                let found = if std == Std::WeekDay {
                    lookup(&SHORT_DAYS, value)
                } else {
                    lookup(&LONG_DAYS, value)
                };
                match found {
                    Some((_, rest)) => value = rest,
                    None => err = true,
                }
            }
            Std::Day | Std::UnderDay | Std::ZeroDay => {
                if std == Std::UnderDay && value.first() == Some(&b' ') {
                    value = &value[1..];
                }
                take_num!(day, getnum(value, std == Std::ZeroDay));
            }
            Std::UnderYearDay | Std::ZeroYearDay => {
                for _ in 0..2 {
                    if std == Std::UnderYearDay && value.first() == Some(&b' ') {
                        value = &value[1..];
                    }
                }
                take_num!(yday, getnum3(value, std == Std::ZeroYearDay));
            }
            Std::Hour => {
                take_num!(hour, getnum(value, false));
                if !(0..24).contains(&hour) {
                    range_err = Some("hour");
                }
            }
            Std::Hour12 | Std::ZeroHour12 => {
                take_num!(hour, getnum(value, std == Std::ZeroHour12));
                if !(0..=12).contains(&hour) {
                    range_err = Some("hour");
                }
            }
            Std::Minute | Std::ZeroMinute => {
                take_num!(min, getnum(value, std == Std::ZeroMinute));
                if !(0..60).contains(&min) {
                    range_err = Some("minute");
                }
            }
            Std::Second | Std::ZeroSecond => {
                take_num!(sec, getnum(value, std == Std::ZeroSecond));
                if !err {
                    if !(0..60).contains(&sec) {
                        range_err = Some("second");
                    } else if value.len() >= 2 && comma_or_period(value[0]) && is_digit_at(value, 1)
                    {
                        // A fractional second in the input, but maybe not in the layout.
                        let (_, next, _) = next_std_chunk(layout);
                        if !matches!(
                            next,
                            Some(Std::FracSecond0 { .. } | Std::FracSecond9 { .. })
                        ) {
                            let mut n = 2;
                            while n < value.len() && is_digit_at(value, n) {
                                n += 1;
                            }
                            match parse_nanoseconds(value, n) {
                                Ok((ns, range)) => {
                                    nsec = ns;
                                    if range.is_some() {
                                        range_err = range;
                                    }
                                }
                                Err(()) => err = true,
                            }
                            value = &value[n..];
                        }
                    }
                }
            }
            Std::Pm | Std::PmLower => {
                if value.len() < 2 {
                    err = true;
                } else {
                    let (p, rest) = value.split_at(2);
                    value = rest;
                    let (pm, am): (&[u8], &[u8]) = if std == Std::Pm {
                        (b"PM", b"AM")
                    } else {
                        (b"pm", b"am")
                    };
                    if p == pm {
                        pm_set = true;
                    } else if p == am {
                        am_set = true;
                    } else {
                        err = true;
                    }
                }
            }
            Std::Iso8601Tz
            | Std::Iso8601ShortTz
            | Std::Iso8601ColonTz
            | Std::Iso8601SecondsTz
            | Std::Iso8601ColonSecondsTz
            | Std::NumTz
            | Std::NumShortTz
            | Std::NumColonTz
            | Std::NumSecondsTz
            | Std::NumColonSecondsTz => {
                let is_z = matches!(
                    std,
                    Std::Iso8601Tz
                        | Std::Iso8601ShortTz
                        | Std::Iso8601ColonTz
                        | Std::Iso8601SecondsTz
                        | Std::Iso8601ColonSecondsTz
                );
                if is_z && value.first() == Some(&b'Z') {
                    value = &value[1..];
                    z_utc = true;
                } else {
                    // Sign, hour, minute, second, and the rest of the value.
                    type ZoneParts<'a> = (u8, &'a [u8], &'a [u8], &'a [u8], &'a [u8]);
                    let parts: Option<ZoneParts<'_>> = match std {
                        Std::Iso8601ColonTz | Std::NumColonTz => {
                            if value.len() < 6 || value[3] != b':' {
                                None
                            } else {
                                Some((value[0], &value[1..3], &value[4..6], b"00", &value[6..]))
                            }
                        }
                        Std::NumShortTz | Std::Iso8601ShortTz => {
                            if value.len() < 3 {
                                None
                            } else {
                                Some((value[0], &value[1..3], b"00", b"00", &value[3..]))
                            }
                        }
                        Std::Iso8601ColonSecondsTz | Std::NumColonSecondsTz => {
                            if value.len() < 9 || value[3] != b':' || value[6] != b':' {
                                None
                            } else {
                                Some((
                                    value[0],
                                    &value[1..3],
                                    &value[4..6],
                                    &value[7..9],
                                    &value[9..],
                                ))
                            }
                        }
                        Std::Iso8601SecondsTz | Std::NumSecondsTz => {
                            if value.len() < 7 {
                                None
                            } else {
                                Some((
                                    value[0],
                                    &value[1..3],
                                    &value[3..5],
                                    &value[5..7],
                                    &value[7..],
                                ))
                            }
                        }
                        _ => {
                            if value.len() < 5 {
                                None
                            } else {
                                Some((value[0], &value[1..3], &value[3..5], b"00", &value[5..]))
                            }
                        }
                    };
                    match parts {
                        None => err = true,
                        Some((sign, hour_part, min_part, sec_part, rest)) => {
                            value = rest;
                            let (mut hr, mut mm, mut ss) = (0i64, 0i64, 0i64);
                            match getnum(hour_part, true) {
                                Ok((n, _)) => {
                                    hr = n;
                                    match getnum(min_part, true) {
                                        Ok((n, _)) => {
                                            mm = n;
                                            match getnum(sec_part, true) {
                                                Ok((n, _)) => ss = n,
                                                Err(()) => err = true,
                                            }
                                        }
                                        Err(()) => err = true,
                                    }
                                }
                                Err(()) => err = true,
                            }
                            // The range tests use > rather than >=, as some people do write
                            // offsets of 24 hours or 60 minutes or 60 seconds.
                            if hr > 24 {
                                range_err = Some("time zone offset hour");
                            }
                            if mm > 60 {
                                range_err = Some("time zone offset minute");
                            }
                            if ss > 60 {
                                range_err = Some("time zone offset second");
                            }
                            zone_offset = (hr * 60 + mm) * 60 + ss;
                            match sign {
                                b'+' => {}
                                b'-' => zone_offset = -zone_offset,
                                _ => err = true,
                            }
                        }
                    }
                }
            }
            Std::Tz => {
                // Only UTC: see the module notes.
                if value.starts_with(b"UTC") {
                    z_utc = true;
                    value = &value[3..];
                } else {
                    err = true;
                }
            }
            Std::FracSecond0 { digits, .. } => {
                // Requires exactly the number of digits in the layout.
                let ndigit = 1 + digits;
                if value.len() < ndigit {
                    err = true;
                } else {
                    match parse_nanoseconds(value, ndigit) {
                        Ok((ns, range)) => {
                            nsec = ns;
                            if range.is_some() {
                                range_err = range;
                            }
                        }
                        Err(()) => err = true,
                    }
                    value = &value[ndigit..];
                }
            }
            Std::FracSecond9 { .. } => {
                if value.len() >= 2 && comma_or_period(value[0]) && value[1].is_ascii_digit() {
                    // Take any number of digits, even more than asked for.
                    let mut i = 0;
                    while i + 1 < value.len() && value[i + 1].is_ascii_digit() {
                        i += 1;
                    }
                    match parse_nanoseconds(value, 1 + i) {
                        Ok((ns, range)) => {
                            nsec = ns;
                            if range.is_some() {
                                range_err = range;
                            }
                        }
                        Err(()) => err = true,
                    }
                    value = &value[1 + i..];
                }
            }
        }
        if let Some(what) = range_err {
            return Err(new_err(stdstr, value, format!(": {what} out of range")));
        }
        if err {
            return Err(new_err(stdstr, hold, String::new()));
        }
    }
    if pm_set && hour < 12 {
        hour += 12;
    } else if am_set && hour == 12 {
        hour = 0;
    }

    // Convert yday to day and month.
    if yday >= 0 {
        let mut d = 0i64;
        let mut m = 0i64;
        if is_leap(year) {
            if yday == 31 + 29 {
                m = 2;
                d = 29;
            } else if yday > 31 + 29 {
                yday -= 1;
            }
        }
        if !(1..=365).contains(&yday) {
            return Err(new_err(
                Vec::new(),
                value,
                ": day-of-year out of range".to_string(),
            ));
        }
        if m == 0 {
            m = (yday - 1) / 31 + 1;
            if i64::from(days_before(m as u32 + 1)) < yday {
                m += 1;
            }
            d = yday - i64::from(days_before(m as u32));
        }
        // If month and day were already seen, yday's must match.
        if month >= 0 && month != m {
            return Err(new_err(
                Vec::new(),
                value,
                ": day-of-year does not match month".to_string(),
            ));
        }
        month = m;
        if day >= 0 && day != d {
            return Err(new_err(
                Vec::new(),
                value,
                ": day-of-year does not match day".to_string(),
            ));
        }
        day = d;
    } else {
        if month < 0 {
            month = 1;
        }
        if day < 0 {
            day = 1;
        }
    }

    // Validate the day of the month.
    if day < 1 || day > days_in(month, year) {
        return Err(new_err(Vec::new(), value, ": day out of range".to_string()));
    }

    // Date normalizes a nanosecond count of a second or more into the seconds.
    let unix = unix_seconds(year, month, day, hour, min, sec) + nsec.div_euclid(1_000_000_000);
    let nanos = nsec.rem_euclid(1_000_000_000) as u32;
    if z_utc {
        return Ok(GoTime {
            unix_secs: unix,
            nanos,
            offset: 0,
            utc: true,
        });
    }
    if zone_offset != -1 {
        return Ok(GoTime {
            unix_secs: unix - zone_offset,
            nanos,
            offset: zone_offset as i32,
            utc: false,
        });
    }
    Ok(GoTime {
        unix_secs: unix,
        nanos,
        offset: 0,
        utc: true,
    })
}
