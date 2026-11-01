//! The part of Go's `time` package cron's schedules run on: an instant plus a location, with civil
//! fields, `time.Date`, `AddDate`, and `Truncate` as Go computes them.

use jiff::Timestamp;
use jiff::tz::TimeZone;
use std::sync::Arc;

/// `*time.Location`.
#[derive(Clone, Debug)]
pub enum Location {
    /// `time.UTC`.
    Utc,
    /// `time.Local`.
    Local,
    /// A zone from `time.LoadLocation`.
    Zone(Arc<TimeZone>),
    /// `time.FixedZone`, with the offset in seconds east of UTC.
    Fixed(i32),
}

impl PartialEq for Location {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Location::Utc, Location::Utc) | (Location::Local, Location::Local) => true,
            (Location::Zone(a), Location::Zone(b)) => {
                a.iana_name() == b.iana_name() && a.iana_name().is_some()
            }
            (Location::Fixed(a), Location::Fixed(b)) => a == b,
            _ => false,
        }
    }
}

impl Location {
    /// `time.LoadLocation`. Zone data comes from the system database, as in Go without
    /// `time/tzdata`, and names are matched case-sensitively, as on Linux.
    pub fn load(name: &str) -> Result<Location, String> {
        if name.is_empty() || name == "UTC" {
            return Ok(Location::Utc);
        }
        if name == "Local" {
            return Ok(Location::Local);
        }
        if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
            return Err("time: invalid location name".to_owned());
        }
        match TimeZone::get(name) {
            Ok(tz) if tz.iana_name() == Some(name) => Ok(Location::Zone(Arc::new(tz))),
            _ => Err(format!("unknown time zone {name}")),
        }
    }

    /// The offset in force at a Unix second.
    pub fn offset_at(&self, unix: i64) -> i64 {
        let lookup = |tz: &TimeZone| -> i64 {
            let clamped = unix.clamp(Timestamp::MIN.as_second(), Timestamp::MAX.as_second());
            let ts = Timestamp::from_second(clamped).unwrap_or(Timestamp::UNIX_EPOCH);
            i64::from(tz.to_offset(ts).seconds())
        };
        match self {
            Location::Utc => 0,
            Location::Fixed(o) => i64::from(*o),
            Location::Zone(tz) => lookup(tz),
            Location::Local => lookup(&TimeZone::system()),
        }
    }
}

/// `time.Time`: an instant in a location.
#[derive(Clone, Debug, PartialEq)]
pub struct ZonedTime {
    pub unix: i64,
    pub nanos: i32,
    pub location: Location,
}

fn days_from_civil(mut y: i64, m: i64, d: i64) -> i64 {
    y -= i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m, d)
}

impl ZonedTime {
    pub fn new(unix: i64, nanos: i32, location: Location) -> Self {
        ZonedTime {
            unix,
            nanos,
            location,
        }
    }

    fn local_seconds(&self) -> i64 {
        self.unix + self.location.offset_at(self.unix)
    }

    /// `Time.Date`: year, month, day in the time's location.
    pub fn date(&self) -> (i64, i64, i64) {
        civil_from_days(self.local_seconds().div_euclid(86400))
    }

    /// `Time.Clock`: hour, minute, second in the time's location.
    pub fn clock(&self) -> (i64, i64, i64) {
        let secs = self.local_seconds().rem_euclid(86400);
        (secs / 3600, (secs % 3600) / 60, secs % 60)
    }

    pub fn year(&self) -> i64 {
        self.date().0
    }

    pub fn month(&self) -> i64 {
        self.date().1
    }

    pub fn day(&self) -> i64 {
        self.date().2
    }

    pub fn hour(&self) -> i64 {
        self.clock().0
    }

    pub fn minute(&self) -> i64 {
        self.clock().1
    }

    pub fn second(&self) -> i64 {
        self.clock().2
    }

    /// `Time.Weekday`, Sunday being 0.
    pub fn weekday(&self) -> i64 {
        (self.local_seconds().div_euclid(86400) + 4).rem_euclid(7)
    }

    /// The offset from UTC, in seconds, at this time.
    pub fn offset(&self) -> i64 {
        self.location.offset_at(self.unix)
    }

    /// `Time.Add`.
    pub fn add_nanos(&self, d: i64) -> ZonedTime {
        let total = i128::from(self.unix) * 1_000_000_000 + i128::from(self.nanos) + i128::from(d);
        let unix = total.div_euclid(1_000_000_000);
        let nanos = total.rem_euclid(1_000_000_000);
        ZonedTime {
            unix: unix as i64,
            nanos: nanos as i32,
            location: self.location.clone(),
        }
    }

    pub fn add_seconds(&self, s: i64) -> ZonedTime {
        self.add_nanos(s.wrapping_mul(1_000_000_000))
    }

    /// `Time.In`.
    pub fn in_location(&self, location: &Location) -> ZonedTime {
        ZonedTime {
            unix: self.unix,
            nanos: self.nanos,
            location: location.clone(),
        }
    }

    /// `Time.Truncate` for a whole number of seconds.
    pub fn truncate_seconds(&self, d: i64) -> ZonedTime {
        ZonedTime {
            unix: self.unix - self.unix.rem_euclid(d),
            nanos: 0,
            location: self.location.clone(),
        }
    }

    /// `Time.AddDate`.
    pub fn add_date(&self, years: i64, months: i64, days: i64) -> ZonedTime {
        let (y, m, d) = self.date();
        let (h, mi, s) = self.clock();
        go_date(
            y + years,
            m + months,
            d + days,
            h,
            mi,
            s,
            self.nanos,
            &self.location,
        )
    }
}

/// `time.Date`, normalizing out-of-range fields and choosing Go's offset in a zone transition.
#[allow(clippy::too_many_arguments)]
pub fn go_date(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    min: i64,
    sec: i64,
    nsec: i32,
    loc: &Location,
) -> ZonedTime {
    let m0 = month - 1;
    let y = year + m0.div_euclid(12);
    let m = m0.rem_euclid(12) + 1;
    let days = days_from_civil(y, m, 1) + day - 1;
    let mut unix = days * 86400 + hour * 3600 + min * 60 + sec;
    // Go looks up the offset for the local seconds as if they were UTC. A nonzero result is applied,
    // then looked up again at the adjusted time, which is what makes its choice in a gap or an
    // overlap deterministic. A zero offset is used as it stands.
    let offset = loc.offset_at(unix);
    if offset != 0 {
        let utc = unix - offset;
        unix -= loc.offset_at(utc);
    }
    ZonedTime {
        unix,
        nanos: nsec,
        location: loc.clone(),
    }
}
