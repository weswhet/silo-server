//! `SpecSchedule` and `ConstantDelaySchedule`.

use super::time::{Location, ZonedTime, go_date};

/// The top bit, set when a star was included in the expression.
pub const STAR_BIT: u64 = 1 << 63;

/// `cron.Schedule`.
#[derive(Clone, Debug, PartialEq)]
pub enum Schedule {
    Spec(SpecSchedule),
    ConstantDelay(ConstantDelaySchedule),
}

impl Schedule {
    /// The next activation after `t`, or `None` when none exists within five years, where Go returns
    /// the zero time.
    pub fn next(&self, t: &ZonedTime) -> Option<ZonedTime> {
        match self {
            Schedule::Spec(s) => s.next(t),
            Schedule::ConstantDelay(c) => Some(c.next(t)),
        }
    }
}

/// `cron.SpecSchedule`: a duty cycle to the second, stored as bit sets.
#[derive(Clone, Debug, PartialEq)]
pub struct SpecSchedule {
    pub second: u64,
    pub minute: u64,
    pub hour: u64,
    pub dom: u64,
    pub month: u64,
    pub dow: u64,
    pub location: Location,
}

/// `cron.ConstantDelaySchedule`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConstantDelaySchedule {
    /// The delay in nanoseconds.
    pub delay: i64,
}

const SECOND: i64 = 1_000_000_000;

/// `cron.Every`: delays under a second round up to one, and sub-second parts are truncated.
pub fn every(duration: i64) -> ConstantDelaySchedule {
    let duration = duration.max(SECOND);
    ConstantDelaySchedule {
        delay: duration - duration % SECOND,
    }
}

impl ConstantDelaySchedule {
    pub fn next(&self, t: &ZonedTime) -> ZonedTime {
        t.add_nanos(self.delay.wrapping_sub(i64::from(t.nanos)))
    }
}

fn bit(n: i64) -> u64 {
    1u64.checked_shl(n as u32).unwrap_or(0)
}

fn day_matches(s: &SpecSchedule, t: &ZonedTime) -> bool {
    let dom_match = bit(t.day()) & s.dom > 0;
    let dow_match = bit(t.weekday()) & s.dow > 0;
    if s.dom & STAR_BIT > 0 || s.dow & STAR_BIT > 0 {
        dom_match && dow_match
    } else {
        dom_match || dow_match
    }
}

impl SpecSchedule {
    /// `SpecSchedule.Next`, including its handling of a midnight DST gap.
    pub fn next(&self, t: &ZonedTime) -> Option<ZonedTime> {
        let orig_location = t.location.clone();
        let local = self.location == Location::Local;
        let loc = if local {
            t.location.clone()
        } else {
            self.location.clone()
        };
        let mut t = if local {
            t.clone()
        } else {
            t.in_location(&self.location)
        };

        t = t.add_nanos(SECOND - i64::from(t.nanos));
        let mut added = false;
        let year_limit = t.year() + 5;

        'wrap: loop {
            if t.year() > year_limit {
                return None;
            }

            while bit(t.month()) & self.month == 0 {
                if !added {
                    added = true;
                    t = go_date(t.year(), t.month(), 1, 0, 0, 0, 0, &loc);
                }
                t = t.add_date(0, 1, 0);
                if t.month() == 1 {
                    continue 'wrap;
                }
            }

            while !day_matches(self, &t) {
                if !added {
                    added = true;
                    t = go_date(t.year(), t.month(), t.day(), 0, 0, 0, 0, &loc);
                }
                t = t.add_date(0, 0, 1);
                if t.hour() != 0 {
                    if t.hour() > 12 {
                        t = t.add_seconds((24 - t.hour()) * 3600);
                    } else {
                        t = t.add_seconds(-t.hour() * 3600);
                    }
                }
                if t.day() == 1 {
                    continue 'wrap;
                }
            }

            while bit(t.hour()) & self.hour == 0 {
                if !added {
                    added = true;
                    t = go_date(t.year(), t.month(), t.day(), t.hour(), 0, 0, 0, &loc);
                }
                t = t.add_seconds(3600);
                if t.hour() == 0 {
                    continue 'wrap;
                }
            }

            while bit(t.minute()) & self.minute == 0 {
                if !added {
                    added = true;
                    t = t.truncate_seconds(60);
                }
                t = t.add_seconds(60);
                if t.minute() == 0 {
                    continue 'wrap;
                }
            }

            while bit(t.second()) & self.second == 0 {
                if !added {
                    added = true;
                    t = t.truncate_seconds(1);
                }
                t = t.add_seconds(1);
                if t.second() == 0 {
                    continue 'wrap;
                }
            }

            return Some(t.in_location(&orig_location));
        }
    }
}
