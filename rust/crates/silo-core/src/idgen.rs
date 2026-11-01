//! `internal/idgen` and `github.com/sony/sonyflake/v2`: 63-bit, time-sorted IDs as decimal strings.
//!
//! The layout is 39 bits of 10 ms time since 2024-01-01 UTC, 8 bits of sequence, and 16 bits of machine
//! ID. A process leases its machine ID from `idgen_machine_leases` under the advisory lock
//! [`CLAIM_LOCK_KEY`]; the queries are here so a database crate can run them. New IDs must sort after
//! existing ones, and two processes may share a machine ID only with their leases an hour apart.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 2024-01-01 00:00:00 UTC, in Unix seconds.
pub const EPOCH_UNIX: i64 = 1_704_067_200;
const TIME_UNIT_NS: i128 = 10_000_000;
const BITS_SEQUENCE: u32 = 8;
const BITS_MACHINE: u32 = 16;
const BITS_TIME: u32 = 39;

/// How long a claim or renewal holds a machine ID.
pub const LEASE_TTL: Duration = Duration::from_secs(120);
/// Renewal leaves several attempts inside one TTL.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(20);
/// Local use of a machine ID ends this long before the database expiry.
pub const EXPIRY_MARGIN: Duration = Duration::from_secs(10);
/// An expired lease rests this long before another process may claim its machine ID.
pub const REUSE_AFTER: Duration = Duration::from_secs(3600);
/// `pg_advisory_xact_lock` key serializing claims ("SILOIDM").
pub const CLAIM_LOCK_KEY: i64 = 0x53494c4f49444d;

/// Claims a never-used machine ID. Bind token, holder, and TTL seconds.
pub const CLAIM_UNUSED_SQL: &str = "
		INSERT INTO idgen_machine_leases (machine_id, token, holder, expires_at)
		SELECT n, $1, $2, statement_timestamp() + make_interval(secs => $3)
		FROM generate_series(0, 65535) AS n
		WHERE NOT EXISTS (SELECT 1 FROM idgen_machine_leases l WHERE l.machine_id = n)
		ORDER BY random()
		LIMIT 1
		RETURNING machine_id";

/// Takes over the machine ID whose lease expired longest ago, at least `reuse after` ago. Bind token,
/// holder, TTL seconds, and reuse seconds.
pub const CLAIM_EXPIRED_SQL: &str = "
			UPDATE idgen_machine_leases
			SET token = $1, holder = $2, acquired_at = statement_timestamp(),
			    expires_at = statement_timestamp() + make_interval(secs => $3)
			WHERE machine_id = (
				SELECT machine_id FROM idgen_machine_leases
				WHERE expires_at < statement_timestamp() - make_interval(secs => $4)
				ORDER BY expires_at
				LIMIT 1
				-- Lock the candidate so its expiry is rechecked against the
				-- latest row: a lease renewed after this statement started is
				-- skipped instead of taken over while its holder still mints.
				FOR UPDATE SKIP LOCKED
			)
			RETURNING machine_id";

/// Renews a lease. Bind machine ID, token, and TTL seconds; one affected row means it is still ours.
pub const RENEW_SQL: &str = "
		UPDATE idgen_machine_leases
		SET expires_at = statement_timestamp() + make_interval(secs => $3)
		WHERE machine_id = $1 AND token = $2";

/// Sonyflake failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OverTimeLimit,
    StartTimeAhead,
    InvalidSequence,
    InvalidMachineId,
    /// `idgen.ErrLeaseExpired`.
    LeaseExpired(u16),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverTimeLimit => f.write_str("idgen: over the time limit"),
            Self::StartTimeAhead => f.write_str("idgen: start time is ahead"),
            Self::InvalidSequence => f.write_str("idgen: invalid sequence number"),
            Self::InvalidMachineId => f.write_str("idgen: invalid machine id"),
            Self::LeaseExpired(id) => {
                write!(f, "idgen: machine ID lease expired (machine ID {id})")
            }
        }
    }
}

impl std::error::Error for Error {}

fn to_internal_time(unix_nanos: i128) -> i64 {
    // Go divides an int64 of nanoseconds, which truncates toward zero.
    (unix_nanos / TIME_UNIT_NS) as i64
}

fn start_time() -> i64 {
    to_internal_time(i128::from(EPOCH_UNIX) * 1_000_000_000)
}

fn now_nanos() -> i128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

/// `Sonyflake.Compose`.
pub fn compose(unix_nanos: i128, sequence: i64, machine_id: i64) -> Result<i64, Error> {
    let elapsed = to_internal_time(unix_nanos) - start_time();
    if elapsed < 0 {
        return Err(Error::StartTimeAhead);
    }
    if elapsed >= 1 << BITS_TIME {
        return Err(Error::OverTimeLimit);
    }
    if !(0..1 << BITS_SEQUENCE).contains(&sequence) {
        return Err(Error::InvalidSequence);
    }
    if !(0..1 << BITS_MACHINE).contains(&machine_id) {
        return Err(Error::InvalidMachineId);
    }
    Ok(elapsed << (BITS_SEQUENCE + BITS_MACHINE) | sequence << BITS_MACHINE | machine_id)
}

/// `Sonyflake.Decompose`: the parts of an ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parts {
    pub time: i64,
    pub sequence: i64,
    pub machine: i64,
}

/// `Sonyflake.Decompose`.
pub fn decompose(id: i64) -> Parts {
    Parts {
        time: id >> (BITS_SEQUENCE + BITS_MACHINE),
        sequence: (id & (((1 << BITS_SEQUENCE) - 1) << BITS_MACHINE)) >> BITS_MACHINE,
        machine: id & ((1 << BITS_MACHINE) - 1),
    }
}

/// `Sonyflake.ToTime`, as Unix nanoseconds.
pub fn to_unix_nanos(id: i64) -> i128 {
    i128::from(start_time() + decompose(id).time) * TIME_UNIT_NS
}

struct State {
    elapsed: i64,
    sequence: i64,
}

/// A Sonyflake generator with the lease deadline of `idgen.generator`.
pub struct Generator {
    machine_id: u16,
    state: Mutex<State>,
    valid_until: Mutex<Option<Instant2>>,
}

/// A moment on two clocks. A deadline passes once either clock reaches it, so neither a wall-clock
/// step nor a suspended monotonic clock can extend a lease.
#[derive(Debug, Clone, Copy)]
pub struct Instant2 {
    pub mono: std::time::Instant,
    pub wall_nanos: i128,
}

impl Instant2 {
    /// Now, on both clocks.
    pub fn now() -> Self {
        Self {
            mono: std::time::Instant::now(),
            wall_nanos: now_nanos(),
        }
    }

    /// `validUntil`: the local deadline for a lease extended by a statement sent at `self`.
    pub fn lease_deadline(self) -> Self {
        let valid = LEASE_TTL - EXPIRY_MARGIN;
        Self {
            mono: self.mono + valid,
            wall_nanos: self.wall_nanos + valid.as_nanos() as i128,
        }
    }
}

impl Generator {
    /// `newGenerator`.
    pub fn new(machine_id: u16) -> Self {
        Self {
            machine_id,
            state: Mutex::new(State {
                elapsed: 0,
                sequence: (1 << BITS_SEQUENCE) - 1,
            }),
            valid_until: Mutex::new(None),
        }
    }

    /// The machine ID this generator mints under.
    pub fn machine_id(&self) -> u16 {
        self.machine_id
    }

    /// Sets the lease deadline. `None` means the generator does not expire.
    pub fn set_valid_until(&self, until: Option<Instant2>) {
        *self.valid_until.lock().expect("lease lock") = until;
    }

    fn expired(&self) -> bool {
        let Some(until) = *self.valid_until.lock().expect("lease lock") else {
            return false;
        };
        let now = Instant2::now();
        now.mono >= until.mono || now.wall_nanos >= until.wall_nanos
    }

    /// One step of `Sonyflake.NextID` at a given time: the ID and how long to wait before using it,
    /// which is nonzero after a sequence overflow.
    pub fn next_at(&self, unix_nanos: i128) -> Result<(i64, Duration), Error> {
        let mask = (1i64 << BITS_SEQUENCE) - 1;
        let mut state = self.state.lock().expect("generator lock");
        let current = to_internal_time(unix_nanos) - start_time();
        let mut wait = Duration::ZERO;
        if state.elapsed < current {
            state.elapsed = current;
            state.sequence = 0;
        } else {
            state.sequence = (state.sequence + 1) & mask;
            if state.sequence == 0 {
                state.elapsed += 1;
                let overtime = state.elapsed - current;
                let nanos =
                    i128::from(overtime) * TIME_UNIT_NS - unix_nanos.rem_euclid(TIME_UNIT_NS);
                wait = Duration::from_nanos(nanos.max(0) as u64);
            }
        }
        if state.elapsed >= 1 << BITS_TIME {
            return Err(Error::OverTimeLimit);
        }
        Ok((
            state.elapsed << (BITS_SEQUENCE + BITS_MACHINE)
                | state.sequence << BITS_MACHINE
                | i64::from(self.machine_id),
            wait,
        ))
    }

    /// `mintID`: a new ID as a decimal string, refused once the lease deadline has passed. It sleeps
    /// for up to one time unit after a sequence overflow, as Go does while holding its mutex.
    pub fn next_id(&self) -> Result<String, Error> {
        if self.expired() {
            return Err(Error::LeaseExpired(self.machine_id));
        }
        let (id, wait) = self.next_at(now_nanos())?;
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        if self.expired() {
            return Err(Error::LeaseExpired(self.machine_id));
        }
        Ok(id.to_string())
    }
}
