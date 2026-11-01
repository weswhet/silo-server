//! Password and PIN hashes: `golang.org/x/crypto/bcrypt`, as `internal/auth/passwordhash` calls it.
//!
//! New hashes are `$2a$`, like Go's, because any rewrite of `users.password_hash` changes the password
//! fingerprint and retires outstanding reset links. The parser reproduces Go's, which is looser than
//! the `bcrypt` crate's: any minor version byte is accepted and the separator after the cost is not
//! checked. The admission queue in front of bcrypt belongs to the auth service.

use silo_gocompat::strings::trim_space;

const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `bcrypt.DefaultCost`.
pub const DEFAULT_COST: u32 = 10;
const MIN_COST: i64 = 4;
const MAX_COST: i64 = 31;
const MIN_HASH_SIZE: usize = 59;
const ENCODED_SALT_SIZE: usize = 22;
const MAX_CRYPTED_HASH_SIZE: usize = 23;

/// bcrypt failures other than a wrong password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    HashTooShort,
    InvalidPrefix(u8),
    VersionTooNew(u8),
    InvalidCost,
    /// The salt is not 16 bytes of the bcrypt alphabet.
    InvalidSalt,
    /// `bcrypt.ErrPasswordTooLong`.
    PasswordTooLong,
    Random,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashTooShort => {
                f.write_str("crypto/bcrypt: hashedSecret too short to be a bcrypted password")
            }
            Self::InvalidPrefix(b) => write!(
                f,
                "crypto/bcrypt: bcrypt hashes must start with '$', but hashedSecret started with '{}'",
                char::from(*b)
            ),
            Self::VersionTooNew(b) => write!(
                f,
                "crypto/bcrypt: bcrypt algorithm version '{}' requested is newer than current version '2'",
                char::from(*b)
            ),
            Self::InvalidCost => f.write_str("crypto/bcrypt: invalid cost"),
            Self::InvalidSalt => f.write_str("crypto/bcrypt: invalid salt"),
            Self::PasswordTooLong => f.write_str("bcrypt: password length exceeds 72 bytes"),
            Self::Random => f.write_str("crypto/bcrypt: read salt"),
        }
    }
}

impl std::error::Error for Error {}

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|a| *a == c).map(|p| p as u32)
}

/// `base64Encode`: the bcrypt alphabet with the padding stripped.
fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 4 / 3 + 2);
    for group in input.chunks(3) {
        let mut acc = 0u32;
        for b in group {
            acc = acc << 8 | u32::from(*b);
        }
        acc <<= 8 * (3 - group.len()) as u32;
        for i in 0..=group.len() {
            let v = (acc >> (18 - 6 * i as u32)) & 63;
            out.push(char::from(ALPHABET[v as usize]));
        }
    }
    out
}

/// `base64Decode` of the 22-character salt. Go's decoder also skips newlines; a stored hash has none.
fn decode_salt(salt: &[u8]) -> Result<[u8; 16], Error> {
    let mut out = [0u8; 16];
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut n = 0;
    for &c in salt {
        acc = acc << 6 | value(c).ok_or(Error::InvalidSalt)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if n == 16 {
                return Err(Error::InvalidSalt);
            }
            out[n] = (acc >> bits) as u8;
            n += 1;
        }
    }
    if n != 16 {
        return Err(Error::InvalidSalt);
    }
    Ok(out)
}

/// `bcrypt()`: the encoded 31-character hash. Blowfish expands from the password and a trailing NUL,
/// cycling over at most the first 72 bytes.
fn raw_hash(password: &[u8], cost: u32, salt: &[u8; 16]) -> String {
    let mut key = Vec::with_capacity(password.len() + 1);
    key.extend_from_slice(password);
    key.push(0);
    key.truncate(72);
    let output = bcrypt::bcrypt(cost, *salt, &key);
    encode(&output[..MAX_CRYPTED_HASH_SIZE])
}

/// `strconv.Atoi` of the two cost characters, which allows a sign.
fn parse_cost(text: &[u8]) -> Option<i64> {
    std::str::from_utf8(text).ok()?.parse::<i64>().ok()
}

/// `bcrypt.CompareHashAndPassword`: `Ok(false)` is `ErrMismatchedHashAndPassword`, and an error is a
/// hash bcrypt cannot read.
pub fn compare(hashed: &[u8], password: &[u8]) -> Result<bool, Error> {
    if hashed.len() < MIN_HASH_SIZE {
        return Err(Error::HashTooShort);
    }
    if hashed[0] != b'$' {
        return Err(Error::InvalidPrefix(hashed[0]));
    }
    if hashed[1] > b'2' {
        return Err(Error::VersionTooNew(hashed[1]));
    }
    let major = hashed[1];
    // Go's `decodeVersion` never checks the minor byte's value past "is it present"; only that
    // presence (which picks `rest`'s offset here) feeds the rest of the comparison.
    let rest = if hashed[2] == b'$' {
        &hashed[3..]
    } else {
        &hashed[4..]
    };
    let cost = parse_cost(&rest[..2]).ok_or(Error::InvalidCost)?;
    if !(MIN_COST..=MAX_COST).contains(&cost) {
        return Err(Error::InvalidCost);
    }
    let rest = &rest[3..];
    let salt_text = &rest[..ENCODED_SALT_SIZE];
    let stored = &rest[ENCODED_SALT_SIZE..];
    let salt = decode_salt(salt_text)?;
    let computed = raw_hash(password, cost as u32, &salt);
    // `hashed.Hash()` re-renders both sides into a fixed 60-byte array and compares `arr[:n]`,
    // where `n` only ever grows by `encodedHashSize` (31) for the hash segment, not by however
    // much `copy` actually wrote. With no minor version, `arr[28:]` has 32 bytes of room, so
    // `copy` can write a 32nd byte of a too-long stored hash into `arr[59]` -- but `n` still ends
    // at 59 (28+31), so that slice never includes index 59 and that byte never enters the
    // comparison. With a minor version, `arr[29:]` only has 31 bytes of room in the first place,
    // so `copy` cannot even write a 32nd byte. Either way the stored hash segment that actually
    // gets compared is always exactly `encodedHashSize` (31) bytes, matching `computed`'s length;
    // only a crafted hash with a trailing byte past the normal 59/60-byte total makes this visible.
    let room = computed.len();
    let stored = &stored[..stored.len().min(room)];
    let _ = major;
    Ok(crate::hexgo::ct_eq(stored, computed.as_bytes()))
}

/// `bcrypt.GenerateFromPassword`.
pub fn generate(password: &[u8], cost: i64) -> Result<String, Error> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|_| Error::Random)?;
    generate_with_salt(password, cost, &salt)
}

/// `generate` with a chosen salt, for differential tests.
pub fn generate_with_salt(password: &[u8], cost: i64, salt: &[u8; 16]) -> Result<String, Error> {
    if password.len() > 72 {
        return Err(Error::PasswordTooLong);
    }
    let cost = if cost < MIN_COST {
        i64::from(DEFAULT_COST)
    } else {
        cost
    };
    if cost > MAX_COST {
        return Err(Error::InvalidCost);
    }
    let hash = raw_hash(password, cost as u32, salt);
    Ok(format!("$2a${cost:02}${}{hash}", encode(salt)))
}

/// The salt a stored hash carries, for differential tests.
pub fn salt_of(hashed: &[u8]) -> Option<[u8; 16]> {
    if hashed.len() < MIN_HASH_SIZE || hashed[0] != b'$' {
        return None;
    }
    let rest = if hashed[2] == b'$' {
        &hashed[3..]
    } else {
        &hashed[4..]
    };
    decode_salt(rest.get(3..3 + ENCODED_SALT_SIZE)?).ok()
}

/// `auth.NormalizeUsername`.
pub fn normalize_username(username: &str) -> &str {
    trim_space(username)
}
