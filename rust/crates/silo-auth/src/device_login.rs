//! `internal/auth/device_login_words.go`: the match-code word lists and `randomMatchCode`.
//!
//! The rest of `device_login.go` (1,528 Go lines: the request/approval/poll state machine and its
//! `device_login_requests` CRUD) is NOT ported this session — it is a large, mostly-independent
//! piece gated on this crate having no settled transaction/repository convention yet beyond
//! [`crate::session`]'s, and on `silo_core::apikey` already carrying the two primitives
//! (`hash_device_login_secret`, `normalize_user_code`/`format_user_code`) that this file and
//! `device_login.go` both depend on — reused here, not re-ported, per the dedup rule. A caller
//! assembling the full flow needs: [`random_match_code`] for the human-readable pairing phrase,
//! `silo_core::apikey::hash_device_login_secret` for the stored secret hash, and
//! `silo_core::apikey::{normalize_user_code, format_user_code}` for the short code a person types.

/// `deviceMatchAdjectives`.
const ADJECTIVES: [&str; 12] = [
    "blue", "busy", "calm", "cozy", "fast", "gold", "kind", "soft", "tall", "tame", "tiny", "warm",
];

/// `deviceMatchNouns`.
const NOUNS: [&str; 20] = [
    "barn", "bell", "cart", "coop", "corn", "cow", "duck", "goat", "hay", "hen", "lamb", "milk",
    "oats", "pail", "pond", "pony", "rake", "shed", "silo", "wool",
];

/// `randomWord`/`randomMatchCode`'s shared error: the word list was empty (never true for the two
/// callers here, but kept for parity with Go's returned error).
#[derive(Debug, thiserror::Error)]
#[error("empty word list")]
pub struct EmptyWordList;

/// `randomWord`: one cryptographically random byte, reduced mod the list length. This is Go's
/// actual algorithm, including its slight selection bias (256 is not a multiple of 12 or 20, so
/// the first `256 % len` words are each very slightly more likely than the rest) — a known,
/// deliberately preserved defect, not a bug to fix here.
fn random_word(list: &[&'static str]) -> Result<&'static str, EmptyWordList> {
    if list.is_empty() {
        return Err(EmptyWordList);
    }
    // `crypto/rand.Read`'s Rust equivalent: a real CSPRNG read, same trust boundary as the
    // `getrandom`/`uuid` dependencies elsewhere in this workspace (e.g. `silo_jwt`'s nonces).
    let mut buf = [0u8; 1];
    getrandom::fill(&mut buf).expect("the OS CSPRNG source is unavailable");
    Ok(list[buf[0] as usize % list.len()])
}

/// `randomMatchCode`: `"<adjective> <noun>"`.
pub fn random_match_code() -> Result<String, EmptyWordList> {
    let adjective = random_word(&ADJECTIVES)?;
    let noun = random_word(&NOUNS)?;
    Ok(format!("{adjective} {noun}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_code_has_one_adjective_and_one_noun() {
        let code = random_match_code().unwrap();
        let parts: Vec<&str> = code.split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert!(ADJECTIVES.contains(&parts[0]));
        assert!(NOUNS.contains(&parts[1]));
    }
}
