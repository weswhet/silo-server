//! A hand-written SASL layer for SMTP AUTH, because `lettre` 0.11 only offers `PLAIN`, `LOGIN`, and
//! `XOAUTH2` (critique finding 11), while Go's mail sender negotiates through go-mail, which prefers
//! SCRAM-SHA-256, then SCRAM-SHA-1, then CRAM-MD5, then (only once the connection is encrypted)
//! PLAIN and LOGIN (`github.com/wneessen/go-mail@v0.7.3/client.go:1429-1444`,
//! `authTypeAutoDiscover`). Silo's own SMTP security modes (`internal/mail/mail.go`) only ever reach
//! `auth` with `isEnc == true` except for `email.smtp_security = "none"`, where go-mail's
//! `authTypeAutoDiscover` narrows the preference list to SCRAM and CRAM-MD5 and refuses PLAIN and
//! LOGIN outright — the behavior critique finding 11 calls out as a security property `lettre`
//! cannot reproduce.
//!
//! Channel-binding variants (`SCRAM-SHA-1-PLUS`, `SCRAM-SHA-256-PLUS`) are not implemented: they
//! need the `tls-server-end-point` channel-binding data from the TLS session, which this crate's
//! mail transport does not yet thread through (see `mail::smtp`). [`select`] therefore never offers
//! them, even to a server that advertises them, so against a server whose `AUTH` capability line
//! lists only the `-PLUS` forms and neither bare `SCRAM-SHA-1`/`SCRAM-SHA-256` nor `CRAM-MD5`,
//! selection fails where go-mail would succeed. This is a disclosed narrowing, not a divergence that
//! weakens a choice Go would make: every mechanism this module does select, it drives with the same
//! bytes RFC 4616, RFC 4954, RFC 2195, and RFC 5802 specify.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// The mechanisms go-mail's `SMTPAuthType` enumerates, in exactly the identifiers an SMTP server's
/// `250-AUTH ...` capability line names them with. Only the ones [`select`] can choose are listed;
/// go-mail's `SMTPAuthCustom`, `SMTPAuthNoAuth`, and the explicit-choice variants have no bearing on
/// auto-discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    ScramSha256,
    ScramSha1,
    CramMd5,
    Plain,
    Login,
}

impl AuthType {
    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            AuthType::ScramSha256 => "SCRAM-SHA-256",
            AuthType::ScramSha1 => "SCRAM-SHA-1",
            AuthType::CramMd5 => "CRAM-MD5",
            AuthType::Plain => "PLAIN",
            AuthType::Login => "LOGIN",
        }
    }
}

/// `Client.authTypeAutoDiscover`: picks the strongest mechanism both this module and the server
/// support. `advertised` is the server's `AUTH` capability line, split on whitespace exactly as
/// go-mail splits `supported` (`strings.Split(supported, " ")`). `is_encrypted` is whether the
/// connection has TLS at the moment AUTH runs — implicit TLS from the start, or a STARTTLS that has
/// already completed; never true for `email.smtp_security = "none"`.
///
/// Returns `None` exactly where go-mail returns `ErrNoSupportedAuthDiscovered`.
pub fn select(advertised: &[&str], is_encrypted: bool) -> Option<AuthType> {
    let prefer: &[AuthType] = if is_encrypted {
        &[
            AuthType::ScramSha256,
            AuthType::ScramSha1,
            AuthType::CramMd5,
            AuthType::Plain,
            AuthType::Login,
        ]
    } else {
        &[
            AuthType::ScramSha256,
            AuthType::ScramSha1,
            AuthType::CramMd5,
        ]
    };
    prefer
        .iter()
        .find(|mechanism| advertised.contains(&mechanism.wire_name()))
        .copied()
}

/// A step in a SASL exchange: the client's next message, and whether the mechanism is finished after
/// sending it (some mechanisms, like PLAIN, finish in one step; SCRAM needs a final step that only
/// verifies the server, sending nothing of substance but still needing the server's last message).
pub struct Step {
    pub response: Vec<u8>,
    pub done: bool,
}

/// What a SASL step can fail with.
#[derive(Debug, thiserror::Error)]
pub enum SaslError {
    #[error("the server's challenge was not valid base64: {0}")]
    BadChallengeEncoding(base64::DecodeError),
    #[error("the server's challenge was malformed: {0}")]
    MalformedChallenge(String),
    #[error("the server's final SCRAM verifier did not match the expected signature")]
    ServerNotAuthenticated,
    #[error("the mechanism does not expect a challenge at this step")]
    UnexpectedChallenge,
}

/// Drives one SASL mechanism's challenge/response exchange. `step(None)` asks for the initial
/// response (sent as the `AUTH <mechanism> <initial-response>` argument, RFC 4954); every later call
/// passes the server's decoded challenge from its `334 <base64>` continuation line.
pub trait Mechanism: Send {
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<Step, SaslError>;
}

/// RFC 4616 PLAIN: one message, `\0<authzid>\0<authcid>\0<password>` with the authorization identity
/// left empty, exactly as go-mail's vendored `smtp.PlainAuth` builds it.
pub struct Plain {
    username: String,
    password: String,
    sent: bool,
}

impl Plain {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            sent: false,
        }
    }
}

impl Mechanism for Plain {
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<Step, SaslError> {
        if self.sent {
            return Err(SaslError::UnexpectedChallenge);
        }
        let _ = challenge; // PLAIN sends its one message as the initial response.
        self.sent = true;
        let mut response = Vec::with_capacity(1 + self.username.len() + 1 + self.password.len());
        response.push(0);
        response.extend_from_slice(self.username.as_bytes());
        response.push(0);
        response.extend_from_slice(self.password.as_bytes());
        Ok(Step {
            response,
            done: true,
        })
    }
}

/// The historical, non-SASL-registered LOGIN mechanism: the server prompts "Username:" then
/// "Password:" (by convention, not by content this client inspects, matching how real servers and
/// go-mail's own `LoginAuth` behave) and the client answers each in turn.
pub struct Login {
    username: String,
    password: String,
    step: u8,
}

impl Login {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            step: 0,
        }
    }
}

impl Mechanism for Login {
    fn step(&mut self, _challenge: Option<&[u8]>) -> Result<Step, SaslError> {
        match self.step {
            0 => {
                self.step = 1;
                Ok(Step {
                    response: self.username.clone().into_bytes(),
                    done: false,
                })
            }
            1 => {
                self.step = 2;
                Ok(Step {
                    response: self.password.clone().into_bytes(),
                    done: true,
                })
            }
            _ => Err(SaslError::UnexpectedChallenge),
        }
    }
}

/// RFC 2195 CRAM-MD5: the server's challenge is an opaque string (conventionally
/// `<process-id.timestamp@hostname>`); the client answers `username SPACE hex(HMAC-MD5(password,
/// challenge))`.
pub struct CramMd5 {
    username: String,
    password: String,
    sent: bool,
}

impl CramMd5 {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            sent: false,
        }
    }
}

impl Mechanism for CramMd5 {
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<Step, SaslError> {
        if self.sent {
            return Err(SaslError::UnexpectedChallenge);
        }
        let challenge = challenge.ok_or(SaslError::UnexpectedChallenge)?;
        self.sent = true;
        let mut mac = Hmac::<md5::Md5>::new_from_slice(self.password.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(challenge);
        let digest = mac.finalize().into_bytes();
        let mut response = self.username.clone().into_bytes();
        response.push(b' ');
        response.extend(hex_lower(&digest).into_bytes());
        Ok(Step {
            response,
            done: true,
        })
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// One hash family's SCRAM primitives (RFC 5802 section 2.2), so [`Scram`] does not repeat itself
/// per algorithm.
pub trait ScramHash {
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8>;
    fn h(data: &[u8]) -> Vec<u8>;
}

pub struct ScramSha1Hash;
impl ScramHash for ScramSha1Hash {
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts a key of any length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
    fn h(data: &[u8]) -> Vec<u8> {
        use sha1::Digest as _;
        Sha1::digest(data).to_vec()
    }
}

pub struct ScramSha256Hash;
impl ScramHash for ScramSha256Hash {
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a key of any length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
    fn h(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn hi<H: ScramHash>(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    // PBKDF2 with an HMAC pseudorandom function, per RFC 5802 section 2.2's definition of `Hi`.
    let mut u = H::hmac(password, &[salt, &1u32.to_be_bytes()].concat());
    let mut result = u.clone();
    for _ in 1..iterations {
        u = H::hmac(password, &u);
        result = xor(&result, &u);
    }
    result
}

/// Escapes `,` and `=` in a SCRAM `username` attribute per RFC 5802 section 5.1.
fn saslprep_escape(s: &str) -> String {
    s.replace('=', "=3D").replace(',', "=2C")
}

/// RFC 5802 SCRAM, generic over [`ScramHash`]. Used as `Scram<ScramSha1Hash>` and
/// `Scram<ScramSha256Hash>`; neither offers channel binding (`gs2-header` is always `"n,,"`), so
/// servers only see this client advertise the bare mechanism name, never the `-PLUS` variant.
pub struct Scram<H> {
    username: String,
    password: String,
    client_nonce: String,
    client_first_bare: String,
    salted_password: Vec<u8>,
    auth_message: Vec<u8>,
    step: u8,
    _hash: std::marker::PhantomData<H>,
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 18];
    getrandom::getrandom(&mut bytes).expect("the OS RNG is available");
    BASE64.encode(bytes)
}

impl<H: ScramHash> Scram<H> {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::with_nonce(username, password, random_nonce())
    }

    /// For tests: pins the client nonce so a worked example (RFC 5802's own, or a fixture captured
    /// from a real server) reproduces byte for byte.
    fn with_nonce(username: impl Into<String>, password: impl Into<String>, nonce: String) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            client_nonce: nonce,
            client_first_bare: String::new(),
            salted_password: Vec::new(),
            auth_message: Vec::new(),
            step: 0,
            _hash: std::marker::PhantomData,
        }
    }

    fn client_first(&mut self) -> Vec<u8> {
        self.client_first_bare = format!(
            "n={},r={}",
            saslprep_escape(&self.username),
            self.client_nonce
        );
        format!("n,,{}", self.client_first_bare).into_bytes()
    }

    fn client_final(&mut self, server_first: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SaslError> {
        let text = std::str::from_utf8(server_first)
            .map_err(|_| SaslError::MalformedChallenge("server-first is not UTF-8".into()))?;
        let mut server_nonce = None;
        let mut salt_b64 = None;
        let mut iterations = None;
        for attr in text.split(',') {
            if let Some(value) = attr.strip_prefix("r=") {
                server_nonce = Some(value);
            } else if let Some(value) = attr.strip_prefix("s=") {
                salt_b64 = Some(value);
            } else if let Some(value) = attr.strip_prefix("i=") {
                iterations = value.parse::<u32>().ok();
            }
        }
        let server_nonce = server_nonce
            .ok_or_else(|| SaslError::MalformedChallenge("server-first has no nonce".into()))?;
        if !server_nonce.starts_with(&self.client_nonce) {
            return Err(SaslError::MalformedChallenge(
                "server nonce does not extend the client nonce".into(),
            ));
        }
        let salt =
            BASE64
                .decode(salt_b64.ok_or_else(|| {
                    SaslError::MalformedChallenge("server-first has no salt".into())
                })?)
                .map_err(SaslError::BadChallengeEncoding)?;
        let iterations = iterations.ok_or_else(|| {
            SaslError::MalformedChallenge("server-first has no iteration count".into())
        })?;

        self.salted_password = hi::<H>(self.password.as_bytes(), &salt, iterations);
        let client_key = H::hmac(&self.salted_password, b"Client Key");
        let stored_key = H::h(&client_key);
        let channel_binding = BASE64.encode("n,,");
        let client_final_without_proof = format!("c={channel_binding},r={server_nonce}");
        self.auth_message = format!(
            "{},{},{}",
            self.client_first_bare, text, client_final_without_proof
        )
        .into_bytes();
        let client_signature = H::hmac(&stored_key, &self.auth_message);
        let client_proof = xor(&client_key, &client_signature);
        let server_key = H::hmac(&self.salted_password, b"Server Key");
        let expected_server_signature = H::hmac(&server_key, &self.auth_message);

        let message = format!(
            "{client_final_without_proof},p={}",
            BASE64.encode(client_proof)
        )
        .into_bytes();
        Ok((message, expected_server_signature))
    }
}

impl<H: ScramHash + Send> Mechanism for Scram<H> {
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<Step, SaslError> {
        match self.step {
            0 => {
                if challenge.is_some() {
                    return Err(SaslError::UnexpectedChallenge);
                }
                self.step = 1;
                Ok(Step {
                    response: self.client_first(),
                    done: false,
                })
            }
            1 => {
                let server_first = challenge.ok_or(SaslError::UnexpectedChallenge)?;
                let (response, expected_server_signature) = self.client_final(server_first)?;
                self.step = 2;
                self.auth_message = expected_server_signature; // stash for the verify step below
                Ok(Step {
                    response,
                    done: false,
                })
            }
            2 => {
                // Verifies the server's final `v=<signature>` message proves it knew the stored key,
                // the step RFC 5802 section 3 requires and go-mail's SCRAM implementation also runs.
                let server_final = challenge.ok_or(SaslError::UnexpectedChallenge)?;
                let text = std::str::from_utf8(server_final).map_err(|_| {
                    SaslError::MalformedChallenge("server-final is not UTF-8".into())
                })?;
                let signature_b64 = text.strip_prefix("v=").ok_or_else(|| {
                    SaslError::MalformedChallenge("server-final has no verifier".into())
                })?;
                let signature = BASE64
                    .decode(signature_b64)
                    .map_err(SaslError::BadChallengeEncoding)?;
                if signature != self.auth_message {
                    return Err(SaslError::ServerNotAuthenticated);
                }
                self.step = 3;
                Ok(Step {
                    response: Vec::new(),
                    done: true,
                })
            }
            _ => Err(SaslError::UnexpectedChallenge),
        }
    }
}

pub type ScramSha1 = Scram<ScramSha1Hash>;
pub type ScramSha256 = Scram<ScramSha256Hash>;

/// Builds the mechanism [`select`] chose.
pub fn mechanism_for(auth_type: AuthType, username: &str, password: &str) -> Box<dyn Mechanism> {
    match auth_type {
        AuthType::ScramSha256 => Box::new(ScramSha256::new(username, password)),
        AuthType::ScramSha1 => Box::new(ScramSha1::new(username, password)),
        AuthType::CramMd5 => Box::new(CramMd5::new(username, password)),
        AuthType::Plain => Box::new(Plain::new(username, password)),
        AuthType::Login => Box::new(Login::new(username, password)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_prefers_scram_then_cram_then_plain_when_encrypted() {
        let advertised = ["LOGIN", "PLAIN", "CRAM-MD5", "SCRAM-SHA-1", "SCRAM-SHA-256"];
        assert_eq!(select(&advertised, true), Some(AuthType::ScramSha256));
        let without_scram256 = ["LOGIN", "PLAIN", "CRAM-MD5", "SCRAM-SHA-1"];
        assert_eq!(select(&without_scram256, true), Some(AuthType::ScramSha1));
        let only_plain_login = ["LOGIN", "PLAIN"];
        assert_eq!(select(&only_plain_login, true), Some(AuthType::Plain));
    }

    #[test]
    fn select_refuses_plain_and_login_without_encryption() {
        let advertised = ["LOGIN", "PLAIN", "CRAM-MD5"];
        assert_eq!(select(&advertised, false), Some(AuthType::CramMd5));
        let only_plain_login = ["LOGIN", "PLAIN"];
        assert_eq!(select(&only_plain_login, false), None);
    }

    /// RFC 2195 appendix A's worked CRAM-MD5 example.
    #[test]
    fn cram_md5_matches_rfc_2195_example() {
        let mut mechanism = CramMd5::new("tim", "tanstaaftanstaaf");
        let step = mechanism
            .step(Some(b"<1896.697170952@postoffice.reston.mci.net>"))
            .unwrap();
        assert!(step.done);
        assert_eq!(
            String::from_utf8(step.response).unwrap(),
            "tim b913a602c7eda7a495b4e6e7334d3890"
        );
    }

    /// RFC 4616's PLAIN example (section 2).
    #[test]
    fn plain_matches_rfc_4616_example() {
        let mut mechanism = Plain::new("tim", "tanstaaftanstaaf");
        let step = mechanism.step(None).unwrap();
        assert!(step.done);
        assert_eq!(step.response, b"\0tim\0tanstaaftanstaaf");
    }

    /// RFC 5802 section 5's worked SCRAM-SHA-1 example, using the example's own client nonce so the
    /// messages reproduce exactly.
    #[test]
    fn scram_sha1_matches_rfc_5802_example() {
        let mut mechanism = Scram::<ScramSha1Hash>::with_nonce(
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL".to_owned(),
        );
        let first = mechanism.step(None).unwrap();
        assert_eq!(
            String::from_utf8(first.response).unwrap(),
            "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"
        );
        let server_first =
            b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        let second = mechanism.step(Some(server_first)).unwrap();
        assert_eq!(
            String::from_utf8(second.response).unwrap(),
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
        );
        let server_final = b"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";
        let third = mechanism.step(Some(server_final)).unwrap();
        assert!(third.done);
    }

    #[test]
    fn scram_sha1_rejects_a_forged_server_signature() {
        let mut mechanism = Scram::<ScramSha1Hash>::with_nonce(
            "user",
            "pencil",
            "fyko+d2lbbFgONRv9qkxdawL".to_owned(),
        );
        mechanism.step(None).unwrap();
        let server_first =
            b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        mechanism.step(Some(server_first)).unwrap();
        let forged = b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(matches!(
            mechanism.step(Some(forged)),
            Err(SaslError::ServerNotAuthenticated)
        ));
    }
}
