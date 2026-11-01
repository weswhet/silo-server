//! Outbound mail, ported from `internal/mail`. [`sasl`] is the hand-written SASL layer critique
//! finding 11 calls for, matching go-mail's mechanism-selection rules exactly. [`smtp`] is the
//! transport that drives it.

pub mod sasl;
pub mod smtp;

pub use sasl::AuthType;
pub use smtp::{Security, SendError};

/// The server, credentials, and envelope [`send`] needs. Grouped into one struct rather than one
/// function with nine parameters, which is also what `internal/mail/mail.go`'s `smtpConfig` and
/// `Message` structs do on the Go side.
pub struct SendRequest<'a> {
    pub host: &'a str,
    pub port: u16,
    pub security: Security,
    pub ehlo_name: &'a str,
    /// Empty means no `AUTH` is attempted, matching Go's `cfg.username != ""` gate in `newClient`.
    pub username: &'a str,
    pub password: &'a str,
    pub from: &'a str,
    pub to: &'a [&'a str],
    pub message: &'a [u8],
}

/// Connects, authenticates (if `username` is non-empty, using [`sasl::select`] exactly as go-mail's
/// `authTypeAutoDiscover` does), sends one message, and disconnects. `mail.Sender.Send`'s dial,
/// auth, and send sequence, minus Go's message builder (see `smtp`'s module doc).
pub async fn send(request: SendRequest<'_>) -> Result<(), SendError> {
    let (mut client, capabilities, is_encrypted) = smtp::Client::connect(
        request.host,
        request.port,
        request.security,
        request.ehlo_name,
    )
    .await?;

    if !request.username.is_empty() {
        let advertised = auth_capability(&capabilities);
        let auth_type = sasl::select(&advertised, is_encrypted).ok_or_else(|| {
            SendError::NotSent(
                "no mutually supported SMTP AUTH mechanism was discovered".to_owned(),
            )
        })?;
        client
            .authenticate(auth_type, request.username, request.password)
            .await?;
    }

    let result = client
        .send_envelope(request.from, request.to, request.message)
        .await;
    client.quit().await;
    result
}

/// Extracts the mechanism names from the `EHLO` reply's `AUTH ...` capability line (RFC 4954
/// section 4). go-mail reads this the same way (`client.Extensions()["AUTH"]`, space-joined).
fn auth_capability(capabilities: &[String]) -> Vec<&str> {
    capabilities
        .iter()
        .find_map(|line| line.strip_prefix("AUTH "))
        .map(|rest| rest.split_whitespace().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_capability_reads_the_auth_line() {
        let capabilities = vec![
            "mail.example.org".to_owned(),
            "AUTH SCRAM-SHA-256 SCRAM-SHA-1 CRAM-MD5 PLAIN LOGIN".to_owned(),
            "SIZE 35882577".to_owned(),
        ];
        assert_eq!(
            auth_capability(&capabilities),
            vec!["SCRAM-SHA-256", "SCRAM-SHA-1", "CRAM-MD5", "PLAIN", "LOGIN"]
        );
    }

    #[test]
    fn auth_capability_is_empty_without_an_auth_line() {
        let capabilities = vec!["mail.example.org".to_owned(), "SIZE 35882577".to_owned()];
        assert!(auth_capability(&capabilities).is_empty());
    }
}
