//! A minimal SMTP client that drives [`super::sasl`] over a real connection, matching the shape of
//! `internal/mail/mail.go`'s three security modes (`email.smtp_security`): implicit TLS (`"tls"`),
//! mandatory STARTTLS (the default, `"starttls"`), and no encryption (`"none"`).
//!
//! This intentionally stops at the AUTH exchange and the envelope commands. Building the MIME
//! message itself (`gomail.Msg`'s multipart, attachment, and header assembly in
//! `internal/mail/mail.go`'s `buildMessage`) is a separate, much larger port that critique finding
//! 11 does not call for; a caller of [`Client::send_envelope`] supplies already-built message bytes.
//!
//! go-mail's two line protections hold here: [`validate_line`] refuses CR or LF in a value bound for
//! a command line, and [`dot_stuff`] is `net/textproto`'s `DotWriter`, so a message body cannot end
//! `DATA` early.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::sasl;

/// `email.smtp_security`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Implicit TLS from the first byte (typically port 465). go-mail's `WithSSL`.
    Tls,
    /// STARTTLS is required; the connection fails if the server does not offer it. go-mail's
    /// `TLSMandatory`, Silo's default.
    StartTls,
    /// Never negotiate TLS. go-mail's `NoTLS`.
    None,
}

/// What a send can fail with. Mirrors `internal/mail/mail.go`'s split between "certainly not sent"
/// (`ErrNotSent`: dial, STARTTLS, or AUTH failed) and "delivery uncertain" (anything after that).
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("smtp dial: {0}")]
    NotSent(String),
    #[error("smtp send: {0}")]
    Uncertain(String),
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// An open, authenticated-or-not SMTP connection. Every operation is request/reply, so one buffered
/// stream serves both directions; `tokio::io::BufReader` passes writes straight through to the inner
/// stream.
pub struct Client {
    stream: BufReader<Stream>,
}

async fn read_reply(stream: &mut BufReader<Stream>) -> Result<(u16, String), String> {
    let mut code = None;
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = stream
            .read_line(&mut line)
            .await
            .map_err(|e| format!("reading SMTP reply: {e}"))?;
        if n == 0 {
            return Err("server closed the connection".to_owned());
        }
        let line = line.trim_end_matches(['\r', '\n']);
        // `textproto.parseCodeLine`, on bytes: a server's reply is untrusted, and a multi-byte
        // character across these offsets must be an error rather than a slice panic.
        let (Some(code_text), Some(separator), Some(rest)) =
            (line.get(..3), line.as_bytes().get(3), line.get(4..))
        else {
            return Err(format!("malformed SMTP reply line: {line:?}"));
        };
        if *separator != b' ' && *separator != b'-' {
            return Err(format!("malformed SMTP reply line: {line:?}"));
        }
        let this_code: u16 = code_text
            .parse()
            .map_err(|_| format!("malformed SMTP reply code: {line:?}"))?;
        code.get_or_insert(this_code);
        lines.push(rest.to_owned());
        if *separator == b' ' {
            break;
        }
    }
    Ok((code.unwrap_or(0), lines.join("\n")))
}

/// go-mail's `smtp.validateLine`: a value on a command line must not hold CR or LF, or it could
/// inject further SMTP commands.
pub fn validate_line(line: &str) -> Result<(), SendError> {
    if line.contains(['\r', '\n']) {
        return Err(SendError::NotSent(
            "smtp: A line must not contain CR or LF".to_owned(),
        ));
    }
    Ok(())
}

/// `net/textproto`'s `DotWriter` over a whole message: doubles a leading dot on each line, writes a
/// bare LF as CRLF, and appends the `.` terminator line. A bare CR passes through, as in Go.
pub fn dot_stuff(message: &[u8]) -> Vec<u8> {
    #[derive(PartialEq)]
    enum State {
        BeginLine,
        Data,
        Cr,
        Begin,
    }
    let mut state = State::Begin;
    let mut out = Vec::with_capacity(message.len() + message.len() / 64 + 5);
    for &c in message {
        if matches!(state, State::Begin | State::BeginLine) {
            state = State::Data;
            if c == b'.' {
                out.push(b'.');
            }
        }
        if state == State::Data {
            if c == b'\r' {
                state = State::Cr;
            } else if c == b'\n' {
                out.push(b'\r');
                state = State::BeginLine;
            }
        } else {
            state = if c == b'\n' {
                State::BeginLine
            } else {
                State::Data
            };
        }
        out.push(c);
    }
    match state {
        State::BeginLine => {}
        State::Cr => out.push(b'\n'),
        State::Begin | State::Data => out.extend_from_slice(b"\r\n"),
    }
    out.extend_from_slice(b".\r\n");
    out
}

async fn send_line(stream: &mut BufReader<Stream>, line: &str) -> Result<(), String> {
    stream
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .map_err(|e| format!("writing SMTP command: {e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("flushing SMTP command: {e}"))
}

impl Client {
    /// Connects to `host:port`, applying `security`'s TLS policy exactly as go-mail's
    /// `DialToSMTPClientWithContext` does: `Tls` dials straight into a TLS handshake, `StartTls`
    /// dials plaintext and then requires a successful `STARTTLS`, and `None` never negotiates TLS at
    /// all. `ehlo_name` is the client name the `EHLO` command announces. Returns the client, the
    /// `EHLO` capability lines, and whether the session is now encrypted (the `isEnc` go-mail's
    /// `auth` needs for [`sasl::select`]).
    pub async fn connect(
        host: &str,
        port: u16,
        security: Security,
        ehlo_name: &str,
    ) -> Result<(Self, Vec<String>, bool), SendError> {
        validate_line(ehlo_name)?;
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| SendError::NotSent(format!("dial {host}:{port}: {e}")))?;

        let (inner, mut is_encrypted) = if security == Security::Tls {
            (Stream::Tls(Box::new(tls_connect(host, tcp).await?)), true)
        } else {
            (Stream::Plain(tcp), false)
        };
        let mut stream = BufReader::new(inner);

        // The greeting (220) precedes any command.
        let (code, text) = read_reply(&mut stream).await.map_err(SendError::NotSent)?;
        if code != 220 {
            return Err(SendError::NotSent(format!(
                "unexpected greeting: {code} {text}"
            )));
        }

        let mut capabilities = ehlo(&mut stream, ehlo_name).await?;

        if security == Security::StartTls {
            if !capabilities
                .iter()
                .any(|c| silo_gocompat::strings::equal_fold(c, "STARTTLS"))
            {
                return Err(SendError::NotSent(
                    "server does not offer STARTTLS and email.smtp_security requires it".to_owned(),
                ));
            }
            send_line(&mut stream, "STARTTLS")
                .await
                .map_err(SendError::NotSent)?;
            let (code, text) = read_reply(&mut stream).await.map_err(SendError::NotSent)?;
            if code != 220 {
                return Err(SendError::NotSent(format!(
                    "STARTTLS refused: {code} {text}"
                )));
            }
            let Stream::Plain(tcp) = stream.into_inner() else {
                unreachable!("StartTls only runs on a plaintext stream")
            };
            stream = BufReader::new(Stream::Tls(Box::new(tls_connect(host, tcp).await?)));
            is_encrypted = true;
            // Capabilities (notably AUTH) must be re-read after STARTTLS: a server may only
            // advertise AUTH once the session is encrypted, and a pre-TLS capability list is
            // unauthenticated plaintext (RFC 3207).
            capabilities = ehlo(&mut stream, ehlo_name).await?;
        }

        Ok((Client { stream }, capabilities, is_encrypted))
    }

    /// Authenticates with `select`ed mechanism `auth_type`, driving [`sasl::Mechanism`] over
    /// `AUTH`/`334` continuation lines per RFC 4954. `smtp.auth`/go-mail's `Client.auth`.
    pub async fn authenticate(
        &mut self,
        auth_type: sasl::AuthType,
        username: &str,
        password: &str,
    ) -> Result<(), SendError> {
        let mut mechanism = sasl::mechanism_for(auth_type, username, password);
        let first = mechanism
            .step(None)
            .map_err(|e| SendError::NotSent(e.to_string()))?;
        let mut line = format!("AUTH {}", auth_type.wire_name());
        if !first.response.is_empty() {
            line.push(' ');
            line.push_str(&BASE64.encode(&first.response));
        }
        send_line(&mut self.stream, &line)
            .await
            .map_err(SendError::NotSent)?;
        let mut done = first.done;
        loop {
            let (code, text) = read_reply(&mut self.stream)
                .await
                .map_err(SendError::NotSent)?;
            if code == 235 {
                return Ok(()); // authentication succeeded
            }
            if code != 334 {
                return Err(SendError::NotSent(format!(
                    "SMTP AUTH failed: {code} {text}"
                )));
            }
            if done {
                return Err(SendError::NotSent(
                    "server sent another challenge after the mechanism finished".to_owned(),
                ));
            }
            let challenge = BASE64
                .decode(text.trim())
                .map_err(|e| SendError::NotSent(format!("decoding AUTH challenge: {e}")))?;
            let step = mechanism
                .step(Some(&challenge))
                .map_err(|e| SendError::NotSent(e.to_string()))?;
            let encoded = BASE64.encode(&step.response);
            send_line(&mut self.stream, &encoded)
                .await
                .map_err(SendError::NotSent)?;
            done = step.done;
        }
    }

    /// `MAIL FROM` / `RCPT TO` / `DATA`, sending `message` through [`dot_stuff`]. Addresses are
    /// checked before the first command, so a refused address sends nothing.
    pub async fn send_envelope(
        &mut self,
        from: &str,
        to: &[&str],
        message: &[u8],
    ) -> Result<(), SendError> {
        validate_line(from)?;
        for recipient in to {
            validate_line(recipient)?;
        }
        self.command_expect(&format!("MAIL FROM:<{from}>"), 250)
            .await?;
        for recipient in to {
            self.command_expect(&format!("RCPT TO:<{recipient}>"), 250)
                .await?;
        }
        self.command_expect("DATA", 354).await?;
        self.stream
            .write_all(&dot_stuff(message))
            .await
            .map_err(|e| SendError::Uncertain(format!("writing message body: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| SendError::Uncertain(format!("flushing message body: {e}")))?;
        let (code, text) = read_reply(&mut self.stream)
            .await
            .map_err(SendError::Uncertain)?;
        if code != 250 {
            return Err(SendError::Uncertain(format!("message body: {code} {text}")));
        }
        Ok(())
    }

    async fn command_expect(&mut self, line: &str, want: u16) -> Result<(), SendError> {
        send_line(&mut self.stream, line)
            .await
            .map_err(SendError::Uncertain)?;
        let (code, text) = read_reply(&mut self.stream)
            .await
            .map_err(SendError::Uncertain)?;
        if code != want {
            return Err(SendError::Uncertain(format!("{line}: {code} {text}")));
        }
        Ok(())
    }

    /// `QUIT`, best-effort.
    pub async fn quit(&mut self) {
        let _ = send_line(&mut self.stream, "QUIT").await;
    }
}

async fn ehlo(stream: &mut BufReader<Stream>, name: &str) -> Result<Vec<String>, SendError> {
    send_line(stream, &format!("EHLO {name}"))
        .await
        .map_err(SendError::NotSent)?;
    let (code, text) = read_reply(stream).await.map_err(SendError::NotSent)?;
    if code != 250 {
        return Err(SendError::NotSent(format!("EHLO refused: {code} {text}")));
    }
    Ok(text.lines().map(str::to_owned).collect())
}

async fn tls_connect(host: &str, tcp: TcpStream) -> Result<TlsStream<TcpStream>, SendError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = rustls_pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| SendError::NotSent(format!("invalid TLS server name {host:?}: {e}")))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| SendError::NotSent(format!("TLS handshake with {host}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_line_refuses_line_breaks() {
        assert!(validate_line("a@example.com").is_ok());
        assert!(validate_line("a@example.com>\r\nDATA").is_err());
        assert!(validate_line("a\nb").is_err());
        assert!(validate_line("a\rb").is_err());
    }
}
