//! TLS for the Postgres wire protocol, matching pgx's per-`sslmode` posture when no
//! `sslrootcert`/`sslcert`/`sslkey` is configured (`config.rs` refuses to start otherwise).
//!
//! pgx's `configTLS` (`pgconn/config.go`) sets `InsecureSkipVerify` on the `tls.Config` it builds
//! for `allow`, `prefer`, and `require` alike when there is no root CA to check against: those
//! modes buy encryption on the wire, not server authentication. `verify-ca` and `verify-full` are
//! the modes that authenticate the server, and this crate does not implement them yet.

use std::sync::Arc;

use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError};
use tokio_postgres_rustls::MakeRustlsConnect;

/// Accepts any server certificate chain, like pgx's `InsecureSkipVerify`. Signatures are still
/// checked cryptographically (via the crypto provider's own algorithms): this skips trusting a
/// particular CA or hostname, not the TLS handshake's integrity.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A `tokio-postgres` TLS connector that encrypts the connection without authenticating the
/// server, for `sslmode` values pgx treats this way (`allow`, `prefer`, `require` without a root
/// CA).
///
/// `direct` is `sslnegotiation=direct`: pgx then offers the `postgresql` ALPN protocol, which a
/// direct TLS connection requires.
pub(crate) fn insecure_connector(direct: bool) -> MakeRustlsConnect {
    let provider = Arc::new(default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("ring's default provider supports TLS 1.2 and 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    if direct {
        config.alpn_protocols = vec![b"postgresql".to_vec()];
    }
    MakeRustlsConnect::new(config)
}
