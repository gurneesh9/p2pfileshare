use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    version::TLS13,
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use std::{net::UdpSocket, sync::Arc};

use crate::{Error, Result};

// ── Server endpoint ────────────────────────────────────────────────────────────

/// Pre-build a QUIC ServerConfig (including TLS cert generation) so it's ready
/// the moment hole punch completes, with no blocking work on the critical path.
pub fn prebuilt_server_config() -> Result<ServerConfig> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["p2pshare".to_string()])
            .map_err(|e| Error::Quic(e.to_string()))?;

    let cert_der: CertificateDer<'static> = cert.der().to_owned();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let ring = Arc::new(rustls::crypto::ring::default_provider());
    let rustls_srv = rustls::ServerConfig::builder_with_provider(ring)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| Error::Quic(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| Error::Quic(e.to_string()))?;

    let quic_srv = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_srv)
        .map_err(|e| Error::Quic(e.to_string()))?;

    Ok(ServerConfig::with_crypto(Arc::new(quic_srv)))
}

/// Build a QUIC server endpoint from a pre-built ServerConfig and a punched socket.
pub fn make_server_endpoint_with_config(socket: UdpSocket, cfg: ServerConfig) -> Result<Endpoint> {
    Endpoint::new(
        EndpointConfig::default(),
        Some(cfg),
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|e| Error::Quic(e.to_string()))
}

// ── Client endpoint ────────────────────────────────────────────────────────────

/// Build a plain QUIC client endpoint (no default client config).
pub fn make_client_endpoint(socket: UdpSocket) -> Result<Endpoint> {
    Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|e| Error::Quic(e.to_string()))
}

/// Build a QUIC `ClientConfig` that skips certificate verification.
///
/// Security comes entirely from the Noise XX handshake that follows.
pub fn skip_verify_client_config() -> Result<ClientConfig> {
    let ring = Arc::new(rustls::crypto::ring::default_provider());
    let rustls_cfg = rustls::ClientConfig::builder_with_provider(ring)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| Error::Quic(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
        .with_no_client_auth();

    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
        .map_err(|e| Error::Quic(e.to_string()))?;

    Ok(ClientConfig::new(Arc::new(quic_cfg)))
}

// ── SkipCertVerification ───────────────────────────────────────────────────────

#[derive(Debug)]
struct SkipCertVerification;

impl ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Return ring's supported schemes without touching global provider state
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
