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

    let mut cfg = ServerConfig::with_crypto(Arc::new(quic_srv));
    cfg.transport_config(Arc::new(p2p_transport_config()));
    Ok(cfg)
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

    let mut cfg = ClientConfig::new(Arc::new(quic_cfg));
    cfg.transport_config(Arc::new(p2p_transport_config()));
    Ok(cfg)
}

// ── Transport config ───────────────────────────────────────────────────────────

fn p2p_transport_config() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    // 128 MB connection-level receive window.
    t.receive_window(quinn::VarInt::from_u32(128 * 1024 * 1024));
    // 64 MB per-stream window — large enough for a full 16 MB chunk + Noise overhead
    // to be in flight so the sender is never stalled waiting for window credits.
    t.stream_receive_window(quinn::VarInt::from_u32(64 * 1024 * 1024));
    // 128 MB send window.
    t.send_window(128 * 1024 * 1024);
    // We only need a handful of streams (1 ctrl bi + 1 data uni), but keep
    // headroom for relay-session streams that share the same config path.
    t.max_concurrent_uni_streams(quinn::VarInt::from_u32(8));
    // BBR instead of the default Cubic. Cubic backs off hard on any packet
    // loss and probes bandwidth slowly, so on real WiFi/internet paths (which
    // always have some loss) it settles well below link capacity and takes many
    // RTTs to get there. BBR models the path's actual bottleneck bandwidth and
    // RTT, so it reaches — and holds — line rate far faster and isn't derailed
    // by non-congestion loss. This is the single biggest lever for "use all the
    // bandwidth the network actually has."
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // 1400-byte initial MTU — safe on Ethernet/WiFi (Ethernet MTU is 1500).
    // This skips the conservative 1200-byte internet default and the PMTUD
    // probe round-trips it would trigger, giving ~17% more payload per packet
    // from the very first frame.
    t.initial_mtu(1400);
    // Keep the hole-punched NAT binding warm during quiet periods, and detect
    // a dead peer within 30 s so a stalled transfer errors out (and can be
    // resumed) instead of hanging forever.
    t.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30))
            .expect("30s fits in VarInt"),
    ));
    t
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
