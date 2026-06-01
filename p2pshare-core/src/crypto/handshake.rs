use quinn::{RecvStream, SendStream};
use snow::{Builder, StatelessTransportState};

use crate::{Error, Result};

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_MSG_LEN: usize = 65535;

pub enum HandshakeRole {
    Initiator,
    Responder,
}

pub struct HandshakeResult {
    /// The remote peer's static X25519 public key, verified by the Noise handshake.
    pub remote_pubkey: [u8; 32],
    /// Stateless transport state — supports explicit per-message nonces, enabling
    /// parallel chunk encryption/decryption without ordering constraints.
    pub transport: StatelessTransportState,
}

/// Perform a Noise XX handshake over an open QUIC bidirectional stream.
///
/// Each Noise handshake message is framed with a 2-byte big-endian length prefix.
/// After the handshake, `into_stateless_transport_mode` is used so chunks can be
/// encrypted with explicit nonces (chunk_index) independently of message ordering.
pub async fn perform_handshake(
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_static_key: &[u8; 32],
    role: HandshakeRole,
) -> Result<HandshakeResult> {
    let params = NOISE_PARAMS
        .parse()
        .map_err(|e: snow::Error| Error::Noise(e.to_string()))?;

    let builder = Builder::new(params).local_private_key(local_static_key);

    let mut hs = match role {
        HandshakeRole::Initiator => builder.build_initiator(),
        HandshakeRole::Responder => builder.build_responder(),
    }
    .map_err(|e| Error::Noise(e.to_string()))?;

    let mut msg_buf = vec![0u8; MAX_MSG_LEN];

    while !hs.is_handshake_finished() {
        if hs.is_my_turn() {
            let len = hs
                .write_message(&[], &mut msg_buf)
                .map_err(|e| Error::Noise(e.to_string()))?;
            send_framed(send, &msg_buf[..len]).await?;
        } else {
            let msg = recv_framed(recv).await?;
            hs.read_message(&msg, &mut msg_buf)
                .map_err(|e| Error::Noise(e.to_string()))?;
        }
    }

    let remote_pubkey: [u8; 32] = hs
        .get_remote_static()
        .ok_or_else(|| Error::Noise("remote static key unavailable post-handshake".to_string()))?
        .try_into()
        .map_err(|_| Error::Noise("remote static key is not 32 bytes".to_string()))?;

    let transport = hs
        .into_stateless_transport_mode()
        .map_err(|e| Error::Noise(e.to_string()))?;

    Ok(HandshakeResult { remote_pubkey, transport })
}

// ── Framing helpers ────────────────────────────────────────────────────────────

async fn send_framed(send: &mut SendStream, msg: &[u8]) -> Result<()> {
    send.write_all(&(msg.len() as u16).to_be_bytes()).await?;
    send.write_all(msg).await?;
    Ok(())
}

async fn recv_framed(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::keypair::Keypair,
        nat::quic::{make_client_endpoint, make_server_endpoint, skip_verify_client_config},
    };
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn noise_xx_handshake_loopback() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let srv_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
        let srv_addr: SocketAddr =
            (Ipv4Addr::LOCALHOST, srv_sock.local_addr().unwrap().port()).into();
        let srv_endpoint = make_server_endpoint(srv_sock.into_std().unwrap()).unwrap();

        let cli_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
        let cli_endpoint = make_client_endpoint(cli_sock.into_std().unwrap()).unwrap();
        let cli_cfg = skip_verify_client_config().unwrap();

        let srv_key_b = kp_b.secret;
        let cli_key_a = kp_a.secret;
        let expected_a_pub = kp_a.public;
        let expected_b_pub = kp_b.public;

        let srv_handle = tokio::spawn(async move {
            let incoming = srv_endpoint.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            perform_handshake(&mut send, &mut recv, &srv_key_b, HandshakeRole::Responder)
                .await
                .unwrap()
        });

        let conn = cli_endpoint
            .connect_with(cli_cfg, srv_addr, "p2pshare")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let cli_result =
            perform_handshake(&mut send, &mut recv, &cli_key_a, HandshakeRole::Initiator)
                .await
                .unwrap();

        let srv_result = srv_handle.await.unwrap();

        assert_eq!(cli_result.remote_pubkey, expected_b_pub);
        assert_eq!(srv_result.remote_pubkey, expected_a_pub);

        // Verify the stateless transport can encrypt/decrypt across sides
        let nonce = 42u64;
        let plaintext = b"hello p2pshare";
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let len = cli_result
            .transport
            .write_message(nonce, plaintext, &mut ciphertext)
            .unwrap();
        ciphertext.truncate(len);

        let mut decrypted = vec![0u8; ciphertext.len()];
        let dec_len = srv_result
            .transport
            .read_message(nonce, &ciphertext, &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..dec_len], plaintext);
    }
}
