use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use crate::{
    crypto::handshake::{perform_handshake, HandshakeRole},
    discovery::{
        dht::DhtLayer,
        share_code::{generate_share_code, secs_until_expiry, to_infohash, to_recv_infohash},
    },
    identity::{fingerprint::to_fingerprint, storage::UserIdentity},
    nat::{
        hole_punch::hole_punch,
        quic::{
            make_client_endpoint, make_server_endpoint_with_config, prebuilt_server_config,
            skip_verify_client_config,
        },
        relay::connect_via_relay,
        stun::external_addr,
    },
    session::{relay_session::RelaySession, Session},
    transfer::manifest::ControlMessage,
    Error, Result,
};

// Chunk nonces start above u32::MAX to avoid colliding with control nonces (0..N)
const CHUNK_NONCE_BASE: u64 = 1 << 32;

// ── PeerSession ────────────────────────────────────────────────────────────────

/// A connected, Noise-authenticated session with a remote peer over a direct QUIC connection.
pub struct PeerSession {
    pub connection: quinn::Connection,
    pub remote_pubkey: [u8; 32],
    pub remote_fingerprint: String,
    pub(crate) noise: Arc<Mutex<snow::StatelessTransportState>>,
    /// Next nonce to use when WE send a message (control or chunk).
    pub(crate) send_nonce: Arc<AtomicU64>,
}

impl PeerSession {
    /// Serialize, encrypt, and send a control message on a QUIC send stream.
    ///
    /// Wire format: `[8-byte BE nonce][4-byte BE encrypted_len][encrypted bytes]`
    pub async fn send_ctrl(
        &self,
        stream: &mut quinn::SendStream,
        msg: &ControlMessage,
    ) -> Result<()> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::Relaxed);
        let plaintext = rmp_serde::to_vec_named(msg).map_err(|e| Error::MsgPack(e.to_string()))?;

        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let enc_len = self
            .noise
            .lock()
            .unwrap()
            .write_message(nonce, &plaintext, &mut ciphertext)
            .map_err(|e| Error::Noise(e.to_string()))?;

        stream.write_all(&nonce.to_be_bytes()).await?;
        stream.write_all(&(enc_len as u32).to_be_bytes()).await?;
        stream.write_all(&ciphertext[..enc_len]).await?;
        Ok(())
    }

    /// Receive, decrypt, and deserialize a control message from a QUIC recv stream.
    pub async fn recv_ctrl(&self, stream: &mut quinn::RecvStream) -> Result<ControlMessage> {
        let mut nonce_buf = [0u8; 8];
        stream.read_exact(&mut nonce_buf).await?;
        let nonce = u64::from_be_bytes(nonce_buf);

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let enc_len = u32::from_be_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; enc_len];
        stream.read_exact(&mut ciphertext).await?;

        let mut plaintext = vec![0u8; enc_len];
        let plain_len = self
            .noise
            .lock()
            .unwrap()
            .read_message(nonce, &ciphertext, &mut plaintext)
            .map_err(|e| Error::Noise(e.to_string()))?;

        rmp_serde::from_slice(&plaintext[..plain_len])
            .map_err(|e| Error::MsgPack(e.to_string()))
    }

    /// Encrypt one chunk, splitting into Noise sub-messages if needed.
    ///
    /// Noise's AEAD limit is 65535 bytes per message (65519 plaintext + 16 tag).
    /// We use a fixed sub-message size and encode the count as a 2-byte prefix so
    /// the receiver knows how many sub-messages to read.
    pub fn encrypt_chunk(&self, chunk_index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        const MAX_PLAIN: usize = 65519;
        let mut out = Vec::with_capacity(plaintext.len() + 32);
        let sub_count = plaintext.chunks(MAX_PLAIN).count() as u16;
        out.extend_from_slice(&sub_count.to_be_bytes());
        let noise = self.noise.lock().unwrap();
        for (i, sub) in plaintext.chunks(MAX_PLAIN).enumerate() {
            let nonce = CHUNK_NONCE_BASE + chunk_index as u64 * 256 + i as u64;
            let mut buf = vec![0u8; sub.len() + 16];
            let len = noise
                .write_message(nonce, sub, &mut buf)
                .map_err(|e| Error::Noise(e.to_string()))?;
            out.extend_from_slice(&(len as u32).to_be_bytes());
            out.extend_from_slice(&buf[..len]);
        }
        Ok(out)
    }

    /// Decrypt one chunk, reassembling from Noise sub-messages.
    pub fn decrypt_chunk(&self, chunk_index: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        const MAX_PLAIN: usize = 65519;
        if ciphertext.len() < 2 {
            return Err(Error::Noise("chunk too short".into()));
        }
        let sub_count = u16::from_be_bytes([ciphertext[0], ciphertext[1]]) as usize;
        let mut pos = 2;
        let mut out = Vec::new();
        let noise = self.noise.lock().unwrap();
        for i in 0..sub_count {
            if pos + 4 > ciphertext.len() {
                return Err(Error::Noise("truncated sub-message length".into()));
            }
            let sub_len = u32::from_be_bytes(ciphertext[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + sub_len > ciphertext.len() {
                return Err(Error::Noise("truncated sub-message body".into()));
            }
            let nonce = CHUNK_NONCE_BASE + chunk_index as u64 * 256 + i as u64;
            let mut buf = vec![0u8; MAX_PLAIN];
            let len = noise
                .read_message(nonce, &ciphertext[pos..pos + sub_len], &mut buf)
                .map_err(|e| Error::Noise(e.to_string()))?;
            out.extend_from_slice(&buf[..len]);
            pos += sub_len;
        }
        Ok(out)
    }
}

// ── Sender / announcer side ────────────────────────────────────────────────────

/// Generate a share code, announce on DHT, wait for receiver, handshake.
///
/// Returns `(share_code, session)`. If hole punching fails the connection
/// automatically falls back to the relay at `RELAY_ADDR`.
pub async fn announce_and_connect(
    identity: &UserIdentity,
    dht: &DhtLayer,
) -> Result<(String, Session)> {
    // Generate TLS cert before any network work so it's ready the moment hole punch completes.
    let server_cfg = prebuilt_server_config()?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_port = socket.local_addr()?.port();
    let socket = Arc::new(socket);

    let code = generate_share_code();
    let infohash_send = to_infohash(&code.display);
    let infohash_recv = to_recv_infohash(&code.display);
    let expires_in = secs_until_expiry();

    eprintln!(
        "[announce] share code: {}  (expires in {}m {}s)",
        code.display,
        expires_in / 60,
        expires_in % 60
    );

    let announce_port = match external_addr(&socket).await {
        Some(ext) => {
            eprintln!("[announce] STUN: external address is {}", ext);
            ext.port()
        }
        None => {
            eprintln!("[announce] STUN failed, falling back to local port {}", local_port);
            local_port
        }
    };

    eprintln!("[announce] announcing on DHT, port {}", announce_port);
    dht.announce(infohash_send, announce_port).await;

    eprintln!("[announce] waiting for receiver...");
    let receiver_addr = poll_for_receiver(dht, infohash_recv, 60).await?;
    eprintln!("[announce] receiver found at {}", receiver_addr);

    eprintln!("[announce] hole punching...");
    match hole_punch(socket.clone(), receiver_addr).await {
        Ok(()) => {
            // ── Direct QUIC path ───────────────────────────────────────────────
            eprintln!("[announce] QUIC server starting...");
            let std_socket = Arc::try_unwrap(socket)
                .map_err(|_| Error::ConnectionFailed("socket still borrowed".to_string()))?
                .into_std()?;
            let endpoint = make_server_endpoint_with_config(std_socket, server_cfg)?;

            let incoming = timeout(Duration::from_secs(15), endpoint.accept())
                .await
                .map_err(|_| {
                    Error::ConnectionFailed("timed out waiting for QUIC connect".to_string())
                })?
                .ok_or_else(|| Error::ConnectionFailed("endpoint closed".to_string()))?;

            let conn = incoming
                .accept()
                .map_err(|e| Error::Quic(e.to_string()))?
                .await
                .map_err(|e| Error::Quic(e.to_string()))?;

            eprintln!("[announce] Noise XX handshake (responder)...");
            let (mut send, mut recv) = conn
                .accept_bi()
                .await
                .map_err(|e| Error::Quic(e.to_string()))?;

            let private_key = identity.private_key_bytes();
            let hs =
                perform_handshake(&mut send, &mut recv, &private_key, HandshakeRole::Responder)
                    .await?;
            let remote_fingerprint = to_fingerprint(&hs.remote_pubkey);

            let session = PeerSession {
                connection: conn,
                remote_pubkey: hs.remote_pubkey,
                remote_fingerprint,
                noise: Arc::new(Mutex::new(hs.transport)),
                send_nonce: Arc::new(AtomicU64::new(0)),
            };

            Ok((code.display, Session::Direct(session)))
        }

        Err(Error::HolePunchTimeout) => {
            // ── Relay fallback ─────────────────────────────────────────────────
            drop(socket);
            drop(server_cfg);
            eprintln!("[announce] hole punch timed out — falling back to relay...");

            let tcp = connect_via_relay(&code.display).await?;
            let (mut read_half, mut write_half) = tcp.into_split();

            let private_key = identity.private_key_bytes();
            eprintln!("[announce] Noise XX handshake (responder, via relay)...");
            let hs = perform_handshake(
                &mut write_half,
                &mut read_half,
                &private_key,
                HandshakeRole::Responder,
            )
            .await?;
            let remote_fingerprint = to_fingerprint(&hs.remote_pubkey);

            let relay_session = RelaySession::from_split(
                read_half,
                write_half,
                hs.remote_pubkey,
                remote_fingerprint,
                hs.transport,
            );

            Ok((code.display, Session::Relay(relay_session)))
        }

        Err(e) => Err(e),
    }
}

// ── Receiver / connector side ─────────────────────────────────────────────────

/// Look up a share code, back-announce, hole punch, handshake.
///
/// Falls back to the relay automatically if hole punching times out.
pub async fn lookup_and_connect(
    identity: &UserIdentity,
    code: &str,
    dht: &DhtLayer,
) -> Result<Session> {
    let code = code.to_uppercase();
    let infohash_send = to_infohash(&code);
    let infohash_recv = to_recv_infohash(&code);

    eprintln!("[connect] looking up {} on DHT...", code);
    let sender_addr = dht
        .lookup(infohash_send)
        .await
        .into_iter()
        .next()
        .ok_or(Error::PeerNotFound)?;
    eprintln!("[connect] sender found at {}", sender_addr);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_port = socket.local_addr()?.port();
    let socket = Arc::new(socket);

    let announce_port = match external_addr(&socket).await {
        Some(ext) => {
            eprintln!("[connect] STUN: external address is {}", ext);
            ext.port()
        }
        None => {
            eprintln!("[connect] STUN failed, falling back to local port {}", local_port);
            local_port
        }
    };

    eprintln!("[connect] back-announcing on DHT, port {}...", announce_port);
    dht.announce(infohash_recv, announce_port).await;

    eprintln!("[connect] hole punching...");
    match hole_punch(socket.clone(), sender_addr).await {
        Ok(()) => {
            // ── Direct QUIC path ───────────────────────────────────────────────
            // Our hole_punch completed (we got a punch from sender), but sender
            // still needs to receive a punch from us to finish its own hole_punch
            // and start the QUIC server. Keep punching until we hand the socket
            // to QUIC (~600ms).
            for _ in 0..10 {
                let _ = socket.send_to(b"p2pshare-punch", sender_addr).await;
                tokio::time::sleep(Duration::from_millis(60)).await;
            }

            eprintln!("[connect] QUIC client connecting...");
            let std_socket = Arc::try_unwrap(socket)
                .map_err(|_| Error::ConnectionFailed("socket still borrowed".to_string()))?
                .into_std()?;

            let endpoint = make_client_endpoint(std_socket)?;
            let client_cfg = skip_verify_client_config()?;

            let conn = endpoint
                .connect_with(client_cfg, sender_addr, "p2pshare")
                .map_err(|e| Error::Quic(e.to_string()))?
                .await
                .map_err(|e| Error::Quic(e.to_string()))?;

            eprintln!("[connect] Noise XX handshake (initiator)...");
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| Error::Quic(e.to_string()))?;

            let private_key = identity.private_key_bytes();
            let hs =
                perform_handshake(&mut send, &mut recv, &private_key, HandshakeRole::Initiator)
                    .await?;
            let remote_fingerprint = to_fingerprint(&hs.remote_pubkey);

            let session = PeerSession {
                connection: conn,
                remote_pubkey: hs.remote_pubkey,
                remote_fingerprint,
                noise: Arc::new(Mutex::new(hs.transport)),
                send_nonce: Arc::new(AtomicU64::new(0)),
            };

            Ok(Session::Direct(session))
        }

        Err(Error::HolePunchTimeout) => {
            // ── Relay fallback ─────────────────────────────────────────────────
            drop(socket);
            eprintln!("[connect] hole punch timed out — falling back to relay...");

            let tcp = connect_via_relay(&code).await?;
            let (mut read_half, mut write_half) = tcp.into_split();

            let private_key = identity.private_key_bytes();
            eprintln!("[connect] Noise XX handshake (initiator, via relay)...");
            let hs = perform_handshake(
                &mut write_half,
                &mut read_half,
                &private_key,
                HandshakeRole::Initiator,
            )
            .await?;
            let remote_fingerprint = to_fingerprint(&hs.remote_pubkey);

            let relay_session = RelaySession::from_split(
                read_half,
                write_half,
                hs.remote_pubkey,
                remote_fingerprint,
                hs.transport,
            );

            Ok(Session::Relay(relay_session))
        }

        Err(e) => Err(e),
    }
}

// ── DHT polling ───────────────────────────────────────────────────────────────

async fn poll_for_receiver(
    dht: &DhtLayer,
    infohash: [u8; 20],
    timeout_secs: u64,
) -> Result<SocketAddr> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let peers = dht.lookup(infohash).await;
        if let Some(addr) = peers.into_iter().next() {
            return Ok(addr);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::PeerNotFound);
        }
        sleep(Duration::from_millis(1500)).await;
    }
}
