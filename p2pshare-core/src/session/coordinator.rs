use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use sha1::{Digest, Sha1};

use crate::{
    contacts::model::Contact,
    crypto::handshake::{perform_handshake, HandshakeRole},
    discovery::{
        dht::DhtLayer,
        mdns,
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

const CHUNK_NONCE_BASE: u64 = 1 << 32;

// ── PeerSession ────────────────────────────────────────────────────────────────

/// A connected, Noise-authenticated session over a direct QUIC connection.
pub struct PeerSession {
    pub connection: quinn::Connection,
    pub remote_pubkey: [u8; 32],
    pub remote_fingerprint: String,
    pub(crate) noise: Arc<Mutex<snow::StatelessTransportState>>,
    pub(crate) send_nonce: Arc<AtomicU64>,
}

impl PeerSession {
    /// Serialize, encrypt, and send a control message.
    /// Wire: `[8-byte BE nonce][4-byte BE enc_len][enc_bytes]`
    pub async fn send_ctrl(
        &self,
        stream: &mut quinn::SendStream,
        msg: &ControlMessage,
    ) -> Result<()> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::Relaxed);
        let plaintext =
            rmp_serde::to_vec_named(msg).map_err(|e| Error::MsgPack(e.to_string()))?;
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

    /// Receive, decrypt, and deserialize a control message.
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
            let sub_len =
                u32::from_be_bytes(ciphertext[pos..pos + 4].try_into().unwrap()) as usize;
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

// ── Shared helper ──────────────────────────────────────────────────────────────

fn make_peer_session(
    conn: quinn::Connection,
    remote_pubkey: [u8; 32],
    transport: snow::StatelessTransportState,
) -> PeerSession {
    PeerSession {
        connection: conn,
        remote_fingerprint: to_fingerprint(&remote_pubkey),
        remote_pubkey,
        noise: Arc::new(Mutex::new(transport)),
        send_nonce: Arc::new(AtomicU64::new(0)),
    }
}

// ── Sender side ────────────────────────────────────────────────────────────────

/// Generate a share code, announce on both LAN (mDNS) and internet (DHT),
/// then accept the first peer to connect — whichever path arrives first wins.
///
/// LAN path: bind a QUIC server immediately, advertise via mDNS.
/// Internet path: STUN + DHT + hole punch (relay fallback on timeout).
pub async fn announce_and_connect(
    identity: &UserIdentity,
    dht: &DhtLayer,
) -> Result<(String, Session)> {
    let code = generate_share_code();
    let private_key = identity.private_key_bytes();
    let expires_in = secs_until_expiry();

    eprintln!(
        "[announce] share code: {}  (expires in {}m {}s)",
        code.display,
        expires_in / 60,
        expires_in % 60
    );

    // ── LAN: bind QUIC server + mDNS advertisement ─────────────────────────────
    let lan_server_cfg = prebuilt_server_config()?;
    let lan_std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let lan_port = lan_std_socket.local_addr()?.port();
    let lan_ep = make_server_endpoint_with_config(lan_std_socket, lan_server_cfg)?;

    let _mdns = match mdns::advertise(&code.display, lan_port) {
        Ok(ad) => Some(ad),
        Err(e) => {
            eprintln!("[announce] mDNS unavailable ({e}) — LAN discovery disabled");
            None
        }
    };

    // ── Internet: STUN + DHT announce ──────────────────────────────────────────
    let internet_server_cfg = prebuilt_server_config()?;
    let punch_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_port = punch_socket.local_addr()?.port();
    let punch_socket = Arc::new(punch_socket);

    let infohash_send = to_infohash(&code.display);
    let infohash_recv = to_recv_infohash(&code.display);

    let announce_port = match external_addr(&punch_socket).await {
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
    eprintln!("[announce] waiting for receiver (LAN or internet)...");

    // ── Race: first connection wins ─────────────────────────────────────────────
    let code_display = code.display.clone();

    let session = tokio::select! {
        // LAN path — accept direct QUIC connections from mDNS-discovered peers.
        // Loop so transient failures (e.g. wrong handshake) don't kill the path.
        Ok(session) = async {
            loop {
                let Some(incoming) = lan_ep.accept().await else {
                    break Err(Error::ConnectionFailed("LAN endpoint closed".into()));
                };
                let conn = match incoming.accept().map_err(|e| Error::Quic(e.to_string())) {
                    Ok(c) => match c.await.map_err(|e| Error::Quic(e.to_string())) {
                        Ok(c) => c,
                        Err(e) => { eprintln!("[announce] LAN connection error: {e}"); continue; }
                    },
                    Err(e) => { eprintln!("[announce] LAN incoming error: {e}"); continue; }
                };
                let (mut send, mut recv) = match conn.accept_bi().await.map_err(|e| Error::Quic(e.to_string())) {
                    Ok(s) => s,
                    Err(e) => { eprintln!("[announce] LAN stream error: {e}"); continue; }
                };
                match perform_handshake(&mut send, &mut recv, &private_key, HandshakeRole::Responder).await {
                    Ok(hs) => {
                        eprintln!("[announce] LAN: connected to {}", to_fingerprint(&hs.remote_pubkey));
                        break Ok(Session::Direct(make_peer_session(conn, hs.remote_pubkey, hs.transport)));
                    }
                    Err(e) => { eprintln!("[announce] LAN handshake error: {e}, retrying"); continue; }
                }
            }
        } => session,

        // Internet path — DHT poll → hole punch → QUIC (relay fallback).
        result = async {
            let receiver_addr = poll_for_receiver(dht, infohash_recv, 60).await?;
            eprintln!("[announce] receiver found at {}", receiver_addr);
            eprintln!("[announce] hole punching...");

            match hole_punch(punch_socket.clone(), receiver_addr).await {
                Ok(()) => {
                    eprintln!("[announce] QUIC server starting (internet)...");
                    let std_socket = Arc::try_unwrap(punch_socket)
                        .map_err(|_| Error::ConnectionFailed("socket still borrowed".into()))?
                        .into_std()?;
                    let ep = make_server_endpoint_with_config(std_socket, internet_server_cfg)?;

                    let incoming = timeout(Duration::from_secs(15), ep.accept())
                        .await
                        .map_err(|_| Error::ConnectionFailed("timed out waiting for QUIC".into()))?
                        .ok_or_else(|| Error::ConnectionFailed("endpoint closed".into()))?;

                    let conn = incoming
                        .accept().map_err(|e| Error::Quic(e.to_string()))?
                        .await.map_err(|e| Error::Quic(e.to_string()))?;

                    eprintln!("[announce] Noise XX handshake (responder, internet)...");
                    let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| Error::Quic(e.to_string()))?;
                    let hs = perform_handshake(&mut send, &mut recv, &private_key, HandshakeRole::Responder).await?;
                    eprintln!("[announce] internet: connected to {}", to_fingerprint(&hs.remote_pubkey));

                    Ok(Session::Direct(make_peer_session(conn, hs.remote_pubkey, hs.transport)))
                }

                Err(Error::HolePunchTimeout) => {
                    drop(punch_socket);
                    drop(internet_server_cfg);
                    eprintln!("[announce] hole punch timed out — falling back to relay...");
                    let tcp = connect_via_relay(&code_display).await?;
                    let (mut rh, mut wh) = tcp.into_split();
                    let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Responder).await?;
                    let fingerprint = to_fingerprint(&hs.remote_pubkey);
                    eprintln!("[announce] relay: connected to {}", fingerprint);
                    Ok(Session::Relay(RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport)))
                }

                Err(e) => Err(e),
            }
        } => result?,
    };

    Ok((code.display, session))
}

// ── Receiver side ──────────────────────────────────────────────────────────────

/// Look up a share code and connect to the sender.
///
/// LAN path (runs for up to 3 s): browse mDNS → direct QUIC connect.
/// Internet path (runs in parallel): DHT lookup → back-announce → hole punch
/// (relay fallback on timeout).
/// The first path to succeed wins; the other is cancelled.
pub async fn lookup_and_connect(
    identity: &UserIdentity,
    code: &str,
    dht: &DhtLayer,
) -> Result<Session> {
    let code_upper = code.to_uppercase();
    let private_key = identity.private_key_bytes();
    let infohash_send = to_infohash(&code_upper);
    let infohash_recv = to_recv_infohash(&code_upper);

    eprintln!("[connect] looking up {} (LAN + internet simultaneously)...", code_upper);

    let session = tokio::select! {
        // LAN path — browse mDNS for up to 3 s, then connect directly.
        // On any error the branch is disabled and internet path continues.
        Ok(session) = async {
            let sender_addr = timeout(
                Duration::from_secs(3),
                mdns::browse_for_code(&code_upper),
            )
            .await
            .map_err(|_| Error::PeerNotFound)?   // timeout → PeerNotFound, disables this branch
            ?;                                     // browse error also disables this branch

            eprintln!("[connect] LAN: found sender at {}", sender_addr);

            let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let ep = make_client_endpoint(std_sock)?;
            let cfg = skip_verify_client_config()?;

            let conn = ep
                .connect_with(cfg, sender_addr, "p2pshare")
                .map_err(|e| Error::Quic(e.to_string()))?
                .await
                .map_err(|e| Error::Quic(e.to_string()))?;

            eprintln!("[connect] LAN: Noise XX handshake (initiator)...");
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| Error::Quic(e.to_string()))?;
            let hs = perform_handshake(&mut send, &mut recv, &private_key, HandshakeRole::Initiator).await?;
            eprintln!("[connect] LAN: connected to {}", to_fingerprint(&hs.remote_pubkey));

            Ok::<Session, Error>(Session::Direct(make_peer_session(conn, hs.remote_pubkey, hs.transport)))
        } => session,

        // Internet path — DHT lookup + back-announce + hole punch (relay fallback).
        result = async {
            let sender_addr = dht
                .lookup(infohash_send)
                .await
                .into_iter()
                .next()
                .ok_or(Error::PeerNotFound)?;
            eprintln!("[connect] internet: sender found at {}", sender_addr);

            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let local_port = socket.local_addr()?.port();
            let socket = Arc::new(socket);

            let announce_port = match external_addr(&socket).await {
                Some(ext) => {
                    eprintln!("[connect] STUN: external address is {}", ext);
                    ext.port()
                }
                None => {
                    eprintln!("[connect] STUN failed, using local port {}", local_port);
                    local_port
                }
            };

            eprintln!("[connect] back-announcing on DHT, port {}...", announce_port);
            dht.announce(infohash_recv, announce_port).await;

            eprintln!("[connect] hole punching...");
            match hole_punch(socket.clone(), sender_addr).await {
                Ok(()) => {
                    // Keep punching so sender completes its own hole_punch (~600ms).
                    for _ in 0..10 {
                        let _ = socket.send_to(b"p2pshare-punch", sender_addr).await;
                        tokio::time::sleep(Duration::from_millis(60)).await;
                    }

                    eprintln!("[connect] internet: QUIC connecting...");
                    let std_socket = Arc::try_unwrap(socket)
                        .map_err(|_| Error::ConnectionFailed("socket still borrowed".into()))?
                        .into_std()?;
                    let ep = make_client_endpoint(std_socket)?;
                    let cfg = skip_verify_client_config()?;

                    let conn = ep
                        .connect_with(cfg, sender_addr, "p2pshare")
                        .map_err(|e| Error::Quic(e.to_string()))?
                        .await
                        .map_err(|e| Error::Quic(e.to_string()))?;

                    eprintln!("[connect] internet: Noise XX handshake (initiator)...");
                    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| Error::Quic(e.to_string()))?;
                    let hs = perform_handshake(&mut send, &mut recv, &private_key, HandshakeRole::Initiator).await?;
                    eprintln!("[connect] internet: connected to {}", to_fingerprint(&hs.remote_pubkey));

                    Ok(Session::Direct(make_peer_session(conn, hs.remote_pubkey, hs.transport)))
                }

                Err(Error::HolePunchTimeout) => {
                    drop(socket);
                    eprintln!("[connect] hole punch timed out — falling back to relay...");
                    let tcp = connect_via_relay(&code_upper).await?;
                    let (mut rh, mut wh) = tcp.into_split();
                    let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Initiator).await?;
                    let fingerprint = to_fingerprint(&hs.remote_pubkey);
                    eprintln!("[connect] relay: connected to {}", fingerprint);
                    Ok(Session::Relay(RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport)))
                }

                Err(e) => Err(e),
            }
        } => result?,
    };

    Ok(session)
}

// ── Relay-only paths (no DHT, no hole punch) ──────────────────────────────────

/// Sender: generate a share code, connect to relay, wait to be paired, handshake.
/// Skips DHT and hole punching entirely — use when `--relay` is passed explicitly.
pub async fn announce_via_relay_only(identity: &UserIdentity) -> Result<(String, Session)> {
    let code = generate_share_code();
    let private_key = identity.private_key_bytes();
    let expires_in = secs_until_expiry();

    eprintln!(
        "[announce] share code: {}  (expires in {}m {}s)",
        code.display,
        expires_in / 60,
        expires_in % 60
    );
    eprintln!("[announce] relay-only mode — connecting to relay...");

    let tcp = connect_via_relay(&code.display).await?;
    let (mut rh, mut wh) = tcp.into_split();

    eprintln!("[announce] Noise XX handshake (responder, relay)...");
    let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Responder).await?;
    let fingerprint = to_fingerprint(&hs.remote_pubkey);
    eprintln!("[announce] relay: connected to {}", fingerprint);

    let session = RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport);
    Ok((code.display, Session::Relay(session)))
}

/// Receiver: connect to relay with the given code, wait to be paired, handshake.
/// Skips DHT and hole punching entirely — use when `--relay` is passed explicitly.
pub async fn connect_via_relay_only(identity: &UserIdentity, code: &str) -> Result<Session> {
    let code_upper = code.to_uppercase();
    let private_key = identity.private_key_bytes();

    eprintln!("[connect] relay-only mode — connecting to relay...");

    let tcp = connect_via_relay(&code_upper).await?;
    let (mut rh, mut wh) = tcp.into_split();

    eprintln!("[connect] Noise XX handshake (initiator, relay)...");
    let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Initiator).await?;
    let fingerprint = to_fingerprint(&hs.remote_pubkey);
    eprintln!("[connect] relay: connected to {}", fingerprint);

    Ok(Session::Relay(RelaySession::from_split(
        rh,
        wh,
        hs.remote_pubkey,
        fingerprint,
        hs.transport,
    )))
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

// ── Contact-based connection ───────────────────────────────────────────────────

/// Connect to a known contact.
///
/// Fast path: use `contact.last_known_addr` if cached.
/// Slow path: DHT lookup by `SHA1(pubkey)`, then hole punch (relay fallback).
/// Identity is verified post-handshake — rejects anyone whose pubkey mismatches.
pub async fn connect_to_contact(
    identity: &UserIdentity,
    contact: &Contact,
    dht: &DhtLayer,
) -> Result<Session> {
    let private_key = identity.private_key_bytes();

    let expected_pubkey: [u8; 32] = hex::decode(&contact.public_key)
        .map_err(|_| Error::ConnectionFailed("invalid contact public key".into()))?
        .try_into()
        .map_err(|_| Error::ConnectionFailed("public key wrong length".into()))?;

    // Resolve peer address: cached first, then DHT.
    let peer_addr: SocketAddr = if let Some(ref addr_str) = contact.last_known_addr {
        match addr_str.parse::<SocketAddr>() {
            Ok(addr) => {
                eprintln!("[contact] using cached address {} for {}", addr, contact.display_name);
                addr
            }
            Err(_) => lookup_contact_on_dht(&contact.public_key, dht).await?,
        }
    } else {
        lookup_contact_on_dht(&contact.public_key, dht).await?
    };

    eprintln!("[contact] connecting to {} at {}", contact.display_name, peer_addr);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_port = socket.local_addr()?.port();
    let socket = Arc::new(socket);

    let announce_port = match external_addr(&socket).await {
        Some(ext) => ext.port(),
        None => local_port,
    };

    // Announce ourselves on the contact's recv infohash so they can find us for back-punch.
    let pk_bytes = hex::decode(&contact.public_key).unwrap_or_default();
    let contact_infohash: [u8; 20] = Sha1::digest(&pk_bytes).into();
    dht.announce(contact_infohash, announce_port).await;

    match hole_punch(socket.clone(), peer_addr).await {
        Ok(()) => {
            for _ in 0..10 {
                let _ = socket.send_to(b"p2pshare-punch", peer_addr).await;
                tokio::time::sleep(Duration::from_millis(60)).await;
            }

            let std_socket = Arc::try_unwrap(socket)
                .map_err(|_| Error::ConnectionFailed("socket still borrowed".into()))?
                .into_std()?;
            let ep = make_client_endpoint(std_socket)?;
            let cfg = skip_verify_client_config()?;

            let conn = ep
                .connect_with(cfg, peer_addr, "p2pshare")
                .map_err(|e| Error::Quic(e.to_string()))?
                .await
                .map_err(|e| Error::Quic(e.to_string()))?;

            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| Error::Quic(e.to_string()))?;
            let hs = perform_handshake(&mut send, &mut recv, &private_key, HandshakeRole::Initiator).await?;

            // Verify identity — reject if pubkey doesn't match contact's stored key.
            if hs.remote_pubkey != expected_pubkey {
                return Err(Error::ConnectionFailed(format!(
                    "identity mismatch: expected {} but got {}",
                    contact.fingerprint,
                    to_fingerprint(&hs.remote_pubkey),
                )));
            }

            eprintln!("[contact] connected and verified: {}", contact.display_name);
            Ok(Session::Direct(make_peer_session(conn, hs.remote_pubkey, hs.transport)))
        }

        Err(Error::HolePunchTimeout) => {
            drop(socket);
            eprintln!("[contact] hole punch failed — falling back to relay...");
            // For contact connections we use the contact fingerprint as the relay pairing token.
            let tcp = connect_via_relay(&contact.fingerprint).await?;
            let (mut rh, mut wh) = tcp.into_split();
            let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Initiator).await?;

            if hs.remote_pubkey != expected_pubkey {
                return Err(Error::ConnectionFailed("identity mismatch on relay".into()));
            }

            let fingerprint = to_fingerprint(&hs.remote_pubkey);
            eprintln!("[contact] relay: connected to {}", fingerprint);
            Ok(Session::Relay(RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport)))
        }

        Err(e) => Err(e),
    }
}

async fn lookup_contact_on_dht(public_key_hex: &str, dht: &DhtLayer) -> Result<SocketAddr> {
    let pk_bytes = hex::decode(public_key_hex)
        .map_err(|_| Error::ConnectionFailed("bad public key hex".into()))?;
    let infohash: [u8; 20] = Sha1::digest(&pk_bytes).into();

    eprintln!("[contact] DHT lookup by pubkey...");
    let peers = dht
        .lookup_with_retry(infohash, Duration::from_secs(20), Duration::from_secs(2))
        .await;

    peers.into_iter().next().ok_or(Error::PeerNotFound)
}
