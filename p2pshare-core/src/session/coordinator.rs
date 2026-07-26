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
        lan_broadcast,
        lan_multicast,
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
        relay::{connect_via_relay, connect_via_relay_at},
        stun::external_addr,
    },
    session::{chunk_nonce, relay_session::RelaySession, Session},
    transfer::manifest::ControlMessage,
    Error, Result,
};

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

    /// Decrypt one Noise sub-message received from the stream.
    pub fn decrypt_sub_message(&self, chunk_index: u32, sub_index: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        const MAX_PLAIN: usize = 65519;
        let mut buf = vec![0u8; MAX_PLAIN];
        let len = self.noise.lock().unwrap()
            .read_message(chunk_nonce(chunk_index, sub_index), ciphertext, &mut buf)
            .map_err(|e| Error::Noise(e.to_string()))?;
        Ok(buf[..len].to_vec())
    }

    pub fn encrypt_chunk(&self, chunk_index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        const MAX_PLAIN: usize = 65519;
        let mut out = Vec::with_capacity(plaintext.len() + 32);
        let sub_count = plaintext.chunks(MAX_PLAIN).count() as u16;
        out.extend_from_slice(&sub_count.to_be_bytes());
        let noise = self.noise.lock().unwrap();
        for (i, sub) in plaintext.chunks(MAX_PLAIN).enumerate() {
            let mut buf = vec![0u8; sub.len() + 16];
            let len = noise
                .write_message(chunk_nonce(chunk_index, i as u32), sub, &mut buf)
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
            let mut buf = vec![0u8; MAX_PLAIN];
            let len = noise
                .read_message(chunk_nonce(chunk_index, i as u32), &ciphertext[pos..pos + sub_len], &mut buf)
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
    let session = announce_and_connect_with_code(identity, dht, &code.display, true).await?;
    Ok((code.display, session))
}

/// Same as `announce_and_connect` but uses a pre-generated share code so the
/// code can be displayed to the user before waiting for a peer.
pub async fn announce_and_connect_with_code(
    identity: &UserIdentity,
    dht: &DhtLayer,
    code: &str,
    allow_relay: bool,
) -> Result<Session> {
    let private_key = identity.private_key_bytes();
    let expires_in = secs_until_expiry();

    eprintln!(
        "[announce] share code: {}  (expires in {}m {}s)",
        code,
        expires_in / 60,
        expires_in % 60
    );

    // ── LAN: bind QUIC server + mDNS advertisement ─────────────────────────────
    let lan_server_cfg = prebuilt_server_config()?;
    let lan_std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let lan_port = lan_std_socket.local_addr()?.port();
    let lan_ep = make_server_endpoint_with_config(lan_std_socket, lan_server_cfg)?;

    let _mdns = match mdns::advertise(code, lan_port) {
        Ok(ad) => Some(ad),
        Err(e) => {
            eprintln!("[announce] mDNS unavailable ({e}) — LAN discovery disabled");
            None
        }
    };
    // Multicast UDP (socket2, custom group 239.255.52.52:52525) — works on iOS where mdns-sd doesn't.
    let _multicaster = lan_multicast::start_multicast(code, lan_port).await.ok();
    // Broadcast UDP fallback for networks that filter multicast.
    let _broadcaster = lan_broadcast::start_broadcast(code, lan_port).await.ok();

    // ── Internet: STUN + DHT announce ──────────────────────────────────────────
    let internet_server_cfg = prebuilt_server_config()?;
    let punch_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_port = punch_socket.local_addr()?.port();
    let punch_socket = Arc::new(punch_socket);

    let infohash_send = to_infohash(code);
    let infohash_recv = to_recv_infohash(code);

    let own_ext_ip;
    let announce_port = match external_addr(&punch_socket).await {
        Some(ext) => {
            eprintln!("[announce] STUN: external address is {}", ext);
            own_ext_ip = Some(ext.ip());
            ext.port()
        }
        None => {
            eprintln!("[announce] STUN failed, falling back to local port {}", local_port);
            own_ext_ip = None;
            local_port
        }
    };

    eprintln!("[announce] announcing on DHT, port {}", announce_port);
    dht.announce(infohash_send, announce_port).await;
    eprintln!("[announce] waiting for receiver (LAN or internet)...");

    // ── Race: first connection wins ─────────────────────────────────────────────
    let code_display = code.to_string();

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
            // Wait as long as the share code is valid — a receiver who takes a
            // few minutes to type the code must not kill the announce (this
            // select! aborts the LAN arm too if any arm errors out).
            let wait_secs = secs_until_expiry().max(120);
            let receiver_addr =
                poll_for_receiver(dht, infohash_recv, infohash_send, announce_port, wait_secs)
                    .await?;
            eprintln!("[announce] receiver found at {}", receiver_addr);

            // Same-NAT: receiver shares our external IP → hairpin NAT → hole punch guaranteed to fail.
            // Give the LAN (mDNS) branch a head start, then fall to relay (or error if relay disabled).
            if own_ext_ip.map(|ip| ip == receiver_addr.ip()).unwrap_or(false) {
                eprintln!("[announce] same network detected — skipping hole punch, waiting for LAN path...");
                sleep(Duration::from_secs(7)).await;
                if !allow_relay {
                    eprintln!("[announce] LAN path didn't win and relay is disabled — failing");
                    return Err(Error::ConnectionFailed("same-NAT: LAN path failed and relay is disabled".into()));
                }
                eprintln!("[announce] LAN path didn't win — connecting via relay (same-NAT)...");
                let tcp = connect_via_relay(&code_display).await?;
                let (mut rh, mut wh) = tcp.into_split();
                let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Responder).await?;
                let fingerprint = to_fingerprint(&hs.remote_pubkey);
                eprintln!("[announce] relay: connected to {}", fingerprint);
                return Ok(Session::Relay(RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport)));
            }

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
                    if !allow_relay {
                        eprintln!("[announce] hole punch timed out and relay is disabled — failing");
                        return Err(Error::ConnectionFailed("hole punch timed out and relay is disabled".into()));
                    }
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

    Ok(session)
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
    allow_relay: bool,
) -> Result<Session> {
    let code_upper = code.to_uppercase();
    let private_key = identity.private_key_bytes();
    let infohash_send = to_infohash(&code_upper);
    let infohash_recv = to_recv_infohash(&code_upper);

    eprintln!("[connect] looking up {} (LAN + internet simultaneously)...", code_upper);

    let session = tokio::select! {
        // LAN path — race multicast and broadcast listeners; first one to see the sender wins.
        // Multicast works on iOS (socket2 + IP_ADD_MEMBERSHIP); broadcast is the fallback.
        // On any error the branch is disabled and internet path continues.
        Ok(session) = async {
            let sender_addr = timeout(Duration::from_secs(8), async {
                tokio::select! {
                    Ok(addr) = lan_multicast::listen_for_multicast(&code_upper) => addr,
                    Ok(addr) = lan_broadcast::listen_for_broadcast(&code_upper) => addr,
                    Ok(addr) = mdns::browse_for_code(&code_upper) => addr,
                }
            })
            .await
            .map_err(|_| Error::PeerNotFound)?;   // timeout → PeerNotFound, disables this branch

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
        // Uses Ok(session) = pattern so DHT misses disable this arm without killing the LAN path.
        // lookup_with_retry waits up to 30 s for DHT propagation before giving up.
        Ok(session) = async {
            sleep(Duration::from_millis(800)).await;
            let sender_addr = dht
                .lookup_with_retry(infohash_send, Duration::from_secs(30), Duration::from_secs(2))
                .await
                .into_iter()
                .next()
                .ok_or(Error::PeerNotFound)?;
            eprintln!("[connect] internet: sender found at {}", sender_addr);

            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let local_port = socket.local_addr()?.port();
            let socket = Arc::new(socket);

            let own_ext = external_addr(&socket).await;
            let announce_port = match own_ext {
                Some(ext) => {
                    eprintln!("[connect] STUN: external address is {}", ext);
                    ext.port()
                }
                None => {
                    eprintln!("[connect] STUN failed, using local port {}", local_port);
                    local_port
                }
            };

            // Same-NAT: sender's external IP == ours → same router → hairpin NAT blocks hole punch.
            // Back-announce so sender can find us, then wait for the LAN path before falling to relay.
            if own_ext.map(|e| e.ip() == sender_addr.ip()).unwrap_or(false) {
                eprintln!("[connect] same network detected — skipping hole punch, preferring LAN...");
                dht.announce(infohash_recv, announce_port).await;
                sleep(Duration::from_secs(8)).await;
                drop(socket);
                if !allow_relay {
                    eprintln!("[connect] LAN path timed out and relay is disabled — failing");
                    return Err(Error::ConnectionFailed("same-NAT: LAN path failed and relay is disabled".into()));
                }
                eprintln!("[connect] LAN path timed out — connecting via relay (same-NAT)...");
                let tcp = connect_via_relay(&code_upper).await?;
                let (mut rh, mut wh) = tcp.into_split();
                let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Initiator).await?;
                let fingerprint = to_fingerprint(&hs.remote_pubkey);
                eprintln!("[connect] relay: connected to {}", fingerprint);
                return Ok(Session::Relay(RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport)));
            }

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
                    if !allow_relay {
                        eprintln!("[connect] hole punch timed out and relay is disabled — failing");
                        return Err(Error::ConnectionFailed("hole punch timed out and relay is disabled".into()));
                    }
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
        } => session,

        else => return Err(Error::PeerNotFound),
    };

    Ok(session)
}

// ── LAN-only paths (mDNS only, no DHT, no relay) ─────────────────────────────

/// Sender: bind a QUIC server, advertise via mDNS, wait for a direct LAN connection.
/// No DHT or relay — fails fast if no peer connects on the local network.
pub async fn announce_mdns_only_with_code(
    identity: &UserIdentity,
    code: &str,
) -> Result<Session> {
    let private_key = identity.private_key_bytes();

    let server_cfg = prebuilt_server_config()?;
    let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let port = std_socket.local_addr()?.port();
    let ep = make_server_endpoint_with_config(std_socket, server_cfg)?;

    // Advertise via mDNS (CLI), multicast (iOS/Android via socket2), and broadcast (fallback).
    let _mdns = mdns::advertise(code, port).ok();
    let _multicaster = lan_multicast::start_multicast(code, port).await.ok();
    let _broadcaster = lan_broadcast::start_broadcast(code, port).await.ok();

    eprintln!("[announce] LAN-only: advertising {} on port {}", code, port);

    loop {
        let Some(incoming) = ep.accept().await else {
            return Err(Error::ConnectionFailed("LAN endpoint closed".into()));
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
                return Ok(Session::Direct(make_peer_session(conn, hs.remote_pubkey, hs.transport)));
            }
            Err(e) => { eprintln!("[announce] LAN handshake error: {e}, retrying"); continue; }
        }
    }
}

/// Receiver: browse mDNS for the sender, connect directly via QUIC.
/// No DHT or relay — fails fast if sender not found on local network within 15 s.
pub async fn lookup_mdns_only(identity: &UserIdentity, code: &str) -> Result<Session> {
    let code_upper = code.to_uppercase();
    let private_key = identity.private_key_bytes();

    eprintln!("[connect] LAN-only: listening for {} via multicast + broadcast...", code_upper);

    let sender_addr = timeout(Duration::from_secs(8), async {
        tokio::select! {
            Ok(addr) = lan_multicast::listen_for_multicast(&code_upper) => addr,
            Ok(addr) = lan_broadcast::listen_for_broadcast(&code_upper) => addr,
        }
    })
    .await
    .map_err(|_| Error::ConnectionFailed(
        "Sender not found on local network. Check that both devices are on the same WiFi and your router does not have AP/Client Isolation enabled.".into()
    ))?;

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

    Ok(Session::Direct(make_peer_session(conn, hs.remote_pubkey, hs.transport)))
}

// ── Relay-only paths (no DHT, no hole punch) ──────────────────────────────────

/// Sender: generate a share code, connect to relay, wait to be paired, handshake.
/// Skips DHT and hole punching entirely — use when `--relay` is passed explicitly.
pub async fn announce_via_relay_only(identity: &UserIdentity) -> Result<(String, Session)> {
    let code = generate_share_code();
    let session = announce_via_relay_only_with_code(identity, &code.display).await?;
    Ok((code.display, session))
}

/// Same as `announce_via_relay_only` but uses a pre-generated code.
pub async fn announce_via_relay_only_with_code(
    identity: &UserIdentity,
    code: &str,
) -> Result<Session> {
    let private_key = identity.private_key_bytes();
    // Print the code BEFORE blocking on the relay so the user can share it.
    println!("Share code: {}", code);
    eprintln!("[announce] relay-only mode — connecting to relay...");
    let tcp = connect_via_relay(code).await?;
    let (mut rh, mut wh) = tcp.into_split();
    eprintln!("[announce] Noise XX handshake (responder, relay)...");
    let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Responder).await?;
    let fingerprint = to_fingerprint(&hs.remote_pubkey);
    eprintln!("[announce] relay: connected to {}", fingerprint);
    Ok(Session::Relay(RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport)))
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

/// Sender: relay-only, connecting through a local TCP proxy opened by Dart.
/// Dart opens the real relay connection (via Network.framework) and exposes a
/// local port — Rust connects to 127.0.0.1:proxy_port instead.  Loopback TCP
/// is never subject to macOS Network Extension content filters.
pub async fn announce_via_relay_only_with_code_via_proxy(
    identity: &UserIdentity,
    code: &str,
    proxy_port: u16,
) -> Result<Session> {
    let private_key = identity.private_key_bytes();
    let proxy_addr = format!("127.0.0.1:{}", proxy_port);
    eprintln!("[announce] relay-only (proxy) — connecting to {}...", proxy_addr);
    let tcp = connect_via_relay_at(&proxy_addr, code).await?;
    let (mut rh, mut wh) = tcp.into_split();
    eprintln!("[announce] Noise XX handshake (responder, relay/proxy)...");
    let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Responder).await?;
    let fingerprint = to_fingerprint(&hs.remote_pubkey);
    eprintln!("[announce] relay/proxy: connected to {}", fingerprint);
    Ok(Session::Relay(RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport)))
}

/// Receiver: relay-only, connecting through a local TCP proxy opened by Dart.
pub async fn connect_via_relay_only_via_proxy(
    identity: &UserIdentity,
    code: &str,
    proxy_port: u16,
) -> Result<Session> {
    let code_upper = code.to_uppercase();
    let private_key = identity.private_key_bytes();
    let proxy_addr = format!("127.0.0.1:{}", proxy_port);
    eprintln!("[connect] relay-only (proxy) — connecting to {}...", proxy_addr);
    let tcp = connect_via_relay_at(&proxy_addr, &code_upper).await?;
    let (mut rh, mut wh) = tcp.into_split();
    eprintln!("[connect] Noise XX handshake (initiator, relay/proxy)...");
    let hs = perform_handshake(&mut wh, &mut rh, &private_key, HandshakeRole::Initiator).await?;
    let fingerprint = to_fingerprint(&hs.remote_pubkey);
    eprintln!("[connect] relay/proxy: connected to {}", fingerprint);
    Ok(Session::Relay(RelaySession::from_split(rh, wh, hs.remote_pubkey, fingerprint, hs.transport)))
}

// ── DHT polling ───────────────────────────────────────────────────────────────

async fn poll_for_receiver(
    dht: &DhtLayer,
    infohash: [u8; 20],
    own_infohash: [u8; 20],
    own_port: u16,
    timeout_secs: u64,
) -> Result<SocketAddr> {
    const REANNOUNCE_INTERVAL: Duration = Duration::from_secs(240);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut last_announce = tokio::time::Instant::now();
    loop {
        let peers = dht.lookup(infohash).await;
        if let Some(addr) = peers.into_iter().next() {
            return Ok(addr);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::PeerNotFound);
        }
        // Refresh our own DHT entry so it doesn't age out of peers' stores
        // while we wait for a slow receiver.
        if last_announce.elapsed() >= REANNOUNCE_INTERVAL {
            dht.announce(own_infohash, own_port).await;
            last_announce = tokio::time::Instant::now();
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
