# P2PShare — Protocol & Architecture Specification

> **Version:** 0.2 — Planning Complete  
> **Scope:** Backend protocol, networking stack, identity system, peer discovery, file transfer  
> **Stack:** Rust core, Flutter FFI bridge (FFI deferred — CLI test harness first)  
> **Status:** Ready for implementation

---

## Table of Contents

1. [Project Goals & Principles](#1-project-goals--principles)
2. [System Overview](#2-system-overview)
3. [Identity System](#3-identity-system)
4. [Peer Discovery](#4-peer-discovery)
5. [NAT Traversal](#5-nat-traversal)
6. [VPS Relay — Zero Knowledge Fallback](#6-vps-relay--zero-knowledge-fallback)
7. [Encryption — Noise Protocol](#7-encryption--noise-protocol)
8. [File Transfer Protocol](#8-file-transfer-protocol)
9. [Contacts & Friend System](#9-contacts--friend-system)
10. [Session Lifecycle — End to End](#10-session-lifecycle--end-to-end)
11. [Rust Workspace Structure](#11-rust-workspace-structure)
12. [Crate Dependencies](#12-crate-dependencies)
13. [Data Structures](#13-data-structures)
14. [Error Handling & Edge Cases](#14-error-handling--edge-cases)
15. [VPS Relay Server Spec](#15-vps-relay-server-spec)
16. [Development Phases](#16-development-phases)
17. [Architecture Decisions & Rationale](#17-architecture-decisions--rationale)

---

## 1. Project Goals & Principles

### What This Is
A fully decentralized, encrypted, peer-to-peer file transfer application. Files move directly between devices anywhere in the world. No cloud storage. No accounts. No company in the middle.

### Core Principles

| Principle | Meaning |
|---|---|
| **Zero storage** | No file or metadata ever touches a server |
| **Zero knowledge relay** | VPS relay forwards encrypted bytes only — mathematically cannot read contents |
| **No central authority** | Discovery via BitTorrent DHT — no servers owned by us for matchmaking |
| **Persistent identity** | Users are identified by a cryptographic keypair stored only on their device |
| **Perfect forward secrecy** | Session keys are ephemeral — discarded after transfer |
| **Resumable transfers** | Chunked protocol — drop and reconnect without restarting |

### What We Are NOT Building
- Cloud storage of any kind
- A server that matches or brokers connections (DHT does this)
- Volunteer relay nodes (we run our own VPS relay — controlled, auditable, zero knowledge)
- A QR code proximity flow (transfers work across the world)

---

## 2. System Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         RUST CORE                                │
│                                                                  │
│  ┌───────────────┐  ┌─────────────────┐  ┌──────────────────┐  │
│  │  Identity     │  │   Discovery     │  │    Transfer      │  │
│  │               │  │                 │  │                  │  │
│  │  Keypair gen  │  │  DHT announce   │  │  QUIC streams    │  │
│  │  Fingerprint  │  │  DHT lookup     │  │  Chunking        │  │
│  │  Contacts DB  │  │  Share codes    │  │  Noise encrypt   │  │
│  │               │  │  Presence       │  │  Hash verify     │  │
│  └───────────────┘  └────────┬────────┘  └────────┬─────────┘  │
│                               │                    │            │
│                        ┌──────┴────────────────────┘            │
│                         │  NAT Traversal                        │
│                         │  UDP hole punching                    │
│                         │  Fallback → VPS relay (Phase 4)       │
│                        └──────────────────────────              │
└──────────────────────────────┬───────────────────────────────── ┘
                               │
                    CLI test harness (Phases 1–3)
                    flutter_rust_bridge FFI (later)
                               │
                    ┌──────────┴──────────┐
                    │     Flutter UI      │
                    └─────────────────────┘
```

### Connection Decision Tree

```
Want to send file
      │
      ▼
Generate session → announce on DHT
      │
      ▼
Try direct connection (IP hint from contacts cache)
      │
  success? ──YES──▶ QUIC transfer (direct)
      │
      NO
      │
      ▼
DHT lookup → get peer IPs → UDP hole punch
      │
  success? ──YES──▶ QUIC transfer (direct)
      │
      NO (symmetric NAT ~20%)
      │
      ▼
Connect via VPS relay (E2E encrypted — relay sees nothing)   ← Phase 4
      │
  connected? ──YES──▶ QUIC transfer (via relay pipe)
      │
      NO
      │
      ▼
Notify user — no path available (extremely rare)
```

---

## 3. Identity System

### Overview
Every user has a persistent keypair generated on first app launch. This keypair IS their identity. No registration. No usernames on a server. The public key is their address on the network.

### Key Generation

```rust
// Generated once on first launch — stored in device secure storage
pub struct UserIdentity {
    pub public_key: [u8; 32],     // X25519 — shared freely, this is your network ID
    pub private_key: [u8; 32],    // Never leaves the device
    pub display_name: String,     // User-set local label only
    pub fingerprint: String,      // Human-readable derived from pubkey
    pub created_at: u64,          // Unix timestamp
}
```

### Fingerprint Format

The fingerprint is a human-readable, typeable representation of the public key. Used for out-of-band sharing (verbally, over text, etc.).

```
Public key (32 bytes):   3f 9a 8b 2c 7d 1e 4f 6a ...
Fingerprint:             MANGO-4471-FLUX-9912

Derivation (explicit):
  word1 = BIP39_WORDLIST[ u16::from_be_bytes([pk[0], pk[1]]) % 2048 ]
  num1  = u16::from_be_bytes([pk[2], pk[3]]) % 10000
  word2 = BIP39_WORDLIST[ u16::from_be_bytes([pk[4], pk[5]]) % 2048 ]
  num2  = u16::from_be_bytes([pk[6], pk[7]]) % 10000
  format: "{WORD1}-{num1:04}-{WORD2}-{num2:04}"

Uses 8 of the 32 pubkey bytes. Collision probability is acceptable for
human-verified identity — full key verification happens via Noise handshake.
```

Fingerprints are:
- Short enough to read aloud or type manually
- Unique enough to identify a peer unambiguously in practice
- Derived deterministically from the public key — no lookup table needed
- NOT a complete key representation — never use alone for cryptographic decisions

### Local Storage

During CLI development: `~/.config/p2pshare/identity.json` (plaintext).  
On mobile (later): device keychain / secure enclave.

```json
{
  "public_key": "3f9a8b2c...",
  "private_key": "...",
  "display_name": "Alice",
  "fingerprint": "MANGO-4471-FLUX-9912",
  "created_at": 1748000000
}
```

### DHT Presence Key

When the app is open, the user announces their presence on the DHT using the standard `announce_peer` API (IP:port only — no arbitrary value storage needed):

```
DHT infohash = SHA1(public_key)     // 20 bytes — standard DHT infohash
Announcement = current IP:port      // standard announce_peer — no BEP 44 required
TTL          = 30 minutes           // re-announced every 25 minutes
```

Any contact who knows your public key can compute the infohash and find your current IP on the DHT. Identity is verified by the Noise handshake after connecting, not by the DHT value.

---

## 4. Peer Discovery

Two mechanisms working together:

### Mechanism A — Short Share Code (New / One-Time Transfers)

Used when sending to someone not yet in contacts, or for a quick one-off transfer.

```
Sender generates:   MANGO-4471
                        │
            infohash = SHA1(code + ":" + floor(unix_time / 3600))
                        │
            Announces at that infohash on DHT (standard announce_peer)
                        │
            Shares code via any channel
            (WhatsApp, SMS, verbally — anything)
                        │
Receiver types:     MANGO-4471
                        │
            Same infohash derivation
                        │
            DHT lookup → gets sender's IP:port
                        │
            Direct connection + Noise handshake
```

**Code properties:**
- `WORD-NNNN` format — 8–12 characters, easy to type and read aloud
- Time-windowed: expires automatically after 1 hour, no cleanup needed
- No server stores or validates codes
- Impersonation protection: Noise XX handshake cryptographically rejects anyone without the sender's private key — guessing the code is not enough

**IMPORTANT — infohash design decision:**  
The original spec included `sender_pk` as a salt in the infohash. This is removed because:
1. Standard DHT `announce_peer` stores IP:port only — the receiver has no way to get `sender_pk` from the DHT to compute the same infohash
2. The salt provides no real security benefit — Noise XX already handles authentication

The infohash is `SHA1(code + ":" + hour)` only. Identity is verified post-connection.

**Code generation:**

```rust
pub fn generate_share_code() -> ShareCode {
    let word = BIP39_WORDLIST[rand::random::<usize>() % BIP39_WORDLIST.len()];
    let num  = rand::random::<u16>() % 10000;

    ShareCode {
        display: format!("{}-{:04}", word.to_uppercase(), num),
        // e.g. "MANGO-4471"
    }
}

pub fn code_to_infohash(code: &str) -> [u8; 20] {
    let hour = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap()
        .as_secs() / 3600;

    sha1(format!("{}:{}", code, hour).as_bytes())
}
```

### Hole Punch Coordination for Share Code Transfers

For hole punching to work, both sides must punch simultaneously — which means both must know each other's IP. The sender gets the receiver's IP via a back-announce:

```
Sender announces:   infohash_send = SHA1(code + ":" + hour)
Receiver announces: infohash_recv = SHA1(code + ":recv:" + hour)

Flow:
  1. Receiver looks up infohash_send → gets sender IP
  2. Receiver announces at infohash_recv with its own IP
  3. Sender polls infohash_recv → gets receiver IP
  4. Both have each other's IPs → simultaneous hole punch
  5. QUIC connection over punched socket
```

This adds ~1–2 seconds for one extra DHT round-trip. Acceptable. Both infohashes expire at the same hour boundary.

### Mechanism B — Contact Lookup (Known Peers)

Used when sending to someone already in the contacts list.

```rust
pub async fn find_contact(contact: &Contact, dht: &Dht) -> Result<SocketAddr> {

    // 1. Try cached IP first (fast path — usually works)
    if let Some(cached) = contact.last_known_addr {
        if try_connect(cached).await.is_ok() {
            return Ok(cached);
        }
    }

    // 2. DHT lookup using their public key
    let infohash = sha1(&contact.public_key);
    let peers = dht.get_peers(infohash).await?;

    // 3. Try each returned address
    for peer_addr in peers {
        if try_connect(peer_addr).await.is_ok() {
            contact.last_known_addr = Some(peer_addr);
            return Ok(peer_addr);
        }
    }

    Err(Error::PeerOffline)
}
```

### DHT Implementation

Uses the `mainline` crate — compatible with the global BitTorrent DHT network (millions of nodes, no infrastructure cost). Development and production both use the global DHT.

```rust
use mainline::Dht;

pub struct DhtLayer {
    dht: Dht,
}

impl DhtLayer {
    pub async fn announce(&self, infohash: [u8; 20], port: u16) {
        self.dht.announce_peer(infohash, port).await;
        // Re-announce every 25 min — DHT entries expire at 30 min
    }

    pub async fn lookup(&self, infohash: [u8; 20]) -> Vec<SocketAddr> {
        self.dht.get_peers(infohash).await
            .unwrap_or_default()
    }
}
```

> **Note:** Verify exact `mainline` 2.x async API before implementing — `announce_peer` / `get_peers` signatures may differ from pseudocode above.

---

## 5. NAT Traversal

### NAT Type Classification

| Type | Prevalence | Hole Punch? |
|---|---|---|
| Full Cone | ~50% | Easy — send to public IP:port |
| Port Restricted | ~30% | Works — simultaneous send from both sides |
| Symmetric | ~20% | Fails — falls back to relay (Phase 4) |

### UDP Hole Punching

Both peers send UDP packets simultaneously using IPs exchanged via the DHT back-announce described in Section 4.

```rust
pub async fn hole_punch(
    local_socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr> {

    let start = Instant::now();

    // Send punches — opens outbound hole in our NAT
    let punch_task = tokio::spawn({
        let socket = local_socket.clone();
        async move {
            for _ in 0..20 {
                let _ = socket.send_to(b"p2pshare-punch", peer_addr).await;
                sleep(Duration::from_millis(100)).await;
            }
        }
    });

    // Listen for incoming punch — confirms peer's hole is open too
    let mut buf = [0u8; 32];
    loop {
        if start.elapsed() > timeout {
            return Err(Error::HolePunchTimeout);
        }

        let (len, addr) = local_socket.recv_from(&mut buf).await?;

        if addr == peer_addr && &buf[..len] == b"p2pshare-punch" {
            punch_task.abort();
            return Ok(addr); // hole is open — proceed to QUIC
        }
    }
}
```

### QUIC Over the Punched Hole

QUIC is established over the same UDP socket after hole punching succeeds.

**TLS for QUIC:** quinn requires TLS. Strategy: generate a throwaway self-signed cert per session with `rcgen`, use a `ServerCertVerifier` that accepts any cert without verification. Noise XX handles real authentication — QUIC TLS is just transport scaffolding here.

```rust
use rcgen::generate_simple_self_signed;
use rustls::client::danger::ServerCertVerifier;

struct SkipCertVerification;

impl ServerCertVerifier for SkipCertVerification {
    // Accept all certs — Noise XX verifies identity, not TLS
    fn verify_server_cert(&self, ..) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    // .. other required trait methods
}

pub async fn establish_quic(
    socket: UdpSocket,
    peer_addr: SocketAddr,
    role: Role,
) -> Result<quinn::Connection> {

    // Server side: generate throwaway cert
    let cert = generate_simple_self_signed(vec!["p2pshare".into()])?;
    let server_config = ServerConfig::with_single_cert(..)?;

    // Client side: skip cert verification
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
        .with_no_client_auth();

    let endpoint = quinn::Endpoint::new(
        EndpointConfig::default(),
        server_config_if_receiver,
        socket,
        Arc::new(TokioRuntime),
    )?;

    match role {
        Role::Sender   => endpoint.connect_with(client_config, peer_addr, "p2pshare")?.await,
        Role::Receiver => endpoint.accept().await?.await,
    }
}
```

> **Note:** Verify exact quinn 0.11 API for `connect_with` and `Endpoint::new` before implementing.

---

## 6. VPS Relay — Zero Knowledge Fallback

> **Status: DEFERRED — Phase 4**  
> The relay is not part of the initial implementation. Phases 1–3 cover direct connection only. Relay will be added once core transfer is validated.

### Design Principle

The relay server is a **dumb pipe**. It has no awareness of:
- File contents (encrypted before leaving sender's device)
- Filenames or sizes
- User identities
- Any metadata beyond session token and IP addresses

It cannot store anything useful even if compelled to — it never has the decryption keys.

### How It Works

```
Phone A                    VPS Relay                    Phone B
  │                            │                            │
  │── CONNECT session_token ──▶│◀── CONNECT session_token ──│
  │                            │                            │
  │                    pairs the two connections            │
  │                            │                            │
  │◀══ encrypted QUIC bytes ═══════════════════════════════▶│
  │                            │                            │
  │                   relay forwards bytes blindly          │
  │                   no decryption possible                │
  │                   no storage                            │
```

### Session Token

A one-time token is embedded in the share code or contact lookup. Both sides present it to the relay — the relay pairs them and begins forwarding. Token is single-use and expires in 10 minutes.

```rust
pub struct RelayToken {
    token: [u8; 16],     // random — just a pairing key
    expires_at: u64,     // unix timestamp — relay enforces this
}
```

### Relay Server (Minimal Rust Binary)

```rust
async fn handle_relay_session(
    token: [u8; 16],
    mut conn_a: QuicConnection,
    mut conn_b: QuicConnection,
) {
    let (mut send_a, mut recv_a) = conn_a.accept_bi().await.unwrap();
    let (mut send_b, mut recv_b) = conn_b.accept_bi().await.unwrap();

    // Pipe bytes bidirectionally — no inspection, no storage
    tokio::join!(
        tokio::io::copy(&mut recv_a, &mut send_b),
        tokio::io::copy(&mut recv_b, &mut send_a),
    );
    // Session ends — both connections close — memory freed — nothing persisted
}
```

### VPS Requirements

- A $5–10/month VPS is sufficient
- CPU: minimal (just forwarding bytes, no processing)
- RAM: minimal (no storage, session state is tiny)
- Bandwidth: the main cost — monitor and scale as needed
- No database needed — purely stateful in-memory session pairing
- Multiple VPS nodes in different regions hardcoded for latency optimization

### Relay Discovery

Relay addresses are hardcoded in the app binary. No server needed to discover relays.

```rust
pub const RELAY_NODES: &[&str] = &[
    "relay1.p2pshare.app:7000",   // US East
    "relay2.p2pshare.app:7000",   // EU West
    "relay3.p2pshare.app:7000",   // Asia Pacific
];
```

App picks the lowest-latency relay by pinging all of them at session start.

---

## 7. Encryption — Noise Protocol

### Pattern: Noise XX

Used for all connections — both known contacts and new peers via share code.

```
XX handshake:
  → e                     Sender sends ephemeral key
  ← e, ee, s, es          Receiver responds + exchanges static key
  → s, se                 Sender sends static key + completes exchange

Both sides end up with:
  - Shared symmetric key derived via Diffie-Hellman
  - Mutual authentication (both parties verified)
  - Perfect forward secrecy (ephemeral keys discarded after handshake)
```

Why XX:
- Works when both parties have static keys (contacts) AND when only one side is known (share code)
- Both sides authenticate each other — prevents man-in-the-middle
- Ephemeral keys mean past sessions cannot be decrypted even if long-term keys are later compromised

### Encryption After Handshake

All file chunks encrypted with **ChaCha20-Poly1305**:
- Authenticated encryption — tampering is detected immediately
- Fast on mobile hardware (no AES acceleration needed)
- 256-bit keys

```rust
use snow::{Builder, params::NoiseParams};

pub fn noise_params() -> NoiseParams {
    "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
}

pub async fn perform_handshake(
    stream: &mut QuicStream,
    local_static_key: &[u8; 32],
    role: Role,
) -> Result<snow::TransportState> {

    let builder = Builder::new(noise_params())
        .local_private_key(local_static_key);

    let mut handshake = match role {
        Role::Sender   => builder.build_initiator()?,
        Role::Receiver => builder.build_responder()?,
    };

    // Exchange handshake messages over QUIC control stream
    let mut buf = vec![0u8; 65535];
    while !handshake.is_handshake_finished() {
        if handshake.is_my_turn() {
            let len = handshake.write_message(&[], &mut buf)?;
            stream.write_all(&buf[..len]).await?;
        } else {
            let len = stream.read(&mut buf).await?;
            handshake.read_message(&buf[..len], &mut vec![])?;
        }
    }

    Ok(handshake.into_transport_mode()?)
}
```

### Identity Verification on Contact Connect

When connecting to a known contact, after the Noise XX handshake:

```rust
let remote_pubkey = handshake.get_remote_static().unwrap();

if remote_pubkey != contact.public_key {
    return Err(Error::IdentityMismatch);
    // Connection rejected — someone is impersonating the contact
}
```

For share code transfers, the remote pubkey is saved and presented to the user as the fingerprint for optional contact add.

---

## 8. File Transfer Protocol

### Transfer Mode

Every transfer declares a `TransferMode`. This is included in `FileManifest` so both sides agree on the protocol variant.

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TransferMode {
    /// Standard bulk transfer — parallel QUIC streams, unordered chunk delivery.
    /// Receiver writes chunks at correct file offset as they arrive.
    /// Only mode implemented in Phases 1–3.
    Bulk,

    /// Progressive streaming — chunks sent in sequential order on a single stream.
    /// Receiver exposes a local HTTP endpoint for the media player.
    /// Enables instant playback of video/audio before transfer completes.
    /// NOT YET IMPLEMENTED — reserved for a future phase.
    Streaming(StreamingConfig),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StreamingConfig {
    pub buffer_chunks: u32,   // how many verified chunks to buffer before playback starts
    pub local_port:    u16,   // receiver opens localhost:port as HTTP byte-range server
}
```

**Streaming mode notes (design, not yet implemented):**

- Sender detects MIME type (video/audio), offers streaming mode
- Chunks sent in-order on a single QUIC stream (no parallelism for ordering guarantee)
- Receiver buffers verified chunks, exposes `localhost:<port>/<session_id>` via a minimal HTTP server
- Flutter UI opens that URL in the platform video player
- Playback starts once `buffer_chunks` chunks are verified
- MP4/MOV files recorded on phones often have `moov` atom at end — sender must rewrite to front before streaming (non-trivial; may require two-pass or requiring fast-start MP4)
- Seeking while receiving requires the relevant chunks to already be received — partial seek support only

For now: `TransferMode::Bulk` is the only valid value. The `Streaming` variant is in the wire format to avoid a breaking change later.

### Chunking Strategy

```rust
pub fn chunk_size_for(file_size: u64) -> u32 {
    match file_size {
        0..=10_000_000           => 65_536,    // < 10MB  → 64KB chunks
        10_000_001..=500_000_000 => 262_144,   // < 500MB → 256KB chunks
        _                        => 1_048_576, // > 500MB → 1MB chunks
    }
}

pub fn parallel_streams_for(mode: &TransferMode, file_size: u64) -> usize {
    match mode {
        TransferMode::Streaming(_) => 1, // ordered — must be single stream
        TransferMode::Bulk => match file_size {
            0..=10_000_000           => 2,
            10_000_001..=500_000_000 => 4,
            _                        => 8,
        },
    }
}
```

### File Manifest

Sent from sender to receiver before transfer begins.

```rust
pub struct FileManifest {
    pub session_id:     [u8; 20],
    pub filename:       String,
    pub mime_type:      String,
    pub total_size:     u64,
    pub chunk_size:     u32,
    pub chunk_count:    u32,
    pub chunks:         Vec<ChunkMeta>,
    pub transfer_mode:  TransferMode,  // Bulk always for now
    pub created_at:     u64,
}

pub struct ChunkMeta {
    pub index: u32,
    pub size:  u32,        // actual size (last chunk may be smaller)
    pub hash:  [u8; 32],   // SHA-256 of plaintext chunk — verified post-decrypt
}
```

### Transfer Flow (Bulk Mode)

```
Sender                                        Receiver
  │                                               │
  │── [control stream] send FileManifest ────────▶│
  │                                               │── verify manifest
  │◀── [control stream] ACK ──────────────────────│
  │                                               │
  │   open N parallel QUIC streams (N = 2/4/8)   │
  │                                               │
  │── [stream 1] chunk 0 ────────────────────────▶│── decrypt → verify SHA-256 → write
  │── [stream 2] chunk 1 ────────────────────────▶│── decrypt → verify SHA-256 → write
  │── [stream 3] chunk 2 ────────────────────────▶│── decrypt → verify SHA-256 → write
  │     ...                                       │
  │                                               │
  │◀── [control] NACK chunk 4 ────────────────────│  (hash mismatch — re-request)
  │── [stream N] chunk 4 (retry) ────────────────▶│
  │                                               │
  │◀── [control] COMPLETE ────────────────────────│
  │                                               │
  │   session keys discarded                      │  session keys discarded
```

### Chunk Send

Memory is bounded by a `bytes_in_flight` counter — prevents large chunk sizes × high parallelism from ballooning memory.

```rust
const MAX_BYTES_IN_FLIGHT: usize = 32 * 1024 * 1024; // 32MB cap

pub async fn send_chunks(
    conn: &quinn::Connection,
    noise: Arc<Mutex<snow::TransportState>>,
    manifest: &FileManifest,
    file_path: &Path,
) -> Result<()> {

    let semaphore       = Arc::new(Semaphore::new(parallel_streams_for(&manifest.transfer_mode, manifest.total_size)));
    let bytes_in_flight = Arc::new(AtomicUsize::new(0));
    let mut handles     = vec![];

    for chunk in &manifest.chunks {
        // Back-pressure: wait if too many bytes are in flight
        while bytes_in_flight.load(Ordering::Relaxed) > MAX_BYTES_IN_FLIGHT {
            tokio::task::yield_now().await;
        }

        let permit          = semaphore.clone().acquire_owned().await?;
        let conn            = conn.clone();
        let noise           = noise.clone();
        let bytes_in_flight = bytes_in_flight.clone();
        let chunk           = chunk.clone();
        let path            = file_path.to_path_buf();

        handles.push(tokio::spawn(async move {
            let mut stream = conn.open_uni().await?;
            let data = read_chunk_from_file(&path, &chunk).await?;

            bytes_in_flight.fetch_add(data.len(), Ordering::Relaxed);

            let mut encrypted = vec![0u8; data.len() + 16];
            noise.lock().await.write_message(&data, &mut encrypted)?;

            stream.write_all(&chunk.index.to_be_bytes()).await?;
            stream.write_all(&encrypted).await?;
            stream.finish().await?;

            bytes_in_flight.fetch_sub(data.len(), Ordering::Relaxed);
            drop(permit);
            Ok::<_, Error>(())
        }));
    }

    futures::future::try_join_all(handles).await?;
    Ok(())
}
```

### Chunk Receive & Verify

```rust
pub async fn receive_chunk(
    stream: &mut quinn::RecvStream,
    noise: &mut snow::TransportState,
    manifest: &FileManifest,
    output_path: &Path,
) -> Result<u32> {

    let mut index_buf = [0u8; 4];
    stream.read_exact(&mut index_buf).await?;
    let index = u32::from_be_bytes(index_buf);

    let encrypted = stream.read_to_end(2 * 1024 * 1024).await?; // 2MB max

    let mut plaintext = vec![0u8; encrypted.len()];
    noise.read_message(&encrypted, &mut plaintext)?;

    let actual_hash   = sha256(&plaintext);
    let expected_hash = manifest.chunks[index as usize].hash;

    if actual_hash != expected_hash {
        return Err(Error::ChunkHashMismatch { index });
        // Caller sends NACK → sender retries this chunk
    }

    let offset = index as u64 * manifest.chunk_size as u64;
    write_chunk_at_offset(output_path, offset, &plaintext).await?;

    Ok(index)
}
```

### Resumability

Transfers are resumable across disconnections and app restarts.

```rust
pub struct TransferState {
    pub session_id:     [u8; 20],
    pub manifest:       FileManifest,
    pub chunks_done:    BTreeSet<u32>,   // persisted to disk
    pub chunks_pending: BTreeSet<u32>,
    pub output_path:    PathBuf,
}

impl TransferState {
    // Persisted as ~/.config/p2pshare/transfers/<session_id_hex>.json
    // On reconnect, receiver sends ResumeRequest { have_chunks }
    // Sender skips those chunks and only sends missing ones
    pub fn save(&self) -> Result<()> { ... }
    pub fn load(session_id: &[u8; 20]) -> Result<Self> { ... }
    pub fn missing_chunks(&self) -> Vec<u32> {
        self.manifest.chunks.iter()
            .map(|c| c.index)
            .filter(|i| !self.chunks_done.contains(i))
            .collect()
    }
}
```

---

## 9. Contacts & Friend System

### Contact Model

```rust
pub struct Contact {
    pub id:              Uuid,
    pub display_name:    String,
    pub public_key:      [u8; 32],               // permanent network identity
    pub fingerprint:     String,                  // human-readable key representation
    pub last_known_addr: Option<SocketAddr>,      // cached for fast reconnect
    pub added_at:        u64,
    pub last_seen:       Option<u64>,
}
```

All contacts stored in local SQLite only. Never synced to any server.

```sql
-- ~/.config/p2pshare/contacts.db
CREATE TABLE contacts (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    public_key      BLOB NOT NULL,
    fingerprint     TEXT NOT NULL,
    last_known_addr TEXT,
    added_at        INTEGER NOT NULL,
    last_seen       INTEGER
);
```

### Adding a Contact

**After a share code transfer:**
```
Transfer completes via share code
Both sides offered: "Add [fingerprint] to contacts?"
If accepted:
  - Public key from the completed Noise handshake saved as new contact
  - User assigns a display name
  - Contact stored locally
```

**Manual add (out of band):**
```
User shares their fingerprint via any channel (text, verbally, etc.)
  e.g. "My ID is MANGO-4471-FLUX-9912"

Other user enters fingerprint in "Add Contact" screen
  App derives public key from fingerprint
  Stores as pending contact

On next app open, the new contact announces their IP on DHT
App resolves and verifies — contact marked as active
```

### Contact Presence

Contacts show as online/offline based on DHT presence:

```rust
pub async fn check_presence(
    contacts: &[Contact],
    dht: &DhtLayer,
) -> HashMap<Uuid, PresenceStatus> {

    let mut statuses = HashMap::new();

    for contact in contacts {
        let infohash = sha1(&contact.public_key);
        let peers = dht.lookup(infohash).await;

        let status = if peers.is_empty() {
            PresenceStatus::Offline
        } else {
            PresenceStatus::Online { addr: peers[0] }
        };

        statuses.insert(contact.id, status);
    }

    statuses
}
```

Presence is checked:
- On app foreground
- Every 5 minutes while app is open
- Before initiating a transfer

---

## 10. Session Lifecycle — End to End

### Full Flow: Share Code (New Person)

```
1.  SENDER: User selects file(s)
2.  SENDER: generate_share_code() → "MANGO-4471"
3.  SENDER: infohash_send = SHA1("MANGO-4471:" + hour)
4.  SENDER: dht.announce(infohash_send, local_port)
5.  SENDER: build_file_manifest(files) → FileManifest { transfer_mode: Bulk }
6.  SENDER: Display share code to user
7.  SENDER: Poll infohash_recv = SHA1("MANGO-4471:recv:" + hour) for receiver IP

8.  RECEIVER: User enters "MANGO-4471"
9.  RECEIVER: infohash_send = SHA1("MANGO-4471:" + hour)
10. RECEIVER: dht.lookup(infohash_send) → sender_addr
11. RECEIVER: dht.announce(infohash_recv, local_port)  ← back-announce for hole punch
12. RECEIVER: hole_punch(sender_addr) [sender simultaneously punches receiver]
                OR connect_via_relay() [Phase 4, if punch fails]
13. RECEIVER: establish_quic(sender_addr)

14. BOTH:    noise_xx_handshake(stream, static_key, role)
    RECEIVER: note remote pubkey → present as fingerprint for optional contact add

15. SENDER:  send FileManifest on control stream
16. RECEIVER: ACK manifest
17. SENDER:  send chunks in parallel QUIC streams (encrypted, Bulk mode)
18. RECEIVER: receive, decrypt, verify SHA-256, write to disk
19. RECEIVER: NACK any failed chunks → sender retries
20. RECEIVER: COMPLETE signal when all chunks verified

21. BOTH:    session keys discarded
22. BOTH:    "Add to contacts?" prompt
```

### Full Flow: Contact Transfer (Known Person)

```
1.  SENDER: User selects contact + file(s)
2.  SENDER: find_contact(contact, dht) → peer_addr (cached or DHT lookup)
3.  SENDER: hole_punch(peer_addr) OR connect_via_relay() [Phase 4]
4.  SENDER: establish_quic(peer_addr)

5.  BOTH:   noise_xx_handshake() — static keys used
6.  SENDER: verify remote pubkey == contact.public_key (reject if mismatch)

7.  → same as steps 15-21 above
```

---

## 11. Rust Workspace Structure

```
p2pshare/                           ← Cargo workspace root
├── Cargo.toml
│
├── p2pshare-core/                  ← library crate (all protocol logic)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       │
│       ├── identity/
│       │   ├── mod.rs
│       │   ├── keypair.rs          ← X25519 keypair generation
│       │   ├── fingerprint.rs      ← pubkey → WORD-NNNN-WORD-NNNN
│       │   └── storage.rs          ← ~/.config/p2pshare/identity.json (CLI)
│       │                             device keychain (mobile, later)
│       │
│       ├── discovery/
│       │   ├── mod.rs
│       │   ├── dht.rs              ← mainline DHT — announce + lookup
│       │   ├── share_code.rs       ← code generation + infohash derivation
│       │   └── presence.rs         ← contact online/offline status via DHT
│       │
│       ├── nat/
│       │   ├── mod.rs
│       │   ├── hole_punch.rs       ← UDP hole punching (simultaneous open)
│       │   ├── quic.rs             ← QUIC endpoint setup, SkipCertVerification
│       │   ├── relay.rs            ← VPS relay client (DEFERRED — Phase 4)
│       │   └── detect.rs           ← NAT type detection (optional)
│       │
│       ├── crypto/
│       │   ├── mod.rs
│       │   ├── handshake.rs        ← Noise XX pattern over QUIC stream
│       │   └── keys.rs             ← ephemeral keypair per session
│       │
│       ├── transfer/
│       │   ├── mod.rs
│       │   ├── manifest.rs         ← FileManifest + TransferMode
│       │   ├── sender.rs           ← parallel chunk send + bytes_in_flight cap
│       │   ├── receiver.rs         ← receive + decrypt + SHA-256 verify + write
│       │   └── resume.rs           ← TransferState persistence
│       │
│       ├── contacts/
│       │   ├── mod.rs
│       │   ├── store.rs            ← SQLite contacts DB
│       │   └── model.rs            ← Contact struct + PresenceStatus
│       │
│       └── session/
│           ├── mod.rs
│           └── coordinator.rs      ← orchestrates all layers
│                                     future Flutter FFI surface
│
├── p2pshare-cli/                   ← CLI test harness (Phases 1–3 testing)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
│
└── p2pshare-relay/                 ← DEFERRED — Phase 4
    ├── Cargo.toml
    └── src/
        ├── main.rs
        ├── session.rs
        └── config.rs
```

### CLI Commands (Test Harness)

**Phase 1:**
```
p2pshare identity                  → show fingerprint + pubkey hex
p2pshare identity --reset          → regenerate keypair
p2pshare announce                  → generate share code, announce on DHT, print code + expiry
p2pshare lookup <CODE>             → DHT lookup, print resolved IP:port list
p2pshare contacts list
p2pshare contacts add <FINGERPRINT> <NAME>
```

**Phase 2:**
```
p2pshare connect <CODE>            → full Phase 2 flow: lookup → punch → QUIC → Noise
                                     prints "connected to <FINGERPRINT>"
p2pshare listen                    → wait for incoming connection, print connector's fingerprint
```

**Phase 3:**
```
p2pshare send <FILE> [<FILE>...]   → announce code, wait for receiver, transfer
p2pshare receive <CODE>            → lookup, connect, receive to ./downloads/
p2pshare transfers                 → list in-progress + resumable transfers
```

---

## 12. Crate Dependencies

### p2pshare-core

```toml
[dependencies]

# Networking
tokio        = { version = "1", features = ["full"] }
quinn        = "0.11"
mainline     = "2"

# QUIC TLS scaffolding (throwaway self-signed cert — Noise handles real auth)
rcgen        = "0.13"
rustls       = { version = "0.23", features = ["ring"] }

# Encryption
snow             = "0.9"
x25519-dalek     = "2"
sha2             = "0.10"
sha1             = "0.10"
chacha20poly1305 = "0.10"
rand             = "0.8"

# Wire format
rmp-serde    = "1"               # MessagePack — compact binary, no schema overhead

# Storage
rusqlite     = { version = "0.31", features = ["bundled"] }
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"

# Utilities
hex          = "0.4"
uuid         = { version = "1", features = ["v4"] }
thiserror    = "1"
tracing      = "0.1"
```

### p2pshare-cli

```toml
[dependencies]
p2pshare-core = { path = "../p2pshare-core" }
tokio         = { version = "1", features = ["full"] }
clap          = { version = "4", features = ["derive"] }
tracing-subscriber = "0.3"
```

> **Flutter FFI note:** `flutter_rust_bridge = "2"` will be added to `p2pshare-core` when Flutter integration begins. Not included now — CLI test harness does not need it.

---

## 13. Data Structures

### Wire Format

All control messages serialized with **MessagePack** (`rmp-serde`). Compact binary, no schema definition overhead.

```rust
#[derive(Serialize, Deserialize)]
pub enum ControlMessage {
    Manifest(FileManifest),
    ManifestAck,
    ChunkNack     { index: u32 },
    ResumeRequest { have_chunks: Vec<u32> },
    Complete,
    Error         { code: u32, message: String },
}

// Chunk stream wire format:
// [chunk_index: u32 big-endian][encrypted_payload: variable length]
// (no length prefix — stream close signals end of chunk)
```

### DHT Announcement

Standard BitTorrent DHT `announce_peer` — stores IP:port at infohash only. No custom value payload (BEP 44 not required). Identity verification is handled by the Noise handshake after connecting.

```
announce_peer(infohash, port)  →  peers can find us at this IP:port
get_peers(infohash)            →  returns list of IP:port
```

---

## 14. Error Handling & Edge Cases

| Scenario | Handling |
|---|---|
| Contact offline | DHT lookup returns empty → show "offline" → queue transfer |
| Share code expired (> 1 hour) | infohash changes each hour → lookup fails → tell sender to regenerate |
| Wrong person connects via share code | Noise handshake with wrong static key → rejected cryptographically |
| Chunk hash mismatch | NACK sent → sender retransmits that chunk only |
| Connection drops mid-transfer | TransferState persisted → reconnect → resume from last verified chunk |
| NAT traversal fails | Automatic fallback to VPS relay (Phase 4) — transparent to user |
| All relays unreachable (Phase 4) | Notify user — transfer cannot proceed — retry later |
| App backgrounded on iOS | QUIC connection kept alive via background task + push notification wake |
| App backgrounded on Android | Foreground service keeps transfer running |
| Receiver back-announce not yet visible | Sender retries infohash_recv lookup with backoff (up to 10s) |
| Contact changes IP | DHT presence auto-updates → next lookup gets new IP — transparent |
| Large file (> 4GB) | u64 offsets throughout — no 32-bit overflow risk |
| bytes_in_flight exceeds 32MB | Sender yield-loops until in-flight drops — back-pressure, no OOM |
| Streaming mode requested (future) | Rejected with Error { code: UNSUPPORTED_MODE } until implemented |

---

## 15. VPS Relay Server Spec

> **DEFERRED — Phase 4.** Reproduced here for reference only.

The relay is a separate, minimal Rust binary deployed on a VPS.

### What It Does

1. Accepts QUIC connections from clients
2. Clients present a relay token (16 bytes)
3. Waits for two clients with matching tokens
4. Pipes bytes bidirectionally between them
5. Closes both connections when either disconnects
6. Stores nothing

### What It Does NOT Do

- No TLS termination beyond QUIC (payload is also Noise-encrypted)
- No logging of transfer contents
- No session persistence
- No authentication beyond token matching

### Deployment

- Single binary, systemd service
- QUIC on port 7000 (UDP)
- Self-signed TLS cert (clients verify via cert fingerprint hardcoded in app)
- No database, no filesystem writes
- Multiple VPS nodes in different regions for latency

---

## 16. Development Phases

### Approach
CLI test harness (`p2pshare-cli`) is built alongside the core library. No Flutter FFI until the full transfer pipeline is validated end-to-end. Global BitTorrent DHT used from day one.

### Implementation Order (Strict)

```
1. Workspace + Cargo.toml skeleton
2. identity:: keypair + fingerprint + storage      → CLI: identity commands
3. discovery:: share_code + dht                    → CLI: announce + lookup    ← MILESTONE 1
4. contacts:: SQLite store                         → CLI: contacts commands
5. nat:: QUIC setup (rcgen + SkipVerification)
6. nat:: hole_punch + back-announce coordination
7. crypto:: Noise XX handshake                     → CLI: connect + listen     ← MILESTONE 2
8. transfer:: manifest (with TransferMode)
9. transfer:: sender (bytes_in_flight cap)
10. transfer:: receiver                            → CLI: send + receive       ← MILESTONE 3
11. transfer:: resume
12. session:: coordinator                                                       ← MILESTONE 4
```

### Phase 1 — Identity & DHT Foundation
- [ ] X25519 keypair generation + storage (`~/.config/p2pshare/identity.json`)
- [ ] Fingerprint derivation: `WORD-NNNN-WORD-NNNN` from pubkey bytes 0–7 via BIP39
- [ ] Share code generation (`WORD-NNNN` format)
- [ ] Infohash derivation: `SHA1(code + ":" + hour)` — no pubkey salt
- [ ] DHT announce + lookup (global BitTorrent DHT via `mainline` crate)
- [ ] Receiver back-announce at `SHA1(code + ":recv:" + hour)` for hole punch coordination
- [ ] Contacts SQLite store + CRUD

**Milestone 1:** Two machines on different networks — `announce` on one, `lookup` on the other, IPs match.

### Phase 2 — Connection & Encryption
- [ ] Throwaway self-signed QUIC TLS cert via `rcgen` + `SkipCertVerification`
- [ ] UDP hole punching with DHT-coordinated simultaneous open
- [ ] QUIC connection establishment over punched hole
- [ ] Noise XX handshake over QUIC control stream
- [ ] Identity verification post-handshake (contact connects)

**Milestone 2:** Two machines establish an authenticated, encrypted QUIC channel. Each prints the other's fingerprint. No server involved.

### Phase 3 — File Transfer
- [ ] `FileManifest` with `TransferMode` enum (`Bulk` only)
- [ ] Parallel chunk send with `bytes_in_flight` memory cap (32MB)
- [ ] Chunk receive + SHA-256 verify + offset write
- [ ] NACK + chunk retry
- [ ] `TransferState` persistence + resume on reconnect

**Milestone 3:** Transfer a 1GB file between two machines on different networks. Kill mid-transfer, reconnect, resume — only missing chunks retransmit.

### Phase 4 — VPS Relay (DEFERRED)
- [ ] `p2pshare-relay` binary
- [ ] Client relay fallback when hole punch fails
- [ ] Relay token generation + matching
- [ ] Deploy to VPS, test from symmetric NAT environments

**Milestone 4:** Transfer completes on networks where hole punching fails (symmetric NAT).

### Phase 5 — Contacts & Presence
- [ ] DHT-based presence (online/offline)
- [ ] Contact add flow (post-transfer + manual fingerprint entry)
- [ ] Contact lookup + cached IP fast path
- [ ] Transfer queuing for offline contacts

**Milestone 5:** Full contacts flow — add a contact, see them go online, send without a share code.

### Phase 6 — Session Coordinator + Flutter FFI
- [ ] `session::coordinator` — unified `send()` / `receive()` API
- [ ] Add `flutter_rust_bridge` to `p2pshare-core`
- [ ] Wire coordinator to Flutter FFI surface

**Milestone 6:** Flutter UI can call `send()` and `receive()` — protocol invisible to UI layer.

### Phase 7 — Mobile Hardening
- [ ] iOS background transfer (BGAppRefreshTask)
- [ ] Android foreground service
- [ ] Network change handling (WiFi → mobile → QUIC connection migration)
- [ ] Battery-aware chunk sizing
- [ ] Mobile keychain for identity storage (replace plaintext JSON)

**Milestone 7:** 1GB transfer completes with phone screen off, switching from WiFi to mobile mid-transfer.

### Phase 8 — Streaming Mode (Future)
- [ ] `TransferMode::Streaming` implementation
- [ ] Sequential ordered chunk send on single QUIC stream
- [ ] Local HTTP byte-range server on receiver for media player
- [ ] MP4 fast-start detection + moov atom rewrite
- [ ] Flutter UI integration: open stream URL in platform player

**Milestone 8:** Receiver starts playing a phone-captured video within 2 seconds of sender initiating transfer.

---

## 17. Architecture Decisions & Rationale

This section records non-obvious design choices made during planning.

### DHT infohash does not include sender pubkey

**Original spec:** `SHA1(code + ":" + hour + ":" + hex(sender_pk))`  
**Adopted:** `SHA1(code + ":" + hour)`

**Why:** Standard BitTorrent DHT `announce_peer` stores only IP:port. The receiver has no way to get `sender_pk` from the DHT in order to compute the same infohash — the original derivation was circular. Authentication is handled entirely by the Noise XX handshake, making the pubkey salt redundant for security.

### Hole punch coordination via DHT back-announce

For share code transfers, the receiver gets the sender's IP from the DHT but the sender doesn't know the receiver's IP — required for simultaneous punch.

**Solution:** Receiver announces at a second infohash (`SHA1(code + ":recv:" + hour)`) immediately after looking up the sender. Sender polls this infohash. Once both have each other's IPs, simultaneous punching proceeds. Adds ~1–2s latency. Both infohashes expire at the same hour boundary.

### QUIC TLS is skip-verify; Noise XX is the real auth layer

Quinn requires TLS for QUIC. Adding a real PKI for QUIC would duplicate the authentication already done by Noise XX. Instead: throwaway self-signed cert via `rcgen` per session, custom `ServerCertVerifier` that accepts all certs. The Noise handshake that follows is the authoritative identity check.

### TransferMode is in the wire format now even though only Bulk is implemented

Adding `TransferMode` to `FileManifest` now avoids a future breaking wire format change when streaming is implemented. Receiver rejects `Streaming` mode with `Error { code: UNSUPPORTED_MODE }` until the feature lands.

### bytes_in_flight cap of 32MB

The semaphore controls concurrency (2/4/8 parallel streams) but doesn't bound memory when chunk sizes are large (1MB chunks × 8 streams = 8MB minimum, but tasks can queue up). The `bytes_in_flight` AtomicUsize counter caps total in-flight bytes at 32MB regardless of chunk size or parallelism.

### Storage is plaintext JSON/SQLite during CLI development

Mobile keychain / secure enclave integration is a Phase 7 concern. Using `~/.config/p2pshare/` plaintext files during Phases 1–6 keeps the implementation simple and avoids platform-specific complexity until the Flutter layer exists.

### Global BitTorrent DHT from day one

No local bootstrap node. The global DHT is the production environment — testing against it from Phase 1 catches real-world latency and routing issues early rather than discovering them at integration time.

---

### Crate API Verification Checklist

Verify these before implementing each module — spec pseudocode may not match exact crate APIs:

| Crate | Check |
|---|---|
| `mainline 2` | `announce_peer` and `get_peers` async signatures |
| `mainline 2` | Whether BEP 44 is supported (not needed, but good to know) |
| `quinn 0.11` | `Endpoint::new` signature and `connect_with` for client config |
| `quinn 0.11` | `open_uni` / `accept_bi` / `RecvStream::read_to_end` API |
| `snow 0.9` | `into_transport_mode()` vs `into_stateless_transport_mode()` |
| `snow 0.9` | `get_remote_static()` availability post-handshake |
| `rcgen 0.13` | `generate_simple_self_signed` return type for rustls cert chain |
| `rustls 0.23` | `ServerCertVerifier` trait method signatures |

---

*End of specification — v0.2*
