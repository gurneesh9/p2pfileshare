# Xend

Send files directly between any two devices — same room or different continents. No cloud, no accounts, no size limits. End-to-end encrypted with automatic relay fallback when direct connections aren't possible.

---

## How it works

Every transfer is identified by a **share code** — a short human-readable string like `OCEAN-4471`. The sender generates one, shares it via any channel (text, verbally, etc.), and the receiver types it in. Discovery, connection, and transfer happen automatically.

**Connection strategy (automatic, in order):**

1. **Same WiFi** — multicast UDP finds the sender instantly on the local network (~1–2s)
2. **Direct / hole punch** — both devices punch through their NAT routers simultaneously using the BitTorrent DHT for coordination (~5–10s)
3. **Relay** — if hole punching fails (symmetric NAT ~20% of networks), traffic is forwarded through an encrypted relay. The relay sees only ciphertext and cannot read anything.

All three paths use the same end-to-end Noise XX encryption. The relay path is transparent to users.

---

## Building

### Prerequisites

- Rust (stable, `rustup`)
- For iOS: Xcode 15+, Flutter 3.x, `flutter_rust_bridge_codegen`

### CLI

```bash
cargo build --release
# Binary at: ./target/release/xend
```

### iOS app

```bash
# Regenerate FFI bindings after any Rust API change
~/.cargo/bin/flutter_rust_bridge_codegen generate

# Run on connected device
cd p2pshare-UI
flutter run
```

---

## CLI Usage

### Send a file

```bash
./xend send /path/to/file.zip
```

Prints a share code immediately, then waits for a receiver. Tries LAN, then DHT + hole punch, then relay automatically.

```
Your fingerprint: OCEAN-4471-FLUX-9912
Share code: CASUAL-3659
[announce] waiting for receiver (LAN or internet)...
```

#### Force relay only (skip LAN + DHT)

```bash
./xend send --relay /path/to/file.zip
```

Useful when you know direct connection won't work, or want the fastest connection on networks that block peer-to-peer traffic.

```
Your fingerprint: OCEAN-4471-FLUX-9912
Share code: CASUAL-3659
[announce] relay-only mode — connecting to relay...
[relay] waiting for peer...
```

### Receive a file

```bash
./xend receive CASUAL-3659
```

Tries LAN discovery first, then DHT, then relay — all automatic. No `--relay` flag needed even if the sender used relay-only mode.

Output is saved to the current directory.

```bash
# Receive to a specific directory
./xend receive CASUAL-3659 --output ~/Downloads
```

### Other commands

```bash
# Show your identity fingerprint and public key
./xend identity

# Look up a share code on the DHT (debugging)
./xend lookup CASUAL-3659

# List saved contacts
./xend contacts list
```

---

## iOS App Usage

### Sending a file

1. Tap **Send** on the home screen
2. Select a file from Files, Photos, or any share sheet
3. A share code appears (e.g. `OCEAN-4471`)
4. Choose connection mode:
   - **Same WiFi** — faster, works only on the same network. Fails if your router has Client/AP Isolation enabled.
   - **Any Network** — works everywhere, uses DHT + relay fallback
5. Share the code with the receiver via any channel
6. Transfer starts automatically when the receiver connects

### Receiving a file

1. Tap **Receive** on the home screen
2. Type the share code from the sender
3. Select connection mode (must match what the sender is expecting — **Any Network** works in all cases)
4. Tap **Connect**
5. File saves to the app's Documents folder

---

## Share Codes

Share codes are in `WORD-NNNN` format (e.g. `MANGO-4471`, `BELT-8929`).

- **Valid for 1 hour** — codes expire automatically, no cleanup needed
- **Single-use by convention** — generate a new code for each transfer
- **Guessing a code is not enough** — the Noise XX handshake cryptographically rejects anyone without the sender's private key, even if they know the code
- **Case-insensitive** — `ocean-4471`, `OCEAN-4471`, and `Ocean-4471` all work

---

## Connection Modes

### Same WiFi (LAN)

Uses multicast UDP (`239.255.52.52:52525`) and broadcast UDP (`255.255.255.255:47474`) in parallel. The receiver connects directly via QUIC over the local network.

**Requirement:** both devices on the same WiFi access point.

**Will not work if** your router has **AP Isolation** (also called Client Isolation or WLAN Isolation) enabled. This is a router setting that blocks all traffic between WiFi clients. Check your router admin panel under WiFi or Security settings.

> AirDrop works despite AP Isolation because it uses WiFi Direct (device-to-device, bypasses the router). Xend uses standard WiFi which routes through the router.

### Any Network

Combines three mechanisms automatically:

| Mechanism | When it wins |
|---|---|
| LAN multicast/broadcast | Both devices on same WiFi with AP Isolation off |
| DHT + hole punch | Both devices behind standard (non-symmetric) NAT |
| Relay | Symmetric NAT, hotel/corporate networks, VPN |

The same code works for all three — the app picks whichever path connects first.

### Relay Only (`--relay` flag / CLI only)

Skips LAN discovery and DHT entirely. Connects directly to the relay server. Use this when:
- You know you're on a restrictive network
- You want the most predictable latency
- LAN and DHT both failed

---

## Security & Privacy

### Encryption

All transfers use **Noise XX** (ChaCha20-Poly1305, BLAKE2s). The handshake provides:

- **Mutual authentication** — both sides verify each other's identity
- **Perfect forward secrecy** — session keys are ephemeral and discarded after each transfer
- **Man-in-the-middle protection** — knowing the share code is not enough to intercept

### Relay privacy

The relay server forwards encrypted bytes only. It never has decryption keys and cannot read file contents, filenames, or sizes. Even if the relay server were compromised, it holds nothing useful.

### Identity

Each device generates an X25519 keypair on first launch. Your **fingerprint** is a human-readable representation of your public key:

```
OCEAN-4471-FLUX-9912
```

Fingerprints can be compared out-of-band to verify you're talking to the right device. Full cryptographic verification happens automatically during every handshake.

Identity is stored locally only — in `~/.config/xend/identity.json` on macOS/Linux, and in the app sandbox on iOS. It is never sent to any server.

### What never leaves your device

- Your private key
- Your contacts list
- File contents before encryption

### What the DHT sees

- Your IP address and port, announced under a time-limited infohash derived from the share code
- Announcements expire after 1 hour automatically

---

## Relay Server

The relay is a minimal Rust binary running at `34.61.29.61:443`.

To run your own:

```bash
cargo build --release -p p2pshare-relay
```

Deploy and set the relay address:

```bash
RELAY_ADDR=your.server.com:443 ./xend send myfile.zip
```

### Deploying the relay

```bash
# On your VPS:
sudo mv p2pshare-relay /usr/local/bin/
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/p2pshare-relay

sudo tee /etc/systemd/system/p2pshare-relay.service > /dev/null <<'EOF'
[Unit]
Description=Xend relay server
After=network.target

[Service]
ExecStart=/usr/local/bin/p2pshare-relay
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now p2pshare-relay
```

---

## Troubleshooting

### "Sender not found on local network"

- Confirm both devices are on the same WiFi network
- Check if your router has **AP Isolation / Client Isolation / WLAN Isolation** enabled in its admin panel — disable it, or switch to **Any Network** mode instead
- Ensure the Xend app has Local Network permission on iOS: **Settings → Privacy & Security → Local Network → Xend**

### "Peer not found" / transfer times out on Any Network

- The share code may have expired (codes are valid for 1 hour) — ask the sender to generate a new one
- The sender's device may have gone offline or the app was backgrounded
- Try `--relay` mode on both sides as a fallback

### Transfer is slow

On relay: speed is limited by your upload bandwidth (sender) and relay server bandwidth. LAN and direct connections are limited only by your local network.

On LAN: if you're seeing relay speeds despite both devices being on WiFi, AP Isolation is likely enabled on your router.

### iOS: file access errors for large files

Ensure the file is stored locally on the device (not iCloud Drive "optimized" / greyed out). iCloud files need to be fully downloaded before Xend can read them.

### Code shows as expired immediately

Share codes are time-windowed to 1-hour boundaries. A code generated at 10:59 expires at 11:00 — 60 seconds later. If this happens, generate a new code.

---

## Project Structure

```
p2pshare-core/      Rust library — all protocol logic
  src/
    identity/       X25519 keypair, fingerprints, local storage
    discovery/      Share codes, DHT (BitTorrent), mDNS, multicast/broadcast
    nat/            QUIC endpoints, UDP hole punching, STUN, relay client
    crypto/         Noise XX handshake
    transfer/       Chunking, sender, receiver, resume state
    session/        Coordinator — ties all layers together
    api.rs          flutter_rust_bridge FFI surface

p2pshare-cli/       xend command-line binary
p2pshare-relay/     Relay server binary
p2pshare-UI/        Flutter iOS app
```

---

## Wire Protocol Summary

```
Control messages:   Noise-encrypted MessagePack over QUIC bidirectional stream
Chunk data:         Noise AEAD (sub-messages of ≤64KB) over QUIC unidirectional streams
Relay transport:    TCP with type-prefixed framing (0x00 = ctrl, 0x01 = chunk)

Manifest (sent before transfer):
  session_id    [u8; 20]   — used for resume matching
  filename      String
  total_size    u64
  chunk_size    u32        — 64KB / 256KB / 1MB depending on file size
  chunk_count   u32
  transfer_mode Bulk       — parallel unordered streams

Chunk integrity: guaranteed by Noise AEAD on each sub-message (GCM authentication)
Resume:          receiver sends ResumeRequest { have_chunks } on reconnect
                 sender skips chunks the receiver already has
```
