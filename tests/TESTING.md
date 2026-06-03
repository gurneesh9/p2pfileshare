# P2PShare CLI — Testing & Validation Guide

This document covers manual validation of all three implemented phases.
Run these tests from the workspace root (`/Users/gurneesh/src/file-sharing`).

---

## Build

```bash
cargo build
# Binary: target/debug/p2pshare
```

For convenience, add an alias or copy the binary:
```bash
alias p2pshare="./target/debug/p2pshare"
```

All tests below assume two terminals (A and B) on the **same machine** for loopback
testing, or on **two different machines** on the same network / across the internet
for real-world validation.

---

## Phase 1 — Identity, DHT, Contacts

### 1.1 Identity creation

```
Terminal A:
  p2pshare identity

Expected output:
  Name:        Unnamed           (or whatever was set)
  Fingerprint: WORD-NNNN-WORD-NNNN
  Public key:  <64 hex chars>
  Created:     Xs ago
```

Each device generates its own identity on first run, stored at
`~/.config/p2pshare/identity.json`.

```bash
# Set a display name
p2pshare identity --name "Alice"

# Regenerate keypair (destroys old identity — new fingerprint)
p2pshare identity --reset
```

### 1.2 Share code generation and DHT lookup

Run on **Machine A** (or Terminal A):
```bash
p2pshare announce
```

Expected:
```
[announce] share code: MANGO-4471  (expires in 59m 23s)
[announce] announcing on DHT, local port XXXXX
[announce] waiting for receiver...
```

Within the same hour, run on **Machine B** (or Terminal B):
```bash
p2pshare lookup MANGO-4471    # Phase 1 lookup (DHT only, no connection)
```

Expected:
```
Looking up MANGO-4471 on DHT...
Infohash: <40 hex chars>
Found 1 peer(s):
  <IP>:<PORT>
```

**Validates:** global BitTorrent DHT announce + lookup works across machines.

### 1.3 Contacts

```bash
# Add a contact by their fingerprint (from p2pshare identity output)
p2pshare contacts add "WORD-NNNN-WORD-NNNN" "Bob"

# List contacts
p2pshare contacts list
# Expected: Name, Fingerprint, Last seen columns

# Remove a contact
p2pshare contacts remove "WORD-NNNN-WORD-NNNN"
```

---

## Phase 2 — Connection + Noise Handshake

This tests the full connection stack: DHT → hole punch → QUIC → Noise XX.
Both sides must run at the same time.

### 2.1 Loopback (same machine, two terminals)

**Terminal A:**
```bash
p2pshare announce
```
Copy the printed share code (e.g. `MANGO-4471`).

**Terminal B:**
```bash
p2pshare connect MANGO-4471
```

**Expected on both sides:**
```
[announce/connect] hole punching...
[announce/connect] hole open, ...
[announce/connect] Noise XX handshake...

✓ Connected!
  Remote peer: WORD-NNNN-WORD-NNNN     ← the other machine's fingerprint
  Remote pubkey: <64 hex chars>
```

**Validate:** The fingerprint printed on A matches B's identity fingerprint (from
`p2pshare identity` on B), and vice versa. This confirms mutual authentication.

### 2.2 Different machines (real NAT traversal)

Run the same `announce` / `connect` flow from two different machines on different
networks (home WiFi + mobile hotspot, or two cloud VMs).

- On most home routers (full cone / port-restricted NAT): the hole punch succeeds
  in ~2–4 seconds.
- On symmetric NAT (some corporate networks, some mobile carriers): the punch
  **times out** with `error: hole punch timed out`. Phase 4 (relay) handles this.

---

## Phase 3 — File Transfer

Both sides must run at the same time. Machine A sends, Machine B receives.

### 3.1 Small file (same machine loopback)

Create a test file:
```bash
echo "Hello, P2PShare!" > /tmp/test.txt
```

**Terminal A (sender):**
```bash
p2pshare send /tmp/test.txt
```
Output:
```
Your fingerprint: WORD-NNNN-WORD-NNNN
[announce] share code: WORD-NNNN  (expires in ...)
[announce] waiting for receiver...
```

**Terminal B (receiver):**
```bash
p2pshare receive WORD-NNNN --output /tmp/received/
```
Output:
```
[recv] 'test.txt' — 18 bytes, 1 chunks
[recv] chunk 0 ✓  (1/1)
[recv] complete ✓ → /tmp/received/test.txt
Saved to: /tmp/received/test.txt
```

Verify the file arrived intact:
```bash
diff /tmp/test.txt /tmp/received/test.txt
# No output = identical
```

### 3.2 Large file (stress test)

Generate a 100MB file:
```bash
dd if=/dev/urandom of=/tmp/large.bin bs=1M count=100
```

**Terminal A:**
```bash
p2pshare send /tmp/large.bin
```

**Terminal B:**
```bash
p2pshare receive WORD-NNNN --output /tmp/received/
```

Expected: 400 chunks of 256KB, sent with 4 parallel QUIC streams.
Watch the progress output:
```
[recv] 'large.bin' — 104857600 bytes, 400 chunks
[recv] chunk 0 ✓  (1/400)
[recv] chunk 3 ✓  (2/400)
...
[recv] chunk 399 ✓  (400/400)
[recv] complete ✓
```

Verify integrity:
```bash
sha256sum /tmp/large.bin /tmp/received/large.bin
# Both hashes must match
```

### 3.3 Resume after interruption

1. Start sending a large file (from 3.2 above).
2. Kill the receiver mid-transfer (`Ctrl-C` on Terminal B).
3. Check that a resume state was saved:
   ```bash
   ls ~/.config/p2pshare/transfers/
   # Should show a .json file
   cat ~/.config/p2pshare/transfers/*.json | python3 -m json.tool | grep chunks_done
   ```
4. Restart **Terminal A** `send` with the same code (re-announce) and restart **Terminal B**
   `receive` to the same output dir.
5. The receiver prints `[recv] resuming: already have N/400 chunks` — only missing
   chunks are transferred.
6. The resume state file is deleted on completion.

> **Note:** For resume to work, the sender must generate a fresh share code on restart
> (new code, new QUIC connection), but the receiver recognises the same `session_id` in
> the manifest and resumes. The manifest `session_id` is stable per file send — if you
> restart the sender with the same file, it generates a new session_id and the transfer
> starts fresh.

### 3.4 Multi-file workflow (repeated sends)

```bash
# Send multiple files in sequence
for f in /tmp/test.txt /tmp/large.bin; do
  p2pshare send "$f"
  # Receiver connects and accepts each one
done
```

Each `send` generates a new share code and connection.

---

## Phase 4 — Relay (Symmetric NAT Fallback)

The relay at `34.68.99.198:443` is a dumb TCP pipe — it forwards encrypted bytes
between two peers without being able to read anything. Hole punching is still
attempted first; the relay is only used when hole punching times out.

### 4.1 Verify the relay server is up

```bash
# Should connect and then hang (relay is waiting for a second client)
# Ctrl-C after 2 seconds — no error means the server accepted the connection
nc -zv 34.68.99.198 443
# Expected: Connection to 34.68.99.198 port 443 [tcp] succeeded!
```

Or with curl:
```bash
curl --connect-timeout 5 -v telnet://34.68.99.198:443 2>&1 | head -5
# Expected: "Connected to 34.68.99.198"
```

### 4.2 Force a relay connection (loopback test)

Because hole punching almost always succeeds on loopback, you need to temporarily
make hole punching fail to exercise the relay path. The cleanest way is to use a
loopback address that causes the punch to time out, or to use the network diagnostic
below.

**Method: drop punch packets with a firewall rule (macOS)**

In a third terminal, block outbound UDP on the loopback port the sender is using:

> This is only needed to simulate symmetric NAT in a controlled environment.
> Skip to 4.3 if you have two machines on different NAT types.

```bash
# Terminal A — note the local port that appears in the STUN output, e.g. 51234
p2pshare send /tmp/test.txt
# [announce] STUN: external address is X.X.X.X:51234   ← note this port
```

```bash
# Terminal C — block UDP so hole punch times out
sudo pfctl -e
echo "block drop quick proto udp from any port 51234" | sudo pfctl -f -
```

Terminal B then connects normally:
```bash
p2pshare receive WORD-NNNN
```

With UDP blocked the punch will time out (~35s) and both sides will fall back to
the relay automatically:
```
[announce] hole punch timed out — falling back to relay...
[relay] connecting to 34.68.99.198:443...
[relay] waiting for peer...
[relay] paired ✓
[announce] Noise XX handshake (responder, via relay)...
Connected to: WORD-NNNN-WORD-NNNN
```

Re-enable the firewall when done:
```bash
sudo pfctl -d
```

### 4.3 Two machines on different networks (recommended relay test)

This is the most realistic test. Use one machine behind a **symmetric NAT** (some
mobile hotspots, corporate VPNs, or certain ISP routers) where hole punching fails.

**Machine A (sender):**
```bash
p2pshare send /tmp/test.txt
# Share code: WORD-NNNN
```

**Machine B (receiver, on symmetric NAT):**
```bash
p2pshare receive WORD-NNNN
```

If Machine B's NAT is symmetric, you will see:
```
[connect] hole punching...
# ... (waits ~35s) ...
[connect] hole punch timed out — falling back to relay...
[relay] connecting to 34.68.99.198:443...
[relay] waiting for peer...
[relay] paired ✓
[connect] Noise XX handshake (initiator, via relay)...
```

On Machine A, the same fallback fires at the same time:
```
[announce] hole punch timed out — falling back to relay...
[relay] connecting to 34.68.99.198:443...
[relay] paired ✓
[announce] Noise XX handshake (responder, via relay)...
Connected to: WORD-NNNN-WORD-NNNN
Sending /tmp/test.txt...
```

Verify the file arrived intact:
```bash
diff /tmp/test.txt /path/to/received/test.txt
```

### 4.4 Relay file transfer with integrity check

```bash
# Generate a 10MB test file
dd if=/dev/urandom of=/tmp/relay_test.bin bs=1M count=10
sha256sum /tmp/relay_test.bin  # record this hash

# A: send
p2pshare send /tmp/relay_test.bin

# B: receive (after relay pairs)
p2pshare receive WORD-NNNN --output /tmp/relay_received/

# Verify integrity
sha256sum /tmp/relay_received/relay_test.bin
# Must match the hash recorded above
```

Note: the relay path sends chunks **sequentially** (no parallel QUIC streams) so
throughput is lower than a direct connection — bounded by the round-trip latency to
`34.68.99.198`. Correctness and integrity are identical.

### 4.5 Relay server diagnostics

Check the relay is running on the GCP VM:
```bash
ssh <user>@34.68.99.198 "sudo systemctl status p2pshare-relay"
# or, if running directly:
ssh <user>@34.68.99.198 "pgrep -a p2pshare-relay"
```

View live relay logs (if running with systemd):
```bash
ssh <user>@34.68.99.198 "sudo journalctl -u p2pshare-relay -f"
```

Each successful pairing logs:
```
INFO p2pshare_relay: piping session (token <hex>)
INFO p2pshare_relay: session closed (token <hex>)
```

Unpaired connections (second peer never arrived) log:
```
INFO p2pshare_relay: <addr>: peer never arrived — closing
```

### 4.6 Confirm relay zero-knowledge property

The relay forwards raw encrypted bytes. It has no way to read the contents because:

- The Noise XX handshake (and all subsequent traffic) is encrypted **end-to-end**
  between the two peers before any bytes reach the relay.
- The relay's TCP stream only carries Noise ciphertext — without the session keys,
  which never leave the peers' machines, the relay sees random bytes.

To confirm: capture relay-side traffic with tcpdump and verify it is not plaintext:
```bash
# On the GCP VM (requires root)
sudo tcpdump -i eth0 port 443 -X -c 200
# Output should be unrecognisable binary — no filenames, no content visible
```

---

## Validation Matrix

| Test | Command | Pass Criterion |
|---|---|---|
| Identity creation | `p2pshare identity` | Fingerprint + pubkey printed, file exists |
| Identity idempotent | Run twice | Same fingerprint both times |
| DHT announce | `p2pshare announce` | Code + infohash printed, no error |
| DHT lookup | `p2pshare lookup <code>` | Peer IP returned within 30s |
| Contacts CRUD | `contacts add / list / remove` | Round-trip without error |
| Phase 2 loopback | `announce` + `connect` | Both print each other's fingerprint |
| Phase 2 mutual auth | Compare fingerprints | A's output = B's identity, B's output = A's identity |
| Small file transfer | `send` + `receive` | `diff` shows no difference |
| Large file integrity | 100MB transfer | `sha256sum` hashes match |
| Resume | Kill + restart receiver | Only missing chunks retransferred |
| Parallel streams | `send` large file | Progress shows multiple chunks per second |
| NACK handling | (automatic) | Transfer completes even if SHA-256 mismatch triggers retry |
| Relay server up | `nc -zv 34.68.99.198 443` | `Connection succeeded` in <2s |
| Relay pairing | Two clients, same code | Both print `[relay] paired ✓` |
| Relay Noise handshake | Relay transfer | Both sides print each other's fingerprint |
| Relay file integrity | `send` + `receive` via relay | `sha256sum` hashes match |
| Relay zero-knowledge | `tcpdump` on VM port 443 | No plaintext visible in capture |

---

## Diagnostics

**Increase verbosity** — set `RUST_LOG` to see all internal logging:
```bash
RUST_LOG=p2pshare=debug p2pshare send /tmp/test.txt
```

**Check stored identity:**
```bash
cat ~/.config/p2pshare/identity.json
```

**Check in-progress transfers:**
```bash
ls -la ~/.config/p2pshare/transfers/
```

**Tell if a transfer used the relay path:**
Look for `[relay]` prefix lines in the output. Direct connections show `[announce]`/`[connect]` prefixes through the QUIC setup; relay connections show the fallback message then `[send/relay]` or `[recv/relay]` chunk progress.

**Check contacts database:**
```bash
sqlite3 ~/.config/p2pshare/contacts.db "SELECT display_name, fingerprint FROM contacts;"
```

---

## Known Limitations (as of Phase 4)

| Limitation | Phase fixed |
|---|---|
| ~~Symmetric NAT (~20% of networks) causes hole punch timeout~~ | ✓ Fixed (Phase 4 relay) |
| Relay transfers are sequential (no parallel streams) — slower than direct | Acceptable for relay fallback |
| Only one file per `send` command | Future |
| No progress bar (only log lines) | Future |
| Streaming mode (`video playback while receiving`) not implemented | Phase 8 |
| Flutter UI not yet connected | Phase 6 |
| Mobile background transfer not implemented | Phase 7 |
