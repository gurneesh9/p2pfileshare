pub mod coordinator;
pub mod relay_session;

pub use coordinator::{
    announce_and_connect, announce_and_connect_with_code, announce_mdns_only_with_code,
    announce_via_relay_only, announce_via_relay_only_with_code, connect_to_contact,
    connect_via_relay_only, lookup_and_connect, lookup_mdns_only, PeerSession,
};
pub use relay_session::RelaySession;

// ── Chunk nonce derivation ─────────────────────────────────────────────────────

/// Control messages use nonces 0..2^32 (a per-session counter); chunk data
/// nonces start at 2^32 so the two ranges can never collide.
pub(crate) const CHUNK_NONCE_BASE: u64 = 1 << 32;

/// Nonce for one Noise sub-message of a file chunk.
///
/// 65536 sub-message slots per chunk: an 8 MB chunk needs 129 slots and even a
/// 4 GB chunk would fit, so nonces are unique across the whole transfer.
/// (The previous spacing of 256 collided for 16 MB chunks, which split into
/// 257 sub-messages — chunk i's sub 256 reused chunk i+1's sub-0 nonce.)
pub(crate) fn chunk_nonce(chunk_index: u32, sub_index: u32) -> u64 {
    CHUNK_NONCE_BASE + ((chunk_index as u64) << 16) + sub_index as u64
}

// ── Session enum ───────────────────────────────────────────────────────────────

/// Unified session type returned by the coordinator.
/// Callers do not need to know whether the connection is direct (QUIC) or
/// going through the relay (TCP) — `send_file` / `receive_file` accept either.
pub enum Session {
    Direct(PeerSession),
    Relay(RelaySession),
}

impl Session {
    pub fn remote_fingerprint(&self) -> &str {
        match self {
            Session::Direct(s) => &s.remote_fingerprint,
            Session::Relay(s) => &s.remote_fingerprint,
        }
    }

    pub fn remote_pubkey(&self) -> &[u8; 32] {
        match self {
            Session::Direct(s) => &s.remote_pubkey,
            Session::Relay(s) => &s.remote_pubkey,
        }
    }
}
