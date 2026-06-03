pub mod coordinator;
pub mod relay_session;

pub use coordinator::{announce_and_connect, lookup_and_connect, PeerSession};
pub use relay_session::RelaySession;

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
