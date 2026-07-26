//! Connection-establishment phase, surfaced to the UI while a session is being
//! set up. Mirrors `progress`: a lock-free global the FFI layer polls, so the
//! coordinator can report which step it's on ("hole punching", "connecting", …)
//! without threading a callback through every call.

use std::sync::atomic::{AtomicU8, Ordering};

static PHASE: AtomicU8 = AtomicU8::new(IDLE);

// Kept in sync with the Dart `ConnPhase` mapping in rust_service.dart.
pub const IDLE: u8 = 0;
pub const ANNOUNCING: u8 = 1;
pub const WAITING_FOR_PEER: u8 = 2;
pub const PEER_FOUND: u8 = 3;
pub const HOLE_PUNCHING: u8 = 4;
pub const CONNECTING: u8 = 5;
pub const HANDSHAKING: u8 = 6;
pub const CONNECTED: u8 = 7;
pub const RELAY_CONNECTING: u8 = 8;

/// Update the current phase.
pub fn set(phase: u8) {
    PHASE.store(phase, Ordering::Relaxed);
}

/// Read the current phase (polled by the UI).
pub fn get() -> u8 {
    PHASE.load(Ordering::Relaxed)
}

/// Back to idle — call when an attempt ends (success, error, or cancel).
pub fn reset() {
    PHASE.store(IDLE, Ordering::Relaxed);
}
