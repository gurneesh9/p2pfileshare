use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::{Error, Result};

const DEFAULT_RELAY: &str = "xend-relay.fly.dev:8443";

// Runtime override — set by Dart on Apple platforms before any relay connection.
// Points all relay TCP connects to a local Dart proxy that bridges to the real
// relay via Network.framework (bypassing BSD socket content filters).
static RELAY_PROXY_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);

pub fn set_relay_proxy_override(addr: String) {
    if let Ok(mut g) = RELAY_PROXY_OVERRIDE.lock() {
        *g = Some(addr);
    }
}

pub fn clear_relay_proxy_override() {
    if let Ok(mut g) = RELAY_PROXY_OVERRIDE.lock() {
        *g = None;
    }
}

pub fn relay_addr() -> String {
    // Proxy override wins (set per-transfer by Dart on macOS/iOS).
    if let Ok(g) = RELAY_PROXY_OVERRIDE.lock() {
        if let Some(ref addr) = *g {
            return addr.clone();
        }
    }
    // Otherwise fall back to env var or compiled default (cached after first read).
    static DEFAULT_ADDR: OnceLock<String> = OnceLock::new();
    DEFAULT_ADDR
        .get_or_init(|| match std::env::var("RELAY_ADDR") {
            Ok(val) if !val.trim().is_empty() => val,
            _ => DEFAULT_RELAY.to_string(),
        })
        .clone()
}

/// Derive a 16-byte pairing token from the share code.
/// Both the sender and receiver compute the same token independently,
/// which the relay server uses to match them together.
pub fn relay_token_for(code: &str) -> [u8; 16] {
    let input = format!("{}:relay", code.to_uppercase());
    Sha256::digest(input.as_bytes())[..16].try_into().unwrap()
}

/// Connect to the relay and wait to be paired with the other peer.
/// Returns the TCP stream once pairing is signalled by the relay.
pub async fn connect_via_relay(code: &str) -> Result<TcpStream> {
    let addr = relay_addr();
    connect_via_relay_at(&addr, code).await
}

/// Connect to `addr` as if it were the relay (used when Dart opens the real
/// relay connection and exposes a local TCP proxy instead).
pub async fn connect_via_relay_at(addr: &str, code: &str) -> Result<TcpStream> {
    let token = relay_token_for(code);

    eprintln!("[relay] connecting to {}...", addr);
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| Error::ConnectionFailed(format!("relay connect: {e}")))?;

    stream.write_all(&token).await?;

    eprintln!("[relay] waiting for peer...");
    let mut sig = [0u8; 1];
    timeout(Duration::from_secs(90), stream.read_exact(&mut sig))
        .await
        .map_err(|_| Error::ConnectionFailed("relay: timed out waiting for peer".into()))?
        .map_err(Error::Io)?;

    if sig[0] != 0x01 {
        return Err(Error::ConnectionFailed(format!(
            "relay: unexpected pairing byte {:#x}",
            sig[0]
        )));
    }

    eprintln!("[relay] paired ✓");
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_proxy_override() {
        set_relay_proxy_override("127.0.0.1:9999".to_string());
        assert_eq!(relay_addr(), "127.0.0.1:9999");
        clear_relay_proxy_override();
    }
}

