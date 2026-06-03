use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::{Error, Result};

pub const RELAY_ADDR: &str = "34.172.20.38:443";

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
    let token = relay_token_for(code);

    eprintln!("[relay] connecting to {}...", RELAY_ADDR);
    let mut stream = TcpStream::connect(RELAY_ADDR)
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
