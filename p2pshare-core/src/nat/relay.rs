use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::{Error, Result};

pub fn relay_addr() -> &'static str {
    static ADDR: OnceLock<String> = OnceLock::new();
    ADDR.get_or_init(|| {
        match std::env::var("RELAY_ADDR") {
            Ok(val) if !val.trim().is_empty() => val,
            _ => {
                println!("RELAY_ADDR Not found");
                std::process::exit(1);
            }
        }
    })
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
    let token = relay_token_for(code);
    let addr = relay_addr();

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
    fn test_relay_addr() {
        std::env::set_var("RELAY_ADDR", "127.0.0.1:1234");
        let addr = relay_addr();
        assert_eq!(addr, "127.0.0.1:1234");
    }
}

