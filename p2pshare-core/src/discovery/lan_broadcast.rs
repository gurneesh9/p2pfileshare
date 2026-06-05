use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::{Error, Result};

const BROADCAST_PORT: u16 = 47474;
const PREFIX: &str = "XEND1:";

/// Continuously broadcasts the sender's QUIC port every 500 ms.
/// Stops when dropped.
pub struct LanBroadcaster {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LanBroadcaster {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start broadcasting `code` + `quic_port` on the LAN subnet so receivers can
/// find the QUIC server without mDNS multicast (which iOS does not support
/// reliably with the mdns-sd crate).
pub async fn start_broadcast(code: &str, quic_port: u16) -> Result<LanBroadcaster> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| Error::ConnectionFailed(format!("broadcast bind: {e}")))?;
    socket
        .set_broadcast(true)
        .map_err(|e| Error::ConnectionFailed(format!("set broadcast: {e}")))?;

    let msg = format!("{}{}: {}", PREFIX, code.to_uppercase(), quic_port);
    let msg_bytes = msg.into_bytes();

    // Collect broadcast targets: 255.255.255.255 + subnet-directed broadcast.
    let mut targets: Vec<SocketAddr> = vec![
        format!("255.255.255.255:{}", BROADCAST_PORT).parse().unwrap(),
    ];
    if let Some(subnet_bcast) = subnet_broadcast() {
        targets.push(SocketAddr::new(IpAddr::V4(subnet_bcast), BROADCAST_PORT));
        eprintln!("[LAN] subnet broadcast: {}", subnet_bcast);
    }

    eprintln!("[LAN] broadcasting {} → port {}", code.to_uppercase(), quic_port);

    let task = tokio::spawn(async move {
        loop {
            for &dest in &targets {
                let _ = socket.send_to(&msg_bytes, dest).await;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    Ok(LanBroadcaster { task })
}

/// Listen for a broadcast from the sender with the given `code`.
/// Returns the sender's QUIC `SocketAddr` (their LAN IP + QUIC port).
pub async fn listen_for_broadcast(code: &str) -> Result<SocketAddr> {
    let code_upper = code.to_uppercase();

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", BROADCAST_PORT))
        .await
        .map_err(|e| Error::ConnectionFailed(format!("broadcast listen: {e}")))?;
    socket
        .set_broadcast(true)
        .map_err(|e| Error::ConnectionFailed(format!("set broadcast: {e}")))?;

    eprintln!("[LAN] listening for {} on broadcast port {}", code_upper, BROADCAST_PORT);

    let mut buf = [0u8; 256];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("recv broadcast: {e}")))?;

        let msg = match std::str::from_utf8(&buf[..len]) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("[LAN] received {} raw bytes from {} (not UTF-8)", len, peer);
                continue;
            }
        };

        eprintln!("[LAN] received from {}: {:?}", peer, msg);

        if !msg.starts_with(PREFIX) {
            continue;
        }

        // Format: "XEND1:CODE: PORT"
        let payload = &msg[PREFIX.len()..];
        let mut parts = payload.splitn(2, ": ");
        let found_code = match parts.next() {
            Some(c) => c.trim().to_uppercase(),
            None => continue,
        };

        if found_code != code_upper {
            continue;
        }

        let quic_port: u16 = match parts.next().and_then(|p| p.trim().parse().ok()) {
            Some(p) if p > 0 => p,
            _ => continue,
        };

        let addr = SocketAddr::new(peer.ip(), quic_port);
        eprintln!("[LAN] found {} at {}", code_upper, addr);
        return Ok(addr);
    }
}

/// Subnet-directed broadcast address for the local WiFi interface (assumes /24).
fn subnet_broadcast() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    if let IpAddr::V4(v4) = sock.local_addr().ok()?.ip() {
        let [a, b, c, _] = v4.octets();
        return Some(Ipv4Addr::new(a, b, c, 255));
    }
    None
}
