use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::{Error, Result};

/// Custom multicast group — avoids conflicts with mDNS (224.0.0.251) and LocalSend (224.0.0.167).
/// 239.255.x.x is the "Organization-Local Scope" range, appropriate for app-defined use.
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 52, 52);
const MULTICAST_PORT: u16 = 52525;
const PREFIX: &str = "XEND1:";

pub struct LanMulticaster {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LanMulticaster {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Build a UDP socket that properly joins the multicast group for receiving.
/// Uses socket2 to set SO_REUSEPORT + IP_ADD_MEMBERSHIP — this is what makes iOS work,
/// unlike the mdns-sd crate which uses raw sockets that can't receive on iOS.
fn bind_multicast_recv() -> std::io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MULTICAST_PORT);
    socket.bind(&bind_addr.into())?;

    // IP_ADD_MEMBERSHIP: join on the default multicast interface (WiFi on iOS/Android).
    socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;
    // Enable loopback so sender and receiver on the same machine can see each other.
    socket.set_multicast_loop_v4(true)?;

    Ok(socket.into())
}

/// Resolve the local WiFi IPv4 address via connect-without-send trick.
fn local_wifi_ip() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// Build a sending socket with IP_MULTICAST_IF set to the local WiFi interface.
/// Without this, iOS returns "No route to host" (os error 65) for multicast sends.
fn bind_multicast_send() -> std::io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    socket.set_multicast_loop_v4(true)?;

    // Tell the OS which interface to use for multicast — required on iOS.
    // Falls back to INADDR_ANY if we can't determine the local IP.
    let iface = local_wifi_ip().unwrap_or(Ipv4Addr::UNSPECIFIED);
    socket.set_multicast_if_v4(&iface)?;

    Ok(socket.into())
}

/// Continuously sends discovery announcements to the multicast group every 500 ms.
/// Stops when dropped.
pub async fn start_multicast(code: &str, quic_port: u16) -> Result<LanMulticaster> {
    let msg = format!("{}{}: {}", PREFIX, code.to_uppercase(), quic_port);
    let msg_bytes = msg.into_bytes();
    let dest: SocketAddr = SocketAddr::V4(SocketAddrV4::new(MULTICAST_ADDR, MULTICAST_PORT));

    let std_sender = bind_multicast_send()
        .map_err(|e| Error::ConnectionFailed(format!("multicast sender bind: {e}")))?;
    let sender = UdpSocket::from_std(std_sender)
        .map_err(|e| Error::ConnectionFailed(format!("multicast sender async: {e}")))?;

    eprintln!(
        "[mcast] announcing {} → port {} on {}:{}",
        code.to_uppercase(),
        quic_port,
        MULTICAST_ADDR,
        MULTICAST_PORT
    );

    let task = tokio::spawn(async move {
        loop {
            if let Err(e) = sender.send_to(&msg_bytes, dest).await {
                eprintln!("[mcast] send error: {e}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    Ok(LanMulticaster { task })
}

/// Listen for a multicast announcement matching `code`.
/// Returns the sender's QUIC SocketAddr (their LAN IP + QUIC port).
pub async fn listen_for_multicast(code: &str) -> Result<SocketAddr> {
    let code_upper = code.to_uppercase();

    let std_socket =
        bind_multicast_recv().map_err(|e| Error::ConnectionFailed(format!("multicast recv socket: {e}")))?;
    let socket =
        UdpSocket::from_std(std_socket).map_err(|e| Error::ConnectionFailed(format!("multicast async wrap: {e}")))?;

    eprintln!(
        "[mcast] listening for {} on {}:{}",
        code_upper, MULTICAST_ADDR, MULTICAST_PORT
    );

    let mut buf = [0u8; 256];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("recv multicast: {e}")))?;

        let msg = match std::str::from_utf8(&buf[..len]) {
            Ok(s) => s,
            Err(_) => continue,
        };

        eprintln!("[mcast] received from {}: {:?}", peer, msg);

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
        eprintln!("[mcast] found {} at {}", code_upper, addr);
        return Ok(addr);
    }
}
