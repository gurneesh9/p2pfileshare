use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::{Error, Result};

const SERVICE_TYPE: &str = "_p2pshare._udp.local.";

/// Get the machine's preferred outbound local IPv4 address.
/// Uses a connect-without-send trick so no packets are transmitted.
fn local_ip() -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip())
}

// ── Advertisement ──────────────────────────────────────────────────────────────

/// An active mDNS advertisement. Unregisters and shuts down when dropped.
pub struct MdnsAdvertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for MdnsAdvertisement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
    }
}

/// Advertise `code` on the LAN via mDNS so peers on the same network can find
/// the QUIC server listening at `port` without going through the DHT.
pub fn advertise(code: &str, port: u16) -> Result<MdnsAdvertisement> {
    let ip = local_ip().ok_or_else(|| {
        Error::ConnectionFailed("cannot determine local IP for mDNS".into())
    })?;

    let daemon = ServiceDaemon::new()
        .map_err(|e| Error::ConnectionFailed(format!("mDNS daemon: {e}")))?;

    let instance = code.to_uppercase();

    // mDNS hostname: lowercase alphanumeric + hyphens, ending with ".local."
    let hostname = format!(
        "{}.local.",
        code.to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>()
    );

    let mut props = HashMap::new();
    props.insert("code".to_string(), instance.clone());

    let service = ServiceInfo::new(SERVICE_TYPE, &instance, &hostname, ip, port, props)
        .map_err(|e| Error::ConnectionFailed(format!("mDNS ServiceInfo: {e}")))?;

    let fullname = service.get_fullname().to_string();

    daemon
        .register(service)
        .map_err(|e| Error::ConnectionFailed(format!("mDNS register: {e}")))?;

    eprintln!("[mDNS] advertising {} on port {}", instance, port);
    Ok(MdnsAdvertisement { daemon, fullname })
}

// ── Discovery ──────────────────────────────────────────────────────────────────

/// Browse the local network for a peer advertising `code`.
/// Returns the peer's QUIC socket address when found.
/// The caller should wrap this with a timeout for the LAN fast-path.
pub async fn browse_for_code(code: &str) -> Result<SocketAddr> {
    let code_upper = code.to_uppercase();

    let daemon = ServiceDaemon::new()
        .map_err(|e| Error::ConnectionFailed(format!("mDNS daemon: {e}")))?;

    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| Error::ConnectionFailed(format!("mDNS browse: {e}")))?;

    eprintln!("[mDNS] browsing for {} on LAN...", code_upper);

    loop {
        let event = receiver
            .recv_async()
            .await
            .map_err(|_| Error::ConnectionFailed("mDNS browse channel closed".into()))?;

        match &event {
            ServiceEvent::ServiceResolved(_) => {}
            ServiceEvent::ServiceFound(ty, name) => {
                eprintln!("[mDNS] found (unresolved): {} / {}", ty, name);
            }
            other => {
                eprintln!("[mDNS] event: {:?}", other);
            }
        }

        if let ServiceEvent::ServiceResolved(info) = event {
            let found_code = info
                .txt_properties
                .get_property_val_str("code")
                .unwrap_or("")
                .to_uppercase();

            if found_code != code_upper {
                eprintln!("[mDNS] resolved different code: {}, want: {}", found_code, code_upper);
                continue;
            }

            // Prefer a non-loopback IPv4 address.
            let ip = info
                .addresses
                .iter()
                .filter(|a| a.is_ipv4() && !a.to_ip_addr().is_loopback())
                .map(|a| a.to_ip_addr())
                .next()
                .or_else(|| info.addresses.iter().map(|a| a.to_ip_addr()).next())
                .ok_or_else(|| {
                    Error::ConnectionFailed("mDNS: resolved service has no addresses".into())
                })?;

            let addr = SocketAddr::new(ip, info.port);
            eprintln!("[mDNS] found {} at {}", code_upper, addr);
            let _ = daemon.shutdown();
            return Ok(addr);
        }
    }
}
