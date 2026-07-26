use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun.cloudflare.com:3478",
];
const STUN_ATTEMPTS: u32 = 2;
const STUN_WAIT: Duration = Duration::from_secs(3);

/// Return the socket's external (NAT-mapped) address.
///
/// Queries every STUN server at once on the shared socket and takes the first
/// valid response — one 3 s deadline total instead of 3 s per server — and
/// retries once, so a single lost datagram doesn't push us onto the relay.
pub async fn external_addr(socket: &UdpSocket) -> Option<SocketAddr> {
    for attempt in 0..STUN_ATTEMPTS {
        if let Some(addr) = query_all(socket).await {
            return Some(addr);
        }
        if attempt + 1 < STUN_ATTEMPTS {
            eprintln!("[stun] no response, retrying...");
        }
    }
    None
}

async fn query_all(socket: &UdpSocket) -> Option<SocketAddr> {
    // Fire a Binding Request at every server, remembering (txn_id, server).
    let mut pending: Vec<([u8; 12], SocketAddr)> = Vec::new();
    for server in STUN_SERVERS {
        let Ok(addrs) = tokio::net::lookup_host(server).await else {
            continue;
        };
        let Some(server_addr) = addrs.into_iter().find(|a| a.is_ipv4()) else {
            continue;
        };
        let txn_id: [u8; 12] = rand::random();
        if socket.send_to(&build_request(&txn_id), server_addr).await.is_ok() {
            pending.push((txn_id, server_addr));
        }
    }
    if pending.is_empty() {
        return None;
    }

    // Accept the first parseable response from any queried server. Unrelated
    // packets (early punches, stray traffic) are skipped, not treated as failure.
    let mut buf = [0u8; 512];
    tokio::time::timeout(STUN_WAIT, async {
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                return None;
            };
            for (txn_id, server_addr) in &pending {
                if from == *server_addr {
                    if let Some(addr) = parse_response(&buf[..len], txn_id) {
                        return Some(addr);
                    }
                }
            }
        }
    })
    .await
    .ok()
    .flatten()
}

fn build_request(txn_id: &[u8; 12]) -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    req[2..4].copy_from_slice(&0x0000u16.to_be_bytes()); // length = 0
    req[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(txn_id);
    req
}

fn parse_response(buf: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    // Must be Binding Success Response (0x0101)
    if u16::from_be_bytes([buf[0], buf[1]]) != 0x0101 {
        return None;
    }
    // Transaction ID must match
    if &buf[8..20] != txn_id {
        return None;
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let attrs = buf.get(20..20 + msg_len)?;

    let mut i = 0;
    while i + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let attr_len = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let val = attrs.get(i + 4..i + 4 + attr_len)?;

        match attr_type {
            // XOR-MAPPED-ADDRESS (preferred)
            0x0020 => {
                if val.len() >= 8 && val[1] == 0x01 {
                    let port = u16::from_be_bytes([val[2], val[3]]) ^ 0x2112;
                    let ip_raw = u32::from_be_bytes([val[4], val[5], val[6], val[7]])
                        ^ MAGIC_COOKIE;
                    let ip = Ipv4Addr::from(ip_raw);
                    return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
                }
            }
            // MAPPED-ADDRESS (fallback)
            0x0001 => {
                if val.len() >= 8 && val[1] == 0x01 {
                    let port = u16::from_be_bytes([val[2], val[3]]);
                    let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
                    return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
                }
            }
            _ => {}
        }

        // attributes are 4-byte aligned
        i += 4 + ((attr_len + 3) & !3);
    }
    None
}
