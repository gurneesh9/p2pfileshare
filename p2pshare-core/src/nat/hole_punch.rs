use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use crate::{Error, Result};

const PUNCH_MAGIC: &[u8] = b"p2pshare-punch";
const PUNCH_INTERVAL_MS: u64 = 200;
const PUNCH_COUNT: usize = 150; // 30s of punching — covers DHT propagation delay
const PUNCH_TIMEOUT_SECS: u64 = 35;

/// Simultaneously punch a hole toward `peer_addr` and wait to receive a punch back.
///
/// Both sides must call this concurrently. Returns when the bidirectional path is open.
/// The socket should then be handed to Quinn via `into_std()`.
pub async fn hole_punch(socket: Arc<UdpSocket>, peer_addr: SocketAddr) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));

    let send_socket = socket.clone();
    let send_stop = stop.clone();
    let punch_task = tokio::spawn(async move {
        for _ in 0..PUNCH_COUNT {
            if send_stop.load(Ordering::Relaxed) {
                break;
            }
            let _ = send_socket.send_to(PUNCH_MAGIC, peer_addr).await;
            sleep(Duration::from_millis(PUNCH_INTERVAL_MS)).await;
        }
    });

    let mut buf = [0u8; 64];
    let result = timeout(Duration::from_secs(PUNCH_TIMEOUT_SECS), async {
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) if addr == peer_addr && &buf[..len] == PUNCH_MAGIC => {
                    return Ok::<(), Error>(());
                }
                Ok(_) => continue, // ignore unrelated packets
                Err(e) => return Err(Error::Io(e)),
            }
        }
    })
    .await;

    stop.store(true, Ordering::Relaxed);
    punch_task.abort();
    let _ = punch_task.await; // ensure send_socket Arc clone is dropped

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => Err(Error::HolePunchTimeout),
    }
}
