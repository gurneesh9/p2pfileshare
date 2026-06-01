use mainline::Dht;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{Error, Result};

pub struct DhtLayer {
    dht: Arc<Dht>,
}

impl DhtLayer {
    pub fn new() -> Result<Self> {
        let dht = Dht::client().map_err(|e| Error::Dht(e.to_string()))?;
        Ok(Self { dht: Arc::new(dht) })
    }

    /// Announce our IP at `infohash` with the given port.
    /// Logs a warning if the announce fails (e.g. DHT not reachable).
    pub async fn announce(&self, infohash: [u8; 20], port: u16) {
        let dht = self.dht.clone();
        let result = tokio::task::spawn_blocking(move || {
            dht.announce_peer(infohash.into(), Some(port))
        })
        .await;

        match result {
            Ok(Ok(_)) => {
                tracing::debug!("DHT announce ok (infohash {})", hex::encode(infohash));
            }
            Ok(Err(e)) => {
                tracing::warn!("DHT announce_peer failed: {e} — lookup may not work");
            }
            Err(e) => {
                tracing::warn!("DHT announce task panicked: {e}");
            }
        }
    }

    /// Query the DHT for peers at `infohash`.
    ///
    /// Returns immediately with whatever peers were found. Returns an empty vec if the
    /// DHT traversal finds nothing (fresh client, peer not yet propagated, or no network).
    pub async fn lookup(&self, infohash: [u8; 20]) -> Vec<SocketAddr> {
        let dht = self.dht.clone();
        tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            let mut peers = Vec::new();
            match dht.get_peers(infohash.into()) {
                Ok(batches) => {
                    for batch in batches {
                        for addr in batch {
                            if !peers.contains(&addr) {
                                peers.push(addr);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("DHT get_peers error: {e}");
                }
            }
            tracing::debug!(
                "DHT lookup took {:.1}s, found {} peers",
                start.elapsed().as_secs_f32(),
                peers.len()
            );
            peers
        })
        .await
        .unwrap_or_default()
    }

    /// Poll `infohash` on the DHT, retrying every `interval` for up to `timeout`.
    /// Returns the first non-empty result, or an empty vec on timeout.
    pub async fn lookup_with_retry(
        &self,
        infohash: [u8; 20],
        timeout: Duration,
        interval: Duration,
    ) -> Vec<SocketAddr> {
        let deadline = Instant::now() + timeout;
        loop {
            let peers = self.lookup(infohash).await;
            if !peers.is_empty() {
                return peers;
            }
            if Instant::now() >= deadline {
                return vec![];
            }
            tokio::time::sleep(interval).await;
        }
    }
}
