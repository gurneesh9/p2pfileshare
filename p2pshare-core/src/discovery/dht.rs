use mainline::Dht;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::{Error, Result};

pub struct DhtLayer {
    dht: Arc<Dht>,
}

impl DhtLayer {
    pub fn new() -> Result<Self> {
        let dht = Dht::client().map_err(|e| Error::Dht(e.to_string()))?;
        Ok(Self { dht: Arc::new(dht) })
    }

    /// Announce our IP at `infohash`. Runs blocking mainline I/O on a threadpool thread.
    pub async fn announce(&self, infohash: [u8; 20], port: u16) {
        let dht = self.dht.clone();
        tokio::task::spawn_blocking(move || {
            let _ = dht.announce_peer(infohash.into(), Some(port));
        })
        .await
        .ok();
    }

    /// Query the DHT for peers at `infohash`. Returns all peers found before the query
    /// terminates. Each call to `get_peers` blocks until the DHT traversal is complete.
    pub async fn lookup(&self, infohash: [u8; 20]) -> Vec<SocketAddr> {
        let dht = self.dht.clone();
        tokio::task::spawn_blocking(move || {
            let mut peers = Vec::new();
            // get_peers returns Result<IntoIter<Vec<SocketAddr>>> — each item is a batch
            if let Ok(batches) = dht.get_peers(infohash.into()) {
                for batch in batches {
                    peers.extend(batch);
                }
            }
            peers
        })
        .await
        .unwrap_or_default()
    }
}
