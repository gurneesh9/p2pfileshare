use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

use crate::{transfer::manifest::ControlMessage, Error, Result};

// Must stay in sync with coordinator's CHUNK_NONCE_BASE.
const CHUNK_NONCE_BASE: u64 = 1 << 32;

// ── Wire message types ─────────────────────────────────────────────────────────

/// A message read from the relay TCP stream.
pub enum RelayMsg {
    Ctrl(ControlMessage),
    Chunk { index: u32, ciphertext: Vec<u8> },
}

// ── Session ────────────────────────────────────────────────────────────────────

/// An authenticated Noise session whose transport is a relay-piped TCP stream.
///
/// All messages share a single full-duplex TCP connection through the relay.
/// Control messages and chunks are distinguished by a 1-byte type prefix:
///   0x00 = control  (Noise-encrypted msgpack ControlMessage)
///   0x01 = chunk    (Noise-encrypted file chunk payload)
pub struct RelaySession {
    pub remote_pubkey: [u8; 32],
    pub remote_fingerprint: String,
    pub(crate) noise: Arc<Mutex<snow::StatelessTransportState>>,
    pub(crate) send_nonce: Arc<AtomicU64>,
    // Async mutexes so lock guards can be held across await points.
    write: tokio::sync::Mutex<OwnedWriteHalf>,
    read: tokio::sync::Mutex<OwnedReadHalf>,
}

impl RelaySession {
    /// Construct from already-split TCP halves (avoids a reunite + re-split).
    pub fn from_split(
        read: OwnedReadHalf,
        write: OwnedWriteHalf,
        remote_pubkey: [u8; 32],
        remote_fingerprint: String,
        transport: snow::StatelessTransportState,
    ) -> Self {
        Self {
            remote_pubkey,
            remote_fingerprint,
            noise: Arc::new(Mutex::new(transport)),
            send_nonce: Arc::new(AtomicU64::new(0)),
            write: tokio::sync::Mutex::new(write),
            read: tokio::sync::Mutex::new(read),
        }
    }

    /// Convenience constructor from an unsplit stream.
    pub fn new(
        stream: TcpStream,
        remote_pubkey: [u8; 32],
        remote_fingerprint: String,
        transport: snow::StatelessTransportState,
    ) -> Self {
        let (read, write) = stream.into_split();
        Self::from_split(read, write, remote_pubkey, remote_fingerprint, transport)
    }

    // ── Outbound ───────────────────────────────────────────────────────────────

    /// Send a control message: `[0x00][8-byte nonce][4-byte enc_len][enc_bytes]`
    pub async fn send_ctrl(&self, msg: &ControlMessage) -> Result<()> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::Relaxed);
        let plaintext =
            rmp_serde::to_vec_named(msg).map_err(|e| Error::MsgPack(e.to_string()))?;

        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let enc_len = self
            .noise
            .lock()
            .unwrap()
            .write_message(nonce, &plaintext, &mut ciphertext)
            .map_err(|e| Error::Noise(e.to_string()))?;

        let mut w = self.write.lock().await;
        w.write_all(&[0x00]).await?;
        w.write_all(&nonce.to_be_bytes()).await?;
        w.write_all(&(enc_len as u32).to_be_bytes()).await?;
        w.write_all(&ciphertext[..enc_len]).await?;
        Ok(())
    }

    /// Send an already-encrypted chunk payload:
    /// `[0x01][4-byte chunk_index][4-byte payload_len][payload]`
    pub async fn send_chunk_raw(&self, chunk_index: u32, payload: &[u8]) -> Result<()> {
        let mut w = self.write.lock().await;
        w.write_all(&[0x01]).await?;
        w.write_all(&chunk_index.to_be_bytes()).await?;
        w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
        w.write_all(payload).await?;
        Ok(())
    }

    // ── Inbound ────────────────────────────────────────────────────────────────

    /// Read the next message from the relay stream (blocking until one arrives).
    pub async fn recv_msg(&self) -> Result<RelayMsg> {
        let mut r = self.read.lock().await;
        let mut type_buf = [0u8; 1];
        r.read_exact(&mut type_buf).await?;

        match type_buf[0] {
            0x00 => {
                let mut nonce_buf = [0u8; 8];
                r.read_exact(&mut nonce_buf).await?;
                let nonce = u64::from_be_bytes(nonce_buf);

                let mut len_buf = [0u8; 4];
                r.read_exact(&mut len_buf).await?;
                let enc_len = u32::from_be_bytes(len_buf) as usize;

                let mut ciphertext = vec![0u8; enc_len];
                r.read_exact(&mut ciphertext).await?;

                let mut plaintext = vec![0u8; enc_len];
                let plain_len = self
                    .noise
                    .lock()
                    .unwrap()
                    .read_message(nonce, &ciphertext, &mut plaintext)
                    .map_err(|e| Error::Noise(e.to_string()))?;

                let msg = rmp_serde::from_slice(&plaintext[..plain_len])
                    .map_err(|e| Error::MsgPack(e.to_string()))?;
                Ok(RelayMsg::Ctrl(msg))
            }

            0x01 => {
                let mut idx_buf = [0u8; 4];
                r.read_exact(&mut idx_buf).await?;
                let chunk_index = u32::from_be_bytes(idx_buf);

                let mut len_buf = [0u8; 4];
                r.read_exact(&mut len_buf).await?;
                let payload_len = u32::from_be_bytes(len_buf) as usize;

                let mut ciphertext = vec![0u8; payload_len];
                r.read_exact(&mut ciphertext).await?;

                Ok(RelayMsg::Chunk { index: chunk_index, ciphertext })
            }

            t => Err(Error::ConnectionFailed(format!(
                "relay: unknown msg type {t:#x}"
            ))),
        }
    }

    /// Read the next message and assert it is a control message.
    pub async fn recv_ctrl_msg(&self) -> Result<ControlMessage> {
        match self.recv_msg().await? {
            RelayMsg::Ctrl(msg) => Ok(msg),
            RelayMsg::Chunk { .. } => {
                Err(Error::ConnectionFailed("expected ctrl msg, got chunk".into()))
            }
        }
    }

    // ── Noise crypto helpers (identical to PeerSession) ────────────────────────

    pub fn encrypt_chunk(&self, chunk_index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        const MAX_PLAIN: usize = 65519;
        let mut out = Vec::with_capacity(plaintext.len() + 32);
        let sub_count = plaintext.chunks(MAX_PLAIN).count() as u16;
        out.extend_from_slice(&sub_count.to_be_bytes());
        let noise = self.noise.lock().unwrap();
        for (i, sub) in plaintext.chunks(MAX_PLAIN).enumerate() {
            let nonce = CHUNK_NONCE_BASE + chunk_index as u64 * 256 + i as u64;
            let mut buf = vec![0u8; sub.len() + 16];
            let len = noise
                .write_message(nonce, sub, &mut buf)
                .map_err(|e| Error::Noise(e.to_string()))?;
            out.extend_from_slice(&(len as u32).to_be_bytes());
            out.extend_from_slice(&buf[..len]);
        }
        Ok(out)
    }

    pub fn decrypt_chunk(&self, chunk_index: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        const MAX_PLAIN: usize = 65519;
        if ciphertext.len() < 2 {
            return Err(Error::Noise("chunk too short".into()));
        }
        let sub_count = u16::from_be_bytes([ciphertext[0], ciphertext[1]]) as usize;
        let mut pos = 2;
        let mut out = Vec::new();
        let noise = self.noise.lock().unwrap();
        for i in 0..sub_count {
            if pos + 4 > ciphertext.len() {
                return Err(Error::Noise("truncated sub-message length".into()));
            }
            let sub_len =
                u32::from_be_bytes(ciphertext[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + sub_len > ciphertext.len() {
                return Err(Error::Noise("truncated sub-message body".into()));
            }
            let nonce = CHUNK_NONCE_BASE + chunk_index as u64 * 256 + i as u64;
            let mut buf = vec![0u8; MAX_PLAIN];
            let len = noise
                .read_message(nonce, &ciphertext[pos..pos + sub_len], &mut buf)
                .map_err(|e| Error::Noise(e.to_string()))?;
            out.extend_from_slice(&buf[..len]);
            pos += sub_len;
        }
        Ok(out)
    }
}
