use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{session::{coordinator::PeerSession, Session}, Error, Result};

use super::{
    manifest::{actual_chunk_size, build_manifest, ControlMessage, FileManifest},
    progress,
    relay_sender::send_file_relay,
};

/// Build manifest, negotiate with receiver, send all chunks on a single QUIC
/// uni-stream, then handle NACKs until the receiver sends Complete.
pub async fn send_file(session: &Session, file_path: &Path) -> Result<()> {
    match session {
        Session::Direct(s) => send_file_direct(s, file_path).await,
        Session::Relay(s) => send_file_relay(s, file_path).await,
    }
}

async fn send_file_direct(session: &PeerSession, file_path: &Path) -> Result<()> {
    eprintln!("[send] building manifest for {}...", file_path.display());
    let manifest = build_manifest(file_path).await?;
    eprintln!(
        "[send] {} chunks × {} bytes, {} bytes total",
        manifest.chunk_count, manifest.chunk_size, manifest.total_size
    );

    let mut file = tokio::fs::File::open(file_path).await?;

    // ── Control bi-stream ──────────────────────────────────────────────────────
    let (mut ctrl_send, mut ctrl_recv) = session
        .connection
        .open_bi()
        .await
        .map_err(|e| Error::Quic(e.to_string()))?;

    session
        .send_ctrl(&mut ctrl_send, &ControlMessage::Manifest(manifest.clone()))
        .await?;

    let chunks_to_skip: std::collections::HashSet<u32> =
        match session.recv_ctrl(&mut ctrl_recv).await? {
            ControlMessage::ManifestAck => {
                eprintln!("[send] fresh transfer");
                Default::default()
            }
            ControlMessage::ResumeRequest { have_chunks } => {
                eprintln!(
                    "[send] resuming — receiver already has {} chunks",
                    have_chunks.len()
                );
                have_chunks.into_iter().collect()
            }
            other => {
                return Err(Error::ConnectionFailed(format!(
                    "unexpected response to manifest: {:?}",
                    other
                )))
            }
        };

    // Pre-credit already-done bytes so the progress bar starts at the right %.
    progress::reset(manifest.total_size);
    let initial_done: u64 = chunks_to_skip
        .iter()
        .map(|&i| actual_chunk_size(i, manifest.chunk_size, manifest.total_size) as u64)
        .sum();
    if initial_done > 0 {
        progress::advance(initial_done);
    }

    // ── Single data uni-stream ─────────────────────────────────────────────────
    // All chunk payloads flow over one persistent stream instead of one stream
    // per chunk.  This eliminates per-stream QUIC setup/teardown overhead and
    // lets QUIC pipeline data with a single send window.
    //
    // Wire format per chunk: [4-byte BE chunk_index][4-byte BE payload_len][payload]
    let mut data = session
        .connection
        .open_uni()
        .await
        .map_err(|e| Error::Quic(e.to_string()))?;

    // ── Initial send ───────────────────────────────────────────────────────────
    let to_send: Vec<u32> = (0..manifest.chunk_count)
        .filter(|i| !chunks_to_skip.contains(i))
        .collect();

    eprintln!(
        "[send] sending {}/{} chunks...",
        to_send.len(),
        manifest.chunk_count
    );

    for &idx in &to_send {
        send_chunk(session, &mut file, &mut data, idx, &manifest).await?;
    }

    // ── NACK / Complete loop ───────────────────────────────────────────────────
    // The data stream stays open so NACKed chunks can be retransmitted on it.
    loop {
        match session.recv_ctrl(&mut ctrl_recv).await? {
            ControlMessage::Complete => {
                eprintln!("[send] transfer complete ✓");
                data.finish().map_err(|e| Error::Quic(e.to_string()))?;
                return Ok(());
            }
            ControlMessage::ChunkNack { index } => {
                eprintln!("[send] NACK chunk {index}, retransmitting");
                send_chunk(session, &mut file, &mut data, index, &manifest).await?;
            }
            ControlMessage::Error { message, .. } => {
                return Err(Error::ConnectionFailed(format!("receiver: {message}")));
            }
            _ => {}
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

async fn send_chunk(
    session: &PeerSession,
    file: &mut tokio::fs::File,
    stream: &mut quinn::SendStream,
    chunk_index: u32,
    manifest: &FileManifest,
) -> Result<()> {
    let plaintext = read_chunk(file, chunk_index, manifest.chunk_size, manifest.total_size).await?;
    let encrypted = session.encrypt_chunk(chunk_index, &plaintext)?;

    stream.write_all(&chunk_index.to_be_bytes()).await?;
    stream
        .write_all(&(encrypted.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&encrypted).await?;

    progress::advance(plaintext.len() as u64);
    Ok(())
}

async fn read_chunk(
    file: &mut tokio::fs::File,
    chunk_index: u32,
    chunk_size: u32,
    total_size: u64,
) -> Result<Vec<u8>> {
    let offset = chunk_index as u64 * chunk_size as u64;
    let size = actual_chunk_size(chunk_index, chunk_size, total_size) as usize;
    let mut buf = vec![0u8; size];
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    file.read_exact(&mut buf).await?;
    Ok(buf)
}
