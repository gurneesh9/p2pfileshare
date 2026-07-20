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
    // From here on the bar is driven exclusively by the receiver's Progress
    // reports (confirmed, decrypted bytes) — never by local writes, which only
    // prove the data reached the local QUIC send buffer.
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

    let to_send: Vec<u32> = (0..manifest.chunk_count)
        .filter(|i| !chunks_to_skip.contains(i))
        .collect();

    eprintln!(
        "[send] sending {}/{} chunks...",
        to_send.len(),
        manifest.chunk_count
    );

    // NACKed chunk indices flow from the ctrl loop to the send loop.
    let (nack_tx, mut nack_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();

    // ── Ctrl loop ──────────────────────────────────────────────────────────────
    // Runs concurrently with the send loop so Progress reports move the bar
    // and NACKs are retransmitted while later chunks are still being sent.
    // Ends on Complete/Error; dropping nack_tx then unblocks the send loop.
    let total_size = manifest.total_size;
    let ctrl_loop = async move {
        loop {
            match session.recv_ctrl(&mut ctrl_recv).await? {
                ControlMessage::Progress { bytes } => progress::set_done(bytes),
                ControlMessage::ChunkNack { index } => {
                    eprintln!("[send] NACK chunk {index}, queueing retransmit");
                    let _ = nack_tx.send(index);
                }
                ControlMessage::Complete => {
                    progress::set_done(total_size);
                    eprintln!("[send] transfer complete ✓");
                    return Ok(());
                }
                ControlMessage::Error { message, .. } => {
                    return Err(Error::ConnectionFailed(format!("receiver: {message}")));
                }
                _ => {}
            }
        }
    };

    // ── Send loop ──────────────────────────────────────────────────────────────
    // Pipelined: while chunk i is being written to the stream, chunk i+1 is
    // read from disk (`tokio::join!` below), so the network never waits on
    // file I/O between chunks.
    let send_loop = async {
        let mut buf: Option<Vec<u8>> = match to_send.first() {
            Some(&first) => {
                Some(read_chunk(&mut file, first, manifest.chunk_size, manifest.total_size).await?)
            }
            None => None,
        };

        for (i, &idx) in to_send.iter().enumerate() {
            let plaintext = buf.take().expect("read-ahead buffer");
            let frame = encode_chunk_frame(session, idx, &plaintext)?;

            let next_idx = to_send.get(i + 1).copied();
            let (write_res, read_res) = tokio::join!(data.write_all(&frame), async {
                match next_idx {
                    Some(n) => {
                        read_chunk(&mut file, n, manifest.chunk_size, manifest.total_size)
                            .await
                            .map(Some)
                    }
                    None => Ok(None),
                }
            });
            write_res?;
            buf = read_res?;

            // Retransmit any chunks NACKed while we were sending.
            while let Ok(nack_idx) = nack_rx.try_recv() {
                retransmit(session, &mut file, &mut data, nack_idx, &manifest).await?;
            }
        }

        // Initial pass done — keep serving NACKs until the ctrl loop finishes
        // (Complete or Error), which closes the channel.
        while let Some(nack_idx) = nack_rx.recv().await {
            retransmit(session, &mut file, &mut data, nack_idx, &manifest).await?;
        }
        Ok(())
    };

    tokio::try_join!(ctrl_loop, send_loop)?;
    data.finish().map_err(|e| Error::Quic(e.to_string()))?;
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Encrypt a chunk and frame it for the data stream:
/// `[4-byte BE chunk_index][4-byte BE payload_len][payload]` in one buffer so
/// the whole frame goes out with a single `write_all`.
fn encode_chunk_frame(session: &PeerSession, chunk_index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let encrypted = session.encrypt_chunk(chunk_index, plaintext)?;
    let mut frame = Vec::with_capacity(8 + encrypted.len());
    frame.extend_from_slice(&chunk_index.to_be_bytes());
    frame.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    frame.extend_from_slice(&encrypted);
    Ok(frame)
}

async fn retransmit(
    session: &PeerSession,
    file: &mut tokio::fs::File,
    stream: &mut quinn::SendStream,
    chunk_index: u32,
    manifest: &FileManifest,
) -> Result<()> {
    eprintln!("[send] retransmitting chunk {chunk_index}");
    let plaintext = read_chunk(file, chunk_index, manifest.chunk_size, manifest.total_size).await?;
    let frame = encode_chunk_frame(session, chunk_index, &plaintext)?;
    stream.write_all(&frame).await?;
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
