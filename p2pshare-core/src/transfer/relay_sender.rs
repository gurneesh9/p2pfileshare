use std::{collections::HashSet, path::Path};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{
    session::relay_session::RelaySession,
    transfer::manifest::{build_manifest, ChunkMeta, ControlMessage, TransferMode},
    Error, Result,
};

/// Send a file over a relay session (sequential — no parallel QUIC streams).
///
/// Protocol matches the direct sender: send all chunks, then loop reading
/// NACKs/Complete. When a NACK arrives the sender immediately retransmits
/// that chunk; Complete terminates the loop.
pub async fn send_file_relay(session: &RelaySession, file_path: &Path) -> Result<()> {
    eprintln!("[send/relay] hashing {}...", file_path.display());
    let manifest = build_manifest(file_path).await?;
    eprintln!(
        "[send/relay] {} chunks × {} bytes, {} bytes total",
        manifest.chunk_count, manifest.chunk_size, manifest.total_size
    );

    if matches!(manifest.transfer_mode, TransferMode::Streaming(_)) {
        return Err(Error::ConnectionFailed("streaming mode not supported".into()));
    }

    // ── Send manifest ──────────────────────────────────────────────────────────
    session
        .send_ctrl(&ControlMessage::Manifest(manifest.clone()))
        .await?;

    // ── Wait for ManifestAck or ResumeRequest ──────────────────────────────────
    let chunks_to_skip: HashSet<u32> = match session.recv_ctrl_msg().await? {
        ControlMessage::ManifestAck => {
            eprintln!("[send/relay] fresh transfer");
            Default::default()
        }
        ControlMessage::ResumeRequest { have_chunks } => {
            eprintln!(
                "[send/relay] resuming — receiver has {} chunks",
                have_chunks.len()
            );
            have_chunks.into_iter().collect()
        }
        other => {
            return Err(Error::ConnectionFailed(format!(
                "unexpected response to manifest: {other:?}"
            )))
        }
    };

    // ── Send all pending chunks sequentially ───────────────────────────────────
    let to_send: Vec<u32> = (0..manifest.chunk_count)
        .filter(|i| !chunks_to_skip.contains(i))
        .collect();

    eprintln!(
        "[send/relay] sending {}/{} chunks...",
        to_send.len(),
        manifest.chunk_count
    );

    for &idx in &to_send {
        send_one_chunk(session, file_path, &manifest.chunks[idx as usize], manifest.chunk_size)
            .await?;
    }

    // ── NACK/Complete loop ─────────────────────────────────────────────────────
    // TCP is full-duplex: receiver sends NACKs as bad chunks arrive (even while
    // the sender was still sending). After all chunks are sent we read until
    // Complete, retransmitting any NACKed chunks immediately.
    loop {
        match session.recv_ctrl_msg().await? {
            ControlMessage::Complete => {
                eprintln!("[send/relay] transfer complete ✓");
                return Ok(());
            }
            ControlMessage::ChunkNack { index } => {
                eprintln!("[send/relay] NACK chunk {index} — retransmitting");
                send_one_chunk(
                    session,
                    file_path,
                    &manifest.chunks[index as usize],
                    manifest.chunk_size,
                )
                .await?;
            }
            ControlMessage::Error { message, .. } => {
                return Err(Error::ConnectionFailed(format!("receiver: {message}")));
            }
            _ => {}
        }
    }
}

async fn send_one_chunk(
    session: &RelaySession,
    file_path: &Path,
    chunk: &ChunkMeta,
    chunk_size: u32,
) -> Result<()> {
    let plaintext = read_chunk(file_path, chunk, chunk_size).await?;
    let encrypted = session.encrypt_chunk(chunk.index, &plaintext)?;
    session.send_chunk_raw(chunk.index, &encrypted).await
}

async fn read_chunk(path: &Path, chunk: &ChunkMeta, chunk_size: u32) -> Result<Vec<u8>> {
    let mut file = tokio::fs::File::open(path).await?;
    let offset = chunk.index as u64 * chunk_size as u64;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; chunk.size as usize];
    file.read_exact(&mut buf).await?;
    Ok(buf)
}
