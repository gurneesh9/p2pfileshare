use std::{collections::HashSet, path::Path};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Mutex as AsyncMutex;

use crate::{
    session::relay_session::RelaySession,
    transfer::{
        manifest::{actual_chunk_size, build_manifest, ControlMessage, TransferMode},
        progress,
    },
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

    // Open file once — no per-chunk open/close.
    let file = AsyncMutex::new(tokio::fs::File::open(file_path).await?);

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

    // Reset progress; pre-credit already-skipped bytes for accurate resume bar.
    progress::reset(manifest.total_size);
    let initial_done: u64 = chunks_to_skip
        .iter()
        .map(|&i| actual_chunk_size(i, manifest.chunk_size, manifest.total_size) as u64)
        .sum();
    if initial_done > 0 {
        progress::advance(initial_done);
    }

    eprintln!(
        "[send/relay] sending {}/{} chunks...",
        to_send.len(),
        manifest.chunk_count
    );

    // Advance progress as chunks are written to the relay TCP buffer.
    // This shows real upload speed (sender → relay); the bar reaches 100% when
    // the upload is done, then the label switches to "Sent — receiver downloading…"
    // until the receiver's Complete message arrives and the screen transitions.
    for &idx in &to_send {
        send_one_chunk(session, &file, idx, manifest.chunk_size, manifest.total_size).await?;
        progress::advance(actual_chunk_size(idx, manifest.chunk_size, manifest.total_size) as u64);
    }

    // ── NACK/Complete loop ─────────────────────────────────────────────────────
    loop {
        match session.recv_ctrl_msg().await? {
            ControlMessage::Complete => {
                eprintln!("[send/relay] transfer complete ✓");
                return Ok(());
            }
            ControlMessage::ChunkNack { index } => {
                eprintln!("[send/relay] NACK chunk {index} — retransmitting");
                send_one_chunk(session, &file, index, manifest.chunk_size, manifest.total_size)
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
    file: &AsyncMutex<tokio::fs::File>,
    chunk_index: u32,
    chunk_size: u32,
    total_size: u64,
) -> Result<()> {
    let plaintext = read_chunk(file, chunk_index, chunk_size, total_size).await?;
    let encrypted = session.encrypt_chunk(chunk_index, &plaintext)?;
    session.send_chunk_raw(chunk_index, &encrypted).await
}

async fn read_chunk(
    file: &AsyncMutex<tokio::fs::File>,
    chunk_index: u32,
    chunk_size: u32,
    total_size: u64,
) -> Result<Vec<u8>> {
    let offset = chunk_index as u64 * chunk_size as u64;
    let size = actual_chunk_size(chunk_index, chunk_size, total_size) as usize;
    let mut buf = vec![0u8; size];
    let mut f = file.lock().await;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    f.read_exact(&mut buf).await?;
    Ok(buf)
}
