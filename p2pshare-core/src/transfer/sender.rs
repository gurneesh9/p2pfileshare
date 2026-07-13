use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;

use crate::{session::{coordinator::PeerSession, Session}, Error, Result};

use super::{
    manifest::{actual_chunk_size, build_manifest, parallel_streams_for, ControlMessage, FileManifest, TransferMode},
    relay_sender::send_file_relay,
};

const MAX_BYTES_IN_FLIGHT: usize = 32 * 1024 * 1024; // 32MB

/// Build manifest, negotiate with receiver, send all chunks, handle NACKs.
///
/// Works transparently over both direct QUIC (`Session::Direct`) and relay
/// TCP (`Session::Relay`) connections.
pub async fn send_file(session: &Session, file_path: &Path) -> Result<()> {
    match session {
        Session::Direct(s) => send_file_direct(s, file_path).await,
        Session::Relay(s) => send_file_relay(s, file_path).await,
    }
}

async fn send_file_direct(session: &PeerSession, file_path: &Path) -> Result<()> {
    // ── Build manifest ─────────────────────────────────────────────────────────
    eprintln!("[send] hashing {}...", file_path.display());
    let manifest = build_manifest(file_path).await?;
    eprintln!(
        "[send] {} chunks × {} bytes, {} bytes total",
        manifest.chunk_count, manifest.chunk_size, manifest.total_size
    );

    // ── Open file once — no per-chunk open/close ───────────────────────────────
    let file = Arc::new(AsyncMutex::new(tokio::fs::File::open(file_path).await?));

    // ── Open control stream ────────────────────────────────────────────────────
    let (mut ctrl_send, mut ctrl_recv) = session
        .connection
        .open_bi()
        .await
        .map_err(|e| Error::Quic(e.to_string()))?;

    // ── Send manifest ──────────────────────────────────────────────────────────
    eprintln!("[send] sending manifest...");
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

    // ── Send chunks ────────────────────────────────────────────────────────────
    let to_send: Vec<u32> = (0..manifest.chunk_count)
        .filter(|i| !chunks_to_skip.contains(i))
        .collect();

    eprintln!(
        "[send] sending {}/{} chunks...",
        to_send.len(),
        manifest.chunk_count
    );

    dispatch_chunks(session, file.clone(), &manifest, &to_send).await?;

    // ── Handle NACKs until receiver sends Complete ─────────────────────────────
    loop {
        match session.recv_ctrl(&mut ctrl_recv).await? {
            ControlMessage::Complete => {
                eprintln!("[send] transfer complete ✓");
                return Ok(());
            }
            ControlMessage::ChunkNack { index } => {
                eprintln!("[send] NACK chunk {}, retrying", index);
                dispatch_chunks(session, file.clone(), &manifest, &[index]).await?;
            }
            ControlMessage::Error { message, .. } => {
                return Err(Error::ConnectionFailed(format!("receiver: {}", message)));
            }
            _ => {}
        }
    }
}

// ── Chunk dispatch ─────────────────────────────────────────────────────────────

async fn dispatch_chunks(
    session: &PeerSession,
    file: Arc<AsyncMutex<tokio::fs::File>>,
    manifest: &FileManifest,
    chunk_indices: &[u32],
) -> Result<()> {
    let parallel = match &manifest.transfer_mode {
        TransferMode::Streaming(_) => 1,
        TransferMode::Bulk => parallel_streams_for(manifest.total_size),
    };

    let semaphore = Arc::new(tokio::sync::Semaphore::new(parallel));
    let bytes_in_flight = Arc::new(AtomicUsize::new(0));
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();

    for &chunk_index in chunk_indices {
        // Back-pressure: don't queue more if memory cap hit
        while bytes_in_flight.load(Ordering::Relaxed) > MAX_BYTES_IN_FLIGHT {
            tokio::task::yield_now().await;
        }

        let permit = semaphore.clone().acquire_owned().await.unwrap();

        // Read plaintext from the persistent handle (seek + read, no open/close).
        let plaintext = read_chunk(&file, chunk_index, manifest.chunk_size, manifest.total_size).await?;

        // Encrypt (sequential, explicit nonce — no ordering constraint on decrypt side)
        let encrypted = session.encrypt_chunk(chunk_index, &plaintext)?;

        let conn = session.connection.clone();
        let bif = bytes_in_flight.clone();
        let enc_len = encrypted.len();

        tasks.spawn(async move {
            bif.fetch_add(enc_len, Ordering::Relaxed);

            let mut stream = conn
                .open_uni()
                .await
                .map_err(|e| Error::Quic(e.to_string()))?;

            // Wire: [4-byte BE chunk_index][encrypted payload]
            stream.write_all(&chunk_index.to_be_bytes()).await?;
            stream.write_all(&encrypted).await?;
            stream.finish().map_err(|e| Error::Quic(e.to_string()))?;

            bif.fetch_sub(enc_len, Ordering::Relaxed);
            drop(permit);
            Ok(())
        });
    }

    // Collect results, surface first error
    while let Some(res) = tasks.join_next().await {
        res.map_err(|e| Error::ConnectionFailed(e.to_string()))??;
    }
    Ok(())
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
