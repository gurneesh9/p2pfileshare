use std::{collections::HashSet, path::{Path, PathBuf}};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::{
    session::relay_session::{RelayMsg, RelaySession},
    transfer::{
        manifest::{actual_chunk_size, ControlMessage, TransferMode},
        resume::{find_resumable, TransferState},
    },
    Error, Result,
};

/// Receive a file over a relay session.
///
/// Protocol mirrors the direct receiver: accept manifest, send Ack/Resume,
/// read chunks and send NACKs for bad ones, send Complete when all chunks
/// are verified and written.
pub async fn receive_file_relay(session: &RelaySession, output_dir: &Path) -> Result<PathBuf> {
    // ── Receive manifest ───────────────────────────────────────────────────────
    let manifest = match session.recv_ctrl_msg().await? {
        ControlMessage::Manifest(m) => m,
        other => {
            return Err(Error::ConnectionFailed(format!(
                "expected Manifest, got {other:?}"
            )))
        }
    };

    if matches!(manifest.transfer_mode, TransferMode::Streaming(_)) {
        session
            .send_ctrl(&ControlMessage::Error {
                code: 1,
                message: "Streaming mode not implemented".to_string(),
            })
            .await?;
        return Err(Error::ConnectionFailed(
            "streaming mode not supported".to_string(),
        ));
    }

    eprintln!(
        "[recv/relay] '{}' — {} bytes, {} chunks",
        manifest.filename, manifest.total_size, manifest.chunk_count
    );

    let output_path = output_dir.join(&manifest.filename);

    // ── Resume or fresh start ──────────────────────────────────────────────────
    let mut state = match find_resumable(&manifest, output_dir) {
        Some(existing) => {
            eprintln!(
                "[recv/relay] resuming: already have {}/{} chunks",
                existing.chunks_done.len(),
                manifest.chunk_count
            );
            session
                .send_ctrl(&ControlMessage::ResumeRequest {
                    have_chunks: existing.chunks_done.iter().copied().collect(),
                })
                .await?;
            existing
        }
        None => {
            tokio::fs::create_dir_all(output_dir).await?;
            {
                let f = tokio::fs::File::create(&output_path).await?;
                f.set_len(manifest.total_size).await?;
            }
            session.send_ctrl(&ControlMessage::ManifestAck).await?;
            TransferState::new(manifest.clone(), output_path.clone())
        }
    };

    // ── Receive chunks ─────────────────────────────────────────────────────────
    // The relay TCP stream is full-duplex: we can send NACKs while the sender
    // is still transmitting later chunks. NACKs are picked up by the sender
    // in its post-send read loop and trigger immediate retransmission.
    let mut pending: HashSet<u32> = state.missing_chunks().into_iter().collect();

    while !pending.is_empty() {
        match session.recv_msg().await? {
            RelayMsg::Chunk { index: chunk_index, ciphertext } => {
                // Noise AEAD decryption: success = authenticated. Failure = corrupted.
                let plaintext = match session.decrypt_chunk(chunk_index, &ciphertext) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[recv/relay] chunk {chunk_index} decrypt failed ({e}) — NACKing");
                        session
                            .send_ctrl(&ControlMessage::ChunkNack { index: chunk_index })
                            .await?;
                        continue;
                    }
                };

                let expected_size = actual_chunk_size(chunk_index, manifest.chunk_size, manifest.total_size) as usize;
                if plaintext.len() != expected_size {
                    eprintln!("[recv/relay] chunk {chunk_index} size mismatch — NACKing");
                    session
                        .send_ctrl(&ControlMessage::ChunkNack { index: chunk_index })
                        .await?;
                    continue;
                }

                let offset = chunk_index as u64 * manifest.chunk_size as u64;
                write_at(&output_path, offset, &plaintext).await?;

                pending.remove(&chunk_index);
                state.chunks_done.insert(chunk_index);
                state.save()?;

                let done = manifest.chunk_count as usize - pending.len();
                eprintln!(
                    "[recv/relay] chunk {chunk_index} ✓  ({done}/{})",
                    manifest.chunk_count
                );
            }

            RelayMsg::Ctrl(msg) => {
                // Unexpected during chunk transfer — surface as error.
                return Err(Error::ConnectionFailed(format!(
                    "unexpected ctrl msg during chunk recv: {msg:?}"
                )));
            }
        }
    }

    // ── Signal complete ────────────────────────────────────────────────────────
    session.send_ctrl(&ControlMessage::Complete).await?;
    eprintln!("[recv/relay] complete ✓ → {}", output_path.display());

    state.delete()?;
    Ok(output_path)
}

async fn write_at(path: &Path, offset: u64, data: &[u8]) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new().write(true).open(path).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    file.write_all(data).await?;
    Ok(())
}
