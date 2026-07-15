use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::{session::{coordinator::PeerSession, Session}, Error, Result};

use super::manifest::{actual_chunk_size, ControlMessage, TransferMode};
use super::progress;
use super::relay_receiver::receive_file_relay;
use super::resume::{find_resumable, TransferState};

// Save resume state every N chunks — worst-case loss = N × chunk_size on crash.
const STATE_SAVE_INTERVAL: u32 = 16;

/// Accept manifest, negotiate resume, receive all chunks, write to `output_dir`.
/// Returns the path of the completed file.
pub async fn receive_file(session: &Session, output_dir: &Path) -> Result<PathBuf> {
    match session {
        Session::Direct(s) => receive_file_direct(s, output_dir).await,
        Session::Relay(s) => receive_file_relay(s, output_dir).await,
    }
}

async fn receive_file_direct(session: &PeerSession, output_dir: &Path) -> Result<PathBuf> {
    // ── Control bi-stream ──────────────────────────────────────────────────────
    let (mut ctrl_send, mut ctrl_recv) = session
        .connection
        .accept_bi()
        .await
        .map_err(|e| Error::Quic(e.to_string()))?;

    // ── Manifest ───────────────────────────────────────────────────────────────
    let manifest = match session.recv_ctrl(&mut ctrl_recv).await? {
        ControlMessage::Manifest(m) => m,
        other => {
            return Err(Error::ConnectionFailed(format!(
                "expected Manifest, got {:?}",
                other
            )))
        }
    };

    if matches!(manifest.transfer_mode, TransferMode::Streaming(_)) {
        session
            .send_ctrl(
                &mut ctrl_send,
                &ControlMessage::Error {
                    code: 1,
                    message: "Streaming mode not implemented".to_string(),
                },
            )
            .await?;
        return Err(Error::ConnectionFailed(
            "streaming mode not supported".to_string(),
        ));
    }

    eprintln!(
        "[recv] '{}' — {} bytes, {} chunks",
        manifest.filename, manifest.total_size, manifest.chunk_count
    );

    let output_path = output_dir.join(&manifest.filename);

    // ── Resume or fresh start ──────────────────────────────────────────────────
    let mut state = match find_resumable(&manifest, output_dir) {
        Some(existing) => {
            eprintln!(
                "[recv] resuming: already have {}/{} chunks",
                existing.chunks_done.len(),
                manifest.chunk_count
            );
            session
                .send_ctrl(
                    &mut ctrl_send,
                    &ControlMessage::ResumeRequest {
                        have_chunks: existing.chunks_done.iter().copied().collect(),
                    },
                )
                .await?;
            existing
        }
        None => {
            tokio::fs::create_dir_all(output_dir).await?;
            {
                let f = tokio::fs::File::create(&output_path).await?;
                f.set_len(manifest.total_size).await?;
            }
            session
                .send_ctrl(&mut ctrl_send, &ControlMessage::ManifestAck)
                .await?;
            TransferState::new(manifest.clone(), output_path.clone())
        }
    };

    // ── Open write handle ──────────────────────────────────────────────────────
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&output_path)
        .await?;

    // ── Accept the sender's single data uni-stream ─────────────────────────────
    // The sender opens this stream immediately after receiving ManifestAck /
    // ResumeRequest, so accept_uni completes without meaningful delay.
    let mut data = session
        .connection
        .accept_uni()
        .await
        .map_err(|e| Error::Quic(e.to_string()))?;

    // ── Progress ───────────────────────────────────────────────────────────────
    let initial_done: u64 = state
        .chunks_done
        .iter()
        .map(|&i| actual_chunk_size(i, manifest.chunk_size, manifest.total_size) as u64)
        .sum();
    progress::reset(manifest.total_size);
    if initial_done > 0 {
        progress::advance(initial_done);
    }

    // ── Receive chunks ─────────────────────────────────────────────────────────
    // Wire per chunk: [4-byte BE chunk_index][4-byte BE payload_len][payload]
    //
    // The stream stays open throughout — NACKed chunks arrive as additional
    // frames on the same stream after the initial pass, so we keep reading
    // until `pending` is empty rather than until stream EOF.
    let mut pending: HashSet<u32> = state.missing_chunks().into_iter().collect();
    let mut chunks_since_save = 0u32;
    // Noise wraps each 65519-byte sub-message with 4-byte length + 16-byte tag,
    // plus 2 bytes for sub_count. ceil(chunk/65519)*20+2 ≤ chunk/3000 for any
    // chunk size, so chunk/2048 gives comfortable headroom.
    let max_payload = manifest.chunk_size as usize + manifest.chunk_size as usize / 2048 + 4096;

    while !pending.is_empty() {
        // ── Read header ────────────────────────────────────────────────────────
        let mut idx_buf = [0u8; 4];
        data.read_exact(&mut idx_buf).await?;
        let chunk_index = u32::from_be_bytes(idx_buf);

        let mut len_buf = [0u8; 4];
        data.read_exact(&mut len_buf).await?;
        let payload_len = u32::from_be_bytes(len_buf) as usize;

        if payload_len > max_payload {
            return Err(Error::ConnectionFailed(format!(
                "chunk {chunk_index} payload_len {payload_len} exceeds max {max_payload}"
            )));
        }

        // ── Read payload ───────────────────────────────────────────────────────
        let mut ciphertext = vec![0u8; payload_len];
        data.read_exact(&mut ciphertext).await?;

        // Skip chunks already received (e.g. a retransmit arriving after a
        // previous retransmit already filled the slot).
        if !pending.contains(&chunk_index) {
            continue;
        }

        // ── Decrypt ────────────────────────────────────────────────────────────
        let plaintext = match session.decrypt_chunk(chunk_index, &ciphertext) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[recv] chunk {chunk_index} decrypt failed ({e}) — NACKing");
                session
                    .send_ctrl(
                        &mut ctrl_send,
                        &ControlMessage::ChunkNack { index: chunk_index },
                    )
                    .await?;
                continue;
            }
        };

        let expected_size =
            actual_chunk_size(chunk_index, manifest.chunk_size, manifest.total_size) as usize;
        if plaintext.len() != expected_size {
            eprintln!(
                "[recv] chunk {chunk_index} size mismatch: got {} expected {} — NACKing",
                plaintext.len(),
                expected_size
            );
            session
                .send_ctrl(
                    &mut ctrl_send,
                    &ControlMessage::ChunkNack { index: chunk_index },
                )
                .await?;
            continue;
        }

        // ── Write ──────────────────────────────────────────────────────────────
        let offset = chunk_index as u64 * manifest.chunk_size as u64;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.write_all(&plaintext).await?;

        progress::advance(plaintext.len() as u64);
        pending.remove(&chunk_index);
        state.chunks_done.insert(chunk_index);

        let done = manifest.chunk_count as usize - pending.len();
        eprintln!(
            "[recv] chunk {chunk_index} ✓  ({done}/{})",
            manifest.chunk_count
        );

        // ── Throttled state save ───────────────────────────────────────────────
        chunks_since_save += 1;
        if chunks_since_save >= STATE_SAVE_INTERVAL {
            let s = state.clone();
            tokio::task::spawn_blocking(move || s.save())
                .await
                .map_err(|e| Error::ConnectionFailed(e.to_string()))??;
            chunks_since_save = 0;
        }
    }

    // ── Final save + signal complete ───────────────────────────────────────────
    let s = state.clone();
    tokio::task::spawn_blocking(move || s.save())
        .await
        .map_err(|e| Error::ConnectionFailed(e.to_string()))??;

    session
        .send_ctrl(&mut ctrl_send, &ControlMessage::Complete)
        .await?;

    eprintln!("[recv] complete ✓ → {}", output_path.display());

    state.delete()?;
    Ok(output_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::keypair::Keypair,
        nat::quic::{
            make_client_endpoint, make_server_endpoint_with_config, prebuilt_server_config,
            skip_verify_client_config,
        },
        session::{coordinator::PeerSession, Session},
        crypto::handshake::{perform_handshake, HandshakeRole},
        transfer::sender::send_file,
    };
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex, atomic::AtomicU64},
    };
    use tokio::net::UdpSocket;

    fn make_session(conn: quinn::Connection, transport: snow::StatelessTransportState, pubkey: [u8; 32]) -> PeerSession {
        use crate::identity::fingerprint::to_fingerprint;
        PeerSession {
            connection: conn,
            remote_fingerprint: to_fingerprint(&pubkey),
            remote_pubkey: pubkey,
            noise: Arc::new(Mutex::new(transport)),
            send_nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    #[tokio::test]
    async fn loopback_file_transfer() {
        // Create a temp file to send
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("hello.txt");
        let content = b"Hello, P2PShare! This is a test file for loopback transfer.";
        tokio::fs::write(&src, content).await.unwrap();

        let out_dir = tmp.path().join("recv");
        tokio::fs::create_dir_all(&out_dir).await.unwrap();

        // Keypairs
        let kp_sender = Keypair::generate();
        let kp_receiver = Keypair::generate();

        // QUIC endpoints
        let srv_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
        let srv_addr: SocketAddr = (Ipv4Addr::LOCALHOST, srv_sock.local_addr().unwrap().port()).into();
        let srv_cfg = prebuilt_server_config().unwrap();
        let srv_ep = make_server_endpoint_with_config(srv_sock.into_std().unwrap(), srv_cfg).unwrap();

        let cli_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
        let cli_ep = make_client_endpoint(cli_sock.into_std().unwrap()).unwrap();
        let cli_cfg = skip_verify_client_config().unwrap();

        let sender_privkey = kp_sender.secret;
        let receiver_privkey = kp_receiver.secret;
        let _sender_pubkey = kp_sender.public;
        let receiver_pubkey = kp_receiver.public;

        let src_clone = src.clone();

        // Sender (server role for QUIC + Noise responder)
        let send_handle = tokio::spawn(async move {
            let incoming = srv_ep.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let (mut s, mut r) = conn.accept_bi().await.unwrap();
            let hs = perform_handshake(&mut s, &mut r, &sender_privkey, HandshakeRole::Responder).await.unwrap();
            let session = Session::Direct(make_session(conn, hs.transport, hs.remote_pubkey));
            send_file(&session, &src_clone).await.unwrap();
            hs.remote_pubkey
        });

        // Receiver (client role for QUIC + Noise initiator)
        let conn = cli_ep.connect_with(cli_cfg, srv_addr, "p2pshare").unwrap().await.unwrap();
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        let hs = perform_handshake(&mut s, &mut r, &receiver_privkey, HandshakeRole::Initiator).await.unwrap();
        let session = Session::Direct(make_session(conn, hs.transport, hs.remote_pubkey));
        let out_path = receive_file(&session, &out_dir).await.unwrap();

        let remote = send_handle.await.unwrap();
        assert_eq!(remote, receiver_pubkey, "sender sees receiver's pubkey");

        let received = tokio::fs::read(&out_path).await.unwrap();
        assert_eq!(received, content);
    }
}
