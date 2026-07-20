use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::Result;

// ── Transfer mode ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferMode {
    /// Parallel QUIC streams, unordered chunk delivery. Only mode implemented.
    Bulk,
    /// Reserved — not yet implemented. Receiver rejects with an error.
    Streaming(StreamingConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    pub buffer_chunks: u32,
    pub local_port: u16,
}

// ── Manifest ───────────────────────────────────────────────────────────────────

/// Sent at the start of every transfer. Chunk integrity is guaranteed by
/// the Noise AEAD on each chunk (read_message authenticates every byte), so
/// we don't need per-chunk SHA-256 hashes here. This keeps the manifest O(1)
/// in size and allows arbitrarily large files without hitting Snow's 65 KB
/// per-message limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub session_id: [u8; 20],
    pub filename: String,
    pub mime_type: String,
    pub total_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub transfer_mode: TransferMode,
    pub created_at: u64,
}

// ── Control messages ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    Manifest(FileManifest),
    ManifestAck,
    ResumeRequest { have_chunks: Vec<u32> },
    ChunkNack { index: u32 },
    /// Receiver → sender: absolute count of bytes received, decrypted, and
    /// authenticated so far. Drives the sender's progress bar so it reflects
    /// confirmed delivery rather than locally-buffered writes.
    Progress { bytes: u64 },
    Complete,
    Error { code: u32, message: String },
}

// ── Helpers ────────────────────────────────────────────────────────────────────

pub fn chunk_size_for(file_size: u64) -> u32 {
    match file_size {
        0..=5_000_000 => 524_288, // 512 KB for files ≤ 5 MB
        // 8 MB for everything else. Larger chunks don't help throughput (all
        // chunks flow on one persistent stream) but cost more memory per chunk
        // and make a NACK retransmit more expensive.
        _ => 8_388_608,
    }
}

/// Returns the actual byte count for chunk `index`, accounting for the last
/// chunk being potentially smaller than `chunk_size`.
pub fn actual_chunk_size(chunk_index: u32, chunk_size: u32, total_size: u64) -> u32 {
    let start = chunk_index as u64 * chunk_size as u64;
    (total_size - start).min(chunk_size as u64) as u32
}

/// Build a `FileManifest` from file metadata only — no file content is read.
/// Chunk integrity is handled by Noise AEAD during transfer.
pub async fn build_manifest(file_path: &Path) -> Result<FileManifest> {
    use rand::Rng;
    use std::time::{SystemTime, UNIX_EPOCH};

    let metadata = tokio::fs::metadata(file_path).await?;
    let total_size = metadata.len();
    let chunk_size = chunk_size_for(total_size);
    let chunk_count = total_size.div_ceil(chunk_size as u64) as u32;

    let filename = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let mime_type = guess_mime(&filename);

    let session_id: [u8; 20] = rand::thread_rng().gen();

    Ok(FileManifest {
        session_id,
        filename,
        mime_type,
        total_size,
        chunk_size,
        chunk_count,
        transfer_mode: TransferMode::Bulk,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    })
}

fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "mp4" | "mov" | "m4v" => "video/mp4",
        "mkv" => "video/x-matroska",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        _ => "application/octet-stream",
    }
    .to_string()
}
