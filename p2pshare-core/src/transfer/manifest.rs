use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub session_id: [u8; 20],
    pub filename: String,
    pub mime_type: String,
    pub total_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub chunks: Vec<ChunkMeta>,
    pub transfer_mode: TransferMode,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    pub index: u32,
    pub size: u32,
    /// SHA-256 of the plaintext chunk — verified post-decryption.
    pub hash: [u8; 32],
}

// ── Control messages ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    Manifest(FileManifest),
    ManifestAck,
    ResumeRequest { have_chunks: Vec<u32> },
    ChunkNack { index: u32 },
    Complete,
    Error { code: u32, message: String },
}

// ── Helpers ────────────────────────────────────────────────────────────────────

pub fn chunk_size_for(file_size: u64) -> u32 {
    match file_size {
        0..=10_000_000 => 65_536,
        10_000_001..=500_000_000 => 262_144,
        _ => 1_048_576,
    }
}

pub fn parallel_streams_for(file_size: u64) -> usize {
    match file_size {
        0..=10_000_000 => 2,
        10_000_001..=500_000_000 => 4,
        _ => 8,
    }
}

/// Build a `FileManifest` by reading the file and computing per-chunk SHA-256 hashes.
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

    let mut file = tokio::fs::File::open(file_path).await?;
    let mut chunks = Vec::with_capacity(chunk_count as usize);
    let mut buf = vec![0u8; chunk_size as usize];

    for index in 0..chunk_count {
        let chunk_start = index as u64 * chunk_size as u64;
        let expected = ((total_size - chunk_start).min(chunk_size as u64)) as usize;

        // Seek to position (for safety — read may be sequential but explicit is safer)
        file.seek(std::io::SeekFrom::Start(chunk_start)).await?;
        file.read_exact(&mut buf[..expected]).await?;

        let hash: [u8; 32] = Sha256::digest(&buf[..expected]).into();
        chunks.push(ChunkMeta { index, size: expected as u32, hash });
    }

    let session_id: [u8; 20] = rand::thread_rng().gen();

    Ok(FileManifest {
        session_id,
        filename,
        mime_type,
        total_size,
        chunk_size,
        chunk_count,
        chunks,
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
