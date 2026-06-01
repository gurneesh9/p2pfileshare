use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("QUIC read error: {0}")]
    QuicStream(#[from] quinn::ReadExactError),

    #[error("QUIC write error: {0}")]
    QuicWrite(#[from] quinn::WriteError),

    #[error("QUIC read-to-end error: {0}")]
    QuicReadToEnd(#[from] quinn::ReadToEndError),

    #[error("Hole punch timed out — try again or check NAT type")]
    HolePunchTimeout,

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("Noise protocol error: {0}")]
    Noise(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Peer not found on DHT — code may be expired or peer is offline")]
    PeerNotFound,

    #[error("Share code expired — please regenerate")]
    ShareCodeExpired,

    #[error("Identity mismatch — unexpected remote public key")]
    IdentityMismatch,

    #[error("Identity file not found; run `p2pshare identity` to create one")]
    IdentityNotFound,

    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("DHT error: {0}")]
    Dht(String),

    #[error("MessagePack error: {0}")]
    MsgPack(String),

    #[error("Chunk hash mismatch for chunk {index}")]
    ChunkHashMismatch { index: u32 },

    #[error("transfer error: {0}")]
    Transfer(String),
}

pub type Result<T> = std::result::Result<T, Error>;
