use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Result;

use super::fingerprint::to_fingerprint;
use super::keypair::Keypair;

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Override the directory where identity and contacts are stored.
/// Call this once at startup with the platform-correct writable path.
pub fn set_data_dir(path: impl Into<PathBuf>) {
    let _ = DATA_DIR.set(path.into());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub public_key: String,   // hex-encoded [u8; 32]
    pub private_key: String,  // hex-encoded [u8; 32]
    pub display_name: String,
    pub fingerprint: String,
    pub created_at: u64,
}

impl UserIdentity {
    pub fn public_key_bytes(&self) -> [u8; 32] {
        let bytes = hex::decode(&self.public_key).expect("stored public_key is valid hex");
        bytes.try_into().expect("stored public_key is 32 bytes")
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        let bytes = hex::decode(&self.private_key).expect("stored private_key is valid hex");
        bytes.try_into().expect("stored private_key is 32 bytes")
    }
}

pub fn config_dir() -> PathBuf {
    // If Flutter has set a platform-correct data dir, use it.
    if let Some(dir) = DATA_DIR.get() {
        return dir.clone();
    }
    // Fallback for desktop: ~/.config/p2pshare
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("p2pshare")
}

fn identity_path() -> PathBuf {
    config_dir().join("identity.json")
}

pub fn load() -> Result<Option<UserIdentity>> {
    let path = identity_path();
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let identity = serde_json::from_str(&content)?;
    Ok(Some(identity))
}

pub fn save(identity: &UserIdentity) -> Result<()> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;
    let content = serde_json::to_string_pretty(identity)?;
    std::fs::write(identity_path(), content)?;
    Ok(())
}

pub fn load_or_create(display_name: Option<String>) -> Result<UserIdentity> {
    if let Some(identity) = load()? {
        return Ok(identity);
    }

    let keypair = Keypair::generate();
    let fingerprint = to_fingerprint(&keypair.public);
    let identity = UserIdentity {
        public_key: hex::encode(keypair.public),
        private_key: hex::encode(keypair.secret),
        display_name: display_name.unwrap_or_else(|| "Unnamed".to_string()),
        fingerprint,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    save(&identity)?;
    Ok(identity)
}

pub fn reset() -> Result<UserIdentity> {
    let path = identity_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    load_or_create(None)
}
