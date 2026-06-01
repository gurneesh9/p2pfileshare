use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{identity::storage::config_dir, Result};

use super::manifest::FileManifest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferState {
    pub session_id: [u8; 20],
    pub manifest: FileManifest,
    /// Chunk indices that have been written and verified.
    pub chunks_done: BTreeSet<u32>,
    pub output_path: PathBuf,
}

impl TransferState {
    pub fn new(manifest: FileManifest, output_path: PathBuf) -> Self {
        Self {
            session_id: manifest.session_id,
            manifest,
            chunks_done: BTreeSet::new(),
            output_path,
        }
    }

    pub fn missing_chunks(&self) -> Vec<u32> {
        (0..self.manifest.chunk_count)
            .filter(|i| !self.chunks_done.contains(i))
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.chunks_done.len() == self.manifest.chunk_count as usize
    }

    pub fn save(&self) -> Result<()> {
        let path = state_path(&self.session_id);
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(session_id: &[u8; 20]) -> Result<Option<Self>> {
        let path = state_path(session_id);
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&path)?;
        Ok(Some(serde_json::from_str(&json)?))
    }

    pub fn delete(&self) -> Result<()> {
        let path = state_path(&self.session_id);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

fn state_path(session_id: &[u8; 20]) -> PathBuf {
    config_dir()
        .join("transfers")
        .join(format!("{}.json", hex::encode(session_id)))
}

pub fn find_resumable(manifest: &FileManifest, output_dir: &Path) -> Option<TransferState> {
    let output_path = output_dir.join(&manifest.filename);
    if !output_path.exists() {
        return None;
    }
    // Look for a saved state for this session
    TransferState::load(&manifest.session_id).ok().flatten()
}
