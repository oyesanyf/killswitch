//! # Durable Atomic Checkpointer with BLAKE3 Chain Verification
//!
//! Atomically persists and recovers `KillSwitchGraphState` snapshots to disk
//! with mandatory BLAKE3 cryptographic trace chain verification.

use std::path::PathBuf;
use async_trait::async_trait;
use killswitch_types::errors::{KillSwitchError, Result};
use killswitch_types::graph::{KillSwitchGraphState, StateCheckpointer};

/// Durable filesystem-backed checkpointer with atomic rename and BLAKE3 verification.
#[derive(Debug, Clone)]
pub struct DurableFileCheckpointer {
    storage_dir: PathBuf,
}

impl DurableFileCheckpointer {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let storage_dir = dir.into();
        std::fs::create_dir_all(&storage_dir)?;
        Ok(Self { storage_dir })
    }

    fn checkpoint_path(&self, incident_id: &str) -> PathBuf {
        self.storage_dir.join(format!("checkpoint_{}.json", incident_id))
    }
}

#[async_trait]
impl StateCheckpointer for DurableFileCheckpointer {
    async fn save_checkpoint(&self, state: &KillSwitchGraphState) -> Result<()> {
        let final_path = self.checkpoint_path(&state.incident_id);
        let temp_path = self.storage_dir.join(format!(
            "checkpoint_{}_{}.tmp",
            state.incident_id,
            uuid::Uuid::new_v4()
        ));

        let data = serde_json::to_vec_pretty(state)
            .map_err(|e| KillSwitchError::LedgerSerializationError(e.to_string()))?;

        // Write to temporary file and flush/sync
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(&data)?;
            file.sync_all()?;
        }

        // Atomic replace / rename
        #[cfg(windows)]
        {
            if final_path.exists() {
                let _ = std::fs::remove_file(&final_path);
            }
            std::fs::rename(&temp_path, &final_path)?;
        }
        #[cfg(not(windows))]
        {
            std::fs::rename(&temp_path, &final_path)?;
        }

        Ok(())
    }

    async fn load_checkpoint(&self, incident_id: &str) -> Result<Option<KillSwitchGraphState>> {
        let path = self.checkpoint_path(incident_id);
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        let state: KillSwitchGraphState = serde_json::from_slice(&data)
            .map_err(|e| KillSwitchError::LedgerSerializationError(e.to_string()))?;

        // Cryptographic Invariant: Mandatory BLAKE3 Trace Chain Verification
        if !state.verify_trace_chain() {
            return Err(KillSwitchError::CryptoError(format!(
                "BLAKE3 execution trace chain verification failed for checkpoint '{}'",
                incident_id
            )));
        }

        Ok(Some(state))
    }

    async fn list_checkpoints(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        if !self.storage_dir.exists() {
            return Ok(ids);
        }
        for entry in std::fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("checkpoint_") && name.ends_with(".json") {
                let id = name
                    .trim_start_matches("checkpoint_")
                    .trim_end_matches(".json")
                    .to_string();
                ids.push(id);
            }
        }
        Ok(ids)
    }
}
