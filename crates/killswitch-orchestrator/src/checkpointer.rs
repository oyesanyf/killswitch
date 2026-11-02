//! # Durable Atomic & Distributed Raft/Valkey Checkpointer with BLAKE3 Chain Verification
//!
//! Atomically persists and recovers `KillSwitchGraphState` snapshots both to local disk
//! (`DurableFileCheckpointer`) and across multi-node Raft + Valkey AOF consensus clusters
//! (`DistributedConsensusCheckpointer`) with mandatory BLAKE3 cryptographic trace chain verification.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use async_trait::async_trait;
use killswitch_telemetry::distributed_consensus::{global_consensus_cluster, ConsensusCommand};
use killswitch_types::errors::{KillSwitchError, Result};
use killswitch_types::graph::{KillSwitchGraphState, StateCheckpointer};

/// Durable filesystem-backed checkpointer with atomic rename, BLAKE3 verification,
/// and automatic replication into the multi-node Raft/Valkey consensus cluster.
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

        // Also replicate checkpoint into the Distributed Raft + Valkey AOF Consensus Cluster
        let state_blake3 = blake3::hash(&data).to_hex().to_string();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let _ = global_consensus_cluster().propose(ConsensusCommand::SaveGraphCheckpoint {
            incident_id: state.incident_id.clone(),
            state_json: String::from_utf8_lossy(&data).to_string(),
            state_blake3,
            updated_at_ms: now_ms,
        });

        Ok(())
    }

    async fn load_checkpoint(&self, incident_id: &str) -> Result<Option<KillSwitchGraphState>> {
        let path = self.checkpoint_path(incident_id);
        let data = if path.exists() {
            std::fs::read(&path)?
        } else if let Some((replicated_json, expected_b3, _idx)) =
            global_consensus_cluster().load_replicated_checkpoint(incident_id)
        {
            let bytes = replicated_json.into_bytes();
            let actual_b3 = blake3::hash(&bytes).to_hex().to_string();
            if actual_b3 != expected_b3 {
                return Err(KillSwitchError::CryptoError(format!(
                    "Replicated Raft/Valkey checkpoint BLAKE3 mismatch for '{}'",
                    incident_id
                )));
            }
            bytes
        } else {
            return Ok(None);
        };

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
        if self.storage_dir.exists() {
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
        }
        for rep_id in global_consensus_cluster().list_replicated_checkpoints() {
            if !ids.contains(&rep_id) {
                ids.push(rep_id);
            }
        }
        Ok(ids)
    }
}

/// Dedicated Distributed Raft/Valkey Consensus Checkpointer for multi-host orchestrator clusters.
#[derive(Debug, Clone, Default)]
pub struct DistributedConsensusCheckpointer {
    local_fallback: Option<DurableFileCheckpointer>,
}

impl DistributedConsensusCheckpointer {
    pub fn new(local_dir: Option<PathBuf>) -> Result<Self> {
        let local_fallback = match local_dir {
            Some(d) => Some(DurableFileCheckpointer::new(d)?),
            None => None,
        };
        Ok(Self { local_fallback })
    }
}

#[async_trait]
impl StateCheckpointer for DistributedConsensusCheckpointer {
    async fn save_checkpoint(&self, state: &KillSwitchGraphState) -> Result<()> {
        if let Some(ref local) = self.local_fallback {
            return local.save_checkpoint(state).await;
        }
        let data = serde_json::to_vec_pretty(state)
            .map_err(|e| KillSwitchError::LedgerSerializationError(e.to_string()))?;
        let state_blake3 = blake3::hash(&data).to_hex().to_string();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        global_consensus_cluster()
            .propose(ConsensusCommand::SaveGraphCheckpoint {
                incident_id: state.incident_id.clone(),
                state_json: String::from_utf8_lossy(&data).to_string(),
                state_blake3,
                updated_at_ms: now_ms,
            })
            .map_err(KillSwitchError::CryptoError)?;
        Ok(())
    }

    async fn load_checkpoint(&self, incident_id: &str) -> Result<Option<KillSwitchGraphState>> {
        if let Some((replicated_json, expected_b3, _idx)) =
            global_consensus_cluster().load_replicated_checkpoint(incident_id)
        {
            let bytes = replicated_json.into_bytes();
            let actual_b3 = blake3::hash(&bytes).to_hex().to_string();
            if actual_b3 != expected_b3 {
                return Err(KillSwitchError::CryptoError(format!(
                    "Replicated Raft/Valkey checkpoint BLAKE3 mismatch for '{}'",
                    incident_id
                )));
            }
            let state: KillSwitchGraphState = serde_json::from_slice(&bytes)
                .map_err(|e| KillSwitchError::LedgerSerializationError(e.to_string()))?;
            if !state.verify_trace_chain() {
                return Err(KillSwitchError::CryptoError(format!(
                    "BLAKE3 execution trace chain verification failed for checkpoint '{}'",
                    incident_id
                )));
            }
            return Ok(Some(state));
        }
        if let Some(ref local) = self.local_fallback {
            return local.load_checkpoint(incident_id).await;
        }
        Ok(None)
    }

    async fn list_checkpoints(&self) -> Result<Vec<String>> {
        Ok(global_consensus_cluster().list_replicated_checkpoints())
    }
}
