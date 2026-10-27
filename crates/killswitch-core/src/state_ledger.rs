//! Cryptographic State Ledger & Atomic Disk Persistence.
//!
//! Provides atomic serialization of `KillChainStatus`, active network quarantine receipts,
//! process suspension records, and history entries with BLAKE3 cryptographic hash chaining.

use chrono::{DateTime, Utc};
use killswitch_types::{
    errors::{KillSwitchError, Result},
    status::{
        IsolationReceipt, KillChainHistoryEntry, KillChainStatus, ProcessIsolationState,
    },
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Complete serialized disk snapshot structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateLedgerSnapshot {
    pub schema_version: u32,
    pub status: KillChainStatus,
    pub network_receipts: Vec<IsolationReceipt>,
    pub process_records: Vec<ProcessIsolationState>,
    pub history: Vec<KillChainHistoryEntry>,
    pub sequence_number: u64,
    pub prev_hash: String,
    pub current_hash: String,
    pub committed_at: DateTime<Utc>,
}

impl StateLedgerSnapshot {
    /// Constructs a fresh default snapshot rooted at GENESIS_HASH.
    pub fn new_initial() -> Self {
        let status = KillChainStatus::default();
        let mut snapshot = Self {
            schema_version: 1,
            status,
            network_receipts: Vec::new(),
            process_records: Vec::new(),
            history: Vec::new(),
            sequence_number: 0,
            prev_hash: GENESIS_HASH.to_string(),
            current_hash: String::new(),
            committed_at: Utc::now(),
        };
        snapshot.current_hash = snapshot.calculate_hash();
        snapshot
    }

    /// Computes the deterministic BLAKE3 hash of this snapshot: BLAKE3(prev_hash || state_json).
    pub fn calculate_hash(&self) -> String {
        #[derive(Serialize)]
        struct HashPayload<'a> {
            schema_version: u32,
            sequence_number: u64,
            status: &'a KillChainStatus,
            network_receipts: &'a [IsolationReceipt],
            process_records: &'a [ProcessIsolationState],
            prev_hash: &'a str,
        }

        let payload = HashPayload {
            schema_version: self.schema_version,
            sequence_number: self.sequence_number,
            status: &self.status,
            network_receipts: &self.network_receipts,
            process_records: &self.process_records,
            prev_hash: &self.prev_hash,
        };

        let json_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(b"::");
        hasher.update(&json_bytes);
        hasher.finalize().to_hex().to_string()
    }
}

/// State Ledger controller handling disk IO and cryptographic integrity verification.
pub struct StateLedger {
    file_path: PathBuf,
    snapshot: StateLedgerSnapshot,
}

impl StateLedger {
    /// Resolves the storage file path based on environment variables or defaults.
    pub fn resolve_storage_path(custom_dir: Option<&Path>) -> PathBuf {
        if let Some(dir) = custom_dir {
            return dir.join("killchain_state.json");
        }
        if let Ok(dir_str) = std::env::var("KILLSWITCH_DATABASE_DIR")
            .or_else(|_| std::env::var("OSOOSI_DATABASE_DIR"))
        {
            let trimmed = dir_str.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed).join("killchain_state.json");
            }
        }
        PathBuf::from("database").join("killchain_state.json")
    }

    /// Opens or initializes the state ledger from disk.
    pub fn open_or_init(custom_dir: Option<&Path>) -> Result<Self> {
        let file_path = Self::resolve_storage_path(custom_dir);

        if file_path.exists() {
            match Self::load_from_path(&file_path) {
                Ok(ledger) => {
                    info!(
                        "📖 [LEDGER] Loaded existing state ledger from '{}'",
                        file_path.display()
                    );
                    return Ok(ledger);
                }
                Err(err) => {
                    warn!(
                        "⚠️ [LEDGER] Failed to load ledger from '{}': {}. Re-initializing clean state.",
                        file_path.display(),
                        err
                    );
                    // Preserve corrupted state ledger for forensic audit and recovery
                    let now_ts = Utc::now().timestamp();
                    let mut corrupt_path = file_path.with_extension(format!("corrupt.{}", now_ts));
                    if corrupt_path.exists() {
                        corrupt_path = file_path.with_extension(format!(
                            "corrupt.{}.{}",
                            now_ts,
                            Utc::now().timestamp_subsec_nanos()
                        ));
                    }
                    if let Err(copy_err) = std::fs::copy(&file_path, &corrupt_path) {
                        warn!(
                            "⚠️ [LEDGER] Failed to backup corrupt ledger to '{}': {}",
                            corrupt_path.display(),
                            copy_err
                        );
                    } else {
                        warn!(
                            "💾 [LEDGER] Preserved corrupted state ledger backup at '{}'",
                            corrupt_path.display()
                        );
                    }
                }
            }
        }

        let snapshot = StateLedgerSnapshot::new_initial();
        let ledger = Self {
            file_path,
            snapshot,
        };
        ledger.commit_to_disk()?;
        info!(
            "📖 [LEDGER] Initialized fresh state ledger at '{}'",
            ledger.file_path.display()
        );
        Ok(ledger)
    }

    /// Loads and verifies a snapshot from disk.
    fn load_from_path(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).map_err(|source| KillSwitchError::LedgerIoError {
                path: path.to_path_buf(),
                source,
            })?;

        let snapshot: StateLedgerSnapshot = serde_json::from_str(&content)
            .map_err(|e| KillSwitchError::LedgerSerializationError(e.to_string()))?;

        // Cryptographic integrity check
        let expected_hash = snapshot.calculate_hash();
        if !killswitch_types::constant_time_eq(&snapshot.current_hash, &expected_hash) {
            return Err(KillSwitchError::StateHashChainMismatch {
                index: snapshot.sequence_number as usize,
                expected: expected_hash,
                calculated: snapshot.current_hash,
            });
        }

        Ok(Self {
            file_path: path.to_path_buf(),
            snapshot,
        })
    }

    /// Returns a reference to the active `KillChainStatus`.
    pub fn status(&self) -> &KillChainStatus {
        &self.snapshot.status
    }

    /// Returns a reference to the complete snapshot.
    pub fn snapshot(&self) -> &StateLedgerSnapshot {
        &self.snapshot
    }

    /// Appends a new event and updates the state snapshot atomically.
    pub fn record_state_transition(
        &mut self,
        new_status: KillChainStatus,
        receipts: Option<Vec<IsolationReceipt>>,
        processes: Option<Vec<ProcessIsolationState>>,
        action: &str,
        operator: &str,
        reason: &str,
    ) -> Result<&StateLedgerSnapshot> {
        let now_str = Utc::now().to_rfc3339();

        // 1. Audit History Event Hash Chaining
        let prev_event_hash = self
            .snapshot
            .history
            .first()
            .map(|h| h.event_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());

        let event_payload = format!(
            "{}:{}:{}:{}:{}",
            prev_event_hash, now_str, action, operator, reason
        );
        let event_hash = blake3::hash(event_payload.as_bytes()).to_hex().to_string();

        let history_entry = KillChainHistoryEntry {
            timestamp: now_str,
            action: action.to_string(),
            operator: operator.to_string(),
            reason: reason.to_string(),
            prev_event_hash,
            event_hash,
        };

        // 2. Snapshot Chaining
        let next_sequence = self.snapshot.sequence_number + 1;
        let prev_snapshot_hash = self.snapshot.current_hash.clone();

        self.snapshot.sequence_number = next_sequence;
        self.snapshot.prev_hash = prev_snapshot_hash;
        self.snapshot.status = new_status;
        if let Some(r) = receipts {
            self.snapshot.network_receipts = r;
        }
        if let Some(p) = processes {
            self.snapshot.process_records = p;
        }
        self.snapshot.history.insert(0, history_entry);
        self.snapshot.committed_at = Utc::now();
        self.snapshot.current_hash = self.snapshot.calculate_hash();

        // 3. Atomic Disk Write
        self.commit_to_disk()?;
        Ok(&self.snapshot)
    }

    /// Updates intermediate health probe telemetry in the snapshot without adding an action entry.
    pub fn update_health_probe_status(&mut self, status: KillChainStatus) -> Result<()> {
        self.snapshot.status = status;
        self.snapshot.current_hash = self.snapshot.calculate_hash();
        self.commit_to_disk()
    }

    /// Atomically commits snapshot to disk via temp file + fsync + rename.
    pub fn commit_to_disk(&self) -> Result<()> {
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| {
                KillSwitchError::LedgerIoError {
                    path: parent.to_path_buf(),
                    source,
                }
            })?;
        }

        let serialized = serde_json::to_string_pretty(&self.snapshot)
            .map_err(|e| KillSwitchError::LedgerSerializationError(e.to_string()))?;

        let temp_path = self
            .file_path
            .with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));

        // Write and sync to temp file
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|source| KillSwitchError::LedgerIoError {
                    path: temp_path.clone(),
                    source,
                })?;

            file.write_all(serialized.as_bytes())
                .map_err(|source| KillSwitchError::LedgerIoError {
                    path: temp_path.clone(),
                    source,
                })?;

            file.sync_all()
                .map_err(|source| KillSwitchError::LedgerIoError {
                    path: temp_path.clone(),
                    source,
                })?;
        }

        // Transactional atomic replace / rename with rollback protection
        if let Err(initial_err) = std::fs::rename(&temp_path, &self.file_path) {
            if !self.file_path.exists() {
                let _ = std::fs::remove_file(&temp_path);
                return Err(KillSwitchError::LedgerIoError {
                    path: self.file_path.clone(),
                    source: initial_err,
                });
            }

            // Two-phase safe replacement with backup:
            let backup_path = self
                .file_path
                .with_extension(format!("bak.{}", uuid::Uuid::new_v4()));
            if let Err(backup_err) = std::fs::rename(&self.file_path, &backup_path) {
                let _ = std::fs::remove_file(&temp_path);
                return Err(KillSwitchError::LedgerIoError {
                    path: self.file_path.clone(),
                    source: backup_err,
                });
            }

            if let Err(rename_err) = std::fs::rename(&temp_path, &self.file_path) {
                // Rollback: restore original file from backup
                let _ = std::fs::rename(&backup_path, &self.file_path);
                let _ = std::fs::remove_file(&temp_path);
                return Err(KillSwitchError::LedgerIoError {
                    path: self.file_path.clone(),
                    source: rename_err,
                });
            }
            let _ = std::fs::remove_file(&backup_path);
        }

        Ok(())
    }

    /// Returns the live TPM 2.0 hardware status and verifies the sealed BLAKE3 ledger anchor.
    pub fn tpm_status_report(&self) -> crate::tpm::TpmStatusReport {
        crate::tpm::verify_tpm_and_ledger_anchor(
            &self.file_path,
            &self.snapshot.current_hash,
            self.snapshot.sequence_number,
        )
    }

    /// Re-seals the active BLAKE3 ledger root hash into the TPM 2.0 / DPAPI seal envelope and returns the updated report.
    pub fn re_seal_tpm_anchor(&self) -> crate::tpm::TpmStatusReport {
        let _ = crate::tpm::seal_ledger_anchor(
            &self.file_path,
            &self.snapshot.current_hash,
            self.snapshot.sequence_number,
        );
        self.tpm_status_report()
    }

    /// Verifies the cryptographic integrity of the historical event chain.
    pub fn verify_integrity(&self) -> Result<()> {
        // 1. Verify snapshot hash
        let expected_hash = self.snapshot.calculate_hash();
        if !killswitch_types::constant_time_eq(&self.snapshot.current_hash, &expected_hash) {
            return Err(KillSwitchError::StateHashChainMismatch {
                index: self.snapshot.sequence_number as usize,
                expected: expected_hash,
                calculated: self.snapshot.current_hash.clone(),
            });
        }

        // 2. Verify audit history reverse chain
        let history = &self.snapshot.history;
        for i in 0..history.len() {
            let current = &history[i];
            let expected_prev = if i + 1 < history.len() {
                history[i + 1].event_hash.as_str()
            } else {
                GENESIS_HASH
            };

            if !killswitch_types::constant_time_eq(&current.prev_event_hash, expected_prev) {
                return Err(KillSwitchError::StateHashChainMismatch {
                    index: i,
                    expected: expected_prev.to_string(),
                    calculated: current.prev_event_hash.clone(),
                });
            }

            let expected_event_hash = blake3::hash(
                format!(
                    "{}:{}:{}:{}:{}",
                    current.prev_event_hash,
                    current.timestamp,
                    current.action,
                    current.operator,
                    current.reason
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string();

            if !killswitch_types::constant_time_eq(&current.event_hash, &expected_event_hash) {
                return Err(KillSwitchError::StateHashChainMismatch {
                    index: i,
                    expected: expected_event_hash,
                    calculated: current.event_hash.clone(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_atomic_persistence_and_cryptographic_hash_chaining() {
        let dir = tempdir().unwrap();
        let mut ledger = StateLedger::open_or_init(Some(dir.path())).unwrap();

        assert_eq!(ledger.snapshot().prev_hash, GENESIS_HASH);
        assert!(!ledger.snapshot().current_hash.is_empty());
        assert!(ledger.verify_integrity().is_ok());

        // Transition 1: Engage
        let s1 = KillChainStatus {
            isolated: true,
            ..KillChainStatus::default()
        };
        ledger
            .record_state_transition(s1, None, None, "ENGAGED", "admin", "Threat detected")
            .unwrap();

        let hash1 = ledger.snapshot().current_hash.clone();
        assert_ne!(hash1, GENESIS_HASH);
        assert!(ledger.verify_integrity().is_ok());

        // Transition 2: Disarm
        let s2 = KillChainStatus {
            isolated: false,
            ..KillChainStatus::default()
        };
        ledger
            .record_state_transition(s2, None, None, "DISARMED", "admin", "Threat resolved")
            .unwrap();

        assert_eq!(ledger.snapshot().prev_hash, hash1);
        assert!(ledger.verify_integrity().is_ok());

        // Reload from disk and assert bit-for-bit fidelity
        let reloaded = StateLedger::open_or_init(Some(dir.path())).unwrap();
        assert_eq!(reloaded.snapshot().sequence_number, 2);
        assert!(reloaded.verify_integrity().is_ok());
    }

    #[test]
    fn test_state_ledger_preserves_corrupted_file_backup() {
        let dir = tempdir().unwrap();
        let state_file = dir.path().join("killchain_state.json");

        // Write a corrupted/tampered file
        std::fs::write(&state_file, b"{\"schema_version\": 1, \"corrupted_json\": true").unwrap();

        // open_or_init must detect corruption and re-initialize clean state
        let ledger = StateLedger::open_or_init(Some(dir.path())).unwrap();
        assert_eq!(ledger.snapshot().sequence_number, 0);

        // Verify that a .corrupt.<timestamp> backup was created
        let backup_files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("killchain_state.corrupt."))
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(
            backup_files.len(),
            1,
            "Expected exactly 1 preserved corrupted ledger backup file"
        );
        let content = std::fs::read(backup_files[0].path()).unwrap();
        assert_eq!(content, b"{\"schema_version\": 1, \"corrupted_json\": true");
    }
}
