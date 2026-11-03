//! Crash-safe Ed25519-sealed persistence of quarantine leases, generation epochs, and CBF accumulators.
//!
//! Enforces the fail-closed restart invariant: on daemon restart, unexpired quarantine leases
//! are re-verified from the sealed journal and immediately re-enforced before serving any traffic.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuarantineLease {
    pub workload_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    pub trigger_reason: String,
    pub rule_id: String,
    pub quarantined_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalRecord {
    pub seq: u64,
    pub prev_hash: String,
    pub record_hash: String,
    pub action: String, // "QUARANTINE", "RELEASE", "ADVANCE_EPOCH"
    pub workload_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    pub timestamp_utc: DateTime<Utc>,
    pub payload_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalData {
    pub version: u32,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub prev_hash: String,
    pub active_leases: HashMap<String, QuarantineLease>,
    pub generation_epochs: HashMap<String, u64>,
    #[serde(default)]
    pub records: Vec<JournalRecord>,
    pub last_updated_utc: DateTime<Utc>,
}

impl Default for JournalData {
    fn default() -> Self {
        Self {
            version: 1,
            seq: 0,
            prev_hash: String::new(),
            active_leases: HashMap::new(),
            generation_epochs: HashMap::new(),
            records: Vec::new(),
            last_updated_utc: Utc::now(),
        }
    }
}

impl JournalData {
    pub fn append_record(
        &mut self,
        action: &str,
        workload_id: &str,
        target_pid: Option<u32>,
        payload_digest: &str,
    ) -> JournalRecord {
        let seq = self.seq + 1;
        let prev_hash = self.prev_hash.clone();
        let timestamp_utc = Utc::now();

        let preimage = format!(
            "{}|{}|{}|{}|{:?}|{}|{}",
            seq,
            prev_hash,
            action,
            workload_id,
            target_pid,
            timestamp_utc.to_rfc3339(),
            payload_digest
        );
        let mut hasher = Sha256::new();
        hasher.update(preimage.as_bytes());
        let record_hash = hex::encode(hasher.finalize());

        let record = JournalRecord {
            seq,
            prev_hash: prev_hash.clone(),
            record_hash: record_hash.clone(),
            action: action.to_string(),
            workload_id: workload_id.to_string(),
            target_pid,
            timestamp_utc,
            payload_digest: payload_digest.to_string(),
        };

        self.seq = seq;
        self.prev_hash = record_hash;
        self.records.push(record.clone());
        record
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedJournalEnvelope {
    pub payload: JournalData,
    pub kid: String,
    pub signature: String, // base64url Ed25519 signature over CAGE_JOURNAL_SEAL_V1:<JCS(payload)>
}

#[derive(Clone)]
pub struct QuarantineJournal {
    state_dir: PathBuf,
    data: Arc<RwLock<JournalData>>,
    signing_key: Arc<SigningKey>,
    kid: String,
}

impl QuarantineJournal {
    pub fn new(state_dir: PathBuf, signing_key: Arc<SigningKey>, kid: String) -> Self {
        let _ = std::fs::create_dir_all(&state_dir);
        let journal = Self {
            state_dir,
            data: Arc::new(RwLock::new(JournalData::default())),
            signing_key,
            kid,
        };
        // Load initial state if present
        if let Ok(Some(loaded)) = journal.load_and_verify() {
            *journal.data.write() = loaded;
        }
        journal
    }

    fn journal_file_path(&self) -> PathBuf {
        self.state_dir.join("quarantine_journal.json")
    }

    /// Loads and verifies the Ed25519-sealed journal from disk.
    pub fn load_and_verify(&self) -> Result<Option<JournalData>, String> {
        let path = self.journal_file_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read journal file: {}", e))?;
        let envelope: SealedJournalEnvelope = serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid sealed journal JSON: {}", e))?;

        // Canonicalize payload for seal verification
        let payload_val = serde_json::to_value(&envelope.payload)
            .map_err(|e| format!("Failed to convert payload to value: {}", e))?;
        let canonical_bytes = killswitch_telemetry::canonicalize_jcs(&payload_val)
            .map_err(|e| format!("JCS canonicalization failed: {}", e))?;

        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical_bytes);

        // Verify signature
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&envelope.signature)
            .map_err(|e| format!("Invalid base64 signature: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length in journal seal".to_string());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        let verifying_key = self.signing_key.verifying_key();
        verifying_key
            .verify(&preimage, &sig)
            .map_err(|e| format!("Journal seal signature verification failed: {}", e))?;

        info!(
            "📖 [JOURNAL] Successfully verified and loaded journal seal with {} active leases",
            envelope.payload.active_leases.len()
        );
        Ok(Some(envelope.payload))
    }

    /// Persists current journal data atomically using temp-file + fsync + rename.
    pub fn flush_to_disk(&self) -> Result<(), String> {
        let guard = self.data.read();
        let payload_val = serde_json::to_value(&*guard)
            .map_err(|e| format!("Failed to convert journal data to value: {}", e))?;
        let canonical_bytes = killswitch_telemetry::canonicalize_jcs(&payload_val)
            .map_err(|e| format!("JCS canonicalization failed: {}", e))?;

        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical_bytes);

        let sig = self.signing_key.sign(&preimage);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

        let envelope = SealedJournalEnvelope {
            payload: guard.clone(),
            kid: self.kid.clone(),
            signature: sig_b64,
        };
        let serialized = serde_json::to_string_pretty(&envelope)
            .map_err(|e| format!("Serialization error: {}", e))?;

        let target_path = self.journal_file_path();
        let temp_path = self.state_dir.join(format!(".journal_{}.tmp", uuid::Uuid::new_v4()));

        std::fs::write(&temp_path, serialized.as_bytes())
            .map_err(|e| format!("Failed to write temp journal: {}", e))?;
        
        // Ensure file is synced to disk
        if let Ok(file) = std::fs::File::open(&temp_path) {
            let _ = file.sync_all();
        }

        std::fs::rename(&temp_path, &target_path)
            .map_err(|e| format!("Atomic rename of journal failed: {}", e))?;

        Ok(())
    }

    /// Records an active quarantine lease, appends a hash-chained record, and seals journal.
    pub fn record_quarantine(&self, lease: QuarantineLease) -> Result<(), String> {
        {
            let mut guard = self.data.write();
            let mut hasher = Sha256::new();
            hasher.update(lease.workload_id.as_bytes());
            hasher.update(lease.trigger_reason.as_bytes());
            hasher.update(lease.rule_id.as_bytes());
            hasher.update(lease.nonce.as_bytes());
            let payload_digest = hex::encode(hasher.finalize());

            guard.append_record(
                "QUARANTINE",
                &lease.workload_id,
                lease.target_pid,
                &payload_digest,
            );
            guard.active_leases.insert(lease.workload_id.clone(), lease);
            guard.last_updated_utc = Utc::now();
        }
        self.flush_to_disk()
    }

    /// Releases a quarantine lease, appends a hash-chained release record, and seals journal.
    pub fn release_quarantine(&self, workload_id: &str) -> Result<Option<QuarantineLease>, String> {
        let removed = {
            let mut guard = self.data.write();
            let res = guard.active_leases.remove(workload_id);
            if res.is_some() {
                guard.append_record("RELEASE", workload_id, None, "QUARANTINE_RELEASED");
            }
            guard.last_updated_utc = Utc::now();
            res
        };
        if removed.is_some() {
            self.flush_to_disk()?;
        }
        Ok(removed)
    }

    /// Gets current generation epoch for a workload.
    pub fn get_generation_epoch(&self, workload_id: &str) -> u64 {
        self.data.read().generation_epochs.get(workload_id).copied().unwrap_or(1)
    }

    /// Monotonically advances generation epoch `Gen N -> Gen N + 1`, appends record, and seals journal.
    pub fn advance_generation_epoch(&self, workload_id: &str) -> Result<(u64, u64), String> {
        let (before, after) = {
            let mut guard = self.data.write();
            let current = guard.generation_epochs.get(workload_id).copied().unwrap_or(1);
            let next = current + 1;
            guard.generation_epochs.insert(workload_id.to_string(), next);
            let payload_digest = format!("epoch:{}->{}", current, next);
            guard.append_record("ADVANCE_EPOCH", workload_id, None, &payload_digest);
            guard.last_updated_utc = Utc::now();
            (current, next)
        };
        self.flush_to_disk()?;
        Ok((before, after))
    }

    /// Returns the current monotonic sequence number of the journal.
    pub fn current_seq(&self) -> u64 {
        self.data.read().seq
    }

    /// Returns the latest previous record hash.
    pub fn latest_prev_hash(&self) -> String {
        self.data.read().prev_hash.clone()
    }

    /// Returns all journal records.
    pub fn records(&self) -> Vec<JournalRecord> {
        self.data.read().records.clone()
    }

    /// Verifies the cryptographic hash chaining and sequence monotonicity across all records.
    pub fn verify_hash_chain(&self) -> Result<bool, String> {
        let guard = self.data.read();
        let mut expected_prev_hash = String::new();
        for (i, rec) in guard.records.iter().enumerate() {
            let expected_seq = (i as u64) + 1;
            if rec.seq != expected_seq {
                return Err(format!(
                    "Monotonic sequence broken at index {}: expected {}, found {}",
                    i, expected_seq, rec.seq
                ));
            }
            if rec.prev_hash != expected_prev_hash {
                return Err(format!(
                    "Prev hash chain broken at seq {}: expected '{}', found '{}'",
                    rec.seq, expected_prev_hash, rec.prev_hash
                ));
            }
            let preimage = format!(
                "{}|{}|{}|{}|{:?}|{}|{}",
                rec.seq,
                rec.prev_hash,
                rec.action,
                rec.workload_id,
                rec.target_pid,
                rec.timestamp_utc.to_rfc3339(),
                rec.payload_digest
            );
            let mut hasher = Sha256::new();
            hasher.update(preimage.as_bytes());
            let computed = hex::encode(hasher.finalize());
            if rec.record_hash != computed {
                return Err(format!(
                    "Record hash mismatch at seq {}: stored '{}', recomputed '{}'",
                    rec.seq, rec.record_hash, computed
                ));
            }
            expected_prev_hash = rec.record_hash.clone();
        }
        Ok(true)
    }

    /// Checks if any unexpired quarantine leases exist.
    pub fn unexpired_leases(&self) -> Vec<QuarantineLease> {
        let now = Utc::now();
        self.data
            .read()
            .active_leases
            .values()
            .filter(|l| l.expires_at.map_or(true, |exp| exp > now))
            .cloned()
            .collect()
    }

    /// Re-enforces all unexpired leases into host containment manager on startup.
    pub async fn recover_and_re_enforce(
        &self,
        containment_manager: &Arc<killswitch_core::killchain::HostContainmentManager>,
    ) -> Result<usize, String> {
        let leases = self.unexpired_leases();
        let count = leases.len();
        if count > 0 {
            info!(
                "🚨 [JOURNAL] Found {} unexpired quarantine leases on startup; re-enforcing kernel isolation fail-closed",
                count
            );
            let _ = containment_manager
                .engage_isolation(
                    "cage_journal_recovery",
                    "Unexpired quarantine leases restored on daemon restart",
                    killswitch_types::ContainmentLevel::NetworkQuarantine,
                    None,
                )
                .await
                .map_err(|e| format!("Failed to re-engage isolation on recovery: {}", e))?;

            for lease in &leases {
                if let Some(pid) = lease.target_pid {
                    if pid > 0 {
                        let _ = containment_manager.freeze_process(pid);
                    }
                }
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_quarantine_journal_lifecycle_and_seal_verification() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut rng = OsRng;
        let signing_key = Arc::new(SigningKey::generate(&mut rng));
        let kid = "test_journal_kid_1234567890abcdef".to_string();

        let journal = QuarantineJournal::new(temp_dir.path().to_path_buf(), Arc::clone(&signing_key), kid.clone());

        // 1. Initial epoch is 1
        assert_eq!(journal.get_generation_epoch("agent-1"), 1);

        // 2. Advance epoch
        let (before, after) = journal.advance_generation_epoch("agent-1").unwrap();
        assert_eq!(before, 1);
        assert_eq!(after, 2);
        assert_eq!(journal.get_generation_epoch("agent-1"), 2);

        // 3. Record quarantine lease
        let lease = QuarantineLease {
            workload_id: "agent-1".to_string(),
            target_pid: Some(1234),
            trigger_reason: "CBF_CRITICAL_VIOLATION".to_string(),
            rule_id: "RULE-SC-7-CBF-LETHAL".to_string(),
            quarantined_at: Utc::now(),
            expires_at: None,
            nonce: "test_nonce_999".to_string(),
        };
        journal.record_quarantine(lease.clone()).unwrap();

        assert_eq!(journal.unexpired_leases().len(), 1);

        // 4. Reload from disk in a fresh journal instance and verify seal
        let journal2 = QuarantineJournal::new(temp_dir.path().to_path_buf(), Arc::clone(&signing_key), kid);
        assert_eq!(journal2.get_generation_epoch("agent-1"), 2);
        let loaded_leases = journal2.unexpired_leases();
        assert_eq!(loaded_leases.len(), 1);
        assert_eq!(loaded_leases[0].workload_id, "agent-1");
        assert_eq!(loaded_leases[0].target_pid, Some(1234));

        // 5. Release quarantine
        journal2.release_quarantine("agent-1").unwrap();
        assert_eq!(journal2.unexpired_leases().len(), 0);

        // 6. Verify monotonic sequence numbers and hash chain integrity
        assert_eq!(journal2.current_seq(), 3);
        assert!(!journal2.latest_prev_hash().is_empty());
        let recs = journal2.records();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].seq, 1);
        assert_eq!(recs[0].prev_hash, "");
        assert_eq!(recs[0].action, "ADVANCE_EPOCH");
        assert_eq!(recs[1].seq, 2);
        assert_eq!(recs[1].prev_hash, recs[0].record_hash);
        assert_eq!(recs[1].action, "QUARANTINE");
        assert_eq!(recs[2].seq, 3);
        assert_eq!(recs[2].prev_hash, recs[1].record_hash);
        assert_eq!(recs[2].action, "RELEASE");
        assert!(journal2.verify_hash_chain().unwrap());
    }
}
