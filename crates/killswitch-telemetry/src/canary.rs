//! # Decoy Canaries and Filesystem Ghost Traps
//!
//! Deploys and monitors high-value decoy artifacts in sensitive directories
//! (`passwords_2025.txt`, `client_billing_records.xlsx`, `id_rsa_backup`, etc.)
//! to detect unauthorized adversary discovery, tampering, or ransomware encryption.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use killswitch_types::adjudication::EvidenceClass;
use killswitch_types::telemetry::{ThreatSeverity, ThreatSignal};

/// Information regarding a deployed canary decoy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryDecoyFile {
    pub path: PathBuf,
    pub filename: String,
    pub blake3_hash: String,
    pub created_at: DateTime<Utc>,
    pub expected_size: u64,
}

/// Status report resulting from a canary directory audit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanaryAuditReport {
    pub total_monitored: usize,
    pub intact_count: usize,
    pub modified_count: usize,
    pub deleted_count: usize,
    pub violated_paths: Vec<String>,
}

/// Manager responsible for deploying and monitoring canary decoy files.
#[derive(Clone)]
pub struct CanaryManager {
    deployed: Arc<RwLock<HashMap<PathBuf, CanaryDecoyFile>>>,
    deploy_dirs: Vec<PathBuf>,
}

impl Default for CanaryManager {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl CanaryManager {
    pub const DECOY_FILENAMES: [&'static str; 5] = [
        "passwords_2025.txt",
        "client_billing_records.xlsx",
        "id_rsa_backup",
        "aws_credentials_old.ini",
        "salary_list.pdf",
    ];

    pub fn new(deploy_dirs: Vec<PathBuf>) -> Self {
        Self {
            deployed: Arc::new(RwLock::new(HashMap::new())),
            deploy_dirs,
        }
    }

    /// Deploys decoy files into the target directories with unique honeytoken payloads.
    pub fn deploy_all(&self) -> Result<usize, std::io::Error> {
        let mut count = 0;
        let mut deployed = self.deployed.write();

        for dir in &self.deploy_dirs {
            if !dir.exists() {
                let _ = fs::create_dir_all(dir);
            }

            for &name in &Self::DECOY_FILENAMES {
                let file_path = dir.join(name);
                let content = format!(
                    "--- CANARY DECOY TRAP ---\nASSET_ID: {}\nHONEYTOKEN_KEY: {}\nDO NOT MODIFY OR TRANSMIT THIS ARTIFACT.\n",
                    name,
                    uuid::Uuid::new_v4()
                );

                fs::write(&file_path, content.as_bytes())?;
                let hash = blake3::hash(content.as_bytes()).to_hex().to_string();
                let meta = fs::metadata(&file_path)?;

                let decoy = CanaryDecoyFile {
                    path: file_path.clone(),
                    filename: name.to_string(),
                    blake3_hash: hash,
                    created_at: Utc::now(),
                    expected_size: meta.len(),
                };

                deployed.insert(file_path, decoy);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Registers a manually created canary decoy file.
    pub fn register_canary(&self, path: PathBuf, hash: String, size: u64) {
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("canary")
            .to_string();

        let decoy = CanaryDecoyFile {
            path: path.clone(),
            filename,
            blake3_hash: hash,
            created_at: Utc::now(),
            expected_size: size,
        };

        self.deployed.write().insert(path, decoy);
    }

    /// Audits all registered decoy files, checking for tampering, modification, or deletion.
    /// If any tampering is detected, synthesizes a critical ThreatSignal.
    pub fn audit_canaries(&self, trigger_pid: Option<u32>) -> (CanaryAuditReport, Option<ThreatSignal>) {
        let deployed = self.deployed.read();
        let total = deployed.len();
        let mut intact = 0;
        let mut modified = 0;
        let mut deleted = 0;
        let mut violated_paths = Vec::new();

        for (path, decoy) in deployed.iter() {
            if !path.exists() {
                deleted += 1;
                violated_paths.push(format!("DELETED: {}", path.display()));
                continue;
            }

            match fs::read(path) {
                Ok(content) => {
                    let current_hash = blake3::hash(&content).to_hex().to_string();
                    if current_hash != decoy.blake3_hash {
                        modified += 1;
                        violated_paths.push(format!("MODIFIED: {}", path.display()));
                    } else {
                        intact += 1;
                    }
                }
                Err(_) => {
                    modified += 1;
                    violated_paths.push(format!("READ_ERROR: {}", path.display()));
                }
            }
        }

        let report = CanaryAuditReport {
            total_monitored: total,
            intact_count: intact,
            modified_count: modified,
            deleted_count: deleted,
            violated_paths: violated_paths.clone(),
        };

        let signal = if modified > 0 || deleted > 0 {
            let pid = trigger_pid.unwrap_or(0);
            let mut sig = ThreatSignal::new(
                "canary-tripwire",
                pid,
                "canary_tamperer",
                0.98,
                ThreatSeverity::Critical,
                EvidenceClass::Behavior,
                format!(
                    "Canary decoy tripwire breached: {} modified, {} deleted. Paths: [{}]",
                    modified,
                    deleted,
                    violated_paths.join(", ")
                ),
            );

            sig.raw_evidence = serde_json::json!({
                "modified_count": modified,
                "deleted_count": deleted,
                "violated_paths": violated_paths,
            });

            Some(sig)
        } else {
            None
        };

        (report, signal)
    }

    /// Cleans up all deployed canary decoy files from disk.
    pub fn cleanup_all(&self) {
        let mut deployed = self.deployed.write();
        for path in deployed.keys() {
            let _ = fs::remove_file(path);
        }
        deployed.clear();
    }

    pub fn monitored_count(&self) -> usize {
        self.deployed.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_deployment_and_tamper_detection() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = CanaryManager::new(vec![temp_dir.path().to_path_buf()]);

        let deployed_count = manager.deploy_all().unwrap();
        assert_eq!(deployed_count, 5);

        // Initial audit must be 100% intact
        let (initial_report, initial_signal) = manager.audit_canaries(None);
        assert_eq!(initial_report.intact_count, 5);
        assert_eq!(initial_report.modified_count, 0);
        assert_eq!(initial_report.deleted_count, 0);
        assert!(initial_signal.is_none());

        // Tamper with one file
        let target_file = temp_dir.path().join("passwords_2025.txt");
        fs::write(&target_file, b"RANSOMWARE_ENCRYPTED_DATA_000").unwrap();

        // Second audit must detect modification and emit ThreatSignal
        let (tampered_report, tampered_signal) = manager.audit_canaries(Some(4321));
        assert_eq!(tampered_report.intact_count, 4);
        assert_eq!(tampered_report.modified_count, 1);
        assert!(tampered_signal.is_some());
        let sig = tampered_signal.unwrap();
        assert_eq!(sig.target_pid, 4321);
        assert_eq!(sig.confidence, 0.98);
        assert_eq!(sig.severity, ThreatSeverity::Critical);

        manager.cleanup_all();
        assert_eq!(manager.monitored_count(), 0);
    }
}
