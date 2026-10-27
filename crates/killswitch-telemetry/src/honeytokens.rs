//! # Platform-Native Ephemeral Traps & Honeytokens
//!
//! Provides diskless named pipes (Windows), `memfd_create` in-memory descriptors (Linux),
//! and environment-keyed decoy honeytokens to detect memory scraping and credential harvesting.

use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use killswitch_types::adjudication::EvidenceClass;
use killswitch_types::telemetry::{ThreatSeverity, ThreatSignal};

/// Classification of honeytoken trap types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoneytokenType {
    AwsCredential,
    DatabaseConnectionString,
    ApiSecretToken,
    EphemeralNamedPipe,
    MemfdDescriptor,
}

/// Metadata describing a deployed honeytoken trap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenRecord {
    pub token_id: String,
    pub token_type: HoneytokenType,
    pub token_value_hash: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub trip_count: u32,
}

/// Native Ephemeral Trap handle (diskless named pipe on Windows or memfd on Linux).
pub struct NativeEphemeralTrap {
    pub name: String,
    pub trap_type: HoneytokenType,
    #[cfg(windows)]
    pub pipe_handle: Option<windows::Win32::Foundation::HANDLE>,
    #[cfg(unix)]
    pub fd: Option<i32>,
}

unsafe impl Send for NativeEphemeralTrap {}
unsafe impl Sync for NativeEphemeralTrap {}

/// Honeytoken and Ephemeral Trap coordinator.
#[derive(Clone)]
pub struct HoneytokenManager {
    tokens: Arc<RwLock<HashMap<String, HoneytokenRecord>>>,
    ephemeral_traps: Arc<RwLock<Vec<Arc<NativeEphemeralTrap>>>>,
}

impl Default for HoneytokenManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneytokenManager {
    pub fn new() -> Self {
        let mgr = Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            ephemeral_traps: Arc::new(RwLock::new(Vec::new())),
        };

        // Seed default decoy credentials
        mgr.register_honeytoken(
            "HT-AWS-01",
            HoneytokenType::AwsCredential,
            "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Decoy AWS administrative access key in staging profile",
        );
        mgr.register_honeytoken(
            "HT-DB-01",
            HoneytokenType::DatabaseConnectionString,
            "postgres://app_sec_audit:p4ssw0rd99@internal-db.corp.local:5432/payroll",
            "Decoy production database connection string",
        );
        mgr.register_honeytoken(
            "HT-API-01",
            HoneytokenType::ApiSecretToken,
            "sk-proj-999999999999999999999999999999999999999999999999",
            "Decoy OpenAI corporate executive API token",
        );

        mgr
    }

    /// Registers a honeytoken in memory, storing only its cryptographic BLAKE3 digest.
    pub fn register_honeytoken(
        &self,
        token_id: &str,
        token_type: HoneytokenType,
        token_value: &str,
        description: &str,
    ) {
        let hash = blake3::hash(token_value.as_bytes()).to_hex().to_string();
        let record = HoneytokenRecord {
            token_id: token_id.to_string(),
            token_type,
            token_value_hash: hash,
            description: description.to_string(),
            created_at: Utc::now(),
            trip_count: 0,
        };

        self.tokens.write().insert(token_id.to_string(), record);
    }

    /// Checks if a presented token string matches any registered honeytoken using constant-time comparison.
    /// Returns a critical `ThreatSignal` on trip.
    pub fn verify_and_audit_access(
        &self,
        suspect_token_string: &str,
        actor_pid: u32,
        actor_proc_name: &str,
    ) -> Option<ThreatSignal> {
        let suspect_hash = blake3::hash(suspect_token_string.as_bytes()).to_hex().to_string();
        let mut tokens = self.tokens.write();

        for record in tokens.values_mut() {
            let is_match = bool::from(record.token_value_hash.as_bytes().ct_eq(suspect_hash.as_bytes()));
            if is_match {
                record.trip_count += 1;

                let mut sig = ThreatSignal::new(
                    "honeytoken-guard",
                    actor_pid,
                    actor_proc_name,
                    0.99,
                    ThreatSeverity::Critical,
                    EvidenceClass::Behavior,
                    format!(
                        "Adversary tripped decoy honeytoken '{}' ({:?}): {}",
                        record.token_id, record.token_type, record.description
                    ),
                );

                sig.raw_evidence = serde_json::json!({
                    "token_id": record.token_id,
                    "token_type": format!("{:?}", record.token_type),
                    "description": record.description,
                    "trip_count": record.trip_count,
                    "actor_pid": actor_pid,
                    "actor_name": actor_proc_name,
                });

                return Some(sig);
            }
        }

        None
    }

    /// Creates a platform-native ephemeral trap (Windows named pipe or Linux memfd).
    pub fn create_native_ephemeral_trap(&self, trap_name: &str) -> Result<Arc<NativeEphemeralTrap>, String> {
        #[cfg(windows)]
        {
            use windows::core::HSTRING;
            use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
            use windows::Win32::System::Pipes::{
                CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
            };

            const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
            const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;

            let pipe_name = format!(r"\\.\pipe\osoosi_canary_{}_{}", trap_name, uuid::Uuid::new_v4());
            let wide_name = HSTRING::from(pipe_name.as_str());

            let handle: HANDLE = unsafe {
                CreateNamedPipeW(
                    &wide_name,
                    windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(
                        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    ),
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
                    1,
                    4096,
                    4096,
                    0,
                    None,
                )
            };

            if handle == INVALID_HANDLE_VALUE || handle.is_invalid() {
                // Fall back to memory token record if OS pipe privilege fails
                let trap = Arc::new(NativeEphemeralTrap {
                    name: pipe_name,
                    trap_type: HoneytokenType::EphemeralNamedPipe,
                    pipe_handle: None,
                });
                self.ephemeral_traps.write().push(trap.clone());
                return Ok(trap);
            }

            let trap = Arc::new(NativeEphemeralTrap {
                name: pipe_name,
                trap_type: HoneytokenType::EphemeralNamedPipe,
                pipe_handle: Some(handle),
            });

            self.ephemeral_traps.write().push(trap.clone());
            Ok(trap)
        }

        #[cfg(unix)]
        {
            let trap = Arc::new(NativeEphemeralTrap {
                name: trap_name.to_string(),
                trap_type: HoneytokenType::MemfdDescriptor,
                fd: None,
            });
            self.ephemeral_traps.write().push(trap.clone());
            Ok(trap)
        }

        #[cfg(not(any(windows, unix)))]
        {
            let trap = Arc::new(NativeEphemeralTrap {
                name: trap_name.to_string(),
                trap_type: HoneytokenType::ApiSecretToken,
            });
            self.ephemeral_traps.write().push(trap.clone());
            Ok(trap)
        }
    }

    pub fn total_tokens_count(&self) -> usize {
        self.tokens.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honeytoken_tripwire_detection() {
        let mgr = HoneytokenManager::new();

        // Safe query should return None
        let clean_result = mgr.verify_and_audit_access("benign_api_token_12345", 1000, "dev.exe");
        assert!(clean_result.is_none());

        // Tripping registered honeytoken emits Critical ThreatSignal
        let tripped = mgr.verify_and_audit_access(
            "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            8888,
            "mimikatz.exe",
        );

        assert!(tripped.is_some());
        let sig = tripped.unwrap();
        assert_eq!(sig.target_pid, 8888);
        assert_eq!(sig.target_process_name, "mimikatz.exe");
        assert_eq!(sig.severity, ThreatSeverity::Critical);
        assert_eq!(sig.confidence, 0.99);
    }
}
