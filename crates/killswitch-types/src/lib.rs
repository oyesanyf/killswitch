//! # `killswitch-types`
//!
//! Foundational domain models, cryptographic BLAKE3 / HMAC-SHA256 primitives,
//! deterministic identities, error taxonomy, adjudication verdict types, containment states,
//! and stateful LangGraph execution traces for the KillSwitch security workspace.

pub mod adjudication;
pub mod errors;
pub mod graph;
pub mod identity;
pub mod octopus;
pub mod status;
pub mod telemetry;

// Re-export error types
pub use errors::{KillSwitchError, KillSwitchResult, Result};

// Re-export identity types
pub use identity::ProcessInstanceIdentity;

// Re-export containment status & auth types
pub use status::{
    constant_time_eq, validate_arm_generation_epoch, validate_caller_pid,
    ActiveNetworkRule, AdminHashAlgorithm, AuthMethod, AuthResult,
    ContainmentLevel, HealthProbeAnomaly, HealthProbeRunner, IsolationReceipt,
    KillChainHealthProbeReport, KillChainHistoryEntry, KillChainStatus, LockoutState,
    NetworkIsolationEngine, NetworkIsolator, OperatorAuthenticator, OperatorCredentials,
    ProbeAnomalyKind, ProcessFreezeStatus, ProcessFreezer, ProcessIsolationMethod,
    ProcessIsolationState, QuarantinedArmEpoch, StoredAdminHash, ThreadTarpitMetrics,
    DEFAULT_CONTROL_PORT, DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
    DEFAULT_REQUIRED_CONSECUTIVE_HEALTHY_PROBES, DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS,
    KILLCHAIN_ISOLATE_TOKEN, KILLCHAIN_RESTORE_TOKEN, LOCKOUT_DURATION_SECS,
    MAX_FAILED_ATTEMPTS,
};

// Re-export adjudication & fraud proof types
pub use adjudication::{
    calculate_consensus, corroboration_multiplier, AdjudicationResult, AuthenticodeChainStatus,
    AuthenticodeStatus, BinaryTrustVerdict, ByzantineKillSwitchFraudProof, EvidenceClass,
    ReaConsensusVote, ReaDetectorEvaluation, ThreatCandidate, VetoReason, VoteAction,
    VoteResult, FRAUD_PROOF_SEAL_CONTEXT, REA_SEAL_CONTEXT,
};

// Re-export octopus multi-ring types
pub use octopus::{
    role_trust_tier, ArmEpoch, ArmMessage, ArmRole, MessageKind, ProvenanceHop,
    TrustTier, MAX_RELAY_HOPS,
};

// Re-export telemetry types
pub use telemetry::{SecurityEvent, TelemetryEventKind, ThreatSeverity, ThreatSignal};

// Re-export LangGraph state types
pub use graph::{
    ApprovalDecision, ExecutionStep, GraphNode, GraphNodeId, GraphNodeOutput,
    KillSwitchGraphState, OperatorApprovalState, OrchestratorMode, StateCheckpointer,
};

// Re-export service types
pub mod service;
pub use service::{ServiceConfig, ServiceError, ServiceState, ServiceStatus};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_byzantine_fraud_proof_keyed_seal() {
        let key = [0x5au8; 32];
        let proof = ByzantineKillSwitchFraudProof::new(
            "peer-orchestrator",
            "peer-rogue-2",
            "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            "cargo.exe",
            "Developer binary illicitly targeted for freeze",
        );

        // Verify canonical unkeyed seal
        assert!(proof.verify_seal());

        // Generate keyed seal
        let keyed_seal = ByzantineKillSwitchFraudProof::compute_keyed_seal(
            &key,
            &proof.peer_id,
            &proof.accused_peer_id,
            &proof.target_binary_hash,
            &proof.proc_name,
            &proof.fraud_reason,
            &proof.timestamp,
        );

        let mut keyed_proof = proof.clone();
        keyed_proof.proof_seal = keyed_seal;
        assert!(keyed_proof.verify_keyed_seal(&key));

        // Wrong key fails
        let wrong_key = [0x5bu8; 32];
        assert!(!keyed_proof.verify_keyed_seal(&wrong_key));
    }

    #[test]
    fn test_isolation_receipt_creation_and_hashing() {
        let receipt = IsolationReceipt::new(
            "session-wfp-001".to_string(),
            NetworkIsolationEngine::WindowsWfpDynamic,
            vec![101, 102, 103],
            vec!["OsoosiBlockAllOutbound".to_string()],
            vec![],
            vec![3030, 53, 67, 68],
            vec!["127.0.0.1".parse::<IpAddr>().unwrap(), "::1".parse::<IpAddr>().unwrap()],
            15,
            "operator-admin".to_string(),
            "High-confidence ransomware detected".to_string(),
        );

        assert_eq!(receipt.engine, NetworkIsolationEngine::WindowsWfpDynamic);
        assert_eq!(receipt.wfp_filter_ids.len(), 3);
        assert_eq!(receipt.terminated_tcp_connections_count, 15);
        assert!(!receipt.receipt_hash_blake3.is_empty());
        assert!(receipt.receipt_id.starts_with("receipt-"));
    }

    #[test]
    fn test_process_isolation_state_lifecycle() {
        let mut proc_state = ProcessIsolationState::new_frozen(
            8080,
            "suspicious_worker.exe".to_string(),
            Some("C:\\Windows\\Temp\\suspicious_worker.exe".into()),
            ProcessIsolationMethod::NtSuspendProcess,
        );

        assert_eq!(proc_state.status, ProcessFreezeStatus::Frozen);
        assert!(proc_state.suspended_at.is_some());
        assert!(proc_state.resumed_at.is_none());

        proc_state.mark_resumed();
        assert_eq!(proc_state.status, ProcessFreezeStatus::Resumed);
        assert!(proc_state.resumed_at.is_some());
    }

    #[test]
    fn test_health_probe_anomaly_and_early_rollback_logic() {
        let now = chrono::Utc::now();
        let hash = KillChainHealthProbeReport::compute_hash(&now, true, 250, 12, 3, "All clear");
        assert!(!hash.is_empty());

        let report = KillChainHealthProbeReport {
            timestamp: now,
            process_tree_integrity_ok: true,
            total_processes_scanned: 250,
            critical_os_anchors_verified: 12,
            frozen_pids_monitored: 2,
            suspicious_unfrozen_processes: vec![],
            orphaned_malicious_children: vec![],
            detected_anomalies: vec![],
            consecutive_healthy_probes: 3,
            required_healthy_probes: 3,
            eligible_for_early_rollback: true,
            rollback_watchdog_max_secs: 1800,
            probe_interval_secs: 60,
            probe_hash_blake3: hash,
            summary: "All clear".to_string(),
        };

        assert!(report.eligible_for_early_rollback);
        assert_eq!(report.consecutive_healthy_probes, report.required_healthy_probes);
    }

    #[test]
    fn test_arm_epoch_token_validation_stale_and_quarantine() {
        // Current epoch 3, presenting epoch 2 -> StaleGenerationEpoch error
        let res_stale = validate_arm_generation_epoch(1, 2, 3, false, None);
        assert!(matches!(
            res_stale,
            Err(KillSwitchError::StaleGenerationEpoch { arm_id: 1, expected: 3, presented: 2 })
        ));

        // Quarantined arm -> ArmQuarantined error
        let res_quarantine = validate_arm_generation_epoch(2, 3, 3, true, Some("Anomalous lateral traffic"));
        assert!(matches!(
            res_quarantine,
            Err(KillSwitchError::ArmQuarantined { arm_id: 2, epoch: 3, .. })
        ));

        // Valid arm
        assert!(validate_arm_generation_epoch(3, 4, 4, false, None).is_ok());
    }

    #[test]
    fn test_multi_voter_consensus_three_classes() {
        let v1 = VoteResult::new(
            Some(7777),
            VoteAction::Isolate,
            0.95,
            EvidenceClass::LiveNetwork,
            "Active exfiltration socket",
            "NetworkVoter",
        );
        let v2 = VoteResult::new(
            Some(7777),
            VoteAction::Isolate,
            0.96,
            EvidenceClass::Behavior,
            "Rapid shadow copy deletion",
            "BehaviorVoter",
        );
        let v3 = VoteResult::new(
            Some(7777),
            VoteAction::Isolate,
            0.94,
            EvidenceClass::Memory,
            "Reflective DLL injection detected",
            "MemoryVoter",
        );

        let (score, classes_count) = calculate_consensus(&[v1, v2, v3]);
        assert_eq!(classes_count, 3);
        // With 3 orthogonal classes, multiplier is 1.00, score >= 0.94 -> actionable
        assert!(score >= 0.94);
    }
}
