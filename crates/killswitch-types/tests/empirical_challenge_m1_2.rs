//! Empirical Adversarial Challenge Suite - Challenger M1-2
//!
//! Stress-testing Octopus multi-ring and state control mechanisms in `crates/killswitch-types`:
//! 1. `ArmMessage` HMAC verification & canonical signing content role binding.
//! 2. `LAW1_STICKY_TAINT_VETO` exhaustive matrix & provenance taint propagation.
//! 3. `LockoutState` 3-strike 300s window & master token bypass vs password lock.
//! 4. `KillChainHealthProbeReport` consecutive healthy probes logic & anomaly reset.
//! 5. `ExecutionStep` BLAKE3 Merkle chain link tamper resistance.

use chrono::{Duration, Utc};
use killswitch_types::{
    constant_time_eq, role_trust_tier, ArmEpoch, ArmMessage, ArmRole, AuthMethod, AuthResult,
    ExecutionStep, GraphNodeId, HealthProbeAnomaly, KillChainHealthProbeReport,
    KillSwitchGraphState, LockoutState, MessageKind, OperatorCredentials, OrchestratorMode,
    ProbeAnomalyKind, ProvenanceHop, TrustTier, LOCKOUT_DURATION_SECS, MAX_FAILED_ATTEMPTS,
    MAX_RELAY_HOPS,
};

// =========================================================================
// 1. ArmMessage HMAC Verification & Role Binding
// =========================================================================

#[test]
fn test_arm_message_hmac_tamper_payload_fails() {
    let seed = [0x42u8; 32];
    let epoch = ArmEpoch::new("arm-anomaly-1", ArmRole::AnomalyDetection, seed);
    let key = epoch.current_key();

    let mut msg = ArmMessage {
        sender_arm_id: "arm-anomaly-1".to_string(),
        sender_role: ArmRole::AnomalyDetection,
        sender_generation: 1,
        target_arm_id: "arm-egress-1".to_string(),
        target_generation: 1,
        kind: MessageKind::Finding,
        correlation_id: "corr-001".to_string(),
        payload: "Initial pristine payload".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Worker,
        signature_hex: String::new(),
    };

    assert!(msg.sign(&key).is_ok());
    assert!(msg.verify_signature(&key));

    // Adversarial tampering: payload bit-flip / modification
    msg.payload = "Tampered payload injecting unauthorized command".to_string();
    assert!(
        !msg.verify_signature(&key),
        "Modified payload MUST fail HMAC verification"
    );

    // Empty payload
    msg.payload = String::new();
    assert!(
        !msg.verify_signature(&key),
        "Empty payload MUST fail HMAC verification"
    );
}

#[test]
fn test_arm_message_hmac_mismatched_epoch_fails() {
    let seed = [0x77u8; 32];
    let mut epoch = ArmEpoch::new("arm-fuzz-1", ArmRole::ContinuousOssFuzz, seed);
    let key_gen1 = epoch.current_key();

    let mut msg = ArmMessage {
        sender_arm_id: "arm-fuzz-1".to_string(),
        sender_role: ArmRole::ContinuousOssFuzz,
        sender_generation: 1,
        target_arm_id: "arm-research-1".to_string(),
        target_generation: 1,
        kind: MessageKind::Alert,
        correlation_id: "corr-gen-1".to_string(),
        payload: "Crash corpus detected".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Untrusted,
        signature_hex: String::new(),
    };

    assert!(msg.sign(&key_gen1).is_ok());
    assert!(msg.verify_signature(&key_gen1));

    // Sever and advance epoch (Gen 1 -> Gen 2)
    let gen2 = epoch.sever_and_regenerate();
    assert_eq!(gen2, 2);
    let key_gen2 = epoch.current_key();
    assert_ne!(key_gen1, key_gen2);

    // 1. Verifying old message with new epoch key MUST fail
    assert!(
        !msg.verify_signature(&key_gen2),
        "Stale epoch message verified with Gen 2 key MUST fail"
    );

    // 2. Adversary mutates sender_generation field in message to spoof current epoch
    msg.sender_generation = 2;
    assert!(
        !msg.verify_signature(&key_gen1),
        "Mismatched generation in signing content MUST fail against Gen 1 key"
    );
    assert!(
        !msg.verify_signature(&key_gen2),
        "Forged generation MUST fail against Gen 2 key because signature was under Gen 1"
    );
}

#[test]
fn test_arm_message_sender_role_binding_challenge() {
    let seed = [0x33u8; 32];
    let epoch_untrusted = ArmEpoch::new("arm-ingest-1", ArmRole::UntrustedDocIngest, seed);
    let key_untrusted = epoch_untrusted.current_key();

    let mut msg = ArmMessage {
        sender_arm_id: "arm-ingest-1".to_string(),
        sender_role: ArmRole::UntrustedDocIngest,
        sender_generation: 1,
        target_arm_id: "arm-worker-1".to_string(),
        target_generation: 1,
        kind: MessageKind::Finding,
        correlation_id: "corr-role-1".to_string(),
        payload: "Document contents".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Untrusted,
        signature_hex: String::new(),
    };

    assert!(msg.sign(&key_untrusted).is_ok());
    assert!(msg.verify_signature(&key_untrusted));

    // Attack Scenario: Adversary intercepts message and alters sender_role from
    // UntrustedDocIngest to AccountingLedgerWrite (PrivilegedSink) or AnomalyDetection (Worker).
    msg.sender_role = ArmRole::AccountingLedgerWrite;

    // If receiver re-derives the key based on the presented sender_role:
    // Derivation: SHA256(MasterSeed || ArmID || Epoch || Role)
    let derived_key_for_tampered_role = {
        let fake_epoch = ArmEpoch::new("arm-ingest-1", ArmRole::AccountingLedgerWrite, seed);
        fake_epoch.current_key()
    };
    assert_ne!(key_untrusted, derived_key_for_tampered_role);

    // Receiver deriving key from (arm_id, epoch, presented_role) correctly rejects the signature:
    assert!(
        !msg.verify_signature(&derived_key_for_tampered_role),
        "Key derived with tampered role MUST fail HMAC verification"
    );

    // POST-FIX VERIFICATION:
    // With self.sender_role bound into canonical_signing_content():
    let signing_content = msg.canonical_signing_content();
    assert!(
        signing_content.contains("AccountingLedgerWrite"),
        "REMEDIATION CONFIRMED: ArmMessage::canonical_signing_content() binds self.sender_role! Content is: {}",
        signing_content
    );
    // Because sender_role is bound into signing content, verify_signature with original key fails:
    let verified_under_stored_key = msg.verify_signature(&key_untrusted);
    assert!(
        !verified_under_stored_key,
        "Mutating sender_role MUST cause verify_signature to fail under stored key"
    );
}

#[test]
fn test_arm_message_corrupt_hex_and_constant_time() {
    let seed = [0x55u8; 32];
    let epoch = ArmEpoch::new("arm-sec-1", ArmRole::CedarPolicyEvaluation, seed);
    let key = epoch.current_key();

    let mut msg = ArmMessage {
        sender_arm_id: "arm-sec-1".to_string(),
        sender_role: ArmRole::CedarPolicyEvaluation,
        sender_generation: 1,
        target_arm_id: "arm-sentinel-1".to_string(),
        target_generation: 1,
        kind: MessageKind::Command,
        correlation_id: "corr-ct-1".to_string(),
        payload: "Authorize action".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::PrivilegedSink,
        signature_hex: String::new(),
    };

    assert!(msg.sign(&key).is_ok());

    // 1. Truncated hex
    msg.signature_hex = msg.signature_hex[..30].to_string();
    assert!(!msg.verify_signature(&key));

    // 2. Non-hex characters
    msg.signature_hex = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".to_string();
    assert!(!msg.verify_signature(&key));

    // 3. Single bit flip in signature
    msg.sign(&key).unwrap();
    let mut bytes = hex::decode(&msg.signature_hex).unwrap();
    bytes[0] ^= 0x01; // flip 1 bit
    msg.signature_hex = hex::encode(bytes);
    assert!(!msg.verify_signature(&key));
}

// =========================================================================
// 2. LAW1_STICKY_TAINT_VETO Exhaustive Matrix
// =========================================================================

#[test]
fn test_sticky_taint_veto_exhaustive_untrusted_to_privileged_sink() {
    let untrusted_roles = [
        ArmRole::UntrustedDocIngest,
        ArmRole::DifferentialProtocolAnalyzer,
        ArmRole::AutonomousProtocolResearch,
        ArmRole::ContinuousOssFuzz,
        ArmRole::TarpitDecoyDefense,
    ];

    let privileged_sink_roles = [
        ArmRole::AccountingLedgerWrite,
        ArmRole::KernelLevelSentinel,
        ArmRole::CedarPolicyEvaluation,
        ArmRole::PostQuantumAttestation,
    ];

    // Verify compile-time classification invariants
    for u in &untrusted_roles {
        assert_eq!(
            role_trust_tier(u),
            TrustTier::Untrusted,
            "{} must be classified as Untrusted",
            u
        );
    }
    for p in &privileged_sink_roles {
        assert_eq!(
            role_trust_tier(p),
            TrustTier::PrivilegedSink,
            "{} must be classified as PrivilegedSink",
            p
        );
        assert!(p.is_privileged_sink());
    }

    // Exhaustive 5 x 4 = 20 pairs: EVERY untrusted message to privileged sink MUST be vetoed
    for sender in &untrusted_roles {
        for recipient in &privileged_sink_roles {
            let msg = ArmMessage {
                sender_arm_id: sender.to_string(),
                sender_role: sender.clone(),
                sender_generation: 1,
                target_arm_id: recipient.to_string(),
                target_generation: 1,
                kind: MessageKind::Finding,
                correlation_id: format!("corr-{}-to-{}", sender, recipient),
                payload: "Attempting to access privileged sink".to_string(),
                provenance: vec![],
                taint_floor: TrustTier::Untrusted,
                signature_hex: String::new(),
            };

            let result = msg.validate_lateral_movement(recipient);
            assert!(
                result.is_err(),
                "LAW1_STICKY_TAINT_VETO must block {} from messaging {}",
                sender,
                recipient
            );
            let err_msg = result.unwrap_err();
            assert!(
                err_msg.contains("LAW1_STICKY_TAINT_VETO"),
                "Error message must cite LAW1_STICKY_TAINT_VETO, got: {}",
                err_msg
            );
        }
    }
}

#[test]
fn test_sticky_taint_permitted_paths() {
    // Untrusted to Worker role is permitted
    let msg_untrusted = ArmMessage {
        sender_arm_id: "doc-ingest".to_string(),
        sender_role: ArmRole::UntrustedDocIngest,
        sender_generation: 1,
        target_arm_id: "anomaly-det".to_string(),
        target_generation: 1,
        kind: MessageKind::Finding,
        correlation_id: "corr-perm-1".to_string(),
        payload: "Extracted tokens".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Untrusted,
        signature_hex: String::new(),
    };
    assert!(
        msg_untrusted.validate_lateral_movement(&ArmRole::AnomalyDetection).is_ok(),
        "Untrusted messaging Worker must be permitted"
    );

    // Worker to PrivilegedSink is permitted
    let msg_worker = ArmMessage {
        sender_arm_id: "anomaly-det".to_string(),
        sender_role: ArmRole::AnomalyDetection,
        sender_generation: 1,
        target_arm_id: "ledger-write".to_string(),
        target_generation: 1,
        kind: MessageKind::Alert,
        correlation_id: "corr-perm-2".to_string(),
        payload: "Confirmed incident record".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Worker,
        signature_hex: String::new(),
    };
    assert!(
        msg_worker.validate_lateral_movement(&ArmRole::AccountingLedgerWrite).is_ok(),
        "Worker messaging PrivilegedSink must be permitted"
    );
}

#[test]
fn test_provenance_relay_ceiling_exceeded() {
    let mut hops = Vec::new();
    for i in 0..MAX_RELAY_HOPS {
        hops.push(ProvenanceHop {
            arm_id: format!("relay-arm-{}", i),
            role: ArmRole::AnomalyDetection,
            generation: 1,
        });
    }

    let msg = ArmMessage {
        sender_arm_id: "relay-origin".to_string(),
        sender_role: ArmRole::AnomalyDetection,
        sender_generation: 1,
        target_arm_id: "target-worker".to_string(),
        target_generation: 1,
        kind: MessageKind::Alert,
        correlation_id: "corr-hop-limit".to_string(),
        payload: "Deep relay payload".to_string(),
        provenance: hops,
        taint_floor: TrustTier::Worker,
        signature_hex: String::new(),
    };

    let result = msg.validate_lateral_movement(&ArmRole::NetworkEgress);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("Relay hop ceiling exceeded"),
        "16 or more relay hops must trigger hop ceiling error"
    );
}

// =========================================================================
// 3. LockoutState 3-Strike Window & Master Token Bypass
// =========================================================================

#[test]
fn test_lockout_state_exact_3_strikes_and_4th_attempt_rejected() {
    let mut lockout = LockoutState::default();
    assert_eq!(lockout.max_failed_attempts, MAX_FAILED_ATTEMPTS); // 3
    assert_eq!(lockout.lockout_duration_secs, LOCKOUT_DURATION_SECS); // 300s
    assert!(!lockout.is_currently_locked());

    // Strike 1
    let r1 = lockout.record_failure(Some(9001));
    assert_eq!(
        r1,
        AuthResult::Failed {
            reason: "Invalid credentials".to_string(),
            attempts_remaining: 2,
        }
    );
    assert!(!lockout.is_currently_locked());
    assert_eq!(lockout.failed_attempts, 1);

    // Strike 2
    let r2 = lockout.record_failure(Some(9001));
    assert_eq!(
        r2,
        AuthResult::Failed {
            reason: "Invalid credentials".to_string(),
            attempts_remaining: 1,
        }
    );
    assert!(!lockout.is_currently_locked());
    assert_eq!(lockout.failed_attempts, 2);

    // Strike 3 - MUST trigger lockout
    let r3 = lockout.record_failure(Some(9001));
    match r3 {
        AuthResult::LockedOut { remaining_seconds, locked_until } => {
            assert_eq!(remaining_seconds, LOCKOUT_DURATION_SECS);
            assert!(locked_until > Utc::now());
        }
        other => panic!("Strike 3 must return LockedOut, got {:?}", other),
    }
    assert!(lockout.is_currently_locked());
    assert_eq!(lockout.failed_attempts, 3);
    assert_eq!(lockout.last_failed_caller_pid, Some(9001));

    // Strike 4 - attempted while locked: MUST fail with LockedOut
    let r4 = lockout.record_failure(Some(9001));
    assert!(
        matches!(r4, AuthResult::LockedOut { .. }),
        "4th attempt must be rejected as LockedOut"
    );
}

#[test]
fn test_authenticator_simulation_password_fails_during_lockout_but_master_token_succeeds() {
    // Model an OperatorAuthenticator using LockoutState
    let mut lockout = LockoutState::default();
    let valid_password = "SuperSecretOperatorPassword123!";
    let master_token = "CONFIRM RESTORE";

    // Trigger 3 strikes to lock the state
    for _ in 0..3 {
        lockout.record_failure(Some(4200));
    }
    assert!(lockout.is_currently_locked());

    // Authentication Gate Logic:
    let authenticate = |lockout: &mut LockoutState, creds: &OperatorCredentials| -> AuthResult {
        // Master token check: Direct bypass (bypasses lockout so admin is never locked out)
        if let Some(token) = &creds.auth_token {
            if constant_time_eq(token, master_token) {
                lockout.record_success();
                return AuthResult::Success {
                    operator: creds.operator_id.clone(),
                    method: AuthMethod::MasterTokenBypass,
                    authenticated_at: Utc::now(),
                };
            }
        }

        // If locked out, password cannot authenticate even if correct!
        if lockout.is_currently_locked() {
            let locked_until = lockout.locked_at.unwrap_or_else(Utc::now)
                + Duration::seconds(lockout.lockout_duration_secs as i64);
            return AuthResult::LockedOut {
                remaining_seconds: lockout.lockout_remaining_secs,
                locked_until,
            };
        }

        // Normal password verification
        if let Some(pass) = &creds.password {
            if constant_time_eq(pass, valid_password) {
                lockout.record_success();
                AuthResult::Success {
                    operator: creds.operator_id.clone(),
                    method: AuthMethod::EnvironmentPassword,
                    authenticated_at: Utc::now(),
                }
            } else {
                lockout.record_failure(creds.caller_pid)
            }
        } else {
            lockout.record_failure(creds.caller_pid)
        }
    };

    // 4th attempt: Operator submits VALID password while locked out
    let creds_with_valid_password = OperatorCredentials {
        operator_id: "analyst-1".to_string(),
        auth_token: None,
        password: Some(valid_password.to_string()),
        caller_pid: Some(4200),
        confirmation_phrase: None,
    };
    let res_password = authenticate(&mut lockout, &creds_with_valid_password);
    assert!(
        matches!(res_password, AuthResult::LockedOut { .. }),
        "Valid password MUST FAIL when interface is in lockout state"
    );
    assert!(lockout.is_currently_locked());

    // Master token attempt: Operator submits MASTER TOKEN while locked out
    let creds_with_master_token = OperatorCredentials {
        operator_id: "sec-admin".to_string(),
        auth_token: Some(master_token.to_string()),
        password: None,
        caller_pid: Some(4200),
        confirmation_phrase: Some("CONFIRM RESTORE".to_string()),
    };
    let res_master = authenticate(&mut lockout, &creds_with_master_token);
    match res_master {
        AuthResult::Success { method, .. } => {
            assert_eq!(
                method,
                AuthMethod::MasterTokenBypass,
                "Master token must authenticate via MasterTokenBypass"
            );
        }
        other => panic!("Master token must succeed during lockout, got {:?}", other),
    }

    // Master token successfully reset the lockout state
    assert!(!lockout.is_currently_locked());
    assert_eq!(lockout.failed_attempts, 0);
}

#[test]
fn test_lockout_auto_expiry_after_300s() {
    let mut lockout = LockoutState::default();

    // Trigger lockout
    for _ in 0..3 {
        lockout.record_failure(Some(5555));
    }
    assert!(lockout.is_currently_locked());

    // Simulate passage of 301 seconds by backdating locked_at
    lockout.locked_at = Some(Utc::now() - Duration::seconds(301));

    // is_currently_locked() must detect expiry and auto-reset
    assert!(
        !lockout.is_currently_locked(),
        "Lockout must auto-expire after 300 seconds"
    );
    assert_eq!(lockout.failed_attempts, 0);
    assert!(!lockout.is_locked);
}

// =========================================================================
// 4. KillChainHealthProbeReport Consecutive Probes & Anomaly Reset
// =========================================================================

#[test]
fn test_consecutive_healthy_probes_progression_and_anomaly_reset() {
    let required_probes = 3;
    let mut consecutive_healthy = 0u32;

    // Probe 1: Healthy
    consecutive_healthy += 1;
    let rep1 = KillChainHealthProbeReport {
        timestamp: Utc::now(),
        process_tree_integrity_ok: true,
        total_processes_scanned: 180,
        critical_os_anchors_verified: 10,
        frozen_pids_monitored: 1,
        suspicious_unfrozen_processes: vec![],
        orphaned_malicious_children: vec![],
        detected_anomalies: vec![],
        consecutive_healthy_probes: consecutive_healthy,
        required_healthy_probes: required_probes,
        eligible_for_early_rollback: consecutive_healthy >= required_probes,
        rollback_watchdog_max_secs: 1800,
        probe_interval_secs: 60,
        probe_hash_blake3: String::new(),
        summary: "Clean probe 1".to_string(),
    };
    assert_eq!(rep1.consecutive_healthy_probes, 1);
    assert!(!rep1.eligible_for_early_rollback);

    // Probe 2: Healthy
    consecutive_healthy += 1;
    let rep2 = KillChainHealthProbeReport {
        timestamp: Utc::now(),
        process_tree_integrity_ok: true,
        total_processes_scanned: 181,
        critical_os_anchors_verified: 10,
        frozen_pids_monitored: 1,
        suspicious_unfrozen_processes: vec![],
        orphaned_malicious_children: vec![],
        detected_anomalies: vec![],
        consecutive_healthy_probes: consecutive_healthy,
        required_healthy_probes: required_probes,
        eligible_for_early_rollback: consecutive_healthy >= required_probes,
        rollback_watchdog_max_secs: 1800,
        probe_interval_secs: 60,
        probe_hash_blake3: String::new(),
        summary: "Clean probe 2".to_string(),
    };
    assert_eq!(rep2.consecutive_healthy_probes, 2);
    assert!(!rep2.eligible_for_early_rollback);

    // Probe 3: ANOMALY DETECTED -> Single anomaly MUST reset consecutive count to 0!
    let anomaly = HealthProbeAnomaly {
        anomaly_id: "anom-001".to_string(),
        kind: ProbeAnomalyKind::UnfrozenSuspiciousProcess,
        offending_pid: Some(6666),
        process_name: Some("mimikatz.exe".to_string()),
        command_line: Some("mimikatz.exe \"sekurlsa::logonpasswords\"".to_string()),
        description: "Suspicious uncontained credential dumper detected".to_string(),
    };
    let is_healthy = false;
    if is_healthy {
        consecutive_healthy += 1;
    } else {
        consecutive_healthy = 0; // RESET
    }

    let rep3 = KillChainHealthProbeReport {
        timestamp: Utc::now(),
        process_tree_integrity_ok: false,
        total_processes_scanned: 182,
        critical_os_anchors_verified: 10,
        frozen_pids_monitored: 1,
        suspicious_unfrozen_processes: vec!["mimikatz.exe".to_string()],
        orphaned_malicious_children: vec![],
        detected_anomalies: vec![anomaly],
        consecutive_healthy_probes: consecutive_healthy,
        required_healthy_probes: required_probes,
        eligible_for_early_rollback: consecutive_healthy >= required_probes,
        rollback_watchdog_max_secs: 1800,
        probe_interval_secs: 60,
        probe_hash_blake3: String::new(),
        summary: "Anomaly detected; reset counter".to_string(),
    };
    assert_eq!(rep3.consecutive_healthy_probes, 0, "Anomaly MUST reset count to 0");
    assert!(!rep3.eligible_for_early_rollback);

    // Probe 4 & 5: Healthy again
    consecutive_healthy += 1; // 1
    consecutive_healthy += 1; // 2
    assert_eq!(consecutive_healthy, 2);

    // Probe 6: Reaches exactly 3 consecutive healthy probes -> eligible for early rollback!
    consecutive_healthy += 1; // 3
    let rep6 = KillChainHealthProbeReport {
        timestamp: Utc::now(),
        process_tree_integrity_ok: true,
        total_processes_scanned: 180,
        critical_os_anchors_verified: 10,
        frozen_pids_monitored: 1,
        suspicious_unfrozen_processes: vec![],
        orphaned_malicious_children: vec![],
        detected_anomalies: vec![],
        consecutive_healthy_probes: consecutive_healthy,
        required_healthy_probes: required_probes,
        eligible_for_early_rollback: consecutive_healthy >= required_probes,
        rollback_watchdog_max_secs: 1800,
        probe_interval_secs: 60,
        probe_hash_blake3: String::new(),
        summary: "Third consecutive healthy probe attained".to_string(),
    };
    assert_eq!(rep6.consecutive_healthy_probes, 3);
    assert!(
        rep6.eligible_for_early_rollback,
        "Exactly 3 consecutive clean probes MUST qualify for early rollback"
    );
}

#[test]
fn test_killchain_health_probe_hash_tamper_resistance() {
    let now = Utc::now();
    let original_hash =
        KillChainHealthProbeReport::compute_hash(&now, true, 200, 12, 3, "Baseline status");

    // 1. Mutate status
    let h_mut_status =
        KillChainHealthProbeReport::compute_hash(&now, false, 200, 12, 3, "Baseline status");
    assert_ne!(original_hash, h_mut_status);

    // 2. Mutate scanned processes
    let h_mut_scanned =
        KillChainHealthProbeReport::compute_hash(&now, true, 201, 12, 3, "Baseline status");
    assert_ne!(original_hash, h_mut_scanned);

    // 3. Mutate consecutive count
    let h_mut_consecutive =
        KillChainHealthProbeReport::compute_hash(&now, true, 200, 12, 2, "Baseline status");
    assert_ne!(original_hash, h_mut_consecutive);

    // 4. Mutate summary
    let h_mut_summary =
        KillChainHealthProbeReport::compute_hash(&now, true, 200, 12, 3, "Modified summary");
    assert_ne!(original_hash, h_mut_summary);
}

// =========================================================================
// 5. ExecutionStep BLAKE3 Merkle Chain Link Tamper Resistance
// =========================================================================

#[test]
fn test_execution_step_merkle_chain_tamper_resistance() {
    let mut state = KillSwitchGraphState::new("incident-merkle-test", OrchestratorMode::Autonomous);

    // 5-step lifecycle
    state.record_execution_step(
        GraphNodeId::Monitoring,
        "in-0",
        "out-0",
        10,
        serde_json::json!({"action": "monitoring"}),
    );
    state.record_execution_step(
        GraphNodeId::IngestingSignals,
        "in-1",
        "out-1",
        15,
        serde_json::json!({"signals": 4}),
    );
    state.record_execution_step(
        GraphNodeId::CorrelatingEdrAndOctopus,
        "in-2",
        "out-2",
        30,
        serde_json::json!({"score": 0.98}),
    );
    state.record_execution_step(
        GraphNodeId::AdjudicatingZeroFalsePositive,
        "in-3",
        "out-3",
        25,
        serde_json::json!({"adjudication": "APPROVED"}),
    );
    state.record_execution_step(
        GraphNodeId::EngagingContainment,
        "in-4",
        "out-4",
        50,
        serde_json::json!({"action": "ISOLATE"}),
    );

    assert_eq!(state.execution_trace.len(), 5);
    assert!(state.verify_trace_chain(), "Initial trace chain must be 100% valid");

    // Attack 1: Mutate prev_chain_hash on step 3
    let mut tampered_state1 = state.clone();
    tampered_state1.execution_trace[3].prev_chain_hash =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    assert!(
        !tampered_state1.verify_trace_chain(),
        "Tampering with prev_chain_hash MUST break the Merkle chain"
    );

    // Attack 2: Mutate step_index on step 2
    let mut tampered_state2 = state.clone();
    tampered_state2.execution_trace[2].step_index = 99;
    assert!(
        !tampered_state2.verify_trace_chain(),
        "Tampering with step_index MUST break trace chain validation"
    );

    // Attack 3: Mutate node_id on step 1
    let mut tampered_state3 = state.clone();
    tampered_state3.execution_trace[1].node_id = GraphNodeId::OptionalOllamaReasoning;
    assert!(
        !tampered_state3.verify_trace_chain(),
        "Tampering with node_id MUST invalidate recomputed chain hash"
    );

    // Attack 4: Mutate input_digest or output_digest
    let mut tampered_state4 = state.clone();
    tampered_state4.execution_trace[4].output_digest = "forged-digest".to_string();
    assert!(
        !tampered_state4.verify_trace_chain(),
        "Tampering with output_digest MUST invalidate chain link"
    );

    // Attack 5: Swap two adjacent steps
    let mut tampered_state5 = state.clone();
    tampered_state5.execution_trace.swap(1, 2);
    assert!(
        !tampered_state5.verify_trace_chain(),
        "Swapping adjacent execution steps MUST break trace chain verification"
    );
}

#[test]
fn test_execution_step_verify_link_direct() {
    let prev_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let step = ExecutionStep::new(
        prev_hash,
        0,
        "2026-10-26T14:00:00Z".to_string(),
        GraphNodeId::Monitoring,
        "input-hash".to_string(),
        "output-hash".to_string(),
        10,
        serde_json::json!({}),
    );

    assert!(step.verify_link(prev_hash));

    // Wrong previous hash returns false
    assert!(!step.verify_link("2222222222222222222222222222222222222222222222222222222222222222"));

    // Tampered chain_hash returns false
    let mut tampered_step = step.clone();
    tampered_step.chain_hash = "3333333333333333333333333333333333333333333333333333333333333333".to_string();
    assert!(!tampered_step.verify_link(prev_hash));
}
