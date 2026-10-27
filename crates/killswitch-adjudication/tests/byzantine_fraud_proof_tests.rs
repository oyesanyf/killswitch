use killswitch_adjudication::byzantine::{
    build_kill_switch_fraud_proof, veto_peer_kill_switch_candidate, PEER_SLASHED_STAKE,
};
use killswitch_adjudication::inventory::register_protected_binary_hash;
use killswitch_types::adjudication::{
    ByzantineKillSwitchFraudProof, VetoReason, FRAUD_PROOF_SEAL_CONTEXT,
};

#[test]
fn test_fraud_proof_canonical_seal_and_verification() {
    assert_eq!(FRAUD_PROOF_SEAL_CONTEXT, b"KILL_SWITCH_FRAUD_PROOF_V2|");
    assert_eq!(PEER_SLASHED_STAKE, 100.0);

    let proof = build_kill_switch_fraud_proof(
        "rogue-peer-007",
        "svchost.exe",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Illicit peer proposal targeting protected OS binary",
    );

    assert_eq!(proof.accused_peer_id, "rogue-peer-007");
    assert_eq!(proof.proc_name, "svchost.exe");
    assert!(proof.verify_seal());
}

#[test]
fn test_fraud_proof_tamper_detection_on_all_fields() {
    let mut proof = build_kill_switch_fraud_proof(
        "rogue-peer-007",
        "svchost.exe",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Illicit peer proposal targeting protected OS binary",
    );

    assert!(proof.verify_seal());

    // 1. Tamper with peer_id
    let original_peer = proof.peer_id.clone();
    proof.peer_id = "tampered-node".to_string();
    assert!(!proof.verify_seal());
    proof.peer_id = original_peer;
    assert!(proof.verify_seal());

    // 2. Tamper with accused_peer_id
    proof.accused_peer_id = "innocent-peer".to_string();
    assert!(!proof.verify_seal());
    proof.accused_peer_id = "rogue-peer-007".to_string();
    assert!(proof.verify_seal());

    // 3. Tamper with target_binary_hash
    proof.target_binary_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(!proof.verify_seal());
    proof.target_binary_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
    assert!(proof.verify_seal());

    // 4. Tamper with proc_name
    proof.proc_name = "explorer.exe".to_string();
    assert!(!proof.verify_seal());
    proof.proc_name = "svchost.exe".to_string();
    assert!(proof.verify_seal());

    // 5. Tamper with fraud_reason
    proof.fraud_reason = "Changed reason".to_string();
    assert!(!proof.verify_seal());
    proof.fraud_reason = "Illicit peer proposal targeting protected OS binary".to_string();
    assert!(proof.verify_seal());

    // 6. Tamper with timestamp
    proof.timestamp = "2020-01-01T00:00:00Z".to_string();
    assert!(!proof.verify_seal());
}

#[test]
fn test_fraud_proof_keyed_seal_verification() {
    let key = [42u8; 32];
    let timestamp = "2026-10-26T12:00:00Z";
    let seal = ByzantineKillSwitchFraudProof::compute_keyed_seal(
        &key,
        "node-local",
        "peer-rogue",
        "hash123",
        "cargo.exe",
        "Protected developer tool",
        timestamp,
    );

    let proof = ByzantineKillSwitchFraudProof {
        peer_id: "node-local".to_string(),
        accused_peer_id: "peer-rogue".to_string(),
        target_binary_hash: "hash123".to_string(),
        proc_name: "cargo.exe".to_string(),
        fraud_reason: "Protected developer tool".to_string(),
        proof_seal: seal,
        timestamp: timestamp.to_string(),
    };

    assert!(proof.verify_keyed_seal(&key));

    // Wrong key fails
    let wrong_key = [99u8; 32];
    assert!(!proof.verify_keyed_seal(&wrong_key));
}

#[test]
fn test_veto_peer_targeting_protected_local_hash() {
    let hash = "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678";
    register_protected_binary_hash(hash);

    let result = veto_peer_kill_switch_candidate(
        Some("byzantine-peer-1"),
        Some(8888),
        Some("internal_worker.exe"),
        Some(hash),
        None,
        Some("Rogue isolation request"),
    );

    assert!(result.is_some());
    let (reason, proof) = result.unwrap();
    assert_eq!(reason, VetoReason::ProtectedBinaryHash);
    assert!(proof.verify_seal());
    assert_eq!(proof.accused_peer_id, "byzantine-peer-1");
    assert_eq!(proof.target_binary_hash, hash);
}

#[test]
fn test_veto_peer_targeting_critical_system_pid() {
    let result = veto_peer_kill_switch_candidate(
        Some("byzantine-peer-2"),
        Some(4),
        Some("system"),
        None,
        None,
        Some("Kernel isolation proposal"),
    );

    assert!(result.is_some());
    let (reason, proof) = result.unwrap();
    assert_eq!(reason, VetoReason::CriticalSystemPid);
    assert!(proof.verify_seal());
    assert_eq!(proof.accused_peer_id, "byzantine-peer-2");
}

#[test]
fn test_veto_peer_targeting_poisoned_yara_rule() {
    let poisoned_rule = r#"
        rule IllicitFreezeSvchost {
            meta:
                author = "rogue-agent"
            strings:
                $s = "svchost.exe"
            condition:
                $s
        }
    "#;

    let result = veto_peer_kill_switch_candidate(
        Some("byzantine-peer-3"),
        None,
        None,
        None,
        Some(poisoned_rule),
        Some("Poisoned rule match"),
    );

    assert!(result.is_some());
    let (reason, proof) = result.unwrap();
    assert_eq!(reason, VetoReason::PoisonedYaraRuleTarget);
    assert!(proof.verify_seal());
    assert_eq!(proof.accused_peer_id, "byzantine-peer-3");
    assert!(proof.fraud_reason.contains("POISONED_YARA_TARGET_VETO"));
}

#[test]
fn test_legitimate_threat_candidate_is_not_vetoed() {
    let benign_rule = r#"
        rule MimikatzArtifact {
            strings:
                $m = "sekurlsa::logonpasswords"
            condition:
                $m
        }
    "#;

    let result = veto_peer_kill_switch_candidate(
        Some("good-peer"),
        Some(9999),
        Some("mimikatz.exe"),
        Some("fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe"),
        Some(benign_rule),
        Some("Active credential theft"),
    );

    // Legitimate threat targeting untrusted PID and non-protected binary is NOT vetoed
    assert!(result.is_none());
}
