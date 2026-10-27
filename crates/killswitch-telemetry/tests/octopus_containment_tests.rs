//! Integration tests for Octopus Arm Containment Ring (Feature 19)

use killswitch_telemetry::octopus::arm_ring::{ArmContainmentRing, ArmRingRegistry};
use killswitch_types::{ArmRole, KillSwitchError};

#[tokio::test]
async fn test_t1_f19_01_monotonic_generation_epoch_advancement() {
    let master_seed = [0x42u8; 32];
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, &master_seed);

    assert_eq!(ring.current_generation(), 1);
    assert!(ring.validate_epoch(1).await.is_ok());

    // Sever and regenerate -> advances Gen 1 -> Gen 2
    let next_gen = ring.sever_and_regenerate("Suspicious lateral scan").await.unwrap();
    assert_eq!(next_gen, 2);
    assert_eq!(ring.current_generation(), 2);

    // Presenting stale Gen 1 must return StaleGenerationEpoch error
    let stale_res = ring.validate_epoch(1).await;
    assert!(matches!(
        stale_res,
        Err(KillSwitchError::StaleGenerationEpoch { arm_id: 0, expected: 2, presented: 1 })
    ));

    // Presenting valid Gen 2 succeeds
    assert!(ring.validate_epoch(2).await.is_ok());
}

#[tokio::test]
async fn test_t1_f19_02_surgical_autotomy_and_quarantine() {
    let master_seed = [0x55u8; 32];
    let ring = ArmContainmentRing::new(1, ArmRole::AccountingLedgerWrite, 1, &master_seed);

    ring.sever("Anomalous privilege escalation attempt").await.unwrap();

    // While severed, validation returns ArmQuarantined error
    let res = ring.validate_epoch(1).await;
    assert!(matches!(
        res,
        Err(KillSwitchError::ArmQuarantined { arm_id: 1, .. })
    ));
}

#[tokio::test]
async fn test_t1_f19_03_capability_token_constant_time_verification() {
    let master_seed = [0x77u8; 32];
    let ring = ArmContainmentRing::new(0, ArmRole::UntrustedDocIngest, 1, &master_seed);

    let token = ring
        .issue_capability("doc_extractor", "s3://invoices/", 60)
        .await
        .unwrap();

    // Valid token passes verification
    assert!(ring.verify_capability(&token).await.is_ok());

    // Tampered bearer agent fails
    let mut bad_bearer = token.clone();
    bad_bearer.bearer_agent = "rogue-agent-99".to_string();
    assert!(ring.verify_capability(&bad_bearer).await.is_err());

    // Tampered tool fails
    let mut bad_tool = token.clone();
    bad_tool.permitted_tool = "rm_rf_root".to_string();
    assert!(ring.verify_capability(&bad_tool).await.is_err());

    // Tampered signature fails HMAC check
    let mut bad_sig = token.clone();
    bad_sig.signature_hex = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let sig_res = ring.verify_capability(&bad_sig).await;
    assert!(matches!(
        sig_res,
        Err(KillSwitchError::MeshHmacVerificationFailed { arm_id: 0 })
    ));
}

#[tokio::test]
async fn test_t1_f19_04_fail_closed_all_18_arm_roles() {
    let all_roles = [
        ArmRole::UntrustedDocIngest,
        ArmRole::AccountingLedgerWrite,
        ArmRole::NetworkEgress,
        ArmRole::OutboundNotification,
        ArmRole::TarpitDecoyDefense,
        ArmRole::KernelLevelSentinel,
        ArmRole::CedarPolicyEvaluation,
        ArmRole::AtlasThreatIntelligence,
        ArmRole::AnomalyDetection,
        ArmRole::VulnerabilityResearch,
        ArmRole::ContinuousOssFuzz,
        ArmRole::ContinuousOsvScanner,
        ArmRole::DifferentialProtocolAnalyzer,
        ArmRole::AutonomousProtocolResearch,
        ArmRole::PostQuantumAttestation,
        ArmRole::EvolutionaryOptimizer,
        ArmRole::DreamRsiOptimizer,
        ArmRole::RecursiveHarnessOptimizer,
    ];

    assert_eq!(all_roles.len(), 18);

    for role in &all_roles {
        let (tools, prefixes) = ArmContainmentRing::default_permissions_for_role(role);
        assert!(!tools.is_empty(), "Role {:?} must have non-empty tools", role);
        assert!(!prefixes.is_empty(), "Role {:?} must have non-empty prefixes", role);
    }
}

#[tokio::test]
async fn test_t1_f19_05_registry_and_watchout_signals() {
    let master_seed = [0x88u8; 32];
    let registry = ArmRingRegistry::new(&master_seed);

    let ring0 = registry.get_ring(0).await.expect("Arm 0 must exist");
    assert_eq!(ring0.current_generation(), 1);

    let new_gen = registry
        .sever_and_regenerate_arm(0, "Integrity invariant breach")
        .await
        .unwrap();
    assert_eq!(new_gen, 2);

    let signals = registry.active_watchout_signals().await;
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].severed_arm_id, 0);
    assert_eq!(signals[0].revoked_generation, 1);
    assert_eq!(signals[0].new_generation, 2);
}
