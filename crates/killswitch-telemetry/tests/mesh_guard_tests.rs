//! Integration tests for MeshGuard, Homological Boundary Audit, and Sticky Taint Veto (Feature 20)

use killswitch_telemetry::octopus::mesh_guard::{HomologicalBoundaryAuditor, MeshGuard};
use killswitch_types::{ArmMessage, ArmRole, KillSwitchError, MessageKind, ProvenanceHop, TrustTier};

#[tokio::test]
async fn test_t1_f20_01_homological_boundary_exactness_2_simplex() {
    // Valid relay chain: Worker -> Worker -> Worker
    let chain = [
        ArmRole::AnomalyDetection,
        ArmRole::VulnerabilityResearch,
        ArmRole::OutboundNotification,
    ];

    let report = HomologicalBoundaryAuditor::audit_role_chain(&chain);
    assert!(report.allowed);
    assert!(report.boundary_squared_zero);
    assert_eq!(report.coboundary_residue, 0);
    assert!(!report.proxy_laundering_detected);
}

#[tokio::test]
async fn test_t1_f20_02_proxy_laundering_veto() {
    // Laundering attempt: UntrustedDocIngest -> AnomalyDetection (Worker) -> AccountingLedgerWrite (PrivilegedSink)
    let laundering_chain = [
        ArmRole::UntrustedDocIngest,
        ArmRole::AnomalyDetection,
        ArmRole::AccountingLedgerWrite,
    ];

    let report = HomologicalBoundaryAuditor::audit_role_chain(&laundering_chain);
    assert!(!report.allowed);
    assert!(report.proxy_laundering_detected);
    assert!(report.reason.contains("LAW1_PROXY_LAUNDERING_VETO"));
}

#[tokio::test]
async fn test_t1_f20_03_direct_boundary_veto() {
    // Direct attempt: UntrustedDocIngest -> AccountingLedgerWrite
    let direct_chain = [
        ArmRole::UntrustedDocIngest,
        ArmRole::AccountingLedgerWrite,
    ];

    let report = HomologicalBoundaryAuditor::audit_role_chain(&direct_chain);
    assert!(!report.allowed);
    assert!(report.reason.contains("LAW1_DIRECT_BOUNDARY_VETO"));
}

#[tokio::test]
async fn test_t1_f20_04_mesh_guard_constant_time_signature_and_route() {
    let guard = MeshGuard::new();
    let sender_key = [0xAAu8; 32];

    guard.allow_route("arm-0", "arm-1", Some(MessageKind::Finding)).await;

    let mut msg = ArmMessage {
        sender_arm_id: "arm-0".to_string(),
        sender_role: ArmRole::AnomalyDetection,
        sender_generation: 1,
        target_arm_id: "arm-1".to_string(),
        target_generation: 1,
        kind: MessageKind::Finding,
        correlation_id: "corr-12345".to_string(),
        payload: "{\"metric\":\"anomaly_detected\"}".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Worker,
        signature_hex: String::new(),
    };

    msg.sign(&sender_key).unwrap();

    // Valid message passes validation
    let valid_res = guard
        .validate_message(&msg, &ArmRole::OutboundNotification, &sender_key)
        .await;
    assert!(valid_res.is_ok());

    // Tampered payload fails HMAC verification in constant time
    let mut tampered_msg = msg.clone();
    tampered_msg.payload = "{\"metric\":\"faked_signature\"}".to_string();
    let tamper_res = guard
        .validate_message(&tampered_msg, &ArmRole::OutboundNotification, &sender_key)
        .await;
    assert!(matches!(
        tamper_res,
        Err(KillSwitchError::MeshHmacVerificationFailed { .. })
    ));
}

#[tokio::test]
async fn test_t1_f20_05_sticky_taint_veto_in_mesh_guard() {
    let guard = MeshGuard::new();
    let sender_key = [0xBBu8; 32];

    guard.allow_route("arm-doc", "arm-ledger", None).await;

    // Message carries Untrusted taint floor from origin
    let mut msg = ArmMessage {
        sender_arm_id: "arm-doc".to_string(),
        sender_role: ArmRole::AnomalyDetection, // Worker acting as proxy
        sender_generation: 1,
        target_arm_id: "arm-ledger".to_string(),
        target_generation: 1,
        kind: MessageKind::Command,
        correlation_id: "corr-taint-99".to_string(),
        payload: "Write ledger entry".to_string(),
        provenance: vec![ProvenanceHop {
            arm_id: "arm-untrusted".to_string(),
            role: ArmRole::UntrustedDocIngest,
            generation: 1,
        }],
        taint_floor: TrustTier::Untrusted,
        signature_hex: String::new(),
    };

    msg.sign(&sender_key).unwrap();

    let res = guard
        .validate_message(&msg, &ArmRole::AccountingLedgerWrite, &sender_key)
        .await;

    // Must be blocked by lateral sink violation / sticky taint
    assert!(matches!(
        res,
        Err(KillSwitchError::LateralSinkViolation { .. })
    ));
}
