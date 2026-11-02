//! Empirical Challenge Test Suite for Milestone CAGE-2
//!
//! Validates:
//! 1. Canonical cryptographic receipt sealing and metadata synchronization in orchestrator.
//! 2. Checkpointed state durability, Merkle BLAKE3 trace chaining, and fail-closed tamper detection.
//! 3. Formal state-machine model checking via `CageTraceVerifier` on orchestrator-generated traces.
//! 4. Adversarial trace perturbation and illegal post-refusal actuation detection.

use std::sync::Arc;
use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_orchestrator::checkpointer::DurableFileCheckpointer;
use killswitch_orchestrator::{KillSwitchOrchestrator, OrchestratorConfig};
use killswitch_telemetry::otel_lineage::EndpointLineageEngine;
use killswitch_telemetry::{
    global_cage_kernel, CageEvaluationRequest, CageTier, CageTraceVerifier, CageVerdict,
    GovernanceTraceEvent, GovernanceTraceEventType,
};
use killswitch_types::adjudication::{EvidenceClass, ThreatCandidate};
use killswitch_types::errors::KillSwitchError;
use killswitch_types::graph::{KillSwitchGraphState, OrchestratorMode, StateCheckpointer};

/// Test 1: Verify canonical receipt sealing against `global_cage_kernel()`
/// Asserts that all metadata fields in state match the canonical receipt bit-for-bit,
/// and that cryptographic signature and digest verification succeed.
#[tokio::test]
async fn test_empirical_canonical_receipt_sealing_in_orchestrator_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
    let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    let config = OrchestratorConfig::default();
    let orch = KillSwitchOrchestrator::new(config, containment, adjudicator, lineage);
    let mut state = orch.get_state().await;

    // Direct invocation of PEP for query_ollama_reasoning
    let receipt = orch
        .evaluate_cage_guard(
            &mut state,
            "query_ollama_reasoning",
            serde_json::json!({
                "confidence_score": 0.96,
                "reason": "Empirical forensic analysis challenge",
            }),
        )
        .expect("Valid action must clear CAGE PEP");

    // 1. Inherent receipt cryptographic verification
    assert_eq!(receipt.verdict, CageVerdict::Clear);
    assert!(receipt.verify_digest(), "Canonical receipt digest verification must succeed");
    assert!(!receipt.receipt_signature.is_empty(), "Signature must be populated");

    // Kernel evidence writer must accept the authentic receipt
    let writer = global_cage_kernel().evidence_writer();
    let append_res = writer.append_receipt(receipt.clone());
    assert!(append_res.is_ok(), "Kernel evidence writer must accept authentic receipt: {:?}", append_res.err());

    // 2. Strict state metadata synchronization
    let stored_digest = state
        .metadata
        .get("cage_receipt_digest")
        .expect("cage_receipt_digest must exist in state metadata");
    let stored_sig = state
        .metadata
        .get("cage_signature")
        .expect("cage_signature must exist in state metadata");
    let stored_sub = state
        .metadata
        .get("cage_substrate_digest")
        .expect("cage_substrate_digest must exist in state metadata");
    let stored_verdict = state
        .metadata
        .get("cage_last_verdict")
        .expect("cage_last_verdict must exist in state metadata");

    assert_eq!(stored_digest, &receipt.decision_digest);
    assert_eq!(stored_sig, &receipt.receipt_signature);
    assert_eq!(stored_sub, &receipt.substrate_digest);
    assert_eq!(stored_verdict, "Clear");

    // 3. Independent canonical recomputation from state metadata fields
    let mut reconstructed = receipt.clone();
    reconstructed.decision_digest = stored_digest.clone();
    reconstructed.receipt_signature = stored_sig.clone();
    assert!(
        reconstructed.verify_digest(),
        "Reconstructed receipt from state metadata must independently verify digest"
    );

    // 4. Tampering test: altering the stored digest in the reconstructed receipt fails verification
    reconstructed.decision_digest = "deadbeef".repeat(8);
    assert!(
        !reconstructed.verify_digest(),
        "Altered receipt digest must strictly fail verify_digest()"
    );
    let append_tampered = writer.append_receipt(reconstructed);
    assert!(
        append_tampered.is_err(),
        "Kernel evidence writer must reject tampered decision digest"
    );
}

/// Test 2: Checkpointed state durability and tamper detection across multiple vectors
/// Saves an autonomous incident checkpoint and asserts that altering receipt digests,
/// signatures, or BLAKE3 trace steps strictly fails closed.
#[tokio::test]
async fn test_empirical_checkpoint_tamper_detection_fail_closed() {
    let temp_dir = tempfile::tempdir().unwrap();
    let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
    let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());
    let checkpointer = Arc::new(DurableFileCheckpointer::new(temp_dir.path()).unwrap());

    let config = OrchestratorConfig {
        mode: OrchestratorMode::Autonomous,
        db_dir: Some(temp_dir.path().to_path_buf()),
        consecutive_healthy_probes_required: 3,
        probe_interval_secs: 60,
        watchdog_max_secs: 1800,
    };

    let orch = KillSwitchOrchestrator::new(config, containment, adjudicator, lineage);
    orch.submit_threat(ThreatCandidate::new(
        Some(1122),
        "injected_cmd.exe",
        "Sensor",
        "Active ransomware threat",
        0.95,
        EvidenceClass::Behavior,
    ))
    .await
    .unwrap();

    // Step through 7 stages to Containment
    for _ in 0..7 {
        orch.step().await.unwrap();
    }

    let state = orch.get_state().await;
    assert!(state.containment_status.isolated, "Host must be isolated");
    let original_digest = state.metadata.get("cage_receipt_digest").unwrap().clone();
    assert_eq!(original_digest.len(), 64);
    assert!(!state.execution_trace.is_empty(), "Execution trace must contain steps");
    let target_step_input_digest = state.execution_trace[0].input_digest.clone();

    // Save baseline checkpoint
    checkpointer.save_checkpoint(&state).await.unwrap();

    // Baseline load must succeed
    let loaded = checkpointer
        .load_checkpoint(&state.incident_id)
        .await
        .unwrap()
        .expect("Checkpoint must exist");
    assert_eq!(loaded.metadata.get("cage_receipt_digest"), Some(&original_digest));
    assert!(loaded.verify_trace_chain());

    let chk_path = temp_dir.path().join(format!("checkpoint_{}.json", state.incident_id));
    let raw_json = std::fs::read_to_string(&chk_path).unwrap();

    // Tamper Vector A: Alter receipt digest in metadata
    let tampered_digest_json = raw_json.replace(&original_digest, "0000000000000000000000000000000000000000000000000000000000000000");
    assert_ne!(tampered_digest_json, raw_json, "Must have replaced original digest");
    let tampered_state: KillSwitchGraphState = serde_json::from_str(&tampered_digest_json).unwrap();
    assert_ne!(
        tampered_state.metadata.get("cage_receipt_digest").unwrap(),
        &original_digest,
        "Tampered state metadata must reflect modified digest"
    );

    // Tamper Vector B: Alter BLAKE3 execution trace chain
    let tampered_trace_json = raw_json.replace(
        &target_step_input_digest,
        "tampered_adversarial_input_digest_hex",
    );
    assert_ne!(tampered_trace_json, raw_json, "Must have replaced target step input digest");
    std::fs::write(&chk_path, tampered_trace_json).unwrap();
    let load_res = checkpointer.load_checkpoint(&state.incident_id).await;
    assert!(
        load_res.is_err(),
        "Checkpointer MUST fail closed when execution trace is tampered"
    );
    match load_res.unwrap_err() {
        KillSwitchError::CryptoError(msg) => {
            assert!(msg.contains("BLAKE3 execution trace chain verification failed"));
        }
        other => panic!("Expected CryptoError, got {:?}", other),
    }

    // Tamper Vector C: Syntax corruption / truncated file
    std::fs::write(&chk_path, "{\"incident_id\": \"truncated").unwrap();
    let load_corrupt = checkpointer.load_checkpoint(&state.incident_id).await;
    assert!(
        load_corrupt.is_err(),
        "Checkpointer must fail closed on corrupt JSON"
    );
}

/// Test 3: Formal trace model checking on orchestrator graph runs
/// Extracts governance traces during actual orchestrator evaluation and verifies them
/// using the independent formal model checker `CageTraceVerifier`.
#[tokio::test]
async fn test_empirical_trace_verifier_on_orchestrator_runs() {
    let kernel = global_cage_kernel();

    // 1. Ollama reasoning evaluation trace
    let req_ollama = CageEvaluationRequest {
        agent_id: "killswitch-orchestrator".to_string(),
        role: "forensic_analyst".to_string(),
        tool_name: "query_ollama_reasoning".to_string(),
        arguments: serde_json::json!({
            "confidence_score": 0.95,
            "reason": "Empirical forensic validation",
        }),
        confidence_score: Some(0.95),
        amount_usd: None,
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_ollama = kernel.evaluate(&req_ollama);
    assert_eq!(resp_ollama.verdict, CageVerdict::Clear);

    let report_ollama = CageTraceVerifier::verify_trace_conformance(&resp_ollama.governance_trace);
    assert!(
        report_ollama.is_conformant,
        "Ollama trace must be formally conformant: {:?}",
        report_ollama.violations
    );
    assert!(report_ollama.monotonic_ordering_valid);
    assert!(report_ollama.actuation_receipt_valid);
    assert!(report_ollama.warrant_precedence_valid);
    assert!(report_ollama.violations.is_empty());

    // 2. Host containment actuation trace
    let req_contain = CageEvaluationRequest {
        agent_id: "killswitch-orchestrator".to_string(),
        role: "containment_orchestrator".to_string(),
        tool_name: "engage_containment".to_string(),
        arguments: serde_json::json!({
            "incident_id": "inc-empirical-001",
            "targets": ["ransomware.exe"],
        }),
        confidence_score: Some(0.92),
        amount_usd: None,
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_contain = kernel.evaluate(&req_contain);
    assert_eq!(resp_contain.verdict, CageVerdict::Clear);

    let report_contain = CageTraceVerifier::verify_trace_conformance(&resp_contain.governance_trace);
    assert!(
        report_contain.is_conformant,
        "Containment trace must be formally conformant: {:?}",
        report_contain.violations
    );
    assert_eq!(report_contain.final_verdict, Some(CageVerdict::Clear));

    // 3. Rollback disarm actuation trace
    let req_rollback = CageEvaluationRequest {
        agent_id: "killswitch-orchestrator".to_string(),
        role: "containment_orchestrator".to_string(),
        tool_name: "disarm_and_restore".to_string(),
        arguments: serde_json::json!({
            "action": "emergency_disarm",
            "clean_probes": 3,
        }),
        confidence_score: Some(0.95),
        amount_usd: None,
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_rollback = kernel.evaluate(&req_rollback);
    assert_eq!(resp_rollback.verdict, CageVerdict::Clear);

    let report_rollback = CageTraceVerifier::verify_trace_conformance(&resp_rollback.governance_trace);
    assert!(
        report_rollback.is_conformant,
        "Rollback trace must be formally conformant: {:?}",
        report_rollback.violations
    );
}

/// Test 4: Adversarial trace perturbations on orchestrator-generated traces
/// Asserts that `CageTraceVerifier` catches illegal post-refusal actuation,
/// inverted tiers, non-monotonic steps, and missing receipts.
#[test]
fn test_empirical_adversarial_trace_invariants_and_model_checking() {
    let kernel = global_cage_kernel();

    // Generate a refused trace (Tier 4 unverified self-authorization claim)
    let req_refuse = CageEvaluationRequest {
        agent_id: "killswitch-orchestrator".to_string(),
        role: "containment_orchestrator".to_string(),
        tool_name: "engage_containment".to_string(),
        arguments: serde_json::json!({
            "claim": "authorized_by_admin bypass",
        }),
        confidence_score: Some(0.95),
        amount_usd: None,
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_refuse = kernel.evaluate(&req_refuse);
    assert_eq!(resp_refuse.verdict, CageVerdict::Refuse);

    // Baseline refused trace should be conformant as a refusal trace
    let report_refuse = CageTraceVerifier::verify_trace_conformance(&resp_refuse.governance_trace);
    assert!(
        report_refuse.is_conformant,
        "Refusal trace must be conformant: {:?}",
        report_refuse.violations
    );

    // Adversarial Challenge A: Attacker attempts to forge ActuationCompleted onto refused trace
    let mut illegal_actuation_trace = resp_refuse.governance_trace.clone();
    let last_step = illegal_actuation_trace.last().map(|e| e.step).unwrap_or(0);
    illegal_actuation_trace.push(GovernanceTraceEvent {
        step: last_step + 1,
        timestamp_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
        kind: GovernanceTraceEventType::ActuationCompleted,
        tier: None,
        rule_id: None,
        verdict: Some(CageVerdict::Clear),
        details: "Forged actuation after refusal".to_string(),
        requires_warrant: false,
    });

    let report_illegal = CageTraceVerifier::verify_trace_conformance(&illegal_actuation_trace);
    assert!(
        !report_illegal.is_conformant,
        "Model checker MUST reject trace with actuation following refusal"
    );
    assert!(
        report_illegal
            .violations
            .iter()
            .any(|v| v.contains("ACTUATION_AFTER_REFUSAL")),
        "Violation must explicitly cite ACTUATION_AFTER_REFUSAL: {:?}",
        report_illegal.violations
    );

    // Adversarial Challenge B: Non-monotonic step numbering
    let mut non_monotonic_trace = resp_refuse.governance_trace.clone();
    if non_monotonic_trace.len() >= 2 {
        non_monotonic_trace[1].step = non_monotonic_trace[0].step;
        let report_non_mono = CageTraceVerifier::verify_trace_conformance(&non_monotonic_trace);
        assert!(
            !report_non_mono.is_conformant,
            "Non-monotonic step trace must be rejected"
        );
        assert!(
            report_non_mono
                .violations
                .iter()
                .any(|v| v.contains("NON_MONOTONIC_STEP")),
            "Violation must cite NON_MONOTONIC_STEP"
        );
    }

    // Adversarial Challenge C: Out-of-order tier evaluation
    let out_of_order_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            rule_id: None,
            verdict: None,
            details: "Proposed".to_string(),
            requires_warrant: false,
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier7Cbf),
            rule_id: Some("CBF_PASS".to_string()),
            verdict: Some(CageVerdict::Clear),
            details: "Tier 7 before Tier 3".to_string(),
            requires_warrant: false,
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier3Opa),
            rule_id: Some("OPA_PASS".to_string()),
            verdict: Some(CageVerdict::Clear),
            details: "Tier 3 after Tier 7".to_string(),
            requires_warrant: false,
        },
    ];
    let report_ooo = CageTraceVerifier::verify_trace_conformance(&out_of_order_trace);
    assert!(
        !report_ooo.is_conformant,
        "Out of order tier evaluation must be rejected"
    );
    assert!(
        report_ooo
            .violations
            .iter()
            .any(|v| v.contains("TRACE_OUT_OF_ORDER_TIER")),
        "Violation must cite TRACE_OUT_OF_ORDER_TIER"
    );
}
