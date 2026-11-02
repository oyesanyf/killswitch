//! # Empirical Challenge & Adversarial Stress Harness for Milestone CAGE-3
//!
//! Focus:
//! 1. CLI Phase 8 verification under diverse conditions (`SubsystemVerifier::run_with_governance(true)`,
//!    `run_with_governance(false)`, `verify_cage_governance()`, concurrent verification tasks).
//! 2. CLI command execution: `handle_cage` across all 5 commands (`status`, `verify`, `compile`,
//!    `evaluate`, `verify-trace`) both over wire and direct in-process fallback.
//! 3. Resilient parameter & error handling: missing `--spec`, missing `--trace`, directory-as-file error,
//!    non-array JSON trace, and unknown CLI actions.
//! 4. Boundary & stress testing: negative amounts, zero amount, exact boundary thresholds ($10k cap,
//!    $5k consensus threshold), extreme amounts (f64::MAX, $1e12), dose barriers (50 mg, 100 mg,
//!    100.001 mg cap breach, 250 mg lethal breach, negative/zero dose).
//! 5. HTTP PEP route validation: Bitwise parity and behavior across dual route prefixes
//!    (`/cage/*` vs `/api/cage/*`) over live Axum server and simulated router.

use std::net::SocketAddr;
use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use killswitch_cli::client::KillSwitchClient;
use killswitch_cli::commands::handle_cage;
use killswitch_cli::verifier::SubsystemVerifier;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_telemetry::cage_governance::*;

// ============================================================================
// Helper Utilities
// ============================================================================

fn setup_test_server_state() -> Arc<ServerState> {
    let temp_dir = tempfile::tempdir().expect("tempdir creation must succeed");
    let containment = Arc::new(
        HostContainmentManager::new_default(Some(temp_dir.path()))
            .expect("HostContainmentManager creation must succeed"),
    );
    Arc::new(ServerState::with_defaults(containment))
}

async fn body_to_bytes(body: Body) -> axum::body::Bytes {
    axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("body read must succeed")
}

// ============================================================================
// SUITE 1: CLI Phase 8 Verification Under Diverse Conditions
// ============================================================================

#[tokio::test]
async fn test_c3_phase_8_verification_full_governance_pipeline() {
    // 1. Full 8-phase diagnostic execution
    let report = SubsystemVerifier::run_with_governance(true)
        .await
        .expect("SubsystemVerifier::run_with_governance(true) must succeed");

    assert!(report.all_passed, "All subsystem phases must pass");
    assert_eq!(report.phases.len(), 8, "Must execute exactly 8 phases when governance is enabled");

    // Verify all phases individually
    for phase in &report.phases {
        assert!(phase.passed, "Phase {} ({}) must pass: {}", phase.phase_number, phase.name, phase.details);
        assert!(!phase.details.is_empty(), "Phase {} details must not be empty", phase.phase_number);
    }

    // Inspect Phase 8 specifically
    let p8 = &report.phases[7];
    assert_eq!(p8.phase_number, 8);
    assert!(p8.name.contains("CAGE") || p8.name.contains("Google CAGE"));
    assert!(p8.passed);
    assert!(p8.details.contains("verified") || p8.details.contains("compiler"));

    // 2. Backward compatibility: run_with_governance(false) must run exactly 7 phases and NOT include Phase 8
    let report_legacy = SubsystemVerifier::run_with_governance(false)
        .await
        .expect("SubsystemVerifier::run_with_governance(false) must succeed");

    assert!(report_legacy.all_passed);
    assert_eq!(report_legacy.phases.len(), 7, "Must execute exactly 7 phases when governance is disabled");
    for phase in &report_legacy.phases {
        assert_ne!(phase.phase_number, 8, "Phase 8 must not run when governance is disabled");
    }
}

#[tokio::test]
async fn test_c3_phase_8_standalone_diagnostic_verification() {
    let p8_report = SubsystemVerifier::verify_cage_governance()
        .await
        .expect("SubsystemVerifier::verify_cage_governance() must succeed");

    assert_eq!(p8_report.phase_number, 8);
    assert!(p8_report.passed, "Phase 8 self-diagnostics must pass");
    assert!(p8_report.name.contains("CAGE"));
    assert!(!p8_report.details.is_empty());
}

#[tokio::test]
async fn test_c3_phase_8_concurrent_verification_thread_safety() {
    // Stress test multi-task concurrent executions of Phase 8 diagnostics
    let mut tasks = Vec::new();
    for _ in 0..10 {
        tasks.push(tokio::spawn(async {
            SubsystemVerifier::verify_cage_governance().await
        }));
    }

    for task in tasks {
        let res = task.await.expect("JoinHandle must succeed");
        let report = res.expect("verify_cage_governance must succeed concurrently");
        assert_eq!(report.phase_number, 8);
        assert!(report.passed);
    }
}

// ============================================================================
// SUITE 2: CLI Command Execution (`handle_cage` across all 5 commands)
// ============================================================================

#[tokio::test]
async fn test_c3_handle_cage_all_five_commands_in_process_fallback() {
    // Client pointing to an inactive port to exercise resilient in-process fallback
    let client = KillSwitchClient::new("127.0.0.1", 58190);

    // 1. handle_cage "status"
    let res_status = handle_cage(&client, "status", None, None, None, None).await;
    assert!(res_status.is_ok(), "handle_cage status must succeed: {:?}", res_status);

    // 2. handle_cage "verify"
    let res_verify = handle_cage(&client, "verify", None, None, None, None).await;
    assert!(res_verify.is_ok(), "handle_cage verify must succeed: {:?}", res_verify);

    // 3. handle_cage "compile" with inline JSON spec across multiple formats
    let formats = [
        ("NativeCage", r#"{"schema_version":"cage-substrate/3.0","contract_id":"cli-native","domain":"general","allowed_tools":["execute_trade"]}"#),
        ("MicrosoftAcs", r#"{"metadata":{"name":"cli-ms-acs"},"behaviorDeclarations":[{"action":"execute_trade","constraints":[{"parameter":"max_single_transfer_usd","value":5000.0}]}]}"#),
        ("LinuxFoundationAaif", r#"{"metadata":{"name":"cli-lf-aaif"},"governedRunLoop":{"stages":[{"name":"g","rules":[{"tool":"execute_trade"}]}]}}"#),
        ("NistOscal", r#"{"oscal-version":"1.0.0","id":"cli-oscal","component-definition":{"components":[{"control-implementations":[{"implemented-requirements":[{"control-id":"ac-3","props":[]}]}]}]}}"#),
        ("LulaValidation", r#"{"kind":"LulaValidation","metadata":{"name":"cli-lula","annotations":{"max_single_transfer_usd":"5000"}},"spec":{"domain":{"kubernetes-spec":{"resources":[{"name":"execute_trade"}]}}}}"#),
    ];

    for (name, spec_str) in formats {
        let res_comp = handle_cage(&client, "compile", Some(spec_str), None, None, None).await;
        assert!(res_comp.is_ok(), "handle_cage compile for format {} must succeed: {:?}", name, res_comp);
    }

    // 4. handle_cage "compile" with spec loaded from temporary file on disk
    let temp_spec_file = tempfile::NamedTempFile::new().expect("temp file creation must succeed");
    let disk_spec = r#"{"schema_version":"cage-substrate/3.0","contract_id":"cli-disk-spec","domain":"finance","allowed_tools":["execute_trade","query_balance"]}"#;
    std::fs::write(temp_spec_file.path(), disk_spec).expect("write spec to disk must succeed");
    let file_path_str = temp_spec_file.path().to_str().expect("valid utf-8 path");

    let res_disk_compile = handle_cage(&client, "compile", Some(file_path_str), None, None, None).await;
    assert!(res_disk_compile.is_ok(), "handle_cage compile with disk file must succeed: {:?}", res_disk_compile);

    // 5. handle_cage "evaluate"
    // 5a. Clean evaluation
    let res_eval_clean = handle_cage(&client, "evaluate", None, Some("execute_trade"), Some(250.0), None).await;
    assert!(res_eval_clean.is_ok(), "handle_cage evaluate (clean) must succeed: {:?}", res_eval_clean);

    // 5b. Refusal evaluation (over limit)
    let res_eval_over = handle_cage(&client, "evaluate", None, Some("execute_trade"), Some(25000.0), None).await;
    assert!(res_eval_over.is_ok(), "handle_cage evaluate (over-limit refusal) must succeed: {:?}", res_eval_over);

    // 5c. Default tool and default amount
    let res_eval_defaults = handle_cage(&client, "evaluate", None, None, None, None).await;
    assert!(res_eval_defaults.is_ok(), "handle_cage evaluate (defaults) must succeed: {:?}", res_eval_defaults);

    // 6. handle_cage "verify-trace"
    // 6a. Conformant trace string
    let conformant_trace_str = r#"[
        {"step":1,"timestamp_ms":1000,"kind":"ActionProposed","tier":null,"verdict":null,"rule_id":null,"requires_warrant":false,"details":"Proposed"},
        {"step":2,"timestamp_ms":1001,"kind":"TierEvaluated","tier":"Tier8Fiscal","verdict":"Clear","rule_id":"PASS","requires_warrant":false,"details":"Cleared"},
        {"step":3,"timestamp_ms":1002,"kind":"ReceiptSigned","tier":null,"verdict":"Clear","rule_id":null,"requires_warrant":false,"details":"Signed"}
    ]"#;
    let res_trace_inline = handle_cage(&client, "verify-trace", None, None, None, Some(conformant_trace_str)).await;
    assert!(res_trace_inline.is_ok(), "handle_cage verify-trace (inline conformant) must succeed: {:?}", res_trace_inline);

    // 6b. Non-conformant trace string (illegal actuation without clear receipt)
    let non_conformant_trace_str = r#"[
        {"step":1,"timestamp_ms":1000,"kind":"ActionProposed","tier":null,"verdict":null,"rule_id":null,"requires_warrant":false,"details":"Proposed"},
        {"step":2,"timestamp_ms":1001,"kind":"ActuationCompleted","tier":null,"verdict":null,"rule_id":null,"requires_warrant":false,"details":"Actuated without clear"}
    ]"#;
    let res_trace_bad = handle_cage(&client, "verify-trace", None, None, None, Some(non_conformant_trace_str)).await;
    assert!(res_trace_bad.is_ok(), "handle_cage verify-trace (inline non-conformant) must succeed: {:?}", res_trace_bad);

    // 6c. Trace loaded from file on disk
    let temp_trace_file = tempfile::NamedTempFile::new().expect("temp trace file creation must succeed");
    std::fs::write(temp_trace_file.path(), conformant_trace_str).expect("write trace to disk must succeed");
    let trace_path_str = temp_trace_file.path().to_str().expect("valid utf-8 path");

    let res_trace_disk = handle_cage(&client, "verify-trace", None, None, None, Some(trace_path_str)).await;
    assert!(res_trace_disk.is_ok(), "handle_cage verify-trace with disk file must succeed: {:?}", res_trace_disk);
}

// ============================================================================
// SUITE 3: CLI Error & Missing Parameter Handling
// ============================================================================

#[tokio::test]
async fn test_c3_handle_cage_missing_parameters_and_error_handling() {
    let client = KillSwitchClient::new("127.0.0.1", 58191);

    // 1. Missing --spec for "compile"
    let err_missing_spec = handle_cage(&client, "compile", None, None, None, None).await;
    assert!(err_missing_spec.is_err(), "compile without --spec must return an error");
    let err_msg = format!("{:?}", err_missing_spec.unwrap_err());
    assert!(err_msg.contains("Missing --spec parameter"), "Error message must mention missing --spec: {}", err_msg);

    // 2. Directory passed as file path for "compile" (read_to_string error)
    let temp_dir = tempfile::tempdir().expect("tempdir creation must succeed");
    let dir_path_str = temp_dir.path().to_str().unwrap();
    let err_dir_spec = handle_cage(&client, "compile", Some(dir_path_str), None, None, None).await;
    assert!(err_dir_spec.is_err(), "compile with directory path must return an error");

    // 2b. Malformed JSON / non-YAML string for "compile"
    let err_malformed = handle_cage(&client, "compile", Some("{ not valid json !!!"), None, None, None).await;
    assert!(err_malformed.is_err(), "compile with malformed JSON must return an error");

    // 3. Missing --trace for "verify-trace"
    let err_missing_trace = handle_cage(&client, "verify-trace", None, None, None, None).await;
    assert!(err_missing_trace.is_err(), "verify-trace without --trace must return an error");
    let err_msg_trace = format!("{:?}", err_missing_trace.unwrap_err());
    assert!(err_msg_trace.contains("Missing --trace parameter"), "Error message must mention missing --trace: {}", err_msg_trace);

    // 4. Corrupted JSON for "verify-trace" (non-array JSON)
    let err_corrupt_trace = handle_cage(&client, "verify-trace", None, None, None, Some("{ not an array }")).await;
    assert!(err_corrupt_trace.is_err(), "verify-trace with non-array JSON must return an error");

    // 5. Unknown CLI subcommand
    for bad_cmd in &["destroy", "quarantine-all", "unknown", ""] {
        let err_unknown = handle_cage(&client, bad_cmd, None, None, None, None).await;
        assert!(err_unknown.is_err(), "Unknown action '{}' must error", bad_cmd);
        let msg = format!("{:?}", err_unknown.unwrap_err());
        assert!(msg.contains("Unknown CAGE action"), "Expected unknown action error: {}", msg);
    }
}

// ============================================================================
// SUITE 4: Boundary Tests (Negative, Zero, High Amounts, Dose & Invariance)
// ============================================================================

#[tokio::test]
async fn test_c3_boundary_evaluations_amounts_and_dose() {
    let kernel = CageGovernanceKernel::new();

    // 1. Zero amount: $0.00
    let req_zero = CageEvaluationRequest {
        agent_id: "boundary_tester".to_string(),
        role: "worker".to_string(),
        tool_name: "execute_trade".to_string(),
        arguments: serde_json::json!({ "amount": 0.0 }),
        confidence_score: Some(0.95),
        amount_usd: Some(0.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_zero = kernel.evaluate(&req_zero);
    assert_eq!(resp_zero.verdict, CageVerdict::Clear, "Zero amount must clear all 8 tiers");

    // 2. Negative amounts: -100.0, -0.01, -1e6
    for neg_amt in &[-0.01, -100.0, -1_000_000.0] {
        let req_neg = CageEvaluationRequest {
            amount_usd: Some(*neg_amt),
            arguments: serde_json::json!({ "amount": *neg_amt }),
            ..req_zero.clone()
        };
        let resp_neg = kernel.evaluate(&req_neg);
        assert_eq!(resp_neg.verdict, CageVerdict::Clear, "Negative amount {} must not crash and should clear without increasing spend", neg_amt);
    }

    // 3. Exact single-transfer limit boundary: $10,000.00 vs $10,000.01
    // Note: $10,000.00 exceeds the $5,000.00 consensus risk threshold, so it requires human approval to reach Tier 7/8.
    let hitl_approval = HitlConsensusApproval {
        operator_id: "chief_risk_officer".to_string(),
        is_approved: true,
        rationale: "Approved treasury reallocation within operational ceiling".to_string(),
        approved_at_ms: 1_700_000_000_000,
        signature_hex: None,
    };

    let req_exact_cap = CageEvaluationRequest {
        amount_usd: Some(10_000.0),
        human_approval: Some(hitl_approval.clone()),
        arguments: serde_json::json!({ "amount": 10_000.0 }),
        ..req_zero.clone()
    };
    let resp_exact = kernel.evaluate(&req_exact_cap);
    assert_eq!(resp_exact.verdict, CageVerdict::Clear, "Exact cap $10,000.00 with consensus approval must clear all 8 tiers");

    let req_over_cap = CageEvaluationRequest {
        amount_usd: Some(10_000.01),
        human_approval: Some(hitl_approval.clone()),
        arguments: serde_json::json!({ "amount": 10_000.01 }),
        ..req_zero.clone()
    };
    let resp_over = kernel.evaluate(&req_over_cap);
    assert_eq!(resp_over.verdict, CageVerdict::Refuse, "$10,000.01 even with human approval must be refused by Tier 3 OPA");
    assert_eq!(resp_over.tier, CageTier::Tier3Opa);
    assert_eq!(resp_over.rule_id, CTRL_OPA_005);

    // 4. Extreme amounts & overflow safety
    for extreme_amt in &[100_000.0, 1_000_000_000.0, 1e12, f64::MAX] {
        let req_extreme = CageEvaluationRequest {
            amount_usd: Some(*extreme_amt),
            arguments: serde_json::json!({ "amount": *extreme_amt }),
            ..req_zero.clone()
        };
        let resp_extreme = kernel.evaluate(&req_extreme);
        assert_eq!(resp_extreme.verdict, CageVerdict::Refuse);
        assert_eq!(resp_extreme.tier, CageTier::Tier3Opa);
    }

    // 5. Consensus risk threshold boundary: $5,000.00 (risk 0.10) vs $5,000.01 (risk 0.90)
    let req_low_risk = CageEvaluationRequest {
        amount_usd: Some(5_000.0),
        arguments: serde_json::json!({ "amount": 5_000.0 }),
        ..req_zero.clone()
    };
    let resp_low_risk = kernel.evaluate(&req_low_risk);
    assert_eq!(resp_low_risk.verdict, CageVerdict::Clear, "$5,000.00 must clear without human approval");

    let req_high_risk_no_hitl = CageEvaluationRequest {
        amount_usd: Some(5_000.01),
        arguments: serde_json::json!({ "amount": 5_000.01 }),
        ..req_zero.clone()
    };
    let resp_high_risk = kernel.evaluate(&req_high_risk_no_hitl);
    assert_eq!(resp_high_risk.verdict, CageVerdict::Refuse, "$5,000.01 must trigger consensus requirement");
    assert_eq!(resp_high_risk.tier, CageTier::Tier6Consensus);
    assert_eq!(resp_high_risk.rule_id, CTRL_CONSENSUS_REQUIRED);

    // 6. Dose boundaries (HealthcareDoseBarrier & Tier 7 CBF)
    // 6a. Safe dose: 50 mg (risk <= 0.85 threshold, single <= 100 mg)
    let req_dose_50 = CageEvaluationRequest {
        tool_name: "administer_medication".to_string(),
        amount_usd: None,
        dose_mg: Some(50.0),
        arguments: serde_json::json!({ "dose_mg": 50.0 }),
        ..req_zero.clone()
    };
    let resp_dose_50 = kernel.evaluate(&req_dose_50);
    assert_eq!(resp_dose_50.verdict, CageVerdict::Clear, "50.0 mg dose must clear");

    // 6b. Dose 50.001 mg -> triggers Tier 6 Consensus requirement
    let req_dose_50_001 = CageEvaluationRequest {
        dose_mg: Some(50.001),
        arguments: serde_json::json!({ "dose_mg": 50.001 }),
        ..req_dose_50.clone()
    };
    let resp_dose_consensus = kernel.evaluate(&req_dose_50_001);
    assert_eq!(resp_dose_consensus.verdict, CageVerdict::Refuse);
    assert_eq!(resp_dose_consensus.tier, CageTier::Tier6Consensus);

    // 6c. Dose 100.0 mg with valid human consensus approval -> Clears
    let med_hitl = HitlConsensusApproval {
        operator_id: "chief_medical_officer".to_string(),
        is_approved: true,
        rationale: "Approved under acute protocol section 4".to_string(),
        approved_at_ms: 1_700_000_000_000,
        signature_hex: None,
    };
    let req_dose_100_approved = CageEvaluationRequest {
        dose_mg: Some(100.0),
        human_approval: Some(med_hitl.clone()),
        arguments: serde_json::json!({ "dose_mg": 100.0 }),
        ..req_dose_50.clone()
    };
    let resp_dose_100 = kernel.evaluate(&req_dose_100_approved);
    assert_eq!(resp_dose_100.verdict, CageVerdict::Clear, "100.0 mg dose with approval must clear Tier 7 CBF");

    // 6d. Dose 100.001 mg with approval -> Breaches single dose cap (100 mg max) at Tier 7 CBF
    let req_dose_over_single = CageEvaluationRequest {
        dose_mg: Some(100.001),
        human_approval: Some(med_hitl.clone()),
        arguments: serde_json::json!({ "dose_mg": 100.001 }),
        ..req_dose_50.clone()
    };
    let resp_dose_over = kernel.evaluate(&req_dose_over_single);
    assert_eq!(resp_dose_over.verdict, CageVerdict::Refuse);
    assert_eq!(resp_dose_over.tier, CageTier::Tier7Cbf);
    assert_eq!(resp_dose_over.rule_id, CTRL_CBF_DOSE_001);

    // 6e. Dose 250.0 mg -> Breaches lethal daily cap (200 mg) at Tier 7 CBF
    let req_dose_lethal = CageEvaluationRequest {
        dose_mg: Some(250.0),
        human_approval: Some(med_hitl),
        arguments: serde_json::json!({ "dose_mg": 250.0 }),
        ..req_dose_50.clone()
    };
    let resp_lethal = kernel.evaluate(&req_dose_lethal);
    assert_eq!(resp_lethal.verdict, CageVerdict::Refuse);
    assert_eq!(resp_lethal.tier, CageTier::Tier7Cbf);
    assert_eq!(resp_lethal.rule_id, CTRL_CBF_DOSE_001);

    // 6f. Zero and negative dose safety
    for d in &[0.0, -10.0] {
        let req_zero_dose = CageEvaluationRequest {
            dose_mg: Some(*d),
            arguments: serde_json::json!({ "dose_mg": *d }),
            ..req_dose_50.clone()
        };
        let resp_d = kernel.evaluate(&req_zero_dose);
        assert_eq!(resp_d.verdict, CageVerdict::Clear);
    }
}

// ============================================================================
// SUITE 5: HTTP PEP Route Validation & Dual Routing Parity (`/cage/*` & `/api/cage/*`)
// ============================================================================

#[tokio::test]
async fn test_c3_http_pep_dual_routing_parity_status_endpoint() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. GET /cage/status
    let req_1 = Request::builder()
        .uri("/cage/status")
        .method("GET")
        .body(Body::empty())
        .expect("request build must succeed");
    let resp_1 = app.clone().oneshot(req_1).await.expect("oneshot must succeed");
    assert_eq!(resp_1.status(), StatusCode::OK);
    let bytes_1 = body_to_bytes(resp_1.into_body()).await;
    let status_1: CageKernelStatusReport = serde_json::from_slice(&bytes_1).expect("json parse must succeed");

    // 2. GET /api/cage/status
    let req_2 = Request::builder()
        .uri("/api/cage/status")
        .method("GET")
        .body(Body::empty())
        .expect("request build must succeed");
    let resp_2 = app.oneshot(req_2).await.expect("oneshot must succeed");
    assert_eq!(resp_2.status(), StatusCode::OK);
    let bytes_2 = body_to_bytes(resp_2.into_body()).await;
    let status_2: CageKernelStatusReport = serde_json::from_slice(&bytes_2).expect("json parse must succeed");

    // Parity verification between /cage/status and /api/cage/status
    assert_eq!(status_1.llm_clients_in_kernel, status_2.llm_clients_in_kernel);
    assert!(!status_1.llm_clients_in_kernel, "Kernel must be deterministic and LLM-free");
    assert_eq!(status_1.active_contract_id, status_2.active_contract_id);
    assert_eq!(status_1.substrate_contract_digest, status_2.substrate_contract_digest);
    assert_eq!(status_1.substrate_format, status_2.substrate_format);
    assert_eq!(status_1.fiscal_cap_usd, status_2.fiscal_cap_usd);
}

#[tokio::test]
async fn test_c3_http_pep_dual_routing_parity_evaluate_endpoint() {
    let state = setup_test_server_state();
    let app = build_router(state);

    let clean_payload = serde_json::json!({
        "agent_id": "dual_router_probe",
        "role": "containment_operator",
        "tool_name": "execute_trade",
        "arguments": { "symbol": "NVDA", "quantity": 5 },
        "confidence_score": 0.95,
        "amount_usd": 300.0
    });

    // 1. POST /cage/evaluate
    let req_1 = Request::builder()
        .uri("/cage/evaluate")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&clean_payload).unwrap()))
        .expect("request build must succeed");
    let resp_1 = app.clone().oneshot(req_1).await.expect("oneshot must succeed");
    assert_eq!(resp_1.status(), StatusCode::OK);
    let bytes_1 = body_to_bytes(resp_1.into_body()).await;
    let eval_1: CageEvaluationResponse = serde_json::from_slice(&bytes_1).expect("json parse must succeed");

    // 2. POST /api/cage/evaluate
    let req_2 = Request::builder()
        .uri("/api/cage/evaluate")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&clean_payload).unwrap()))
        .expect("request build must succeed");
    let resp_2 = app.clone().oneshot(req_2).await.expect("oneshot must succeed");
    assert_eq!(resp_2.status(), StatusCode::OK);
    let bytes_2 = body_to_bytes(resp_2.into_body()).await;
    let eval_2: CageEvaluationResponse = serde_json::from_slice(&bytes_2).expect("json parse must succeed");

    assert_eq!(eval_1.verdict, CageVerdict::Clear);
    assert_eq!(eval_2.verdict, CageVerdict::Clear);
    assert_eq!(eval_1.verdict, eval_2.verdict);
    assert_eq!(eval_1.tier, eval_2.tier);
    assert!(!eval_1.receipt.receipt_signature.is_empty());
    assert!(!eval_2.receipt.receipt_signature.is_empty());

    // 3. Test Refusal Parity across /cage/evaluate and /api/cage/evaluate
    let over_payload = serde_json::json!({
        "agent_id": "dual_router_probe",
        "role": "containment_operator",
        "tool_name": "execute_trade",
        "arguments": { "amount": 25000.0 },
        "confidence_score": 0.95,
        "amount_usd": 25000.0
    });

    let req_over_1 = Request::builder()
        .uri("/cage/evaluate")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&over_payload).unwrap()))
        .unwrap();
    let resp_over_1 = app.clone().oneshot(req_over_1).await.unwrap();
    assert_eq!(resp_over_1.status(), StatusCode::OK);
    let eval_over_1: CageEvaluationResponse = serde_json::from_slice(&body_to_bytes(resp_over_1.into_body()).await).unwrap();

    let req_over_2 = Request::builder()
        .uri("/api/cage/evaluate")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&over_payload).unwrap()))
        .unwrap();
    let resp_over_2 = app.oneshot(req_over_2).await.unwrap();
    assert_eq!(resp_over_2.status(), StatusCode::OK);
    let eval_over_2: CageEvaluationResponse = serde_json::from_slice(&body_to_bytes(resp_over_2.into_body()).await).unwrap();

    assert_eq!(eval_over_1.verdict, CageVerdict::Refuse);
    assert_eq!(eval_over_2.verdict, CageVerdict::Refuse);
    assert_eq!(eval_over_1.rule_id, CTRL_OPA_005);
    assert_eq!(eval_over_2.rule_id, CTRL_OPA_005);
    assert_eq!(eval_over_1.tier, CageTier::Tier3Opa);
    assert_eq!(eval_over_2.tier, CageTier::Tier3Opa);
}

#[tokio::test]
async fn test_c3_http_pep_dual_routing_parity_compile_substrate_endpoint() {
    let state = setup_test_server_state();
    let app = build_router(state);

    let native_spec = serde_json::json!({
        "schema_version": "cage-substrate/3.0",
        "contract_id": "dual-route-contract",
        "domain": "containment",
        "allowed_tools": ["isolate_network", "execute_trade"],
        "parameter_bounds": {
            "max_single_transfer_usd": 8000.0,
            "max_dose_mg": 50.0,
            "fiscal_cap_usd": 40000.0
        }
    });

    // 1. POST /cage/compile-substrate
    let req_1 = Request::builder()
        .uri("/cage/compile-substrate")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&native_spec).unwrap()))
        .unwrap();
    let resp_1 = app.clone().oneshot(req_1).await.unwrap();
    assert_eq!(resp_1.status(), StatusCode::OK);
    let art_1: CompiledSubstrateArtifact = serde_json::from_slice(&body_to_bytes(resp_1.into_body()).await).unwrap();

    // 2. POST /api/cage/compile-substrate
    let req_2 = Request::builder()
        .uri("/api/cage/compile-substrate")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&native_spec).unwrap()))
        .unwrap();
    let resp_2 = app.clone().oneshot(req_2).await.unwrap();
    assert_eq!(resp_2.status(), StatusCode::OK);
    let art_2: CompiledSubstrateArtifact = serde_json::from_slice(&body_to_bytes(resp_2.into_body()).await).unwrap();

    // Bitwise digest parity
    assert_eq!(art_1.contract_id, "dual-route-contract");
    assert_eq!(art_2.contract_id, "dual-route-contract");
    assert_eq!(art_1.substrate_contract_digest, art_2.substrate_contract_digest);
    assert_eq!(art_1.format, art_2.format);
    assert!(art_1.verify_digest());
    assert!(art_2.verify_digest());

    // 3. Non-object payload (e.g. JSON array) -> 400 Bad Request on both endpoints
    let non_object_spec = serde_json::json!(["forbidden", "array", "payload"]);
    for uri in &["/cage/compile-substrate", "/api/cage/compile-substrate"] {
        let req_err = Request::builder()
            .uri(*uri)
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&non_object_spec).unwrap()))
            .unwrap();
        let resp_err = app.clone().oneshot(req_err).await.unwrap();
        assert_eq!(resp_err.status(), StatusCode::BAD_REQUEST, "Expected 400 Bad Request on {}", uri);
    }

    // 4. Unrecognized specification object -> 400 Bad Request on both endpoints
    let unrecognized_spec = serde_json::json!({ "unrecognized_field": true });
    for uri in &["/cage/compile-substrate", "/api/cage/compile-substrate"] {
        let req_err = Request::builder()
            .uri(*uri)
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&unrecognized_spec).unwrap()))
            .unwrap();
        let resp_err = app.clone().oneshot(req_err).await.unwrap();
        assert_eq!(resp_err.status(), StatusCode::BAD_REQUEST, "Expected 400 Bad Request on unrecognized payload for {}", uri);
    }
}

#[tokio::test]
async fn test_c3_http_pep_dual_routing_parity_verify_trace_endpoint() {
    let state = setup_test_server_state();
    let app = build_router(state);

    let trace_events = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Action proposed".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Fiscal spend verified".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: None,
            verdict: Some(CageVerdict::Clear),
            rule_id: None,
            requires_warrant: false,
            details: "Receipt signed".to_string(),
        },
    ];

    // Test raw array payload on both prefixes
    let raw_array_bytes = serde_json::to_vec(&trace_events).unwrap();
    for uri in &["/cage/verify-trace", "/api/cage/verify-trace"] {
        let req = Request::builder()
            .uri(*uri)
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(raw_array_bytes.clone()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "Failed on {}", uri);
        let rep: TraceConformanceReport = serde_json::from_slice(&body_to_bytes(resp.into_body()).await).unwrap();
        assert!(rep.is_conformant, "Trace must be conformant on {}", uri);
        assert!(rep.violations.is_empty());
    }

    // Test object wrapper { "trace": [...] } on both prefixes
    let obj_payload = serde_json::json!({
        "trace": trace_events,
        "requires_warrant": false
    });
    let obj_bytes = serde_json::to_vec(&obj_payload).unwrap();
    for uri in &["/cage/verify-trace", "/api/cage/verify-trace"] {
        let req = Request::builder()
            .uri(*uri)
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(obj_bytes.clone()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "Failed on {} with object payload", uri);
        let rep: TraceConformanceReport = serde_json::from_slice(&body_to_bytes(resp.into_body()).await).unwrap();
        assert!(rep.is_conformant);
    }

    // Test violation trace on both prefixes
    let bad_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Action proposed".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::ActuationCompleted,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Actuation without receipt".to_string(),
        },
    ];
    let bad_bytes = serde_json::to_vec(&bad_trace).unwrap();
    for uri in &["/cage/verify-trace", "/api/cage/verify-trace"] {
        let req = Request::builder()
            .uri(*uri)
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(bad_bytes.clone()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let rep: TraceConformanceReport = serde_json::from_slice(&body_to_bytes(resp.into_body()).await).unwrap();
        assert!(!rep.is_conformant, "Expected non-conformant on {}", uri);
        assert!(!rep.violations.is_empty());
    }
}

#[tokio::test]
async fn test_c3_live_http_client_e2e_over_tcp_socket() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // Bind real TCP listener on loopback
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tcp listener bind must succeed");
    let local_addr: SocketAddr = listener.local_addr().expect("local addr must resolve");
    let port = local_addr.port();

    // Spawn server task
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum server loop must run");
    });

    // Construct client connected to live TCP port
    let client = KillSwitchClient::new("127.0.0.1", port);

    // 1. Live get_cage_status
    let status = client.get_cage_status().await.expect("Live get_cage_status must succeed");
    assert!(!status.llm_clients_in_kernel);
    assert!(!status.substrate_contract_digest.is_empty());

    // 2. Live evaluate_cage (clean)
    let req_clean = CageEvaluationRequest {
        agent_id: "live_socket_probe".to_string(),
        role: "operator".to_string(),
        tool_name: "execute_trade".to_string(),
        arguments: serde_json::json!({ "shares": 10 }),
        confidence_score: Some(0.92),
        amount_usd: Some(150.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_clean = client.evaluate_cage(&req_clean).await.expect("Live evaluate_cage must succeed");
    assert_eq!(resp_clean.verdict, CageVerdict::Clear);

    // 3. Live evaluate_cage (refuse)
    let req_refuse = CageEvaluationRequest {
        amount_usd: Some(15_000.0),
        ..req_clean
    };
    let resp_refuse = client.evaluate_cage(&req_refuse).await.expect("Live evaluate_cage over-limit must succeed");
    assert_eq!(resp_refuse.verdict, CageVerdict::Refuse);
    assert_eq!(resp_refuse.tier, CageTier::Tier3Opa);

    // 4. Live compile_substrate
    let spec = serde_json::json!({
        "schema_version": "cage-substrate/3.0",
        "contract_id": "live-socket-contract",
        "domain": "containment",
        "allowed_tools": ["isolate_network"]
    });
    let art = client.compile_substrate(&spec).await.expect("Live compile_substrate must succeed");
    assert_eq!(art.contract_id, "live-socket-contract");

    // 5. Live verify_cage_trace
    let trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Action proposed".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Cleared".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: None,
            verdict: Some(CageVerdict::Clear),
            rule_id: None,
            requires_warrant: false,
            details: "Signed".to_string(),
        },
    ];
    let trace_rep = client.verify_cage_trace(&trace).await.expect("Live verify_cage_trace must succeed");
    assert!(trace_rep.is_conformant);

    // 6. Direct HTTP probe against the /cage/* prefix over wire (raw reqwest)
    let raw_http = reqwest::Client::new();
    let url_cage_status = format!("http://127.0.0.1:{}/cage/status", port);
    let wire_resp = raw_http.get(&url_cage_status).send().await.expect("Wire GET /cage/status must succeed");
    assert_eq!(wire_resp.status(), reqwest::StatusCode::OK);
    let wire_status: CageKernelStatusReport = wire_resp.json().await.expect("JSON parse of /cage/status must succeed");
    assert_eq!(wire_status.active_contract_id, status.active_contract_id);
}
