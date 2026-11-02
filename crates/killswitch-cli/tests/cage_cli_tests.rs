//! Integration tests for CAGE CLI integration, flag wiring, and SubsystemVerifier Phase 8.

use killswitch_cli::client::KillSwitchClient;
use killswitch_cli::commands::handle_cage;
use killswitch_cli::verifier::SubsystemVerifier;
use killswitch_telemetry::cage_governance::*;

#[tokio::test]
async fn test_subsystem_verifier_8_phases_with_cage_governance() {
    let report = SubsystemVerifier::run_with_governance(true)
        .await
        .expect("All 8 phases including CAGE must pass");
    assert!(report.all_passed, "SubsystemVerifier must report all_passed == true");
    assert_eq!(report.phases.len(), 8, "Must verify all 8 subsystem phases including CAGE");

    for phase in &report.phases {
        assert!(phase.passed, "Phase {} ({}) failed: {}", phase.phase_number, phase.name, phase.details);
    }

    let p8 = &report.phases[7];
    assert_eq!(p8.phase_number, 8);
    assert!(p8.name.contains("CAGE"));
    assert!(p8.passed);
}

#[tokio::test]
async fn test_subsystem_verifier_standalone_cage_governance() {
    let report = SubsystemVerifier::verify_cage_governance()
        .await
        .expect("Standalone CAGE verification must succeed");
    assert_eq!(report.phase_number, 8);
    assert!(report.name.contains("CAGE"));
    assert!(report.passed);
    assert!(!report.details.is_empty());
}

#[tokio::test]
async fn test_cage_client_in_process_fallback() {
    // Point client to an unused port to exercise robust in-process fallback
    let client = KillSwitchClient::new("127.0.0.1", 59982);

    // 1. Status query
    let status = client.get_cage_status().await.expect("get_cage_status must succeed");
    assert!(!status.llm_clients_in_kernel);
    assert!(!status.substrate_contract_digest.is_empty());
    assert!(status.fiscal_cap_usd > 0.0);

    // 2. Evaluation query (Clear)
    let req_clean = CageEvaluationRequest {
        agent_id: "cli_test_trader".to_string(),
        role: "trader".to_string(),
        tool_name: "execute_trade".to_string(),
        arguments: serde_json::json!({ "symbol": "MSFT", "quantity": 10 }),
        confidence_score: Some(0.95),
        amount_usd: Some(500.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_clean = client.evaluate_cage(&req_clean).await.expect("evaluate_cage must succeed");
    assert_eq!(resp_clean.verdict, CageVerdict::Clear);
    assert!(!resp_clean.receipt.receipt_signature.is_empty());

    // 3. Evaluation query (Refuse on Tier 3 OPA single transfer limit)
    let req_over = CageEvaluationRequest {
        amount_usd: Some(25_000.0),
        ..req_clean
    };
    let resp_over = client.evaluate_cage(&req_over).await.expect("evaluate_cage must succeed");
    assert_eq!(resp_over.verdict, CageVerdict::Refuse);
    assert_eq!(resp_over.tier, CageTier::Tier3Opa);
    assert_eq!(resp_over.rule_id, CTRL_OPA_005);

    // 4. Substrate compilation
    let spec = serde_json::json!({
        "schema_version": "cage-substrate/3.0",
        "contract_id": "cli-test-contract",
        "domain": "containment",
        "allowed_tools": ["isolate_network", "execute_trade"],
        "parameter_bounds": {
            "max_single_transfer_usd": 10000.0,
            "max_dose_mg": 100.0,
            "fiscal_cap_usd": 50000.0
        }
    });
    let artifact = client.compile_substrate(&spec).await.expect("compile_substrate must succeed");
    assert_eq!(artifact.contract_id, "cli-test-contract");
    assert!(artifact.verify_digest());

    // 5. Trace model checking (Conformant)
    let trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Proposed".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Clear".to_string(),
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
    let trace_rep = client.verify_cage_trace(&trace).await.expect("verify_cage_trace must succeed");
    assert!(trace_rep.is_conformant);
}

#[tokio::test]
async fn test_cage_cli_command_handlers() {
    let client = KillSwitchClient::new("127.0.0.1", 59983);

    // 1. handle_cage status
    handle_cage(&client, "status", None, None, None, None)
        .await
        .expect("handle_cage status must succeed");

    // 2. handle_cage verify
    handle_cage(&client, "verify", None, None, None, None)
        .await
        .expect("handle_cage verify must succeed");

    // 3. handle_cage compile
    let spec_str = r#"{"schema_version":"cage-substrate/3.0","contract_id":"cli-cmd-spec","domain":"finance","allowed_tools":["execute_trade"]}"#;
    handle_cage(&client, "compile", Some(spec_str), None, None, None)
        .await
        .expect("handle_cage compile must succeed");

    // 4. handle_cage evaluate
    handle_cage(&client, "evaluate", None, Some("execute_trade"), Some(250.0), None)
        .await
        .expect("handle_cage evaluate must succeed");

    // 5. handle_cage verify-trace
    let trace_str = r#"[{"step":1,"timestamp_ms":1000,"kind":"ActionProposed","tier":null,"verdict":null,"rule_id":null,"requires_warrant":false,"details":"test"},{"step":2,"timestamp_ms":1001,"kind":"TierEvaluated","tier":"Tier8Fiscal","verdict":"Clear","rule_id":"PASS","requires_warrant":false,"details":"cleared"},{"step":3,"timestamp_ms":1002,"kind":"ReceiptSigned","tier":null,"verdict":"Clear","rule_id":null,"requires_warrant":false,"details":"signed"}]"#;
    handle_cage(&client, "verify-trace", None, None, None, Some(trace_str))
        .await
        .expect("handle_cage verify-trace must succeed");
}
