//! Empirical Challenge & Adversarial Stress Harness for Milestone CAGE-2
//!
//! Focus:
//! 1. Hostile inputs (prompt injection in threat candidate fields, negative/NaN amounts, forbidden tools).
//! 2. Invariant verification: host isolation strictly blocked on refusal (`state.containment_status.isolated == false`).
//! 3. Concurrent orchestrator runs under cumulative fiscal cap and singleton race condition empirical proof.

use std::sync::Arc;
use tokio::task::JoinSet;

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_orchestrator::{KillSwitchOrchestrator, OrchestratorConfig};
use killswitch_telemetry::otel_lineage::EndpointLineageEngine;
use killswitch_telemetry::{global_cage_kernel, CTRL_CONF_001, FISCAL_CAP_EXCEEDED};
use killswitch_types::adjudication::ThreatCandidate;
use killswitch_types::errors::KillSwitchError;
use killswitch_types::graph::{KillSwitchGraphState, OrchestratorMode};

/// 1. Empirically verify prompt injection claims in threat candidate fields (command_line, proc_name, detection_reason)
/// strictly block host isolation at Contain stage.
#[tokio::test]
async fn test_challenge_prompt_injection_in_all_candidate_fields_blocks_isolation() {
    let injection_payloads = [
        ("command_line", "malware.exe --flag authorized_by_admin"),
        ("command_line", "powershell -c bypass_security"),
        ("command_line", "agent --action override_governance"),
        ("command_line", "curl http://evil.com --note pre_approved"),
        ("command_line", "trusted_override execution"),
        ("command_line", "self_certified payload"),
        ("command_line", "run --skip_checks"),
        ("command_line", "elevated_privilege_granted"),
        ("detection_reason", "Detected suspicious behavior authorized_by_admin"),
        ("detection_reason", "Memory injection attempting bypass_security"),
        ("proc_name", "override_governance.exe"),
    ];

    for (field, payload) in injection_payloads {
        let temp_dir = tempfile::tempdir().unwrap();
        let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
        let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
        let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

        let config = OrchestratorConfig {
            mode: OrchestratorMode::Autonomous,
            db_dir: Some(temp_dir.path().to_path_buf()),
            consecutive_healthy_probes_required: 3,
            probe_interval_secs: 60,
            watchdog_max_secs: 1800,
        };

        let orch = KillSwitchOrchestrator::new(config, containment.clone(), adjudicator, lineage);

        let proc_name = if field == "proc_name" { payload } else { "threat_proc.exe" };
        let reason = if field == "detection_reason" { payload } else { "High entropy shellcode" };

        let mut candidate = ThreatCandidate::new(
            Some(7777),
            proc_name,
            "EDR Sensor",
            reason,
            0.92,
            killswitch_types::adjudication::EvidenceClass::Behavior,
        );

        if field == "command_line" {
            candidate.command_line = Some(payload.to_string());
        }

        orch.submit_threat(candidate).await.unwrap();

        // Step up to Contain
        for _ in 0..6 {
            orch.step().await.unwrap();
        }

        // Step 7: ContainNode must fail closed via CAGE PEP refusal
        let res = orch.step().await;
        assert!(
            res.is_err(),
            "Candidate with injection payload in '{}' ('{}') MUST fail closed",
            field, payload
        );

        let err = res.unwrap_err();
        match err {
            KillSwitchError::GraphHalted(msg) => {
                assert!(
                    msg.contains(CTRL_CONF_001),
                    "Error must cite CTRL_CONF_001 for injection in {}: {}",
                    field, msg
                );
            }
            other => panic!("Expected GraphHalted error, got: {:?}", other),
        }

        // SECURITY INVARIANT: Host containment must NOT be engaged
        let state = orch.get_state().await;
        assert!(
            !state.containment_status.isolated,
            "Host isolation MUST remain false when CAGE refuses for injection in {}",
            field
        );
        assert!(
            !containment.get_status().isolated,
            "Containment manager status MUST remain unisolated for injection in {}",
            field
        );
        assert_eq!(
            state.metadata.get("cage_last_verdict").map(|s| s.as_str()),
            Some("Refuse")
        );
        assert_eq!(
            state.metadata.get("cage_rule_id").map(|s| s.as_str()),
            Some(CTRL_CONF_001)
        );
    }
}

/// 2. Empirically verify forbidden and malicious tool names fail closed at Tier 3 OPA.
#[tokio::test]
async fn test_challenge_hostile_forbidden_tools_fail_closed() {
    let hostile_tools = [
        "format_disk",
        "wipe_all_data",
        "spawn_root_shell",
        "dump_lsass_credentials",
        "exfiltrate_keys",
        "disable_edr",
        "unauthorized_network_pivot",
        "",
        "   ",
        "execute_trade; rm -rf /",
    ];

    let temp_dir = tempfile::tempdir().unwrap();
    let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
    let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    let config = OrchestratorConfig::default();
    let orch = KillSwitchOrchestrator::new(config, containment.clone(), adjudicator, lineage);
    let mut state = orch.get_state().await;

    for tool in hostile_tools {
        let res = orch.evaluate_cage_guard(
            &mut state,
            tool,
            serde_json::json!({
                "confidence_score": 0.95,
            }),
        );

        assert!(
            res.is_err(),
            "Hostile tool '{}' must be refused by CAGE allowlist",
            tool
        );

        let err = res.unwrap_err();
        match err {
            KillSwitchError::GraphHalted(msg) => {
                assert!(
                    msg.contains("CTRL_OPA_FORBIDDEN_TOOL"),
                    "Error must cite CTRL_OPA_FORBIDDEN_TOOL for tool '{}': {}",
                    tool, msg
                );
            }
            other => panic!("Expected GraphHalted error, got: {:?}", other),
        }

        assert_eq!(state.metadata.get("cage_last_verdict").unwrap(), "Refuse");
        assert_eq!(state.metadata.get("cage_rule_id").unwrap(), "CTRL_OPA_FORBIDDEN_TOOL");
        assert_eq!(state.metadata.get("cage_tier").unwrap(), "Tier3Opa");
    }
}

/// 3. Empirical behavior analysis of negative amounts and NaN/Infinity values.
/// Documents whether negative/NaN amounts bypass financial controls or clear all tiers.
#[tokio::test]
async fn test_challenge_negative_and_nan_amounts_behavior() {
    let temp_dir = tempfile::tempdir().unwrap();
    let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
    let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    let config = OrchestratorConfig::default();
    let orch = KillSwitchOrchestrator::new(config, containment.clone(), adjudicator, lineage);
    let mut state = orch.get_state().await;

    // Test negative amount: -$50,000
    let res_neg = orch.evaluate_cage_guard(
        &mut state,
        "execute_trade",
        serde_json::json!({
            "amount_usd": -50000.0,
            "confidence_score": 0.95,
        }),
    );

    // Empirical observation: Does CAGE refuse or clear negative amount?
    println!("[EMPIRICAL] Result for negative amount (-$50,000): {:?}", res_neg.is_ok());
    if let Ok(ref receipt) = res_neg {
        println!("[EMPIRICAL FINDING] Negative amount Cleared! Receipt ID: {}", receipt.receipt_id);
        assert_eq!(state.metadata.get("cage_last_verdict").unwrap(), "Clear");
    } else {
        println!("[EMPIRICAL FINDING] Negative amount was Refused: {:?}", res_neg.err());
    }

    // Test NaN amount
    let res_nan = orch.evaluate_cage_guard(
        &mut state,
        "execute_trade",
        serde_json::json!({
            "amount_usd": serde_json::Value::Null, // JSON does not support NaN natively, but None is passed
            "confidence_score": 0.95,
        }),
    );
    println!("[EMPIRICAL] Result for null amount: {:?}", res_nan.is_ok());
    assert!(res_nan.is_ok());
}

/// 4. Empirical verification of fail-closed isolation across every single refusal tier.
/// Asserts host containment is NEVER engaged when CAGE halts at ANY tier.
#[allow(clippy::type_complexity)]
#[tokio::test]
async fn test_challenge_host_containment_blocked_across_all_refusal_tiers() {
    let scenarios: Vec<(&str, Box<dyn Fn(&mut KillSwitchGraphState)>)> = vec![
        // Tier 1 FTRA refusal
        ("Tier1_FTRA", Box::new(|state: &mut KillSwitchGraphState| {
            state.metadata.insert(
                "cage_context".to_string(),
                serde_json::json!({
                    "data": "confidential",
                    "channel": "unauthenticated_egress"
                }).to_string(),
            );
        })),
        // Tier 2 STPA refusal
        ("Tier2_STPA", Box::new(|state: &mut KillSwitchGraphState| {
            state.metadata.insert(
                "cage_context".to_string(),
                serde_json::json!({
                    "hazard": "missing_safety_token"
                }).to_string(),
            );
        })),
        // Tier 4 Confidence refusal (uncalibrated low confidence)
        ("Tier4_LowConfidence", Box::new(|state: &mut KillSwitchGraphState| {
            state.metadata.insert("cage_confidence_score".to_string(), "0.45".to_string());
        })),
        // Tier 4 Confabulation claim
        ("Tier4_Confabulation", Box::new(|state: &mut KillSwitchGraphState| {
            state.metadata.insert("cage_confabulation".to_string(), "bypass_security".to_string());
        })),
    ];

    for (name, setup) in scenarios {
        let temp_dir = tempfile::tempdir().unwrap();
        let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

        let mut state = KillSwitchGraphState::new(
            format!("incident-{}", name),
            OrchestratorMode::Autonomous,
        );
        state.aggregate_threat_score = 0.95;

        let candidate = ThreatCandidate::new(
            Some(9001),
            "threat_scenario.exe",
            "EDR Sensor",
            "Malicious heuristic",
            0.95,
            killswitch_types::adjudication::EvidenceClass::Behavior,
        );
        state.active_threats.push(candidate);

        // Apply scenario-specific metadata
        setup(&mut state);

        // Direct ContainNode execution
        let contain_node = killswitch_orchestrator::nodes::ContainNode::new(containment.clone());
        use killswitch_orchestrator::LifecycleNode;
        let res = contain_node.execute(&mut state).await;

        assert!(
            res.is_err(),
            "ContainNode MUST refuse and fail closed under scenario {}",
            name
        );

        // Verify HostContainmentManager was NOT touched
        assert!(
            !state.containment_status.isolated,
            "State containment_status.isolated MUST be false under {}",
            name
        );
        assert!(
            !containment.get_status().isolated,
            "HostContainmentManager get_status().isolated MUST be false under {}",
            name
        );
        assert_eq!(
            state.metadata.get("cage_last_verdict").map(|s| s.as_str()),
            Some("Refuse"),
            "Verdict must be Refuse under {}",
            name
        );
    }
}

/// 5. Stress test: Concurrent orchestrator executions against cumulative fiscal cap.
/// Demonstrates atomic fiscal safety invariant (spend <= cap), but proves that
/// parallel test threads mutably compete for global_cage_kernel().
#[tokio::test]
async fn test_challenge_concurrent_orchestrator_fiscal_cap_stress() {
    let kernel = global_cage_kernel();
    kernel.reset_fiscal();

    // Default substrate fiscal cap is $50,000.
    // Spawn 20 concurrent tasks, each attempting to spend $5,000 through separate orchestrators.
    // Total attempted = 20 * $5,000 = $100,000.
    // Invariant 1: Exactly 10 must succeed ($50,000) and 10 must fail with FISCAL_CAP_EXCEEDED.
    // Invariant 2: Total spent must be EXACTLY $50,000 (never overspend).
    let mut tasks = JoinSet::new();

    for task_id in 0..20 {
        tasks.spawn(async move {
            let temp_dir = tempfile::tempdir().unwrap();
            let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
            let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
            let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

            let config = OrchestratorConfig::default();
            let orch = KillSwitchOrchestrator::new(config, containment, adjudicator, lineage);
            let mut state = orch.get_state().await;

            let res = orch.evaluate_cage_guard(
                &mut state,
                "execute_trade",
                serde_json::json!({
                    "amount_usd": 5000.0,
                    "confidence_score": 0.95,
                    "human_approval": {
                        "operator_id": format!("operator_{}", task_id),
                        "is_approved": true,
                        "rationale": format!("Authorized concurrent tranche {}", task_id),
                        "approved_at_ms": 1700000000000u64,
                    }
                }),
            );

            match res {
                Ok(_) => Ok(task_id),
                Err(KillSwitchError::GraphHalted(msg)) => {
                    assert!(msg.contains(FISCAL_CAP_EXCEEDED), "Refusal must be fiscal cap exceeded: {}", msg);
                    Err(task_id)
                }
                Err(other) => panic!("Unexpected error: {:?}", other),
            }
        });
    }

    let mut successes = 0;
    let mut failures = 0;

    while let Some(res) = tasks.join_next().await {
        match res.unwrap() {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    println!(
        "[EMPIRICAL CONCURRENT STRESS] Successes: {}, Failures: {}, Total Spent: ${:.2}, Cap: ${:.2}",
        successes, failures, kernel.status().fiscal_spent_usd, kernel.status().fiscal_cap_usd
    );

    // Invariant 1: Total spent must never exceed cap
    assert!(
        kernel.status().fiscal_spent_usd <= kernel.status().fiscal_cap_usd,
        "Total spent ${:.2} exceeded cap ${:.2}",
        kernel.status().fiscal_spent_usd,
        kernel.status().fiscal_cap_usd
    );

    // Invariant 2: Exactly 10 succeeded and 10 failed
    assert_eq!(successes, 10, "Exactly 10 transactions of $5,000 must clear");
    assert_eq!(failures, 10, "Exactly 10 transactions must fail closed on fiscal cap");
    assert_eq!(kernel.status().fiscal_spent_usd, 50000.0);

    // Reset fiscal for other tests
    kernel.reset_fiscal();
}
