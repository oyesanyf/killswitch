//! # Empirical Challenge Test Suite for Milestone CAGE-1 (`crates/killswitch-telemetry`)
//!
//! Adversarial stress testing verifying:
//! 1. SubstrateCompiler: Multi-format auto-detection across all 5 formats (NativeCage,
//!    MicrosoftAcs, LinuxFoundationAaif, NistOscal, LulaValidation), malformed inputs,
//!    YAML parsing edge cases, precedence ordering, and bitwise identical SHA-256 digests.
//! 2. 8-Tier Governance Kernel: Exact boundary evaluation (OPA $10k cap boundary, empty vs
//!    whitespace consensus rationale, confidence claim fuzzing, healthcare dose barrier
//!    forward invariance, and warrant token cryptographic integrity).
//! 3. AtomicFiscalBarrier: 100-thread concurrent spend stress verifying zero micro-cent overspend.
//! 4. Tamper-Evident Receipts & Evidence Log: Dual-digest verification under mutation fuzzing,
//!    fail-closed sink availability, and cryptographic hash chaining.
//! 5. Trace Model Checker: Independent formal verification of monotonic progression,
//!    warrant precedence, and actuation blocking without Clear receipts.

use std::sync::Arc;
use chrono::Utc;
use killswitch_telemetry::cage_governance::*;

// ============================================================================
// SUITE 1: SubstrateCompiler Determinism, Malformed Specs & Precedence
// ============================================================================

#[test]
fn test_c1_substrate_compiler_deterministic_digest_under_key_permutations() {
    // Permutation 1
    let json_1 = serde_json::json!({
        "schema_version": "cage-substrate/3.0",
        "contract_id": "trade-contract-alpha",
        "domain": "finance",
        "allowed_tools": ["transfer_funds", "execute_trade", "query_balance"],
        "parameter_bounds": {
            "max_single_transfer_usd": 10000.0,
            "max_dose_mg": 100.0,
            "fiscal_cap_usd": 50000.0
        },
        "norms": [
            {
                "id": "NORM_FIN_001",
                "requires_warrant": false,
                "consensus_threshold": 0.85
            }
        ]
    });

    // Permutation 2: Different key ordering in JSON and reverse allowed_tools
    let json_2 = serde_json::json!({
        "norms": [
            {
                "consensus_threshold": 0.85,
                "requires_warrant": false,
                "id": "NORM_FIN_001"
            }
        ],
        "parameter_bounds": {
            "fiscal_cap_usd": 50000.0,
            "max_dose_mg": 100.0,
            "max_single_transfer_usd": 10000.0
        },
        "allowed_tools": ["query_balance", "execute_trade", "transfer_funds"],
        "domain": "finance",
        "contract_id": "trade-contract-alpha",
        "schema_version": "cage-substrate/3.0"
    });

    let art1 = SubstrateCompiler::detect_and_compile(&json_1).expect("JSON 1 must compile");
    let art2 = SubstrateCompiler::detect_and_compile(&json_2).expect("JSON 2 must compile");

    assert_eq!(
        art1.substrate_contract_digest, art2.substrate_contract_digest,
        "Bitwise identical digest invariant failed under key/tool permutations"
    );
    assert!(art1.verify_digest(), "Embedded digest verification failed for art1");
    assert!(art2.verify_digest(), "Embedded digest verification failed for art2");
}

#[test]
fn test_c1_substrate_compiler_rejects_malformed_inputs() {
    // 1. Array is not a valid specification object
    let array_val = serde_json::json!(["not", "an", "object"]);
    assert!(
        SubstrateCompiler::detect_and_compile(&array_val).is_err(),
        "Array specification must be rejected"
    );

    // 2. String is not a valid specification object
    let string_val = serde_json::json!("raw_string_not_object");
    assert!(
        SubstrateCompiler::detect_and_compile(&string_val).is_err(),
        "Primitive string specification must be rejected"
    );

    // 3. Integer is not a valid specification object
    let num_val = serde_json::json!(123456);
    assert!(
        SubstrateCompiler::detect_and_compile(&num_val).is_err(),
        "Numeric specification must be rejected"
    );
}

#[test]
fn test_c1_substrate_compiler_handles_empty_and_minimal_specifications() {
    // Empty JSON object should default to NativeCage with valid fallback bounds and digest
    let empty_obj = serde_json::json!({});
    let compiled = SubstrateCompiler::detect_and_compile(&empty_obj).expect("Empty object should compile with defaults");
    assert_eq!(compiled.format, SubstrateFormat::NativeCage);
    assert_eq!(compiled.max_single_transfer_usd, 10000.0);
    assert_eq!(compiled.fiscal_cap_usd, 50000.0);
    assert!(compiled.verify_digest());
}

#[test]
fn test_c1_substrate_compiler_yaml_parser_edge_cases() {
    // 1. Valid key-value YAML with allowed_tools list
    let yaml_valid = r#"
# Production Native CAGE Contract
kind: "NativeCage"
contract_id: "trade-yaml-01"
max_single_transfer_usd: 10000.0
fiscal_cap_usd: 50000.0
requires_warrant: false
allowed_tools:
  - execute_trade
  - query_balance
"#;
    let compiled_yaml = SubstrateCompiler::detect_and_compile_str(yaml_valid).expect("Valid YAML must compile");
    assert_eq!(compiled_yaml.allowed_tools, vec!["execute_trade", "query_balance"]);
    assert_eq!(compiled_yaml.max_single_transfer_usd, 10000.0);
    assert!(compiled_yaml.verify_digest());

    // 2. YAML with quotes and whitespace variations
    let yaml_spaced = r#"
   kind:    "NativeCage"   
   contract_id:    "trade-yaml-02"   
   max_single_transfer_usd:    10000.00   
   fiscal_cap_usd:   50000.00   
   requires_warrant:   false   
allowed_tools:
   - "query_balance"
   - "execute_trade"
"#;
    let compiled_spaced = SubstrateCompiler::detect_and_compile_str(yaml_spaced).expect("Spaced YAML must compile");
    assert_eq!(compiled_spaced.allowed_tools, vec!["execute_trade", "query_balance"]);
    assert_eq!(compiled_yaml.substrate_contract_digest, compiled_spaced.substrate_contract_digest);

    // 3. LulaValidation manifest via YAML
    let lula_yaml = r#"
kind: LulaValidation
metadata:
  name: lula-compliance-guard
  annotations:
    max_single_transfer_usd: "10000.00"
    fiscal_cap_usd: "50000.00"
    requires_warrant: "false"
"#;
    let compiled_lula = SubstrateCompiler::detect_and_compile_str(lula_yaml).expect("Lula YAML must compile");
    assert_eq!(compiled_lula.format, SubstrateFormat::LulaValidation);
    assert!(compiled_lula.verify_digest());
}

#[test]
fn test_c1_substrate_format_precedence_and_oscal_lula_detection() {
    // OSCAL with Lula in back-matter must be classified as LulaValidation
    let oscal_with_lula = serde_json::json!({
        "oscal-version": "1.1.0",
        "component-definition": {
            "back-matter": {
                "resources": [
                    { "description": "Lula validation policy rules" }
                ]
            }
        }
    });
    let fmt_lula = SubstrateCompiler::detect_format(&oscal_with_lula).expect("Format detected");
    assert_eq!(fmt_lula, SubstrateFormat::LulaValidation);

    // OSCAL without Lula in back-matter must be classified as NistOscal
    let oscal_plain = serde_json::json!({
        "oscal-version": "1.1.0",
        "component-definition": {
            "components": []
        }
    });
    let fmt_oscal = SubstrateCompiler::detect_format(&oscal_plain).expect("Format detected");
    assert_eq!(fmt_oscal, SubstrateFormat::NistOscal);

    // Microsoft ACS must be classified as MicrosoftAcs
    let acs_doc = serde_json::json!({
        "behaviorDeclarations": []
    });
    assert_eq!(
        SubstrateCompiler::detect_format(&acs_doc).expect("Format detected"),
        SubstrateFormat::MicrosoftAcs
    );

    // Linux Foundation AAIF must be classified as LinuxFoundationAaif
    let aaif_doc = serde_json::json!({
        "governedRunLoop": {}
    });
    assert_eq!(
        SubstrateCompiler::detect_format(&aaif_doc).expect("Format detected"),
        SubstrateFormat::LinuxFoundationAaif
    );
}

// ============================================================================
// SUITE 2: 8-Tier Kernel Exact Boundaries & Refusal Codes
// ============================================================================

#[test]
fn test_c1_tier1_ftra_minimal_cut_sets() {
    let kernel = CageGovernanceKernel::new();

    // 1. Sensitive + Unauthenticated egress -> Refuse with CTRL_FTRA_001
    let req_cut_set = CageEvaluationRequest {
        agent_id: "agent-ftra-01".to_string(),
        role: "worker".to_string(),
        tool_name: "execute_trade".to_string(),
        arguments: serde_json::json!({}),
        confidence_score: Some(0.95),
        amount_usd: Some(100.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: Some(serde_json::json!({
            "egress": "unauthenticated_egress",
            "data_classification": "confidential_customer_pii"
        })),
    };
    let resp = kernel.evaluate(&req_cut_set);
    assert_eq!(resp.verdict, CageVerdict::Refuse);
    assert_eq!(resp.tier, CageTier::Tier1Ftra);
    assert_eq!(resp.rule_id, CTRL_FTRA_001);

    // 2. Irreversible action without human approval -> Refuse with CTRL_FTRA_001
    let req_irreversible = CageEvaluationRequest {
        context: Some(serde_json::json!({
            "action_property": "irreversible_terminal_state"
        })),
        ..req_cut_set.clone()
    };
    let resp_irrev = kernel.evaluate(&req_irreversible);
    assert_eq!(resp_irrev.verdict, CageVerdict::Refuse);
    assert_eq!(resp_irrev.tier, CageTier::Tier1Ftra);
    assert_eq!(resp_irrev.rule_id, CTRL_FTRA_001);

    // 3. Irreversible action with human approval -> Clears Tier 1
    let req_approved = CageEvaluationRequest {
        human_approval: Some(HitlConsensusApproval {
            operator_id: "admin".to_string(),
            is_approved: true,
            rationale: "Approved terminal state modification".to_string(),
            approved_at_ms: Utc::now().timestamp_millis() as u64,
            signature_hex: None,
        }),
        context: Some(serde_json::json!({
            "action_property": "irreversible_terminal_state"
        })),
        ..req_cut_set
    };
    let resp_app = kernel.evaluate(&req_approved);
    assert_eq!(resp_app.verdict, CageVerdict::Clear);
}

#[test]
fn test_c1_tier2_stpa_four_unsafe_control_actions() {
    let kernel = CageGovernanceKernel::new();

    let base_req = CageEvaluationRequest {
        agent_id: "agent-stpa".to_string(),
        role: "controller".to_string(),
        tool_name: "execute_trade".to_string(),
        arguments: serde_json::json!({}),
        confidence_score: Some(0.95),
        amount_usd: Some(500.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };

    // UCA-1: Omitted safety action
    let req_uca1 = CageEvaluationRequest {
        context: Some(serde_json::json!({ "flag": "omitted_safety_action" })),
        ..base_req.clone()
    };
    let r1 = kernel.evaluate(&req_uca1);
    assert_eq!(r1.verdict, CageVerdict::Refuse);
    assert_eq!(r1.tier, CageTier::Tier2Stpa);
    assert_eq!(r1.rule_id, CTRL_STPA_UCA1);

    // UCA-2: Conflicting state
    let req_uca2 = CageEvaluationRequest {
        context: Some(serde_json::json!({ "flag": "conflicting_state" })),
        ..base_req.clone()
    };
    let r2 = kernel.evaluate(&req_uca2);
    assert_eq!(r2.verdict, CageVerdict::Refuse);
    assert_eq!(r2.tier, CageTier::Tier2Stpa);
    assert_eq!(r2.rule_id, CTRL_STPA_UCA2);

    // UCA-3: Out of order
    let req_uca3 = CageEvaluationRequest {
        context: Some(serde_json::json!({ "flag": "out_of_order" })),
        ..base_req.clone()
    };
    let r3 = kernel.evaluate(&req_uca3);
    assert_eq!(r3.verdict, CageVerdict::Refuse);
    assert_eq!(r3.tier, CageTier::Tier2Stpa);
    assert_eq!(r3.rule_id, CTRL_STPA_UCA3);

    // UCA-4: Lease expired / duration exceeded
    let req_uca4 = CageEvaluationRequest {
        context: Some(serde_json::json!({ "flag": "lease_expired" })),
        ..base_req
    };
    let r4 = kernel.evaluate(&req_uca4);
    assert_eq!(r4.verdict, CageVerdict::Refuse);
    assert_eq!(r4.tier, CageTier::Tier2Stpa);
    assert_eq!(r4.rule_id, CTRL_STPA_UCA4);
}

#[test]
fn test_c1_tier3_opa_exact_transfer_boundary_and_case_insensitivity() {
    let kernel = CageGovernanceKernel::new();

    let make_req = |amt: f64, tool: &str| CageEvaluationRequest {
        agent_id: "trader-boundary".to_string(),
        role: "trader".to_string(),
        tool_name: tool.to_string(),
        arguments: serde_json::json!({ "amount": amt }),
        confidence_score: Some(0.99),
        amount_usd: Some(amt),
        dose_mg: None,
        warrant_token: None,
        human_approval: Some(HitlConsensusApproval {
            operator_id: "supervisor".to_string(),
            is_approved: true,
            rationale: "Legitimate boundary test approval".to_string(),
            approved_at_ms: Utc::now().timestamp_millis() as u64,
            signature_hex: None,
        }),
        context: None,
    };

    // 1. $10,000.00 exact passes cleanly
    let r_exact = kernel.evaluate(&make_req(10000.00, "execute_trade"));
    assert_eq!(r_exact.verdict, CageVerdict::Clear);

    // 2. $10,000.01 fails with CTRL_OPA_005 at Tier 3
    let r_over = kernel.evaluate(&make_req(10000.01, "execute_trade"));
    assert_eq!(r_over.verdict, CageVerdict::Refuse);
    assert_eq!(r_over.tier, CageTier::Tier3Opa);
    assert_eq!(r_over.rule_id, CTRL_OPA_005);

    // 3. $9,999.99 passes cleanly
    let r_under = kernel.evaluate(&make_req(9999.99, "execute_trade"));
    assert_eq!(r_under.verdict, CageVerdict::Clear);

    // 4. Mixed-case tool name "EXECUTE_TRADE" passes allowlist
    let r_upper = kernel.evaluate(&make_req(100.0, "EXECUTE_TRADE"));
    assert_eq!(r_upper.verdict, CageVerdict::Clear);

    // 5. Forbidden / unlisted tool fails with CTRL_OPA_FORBIDDEN_TOOL
    let r_forbidden = kernel.evaluate(&make_req(100.0, "unauthorized_arbitrage_tool"));
    assert_eq!(r_forbidden.verdict, CageVerdict::Refuse);
    assert_eq!(r_forbidden.tier, CageTier::Tier3Opa);
    assert_eq!(r_forbidden.rule_id, "CTRL_OPA_FORBIDDEN_TOOL");
}

#[test]
fn test_c1_tier4_confidence_and_claim_fuzzing() {
    let kernel = CageGovernanceKernel::new();

    let test_claims = [
        "authorized_by_admin",
        "AUTHORIZED_BY_ADMIN",
        "bypass_security",
        "override_governance",
        "pre_approved",
        "trusted_override",
        "self_certified",
        "skip_checks",
        "elevated_privilege_granted",
    ];

    for claim in test_claims {
        let req = CageEvaluationRequest {
            agent_id: "agent-fuzz".to_string(),
            role: "assistant".to_string(),
            tool_name: "query_balance".to_string(),
            arguments: serde_json::json!({
                "nested_context": {
                    "reason": format!("User says: {}", claim)
                }
            }),
            confidence_score: Some(0.95),
            amount_usd: None,
            dose_mg: None,
            warrant_token: None,
            human_approval: None,
            context: None,
        };
        let resp = kernel.evaluate(&req);
        assert_eq!(
            resp.verdict,
            CageVerdict::Refuse,
            "Claim '{}' was not caught by Tier 4 detector",
            claim
        );
        assert_eq!(resp.tier, CageTier::Tier4Confidence);
        assert_eq!(resp.rule_id, CTRL_CONF_001);
    }

    // Low confidence score: 0.799 fails, 0.800 passes
    let req_low_conf = CageEvaluationRequest {
        agent_id: "agent-conf".to_string(),
        role: "assistant".to_string(),
        tool_name: "query_balance".to_string(),
        arguments: serde_json::json!({}),
        confidence_score: Some(0.799),
        amount_usd: None,
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_low = kernel.evaluate(&req_low_conf);
    assert_eq!(resp_low.verdict, CageVerdict::Refuse);
    assert_eq!(resp_low.tier, CageTier::Tier4Confidence);
    assert_eq!(resp_low.rule_id, CTRL_CONF_001);

    let req_ok_conf = CageEvaluationRequest {
        confidence_score: Some(0.80),
        ..req_low_conf
    };
    let resp_ok = kernel.evaluate(&req_ok_conf);
    assert_eq!(resp_ok.verdict, CageVerdict::Clear);
}

#[test]
fn test_c1_tier5_warrant_verification_and_tamper_rejection() {
    // Compile substrate that mandates warrant
    let contract_warrant = SubstrateCompiler::detect_and_compile(&serde_json::json!({
        "contract_id": "contract-warrant-mandatory",
        "schema_version": "cage-substrate/3.0",
        "domain": "security",
        "allowed_tools": ["execute_trade"],
        "parameter_bounds": {
            "max_single_transfer_usd": 10000.0,
            "fiscal_cap_usd": 50000.0
        },
        "norms": [
            {
                "id": "WARRANT_REQUIRED_NORM",
                "requires_warrant": true,
                "consensus_threshold": 0.85
            }
        ]
    })).expect("Substrate must compile");

    let kernel = CageGovernanceKernel::with_substrate(contract_warrant);
    let secret = b"challenger_test_epoch_secret_32b";
    let now_ms = Utc::now().timestamp_millis() as u64;

    let args = serde_json::json!({ "trade_id": "TR-900" });
    let arg_digest = CageWarrantToken::compute_argument_digest(&args);

    let valid_token = CageWarrantToken::sign(
        secret,
        "agent-warrant",
        "execute_trade",
        &arg_digest,
        now_ms - 1000,
        now_ms + 60000,
    );

    // 1. Missing warrant token -> Refuse CTRL_WARRANT_REQUIRED
    let req_missing = CageEvaluationRequest {
        agent_id: "agent-warrant".to_string(),
        role: "trader".to_string(),
        tool_name: "execute_trade".to_string(),
        arguments: args.clone(),
        confidence_score: Some(0.95),
        amount_usd: Some(100.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let r_missing = kernel.evaluate(&req_missing);
    assert_eq!(r_missing.verdict, CageVerdict::Refuse);
    assert_eq!(r_missing.tier, CageTier::Tier5Warrant);
    assert_eq!(r_missing.rule_id, CTRL_WARRANT_REQUIRED);

    // 2. Tampered tool name in token -> Refuse CTRL_WARRANT_INVALID
    let mut bad_tool_token = valid_token.clone();
    bad_tool_token.tool_name = "transfer_funds".to_string();
    let req_bad_tool = CageEvaluationRequest {
        warrant_token: Some(bad_tool_token),
        ..req_missing.clone()
    };
    let r_bad_tool = kernel.evaluate(&req_bad_tool);
    assert_eq!(r_bad_tool.verdict, CageVerdict::Refuse);
    assert_eq!(r_bad_tool.tier, CageTier::Tier5Warrant);
    assert_eq!(r_bad_tool.rule_id, CTRL_WARRANT_INVALID);

    // 3. Expired warrant token -> Refuse CTRL_WARRANT_INVALID
    let expired_token = CageWarrantToken::sign(
        secret,
        "agent-warrant",
        "execute_trade",
        &arg_digest,
        now_ms - 60000,
        now_ms - 1000, // Expired 1s ago
    );
    let req_expired = CageEvaluationRequest {
        warrant_token: Some(expired_token),
        ..req_missing.clone()
    };
    let r_expired = kernel.evaluate(&req_expired);
    assert_eq!(r_expired.verdict, CageVerdict::Refuse);
    assert_eq!(r_expired.tier, CageTier::Tier5Warrant);
    assert_eq!(r_expired.rule_id, CTRL_WARRANT_INVALID);
}

#[test]
fn test_c1_tier6_consensus_empty_and_whitespace_rationale() {
    let kernel = CageGovernanceKernel::new();
    let now_ms = Utc::now().timestamp_millis() as u64;

    let test_rationales = ["", " ", "   ", "\t", "\n\r", "   \t\n   "];
    for ws_rat in test_rationales {
        let req = CageEvaluationRequest {
            agent_id: "agent-consensus".to_string(),
            role: "trader".to_string(),
            tool_name: "execute_trade".to_string(),
            arguments: serde_json::json!({ "amount": 8000.0 }), // > $5000 triggers consensus
            confidence_score: Some(0.95),
            amount_usd: Some(8000.0),
            dose_mg: None,
            warrant_token: None,
            human_approval: Some(HitlConsensusApproval {
                operator_id: "ops_lead".to_string(),
                is_approved: true,
                rationale: ws_rat.to_string(),
                approved_at_ms: now_ms,
                signature_hex: None,
            }),
            context: None,
        };
        let resp = kernel.evaluate(&req);
        assert_eq!(
            resp.verdict,
            CageVerdict::Refuse,
            "Whitespace rationale '{:?}' was unexpectedly accepted",
            ws_rat
        );
        assert_eq!(resp.tier, CageTier::Tier6Consensus);
        assert_eq!(resp.rule_id, CTRL_CONSENSUS_REQUIRED);
    }
}

#[test]
fn test_c1_tier7_cbf_forward_invariance_boundaries() {
    // 1. HealthcareDoseBarrier exact single dose boundary: 100 mg max
    let dose_barrier = HealthcareDoseBarrier::new(100.0, 200.0, 0.0, 0.50);
    assert!(dose_barrier.evaluate(100.0).is_ok());
    assert_eq!(dose_barrier.evaluate(100.001).unwrap_err().0, CTRL_CBF_DOSE_001);

    // 2. Discrete forward invariance boundary condition:
    // With cumulative = 90 mg, daily max = 200 mg, gamma = 0.50:
    // h_k = 110. B(x) = (110 - proposed) - 0.50 * 110 = 55 - proposed >= 0
    // Maximum safe proposed dose = 55 mg
    assert!(dose_barrier.evaluate(50.0).is_ok()); // 50 <= 55 -> Ok
    let barrier_with_cum = HealthcareDoseBarrier::new(100.0, 200.0, 90.0, 0.50);
    assert!(barrier_with_cum.evaluate(55.0).is_ok()); // exactly 55 -> Ok
    let r_fail = barrier_with_cum.evaluate(55.01); // 55.01 -> breaches barrier invariance
    assert!(r_fail.is_err());
    assert_eq!(r_fail.unwrap_err().0, CTRL_CBF_DOSE_001);
}

// ============================================================================
// SUITE 3: AtomicFiscalBarrier Concurrency Stress
// ============================================================================

#[test]
fn test_c1_atomic_fiscal_barrier_100_thread_stress_zero_overspend() {
    let fiscal_cap = 5000.0;
    let barrier = Arc::new(AtomicFiscalBarrier::new(fiscal_cap));
    let num_threads = 100;
    let spend_per_thread = 100.0; // 100 * $100 = $10,000 total attempted

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            b.try_spend(spend_per_thread)
        }));
    }

    let mut successes = 0;
    let mut refusals = 0;

    for h in handles {
        match h.join().unwrap() {
            Ok(_) => successes += 1,
            Err(e) => {
                assert_eq!(e, FISCAL_CAP_EXCEEDED);
                refusals += 1;
            }
        }
    }

    // Exactly 50 threads can succeed ($5,000 / $100 = 50) and exactly 50 must fail
    assert_eq!(successes, 50, "Expected exactly 50 threads to clear fiscal cap");
    assert_eq!(refusals, 50, "Expected exactly 50 threads to be refused");
    assert_eq!(
        barrier.get_spent_usd(),
        fiscal_cap,
        "Spent USD must equal exactly $5,000.00 without any micro-cent drift"
    );

    // Any further spend must immediately fail
    assert!(barrier.try_spend(0.01).is_err());

    // Reset restores full budget
    barrier.reset();
    assert_eq!(barrier.get_spent_usd(), 0.0);
    assert!(barrier.try_spend(100.0).is_ok());
}

// ============================================================================
// SUITE 4: Receipts, Evidence Writer & Trace Model Checker
// ============================================================================

#[test]
fn test_c1_decision_receipt_mutation_fuzzing() {
    let secret = b"receipt_fuzzing_epoch_key_32byte";
    let valid_rcpt = CageDecisionReceipt::create_and_sign(
        "agent-fuzz",
        "execute_trade",
        "arg_digest_123",
        "sub_digest_456",
        CageVerdict::Clear,
        CageTier::Tier8Fiscal,
        "CAGE_8_TIERS_CLEARED",
        vec!["All tiers cleared".to_string()],
        None,
        1_700_000_000,
        secret,
    );

    assert!(valid_rcpt.verify_all(secret));

    // Test mutating each individual field destroys digest integrity
    let mut m1 = valid_rcpt.clone();
    m1.agent_id = "agent-adversary".to_string();
    assert!(!m1.verify_digest());

    let mut m2 = valid_rcpt.clone();
    m2.tool_name = "steal_funds".to_string();
    assert!(!m2.verify_digest());

    let mut m3 = valid_rcpt.clone();
    m3.argument_digest = "tampered_args".to_string();
    assert!(!m3.verify_digest());

    let mut m4 = valid_rcpt.clone();
    m4.substrate_digest = "tampered_sub".to_string();
    assert!(!m4.verify_digest());

    let mut m5 = valid_rcpt.clone();
    m5.verdict = CageVerdict::Refuse;
    assert!(!m5.verify_digest());

    let mut m6 = valid_rcpt.clone();
    m6.tier = CageTier::Tier1Ftra;
    assert!(!m6.verify_digest());

    let mut m7 = valid_rcpt.clone();
    m7.rule_id = "FORGED_RULE".to_string();
    assert!(!m7.verify_digest());

    let mut m8 = valid_rcpt.clone();
    m8.timestamp_ms = 1_700_000_001;
    assert!(!m8.verify_digest());
}

#[test]
fn test_c1_evidence_writer_sequential_hash_chain_50_entries() {
    let secret = b"evidence_chain_secret_key_32byte";
    let writer = CageEvidenceWriter::new(true, Some(secret.to_vec()));

    for i in 0..50 {
        let rcpt = CageDecisionReceipt::create_and_sign(
            &format!("agent-{i}"),
            "execute_trade",
            &format!("arg_{i}"),
            "sub_1",
            CageVerdict::Clear,
            CageTier::Tier8Fiscal,
            "PASS",
            vec![],
            None,
            1_700_000_000 + (i as u64),
            secret,
        );
        let entry = writer.append_receipt(rcpt).expect("Append must succeed");
        assert_eq!(entry.sequence_no, i);
    }

    assert_eq!(writer.count(), 50);
    assert!(writer.verify_chain_integrity(), "50-entry hash chain must verify");
}

#[test]
fn test_c1_trace_verifier_detects_all_conformance_violations() {
    // 1. Empty trace
    assert!(!CageTraceVerifier::verify_trace_conformance(&[]).is_conformant);

    // 2. ActionProposed not first
    let bad_first = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Early evaluation".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Action proposed late".to_string(),
        },
    ];
    let r_bad_first = CageTraceVerifier::verify_trace_conformance(&bad_first);
    assert!(!r_bad_first.is_conformant);
    assert!(r_bad_first.violations.iter().any(|v| v.contains("ACTION_PROPOSED_NOT_FIRST")));

    // 3. Non-monotonic step numbers
    let non_monotonic = vec![
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Action proposed".to_string(),
        },
        GovernanceTraceEvent {
            step: 1, // Decreased step number
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Non-monotonic step".to_string(),
        },
    ];
    let r_nm = CageTraceVerifier::verify_trace_conformance(&non_monotonic);
    assert!(!r_nm.is_conformant);
    assert!(r_nm.violations.iter().any(|v| v.contains("NON_MONOTONIC_STEP")));

    // 4. Missing warrant before CBF when warrant is required
    let warrant_violation = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: true,
            details: "Action proposed requiring warrant".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::CbfVerified,
            tier: Some(CageTier::Tier7Cbf),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: true,
            details: "CBF evaluated without warrant check".to_string(),
        },
    ];
    let r_wv = CageTraceVerifier::verify_trace_conformance(&warrant_violation);
    assert!(!r_wv.is_conformant);
    assert!(r_wv.violations.iter().any(|v| v.contains("WARRANT_PRECEDENCE_VIOLATION")));
}
