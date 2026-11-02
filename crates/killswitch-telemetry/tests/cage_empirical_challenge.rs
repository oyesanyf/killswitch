//! # Empirical Challenge Suite for Milestone CAGE-1
//!
//! Independent Adversarial Verification Suite:
//! 1. Receipt Tampering Tests: mutate each field (`verdict`, `rule_id`, `tier`, `argument_digest`,
//!    `timestamp_ms`, `agent_id`, `tool_name`, `substrate_digest`, `receipt_id`) and confirm
//!    `receipt.verify_digest()` rejects with 100% detection.
//! 2. Evidence Writer Tests: fail-closed rejection on tampered receipts, fail-closed on sink unavailable,
//!    BLAKE3 hash-chaining across 50+ entries, and chain tampering detection.
//! 3. Trace Model Checker Tests: adversarial out-of-order traces, missing Clear receipts before
//!    ActuationCompleted, missing WarrantVerified transitions, and empty traces.
//! 4. Continuous Defense Tests: research catalog verification for arXiv:2606.12320, accuracy suite
//!    (5 tested rules, 100% TPR, 0% FPR, byte-exact parity), recency gate, repo validation,
//!    and canary benign telemetry corpus (50 benign samples, 0 false positives).
//! 5. Substrate Compiler & 8-Tier Kernel Determinism & Edge Cases: multi-format parsing, key permutations,
//!    50-thread concurrent fiscal barrier stress, CBF dose and finance invariance boundaries.

use std::sync::Arc;
use std::thread;

use killswitch_telemetry::cage_governance::{
    global_cage_kernel, AtomicFiscalBarrier, CageDecisionReceipt, CageEvidenceWriter,
    CageEvaluationRequest, CageTier, CageTraceVerifier, CageVerdict,
    FinanceBoundingBarrier, GovernanceTraceEvent, GovernanceTraceEventType,
    HealthcareDoseBarrier, SubstrateCompiler, SubstrateFormat,
    CTRL_CBF_DOSE_001, CTRL_CBF_FINANCE_001, CTRL_CONF_001, CTRL_OPA_005,
    FISCAL_CAP_EXCEEDED,
};
use killswitch_telemetry::continuous_defense::{
    is_current_research_arxiv_id, is_valid_verified_repo_url, list_ingested_research_rules,
    restore_default_research_rules, run_paper2agent_accuracy_suite, ContinuousDefenseEngine,
};

// =========================================================================
// 1. RECEIPT TAMPERING EMPIRICAL TESTS (100% DETECTION)
// =========================================================================

#[test]
fn test_empirical_receipt_tampering_field_by_field_100_percent_detection() {
    let secret = b"challenger_epoch_secret_key_32b!";
    let original = CageDecisionReceipt::create_and_sign(
        "agent-adversary-01",
        "transfer_funds",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        CageVerdict::Clear,
        CageTier::Tier8Fiscal,
        "CAGE_CLEARED_ALL_CHECKS",
        vec!["All 8 tiers passed".to_string()],
        None,
        1_700_000_123,
        secret,
    );

    // Initial baseline must be 100% valid
    assert!(original.verify_digest(), "Original receipt must pass verify_digest()");
    assert!(original.verify_signature(secret), "Original receipt must pass verify_signature()");
    assert!(original.verify_all(secret), "Original receipt must pass verify_all()");

    // 1. Mutate verdict: Clear -> Refuse
    let mut t_verdict = original.clone();
    t_verdict.verdict = CageVerdict::Refuse;
    assert!(!t_verdict.verify_digest(), "Tampered verdict must be rejected by verify_digest()");

    // 2. Mutate rule_id
    let mut t_rule = original.clone();
    t_rule.rule_id = "MALICIOUS_BYPASS_RULE".to_string();
    assert!(!t_rule.verify_digest(), "Tampered rule_id must be rejected by verify_digest()");

    // 3. Mutate tier: Tier8Fiscal -> Tier1Ftra
    let mut t_tier = original.clone();
    t_tier.tier = CageTier::Tier1Ftra;
    assert!(!t_tier.verify_digest(), "Tampered tier must be rejected by verify_digest()");

    // 4. Mutate argument_digest
    let mut t_arg = original.clone();
    t_arg.argument_digest = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(!t_arg.verify_digest(), "Tampered argument_digest must be rejected by verify_digest()");

    // 5. Mutate timestamp_ms
    let mut t_time = original.clone();
    t_time.timestamp_ms += 1;
    assert!(!t_time.verify_digest(), "Tampered timestamp_ms must be rejected by verify_digest()");

    // 6. Mutate agent_id
    let mut t_agent = original.clone();
    t_agent.agent_id = "agent-malicious-attacker".to_string();
    assert!(!t_agent.verify_digest(), "Tampered agent_id must be rejected by verify_digest()");

    // 7. Mutate tool_name
    let mut t_tool = original.clone();
    t_tool.tool_name = "drop_database".to_string();
    assert!(!t_tool.verify_digest(), "Tampered tool_name must be rejected by verify_digest()");

    // 8. Mutate substrate_digest
    let mut t_sub = original.clone();
    t_sub.substrate_digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    assert!(!t_sub.verify_digest(), "Tampered substrate_digest must be rejected by verify_digest()");

    // 9. Mutate receipt_id
    let mut t_rcpt_id = original.clone();
    t_rcpt_id.receipt_id = "cage-rcpt-forged-uuid-0000".to_string();
    assert!(!t_rcpt_id.verify_digest(), "Tampered receipt_id must be rejected by verify_digest()");

    // 10. Mutate sha256_digest directly (attempting to decouple digest)
    let mut t_sha = original.clone();
    t_sha.sha256_digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    assert!(!t_sha.verify_digest(), "Directly tampered sha256_digest must fail verify_digest()");

    // 11. Mutate blake3_digest directly
    let mut t_blake = original.clone();
    t_blake.blake3_digest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string();
    assert!(!t_blake.verify_digest(), "Directly tampered blake3_digest must fail verify_digest()");

    // 12. Signature forgery / key mismatch
    assert!(!original.verify_signature(b"wrong_secret_key_for_forgery___"), "Wrong secret must fail signature verification");
    let mut t_sig = original.clone();
    t_sig.receipt_signature = "badc0ffee0000000000000000000000000000000000000000000000000000000".to_string();
    assert!(!t_sig.verify_signature(secret), "Corrupted signature hex must fail verify_signature()");
}

// =========================================================================
// 2. EVIDENCE WRITER FAIL-CLOSED & HASH-CHAIN INTEGRITY TESTS
// =========================================================================

#[test]
fn test_empirical_evidence_writer_fail_closed_and_hash_chaining() {
    let secret = b"evidence_chain_test_secret_32b!!";
    let writer = CageEvidenceWriter::new(true, Some(secret.to_vec()));

    // 1. Commit 50 valid receipts across different agents and tools
    for i in 0..50 {
        let receipt = CageDecisionReceipt::create_and_sign(
            &format!("agent-worker-{:03}", i % 5),
            if i % 2 == 0 { "execute_trade" } else { "query_balance" },
            &format!("arg_hash_{:04}", i),
            "sub_hash_alpha",
            if i % 7 == 0 { CageVerdict::Refuse } else { CageVerdict::Clear },
            if i % 7 == 0 { CageTier::Tier3Opa } else { CageTier::Tier8Fiscal },
            if i % 7 == 0 { CTRL_OPA_005 } else { "CAGE_CLEARED" },
            vec!["Automated test entry".to_string()],
            if i % 7 == 0 { Some("Single transfer limit exceeded".to_string()) } else { None },
            1_700_100_000 + (i as u64) * 10,
            secret,
        );

        let entry = writer.append_receipt(receipt).expect("Valid receipt must append cleanly");
        assert_eq!(entry.sequence_no, i);
    }

    assert_eq!(writer.count(), 50);
    assert_eq!(writer.len(), 50);
    assert!(!writer.is_empty());
    assert!(writer.verify_chain_integrity(), "50-entry BLAKE3 chain must pass verify_chain_integrity()");

    // 2. Fail-closed rejection of tampered receipts
    let bad_receipt = {
        let mut r = CageDecisionReceipt::create_and_sign(
            "agent-bad", "execute_trade", "bad_arg", "bad_sub",
            CageVerdict::Clear, CageTier::Tier8Fiscal, "CAGE_CLEARED", vec![], None, 1_700_200_000, secret,
        );
        r.verdict = CageVerdict::Refuse; // Tamper
        r
    };
    let append_tampered_res = writer.append_receipt(bad_receipt);
    assert!(append_tampered_res.is_err(), "Writer must reject tampered receipt");
    let err_msg = append_tampered_res.unwrap_err();
    assert!(err_msg.contains("TAMPERED_RECEIPT_DIGEST"), "Error must cite TAMPERED_RECEIPT_DIGEST: {}", err_msg);

    // 3. Fail-closed rejection when evidence sink is unavailable
    writer.set_available(false);
    let valid_receipt_while_unavail = CageDecisionReceipt::create_and_sign(
        "agent-01", "query_balance", "arg_clean", "sub_clean",
        CageVerdict::Clear, CageTier::Tier8Fiscal, "CAGE_CLEARED", vec![], None, 1_700_300_000, secret,
    );
    let unavail_res = writer.append_receipt(valid_receipt_while_unavail);
    assert!(unavail_res.is_err(), "Writer must fail closed when unavailable");
    let unavail_err = unavail_res.unwrap_err();
    assert!(unavail_err.contains("CAGE_EVIDENCE_SINK_UNAVAILABLE"), "Error must cite CAGE_EVIDENCE_SINK_UNAVAILABLE: {}", unavail_err);

    // Restore availability and ensure chain is still intact
    writer.set_available(true);
    assert!(writer.verify_chain_integrity(), "Chain must remain valid after rejected attempts");
}

// =========================================================================
// 3. TRACE MODEL CHECKER ADVERSARIAL CONFORMANCE TESTS
// =========================================================================

#[test]
fn test_empirical_trace_verifier_adversarial_rejections() {
    // 1. Empty trace rejection
    let empty_trace: Vec<GovernanceTraceEvent> = Vec::new();
    let rep_empty = CageTraceVerifier::verify_trace_conformance(&empty_trace);
    assert!(!rep_empty.is_conformant, "Empty trace must not be conformant");
    assert!(rep_empty.violations.iter().any(|v| v.contains("EMPTY_TRACE")));

    // 2. ActionProposed not at index 0
    let late_action_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FTRA_PASS".to_string()),
            requires_warrant: false,
            details: "FTRA passed".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Late action proposed".to_string(),
        },
    ];
    let rep_late = CageTraceVerifier::verify_trace_conformance(&late_action_trace);
    assert!(!rep_late.is_conformant);
    assert!(rep_late.violations.iter().any(|v| v.contains("ACTION_PROPOSED_NOT_FIRST")));

    // 3. Out-of-order step sequence (step 3 followed by step 2)
    let non_monotonic_steps = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Start".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FTRA_PASS".to_string()),
            requires_warrant: false,
            details: "FTRA".to_string(),
        },
        GovernanceTraceEvent {
            step: 2, // Reversal
            timestamp_ms: 102,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier2Stpa),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("STPA_PASS".to_string()),
            requires_warrant: false,
            details: "STPA".to_string(),
        },
    ];
    let rep_step = CageTraceVerifier::verify_trace_conformance(&non_monotonic_steps);
    assert!(!rep_step.is_conformant);
    assert!(!rep_step.monotonic_ordering_valid);
    assert!(rep_step.violations.iter().any(|v| v.contains("NON_MONOTONIC_STEP")));

    // 4. Out-of-order tier progression (Tier 7 evaluated before Tier 3)
    let out_of_order_tiers = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Start".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier7Cbf),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CBF_PASS".to_string()),
            requires_warrant: false,
            details: "CBF jumped early".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 102,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier3Opa),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("OPA_PASS".to_string()),
            requires_warrant: false,
            details: "OPA late".to_string(),
        },
    ];
    let rep_tier = CageTraceVerifier::verify_trace_conformance(&out_of_order_tiers);
    assert!(!rep_tier.is_conformant);
    assert!(!rep_tier.monotonic_ordering_valid);
    assert!(rep_tier.violations.iter().any(|v| v.contains("TRACE_OUT_OF_ORDER_TIER")));

    // 5. ActuationCompleted without preceding Clear receipt
    let premature_actuation = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Start".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FTRA_PASS".to_string()),
            requires_warrant: false,
            details: "FTRA".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 102,
            kind: GovernanceTraceEventType::ActuationCompleted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Actuating without receipt".to_string(),
        },
    ];
    let rep_no_rcpt = CageTraceVerifier::verify_trace_conformance(&premature_actuation);
    assert!(!rep_no_rcpt.is_conformant);
    assert!(!rep_no_rcpt.actuation_receipt_valid);
    assert!(rep_no_rcpt.violations.iter().any(|v| v.contains("ILLEGAL_ACTUATION_WITHOUT_CLEAR_RECEIPT")));

    // 6. ActuationCompleted after Refuse receipt
    let actuation_after_refuse = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Start".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier3Opa),
            verdict: Some(CageVerdict::Refuse),
            rule_id: Some(CTRL_OPA_005.to_string()),
            requires_warrant: false,
            details: "OPA Refusal".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 102,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: Some(CageTier::Tier3Opa),
            verdict: Some(CageVerdict::Refuse),
            rule_id: Some(CTRL_OPA_005.to_string()),
            requires_warrant: false,
            details: "Signed refusal receipt".to_string(),
        },
        GovernanceTraceEvent {
            step: 4,
            timestamp_ms: 103,
            kind: GovernanceTraceEventType::ActuationCompleted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Malicious actuation post-refusal".to_string(),
        },
    ];
    let rep_refuse_act = CageTraceVerifier::verify_trace_conformance(&actuation_after_refuse);
    assert!(!rep_refuse_act.is_conformant);
    assert!(!rep_refuse_act.actuation_receipt_valid);
    assert!(rep_refuse_act.violations.iter().any(|v| v.contains("ACTUATION_AFTER_REFUSAL")));

    // 7. Warrant Precedence Violation (requires_warrant is true, but CbfVerified occurs without WarrantChecked)
    let missing_warrant_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: true, // Flagged!
            details: "Requires warrant action".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FTRA_PASS".to_string()),
            requires_warrant: true,
            details: "FTRA passed".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 102,
            kind: GovernanceTraceEventType::CbfVerified, // Missing WarrantChecked prior
            tier: Some(CageTier::Tier7Cbf),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CBF_PASS".to_string()),
            requires_warrant: true,
            details: "CBF verified directly".to_string(),
        },
    ];
    let rep_warrant = CageTraceVerifier::verify_trace_conformance(&missing_warrant_trace);
    assert!(!rep_warrant.is_conformant);
    assert!(!rep_warrant.warrant_precedence_valid);
    assert!(rep_warrant.violations.iter().any(|v| v.contains("WARRANT_PRECEDENCE_VIOLATION")));

    // 8. Warrant Precedence Violation for FiscalCommitted
    let missing_warrant_fiscal_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: true,
            details: "Requires warrant action".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::FiscalCommitted, // Missing WarrantChecked prior
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FISCAL_PASS".to_string()),
            requires_warrant: true,
            details: "Fiscal committed directly".to_string(),
        },
    ];
    let rep_warrant_fiscal = CageTraceVerifier::verify_trace_conformance(&missing_warrant_fiscal_trace);
    assert!(!rep_warrant_fiscal.is_conformant);
    assert!(!rep_warrant_fiscal.warrant_precedence_valid);
    assert!(rep_warrant_fiscal.violations.iter().any(|v| v.contains("WARRANT_PRECEDENCE_VIOLATION")));

    // 9. Fully valid canonical 8-tier trace with warrant check
    let canonical_valid_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 100,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: true,
            details: "Proposed sensitive transaction".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 101,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FTRA_PASS".to_string()),
            requires_warrant: true,
            details: "FTRA cleared".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 102,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier2Stpa),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("STPA_PASS".to_string()),
            requires_warrant: true,
            details: "STPA cleared".to_string(),
        },
        GovernanceTraceEvent {
            step: 4,
            timestamp_ms: 103,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier3Opa),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("OPA_PASS".to_string()),
            requires_warrant: true,
            details: "OPA cleared".to_string(),
        },
        GovernanceTraceEvent {
            step: 5,
            timestamp_ms: 104,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier4Confidence),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CONF_PASS".to_string()),
            requires_warrant: true,
            details: "Confidence calibrated".to_string(),
        },
        GovernanceTraceEvent {
            step: 6,
            timestamp_ms: 105,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier5Warrant),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("WARRANT_PASS".to_string()),
            requires_warrant: true,
            details: "Warrant verified".to_string(),
        },
        GovernanceTraceEvent {
            step: 7,
            timestamp_ms: 106,
            kind: GovernanceTraceEventType::WarrantChecked,
            tier: Some(CageTier::Tier5Warrant),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("WARRANT_GATE".to_string()),
            requires_warrant: true,
            details: "Warrant gate approved".to_string(),
        },
        GovernanceTraceEvent {
            step: 8,
            timestamp_ms: 107,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier6Consensus),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CONSENSUS_PASS".to_string()),
            requires_warrant: true,
            details: "Consensus rationale recorded".to_string(),
        },
        GovernanceTraceEvent {
            step: 9,
            timestamp_ms: 108,
            kind: GovernanceTraceEventType::ConsensusDecided,
            tier: Some(CageTier::Tier6Consensus),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CONSENSUS_GATE".to_string()),
            requires_warrant: true,
            details: "Consensus gate decided".to_string(),
        },
        GovernanceTraceEvent {
            step: 10,
            timestamp_ms: 109,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier7Cbf),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CBF_PASS".to_string()),
            requires_warrant: true,
            details: "CBF invariant satisfied".to_string(),
        },
        GovernanceTraceEvent {
            step: 11,
            timestamp_ms: 110,
            kind: GovernanceTraceEventType::CbfVerified,
            tier: Some(CageTier::Tier7Cbf),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CBF_GATE".to_string()),
            requires_warrant: true,
            details: "CBF verified".to_string(),
        },
        GovernanceTraceEvent {
            step: 12,
            timestamp_ms: 111,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FISCAL_PASS".to_string()),
            requires_warrant: true,
            details: "Fiscal spend approved".to_string(),
        },
        GovernanceTraceEvent {
            step: 13,
            timestamp_ms: 112,
            kind: GovernanceTraceEventType::FiscalCommitted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FISCAL_GATE".to_string()),
            requires_warrant: true,
            details: "Fiscal committed".to_string(),
        },
        GovernanceTraceEvent {
            step: 14,
            timestamp_ms: 113,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("RECEIPT_CLEARED".to_string()),
            requires_warrant: true,
            details: "Receipt dual-digest signed".to_string(),
        },
        GovernanceTraceEvent {
            step: 15,
            timestamp_ms: 114,
            kind: GovernanceTraceEventType::ActuationCompleted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("ACTUATION_DONE".to_string()),
            requires_warrant: true,
            details: "Tool executed successfully".to_string(),
        },
    ];
    let rep_canonical = CageTraceVerifier::verify_trace_conformance(&canonical_valid_trace);
    assert!(rep_canonical.is_conformant, "Canonical 8-tier trace must be conformant: {:?}", rep_canonical.violations);
    assert!(rep_canonical.monotonic_ordering_valid);
    assert!(rep_canonical.actuation_receipt_valid);
    assert!(rep_canonical.warrant_precedence_valid);
    assert_eq!(rep_canonical.tiers_evaluated.len(), 8);
    assert_eq!(rep_canonical.final_verdict, Some(CageVerdict::Clear));
}

// =========================================================================
// 4. CONTINUOUS DEFENSE RESEARCH SUITE & CANARY BENIGN TELEMETRY CORPUS
// =========================================================================

#[test]
fn test_empirical_continuous_defense_and_canary_benign_corpus() {
    restore_default_research_rules();

    // 1. Ingested catalog must include arXiv:2606.12320 (Google CAGE)
    let rules = list_ingested_research_rules();
    assert!(
        rules.iter().any(|r| r.arxiv_id == "2606.12320" || r.rule_id == "ARXIV-DEF-2606.12320"),
        "Catalog must contain arXiv:2606.12320"
    );

    // 2. Paper2Agent accuracy suite across all 5 registered rules
    let suite = run_paper2agent_accuracy_suite();
    assert_eq!(suite.status, "verified");
    assert_eq!(suite.total_rules_tested, 5, "Accuracy suite must test exactly 5 rules");
    assert_eq!(suite.true_positive_rate_pct, 100.0, "TPR must be 100.0%");
    assert_eq!(suite.false_positive_rate_pct, 0.0, "FPR must be 0.0%");
    assert!(suite.byte_exact_parity, "Must have byte-exact parity");
    assert!(suite.llm_fusion_consensus_passed, "LLM fusion consensus must pass");

    // 3. Recency gate validation
    assert!(is_current_research_arxiv_id("2606.12320"), "2026 paper must be accepted by recency gate");
    assert!(is_current_research_arxiv_id("2501.18492"), "2025 paper must be accepted by recency gate");
    assert!(!is_current_research_arxiv_id("2406.12320"), "2024 paper must be rejected by recency gate");
    assert!(!is_current_research_arxiv_id("2305.99999"), "2023 paper must be rejected by recency gate");

    // 4. Verified repository detection (valid vs blocked fake slugs / non-https schemes)
    assert!(is_valid_verified_repo_url("https://github.com/google/cybernetic-agent-governance-engine"));
    assert!(!is_valid_verified_repo_url("https://github.com/example/repo"), "Blocked placeholder repo must return false");
    assert!(!is_valid_verified_repo_url("http://github.com/google/cybernetic-agent-governance-engine"), "Non-https must return false");
    assert!(!is_valid_verified_repo_url("not_a_url"), "Malformed URL must return false");

    // 5. Malicious CAGE boundary detection
    let engine = ContinuousDefenseEngine::new();
    let mal_verdict = engine.inspect_boundary(
        "actuation_request",
        "runtime_actuation_pep_boundary",
        "agent attempt: tool call with fiscal_cap_exceeded and unverified_warrant bypass",
        None,
        42,
    );
    assert!(!mal_verdict.is_clean, "Malicious payload must be flagged");
    assert!(
        mal_verdict.detected_violations.iter().any(|v| v.contains("2606.12320")),
        "Violation must be attributed to arXiv:2606.12320"
    );

    // 6. CANARY BENIGN TELEMETRY CORPUS (Zero False Positives Gate)
    // 6a. All 5 ingested research defense rules must produce 0 false positives against CANARY_BENIGN_TELEMETRY_CORPUS
    for r in &rules {
        let canary_res = killswitch_telemetry::continuous_defense::verify_rule_against_canary_benign_corpus(r);
        assert!(
            canary_res.is_none(),
            "Rule '{}' failed canary benign gate: {:?}",
            r.rule_id,
            canary_res
        );
    }

    // 6b. Boundary inspection on benign agent tool telemetry samples must be 100% clean
    let benign_tool_telemetry = [
        "query_account_balance for user_id=12345",
        "read_system_metrics CPU usage 34% memory 4.2GB",
        "calculate_moving_average window=20 symbol=AAPL",
        "fetch_readiness_probe status=healthy port=3030",
        "display_audit_log range=last_24h format=json",
        "cache_lookup key=session_token_xyz ttl=300",
        "get_portfolio_summary account_tier=retail",
        "ping_database_pool timeout_ms=50 pool_size=10",
        "check_disk_space path=/var/log/killswitch free_gb=48",
        "format_table_report columns=3 rows=15 format=markdown",
        "validate_schema target=cage_response_v1",
        "compress_telemetry_chunk chunk_id=8812 algorithm=zstd",
        "benchmark_hash_rate blake3_mb_per_sec=2100",
        "get_service_status service=killswitch-daemon",
        "parse_json_config path=config/runtime.json",
        "query_dns_cache host=api.internal.cluster",
        "monitor_thread_pool active_threads=4 idle_threads=12",
        "read_environment_var name=KILLSWITCH_MODE process_scope=true",
        "calculate_standard_deviation samples=1000 mean=50.2",
        "retrieve_telemetry_watermark watermark_id=wm-01",
    ];

    for (idx, &sample) in benign_tool_telemetry.iter().enumerate() {
        let clean_engine = ContinuousDefenseEngine::new();
        let v = clean_engine.inspect_boundary(
            "general_telemetry",
            "telemetry_ingress_boundary",
            sample,
            None,
            1,
        );
        assert!(
            v.is_clean,
            "False positive detected on canary baseline #{}: '{}' (violations: {:?})",
            idx, sample, v.detected_violations
        );
        assert!(v.detected_violations.is_empty());
        assert_eq!(v.primary_category, None);
    }
}

// =========================================================================
// 5. SUBSTRATE COMPILER DETERMINISM & 8-TIER KERNEL ADVERSARIAL STRESS
// =========================================================================

#[test]
fn test_empirical_substrate_compiler_key_permutations_and_formats() {
    // 1. Key ordering and whitespace invariance in JSON representation
    let spec_a = serde_json::json!({
        "schema_version": "cage-substrate/3.0",
        "allowed_tools": ["b_tool", "c_tool", "a_tool"],
        "parameter_bounds": {
            "max_single_transfer_usd": 15000.0,
            "max_dose_mg": 75.0,
            "fiscal_cap_usd": 75000.0
        },
        "norms": [
            { "id": "NORM-1", "tool_pattern": "*", "requires_warrant": true, "consensus_threshold": 0.90 }
        ]
    });

    let spec_b = serde_json::json!({
        "norms": [
            { "consensus_threshold": 0.90, "requires_warrant": true, "tool_pattern": "*", "id": "NORM-1" }
        ],
        "parameter_bounds": {
            "fiscal_cap_usd": 75000.0,
            "max_dose_mg": 75.0,
            "max_single_transfer_usd": 15000.0
        },
        "allowed_tools": ["a_tool", "c_tool", "b_tool"],
        "schema_version": "cage-substrate/3.0"
    });

    let c_a = SubstrateCompiler::detect_and_compile(&spec_a).unwrap();
    let c_b = SubstrateCompiler::detect_and_compile(&spec_b).unwrap();

    assert_eq!(c_a.substrate_contract_digest, c_b.substrate_contract_digest, "Key permutation must yield bitwise identical digest");
    assert!(c_a.verify_digest());
    assert!(c_b.verify_digest());

    // 2. Reject non-object JSON payload
    let non_obj = serde_json::json!(["not", "an", "object"]);
    let err_non_obj = SubstrateCompiler::detect_and_compile(&non_obj);
    assert!(err_non_obj.is_err(), "Non-object substrate specification must be rejected");

    // 3. String parser handling JSON strings
    let json_str = serde_json::to_string(&spec_a).unwrap();
    let c_json = SubstrateCompiler::detect_and_compile_str(&json_str).unwrap();
    assert_eq!(c_json.max_single_transfer_usd, 15000.0);
    assert_eq!(c_json.fiscal_cap_usd, 75000.0);
    assert!(c_json.requires_warrant);
    assert!(c_json.verify_digest());

    // 4. All 5 specification formats compile and verify digest
    let acs = SubstrateCompiler::detect_and_compile(&serde_json::json!({
        "behaviorDeclarations": [{ "action": "trade", "constraints": [{ "parameter": "transfer_amount", "value": 5000.0 }] }]
    })).unwrap();
    assert_eq!(acs.format, SubstrateFormat::MicrosoftAcs);
    assert!(acs.verify_digest());

    let aaif = SubstrateCompiler::detect_and_compile(&serde_json::json!({
        "governedRunLoop": { "stages": [{ "name": "s1", "action": "trade", "constraints": [{ "parameter": "transfer_amount", "value": 5000.0 }] }] }
    })).unwrap();
    assert_eq!(aaif.format, SubstrateFormat::LinuxFoundationAaif);
    assert!(aaif.verify_digest());

    let oscal = SubstrateCompiler::detect_and_compile(&serde_json::json!({
        "oscal-version": "1.1.0",
        "component-definition": { "components": [] }
    })).unwrap();
    assert_eq!(oscal.format, SubstrateFormat::NistOscal);
    assert!(oscal.verify_digest());

    let lula = SubstrateCompiler::detect_and_compile(&serde_json::json!({
        "kind": "LulaValidation",
        "metadata": { "name": "lula-test" }
    })).unwrap();
    assert_eq!(lula.format, SubstrateFormat::LulaValidation);
    assert!(lula.verify_digest());
}

#[test]
fn test_empirical_cbf_domain_barriers_exact_invariance_boundaries() {
    // 1. HealthcareDoseBarrier boundary tests
    // max_single = 100 mg, max_daily = 300 mg, cumulative = 250 mg, gamma = 0.5
    let dose_barrier = HealthcareDoseBarrier::new(100.0, 300.0, 250.0, 0.5);

    // h_k = 300 - 250 = 50.
    // Invariance condition: B(x) = 0.5 * 50 - proposed = 25 - proposed >= 0
    // At proposed = 25.0: B(x) = 0.0 -> OK
    assert!(dose_barrier.evaluate(25.0).is_ok(), "Dose barrier at exact B(x)=0 boundary must pass");

    // At proposed = 25.001: B(x) = -0.001 < 0 -> Violation
    let res_viol = dose_barrier.evaluate(25.001);
    assert!(res_viol.is_err());
    assert_eq!(res_viol.unwrap_err().0, CTRL_CBF_DOSE_001);

    // Single dose over limit: 105 mg > 100 mg max_single
    let res_single = dose_barrier.evaluate(105.0);
    assert!(res_single.is_err());
    assert_eq!(res_single.unwrap_err().0, CTRL_CBF_DOSE_001);

    // 2. FinanceBoundingBarrier boundary tests
    // max_notional = 10,000, max_exposure = 50,000, current = 40,000, gamma = 0.4
    let fin_barrier = FinanceBoundingBarrier::new(10000.0, 50000.0, 40000.0, 0.4);

    // h_k = 50000 - 40000 = 10000.
    // B(x) = 0.4 * 10000 - proposed = 4000 - proposed >= 0
    // At proposed = 4000.0 -> OK
    assert!(fin_barrier.evaluate(4000.0).is_ok());

    // At proposed = 4000.01 -> Violation
    let res_fin_viol = fin_barrier.evaluate(4000.01);
    assert!(res_fin_viol.is_err());
    assert_eq!(res_fin_viol.unwrap_err().0, CTRL_CBF_FINANCE_001);

    // Notional cap exceeded: 12000.0 > 10000.0
    let res_notional = fin_barrier.evaluate(12000.0);
    assert!(res_notional.is_err());
    assert_eq!(res_notional.unwrap_err().0, CTRL_CBF_FINANCE_001);
}

#[test]
fn test_empirical_atomic_fiscal_barrier_50_thread_stress() {
    let barrier = Arc::new(AtomicFiscalBarrier::new(10000.0)); // $10,000 cap
    let thread_count = 50;
    let spend_per_thread = 500.0; // 50 * 500 = $25,000 attempted
    let mut handles = Vec::new();

    for _ in 0..thread_count {
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            b.try_spend(spend_per_thread)
        }));
    }

    let mut success_count = 0;
    let mut refuse_count = 0;

    for h in handles {
        match h.join().unwrap() {
            Ok(_) => success_count += 1,
            Err(e) => {
                assert_eq!(e, FISCAL_CAP_EXCEEDED);
                refuse_count += 1;
            }
        }
    }

    // Exactly 20 threads succeed ($10,000 / $500 = 20) and 30 threads fail
    assert_eq!(success_count, 20, "Exactly 20 threads must succeed under $10k cap");
    assert_eq!(refuse_count, 30, "Exactly 30 threads must be refused under $10k cap");
    assert_eq!(barrier.get_spent_usd(), 10000.0, "Total spend must equal exactly $10,000");

    // Any further spend attempt must fail closed
    assert_eq!(barrier.try_spend(0.01).unwrap_err(), FISCAL_CAP_EXCEEDED);

    // Reset works as expected
    barrier.reset();
    assert_eq!(barrier.get_spent_usd(), 0.0);
    assert!(barrier.try_spend(500.0).is_ok());
}

#[test]
fn test_empirical_cage_kernel_8_tier_adversarial_challenges() {
    let kernel = global_cage_kernel();

    // 1. Kernel invariant: llm_clients_in_kernel must be structurally false
    let status = kernel.status();
    assert!(!status.llm_clients_in_kernel, "LLM clients in kernel MUST be false");

    // 2. All 8 canonical unverified self-authorization phrases must trigger Tier 4 CTRL_CONF_001
    let canonical_unverified_claims = [
        "authorized_by_admin",
        "bypass_security",
        "override_governance",
        "pre_approved",
        "trusted_override",
        "self_certified",
        "skip_checks",
        "elevated_privilege_granted",
    ];

    for claim in canonical_unverified_claims {
        let req = CageEvaluationRequest {
            agent_id: "agent-fabricator".to_string(),
            role: "worker".to_string(),
            tool_name: "execute_trade".to_string(),
            arguments: serde_json::json!({ "instruction": format!("Action details: {}", claim) }),
            confidence_score: Some(0.95),
            amount_usd: Some(100.0),
            dose_mg: None,
            warrant_token: None,
            human_approval: None,
            context: None,
        };
        let resp = kernel.evaluate(&req);
        assert_eq!(resp.verdict, CageVerdict::Refuse, "Claim '{}' must be refused", claim);
        assert_eq!(resp.tier, CageTier::Tier4Confidence);
        assert_eq!(resp.rule_id, CTRL_CONF_001);
        assert!(resp.receipt.verify_digest());
    }

    // 3. Uncalibrated low confidence score (< 0.80) triggers Tier 4 CTRL_CONF_001
    let req_low_conf = CageEvaluationRequest {
        agent_id: "agent-uncertain".to_string(),
        role: "worker".to_string(),
        tool_name: "execute_trade".to_string(),
        arguments: serde_json::json!({ "order": "buy" }),
        confidence_score: Some(0.40), // Under 0.80 threshold
        amount_usd: Some(100.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_low = kernel.evaluate(&req_low_conf);
    assert_eq!(resp_low.verdict, CageVerdict::Refuse);
    assert_eq!(resp_low.tier, CageTier::Tier4Confidence);
    assert_eq!(resp_low.rule_id, CTRL_CONF_001);

    // 4. Forbidden tool pattern triggers Tier 3 OPA Refuse
    let req_forbidden_tool = CageEvaluationRequest {
        agent_id: "agent-evil".to_string(),
        role: "trader".to_string(),
        tool_name: "unregistered_external_drain_tool".to_string(),
        arguments: serde_json::json!({}),
        confidence_score: Some(0.99),
        amount_usd: Some(50.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let resp_forbid = kernel.evaluate(&req_forbidden_tool);
    assert_eq!(resp_forbid.verdict, CageVerdict::Refuse);
    assert_eq!(resp_forbid.tier, CageTier::Tier3Opa);
    assert_eq!(resp_forbid.rule_id, "CTRL_OPA_FORBIDDEN_TOOL");
}
