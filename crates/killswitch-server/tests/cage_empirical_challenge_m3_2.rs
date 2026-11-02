//! # Empirical Challenge Test Suite for Milestone CAGE-3 (`crates/killswitch-server`)
//!
//! Independent Adversarial Verification:
//! 1. Formal Trace Model Checker Edge Cases:
//!    a) Out-of-order steps (e.g. step 1 -> step 3 -> step 2).
//!    b) Non-monotonic timestamps (clock skew or time-travel attacks).
//!    c) Skipped actuation receipts (actuation completed without prior Clear receipt).
//!    d) Actuation after refusal receipt (actuation completed post Refuse receipt).
//!    e) Missing warrant precedence when required (CBF or Fiscal evaluation without WarrantChecked).
//! 2. Substrate Compiler Determinism Across all 5 Formats:
//!    - Bitwise identical SHA-256 `substrate_contract_digest` across 100 repeated compilations
//!      of `NativeCage`, `MicrosoftAcs`, `LinuxFoundationAaif`, `NistOscal`, and `LulaValidation`.
//!    - Key permutation & formatting resilience.
//!    - Embedded digest constant-time verification.
//! 3. WebUI Safe DOM Invariant Verification:
//!    - Automated static AST/source grep analysis asserting strictly zero `innerHTML`
//!      occurrences in `crates/killswitch-server/src/webui.rs`.

use std::fs;
use std::path::PathBuf;

use killswitch_telemetry::cage_governance::{
    CageTier, CageTraceVerifier, CageVerdict, GovernanceTraceEvent, GovernanceTraceEventType,
    SubstrateCompiler, SubstrateFormat,
};

// ============================================================================
// PART 1: Formal Trace Model Checker Edge Cases
// ============================================================================

/// 1a. Assert that out-of-order trace steps (e.g., step 1 -> step 3 -> step 2)
/// are strictly rejected by the trace model checker.
#[test]
fn test_trace_model_checker_edge_case_1a_out_of_order_steps() {
    let trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Step 1 proposed".to_string(),
        },
        GovernanceTraceEvent {
            step: 3, // Jumps to step 3 prematurely
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FTRA_PASS".to_string()),
            requires_warrant: false,
            details: "Step 3 jumped".to_string(),
        },
        GovernanceTraceEvent {
            step: 2, // Steps backwards to step 2 (out of order!)
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: None,
            requires_warrant: false,
            details: "Step 2 out of order".to_string(),
        },
    ];

    let report = CageTraceVerifier::verify_trace_conformance(&trace);
    assert!(
        !report.is_conformant,
        "Trace with out-of-order steps (1 -> 3 -> 2) MUST be non-conformant"
    );
    assert!(
        !report.monotonic_ordering_valid,
        "monotonic_ordering_valid MUST be false"
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.contains("NON_MONOTONIC_STEP")),
        "Report violations must explicitly cite NON_MONOTONIC_STEP: {:?}",
        report.violations
    );
}

/// 1b. Non-monotonic timestamps (clock skew or time-travel attacks).
/// Adversary attempts time-travel replay where step numbers are monotonic (1 -> 2 -> 3),
/// but timestamps regress backwards (e.g. 2000ms -> 1000ms -> 1500ms).
#[test]
fn test_trace_model_checker_edge_case_1b_non_monotonic_timestamps_clock_skew() {
    let clock_skew_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 2000, // Initial event at t=2000ms
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Action proposed at t=2000ms".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1000, // Clock skew / time-travel backward jump to t=1000ms!
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Fiscal evaluated at t=1000ms (clock skew)".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1500,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: None,
            verdict: Some(CageVerdict::Clear),
            rule_id: None,
            requires_warrant: false,
            details: "Receipt signed at t=1500ms".to_string(),
        },
    ];

    let report = CageTraceVerifier::verify_trace_conformance(&clock_skew_trace);

    // EMPIRICAL CHALLENGE FINDING:
    // In cage_governance.rs lines 1184-1193, verify_trace_conformance only checks `event.step <= last_step`.
    // It NEVER checks `event.timestamp_ms < last_timestamp_ms`!
    // As a result, clock skew and time-travel attacks currently bypass model checking undetected.
    println!(
        "[EMPIRICAL CHALLENGE 1b] Clock Skew Trace Report: is_conformant={}, monotonic_ordering_valid={}, violations={:?}",
        report.is_conformant, report.monotonic_ordering_valid, report.violations
    );

    let has_timestamp_violation = report
        .violations
        .iter()
        .any(|v| v.to_ascii_uppercase().contains("TIMESTAMP"));

    assert!(
        !report.is_conformant,
        "Trace with clock skew / non-monotonic timestamps MUST be non-conformant"
    );
    assert!(
        !report.monotonic_ordering_valid,
        "monotonic_ordering_valid MUST be false on clock skew"
    );
    assert!(
        has_timestamp_violation,
        "Report violations must cite NON_MONOTONIC_TIMESTAMP: {:?}",
        report.violations
    );
}

/// 1c. Skipped actuation receipts (actuating without clear receipt).
/// Assert that ActuationCompleted without a preceding Clear receipt is rejected.
#[test]
fn test_trace_model_checker_edge_case_1c_skipped_actuation_receipt() {
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
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FTRA_PASS".to_string()),
            requires_warrant: false,
            details: "FTRA passed".to_string(),
        },
        // SKIPPED ReceiptSigned event! Directly completing actuation:
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::ActuationCompleted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Actuating without clear receipt".to_string(),
        },
    ];

    let report = CageTraceVerifier::verify_trace_conformance(&trace);
    assert!(
        !report.is_conformant,
        "Skipping actuation receipt MUST render trace non-conformant"
    );
    assert!(
        !report.actuation_receipt_valid,
        "actuation_receipt_valid MUST be false"
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.contains("ILLEGAL_ACTUATION_WITHOUT_CLEAR_RECEIPT")),
        "Report violations must cite ILLEGAL_ACTUATION_WITHOUT_CLEAR_RECEIPT: {:?}",
        report.violations
    );
}

/// 1d. Actuation after refusal receipt.
/// Assert that ActuationCompleted following a Refuse receipt is rejected.
#[test]
fn test_trace_model_checker_edge_case_1d_actuation_after_refusal_receipt() {
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
            tier: Some(CageTier::Tier3Opa),
            verdict: Some(CageVerdict::Refuse),
            rule_id: Some("CTRL_OPA_005".to_string()),
            requires_warrant: false,
            details: "OPA refused".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: Some(CageTier::Tier3Opa),
            verdict: Some(CageVerdict::Refuse),
            rule_id: Some("CTRL_OPA_005".to_string()),
            requires_warrant: false,
            details: "Refusal receipt signed".to_string(),
        },
        // Hostile actuation after refusal:
        GovernanceTraceEvent {
            step: 4,
            timestamp_ms: 1003,
            kind: GovernanceTraceEventType::ActuationCompleted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Malicious actuation executed post-refusal".to_string(),
        },
    ];

    let report = CageTraceVerifier::verify_trace_conformance(&trace);
    assert!(
        !report.is_conformant,
        "Actuation post-refusal MUST render trace non-conformant"
    );
    assert!(
        !report.actuation_receipt_valid,
        "actuation_receipt_valid MUST be false"
    );
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.contains("ACTUATION_AFTER_REFUSAL")),
        "Report violations must cite ACTUATION_AFTER_REFUSAL: {:?}",
        report.violations
    );
}

/// 1e. Missing warrant precedence when required.
/// Assert that CBF or Fiscal evaluation without prior WarrantChecked is rejected
/// whenever requires_warrant is true.
#[test]
fn test_trace_model_checker_edge_case_1e_missing_warrant_precedence() {
    // Case 1: CBF evaluated without warrant
    let cbf_missing_warrant = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: true,
            details: "Action requires warrant".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier1Ftra),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FTRA_PASS".to_string()),
            requires_warrant: true,
            details: "FTRA passed".to_string(),
        },
        // Jumps directly to CbfVerified without WarrantChecked!
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::CbfVerified,
            tier: Some(CageTier::Tier7Cbf),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("CBF_PASS".to_string()),
            requires_warrant: true,
            details: "CBF verified without warrant".to_string(),
        },
    ];

    let report_cbf = CageTraceVerifier::verify_trace_conformance(&cbf_missing_warrant);
    assert!(
        !report_cbf.is_conformant,
        "Missing warrant for CBF MUST render trace non-conformant"
    );
    assert!(
        !report_cbf.warrant_precedence_valid,
        "warrant_precedence_valid MUST be false"
    );
    assert!(
        report_cbf
            .violations
            .iter()
            .any(|v| v.contains("WARRANT_PRECEDENCE_VIOLATION")),
        "Violations must cite WARRANT_PRECEDENCE_VIOLATION: {:?}",
        report_cbf.violations
    );

    // Case 2: FiscalCommitted evaluated without warrant
    let fiscal_missing_warrant = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: true,
            details: "Action requires warrant".to_string(),
        },
        // Jumps directly to FiscalCommitted without WarrantChecked!
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::FiscalCommitted,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("FISCAL_PASS".to_string()),
            requires_warrant: true,
            details: "Fiscal committed without warrant".to_string(),
        },
    ];

    let report_fiscal = CageTraceVerifier::verify_trace_conformance(&fiscal_missing_warrant);
    assert!(
        !report_fiscal.is_conformant,
        "Missing warrant for Fiscal MUST render trace non-conformant"
    );
    assert!(
        !report_fiscal.warrant_precedence_valid,
        "warrant_precedence_valid MUST be false"
    );
    assert!(
        report_fiscal
            .violations
            .iter()
            .any(|v| v.contains("WARRANT_PRECEDENCE_VIOLATION")),
        "Violations must cite WARRANT_PRECEDENCE_VIOLATION: {:?}",
        report_fiscal.violations
    );
}

// ============================================================================
// PART 2: Substrate Compiler Determinism Across All 5 Formats
// ============================================================================

/// Asserts bitwise identical SHA-256 `substrate_contract_digest` across repeated
/// compilations of NativeCage, MicrosoftAcs, LinuxFoundationAaif, NistOscal, and LulaValidation.
#[test]
fn test_substrate_compiler_determinism_across_all_5_formats() {
    // 1. NativeCage format specification
    let native_cage_spec = serde_json::json!({
        "schema_version": "cage-substrate/3.0",
        "contract_id": "challenge-contract-native",
        "domain": "finance",
        "allowed_tools": ["transfer_funds", "execute_trade", "query_balance"],
        "parameter_bounds": {
            "max_single_transfer_usd": 15000.0,
            "max_dose_mg": 50.0,
            "fiscal_cap_usd": 75000.0
        },
        "norms": [
            {
                "id": "NORM_FIN_001",
                "requires_warrant": false,
                "consensus_threshold": 0.85
            }
        ]
    });

    // 2. MicrosoftAcs format specification
    let microsoft_acs_spec = serde_json::json!({
        "metadata": {
            "name": "challenge-contract-acs"
        },
        "behaviorDeclarations": [
            {
                "action": "execute_trade",
                "requires_warrant": false,
                "constraints": [
                    { "parameter": "max_single_transfer_usd", "value": 15000.0 },
                    { "parameter": "fiscal_cap_usd", "value": 75000.0 },
                    { "parameter": "max_dose_mg", "value": 50.0 },
                    { "parameter": "consensus_threshold", "value": 0.85 }
                ]
            },
            {
                "action": "query_balance",
                "requires_warrant": false,
                "constraints": []
            }
        ]
    });

    // 3. LinuxFoundationAaif format specification
    let aaif_spec = serde_json::json!({
        "governedRunLoop": {
            "stages": [
                {
                    "action": "execute_trade",
                    "threshold": 0.85,
                    "constraints": [
                        { "parameter": "max_single_transfer_usd", "value": 15000.0 },
                        { "parameter": "fiscal_cap_usd", "value": 75000.0 },
                        { "parameter": "max_dose_mg", "value": 50.0 }
                    ]
                },
                {
                    "action": "query_balance",
                    "threshold": 0.85,
                    "constraints": []
                }
            ]
        }
    });

    // 4. NistOscal format specification
    let oscal_spec = serde_json::json!({
        "oscal-version": "1.1.0",
        "id": "challenge-contract-oscal",
        "component-definition": {
            "components": [
                {
                    "control-implementations": [
                        {
                            "implemented-requirements": [
                                {
                                    "control-id": "ac-3",
                                    "props": [
                                        { "name": "max_single_transfer_usd", "value": "15000.00" },
                                        { "name": "max_dose_mg", "value": "50.00" },
                                        { "name": "fiscal_cap_usd", "value": "75000.00" },
                                        { "name": "requires_warrant", "value": "false" },
                                        { "name": "consensus_threshold", "value": "0.85" }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    });

    // 5. LulaValidation format specification
    let lula_spec = serde_json::json!({
        "kind": "LulaValidation",
        "metadata": {
            "name": "challenge-contract-lula",
            "annotations": {
                "max_single_transfer_usd": "15000.00",
                "max_dose_mg": "50.00",
                "fiscal_cap_usd": "75000.00",
                "requires_warrant": "false",
                "consensus_threshold": "0.85"
            }
        },
        "spec": {
            "domain": {
                "kubernetes-spec": {
                    "resources": [
                        { "name": "execute_trade" },
                        { "name": "query_balance" }
                    ]
                }
            }
        }
    });

    let format_test_cases = [
        ("NativeCage", SubstrateFormat::NativeCage, native_cage_spec),
        ("MicrosoftAcs", SubstrateFormat::MicrosoftAcs, microsoft_acs_spec),
        ("LinuxFoundationAaif", SubstrateFormat::LinuxFoundationAaif, aaif_spec),
        ("NistOscal", SubstrateFormat::NistOscal, oscal_spec),
        ("LulaValidation", SubstrateFormat::LulaValidation, lula_spec),
    ];

    for (name, expected_fmt, spec) in format_test_cases {
        // Compile initial artifact
        let initial_art = SubstrateCompiler::detect_and_compile(&spec)
            .unwrap_or_else(|e| panic!("Initial compilation failed for format {}: {}", name, e));

        assert_eq!(
            initial_art.format, expected_fmt,
            "Format detection mismatch for {}",
            name
        );

        let initial_digest = initial_art.substrate_contract_digest.clone();
        assert_eq!(
            initial_digest.len(),
            64,
            "SHA-256 digest must be 64 hex characters for {}",
            name
        );
        assert!(
            initial_art.verify_digest(),
            "Initial digest verification failed for {}",
            name
        );

        // Run 100 repeated compilations and verify bitwise identical SHA-256 digest
        for iteration in 1..=100 {
            let iter_art = SubstrateCompiler::detect_and_compile(&spec).unwrap_or_else(|e| {
                panic!("Iteration {} failed for format {}: {}", iteration, name, e)
            });

            assert_eq!(
                iter_art.substrate_contract_digest, initial_digest,
                "Digest diverged on iteration {} for format {}! Expected {}, got {}",
                iteration, name, initial_digest, iter_art.substrate_contract_digest
            );
            assert!(
                iter_art.verify_digest(),
                "Digest verification failed on iteration {} for format {}",
                iteration, name
            );
        }

        println!(
            "[CONFIRMED DETERMINISM] Format: {:<20} | SHA-256: {} | 100/100 identical runs",
            name, initial_digest
        );
    }
}

// ============================================================================
// PART 3: WebUI Safe DOM Invariant Verification
// ============================================================================

/// Scans `crates/killswitch-server/src/webui.rs` for `innerHTML` occurrences.
/// Enforces the WebUI Safe DOM invariant: strictly zero `innerHTML` in active code.
#[test]
fn test_webui_safe_dom_invariant_zero_inner_html() {
    // Locate crates/killswitch-server/src/webui.rs
    let candidates = [
        PathBuf::from("crates/killswitch-server/src/webui.rs"),
        PathBuf::from("../killswitch-server/src/webui.rs"),
        PathBuf::from("../../crates/killswitch-server/src/webui.rs"),
        PathBuf::from("src/webui.rs"),
    ];

    let webui_path = candidates
        .iter()
        .find(|p| p.exists())
        .expect("Could not locate crates/killswitch-server/src/webui.rs");

    let content = fs::read_to_string(webui_path).expect("Failed to read webui.rs");

    // Perform static line-by-line inspection
    let mut inner_html_occurrences = Vec::new();
    let mut code_inner_html_occurrences = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.contains("innerHTML") {
            inner_html_occurrences.push((line_num + 1, trimmed.to_string()));

            // Determine if the occurrence is active JavaScript code vs pure comment
            let is_comment = trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*');
            if !is_comment {
                code_inner_html_occurrences.push((line_num + 1, trimmed.to_string()));
            }
        }
    }

    println!(
        "[EMPIRICAL CHALLENGE 3] Total innerHTML occurrences: {}, Active code occurrences: {}",
        inner_html_occurrences.len(),
        code_inner_html_occurrences.len()
    );

    for (num, line) in &inner_html_occurrences {
        println!("  Line {}: {}", num, line);
    }

    // EMPIRICAL ASSESSMENT OF WEBUI SAFE DOM INVARIANT:
    // If code_inner_html_occurrences is non-empty, the invariant is breached in active code!
    // In webui.rs:
    // Line 1365: const origHtml = btn ? btn.innerHTML : '';
    // Line 1375: btn.innerHTML = origHtml;
    assert!(
        code_inner_html_occurrences.is_empty(),
        "webui.rs violates Safe DOM Invariant! Found {} active innerHTML assignments/reads: {:?}",
        code_inner_html_occurrences.len(),
        code_inner_html_occurrences
    );
}
