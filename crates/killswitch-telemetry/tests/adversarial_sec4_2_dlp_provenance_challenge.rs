//! # Adversarial Empirical Challenge Suite: Requirement R5 & R7
//!
//! Subagent: `challenger_sec4_2`
//! Empirical challenge harness testing:
//! 1. Semantic DLP Entity Boundaries:
//!    - Deal Value threshold boundary ($999,999 vs. $1,000,000, large deals $45M, $12.5M, USD 4,200,000)
//!    - Strict Default-Deny on unclassified sensitive markers (never Allow)
//!    - PHI / HIPAA entities: SSN format, invalid area codes (000, 666, 900-999), invalid group/serial, medical context
//!    - Payment Card PAN: Valid Luhn vs. invalid checksum false-positive suppression
//!    - NPI validation: 10-digit Luhn with 80840 prefix
//!    - Presidio zero-PII scrubbing (<ZK_PII:TYPE:HASH8>) and volatile_scrub_bytes
//! 2. Repository Provenance & CI Verification:
//!    - Zero tracked .exe/.dll files in git
//!    - dist/SHA256SUMS.txt format
//!    - .github/workflows/ci.yml jobs and validity

use killswitch_telemetry::otel_lineage::{DlpClassification, DlpPolicy};
use killswitch_telemetry::semantic_dlp::{
    luhn_check, volatile_scrub_bytes, PresidioGlinerPiiZeroGuard, RedactXStructuredValidator,
    SemanticDlpEngine, SemanticEntityKind,
};
use std::path::Path;

// ============================================================================
// MODULE 1: DEAL VALUE THRESHOLD BOUNDARY & STRESS TESTS
// ============================================================================

#[test]
fn test_deal_value_boundary_exactly_999999() {
    let engine = SemanticDlpEngine::new();
    let payload = "Acquisition deal value: $999,999 payable at closing";
    let matches = engine.scan_payload(payload);
    assert!(!matches.is_empty(), "Should detect deal value for $999,999");
    let entity = &matches[0];
    assert_eq!(entity.kind, SemanticEntityKind::DealValue);
    assert_eq!(entity.classification, DlpClassification::Confidential);
    assert_eq!(entity.policy, DlpPolicy::Block);

    // Also without comma
    let payload_no_comma = "Acquisition deal value: $999999 payable at closing";
    let matches_nc = engine.scan_payload(payload_no_comma);
    assert!(!matches_nc.is_empty());
    assert_eq!(
        matches_nc[0].classification,
        DlpClassification::Confidential
    );
    assert_eq!(matches_nc[0].policy, DlpPolicy::Block);
}

#[test]
fn test_deal_value_boundary_exactly_1000000() {
    let engine = SemanticDlpEngine::new();
    let payload = "Acquisition deal value: $1,000,000 payable at closing";
    let matches = engine.scan_payload(payload);
    assert!(
        !matches.is_empty(),
        "Should detect deal value for $1,000,000"
    );
    let entity = &matches[0];
    assert_eq!(entity.kind, SemanticEntityKind::DealValue);
    assert_eq!(entity.classification, DlpClassification::CrownJewel);
    assert_eq!(entity.policy, DlpPolicy::Quarantine);

    // Also without comma
    let payload_no_comma = "Acquisition deal value: $1000000 payable at closing";
    let matches_nc = engine.scan_payload(payload_no_comma);
    assert!(!matches_nc.is_empty());
    assert_eq!(matches_nc[0].classification, DlpClassification::CrownJewel);
    assert_eq!(matches_nc[0].policy, DlpPolicy::Quarantine);
}

#[test]
fn test_deal_value_large_deals_45m_and_12_5m() {
    let engine = SemanticDlpEngine::new();

    // $45M
    let payload_45m = "Target merger acquisition deal value: $45M";
    let matches_45m = engine.scan_payload(payload_45m);
    assert!(!matches_45m.is_empty(), "Must detect $45M deal value");
    assert_eq!(matches_45m[0].kind, SemanticEntityKind::DealValue);
    assert_eq!(matches_45m[0].classification, DlpClassification::CrownJewel);
    assert_eq!(matches_45m[0].policy, DlpPolicy::Quarantine);

    // $12.5M
    let payload_12_5m = "Target merger acquisition deal value: $12.5M";
    let matches_12_5m = engine.scan_payload(payload_12_5m);
    assert!(!matches_12_5m.is_empty(), "Must detect $12.5M deal value");
    assert_eq!(matches_12_5m[0].kind, SemanticEntityKind::DealValue);
    assert_eq!(
        matches_12_5m[0].classification,
        DlpClassification::CrownJewel
    );
    assert_eq!(matches_12_5m[0].policy, DlpPolicy::Quarantine);
}

#[test]
fn test_deal_value_currency_symbols_euro_and_pound() {
    let engine = SemanticDlpEngine::new();

    // Euro above threshold: €1,500,000 -> CrownJewel, Quarantine
    let payload_euro_high = "Acquisition transaction value: €1,500,000";
    let matches_eh = engine.scan_payload(payload_euro_high);
    assert!(!matches_eh.is_empty());
    assert_eq!(matches_eh[0].classification, DlpClassification::CrownJewel);
    assert_eq!(matches_eh[0].policy, DlpPolicy::Quarantine);

    // Euro below threshold: €850,000 -> Confidential, Block
    let payload_euro_low = "Acquisition transaction value: €850,000";
    let matches_el = engine.scan_payload(payload_euro_low);
    assert!(!matches_el.is_empty());
    assert_eq!(
        matches_el[0].classification,
        DlpClassification::Confidential
    );
    assert_eq!(matches_el[0].policy, DlpPolicy::Block);

    // Pound above threshold: £2,500,000 -> CrownJewel, Quarantine
    let payload_pound_high = "Acquisition transaction value: £2,500,000";
    let matches_ph = engine.scan_payload(payload_pound_high);
    assert!(!matches_ph.is_empty());
    assert_eq!(matches_ph[0].classification, DlpClassification::CrownJewel);
    assert_eq!(matches_ph[0].policy, DlpPolicy::Quarantine);
}

#[test]
fn test_defect_1_usd_currency_code_currently_unmatched() {
    let engine = SemanticDlpEngine::new();
    let payload = "Acquisition transaction value: USD 4,200,000 payable at close";
    let matches = engine.scan_payload(payload);
    assert!(
        !matches.is_empty(),
        "Remediated: ISO 4217 currency code 'USD 4,200,000' must be detected as a sensitive deal value"
    );
    let entity = &matches[0];
    assert_eq!(entity.kind, SemanticEntityKind::DealValue);
    assert_eq!(entity.classification, DlpClassification::CrownJewel);
    assert_eq!(entity.policy, DlpPolicy::Quarantine);

    let verdict = engine.evaluate_verdict(payload);
    assert!(
        !verdict.is_allow(),
        "Remediated: USD 4,200,000 deal must not evaluate to Allow"
    );
    assert!(
        verdict.is_deny(),
        "Remediated: USD 4,200,000 deal must evaluate to Deny (Quarantine)"
    );

    // Attached and lookahead variants
    let payload_att = "Acquisition transaction value: USD4.2M payable at close";
    let matches_att = engine.scan_payload(payload_att);
    assert!(!matches_att.is_empty(), "USD4.2M must be detected");
    assert_eq!(matches_att[0].classification, DlpClassification::CrownJewel);
    assert_eq!(matches_att[0].policy, DlpPolicy::Quarantine);

    let payload_sep_word = "Acquisition transaction value: USD 4.2 million payable at close";
    let matches_sep_word = engine.scan_payload(payload_sep_word);
    assert!(
        !matches_sep_word.is_empty(),
        "USD 4.2 million must be detected"
    );
    assert_eq!(
        matches_sep_word[0].classification,
        DlpClassification::CrownJewel
    );
    assert_eq!(matches_sep_word[0].policy, DlpPolicy::Quarantine);
}

#[test]
fn test_defect_2_global_million_substring_inflates_sub_1m_deal() {
    let engine = SemanticDlpEngine::new();
    let payload = "Acquisition deal value: $500,000 for a company with 10 million users";
    let matches = engine.scan_payload(payload);
    assert!(!matches.is_empty(), "Must detect $500,000 deal value");
    assert_eq!(matches[0].kind, SemanticEntityKind::DealValue);
    // Remediated: Sub-$1M deal must NOT be inflated by unrelated 'million' in payload.
    // It must remain Confidential + Block.
    assert_eq!(
        matches[0].classification,
        DlpClassification::Confidential,
        "Remediated: $500,000 deal is classified as Confidential (not inflated to CrownJewel)"
    );
    assert_eq!(
        matches[0].policy,
        DlpPolicy::Block,
        "Remediated: $500,000 deal evaluates to Block (not Quarantine)"
    );

    let verdict = engine.evaluate_verdict(payload);
    assert!(
        verdict.is_restricted(),
        "Remediated: Sub-$1M deal evaluates to Restricted (Block)"
    );
    assert!(
        !verdict.is_allow(),
        "Remediated: Sub-$1M deal must not evaluate to Allow"
    );
}

// ============================================================================
// MODULE 2: STRICT DEFAULT-DENY ON UNCLASSIFIED SENSITIVE MARKERS
// ============================================================================

#[test]
fn test_strict_default_deny_all_markers_never_allow() {
    let engine = SemanticDlpEngine::new();
    let test_cases = [
        "Internal operational report: confidential data included",
        "Strategic plans: strictly confidential - executive team only",
        "Employee compensation records: do not distribute",
        "Algorithm architecture details: proprietary and confidential",
        "Core scoring heuristics: trade secret of the enterprise",
        "Engineering design doc: internal only",
        "Compliance audit finding: restricted distribution",
        "Board of directors advisory: privileged and confidential",
        "Legal dispute assessment: attorney-client privileged",
    ];

    for case in &test_cases {
        let matches = engine.scan_payload(case);
        assert!(
            !matches.is_empty(),
            "Payload '{}' must trigger sensitive entity detection",
            case
        );

        let entity = &matches[0];
        assert_ne!(
            entity.policy,
            DlpPolicy::Allow,
            "Sensitive marker '{}' must NEVER evaluate to Allow",
            case
        );
        assert!(
            entity.policy >= DlpPolicy::Block,
            "Sensitive marker '{}' must evaluate to Block or Quarantine, got {:?}",
            case,
            entity.policy
        );

        let verdict = engine.evaluate_verdict(case);
        assert!(
            !verdict.is_allow(),
            "Verdict for '{}' must NOT be Allow",
            case
        );

        let verdict_fail_closed = engine.evaluate_verdict_fail_closed(case);
        assert!(
            !verdict_fail_closed.is_allow(),
            "Fail-closed verdict for '{}' must NOT be Allow",
            case
        );
    }
}

// ============================================================================
// MODULE 3: PHI / HIPAA ENTITIES & SSN BOUNDARY STRESS
// ============================================================================

#[test]
fn test_ssn_structural_validation_valid_and_invalid() {
    // Valid SSA SSN formats
    assert!(RedactXStructuredValidator::ssn_valid("123", "45", "6789"));
    assert!(RedactXStructuredValidator::ssn_valid("219", "45", "6789"));
    assert!(RedactXStructuredValidator::ssn_valid("789", "12", "3456"));

    // Invalid Area: 000
    assert!(!RedactXStructuredValidator::ssn_valid("000", "45", "6789"));
    // Invalid Area: 666
    assert!(!RedactXStructuredValidator::ssn_valid("666", "45", "6789"));
    // Invalid Area: 900-999
    assert!(!RedactXStructuredValidator::ssn_valid("900", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("950", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("999", "45", "6789"));

    // Invalid Group: 00
    assert!(!RedactXStructuredValidator::ssn_valid("219", "00", "6789"));

    // Invalid Serial: 0000
    assert!(!RedactXStructuredValidator::ssn_valid("219", "45", "0000"));

    // Invalid digit counts / non-numeric
    assert!(!RedactXStructuredValidator::ssn_valid("21", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("219", "4", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("219", "45", "678"));
    assert!(!RedactXStructuredValidator::ssn_valid("ABC", "45", "6789"));
}

#[test]
fn test_phi_medical_context_detection_and_quarantine() {
    let engine = SemanticDlpEngine::new();

    // Valid SSN with medical context -> PhiMedicalRecord, CrownJewel, Quarantine
    let medical_payload =
        "Patient John Doe medical record: SSN 219-45-6789, diagnosis: hypertension";
    let matches = engine.scan_payload(medical_payload);
    assert!(!matches.is_empty(), "Must detect SSN in medical context");
    let ssn_match = matches
        .iter()
        .find(|m| m.kind == SemanticEntityKind::PhiMedicalRecord);
    assert!(ssn_match.is_some(), "Must match PhiMedicalRecord");
    let m = ssn_match.unwrap();
    assert_eq!(m.classification, DlpClassification::CrownJewel);
    assert_eq!(m.policy, DlpPolicy::Quarantine);
    assert!(m.confidence >= 0.98, "High confidence with medical context");

    // Valid SSN without explicit medical context -> Still caught and quarantined
    let general_payload = "Payroll export record: SSN 219-45-6789 verified";
    let matches_gen = engine.scan_payload(general_payload);
    assert!(!matches_gen.is_empty());
    assert_eq!(matches_gen[0].kind, SemanticEntityKind::PhiMedicalRecord);
    assert_eq!(matches_gen[0].policy, DlpPolicy::Quarantine);

    // Invalid SSN (area 000 or 666) -> Must NOT trigger SSN match
    let invalid_ssn_payload = "Sample test case: SSN 000-45-6789 and 666-12-3456";
    let matches_inv = engine.scan_payload(invalid_ssn_payload);
    assert!(
        matches_inv.is_empty(),
        "Invalid SSNs with areas 000 or 666 must NOT trigger false positive matches"
    );
}

// ============================================================================
// MODULE 4: PAYMENT CARD PAN LUHN VALIDATION & FALSE POSITIVE SUPPRESSION
// ============================================================================

#[test]
fn test_payment_card_luhn_valid_cards() {
    // Standard test card numbers known to satisfy Luhn:
    // Visa 16-digit
    assert!(luhn_check("4532015112830366"));
    // Mastercard 16-digit
    assert!(luhn_check("5425233430109903"));
    // Amex 15-digit
    assert!(luhn_check("378282246310005"));

    let engine = SemanticDlpEngine::new();
    let payload = "Payment processing for customer card 4532015112830366 on file";
    let matches = engine.scan_payload(payload);
    assert!(!matches.is_empty());
    assert_eq!(matches[0].kind, SemanticEntityKind::PaymentCard);
    assert_eq!(matches[0].classification, DlpClassification::CrownJewel);
    assert_eq!(matches[0].policy, DlpPolicy::Quarantine);
}

#[test]
fn test_payment_card_luhn_invalid_checksum_false_positive_suppression() {
    // Changed last digit -> checksum fails
    assert!(!luhn_check("4532015112830367"));
    assert!(!luhn_check("5425233430109904"));
    assert!(!luhn_check("378282246310006"));

    // Arbitrary digit sequence that does not satisfy Luhn
    assert!(!luhn_check("1234567890123456"));

    let engine = SemanticDlpEngine::new();
    let payload_invalid = "Arbitrary sequence 4532015112830367 and 1234567890123456";
    let matches = engine.scan_payload(payload_invalid);
    let card_matches: Vec<_> = matches
        .into_iter()
        .filter(|m| m.kind == SemanticEntityKind::PaymentCard)
        .collect();
    assert!(
        card_matches.is_empty(),
        "Numbers with invalid Luhn checksum must NOT trigger PaymentCard detections"
    );
}

// ============================================================================
// MODULE 5: 10-DIGIT NPI VALIDATION WITH 80840 PREFIX
// ============================================================================

#[test]
fn test_npi_validation_10_digit_luhn_with_80840_prefix() {
    // 1234567893: 808401234567893 passes Luhn
    assert!(RedactXStructuredValidator::npi_valid("1234567893"));

    // Invalid check digit: 1234567890
    assert!(!RedactXStructuredValidator::npi_valid("1234567890"));

    // All zeros: 0000000000 (808400000000000 -> 8*2-9=7, 8, 4*2=8, sum=23 % 10 != 0)
    assert!(!RedactXStructuredValidator::npi_valid("0000000000"));

    // Invalid lengths
    assert!(!RedactXStructuredValidator::npi_valid("123456789")); // 9 digits
    assert!(!RedactXStructuredValidator::npi_valid("12345678901")); // 11 digits

    // Non-digits
    assert!(!RedactXStructuredValidator::npi_valid("123456789A"));
    assert!(!RedactXStructuredValidator::npi_valid(" 12345678 "));
}

#[test]
fn test_defect_3_npi_unmatched_in_scan_payload() {
    let engine = SemanticDlpEngine::new();
    let payload = "Attending physician Dr. Alice Smith NPI 1234567893 authorized treatment";
    let matches = engine.scan_payload(payload);
    assert!(
        !matches.is_empty(),
        "Remediated: Valid NPI 1234567893 in clinical context must be detected by SemanticDlpEngine::scan_payload"
    );
    let npi_match = matches
        .iter()
        .find(|m| m.kind == SemanticEntityKind::PhiMedicalRecord);
    assert!(
        npi_match.is_some(),
        "Remediated: Must match PhiMedicalRecord for valid NPI"
    );
    let entity = npi_match.unwrap();
    assert_eq!(entity.classification, DlpClassification::CrownJewel);
    assert_eq!(entity.policy, DlpPolicy::Quarantine);
    assert!(entity.raw.contains("1234567893") || entity.text.contains("1234567893"));

    let verdict = engine.evaluate_verdict(payload);
    assert!(
        !verdict.is_allow(),
        "Remediated: Clinical NPI payload must not evaluate to Allow"
    );
    assert!(
        verdict.is_deny(),
        "Remediated: Clinical NPI payload must evaluate to Deny (Quarantine)"
    );
}

#[test]
fn test_defect_3_mrn_detection_in_scan_payload() {
    let engine = SemanticDlpEngine::new();
    let payload = "Patient medical record: MRN 1234569 admitted for treatment";
    let matches = engine.scan_payload(payload);
    assert!(
        !matches.is_empty(),
        "Remediated: Valid MRN in medical record context must be detected by SemanticDlpEngine::scan_payload"
    );
    let mrn_match = matches
        .iter()
        .find(|m| m.kind == SemanticEntityKind::PhiMedicalRecord);
    assert!(
        mrn_match.is_some(),
        "Remediated: Must match PhiMedicalRecord for valid MRN"
    );
    let entity = mrn_match.unwrap();
    assert_eq!(entity.classification, DlpClassification::CrownJewel);
    assert_eq!(entity.policy, DlpPolicy::Quarantine);

    let verdict = engine.evaluate_verdict(payload);
    assert!(
        !verdict.is_allow(),
        "Remediated: Clinical MRN payload must not evaluate to Allow"
    );
    assert!(
        verdict.is_deny(),
        "Remediated: Clinical MRN payload must evaluate to Deny (Quarantine)"
    );
}

// ============================================================================
// MODULE 6: PRESIDIO ZERO-PII SCRUBBING & VOLATILE MEMORY SCRUBBING
// ============================================================================

#[test]
fn test_presidio_zero_pii_scrubbing_and_commitment() {
    let raw_text = "Patient SSN 219-45-6789 and Card 4532015112830366 admitted to triage.";
    let (scrubbed, proof) = PresidioGlinerPiiZeroGuard::scrub_and_prove(raw_text);

    // Verify original sensitive values are eradicated from scrubbed text
    assert!(!scrubbed.contains("219-45-6789"), "SSN must be purged");
    assert!(!scrubbed.contains("4532015112830366"), "PAN must be purged");

    // Verify format <ZK_PII:TYPE:HASH8>
    assert!(
        scrubbed.contains("<ZK_PII:SSN:"),
        "Must contain ZK SSN commitment"
    );
    assert!(
        scrubbed.contains("<ZK_PII:PAN:"),
        "Must contain ZK PAN commitment"
    );

    // Verify commitment hash format: exactly 8 hex chars
    if let Some(idx) = scrubbed.find("<ZK_PII:SSN:") {
        let tag = &scrubbed[idx..idx + 21]; // "<ZK_PII:SSN:12345678>" is 21 chars
        assert!(tag.ends_with('>'));
        let hash_part = &tag[12..20];
        assert_eq!(hash_part.len(), 8);
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // Verify zero leakage proof
    assert!(proof.zero_leakage_verified);
    assert_eq!(proof.redacted_entity_count, 2);
    assert_eq!(proof.commitment_hash.len(), 64);
}

#[test]
fn test_volatile_scrub_bytes_clears_memory() {
    let mut secret_buf = *b"super_secret_pii_data_to_be_purged_0987654321";
    volatile_scrub_bytes(&mut secret_buf);

    for (i, &b) in secret_buf.iter().enumerate() {
        assert_eq!(b, 0u8, "Byte at index {} must be zeroized", i);
    }
}

// ============================================================================
// MODULE 7: REPOSITORY PROVENANCE & CI VERIFICATION (R7)
// ============================================================================

#[test]
fn test_provenance_zero_tracked_binaries_in_git() {
    let git_cmd = if Path::new("C:\\Program Files\\Git\\cmd\\git.exe").exists() {
        "C:\\Program Files\\Git\\cmd\\git.exe"
    } else {
        "git"
    };

    let output = std::process::Command::new(git_cmd)
        .args(["ls-files", "*.exe", "*.dll"])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            stdout.is_empty(),
            "Git index must not track any .exe or .dll files! Found: {}",
            stdout
        );
    }
}

#[test]
fn test_provenance_dist_sha256sums_exists_and_valid() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let manifest_path = root.join("dist").join("SHA256SUMS.txt");
    assert!(manifest_path.exists(), "dist/SHA256SUMS.txt must exist");

    let content = std::fs::read_to_string(&manifest_path).expect("Failed to read SHA256SUMS.txt");
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "SHA256SUMS.txt must not be empty");

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            parts.len(),
            2,
            "Each line must have exactly 2 parts: <hash>  <filename>, got '{}'",
            line
        );
        assert_eq!(
            parts[0].len(),
            64,
            "Hash must be 64 characters long: '{}'",
            parts[0]
        );
        assert!(
            parts[0].chars().all(|c| c.is_ascii_hexdigit()),
            "Hash must be hexadecimal: '{}'",
            parts[0]
        );
    }
}

#[test]
fn test_provenance_ci_yaml_validity_and_jobs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let ci_yaml_path = root.join(".github").join("workflows").join("ci.yml");
    assert!(ci_yaml_path.exists(), ".github/workflows/ci.yml must exist");

    let content = std::fs::read_to_string(&ci_yaml_path).expect("Failed to read ci.yml");

    assert!(content.contains("name: CI"));
    assert!(content.contains("push:"));
    assert!(content.contains("pull_request:"));
    assert!(content.contains("jobs:"));
    assert!(content.contains("test:"));
    assert!(content.contains("clippy:"));
    assert!(content.contains("binary-integrity:"));
    assert!(content.contains("cargo test --workspace"));
    assert!(content.contains("e2e_peer_review_remediation"));
    assert!(content.contains("git ls-files '*.exe' '*.dll'"));
}
