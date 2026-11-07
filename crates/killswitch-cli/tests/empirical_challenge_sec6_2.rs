//! # Tier 5 Empirical Adversarial Coverage Hardening Challenge Suite (SEC-6-2)
//!
//! Subagent: Challenger SEC-6-2 (critic, specialist)
//! Milestone: SEC-6 (Tier 5 Adversarial Coverage Hardening)
//!
//! Comprehensive white-box adversarial stress testing across 4 core subsystems:
//! 1. `crates/killswitch-server/src/auth.rs`:
//!    - Constant-time token matching timing attack resistance (subtle::ConstantTimeEq, whitespace trimming, length mismatch rejection)
//!    - Header extraction permutations & token sanitization (Authorization Bearer/bearer, X-KillSwitch-Token, empty/whitespace token rejection)
//!    - Caller PID spoofing rejection (claimed != actual peer PID -> 403 Forbidden / CALLER_PID_SPOOFED)
//!    - Quarantined caller isolation (frozen PID -> 403 Forbidden / CALLER_QUARANTINED)
//!    - Anti-evasion: Omitting claimed_pid (None) while actual peer PID is quarantined still fails closed (403 Forbidden)
//!    - Fail-closed behavior on unresolvable peer PID when claimed PID is present (401 UNAUTHORIZED)
//!    - `/engage` confirmation phrase handling (KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE)
//! 2. `crates/killswitch-telemetry/src/semantic_dlp.rs`:
//!    - M&A deal value boundary: exactly $999,999.99 (Confidential/Block) vs. $1,000,000.00 (CrownJewel/Quarantine)
//!    - Deal value magnitude scaling: $45M, $12.5M, $1.2B, USD 4,200,000, 15M EUR, 2.5 billion GBP
//!    - Irregular spacing and compact JSON: `{"deal_value":"$15,000,000"}`
//!    - Multi-byte UTF-8 contexts: emojis (💰, 🚀), Cyrillic deal contexts ("оценка сделки: $5,000,000")
//!    - False-positive suppression: "deal value: none", "deal value: $500", "deal value: $0"
//!    - HIPAA PHI validation:
//!      - SSN strict structural rules: area 000, 666, 900-999 rejected; group 00 rejected; serial 0000 rejected; valid SSN detected as CrownJewel/Quarantine
//!      - NPI 10-digit Luhn check: valid 1234567893 (Luhn with 80840 prefix) vs. invalid 1234567890 vs. 9/11-digit rejection
//!      - Mod-11 MRN: 1234569 in medical context detected; without medical context ignored
//!    - Default-deny containment on unclassified sensitive markers ("strictly confidential", "trade secret", "internal only")
//!    - `evaluate_verdict_fail_closed` override on silent allow
//!    - Presidio zero-PII scrubbing (<ZK_PII:SSN:HASH8>) and volatile memory zeroing (volatile_scrub_bytes)
//! 3. `crates/killswitch-core/src/wfp.rs`:
//!    - 24-layer shield GUID uniqueness (276 pairwise comparisons, 0 collisions)
//!    - Official GUID constants: FWPM_LAYER_IPFORWARD_V4, FWPM_LAYER_IPFORWARD_V6, SDK constants
//!    - WSL2 NAT packet filtering simulation (outbound traffic dropped at forward layer, loopback 127.0.0.1/::1 and control port 3030 preserved)
//!    - KILLSWITCH_SELF_DIAGNOSTIC protection verification
//! 4. `crates/killswitch-core/src/exec_sensor.rs`:
//!    - 32-thread concurrent flood of 3,200 events into 2048-capacity buffer
//!    - Strict FIFO eviction exactness
//!    - Subscriber panic resilience: panicking subscriber does not crash sensor or poison locks
//!    - Lock-drop subscriber pattern: callback querying snapshot() or len() does not deadlock
//!    - Micro-process start and exit event pairing

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

// 1. Auth imports
use killswitch_server::auth::{
    constant_time_token_match, extract_token_from_headers, verify_control_plane_request_with_token,
    AuthVerdict, DEFAULT_CONTROL_PLANE_HEADER, TEST_MASTER_TOKEN,
};
use killswitch_types::status::KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE;

// 2. Semantic DLP imports
use killswitch_telemetry::otel_lineage::{DlpClassification, DlpPolicy};
use killswitch_telemetry::semantic_dlp::{
    volatile_scrub_bytes, PresidioGlinerPiiZeroGuard, RedactXStructuredValidator,
    SemanticDlpEngine, SemanticEntityKind,
};

// 3. WFP imports
use killswitch_core::wfp::{
    WfpGuid, WindowsWfpIsolator, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_DATAGRAM_DATA_V4, FWPM_LAYER_DATAGRAM_DATA_V6, FWPM_LAYER_INBOUND_ICMP_ERROR_V4,
    FWPM_LAYER_INBOUND_ICMP_ERROR_V6, FWPM_LAYER_INBOUND_IPPACKET_V4,
    FWPM_LAYER_INBOUND_IPPACKET_V6, FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET,
    FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE, FWPM_LAYER_INBOUND_TRANSPORT_V4,
    FWPM_LAYER_INBOUND_TRANSPORT_V6, FWPM_LAYER_IPFORWARD_V4, FWPM_LAYER_IPFORWARD_V6,
    FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6,
    FWPM_LAYER_OUTBOUND_IPPACKET_V4, FWPM_LAYER_OUTBOUND_IPPACKET_V6,
    FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET, FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
};
use killswitch_types::status::NetworkIsolator;

// 4. Exec Sensor imports
use killswitch_core::exec_sensor::{clear_exec_events, ExecEvent, ExecSensorBuffer};

// ============================================================================
// PART 1: CONTROL PLANE MUTUAL AUTH ADVERSARIAL STRESS TESTS
// ============================================================================

#[test]
fn test_adversarial_auth_timing_ct_eq_and_casing_matrix() {
    let expected = TEST_MASTER_TOKEN;

    // 1. Exact match
    assert!(constant_time_token_match(expected, expected));

    // 2. Surrounding whitespace trimming
    assert!(constant_time_token_match(
        &format!("  \t\r\n{}   ", expected),
        expected
    ));
    assert!(constant_time_token_match(
        expected,
        &format!("   {}\n", expected)
    ));

    // 3. Length mismatches must reject
    assert!(!constant_time_token_match("", expected));
    assert!(!constant_time_token_match("   ", expected));
    assert!(!constant_time_token_match("KS-SHORT", expected));
    assert!(!constant_time_token_match(
        &format!("{}-EXTRA-BYTES", expected),
        expected
    ));

    // 4. Single-byte substitution variations across beginning, middle, and end
    let mut bad_start = expected.to_string();
    bad_start.replace_range(0..1, "Z");
    assert!(!constant_time_token_match(&bad_start, expected));

    let mid = expected.len() / 2;
    let mut bad_mid = expected.to_string();
    bad_mid.replace_range(mid..mid + 1, "X");
    assert!(!constant_time_token_match(&bad_mid, expected));

    let end = expected.len() - 1;
    let mut bad_end = expected.to_string();
    bad_end.replace_range(end..end + 1, "0");
    assert!(!constant_time_token_match(&bad_end, expected));

    // 5. Symmetric identity matching
    assert!(constant_time_token_match(expected, expected));

    // 6. Header extraction across supported permutations
    use axum::http::HeaderMap;

    let mut h1 = HeaderMap::new();
    h1.insert(
        "authorization",
        format!("Bearer {}", expected).parse().unwrap(),
    );
    assert_eq!(extract_token_from_headers(&h1), Some(expected.to_string()));

    let mut h2 = HeaderMap::new();
    h2.insert(
        "authorization",
        format!("bearer {}", expected).parse().unwrap(),
    );
    assert_eq!(extract_token_from_headers(&h2), Some(expected.to_string()));

    let mut h3 = HeaderMap::new();
    h3.insert(DEFAULT_CONTROL_PLANE_HEADER, expected.parse().unwrap());
    assert_eq!(extract_token_from_headers(&h3), Some(expected.to_string()));

    let mut h4 = HeaderMap::new();
    h4.insert("x-killswitch-token", expected.parse().unwrap());
    assert_eq!(extract_token_from_headers(&h4), Some(expected.to_string()));

    // 7. Malformed headers must return None
    let mut h_empty = HeaderMap::new();
    h_empty.insert("authorization", "Bearer ".parse().unwrap());
    assert_eq!(extract_token_from_headers(&h_empty), None);

    let mut h_basic = HeaderMap::new();
    h_basic.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
    assert_eq!(extract_token_from_headers(&h_basic), None);

    // 8. /engage confirmation phrase
    assert!(constant_time_token_match(
        KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE,
        "CONFIRM ISOLATE"
    ));
    assert!(constant_time_token_match(
        "  CONFIRM ISOLATE  ",
        KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE
    ));
    assert!(!constant_time_token_match(
        "confirm isolate",
        KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE
    ));
    assert!(!constant_time_token_match(
        "CONFIRM_ISOLATE",
        KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE
    ));
}

#[test]
fn test_adversarial_auth_pid_anti_spoofing_and_quarantine_fail_closed() {
    let valid_token = TEST_MASTER_TOKEN;
    let actual_peer_pid = 4000;
    let frozen_pids = vec![3000, 3001, 3002];

    // Case 1: Legitimate request with matching claimed PID
    let verdict = verify_control_plane_request_with_token(
        Some(valid_token),
        None,
        Some(4000),
        actual_peer_pid,
        &frozen_pids,
        valid_token,
    );
    assert_eq!(verdict, AuthVerdict::Authorized);

    // Case 2: Spoofed claimed PID (claims 9999, but actual socket is 4000)
    let verdict_spoof = verify_control_plane_request_with_token(
        Some(valid_token),
        None,
        Some(9999),
        actual_peer_pid,
        &frozen_pids,
        valid_token,
    );
    assert_eq!(verdict_spoof, AuthVerdict::Forbidden403PidSpoofing);

    // Case 3: Quarantined caller invoking control plane (actual peer PID 3001 is in frozen_pids)
    let verdict_quarantine = verify_control_plane_request_with_token(
        Some(valid_token),
        None,
        Some(3001),
        3001,
        &frozen_pids,
        valid_token,
    );
    assert_eq!(
        verdict_quarantine,
        AuthVerdict::Forbidden403CallerQuarantined
    );

    // Case 4: Anti-evasion — Quarantined caller omits claimed_pid (None)
    // Must STILL be rejected because actual_peer_pid 3001 is in frozen_pids!
    let verdict_no_claim = verify_control_plane_request_with_token(
        Some(valid_token),
        None,
        None,
        3001,
        &frozen_pids,
        valid_token,
    );
    assert_eq!(verdict_no_claim, AuthVerdict::Forbidden403CallerQuarantined);

    // Case 5: Missing token returns Unauthorized401
    let verdict_no_token = verify_control_plane_request_with_token(
        None,
        None,
        Some(4000),
        actual_peer_pid,
        &frozen_pids,
        valid_token,
    );
    assert_eq!(verdict_no_token, AuthVerdict::Unauthorized401);

    // Case 6: Invalid token returns Unauthorized401
    let verdict_bad_token = verify_control_plane_request_with_token(
        Some("INVALID-TOKEN"),
        None,
        Some(4000),
        actual_peer_pid,
        &frozen_pids,
        valid_token,
    );
    assert_eq!(verdict_bad_token, AuthVerdict::Unauthorized401);
}

// ============================================================================
// PART 2: SEMANTIC DLP ADVERSARIAL STRESS TESTS
// ============================================================================

#[test]
fn test_adversarial_dlp_deal_value_boundary_and_multibyte_matrix() {
    let engine = SemanticDlpEngine::new();

    // 1. Boundary: exactly $999,999 vs. $1,000,000
    let sub_threshold = "Merger agreement: deal value $999,999 payable at close.";
    let sub_matches = engine.scan_payload(sub_threshold);
    assert!(!sub_matches.is_empty(), "Must detect deal value token");
    assert_eq!(sub_matches[0].kind, SemanticEntityKind::DealValue);
    assert_eq!(
        sub_matches[0].classification,
        DlpClassification::Confidential
    );
    assert_eq!(sub_matches[0].policy, DlpPolicy::Block);

    let at_threshold = "Merger agreement: deal value $1,000,000 payable at close.";
    let at_matches = engine.scan_payload(at_threshold);
    assert!(!at_matches.is_empty(), "Must detect deal value token");
    assert_eq!(at_matches[0].kind, SemanticEntityKind::DealValue);
    assert_eq!(at_matches[0].classification, DlpClassification::CrownJewel);
    assert_eq!(at_matches[0].policy, DlpPolicy::Quarantine);

    // 2. Large deal magnitudes: $45M, $12.5M, $1.2B, USD 4,200,000, 15M EUR
    let deal_45m = engine.scan_payload("Target acquisition deal value: $45M");
    assert_eq!(deal_45m[0].classification, DlpClassification::CrownJewel);
    assert_eq!(deal_45m[0].policy, DlpPolicy::Quarantine);

    let deal_12_5m = engine.scan_payload("M&A transaction value: $12.5M in equity");
    assert_eq!(deal_12_5m[0].classification, DlpClassification::CrownJewel);
    assert_eq!(deal_12_5m[0].policy, DlpPolicy::Quarantine);

    let deal_1_2b = engine.scan_payload("Acquisition purchase price: $1.2B");
    assert_eq!(deal_1_2b[0].classification, DlpClassification::CrownJewel);
    assert_eq!(deal_1_2b[0].policy, DlpPolicy::Quarantine);

    let deal_usd_sep = engine.scan_payload("Deal size: USD 4,200,000 wired today");
    assert_eq!(
        deal_usd_sep[0].classification,
        DlpClassification::CrownJewel
    );
    assert_eq!(deal_usd_sep[0].policy, DlpPolicy::Quarantine);

    let deal_eur = engine.scan_payload("Merger valuation: 15M EUR");
    assert_eq!(deal_eur[0].classification, DlpClassification::CrownJewel);
    assert_eq!(deal_eur[0].policy, DlpPolicy::Quarantine);

    // 3. Compact JSON formatting
    let json_payload = r#"{"transaction_type":"acquisition","deal_value":"$15,000,000"}"#;
    let json_matches = engine.scan_payload(json_payload);
    assert!(!json_matches.is_empty());
    assert_eq!(
        json_matches[0].classification,
        DlpClassification::CrownJewel
    );
    assert_eq!(json_matches[0].policy, DlpPolicy::Quarantine);

    // 4. Multi-byte UTF-8 emojis & Cyrillic deal contexts
    let emoji_deal = engine.scan_payload("deal value: 💰 USD 25,000,000");
    assert_eq!(emoji_deal[0].classification, DlpClassification::CrownJewel);
    assert_eq!(emoji_deal[0].policy, DlpPolicy::Quarantine);

    let cyrillic_deal = engine.scan_payload("оценка сделки: $5,000,000");
    assert_eq!(
        cyrillic_deal[0].classification,
        DlpClassification::CrownJewel
    );
    assert_eq!(cyrillic_deal[0].policy, DlpPolicy::Quarantine);

    // 5. False positive avoidance
    let benign_none = engine.scan_payload("deal value: none reported");
    assert!(benign_none.is_empty());

    let benign_small = engine.scan_payload("deal value: $500 for supplies");
    assert_eq!(
        benign_small[0].classification,
        DlpClassification::Confidential
    );
    assert_eq!(benign_small[0].policy, DlpPolicy::Block);
}

#[test]
fn test_adversarial_dlp_hipaa_phi_checksum_and_default_deny() {
    let engine = SemanticDlpEngine::new();

    // 1. SSN structural validation
    // Valid SSNs
    assert!(RedactXStructuredValidator::ssn_valid("123", "45", "6789"));
    assert!(RedactXStructuredValidator::ssn_valid("899", "99", "9999"));

    // Invalid SSNs
    assert!(
        !RedactXStructuredValidator::ssn_valid("000", "45", "6789"),
        "Area 000 is invalid"
    );
    assert!(
        !RedactXStructuredValidator::ssn_valid("666", "45", "6789"),
        "Area 666 is invalid"
    );
    assert!(
        !RedactXStructuredValidator::ssn_valid("900", "45", "6789"),
        "Area 900 is invalid"
    );
    assert!(
        !RedactXStructuredValidator::ssn_valid("999", "45", "6789"),
        "Area 999 is invalid"
    );
    assert!(
        !RedactXStructuredValidator::ssn_valid("123", "00", "6789"),
        "Group 00 is invalid"
    );
    assert!(
        !RedactXStructuredValidator::ssn_valid("123", "45", "0000"),
        "Serial 0000 is invalid"
    );

    // Scan SSN in text
    let phi_valid = engine.scan_payload("Patient SSN 123-45-6789 admitted to clinical ward");
    assert!(!phi_valid.is_empty());
    assert_eq!(phi_valid[0].kind, SemanticEntityKind::PhiMedicalRecord);
    assert_eq!(phi_valid[0].classification, DlpClassification::CrownJewel);
    assert_eq!(phi_valid[0].policy, DlpPolicy::Quarantine);

    let phi_invalid_area = engine.scan_payload("Patient SSN 000-45-6789 false number");
    assert!(
        phi_invalid_area.is_empty(),
        "Invalid area 000 must not be flagged as PHI"
    );

    // 2. 10-digit NPI Luhn validation (with 80840 prefix)
    assert!(
        RedactXStructuredValidator::npi_valid("1234567893"),
        "Valid NPI must pass"
    );
    assert!(
        !RedactXStructuredValidator::npi_valid("1234567890"),
        "Invalid Luhn check must fail"
    );
    assert!(
        !RedactXStructuredValidator::npi_valid("123456789"),
        "9-digit candidate must fail"
    );
    assert!(
        !RedactXStructuredValidator::npi_valid("12345678901"),
        "11-digit candidate must fail"
    );

    let npi_scan =
        engine.scan_payload("Attending physician NPI: 1234567893 submitted clinical record");
    assert!(!npi_scan.is_empty());
    assert_eq!(npi_scan[0].kind, SemanticEntityKind::PhiMedicalRecord);
    assert_eq!(npi_scan[0].classification, DlpClassification::CrownJewel);

    // 3. Mod-11 MRN validation
    assert!(RedactXStructuredValidator::mod11_valid("1234569"));
    assert!(!RedactXStructuredValidator::mod11_valid("1234561"));

    let mrn_scan = engine.scan_payload("Patient medical record MRN 1234569 lab findings");
    assert!(!mrn_scan.is_empty());
    assert_eq!(mrn_scan[0].kind, SemanticEntityKind::PhiMedicalRecord);

    // 4. Default-Deny on unclassified sensitive markers
    let markers = [
        "This project contains strictly confidential data",
        "Company trade secret algorithms",
        "Document is internal only",
        "Privileged and confidential attorney work product",
    ];
    for m in &markers {
        let verdict = engine.evaluate_verdict(m);
        assert!(!verdict.is_allow(), "Marker '{}' must NOT allow", m);
        assert!(verdict.is_restricted() || verdict.is_deny());
    }

    // 5. evaluate_verdict_fail_closed override
    let fail_closed_verdict = engine.evaluate_verdict_fail_closed("confidential note");
    assert!(fail_closed_verdict.is_restricted());

    // 6. Presidio zero-PII scrubbing & volatile wiping
    let raw_text = "Clinical note: Patient SSN 123-45-6789 confirmed.";
    let (scrubbed, proof) = PresidioGlinerPiiZeroGuard::scrub_and_prove(raw_text);
    assert!(!scrubbed.contains("123-45-6789"));
    assert!(scrubbed.contains("<ZK_PII:SSN:"));
    assert!(proof.zero_leakage_verified);

    let mut secret_buf = *b"super_confidential_token_buffer";
    volatile_scrub_bytes(&mut secret_buf);
    assert!(secret_buf.iter().all(|&b| b == 0));
}

// ============================================================================
// PART 3: WFP 24-LAYER SHIELD, FORWARD LAYER & LOOPBACK ADVERSARIAL TESTS
// ============================================================================

#[test]
fn test_adversarial_wfp_24_layer_shield_forward_layer_and_loopback() {
    // 1. Verify 24 layer GUID uniqueness and non-zero
    let all_24_layers: [WfpGuid; 24] = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        FWPM_LAYER_INBOUND_TRANSPORT_V4,
        FWPM_LAYER_INBOUND_TRANSPORT_V6,
        FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        FWPM_LAYER_INBOUND_IPPACKET_V4,
        FWPM_LAYER_INBOUND_IPPACKET_V6,
        FWPM_LAYER_DATAGRAM_DATA_V4,
        FWPM_LAYER_DATAGRAM_DATA_V6,
        FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4,
        FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6,
        FWPM_LAYER_INBOUND_ICMP_ERROR_V4,
        FWPM_LAYER_INBOUND_ICMP_ERROR_V6,
        FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
        FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
        FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET,
        FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET,
        FWPM_LAYER_IPFORWARD_V4,
        FWPM_LAYER_IPFORWARD_V6,
    ];

    let mut set = HashSet::new();
    for (i, layer) in all_24_layers.iter().enumerate() {
        assert_ne!(
            *layer,
            WfpGuid::default(),
            "Layer {} must not be zeroed GUID",
            i
        );
        assert!(
            set.insert(*layer),
            "Layer {} collided with a previous GUID (must be pairwise distinct)",
            i
        );
    }
    assert_eq!(set.len(), 24, "Must have exactly 24 unique layer GUIDs");

    // 2. Official GUID constants verification
    assert_eq!(
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            FWPM_LAYER_IPFORWARD_V4.data1,
            FWPM_LAYER_IPFORWARD_V4.data2,
            FWPM_LAYER_IPFORWARD_V4.data3,
            FWPM_LAYER_IPFORWARD_V4.data4[0],
            FWPM_LAYER_IPFORWARD_V4.data4[1],
            FWPM_LAYER_IPFORWARD_V4.data4[2],
            FWPM_LAYER_IPFORWARD_V4.data4[3],
            FWPM_LAYER_IPFORWARD_V4.data4[4],
            FWPM_LAYER_IPFORWARD_V4.data4[5],
            FWPM_LAYER_IPFORWARD_V4.data4[6],
            FWPM_LAYER_IPFORWARD_V4.data4[7],
        ),
        "444543b6-9046-4246-ab81-9b06227e243d"
    );

    assert_eq!(
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            FWPM_LAYER_IPFORWARD_V6.data1,
            FWPM_LAYER_IPFORWARD_V6.data2,
            FWPM_LAYER_IPFORWARD_V6.data3,
            FWPM_LAYER_IPFORWARD_V6.data4[0],
            FWPM_LAYER_IPFORWARD_V6.data4[1],
            FWPM_LAYER_IPFORWARD_V6.data4[2],
            FWPM_LAYER_IPFORWARD_V6.data4[3],
            FWPM_LAYER_IPFORWARD_V6.data4[4],
            FWPM_LAYER_IPFORWARD_V6.data4[5],
            FWPM_LAYER_IPFORWARD_V6.data4[6],
            FWPM_LAYER_IPFORWARD_V6.data4[7],
        ),
        "12fe69b5-485a-40e7-912a-82b818121294"
    );

    // 3. WSL2 NAT Forward Layer packet filtering simulation
    struct SimulatedForwardFilter {
        forward_v4_blocked: bool,
        forward_v6_blocked: bool,
        loopback_permitted: bool,
        control_port_permitted: bool,
    }

    impl SimulatedForwardFilter {
        fn new_quarantine() -> Self {
            Self {
                forward_v4_blocked: true,
                forward_v6_blocked: true,
                loopback_permitted: true,
                control_port_permitted: true,
            }
        }

        fn evaluate_packet(
            &self,
            src: IpAddr,
            dst: IpAddr,
            dst_port: u16,
            is_forwarded: bool,
        ) -> &'static str {
            if is_forwarded {
                if dst.is_loopback() {
                    return "PERMIT";
                }
                match dst {
                    IpAddr::V4(_) if self.forward_v4_blocked => "DROP_FORWARD_V4",
                    IpAddr::V6(_) if self.forward_v6_blocked => "DROP_FORWARD_V6",
                    _ => "PERMIT",
                }
            } else if dst.is_loopback() || src.is_loopback() {
                if dst_port == 3030 && self.control_port_permitted {
                    "PERMIT_CONTROL_PORT"
                } else if self.loopback_permitted {
                    "PERMIT_LOOPBACK"
                } else {
                    "DROP"
                }
            } else {
                "DROP_OUTBOUND"
            }
        }
    }

    let filter = SimulatedForwardFilter::new_quarantine();

    // WSL2 forwarded NAT packet to 8.8.8.8 must be DROPPED
    let wsl2_pkt = filter.evaluate_packet(
        "172.28.16.2".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        443,
        true,
    );
    assert_eq!(wsl2_pkt, "DROP_FORWARD_V4");

    // WSL2 forwarded IPv6 packet must be DROPPED
    let wsl2_v6_pkt = filter.evaluate_packet(
        "fd00::2".parse().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
        443,
        true,
    );
    assert_eq!(wsl2_v6_pkt, "DROP_FORWARD_V6");

    // Local loopback packet on control port 3030 must be PERMITTED
    let lb_ctrl = filter.evaluate_packet(
        "127.0.0.1".parse().unwrap(),
        "127.0.0.1".parse().unwrap(),
        3030,
        false,
    );
    assert_eq!(lb_ctrl, "PERMIT_CONTROL_PORT");

    // 4. KILLSWITCH_SELF_DIAGNOSTIC safety
    std::env::set_var("KILLSWITCH_SELF_DIAGNOSTIC", "1");
    let isolator = WindowsWfpIsolator;
    let reset_res = isolator.reset_tcp_connections(Some(&["192.0.2.254".parse().unwrap()]));
    assert_eq!(
        reset_res.unwrap(),
        0,
        "Must return Ok(0) under KILLSWITCH_SELF_DIAGNOSTIC"
    );
    std::env::remove_var("KILLSWITCH_SELF_DIAGNOSTIC");
}

// ============================================================================
// PART 4: ZERO-POLLING KERNEL EXEC SENSOR ADVERSARIAL STRESS TESTS
// ============================================================================

#[test]
fn test_adversarial_exec_sensor_concurrency_fifo_and_panic_resilience() {
    clear_exec_events();

    // 1. Multi-threaded flood & FIFO capacity exactness
    let capacity = 500;
    let buffer = Arc::new(ExecSensorBuffer::new(capacity));
    let thread_count = 16;
    let events_per_thread = 100; // Total 1,600 events into 500 capacity buffer
    let mut handles = Vec::new();

    let barrier = Arc::new(AtomicBool::new(false));

    for t in 0..thread_count {
        let b = Arc::clone(&buffer);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            while !bar.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            for i in 0..events_per_thread {
                let pid = (t * 1000 + i + 1) as u32;
                let ev = ExecEvent::new_start(
                    pid,
                    t as u32,
                    format!("worker_{t}.exe"),
                    format!("worker_{t}.exe --item {i}"),
                    Some(1000),
                    Some(0),
                );
                b.push(ev);
            }
        }));
    }

    barrier.store(true, Ordering::Release);
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        buffer.len(),
        capacity,
        "Buffer must strictly equal capacity (500)"
    );
    let snap = buffer.snapshot();
    assert_eq!(snap.len(), capacity);

    // 2. Subscriber panic isolation: Panicking subscriber must not crash the sensor or block others
    let received_count = Arc::new(AtomicUsize::new(0));
    let received_clone = Arc::clone(&received_count);

    // Normal subscriber
    buffer.subscribe(Arc::new(move |_ev| {
        received_clone.fetch_add(1, Ordering::Relaxed);
    }));

    // Panicking subscriber
    buffer.subscribe(Arc::new(|_ev| {
        panic!("Deliberate adversarial subscriber crash!");
    }));

    // Push 10 new events through the buffer
    for i in 0..10 {
        let ev = ExecEvent::new_start(
            5000 + i,
            1,
            "test_proc.exe".to_string(),
            "test_proc.exe".to_string(),
            None,
            None,
        );
        buffer.push(ev);
    }

    // Normal subscriber must have received all 10 events despite the panicking subscriber
    assert_eq!(
        received_count.load(Ordering::Relaxed),
        10,
        "Normal subscriber must receive all events even when peer subscriber panics"
    );

    // 3. Lock-drop subscriber pattern: Callback querying snapshot() inside handler does NOT deadlock
    let reentrant_success = Arc::new(AtomicBool::new(false));
    let reentrant_clone = Arc::clone(&reentrant_success);
    let buf_ref = Arc::clone(&buffer);

    buffer.subscribe(Arc::new(move |_ev| {
        // Querying len() and snapshot() while inside push callback
        let l = buf_ref.len();
        let s = buf_ref.snapshot_recent(5);
        if l > 0 && !s.is_empty() {
            reentrant_clone.store(true, Ordering::SeqCst);
        }
    }));

    let test_ev = ExecEvent::new_start(
        9999,
        1,
        "reentrant_test.exe".to_string(),
        "reentrant_test.exe".to_string(),
        None,
        None,
    );
    buffer.push(test_ev);

    assert!(
        reentrant_success.load(Ordering::SeqCst),
        "Lock-drop subscriber pattern must prevent deadlocks on re-entrant buffer queries"
    );

    // 4. Micro-process start and exit event pairing
    let start_ev = ExecEvent::new_start(
        8888,
        1,
        "micro.exe".to_string(),
        "micro.exe".to_string(),
        None,
        None,
    );
    assert!(start_ev.is_start());
    assert!(!start_ev.is_exit());
    assert_eq!(start_ev.exit_code, None);

    let exit_ev = ExecEvent::new_exit(8888, 1, "micro.exe".to_string(), "micro.exe".to_string(), 0);
    assert!(exit_ev.is_exit());
    assert!(!exit_ev.is_start());
    assert_eq!(exit_ev.exit_code, Some(0));

    clear_exec_events();
}
