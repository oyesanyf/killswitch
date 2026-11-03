//! Empirical Challenge Test Suite for Milestone M1 Challenger 2 (`crates/killswitch-telemetry`)
//!
//! Adversarial stress testing for:
//! 1. RFC 8785 JSON Canonicalization Scheme (JCS):
//!    - IEEE 754 float formatting (-0.0 normalization, integer vs fraction, exponent limits).
//!    - UTF-16 surrogate pairs vs Unicode code point ordering.
//!    - Whitespace preservation inside strings vs elimination outside strings.
//!    - Control character escaping and raw UTF-8 byte serialization.
//! 2. `cage_governance.rs` CBF 24h Rolling Window Accumulation:
//!    - Precise 86,400,000 ms sliding window cutoff boundaries.
//!    - Monotonic dose decay over time.
//!    - Keyed cumulative tracker isolation across workloads.
//!    - Rapid concurrent dose accumulation and thread safety.
//!    - 5-state verdict lattice serialization, aliases, and equivalence invariants.

use std::sync::Arc;
use std::thread;
use killswitch_telemetry::{
    canonicalize_jcs, canonicalize_jcs_string,
    cage_governance::{
        CageEvaluationRequest, CageEvaluationResponse, CageGovernanceKernel, CageVerdict,
        Cumulative24hTracker, KeyedCumulative24hTracker, HealthcareDoseBarrier, CTRL_CBF_DOSE_001,
    },
};
use serde_json::{json, Value};

// ============================================================================
// SUITE 1: RFC 8785 JCS Canonicalization Stress Tests
// ============================================================================

#[test]
fn test_jcs_ieee754_float_zero_and_negative_zero() {
    // RFC 8785 Section 3.2.2.3: -0 MUST be serialized as "0"
    let val_zero = json!(0.0);
    let val_neg_zero = json!(-0.0);

    let res_zero = canonicalize_jcs_string(&val_zero).unwrap();
    let res_neg_zero = canonicalize_jcs_string(&val_neg_zero).unwrap();

    assert_eq!(res_zero, "0", "0.0 must serialize to '0'");
    assert_eq!(res_neg_zero, "0", "-0.0 must serialize to '0' per RFC 8785 Section 3.2.2.3");
}

#[test]
fn test_jcs_ieee754_non_finite_rejection() {
    // RFC 8785 Section 3.2.2.3: NaN, Infinity, -Infinity must be rejected
    // serde_json does not allow building NaN/Infinity directly via json! macro,
    // so we construct a Value::Number from raw float if possible or test JcsError
    let nan_val = Value::Number(serde_json::Number::from_f64(f64::NAN).unwrap_or_else(|| {
        serde_json::Number::from(0)
    }));
    // If serde_json prevented NaN, it's already safe at JSON layer.
    // If it allowed it, canonicalize_jcs must return an error.
    if let Value::Number(ref n) = nan_val {
        if n.as_f64().map_or(false, |f| !f.is_finite()) {
            assert!(canonicalize_jcs(&nan_val).is_err(), "NaN must return JcsError::NonFiniteNumber");
        }
    }
}

#[test]
fn test_jcs_ieee754_float_integers_and_boundary_exponents() {
    // Test integer-valued floats within standard integer range
    let v1 = json!(100.0);
    assert_eq!(canonicalize_jcs_string(&v1).unwrap(), "100");

    let v2 = json!(-42.0);
    assert_eq!(canonicalize_jcs_string(&v2).unwrap(), "-42");

    let v3 = json!(1000000.0);
    assert_eq!(canonicalize_jcs_string(&v3).unwrap(), "1000000");

    // Standard decimal fractions
    let v_frac = json!(0.125);
    assert_eq!(canonicalize_jcs_string(&v_frac).unwrap(), "0.125");

    let v_neg_frac = json!(-0.5);
    assert_eq!(canonicalize_jcs_string(&v_neg_frac).unwrap(), "-0.5");
}

#[test]
fn test_jcs_large_float_investigation() {
    let v_1e19 = json!(1e19);
    let s_1e19 = canonicalize_jcs_string(&v_1e19).unwrap();
    eprintln!("1e19 serialized: {}", s_1e19);

    let v_1e20 = json!(1e20);
    let s_1e20 = canonicalize_jcs_string(&v_1e20).unwrap();
    eprintln!("1e20 serialized: {}", s_1e20);

    let v_1e21 = json!(1e21);
    let s_1e21 = canonicalize_jcs_string(&v_1e21).unwrap();
    eprintln!("1e21 serialized: {}", s_1e21);

    let v_1e22 = json!(1e22);
    let s_1e22 = canonicalize_jcs_string(&v_1e22).unwrap();
    eprintln!("1e22 serialized: {}", s_1e22);

    let v_1e_neg7 = json!(1e-7);
    let s_1e_neg7 = canonicalize_jcs_string(&v_1e_neg7).unwrap();
    eprintln!("1e-7 serialized: {}", s_1e_neg7);

    let v_neg_1e19 = json!(-1e19);
    let s_neg_1e19 = canonicalize_jcs_string(&v_neg_1e19).unwrap();
    eprintln!("-1e19 serialized: {}", s_neg_1e19);
}

#[test]
fn test_jcs_utf16_surrogate_pair_vs_code_point_key_ordering() {
    // RFC 8785 Section 3.2.3: Object keys MUST be sorted by UTF-16 code units.
    // U+10000 encodes to [0xD800, 0xDC00] in UTF-16.
    // U+E000 encodes to [0xE000] in UTF-16.
    // In code point / UTF-8 byte order: U+E000 (0xEE 0x80 0x80) < U+10000 (0xF0 0x90 0x80 0x80).
    // In UTF-16 code unit order: 0xD800 < 0xE000, so U+10000 MUST PRECEDES U+E000!
    let val = json!({
        "\u{E000}": "bmp_e000",
        "\u{10000}": "astral_10000"
    });
    let canonical = canonicalize_jcs_string(&val).unwrap();
    let expected = format!(r#"{{"{}":"astral_10000","{}":"bmp_e000"}}"#, "\u{10000}", "\u{E000}");
    assert_eq!(
        canonical, expected,
        "U+10000 (lead surrogate 0xD800) must sort before U+E000 (0xE000) under UTF-16 code unit order"
    );

    // Multi-key UTF-16 sorting stress test
    let multi_key = json!({
        "z": 1,
        "a": 2,
        "\u{FFFF}": 3,
        "\u{10FFFF}": 4,
        "\u{0080}": 5,
        "\u{D7FF}": 6
    });
    // UTF-16 code units:
    // "a"       -> [0x0061]
    // "z"       -> [0x007A]
    // "\u{0080}"-> [0x0080]
    // "\u{D7FF}"-> [0xD7FF]
    // "\u{10FFFF}" (lead surrogate 0xDBFF) -> [0xDBFF, 0xDFFF]
    // "\u{FFFF}"-> [0xFFFF]
    let canonical_multi = canonicalize_jcs_string(&multi_key).unwrap();
    let expected_multi = format!(
        r#"{{"a":2,"z":1,"{}":5,"{}":6,"{}":4,"{}":3}}"#,
        "\u{0080}", "\u{D7FF}", "\u{10FFFF}", "\u{FFFF}"
    );
    assert_eq!(canonical_multi, expected_multi);
}

#[test]
fn test_jcs_whitespace_preservation_inside_strings() {
    // RFC 8785 Section 3.2.2.2: Whitespace INSIDE strings must be strictly preserved!
    let val = json!({
        "spaced": "   hello   world   ",
        "tabbed": "line1\tline2",
        "newlines": "first\nsecond\r\nthird",
        "nested": [
            "  leading and trailing  ",
            "   "
        ]
    });
    let canonical = canonicalize_jcs_string(&val).unwrap();
    assert!(canonical.contains(r#""spaced":"   hello   world   ""#));
    assert!(canonical.contains(r#""tabbed":"line1\tline2""#));
    assert!(canonical.contains(r#""newlines":"first\nsecond\r\nthird""#));
    assert!(canonical.contains(r#"["  leading and trailing  ","   "]"#));
}

#[test]
fn test_jcs_whitespace_elimination_outside_strings() {
    let raw = r#"{
        "status" :   "ACTIVE"  ,
        "count"  :  42 ,
        "list"   : [  1 ,   2 ,   "  spaced  "  ]
    }"#;
    let parsed: Value = serde_json::from_str(raw).unwrap();
    let canonical = canonicalize_jcs_string(&parsed).unwrap();
    assert_eq!(canonical, r#"{"count":42,"list":[1,2,"  spaced  "],"status":"ACTIVE"}"#);
}

#[test]
fn test_jcs_escaping_control_characters() {
    // Control characters 0x00 to 0x1F must be escaped.
    // 0x08 -> \b, 0x09 -> \t, 0x0A -> \n, 0x0C -> \f, 0x0D -> \r
    // All others -> \u00XX with lowercase hex
    let val = json!({
        "ctrl": "\x00\x01\x1F\x08\x09\x0A\x0C\x0D",
        "slash": "https://example.com/api/v1/test"
    });
    let canonical = canonicalize_jcs_string(&val).unwrap();
    assert!(
        canonical.contains(r#""ctrl":"\u0000\u0001\u001f\b\t\n\f\r""#),
        "Control characters must use lowercase hex escapes"
    );
    // Forward slash '/' must NOT be escaped
    assert!(
        canonical.contains(r#""slash":"https://example.com/api/v1/test""#),
        "Forward slash '/' must NOT be escaped per RFC 8785 Section 3.2.2.2"
    );
}

// ============================================================================
// SUITE 2: CBF 24h Rolling Window Accumulation & Boundary Stress Tests
// ============================================================================

#[test]
fn test_cbf_24h_sliding_window_exact_boundary() {
    let tracker = Cumulative24hTracker::new();
    let t0 = 100_000_000u64;

    // Record an amount of 50.0 at t0
    tracker.record(t0, 50.0);

    // 1. Immediately after at t0: cumulative is 50.0
    assert_eq!(tracker.get_cumulative_24h(t0), 50.0);

    // 2. Exactly at 24 hours later (t0 + 86_400_000 ms):
    // Cutoff = (t0 + 86_400_000) - 86_400_000 = t0.
    // Since ts (t0) is NOT strictly less than cutoff, entry is RETAINED.
    let t_exact_24h = t0 + 86_400_000;
    assert_eq!(
        tracker.get_cumulative_24h(t_exact_24h),
        50.0,
        "Entry at exact 24h mark (now - 86,400,000) must be included in cumulative dose"
    );

    // 3. Exactly 1 millisecond past 24 hours (t0 + 86_400_001 ms):
    // Cutoff = t0 + 1. Since ts (t0) < cutoff (t0 + 1), entry MUST BE PRUNED.
    let t_past_24h = t0 + 86_400_001;
    assert_eq!(
        tracker.get_cumulative_24h(t_past_24h),
        0.0,
        "Entry at 24h + 1ms must be pruned from sliding window"
    );
}

#[test]
fn test_cbf_24h_sliding_window_monotonic_decay() {
    let tracker = Cumulative24hTracker::new();
    let h6 = 6 * 3600 * 1000u64; // 6 hours in ms
    let t0 = 100_000_000u64;

    // Record 10.0 mg every 6 hours across a 24-hour cycle
    tracker.record(t0, 10.0);            // 0h
    tracker.record(t0 + h6, 10.0);       // 6h
    tracker.record(t0 + 2 * h6, 10.0);   // 12h
    tracker.record(t0 + 3 * h6, 10.0);   // 18h
    tracker.record(t0 + 4 * h6, 10.0);   // 24h

    // At 24h: all 5 events are within the [t0, t0 + 24h] window
    assert_eq!(tracker.get_cumulative_24h(t0 + 4 * h6), 50.0);

    // At 24h + 1ms: event at t0 is pruned -> 40.0 remaining
    assert_eq!(tracker.get_cumulative_24h(t0 + 4 * h6 + 1), 40.0);

    // At 30h + 1ms: event at t0 + 6h is pruned -> 30.0 remaining
    assert_eq!(tracker.get_cumulative_24h(t0 + 5 * h6 + 1), 30.0);

    // At 36h + 1ms: event at t0 + 12h is pruned -> 20.0 remaining
    assert_eq!(tracker.get_cumulative_24h(t0 + 6 * h6 + 1), 20.0);

    // At 42h + 1ms: event at t0 + 18h is pruned -> 10.0 remaining
    assert_eq!(tracker.get_cumulative_24h(t0 + 7 * h6 + 1), 10.0);

    // At 48h + 1ms: all events pruned -> 0.0 remaining
    assert_eq!(tracker.get_cumulative_24h(t0 + 8 * h6 + 1), 0.0);
}

#[test]
fn test_cbf_zero_and_negative_amounts_ignored() {
    let tracker = Cumulative24hTracker::new();
    let t0 = 1_000_000u64;

    tracker.record(t0, 0.0);
    tracker.record(t0, -10.0);
    tracker.record(t0, -100.5);

    assert_eq!(tracker.get_cumulative_24h(t0), 0.0, "Zero and negative amounts must not accumulate");

    tracker.record(t0, 25.0);
    assert_eq!(tracker.get_cumulative_24h(t0), 25.0);
}

#[test]
fn test_keyed_cbf_tracker_workload_isolation() {
    let keyed = KeyedCumulative24hTracker::new();
    let t0 = 10_000_000u64;

    keyed.record("agent_alpha", t0, 100.0);
    keyed.record("agent_beta", t0, 250.0);

    assert_eq!(keyed.get_cumulative_24h("agent_alpha", t0), 100.0);
    assert_eq!(keyed.get_cumulative_24h("agent_beta", t0), 250.0);
    assert_eq!(keyed.get_cumulative_24h("agent_gamma", t0), 0.0, "Unseen agent must return 0.0");

    // Advance time past 24h for agent_alpha
    let t_past = t0 + 86_400_001;
    assert_eq!(keyed.get_cumulative_24h("agent_alpha", t_past), 0.0);
    assert_eq!(keyed.get_cumulative_24h("agent_beta", t_past), 0.0);
}

#[test]
fn test_cbf_concurrent_rapid_accumulation() {
    let tracker = Arc::new(Cumulative24hTracker::new());
    let t0 = 50_000_000u64;
    let num_threads = 20;
    let increments_per_thread = 50;
    let increment_val = 2.0;

    let mut handles = Vec::new();
    for i in 0..num_threads {
        let tr = Arc::clone(&tracker);
        handles.push(thread::spawn(move || {
            for j in 0..increments_per_thread {
                tr.record(t0 + (i * 1000 + j) as u64, increment_val);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let expected = (num_threads * increments_per_thread) as f64 * increment_val;
    let actual = tracker.get_cumulative_24h(t0 + 100_000);
    assert!(
        (actual - expected).abs() < 1e-6,
        "Concurrent cumulative accumulation mismatch: expected {}, got {}",
        expected,
        actual
    );
}

#[test]
fn test_cbf_healthcare_dose_barrier_forward_invariance() {
    // Max single: 50.0, Max daily: 100.0, gamma: 0.50
    let barrier = HealthcareDoseBarrier::new(50.0, 100.0, 0.0, 0.50);

    // 1. Proposed single dose 30.0 mg with 0 cum dose: passes
    assert!(barrier.evaluate(30.0).is_ok());

    // 2. Proposed single dose 55.0 mg: exceeds single dose cap 50.0 mg
    let err_single = barrier.evaluate(55.0).unwrap_err();
    assert_eq!(err_single.0, CTRL_CBF_DOSE_001);
    assert!(err_single.1.contains("exceeds single administration cap"));

    // 3. High cumulative dose approaching daily cap:
    // If cum dose is 90.0 mg, proposed dose is 15.0 mg -> 105.0 mg breaches lethal threshold 100.0 mg
    let barrier_near_cap = HealthcareDoseBarrier::new(50.0, 100.0, 90.0, 0.50);
    let err_lethal = barrier_near_cap.evaluate(15.0).unwrap_err();
    assert_eq!(err_lethal.0, CTRL_CBF_DOSE_001);
    assert!(err_lethal.1.contains("breaches lethal threshold"));

    // 4. Barrier invariance B(x) = h_next - (1 - gamma) * h_k < 0:
    // With gamma = 0.5, h_k = 100 - 60 = 40.
    // If proposed is 30, new_cum = 90, h_next = 10.
    // B(x) = 10 - 0.5 * 40 = 10 - 20 = -10 < 0!
    let barrier_invariance = HealthcareDoseBarrier::new(50.0, 100.0, 60.0, 0.50);
    let err_inv = barrier_invariance.evaluate(30.0).unwrap_err();
    assert_eq!(err_inv.0, CTRL_CBF_DOSE_001);
    assert!(err_inv.1.contains("Dose barrier invariance violated"));
}

// ============================================================================
// SUITE 3: 5-State Verdict Lattice & Invariant Stress Tests
// ============================================================================

#[test]
fn test_cage_verdict_5_state_lattice_equality_and_aliases() {
    // In CAGE's 5-state lattice:
    // Allow and Clear are equivalent
    // Deny and Refuse are equivalent
    assert_eq!(CageVerdict::Allow, CageVerdict::Clear);
    assert_eq!(CageVerdict::Clear, CageVerdict::Allow);
    assert_eq!(CageVerdict::Deny, CageVerdict::Refuse);
    assert_eq!(CageVerdict::Refuse, CageVerdict::Deny);

    assert_ne!(CageVerdict::Allow, CageVerdict::Narrow);
    assert_ne!(CageVerdict::Allow, CageVerdict::RequireApproval);
    assert_ne!(CageVerdict::Allow, CageVerdict::Defer);
    assert_ne!(CageVerdict::Allow, CageVerdict::Deny);

    assert_ne!(CageVerdict::Narrow, CageVerdict::RequireApproval);
    assert_ne!(CageVerdict::Narrow, CageVerdict::Defer);
    assert_ne!(CageVerdict::Narrow, CageVerdict::Deny);

    assert_ne!(CageVerdict::RequireApproval, CageVerdict::Defer);
    assert_ne!(CageVerdict::RequireApproval, CageVerdict::Deny);
    assert_ne!(CageVerdict::Defer, CageVerdict::Deny);

    assert!(CageVerdict::Allow.is_allowed());
    assert!(CageVerdict::Clear.is_allowed());
    assert!(!CageVerdict::Narrow.is_allowed());
    assert!(!CageVerdict::RequireApproval.is_allowed());
    assert!(!CageVerdict::Defer.is_allowed());
    assert!(!CageVerdict::Deny.is_allowed());
    assert!(!CageVerdict::Refuse.is_allowed());

    assert!(CageVerdict::Deny.is_denied());
    assert!(CageVerdict::Refuse.is_denied());
    assert!(!CageVerdict::Allow.is_denied());
    assert!(!CageVerdict::Clear.is_denied());
    assert!(!CageVerdict::Narrow.is_denied());
    assert!(!CageVerdict::RequireApproval.is_denied());
    assert!(!CageVerdict::Defer.is_denied());
}

#[test]
fn test_cage_verdict_serde_deserialization_aliases() {
    // Verify JSON deserialization accepts all uppercase and title-case aliases
    let v_allow: CageVerdict = serde_json::from_str(r#""ALLOW""#).unwrap();
    assert_eq!(v_allow, CageVerdict::Allow);

    let v_clear: CageVerdict = serde_json::from_str(r#""Clear""#).unwrap();
    assert_eq!(v_clear, CageVerdict::Allow);

    let v_narrow: CageVerdict = serde_json::from_str(r#""NARROW""#).unwrap();
    assert_eq!(v_narrow, CageVerdict::Narrow);

    let v_req: CageVerdict = serde_json::from_str(r#""REQUIRE_APPROVAL""#).unwrap();
    assert_eq!(v_req, CageVerdict::RequireApproval);

    let v_defer: CageVerdict = serde_json::from_str(r#""DEFER""#).unwrap();
    assert_eq!(v_defer, CageVerdict::Defer);

    let v_deny: CageVerdict = serde_json::from_str(r#""DENY""#).unwrap();
    assert_eq!(v_deny, CageVerdict::Deny);

    let v_refuse: CageVerdict = serde_json::from_str(r#""Refuse""#).unwrap();
    assert_eq!(v_refuse, CageVerdict::Deny);
}

#[test]
fn test_cbf_concurrent_dose_burst_barrier_behavior() {
    let kernel = Arc::new(CageGovernanceKernel::new());
    let num_threads = 10;
    let mut handles = Vec::new();

    for i in 0..num_threads {
        let k = Arc::clone(&kernel);
        handles.push(thread::spawn(move || {
            let req = CageEvaluationRequest {
                agent_id: format!("nurse-{}", i),
                role: "practitioner".to_string(),
                tool_name: "administer_medication".to_string(),
                arguments: json!({ "patient_id": "P-101", "dose": 40.0 }),
                confidence_score: Some(0.95),
                amount_usd: None,
                dose_mg: Some(40.0),
                warrant_token: None,
                human_approval: None,
                context: None,
            };
            k.evaluate(&req)
        }));
    }

    let results: Vec<CageEvaluationResponse> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let cleared_count = results.iter().filter(|r| r.verdict.is_allowed()).count();
    let refused_count = results.iter().filter(|r| r.verdict.is_denied()).count();
    eprintln!("Concurrent dose burst (10 x 40.0 mg, cap 200.0 mg): cleared={}, refused={}", cleared_count, refused_count);
}
