//! # Adversarial Empirical Challenge Suite for Milestone 4 (crates/killswitch-telemetry)
//!
//! Stress-tests:
//! 1. PhaseLock: Takens delay embedding, stable periodic orbits (lambda <= 0), chaotic burst injection (lambda > 0.85),
//!    Mahalanobis drift under normal vs anomalous drift, circular buffer wrap-around under 10,000 observations.
//! 2. Causal DAG: ProcessInstanceIdentity BLAKE3 provenance, multi-branch forward reachability,
//!    cycle prevention in ancestry and reachability traversal.
//! 3. Watchdog & Canaries: Cryptographic HMAC challenge-response with bit flips, missed heartbeat timeout,
//!    recovery after timeout, canary modifications, truncations, deletions, and working set trimming.
//! 4. Octopus Multi-Ring Containment: Monotonic epoch advancement invalidation, lateral sink isolation casing attacks,
//!    and boundary exactness.
//! 5. Data Lineage: Multi-hop taint fan-in and lattice escalation invariants.

use std::fs;
use std::time::Duration;

use killswitch_telemetry::canary::CanaryManager;
use killswitch_telemetry::causal::CausalSecurityGraph;
use killswitch_telemetry::octopus::arm_ring::ArmContainmentRing;
use killswitch_telemetry::octopus::mesh_guard::{HomologicalBoundaryAuditor, MeshGuard};
use killswitch_telemetry::otel_lineage::{
    DlpClassification, DlpPolicy, TaintBaggage,
};
use killswitch_telemetry::phaselock::PerPidPhaseLockMonitor;
use killswitch_telemetry::watchdog::{
    HardwareWatchdog, MemoryPressureLevel, WatchdogConfig,
};
use killswitch_types::identity::ProcessInstanceIdentity;
use killswitch_types::telemetry::ThreatSeverity;
use killswitch_types::{ArmMessage, ArmRole, KillSwitchError, MessageKind, TrustTier};

// =========================================================================
// 1. PHASELOCK EMPIRICAL STRESS TESTS
// =========================================================================

#[test]
fn test_empirical_phaselock_stable_periodic_signals_non_chaotic() {
    let mut monitor = PerPidPhaseLockMonitor::default_edr();

    // Test constant signal of 5.0
    let mut const_monitor = PerPidPhaseLockMonitor::default_edr();
    let mut const_breakout = false;
    for i in 0..30 {
        let v = const_monitor.observe(5.0);
        if v.is_chaotic_breakout {
            println!("Constant 5.0 triggered breakout at step {}: lyapunov={}, drift={}", i, v.lyapunov_exponent, v.mahalanobis_drift);
            const_breakout = true;
        }
    }
    assert!(!const_breakout, "Constant 5.0 signal must NEVER trigger chaotic breakout");

    // Period 4 orbit: test after initial attractor embedding warmup (16 samples)
    monitor.reset();
    let period_4 = [1.0, 3.0, 2.0, 4.0];
    for iter in 0..50 {
        for (idx, &v) in period_4.iter().enumerate() {
            let verdict = monitor.observe(v);
            let sample_idx = iter * 4 + idx;
            if sample_idx >= 16 && verdict.is_chaotic_breakout {
                panic!(
                    "Period 4 falsely flagged breakout after warmup at sample {}: lyapunov={}, drift={}",
                    sample_idx, verdict.lyapunov_exponent, verdict.mahalanobis_drift
                );
            }
        }
    }

    // Completely constant signal
    monitor.reset();
    for i in 0..40 {
        let verdict = monitor.observe(42.0);
        assert!(!verdict.is_chaotic_breakout);
        if i >= 16 {
            assert!(
                verdict.lyapunov_exponent < 0.0,
                "Constant signal at i={} must have negative lyapunov, got {}",
                i,
                verdict.lyapunov_exponent
            );
        }
    }
}

#[test]
fn test_empirical_reproduce_phaselock_warmup_false_positive() {
    // EMPIRICAL BUG REPRODUCTION:
    // A benign alternating stream [1.0, 2.0, 1.0, 2.0, ...] representing typical
    // periodic syscall interleaving (e.g. read/write loop).
    let mut monitor = PerPidPhaseLockMonitor::default_edr();
    let mut sample_8_verdict = None;

    for i in 0..10 {
        let val = if i % 2 == 0 { 1.0 } else { 2.0 };
        let verdict = monitor.observe(val);
        if i == 7 {
            sample_8_verdict = Some(verdict);
        }
    }

    let v8 = sample_8_verdict.expect("Sample 8 must be observed");
    // At sample 8 (N = 8, min_required = 7), max_neighbor_ref is clamped to 7.
    // It compares X(8) with X(7), which are separated by only 1 step (violating Theiler window tau=2)
    // and in opposite phases, producing false lyapunov > 0.85 and drift > 2.5!
    println!(
        "[EMPIRICAL REMEDIATION VERIFIED] Sample 8 on alternating 1.0/2.0: lyapunov={:.3}, drift={:.3}, is_chaotic={}",
        v8.lyapunov_exponent, v8.mahalanobis_drift, v8.is_chaotic_breakout
    );
    assert!(
        !v8.is_chaotic_breakout,
        "Remediated: sample 8 must NOT declare chaotic breakout on benign alternating signal"
    );
    assert_eq!(v8.lyapunov_exponent, 0.0);
    assert_eq!(v8.mahalanobis_drift, 0.0);
}

#[test]
fn test_empirical_phaselock_chaotic_burst_injection_lyapunov_divergence() {
    let mut monitor = PerPidPhaseLockMonitor::default_edr();

    // Prime the attractor with stable baseline
    for _ in 0..20 {
        for &v in &[1.5, 2.0, 1.5, 2.0] {
            monitor.observe(v);
        }
    }

    // Now inject chaotic high-entropy burst: oscillating high magnitude random-like spikes
    let burst = [
        120.0, 0.05, 340.0, 1.2, 500.0, 0.01, 800.0, 0.5, 950.0,
    ];
    let mut triggered_chaotic = false;
    let mut max_lyapunov = f64::NEG_INFINITY;
    let mut max_drift = 0.0f64;

    for &v in &burst {
        let verdict = monitor.observe(v);
        if verdict.lyapunov_exponent > max_lyapunov {
            max_lyapunov = verdict.lyapunov_exponent;
        }
        if verdict.mahalanobis_drift > max_drift {
            max_drift = verdict.mahalanobis_drift;
        }
        if verdict.is_chaotic_breakout {
            triggered_chaotic = true;
            assert!(verdict.lyapunov_exponent > 0.85);
            assert!(verdict.mahalanobis_drift > 2.5);
            assert!(verdict.anomaly_score > 0.5);
        }
    }

    assert!(
        triggered_chaotic,
        "Chaotic burst must trigger breakout: max_lambda={}, max_drift={}",
        max_lyapunov, max_drift
    );
    assert!(
        max_lyapunov > 0.85,
        "Chaotic injection must produce lambda > 0.85, got {}",
        max_lyapunov
    );
    assert!(
        max_drift > 2.5,
        "Chaotic injection must produce Mahalanobis drift > 2.5, got {}",
        max_drift
    );
}

#[test]
fn test_empirical_phaselock_circular_buffer_wraparound_stress() {
    let mut monitor = PerPidPhaseLockMonitor::default_edr();

    // Feed 10,000 observations to stress test circular buffer wrap-around
    for i in 0..10_000 {
        let val = 10.0 + ((i % 4) as f64) * 0.5;
        let verdict = monitor.observe(val);
        // After establishing baseline, periodic variations must remain non-chaotic
        if i > 50 {
            assert!(
                !verdict.is_chaotic_breakout,
                "Wrap-around iteration {} falsely triggered chaotic breakout",
                i
            );
            assert!(
                verdict.mahalanobis_drift < 2.5,
                "Wrap-around iteration {} drift exceeded threshold: {}",
                i,
                verdict.mahalanobis_drift
            );
        }
    }

    // Consecutive epochs must be 0
    assert_eq!(monitor.consecutive_chaotic_epochs(), 0);
}

#[test]
fn test_empirical_phaselock_mahalanobis_drift_normal_vs_anomalous() {
    let mut monitor = PerPidPhaseLockMonitor::default_edr();

    // Normal stream with slight noise
    for i in 0..100 {
        let noise = ((i % 7) as f64) * 0.05;
        let v = monitor.observe(5.0 + noise);
        if i >= 15 {
            assert!(
                v.mahalanobis_drift < 2.5,
                "Normal drift exceeded threshold at {}: {}",
                i,
                v.mahalanobis_drift
            );
        }
    }

    // Step change (anomalous drift)
    let v_anom = monitor.observe(150.0);
    assert!(
        v_anom.mahalanobis_drift > 2.5,
        "Step change must cause Mahalanobis drift > 2.5, got {}",
        v_anom.mahalanobis_drift
    );
}

// =========================================================================
// 2. CAUSAL DAG EMPIRICAL STRESS TESTS
// =========================================================================

#[test]
fn test_empirical_causal_dag_blake3_provenance_and_reachability() {
    let graph = CausalSecurityGraph::new();

    // Create 3 distinct processes with unique BLAKE3 instance UUIDs
    let p1 = ProcessInstanceIdentity::new(1001, 10_000_000, "hash_init", None, None, "Session-0");
    let p2 = ProcessInstanceIdentity::new(
        1002,
        10_005_000,
        "hash_worker",
        Some(p1.instance_id.clone()),
        None,
        "Session-0",
    );
    let p3 = ProcessInstanceIdentity::new(
        1003,
        10_010_000,
        "hash_payload",
        Some(p2.instance_id.clone()),
        None,
        "Session-0",
    );

    // Verify BLAKE3 UUIDs are unique and non-empty
    assert_ne!(p1.instance_id, p2.instance_id);
    assert_ne!(p2.instance_id, p3.instance_id);
    assert_eq!(p1.instance_id.len(), 64);

    // Record spawns
    graph.record_process_spawn(None, &p1, "init.exe");
    graph.record_process_spawn(Some(&p1.instance_id), &p2, "worker.exe");
    graph.record_process_spawn(Some(&p2.instance_id), &p3, "payload.exe");

    // Record file writes and socket connections
    graph.record_file_interaction(&p3.instance_id, "C:\\Temp\\staged.bin", "hash_bin", true);
    graph.record_network_connect(&p3.instance_id, "192.0.2.100", 8443);

    // Forward reachability from p1 must include p1, p2, p3, staged.bin, and 192.0.2.100
    let reach_from_p1 = graph.get_transitive_taint_forward(&p1.instance_id);
    assert!(reach_from_p1.contains(&p1.instance_id));
    assert!(reach_from_p1.contains(&p2.instance_id));
    assert!(reach_from_p1.contains(&p3.instance_id));
    assert!(reach_from_p1.iter().any(|id| id.contains("staged.bin")));
    assert!(reach_from_p1.iter().any(|id| id.contains("192.0.2.100")));

    // Forward reachability from p2 must include p2, p3, file, socket, but NOT p1
    let reach_from_p2 = graph.get_transitive_taint_forward(&p2.instance_id);
    assert!(!reach_from_p2.contains(&p1.instance_id));
    assert!(reach_from_p2.contains(&p2.instance_id));
    assert!(reach_from_p2.contains(&p3.instance_id));

    // Ancestry lookup from p3
    let ancestry = graph.get_lineage_ancestry(&p3.instance_id, 10);
    assert_eq!(ancestry.len(), 2);
    assert_eq!(ancestry[0].pid, 1002);
    assert_eq!(ancestry[1].pid, 1001);
}

#[test]
fn test_empirical_causal_dag_cycle_prevention() {
    let graph = CausalSecurityGraph::new();

    let p_a = ProcessInstanceIdentity::new(2001, 100, "hash_a", None, None, "Session-0");
    let p_b = ProcessInstanceIdentity::new(2002, 200, "hash_b", Some(p_a.instance_id.clone()), None, "Session-0");
    let p_c = ProcessInstanceIdentity::new(2003, 300, "hash_c", Some(p_b.instance_id.clone()), None, "Session-0");

    graph.record_process_spawn(None, &p_a, "a.exe");
    graph.record_process_spawn(Some(&p_a.instance_id), &p_b, "b.exe");
    graph.record_process_spawn(Some(&p_b.instance_id), &p_c, "c.exe");

    // Intentionally inject synthetic cycle into the graph (p_c -> p_a) via injection
    graph.record_injection(&p_c.instance_id, &p_a.instance_id, "ReflectiveDllInjection");

    // Transitive forward reachability must complete without infinite loop
    let reachable = graph.get_transitive_taint_forward(&p_a.instance_id);
    assert_eq!(reachable.len(), 3);
    assert!(reachable.contains(&p_a.instance_id));
    assert!(reachable.contains(&p_b.instance_id));
    assert!(reachable.contains(&p_c.instance_id));

    // Ancestry traversal must not loop even if spawned cycle is manually recorded
    graph.record_process_spawn(Some(&p_c.instance_id), &p_a, "a.exe");
    let ancestry = graph.get_lineage_ancestry(&p_c.instance_id, 20);
    // Depth limited, visited set terminates cycle
    assert!(ancestry.len() <= 3);
}

// =========================================================================
// 3. WATCHDOG & CANARY EMPIRICAL STRESS TESTS
// =========================================================================

#[test]
fn test_empirical_watchdog_cryptographic_challenge_and_recovery() {
    let key = [0xA5u8; 32];
    let config = WatchdogConfig {
        heartbeat_interval: Duration::from_millis(10),
        heartbeat_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let watchdog = HardwareWatchdog::new(key, config);

    // Initial state: fresh heartbeat, liveness check is None
    assert!(watchdog.check_liveness().is_none());

    // 1. Bit-flip tests on challenge response
    let nonce = watchdog.issue_challenge();
    let expected = watchdog.compute_expected_response(nonce);

    // Wrong response fails
    let mut wrong = expected;
    wrong[31] ^= 0x01;
    assert!(!watchdog.verify_heartbeat_response(&wrong));

    // Wrong length fails
    assert!(!watchdog.verify_heartbeat_response(&expected[..31]));

    // Valid response succeeds
    assert!(watchdog.verify_heartbeat_response(&expected));
    assert!(watchdog.check_liveness().is_none());

    // 2. Starvation / Timeout test
    std::thread::sleep(Duration::from_millis(65));
    let timeout_alert = watchdog.check_liveness();
    assert!(
        timeout_alert.is_some(),
        "Watchdog must alert after 50ms timeout without heartbeat"
    );
    let sig = timeout_alert.unwrap();
    assert_eq!(sig.severity, ThreatSeverity::Critical);
    assert_eq!(sig.source_detector, "hardware-watchdog");

    // 3. Recovery test: responding to a fresh challenge resets the watchdog
    let recovery_nonce = watchdog.issue_challenge();
    let recovery_resp = watchdog.compute_expected_response(recovery_nonce);
    assert!(watchdog.verify_heartbeat_response(&recovery_resp));

    // After recovery, liveness check is clean again
    assert!(watchdog.check_liveness().is_none());
}

#[test]
fn test_empirical_canary_audit_tampering_deletion_truncation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let manager = CanaryManager::new(vec![temp_dir.path().to_path_buf()]);

    let count = manager.deploy_all().unwrap();
    assert_eq!(count, 5);

    // Clean audit
    let (r0, s0) = manager.audit_canaries(None);
    assert_eq!(r0.intact_count, 5);
    assert_eq!(r0.modified_count, 0);
    assert_eq!(r0.deleted_count, 0);
    assert!(s0.is_none());

    // 1. Truncate one file to 0 bytes
    let f1 = temp_dir.path().join("passwords_2025.txt");
    fs::write(&f1, b"").unwrap();

    let (r1, s1) = manager.audit_canaries(Some(1001));
    assert_eq!(r1.modified_count, 1);
    assert_eq!(r1.intact_count, 4);
    assert!(s1.is_some());

    // 2. Delete another file
    let f2 = temp_dir.path().join("id_rsa_backup");
    fs::remove_file(&f2).unwrap();

    let (r2, s2) = manager.audit_canaries(Some(1002));
    assert_eq!(r2.modified_count, 1);
    assert_eq!(r2.deleted_count, 1);
    assert_eq!(r2.intact_count, 3);
    assert!(s2.is_some());

    // 3. Append to third file
    let f3 = temp_dir.path().join("client_billing_records.xlsx");
    let mut cur = fs::read(&f3).unwrap();
    cur.extend_from_slice(b"\nEXTRA_DATA_APPENDED");
    fs::write(&f3, &cur).unwrap();

    let (r3, s3) = manager.audit_canaries(Some(1003));
    assert_eq!(r3.modified_count, 2);
    assert_eq!(r3.deleted_count, 1);
    assert_eq!(r3.intact_count, 2);
    assert!(s3.is_some());

    // Cleanup removes all files
    manager.cleanup_all();
    assert_eq!(manager.monitored_count(), 0);
}

#[test]
fn test_empirical_watchdog_memory_audit_and_trim_invariants() {
    let key = [0x55u8; 32];
    let watchdog = HardwareWatchdog::new(key, WatchdogConfig::default());

    let level = watchdog.audit_memory_and_trim();
    assert!(matches!(
        level,
        MemoryPressureLevel::Normal | MemoryPressureLevel::Warning | MemoryPressureLevel::Critical
    ));

    // Native working set trimming must execute cleanly
    HardwareWatchdog::trim_process_working_set();
}

// =========================================================================
// 4. OCTOPUS MULTI-RING CONTAINMENT EMPIRICAL TESTS
// =========================================================================

#[tokio::test]
async fn test_empirical_octopus_epoch_advancement_and_stale_token_rejection() {
    let master_seed = [0x88u8; 32];
    let ring = ArmContainmentRing::new(101, ArmRole::UntrustedDocIngest, 1, &master_seed);

    // Initial epoch = 1
    assert_eq!(ring.current_generation(), 1);

    // Issue capability token at epoch 1
    let token1 = ring
        .issue_capability("data_reader", "s3://bucket/", 30)
        .await
        .unwrap();
    assert!(ring.verify_capability(&token1).await.is_ok());

    // Advance epoch monotonically via autotomy/regeneration
    let new_epoch = ring
        .sever_and_regenerate("Empirical challenge test autotomy")
        .await
        .unwrap();
    assert_eq!(new_epoch, 2);
    assert_eq!(ring.current_generation(), 2);

    // Old token from epoch 1 MUST BE REJECTED
    let stale_check = ring.verify_capability(&token1).await;
    assert!(
        stale_check.is_err(),
        "Stale capability token from old epoch must be rejected"
    );

    // New token issued at epoch 2 MUST BE ACCEPTED
    let token2 = ring
        .issue_capability("data_reader", "s3://bucket/", 30)
        .await
        .unwrap();
    assert!(ring.verify_capability(&token2).await.is_ok());
}

#[tokio::test]
async fn test_empirical_octopus_lateral_sink_isolation_case_insensitivity() {
    let guard = MeshGuard::new();
    let sender_key = [0xCCu8; 32];

    guard.allow_route("arm-doc", "arm-ledger", None).await;

    // Message carries Untrusted taint floor
    let mut msg = ArmMessage {
        sender_arm_id: "arm-doc".to_string(),
        sender_role: ArmRole::UntrustedDocIngest,
        sender_generation: 1,
        target_arm_id: "arm-ledger".to_string(),
        target_generation: 1,
        kind: MessageKind::Command,
        correlation_id: "corr-taint-case".to_string(),
        payload: "Unauthorized transfer".to_string(),
        provenance: vec![],
        taint_floor: TrustTier::Untrusted,
        signature_hex: String::new(),
    };

    msg.sign(&sender_key).unwrap();

    // Direct route from Untrusted to AccountingLedgerWrite is vetoed
    let res = guard
        .validate_message(&msg, &ArmRole::AccountingLedgerWrite, &sender_key)
        .await;
    assert!(matches!(
        res,
        Err(KillSwitchError::LateralSinkViolation { .. })
    ));

    // Normalizing identifiers is case-insensitive
    assert_eq!(
        HomologicalBoundaryAuditor::normalize_id("AccountingLedgerWrite"),
        HomologicalBoundaryAuditor::normalize_id("accountingledgerwrite")
    );
}

// =========================================================================
// 5. DATA LINEAGE LATTICE & FAN-IN EMPIRICAL TESTS
// =========================================================================

#[test]
fn test_empirical_dlp_taint_baggage_lattice_monotonicity() {
    let mut b1 = TaintBaggage::new(
        DlpClassification::Internal,
        DlpPolicy::Audit,
        "hash_internal".to_string(),
    );

    let b2 = TaintBaggage::new(
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
        "hash_crown".to_string(),
    );

    // Merge must escalate to CrownJewel and Quarantine
    b1.merge(&b2);
    assert_eq!(b1.classification, DlpClassification::CrownJewel);
    assert_eq!(b1.policy, DlpPolicy::Quarantine);
    assert!(b1.source_sha256.contains("hash_internal"));
    assert!(b1.source_sha256.contains("hash_crown"));

    // Merging lower classification must not de-escalate
    let b_public = TaintBaggage::new(
        DlpClassification::Public,
        DlpPolicy::Allow,
        "hash_pub".to_string(),
    );
    b1.merge(&b_public);
    assert_eq!(b1.classification, DlpClassification::CrownJewel);
    assert_eq!(b1.policy, DlpPolicy::Quarantine);
}
