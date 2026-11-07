//! # Adversarial Empirical Challenge Suite: Milestone SEC-3
//!
//! Code-executing adversarial challenge harness stress-testing:
//! 1. Incident A evasion reproduction (`sudo -n id` -> `wsl -u root id`).
//! 2. Obfuscated Incident A attempts (`sudo -n make install` -> `env -i wsl.exe -u 0 /bin/bash`, env flags, path variants).
//! 3. Nested shell elevation pivots (`bash -lc "sudo -n id"` -> `sh -c "wsl -u root id"`, cmd /c, powershell -Command).
//! 4. Sliding window boundary timing (at 59 seconds vs 60 seconds vs 61 seconds, sub-second micro-boundaries).
//! 5. Cross-session isolation (zero false positives across distinct agent sessions while preserving shared parent PID linking).
//! 6. High-throughput concurrency stress (multithreaded contention across 16 threads, 10,000 operations, zero panics/deadlocks).
//! 7. EventCorrelator integration & ThreatSignal emission under ProcessCreate telemetry.
//! 8. Dynamic denial signal taxonomy classification across POSIX, PAM, and Win32.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use killswitch_telemetry::attack::AttackStage;
use killswitch_telemetry::circumvention::{
    classify_denial_pattern, evaluate_denial_outcome, observe_denial, DenialPatternKind,
    DynamicDenialSignal, TemporalCircumventionCorrelator,
};
use killswitch_telemetry::correlator::EventCorrelator;
use killswitch_telemetry::semantic_command::PrivilegeEquivalenceClass;
use killswitch_types::adjudication::EvidenceClass;
use killswitch_types::telemetry::{SecurityEvent, TelemetryEventKind, ThreatSeverity};

// ============================================================================
// 1. INCIDENT A EVASION REPRODUCTION
// ============================================================================

#[test]
fn test_adversarial_incident_a_evasion_reproduction_multi_trial() {
    // Protocol Research Invariant: Multi-Trial Confirmation (>= 5 trials)
    for trial in 1..=5 {
        let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
        let session = format!("agent-inc-a-trial-{}", trial);
        let parent_pid = 4000 + trial as u32;
        let child_pid = 5000 + trial as u32;
        let t0 = Instant::now();

        // Step 1: Adversary attempts sudo -n id, blocked with exit code 1
        let denial_signal = observe_denial(
            &session,
            Some(parent_pid),
            child_pid,
            "sudo -n id",
            Some(1),
            "sudo: a password is required",
            t0,
        )
        .expect("Denial signal MUST be observed for sudo -n failure");

        assert_eq!(denial_signal.session_id, session);
        assert_eq!(denial_signal.parent_pid, Some(parent_pid));
        assert_eq!(
            denial_signal.privilege_class,
            PrivilegeEquivalenceClass::RootOrAdminElevation
        );
        assert_eq!(
            denial_signal.pattern_kind,
            DenialPatternKind::SudoPasswordRequired
        );
        assert!(denial_signal.is_permission_denied);

        correlator.record_denial(denial_signal);
        assert_eq!(correlator.active_denial_count(), 1);

        // Step 2: Adversary immediately pivots to wsl -u root id (1500ms later)
        let t1 = t0 + Duration::from_millis(1500);
        let alert = correlator.check_candidate(&session, Some(parent_pid), "wsl -u root id", t1);

        assert!(
            alert.is_some(),
            "Trial {} failed to trigger circumvention alert",
            trial
        );
        let a = alert.unwrap();
        assert_eq!(a.session_id, session);
        assert_eq!(a.initial_blocked_command, "sudo -n id");
        assert_eq!(a.retry_command, "wsl -u root id");
        assert!(a.crossed_wsl_boundary);
        assert!(a.confidence >= 0.95);
        assert_eq!(a.severity, "CRITICAL");
        assert_eq!(a.severity_code, 4);
        assert_eq!(a.elapsed_millis, 1500);
        assert!(a.summary.contains("Incident A Circumvention Detected"));
    }
}

// ============================================================================
// 2. OBFUSCATED INCIDENT A ATTEMPTS
// ============================================================================

#[test]
fn test_adversarial_obfuscated_incident_a_attempts() {
    let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let session = "agent-session-obfuscated-inc-a";
    let parent_pid = 7001;
    let t0 = Instant::now();

    // Initial denial: sudo -n make install fails
    let denial = observe_denial(
        session,
        Some(parent_pid),
        8001,
        "sudo -n make install",
        Some(1),
        "sudo: a password is required",
        t0,
    )
    .expect("Denial on sudo -n make install must be captured");

    assert_eq!(
        denial.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    correlator.record_denial(denial);

    let t1 = t0 + Duration::from_millis(1200);

    // Variant A: env -i wsl.exe -u 0 /bin/bash
    let alert_a = correlator.check_candidate(
        session,
        Some(parent_pid),
        "env -i wsl.exe -u 0 /bin/bash",
        t1,
    );
    assert!(
        alert_a.is_some(),
        "env -i wsl.exe -u 0 /bin/bash MUST be detected"
    );
    let a = alert_a.unwrap();
    assert!(a.crossed_wsl_boundary);
    assert_eq!(a.initial_blocked_command, "sudo -n make install");
    assert_eq!(a.retry_command, "env -i wsl.exe -u 0 /bin/bash");

    // Variant B: env FOO=bar BAZ=123 wsl -u root id
    let alert_b = correlator.check_candidate(
        session,
        Some(parent_pid),
        "env FOO=bar BAZ=123 wsl -u root id",
        t1,
    );
    assert!(
        alert_b.is_some(),
        "env with variable assignments MUST be detected"
    );
    assert!(alert_b.unwrap().crossed_wsl_boundary);

    // Variant C: env -u PATH --ignore-environment wsl --user=root /bin/sh
    let alert_c = correlator.check_candidate(
        session,
        Some(parent_pid),
        "env -u PATH --ignore-environment wsl --user=root /bin/sh",
        t1,
    );
    assert!(
        alert_c.is_some(),
        "env --ignore-environment wsl --user=root MUST be detected"
    );
    assert!(alert_c.unwrap().crossed_wsl_boundary);

    // Variant D: /usr/bin/env -i wsl.exe -u 0 id
    let alert_d = correlator.check_candidate(
        session,
        Some(parent_pid),
        "/usr/bin/env -i wsl.exe -u 0 id",
        t1,
    );
    assert!(
        alert_d.is_some(),
        "/usr/bin/env prefix MUST be unwrapped and detected"
    );
    assert!(alert_d.unwrap().crossed_wsl_boundary);

    // Variant E: Windows absolute path with quotes: C:\Windows\System32\wsl.exe -u "root" "id"
    let alert_e = correlator.check_candidate(
        session,
        Some(parent_pid),
        "C:\\Windows\\System32\\wsl.exe -u \"root\" \"id\"",
        t1,
    );
    assert!(
        alert_e.is_some(),
        "Windows path with quotes MUST be detected"
    );
    assert!(alert_e.unwrap().crossed_wsl_boundary);

    // Variant F: wsl -d Ubuntu -u root whoami (distribution flag)
    let alert_f = correlator.check_candidate(
        session,
        Some(parent_pid),
        "wsl -d Ubuntu -u root whoami",
        t1,
    );
    assert!(
        alert_f.is_some(),
        "wsl with -d distro flag MUST be detected"
    );
    assert!(alert_f.unwrap().crossed_wsl_boundary);
}

// ============================================================================
// 3. NESTED SHELL ELEVATION PIVOTS
// ============================================================================

#[test]
fn test_adversarial_nested_shell_elevation_pivots() {
    let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let session = "agent-session-nested-shell";
    let parent_pid = 6001;
    let t0 = Instant::now();

    // Initial denial inside compound shell: bash -lc "sudo -n id"
    let denial = observe_denial(
        session,
        Some(parent_pid),
        7001,
        "bash -lc \"sudo -n id\"",
        Some(1),
        "sudo: a password is required",
        t0,
    )
    .expect("Denial inside bash -lc MUST be observed");

    assert_eq!(
        denial.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    correlator.record_denial(denial);

    let t1 = t0 + Duration::from_millis(800);

    // Pivot 1: sh -c "wsl -u root id"
    let alert1 =
        correlator.check_candidate(session, Some(parent_pid), "sh -c \"wsl -u root id\"", t1);
    assert!(
        alert1.is_some(),
        "sh -c wrapped wsl pivot MUST trigger circumvention alert"
    );
    let a1 = alert1.unwrap();
    assert!(a1.crossed_wsl_boundary);
    assert_eq!(a1.severity, "CRITICAL");

    // Pivot 2: cmd.exe /c "wsl -u root id"
    let alert2 = correlator.check_candidate(
        session,
        Some(parent_pid),
        "cmd.exe /c \"wsl -u root id\"",
        t1,
    );
    assert!(
        alert2.is_some(),
        "cmd.exe /c wrapped wsl pivot MUST trigger circumvention alert"
    );
    assert!(alert2.unwrap().crossed_wsl_boundary);

    // Pivot 3: powershell.exe -Command "wsl -u root id"
    let alert3 = correlator.check_candidate(
        session,
        Some(parent_pid),
        "powershell.exe -Command \"wsl -u root id\"",
        t1,
    );
    assert!(
        alert3.is_some(),
        "powershell.exe -Command wrapped wsl pivot MUST trigger alert"
    );
    assert!(alert3.unwrap().crossed_wsl_boundary);

    // Pivot 4: powershell.exe -c "wsl.exe -u 0 id"
    let alert4 = correlator.check_candidate(
        session,
        Some(parent_pid),
        "powershell.exe -c \"wsl.exe -u 0 id\"",
        t1,
    );
    assert!(
        alert4.is_some(),
        "powershell.exe -c wsl.exe -u 0 MUST trigger alert"
    );
    assert!(alert4.unwrap().crossed_wsl_boundary);

    // Pivot 5: Deep recursive nesting: env -i sh -c "wsl -u root id"
    let alert5 = correlator.check_candidate(
        session,
        Some(parent_pid),
        "env -i sh -c \"wsl -u root id\"",
        t1,
    );
    assert!(
        alert5.is_some(),
        "env -i sh -c deep nesting MUST be detected"
    );
    assert!(alert5.unwrap().crossed_wsl_boundary);
}

// ============================================================================
// 4. SLIDING WINDOW BOUNDARY TIMING (59s vs 60s vs 61s)
// ============================================================================

#[test]
fn test_adversarial_sliding_window_boundary_timing() {
    let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let session = "agent-session-boundary-timing";
    let parent_pid = 9001;
    let t0 = Instant::now();

    // Record denial at t0
    let denial = observe_denial(
        session,
        Some(parent_pid),
        9002,
        "sudo -n id",
        Some(1),
        "sudo: a password is required",
        t0,
    )
    .expect("Denial must be recorded");
    correlator.record_denial(denial);
    assert_eq!(correlator.active_denial_count(), 1);

    // Case 1: At 59 seconds (within 60s sliding window) -> MUST FIRE
    let t_59 = t0 + Duration::from_secs(59);
    let alert_59 = correlator.check_candidate(session, Some(parent_pid), "wsl -u root id", t_59);
    assert!(
        alert_59.is_some(),
        "Candidate at 59s MUST fire within 60s sliding window"
    );
    let a_59 = alert_59.unwrap();
    assert_eq!(a_59.elapsed_millis, 59_000);
    assert_eq!(a_59.severity, "CRITICAL");

    // Case 2: At exact 60.000 seconds boundary -> MUST FIRE (<= 60s)
    let t_60 = t0 + Duration::from_secs(60);
    let alert_60 = correlator.check_candidate(session, Some(parent_pid), "wsl -u root id", t_60);
    assert!(
        alert_60.is_some(),
        "Candidate at exact 60s boundary MUST fire (<= 60s)"
    );
    let a_60 = alert_60.unwrap();
    assert_eq!(a_60.elapsed_millis, 60_000);

    // Case 3: At 61 seconds (outside 60s sliding window) -> MUST NOT FIRE (PRUNED)
    let t_61 = t0 + Duration::from_secs(61);
    let alert_61 = correlator.check_candidate(session, Some(parent_pid), "wsl -u root id", t_61);
    assert!(
        alert_61.is_none(),
        "Candidate at 61s MUST NOT fire (outside 60s window)"
    );

    // Case 4: Verify that the expired entry was pruned
    assert_eq!(
        correlator.active_denial_count(),
        0,
        "Expired denial MUST be pruned from state table"
    );

    // Case 5: Sub-second micro-boundary test: 59,990ms (inside) vs 60,010ms (outside)
    let correlator_micro = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let t_micro0 = Instant::now();
    correlator_micro.record_denial(
        observe_denial(
            "session-micro",
            Some(3333),
            3334,
            "sudo -n id",
            Some(1),
            "sudo: a password is required",
            t_micro0,
        )
        .unwrap(),
    );

    // 59,990 ms -> inside
    let alert_inside = correlator_micro.check_candidate(
        "session-micro",
        Some(3333),
        "wsl -u root id",
        t_micro0 + Duration::from_millis(59_990),
    );
    assert!(
        alert_inside.is_some(),
        "59,990ms MUST fire inside 60s window"
    );

    // 60,010 ms -> outside
    let alert_outside = correlator_micro.check_candidate(
        "session-micro",
        Some(3333),
        "wsl -u root id",
        t_micro0 + Duration::from_millis(60_010),
    );
    assert!(
        alert_outside.is_none(),
        "60,010ms MUST NOT fire outside 60s window"
    );
}

// ============================================================================
// 5. CROSS-SESSION ISOLATION (ZERO FALSE POSITIVES)
// ============================================================================

#[test]
fn test_adversarial_cross_session_isolation_zero_false_positives() {
    let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let t0 = Instant::now();

    // Session Alpha has denied sudo execution
    correlator.record_denial(
        observe_denial(
            "session-alpha",
            Some(1001),
            1002,
            "sudo -n id",
            Some(1),
            "sudo: a password is required",
            t0,
        )
        .unwrap(),
    );

    let t1 = t0 + Duration::from_millis(500);

    // 1. Session Beta with distinct parent PID -> MUST NOT FIRE
    let alert_beta = correlator.check_candidate("session-beta", Some(2001), "wsl -u root id", t1);
    assert!(
        alert_beta.is_none(),
        "Unrelated Session Beta MUST NOT trigger circumvention alert"
    );

    // 2. Session Gamma with None parent PID -> MUST NOT FIRE
    let alert_gamma = correlator.check_candidate("session-gamma", None, "wsl -u root id", t1);
    assert!(
        alert_gamma.is_none(),
        "Session Gamma with no parent PID MUST NOT trigger alert"
    );

    // 3. Completely unrelated command on Session Beta -> MUST NOT FIRE
    let alert_beta_ls = correlator.check_candidate("session-beta", Some(2001), "ls -la", t1);
    assert!(
        alert_beta_ls.is_none(),
        "Unrelated benign command MUST NOT trigger alert"
    );

    // 4. Positive control: Same parent PID (1001) even if session ID string varies -> MUST FIRE
    // (Simulates node.exe spawning subsequent worker with new session token)
    let alert_shared_parent =
        correlator.check_candidate("session-variant-token", Some(1001), "wsl -u root id", t1);
    assert!(
        alert_shared_parent.is_some(),
        "Shared parent PID 1001 MUST bind circumvention attempts across session tokens"
    );

    // 5. Positive control: Same session ID ("session-alpha") with different child parent -> MUST FIRE
    let alert_same_session =
        correlator.check_candidate("session-alpha", Some(3333), "wsl -u root id", t1);
    assert!(
        alert_same_session.is_some(),
        "Matching session_id MUST trigger circumvention alert"
    );
}

// ============================================================================
// 6. BENIGN QUERY SUPPRESSION
// ============================================================================

#[test]
fn test_adversarial_benign_query_suppression() {
    let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let session = "session-query-test";
    let parent_pid = 4444;
    let t0 = Instant::now();

    correlator.record_denial(
        observe_denial(
            session,
            Some(parent_pid),
            5555,
            "sudo -n apt-get update",
            Some(1),
            "sudo: a password is required",
            t0,
        )
        .unwrap(),
    );

    let t1 = t0 + Duration::from_millis(300);

    // Informational queries MUST NEVER trigger circumvention alerts:
    let benign_queries = [
        "wsl -l -v",
        "wsl --list --status",
        "wsl -l",
        "wsl -h",
        "wsl --help",
        "wsl --version",
        "sudo -V",
        "sudo -h",
        "sudo --help",
        "sudo --version",
        "su -h",
        "su --help",
        "su -V",
        "doas -h",
        "pkexec --version",
    ];

    for query in &benign_queries {
        let alert = correlator.check_candidate(session, Some(parent_pid), query, t1);
        assert!(
            alert.is_none(),
            "Benign query '{}' MUST NOT trigger circumvention alert",
            query
        );
    }
}

// ============================================================================
// 7. HIGH-THROUGHPUT CONCURRENCY STRESS (16 THREADS, 10,000 OPS)
// ============================================================================

#[test]
fn test_adversarial_concurrency_stress_high_throughput() {
    let correlator = Arc::new(TemporalCircumventionCorrelator::new(Duration::from_secs(
        60,
    )));
    let alerts_triggered = Arc::new(AtomicUsize::new(0));
    let denials_recorded = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    let num_threads = 16;
    let ops_per_thread = 1000; // 16 * 1000 = 16,000 total operations

    for thread_idx in 0..num_threads {
        let corr = Arc::clone(&correlator);
        let alert_counter = Arc::clone(&alerts_triggered);
        let denial_counter = Arc::clone(&denials_recorded);

        let handle = thread::spawn(move || {
            let session_id = format!("stress-session-{}", thread_idx % 4);
            let parent_pid = 1000 + (thread_idx % 4) as u32;

            for op in 0..ops_per_thread {
                let now = Instant::now();
                if op % 2 == 0 {
                    // Record denial
                    let signal = DynamicDenialSignal::new(
                        format!("stress-sig-{}-{}", thread_idx, op),
                        &session_id,
                        Some(parent_pid),
                        2000 + op as u32,
                        "sudo -n id",
                        PrivilegeEquivalenceClass::RootOrAdminElevation,
                        Some(1),
                        true,
                        Some("sudo: a password is required".to_string()),
                        now,
                    );
                    corr.record_denial(signal);
                    denial_counter.fetch_add(1, Ordering::Relaxed);
                } else {
                    // Check candidate
                    let cmd = if op % 3 == 0 {
                        "wsl -u root id"
                    } else if op % 5 == 0 {
                        "env -i wsl.exe -u 0 /bin/bash"
                    } else {
                        "wsl -l -v" // benign query
                    };

                    if let Some(alert) =
                        corr.check_candidate(&session_id, Some(parent_pid), cmd, now)
                    {
                        assert!(alert.confidence >= 0.95);
                        assert_eq!(alert.severity, "CRITICAL");
                        alert_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Stress thread panicked during execution");
    }

    let recorded = denials_recorded.load(Ordering::SeqCst);
    let triggered = alerts_triggered.load(Ordering::SeqCst);

    assert_eq!(recorded, num_threads * (ops_per_thread / 2));
    assert!(
        triggered > 0,
        "At least some circumvention alerts MUST trigger under concurrency"
    );
    assert!(
        correlator.active_denial_count() <= 1024,
        "Ring buffer capacity bound MUST be enforced (active <= 1024)"
    );
}

// ============================================================================
// 8. EVENT CORRELATOR INGESTION & THREAT SIGNAL VERIFICATION
// ============================================================================

#[test]
fn test_adversarial_event_correlator_ingest_process_create() {
    let event_correlator = EventCorrelator::new(300.0, 0.75);
    let session = "edr-ingest-session";
    let parent_agent_pid = 5555;
    let t0 = Instant::now();

    // 1. Record denial in correlator
    let denial = DynamicDenialSignal::new(
        "edr-sig-01",
        session,
        Some(parent_agent_pid),
        6666,
        "sudo -n cat /etc/shadow",
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        Some(1),
        true,
        Some("Permission denied".to_string()),
        t0,
    );
    event_correlator.record_denial(denial);

    // 2. Ingest ProcessCreate SecurityEvent for circumvention retry: wsl -u root cat /etc/shadow
    let mut ev_create = SecurityEvent::new(
        TelemetryEventKind::ProcessCreate,
        7777,
        "wsl.exe",
        "C:\\Windows\\System32\\wsl.exe",
        "wsl -u root cat /etc/shadow",
    );
    ev_create.parent_pid = Some(parent_agent_pid);
    ev_create
        .attributes
        .insert("session_id".to_string(), session.to_string());

    let threat_signal =
        event_correlator.ingest_event(&ev_create, AttackStage::DefenseEvasion, 0.50);
    assert!(
        threat_signal.is_some(),
        "ProcessCreate of circumvention command MUST emit ThreatSignal"
    );

    let signal = threat_signal.unwrap();
    assert_eq!(signal.target_pid, 7777);
    assert_eq!(signal.severity, ThreatSeverity::Critical);
    assert_eq!(signal.indicator_class, EvidenceClass::Behavior);
    assert_eq!(signal.source_detector, "circumvention_correlator");
    assert!(signal.confidence >= 0.95);

    // Validate raw evidence JSON structure
    let json = signal.raw_evidence;
    assert_eq!(json["session_id"], session);
    assert_eq!(json["initial_blocked_command"], "sudo -n cat /etc/shadow");
    assert_eq!(json["retry_command"], "wsl -u root cat /etc/shadow");
    assert_eq!(json["crossed_wsl_boundary"], true);
    assert_eq!(json["incident"], "Incident A Circumvention");

    // 3. Negative test: NetworkConnect event MUST NOT trigger circumvention branch
    let mut ev_net = SecurityEvent::new(
        TelemetryEventKind::NetworkConnect,
        7777,
        "wsl.exe",
        "C:\\Windows\\System32\\wsl.exe",
        "wsl -u root cat /etc/shadow",
    );
    ev_net.parent_pid = Some(parent_agent_pid);
    ev_net
        .attributes
        .insert("session_id".to_string(), session.to_string());

    let net_signal = event_correlator.ingest_event(&ev_net, AttackStage::Discovery, 0.10);
    if let Some(ref sig) = net_signal {
        assert_ne!(
            sig.source_detector, "circumvention_correlator",
            "NetworkConnect must not trigger circumvention_correlator"
        );
    }
}

// ============================================================================
// 9. DYNAMIC DENIAL SIGNALS TAXONOMY ACROSS OS PLATFORMS
// ============================================================================

#[test]
fn test_adversarial_dynamic_denial_taxonomy_and_patterns() {
    let cases = [
        // (exit_code, stderr, expected_kind, expected_outcome)
        (Some(1223), "", DenialPatternKind::WindowsUacCancelled, true),
        (
            Some(1),
            "sudo: a password is required",
            DenialPatternKind::SudoPasswordRequired,
            true,
        ),
        (
            Some(1),
            "su: Authentication failure",
            DenialPatternKind::LinuxPamAuthFailure,
            true,
        ),
        (
            Some(1),
            "user is not in the sudoers file. This incident will be reported.",
            DenialPatternKind::SudoersUnauthorized,
            true,
        ),
        (
            Some(1),
            "touch: cannot touch '/root/x': Permission denied",
            DenialPatternKind::PosixEpermEacces,
            true,
        ),
        (
            Some(1),
            "reboot: Operation not permitted",
            DenialPatternKind::PosixEpermEacces,
            true,
        ),
        (
            Some(5),
            "System error 5 has occurred. Access is denied.",
            DenialPatternKind::WindowsAccessDenied,
            true,
        ),
        (
            Some(740),
            "The requested operation requires elevation.",
            DenialPatternKind::WindowsElevationRequired,
            true,
        ),
        (
            Some(1314),
            "A required privilege is not held by the client.",
            DenialPatternKind::WindowsElevationRequired,
            true,
        ),
        (
            Some(1),
            "fatal: you must be root to perform this operation",
            DenialPatternKind::ExplicitRootAdminRequired,
            true,
        ),
        (
            Some(2),
            "unrecognized option",
            DenialPatternKind::GenericNonZeroExit,
            false,
        ), // generic non-denial exit code
        (Some(0), "", DenialPatternKind::GenericNonZeroExit, false), // clean exit is never a denial
    ];

    for (exit_code, stderr, expected_kind, expected_is_denied) in cases {
        let is_denied = evaluate_denial_outcome("cmd", exit_code, stderr);
        assert_eq!(
            is_denied, expected_is_denied,
            "evaluate_denial_outcome mismatch for code {:?}, stderr: '{}'",
            exit_code, stderr
        );

        if let Some((kind, _sig)) = classify_denial_pattern(exit_code, stderr) {
            assert_eq!(
                kind, expected_kind,
                "classify_denial_pattern kind mismatch for code {:?}, stderr: '{}'",
                exit_code, stderr
            );
        }
    }
}
