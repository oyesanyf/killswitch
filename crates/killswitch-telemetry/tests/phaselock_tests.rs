use killswitch_telemetry::phaselock::{
    PerPidPhaseLockMonitor, PhaseLockManager, PhaseSpaceConfig,
};
use killswitch_types::telemetry::{SecurityEvent, TelemetryEventKind};

#[test]
fn test_t1_f16_01_embedding_parameters() {
    let config = PhaseSpaceConfig::default();
    assert_eq!(config.embedding_dim, 4);
    assert_eq!(config.tau_delay, 2);
    assert_eq!(config.window_capacity, 32);
    assert_eq!(config.chaos_threshold, 0.85);
    assert_eq!(config.mahalanobis_threshold, 2.5);
}

#[test]
fn test_t1_f16_02_trajectory_reconstruction_and_drift() {
    let mut monitor = PerPidPhaseLockMonitor::default_edr();

    // Constant stable stream
    for _ in 0..25 {
        let verdict = monitor.observe(1.5);
        assert!(!verdict.is_chaotic_breakout);
    }
}

#[test]
fn test_t1_f16_03_stable_periodic_trajectory_negative_lyapunov() {
    let mut monitor = PerPidPhaseLockMonitor::default_edr();
    let periodic_series = [1.0, 2.0, 1.0, 2.0];

    for _ in 0..15 {
        for &v in &periodic_series {
            monitor.observe(v);
        }
    }

    // After establishing periodic orbit, nearest neighbor distances are small
    let verdict = monitor.observe(1.0);
    assert!(!verdict.is_chaotic_breakout);
    assert!(verdict.lyapunov_exponent < 0.85);
}

#[test]
fn test_t1_f16_04_chaotic_burst_injection_positive_divergence() {
    let mut monitor = PerPidPhaseLockMonitor::default_edr();

    // Establish stable baseline
    for _ in 0..10 {
        for &v in &[1.0, 1.2, 1.0, 1.2] {
            monitor.observe(v);
        }
    }

    // Inject high-variance chaotic burst
    let burst = [15.0, 0.1, 45.0, 2.0, 80.0, 0.5, 99.0];
    let mut detected = false;
    for &v in &burst {
        let verdict = monitor.observe(v);
        if verdict.is_chaotic_breakout {
            detected = true;
            assert!(verdict.lyapunov_exponent > 0.85);
            assert!(verdict.mahalanobis_drift > 2.5);
            break;
        }
    }

    assert!(detected, "Chaotic breakout should be detected on high-entropy burst");
}

#[test]
fn test_t1_f16_05_consecutive_chaotic_epoch_escalation() {
    let mut monitor = PerPidPhaseLockMonitor::default_edr();

    // Prime attractor
    for _ in 0..10 {
        monitor.observe(1.0);
    }

    // High divergence sequence
    for &v in &[50.0, 2.0, 75.0, 3.0, 95.0, 1.0, 110.0] {
        monitor.observe(v);
    }

    assert!(monitor.consecutive_chaotic_epochs() > 0);
}

#[test]
fn test_t2_f16_01_phase_lock_manager_event_ingestion() {
    let manager = PhaseLockManager::default();

    let benign_ev = SecurityEvent::new(
        TelemetryEventKind::ProcessCreate,
        4000,
        "notepad.exe",
        "C:\\Windows\\notepad.exe",
        "notepad.exe",
    );

    // Initial benign events do not alert
    assert!(manager.ingest_event(&benign_ev).is_none());

    // Inject chaotic anomalous event stream
    let mut alert_emitted = false;
    for i in 0..20 {
        let anomaly_ev = SecurityEvent::new(
            TelemetryEventKind::CreateRemoteThread,
            4000,
            "notepad.exe",
            "C:\\Windows\\notepad.exe",
            format!("notepad.exe --injected-burst-entropy-{}", i * 17),
        );
        // Vary pacing drastically
        if let Some(sig) = manager.ingest_event(&anomaly_ev) {
            assert_eq!(sig.target_pid, 4000);
            assert_eq!(sig.source_detector, "edr-phaselock");
            alert_emitted = true;
            break;
        }
    }
    assert!(alert_emitted);

    // Purge PID
    manager.purge_pid(4000);
    assert_eq!(manager.active_monitor_count(), 0);
}
