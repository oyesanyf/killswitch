//! Integration tests for Canaries, Watchdog & Honeytokens (Feature 18)

use std::fs;
use std::time::Duration;
use killswitch_telemetry::canary::CanaryManager;
use killswitch_telemetry::honeytokens::HoneytokenManager;
use killswitch_telemetry::watchdog::{HardwareWatchdog, MemoryPressureLevel, WatchdogConfig};
use killswitch_types::telemetry::ThreatSeverity;

#[test]
fn test_t1_f18_01_canary_deployment_and_tripwire_audit() {
    let temp_dir = tempfile::tempdir().unwrap();
    let manager = CanaryManager::new(vec![temp_dir.path().to_path_buf()]);

    let deployed = manager.deploy_all().unwrap();
    assert_eq!(deployed, 5);

    // Initial audit: intact
    let (report, sig) = manager.audit_canaries(None);
    assert_eq!(report.intact_count, 5);
    assert_eq!(report.modified_count, 0);
    assert_eq!(report.deleted_count, 0);
    assert!(sig.is_none());

    // Modify a canary
    let canary_path = temp_dir.path().join("salary_list.pdf");
    fs::write(&canary_path, b"ENCRYPTED_BY_RANSOMWARE_VIRUS").unwrap();

    let (mod_report, mod_sig) = manager.audit_canaries(Some(1234));
    assert_eq!(mod_report.modified_count, 1);
    assert!(mod_sig.is_some());
    let s = mod_sig.unwrap();
    assert_eq!(s.target_pid, 1234);
    assert_eq!(s.severity, ThreatSeverity::Critical);

    // Delete a canary
    let deleted_path = temp_dir.path().join("id_rsa_backup");
    let _ = fs::remove_file(deleted_path);

    let (del_report, del_sig) = manager.audit_canaries(Some(5678));
    assert_eq!(del_report.deleted_count, 1);
    assert!(del_sig.is_some());

    manager.cleanup_all();
    assert_eq!(manager.monitored_count(), 0);
}

#[test]
fn test_t1_f18_02_honeytoken_access_detection() {
    let mgr = HoneytokenManager::new();

    // Querying with benign string -> None
    let clean = mgr.verify_and_audit_access("clean_standard_string", 100, "dev.exe");
    assert!(clean.is_none());

    // Querying with seeded decoy AWS credential -> Critical alert
    let tripped = mgr.verify_and_audit_access(
        "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        200,
        "stealer.exe",
    );
    assert!(tripped.is_some());
    let sig = tripped.unwrap();
    assert_eq!(sig.target_pid, 200);
    assert_eq!(sig.confidence, 0.99);
}

#[test]
fn test_t1_f18_03_hardware_watchdog_hmac_challenge() {
    let key = [0x55u8; 32];
    let watchdog = HardwareWatchdog::new(key, WatchdogConfig::default());

    let nonce = watchdog.issue_challenge();
    let expected = watchdog.compute_expected_response(nonce);

    // Valid response passes in constant time
    assert!(watchdog.verify_heartbeat_response(&expected));
    assert!(watchdog.check_liveness().is_none());

    // Tampered response fails
    let mut bad_resp = expected;
    bad_resp[0] ^= 0x01;
    assert!(!watchdog.verify_heartbeat_response(&bad_resp));
}

#[test]
fn test_t1_f18_04_watchdog_timeout_alert_emission() {
    let key = [0x99u8; 32];
    let config = WatchdogConfig {
        heartbeat_timeout: Duration::from_millis(10),
        ..Default::default()
    };
    let watchdog = HardwareWatchdog::new(key, config);

    std::thread::sleep(Duration::from_millis(15));
    let alert = watchdog.check_liveness();
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().severity, ThreatSeverity::Critical);
}

#[test]
fn test_t1_f18_05_memory_audit_and_trimming() {
    let key = [0x33u8; 32];
    let watchdog = HardwareWatchdog::new(key, WatchdogConfig::default());

    // Verify memory audit runs without panicking and returns valid status
    let status = watchdog.audit_memory_and_trim();
    assert!(matches!(
        status,
        MemoryPressureLevel::Normal | MemoryPressureLevel::Warning | MemoryPressureLevel::Critical
    ));

    // Process working set trimming execution
    HardwareWatchdog::trim_process_working_set();
}
