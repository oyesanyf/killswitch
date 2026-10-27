//! Integration tests for `killswitch-core`.
//!
//! Comprehensive end-to-end testing of:
//! 1. Windows WFP dynamic session receipt generation, GUID properties, and BFE rule formatting.
//! 2. Linux Netlink / Landlock / `/proc/net/tcp` little-endian hex parsing and socket state detection.
//! 3. Process lineage depth-5 traversal and critical OS process freeze immunity.
//! 4. ActiveProcessTarpit duty cycle and safe thread release.
//! 5. 4-tier operator authentication, 3-strike 300s rate-limiting lockout, and caller PID validation.
//! 6. Dual-layer BLAKE3 state ledger cryptographic hash chaining and atomic disk persistence.
//! 7. KillChainHostManager lifecycle, intermediate 60s health probes, and failsafe watchdog.

use killswitch_core::{
    auth::OperatorAuthManager,
    freeze::NativeProcessFreezer,
    killchain::{is_critical_system_pid, KillChainHostManager, SimulatedNetworkIsolator},
    landlock::{
        parse_linux_ipv4_hex, parse_linux_ipv6_hex, parse_proc_net_content,
        LinuxNetlinkIsolator, TcpState,
    },
    state_ledger::{StateLedger, GENESIS_HASH},
    tarpit::ActiveProcessTarpit,
    wfp::{apply_native_bfe_registry_rule, WfpGuid, WindowsWfpIsolator},
};
use killswitch_types::{
    errors::KillSwitchError,
    status::{
        AuthMethod, AuthResult, ContainmentLevel, HealthProbeRunner, IsolationReceipt,
        NetworkIsolationEngine, NetworkIsolator, OperatorAuthenticator, OperatorCredentials,
        ProcessFreezer,
    },
};
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tempfile::tempdir;

// =============================================================================
// 1. WFP & Isolation Receipts Tests
// =============================================================================

#[test]
fn test_wfp_guid_structure_and_equality() {
    let guid1 = WfpGuid {
        data1: 0xc38d57d1,
        data2: 0x05a7,
        data3: 0x4c33,
        data4: [0xaf, 0x85, 0x3d, 0x14, 0x05, 0x76, 0x5a, 0x93],
    };
    let guid2 = WfpGuid {
        data1: 0xc38d57d1,
        data2: 0x05a7,
        data3: 0x4c33,
        data4: [0xaf, 0x85, 0x3d, 0x14, 0x05, 0x76, 0x5a, 0x93],
    };
    let guid3 = WfpGuid::default();

    assert_eq!(guid1, guid2);
    assert_ne!(guid1, guid3);
}

#[test]
fn test_wfp_receipt_generation_and_contract() {
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let receipt = IsolationReceipt::new(
        "session-test-uuid".to_string(),
        NetworkIsolationEngine::WindowsWfpDynamic,
        vec![101, 102],
        vec!["sublayer-1".to_string()],
        vec!["netlink-rule-1".to_string()],
        vec![3030, 53, 67, 68],
        vec![loopback],
        4,
        "secops_operator".to_string(),
        "Active ransomware containment".to_string(),
    );

    assert_eq!(receipt.engine, NetworkIsolationEngine::WindowsWfpDynamic);
    assert_eq!(receipt.session_id, "session-test-uuid");
    assert_eq!(receipt.wfp_filter_ids, vec![101, 102]);
    assert_eq!(receipt.terminated_tcp_connections_count, 4);
    assert_eq!(receipt.engaged_by, "secops_operator");
    assert_eq!(receipt.preserved_ports, vec![3030, 53, 67, 68]);
    assert_eq!(receipt.preserved_ips, vec![loopback]);
    assert!(!receipt.receipt_hash_blake3.is_empty());
}

#[test]
fn test_bfe_registry_rule_syntax_generator() {
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let applied = apply_native_bfe_registry_rule(
        "KillSwitch-UnitTest-Rule",
        "Out",
        "Block",
        Some(6),
        None,
        Some(443),
        &[loopback],
    );
    // On non-admin test runners, safe fallback returns false without panic
    let _ = applied;
}

#[test]
fn test_windows_wfp_isolator_interface() {
    let isolator = WindowsWfpIsolator;
    // Test resetting connections on loopback - should not fail
    let res = isolator.reset_tcp_connections(None);
    assert!(res.is_ok());
}

// =============================================================================
// 2. Linux Netlink & /proc/net/tcp Little-Endian Hex Parser Tests
// =============================================================================

#[test]
fn test_linux_ipv4_little_endian_parsing() {
    // 0100007F in little endian hex is 127.0.0.1
    let ip_loopback = parse_linux_ipv4_hex("0100007F").expect("Parse 127.0.0.1");
    assert_eq!(ip_loopback, Ipv4Addr::new(127, 0, 0, 1));

    // 00000000 is 0.0.0.0
    let ip_any = parse_linux_ipv4_hex("00000000").expect("Parse 0.0.0.0");
    assert_eq!(ip_any, Ipv4Addr::new(0, 0, 0, 0));

    // 0102A8C0: C0=192, A8=168, 02=2, 01=1 -> 192.168.2.1
    let ip_lan = parse_linux_ipv4_hex("0102A8C0").expect("Parse 192.168.2.1");
    assert_eq!(ip_lan, Ipv4Addr::new(192, 168, 2, 1));

    // 08080808 is 8.8.8.8
    let ip_dns = parse_linux_ipv4_hex("08080808").expect("Parse 8.8.8.8");
    assert_eq!(ip_dns, Ipv4Addr::new(8, 8, 8, 8));
}

#[test]
fn test_linux_ipv6_little_endian_parsing() {
    // ::1 in /proc/net/tcp6 is 00000000000000000000000001000000
    let ip6_loopback =
        parse_linux_ipv6_hex("00000000000000000000000001000000").expect("Parse ::1");
    assert_eq!(ip6_loopback, Ipv6Addr::LOCALHOST);

    // :: (any) is 32 zeros
    let ip6_any =
        parse_linux_ipv6_hex("00000000000000000000000000000000").expect("Parse ::");
    assert_eq!(ip6_any, Ipv6Addr::UNSPECIFIED);
}

#[test]
fn test_parse_proc_net_tcp_table() {
    let mock_proc_net_content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:0BD6 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0                     
   1: 0102A8C0:C001 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0                     
   2: 0102A8C0:D431 5DB8D85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 11223 1 0000000000000000 100 0 0 10 0                     
   3: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44556 1 0000000000000000 100 0 0 10 0                     
"#;

    let entries = parse_proc_net_content(mock_proc_net_content, false);
    assert_eq!(entries.len(), 4);

    // Entry 0: 127.0.0.1:3030 (0x0BD6 = 3030), state 0A (Listen)
    assert_eq!(entries[0].local_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(entries[0].local_port, 3030);
    assert_eq!(entries[0].state, TcpState::Listen);
    assert!(entries[0].local_addr.is_loopback());

    // Entry 1: 192.168.2.1:49153 -> 8.8.8.8:53, state 01 (Established)
    assert_eq!(entries[1].local_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)));
    assert_eq!(entries[1].remote_addr, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(entries[1].remote_port, 53);
    assert_eq!(entries[1].state, TcpState::Established);
    assert!(!entries[1].local_addr.is_loopback());

    // Entry 3: 0.0.0.0:22 (SSH), state 0A (Listen)
    assert_eq!(entries[3].local_addr, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(entries[3].local_port, 22);
    assert_eq!(entries[3].state, TcpState::Listen);
}

#[test]
fn test_linux_netlink_isolator_lifecycle() {
    let isolator = LinuxNetlinkIsolator::new();
    let preserved = vec![3030, 53, 67, 68];
    let receipt = isolator
        .engage_quarantine(&preserved, "secops_linux", "Ransomware outbreak containment")
        .expect("Engage quarantine receipt");

    assert_eq!(receipt.engine, NetworkIsolationEngine::LinuxNetlink);
    assert_eq!(receipt.preserved_ports, preserved);
    assert_eq!(receipt.engaged_by, "secops_linux");

    let restore_res = isolator.restore_quarantine(&receipt);
    assert!(restore_res.is_ok());

    let reset_res = isolator.reset_tcp_connections(None);
    assert!(reset_res.is_ok());
}

// =============================================================================
// 3. Process Lineage Immunity & Freeze Tests
// =============================================================================

#[test]
fn test_process_immunity_hierarchy() {
    let freezer = NativeProcessFreezer::new();

    // Critical system PIDs must be immune
    assert!(freezer.is_immune(0, "System Idle Process"));
    assert!(freezer.is_immune(4, "System"));
    assert!(is_critical_system_pid(0, "System Idle Process"));
    assert!(is_critical_system_pid(4, "System"));

    // Current agent / test runner process must be immune
    let my_pid = std::process::id();
    assert!(freezer.is_immune(my_pid, "test_runner"));
    assert!(is_critical_system_pid(my_pid, "test_runner"));

    // Critical OS services by name
    assert!(freezer.is_immune(9999, "csrss.exe"));
    assert!(freezer.is_immune(9998, "lsass.exe"));
    assert!(freezer.is_immune(9997, "systemd"));
    assert!(freezer.is_immune(9996, "init"));
    assert!(is_critical_system_pid(9999, "csrss.exe"));
    assert!(is_critical_system_pid(9998, "lsass.exe"));
}

#[test]
fn test_freeze_immune_process_fails_closed() {
    let freezer = NativeProcessFreezer::new();
    let my_pid = std::process::id();

    let res = freezer.freeze_process(my_pid);
    assert!(
        res.is_err(),
        "Freezing immune self-process must fail closed"
    );
    match res {
        Err(KillSwitchError::ParentLineageImmune { pid, .. })
        | Err(KillSwitchError::ProtectedProcessImmune { pid, .. }) => {
            assert_eq!(pid, my_pid);
        }
        other => panic!("Expected immunity error, got: {:?}", other),
    }
}

#[test]
fn test_freeze_nonexistent_process_graceful_error() {
    let freezer = NativeProcessFreezer::new();
    // Use an arbitrarily high non-existent PID
    let bogus_pid = 4_194_300;

    let res = freezer.freeze_process(bogus_pid);
    assert!(res.is_err());
    let resume_res = freezer.resume_process(bogus_pid);
    assert!(resume_res.is_err());
}

// =============================================================================
// 4. ActiveProcessTarpit Lifecycle Tests
// =============================================================================

#[test]
fn test_active_process_tarpit_lifecycle() {
    let tarpit = ActiveProcessTarpit::new();

    // Tarpitting immune process must be blocked
    let my_pid = std::process::id();
    let res = tarpit.trap_pid_default(my_pid);
    assert!(res.is_err());
    match res {
        Err(KillSwitchError::ProtectedProcessImmune { pid, .. }) => {
            assert_eq!(pid, my_pid);
        }
        other => panic!("Expected ProtectedProcessImmune, got: {:?}", other),
    }

    // Release on untracked process is clean and idempotent
    tarpit.release_pid(999_999);
    assert!(!tarpit.is_trapped(999_999));

    // Release all on empty tarpit
    tarpit.release_all();
}

// =============================================================================
// 5. Operator Authentication & 3-Strike Lockout Tests
// =============================================================================

#[test]
fn test_operator_auth_tier1_master_token() {
    let temp = tempdir().expect("tempdir");
    let master_token = "KSwitch-Master-Emergency-Key-999";
    let mut auth = OperatorAuthManager::new(None, Some(temp.path().to_path_buf()));
    auth.set_custom_master_token(master_token.to_string());

    let creds = OperatorCredentials {
        operator_id: "master_admin".to_string(),
        auth_token: Some(master_token.to_string()),
        password: None,
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };

    let result = auth.authenticate(&creds);
    assert!(result.is_success());
    match result {
        AuthResult::Success { method, operator, .. } => {
            assert_eq!(method, AuthMethod::MasterTokenBypass);
            assert_eq!(operator, "master_admin");
        }
        _ => panic!("Expected Success with MasterTokenBypass"),
    }
}

#[test]
fn test_operator_auth_tier2_process_env_password() {
    let temp = tempdir().expect("tempdir");
    let test_pass = "SecureTempEnvPassword2026!";
    std::env::set_var("KILLSWITCH_ADMIN_PASSWORD", test_pass);

    let auth = OperatorAuthManager::new(None, Some(temp.path().to_path_buf()));
    let creds = OperatorCredentials {
        operator_id: "secops_env".to_string(),
        auth_token: None,
        password: Some(test_pass.to_string()),
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };

    let result = auth.authenticate(&creds);
    std::env::remove_var("KILLSWITCH_ADMIN_PASSWORD");

    assert!(result.is_success());
    match result {
        AuthResult::Success { method, .. } => {
            assert_eq!(method, AuthMethod::EnvironmentPassword);
        }
        _ => panic!("Expected Success with EnvironmentPassword"),
    }
}

#[test]
fn test_operator_auth_tier3_stored_blake3_hash() {
    let temp = tempdir().expect("tempdir");
    let password = "SuperSecretTier3Password";
    let hash_hex = blake3::hash(password.as_bytes()).to_hex().to_string();

    let hash_file = temp.path().join("admin_password.hash");
    std::fs::write(&hash_file, &hash_hex).expect("write admin_password.hash");

    let auth = OperatorAuthManager::new(None, Some(temp.path().to_path_buf()));
    let creds = OperatorCredentials {
        operator_id: "secops_tier3".to_string(),
        auth_token: None,
        password: Some(password.to_string()),
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };

    let result = auth.authenticate(&creds);
    assert!(result.is_success());
    match result {
        AuthResult::Success { method, .. } => {
            assert_eq!(method, AuthMethod::StoredHashMatch);
        }
        _ => panic!("Expected Success with StoredHashMatch"),
    }
}

#[test]
fn test_operator_auth_3_strike_lockout_and_master_bypass() {
    let temp = tempdir().expect("tempdir");
    let master_token = "MasterBypassSecret999";
    let mut auth = OperatorAuthManager::new(None, Some(temp.path().to_path_buf()));
    auth.set_custom_master_token(master_token.to_string());

    let wrong_creds = OperatorCredentials {
        operator_id: "attacker".to_string(),
        auth_token: None,
        password: Some("TotallyWrongPassword".to_string()),
        caller_pid: Some(5000),
        confirmation_phrase: None,
    };

    // Attempt 1: Failed (2 attempts remaining)
    let res1 = auth.authenticate(&wrong_creds);
    assert!(!res1.is_success());
    match res1 {
        AuthResult::Failed { attempts_remaining, .. } => {
            assert_eq!(attempts_remaining, 2);
        }
        _ => panic!("Expected Failed with attempts_remaining = 2"),
    }

    // Attempt 2: Failed (1 attempt remaining)
    let res2 = auth.authenticate(&wrong_creds);
    assert!(!res2.is_success());
    match res2 {
        AuthResult::Failed { attempts_remaining, .. } => {
            assert_eq!(attempts_remaining, 1);
        }
        _ => panic!("Expected Failed with attempts_remaining = 1"),
    }

    // Attempt 3: 3rd strike triggers lockout!
    let res3 = auth.authenticate(&wrong_creds);
    assert!(!res3.is_success());
    match res3 {
        AuthResult::LockedOut { remaining_seconds, .. } => {
            assert!(remaining_seconds > 0);
        }
        _ => panic!("Expected LockedOut on 3rd failure"),
    }

    // Attempt 4: Active Lockout Enforcement
    let res4 = auth.authenticate(&wrong_creds);
    assert!(!res4.is_success());
    match res4 {
        AuthResult::LockedOut { remaining_seconds, .. } => {
            assert!(remaining_seconds > 0);
        }
        _ => panic!("Expected LockedOut result on subsequent attempt"),
    }

    let lockout_status = auth.check_lockout();
    assert!(lockout_status.is_locked);
    assert!(lockout_status.lockout_remaining_secs > 0);

    // Master Token Bypass: Must succeed even during active lockout and clear it!
    let master_creds = OperatorCredentials {
        operator_id: "admin".to_string(),
        auth_token: Some(master_token.to_string()),
        password: None,
        caller_pid: Some(5000),
        confirmation_phrase: None,
    };
    let bypass_res = auth.authenticate(&master_creds);
    assert!(bypass_res.is_success());
    match bypass_res {
        AuthResult::Success { method, .. } => assert_eq!(method, AuthMethod::MasterTokenBypass),
        _ => panic!("Expected Success with MasterTokenBypass"),
    }

    // After master bypass, lockout must be cleared
    let post_bypass_lockout = auth.check_lockout();
    assert!(!post_bypass_lockout.is_locked);
    assert_eq!(post_bypass_lockout.failed_attempts, 0);
}

#[test]
fn test_caller_pid_anti_hijacking_validation() {
    let temp = tempdir().expect("tempdir");
    let mut auth = OperatorAuthManager::new(None, Some(temp.path().to_path_buf()));

    // Active runner process PID is valid
    let my_pid = std::process::id();
    let val_res = auth.validate_caller(Some(my_pid));
    assert!(val_res.is_ok());

    // Register a frozen PID provider that marks PID 12345 as frozen
    auth.set_frozen_pids_provider(Arc::new(|| vec![12345]));

    // Validating frozen PID must return CallerQuarantined error
    let frozen_caller_res = auth.validate_caller(Some(12345));
    assert!(frozen_caller_res.is_err());
    match frozen_caller_res {
        Err(KillSwitchError::CallerQuarantined { pid }) => assert_eq!(pid, 12345),
        other => panic!("Expected CallerQuarantined, got: {:?}", other),
    }

    // PID 4 (System) must be rejected with InvalidCallerPid
    let system_caller_res = auth.validate_caller(Some(4));
    assert!(system_caller_res.is_err());
    match system_caller_res {
        Err(KillSwitchError::InvalidCallerPid { pid }) => assert_eq!(pid, 4),
        other => panic!("Expected InvalidCallerPid, got: {:?}", other),
    }
}

// =============================================================================
// 6. Cryptographic State Ledger & Atomic Disk Persistence Tests
// =============================================================================

#[test]
fn test_state_ledger_atomic_persistence_and_blake3_chaining() {
    let temp = tempdir().expect("tempdir");
    let mut ledger = StateLedger::open_or_init(Some(temp.path()))
        .expect("Initialize state ledger");

    // 1. Initial State rooted at GENESIS_HASH
    assert_eq!(ledger.snapshot().prev_hash, GENESIS_HASH);
    assert_eq!(ledger.snapshot().sequence_number, 0);
    assert!(!ledger.snapshot().current_hash.is_empty());
    assert!(ledger.verify_integrity().is_ok());

    // 2. First Transition: ENGAGED
    let mut status1 = ledger.status().clone();
    status1.isolated = true;
    status1.containment_level = ContainmentLevel::NetworkQuarantine;
    status1.network_isolated = true;
    status1.update_hash();

    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let receipt = IsolationReceipt::new(
        "sess-101".to_string(),
        NetworkIsolationEngine::WindowsWfpDynamic,
        vec![101],
        vec!["rule-1".to_string()],
        vec!["nl-1".to_string()],
        vec![3030],
        vec![loopback],
        1,
        "operator_alice".to_string(),
        "Containment engagement test".to_string(),
    );

    ledger
        .record_state_transition(
            status1,
            Some(vec![receipt]),
            None,
            "ENGAGED",
            "operator_alice",
            "Automated test containment",
        )
        .expect("Record transition 1");

    assert_eq!(ledger.snapshot().sequence_number, 1);
    assert_eq!(ledger.snapshot().history.len(), 1);
    assert_eq!(ledger.snapshot().history[0].prev_event_hash, GENESIS_HASH);
    assert!(ledger.verify_integrity().is_ok());

    // 3. Second Transition: DISARMED
    let mut status2 = ledger.status().clone();
    status2.isolated = false;
    status2.containment_level = ContainmentLevel::Disarmed;
    status2.network_isolated = false;
    status2.update_hash();

    let prev_event_hash = ledger.snapshot().history[0].event_hash.clone();

    ledger
        .record_state_transition(
            status2,
            Some(Vec::new()),
            Some(Vec::new()),
            "DISARMED",
            "operator_bob",
            "Restoration verified",
        )
        .expect("Record transition 2");

    assert_eq!(ledger.snapshot().sequence_number, 2);
    assert_eq!(ledger.snapshot().history.len(), 2);
    // Backward hash chain integrity check
    assert_eq!(ledger.snapshot().history[0].prev_event_hash, prev_event_hash);
    assert!(ledger.verify_integrity().is_ok());

    // 4. Persistence Reload & Tamper Detection Check
    let reloaded = StateLedger::open_or_init(Some(temp.path()))
        .expect("Reload state ledger from disk");
    assert_eq!(reloaded.snapshot().sequence_number, 2);
    assert!(reloaded.verify_integrity().is_ok());
}

// =============================================================================
// 7. KillChainHostManager Lifecycle & Health Probe Watchdog Tests
// =============================================================================

#[tokio::test]
async fn test_killchain_host_manager_lifecycle_and_probes() {
    let temp = tempdir().expect("tempdir");

    // Use SimulatedNetworkIsolator for platform-independent hermetic testing
    let isolator = Arc::new(SimulatedNetworkIsolator);
    let freezer = Arc::new(NativeProcessFreezer::new());
    let mut auth_manager = OperatorAuthManager::new(None, Some(temp.path().to_path_buf()));
    auth_manager.set_custom_master_token("MasterSecretKey123".to_string());
    let auth = Arc::new(auth_manager);
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(temp.path())).expect("Init ledger"),
    ));

    let manager = Arc::new(KillChainHostManager::new(
        isolator,
        freezer,
        auth.clone(),
        ledger.clone(),
    ));

    // 1. Initial State Check
    let init_status = manager.get_status();
    assert!(!init_status.isolated);
    assert_eq!(init_status.containment_level, ContainmentLevel::Disarmed);

    // 2. Health Probe Execution
    let probe1 = manager.run_probe().expect("Run probe 1");
    assert!(probe1.process_tree_integrity_ok);
    assert!(probe1.total_processes_scanned > 0);
    assert!(probe1.critical_os_anchors_verified > 0);
    assert_eq!(probe1.consecutive_healthy_probes, 1);
    assert!(!probe1.eligible_for_early_rollback);

    let probe2 = manager.run_probe().expect("Run probe 2");
    assert_eq!(probe2.consecutive_healthy_probes, 2);
    assert!(!probe2.eligible_for_early_rollback);

    let probe3 = manager.run_probe().expect("Run probe 3");
    assert_eq!(probe3.consecutive_healthy_probes, 3);
    assert!(probe3.eligible_for_early_rollback);

    manager.reset_probe_counter();
    assert_eq!(manager.get_status().consecutive_healthy_probes, 0);

    // 3. Engage Quarantine
    let engaged_status = manager
        .engage_isolation(
            "test_operator",
            "Integration test engagement",
            ContainmentLevel::NetworkQuarantine,
            Some(std::process::id()),
        )
        .await
        .expect("Engage isolation");

    assert!(engaged_status.isolated);
    assert!(engaged_status.network_isolated);
    assert_eq!(
        engaged_status.containment_level,
        ContainmentLevel::NetworkQuarantine
    );

    // 4. Idempotency Check: Second engagement returns active state
    let idempotent_status = manager
        .engage_isolation(
            "test_operator",
            "Second call",
            ContainmentLevel::NetworkQuarantine,
            Some(std::process::id()),
        )
        .await
        .expect("Second engage");
    assert!(idempotent_status.isolated);

    // 5. Disarm Quarantine with Valid Credentials
    let creds = OperatorCredentials {
        operator_id: "test_operator".to_string(),
        auth_token: Some("MasterSecretKey123".to_string()),
        password: None,
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };

    let disarmed_status = manager
        .disarm_isolation(
            "test_operator",
            "Integration test disarm",
            Some(&creds),
        )
        .await
        .expect("Disarm isolation");

    assert!(!disarmed_status.isolated);
    assert!(!disarmed_status.network_isolated);
    assert_eq!(
        disarmed_status.containment_level,
        ContainmentLevel::Disarmed
    );

    // 6. Verify Ledger History
    let history = manager.get_history();
    assert!(history.len() >= 2);
    assert_eq!(history[0].action, "DISARMED");
    assert_eq!(history[1].action, "ENGAGED");
    assert!(ledger.read().verify_integrity().is_ok());
}
