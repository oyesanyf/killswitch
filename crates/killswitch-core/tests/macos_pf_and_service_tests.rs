//! Integration tests for Milestone 2 Extension requirements:
//! - Feature 29: macOS Native PF Isolation (`/dev/pf` ioctls, loopback & port 3030 preservation, zero `pfctl`)
//! - Feature 30: macOS Process Freeze & System Whitelist (`launchd`, `WindowServer`, etc.)
//! - Feature 31: Native OS Service Lifecycle (Win32 SCM, Linux systemd, macOS launchd, zero CLI tools, shutdown auto-disarm)

use killswitch_core::{
    default_service_manager, execute_host_disarm_unauthenticated,
    generate_launchd_plist, generate_quarantine_rules, generate_systemd_unit,
    get_active_darwin_sockets, is_critical_system_pid, LinuxServiceManager,
    MacOsPfIsolator, MacOsServiceManager, NativeProcessFreezer, NativeServiceManager,
    PF_DEVICE_PATH,
};
use killswitch_types::{
    service::{ServiceConfig, ServiceError, ServiceState},
    status::{NetworkIsolationEngine, NetworkIsolator, ProcessFreezer, DEFAULT_CONTROL_PORT},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

// -----------------------------------------------------------------------------
// Feature 29: macOS Native PF Network Isolation
// -----------------------------------------------------------------------------

#[test]
fn test_f29_macos_pf_anchor_quarantine_rules_generation() {
    let preserved_ports = vec![DEFAULT_CONTROL_PORT, 53, 67, 68];
    let (rules, syntax) = generate_quarantine_rules("killswitch", &preserved_ports);

    assert!(!rules.is_empty(), "PF rule set must not be empty");
    assert!(
        syntax.contains("Anchor: killswitch"),
        "Syntax must reference anchor 'killswitch'"
    );

    // Invariant: lo0, 127.0.0.1, ::1 preserved with quick
    assert!(
        syntax.contains("pass quick on lo0 all"),
        "Rule syntax must preserve lo0 interface"
    );
    assert!(
        syntax.contains("pass quick from 127.0.0.1 to any"),
        "Rule syntax must explicitly pass 127.0.0.1"
    );
    assert!(
        syntax.contains("pass quick from ::1 to any"),
        "Rule syntax must explicitly pass ::1"
    );

    // Invariant: local control port 3030 preserved
    assert!(
        syntax.contains("port 3030"),
        "Rule syntax must preserve port 3030"
    );

    // Invariant: DNS 53 and DHCP 67/68 preserved
    assert!(
        syntax.contains("port 53"),
        "Rule syntax must preserve DNS 53"
    );
    assert!(
        syntax.contains("port 67"),
        "Rule syntax must preserve DHCP 67"
    );
    assert!(
        syntax.contains("port 68"),
        "Rule syntax must preserve DHCP 68"
    );

    // Invariant: Default hermetic block drop
    assert!(
        syntax.contains("block drop in all"),
        "Rule syntax must end with default block drop in"
    );
    assert!(
        syntax.contains("block drop out all"),
        "Rule syntax must end with default block drop out"
    );
}

#[test]
fn test_f29_macos_pf_isolator_lifecycle_and_contract() {
    let isolator = MacOsPfIsolator::with_anchor("test_anchor_f29");
    assert_eq!(isolator.anchor_name, "test_anchor_f29");
    assert_eq!(isolator.device_path, PathBuf::from(PF_DEVICE_PATH));

    // Engage quarantine
    let receipt = isolator
        .engage_quarantine(
            &[DEFAULT_CONTROL_PORT, 53],
            "sec_admin",
            "Simulated lateral movement threat",
        )
        .expect("engage_quarantine must succeed");

    assert_eq!(receipt.engine, NetworkIsolationEngine::DarwinPf);
    assert!(receipt.session_id.contains("test_anchor_f29"));
    assert!(receipt.preserved_ports.contains(&DEFAULT_CONTROL_PORT));
    assert!(receipt.preserved_ports.contains(&53));
    assert!(receipt.preserved_ips.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(receipt.preserved_ips.contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
    assert_eq!(receipt.engaged_by, "sec_admin");

    // Revert quarantine
    let revert_res = isolator.restore_quarantine(&receipt);
    assert!(revert_res.is_ok(), "restore_quarantine must succeed");

    // Reset TCP connections
    let reset_res = isolator.reset_tcp_connections(None);
    assert!(reset_res.is_ok(), "reset_tcp_connections must succeed");
}

#[test]
fn test_f29_darwin_socket_inspection() {
    let sockets = get_active_darwin_sockets().expect("get_active_darwin_sockets must succeed");
    assert!(!sockets.is_empty(), "Socket list should not be empty");

    for sock in &sockets {
        if sock.is_loopback {
            assert!(
                !sock.is_external_connection(),
                "Loopback socket must not be classified as external"
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Feature 30: macOS Process Freeze & System Whitelist Immunity
// -----------------------------------------------------------------------------

#[test]
fn test_f30_macos_critical_system_whitelist_in_freeze() {
    let freezer = NativeProcessFreezer::new();

    let macos_daemons = [
        ("launchd", 1),
        ("WindowServer", 88),
        ("loginwindow", 89),
        ("kernel_task", 0),
        ("UserEventAgent", 90),
        ("cfprefsd", 91),
        ("opendirectoryd", 92),
        ("mds", 93),
        ("Finder", 94),
        ("Dock", 95),
        ("Terminal", 96),
        ("iTerm2", 97),
        // Case variations
        ("windowserver", 100),
        ("LOGINWINDOW", 101),
        ("TERMINAL", 102),
        ("iterm2", 103),
    ];

    for (name, pid) in macos_daemons {
        assert!(
            freezer.is_immune(pid, name),
            "ProcessFreezer must recognize macOS '{}' (PID {}) as immune",
            name,
            pid
        );
        assert!(
            is_critical_system_pid(pid, name),
            "is_critical_system_pid must recognize macOS '{}' (PID {}) as immune",
            name,
            pid
        );
    }
}

#[test]
fn test_f30_freeze_attempt_on_immune_macos_process_fails_closed() {
    let freezer = NativeProcessFreezer::new();

    // Attempting to freeze launchd (PID 1) or WindowServer must return ProtectedProcessImmune error
    let res = freezer.freeze_process(1);
    assert!(
        res.is_err(),
        "Freezing PID 1 (launchd/systemd) must fail closed with immunity error"
    );
}

// -----------------------------------------------------------------------------
// Feature 31: Native OS Service Lifecycle & Unconditional Shutdown Disarm
// -----------------------------------------------------------------------------

#[test]
fn test_f31_linux_systemd_unit_generation_and_filesystem_installer() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mgr = LinuxServiceManager::with_root_dir(temp_dir.path());

    let config = ServiceConfig {
        name: "killswitch".to_string(),
        display_name: "KillSwitch Native Security Daemon".to_string(),
        description: "Zero-OS-tool host containment agent".to_string(),
        executable_path: PathBuf::from("/usr/local/bin/killswitch"),
        arguments: vec!["service".to_string(), "run".to_string()],
        working_dir: Some(PathBuf::from("/var/run/killswitch")),
        auto_start: true,
        root_dir: Some(temp_dir.path().to_path_buf()),
    };

    // 1. Generate unit definition syntax
    let unit = generate_systemd_unit(&config);
    assert!(unit.contains("[Unit]"));
    assert!(unit.contains("Description=Zero-OS-tool host containment agent"));
    assert!(unit.contains("Type=notify"));
    assert!(unit.contains("ExecStart=/usr/local/bin/killswitch service run"));
    assert!(unit.contains("WorkingDirectory=/var/run/killswitch"));
    assert!(unit.contains("Restart=on-failure"));
    assert!(unit.contains("KillMode=process"));

    // 2. Install unit directly to filesystem
    mgr.install_service(&config).expect("Service installation must succeed");

    let unit_file = temp_dir.path().join("etc/systemd/system/killswitch.service");
    assert!(unit_file.exists(), "Unit file must be created on disk");

    // 3. Query status
    let status = mgr.service_status("killswitch").expect("Query status must succeed");
    assert!(status.is_installed, "Service must be marked installed");
    assert_eq!(status.name, "killswitch");

    // 4. Uninstall
    mgr.uninstall_service("killswitch").expect("Uninstall must succeed");
    assert!(!unit_file.exists(), "Unit file must be deleted upon uninstall");

    // 5. Subsequent uninstall returns NotFound
    let err = mgr.uninstall_service("killswitch");
    assert!(matches!(err, Err(ServiceError::NotFound(_))));
}

#[test]
fn test_f31_macos_launchd_plist_generation_and_filesystem_installer() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mgr = MacOsServiceManager::with_root_dir(temp_dir.path());

    let config = ServiceConfig {
        name: "killswitch".to_string(),
        display_name: "KillSwitch Security Daemon".to_string(),
        description: "Zero-OS-tool host containment agent".to_string(),
        executable_path: PathBuf::from("/usr/local/bin/killswitch"),
        arguments: vec!["service".to_string(), "run".to_string()],
        working_dir: None,
        auto_start: true,
        root_dir: Some(temp_dir.path().to_path_buf()),
    };

    // 1. Generate XML property list definition
    let plist = generate_launchd_plist(&config);
    assert!(plist.contains("<!DOCTYPE plist PUBLIC"));
    assert!(plist.contains("<key>Label</key>"));
    assert!(plist.contains("<string>com.oshoosi.killswitch</string>"));
    assert!(plist.contains("<key>ProgramArguments</key>"));
    assert!(plist.contains("<string>/usr/local/bin/killswitch</string>"));
    assert!(plist.contains("<string>service</string>"));
    assert!(plist.contains("<string>run</string>"));
    assert!(plist.contains("<key>RunAtLoad</key>"));
    assert!(plist.contains("<true/>"));
    assert!(plist.contains("<key>KeepAlive</key>"));

    // 2. Install plist directly to filesystem
    mgr.install_service(&config).expect("Service installation must succeed");

    let plist_file = temp_dir
        .path()
        .join("Library/LaunchDaemons/com.oshoosi.killswitch.plist");
    assert!(plist_file.exists(), "Launchd plist file must be created on disk");

    // 3. Query status
    let status = mgr.service_status("killswitch").expect("Query status must succeed");
    assert!(status.is_installed, "Service must be marked installed");
    assert_eq!(status.name, "killswitch");

    // 4. Uninstall
    mgr.uninstall_service("killswitch").expect("Uninstall must succeed");
    assert!(!plist_file.exists(), "Plist file must be deleted upon uninstall");
}

#[test]
fn test_f31_unconditional_shutdown_disarm_guarantee() {
    // Calling execute_host_disarm_unauthenticated() must never panic,
    // must restore network rules, release all tarpitted processes, and update status
    let disarm_status = execute_host_disarm_unauthenticated()
        .expect("execute_host_disarm_unauthenticated must always succeed");

    assert!(!disarm_status.isolated);
    assert!(!disarm_status.network_isolated);
    assert!(disarm_status.frozen_pids.is_empty());
    assert!(disarm_status.tarpitted_pids.is_empty());
}

#[test]
fn test_f31_default_service_manager_instantiation() {
    let mgr = default_service_manager();
    // Non-existent service query returns is_installed: false
    let status = mgr.service_status("nonexistent_ks_service_99999");
    assert!(status.is_ok());
    let s = status.unwrap();
    assert!(!s.is_installed);
    assert_eq!(s.state, ServiceState::NotInstalled);
}
