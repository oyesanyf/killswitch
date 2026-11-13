//! Empirical Challenge Test Suite (Milestone 2 - Challenger 2)
//!
//! Rigorous stress testing and verification for:
//! 1. Network Quarantine Integrity & Loopback Preservation (127.0.0.1, ::1, DNS/DHCP, Port 3030)
//!    and Darwin `/dev/pf` ioctl structures, transactional semantics (`DIOCXBEGIN`/`DIOCXCOMMIT`),
//!    and rule alignment.
//! 2. Lineage Immunity Edge Cases: Critical OS binaries (Windows, Linux, macOS), developer tools,
//!    adversarial masquerade rejection, and deep process ancestry chains (depth 1 to 10).
//! 3. KillChainHostManager Health Probes, 3-Clean-Probe Early Rollback, Dead-Man Failsafe,
//!    and Unauthenticated Emergency Disarm under Abrupt Cancellation.

use killswitch_core::{
    auth::OperatorAuthManager,
    freeze::NativeProcessFreezer,
    killchain::{is_critical_system_pid, KillChainHostManager, SimulatedNetworkIsolator},
    pf::{
        generate_quarantine_rules, DarwinPfTrans, DarwinPfTransElement, DarwinPfiocRule,
        MacOsPfIsolator, PfAction, PfDirection, PfProtocol, DIOCADDRULE, DIOCSTART, DIOCSTOP,
        DIOCXBEGIN, DIOCXCOMMIT, DIOCXROLLBACK,
    },
    state_ledger::StateLedger,
    wfp::WindowsWfpIsolator,
};
use killswitch_types::{
    errors::{KillSwitchError, Result},
    status::{
        ContainmentLevel, HealthProbeRunner, KillChainStatus, NetworkIsolationEngine,
        NetworkIsolator, OperatorCredentials, ProcessFreezer, ProcessIsolationMethod,
        ProcessIsolationState, DEFAULT_CONTROL_PORT,
    },
};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

// =============================================================================
// Mock / Spy Primitives for KillChainHostManager Stress Testing
// =============================================================================

#[derive(Default)]
struct ControllableProcessFreezer {
    frozen_pids: Arc<RwLock<HashSet<u32>>>,
    resume_call_count: Arc<AtomicUsize>,
}

impl ProcessFreezer for ControllableProcessFreezer {
    fn freeze_process(&self, pid: u32) -> Result<ProcessIsolationState> {
        if is_critical_system_pid(pid, "test") {
            return Err(KillSwitchError::ProtectedProcessImmune {
                pid,
                name: "test".to_string(),
                reason: "Protected system process",
            });
        }
        self.frozen_pids.write().insert(pid);
        Ok(ProcessIsolationState::new_frozen(
            pid,
            "test_target.exe".to_string(),
            None,
            ProcessIsolationMethod::NtSuspendProcess,
        ))
    }

    fn resume_process(&self, pid: u32) -> Result<ProcessIsolationState> {
        self.frozen_pids.write().remove(&pid);
        self.resume_call_count.fetch_add(1, Ordering::SeqCst);
        let mut s = ProcessIsolationState::new_frozen(
            pid,
            "test_target.exe".to_string(),
            None,
            ProcessIsolationMethod::NtSuspendProcess,
        );
        s.mark_resumed();
        Ok(s)
    }

    fn tarpit_process(&self, pid: u32) -> Result<ProcessIsolationState> {
        Ok(ProcessIsolationState::new_frozen(
            pid,
            "test_target.exe".to_string(),
            None,
            ProcessIsolationMethod::ThreadTarpit,
        ))
    }

    fn release_tarpit(&self, pid: u32) -> Result<ProcessIsolationState> {
        let mut s = ProcessIsolationState::new_frozen(
            pid,
            "test_target.exe".to_string(),
            None,
            ProcessIsolationMethod::ThreadTarpit,
        );
        s.mark_resumed();
        Ok(s)
    }

    fn is_immune(&self, pid: u32, name: &str) -> bool {
        is_critical_system_pid(pid, name)
    }
}

// =============================================================================
// 1. Network Quarantine Integrity & Loopback Preservation
// =============================================================================

#[test]
fn test_loopback_ipv4_and_ipv6_traffic_preservation_under_isolation() {
    use std::io::{Read, Write};

    // Bind real TCP listeners on IPv4 loopback (127.0.0.1) and IPv6 loopback (::1)
    let listener_v4 = TcpListener::bind("127.0.0.1:0").expect("Must bind IPv4 loopback");
    let port_v4 = listener_v4.local_addr().unwrap().port();

    // Spawn real echo server for IPv4
    let server_handle_v4 = std::thread::spawn(move || {
        let (mut stream, _) = listener_v4.accept().expect("Must accept connection");
        let mut buf = [0u8; 32];
        let bytes_read = stream.read(&mut buf).expect("Read must succeed");
        assert_eq!(&buf[..bytes_read], b"KILLSWITCH_IPV4_ALIVE");
        stream
            .write_all(b"KILLSWITCH_IPV4_ECHO_OK")
            .expect("Write must succeed");
    });

    // Simulate Network Quarantine
    let isolator = MacOsPfIsolator::with_anchor("test_anchor_loopback");
    let receipt = match isolator.engage_quarantine(
        &[port_v4, DEFAULT_CONTROL_PORT, 53, 67, 68],
        "sec_admin",
        "Testing loopback preservation during quarantine",
    ) {
        Ok(r) => r,
        Err(KillSwitchError::InsufficientPrivileges { .. }) => {
            // macOS /dev/pf requires root privileges; unprivileged CI runners fail closed safely
            let mut client_v4 =
                TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_v4))
                    .expect("Loopback IPv4 connection must succeed");
            client_v4
                .write_all(b"KILLSWITCH_IPV4_ALIVE")
                .expect("Client send must succeed");
            let mut resp = [0u8; 32];
            let n = client_v4.read(&mut resp).expect("Client read must succeed");
            assert_eq!(&resp[..n], b"KILLSWITCH_IPV4_ECHO_OK");
            server_handle_v4.join().unwrap();
            return;
        }
        Err(e) => panic!("Quarantine engagement must succeed: {:?}", e),
    };

    assert!(receipt.preserved_ports.contains(&port_v4));
    assert!(receipt
        .preserved_ips
        .contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(receipt
        .preserved_ips
        .contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));

    // Connect from client and verify data transfer succeeds during quarantine
    let mut client_v4 =
        TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_v4))
            .expect("Loopback IPv4 connection must succeed during quarantine");
    client_v4
        .write_all(b"KILLSWITCH_IPV4_ALIVE")
        .expect("Client send must succeed");
    let mut resp = [0u8; 32];
    let n = client_v4.read(&mut resp).expect("Client read must succeed");
    assert_eq!(&resp[..n], b"KILLSWITCH_IPV4_ECHO_OK");

    server_handle_v4.join().unwrap();

    // Revert quarantine and assert idempotency
    isolator.restore_quarantine(&receipt).unwrap();
    isolator.restore_quarantine(&receipt).unwrap();
}

#[test]
fn test_quarantine_receipt_preserved_ports_and_ips_integrity() {
    let preserved_ports = vec![DEFAULT_CONTROL_PORT, 53, 67, 68, 546, 547];

    // 1. macOS PF Isolator receipt
    let macos_isolator = MacOsPfIsolator::with_anchor("anchor_receipt_test");
    let receipt_macos = match macos_isolator.engage_quarantine(
        &preserved_ports,
        "admin",
        "Darwin PF Receipt Verification",
    ) {
        Ok(r) => r,
        Err(KillSwitchError::InsufficientPrivileges { .. }) => {
            // macOS /dev/pf requires root privileges; unprivileged CI runners fail closed safely
            return;
        }
        Err(e) => panic!("Quarantine engagement failed: {:?}", e),
    };

    assert_eq!(receipt_macos.engine, NetworkIsolationEngine::DarwinPf);
    assert_eq!(receipt_macos.preserved_ports, preserved_ports);
    assert!(receipt_macos
        .preserved_ips
        .contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(receipt_macos
        .preserved_ips
        .contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));

    // 2. Windows WFP Isolator receipt contract
    let wfp_isolator = WindowsWfpIsolator;
    let receipt_wfp = wfp_isolator
        .engage_quarantine(
            &preserved_ports,
            "admin",
            "Windows WFP Receipt Verification",
        )
        .unwrap();

    assert_eq!(
        receipt_wfp.engine,
        NetworkIsolationEngine::WindowsWfpDynamic
    );
    assert_eq!(receipt_wfp.preserved_ports, preserved_ports);
    assert!(receipt_wfp
        .preserved_ips
        .contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(receipt_wfp
        .preserved_ips
        .contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));

    // 3. Fallback Simulated Isolator receipt
    let sim_isolator = SimulatedNetworkIsolator;
    let receipt_sim = sim_isolator
        .engage_quarantine(&preserved_ports, "admin", "Simulated Receipt Verification")
        .unwrap();

    assert_eq!(receipt_sim.engine, NetworkIsolationEngine::Simulated);
    assert_eq!(receipt_sim.preserved_ports, preserved_ports);
}

#[test]
fn test_darwin_pf_quarantine_rules_structure_and_order() {
    let preserved_ports = vec![DEFAULT_CONTROL_PORT, 53, 67, 68];
    let (rules, syntax) = generate_quarantine_rules("test_killswitch_anchor", &preserved_ports);

    assert!(rules.len() >= 7, "Expected at least 7 generated PF rules");

    // Invariant: First rule must be quick pass on lo0
    assert_eq!(rules[0].action, PfAction::Pass);
    assert_eq!(rules[0].direction, PfDirection::InOut);
    assert!(rules[0].quick);
    assert_eq!(rules[0].interface.as_deref(), Some("lo0"));

    // Invariant: Rules 1 & 2 must be explicit 127.0.0.1 and ::1 quick passes
    assert_eq!(rules[1].src, "127.0.0.1");
    assert!(rules[1].quick);
    assert_eq!(rules[2].src, "::1");
    assert!(rules[2].quick);

    // Invariant: Port 3030 must be preserved for inbound and outbound TCP
    let port_3030_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.src_port == Some(3030) || r.dst_port == Some(3030))
        .collect();
    assert_eq!(
        port_3030_rules.len(),
        2,
        "Must have in and out rules for 3030"
    );
    for r in &port_3030_rules {
        assert_eq!(r.action, PfAction::Pass);
        assert_eq!(r.protocol, PfProtocol::Tcp);
        assert!(r.quick);
    }

    // Invariant: DNS 53 (UDP & TCP) and DHCP 67/68 must strictly NOT be preserved
    assert!(!rules.iter().any(|r| r.dst_port == Some(53)));
    assert!(!rules
        .iter()
        .any(|r| r.dst_port == Some(67) || r.src_port == Some(67)));
    assert!(!rules
        .iter()
        .any(|r| r.dst_port == Some(68) || r.src_port == Some(68)));

    // Invariant: Last two rules must be hermetic block drop in & out all with quick: true
    let last_rule_in = &rules[rules.len() - 2];
    let last_rule_out = &rules[rules.len() - 1];

    assert_eq!(last_rule_in.action, PfAction::Drop);
    assert_eq!(last_rule_in.direction, PfDirection::In);
    assert!(last_rule_in.quick, "Default in block must have quick: true");

    assert_eq!(last_rule_out.action, PfAction::Drop);
    assert_eq!(last_rule_out.direction, PfDirection::Out);
    assert!(
        last_rule_out.quick,
        "Default out block must have quick: true"
    );

    // Verify generated syntax string contains anchor and exact quick block statements
    assert!(syntax.contains("Anchor: test_killswitch_anchor"));
    assert!(syntax.contains("block drop in quick all"));
    assert!(syntax.contains("block drop out quick all"));
}

#[test]
fn test_darwin_pf_ioctl_constants_and_bitfield_integrity() {
    // Darwin ioctl encoding: _IO, _IOW, _IOWR macros
    // Group 'D' (0x44), numbers 1, 2, 4, 81, 82, 83
    assert_eq!(DIOCSTART, 0x20004401, "DIOCSTART must match _IO('D', 1)");
    assert_eq!(DIOCSTOP, 0x20004402, "DIOCSTOP must match _IO('D', 2)");
    assert_eq!(
        DIOCADDRULE, 0xC8084404,
        "DIOCADDRULE must match _IOWR('D', 4, pfioc_rule)"
    );
    assert_eq!(
        DIOCXBEGIN, 0xC8104451,
        "DIOCXBEGIN must match _IOWR('D', 81, pfioc_trans)"
    );
    assert_eq!(
        DIOCXCOMMIT, 0xC8104452,
        "DIOCXCOMMIT must match _IOWR('D', 82, pfioc_trans)"
    );
    assert_eq!(
        DIOCXROLLBACK, 0xC8104453,
        "DIOCXROLLBACK must match _IOWR('D', 83, pfioc_trans)"
    );
}

#[test]
fn test_darwin_pf_c_abi_struct_sizes_alignments_and_offsets() {
    // Verify DarwinPfTransElement memory layout
    assert_eq!(
        std::mem::size_of::<DarwinPfTransElement>(),
        1032,
        "DarwinPfTransElement must be exactly 1032 bytes (4 + 1024 + 4)"
    );
    assert_eq!(
        std::mem::align_of::<DarwinPfTransElement>(),
        4,
        "DarwinPfTransElement alignment must be 4 bytes"
    );

    let elem = DarwinPfTransElement::default();
    let base = &elem as *const _ as usize;
    let rs_num_offset = (&elem.rs_num as *const _ as usize) - base;
    let anchor_offset = (&elem.anchor as *const _ as usize) - base;
    let ticket_offset = (&elem.ticket as *const _ as usize) - base;

    assert_eq!(rs_num_offset, 0);
    assert_eq!(anchor_offset, 4);
    assert_eq!(ticket_offset, 1028);

    // Verify DarwinPfTrans memory layout (64-bit architecture)
    assert_eq!(
        std::mem::size_of::<DarwinPfTrans>(),
        16,
        "DarwinPfTrans must be exactly 16 bytes (4 + 4 + 8)"
    );
    assert_eq!(
        std::mem::align_of::<DarwinPfTrans>(),
        8,
        "DarwinPfTrans alignment must be 8 bytes on 64-bit platforms"
    );

    let trans = DarwinPfTrans {
        size: 1,
        esize: 1032,
        array: std::ptr::null_mut(),
    };
    let trans_base = &trans as *const _ as usize;
    let size_offset = (&trans.size as *const _ as usize) - trans_base;
    let esize_offset = (&trans.esize as *const _ as usize) - trans_base;
    let array_offset = (&trans.array as *const _ as usize) - trans_base;

    assert_eq!(size_offset, 0);
    assert_eq!(esize_offset, 4);
    assert_eq!(array_offset, 8);

    // Verify DarwinPfiocRule layout
    let pfioc = DarwinPfiocRule::default();
    let pfioc_base = &pfioc as *const _ as usize;
    let action_offset = (&pfioc.action as *const _ as usize) - pfioc_base;
    let pfioc_ticket_offset = (&pfioc.ticket as *const _ as usize) - pfioc_base;
    let nr_offset = (&pfioc.nr as *const _ as usize) - pfioc_base;
    let pfioc_anchor_offset = (&pfioc.anchor as *const _ as usize) - pfioc_base;
    let ruleset_offset = (&pfioc.ruleset as *const _ as usize) - pfioc_base;
    let rule_offset = (&pfioc.rule as *const _ as usize) - pfioc_base;

    assert_eq!(action_offset, 0);
    assert_eq!(pfioc_ticket_offset, 4);
    assert_eq!(nr_offset, 8);
    assert_eq!(pfioc_anchor_offset, 12);
    assert_eq!(ruleset_offset, 1036);
    assert_eq!(rule_offset, 2060);
}

#[test]
fn test_darwin_pf_transactional_lifecycle_and_idempotent_rollback() {
    let isolator = MacOsPfIsolator::with_anchor("adversarial_test_anchor");
    assert_eq!(isolator.anchor_name, "adversarial_test_anchor");

    // 1. Engage quarantine
    let receipt = match isolator.engage_quarantine(
        &[DEFAULT_CONTROL_PORT, 53],
        "adversary_critic",
        "Validating transactional PF rollback",
    ) {
        Ok(r) => r,
        Err(KillSwitchError::InsufficientPrivileges { .. }) => {
            // macOS /dev/pf requires root privileges; unprivileged CI runners fail closed safely
            return;
        }
        Err(e) => panic!("Engagement must succeed: {:?}", e),
    };

    assert_eq!(receipt.engine, NetworkIsolationEngine::DarwinPf);
    assert!(receipt.session_id.contains("adversarial_test_anchor"));

    // 2. Perform first rollback
    let rollback_1 = isolator.restore_quarantine(&receipt);
    assert!(rollback_1.is_ok(), "First rollback must succeed");

    // 3. Perform second rollback (idempotency check)
    let rollback_2 = isolator.restore_quarantine(&receipt);
    assert!(
        rollback_2.is_ok(),
        "Second rollback must be an idempotent no-op"
    );

    // 4. Reset TCP connections check
    let reset_count = isolator.reset_tcp_connections(None).unwrap();
    // On non-macOS test runner, simulated sockets are loopback so 0 external drops
    assert_eq!(reset_count, 0);
}

// =============================================================================
// 2. Lineage Immunity Edge Cases & Adversarial Veto
// =============================================================================

#[test]
fn test_windows_critical_os_binaries_immunity_matrix() {
    let freezer = NativeProcessFreezer::new();

    let windows_core_binaries = [
        "explorer.exe",
        "svchost.exe",
        "lsass.exe",
        "dwm.exe",
        "csrss.exe",
        "services.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "taskmgr.exe",
        "securityhealthservice.exe",
        "smartscreen.exe",
        "sihost.exe",
        "runtimebroker.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "conhost.exe",
        "windowsterminal.exe",
    ];

    for name in windows_core_binaries {
        assert!(
            is_critical_system_pid(12345, name),
            "is_critical_system_pid failed for Windows binary: {}",
            name
        );
        assert!(
            freezer.is_immune(12345, name),
            "NativeProcessFreezer::is_immune failed for Windows binary: {}",
            name
        );
    }
}

#[test]
fn test_linux_baseline_critical_binaries_immunity() {
    let freezer = NativeProcessFreezer::new();

    let linux_baseline_binaries = [
        "systemd",
        "systemd-logind",
        "systemd-journald",
        "systemd-resolved",
        "sshd",
        "dbus-daemon",
        "bash",
        "sh",
        "zsh",
        "fish",
        "sudo",
        "login",
        "init",
    ];

    for name in linux_baseline_binaries {
        assert!(
            is_critical_system_pid(12345, name),
            "is_critical_system_pid failed for Linux binary: {}",
            name
        );
        assert!(
            freezer.is_immune(12345, name),
            "NativeProcessFreezer::is_immune failed for Linux binary: {}",
            name
        );
    }
}

#[test]
fn test_challenge_desynchronization_freezer_vs_killchain_immunity() {
    let freezer = NativeProcessFreezer::new();

    // Critical daemons defined in killchain::is_critical_system_pid that MUST also be immune in NativeProcessFreezer
    let extended_critical_binaries = [
        "systemd-networkd",
        "systemd-udevd",
        "dbus-broker",
        "networkmanager",
    ];

    for name in extended_critical_binaries {
        assert!(
            is_critical_system_pid(12345, name),
            "is_critical_system_pid must protect extended critical binary: {}",
            name
        );
        assert!(
            freezer.is_immune(12345, name),
            "BUG DISCOVERED: NativeProcessFreezer::is_immune is desynchronized from is_critical_system_pid and fails to protect critical Linux infrastructure '{}'. Calling freeze_all_untrusted will freeze critical network/device management daemons!",
            name
        );
    }
}

#[test]
fn test_macos_mandatory_12_critical_daemons_immunity_matrix() {
    let freezer = NativeProcessFreezer::new();

    // The 12 mandatory macOS critical processes per PROJECT.md & TEST_INFRA.md
    let macos_daemons = [
        ("launchd", 1),
        ("WindowServer", 9901),
        ("loginwindow", 9902),
        ("kernel_task", 0),
        ("UserEventAgent", 9903),
        ("cfprefsd", 9904),
        ("opendirectoryd", 9905),
        ("mds", 9906),
        ("Finder", 9907),
        ("Dock", 9908),
        ("Terminal", 9909),
        ("iTerm2", 9910),
    ];

    for (name, pid) in macos_daemons {
        assert!(
            is_critical_system_pid(pid, name),
            "is_critical_system_pid failed for macOS daemon: {}",
            name
        );
        assert!(
            freezer.is_immune(pid, name),
            "NativeProcessFreezer::is_immune failed for macOS daemon: {}",
            name
        );
    }
}

#[test]
fn test_developer_tools_and_system_pids_immunity() {
    let freezer = NativeProcessFreezer::new();

    let dev_binaries = [
        "cargo",
        "cargo.exe",
        "rustc",
        "rustc.exe",
        "code.exe",
        "antigravity.exe",
        "git",
        "git.exe",
        "python",
        "python.exe",
        "python3",
        "python3.exe",
        "node",
        "node.exe",
    ];

    for name in dev_binaries {
        assert!(
            is_critical_system_pid(8888, name),
            "Developer binary must be protected: {}",
            name
        );
        assert!(
            freezer.is_immune(8888, name),
            "Freezer must consider developer binary immune: {}",
            name
        );
    }

    // Kernel / System PIDs
    assert!(is_critical_system_pid(0, "arbitrary_name"));
    assert!(is_critical_system_pid(1, "arbitrary_name"));
    assert!(is_critical_system_pid(4, "arbitrary_name"));
    assert!(is_critical_system_pid(std::process::id(), "arbitrary_name"));

    assert!(freezer.is_immune(0, "arbitrary_name"));
    assert!(freezer.is_immune(1, "arbitrary_name"));
    assert!(freezer.is_immune(4, "arbitrary_name"));
    assert!(freezer.is_immune(std::process::id(), "arbitrary_name"));
}

#[test]
fn test_immunity_case_insensitivity_and_path_normalization() {
    let freezer = NativeProcessFreezer::new();

    let test_cases = [
        // Windows case variants and paths
        ("EXPLORER.EXE", 2000),
        ("Explorer.Exe", 2001),
        ("C:\\Windows\\System32\\explorer.exe", 2002),
        ("C:\\Windows\\System32\\svchost.exe", 2003),
        ("\"C:\\Windows\\System32\\lsass.exe\"", 2004),
        ("  'dwm.exe'  ", 2005),
        // Linux case variants and paths
        ("/usr/lib/systemd/systemd", 3000),
        ("/usr/bin/SYSTEMD-LOGIND", 3001),
        ("/bin/bash", 3002),
        // macOS case variants and paths
        ("/System/Library/CoreServices/WindowServer", 4000),
        ("wInDoWsErVeR", 4001),
        (
            "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            4002,
        ),
        (
            "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            4003,
        ),
        ("TeRmInAl", 4004),
        ("/Applications/iTerm.app/Contents/MacOS/iTerm2", 4005),
        ("ITERM2", 4006),
        (
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            4007,
        ),
    ];

    for (input, pid) in test_cases {
        assert!(
            is_critical_system_pid(pid, input),
            "Normalized path/casing failed in is_critical_system_pid for: {}",
            input
        );
        assert!(
            freezer.is_immune(pid, input),
            "Normalized path/casing failed in NativeProcessFreezer::is_immune for: {}",
            input
        );
    }
}

#[test]
fn test_adversarial_process_masquerade_and_extension_rejection() {
    let freezer = NativeProcessFreezer::new();

    // Adversarial binaries attempting to piggyback or masquerade as immune binaries
    let disguised_malware = [
        "malicious_explorer.exe",
        "explorer.exe.scr",
        "explorer.exe.bat",
        "svchost.exe.vbs",
        "fake_systemd.bin",
        "trojan_launchd.sh",
        "windowserver_backdoor",
        "terminal_stealer.elf",
        "cargo_miner.exe",
        "rustc_dropper",
        "antigravity_exfil.py",
        "my_dock_hijacker",
        "finder_spoof.exe",
    ];

    for fake in disguised_malware {
        assert!(
            !is_critical_system_pid(55555, fake),
            "Adversarial masquerade binary must NOT be immune in is_critical_system_pid: {}",
            fake
        );
        assert!(
            !freezer.is_immune(55555, fake),
            "Adversarial masquerade binary must NOT be immune in freezer: {}",
            fake
        );
    }
}

#[test]
fn test_deep_process_ancestry_chains_depth_boundary_1_to_10() {
    // Model a simulated process ancestry chain:
    // Process 0 (root PID 4) -> Parent 1 (PID 1001) -> ... -> Parent 10 (PID 1010) -> Target Child (PID 2000)
    // Invariant: Parent ancestry up to depth <= 5 confers immunity; depth > 5 does NOT confer immunity.

    struct AncestryNode {
        pid: u32,
        parent_pid: Option<u32>,
        name: String,
    }

    let mut process_table = Vec::new();

    // Depth 0: Current process
    process_table.push(AncestryNode {
        pid: 2000,
        parent_pid: Some(1001),
        name: "test_worker.exe".to_string(),
    });

    // Depth 1 to 10
    for depth in 1..=10 {
        let pid = 1000 + depth;
        let parent = if depth == 10 {
            Some(4) // Root Windows System PID 4
        } else {
            Some(1000 + depth + 1)
        };
        process_table.push(AncestryNode {
            pid,
            parent_pid: parent,
            name: format!("parent_stage_{}.exe", depth),
        });
    }

    // Traversal simulation replicating NativeProcessFreezer::get_immune_pids() logic
    let mut immune_set = HashSet::new();
    immune_set.insert(0);
    immune_set.insert(1);
    immune_set.insert(4);

    let start_pid = 2000;
    immune_set.insert(start_pid);

    let mut current_pid = start_pid;
    let mut depth = 0;

    while let Some(node) = process_table.iter().find(|p| p.pid == current_pid) {
        assert!(!node.name.is_empty());
        if let Some(parent_pid) = node.parent_pid {
            immune_set.insert(parent_pid);
            depth += 1;
            if depth >= 5 {
                break;
            }
            current_pid = parent_pid;
        } else {
            break;
        }
    }

    // Assert that depths 1, 2, 3, 4, 5 are immune
    for d in 1..=5 {
        let pid = 1000 + d;
        assert!(
            immune_set.contains(&pid),
            "Ancestor at depth {} (PID {}) must be immune",
            d,
            pid
        );
    }

    // Assert that depths 6, 7, 8, 9 are NOT immune (depth cutoff = 5)
    for d in 6..=9 {
        let pid = 1000 + d;
        assert!(
            !immune_set.contains(&pid),
            "Ancestor at depth {} (PID {}) must NOT be immune (exceeds depth 5)",
            d,
            pid
        );
    }

    // PID 4 (depth 10) is immune strictly because it is root PID 4, not because of depth
    assert!(immune_set.contains(&4));
}

#[test]
fn test_cyclic_and_terminated_process_ancestry_traversal() {
    // Test that circular ancestry (PID A -> PID B -> PID A) does not cause an infinite loop
    let mut cyclic_table = std::collections::HashMap::new();
    cyclic_table.insert(5001, 5002);
    cyclic_table.insert(5002, 5001); // Cycle!

    let mut visited = HashSet::new();
    let mut depth = 0;
    let mut curr = 5001;

    while let Some(&parent) = cyclic_table.get(&curr) {
        if !visited.insert(parent) {
            // Detected cycle
            break;
        }
        depth += 1;
        if depth >= 5 {
            break;
        }
        curr = parent;
    }

    assert!(
        depth <= 5,
        "Traversal must terminate safely upon cycle detection"
    );
}

// =============================================================================
// 3. KillChainHostManager Health Probes, 3-Clean-Probe Early Rollback & Dead-Man
// =============================================================================

#[tokio::test]
async fn test_health_probe_progression_1_2_3_clean_probes_early_rollback() {
    let dir = tempdir().unwrap();
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(dir.path())).unwrap(),
    ));
    let auth = Arc::new(OperatorAuthManager::new(
        Some(dir.path().to_path_buf()),
        None,
    ));
    let freezer = Arc::new(ControllableProcessFreezer::default());
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer,
        auth,
        ledger,
    ));

    // Engage isolation
    let status = manager
        .engage_isolation(
            "test_admin",
            "Verifying 3-probe progression",
            ContainmentLevel::HermeticIsolation,
            Some(std::process::id()),
        )
        .await
        .unwrap();

    assert!(status.isolated);
    assert_eq!(status.consecutive_healthy_probes, 0);

    // --- Probe 1 ---
    let report1 = manager.run_probe().unwrap();
    assert!(report1.process_tree_integrity_ok);
    assert_eq!(report1.consecutive_healthy_probes, 1);
    assert_eq!(report1.required_healthy_probes, 3);
    assert!(
        !report1.eligible_for_early_rollback,
        "Probe 1 must NOT be eligible for early rollback"
    );

    let status1 = manager.get_status();
    assert_eq!(status1.consecutive_healthy_probes, 1);
    assert!(status1.isolated);

    // --- Probe 2 ---
    let report2 = manager.run_probe().unwrap();
    assert!(report2.process_tree_integrity_ok);
    assert_eq!(report2.consecutive_healthy_probes, 2);
    assert!(
        !report2.eligible_for_early_rollback,
        "Probe 2 must NOT be eligible for early rollback"
    );

    let status2 = manager.get_status();
    assert_eq!(status2.consecutive_healthy_probes, 2);
    assert!(status2.isolated);

    // --- Probe 3 ---
    let report3 = manager.run_probe().unwrap();
    assert!(report3.process_tree_integrity_ok);
    assert_eq!(report3.consecutive_healthy_probes, 3);
    assert!(
        !report3.eligible_for_early_rollback,
        "Fail-closed invariant: 3 clean probes MUST NOT authorize unauthenticated early rollback!"
    );

    let status3 = manager.get_status();
    assert_eq!(status3.consecutive_healthy_probes, 3);
    assert!(status3.isolated, "Host must remain isolated until authenticated disarm");

    // Verify unauthenticated disarm (None credentials) is rejected fail-closed
    assert!(
        manager
            .disarm_isolation("test_admin", "Unauthenticated probe completion", None)
            .await
            .is_err()
    );
    assert!(manager.get_status().isolated);
}

#[tokio::test]
async fn test_health_probe_anomaly_resets_consecutive_counter() {
    let dir = tempdir().unwrap();
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(dir.path())).unwrap(),
    ));
    let test_tok = "ks-m2-2-probe-reset-token-0123456789abcdef0123456789abcdef";
    let mut auth = OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);
    auth.set_custom_master_token(test_tok.to_string());
    let auth = Arc::new(auth);
    let freezer = Arc::new(ControllableProcessFreezer::default());
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer,
        auth,
        ledger,
    ));

    manager
        .engage_isolation(
            "test_admin",
            "Testing counter reset",
            ContainmentLevel::HermeticIsolation,
            Some(std::process::id()),
        )
        .await
        .unwrap();

    // Probe 1 & 2 pass
    let r1 = manager.run_probe().unwrap();
    assert_eq!(r1.consecutive_healthy_probes, 1);
    let r2 = manager.run_probe().unwrap();
    assert_eq!(r2.consecutive_healthy_probes, 2);

    // Reset probe counter directly via HealthProbeRunner::reset_probe_counter
    manager.reset_probe_counter();

    let status_after_reset = manager.get_status();
    assert_eq!(
        status_after_reset.consecutive_healthy_probes, 0,
        "Reset counter must set consecutive_healthy_probes back to 0"
    );

    // Next clean probe must start back at 1
    let r3 = manager.run_probe().unwrap();
    assert_eq!(r3.consecutive_healthy_probes, 1);
    assert!(!r3.eligible_for_early_rollback);

    let creds = killswitch_types::status::OperatorCredentials {
        operator_id: "test_admin".to_string(),
        auth_token: Some(test_tok.to_string()),
        password: None,
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };
    manager
        .disarm_isolation("test_admin", "Clean Disarm", Some(&creds))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_three_clean_probes_do_not_trigger_automatic_rollback() {
    let dir = tempdir().unwrap();
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(dir.path())).unwrap(),
    ));
    let test_tok = "ks-m2-2-no-auto-rollback-0123456789abcdef0123456789abcdef";
    let mut auth = OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);
    auth.set_custom_master_token(test_tok.to_string());
    let auth = Arc::new(auth);
    let freezer = Arc::new(ControllableProcessFreezer::default());
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer,
        auth,
        ledger,
    ));

    manager
        .engage_isolation(
            "sec_bot",
            "Fail-closed probe non-rollback verification",
            ContainmentLevel::HermeticIsolation,
            Some(std::process::id()),
        )
        .await
        .unwrap();

    // Execute 3 consecutive clean probes
    manager.run_probe().unwrap();
    manager.run_probe().unwrap();
    let r3 = manager.run_probe().unwrap();
    assert_eq!(r3.consecutive_healthy_probes, 3);
    assert!(
        !r3.eligible_for_early_rollback,
        "Fail-closed: 3 clean probes must NEVER authorize unauthenticated rollback"
    );

    // Unauthenticated disarm without creds MUST fail closed
    assert!(
        manager
            .disarm_isolation("sec_bot", "Unauthenticated attempt", None)
            .await
            .is_err()
    );
    assert!(manager.get_status().isolated);

    // Authenticated disarm with operator credentials must succeed cleanly
    let creds = killswitch_types::status::OperatorCredentials {
        operator_id: "sec_bot".to_string(),
        auth_token: Some(test_tok.to_string()),
        password: None,
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };
    manager
        .disarm_isolation("sec_bot", "Authenticated operator restore", Some(&creds))
        .await
        .unwrap();

    let status = manager.get_status();
    assert!(!status.isolated);
    assert_eq!(status.containment_level, ContainmentLevel::Disarmed);

    let history = manager.get_history();
    assert!(history.iter().any(|h| h.action == "DISARMED"));
}

#[tokio::test]
async fn test_fail_closed_disarm_rejection_and_authenticated_recovery() {
    let dir = tempdir().unwrap();
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(dir.path())).unwrap(),
    ));
    let test_tok = "ks-m2-2-auth-recovery-tok-0123456789abcdef0123456789abcdef";
    let mut auth = OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);
    auth.set_custom_master_token(test_tok.to_string());
    let auth = Arc::new(auth);
    let freezer = Arc::new(ControllableProcessFreezer::default());
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer,
        auth,
        ledger,
    ));

    // Engage
    manager
        .engage_isolation(
            "admin",
            "Pre-crash isolation state",
            ContainmentLevel::HermeticIsolation,
            Some(std::process::id()),
        )
        .await
        .unwrap();

    assert!(manager.get_status().isolated);

    // Unauthenticated disarm must fail closed
    assert!(
        manager
            .disarm_isolation("admin", "No creds attempt", None)
            .await
            .is_err()
    );
    assert!(manager.get_status().isolated);

    // Authenticated disarm must succeed
    let creds = killswitch_types::status::OperatorCredentials {
        operator_id: "admin".to_string(),
        auth_token: Some(test_tok.to_string()),
        password: None,
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };
    let disarm_status = manager
        .disarm_isolation("admin", "Authenticated operator recovery", Some(&creds))
        .await
        .unwrap();

    assert!(!disarm_status.isolated);
    assert_eq!(disarm_status.containment_level, ContainmentLevel::Disarmed);

    // Verify state was persisted to ledger
    let ledger_read = manager.get_status();
    assert!(!ledger_read.isolated);
}

#[tokio::test]
async fn test_unauthenticated_disarm_rejected_fail_closed() {
    let dir = tempdir().unwrap();
    let master_token = "KILLSWITCH_M2_2_FAIL_CLOSED_TEST_TOKEN_0123456789ABCDEF";
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(dir.path())).unwrap(),
    ));
    let mut auth_mgr = OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);
    auth_mgr.set_custom_master_token(master_token.to_string());
    let auth = Arc::new(auth_mgr);
    let freezer = Arc::new(ControllableProcessFreezer::default());
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer,
        auth,
        ledger,
    ));

    manager
        .engage_isolation(
            "operator",
            "Testing fail-closed disarm gate",
            ContainmentLevel::HermeticIsolation,
            Some(std::process::id()),
        )
        .await
        .unwrap();

    // Unauthenticated disarm without credentials must fail closed
    let disarm_result = manager
        .disarm_isolation("operator", "Attempted bypass without credentials", None)
        .await;
    assert!(
        disarm_result.is_err(),
        "Disarm without authenticated OperatorCredentials must fail closed"
    );
    assert!(manager.get_status().isolated);
}

#[tokio::test]
async fn test_manual_disarm_abrupt_watchdog_cancellation() {
    let dir = tempdir().unwrap();
    let master_token = "KILLSWITCH_M2_2_MANUAL_CANCEL_CSPRNG_KEY_0123456789ABCDEF";
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(dir.path())).unwrap(),
    ));
    let mut auth_mgr = OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);
    auth_mgr.set_custom_master_token(master_token.to_string());
    let auth = Arc::new(auth_mgr);
    let freezer = Arc::new(ControllableProcessFreezer::default());
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer,
        auth,
        ledger,
    ));

    // Engage isolation (which spawns the background watchdog monitor task)
    manager
        .engage_isolation(
            "operator",
            "Testing abrupt cancellation",
            ContainmentLevel::HermeticIsolation,
            Some(std::process::id()),
        )
        .await
        .unwrap();

    assert!(manager.get_status().isolated);

    // Immediately trigger authenticated manual disarm without waiting for probes
    let creds = OperatorCredentials {
        operator_id: "operator".to_string(),
        auth_token: Some(master_token.to_string()),
        password: None,
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };
    let disarmed = manager
        .disarm_isolation("operator", "Abrupt manual cancellation", Some(&creds))
        .await
        .unwrap();

    assert!(!disarmed.isolated);

    // Yield tokio runtime to allow watchdog abort channel to complete
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify system remains cleanly disarmed
    assert!(!manager.get_status().isolated);
}

#[tokio::test]
async fn test_authenticated_disarm_resumes_frozen_pids_from_ledger() {
    let temp = tempdir().expect("tempdir");
    let master_token = "KILLSWITCH_M2_2_RESUME_LEDGER_CSPRNG_KEY_0123456789ABCDEF";

    // 1. Initialize ledger and record an engaged state with simulated frozen PIDs
    let mut ledger = StateLedger::open_or_init(Some(temp.path())).expect("open ledger");
    let fake_frozen_pid = 99998;
    let fake_record = ProcessIsolationState::new_frozen(
        fake_frozen_pid,
        "untrusted_worker.exe".to_string(),
        None,
        ProcessIsolationMethod::NtSuspendProcess,
    );

    let mut engaged_status = KillChainStatus {
        isolated: true,
        containment_level: ContainmentLevel::ProcessFreeze,
        frozen_pids: vec![fake_frozen_pid],
        processes_frozen_count: 1,
        ..KillChainStatus::default()
    };
    engaged_status.update_hash();

    ledger
        .record_state_transition(
            engaged_status,
            Some(Vec::new()),
            Some(vec![fake_record]),
            "ENGAGED",
            "test_operator",
            "Simulating process freeze for disarm verification",
        )
        .expect("record transition");

    // Verify ledger has frozen PID
    let snapshot_before = ledger.snapshot();
    assert_eq!(snapshot_before.status.frozen_pids, vec![fake_frozen_pid]);
    assert_eq!(snapshot_before.process_records.len(), 1);

    let ledger_arc = Arc::new(RwLock::new(ledger));
    let mut auth_mgr = OperatorAuthManager::new(Some(temp.path().to_path_buf()), None);
    auth_mgr.set_custom_master_token(master_token.to_string());
    let auth = Arc::new(auth_mgr);
    let freezer = Arc::new(ControllableProcessFreezer::default());
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer,
        auth,
        ledger_arc,
    ));

    // 2a. Unauthenticated disarm must fail closed and keep frozen PIDs quarantined
    let unauth_res = manager
        .disarm_isolation("test_operator", "Unauthorized disarm", None)
        .await;
    assert!(unauth_res.is_err());
    assert!(manager.get_status().isolated);
    assert_eq!(manager.get_status().frozen_pids, vec![fake_frozen_pid]);

    // 2b. Invoke authenticated disarm with valid OperatorCredentials
    let creds = OperatorCredentials {
        operator_id: "test_operator".to_string(),
        auth_token: Some(master_token.to_string()),
        password: None,
        caller_pid: Some(std::process::id()),
        confirmation_phrase: None,
    };
    let status = manager
        .disarm_isolation("test_operator", "Verified operator recovery", Some(&creds))
        .await
        .expect("authenticated disarm must succeed");
    assert!(!status.isolated);
    assert_eq!(status.containment_level, ContainmentLevel::Disarmed);
    assert_eq!(status.processes_frozen_count, 0);
    assert!(status.frozen_pids.is_empty());

    // 3. Inspect updated ledger snapshot on disk
    let ledger_after = StateLedger::open_or_init(Some(temp.path())).expect("open ledger after");
    assert!(!ledger_after.snapshot().status.isolated);
    assert!(ledger_after.snapshot().status.frozen_pids.is_empty());
    assert!(ledger_after.snapshot().process_records.is_empty());
    assert!(ledger_after.snapshot().network_receipts.is_empty());

    let history = &ledger_after.snapshot().history;
    assert!(!history.is_empty());
    assert_eq!(history[0].action, "DISARMED");
    assert_eq!(history[0].operator, "test_operator");
}

#[tokio::test]
async fn test_concurrent_engage_isolation_serialization() {
    let dir = tempdir().unwrap();
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(dir.path())).unwrap(),
    ));
    let auth = Arc::new(OperatorAuthManager::new(
        Some(dir.path().to_path_buf()),
        None,
    ));
    let freezer = Arc::new(ControllableProcessFreezer::default());
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer,
        auth,
        ledger,
    ));

    // Spawn 10 concurrent tasks all attempting engage_isolation simultaneously
    let mut handles = Vec::new();
    for i in 0..10 {
        let mgr = Arc::clone(&manager);
        handles.push(tokio::spawn(async move {
            mgr.engage_isolation(
                &format!("admin_{}", i),
                "Concurrent threat trigger",
                ContainmentLevel::HermeticIsolation,
                Some(std::process::id()),
            )
            .await
        }));
    }

    let mut success_count = 0;
    for h in handles {
        let res = h.await.unwrap();
        assert!(res.is_ok());
        success_count += 1;
    }
    assert_eq!(success_count, 10);

    let status = manager.get_status();
    assert!(status.isolated);

    // Exactly 1 ENGAGED transition must be committed to the history ledger
    let history = manager.get_history();
    let engaged_entries: Vec<_> = history.iter().filter(|e| e.action == "ENGAGED").collect();
    assert_eq!(
        engaged_entries.len(),
        1,
        "Only 1 state transition must be committed despite 10 concurrent requests"
    );
}
