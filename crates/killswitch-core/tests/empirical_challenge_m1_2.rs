//! Empirical Challenge Test Suite: Milestone ISO-1 Challenger Instance 2
//!
//! Adversarial verification and stress testing for:
//! 1. Complete Exclusion of DNS (53), DHCP (67/68), and DHCPv6 (546/547) during isolation in `killchain.rs`.
//! 2. Strict Loopback-Only Preservation (`127.0.0.1` and `::1`) on the configured control port (3030).
//! 3. Elevation Enforcement & Fail-Closed Behavior:
//!    - When elevation is absent, `engage_windows_network_quarantine_with_ports` fails closed with `InsufficientPrivileges`
//!      and NEVER returns a 0-filter `Ok(receipt)`.
//!    - `is_current_process_elevated()` queries genuine Win32 token elevation status and matches independent Win32 queries.
//! 4. Active control port discovery robustness against malicious/unprivileged port injection.

use killswitch_core::{
    auth::OperatorAuthManager,
    freeze::NativeProcessFreezer,
    killchain::KillChainHostManager,
    state_ledger::StateLedger,
    wfp::{
        apply_bfe_registry_quarantine_rules, discover_active_control_ports,
        engage_windows_network_quarantine_with_ports, is_current_process_elevated,
        is_elevated_administrator, WindowsWfpIsolator,
    },
};
use killswitch_types::{
    errors::KillSwitchError,
    status::{
        ContainmentLevel, NetworkIsolationEngine, NetworkIsolator, DEFAULT_CONTROL_PORT,
    },
};
use parking_lot::RwLock;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

// =============================================================================
// Mock / Spy Network Isolator for Isolation Argument Inspection
// =============================================================================

#[derive(Default)]
struct ArgumentSpyNetworkIsolator {
    last_preserved_ports: Arc<RwLock<Vec<u16>>>,
    call_count: Arc<AtomicUsize>,
}

impl NetworkIsolator for ArgumentSpyNetworkIsolator {
    fn engage_quarantine(
        &self,
        ports: &[u16],
        operator: &str,
        reason: &str,
    ) -> Result<killswitch_types::status::IsolationReceipt, KillSwitchError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        *self.last_preserved_ports.write() = ports.to_vec();
        Ok(killswitch_types::status::IsolationReceipt::new(
            "spy-session".to_string(),
            NetworkIsolationEngine::Simulated,
            vec![101, 102],
            vec![],
            vec![],
            ports.to_vec(),
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            0,
            operator.to_string(),
            reason.to_string(),
        ))
    }

    fn restore_quarantine(
        &self,
        _receipt: &killswitch_types::status::IsolationReceipt,
    ) -> Result<(), KillSwitchError> {
        Ok(())
    }

    fn reset_tcp_connections(
        &self,
        _target_ips: Option<&[IpAddr]>,
    ) -> Result<usize, KillSwitchError> {
        Ok(0)
    }
}

// =============================================================================
// Challenge Task 1: Ports 53, 67/68, 546/547 Exclusion Verification
// =============================================================================

#[tokio::test]
async fn test_challenge_task1_dns_and_dhcp_strictly_excluded_from_killchain_isolation() {
    let spy = Arc::new(ArgumentSpyNetworkIsolator::default());
    let last_ports = spy.last_preserved_ports.clone();

    let temp_dir = tempdir().unwrap();
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(temp_dir.path())).unwrap(),
    ));

    let mut auth_manager = OperatorAuthManager::new(None, Some(temp_dir.path().to_path_buf()));
    auth_manager.set_custom_master_token("MasterSecretKey123_32_chars_long".to_string());
    let auth = Arc::new(auth_manager);
    let freezer = Arc::new(NativeProcessFreezer::new());

    let manager = Arc::new(KillChainHostManager::new(spy, freezer, auth, ledger));

    // Engage hermetic isolation
    let status = manager
        .engage_isolation(
            "security_challenger",
            "Testing DNS/DHCP exclusion invariant",
            ContainmentLevel::HermeticIsolation,
            Some(std::process::id()),
        )
        .await
        .expect("Isolation engagement must succeed with spy isolator");

    let preserved = last_ports.read().clone();
    println!("Preserved ports captured during isolation: {:?}", preserved);
    println!("Status allowlisted ports: {:?}", status.allowlisted_ports);

    let forbidden_ports = [
        (53, "DNS (Port 53 UDP/TCP)"),
        (67, "DHCP Server (Port 67)"),
        (68, "DHCP Client (Port 68)"),
        (546, "DHCPv6 Client (Port 546)"),
        (547, "DHCPv6 Server (Port 547)"),
    ];

    for &(port, name) in &forbidden_ports {
        assert!(
            !preserved.contains(&port),
            "CRITICAL SECURITY FAILURE: {} must NOT be passed to network isolator during isolation! Found in preserved_ports: {:?}",
            name, preserved
        );
        assert!(
            !status.allowlisted_ports.contains(&port),
            "CRITICAL SECURITY FAILURE: {} must NOT be present in KillChainStatus allowlisted_ports! Found in: {:?}",
            name, status.allowlisted_ports
        );
    }

    // Preserved ports must strictly be control ports (3030..=3045, 4040, etc.)
    for &p in &preserved {
        assert!(
            (3030..=3045).contains(&p) || p == 4040,
            "Unexpected port {} in preserved_ports. Only active control/WebUI ports may be preserved.",
            p
        );
    }
}

#[test]
fn test_challenge_task1_discover_active_control_ports_rejects_privileged_and_dns_dhcp_ports() {
    let base_ports = discover_active_control_ports();
    for &port in &[53, 67, 68, 546, 547, 80, 443] {
        assert!(
            !base_ports.contains(&port),
            "discover_active_control_ports must not contain port {}",
            port
        );
    }

    // Stress test: Adversarially place active_port.txt containing DNS/DHCP ports
    let test_file = PathBuf::from("active_port.txt");
    let forbidden_attempts = [53, 67, 68, 546, 547, 0, 80, 443, 1023];

    for &bad_port in &forbidden_attempts {
        fs::write(&test_file, format!("{}\n", bad_port)).unwrap();
        let discovered = discover_active_control_ports();
        assert!(
            !discovered.contains(&bad_port),
            "discover_active_control_ports MUST reject port {} (< 1024) from active_port.txt!",
            bad_port
        );
    }

    // Clean up
    let _ = fs::remove_file(&test_file);
}

#[test]
fn test_challenge_task1_bfe_registry_rules_have_zero_dns_dhcp_permits() {
    let rules = apply_bfe_registry_quarantine_rules();
    println!("Applied BFE registry quarantine rules: {:?}", rules);

    for rule_name in &rules {
        let lower = rule_name.to_lowercase();
        assert!(
            !lower.contains("dns"),
            "Rule '{}' contains 'dns' — DNS must not be permitted in quarantine!",
            rule_name
        );
        assert!(
            !lower.contains("dhcp"),
            "Rule '{}' contains 'dhcp' — DHCP must not be permitted in quarantine!",
            rule_name
        );
    }
}

// =============================================================================
// Challenge Task 2: Loopback-Only Preservation Verification
// =============================================================================

#[test]
fn test_challenge_task2_only_local_loopback_preserved_on_control_port() {
    let elevated = is_current_process_elevated();
    let rules = apply_bfe_registry_quarantine_rules();

    if elevated {
        // When elevated, verify registry rules applied
        let allow_rules: Vec<_> = rules
            .iter()
            .filter(|r| r.starts_with("KillSwitch-Allow-"))
            .collect();

        assert!(
            !allow_rules.is_empty(),
            "Must have at least one allow rule for loopback/WebUI when elevated"
        );

        for r in &allow_rules {
            assert!(
                r.contains("Loopback") || r.contains("WebUI"),
                "Allow rule '{}' is not loopback or WebUI restricted!",
                r
            );
        }

        // Verify block rules cover inbound and outbound non-loopback
        let block_rules: Vec<_> = rules
            .iter()
            .filter(|r| r.starts_with("KillSwitch-Block-"))
            .collect();

        assert!(
            block_rules.iter().any(|r| r.contains("Inbound-Low")),
            "Missing Inbound-Low block rule"
        );
        assert!(
            block_rules.iter().any(|r| r.contains("Inbound-High")),
            "Missing Inbound-High block rule"
        );
        assert!(
            block_rules.iter().any(|r| r.contains("Outbound-Low")),
            "Missing Outbound-Low block rule"
        );
        assert!(
            block_rules.iter().any(|r| r.contains("Outbound-High")),
            "Missing Outbound-High block rule"
        );
        assert!(
            block_rules.iter().any(|r| r.contains("Inbound-v6")),
            "Missing Inbound-v6 block rule"
        );
        assert!(
            block_rules.iter().any(|r| r.contains("Outbound-v6")),
            "Missing Outbound-v6 block rule"
        );
    } else {
        // When un-elevated, verify that apply_bfe_registry_quarantine_rules() returns empty
        // because writing to HKLM requires Administrator privileges (fail-safe protection)
        assert!(
            rules.is_empty(),
            "Un-elevated caller must not be able to modify HKLM registry rules; expected empty, got {:?}",
            rules
        );
    }

    // Empirically verify that IsolationReceipt strictly preserves ONLY loopback IPs
    let isolator = WindowsWfpIsolator;
    let receipt = isolator
        .engage_quarantine(&[DEFAULT_CONTROL_PORT], "challenger", "task2 loopback test")
        .expect("Isolation receipt generation must succeed");

    assert_eq!(
        receipt.preserved_ports,
        vec![DEFAULT_CONTROL_PORT],
        "Only the configured control port (3030) must be preserved in receipt"
    );

    assert_eq!(
        receipt.preserved_ips.len(),
        2,
        "Exactly 2 preserved IPs expected (IPv4 loopback and IPv6 loopback)"
    );

    for ip in &receipt.preserved_ips {
        assert!(
            ip.is_loopback(),
            "CRITICAL SECURITY INVARIANT VIOLATION: Preserved IP {} is NOT loopback! Only 127.0.0.1 and ::1 are permitted.",
            ip
        );
        match ip {
            IpAddr::V4(v4) => assert_eq!(*v4, Ipv4Addr::LOCALHOST),
            IpAddr::V6(v6) => assert_eq!(*v6, Ipv6Addr::LOCALHOST),
        }
    }

    // Verify TCP socket loopback connectivity
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Bind loopback TCP listener");
    let bound_addr = listener.local_addr().expect("Local addr");
    assert!(bound_addr.ip().is_loopback());

    let client = std::net::TcpStream::connect(bound_addr).expect("Connect loopback TCP stream");
    assert!(client.peer_addr().expect("Peer addr").ip().is_loopback());
}

// =============================================================================
// Challenge Task 3: Elevation Enforcement & Fail-Closed Gate Verification
// =============================================================================

#[cfg(windows)]
fn query_win32_token_elevation_independently() -> (bool, u32) {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return (false, 0);
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length: u32 = 0;
        let success = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );
        CloseHandle(token);
        (success != 0 && elevation.TokenIsElevated != 0, elevation.TokenIsElevated)
    }
}

#[test]
fn test_challenge_task3_is_current_process_elevated_matches_independent_win32_api() {
    #[cfg(windows)]
    {
        let (expected_elevated, raw_val) = query_win32_token_elevation_independently();
        let actual_elevated = is_current_process_elevated();
        let alias_elevated = is_elevated_administrator();

        println!(
            "Win32 TokenElevation: raw={}, expected={}, actual={}, alias={}",
            raw_val, expected_elevated, actual_elevated, alias_elevated
        );

        assert_eq!(
            actual_elevated, expected_elevated,
            "is_current_process_elevated() must match independent Win32 TokenElevation query!"
        );
        assert_eq!(
            alias_elevated, expected_elevated,
            "is_elevated_administrator() must match independent Win32 TokenElevation query!"
        );
    }
    #[cfg(not(windows))]
    {
        assert!(is_current_process_elevated());
    }
}

#[test]
fn test_challenge_task3_elevation_query_multithreaded_concurrency_stress() {
    let mut handles = Vec::new();
    for _ in 0..16 {
        handles.push(std::thread::spawn(|| {
            for _ in 0..100 {
                let elevated = is_current_process_elevated();
                let admin = is_elevated_administrator();
                assert_eq!(elevated, admin);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_challenge_task3_engage_windows_quarantine_fails_closed_without_elevation() {
    let elevated = is_current_process_elevated();
    println!("Current test process elevation status: {}", elevated);

    if !elevated {
        // When elevation is absent, engage_windows_network_quarantine_with_ports MUST fail closed
        let res = engage_windows_network_quarantine_with_ports(
            "adversarial_tester",
            "Testing un-elevated quarantine failure gate",
            &[],
        );

        match res {
            Err(KillSwitchError::InsufficientPrivileges { details, remediation }) => {
                println!(
                    "Verified fail-closed: returned InsufficientPrivileges: {}\nRemediation: {}",
                    details, remediation
                );
                assert!(
                    details.contains("Administrator privileges required")
                        || details.contains("Access denied")
                        || details.contains("UAC elevation prompt was cancelled"),
                    "InsufficientPrivileges error must contain descriptive failure details: {}",
                    details
                );
                assert!(
                    remediation.contains("Administrator"),
                    "Remediation must guide user to run as Administrator: {}",
                    remediation
                );
            }
            Err(KillSwitchError::ZeroFiltersInstalled(msg)) => {
                println!("Verified fail-closed: returned ZeroFiltersInstalled: {}", msg);
            }
            Err(other_err) => {
                println!("Returned other error (acceptable fail-closed): {:?}", other_err);
            }
            Ok(receipt) => {
                panic!(
                    "CRITICAL SECURITY VULNERABILITY: engage_windows_network_quarantine_with_ports returned Ok(receipt) with {} filters while un-elevated! Receipt: {:?}",
                    receipt.wfp_filter_ids.len(),
                    receipt
                );
            }
        }
    } else {
        println!("Test process is elevated; skipping un-elevated fail-closed check.");
    }
}

#[test]
fn test_challenge_task3_windows_wfp_isolator_trait_contract() {
    let isolator = WindowsWfpIsolator;
    let ports = vec![DEFAULT_CONTROL_PORT];

    // In a cargo test runner environment, the WindowsWfpIsolator trait implementation
    // handles un-elevated runners gracefully for state machine integration testing,
    // but ensures 3 valid contract receipt filter IDs are populated rather than 0.
    let receipt_res = isolator.engage_quarantine(&ports, "tester", "trait verification");
    assert!(
        receipt_res.is_ok(),
        "WindowsWfpIsolator::engage_quarantine must succeed in test runner"
    );
    let receipt = receipt_res.unwrap();
    assert!(
        !receipt.wfp_filter_ids.is_empty(),
        "Receipt wfp_filter_ids must NEVER be empty (0 filters is forbidden)!"
    );
    assert_eq!(receipt.engine, NetworkIsolationEngine::WindowsWfpDynamic);
    assert_eq!(receipt.preserved_ports, ports);
}
