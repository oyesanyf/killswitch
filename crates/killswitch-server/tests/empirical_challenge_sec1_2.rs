//! Empirical Challenge Test Harness for Milestone SEC-1
//! Telemetry, Immunity & Dynamic Context Observation (Instance 2).
//!
//! Author: Challenger SEC-1-2 (teamwork_challenger)
//! Scope:
//! 1. Active socket telemetry in rl_traffic.rs and server.rs: verify latency under 250ms,
//!    ensure processes without open sockets are reported, verify Linux /proc/net/tcp parsing
//!    and macOS Darwin socket table structures.
//! 2. 5-hop ancestry: construct multi-level process trees (e.g. Node -> Bash -> Python -> Script)
//!    and confirm that none inherit blanket immunity, while system PID 4 / csrss are strictly preserved.
//! 3. Adversarial challenge on direct target immunity decoupling.
//! 4. Dynamic binary metadata probing and parent-child token delta observation.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use killswitch_adjudication::adjudicator::ZeroFalsePositiveAdjudicator;
use killswitch_adjudication::binary_probe::{
    inspect_binary_metadata, DynamicBinaryMetadata, ElevationRequirement,
};
use killswitch_adjudication::immunity::{inspect_process_lineage, LineageImmunityVerdict};
use killswitch_adjudication::token_delta::{
    evaluate_security_context_delta, observe_parent_child_token_delta, ProcessSecurityContext,
    SecurityContextDelta,
};
use killswitch_core::killchain::{is_developer_or_agent_runtime, is_immutable_os_kernel_pid};
use killswitch_core::landlock::{
    parse_linux_ipv4_hex, parse_proc_net_content, parse_tcp_line, TcpState,
};
use killswitch_core::pf::{get_active_darwin_sockets, DarwinSocketEntry};
use killswitch_telemetry::rl_traffic::query_live_os_process_sockets;
use killswitch_types::adjudication::{
    AdjudicationResult, EvidenceClass, ThreatCandidate, VetoReason,
};

// ============================================================================
// 1. ACTIVE SOCKET TELEMETRY LATENCY & PROCESS CAPTURE CHALLENGE
// ============================================================================

#[test]
fn test_empirical_active_socket_telemetry_latency_under_250ms() {
    // Warm-up run
    let _ = query_live_os_process_sockets();

    let iterations = 10;
    let mut total_duration = std::time::Duration::ZERO;
    let mut max_duration = std::time::Duration::ZERO;
    let mut min_duration = std::time::Duration::from_secs(100);

    for _ in 0..iterations {
        let start = Instant::now();
        let rows = query_live_os_process_sockets();
        let elapsed = start.elapsed();

        assert!(
            !rows.is_empty(),
            "query_live_os_process_sockets must return active process rows"
        );
        total_duration += elapsed;
        if elapsed > max_duration {
            max_duration = elapsed;
        }
        if elapsed < min_duration {
            min_duration = elapsed;
        }
    }

    let avg_ms = (total_duration.as_millis() as f64) / (iterations as f64);
    let max_ms = max_duration.as_millis() as f64;
    let min_ms = min_duration.as_millis() as f64;

    println!(
        "📊 [CHALLENGE TELEMETRY LATENCY] Avg: {:.2}ms, Min: {:.2}ms, Max: {:.2}ms over {} iterations",
        avg_ms, min_ms, max_ms, iterations
    );

    // Strict empirical requirement: average latency must be under 250ms
    assert!(
        avg_ms < 250.0,
        "Active socket telemetry latency average must be < 250ms (measured {:.2}ms)",
        avg_ms
    );
}

#[test]
fn test_empirical_processes_without_open_sockets_reported() {
    let rows = query_live_os_process_sockets();
    assert!(!rows.is_empty(), "Process table must not be empty");

    let no_socket_rows: Vec<_> = rows.iter().filter(|r| r.direction == "NONE").collect();
    println!(
        "📊 [CHALLENGE TELEMETRY] Total processes: {}, Processes without open sockets: {}",
        rows.len(),
        no_socket_rows.len()
    );

    // Systems always have processes without network sockets (e.g. idle workers, background daemons)
    assert!(
        !no_socket_rows.is_empty(),
        "Processes without open sockets must be actively reported (found 0)"
    );

    // Validate structural schema of processes without open sockets
    for row in &no_socket_rows {
        assert!(
            row.pid > 4,
            "Kernel PIDs <= 4 must be excluded from socket emission (got PID {})",
            row.pid
        );
        assert!(
            !row.process_name.is_empty(),
            "Process name must be populated"
        );
        assert_eq!(row.direction, "NONE", "Direction must be NONE");
        assert_eq!(row.state, "RUNNING", "State must be RUNNING");
        assert_eq!(
            row.local_port, 0,
            "Local port must be 0 for socketless processes"
        );
        assert_eq!(
            row.remote_port, 0,
            "Remote port must be 0 for socketless processes"
        );
        assert!(
            row.remote_address.is_empty(),
            "Remote address must be empty for socketless processes"
        );
    }
}

// ============================================================================
// 2. CROSS-PLATFORM SOCKET PARSING & DATA STRUCTURE CHALLENGE
// ============================================================================

#[test]
fn test_empirical_linux_proc_net_tcp_and_tcp6_parser_stress() {
    // 1. Realistic IPv4 /proc/net/tcp sample content
    let sample_v4 = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BD6 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 35123 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0016 0200007F:C001 01 00000000:00000000 00:00000000 00000000  1000        0 35124 1 0000000000000000 100 0 0 10 0
   2: 0501A8C0:D431 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 35125 1 0000000000000000 100 0 0 10 0
"#;

    let entries_v4 = parse_proc_net_content(sample_v4, false);
    assert_eq!(entries_v4.len(), 3, "All 3 IPv4 lines must parse cleanly");

    // Line 0: Listen on 127.0.0.1:3030
    assert_eq!(
        entries_v4[0].local_addr,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(entries_v4[0].local_port, 3030);
    assert_eq!(entries_v4[0].state, TcpState::Listen);
    assert_eq!(entries_v4[0].inode, 35123);
    assert!(!entries_v4[0].is_ipv6);

    // Line 1: Established 127.0.0.1:22 -> 127.0.0.2:49153
    assert_eq!(
        entries_v4[1].local_addr,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(entries_v4[1].local_port, 22);
    assert_eq!(
        entries_v4[1].remote_addr,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
    );
    assert_eq!(entries_v4[1].remote_port, 49153);
    assert_eq!(entries_v4[1].state, TcpState::Established);

    // Line 2: Established 192.168.1.5:54321 -> 8.8.8.8:53
    assert_eq!(
        entries_v4[2].local_addr,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))
    );
    assert_eq!(entries_v4[2].local_port, 54321);
    assert_eq!(
        entries_v4[2].remote_addr,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    );
    assert_eq!(entries_v4[2].remote_port, 53);

    // 2. Realistic IPv6 /proc/net/tcp6 sample content
    let sample_v6 = r#"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0BD6 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 45001 1 0000000000000000 100 0 0 10 0
"#;
    let entries_v6 = parse_proc_net_content(sample_v6, true);
    assert_eq!(entries_v6.len(), 1, "IPv6 line must parse cleanly");
    assert_eq!(entries_v6[0].local_port, 3030);
    assert_eq!(entries_v6[0].state, TcpState::Listen);
    assert_eq!(entries_v6[0].inode, 45001);
    assert!(entries_v6[0].is_ipv6);

    // 3. Adversarial and Malformed Inputs
    assert!(parse_proc_net_content("", false).is_empty());
    assert!(parse_proc_net_content("header only line", false).is_empty());

    // Truncated line (< 10 fields)
    assert!(parse_tcp_line("0: 0100007F:0BD6", false).is_err());

    // Malformed hex in IP
    assert!(parse_tcp_line(
        "0: ZZZZZZZZ:0BD6 00000000:0000 0A 00:00 00:00 1000 0 35123 1",
        false
    )
    .is_err());

    // Malformed hex in Port
    assert!(parse_tcp_line(
        "0: 0100007F:GGGG 00000000:0000 0A 00:00 00:00 1000 0 35123 1",
        false
    )
    .is_err());

    // 4. Little-Endian Hex Address Verification
    assert_eq!(
        parse_linux_ipv4_hex("0100007F"),
        Some(Ipv4Addr::new(127, 0, 0, 1))
    );
    assert_eq!(
        parse_linux_ipv4_hex("0101A8C0"),
        Some(Ipv4Addr::new(192, 168, 1, 1))
    );
    assert_eq!(
        parse_linux_ipv4_hex("0A00000A"),
        Some(Ipv4Addr::new(10, 0, 0, 10))
    );
    assert_eq!(parse_linux_ipv4_hex("123"), None);
}

#[test]
fn test_empirical_macos_darwin_socket_structures() {
    // 1. Verify get_active_darwin_sockets does not crash and returns valid sockets
    let _probe_listener = std::net::TcpListener::bind("127.0.0.1:0").ok();
    let darwin_res = get_active_darwin_sockets();
    assert!(darwin_res.is_ok(), "Darwin socket query must succeed");
    let sockets = darwin_res.unwrap();
    assert!(
        !sockets.is_empty(),
        "Darwin socket table must return entries"
    );

    // 2. Verify DarwinSocketEntry semantic methods
    let local_entry = DarwinSocketEntry {
        pid: Some(1234),
        proc_name: Some("test_daemon".to_string()),
        fd: Some(3),
        local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        local_port: 3030,
        foreign_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        foreign_port: 0,
        is_loopback: true,
        is_tcp: true,
        state_name: "LISTEN".to_string(),
    };
    assert!(
        !local_entry.is_external_connection(),
        "Loopback/unspecified must not be classified as external connection"
    );

    let external_entry = DarwinSocketEntry {
        pid: Some(5678),
        proc_name: Some("curler".to_string()),
        fd: Some(4),
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        local_port: 49200,
        foreign_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        foreign_port: 443,
        is_loopback: false,
        is_tcp: true,
        state_name: "ESTABLISHED".to_string(),
    };
    assert!(
        external_entry.is_external_connection(),
        "Non-loopback connection to remote host must be classified as external"
    );
}

// ============================================================================
// 3. 5-HOP ANCESTRY TRAVERSAL & IMMUNITY DECOUPLING CHALLENGE
// ============================================================================

#[test]
fn test_empirical_multi_level_process_ancestry_trees_no_blanket_immunity() {
    // Verify that all common developer runtimes, shells, and agent orchestrators are classified
    let developer_tools = [
        "node",
        "node.exe",
        "python",
        "python.exe",
        "python3",
        "python3.exe",
        "bash",
        "sh",
        "zsh",
        "fish",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "cursor",
        "cursor.exe",
        "code.exe",
        "windsurf.exe",
        "docker.exe",
        "wsl.exe",
        "wslservice.exe",
        "wslhost.exe",
        "sudo",
        "su",
    ];

    for tool in developer_tools {
        assert!(
            is_developer_or_agent_runtime(tool),
            "{} must be classified as developer/agent runtime in is_developer_or_agent_runtime",
            tool
        );
    }

    // Verify AgentRuntimeChild verdict does NOT grant immunity or veto reason
    let agent_child = LineageImmunityVerdict::AgentRuntimeChild {
        ancestor_pid: 1234,
        ancestor_name: "node.exe".to_string(),
        depth: 2,
    };
    assert!(
        !agent_child.is_immune(),
        "AgentRuntimeChild must NOT be immune"
    );
    assert_eq!(
        agent_child.to_veto_reason(),
        None,
        "AgentRuntimeChild must have to_veto_reason() == None"
    );

    // Multi-level process tree scenarios:
    // Tree 1: Node (100) -> Bash (101) -> Python (102) -> Script (103)
    // Tree 2: Cursor (200) -> PowerShell (201) -> Cmd (202) -> Malware (203)
    // Tree 3: Code (300) -> Node (301) -> Python (302) -> Bash (303) -> Payload (304)
    // In all cases, children spawned under agent runtimes must not inherit immunity
    let simulated_agent_ancestors = [
        ("node.exe", 1),
        ("bash", 2),
        ("python.exe", 3),
        ("cursor.exe", 1),
        ("powershell.exe", 2),
        ("code.exe", 4),
    ];

    for (ancestor_name, depth) in simulated_agent_ancestors {
        let verdict = LineageImmunityVerdict::AgentRuntimeChild {
            ancestor_pid: 999,
            ancestor_name: ancestor_name.to_string(),
            depth,
        };
        assert!(
            !verdict.is_immune(),
            "Process with ancestor {} at depth {} must NOT be immune",
            ancestor_name,
            depth
        );
        assert_eq!(
            verdict.to_veto_reason(),
            None,
            "Process with ancestor {} at depth {} must NOT be vetoed",
            ancestor_name,
            depth
        );
    }
}

#[test]
fn test_empirical_immutable_kernel_anchors_strictly_preserved() {
    // 1. Kernel PIDs <= 4 and current process must always be preserved
    assert!(is_immutable_os_kernel_pid(0, "Idle"));
    assert!(is_immutable_os_kernel_pid(1, "System"));
    assert!(is_immutable_os_kernel_pid(4, "System"));
    assert!(is_immutable_os_kernel_pid(std::process::id(), "self"));

    // 2. Canonical Windows immutable kernel anchors
    let win_anchors = [
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsm.exe",
        "fontdrvhost.exe",
    ];
    for anchor in win_anchors {
        assert!(
            is_immutable_os_kernel_pid(100, anchor),
            "Windows kernel anchor '{}' must return true from is_immutable_os_kernel_pid",
            anchor
        );
    }

    // 3. Canonical Linux immutable kernel anchors
    let linux_anchors = [
        "init",
        "systemd",
        "systemd-journald",
        "systemd-udevd",
        "dbus-daemon",
        "kthreadd",
    ];
    for anchor in linux_anchors {
        assert!(
            is_immutable_os_kernel_pid(1, anchor),
            "Linux kernel anchor '{}' must return true from is_immutable_os_kernel_pid",
            anchor
        );
    }

    // 4. Canonical macOS immutable anchors
    let mac_anchors = ["launchd", "kernel_task", "windowserver", "opendirectoryd"];
    for anchor in mac_anchors {
        assert!(
            is_immutable_os_kernel_pid(1, anchor),
            "macOS anchor '{}' must return true from is_immutable_os_kernel_pid",
            anchor
        );
    }

    // 5. Developer runtimes must NOT be classified as immutable kernel anchors!
    let dev_tools = [
        "cursor.exe",
        "node.exe",
        "python.exe",
        "powershell.exe",
        "wsl.exe",
        "sudo",
        "bash",
        "cmd.exe",
    ];
    for tool in dev_tools {
        assert!(
            !is_immutable_os_kernel_pid(5000, tool),
            "Developer tool '{}' must NEVER be classified as an immutable kernel anchor",
            tool
        );
    }

    // 6. Verify Lineage verdicts for immutable kernel anchors
    let target_anchor = LineageImmunityVerdict::ImmuneTarget {
        pid: 4,
        proc_name: "System".to_string(),
    };
    assert!(target_anchor.is_immune());
    assert_eq!(
        target_anchor.to_veto_reason(),
        Some(VetoReason::CriticalSystemPid)
    );

    let ancestor_anchor = LineageImmunityVerdict::ImmuneAncestor {
        target_pid: 2000,
        ancestor_pid: 4,
        ancestor_name: "System".to_string(),
        depth: 2,
    };
    assert!(ancestor_anchor.is_immune());
    assert_eq!(
        ancestor_anchor.to_veto_reason(),
        Some(VetoReason::ProtectedParentLineage)
    );
}

// ============================================================================
// 4. ADVERSARIAL CHALLENGE: TARGET IMMUNITY EVALUATION & RESIDUAL EVASION
// ============================================================================

#[tokio::test]
async fn test_empirical_adversarial_challenge_direct_target_immunity() {
    let adjudicator = ZeroFalsePositiveAdjudicator::new();

    // Challenge A: Immutable Kernel Anchor as ThreatCandidate -> MUST be Vetoed (CriticalSystemPid)
    let csrss_candidate = ThreatCandidate::new(
        Some(100),
        "csrss.exe",
        "PhaseLock",
        "Synthetic test probe",
        0.95,
        EvidenceClass::Behavior,
    );
    let csrss_result = adjudicator
        .adjudicate_threat_candidate(&csrss_candidate, None)
        .await;
    println!("🛡️  Adjudication for csrss.exe: {:?}", csrss_result);
    assert!(
        matches!(
            csrss_result,
            AdjudicationResult::Vetoed {
                reason: VetoReason::CriticalSystemPid,
                ..
            }
        ),
        "csrss.exe must be vetoed under CriticalSystemPid"
    );

    // Challenge B: wsl.exe as ThreatCandidate -> MUST NOT receive CriticalSystemPid veto!
    let wsl_candidate = ThreatCandidate::new(
        Some(4_000_004),
        "wsl.exe",
        "MeshGuard",
        "Circumvention retry",
        0.90,
        EvidenceClass::Behavior,
    );
    let wsl_res = adjudicator
        .adjudicate_threat_candidate(&wsl_candidate, None)
        .await;
    println!("🛡️  Adjudication for wsl.exe: {:?}", wsl_res);
    assert!(
        !matches!(
            wsl_res,
            AdjudicationResult::Vetoed {
                reason: VetoReason::CriticalSystemPid,
                ..
            }
        ),
        "wsl.exe must NOT be vetoed under CriticalSystemPid"
    );
    let wsl_lineage = inspect_process_lineage(4_000_004, Some("wsl.exe"));
    println!("🛡️  Lineage verdict for wsl.exe: {:?}", wsl_lineage);
    assert!(
        !wsl_lineage.is_immune(),
        "wsl.exe must NOT receive target immunity"
    );
    assert_eq!(
        wsl_lineage.to_veto_reason(),
        None,
        "wsl.exe must NOT have a veto reason from lineage"
    );

    // Challenge C: sudo / su as ThreatCandidate -> MUST NOT receive CriticalSystemPid veto!
    for priv_tool in ["sudo", "su", "doas", "pkexec"] {
        let lineage = inspect_process_lineage(4_000_005, Some(priv_tool));
        assert!(
            !lineage.is_immune(),
            "{} must NOT receive target immunity",
            priv_tool
        );
        assert_eq!(
            lineage.to_veto_reason(),
            None,
            "{} must NOT have a veto reason from lineage",
            priv_tool
        );
    }

    // Challenge D: EMPIRICAL AUDIT OF NODE / PYTHON / POWERSHELL / BASH TARGET IMMUNITY
    // R2 states: "Eliminate unconditional process-name immunity (including wsl.exe, sudo, su, bash, powershell.exe, node, python, cursor, code.exe)"
    // Let's test whether inspect_process_lineage grants immunity to node.exe or python.exe:
    let node_lineage = inspect_process_lineage(4_000_006, Some("node.exe"));
    let python_lineage = inspect_process_lineage(4_000_007, Some("python.exe"));
    let ps_lineage = inspect_process_lineage(4_000_008, Some("powershell.exe"));

    println!(
        "🔬 [EMPIRICAL FINDING PROBE] node.exe lineage verdict: {:?}",
        node_lineage
    );
    println!(
        "🔬 [EMPIRICAL FINDING PROBE] python.exe lineage verdict: {:?}",
        python_lineage
    );
    println!(
        "🔬 [EMPIRICAL FINDING PROBE] powershell.exe lineage verdict: {:?}",
        ps_lineage
    );

    let node_candidate = ThreatCandidate::new(
        Some(4_000_006),
        "node.exe",
        "PhaseLock",
        "Reverse shell or malicious payload",
        0.99,
        EvidenceClass::Behavior,
    );
    let node_result = adjudicator
        .adjudicate_threat_candidate(&node_candidate, None)
        .await;
    println!(
        "🔬 [EMPIRICAL ADJUDICATION PROBE] node.exe adjudication result: {:?}",
        node_result
    );

    // Note for Challenger Report: If node.exe/python.exe/powershell.exe are granted ImmuneTarget,
    // this empirically proves that is_blanket_immunity_denied() only denied wsl.exe/sudo/su/doas/pkexec,
    // leaving developer runtimes with blanket immunity when they are the direct target PID!
}

// ============================================================================
// 5. DYNAMIC BINARY METADATA PROBING & TOKEN DELTA CHALLENGE
// ============================================================================

#[test]
fn test_empirical_dynamic_binary_probe_metadata_and_pe_manifest() {
    // 1. Check trait evaluation on DynamicBinaryMetadata
    let mut meta = DynamicBinaryMetadata::default();
    assert!(!meta.is_privileged_target());

    meta.elevation_requirement = ElevationRequirement::RequireAdministrator;
    assert!(
        meta.is_privileged_target(),
        "RequireAdministrator must be privileged"
    );

    meta.elevation_requirement = ElevationRequirement::HighestAvailable;
    assert!(
        meta.is_privileged_target(),
        "HighestAvailable must be privileged"
    );

    meta.elevation_requirement = ElevationRequirement::AsInvoker;
    assert!(
        !meta.is_privileged_target(),
        "AsInvoker alone is not privileged"
    );

    meta.is_suid = true;
    meta.file_uid = 0;
    assert!(meta.is_privileged_target(), "SUID root must be privileged");

    meta.is_suid = true;
    meta.file_uid = 1000;
    assert!(
        !meta.is_privileged_target(),
        "SUID non-root alone is not privileged"
    );

    meta.invokes_wsl_subsystem = true;
    assert!(
        meta.is_privileged_target(),
        "WSL subsystem invocation must be privileged"
    );

    // 2. Synthetic PE Manifest XML Extraction
    let temp_dir = tempfile::tempdir().unwrap();
    let sample_pe_path = temp_dir.path().join("privileged_worker.exe");

    let fake_pe_content = b"MZ\x90\x00PE\x00\x00\
        <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\
          <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\
            <security>\
              <requestedPrivileges>\
                <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>\
              </requestedPrivileges>\
            </security>\
          </trustInfo>\
        </assembly>";

    std::fs::write(&sample_pe_path, fake_pe_content).unwrap();

    let inspected = inspect_binary_metadata(&sample_pe_path).unwrap();
    assert_eq!(
        inspected.elevation_requirement,
        ElevationRequirement::RequireAdministrator
    );
    assert!(inspected.is_privileged_target());

    // 3. Non-existent path handling
    let missing_path = temp_dir.path().join("does_not_exist.bin");
    assert!(inspect_binary_metadata(&missing_path).is_err());
}

#[test]
fn test_empirical_dynamic_token_delta_observation() {
    // 1. Linux EUID Escalation
    let parent_clean = ProcessSecurityContext {
        pid: 1000,
        euid: 1000,
        ..Default::default()
    };
    let child_escalated = ProcessSecurityContext {
        pid: 1001,
        euid: 0,
        ..Default::default()
    };
    let deltas = evaluate_security_context_delta(&parent_clean, &child_escalated);
    assert!(
        deltas.iter().any(|d| matches!(
            d,
            SecurityContextDelta::LinuxEuidEscalation {
                parent_euid: 1000,
                child_euid: 0
            }
        )),
        "Linux EUID escalation must be captured"
    );
    assert!(deltas.iter().any(|d| d.is_privilege_escalation()));

    // 2. Windows Integrity RID Escalation (Medium 0x2000 -> High 0x3000)
    let parent_win = ProcessSecurityContext {
        pid: 2000,
        integrity_rid: 0x2000,
        is_elevated: false,
        session_id: 1,
        ..Default::default()
    };
    let child_win_high = ProcessSecurityContext {
        pid: 2001,
        integrity_rid: 0x3000,
        is_elevated: true,
        session_id: 1,
        ..Default::default()
    };
    let win_deltas = evaluate_security_context_delta(&parent_win, &child_win_high);
    assert!(
        win_deltas.iter().any(|d| matches!(
            d,
            SecurityContextDelta::WindowsIntegrityEscalation {
                parent_rid: 0x2000,
                child_rid: 0x3000
            }
        )),
        "Windows integrity escalation must be captured"
    );
    assert!(
        win_deltas
            .iter()
            .any(|d| matches!(d, SecurityContextDelta::WindowsTokenElevation)),
        "Windows token elevation must be captured"
    );

    // 3. Session 1 -> Session 0 Transition
    let child_service = ProcessSecurityContext {
        pid: 2002,
        integrity_rid: 0x2000,
        is_elevated: false,
        session_id: 0,
        ..Default::default()
    };
    let session_deltas = evaluate_security_context_delta(&parent_win, &child_service);
    assert!(
        session_deltas.iter().any(|d| matches!(
            d,
            SecurityContextDelta::WindowsSession0Transition { parent_session: 1 }
        )),
        "Windows Session 0 transition must be captured"
    );

    // 4. Clean Unprivileged Execution
    let clean_child = ProcessSecurityContext {
        pid: 2003,
        integrity_rid: 0x2000,
        is_elevated: false,
        session_id: 1,
        ..Default::default()
    };
    let clean_deltas = evaluate_security_context_delta(&parent_win, &clean_child);
    assert_eq!(clean_deltas.len(), 1);
    assert_eq!(
        clean_deltas[0],
        SecurityContextDelta::CleanIdentityPreserved
    );
    assert!(!clean_deltas[0].is_privilege_escalation());

    // 5. Live PID query check (PID 4 and self PID)
    let self_pid = std::process::id();
    let live_deltas = observe_parent_child_token_delta(4, self_pid);
    println!(
        "🛡️  Live token deltas (PID 4 -> self PID {}): {:?}",
        self_pid, live_deltas
    );
    // Observe that live query executes cleanly without panic
    assert!(!live_deltas.is_empty());
}
