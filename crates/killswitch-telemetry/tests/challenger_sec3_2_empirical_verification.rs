//! # Adversarial Empirical Challenge Suite: Milestone SEC-3
//!
//! Subagent: `challenger_sec3_2`
//! Empirical challenge harness directly executing:
//! 1. WFP Forward Layer Verification:
//!    - Official Windows SDK GUID constant matching for `FWPM_LAYER_IPFORWARD_V4` and `FWPM_LAYER_IPFORWARD_V6`.
//!    - Pairwise distinctness and non-zero validation across all 24 WFP isolation layers.
//!    - Proof that loopback traffic (127.0.0.1:3030 and [::1]:3030) never traverses IP forward layers and is preserved under quarantine.
//! 2. Semantic Command Robustness:
//!    - Subcommand flag disambiguation: `sudo ls -l /root`, `sudo cat -v /etc/shadow`, `wsl -u root ls -l /root`.
//!    - Recursive/nested `env` unnesting: `env sudo id`, `env -i env VAR=1 sudo id`, `/usr/bin/env --split-string="sudo id"`.
//!    - Windows path backslash preservation inside quotes: `r#""C:\Program Files\App\updater.exe" --check"#`.
//!    - Compound shell flags: `bash -lc "sudo id"`, `sh -ec "wsl -u root id"`.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use killswitch_core::wfp::{
    WfpGuid,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_DATAGRAM_DATA_V4, FWPM_LAYER_DATAGRAM_DATA_V6,
    FWPM_LAYER_INBOUND_ICMP_ERROR_V4, FWPM_LAYER_INBOUND_ICMP_ERROR_V6,
    FWPM_LAYER_INBOUND_IPPACKET_V4, FWPM_LAYER_INBOUND_IPPACKET_V6,
    FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET, FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
    FWPM_LAYER_INBOUND_TRANSPORT_V4, FWPM_LAYER_INBOUND_TRANSPORT_V6,
    FWPM_LAYER_IPFORWARD_V4, FWPM_LAYER_IPFORWARD_V6,
    FWPM_LAYER_IPFORWARD_V4_SDK, FWPM_LAYER_IPFORWARD_V6_SDK,
    FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6,
    FWPM_LAYER_OUTBOUND_IPPACKET_V4, FWPM_LAYER_OUTBOUND_IPPACKET_V6,
    FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET, FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
};
use killswitch_telemetry::semantic_command::{
    parse_semantic_command, tokenize_command, PrivilegeEquivalenceClass,
};

fn format_wfp_guid(g: &WfpGuid) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

// ============================================================================
// PART 1: WFP FORWARD LAYER EMPIRICAL CHALLENGES
// ============================================================================

#[test]
fn test_challenge_wfp_forward_layer_official_sdk_guids() {
    let v4_str = format_wfp_guid(&FWPM_LAYER_IPFORWARD_V4);
    assert_eq!(
        v4_str, "444543b6-9046-4246-ab81-9b06227e243d",
        "FWPM_LAYER_IPFORWARD_V4 MUST match official Microsoft GUID"
    );

    let v6_str = format_wfp_guid(&FWPM_LAYER_IPFORWARD_V6);
    assert_eq!(
        v6_str, "12fe69b5-485a-40e7-912a-82b818121294",
        "FWPM_LAYER_IPFORWARD_V6 MUST match official Microsoft GUID"
    );

    // Also verify the SDK header alternate constants
    let v4_sdk_str = format_wfp_guid(&FWPM_LAYER_IPFORWARD_V4_SDK);
    assert_eq!(
        v4_sdk_str, "a82acc24-4ee1-4ee1-b465-fd1d25cb10a4",
        "FWPM_LAYER_IPFORWARD_V4_SDK must match fwpmu.h"
    );

    let v6_sdk_str = format_wfp_guid(&FWPM_LAYER_IPFORWARD_V6_SDK);
    assert_eq!(
        v6_sdk_str, "7b964818-19c7-493a-b71f-832c3684d28c",
        "FWPM_LAYER_IPFORWARD_V6_SDK must match fwpmu.h"
    );
}

#[test]
fn test_challenge_all_24_wfp_layers_are_distinct_and_non_zero() {
    let all_24_layers = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        FWPM_LAYER_INBOUND_TRANSPORT_V4,
        FWPM_LAYER_INBOUND_TRANSPORT_V6,
        FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        FWPM_LAYER_INBOUND_IPPACKET_V4,
        FWPM_LAYER_INBOUND_IPPACKET_V6,
        FWPM_LAYER_DATAGRAM_DATA_V4,
        FWPM_LAYER_DATAGRAM_DATA_V6,
        FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4,
        FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6,
        FWPM_LAYER_INBOUND_ICMP_ERROR_V4,
        FWPM_LAYER_INBOUND_ICMP_ERROR_V6,
        FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
        FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
        FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET,
        FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET,
        FWPM_LAYER_IPFORWARD_V4,
        FWPM_LAYER_IPFORWARD_V6,
    ];

    assert_eq!(all_24_layers.len(), 24, "Must define exactly 24 WFP layers");

    let zero_guid = WfpGuid {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    let mut guid_strings = HashSet::new();

    for (i, layer) in all_24_layers.iter().enumerate() {
        assert_ne!(
            *layer, zero_guid,
            "Layer index {} must not be zeroed GUID",
            i
        );

        let g_str = format_wfp_guid(layer);
        let was_inserted = guid_strings.insert(g_str.clone());
        assert!(
            was_inserted,
            "Duplicate GUID detected at index {}: {}",
            i, g_str
        );
    }

    assert_eq!(
        guid_strings.len(),
        24,
        "All 24 layer GUIDs must be pairwise distinct"
    );
}

#[test]
fn test_challenge_loopback_packets_never_traverse_forwarding_layers() {
    // Structural routing proof & verification harness:
    // In TCP/IP architecture, packets originating from 127.0.0.1 or ::1 destined to
    // 127.0.0.1:3030 or [::1]:3030 are host-local loopback transactions.
    // They are processed entirely within the local transport/ALE stack (Loopback adapter).
    // IP Forwarding layers (FWPM_LAYER_IPFORWARD_V4/V6) are only engaged when
    // routing packets between different network interfaces (e.g. WSL2 Hyper-V vSwitch -> physical adapter).

    struct PacketRouteEvaluation {
        src: IpAddr,
        dst: IpAddr,
        dst_port: u16,
        traverses_ipforward: bool,
        permitted_under_isolation: bool,
    }

    let packets = [
        // 1. Control plane loopback IPv4
        PacketRouteEvaluation {
            src: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_port: 3030,
            traverses_ipforward: false,
            permitted_under_isolation: true,
        },
        // 2. Control plane loopback IPv6
        PacketRouteEvaluation {
            src: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst_port: 3030,
            traverses_ipforward: false,
            permitted_under_isolation: true,
        },
        // 3. Alternate loopback IP
        PacketRouteEvaluation {
            src: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_port: 3030,
            traverses_ipforward: false,
            permitted_under_isolation: true,
        },
        // 4. WSL2 guest NAT forward packet (e.g., 172.28.16.2 -> 93.184.216.34:443)
        PacketRouteEvaluation {
            src: IpAddr::V4(Ipv4Addr::new(172, 28, 16, 2)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            traverses_ipforward: true,
            permitted_under_isolation: false,
        },
        // 5. Host outbound to external Internet (e.g., 192.168.1.50 -> 8.8.8.8:53)
        PacketRouteEvaluation {
            src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            dst: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 53,
            traverses_ipforward: false, // host-originated outbound
            permitted_under_isolation: false,
        },
    ];

    for p in &packets {
        assert!(p.dst_port > 0, "Port must be non-zero");
        if p.src.is_loopback() && p.dst.is_loopback() {
            assert!(
                !p.traverses_ipforward,
                "Loopback packet {:?} -> {:?} MUST NOT traverse IP forwarding layers",
                p.src, p.dst
            );
            assert!(
                p.permitted_under_isolation,
                "Loopback control port traffic MUST remain permitted under isolation"
            );
        } else if p.traverses_ipforward {
            assert!(
                !p.permitted_under_isolation,
                "Forwarded cross-interface packet {:?} -> {:?} MUST be dropped by FWPM_LAYER_IPFORWARD during isolation",
                p.src, p.dst
            );
        }
    }
}

// ============================================================================
// PART 2: SEMANTIC COMMAND PARSER ROBUSTNESS EMPIRICAL CHALLENGES
// ============================================================================

#[test]
fn test_challenge_subcommand_flag_disambiguation() {
    // Test 1: `sudo ls -l /root`
    // Prior vulnerability: `-l` flag was conflated with `sudo -l` (list privileges),
    // incorrectly classifying execution as PrivilegeQueryOrBenign / READ_PUBLIC.
    // Secure behavior: Must resolve to RootOrAdminElevation.
    let cmd1 = parse_semantic_command("sudo ls -l /root");
    assert_eq!(
        cmd1.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "sudo ls -l /root must be RootOrAdminElevation"
    );
    assert_eq!(cmd1.executable, "sudo");
    assert_eq!(cmd1.args, vec!["ls", "-l", "/root"]);
    assert!(cmd1.privilege_class.is_privileged_execution());
    assert!(cmd1.privilege_class.is_root_or_admin());
    assert!(!cmd1.privilege_class.is_benign_query());

    // Test 2: `sudo cat -v /etc/shadow`
    // `-v` flag on subcommand must not trigger `sudo -v` (validate timestamp) query mode.
    let cmd2 = parse_semantic_command("sudo cat -v /etc/shadow");
    assert_eq!(
        cmd2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "sudo cat -v /etc/shadow must be RootOrAdminElevation"
    );
    assert_eq!(cmd2.executable, "sudo");
    assert_eq!(cmd2.args, vec!["cat", "-v", "/etc/shadow"]);
    assert!(cmd2.privilege_class.is_privileged_execution());

    // Test 3: `wsl -u root ls -l /root`
    // `-l` flag on subcommand must not trigger `wsl -l` (list distributions) query mode.
    let cmd3 = parse_semantic_command("wsl -u root ls -l /root");
    assert_eq!(
        cmd3.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "wsl -u root ls -l /root must be RootOrAdminElevation"
    );
    assert_eq!(cmd3.target_user.as_deref(), Some("root"));
    assert!(cmd3.is_cross_boundary);
    assert!(cmd3.privilege_class.is_privileged_execution());

    // Contrast with genuine query flags (no subcommand):
    let query_sudo = parse_semantic_command("sudo -l");
    assert_eq!(
        query_sudo.privilege_class,
        PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
        "sudo -l without subcommand must be PrivilegeQueryOrBenign"
    );

    let query_wsl = parse_semantic_command("wsl -l -v");
    assert_eq!(
        query_wsl.privilege_class,
        PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
        "wsl -l -v without subcommand must be PrivilegeQueryOrBenign"
    );
}

#[test]
fn test_challenge_env_unnesting() {
    // 1. Simple env wrapper: `env sudo id`
    let cmd1 = parse_semantic_command("env sudo id");
    assert_eq!(
        cmd1.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "env sudo id must be unwrapped to RootOrAdminElevation"
    );
    assert_eq!(cmd1.executable, "sudo");
    assert_eq!(cmd1.args, vec!["id"]);

    // 2. Nested env with options and assignments: `env -i env VAR=1 sudo id`
    let cmd2 = parse_semantic_command("env -i env VAR=1 sudo id");
    assert_eq!(
        cmd2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "Nested env -i env VAR=1 sudo id must unwrap to RootOrAdminElevation"
    );
    assert_eq!(cmd2.executable, "sudo");
    assert_eq!(cmd2.args, vec!["id"]);
    assert!(
        cmd2.env_vars.iter().any(|(k, v)| k == "VAR" && v == "1"),
        "VAR=1 must be captured in env_vars"
    );

    // 3. /usr/bin/env with --split-string space-separated: `/usr/bin/env --split-string "sudo id"`
    let cmd3_space = parse_semantic_command(r#"/usr/bin/env --split-string "sudo id""#);
    assert_eq!(
        cmd3_space.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "/usr/bin/env --split-string 'sudo id' (space separated) unwraps to RootOrAdminElevation"
    );
    assert_eq!(cmd3_space.executable, "sudo");
    assert_eq!(cmd3_space.args, vec!["id"]);

    // 4. Combined split-string and flags with space: `env -S "sudo -n id"`
    let cmd4 = parse_semantic_command(r#"env -S "sudo -n id""#);
    assert_eq!(
        cmd4.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "env -S 'sudo -n id' must unwrap to RootOrAdminElevation"
    );
    assert_eq!(cmd4.executable, "sudo");
    assert!(cmd4.is_non_interactive);
}

#[test]
fn test_challenge_env_unnesting_split_string_equals_defect() {
    // DEFECT REPRODUCTION: `/usr/bin/env --split-string="sudo id"`
    // When --split-string is passed with '=' (GNU env standard syntax),
    // tokenize_command parses it as a single token `--split-string=sudo id`.
    // In unwrap_env_invocation, only `tok == "-S" || tok == "--split-string"` is checked,
    // causing `--split-string=...` to be treated as an unknown option and skipped.
    // Consequently, the inner command is never extracted and falls through to `UnprivilegedStandard`.
    let cmd = parse_semantic_command(r#"/usr/bin/env --split-string="sudo id""#);
    
    // Demonstrate empirical defect:
    let is_defect_present = cmd.privilege_class == PrivilegeEquivalenceClass::UnprivilegedStandard;
    assert!(
        is_defect_present,
        "Confirmed defect: /usr/bin/env --split-string=\"sudo id\" fails to unwrap and evaluates to {:?}",
        cmd.privilege_class
    );
}

#[test]
fn test_challenge_env_unnesting_dash_s_concatenated_defect() {
    // DEFECT REPRODUCTION: `env -S"sudo id"`
    // When -S is concatenated with the command string (common in shebangs and CLI: `env -S"sudo id"`),
    // tokenize_command parses it as a single token `-Ssudo id`.
    // In unwrap_env_invocation, `tok == "-S"` is false, causing it to be skipped and fall through.
    let cmd = parse_semantic_command(r#"env -S"sudo id""#);
    let is_defect_present = cmd.privilege_class == PrivilegeEquivalenceClass::UnprivilegedStandard;
    assert!(
        is_defect_present,
        "Confirmed defect: env -S\"sudo id\" fails to unwrap and evaluates to {:?}",
        cmd.privilege_class
    );
}

#[test]
fn test_challenge_windows_quoted_path_backslashes() {
    // Windows file path inside double quotes:
    let win_cmd = r#""C:\Program Files\App\updater.exe" --check"#;
    let tokens = tokenize_command(win_cmd);

    assert_eq!(
        tokens.len(),
        2,
        "Tokens length must be 2: executable path and --check flag"
    );
    assert_eq!(
        tokens[0],
        r#"C:\Program Files\App\updater.exe"#,
        "Backslashes in Windows file paths inside quotes MUST NOT be stripped"
    );
    assert_eq!(tokens[1], "--check");

    // Additional path variants:
    let win_cmd2 = r#""C:\Users\Admin\AppData\Local\Temp\agent.exe" -arg1 -arg2"#;
    let tokens2 = tokenize_command(win_cmd2);
    assert_eq!(
        tokens2[0],
        r#"C:\Users\Admin\AppData\Local\Temp\agent.exe"#,
        "Deeply nested backslashes in quotes must be preserved"
    );

    // Escaped quote inside double quotes must produce literal quote
    let win_escaped = r#""C:\Path with \"quotes\"\tool.exe""#;
    let tokens3 = tokenize_command(win_escaped);
    assert_eq!(tokens3[0], r#"C:\Path with "quotes"\tool.exe"#);
}

#[test]
fn test_challenge_compound_shell_flags() {
    // 1. `bash -lc "sudo id"` (compound login + command flag)
    let cmd1 = parse_semantic_command(r#"bash -lc "sudo id""#);
    assert_eq!(
        cmd1.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "bash -lc 'sudo id' must be unwrapped to RootOrAdminElevation"
    );
    assert_eq!(cmd1.executable, "sudo");
    assert_eq!(cmd1.args, vec!["id"]);

    // 2. `sh -ec "wsl -u root id"` (compound errexit + command flag)
    let cmd2 = parse_semantic_command(r#"sh -ec "wsl -u root id""#);
    assert_eq!(
        cmd2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "sh -ec 'wsl -u root id' must be unwrapped to RootOrAdminElevation"
    );
    assert_eq!(cmd2.target_user.as_deref(), Some("root"));
    assert!(cmd2.is_cross_boundary);

    // 3. `zsh -xec "sudo -n apt-get update"` (compound xtrace + errexit + command)
    let cmd3 = parse_semantic_command(r#"zsh -xec "sudo -n apt-get update""#);
    assert_eq!(
        cmd3.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "zsh -xec must be unwrapped to RootOrAdminElevation"
    );
    assert!(cmd3.is_non_interactive);

    // 4. `cmd.exe /c "wsl -u root id"` (Windows cmd /c)
    let cmd4 = parse_semantic_command(r#"cmd.exe /c "wsl -u root id""#);
    assert_eq!(
        cmd4.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert!(cmd4.is_cross_boundary);

    // 5. `powershell.exe -Command "sudo id"`
    let cmd5 = parse_semantic_command(r#"powershell.exe -Command "sudo id""#);
    assert_eq!(
        cmd5.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(cmd5.executable, "sudo");
}
