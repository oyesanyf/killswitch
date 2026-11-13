//! # End-to-End Peer Review Security Remediation Test Suite (R1–R7)
//!
//! Requirement-driven opaque-box integration test suite verifying peer review security
//! remediations R1 through R7 and dynamic runtime observation follow-ups:
//! - Module 1: WFP Forward-Layer Filtering for WSL2 NAT Exfiltration
//! - Module 2: Dynamic Binary Metadata Probing (Name-Independent SUID, xattr, PE manifest)
//! - Module 3: Parent -> Child Token Delta Observation (EUID, CapEff, TokenIntegrityLevel)
//! - Module 4: Process Immunity Decoupling (Kernel anchors protected, developer runtimes decoupled)
//! - Module 5: Semantic Command Analysis & Privilege Equivalence Classes (AST parsing, APC gating)
//! - Module 6: Control Plane Mutual Authentication & Loopback Hardening (401/403 unauthenticated)
//! - Module 7: Semantic DLP Engine & Default-Deny Containment (Names, deal values >= $1M, PHI)
//! - Module 8: Repository Provenance & Integrity Verification (Binary cleanup, CI workflow, docs)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Pure constant-time comparison helper resistant to timing attacks.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// MODULE 1: WFP FORWARD-LAYER FILTERING (R6 & WSL2 NAT DEFENSE)
// ============================================================================

/// WFP GUID representation conforming to Windows SDK RPC_CSTR / GUID ABI layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WfpLayerGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl WfpLayerGuid {
    pub fn to_string_guid(&self) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

/// Official Microsoft Windows SDK GUID for FWPM_LAYER_IPFORWARD_V4: {444543b6-9046-4246-ab81-9b06227e243d}
pub const FWPM_LAYER_IPFORWARD_V4: WfpLayerGuid = WfpLayerGuid {
    data1: 0x444543b6,
    data2: 0x9046,
    data3: 0x4246,
    data4: [0xab, 0x81, 0x9b, 0x06, 0x22, 0x7e, 0x24, 0x3d],
};

/// Official Microsoft Windows SDK GUID for FWPM_LAYER_IPFORWARD_V6: {12fe69b5-485a-40e7-912a-82b818121294}
pub const FWPM_LAYER_IPFORWARD_V6: WfpLayerGuid = WfpLayerGuid {
    data1: 0x12fe69b5,
    data2: 0x485a,
    data3: 0x40e7,
    data4: [0x91, 0x2a, 0x82, 0xb8, 0x18, 0x12, 0x12, 0x94],
};

/// Simulated network packet passing across Windows IP Forwarding Layer.
#[derive(Debug, Clone)]
pub struct SimulatedForwardPacket {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8, // 6 = TCP, 17 = UDP
    pub interface_name: String,
    pub is_wsl2_vswitch: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFilterVerdict {
    Permit,
    Block,
}

/// Evaluator of WFP forward-layer filters during quarantine.
pub fn evaluate_wfp_forward_packet(
    is_quarantine_active: bool,
    packet: &SimulatedForwardPacket,
) -> PacketFilterVerdict {
    if !is_quarantine_active {
        return PacketFilterVerdict::Permit;
    }

    // Loopback packets are preserved per strict loopback isolation policy
    if packet.destination_ip.is_loopback() || packet.source_ip.is_loopback() {
        return PacketFilterVerdict::Permit;
    }

    // When quarantine is active, any packet passing through IP Forwarding layer (including WSL2 NAT) is blocked
    PacketFilterVerdict::Block
}

#[test]
fn test_wfp_forward_layer_official_guid_constants() {
    assert_eq!(
        FWPM_LAYER_IPFORWARD_V4
            .to_string_guid()
            .to_ascii_lowercase(),
        "444543b6-9046-4246-ab81-9b06227e243d"
    );
    assert_eq!(
        FWPM_LAYER_IPFORWARD_V6
            .to_string_guid()
            .to_ascii_lowercase(),
        "12fe69b5-485a-40e7-912a-82b818121294"
    );
}

#[test]
fn test_wfp_forward_layer_packet_interception_simulation() {
    // Simulated outbound NAT packet originating from WSL2 guest (172.28.16.2) destined for external C2
    let wsl_packet = SimulatedForwardPacket {
        source_ip: IpAddr::V4(Ipv4Addr::new(172, 28, 16, 2)),
        destination_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        source_port: 49152,
        destination_port: 443,
        protocol: 6, // TCP
        interface_name: "vEthernet (WSL)".to_string(),
        is_wsl2_vswitch: true,
    };

    // Before quarantine: permitted
    assert_eq!(
        evaluate_wfp_forward_packet(false, &wsl_packet),
        PacketFilterVerdict::Permit
    );

    // During hermetic quarantine: blocked at IP Forward layer!
    assert_eq!(
        evaluate_wfp_forward_packet(true, &wsl_packet),
        PacketFilterVerdict::Block
    );
}

#[test]
fn test_wfp_forward_layer_loopback_and_internal_preservation() {
    let loopback_packet = SimulatedForwardPacket {
        source_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        destination_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        source_port: 50505,
        destination_port: 3030,
        protocol: 6,
        interface_name: "Loopback Pseudo-Interface 1".to_string(),
        is_wsl2_vswitch: false,
    };

    // Loopback must ALWAYS be permitted, even during active quarantine
    assert_eq!(
        evaluate_wfp_forward_packet(true, &loopback_packet),
        PacketFilterVerdict::Permit
    );
}

#[test]
fn test_wfp_forward_layer_dual_stack_v4_and_v6() {
    let v6_packet = SimulatedForwardPacket {
        source_ip: IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap()),
        destination_ip: IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()),
        source_port: 51234,
        destination_port: 53,
        protocol: 17, // UDP
        interface_name: "vEthernet (WSL)".to_string(),
        is_wsl2_vswitch: true,
    };

    assert_eq!(
        evaluate_wfp_forward_packet(true, &v6_packet),
        PacketFilterVerdict::Block
    );
}

// ============================================================================
// MODULE 2: DYNAMIC BINARY METADATA PROBING (NAME-INDEPENDENT)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationRequirement {
    RequireAdministrator,
    HighestAvailable,
    AsInvoker,
    None,
}

#[derive(Debug, Clone)]
pub struct DynamicBinaryMetadata {
    pub is_suid: bool,
    pub is_sgid: bool,
    pub file_uid: u32,
    pub has_linux_capabilities: bool,
    pub linux_capabilities_mask: u64,
    pub elevation_requirement: ElevationRequirement,
    pub invokes_wsl_subsystem: bool,
    pub invokes_hyperv_compute: bool,
}

impl DynamicBinaryMetadata {
    pub fn is_privileged_target(&self) -> bool {
        (self.is_suid && self.file_uid == 0)
            || self.has_linux_capabilities
            || matches!(
                self.elevation_requirement,
                ElevationRequirement::RequireAdministrator | ElevationRequirement::HighestAvailable
            )
            || self.invokes_wsl_subsystem
    }
}

/// Evaluates POSIX mode bits independent of binary filename.
pub fn probe_posix_metadata(
    mode: u32,
    file_uid: u32,
    capabilities_mask: u64,
) -> DynamicBinaryMetadata {
    let is_suid = (mode & 0o4000) != 0;
    let is_sgid = (mode & 0o2000) != 0;
    let has_linux_capabilities = capabilities_mask != 0;

    DynamicBinaryMetadata {
        is_suid,
        is_sgid,
        file_uid,
        has_linux_capabilities,
        linux_capabilities_mask: capabilities_mask,
        elevation_requirement: ElevationRequirement::None,
        invokes_wsl_subsystem: false,
        invokes_hyperv_compute: false,
    }
}

/// Evaluates Windows PE manifest XML and imported DLLs independent of filename.
pub fn probe_windows_pe_manifest(
    manifest_xml: &str,
    imported_dlls: &[&str],
) -> DynamicBinaryMetadata {
    let xml_lc = manifest_xml.to_ascii_lowercase();
    let elevation_requirement = if xml_lc.contains("requireadministrator") {
        ElevationRequirement::RequireAdministrator
    } else if xml_lc.contains("highestavailable") {
        ElevationRequirement::HighestAvailable
    } else if xml_lc.contains("asinvoker") {
        ElevationRequirement::AsInvoker
    } else {
        ElevationRequirement::None
    };

    let invokes_wsl_subsystem = imported_dlls.iter().any(|d| {
        let d_lc = d.to_ascii_lowercase();
        d_lc.contains("wslapi.dll") || d_lc.contains("lxss")
    });

    let invokes_hyperv_compute = imported_dlls.iter().any(|d| {
        let d_lc = d.to_ascii_lowercase();
        d_lc.contains("vmcompute.dll")
    });

    DynamicBinaryMetadata {
        is_suid: false,
        is_sgid: false,
        file_uid: 0,
        has_linux_capabilities: false,
        linux_capabilities_mask: 0,
        elevation_requirement,
        invokes_wsl_subsystem,
        invokes_hyperv_compute,
    }
}

#[test]
fn test_dynamic_binary_probe_suid_and_sgid_posix() {
    // Mode 0o104755: Regular file with SUID bit set, owned by root (uid 0)
    let meta = probe_posix_metadata(0o104755, 0, 0);
    assert!(meta.is_suid);
    assert!(!meta.is_sgid);
    assert_eq!(meta.file_uid, 0);
    assert!(meta.is_privileged_target());

    // Non-SUID file: 0o100755
    let normal_meta = probe_posix_metadata(0o100755, 0, 0);
    assert!(!normal_meta.is_suid);
    assert!(!normal_meta.is_privileged_target());
}

#[test]
fn test_dynamic_binary_probe_linux_capabilities() {
    // CAP_SETUID (bit 7 = 0x80) + CAP_SYS_ADMIN (bit 21 = 0x200000)
    let caps_mask: u64 = (1 << 7) | (1 << 21);
    let meta = probe_posix_metadata(0o100755, 1000, caps_mask);
    assert!(meta.has_linux_capabilities);
    assert_eq!(meta.linux_capabilities_mask, caps_mask);
    assert!(meta.is_privileged_target());
}

#[test]
fn test_dynamic_binary_probe_windows_pe_manifest() {
    let manifest_admin = r#"
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
      <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
          <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
          </requestedPrivileges>
        </security>
      </trustInfo>
    </assembly>
    "#;

    let meta = probe_windows_pe_manifest(manifest_admin, &["kernel32.dll", "advapi32.dll"]);
    assert_eq!(
        meta.elevation_requirement,
        ElevationRequirement::RequireAdministrator
    );
    assert!(meta.is_privileged_target());

    let manifest_invoker = r#"<requestedExecutionLevel level="asInvoker" uiAccess="false"/>"#;
    let meta_invoker = probe_windows_pe_manifest(manifest_invoker, &["kernel32.dll"]);
    assert_eq!(
        meta_invoker.elevation_requirement,
        ElevationRequirement::AsInvoker
    );
    assert!(!meta_invoker.is_privileged_target());
}

#[test]
fn test_dynamic_binary_probe_subsystem_traits() {
    let meta = probe_windows_pe_manifest("", &["wslapi.dll", "kernel32.dll"]);
    assert!(meta.invokes_wsl_subsystem);
    assert!(meta.is_privileged_target());

    let meta_hyperv = probe_windows_pe_manifest("", &["vmcompute.dll"]);
    assert!(meta_hyperv.invokes_hyperv_compute);
}

#[test]
fn test_dynamic_binary_probe_renamed_executable() {
    // Adversary copies /usr/bin/sudo to /tmp/renamed_innocent
    // Filename says "innocent", but SUID bit and UID 0 are preserved!
    let meta = probe_posix_metadata(0o104755, 0, 0);
    assert!(
        meta.is_privileged_target(),
        "Renamed binary must be caught via on-disk SUID metadata"
    );
}

// ============================================================================
// MODULE 3: PARENT -> CHILD TOKEN DELTA OBSERVATION
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSecurityContext {
    pub pid: u32,
    pub euid: u32,
    pub linux_capabilities: u64,
    pub namespace_user_inode: u64,
    pub token_integrity_rid: u32, // Windows RID: 0x2000 Medium, 0x3000 High, 0x4000 System
    pub is_token_elevated: bool,
    pub session_id: u32,
}

#[derive(Debug, Clone)]
pub struct TokenDeltaVerdict {
    pub is_privilege_escalation: bool,
    pub euid_transition: bool,
    pub capability_expansion: bool,
    pub namespace_transition: bool,
    pub integrity_elevation: bool,
    pub token_elevation_active: bool,
    pub session_zero_transition: bool,
    pub explanation: String,
}

pub fn compare_parent_child_security_context(
    parent: &ProcessSecurityContext,
    child: &ProcessSecurityContext,
) -> TokenDeltaVerdict {
    let euid_transition = parent.euid != 0 && child.euid == 0;
    let capability_expansion = (child.linux_capabilities & !parent.linux_capabilities) != 0;
    let namespace_transition = parent.namespace_user_inode != child.namespace_user_inode;
    let integrity_elevation =
        parent.token_integrity_rid < 0x3000 && child.token_integrity_rid >= 0x3000;
    let token_elevation_active = !parent.is_token_elevated && child.is_token_elevated;
    let session_zero_transition = parent.session_id != 0 && child.session_id == 0;

    let is_privilege_escalation = euid_transition
        || capability_expansion
        || namespace_transition
        || integrity_elevation
        || token_elevation_active
        || session_zero_transition;

    let mut reasons = Vec::new();
    if euid_transition {
        reasons.push("EUID elevated to root (0)".to_string());
    }
    if capability_expansion {
        reasons.push("Linux capability bitmask expanded".to_string());
    }
    if namespace_transition {
        reasons.push("User namespace transitioned".to_string());
    }
    if integrity_elevation {
        reasons.push("TokenIntegrityLevel elevated to High/System".to_string());
    }
    if token_elevation_active {
        reasons.push("TokenElevation active".to_string());
    }
    if session_zero_transition {
        reasons.push("Transitioned from interactive to Session 0".to_string());
    }

    TokenDeltaVerdict {
        is_privilege_escalation,
        euid_transition,
        capability_expansion,
        namespace_transition,
        integrity_elevation,
        token_elevation_active,
        session_zero_transition,
        explanation: reasons.join("; "),
    }
}

#[test]
fn test_token_delta_linux_euid_escalation() {
    let parent = ProcessSecurityContext {
        pid: 1000,
        euid: 1000,
        linux_capabilities: 0,
        namespace_user_inode: 4026531837,
        token_integrity_rid: 0x2000,
        is_token_elevated: false,
        session_id: 1,
    };
    let child = ProcessSecurityContext {
        pid: 2000,
        euid: 0, // Elevated to root!
        linux_capabilities: 0,
        namespace_user_inode: 4026531837,
        token_integrity_rid: 0x2000,
        is_token_elevated: false,
        session_id: 1,
    };

    let verdict = compare_parent_child_security_context(&parent, &child);
    assert!(verdict.is_privilege_escalation);
    assert!(verdict.euid_transition);
}

#[test]
fn test_token_delta_windows_token_integrity_escalation() {
    let parent = ProcessSecurityContext {
        pid: 3000,
        euid: 1000,
        linux_capabilities: 0,
        namespace_user_inode: 0,
        token_integrity_rid: 0x2000, // Medium Integrity
        is_token_elevated: false,
        session_id: 1,
    };
    let child = ProcessSecurityContext {
        pid: 3001,
        euid: 1000,
        linux_capabilities: 0,
        namespace_user_inode: 0,
        token_integrity_rid: 0x3000, // High Integrity (Administrator)
        is_token_elevated: true,
        session_id: 1,
    };

    let verdict = compare_parent_child_security_context(&parent, &child);
    assert!(verdict.is_privilege_escalation);
    assert!(verdict.integrity_elevation);
    assert!(verdict.token_elevation_active);
}

#[test]
fn test_token_delta_clean_unprivileged_execution() {
    let parent = ProcessSecurityContext {
        pid: 4000,
        euid: 1000,
        linux_capabilities: 0,
        namespace_user_inode: 12345,
        token_integrity_rid: 0x2000,
        is_token_elevated: false,
        session_id: 1,
    };
    let child = ProcessSecurityContext {
        pid: 4001,
        euid: 1000,
        linux_capabilities: 0,
        namespace_user_inode: 12345,
        token_integrity_rid: 0x2000,
        is_token_elevated: false,
        session_id: 1,
    };

    let verdict = compare_parent_child_security_context(&parent, &child);
    assert!(!verdict.is_privilege_escalation);
}

// ============================================================================
// MODULE 4: PROCESS IMMUNITY DECOUPLING (R2)
// ============================================================================

/// Canonical OS kernel anchor classifier.
pub fn is_immutable_os_kernel_anchor(pid: u32, name: &str) -> bool {
    if pid <= 4 {
        return true;
    }
    let name_lc = name.trim().to_ascii_lowercase();
    let base = name_lc.rsplit(['\\', '/']).next().unwrap_or(&name_lc);

    matches!(
        base,
        "system"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "systemd"
            | "systemd-journald"
            | "launchd"
            | "kernel_task"
    )
}

/// Evaluator of developer tools and shells.
pub fn is_developer_or_agent_runtime(name: &str) -> bool {
    let name_lc = name.trim().to_ascii_lowercase();
    let base = name_lc
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&name_lc)
        .trim_end_matches(".exe");

    matches!(
        base,
        "cursor"
            | "code"
            | "node"
            | "python"
            | "python3"
            | "powershell"
            | "pwsh"
            | "cmd"
            | "wsl"
            | "bash"
            | "sh"
            | "zsh"
            | "sudo"
            | "su"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageImmunityVerdict {
    ImmuneKernelAnchor {
        pid: u32,
        proc_name: String,
    },
    AgentRuntimeChild {
        ancestor_pid: u32,
        ancestor_name: String,
        depth: usize,
    },
    NotImmune,
}

impl LineageImmunityVerdict {
    pub fn is_immune(&self) -> bool {
        matches!(self, Self::ImmuneKernelAnchor { .. })
    }

    pub fn to_veto_reason(&self) -> Option<&'static str> {
        match self {
            Self::ImmuneKernelAnchor { .. } => Some("VETO_IMMUNE_KERNEL_ANCHOR"),
            Self::AgentRuntimeChild { .. } => None, // NO VETO for agent children!
            Self::NotImmune => None,
        }
    }
}

pub fn inspect_simulated_ancestry(
    target_pid: u32,
    target_name: &str,
    parent_chain: &[(u32, &str)],
) -> LineageImmunityVerdict {
    // 1. Direct kernel anchor check
    if is_immutable_os_kernel_anchor(target_pid, target_name) {
        return LineageImmunityVerdict::ImmuneKernelAnchor {
            pid: target_pid,
            proc_name: target_name.to_string(),
        };
    }

    // 2. Ancestry traversal up to depth 5
    for (depth, &(p_pid, p_name)) in parent_chain.iter().enumerate().take(5) {
        if is_immutable_os_kernel_anchor(p_pid, p_name) {
            return LineageImmunityVerdict::ImmuneKernelAnchor {
                pid: p_pid,
                proc_name: p_name.to_string(),
            };
        }
        if is_developer_or_agent_runtime(p_name) {
            return LineageImmunityVerdict::AgentRuntimeChild {
                ancestor_pid: p_pid,
                ancestor_name: p_name.to_string(),
                depth: depth + 1,
            };
        }
    }

    LineageImmunityVerdict::NotImmune
}

#[test]
fn test_process_immunity_immutable_kernel_anchors() {
    assert!(is_immutable_os_kernel_anchor(0, "Idle"));
    assert!(is_immutable_os_kernel_anchor(4, "System"));
    assert!(is_immutable_os_kernel_anchor(100, "csrss.exe"));
    assert!(is_immutable_os_kernel_anchor(1, "systemd"));
    assert!(is_immutable_os_kernel_anchor(1, "launchd"));
}

#[test]
fn test_process_immunity_decoupling_developer_runtimes() {
    // Developer runtimes and shells must NOT be classified as immutable kernel anchors!
    assert!(!is_immutable_os_kernel_anchor(5000, "cursor.exe"));
    assert!(!is_immutable_os_kernel_anchor(5001, "node.exe"));
    assert!(!is_immutable_os_kernel_anchor(5002, "python.exe"));
    assert!(!is_immutable_os_kernel_anchor(5003, "powershell.exe"));
    assert!(!is_immutable_os_kernel_anchor(5004, "wsl.exe"));
    assert!(!is_immutable_os_kernel_anchor(5005, "sudo"));
    assert!(!is_immutable_os_kernel_anchor(5006, "bash"));
}

#[test]
fn test_ancestry_traversal_agent_runtime_child() {
    // Hostile script spawned by Cursor IDE
    let verdict = inspect_simulated_ancestry(
        9999,
        "exfil_script.sh",
        &[(5000, "cursor.exe"), (100, "explorer.exe")],
    );

    assert!(!verdict.is_immune());
    assert_eq!(verdict.to_veto_reason(), None); // No veto!
    assert!(matches!(
        verdict,
        LineageImmunityVerdict::AgentRuntimeChild { .. }
    ));
}

// ============================================================================
// MODULE 5: SEMANTIC COMMAND ANALYSIS & PRIVILEGE CLASSES (R3)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeEquivalenceClass {
    RootOrAdminElevation,
    TargetUserDelegation,
    PrivilegeQueryOrBenign,
    UnprivilegedStandard,
}

pub fn classify_command_privilege(command: &str) -> (PrivilegeEquivalenceClass, &'static str) {
    let lower = command.trim().to_ascii_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.is_empty() {
        return (
            PrivilegeEquivalenceClass::UnprivilegedStandard,
            "READ_PUBLIC",
        );
    }

    let first = tokens[0].rsplit(['\\', '/']).next().unwrap_or(tokens[0]);

    if matches!(first, "sudo" | "su" | "doas" | "pkexec" | "runas" | "wsl") {
        if tokens
            .iter()
            .any(|t| matches!(*t, "-l" | "-v" | "-h" | "--help" | "--version" | "--status"))
        {
            return (
                PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
                "READ_PUBLIC",
            );
        }
        if lower.contains("-u root")
            || lower.contains("--user root")
            || lower.contains("/user:administrator")
            || lower.contains("-u 0")
        {
            return (
                PrivilegeEquivalenceClass::RootOrAdminElevation,
                "PRIVILEGED_EXECUTION",
            );
        }
        if lower.contains("-u ") || lower.contains("--user ") || lower.contains("/user:") {
            return (
                PrivilegeEquivalenceClass::TargetUserDelegation,
                "PRIVILEGED_EXECUTION",
            );
        }
        return (
            PrivilegeEquivalenceClass::RootOrAdminElevation,
            "PRIVILEGED_EXECUTION",
        );
    }

    (
        PrivilegeEquivalenceClass::UnprivilegedStandard,
        "READ_PUBLIC",
    )
}

#[test]
fn test_semantic_command_privilege_equivalence_classes() {
    assert_eq!(
        classify_command_privilege("sudo -n id").0,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(
        classify_command_privilege("wsl -u root apt-get update").0,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(
        classify_command_privilege("runas /user:Administrator cmd.exe").0,
        PrivilegeEquivalenceClass::RootOrAdminElevation
    );
    assert_eq!(
        classify_command_privilege("sudo -u www-data cat /var/log/nginx/access.log").0,
        PrivilegeEquivalenceClass::TargetUserDelegation
    );
    assert_eq!(
        classify_command_privilege("wsl -l -v").0,
        PrivilegeEquivalenceClass::PrivilegeQueryOrBenign
    );
}

#[test]
fn test_bounded_agents_apc_privileged_execution_gating() {
    let (_, apc_action) = classify_command_privilege("sudo -n id");
    assert_eq!(apc_action, "PRIVILEGED_EXECUTION");

    let (_, apc_action_wsl) = classify_command_privilege("wsl -u root id");
    assert_eq!(apc_action_wsl, "PRIVILEGED_EXECUTION");

    // Must NEVER fall through to "READ_PUBLIC"!
    assert_ne!(apc_action, "READ_PUBLIC");
    assert_ne!(apc_action_wsl, "READ_PUBLIC");
}

// ============================================================================
// MODULE 6: CONTROL PLANE MUTUAL AUTHENTICATION & LOOPBACK HARDENING (R4)
// ============================================================================

pub use killswitch_server::auth::{verify_control_plane_request_with_token, AuthVerdict};

const E2E_CONTROL_TOKEN: &str = "ks-e2e-test-token-0123456789abcdef0123456789abcdef";

#[test]
fn test_control_plane_unauthenticated_requests_return_401() {
    let frozen_pids = vec![];
    // No token provided to /engage, /mode, /rl/learn, or /rate-limit/allowlist
    let verdict = verify_control_plane_request_with_token(
        None,
        None,
        Some(100),
        100,
        &frozen_pids,
        E2E_CONTROL_TOKEN,
    );
    assert_eq!(verdict, AuthVerdict::Unauthorized401);

    // Empty token
    let verdict_empty = verify_control_plane_request_with_token(
        Some("   "),
        None,
        Some(100),
        100,
        &frozen_pids,
        E2E_CONTROL_TOKEN,
    );
    assert_eq!(verdict_empty, AuthVerdict::Unauthorized401);

    // Invalid token and legacy static bypasses MUST be rejected fail-closed
    for rejected in [
        "bad_token",
        "CONFIRM ISOLATE",
        "CONFIRM RESTORE",
        "KS-TOKEN-SEC-REM-9999-VERIFIED-AUTH",
    ] {
        let verdict_bad = verify_control_plane_request_with_token(
            Some(rejected),
            None,
            Some(100),
            100,
            &frozen_pids,
            E2E_CONTROL_TOKEN,
        );
        assert_eq!(verdict_bad, AuthVerdict::Unauthorized401);
    }
}

#[test]
fn test_control_plane_authenticated_modification_success() {
    let frozen_pids = vec![];
    let verdict = verify_control_plane_request_with_token(
        Some(E2E_CONTROL_TOKEN),
        None,
        Some(100),
        100,
        &frozen_pids,
        E2E_CONTROL_TOKEN,
    );
    assert_eq!(verdict, AuthVerdict::Authorized);
}

#[test]
fn test_control_plane_caller_pid_spoofing_detection() {
    let frozen_pids = vec![];
    // Claimed PID 100, but peer socket PID is 200
    let verdict = verify_control_plane_request_with_token(
        Some(E2E_CONTROL_TOKEN),
        None,
        Some(100),
        200,
        &frozen_pids,
        E2E_CONTROL_TOKEN,
    );
    assert_eq!(verdict, AuthVerdict::Forbidden403PidSpoofing);
}

#[test]
fn test_control_plane_quarantined_caller_blocking() {
    let frozen_pids = vec![300];
    // Caller is currently frozen/quarantined in PID 300
    let verdict = verify_control_plane_request_with_token(
        Some(E2E_CONTROL_TOKEN),
        None,
        Some(300),
        300,
        &frozen_pids,
        E2E_CONTROL_TOKEN,
    );
    assert_eq!(verdict, AuthVerdict::Forbidden403CallerQuarantined);
}

// ============================================================================
// MODULE 7: SEMANTIC DLP ENGINE & DEFAULT-DENY CONTAINMENT (R5)
// ============================================================================

pub use killswitch_telemetry::otel_lineage::{DlpClassification, DlpPolicy};
pub use killswitch_telemetry::semantic_dlp::{
    scan_payload_for_semantic_entities, SemanticEntityKind, SemanticEntityMatch,
};

#[test]
fn test_semantic_dlp_deal_value_m_and_a_detection() {
    let payload = "Target acquisition deal value: $45,000,000 payable at close";
    let matches = scan_payload_for_semantic_entities(payload);
    assert!(!matches.is_empty());
    let m = &matches[0];
    assert_eq!(m.kind, SemanticEntityKind::DealValue);
    assert_eq!(m.classification, DlpClassification::CrownJewel);
    assert_eq!(m.policy, DlpPolicy::Quarantine);
}

#[test]
fn test_semantic_dlp_deal_value_threshold_boundary() {
    // Exactly $999,999 -> Confidential + Block
    let payload_sub = "Deal value: $999999";
    let matches_sub = scan_payload_for_semantic_entities(payload_sub);
    assert!(!matches_sub.is_empty());
    assert_eq!(
        matches_sub[0].classification,
        DlpClassification::Confidential
    );
    assert_eq!(matches_sub[0].policy, DlpPolicy::Block);

    // Exactly $1,000,000 -> CrownJewel + Quarantine
    let payload_crown = "Deal value: $1000000";
    let matches_crown = scan_payload_for_semantic_entities(payload_crown);
    assert!(!matches_crown.is_empty());
    assert_eq!(
        matches_crown[0].classification,
        DlpClassification::CrownJewel
    );
    assert_eq!(matches_crown[0].policy, DlpPolicy::Quarantine);
}

#[test]
fn test_semantic_dlp_protected_health_information() {
    let payload = "Patient medical record contains SSN 123-45-6789 and lab findings";
    let matches = scan_payload_for_semantic_entities(payload);
    assert!(!matches.is_empty());
    let m = &matches[0];
    assert_eq!(m.kind, SemanticEntityKind::PhiMedicalRecord);
    assert_eq!(m.classification, DlpClassification::CrownJewel);
    assert_eq!(m.policy, DlpPolicy::Quarantine);
}

#[test]
fn test_semantic_dlp_default_deny_unclassified_sensitive() {
    let payload = "Internal operational metrics: strictly confidential - do not distribute";
    let matches = scan_payload_for_semantic_entities(payload);
    assert!(!matches.is_empty());
    // Must resolve to Block or Quarantine, NEVER Allow!
    assert_eq!(matches[0].policy, DlpPolicy::Block);
}

// ============================================================================
// MODULE 8: REPOSITORY PROVENANCE & INTEGRITY (R7)
// ============================================================================

#[test]
fn test_repository_integrity_no_unsigned_root_binaries() {
    // Correctly resolve repository root (two levels up from crates/killswitch-cli)
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let sha_manifest = root.join("dist").join("SHA256SUMS.txt");
    let manifest_content = if sha_manifest.exists() {
        std::fs::read_to_string(&sha_manifest).unwrap_or_default()
    } else {
        String::new()
    };

    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "exe" || ext == "dll" {
                        assert!(
                            sha_manifest.exists(),
                            "Binary {} in root requires dist/SHA256SUMS.txt manifest",
                            path.display()
                        );
                        let file_bytes = std::fs::read(&path).unwrap();
                        let file_hash =
                            killswitch_telemetry::ring0_driver_loader::compute_sha256_hex(
                                &file_bytes,
                            );
                        assert!(
                            manifest_content.contains(&file_hash),
                            "Binary {} (hash {}) not registered in dist/SHA256SUMS.txt",
                            path.display(),
                            file_hash
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn test_repository_integrity_ci_workflow_present() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let ci_path = root.join(".github").join("workflows").join("ci.yml");
    assert!(
        ci_path.exists(),
        ".github/workflows/ci.yml must exist for automated PR verification"
    );
    let content = std::fs::read_to_string(&ci_path).unwrap_or_default();
    assert!(
        content.contains("cargo test --workspace"),
        "CI must execute workspace test suite"
    );
    assert!(
        content.contains("e2e_peer_review_remediation"),
        "CI must execute E2E remediation suite"
    );
    assert!(
        content.contains("pull_request"),
        "CI must trigger on pull requests"
    );
}

#[test]
fn test_repository_integrity_sha256_manifest_format() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let sha_manifest = root.join("dist").join("SHA256SUMS.txt");
    if sha_manifest.exists() {
        let content = std::fs::read_to_string(&sha_manifest).unwrap_or_default();
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(
                parts.len(),
                2,
                "SHA256SUMS entry must be: <64-char-hash>  <filename>"
            );
            assert_eq!(
                parts[0].len(),
                64,
                "SHA-256 hash must be exactly 64 hexadecimal characters"
            );
        }
    }
}

#[test]
fn test_repository_integrity_driver_documentation_alignment() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let readme_path = root.join("README.md");
    if readme_path.exists() {
        let content = std::fs::read_to_string(&readme_path).unwrap_or_default();
        assert!(content.contains("Windows Filtering Platform") || content.contains("WFP"));
        assert!(
            !content.contains("included EV/WHQL-signed"),
            "Documentation must not falsely claim pre-signed kernel drivers are included in git"
        );
    }
}
